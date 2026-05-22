"""JWT auth helpers + login route.

Issues short-lived access tokens for the dashboard API and a longer-lived
refresh token in an HttpOnly cookie. Passwords are stored as argon2 hashes
in `users.password_hash`.

We default to HS256 + `settings.secret_key`. RS256 with mounted keys is
supported for prod hardening (Phase 5 stretch) but adds key-management
complexity that isn't worth carrying on day one for a single-issuer setup.

A FastAPI dependency `current_user` enforces auth on every protected route.
"""

from __future__ import annotations

import re
import time
from datetime import UTC, datetime, timedelta
from typing import Annotated

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from fastapi import APIRouter, Cookie, Depends, HTTPException, Request, Response, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel
from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from honeystrike.config import get_settings
from honeystrike.core.db import get_sessionmaker
from honeystrike.core.models import User

ACCESS_TOKEN_TYPE = "access"
REFRESH_TOKEN_TYPE = "refresh"
REFRESH_COOKIE_NAME = "hs_refresh"

_hasher = PasswordHasher()
_bearer = HTTPBearer(auto_error=False)

# Username: 3–32 chars, starts alphanumeric, then alphanumerics / _ / - / .
_USERNAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.\-]{2,31}$")
_PASSWORD_MIN = 8
_PASSWORD_MAX = 128


def validate_registration(username: str, password: str) -> str | None:
    """Return an error message if the credentials are unacceptable, else None.
    Pure function so it can be unit-tested without a database."""
    if not _USERNAME_RE.match(username or ""):
        return ("username must be 3–32 chars, start with a letter or number, and "
                "contain only letters, numbers, and . _ -")
    if not (_PASSWORD_MIN <= len(password or "") <= _PASSWORD_MAX):
        return f"password must be {_PASSWORD_MIN}–{_PASSWORD_MAX} characters"
    return None


# Simple in-process sliding-window limiter for account creation, so an open
# demo can't be flooded with sign-ups. Resets when the API restarts.
_REGISTER_MAX_PER_WINDOW = 10
_REGISTER_WINDOW_SECONDS = 300.0
_register_times: list[float] = []


def _registration_rate_limit() -> None:
    now = time.time()
    cutoff = now - _REGISTER_WINDOW_SECONDS
    _register_times[:] = [t for t in _register_times if t > cutoff]
    if len(_register_times) >= _REGISTER_MAX_PER_WINDOW:
        retry = int(_REGISTER_WINDOW_SECONDS - (now - _register_times[0])) + 1
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"too many sign-ups; retry in ~{retry}s",
            headers={"Retry-After": str(retry)},
        )
    _register_times.append(now)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def hash_password(plain: str) -> str:
    return _hasher.hash(plain)


def verify_password(plain: str, hashed: str) -> bool:
    try:
        _hasher.verify(hashed, plain)
        return True
    except VerifyMismatchError:
        return False


def issue_token(*, subject: str, token_type: str, ttl_seconds: int) -> str:
    """Sign a JWT for `subject`. `token_type` is embedded as a claim."""
    settings = get_settings()
    now = datetime.now(UTC)
    payload = {
        "sub": subject,
        "type": token_type,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(seconds=ttl_seconds)).timestamp()),
    }
    return jwt.encode(payload, settings.secret_key, algorithm="HS256")


def decode_token(token: str, *, expected_type: str | None = None) -> dict:
    """Verify signature + expiry. Raises HTTPException on any failure."""
    settings = get_settings()
    try:
        payload = jwt.decode(token, settings.secret_key, algorithms=["HS256"])
    except jwt.ExpiredSignatureError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="token expired"
        ) from exc
    except jwt.InvalidTokenError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid token"
        ) from exc
    if expected_type and payload.get("type") != expected_type:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="wrong token type"
        )
    return payload


# ---------------------------------------------------------------------------
# Dependency
# ---------------------------------------------------------------------------

async def get_db() -> AsyncSession:                       # pragma: no cover
    """FastAPI dep — yields one session per request."""
    sessionmaker = get_sessionmaker()
    async with sessionmaker() as db:
        yield db


async def current_user(                                   # pragma: no cover
    request: Request,
    creds: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> User:
    """Resolve the user from the Authorization header.

    Stored on `request.state.user` so request middleware can read it without
    re-doing the DB lookup.
    """
    if creds is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="not authenticated"
        )
    payload = decode_token(creds.credentials, expected_type=ACCESS_TOKEN_TYPE)
    username = payload.get("sub")
    if not username:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid subject"
        )
    user = (
        (await db.execute(select(User).where(User.username == username, User.is_active.is_(True))))
        .scalars()
        .first()
    )
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="user not found"
        )
    request.state.user = user
    return user


async def require_admin(                                  # pragma: no cover
    user: Annotated[User, Depends(current_user)],
) -> User:
    """Dependency for Lead-only (admin) routes. 403 for members."""
    if user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="this action requires a SOC Lead (admin) account",
        )
    return user


# ---------------------------------------------------------------------------
# Login + refresh routes
# ---------------------------------------------------------------------------

class LoginIn(BaseModel):
    username: str
    password: str


class RegisterIn(BaseModel):
    username: str
    password: str


class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int


class AuthConfigOut(BaseModel):
    allow_registration: bool


class MeOut(BaseModel):
    username: str
    role: str
    is_admin: bool


router = APIRouter(prefix="/api/auth", tags=["auth"])


def _issue_session(user: User, response: Response) -> TokenOut:
    """Issue an access token (returned) + refresh cookie for a logged-in user."""
    settings = get_settings()
    access = issue_token(
        subject=user.username,
        token_type=ACCESS_TOKEN_TYPE,
        ttl_seconds=settings.jwt_access_ttl_seconds,
    )
    refresh = issue_token(
        subject=user.username,
        token_type=REFRESH_TOKEN_TYPE,
        ttl_seconds=settings.jwt_refresh_ttl_seconds,
    )
    response.set_cookie(
        REFRESH_COOKIE_NAME,
        refresh,
        max_age=settings.jwt_refresh_ttl_seconds,
        httponly=True,
        samesite="lax",
        secure=settings.app_env == "production",
    )
    return TokenOut(access_token=access, expires_in=settings.jwt_access_ttl_seconds)


@router.get("/config", response_model=AuthConfigOut)
async def auth_config() -> AuthConfigOut:
    """Public — lets the login page show/hide the 'create account' UI."""
    return AuthConfigOut(allow_registration=get_settings().allow_registration)


@router.get("/me", response_model=MeOut)
async def me(user: Annotated[User, Depends(current_user)]) -> MeOut:
    """Current user's identity + role — the frontend uses this to render the
    role badge and lock Lead-only actions."""
    return MeOut(username=user.username, role=user.role, is_admin=user.role == "admin")


@router.post("/register", response_model=TokenOut, status_code=status.HTTP_201_CREATED)
async def register(
    payload: RegisterIn,
    response: Response,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> TokenOut:
    """Self-service account creation. Gated by ALLOW_REGISTRATION. On success
    the new user is logged in immediately (access token + refresh cookie)."""
    settings = get_settings()
    if not settings.allow_registration:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="account registration is disabled on this instance",
        )

    username = (payload.username or "").strip()
    err = validate_registration(username, payload.password)
    if err:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=err)

    # Case-insensitive uniqueness so "Admin" can't shadow "admin".
    existing = (
        await db.execute(
            select(User).where(func.lower(User.username) == username.lower())
        )
    ).scalars().first()
    if existing is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="username already taken"
        )

    # Rate-limit only *successful* creations (validation/dup failures above are
    # cheap and shouldn't burn a visitor's quota), guarding the costly argon2
    # hash + insert against flooding.
    _registration_rate_limit()

    user = User(
        username=username,
        password_hash=hash_password(payload.password),
        role="member",          # self-service signups are always Analysts
        is_active=True,
        last_login_at=datetime.now(UTC),
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)
    return _issue_session(user, response)


@router.post("/login", response_model=TokenOut)           # pragma: no cover
async def login(
    payload: LoginIn,
    response: Response,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> TokenOut:
    user = (
        (await db.execute(select(User).where(User.username == payload.username)))
        .scalars()
        .first()
    )
    if user is None or not user.is_active or not verify_password(payload.password, user.password_hash):
        # Same response for unknown user / wrong password to avoid leaking which is which.
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid credentials"
        )
    await db.execute(
        update(User)
        .where(User.id == user.id)
        .values(last_login_at=datetime.now(UTC))
    )
    await db.commit()
    return _issue_session(user, response)


@router.post("/refresh", response_model=TokenOut)         # pragma: no cover
async def refresh_token(
    hs_refresh: Annotated[str | None, Cookie()] = None,
    db: Annotated[AsyncSession, Depends(get_db)] = None,  # type: ignore[assignment]
) -> TokenOut:
    if not hs_refresh:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="missing refresh token"
        )
    payload = decode_token(hs_refresh, expected_type=REFRESH_TOKEN_TYPE)
    username = payload.get("sub")
    if not username:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid subject"
        )
    user = (
        (await db.execute(select(User).where(User.username == username, User.is_active.is_(True))))
        .scalars()
        .first()
    )
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="user not found"
        )
    settings = get_settings()
    access = issue_token(
        subject=user.username,
        token_type=ACCESS_TOKEN_TYPE,
        ttl_seconds=settings.jwt_access_ttl_seconds,
    )
    return TokenOut(access_token=access, expires_in=settings.jwt_access_ttl_seconds)


@router.post("/logout")                                   # pragma: no cover
async def logout(response: Response) -> dict:
    response.delete_cookie(REFRESH_COOKIE_NAME)
    return {"ok": True}
