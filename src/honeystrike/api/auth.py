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

from datetime import UTC, datetime, timedelta
from typing import Annotated

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from fastapi import APIRouter, Cookie, Depends, HTTPException, Request, Response, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from honeystrike.config import get_settings
from honeystrike.core.db import get_sessionmaker
from honeystrike.core.models import User

ACCESS_TOKEN_TYPE = "access"
REFRESH_TOKEN_TYPE = "refresh"
REFRESH_COOKIE_NAME = "hs_refresh"

_hasher = PasswordHasher()
_bearer = HTTPBearer(auto_error=False)


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


# ---------------------------------------------------------------------------
# Login + refresh routes
# ---------------------------------------------------------------------------

class LoginIn(BaseModel):
    username: str
    password: str


class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int


router = APIRouter(prefix="/api/auth", tags=["auth"])


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
    await db.execute(
        update(User)
        .where(User.id == user.id)
        .values(last_login_at=datetime.now(UTC))
    )
    await db.commit()
    return TokenOut(
        access_token=access,
        expires_in=settings.jwt_access_ttl_seconds,
    )


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
