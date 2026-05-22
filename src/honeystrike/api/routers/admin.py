"""`/api/admin/*` — SOC Lead (admin) only. Manage operator accounts.

GET   /api/admin/users                  list accounts + role + rank
POST  /api/admin/users/{id}/role        promote/demote (admin ↔ member)
POST  /api/admin/users/{id}/active      activate / deactivate

Guards keep an instance from locking itself out: you can't demote or
deactivate the last remaining active admin (including yourself).
"""

from __future__ import annotations

import uuid
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from honeystrike.api.auth import get_db, require_admin
from honeystrike.core import progression
from honeystrike.core.models import User, UserProgress

router = APIRouter(prefix="/api/admin", tags=["admin"])


class RoleIn(BaseModel):
    role: str


class ActiveIn(BaseModel):
    is_active: bool


async def _active_admin_count(db: AsyncSession) -> int:
    return int(
        (await db.execute(
            select(func.count(User.id)).where(User.role == "admin", User.is_active.is_(True))
        )).scalar_one()
    )


async def _load(db: AsyncSession, user_id: uuid.UUID) -> User:
    user = (await db.execute(select(User).where(User.id == user_id))).scalars().first()
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="user not found")
    return user


@router.get("/users")
async def list_users(
    db: Annotated[AsyncSession, Depends(get_db)],
    _admin: Annotated[User, Depends(require_admin)],
) -> list[dict[str, Any]]:
    rows = (
        await db.execute(
            select(User, UserProgress)
            .outerjoin(UserProgress, UserProgress.user_id == User.id)
            .order_by(User.created_at.asc())
        )
    ).all()
    out = []
    for user, prog in rows:
        xp = prog.xp if prog else 0
        out.append({
            "id": str(user.id),
            "username": user.username,
            "role": user.role,
            "is_active": user.is_active,
            "created_at": user.created_at.isoformat() if user.created_at else None,
            "last_login_at": user.last_login_at.isoformat() if user.last_login_at else None,
            "xp": xp,
            "rank": progression.rank_for(xp)["name"],
        })
    return out


@router.post("/users/{user_id}/role")
async def set_role(
    user_id: uuid.UUID,
    body: RoleIn,
    db: Annotated[AsyncSession, Depends(get_db)],
    admin: Annotated[User, Depends(require_admin)],
) -> dict[str, Any]:
    if body.role not in ("admin", "member"):
        raise HTTPException(status_code=422, detail="role must be 'admin' or 'member'")
    user = await _load(db, user_id)
    # Don't allow demoting the last active admin.
    if user.role == "admin" and body.role == "member" and await _active_admin_count(db) <= 1:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="can't demote the last remaining admin",
        )
    user.role = body.role
    await db.commit()
    return {"ok": True, "id": str(user.id), "role": user.role}


@router.post("/users/{user_id}/active")
async def set_active(
    user_id: uuid.UUID,
    body: ActiveIn,
    db: Annotated[AsyncSession, Depends(get_db)],
    admin: Annotated[User, Depends(require_admin)],
) -> dict[str, Any]:
    user = await _load(db, user_id)
    if not body.is_active and user.role == "admin" and await _active_admin_count(db) <= 1:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="can't deactivate the last remaining admin",
        )
    user.is_active = body.is_active
    await db.commit()
    return {"ok": True, "id": str(user.id), "is_active": user.is_active}
