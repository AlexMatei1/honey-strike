"""`/api/profile` — current operator's profile.

Returns the authenticated user's basic info plus a handful of stats that
need server-side aggregation. The dashboard pulls the rest (overview, geo,
top TTPs) from existing endpoints to avoid duplicating the SQL here.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from honeystrike.api.auth import current_user, get_db
from honeystrike.core.models import Fingerprint, Session, User

router = APIRouter(prefix="/api/profile", tags=["profile"])


@router.get("")
async def get_profile(
    db: Annotated[AsyncSession, Depends(get_db)],
    user: Annotated[User, Depends(current_user)],
) -> dict[str, Any]:
    """All-time stats for the operator's HoneyStrike instance — these are
    platform-wide counts, not per-user, but on a single-operator instance
    they are effectively 'your' numbers."""
    total_sessions = int(
        (await db.execute(select(func.count(Session.id)))).scalar_one()
    )
    critical_sessions = int(
        (await db.execute(
            select(func.count(Session.id)).where(Session.severity == "critical")
        )).scalar_one()
    )
    unique_ips = int(
        (await db.execute(select(func.count(func.distinct(Session.src_ip))))).scalar_one()
    )
    unique_countries = int(
        (await db.execute(
            select(func.count(func.distinct(Fingerprint.country_iso)))
            .where(Fingerprint.country_iso.isnot(None))
        )).scalar_one()
    )
    max_score = int(
        (await db.execute(select(func.coalesce(func.max(Session.threat_score), 0)))).scalar_one()
    )
    member_for_days = (
        (datetime.now(UTC) - user.created_at).days if user.created_at else 0
    )
    return {
        "username": user.username,
        "role": "operator",                            # single-operator platform
        "is_active": user.is_active,
        "created_at": user.created_at.isoformat() if user.created_at else None,
        "last_login_at": user.last_login_at.isoformat() if user.last_login_at else None,
        "member_for_days": member_for_days,
        "stats": {
            "total_sessions": total_sessions,
            "critical_sessions": critical_sessions,
            "unique_ips": unique_ips,
            "unique_countries": unique_countries,
            "max_threat_score": max_score,
        },
    }
