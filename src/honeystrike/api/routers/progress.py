"""`/api/progress` — server-side gamification state per account.

GET  /api/progress         current user's XP / rank / streak / badges / activity
POST /api/progress/event   apply one action ({action, meta}) and return updated

The XP/badge rules live in `core.progression`; this router just persists the
JSONB state on `user_progress` and joins in platform stats + the lesson
catalogue for the stat-dependent badges.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from honeystrike.api.auth import current_user, get_db
from honeystrike.core import progression
from honeystrike.core.models import Fingerprint, Session, User, UserProgress

router = APIRouter(prefix="/api/progress", tags=["progress"])


class EventIn(BaseModel):
    action: str
    meta: dict[str, Any] | None = None


async def _platform_stats(db: AsyncSession) -> dict[str, int]:
    critical = int(
        (await db.execute(
            select(func.count(Session.id)).where(Session.severity == "critical")
        )).scalar_one()
    )
    countries = int(
        (await db.execute(
            select(func.count(func.distinct(Fingerprint.country_iso)))
            .where(Fingerprint.country_iso.isnot(None))
        )).scalar_one()
    )
    return {"critical_sessions": critical, "unique_countries": countries}


def _lessons_index() -> dict[str, Any]:
    # Imported lazily so a lesson-catalogue change doesn't ripple imports.
    from honeystrike.api.routers.lessons import _catalogue

    idx: dict[str, Any] = {"_all_attack": set(), "_all_defend": set()}
    for item in _catalogue():
        idx["_all_" + item["family"]].add(item["id"])
    return idx


async def _get_or_create(db: AsyncSession, user: User) -> UserProgress:
    row = (
        await db.execute(select(UserProgress).where(UserProgress.user_id == user.id))
    ).scalars().first()
    if row is None:
        row = UserProgress(user_id=user.id)
        db.add(row)
        await db.flush()
    return row


def _to_dict(row: UserProgress) -> dict[str, Any]:
    return {
        "xp": row.xp,
        "streak": row.streak,
        "best_streak": row.best_streak,
        "counts": dict(row.counts or {}),
        "activity": list(row.activity or []),
        "badges": dict(row.badges or {}),
    }


def _write_back(row: UserProgress, prog: dict[str, Any]) -> None:
    row.xp = prog["xp"]
    row.streak = prog["streak"]
    row.best_streak = prog["best_streak"]
    row.counts = prog["counts"]
    row.activity = prog["activity"]
    row.badges = prog["badges"]
    row.updated_at = datetime.now(UTC)


def _serialize(prog: dict[str, Any]) -> dict[str, Any]:
    return {
        "xp": prog["xp"],
        "streak": prog["streak"],
        "best_streak": prog["best_streak"],
        "rank": progression.rank_for(prog["xp"]),
        "counts": prog["counts"],
        "activity": prog["activity"][:30],
        "badges": progression.serialize_badges(prog),
    }


def _lessons_done(prog: dict[str, Any], idx: dict[str, Any]) -> dict[str, Any]:
    done_ids = set(prog.get("counts", {}).get("lessonsDoneIds", []))
    out = dict(idx)
    out["attack"] = {x.split(":", 1)[1] for x in done_ids if x.startswith("attack:")}
    out["defend"] = {x.split(":", 1)[1] for x in done_ids if x.startswith("defend:")}
    return out


@router.get("")
async def get_progress(
    db: Annotated[AsyncSession, Depends(get_db)],
    user: Annotated[User, Depends(current_user)],
) -> dict[str, Any]:
    row = await _get_or_create(db, user)
    prog = _to_dict(row)
    stats = await _platform_stats(db)
    lessons = _lessons_done(prog, _lessons_index())
    newly = progression.evaluate_badges(prog, stats=stats, lessons=lessons)
    if newly:
        _write_back(row, prog)
    await db.commit()
    out = _serialize(prog)
    out["newly_earned"] = newly
    return out


@router.post("/event")
async def record_event(
    body: EventIn,
    db: Annotated[AsyncSession, Depends(get_db)],
    user: Annotated[User, Depends(current_user)],
) -> dict[str, Any]:
    row = await _get_or_create(db, user)
    prog = _to_dict(row)
    progression.apply_event(prog, body.action, body.meta)
    stats = await _platform_stats(db)
    lessons = _lessons_done(prog, _lessons_index())
    newly = progression.evaluate_badges(prog, stats=stats, lessons=lessons)
    _write_back(row, prog)
    await db.commit()
    out = _serialize(prog)
    out["newly_earned"] = newly
    return out
