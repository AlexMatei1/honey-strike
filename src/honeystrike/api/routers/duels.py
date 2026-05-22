"""`/api/duels/*` — member-vs-member consensual PvP.

Flow: A challenges B → B accepts → timed match. The attacker fires scenario
"waves"; each wave hides its MITRE technique. The defender must label the
technique in time to "block" the wave. At the end:

  defender_score = 10 × waves blocked (labelled correctly)
  attacker_score = 10 × waves that got through (unlabelled at finish)

Winner gets +25 XP (duel_win) + the +10 both sides get for playing. Firing
and labelling are unlocked *inside an active duel* even for Analysts — that's
the consent boundary: PvP is mutual, unilateral firing stays Lead-only.
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm.attributes import flag_modified

from honeystrike.api.auth import current_user, get_db
from honeystrike.core import progression
from honeystrike.core.models import Duel, User, UserProgress
from honeystrike.api.routers.play import _SCENARIOS, _dispatch_scenario, AttackIn

router = APIRouter(prefix="/api/duels", tags=["duels"])

WAVE_POINTS = 10
MAX_WAVES = 20
# Scenarios usable in a duel: must carry at least one expected TTP to label.
_DUEL_SCENARIOS = [s for s in _SCENARIOS if s.get("expected_ttps")]
_BY_ID = {s["id"]: s for s in _DUEL_SCENARIOS}


# ---------------------------------------------------------------------------
# IO
# ---------------------------------------------------------------------------

class ChallengeIn(BaseModel):
    opponent: str
    duration_seconds: int = Field(300, ge=60, le=1800)


class FireIn(BaseModel):
    scenario: str


class LabelIn(BaseModel):
    wave_id: str
    technique_id: str


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _now() -> datetime:
    return datetime.now(UTC)


async def _load(db: AsyncSession, duel_id: uuid.UUID) -> Duel:
    d = (await db.execute(select(Duel).where(Duel.id == duel_id))).scalars().first()
    if d is None:
        raise HTTPException(status_code=404, detail="duel not found")
    return d


async def _username(db: AsyncSession, uid: uuid.UUID) -> str:
    return (await db.execute(select(User.username).where(User.id == uid))).scalar_one()


async def _award(db: AsyncSession, user_id: uuid.UUID, action: str, meta: dict) -> None:
    """Apply one progression event to another user (for duel XP)."""
    row = (
        await db.execute(select(UserProgress).where(UserProgress.user_id == user_id))
    ).scalars().first()
    if row is None:
        row = UserProgress(user_id=user_id)
        db.add(row)
        await db.flush()
    prog = {
        "xp": row.xp, "streak": row.streak, "best_streak": row.best_streak,
        "counts": dict(row.counts or {}), "activity": list(row.activity or []),
        "badges": dict(row.badges or {}),
    }
    progression.apply_event(prog, action, meta)
    progression.evaluate_badges(
        prog, stats={}, lessons={"attack": set(), "defend": set(), "_all_attack": set(), "_all_defend": set()},
    )
    row.xp, row.streak, row.best_streak = prog["xp"], prog["streak"], prog["best_streak"]
    row.counts, row.activity, row.badges = prog["counts"], prog["activity"], prog["badges"]
    row.updated_at = _now()


async def _serialize(db: AsyncSession, d: Duel, viewer: User) -> dict[str, Any]:
    is_attacker = d.attacker_id == viewer.id
    waves_out = []
    for w in (d.waves or []):
        item = {
            "id": w["id"], "scenario": w["scenario"], "label": w.get("label", w["scenario"]),
            "fired_at": w.get("fired_at"), "resolved": w.get("resolved", False),
            "correct": w.get("correct"), "labeled_ttp": w.get("labeled_ttp"),
        }
        # Hide the answer from the defender until the wave is resolved / duel over.
        if is_attacker or w.get("resolved") or d.status in ("finished", "expired"):
            item["expected_ttps"] = w.get("expected_ttps", [])
        waves_out.append(item)
    return {
        "id": str(d.id),
        "attacker": await _username(db, d.attacker_id),
        "defender": await _username(db, d.defender_id),
        "your_role": "attacker" if is_attacker else "defender",
        "status": d.status,
        "duration_seconds": d.duration_seconds,
        "attacker_score": d.attacker_score,
        "defender_score": d.defender_score,
        "waves": waves_out,
        "started_at": d.started_at.isoformat() if d.started_at else None,
        "ends_at": d.ends_at.isoformat() if d.ends_at else None,
        "finished_at": d.finished_at.isoformat() if d.finished_at else None,
        "seconds_left": (
            max(0, int((d.ends_at - _now()).total_seconds())) if d.ends_at and d.status == "active" else 0
        ),
    }


def _tally(d: Duel) -> None:
    blocked = sum(1 for w in (d.waves or []) if w.get("correct"))
    through = sum(1 for w in (d.waves or []) if not w.get("correct"))
    d.defender_score = blocked * WAVE_POINTS
    d.attacker_score = through * WAVE_POINTS


async def _finalize(db: AsyncSession, d: Duel) -> None:
    if d.status not in ("active", "pending"):
        return
    _tally(d)
    d.status = "finished"
    d.finished_at = _now()
    a_win = d.attacker_score > d.defender_score
    d_win = d.defender_score > d.attacker_score
    a_name = await _username(db, d.attacker_id)
    d_name = await _username(db, d.defender_id)
    await _award(db, d.attacker_id, "duel_played", {"won": a_win, "opponent": d_name})
    await _award(db, d.defender_id, "duel_played", {"won": d_win, "opponent": a_name})
    if a_win:
        await _award(db, d.attacker_id, "duel_win", {"opponent": d_name})
    elif d_win:
        await _award(db, d.defender_id, "duel_win", {"opponent": a_name})


async def _expire_if_due(db: AsyncSession, d: Duel) -> None:
    if d.status == "active" and d.ends_at and _now() >= d.ends_at:
        await _finalize(db, d)
        await db.commit()


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.get("/scenarios")
async def duel_scenarios(_u: Annotated[User, Depends(current_user)]) -> list[dict[str, Any]]:
    return [{"id": s["id"], "label": s["label"], "service": s["service"]} for s in _DUEL_SCENARIOS]


@router.get("/opponents")
async def opponents(
    db: Annotated[AsyncSession, Depends(get_db)],
    user: Annotated[User, Depends(current_user)],
) -> list[dict[str, Any]]:
    rows = (
        await db.execute(
            select(User.username, User.role, User.last_login_at)
            .where(User.id != user.id, User.is_active.is_(True))
            .order_by(User.last_login_at.desc().nullslast())
            .limit(50)
        )
    ).all()
    return [{"username": u, "role": r,
             "last_seen": (ll.isoformat() if ll else None)} for u, r, ll in rows]


@router.post("/challenge")
async def challenge(
    body: ChallengeIn,
    db: Annotated[AsyncSession, Depends(get_db)],
    user: Annotated[User, Depends(current_user)],
) -> dict[str, Any]:
    opp = (
        await db.execute(select(User).where(User.username == body.opponent, User.is_active.is_(True)))
    ).scalars().first()
    if opp is None:
        raise HTTPException(status_code=404, detail="opponent not found")
    if opp.id == user.id:
        raise HTTPException(status_code=422, detail="you can't duel yourself")
    # No duplicate open duel between the same pair.
    existing = (
        await db.execute(
            select(Duel).where(
                Duel.status.in_(("pending", "active")),
                or_(
                    (Duel.attacker_id == user.id) & (Duel.defender_id == opp.id),
                    (Duel.attacker_id == opp.id) & (Duel.defender_id == user.id),
                ),
            )
        )
    ).scalars().first()
    if existing is not None:
        raise HTTPException(status_code=409, detail="there's already an open duel with this player")
    d = Duel(attacker_id=user.id, defender_id=opp.id, duration_seconds=body.duration_seconds)
    db.add(d)
    await db.commit()
    await db.refresh(d)
    return await _serialize(db, d, user)


@router.get("/inbox")
async def inbox(
    db: Annotated[AsyncSession, Depends(get_db)],
    user: Annotated[User, Depends(current_user)],
) -> list[dict[str, Any]]:
    rows = (
        await db.execute(
            select(Duel).where(Duel.defender_id == user.id, Duel.status == "pending")
            .order_by(Duel.created_at.desc())
        )
    ).scalars().all()
    return [await _serialize(db, d, user) for d in rows]


@router.get("/mine")
async def mine(
    db: Annotated[AsyncSession, Depends(get_db)],
    user: Annotated[User, Depends(current_user)],
) -> list[dict[str, Any]]:
    rows = (
        await db.execute(
            select(Duel).where(
                or_(Duel.attacker_id == user.id, Duel.defender_id == user.id),
                Duel.status.in_(("pending", "active")),
            ).order_by(Duel.created_at.desc())
        )
    ).scalars().all()
    for d in rows:
        await _expire_if_due(db, d)
    return [await _serialize(db, d, user) for d in rows]


@router.get("/leaderboard")
async def leaderboard(
    db: Annotated[AsyncSession, Depends(get_db)],
    _u: Annotated[User, Depends(current_user)],
) -> list[dict[str, Any]]:
    rows = (
        await db.execute(
            select(User.username, UserProgress.counts, UserProgress.xp)
            .join(UserProgress, UserProgress.user_id == User.id)
        )
    ).all()
    out = []
    for username, counts, xp in rows:
        counts = counts or {}
        played = int(counts.get("duelsPlayed", 0))
        if played == 0:
            continue
        out.append({
            "username": username,
            "duels_played": played,
            "duels_won": int(counts.get("duelsWon", 0)),
            "xp": xp,
        })
    out.sort(key=lambda r: (r["duels_won"], r["xp"]), reverse=True)
    return out[:20]


@router.post("/{duel_id}/accept")
async def accept(
    duel_id: uuid.UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    user: Annotated[User, Depends(current_user)],
) -> dict[str, Any]:
    d = await _load(db, duel_id)
    if d.defender_id != user.id:
        raise HTTPException(status_code=403, detail="only the challenged player can accept")
    if d.status != "pending":
        raise HTTPException(status_code=409, detail=f"duel is {d.status}")
    d.status = "active"
    d.started_at = _now()
    d.ends_at = d.started_at + timedelta(seconds=d.duration_seconds)
    await db.commit()
    return await _serialize(db, d, user)


@router.post("/{duel_id}/decline")
async def decline(
    duel_id: uuid.UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    user: Annotated[User, Depends(current_user)],
) -> dict[str, Any]:
    d = await _load(db, duel_id)
    if d.defender_id != user.id:
        raise HTTPException(status_code=403, detail="only the challenged player can decline")
    if d.status != "pending":
        raise HTTPException(status_code=409, detail=f"duel is {d.status}")
    d.status = "declined"
    await db.commit()
    return {"ok": True, "status": "declined"}


@router.post("/{duel_id}/fire")
async def fire(
    duel_id: uuid.UUID,
    body: FireIn,
    db: Annotated[AsyncSession, Depends(get_db)],
    user: Annotated[User, Depends(current_user)],
) -> dict[str, Any]:
    d = await _load(db, duel_id)
    await _expire_if_due(db, d)
    if d.status != "active":
        raise HTTPException(status_code=409, detail=f"duel is {d.status}")
    if d.attacker_id != user.id:
        raise HTTPException(status_code=403, detail="only the attacker fires in this duel")
    meta = _BY_ID.get(body.scenario)
    if meta is None:
        raise HTTPException(status_code=400, detail="scenario not available in duels")
    if len(d.waves or []) >= MAX_WAVES:
        raise HTTPException(status_code=429, detail="wave limit reached")

    wave = {
        "id": uuid.uuid4().hex[:8],
        "scenario": meta["id"],
        "label": meta["label"],
        "expected_ttps": [t.upper() for t in meta.get("expected_ttps", [])],
        "fired_at": _now().isoformat(),
        "resolved": False,
        "correct": False,
        "labeled_ttp": None,
    }
    waves = list(d.waves or [])
    waves.append(wave)
    d.waves = waves
    flag_modified(d, "waves")          # ensure the JSONB column is written
    await db.commit()

    # Fire the real runner for authenticity (best-effort, non-blocking) so the
    # attack also shows on the live dashboard.
    target = meta["default_target"]
    try:
        coro = _dispatch_scenario(
            AttackIn(scenario=meta["id"], target=target, intensity="burst"), target, meta,
        )
        asyncio.create_task(_guarded(coro))
    except Exception:       # noqa: BLE001
        pass
    return await _serialize(db, d, user)


async def _guarded(coro) -> None:        # noqa: ANN001 — fire-and-forget
    try:
        await coro
    except Exception:       # noqa: BLE001
        pass


@router.post("/{duel_id}/label")
async def label(
    duel_id: uuid.UUID,
    body: LabelIn,
    db: Annotated[AsyncSession, Depends(get_db)],
    user: Annotated[User, Depends(current_user)],
) -> dict[str, Any]:
    d = await _load(db, duel_id)
    await _expire_if_due(db, d)
    if d.status != "active":
        raise HTTPException(status_code=409, detail=f"duel is {d.status}")
    if d.defender_id != user.id:
        raise HTTPException(status_code=403, detail="only the defender labels in this duel")
    guess = body.technique_id.strip().upper()
    waves = list(d.waves or [])
    found = None
    for w in waves:
        if w["id"] == body.wave_id:
            found = w
            break
    if found is None:
        raise HTTPException(status_code=404, detail="wave not found")
    if found.get("resolved"):
        raise HTTPException(status_code=409, detail="wave already resolved")
    correct = guess in [t.upper() for t in found.get("expected_ttps", [])]
    found["labeled_ttp"] = guess
    if correct:
        found["resolved"] = True
        found["correct"] = True
    d.waves = waves
    flag_modified(d, "waves")          # ensure the JSONB mutation is persisted
    _tally(d)
    await db.commit()
    return {"correct": correct, "wave_id": body.wave_id, **(await _serialize(db, d, user))}


@router.post("/{duel_id}/finish")
async def finish(
    duel_id: uuid.UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    user: Annotated[User, Depends(current_user)],
) -> dict[str, Any]:
    d = await _load(db, duel_id)
    if user.id not in (d.attacker_id, d.defender_id):
        raise HTTPException(status_code=403, detail="not your duel")
    if d.status == "active" or d.status == "pending":
        await _finalize(db, d)
        await db.commit()
    return await _serialize(db, d, user)


@router.get("/{duel_id}")
async def get_duel(
    duel_id: uuid.UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    user: Annotated[User, Depends(current_user)],
) -> dict[str, Any]:
    d = await _load(db, duel_id)
    if user.id not in (d.attacker_id, d.defender_id):
        raise HTTPException(status_code=403, detail="not your duel")
    await _expire_if_due(db, d)
    return await _serialize(db, d, user)
