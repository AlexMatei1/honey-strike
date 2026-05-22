"""`/api/arena/*` — open PvP arena (free-for-all during a 'PvP window').

A SOC Lead opens a timed window. While it's open, ANY member can fire scenario
waves at the shared honeypot, and anyone can race to label each wave's MITRE
technique — first correct label blocks it and scores the labeller. Waves that
survive the window score their firer. A live scoreboard ranks everyone.

State is in-process (one window per instance, ephemeral) — no schema needed;
it resets if the API restarts, which is fine for a live event.
"""

from __future__ import annotations

import asyncio
import time
import uuid
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from honeystrike.api.auth import current_user, get_db, require_admin
from honeystrike.api.routers.duels import _award
from honeystrike.api.routers.play import _SCENARIOS, _dispatch_scenario, AttackIn
from honeystrike.core.models import User
from sqlalchemy.ext.asyncio import AsyncSession

router = APIRouter(prefix="/api/arena", tags=["arena"])

WAVE_POINTS = 10
MAX_WAVES = 60
_DUEL_SCENARIOS = [s for s in _SCENARIOS if s.get("expected_ttps")]
_BY_ID = {s["id"]: s for s in _DUEL_SCENARIOS}

# In-process arena state.
_arena: dict[str, Any] = {
    "open": False,
    "ends_at": None,        # epoch seconds
    "opened_by": None,
    "waves": [],            # list of wave dicts
    "scores": {},           # username -> points
}


class OpenIn(BaseModel):
    duration_seconds: int = Field(600, ge=60, le=3600)


class FireIn(BaseModel):
    scenario: str


class LabelIn(BaseModel):
    wave_id: str
    technique_id: str


def _now() -> float:
    return time.time()


def _is_open() -> bool:
    if not _arena["open"]:
        return False
    if _arena["ends_at"] and _now() >= _arena["ends_at"]:
        _close()
        return False
    return True


def _close() -> None:
    """End the window: any unblocked wave scores its firer."""
    if not _arena["open"]:
        return
    for w in _arena["waves"]:
        if not w["resolved"]:
            w["resolved"] = True
            w["timed_out"] = True
            _arena["scores"][w["fired_by"]] = _arena["scores"].get(w["fired_by"], 0) + WAVE_POINTS
    _arena["open"] = False


def _seconds_left() -> int:
    if not _arena["open"] or not _arena["ends_at"]:
        return 0
    return max(0, int(_arena["ends_at"] - _now()))


def _scoreboard() -> list[dict[str, Any]]:
    rows = [{"username": u, "points": p} for u, p in _arena["scores"].items()]
    rows.sort(key=lambda r: r["points"], reverse=True)
    return rows


def _state(viewer: User) -> dict[str, Any]:
    open_now = _is_open()
    waves = []
    for w in _arena["waves"][-30:]:
        item = {
            "id": w["id"], "scenario": w["scenario"], "label": w["label"],
            "fired_by": w["fired_by"], "resolved": w["resolved"],
            "blocked_by": w.get("blocked_by"),
        }
        # Reveal the answer only once the wave is resolved or the window closed.
        if w["resolved"] or not open_now:
            item["expected_ttps"] = w["expected_ttps"]
        waves.append(item)
    return {
        "open": open_now,
        "seconds_left": _seconds_left(),
        "waves": list(reversed(waves)),
        "scoreboard": _scoreboard(),
        "you": viewer.username,
    }


@router.get("/scenarios")
async def arena_scenarios(_u: Annotated[User, Depends(current_user)]) -> list[dict[str, Any]]:
    return [{"id": s["id"], "label": s["label"], "service": s["service"]} for s in _DUEL_SCENARIOS]


@router.get("/state")
async def state(user: Annotated[User, Depends(current_user)]) -> dict[str, Any]:
    return _state(user)


@router.post("/open")
async def open_window(
    body: OpenIn,
    admin: Annotated[User, Depends(require_admin)],
) -> dict[str, Any]:
    """Open a fresh PvP window (Lead only). Resets waves + scores."""
    _arena.update({
        "open": True,
        "ends_at": _now() + body.duration_seconds,
        "opened_by": admin.username,
        "waves": [],
        "scores": {},
    })
    return _state(admin)


@router.post("/close")
async def close_window(admin: Annotated[User, Depends(require_admin)]) -> dict[str, Any]:
    _close()
    return _state(admin)


@router.post("/fire")
async def fire(
    body: FireIn,
    user: Annotated[User, Depends(current_user)],
) -> dict[str, Any]:
    if not _is_open():
        raise HTTPException(status_code=409, detail="no PvP window is open right now")
    meta = _BY_ID.get(body.scenario)
    if meta is None:
        raise HTTPException(status_code=400, detail="scenario not available in the arena")
    if len(_arena["waves"]) >= MAX_WAVES:
        raise HTTPException(status_code=429, detail="arena wave limit reached")
    wave = {
        "id": uuid.uuid4().hex[:8],
        "scenario": meta["id"],
        "label": meta["label"],
        "expected_ttps": [t.upper() for t in meta.get("expected_ttps", [])],
        "fired_by": user.username,
        "fired_at": _now(),
        "resolved": False,
        "blocked_by": None,
    }
    _arena["waves"].append(wave)
    # Fire the real runner too (best-effort) so it shows on the live dashboard.
    target = meta["default_target"]
    try:
        asyncio.create_task(_guarded(_dispatch_scenario(
            AttackIn(scenario=meta["id"], target=target, intensity="burst"), target, meta)))
    except Exception:       # noqa: BLE001
        pass
    return _state(user)


async def _guarded(coro) -> None:        # noqa: ANN001
    try:
        await coro
    except Exception:       # noqa: BLE001
        pass


@router.post("/label")
async def label(
    body: LabelIn,
    db: Annotated[AsyncSession, Depends(get_db)],
    user: Annotated[User, Depends(current_user)],
) -> dict[str, Any]:
    if not _is_open():
        raise HTTPException(status_code=409, detail="no PvP window is open right now")
    guess = body.technique_id.strip().upper()
    wave = next((w for w in _arena["waves"] if w["id"] == body.wave_id), None)
    if wave is None:
        raise HTTPException(status_code=404, detail="wave not found")
    if wave["resolved"]:
        return {"correct": False, "already_resolved": True, **_state(user)}
    if user.username == wave["fired_by"]:
        raise HTTPException(status_code=403, detail="you can't label your own wave")
    correct = guess in wave["expected_ttps"]
    if not correct:
        return {"correct": False, **_state(user)}
    # First correct label wins — resolve synchronously (no await) to avoid races.
    wave["resolved"] = True
    wave["blocked_by"] = user.username
    _arena["scores"][user.username] = _arena["scores"].get(user.username, 0) + WAVE_POINTS
    # Award XP for the correct catch.
    await _award(db, user.id, "correct_label", None)
    await db.commit()
    return {"correct": True, **_state(user)}
