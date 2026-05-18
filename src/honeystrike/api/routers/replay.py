"""`/api/replay/{session_id}` — chronological event playback.

Returns the session's events in order with a `t_ms` field (milliseconds
since session start). The browser-side player uses these offsets to
replay the attack at variable speed, mimicking the real cadence.

Also returns a derived "score timeline": how the running threat score
would have looked after each event, so the UI can animate the score bar
climbing as the events play out.
"""

from __future__ import annotations

import uuid
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from honeystrike.api.auth import current_user, get_db
from honeystrike.core.models import Event, Fingerprint, Session, TTPMatch, User

router = APIRouter(prefix="/api/replay", tags=["replay"])


class ReplayEvent(BaseModel):
    id: uuid.UUID
    event_type: str
    t_ms: int                          # offset from session start, milliseconds
    payload: dict[str, Any]


class ScoreFrame(BaseModel):
    t_ms: int
    label: str
    delta: int                         # contribution at this point
    running_score: int                 # cumulative


class ReplayOut(BaseModel):
    session_id: uuid.UUID
    src_ip: str
    service: str
    final_severity: str
    final_score: int
    duration_ms: int
    events: list[ReplayEvent]
    score_timeline: list[ScoreFrame]
    ttps: list[dict[str, Any]]
    tool_signatures: list[dict[str, Any]]


def _src_ip(value: Any) -> str:
    return str(value) if value is not None else ""


def _build_score_timeline(
    events: list[Event],
    *,
    ttps: list[TTPMatch],
    tools: list[dict[str, Any]],
    final_score: int,
) -> list[ScoreFrame]:
    """Heuristic playback of how the score got to `final_score`.

    Real scoring runs once at session close; this synthesises a per-event
    contribution so the UI can animate the bar climbing as the player
    watches. The shape matches `threat_scoring.score_session`:

      - each auth attempt contributes ~5 points up to a cap
      - first CVE / SQLi / scanner hit adds 10 points
      - each TTP that fires contributes its confidence * 50 / N pts
      - everything is clamped to `final_score` at the end so the
        animation lands exactly on the real score
    """
    if not events:
        return []
    started = events[0].ts
    frames: list[ScoreFrame] = []
    running = 0

    # Decompose target into per-event contributions, evenly spread across
    # signal-bearing events.
    signal_events: list[tuple[Event, str, int]] = []
    for ev in events:
        et = ev.event_type
        payload = ev.payload or {}
        if et == "SSH_AUTH_ATTEMPT":
            signal_events.append((ev, "auth attempt", 6))
        elif et == "HTTP_REQUEST":
            if payload.get("cve_signature"):
                signal_events.append((ev, f"CVE {payload['cve_signature']}", 18))
            elif payload.get("sqli_pattern"):
                signal_events.append((ev, "SQLi pattern", 14))
            elif payload.get("path_traversal"):
                signal_events.append((ev, "path traversal", 10))
            elif payload.get("scanner_detected"):
                signal_events.append((ev, f"scanner {payload['scanner_detected']}", 8))
            else:
                signal_events.append((ev, "HTTP probe", 3))
        elif et == "FTP_COMMAND":
            if (payload.get("command") or "").upper() == "PASS":
                signal_events.append((ev, "FTP auth", 5))
        elif et == "RDP_CONNECT":
            signal_events.append((ev, "RDP handshake", 6))
        elif et == "TLS_CLIENT_HELLO":
            signal_events.append((ev, "TLS handshake", 4))
        elif et == "SSH_COMMAND":
            signal_events.append((ev, "post-auth command", 12))

    # Renormalise so the running total ends at `final_score`.
    total = sum(c for _, _, c in signal_events) or 1
    scale = final_score / total if final_score > 0 else 0

    for ev, label, raw in signal_events:
        delta = max(1, int(round(raw * scale))) if scale else raw
        running = min(final_score or running + delta, running + delta)
        t_ms = int((ev.ts - started).total_seconds() * 1000)
        frames.append(ScoreFrame(t_ms=t_ms, label=label, delta=delta, running_score=running))

    # Final frame: pin to exact target score.
    if frames and frames[-1].running_score != final_score:
        frames[-1] = ScoreFrame(
            t_ms=frames[-1].t_ms, label=frames[-1].label,
            delta=frames[-1].delta + (final_score - frames[-1].running_score),
            running_score=final_score,
        )
    return frames


@router.get("/{session_id}", response_model=ReplayOut)
async def replay(
    session_id: uuid.UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    _user: Annotated[User, Depends(current_user)],
) -> ReplayOut:
    sess = (
        (await db.execute(select(Session).where(Session.id == session_id)))
        .scalars().first()
    )
    if sess is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail="session not found")

    fp = (
        (await db.execute(select(Fingerprint).where(Fingerprint.session_id == session_id)))
        .scalars().first()
    )
    ttps = (
        (await db.execute(
            select(TTPMatch)
            .where(TTPMatch.session_id == session_id)
            .order_by(TTPMatch.confidence.desc())
        ))
        .scalars().all()
    )
    raw_events = (
        (await db.execute(
            select(Event)
            .where(Event.session_id == session_id)
            .order_by(Event.ts.asc())
        ))
        .scalars().all()
    )

    started = raw_events[0].ts if raw_events else sess.started_at
    events_out = [
        ReplayEvent(
            id=e.id, event_type=e.event_type,
            t_ms=int((e.ts - started).total_seconds() * 1000),
            payload=e.payload,
        )
        for e in raw_events
    ]
    tool_sigs = (fp.tool_signatures if fp else []) or []
    score_timeline = _build_score_timeline(
        raw_events, ttps=ttps, tools=tool_sigs, final_score=sess.threat_score,
    )

    return ReplayOut(
        session_id=sess.id,
        src_ip=_src_ip(sess.src_ip),
        service=sess.service,
        final_severity=sess.severity,
        final_score=sess.threat_score,
        duration_ms=sess.duration_ms or 0,
        events=events_out,
        score_timeline=score_timeline,
        ttps=[
            {
                "technique_id": t.technique_id,
                "technique_name": t.technique_name,
                "tactic": t.tactic,
                "confidence": float(t.confidence),
            }
            for t in ttps
        ],
        tool_signatures=tool_sigs,
    )
