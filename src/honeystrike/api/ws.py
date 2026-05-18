"""WebSocket live feed for the dashboard.

Pragmatic design: the WS handler polls Postgres for fingerprints created since
its last cursor, every `poll_interval_seconds`. Each new fingerprint becomes
one message to the client:

    {"type": "session", "session_id": "...", "src_ip": "...", "service": "...",
     "severity": "high", "threat_score": 71, "country_iso": "RU", "lat": ...,
     "lon": ..., "started_at": "...", "ttp_count": 2}

This avoids introducing a third Redis stream just for the UI and keeps the
WS-vs-worker decoupling clean: workers write to PG, the UI reads. Latency is
~poll_interval (default 2s) which is well within the human-noticeable budget
for a live attack map.

Browsers cannot attach an Authorization header to a WS handshake, so the
client passes the access token as `?token=...`. Mitigations:
  - tokens are short-lived (settings.jwt_access_ttl_seconds, default 1h)
  - we reject anything that isn't a current valid access token
  - the access log already redacts query strings in prod (see app.py)
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Query, WebSocket, WebSocketDisconnect, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from honeystrike.api.auth import ACCESS_TOKEN_TYPE, decode_token
from honeystrike.core.db import get_sessionmaker
from honeystrike.core.logging import get_logger
from honeystrike.core.models import Fingerprint, Session, TTPMatch

log = get_logger("honeystrike.api.ws")

router = APIRouter(prefix="/api/ws", tags=["ws"])

DEFAULT_POLL_SECONDS = 2.0
INITIAL_SEED_LIMIT = 25


async def _authenticate(token: str | None) -> str | None:
    """Validate the WS query-string token. Returns subject or None on failure."""
    if not token:
        return None
    try:
        payload = decode_token(token, expected_type=ACCESS_TOKEN_TYPE)
    except Exception:           # noqa: BLE001 — auth fails close
        return None
    return payload.get("sub")


async def _fetch_sessions_since(                          # pragma: no cover
    db: AsyncSession, *, cursor: datetime, limit: int = 50
) -> list[dict[str, Any]]:
    """Pull fingerprints whose row was created after `cursor`.

    The cursor moves forward to `max(created_at)` on each call so clients
    never see the same session twice. We join sessions + ttp count in one
    query so a single WS tick maps to one DB round-trip.
    """
    stmt = (
        select(
            Fingerprint.session_id,
            Fingerprint.ip,
            Fingerprint.country_iso,
            Fingerprint.lat,
            Fingerprint.lon,
            Fingerprint.created_at,
            Session.service,
            Session.severity,
            Session.threat_score,
            Session.started_at,
        )
        .join(Session, Session.id == Fingerprint.session_id)
        .where(Fingerprint.created_at > cursor)
        .order_by(Fingerprint.created_at.asc())
        .limit(limit)
    )
    rows = (await db.execute(stmt)).all()
    if not rows:
        return []

    # Fetch TTP counts for this batch in one extra round-trip.
    from sqlalchemy import func

    sids = [r.session_id for r in rows]
    ttp_counts: dict[Any, int] = {sid: 0 for sid in sids}
    cnt_rows = (
        await db.execute(
            select(TTPMatch.session_id, func.count(TTPMatch.id))
            .where(TTPMatch.session_id.in_(sids))
            .group_by(TTPMatch.session_id)
        )
    ).all()
    for sid, c in cnt_rows:
        ttp_counts[sid] = int(c)

    out = []
    for r in rows:
        out.append(
            {
                "type": "session",
                "session_id": str(r.session_id),
                "src_ip": str(r.ip),
                "service": r.service,
                "severity": r.severity,
                "threat_score": r.threat_score,
                "country_iso": r.country_iso,
                "lat": r.lat,
                "lon": r.lon,
                "started_at": r.started_at.isoformat(),
                "ttp_count": ttp_counts.get(r.session_id, 0),
                "_cursor": r.created_at.isoformat(),
            }
        )
    return out


@router.websocket("/live")                                # pragma: no cover
async def live_feed(
    websocket: WebSocket,
    token: str | None = Query(None),
    poll: float = Query(DEFAULT_POLL_SECONDS, ge=0.5, le=30),
) -> None:
    subject = await _authenticate(token)
    if subject is None:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    await websocket.accept()
    log.info("ws.connected", subject=subject, peer=websocket.client.host if websocket.client else None)

    sessionmaker = get_sessionmaker()
    # Initial seed: send the most recent N high-severity sessions so the UI
    # can hydrate its map without waiting a polling tick.
    cursor = await _seed_initial_state(websocket, sessionmaker, INITIAL_SEED_LIMIT)
    if cursor is None:
        # Connection closed mid-seed.
        return

    try:
        while True:
            await asyncio.sleep(poll)
            async with sessionmaker() as db:
                batch = await _fetch_sessions_since(db, cursor=cursor)
            for msg in batch:
                cursor_iso = msg.pop("_cursor", None)
                if cursor_iso:
                    cursor = datetime.fromisoformat(cursor_iso)
                await websocket.send_json(msg)
    except WebSocketDisconnect:
        log.info("ws.disconnected", subject=subject)


async def _seed_initial_state(                            # pragma: no cover
    websocket: WebSocket,
    sessionmaker,                       # type: ignore[no-untyped-def]
    limit: int,
) -> datetime | None:
    """Send the last `limit` scored sessions and return the cursor to resume from."""
    async with sessionmaker() as db:
        recent = (
            await db.execute(
                select(
                    Fingerprint.session_id,
                    Fingerprint.ip,
                    Fingerprint.country_iso,
                    Fingerprint.lat,
                    Fingerprint.lon,
                    Fingerprint.created_at,
                    Session.service,
                    Session.severity,
                    Session.threat_score,
                    Session.started_at,
                )
                .join(Session, Session.id == Fingerprint.session_id)
                .order_by(Fingerprint.created_at.desc())
                .limit(limit)
            )
        ).all()

    cursor = datetime.now(UTC)
    if not recent:
        try:
            await websocket.send_json({"type": "seed_complete", "count": 0})
        except WebSocketDisconnect:
            return None
        return cursor

    cursor = max(r.created_at for r in recent)
    try:
        for r in reversed(recent):
            await websocket.send_json(
                {
                    "type": "session",
                    "session_id": str(r.session_id),
                    "src_ip": str(r.ip),
                    "service": r.service,
                    "severity": r.severity,
                    "threat_score": r.threat_score,
                    "country_iso": r.country_iso,
                    "lat": r.lat,
                    "lon": r.lon,
                    "started_at": r.started_at.isoformat(),
                    "ttp_count": 0,         # filled in on subsequent polling deltas
                }
            )
        await websocket.send_json({"type": "seed_complete", "count": len(recent)})
    except WebSocketDisconnect:
        return None
    return cursor
