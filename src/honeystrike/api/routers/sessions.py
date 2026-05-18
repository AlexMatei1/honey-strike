"""Sessions API — list, detail, events.

Mirrors docs/02_API_Contracts.md `GET /api/sessions*`.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from pathlib import Path
from typing import Annotated

import redis.asyncio as aioredis
from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import FileResponse
from sqlalchemy import and_, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from honeystrike.api.auth import current_user, get_db
from honeystrike.api.schemas import (
    AlertSummary,
    EventPayload,
    EventPreview,
    EventsPage,
    FingerprintPayload,
    ReportJobOut,
    SessionDetail,
    SessionListItem,
    SessionsPage,
    ToolSignaturePayload,
    TTPMatchPayload,
)
from honeystrike.config import get_settings
from honeystrike.core.models import Alert, Event, Fingerprint, Report, Session, TTPMatch, User
from honeystrike.workers.reports.worker import publish_report_job

router = APIRouter(prefix="/api/sessions", tags=["sessions"])

_VALID_SERVICES = {"ssh", "http", "ftp", "rdp"}
_EVENT_PREVIEW_LIMIT = 20


def _src_ip_str(value) -> str:
    """asyncpg returns inet as IPv4Address/IPv6Address. Stringify defensively."""
    return str(value) if value is not None else ""


@router.get("", response_model=SessionsPage)
async def list_sessions(
    db: Annotated[AsyncSession, Depends(get_db)],
    _user: Annotated[User, Depends(current_user)],
    page: int = Query(1, ge=1),
    limit: int = Query(50, ge=1, le=200),
    service: str | None = None,
    min_score: int | None = Query(None, ge=0, le=100),
    from_ts: datetime | None = None,
    to_ts: datetime | None = None,
) -> SessionsPage:
    if service and service not in _VALID_SERVICES:
        raise HTTPException(status_code=400, detail="invalid service filter")
    conditions = []
    if service:
        conditions.append(Session.service == service)
    if min_score is not None:
        conditions.append(Session.threat_score >= min_score)
    if from_ts:
        conditions.append(Session.started_at >= from_ts)
    if to_ts:
        conditions.append(Session.started_at <= to_ts)

    where = and_(*conditions) if conditions else None
    total_q = select(func.count(Session.id))
    if where is not None:
        total_q = total_q.where(where)
    total = int((await db.execute(total_q)).scalar_one())

    # Per-session TTP counts in one round-trip — left join + group_by.
    base_q = (
        select(Session, func.count(TTPMatch.id).label("ttp_count"))
        .outerjoin(TTPMatch, TTPMatch.session_id == Session.id)
        .group_by(Session.id)
        .order_by(Session.started_at.desc())
        .offset((page - 1) * limit)
        .limit(limit)
    )
    if where is not None:
        base_q = base_q.where(where)

    rows = (await db.execute(base_q)).all()

    items: list[SessionListItem] = []
    for row in rows:
        sess: Session = row[0]
        items.append(
            SessionListItem(
                id=sess.id,
                src_ip=_src_ip_str(sess.src_ip),
                service=sess.service,
                state=sess.state,
                threat_score=sess.threat_score,
                severity=sess.severity,
                country_iso=None,        # populated in detail; list stays cheap
                started_at=sess.started_at,
                ended_at=sess.ended_at,
                duration_ms=sess.duration_ms,
                ttp_count=int(row[1]),
            )
        )
    return SessionsPage(total=total, page=page, limit=limit, items=items)


@router.get("/{session_id}", response_model=SessionDetail)
async def get_session(
    session_id: uuid.UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    _user: Annotated[User, Depends(current_user)],
) -> SessionDetail:
    sess = (
        (await db.execute(select(Session).where(Session.id == session_id)))
        .scalars()
        .first()
    )
    if sess is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="session not found")

    fp = (
        (await db.execute(select(Fingerprint).where(Fingerprint.session_id == session_id)))
        .scalars()
        .first()
    )
    ttps = (
        (
            await db.execute(
                select(TTPMatch)
                .where(TTPMatch.session_id == session_id)
                .order_by(TTPMatch.confidence.desc())
            )
        )
        .scalars()
        .all()
    )
    event_total = int(
        (
            await db.execute(
                select(func.count(Event.id)).where(Event.session_id == session_id)
            )
        ).scalar_one()
    )
    preview_rows = (
        (
            await db.execute(
                select(Event)
                .where(Event.session_id == session_id)
                .order_by(Event.ts.asc())
                .limit(_EVENT_PREVIEW_LIMIT)
            )
        )
        .scalars()
        .all()
    )
    alert_rows = (
        (
            await db.execute(
                select(Alert)
                .where(Alert.session_id == session_id)
                .order_by(Alert.dispatched_at.desc())
            )
        )
        .scalars()
        .all()
    )

    fingerprint_payload = None
    if fp is not None:
        fingerprint_payload = FingerprintPayload(
            country_iso=fp.country_iso,
            country_name=fp.country_name,
            city=fp.city,
            lat=fp.lat,
            lon=fp.lon,
            asn=fp.asn,
            org=fp.org,
            abuse_score=fp.abuse_score,
            tool_signatures=[
                ToolSignaturePayload(name=s.get("name", ""), confidence=float(s.get("confidence", 0)))
                for s in (fp.tool_signatures or [])
            ],
            ja3_hash=fp.ja3_hash,
            timing_pattern=fp.timing_pattern,
            attempt_rate_rpm=float(fp.attempt_rate_rpm) if fp.attempt_rate_rpm is not None else None,
        )

    return SessionDetail(
        id=sess.id,
        src_ip=_src_ip_str(sess.src_ip),
        src_port=sess.src_port,
        service=sess.service,
        state=sess.state,
        threat_score=sess.threat_score,
        severity=sess.severity,
        started_at=sess.started_at,
        ended_at=sess.ended_at,
        duration_ms=sess.duration_ms,
        event_count=sess.event_count,
        fingerprint=fingerprint_payload,
        ttps=[
            TTPMatchPayload(
                technique_id=t.technique_id,
                technique_name=t.technique_name,
                tactic=t.tactic,
                confidence=float(t.confidence),
                matched_at=t.matched_at,
            )
            for t in ttps
        ],
        events=EventPreview(
            total=event_total,
            preview=[
                EventPayload(
                    id=e.id,
                    event_type=e.event_type,
                    service=e.service,
                    timestamp=e.ts,
                    payload=e.payload,
                )
                for e in preview_rows
            ],
        ),
        alerts=[
            AlertSummary(
                channel=a.channel,
                severity=a.severity,
                threat_score=a.threat_score,
                dispatched_at=a.dispatched_at,
            )
            for a in alert_rows
        ],
    )


@router.get("/{session_id}/events", response_model=EventsPage)
async def list_session_events(
    session_id: uuid.UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    _user: Annotated[User, Depends(current_user)],
    event_type: str | None = None,
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
) -> EventsPage:
    sess_exists = (
        (await db.execute(select(Session.id).where(Session.id == session_id)))
        .scalars()
        .first()
    )
    if sess_exists is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="session not found")

    conditions = [Event.session_id == session_id]
    if event_type:
        conditions.append(Event.event_type == event_type)
    where = and_(*conditions)

    total = int(
        (await db.execute(select(func.count(Event.id)).where(where))).scalar_one()
    )
    rows = (
        (
            await db.execute(
                select(Event)
                .where(where)
                .order_by(Event.ts.asc())
                .offset(offset)
                .limit(limit)
            )
        )
        .scalars()
        .all()
    )
    return EventsPage(
        total=total,
        items=[
            EventPayload(
                id=e.id,
                event_type=e.event_type,
                service=e.service,
                timestamp=e.ts,
                payload=e.payload,
            )
            for e in rows
        ],
    )


# ---------------------------------------------------------------------------
# Reports
# ---------------------------------------------------------------------------

@router.post("/{session_id}/report", response_model=ReportJobOut, status_code=202)
async def trigger_report(
    session_id: uuid.UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    _user: Annotated[User, Depends(current_user)],
    format: str = Query("pdf", pattern="^(pdf|html)$"),
) -> ReportJobOut:
    """Queue an asynchronous report-generation job for `session_id`.

    The worker picks it up from `honeystrike:report_jobs` within a poll tick.
    `report_id` returned here is a synthetic placeholder; the persisted
    `reports` row's id is queryable once the worker completes (poll via
    `GET /api/sessions/{id}/report?format=...`).
    """
    sess_exists = (
        (await db.execute(select(Session.id).where(Session.id == session_id)))
        .scalars()
        .first()
    )
    if sess_exists is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="session not found"
        )

    settings = get_settings()
    client = aioredis.from_url(settings.redis_url)
    try:
        await publish_report_job(client, session_id=session_id, fmt=format)
    finally:
        await client.aclose()
    # Synthetic id — the real persisted row's id appears when the worker
    # finishes. The client just needs something to poll on, not a guarantee.
    return ReportJobOut(report_id=uuid.uuid4(), status="queued", estimated_seconds=5)


@router.get("/{session_id}/report")
async def download_report(
    session_id: uuid.UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    _user: Annotated[User, Depends(current_user)],
    format: str = Query("pdf", pattern="^(pdf|html)$"),
):
    """Stream the generated report file. 404 if not yet generated or expired."""
    row = (
        (
            await db.execute(
                select(Report)
                .where(Report.session_id == session_id)
                .where(Report.format == format)
                .order_by(Report.generated_at.desc())
                .limit(1)
            )
        )
        .scalars()
        .first()
    )
    if row is None or not row.file_path:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="report not yet generated for this session",
        )
    path = Path(row.file_path)
    if not path.is_file():
        # Row stale (file purged by retention sweep); flag 410 so caller can re-queue.
        raise HTTPException(
            status_code=status.HTTP_410_GONE,
            detail="report file no longer on disk",
        )
    media = "application/pdf" if format == "pdf" else "text/html"
    return FileResponse(path, media_type=media, filename=path.name)
