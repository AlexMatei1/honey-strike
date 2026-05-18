"""Analytics REST API — overview, top TTPs, geo breakdown, timeline.

All endpoints take a `days` window so the dashboard can hand callers a single
configurable lookback. Numbers are computed at query time rather than from a
materialised summary table — at our session volumes (tens of thousands)
those queries return in well under a second; the materialised cache lives in
Phase 5 if needed.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from honeystrike.api.auth import current_user, get_db
from honeystrike.api.schemas import (
    GeoStat,
    OverviewStats,
    TimelineBucket,
    TTPStat,
)
from honeystrike.core.models import Fingerprint, Session, TTPMatch, User
from honeystrike.workers.intel.ttp_rules import EMBEDDED_TECHNIQUES

router = APIRouter(prefix="/api/stats", tags=["stats"])


def _window_start(days: int) -> datetime:
    return datetime.now(UTC) - timedelta(days=days)


@router.get("/overview", response_model=OverviewStats)
async def overview(
    db: Annotated[AsyncSession, Depends(get_db)],
    _user: Annotated[User, Depends(current_user)],
    days: int = Query(7, ge=1, le=365),
) -> OverviewStats:
    since = _window_start(days)
    base = select(Session).where(Session.started_at >= since)

    total_sessions = int(
        (await db.execute(select(func.count()).select_from(base.subquery()))).scalar_one()
    )
    unique_ips = int(
        (
            await db.execute(
                select(func.count(func.distinct(Session.src_ip)))
                .where(Session.started_at >= since)
            )
        ).scalar_one()
    )

    svc_rows = (
        await db.execute(
            select(Session.service, func.count(Session.id))
            .where(Session.started_at >= since)
            .group_by(Session.service)
        )
    ).all()
    sessions_by_service = {svc: int(cnt) for svc, cnt in svc_rows}

    sev_rows = (
        await db.execute(
            select(Session.severity, func.count(Session.id))
            .where(Session.started_at >= since)
            .group_by(Session.severity)
        )
    ).all()
    severity_breakdown = {sev: int(cnt) for sev, cnt in sev_rows}

    geo_rows = (
        await db.execute(
            select(Fingerprint.country_iso, func.count(Fingerprint.id))
            .join(Session, Session.id == Fingerprint.session_id)
            .where(Session.started_at >= since)
            .where(Fingerprint.country_iso.isnot(None))
            .group_by(Fingerprint.country_iso)
            .order_by(func.count(Fingerprint.id).desc())
            .limit(10)
        )
    ).all()
    top_countries = [{"iso": iso, "count": int(cnt)} for iso, cnt in geo_rows]

    ttp_rows = (
        await db.execute(
            select(TTPMatch.technique_id, func.count(TTPMatch.id))
            .join(Session, Session.id == TTPMatch.session_id)
            .where(Session.started_at >= since)
            .group_by(TTPMatch.technique_id)
            .order_by(func.count(TTPMatch.id).desc())
            .limit(10)
        )
    ).all()
    top_ttps = [{"technique_id": tid, "count": int(cnt)} for tid, cnt in ttp_rows]

    avg_row = (
        await db.execute(
            select(func.coalesce(func.avg(Session.threat_score), 0.0))
            .where(Session.started_at >= since)
        )
    ).scalar_one()

    return OverviewStats(
        period_days=days,
        total_sessions=total_sessions,
        unique_ips=unique_ips,
        sessions_by_service=sessions_by_service,
        severity_breakdown=severity_breakdown,
        top_countries=top_countries,
        top_ttps=top_ttps,
        avg_threat_score=round(float(avg_row), 2),
    )


@router.get("/ttps", response_model=list[TTPStat])
async def ttps(
    db: Annotated[AsyncSession, Depends(get_db)],
    _user: Annotated[User, Depends(current_user)],
    days: int = Query(30, ge=1, le=365),
    limit: int = Query(20, ge=1, le=100),
) -> list[TTPStat]:
    since = _window_start(days)
    rows = (
        await db.execute(
            select(
                TTPMatch.technique_id,
                TTPMatch.technique_name,
                TTPMatch.tactic,
                func.count(TTPMatch.id).label("c"),
            )
            .join(Session, Session.id == TTPMatch.session_id)
            .where(Session.started_at >= since)
            .group_by(TTPMatch.technique_id, TTPMatch.technique_name, TTPMatch.tactic)
            .order_by(func.count(TTPMatch.id).desc())
            .limit(limit)
        )
    ).all()
    grand_total = sum(int(r.c) for r in rows) or 1
    out: list[TTPStat] = []
    for r in rows:
        info = EMBEDDED_TECHNIQUES.get(r.technique_id)
        out.append(
            TTPStat(
                technique_id=r.technique_id,
                name=r.technique_name or (info.name if info else r.technique_id),
                tactic=r.tactic or (info.tactic if info else "Unknown"),
                count=int(r.c),
                pct=round(int(r.c) * 100 / grand_total, 1),
            )
        )
    return out


@router.get("/geo", response_model=list[GeoStat])
async def geo(
    db: Annotated[AsyncSession, Depends(get_db)],
    _user: Annotated[User, Depends(current_user)],
    days: int = Query(7, ge=1, le=365),
    limit: int = Query(25, ge=1, le=200),
) -> list[GeoStat]:
    since = _window_start(days)
    rows = (
        await db.execute(
            select(
                Fingerprint.country_iso,
                Fingerprint.country_name,
                func.count(Fingerprint.id).label("c"),
            )
            .join(Session, Session.id == Fingerprint.session_id)
            .where(Session.started_at >= since)
            .group_by(Fingerprint.country_iso, Fingerprint.country_name)
            .order_by(func.count(Fingerprint.id).desc())
            .limit(limit)
        )
    ).all()
    grand_total = sum(int(r.c) for r in rows) or 1
    return [
        GeoStat(
            country_iso=r.country_iso,
            country_name=r.country_name,
            count=int(r.c),
            pct=round(int(r.c) * 100 / grand_total, 1),
        )
        for r in rows
    ]


@router.get("/timeline", response_model=list[TimelineBucket])
async def timeline(
    db: Annotated[AsyncSession, Depends(get_db)],
    _user: Annotated[User, Depends(current_user)],
    days: int = Query(7, ge=1, le=90),
    bucket: str = Query("hour", pattern="^(hour|day)$"),
) -> list[TimelineBucket]:
    since = _window_start(days)
    trunc = func.date_trunc(bucket, Session.started_at)
    rows = (
        await db.execute(
            select(
                trunc.label("bucket"),
                func.count(Session.id).label("c"),
                func.coalesce(func.avg(Session.threat_score), 0.0).label("avg_score"),
            )
            .where(Session.started_at >= since)
            .group_by(trunc)
            .order_by(trunc.asc())
        )
    ).all()
    return [
        TimelineBucket(
            bucket=r.bucket,
            count=int(r.c),
            avg_score=round(float(r.avg_score), 2),
        )
        for r in rows
    ]
