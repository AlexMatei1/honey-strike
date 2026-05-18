"""ReportWorker — generates per-session PDF / HTML threat-intel reports.

Architecture:
  - Stream:           `honeystrike:report_jobs`
  - Consumer group:   `reports`

Producers (API endpoint, FingerprintWorker auto-trigger) push a tiny envelope
onto the stream:

    { "session_id": "...", "format": "pdf" }     # or "html"

The worker pulls the session + fingerprint + TTPs + a bounded event preview
+ dispatched alerts from Postgres, runs the renderer, writes the file under
`settings.reports_dir`, and inserts a `reports` row pointing at it. The
expiry timestamp is calculated against `settings.reports_retention_days`.

Idempotency: re-running the same `(session_id, format)` overwrites the file
and updates the existing `reports` row (delete-then-insert).
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import redis.asyncio as aioredis
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from honeystrike.core.logging import get_logger
from honeystrike.core.models import (
    Alert,
    Event,
    Fingerprint,
    Report,
    Session,
    TTPMatch,
)
from honeystrike.workers.reports.renderer import (
    ReportContext,
    render_html,
    render_pdf,
    safe_filename,
)

log = get_logger(__name__)

CONSUMER_GROUP = "reports"
REPORT_STREAM = "honeystrike:report_jobs"
EVENT_PREVIEW_LIMIT = 30
_VALID_FORMATS = {"pdf", "html"}


class ReportWorker:
    """Single-process worker. One instance per container."""

    def __init__(
        self,
        *,
        redis_client: aioredis.Redis,
        stream: str,
        consumer_name: str,
        db_session_factory: Any,
        reports_dir: Path,
        retention_days: int,
        read_block_ms: int = 5_000,
    ) -> None:
        self._redis = redis_client
        self._stream = stream
        self._consumer_name = consumer_name
        self._db_factory = db_session_factory
        self._reports_dir = Path(reports_dir)
        self._retention_days = retention_days
        self._read_block_ms = read_block_ms
        self._stop = asyncio.Event()

    async def setup(self) -> None:
        try:
            await self._redis.xgroup_create(
                self._stream, CONSUMER_GROUP, id="0", mkstream=True
            )
            log.info("report.consumer_group_created", group=CONSUMER_GROUP)
        except aioredis.ResponseError as exc:
            if "BUSYGROUP" not in str(exc):
                raise
        self._reports_dir.mkdir(parents=True, exist_ok=True)

    async def stop(self) -> None:
        self._stop.set()

    async def run(self) -> None:
        await self.setup()
        log.info(
            "report.worker_started",
            stream=self._stream,
            consumer=self._consumer_name,
            reports_dir=str(self._reports_dir),
        )
        while not self._stop.is_set():
            try:
                entries = await self._redis.xreadgroup(
                    groupname=CONSUMER_GROUP,
                    consumername=self._consumer_name,
                    streams={self._stream: ">"},
                    count=50,
                    block=self._read_block_ms,
                )
            except aioredis.ConnectionError as exc:
                log.warning("report.redis_disconnected", error=str(exc))
                await asyncio.sleep(2)
                continue

            for _stream_name, items in entries or []:
                for entry_id, fields in items:
                    await self._process_entry(entry_id, fields)

    async def _process_entry(self, entry_id: str, fields: dict[str, str]) -> None:
        try:
            session_id = uuid.UUID(fields["session_id"])
            fmt = fields.get("format", "pdf")
        except (KeyError, ValueError) as exc:
            log.warning("report.bad_envelope", entry_id=entry_id, error=str(exc))
            await self._ack(entry_id)
            return

        if fmt not in _VALID_FORMATS:
            log.warning("report.unsupported_format", entry_id=entry_id, format=fmt)
            await self._ack(entry_id)
            return

        try:
            await self._generate(session_id, fmt)
        except Exception:           # noqa: BLE001
            log.exception("report.generate_failed", session_id=str(session_id), format=fmt)
            # Don't ACK on failure — Redis re-delivers, we retry once on
            # restart. The same envelope blocking forever is preferable to
            # silently dropping a report that an operator triggered.
            return

        await self._ack(entry_id)

    async def _ack(self, entry_id: str) -> None:
        try:
            await self._redis.xack(self._stream, CONSUMER_GROUP, entry_id)
        except aioredis.RedisError as exc:
            log.warning("report.xack_failed", error=str(exc))

    async def _generate(self, session_id: uuid.UUID, fmt: str) -> None:
        async with self._db_factory() as db:           # type: AsyncSession
            ctx = await _build_report_context(db, session_id)
        if ctx is None:
            log.warning("report.session_not_found", session_id=str(session_id))
            return

        if fmt == "pdf":
            payload = render_pdf(ctx)
            mode = "wb"
        else:
            payload = render_html(ctx).encode("utf-8")
            mode = "wb"

        filename = safe_filename(session_id, fmt)
        path = self._reports_dir / filename
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, mode) as fh:
            fh.write(payload)
        size = len(payload)

        async with self._db_factory() as db:           # type: AsyncSession
            await _upsert_report_row(
                db,
                session_id=session_id,
                fmt=fmt,
                file_path=str(path),
                size_bytes=size,
                threat_score=ctx.session["threat_score"],
                retention_days=self._retention_days,
            )

        log.info(
            "report.generated",
            session_id=str(session_id),
            format=fmt,
            file=str(path),
            size_bytes=size,
        )


# ---------------------------------------------------------------------------
# Helpers — module-level so producers can import publish_report_job.
# ---------------------------------------------------------------------------

async def publish_report_job(
    redis_client: aioredis.Redis,
    *,
    session_id: str | uuid.UUID,
    fmt: str = "pdf",
    stream: str = REPORT_STREAM,
    maxlen: int = 10_000,
) -> None:
    """Push one report-job envelope onto the stream."""
    if fmt not in _VALID_FORMATS:
        raise ValueError(f"unsupported report format: {fmt!r}")
    await redis_client.xadd(
        stream,
        {"session_id": str(session_id), "format": fmt},
        maxlen=maxlen,
        approximate=True,
    )


async def _build_report_context(
    db: AsyncSession, session_id: uuid.UUID
) -> ReportContext | None:
    sess = (
        (await db.execute(select(Session).where(Session.id == session_id)))
        .scalars()
        .first()
    )
    if sess is None:
        return None
    fp = (
        (
            await db.execute(
                select(Fingerprint).where(Fingerprint.session_id == session_id)
            )
        )
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
    events = (
        (
            await db.execute(
                select(Event)
                .where(Event.session_id == session_id)
                .order_by(Event.ts.asc())
                .limit(EVENT_PREVIEW_LIMIT)
            )
        )
        .scalars()
        .all()
    )
    alerts = (
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

    fingerprint_payload: dict[str, Any] | None = None
    if fp is not None:
        fingerprint_payload = {
            "country_iso": fp.country_iso,
            "country_name": fp.country_name,
            "city": fp.city,
            "asn": fp.asn,
            "org": fp.org,
            "abuse_score": fp.abuse_score,
            "abuse_reports": fp.abuse_reports,
            "tool_signatures": [
                {"name": s.get("name", ""), "confidence": float(s.get("confidence", 0))}
                for s in (fp.tool_signatures or [])
            ],
            "ja3_hash": fp.ja3_hash,
            "timing_pattern": fp.timing_pattern,
            "attempt_rate_rpm": float(fp.attempt_rate_rpm)
            if fp.attempt_rate_rpm is not None
            else None,
        }

    return ReportContext(
        session={
            "id": str(sess.id),
            "src_ip": str(sess.src_ip),
            "service": sess.service,
            "state": sess.state,
            "threat_score": sess.threat_score,
            "severity": sess.severity,
            "started_at": sess.started_at.isoformat(timespec="seconds"),
            "ended_at": sess.ended_at.isoformat(timespec="seconds")
            if sess.ended_at
            else None,
            "duration_ms": sess.duration_ms,
            "event_count": sess.event_count,
        },
        fingerprint=fingerprint_payload,
        ttps=[
            {
                "technique_id": t.technique_id,
                "technique_name": t.technique_name,
                "tactic": t.tactic,
                "confidence": float(t.confidence),
            }
            for t in ttps
        ],
        events=[
            {
                "timestamp": e.ts.isoformat(timespec="seconds"),
                "event_type": e.event_type,
                "payload_repr": json.dumps(e.payload, ensure_ascii=False, indent=None)[:500],
            }
            for e in events
        ],
        alerts=[
            {
                "channel": a.channel,
                "severity": a.severity,
                "dispatched_at": a.dispatched_at.isoformat(timespec="seconds"),
            }
            for a in alerts
        ],
        generated_at=datetime.now(UTC).isoformat(timespec="seconds"),
    )


async def _upsert_report_row(
    db: AsyncSession,
    *,
    session_id: uuid.UUID,
    fmt: str,
    file_path: str,
    size_bytes: int,
    threat_score: int,
    retention_days: int,
) -> None:
    """Replace any existing row for `(session_id, format)` with the fresh one.

    Composite uniqueness isn't enforced at the schema level, so we explicitly
    delete-then-insert to keep "latest report wins" semantics.
    """
    await db.execute(
        Report.__table__.delete()
        .where(Report.session_id == session_id)
        .where(Report.format == fmt)
    )
    expires_at = datetime.now(UTC) + timedelta(days=retention_days)
    await db.execute(
        Report.__table__.insert().values(
            session_id=session_id,
            format=fmt,
            file_path=file_path,
            file_size_bytes=size_bytes,
            threat_score_snapshot=threat_score,
            expires_at=expires_at,
        )
    )
    await db.commit()


# ---------------------------------------------------------------------------
# Entrypoint — `python -m honeystrike.workers.reports.worker`
# ---------------------------------------------------------------------------

async def _main() -> None:
    from honeystrike.config import get_settings
    from honeystrike.core.db import dispose_engine, get_sessionmaker
    from honeystrike.core.event_bus import EventBus
    from honeystrike.core.logging import configure_logging

    settings = get_settings()
    configure_logging(level=settings.log_level, json=settings.app_env == "production")
    bus = await EventBus(
        settings.redis_url,
        stream=settings.redis_stream,
        maxlen=settings.redis_stream_maxlen,
    ).connect()

    sessionmaker = get_sessionmaker()
    consumer_name = os.getenv("WORKER_CONSUMER_NAME", f"report-{os.getpid()}")
    worker = ReportWorker(
        redis_client=bus.client,
        stream=REPORT_STREAM,
        consumer_name=consumer_name,
        db_session_factory=sessionmaker,
        reports_dir=Path(settings.reports_dir),
        retention_days=settings.reports_retention_days,
    )

    try:
        await worker.run()
    finally:
        with contextlib.suppress(Exception):
            await bus.close()
        await dispose_engine()


if __name__ == "__main__":
    asyncio.run(_main())
