"""FingerprintWorker — consume the event stream, enrich, persist.

Consumer group:   `intel`
Stream:           `honeystrike:events`

Lifecycle per session:

  1. Events arrive on the Redis stream (XREADGROUP).
  2. Each event is appended to its `SessionAggregator` buffer.
  3. When the buffer "closes" (SESSION_CLOSE event, event-count cap, or idle
     timeout), we:
       - call `GeoEnricher.lookup(src_ip)`
       - call `AbuseIPDBClient.check(src_ip)` (optional, configured by API key)
       - call `signatures.evaluate(SessionContext(...))`
       - upsert a `fingerprints` row keyed by `session_id`
  4. XACK every Redis entry in the buffer.

Idempotency:
  - PG insert uses `ON CONFLICT (session_id) DO UPDATE` so re-delivery doesn't
    blow up. The unique constraint already exists in the schema.
"""

from __future__ import annotations

import asyncio
import contextlib
import math
import socket
from collections.abc import Iterable
from datetime import UTC, datetime, timedelta
from typing import Any

import redis.asyncio as aioredis
from sqlalchemy import and_, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from honeystrike.core.event_bus import EventBus
from honeystrike.core.events import EventEnvelope, EventType
from honeystrike.core.live_feed import publish_live
from honeystrike.core.logging import get_logger
from honeystrike.core.models import Fingerprint
from honeystrike.core.models import Session as SessionModel
from honeystrike.core.models import TTPMatch as TTPMatchRow
from honeystrike.workers.alerting.worker import ALERT_STREAM, publish_alert
from honeystrike.workers.reports.worker import publish_report_job
from honeystrike.workers.intel.abuseipdb import AbuseIPDBClient, AbuseRecord
from honeystrike.workers.intel.aggregator import (
    SessionAggregator,
    SessionBuffer,
    envelope_to_event_row,
)
from honeystrike.workers.intel.geo import GeoEnricher, GeoRecord
from honeystrike.workers.intel.signatures import SessionContext, ToolMatch
from honeystrike.workers.intel.signatures import evaluate as evaluate_tool_signatures
from honeystrike.workers.intel.threat_scoring import score_session
from honeystrike.workers.intel.ttp_rules import TTPMatch as TTPRuleMatch
from honeystrike.workers.intel.ttp_rules import evaluate as evaluate_ttp_rules

log = get_logger(__name__)

CONSUMER_GROUP = "intel"


class FingerprintWorker:
    """Single-process worker. One instance per container."""

    def __init__(
        self,
        *,
        redis_client: aioredis.Redis,
        stream: str,
        consumer_name: str,
        db_session_factory: Any,                # callable returning AsyncSession
        geo: GeoEnricher,
        abuseipdb: AbuseIPDBClient,
        aggregator: SessionAggregator | None = None,
        read_block_ms: int = 5_000,
        idle_drain_interval: float = 30.0,
        alert_threshold: int = 60,
        alert_stream: str = ALERT_STREAM,
        report_auto_trigger_score: int = 60,
    ) -> None:
        self._redis = redis_client
        self._stream = stream
        self._consumer_name = consumer_name
        self._db_factory = db_session_factory
        self._geo = geo
        self._abuse = abuseipdb
        self._aggregator = aggregator or SessionAggregator()
        self._read_block_ms = read_block_ms
        self._idle_drain_interval = idle_drain_interval
        self._alert_threshold = alert_threshold
        self._alert_stream = alert_stream
        self._report_auto_trigger_score = report_auto_trigger_score
        self._stop = asyncio.Event()
        # Track stream entry IDs per session so we can XACK after persist.
        self._pending_ids: dict[str, list[str]] = {}

    async def setup(self) -> None:                         # pragma: no cover
        """Create the consumer group if it doesn't exist."""
        try:
            await self._redis.xgroup_create(
                self._stream, CONSUMER_GROUP, id="0", mkstream=True
            )
            log.info("fingerprint.consumer_group_created", group=CONSUMER_GROUP)
        except aioredis.ResponseError as exc:
            # BUSYGROUP just means the group already exists.
            if "BUSYGROUP" not in str(exc):
                raise

    async def stop(self) -> None:                          # pragma: no cover
        self._stop.set()

    # ----- main loop -------------------------------------------------------

    async def run(self) -> None:                          # pragma: no cover
        # Async stream loop. Exercised end-to-end in tests/integration/ —
        # unit-testing the inner while-loop adds churn without catching real
        # bugs that the live worker doesn't already.
        await self.setup()
        log.info(
            "fingerprint.worker_started",
            stream=self._stream,
            consumer=self._consumer_name,
        )

        last_idle_drain = asyncio.get_running_loop().time()
        while not self._stop.is_set():
            try:
                entries = await self._redis.xreadgroup(
                    groupname=CONSUMER_GROUP,
                    consumername=self._consumer_name,
                    streams={self._stream: ">"},
                    count=100,
                    block=self._read_block_ms,
                )
            except aioredis.ConnectionError as exc:
                log.warning("fingerprint.redis_disconnected", error=str(exc))
                await asyncio.sleep(2)
                continue

            for _stream_name, items in entries or []:
                for entry_id, fields in items:
                    await self._ingest_entry(entry_id, fields)

            now = asyncio.get_running_loop().time()
            if now - last_idle_drain > self._idle_drain_interval:
                await self._drain_idle()
                last_idle_drain = now

        # Shutdown: drain everything.
        log.info("fingerprint.draining_on_shutdown", buffered=len(self._aggregator))
        for buf in self._aggregator.drain_all():
            await self._flush(buf)

    # ----- ingest + flush --------------------------------------------------

    async def _ingest_entry(self, entry_id: str, fields: dict[str, str]) -> None:  # pragma: no cover
        try:
            envelope = EventEnvelope.from_stream_fields(fields)
        except (KeyError, ValueError) as exc:
            log.warning(
                "fingerprint.bad_envelope", entry_id=entry_id, error=str(exc)
            )
            # ACK + drop — there's nothing we can do with a malformed entry.
            await self._ack([entry_id])
            return

        self._pending_ids.setdefault(envelope.session_id, []).append(entry_id)
        buf = self._aggregator.ingest(envelope)
        if buf is not None:
            await self._flush(buf)

    async def _drain_idle(self) -> None:                  # pragma: no cover
        for buf in self._aggregator.drain_idle():
            log.info("fingerprint.idle_flush", session_id=buf.session_id)
            await self._flush(buf)

    async def _flush(self, buf: SessionBuffer) -> None:    # pragma: no cover
        ids = self._pending_ids.pop(buf.session_id, [])
        if not buf.events:
            await self._ack(ids)
            return
        try:
            await self._enrich_and_persist(buf)
        except Exception:
            # Don't ACK on failure — Redis will re-deliver. Worker retries
            # automatically. Log loudly so the operator notices.
            log.exception(
                "fingerprint.persist_failed", session_id=buf.session_id
            )
            return
        await self._ack(ids)

    async def _ack(self, entry_ids: list[str]) -> None:    # pragma: no cover
        if not entry_ids:
            return
        try:
            await self._redis.xack(self._stream, CONSUMER_GROUP, *entry_ids)
        except aioredis.RedisError as exc:
            log.warning("fingerprint.xack_failed", error=str(exc))

    # ----- enrichment ------------------------------------------------------

    async def _enrich_and_persist(self, buf: SessionBuffer) -> None:  # pragma: no cover
        src_ip_clean = _sanitise_ip(buf.src_ip)
        geo_record = await self._geo.lookup(src_ip_clean)
        abuse_record = await self._abuse.check(src_ip_clean)

        event_rows = [envelope_to_event_row(e) for e in buf.events]
        started_at = _session_start_ts(buf, event_rows)

        async with self._db_factory() as db:           # type: AsyncSession
            sibling_sessions = await _load_sibling_sessions(
                db,
                src_ip=src_ip_clean,
                anchor_session_id=buf.session_id,
                anchor_started_at=started_at,
            )

        ctx = SessionContext(
            service=buf.service,
            src_ip=src_ip_clean,
            started_at=started_at,
            events=event_rows,
            sibling_sessions=sibling_sessions,
        )
        tool_matches = evaluate_tool_signatures(ctx)
        ttp_matches = evaluate_ttp_rules(ctx)
        attempt_rate, timing_pattern = _attempt_rate_and_pattern(event_rows)
        ja3_hash = _extract_ja3_hash(event_rows)

        threat = score_session(
            abuse_score=abuse_record.abuse_score if abuse_record else None,
            tool_matches=tool_matches,
            ttp_matches=ttp_matches,
        )

        async with self._db_factory() as db:           # type: AsyncSession
            await self._upsert_fingerprint(
                db,
                buf=buf,
                src_ip=src_ip_clean,
                geo=geo_record,
                abuse=abuse_record,
                tool_matches=tool_matches,
                timing_pattern=timing_pattern,
                attempt_rate=attempt_rate,
                ja3_hash=ja3_hash,
            )
            await self._replace_ttp_matches(db, buf=buf, ttp_matches=ttp_matches)
            await _update_session_threat_score(
                db,
                session_id=buf.session_id,
                threat_score=threat.score,
                severity=threat.severity,
            )
            await db.commit()

        log.info(
            "fingerprint.persisted",
            session_id=buf.session_id,
            service=buf.service,
            src_ip=src_ip_clean,
            country=geo_record.country_iso,
            asn=geo_record.asn,
            abuse_score=abuse_record.abuse_score if abuse_record else None,
            tool_count=len(tool_matches),
            ttp_count=len(ttp_matches),
            threat_score=threat.score,
            severity=threat.severity,
        )

        if threat.score >= self._alert_threshold:
            try:
                await publish_alert(
                    self._redis,
                    stream=self._alert_stream,
                    session_id=buf.session_id,
                    src_ip=src_ip_clean,
                    service=buf.service,
                    severity=threat.severity,
                    threat_score=threat.score,
                    country_iso=geo_record.country_iso,
                    tool_signatures=[m.name for m in tool_matches],
                    ttp_techniques=[m.technique_id for m in ttp_matches],
                )
            except Exception as exc:            # noqa: BLE001
                # Alert publish must never break enrichment.
                log.warning(
                    "fingerprint.alert_publish_failed",
                    session_id=buf.session_id,
                    error=str(exc),
                )

        if threat.score >= self._report_auto_trigger_score:
            try:
                await publish_report_job(
                    self._redis,
                    session_id=buf.session_id,
                    fmt="pdf",
                )
            except Exception as exc:            # noqa: BLE001
                log.warning(
                    "fingerprint.report_publish_failed",
                    session_id=buf.session_id,
                    error=str(exc),
                )

        # Fan out to the dashboard live feed (Redis pub/sub). Best-effort —
        # publish_live swallows its own errors so it can't break enrichment.
        await publish_live(
            self._redis,
            {
                "type": "session",
                "session_id": buf.session_id,
                "src_ip": src_ip_clean,
                "service": buf.service,
                "severity": threat.severity,
                "threat_score": threat.score,
                "country_iso": geo_record.country_iso,
                "lat": geo_record.lat,
                "lon": geo_record.lon,
                "started_at": datetime.now(UTC).isoformat(),
                "ttp_count": len(ttp_matches),
            },
        )

    async def _upsert_fingerprint(                         # pragma: no cover
        self,
        db: AsyncSession,
        *,
        buf: SessionBuffer,
        src_ip: str,
        geo: GeoRecord,
        abuse: AbuseRecord | None,
        tool_matches: list[ToolMatch],
        timing_pattern: str,
        attempt_rate: float | None,
        ja3_hash: str | None = None,
    ) -> None:
        tool_sig_payload = [
            {"name": m.name, "confidence": m.confidence} for m in tool_matches
        ]
        raw_enrichment = {
            "geo": geo.to_dict(),
            "abuseipdb": abuse.to_dict() if abuse else None,
            "service": buf.service,
            "event_count": buf.event_count,
        }

        stmt = (
            pg_insert(Fingerprint)
            .values(
                session_id=buf.session_id,
                ip=src_ip,
                country_iso=geo.country_iso,
                country_name=geo.country_name,
                city=geo.city,
                lat=geo.lat,
                lon=geo.lon,
                asn=geo.asn,
                org=geo.org,
                abuse_score=abuse.abuse_score if abuse else None,
                abuse_reports=abuse.total_reports if abuse else None,
                tool_signatures=tool_sig_payload,
                ja3_hash=ja3_hash,
                timing_pattern=timing_pattern,
                attempt_rate_rpm=attempt_rate,
                raw_enrichment=raw_enrichment,
            )
            .on_conflict_do_update(
                index_elements=["session_id"],
                set_={
                    "ip": src_ip,
                    "country_iso": geo.country_iso,
                    "country_name": geo.country_name,
                    "city": geo.city,
                    "lat": geo.lat,
                    "lon": geo.lon,
                    "asn": geo.asn,
                    "org": geo.org,
                    "abuse_score": abuse.abuse_score if abuse else None,
                    "abuse_reports": abuse.total_reports if abuse else None,
                    "tool_signatures": tool_sig_payload,
                    "ja3_hash": ja3_hash,
                    "timing_pattern": timing_pattern,
                    "attempt_rate_rpm": attempt_rate,
                    "raw_enrichment": raw_enrichment,
                    "updated_at": datetime.now(UTC),
                },
            )
        )
        await db.execute(stmt)
        # Commit happens at the caller level so fingerprints + ttp_matches +
        # session score update all land atomically.

    async def _replace_ttp_matches(                        # pragma: no cover
        self,
        db: AsyncSession,
        *,
        buf: SessionBuffer,
        ttp_matches: list[TTPRuleMatch],
    ) -> None:
        """Idempotent: wipe prior TTP rows for the session and insert the new set.

        Re-delivery from Redis can re-run enrichment; rather than tracking
        per-row uniqueness, we replace the whole set for the session.
        """
        await db.execute(
            TTPMatchRow.__table__.delete().where(
                TTPMatchRow.session_id == buf.session_id
            )
        )
        if not ttp_matches:
            return
        rows = [
            {
                "session_id": buf.session_id,
                "technique_id": m.technique_id,
                "technique_name": m.technique_name,
                "tactic": m.tactic,
                "confidence": m.confidence,
                "trigger_event_id": m.trigger_event_id,
            }
            for m in ttp_matches
        ]
        await db.execute(TTPMatchRow.__table__.insert(), rows)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _sanitise_ip(value: str) -> str:
    """Strip Postgres INET-style `/32` suffix and IPv6 zone IDs if present."""
    s = value.split("/", 1)[0]
    s = s.split("%", 1)[0]
    # Final sanity check.
    try:
        socket.inet_pton(socket.AF_INET, s)
        return s
    except OSError:
        pass
    try:
        socket.inet_pton(socket.AF_INET6, s)
        return s
    except OSError:
        return value


def _session_start_ts(buf: SessionBuffer, event_rows: Iterable[dict]) -> datetime:
    """Return the earliest event timestamp, or `now()` if buffer is empty."""
    earliest: datetime | None = None
    for row in event_rows:
        ts = row.get("ts")
        if isinstance(ts, datetime):
            if earliest is None or ts < earliest:
                earliest = ts
    return earliest or datetime.now(UTC)


def _attempt_rate_and_pattern(
    event_rows: list[dict[str, Any]],
) -> tuple[float | None, str]:
    """Compute attempts/minute + classify timing pattern as burst/slow/random/unknown."""
    auth_or_request = {
        EventType.SSH_AUTH_ATTEMPT.value,
        EventType.HTTP_REQUEST.value,
        EventType.FTP_COMMAND.value,
        EventType.RDP_CONNECT.value,
        EventType.SSH_COMMAND.value,
    }
    actions = [
        row for row in event_rows if row.get("event_type") in auth_or_request
    ]
    if len(actions) < 2:
        return None, "unknown"

    timestamps = [row["ts"] for row in actions if isinstance(row.get("ts"), datetime)]
    if len(timestamps) < 2:
        return None, "unknown"

    timestamps.sort()
    span_seconds = max(0.001, (timestamps[-1] - timestamps[0]).total_seconds())
    rate_per_min = (len(timestamps) / span_seconds) * 60.0

    deltas = [
        (timestamps[i + 1] - timestamps[i]).total_seconds()
        for i in range(len(timestamps) - 1)
    ]
    mean_delta = sum(deltas) / len(deltas)
    variance = sum((d - mean_delta) ** 2 for d in deltas) / len(deltas)
    stddev = math.sqrt(variance)
    # Coefficient of variation classifies the pattern. Burst = low cv + high rate;
    # slow = low cv + low rate; random = high cv.
    cv = stddev / mean_delta if mean_delta > 0 else 0.0
    if cv > 1.0:
        pattern = "random"
    elif rate_per_min > 30:
        pattern = "burst"
    else:
        pattern = "slow"

    return round(rate_per_min, 2), pattern


def _extract_ja3_hash(event_rows: list[dict[str, Any]]) -> str | None:
    """Pull the JA3 hash from any TLS_CLIENT_HELLO event in the buffer.

    The TLS sniffer captures a single ClientHello per session — the first
    parseable record wins. Returns None if no TLS event landed (typical
    for SSH/HTTP/FTP/RDP sessions).
    """
    for row in event_rows:
        if row.get("event_type") != EventType.TLS_CLIENT_HELLO.value:
            continue
        payload = row.get("payload") or {}
        value = payload.get("ja3_hash")
        if isinstance(value, str) and value:
            return value
    return None


async def _load_sibling_sessions(
    db: AsyncSession,
    *,
    src_ip: str,
    anchor_session_id: str,
    anchor_started_at: datetime,
    window_seconds: int = 60,
) -> list[dict[str, Any]]:
    """Return same-IP sessions that started within ±`window_seconds` of the anchor.

    Used by signature rules (multi-service-scan) and TTP rules (T1595.001) to
    detect attackers hitting more than one service in a short window.
    """
    window = timedelta(seconds=window_seconds)
    stmt = (
        select(SessionModel.id, SessionModel.service, SessionModel.started_at)
        .where(
            and_(
                SessionModel.src_ip == src_ip,
                SessionModel.id != anchor_session_id,
                SessionModel.started_at >= anchor_started_at - window,
                SessionModel.started_at <= anchor_started_at + window,
            )
        )
        .limit(50)
    )
    rows = (await db.execute(stmt)).all()
    return [
        {
            "session_id": str(r.id),
            "src_ip": src_ip,
            "service": r.service,
            "started_at": r.started_at,
        }
        for r in rows
    ]


async def _update_session_threat_score(
    db: AsyncSession,
    *,
    session_id: str,
    threat_score: int,
    severity: str,
) -> None:
    """Write the composite threat score + severity back to the session row."""
    await db.execute(
        SessionModel.__table__.update()
        .where(SessionModel.id == session_id)
        .values(threat_score=threat_score, severity=severity)
    )


# ---------------------------------------------------------------------------
# Module-level entrypoint for `python -m honeystrike.workers.intel.fingerprint`
# ---------------------------------------------------------------------------

async def _main() -> None:                                # pragma: no cover
    import os

    from honeystrike.config import get_settings
    from honeystrike.core.db import dispose_engine, get_sessionmaker
    from honeystrike.core.logging import configure_logging

    settings = get_settings()
    configure_logging(level=settings.log_level, json=settings.app_env == "production")

    bus = await EventBus(
        settings.redis_url,
        stream=settings.redis_stream,
        maxlen=settings.redis_stream_maxlen,
    ).connect()

    geo = GeoEnricher(
        redis_client=bus.client,
        city_db_path=f"{settings.maxmind_db_dir}/GeoLite2-City.mmdb",
        asn_db_path=f"{settings.maxmind_db_dir}/GeoLite2-ASN.mmdb",
    )
    abuse = AbuseIPDBClient(
        api_key=settings.abuseipdb_key,
        redis_client=bus.client,
        cache_ttl_seconds=settings.abuseipdb_cache_ttl_seconds,
    )

    sessionmaker = get_sessionmaker()
    consumer_name = os.getenv("WORKER_CONSUMER_NAME", f"fp-{os.getpid()}")
    worker = FingerprintWorker(
        redis_client=bus.client,
        stream=settings.redis_stream,
        consumer_name=consumer_name,
        db_session_factory=sessionmaker,
        geo=geo,
        abuseipdb=abuse,
        alert_threshold=settings.alert_threshold_high,
        report_auto_trigger_score=settings.report_auto_trigger_score,
    )

    try:
        await worker.run()
    finally:
        with contextlib.suppress(Exception):
            await abuse.aclose()
        with contextlib.suppress(Exception):
            geo.close()
        await bus.close()
        await dispose_engine()


if __name__ == "__main__":
    asyncio.run(_main())
