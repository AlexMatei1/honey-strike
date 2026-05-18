"""AlertingWorker — drives alert dispatch.

Consumer:
  - Stream:           `honeystrike:alerts`
  - Consumer group:   `alerting`

Each stream entry is published by the FingerprintWorker after it has scored a
session and the resulting severity exceeds the configured threshold. The
worker:

  1. parses the alert envelope (session_id + scored metadata),
  2. checks a Redis-backed dedup window keyed by (src_ip, severity),
  3. dispatches to every enabled `Channel` in parallel,
  4. records one `alerts` row per channel that succeeded.

Dedup TTL = `settings.alert_cooldown_seconds` (default 30 min). Two scored
sessions from the same IP at the same severity within that window produce
exactly one alert burst, no matter how often the FingerprintWorker re-runs.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
from typing import Any

import redis.asyncio as aioredis
from sqlalchemy.ext.asyncio import AsyncSession

from honeystrike.core.logging import get_logger
from honeystrike.core.models import Alert
from honeystrike.workers.alerting.channels import (
    AlertMessage,
    Channel,
    format_alert,
)

log = get_logger(__name__)

CONSUMER_GROUP = "alerting"
ALERT_STREAM = "honeystrike:alerts"
DEDUP_PREFIX = "alert:dedup"


class AlertingWorker:
    """Single-process worker. One instance per container."""

    def __init__(
        self,
        *,
        redis_client: aioredis.Redis,
        stream: str,
        consumer_name: str,
        db_session_factory: Any,
        channels: list[Channel],
        cooldown_seconds: int,
        read_block_ms: int = 5_000,
    ) -> None:
        self._redis = redis_client
        self._stream = stream
        self._consumer_name = consumer_name
        self._db_factory = db_session_factory
        self._channels = channels
        self._cooldown = cooldown_seconds
        self._read_block_ms = read_block_ms
        self._stop = asyncio.Event()

    async def setup(self) -> None:
        try:
            await self._redis.xgroup_create(
                self._stream, CONSUMER_GROUP, id="0", mkstream=True
            )
            log.info("alerting.consumer_group_created", group=CONSUMER_GROUP)
        except aioredis.ResponseError as exc:
            if "BUSYGROUP" not in str(exc):
                raise

    async def stop(self) -> None:
        self._stop.set()

    async def run(self) -> None:
        await self.setup()
        log.info(
            "alerting.worker_started",
            stream=self._stream,
            consumer=self._consumer_name,
            channels=[c.name for c in self._channels],
        )
        while not self._stop.is_set():
            try:
                entries = await self._redis.xreadgroup(
                    groupname=CONSUMER_GROUP,
                    consumername=self._consumer_name,
                    streams={self._stream: ">"},
                    count=20,
                    block=self._read_block_ms,
                )
            except aioredis.ConnectionError as exc:
                log.warning("alerting.redis_disconnected", error=str(exc))
                await asyncio.sleep(2)
                continue

            for _stream_name, items in entries or []:
                for entry_id, fields in items:
                    await self._process_entry(entry_id, fields)

    async def _process_entry(self, entry_id: str, fields: dict[str, str]) -> None:
        try:
            envelope = parse_alert_fields(fields)
        except (KeyError, ValueError, json.JSONDecodeError) as exc:
            log.warning("alerting.bad_envelope", entry_id=entry_id, error=str(exc))
            await self._ack(entry_id)
            return

        msg = format_alert(**envelope)
        first_time = await self._claim_dedup(msg.src_ip, msg.severity)
        if not first_time:
            log.info(
                "alerting.deduped",
                session_id=msg.session_id,
                src_ip=msg.src_ip,
                severity=msg.severity,
            )
            await self._ack(entry_id)
            return

        await self._dispatch(msg)
        await self._ack(entry_id)

    async def _claim_dedup(self, src_ip: str, severity: str) -> bool:
        """SET NX with TTL — returns True the first time within the window."""
        key = f"{DEDUP_PREFIX}:{src_ip}:{severity}"
        try:
            ok = await self._redis.set(key, "1", ex=self._cooldown, nx=True)
        except aioredis.RedisError as exc:
            log.warning("alerting.dedup_redis_failed", error=str(exc))
            # Fail-open: better to over-page than to silently swallow.
            return True
        return bool(ok)

    async def _dispatch(self, msg: AlertMessage) -> None:
        results = await asyncio.gather(
            *(self._try_send(c, msg) for c in self._channels),
            return_exceptions=False,
        )
        successful = [name for name in results if name]
        if not successful:
            log.warning(
                "alerting.no_channel_succeeded",
                session_id=msg.session_id,
                src_ip=msg.src_ip,
            )
            return
        async with self._db_factory() as db:  # type: AsyncSession
            await _persist_alert_rows(db, msg=msg, channels=successful)

    async def _try_send(self, channel: Channel, msg: AlertMessage) -> str | None:
        try:
            await channel.send(msg)
            return channel.name
        except Exception as exc:
            log.warning(
                "alerting.channel_failed",
                channel=channel.name,
                session_id=msg.session_id,
                error=str(exc),
            )
            return None

    async def _ack(self, entry_id: str) -> None:
        try:
            await self._redis.xack(self._stream, CONSUMER_GROUP, entry_id)
        except aioredis.RedisError as exc:
            log.warning("alerting.xack_failed", error=str(exc))


# ---------------------------------------------------------------------------
# Helpers (module level so the FingerprintWorker can call publish_alert)
# ---------------------------------------------------------------------------

def parse_alert_fields(fields: dict[str, str]) -> dict[str, Any]:
    """Pull the typed kwargs back out of the Redis stream's flat field map."""
    tools = fields.get("tool_signatures") or "[]"
    ttps = fields.get("ttp_techniques") or "[]"
    return {
        "session_id": fields["session_id"],
        "src_ip": fields["src_ip"],
        "service": fields["service"],
        "severity": fields["severity"],
        "threat_score": int(fields["threat_score"]),
        "country_iso": fields.get("country_iso") or None,
        "tool_signatures": json.loads(tools),
        "ttp_techniques": json.loads(ttps),
    }


async def publish_alert(
    redis_client: aioredis.Redis,
    *,
    stream: str = ALERT_STREAM,
    session_id: str,
    src_ip: str,
    service: str,
    severity: str,
    threat_score: int,
    country_iso: str | None,
    tool_signatures: list[str],
    ttp_techniques: list[str],
    maxlen: int = 10_000,
) -> None:
    """Push one alert envelope onto the stream. Called by the FingerprintWorker."""
    fields = {
        "session_id": session_id,
        "src_ip": src_ip,
        "service": service,
        "severity": severity,
        "threat_score": str(threat_score),
        "country_iso": country_iso or "",
        "tool_signatures": json.dumps(tool_signatures),
        "ttp_techniques": json.dumps(ttp_techniques),
    }
    await redis_client.xadd(stream, fields, maxlen=maxlen, approximate=True)


async def _persist_alert_rows(
    db: AsyncSession, *, msg: AlertMessage, channels: list[str]
) -> None:
    rows = [
        {
            "session_id": msg.session_id,
            "channel": name,
            "severity": msg.severity,
            "threat_score": msg.threat_score,
            "payload": {
                "src_ip": msg.src_ip,
                "service": msg.service,
                "subject": msg.subject,
                "tool_signatures": msg.tool_signatures,
                "ttp_techniques": msg.ttp_techniques,
            },
        }
        for name in channels
    ]
    await db.execute(Alert.__table__.insert(), rows)
    await db.commit()


# ---------------------------------------------------------------------------
# Module-level entrypoint for `python -m honeystrike.workers.alerting.worker`
# ---------------------------------------------------------------------------

async def _main() -> None:
    import os

    from honeystrike.config import get_settings
    from honeystrike.core.db import dispose_engine, get_sessionmaker
    from honeystrike.core.event_bus import EventBus
    from honeystrike.core.logging import configure_logging
    from honeystrike.workers.alerting.channels import build_channels_from_settings

    settings = get_settings()
    configure_logging(level=settings.log_level, json=settings.app_env == "production")
    bus = await EventBus(
        settings.redis_url,
        stream=settings.redis_stream,
        maxlen=settings.redis_stream_maxlen,
    ).connect()

    channels = build_channels_from_settings(settings)
    sessionmaker = get_sessionmaker()
    consumer_name = os.getenv("WORKER_CONSUMER_NAME", f"alert-{os.getpid()}")

    worker = AlertingWorker(
        redis_client=bus.client,
        stream=ALERT_STREAM,
        consumer_name=consumer_name,
        db_session_factory=sessionmaker,
        channels=channels,
        cooldown_seconds=settings.alert_cooldown_seconds,
    )

    try:
        await worker.run()
    finally:
        for c in channels:
            close = getattr(c, "aclose", None)
            if close is not None:
                with contextlib.suppress(Exception):
                    await close()
        await bus.close()
        await dispose_engine()


if __name__ == "__main__":
    asyncio.run(_main())
