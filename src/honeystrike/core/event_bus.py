"""Redis Streams event publisher.

The honeypot services produce events; the intel / report / dashboard workers
consume from the `honeystrike:events` stream via consumer groups. See
`docs/03_Domain_Events.md` for the catalogue and delivery guarantees.

Connection management is intentionally per-process (one pool per worker).
"""

from __future__ import annotations

from typing import Self

import redis.asyncio as aioredis

from honeystrike.core.events import EventEnvelope
from honeystrike.core.logging import get_logger

log = get_logger(__name__)


class EventBus:
    """Async Redis Streams publisher with bounded stream length."""

    def __init__(
        self,
        redis_url: str,
        *,
        stream: str = "honeystrike:events",
        maxlen: int = 100_000,
    ) -> None:
        self._url = redis_url
        self._stream = stream
        self._maxlen = maxlen
        self._client: aioredis.Redis | None = None

    async def connect(self) -> Self:
        self._client = aioredis.from_url(
            self._url,
            decode_responses=True,
            health_check_interval=30,
        )
        await self._client.ping()
        log.info("event_bus.connected", url=self._url, stream=self._stream)
        return self

    async def close(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    @property
    def client(self) -> aioredis.Redis:
        if self._client is None:
            raise RuntimeError("EventBus not connected — call .connect() first")
        return self._client

    async def publish(self, envelope: EventEnvelope) -> str:
        """Publish an event. Returns the Redis-assigned stream entry ID."""
        entry_id = await self.client.xadd(
            self._stream,
            envelope.to_stream_fields(),
            maxlen=self._maxlen,
            approximate=True,
        )
        log.debug(
            "event_bus.published",
            event_type=envelope.event_type.value,
            session_id=envelope.session_id,
            entry_id=entry_id,
        )
        return entry_id  # type: ignore[no-any-return]

    async def stream_length(self) -> int:
        return int(await self.client.xlen(self._stream))
