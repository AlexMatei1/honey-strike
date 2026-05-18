"""Session lifecycle — create on connect, persist events, close on disconnect.

Every honeypot service uses this to:
  1. Open a session row (`SessionManager.open`)
  2. Record events as they arrive (`record_event`) — writes to PG and emits
     to the Redis stream in the same call
  3. Close the session (`close`) — updates `ended_at`, `duration_ms`,
     `event_count`, and emits SESSION_CLOSE

This module is *not* responsible for fingerprinting, scoring or alerting.
Those are downstream workers consuming from the Redis stream.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import update
from sqlalchemy.ext.asyncio import AsyncSession

from honeystrike.core.event_bus import EventBus
from honeystrike.core.events import EventEnvelope, EventType, Service
from honeystrike.core.logging import get_logger
from honeystrike.core.models import Event as EventRow
from honeystrike.core.models import Session as SessionRow

log = get_logger(__name__)


class SessionManager:
    """Coordinates session+event persistence with Redis stream emission."""

    def __init__(self, db: AsyncSession, bus: EventBus) -> None:
        self._db = db
        self._bus = bus

    async def open(
        self,
        *,
        service: Service,
        src_ip: str,
        src_port: int,
        local_port: int,
    ) -> uuid.UUID:
        """Insert a `sessions` row and emit SESSION_OPEN.

        Returns the new session id. The caller passes this id to every
        subsequent `record_event()` call.
        """
        row = SessionRow(
            src_ip=src_ip,
            src_port=src_port,
            service=service.value,
        )
        self._db.add(row)
        await self._db.flush()
        session_id = row.id
        await self._db.commit()

        envelope = EventEnvelope(
            event_type=EventType.SESSION_OPEN,
            session_id=str(session_id),
            service=service,
            src_ip=src_ip,
            src_port=src_port,
            payload={
                "service": service.value,
                "remote_addr": f"{src_ip}:{src_port}",
                "local_port": local_port,
            },
        )
        await self._bus.publish(envelope)
        log.info(
            "session.opened",
            session_id=str(session_id),
            service=service.value,
            src_ip=src_ip,
            src_port=src_port,
        )
        return session_id

    async def record_event(
        self,
        *,
        session_id: uuid.UUID,
        event_type: EventType,
        service: Service,
        src_ip: str,
        src_port: int,
        payload: dict[str, Any],
    ) -> uuid.UUID:
        """Append a row to `events` and publish to Redis."""
        event_id = uuid.uuid4()
        row = EventRow(
            id=event_id,
            session_id=session_id,
            event_type=event_type.value,
            service=service.value,
            src_ip=src_ip,
            payload=payload,
        )
        self._db.add(row)
        await self._db.commit()

        envelope = EventEnvelope(
            id=str(event_id),
            event_type=event_type,
            session_id=str(session_id),
            service=service,
            src_ip=src_ip,
            src_port=src_port,
            payload=payload,
        )
        await self._bus.publish(envelope)
        return event_id

    async def close(
        self,
        *,
        session_id: uuid.UUID,
        service: Service,
        src_ip: str,
        src_port: int,
        event_count: int,
        duration_ms: int,
        close_reason: str,
        state: str = "CLOSED",
    ) -> None:
        """Mark session closed and emit SESSION_CLOSE."""
        await self._db.execute(
            update(SessionRow)
            .where(SessionRow.id == session_id)
            .values(
                state=state,
                event_count=event_count,
                duration_ms=duration_ms,
                ended_at=datetime.now(UTC),
            )
        )
        await self._db.commit()

        envelope = EventEnvelope(
            event_type=EventType.SESSION_CLOSE,
            session_id=str(session_id),
            service=service,
            src_ip=src_ip,
            src_port=src_port,
            payload={
                "duration_ms": duration_ms,
                "event_count": event_count,
                "close_reason": close_reason,
                "final_threat_score": 0,  # scorer worker fills in real value
            },
        )
        await self._bus.publish(envelope)
        log.info(
            "session.closed",
            session_id=str(session_id),
            event_count=event_count,
            duration_ms=duration_ms,
            close_reason=close_reason,
        )
