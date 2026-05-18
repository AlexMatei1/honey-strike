"""In-memory session-event aggregation for the FingerprintWorker.

A session can span many events spread over up to 5 minutes (longer for SSH
shells with the timeout cap). We can't enrich every event individually —
geolocation, AbuseIPDB, and signature evaluation all need a *session-level*
view. So the worker buffers events keyed by `session_id`, then flushes when:

  - a `SESSION_CLOSE` event arrives                                   (normal path)
  - the buffer's oldest event is older than `idle_timeout_seconds`    (safety net for
    sessions where SESSION_CLOSE was lost — at-least-once delivery)
  - the buffer exceeds `max_events_per_session` events                (cap, e.g. a
    runaway SSH command spammer)

Pure data + control-flow; no I/O. The worker class owns the I/O.
"""

from __future__ import annotations

import time
from collections import OrderedDict
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from honeystrike.core.events import EventEnvelope, EventType


@dataclass(slots=True)
class SessionBuffer:
    session_id: str
    service: str
    src_ip: str
    src_port: int
    started_at_monotonic: float
    last_event_monotonic: float
    events: list[EventEnvelope] = field(default_factory=list)

    @property
    def event_count(self) -> int:
        return len(self.events)

    @property
    def closed(self) -> bool:
        return any(
            e.event_type is EventType.SESSION_CLOSE for e in self.events
        )


class SessionAggregator:
    """Order-preserving event buffer per session.

    OrderedDict gives us O(1) eviction of the oldest session when we hit the
    overall session-count cap, which protects the worker against an attacker
    spraying millions of session ids.
    """

    def __init__(
        self,
        *,
        idle_timeout_seconds: float = 90.0,
        max_events_per_session: int = 5000,
        max_sessions: int = 10_000,
    ) -> None:
        self._idle_timeout = idle_timeout_seconds
        self._max_events = max_events_per_session
        self._max_sessions = max_sessions
        self._buffers: OrderedDict[str, SessionBuffer] = OrderedDict()

    def __len__(self) -> int:
        return len(self._buffers)

    def ingest(self, envelope: EventEnvelope) -> SessionBuffer | None:
        """Add an event to its session's buffer.

        Returns the buffer if it's ready to flush (session closed or capped),
        else None — the caller schedules a future drain via `drain_idle()`.
        """
        now = time.monotonic()
        buf = self._buffers.get(envelope.session_id)
        if buf is None:
            buf = SessionBuffer(
                session_id=envelope.session_id,
                service=envelope.service.value,
                src_ip=envelope.src_ip,
                src_port=envelope.src_port,
                started_at_monotonic=now,
                last_event_monotonic=now,
            )
            self._buffers[envelope.session_id] = buf
            self._evict_if_full()
        else:
            buf.last_event_monotonic = now
            # Move to most-recent end of the OrderedDict.
            self._buffers.move_to_end(envelope.session_id)

        buf.events.append(envelope)

        if envelope.event_type is EventType.SESSION_CLOSE:
            return self._pop(envelope.session_id)
        if buf.event_count >= self._max_events:
            return self._pop(envelope.session_id)
        return None

    def drain_idle(self) -> list[SessionBuffer]:
        """Return + remove buffers whose last event is older than the timeout."""
        now = time.monotonic()
        to_drop: list[str] = []
        result: list[SessionBuffer] = []
        for sid, buf in self._buffers.items():
            if (now - buf.last_event_monotonic) > self._idle_timeout:
                to_drop.append(sid)
            else:
                # OrderedDict is sorted by recency — once we hit a fresh one
                # everything after is fresher.
                break
        for sid in to_drop:
            result.append(self._buffers.pop(sid))
        return result

    def drain_all(self) -> Iterable[SessionBuffer]:
        """Forcefully drain everything (e.g. on shutdown)."""
        while self._buffers:
            yield self._buffers.popitem(last=False)[1]

    def _pop(self, sid: str) -> SessionBuffer | None:
        return self._buffers.pop(sid, None)

    def _evict_if_full(self) -> None:
        while len(self._buffers) > self._max_sessions:
            self._buffers.popitem(last=False)


def envelope_to_event_row(envelope: EventEnvelope) -> dict[str, Any]:
    """Convert a wire envelope to the dict shape signatures.SessionContext expects."""
    from datetime import datetime
    return {
        "event_type": envelope.event_type.value,
        "ts": datetime.fromisoformat(envelope.timestamp),
        "payload": dict(envelope.payload),
    }
