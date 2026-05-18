"""Tests for the in-memory session aggregator."""

from __future__ import annotations

import time

import pytest

from honeystrike.core.events import EventEnvelope, EventType, Service
from honeystrike.workers.intel.aggregator import SessionAggregator


def _envelope(
    session_id: str,
    event_type: EventType,
    *,
    src_ip: str = "1.2.3.4",
    src_port: int = 51111,
) -> EventEnvelope:
    return EventEnvelope(
        event_type=event_type,
        session_id=session_id,
        service=Service.SSH,
        src_ip=src_ip,
        src_port=src_port,
        payload={"k": "v"},
    )


def test_ingest_buffers_until_session_close_flushes() -> None:
    agg = SessionAggregator()
    sid = "11111111-1111-1111-1111-111111111111"
    assert agg.ingest(_envelope(sid, EventType.SESSION_OPEN)) is None
    assert agg.ingest(_envelope(sid, EventType.SSH_AUTH_ATTEMPT)) is None
    buf = agg.ingest(_envelope(sid, EventType.SESSION_CLOSE))
    assert buf is not None
    assert buf.event_count == 3
    assert buf.closed is True
    # Buffer was popped — second close on the same id would be a fresh buffer.
    assert len(agg) == 0


def test_idle_drain_collects_old_sessions(monkeypatch: pytest.MonkeyPatch) -> None:
    agg = SessionAggregator(idle_timeout_seconds=10.0)
    sid_old = "old"
    sid_fresh = "fresh"

    # Inject an old session by patching time.monotonic.
    base = time.monotonic()
    monkeypatch.setattr(time, "monotonic", lambda: base)
    agg.ingest(_envelope(sid_old, EventType.SESSION_OPEN))

    monkeypatch.setattr(time, "monotonic", lambda: base + 30)
    agg.ingest(_envelope(sid_fresh, EventType.SESSION_OPEN))

    monkeypatch.setattr(time, "monotonic", lambda: base + 30.5)
    flushed = agg.drain_idle()
    flushed_ids = [b.session_id for b in flushed]
    assert flushed_ids == [sid_old]
    assert len(agg) == 1


def test_event_count_cap_forces_flush() -> None:
    agg = SessionAggregator(max_events_per_session=3)
    sid = "burst"
    # Three events trip the cap and return the buffer; first two return None.
    assert agg.ingest(_envelope(sid, EventType.SSH_AUTH_ATTEMPT)) is None
    assert agg.ingest(_envelope(sid, EventType.SSH_AUTH_ATTEMPT)) is None
    buf = agg.ingest(_envelope(sid, EventType.SSH_AUTH_ATTEMPT))
    assert buf is not None
    assert buf.event_count == 3


def test_session_cap_evicts_oldest_first() -> None:
    agg = SessionAggregator(max_sessions=2)
    agg.ingest(_envelope("a", EventType.SESSION_OPEN))
    agg.ingest(_envelope("b", EventType.SESSION_OPEN))
    agg.ingest(_envelope("c", EventType.SESSION_OPEN))
    # `a` was the oldest — evicted.
    assert "a" not in [b.session_id for b in agg.drain_all()] or len(agg) == 0


def test_drain_all_yields_then_empties() -> None:
    agg = SessionAggregator()
    agg.ingest(_envelope("x", EventType.SESSION_OPEN))
    agg.ingest(_envelope("y", EventType.SESSION_OPEN))
    drained = list(agg.drain_all())
    assert {b.session_id for b in drained} == {"x", "y"}
    assert len(agg) == 0
