"""Tests for the FingerprintWorker — focuses on the pure helpers and the
ingest-then-flush state machine. End-to-end Redis + DB exercise lives in the
integration suite.
"""

from __future__ import annotations

import math
from datetime import UTC, datetime, timedelta

import uuid

import pytest

from honeystrike.core.events import EventType
from honeystrike.workers.intel.fingerprint import (
    _attempt_rate_and_pattern,
    _load_sibling_sessions,
    _sanitise_ip,
    _session_start_ts,
)
from honeystrike.workers.intel.aggregator import SessionBuffer


def test_sanitise_ip_strips_postgres_inet_suffix() -> None:
    assert _sanitise_ip("172.20.0.1/32") == "172.20.0.1"
    assert _sanitise_ip("203.0.113.7") == "203.0.113.7"
    assert _sanitise_ip("2001:db8::1/128") == "2001:db8::1"
    # Unparseable input: return as-is rather than raise.
    assert _sanitise_ip("not an ip") == "not an ip"


def test_attempt_rate_and_pattern_classifies_burst() -> None:
    t0 = datetime(2026, 5, 1, 12, 0, tzinfo=UTC)
    # 12 events in 1.1s = ~654/min → very high rate, low cv → burst.
    rows = [
        {
            "event_type": EventType.SSH_AUTH_ATTEMPT.value,
            "ts": t0 + timedelta(milliseconds=i * 100),
        }
        for i in range(12)
    ]
    rate, pattern = _attempt_rate_and_pattern(rows)
    assert rate is not None and rate > 600
    assert pattern == "burst"


def test_attempt_rate_and_pattern_classifies_slow() -> None:
    t0 = datetime(2026, 5, 1, 12, 0, tzinfo=UTC)
    # 5 events spread over 60s = 5/min, low cv → slow.
    rows = [
        {
            "event_type": EventType.SSH_AUTH_ATTEMPT.value,
            "ts": t0 + timedelta(seconds=i * 15),
        }
        for i in range(5)
    ]
    rate, pattern = _attempt_rate_and_pattern(rows)
    assert rate is not None and rate < 30
    assert pattern == "slow"


def test_attempt_rate_and_pattern_classifies_random() -> None:
    t0 = datetime(2026, 5, 1, 12, 0, tzinfo=UTC)
    deltas_ms = [10, 5000, 12, 8000, 9]   # huge variance → random
    rows = []
    cum = 0
    for d in deltas_ms:
        cum += d
        rows.append({
            "event_type": EventType.SSH_AUTH_ATTEMPT.value,
            "ts": t0 + timedelta(milliseconds=cum),
        })
    _rate, pattern = _attempt_rate_and_pattern(rows)
    assert pattern == "random"


def test_attempt_rate_and_pattern_unknown_for_one_event() -> None:
    t0 = datetime(2026, 5, 1, 12, 0, tzinfo=UTC)
    rate, pattern = _attempt_rate_and_pattern([
        {"event_type": EventType.SSH_AUTH_ATTEMPT.value, "ts": t0},
    ])
    assert rate is None
    assert pattern == "unknown"


def test_session_start_ts_returns_earliest_event() -> None:
    t0 = datetime(2026, 5, 1, 12, 0, tzinfo=UTC)
    buf = SessionBuffer(
        session_id="s", service="ssh", src_ip="1.2.3.4", src_port=1234,
        started_at_monotonic=0.0, last_event_monotonic=0.0,
    )
    rows = [
        {"ts": t0 + timedelta(seconds=5)},
        {"ts": t0},
        {"ts": t0 + timedelta(seconds=10)},
    ]
    assert _session_start_ts(buf, rows) == t0


def test_session_start_ts_falls_back_to_now_when_empty() -> None:
    buf = SessionBuffer(
        session_id="s", service="ssh", src_ip="1.2.3.4", src_port=1234,
        started_at_monotonic=0.0, last_event_monotonic=0.0,
    )
    before = datetime.now(UTC)
    result = _session_start_ts(buf, [])
    delta = (result - before).total_seconds()
    assert math.fabs(delta) < 1.0


# ---------------------------------------------------------------------------
# Sibling-sessions loader
# ---------------------------------------------------------------------------

class _FakeRow:
    def __init__(self, id_: uuid.UUID, service: str, started_at: datetime) -> None:
        self.id = id_
        self.service = service
        self.started_at = started_at


class _FakeResult:
    def __init__(self, rows: list[_FakeRow]) -> None:
        self._rows = rows

    def all(self) -> list[_FakeRow]:
        return self._rows


class _FakeDB:
    """Minimal stand-in that records the executed statement and returns canned rows."""

    def __init__(self, rows: list[_FakeRow]) -> None:
        self._rows = rows
        self.executed_stmt = None

    async def execute(self, stmt):
        self.executed_stmt = stmt
        return _FakeResult(self._rows)


@pytest.mark.asyncio
async def test_load_sibling_sessions_returns_dicts_with_expected_shape() -> None:
    anchor_id = str(uuid.uuid4())
    sib_id = uuid.uuid4()
    anchor_ts = datetime(2026, 5, 17, 12, 0, tzinfo=UTC)
    rows = [_FakeRow(sib_id, "http", anchor_ts + timedelta(seconds=5))]
    db = _FakeDB(rows)

    result = await _load_sibling_sessions(
        db,  # type: ignore[arg-type]
        src_ip="1.2.3.4",
        anchor_session_id=anchor_id,
        anchor_started_at=anchor_ts,
    )

    assert result == [
        {
            "session_id": str(sib_id),
            "src_ip": "1.2.3.4",
            "service": "http",
            "started_at": anchor_ts + timedelta(seconds=5),
        }
    ]
    # Sanity: a statement was issued.
    assert db.executed_stmt is not None


@pytest.mark.asyncio
async def test_load_sibling_sessions_empty_when_no_rows() -> None:
    db = _FakeDB([])
    result = await _load_sibling_sessions(
        db,  # type: ignore[arg-type]
        src_ip="9.9.9.9",
        anchor_session_id=str(uuid.uuid4()),
        anchor_started_at=datetime.now(UTC),
    )
    assert result == []
