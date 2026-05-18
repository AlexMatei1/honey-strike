"""Tests for SessionManager — verifies the open/record/close lifecycle
publishes envelopes correctly and writes the rows we expect to the DB.

We pass fakes for the AsyncSession and EventBus so the test stays hermetic
(no Postgres / Redis required). Real DB writes are exercised by every
integration test that hits a honeypot.
"""

from __future__ import annotations

import uuid

import pytest

from honeystrike.core.events import EventEnvelope, EventType, Service
from honeystrike.core.session_manager import SessionManager


class _FakeBus:
    def __init__(self) -> None:
        self.published: list[EventEnvelope] = []

    async def publish(self, env: EventEnvelope) -> None:
        self.published.append(env)


class _FakeDB:
    """Minimal AsyncSession stand-in. Captures `add` rows and tracks commits."""

    def __init__(self) -> None:
        self.added: list[object] = []
        self.commits = 0
        self.flushes = 0
        self.executed: list[object] = []

    def add(self, row) -> None:
        self.added.append(row)

    async def flush(self) -> None:
        self.flushes += 1
        # Mimic Postgres assigning a UUID PK on flush.
        if self.added:
            row = self.added[-1]
            if getattr(row, "id", None) is None:
                row.id = uuid.uuid4()

    async def commit(self) -> None:
        self.commits += 1

    async def execute(self, stmt) -> None:
        self.executed.append(stmt)


@pytest.mark.asyncio
async def test_open_inserts_row_emits_session_open_and_returns_id() -> None:
    db = _FakeDB()
    bus = _FakeBus()
    mgr = SessionManager(db, bus)  # type: ignore[arg-type]

    sid = await mgr.open(
        service=Service.SSH,
        src_ip="1.2.3.4",
        src_port=51111,
        local_port=22,
    )

    assert isinstance(sid, uuid.UUID)
    # One row inserted, one flush + commit.
    assert len(db.added) == 1
    assert db.flushes == 1
    assert db.commits == 1
    # One envelope published, of type SESSION_OPEN, with the right metadata.
    assert len(bus.published) == 1
    env = bus.published[0]
    assert env.event_type == EventType.SESSION_OPEN
    assert env.service == Service.SSH
    assert env.src_ip == "1.2.3.4"
    assert env.payload["remote_addr"] == "1.2.3.4:51111"
    assert env.payload["local_port"] == 22


@pytest.mark.asyncio
async def test_record_event_appends_row_and_emits_envelope() -> None:
    db = _FakeDB()
    bus = _FakeBus()
    mgr = SessionManager(db, bus)  # type: ignore[arg-type]

    sid = uuid.uuid4()
    eid = await mgr.record_event(
        session_id=sid,
        event_type=EventType.SSH_AUTH_ATTEMPT,
        service=Service.SSH,
        src_ip="1.2.3.4",
        src_port=51111,
        payload={"username": "root", "auth_type": "password"},
    )

    assert isinstance(eid, uuid.UUID)
    assert len(db.added) == 1
    assert db.commits == 1
    assert bus.published[0].event_type == EventType.SSH_AUTH_ATTEMPT
    assert bus.published[0].payload["username"] == "root"
    # The published envelope carries the same id as the persisted row.
    assert bus.published[0].id == str(eid)


@pytest.mark.asyncio
async def test_close_updates_row_and_emits_session_close() -> None:
    db = _FakeDB()
    bus = _FakeBus()
    mgr = SessionManager(db, bus)  # type: ignore[arg-type]

    sid = uuid.uuid4()
    await mgr.close(
        session_id=sid,
        service=Service.SSH,
        src_ip="1.2.3.4",
        src_port=51111,
        event_count=7,
        duration_ms=4500,
        close_reason="client_disconnect",
    )

    # One UPDATE on `sessions` (captured in `executed`), one commit.
    assert len(db.executed) == 1
    assert db.commits == 1
    env = bus.published[0]
    assert env.event_type == EventType.SESSION_CLOSE
    assert env.payload["duration_ms"] == 4500
    assert env.payload["event_count"] == 7
    assert env.payload["close_reason"] == "client_disconnect"


@pytest.mark.asyncio
async def test_close_accepts_timeout_state() -> None:
    db = _FakeDB()
    bus = _FakeBus()
    mgr = SessionManager(db, bus)  # type: ignore[arg-type]

    await mgr.close(
        session_id=uuid.uuid4(),
        service=Service.HTTP,
        src_ip="1.2.3.4",
        src_port=51111,
        event_count=0,
        duration_ms=0,
        close_reason="idle_timeout",
        state="TIMEOUT",
    )
    # No row in `added` because close is UPDATE-only.
    assert db.added == []
    assert len(db.executed) == 1
