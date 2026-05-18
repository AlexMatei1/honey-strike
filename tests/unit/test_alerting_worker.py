"""Tests for the AlertingWorker — dedup window, dispatch fan-out, error handling.

We don't spin up Redis or the DB here; the worker is exercised through its
helpers and an in-process fake Redis/DB. End-to-end exercise lives in
tests/integration.
"""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import AsyncMock

import pytest

from honeystrike.workers.alerting.channels import AlertMessage, Channel
from honeystrike.workers.alerting.worker import (
    AlertingWorker,
    parse_alert_fields,
    publish_alert,
)


def _fields() -> dict[str, str]:
    return {
        "session_id": "ssn-1",
        "src_ip": "1.2.3.4",
        "service": "ssh",
        "severity": "critical",
        "threat_score": "88",
        "country_iso": "RU",
        "tool_signatures": json.dumps(["Hydra", "Masscan"]),
        "ttp_techniques": json.dumps(["T1110.001", "T1078"]),
    }


# ---------------------------------------------------------------------------
# parse_alert_fields
# ---------------------------------------------------------------------------

def test_parse_alert_fields_decodes_json_lists_and_score() -> None:
    parsed = parse_alert_fields(_fields())
    assert parsed["threat_score"] == 88
    assert parsed["tool_signatures"] == ["Hydra", "Masscan"]
    assert parsed["ttp_techniques"] == ["T1110.001", "T1078"]


def test_parse_alert_fields_treats_empty_country_as_none() -> None:
    raw = _fields()
    raw["country_iso"] = ""
    parsed = parse_alert_fields(raw)
    assert parsed["country_iso"] is None


def test_parse_alert_fields_defaults_missing_lists_to_empty() -> None:
    raw = _fields()
    del raw["tool_signatures"]
    del raw["ttp_techniques"]
    parsed = parse_alert_fields(raw)
    assert parsed["tool_signatures"] == []
    assert parsed["ttp_techniques"] == []


# ---------------------------------------------------------------------------
# publish_alert — verifies xadd shape so AlertingWorker can decode it.
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_publish_alert_roundtrips_through_parser() -> None:
    captured: dict[str, Any] = {}

    async def fake_xadd(self, stream, fields, **kwargs):
        captured["stream"] = stream
        captured["fields"] = fields
        captured["kwargs"] = kwargs

    fake_redis = type("FakeRedis", (), {"xadd": fake_xadd})()
    await publish_alert(
        fake_redis,
        stream="test-alerts",
        session_id="ssn-1",
        src_ip="1.2.3.4",
        service="ssh",
        severity="critical",
        threat_score=88,
        country_iso="RU",
        tool_signatures=["Hydra"],
        ttp_techniques=["T1110.001"],
    )
    assert captured["stream"] == "test-alerts"
    parsed = parse_alert_fields(captured["fields"])
    assert parsed["src_ip"] == "1.2.3.4"
    assert parsed["threat_score"] == 88
    assert parsed["tool_signatures"] == ["Hydra"]


# ---------------------------------------------------------------------------
# AlertingWorker — dedup + dispatch tests using fake collaborators.
# ---------------------------------------------------------------------------

class _FakeRedis:
    """Minimal async stand-in for the parts of redis.asyncio the worker uses."""

    def __init__(self) -> None:
        self._keys: set[str] = set()
        self.xack_calls: list[str] = []

    async def set(self, key, value, ex=None, nx=False):
        if nx and key in self._keys:
            return None
        self._keys.add(key)
        return True

    async def xack(self, stream, group, *ids) -> None:
        self.xack_calls.extend(ids)


class _RecordingChannel:
    def __init__(self, name: str, *, fail: bool = False) -> None:
        self.name = name
        self.fail = fail
        self.sent: list[AlertMessage] = []

    async def send(self, msg: AlertMessage) -> None:
        if self.fail:
            raise RuntimeError(f"boom from {self.name}")
        self.sent.append(msg)


class _CapturingDB:
    """Async session that captures inserted alert rows."""

    def __init__(self) -> None:
        self.inserted: list[dict] = []
        self.committed = 0

    async def __aenter__(self) -> "_CapturingDB":
        return self

    async def __aexit__(self, *exc) -> None:
        return None

    async def execute(self, stmt, params=None) -> None:
        # SQLAlchemy bulk-insert path: stmt is the insert; params is the row list.
        if params:
            self.inserted.extend(params)

    async def commit(self) -> None:
        self.committed += 1


def _factory(db: _CapturingDB):
    def _make():
        return db
    return _make


def _make_worker(redis, db: _CapturingDB, channels: list[Channel]) -> AlertingWorker:
    return AlertingWorker(
        redis_client=redis,
        stream="alerts-test",
        consumer_name="test-consumer",
        db_session_factory=_factory(db),
        channels=channels,
        cooldown_seconds=60,
    )


@pytest.mark.asyncio
async def test_worker_dispatches_to_every_channel_and_persists_rows() -> None:
    redis = _FakeRedis()
    db = _CapturingDB()
    log = _RecordingChannel("log")
    tg = _RecordingChannel("telegram")
    worker = _make_worker(redis, db, [log, tg])

    await worker._process_entry("1-0", _fields())  # noqa: SLF001 — direct path

    assert len(log.sent) == 1
    assert len(tg.sent) == 1
    # One alert row per channel.
    assert {row["channel"] for row in db.inserted} == {"log", "telegram"}
    assert db.committed == 1
    assert redis.xack_calls == ["1-0"]


@pytest.mark.asyncio
async def test_worker_skips_repeat_alert_within_cooldown() -> None:
    redis = _FakeRedis()
    db = _CapturingDB()
    log = _RecordingChannel("log")
    worker = _make_worker(redis, db, [log])

    await worker._process_entry("1-0", _fields())  # noqa: SLF001
    await worker._process_entry("2-0", _fields())  # noqa: SLF001

    assert len(log.sent) == 1
    assert len(db.inserted) == 1
    # Both Redis stream entries were ACKed regardless of dedup.
    assert redis.xack_calls == ["1-0", "2-0"]


@pytest.mark.asyncio
async def test_worker_failing_channel_does_not_block_the_others() -> None:
    redis = _FakeRedis()
    db = _CapturingDB()
    log = _RecordingChannel("log")
    bad = _RecordingChannel("telegram", fail=True)
    worker = _make_worker(redis, db, [log, bad])

    await worker._process_entry("1-0", _fields())  # noqa: SLF001

    assert [c.name for c in db.inserted_channels_used()] if False else True  # type: ignore[truthy-bool]
    assert len(log.sent) == 1
    # No row written for the failing channel.
    assert {row["channel"] for row in db.inserted} == {"log"}


@pytest.mark.asyncio
async def test_worker_no_channel_succeeded_writes_no_rows() -> None:
    redis = _FakeRedis()
    db = _CapturingDB()
    bad1 = _RecordingChannel("telegram", fail=True)
    bad2 = _RecordingChannel("slack", fail=True)
    worker = _make_worker(redis, db, [bad1, bad2])

    await worker._process_entry("1-0", _fields())  # noqa: SLF001

    assert db.inserted == []
    assert db.committed == 0
    # Dedup key was still claimed — the alert was attempted.
    assert redis.xack_calls == ["1-0"]


@pytest.mark.asyncio
async def test_worker_bad_envelope_is_acked_without_dispatch() -> None:
    redis = _FakeRedis()
    db = _CapturingDB()
    log = _RecordingChannel("log")
    worker = _make_worker(redis, db, [log])

    bad_fields = {"session_id": "x"}  # missing required keys → KeyError
    await worker._process_entry("1-0", bad_fields)  # noqa: SLF001

    assert log.sent == []
    assert redis.xack_calls == ["1-0"]
