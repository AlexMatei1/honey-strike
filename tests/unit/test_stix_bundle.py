"""Tests for the STIX 2.1 bundle builder (Phase 5 stretch).

Live DB exercise lives in tests/integration. Here we feed `build_bundle`
a fake AsyncSession whose `execute` returns the rows the SELECTs expect, in
the order they're called.
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime

import pytest

from honeystrike.api.stix import HONEYSTRIKE_IDENTITY_ID, build_bundle


class _Row:
    """SQLAlchemy `_row.RowMapping` stand-in — supports both attribute
    access and indexed access used in the builder."""

    def __init__(self, **kw) -> None:
        for k, v in kw.items():
            setattr(self, k, v)


class _Result:
    def __init__(self, rows) -> None:
        self._rows = rows

    def all(self):
        return self._rows


class _FakeDB:
    """Returns canned results in the order `execute` is called."""

    def __init__(self, *result_batches) -> None:
        self._batches = list(result_batches)

    async def execute(self, _stmt):
        if not self._batches:
            return _Result([])
        return _Result(self._batches.pop(0))


def _session_row(*, ip: str, score: int, severity: str, ttp_ids: list[str]) -> _Row:
    return _Row(
        id=uuid.uuid4(),
        src_ip=ip,
        service="ssh",
        threat_score=score,
        severity=severity,
        started_at=datetime(2026, 5, 17, 10, 0, tzinfo=UTC),
        ended_at=datetime(2026, 5, 17, 10, 1, tzinfo=UTC),
        country_iso="RU",
        asn=12345,
        org="Scanner Co.",
        tool_signatures=[{"name": "Hydra", "confidence": 0.92}],
    )


@pytest.mark.asyncio
async def test_build_bundle_emits_identity_first() -> None:
    sess = _session_row(ip="203.0.113.7", score=82, severity="critical", ttp_ids=[])
    db = _FakeDB([sess], [(sess.id, "T1110.001")])
    bundle = await build_bundle(db, days=7, min_score=60, limit=500)  # type: ignore[arg-type]
    objects = json.loads(bundle.serialize())["objects"]
    assert objects[0]["type"] == "identity"
    assert objects[0]["id"] == HONEYSTRIKE_IDENTITY_ID


@pytest.mark.asyncio
async def test_build_bundle_emits_one_indicator_per_unique_ip() -> None:
    s1 = _session_row(ip="1.1.1.1", score=80, severity="critical", ttp_ids=[])
    s2 = _session_row(ip="1.1.1.1", score=75, severity="high", ttp_ids=[])
    s3 = _session_row(ip="2.2.2.2", score=70, severity="high", ttp_ids=[])
    db = _FakeDB([s1, s2, s3], [])
    bundle = await build_bundle(db, days=7, min_score=60, limit=500)  # type: ignore[arg-type]
    types = [o["type"] for o in json.loads(bundle.serialize())["objects"]]
    # 2 unique IPs → 2 indicators (one per IP).
    assert types.count("indicator") == 2
    # 3 sessions → 3 each of address, network-traffic, observed-data, sighting.
    for t in ("ipv4-addr", "network-traffic", "observed-data", "sighting"):
        assert types.count(t) == 3


@pytest.mark.asyncio
async def test_build_bundle_returns_empty_objects_when_no_sessions() -> None:
    db = _FakeDB([], [])
    bundle = await build_bundle(db, days=7, min_score=60, limit=500)  # type: ignore[arg-type]
    objects = json.loads(bundle.serialize())["objects"]
    # Only the identity SDO when no sessions match.
    assert [o["type"] for o in objects] == ["identity"]


@pytest.mark.asyncio
async def test_indicator_pattern_uses_ipv4_value_filter() -> None:
    sess = _session_row(ip="9.9.9.9", score=90, severity="critical", ttp_ids=[])
    db = _FakeDB([sess], [])
    bundle = await build_bundle(db, days=7, min_score=60, limit=500)  # type: ignore[arg-type]
    indicator = next(
        o for o in json.loads(bundle.serialize())["objects"] if o["type"] == "indicator"
    )
    assert indicator["pattern"] == "[ipv4-addr:value = '9.9.9.9']"
    assert indicator["pattern_type"] == "stix"
    assert "malicious-activity" in indicator["indicator_types"]
