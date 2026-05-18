"""Smoke tests for the Pydantic response models in `api/schemas.py`.

The full request/response cycle is exercised in tests/integration. Here we
just confirm every model constructs with realistic field values, that
optional fields default sensibly, and that the camel-case-ish boundaries
between ORM rows and JSON payloads don't drift.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from honeystrike.api.schemas import (
    AlertSummary,
    EventPayload,
    EventPreview,
    EventsPage,
    FingerprintPayload,
    GeoStat,
    HealthOut,
    OverviewStats,
    ReportJobOut,
    SessionDetail,
    SessionListItem,
    SessionsPage,
    TimelineBucket,
    ToolSignaturePayload,
    TTPMatchPayload,
    TTPStat,
)

T0 = datetime(2026, 5, 17, 12, 0, tzinfo=UTC)
SID = uuid.UUID("11111111-1111-1111-1111-111111111111")
EID = uuid.UUID("22222222-2222-2222-2222-222222222222")


def test_session_list_item_serialises_minimal_fields() -> None:
    item = SessionListItem(
        id=SID,
        src_ip="1.2.3.4",
        service="ssh",
        state="CLOSED",
        threat_score=72,
        severity="high",
        started_at=T0,
    )
    out = item.model_dump()
    assert out["id"] == SID
    assert out["country_iso"] is None
    assert out["ended_at"] is None
    assert out["duration_ms"] is None
    assert out["ttp_count"] == 0


def test_sessions_page_round_trips() -> None:
    page = SessionsPage(
        total=2,
        page=1,
        limit=50,
        items=[
            SessionListItem(
                id=SID, src_ip="1.1.1.1", service="ssh", state="CLOSED",
                threat_score=10, severity="low", started_at=T0,
            )
        ],
    )
    out = page.model_dump(mode="json")
    assert out["total"] == 2
    assert len(out["items"]) == 1


def test_fingerprint_payload_accepts_tool_signatures() -> None:
    fp = FingerprintPayload(
        country_iso="RU",
        tool_signatures=[
            ToolSignaturePayload(name="Hydra", confidence=0.92),
            ToolSignaturePayload(name="Masscan", confidence=0.85),
        ],
    )
    assert len(fp.tool_signatures) == 2
    assert fp.tool_signatures[0].name == "Hydra"


def test_session_detail_with_full_payload() -> None:
    fp = FingerprintPayload(country_iso="CN", asn=4134, abuse_score=82)
    detail = SessionDetail(
        id=SID,
        src_ip="1.2.3.4",
        src_port=51111,
        service="ssh",
        state="CLOSED",
        threat_score=72,
        severity="high",
        started_at=T0,
        ended_at=T0,
        duration_ms=4500,
        event_count=12,
        fingerprint=fp,
        ttps=[
            TTPMatchPayload(
                technique_id="T1110.001",
                technique_name="Brute Force: Password Guessing",
                tactic="Credential Access",
                confidence=0.9,
                matched_at=T0,
            )
        ],
        events=EventPreview(
            total=12,
            preview=[
                EventPayload(
                    id=EID, event_type="SSH_AUTH_ATTEMPT", service="ssh",
                    timestamp=T0, payload={"username": "root"},
                ),
            ],
        ),
        alerts=[
            AlertSummary(
                channel="log", severity="high",
                threat_score=72, dispatched_at=T0,
            )
        ],
    )
    out = detail.model_dump(mode="json")
    assert out["fingerprint"]["country_iso"] == "CN"
    assert out["ttps"][0]["technique_id"] == "T1110.001"
    assert out["events"]["preview"][0]["payload"]["username"] == "root"
    assert out["alerts"][0]["channel"] == "log"


def test_events_page_serialises_payload_dicts() -> None:
    page = EventsPage(
        total=1,
        items=[
            EventPayload(
                id=EID, event_type="HTTP_REQUEST", service="http",
                timestamp=T0, payload={"uri": "/.env"},
            )
        ],
    )
    out = page.model_dump(mode="json")
    assert out["total"] == 1
    assert out["items"][0]["payload"]["uri"] == "/.env"


def test_overview_stats_accepts_documented_shape() -> None:
    o = OverviewStats(
        period_days=7,
        total_sessions=120,
        unique_ips=33,
        sessions_by_service={"ssh": 80, "http": 30, "ftp": 10},
        severity_breakdown={"low": 50, "medium": 40, "high": 20, "critical": 10},
        top_countries=[{"iso": "RU", "count": 50}],
        top_ttps=[{"technique_id": "T1110.001", "count": 60}],
        avg_threat_score=41.2,
    )
    assert o.model_dump()["avg_threat_score"] == 41.2


def test_ttp_and_geo_and_timeline_models() -> None:
    t = TTPStat(
        technique_id="T1190",
        name="Exploit Public-Facing Application",
        tactic="Initial Access",
        count=14,
        pct=18.4,
    )
    g = GeoStat(country_iso="DE", country_name="Germany", count=5, pct=4.1)
    tl = TimelineBucket(bucket=T0, count=12, avg_score=44.0)
    assert t.pct == 18.4
    assert g.country_iso == "DE"
    assert tl.count == 12


def test_health_and_report_job_models() -> None:
    h = HealthOut(status="ok", version="0.1.0", db="ok", redis="ok")
    r = ReportJobOut(report_id=SID)
    assert h.status == "ok"
    assert r.status == "queued"
    assert r.estimated_seconds == 5
