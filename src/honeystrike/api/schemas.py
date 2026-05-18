"""Pydantic response models for the dashboard API.

Mirrors docs/02_API_Contracts.md. Models are response-side only — request-side
inputs live next to the routers that consume them.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class _OrmBase(BaseModel):
    model_config = ConfigDict(from_attributes=True)


# ---------------------------------------------------------------------------
# Sessions
# ---------------------------------------------------------------------------

class SessionListItem(BaseModel):
    id: uuid.UUID
    src_ip: str
    service: str
    state: str
    threat_score: int
    severity: str
    country_iso: str | None = None
    started_at: datetime
    ended_at: datetime | None = None
    duration_ms: int | None = None
    ttp_count: int = 0


class SessionsPage(BaseModel):
    total: int
    page: int
    limit: int
    items: list[SessionListItem]


class ToolSignaturePayload(BaseModel):
    name: str
    confidence: float


class FingerprintPayload(BaseModel):
    country_iso: str | None = None
    country_name: str | None = None
    city: str | None = None
    lat: float | None = None
    lon: float | None = None
    asn: int | None = None
    org: str | None = None
    abuse_score: int | None = None
    tool_signatures: list[ToolSignaturePayload] = Field(default_factory=list)
    ja3_hash: str | None = None
    timing_pattern: str | None = None
    attempt_rate_rpm: float | None = None


class TTPMatchPayload(BaseModel):
    technique_id: str
    technique_name: str
    tactic: str
    confidence: float
    matched_at: datetime


class EventPayload(BaseModel):
    id: uuid.UUID
    event_type: str
    service: str
    timestamp: datetime
    payload: dict[str, Any]


class EventPreview(BaseModel):
    total: int
    preview: list[EventPayload]


class AlertSummary(BaseModel):
    channel: str
    severity: str
    threat_score: int
    dispatched_at: datetime


class SessionDetail(BaseModel):
    id: uuid.UUID
    src_ip: str
    src_port: int
    service: str
    state: str
    threat_score: int
    severity: str
    started_at: datetime
    ended_at: datetime | None = None
    duration_ms: int | None = None
    event_count: int = 0
    fingerprint: FingerprintPayload | None = None
    ttps: list[TTPMatchPayload] = Field(default_factory=list)
    events: EventPreview
    alerts: list[AlertSummary] = Field(default_factory=list)


class EventsPage(BaseModel):
    total: int
    items: list[EventPayload]


class ReportJobOut(BaseModel):
    report_id: uuid.UUID
    status: str = "queued"
    estimated_seconds: int = 5


# ---------------------------------------------------------------------------
# Analytics
# ---------------------------------------------------------------------------

class OverviewStats(BaseModel):
    period_days: int
    total_sessions: int
    unique_ips: int
    sessions_by_service: dict[str, int]
    severity_breakdown: dict[str, int]
    top_countries: list[dict[str, Any]]
    top_ttps: list[dict[str, Any]]
    avg_threat_score: float


class TTPStat(BaseModel):
    technique_id: str
    name: str
    tactic: str
    count: int
    pct: float


class GeoStat(BaseModel):
    country_iso: str | None
    country_name: str | None
    count: int
    pct: float


class TimelineBucket(BaseModel):
    bucket: datetime
    count: int
    avg_score: float


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------

class HealthOut(BaseModel):
    status: str
    version: str
    db: str
    redis: str
