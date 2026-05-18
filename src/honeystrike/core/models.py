"""SQLAlchemy 2.0 ORM models. Schema lives in Alembic migrations; this file
mirrors the table structure so we can query/insert with the ORM.

Only the columns honeypot services touch are mapped here for Phase 2. The
remaining tables (fingerprints, ttp_matches, reports, alerts, ml_anomaly_scores,
geo_cache) get full mappings as their workers come online.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    Integer,
    Numeric,
    SmallInteger,
    String,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import CHAR, DOUBLE_PRECISION, INET, JSONB, UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


# All persisted timestamps are TIMESTAMPTZ at the SQL level; mirror that
# here so SQLAlchemy emits the right type for parameterised UPDATEs.
_TS = DateTime(timezone=True)


class Session(Base):
    __tablename__ = "sessions"
    __table_args__ = (
        CheckConstraint(
            "service IN ('ssh','http','ftp','rdp','tls')", name="ck_service"
        ),
        CheckConstraint(
            "state IN ('OPEN','CLOSED','TIMEOUT')", name="ck_state"
        ),
        CheckConstraint(
            "threat_score BETWEEN 0 AND 100", name="ck_threat_score"
        ),
        CheckConstraint(
            "severity IN ('low','medium','high','critical')", name="ck_severity"
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()")
    )
    src_ip: Mapped[str] = mapped_column(INET, nullable=False)
    src_port: Mapped[int] = mapped_column(Integer, nullable=False)
    service: Mapped[str] = mapped_column(String(8), nullable=False)
    state: Mapped[str] = mapped_column(
        String(16), nullable=False, server_default=text("'OPEN'")
    )
    threat_score: Mapped[int] = mapped_column(
        SmallInteger, nullable=False, server_default=text("0")
    )
    severity: Mapped[str] = mapped_column(
        String(8), nullable=False, server_default=text("'low'")
    )
    duration_ms: Mapped[int | None] = mapped_column(Integer)
    event_count: Mapped[int] = mapped_column(
        Integer, nullable=False, server_default=text("0")
    )
    started_at: Mapped[datetime] = mapped_column(
        _TS, nullable=False, server_default=func.now()
    )
    ended_at: Mapped[datetime | None] = mapped_column(_TS)
    created_at: Mapped[datetime] = mapped_column(
        _TS, nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        _TS, nullable=False, server_default=func.now()
    )


class Event(Base):
    __tablename__ = "events"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()")
    )
    session_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("sessions.id", ondelete="CASCADE"),
        nullable=False,
    )
    event_type: Mapped[str] = mapped_column(String(32), nullable=False)
    service: Mapped[str] = mapped_column(String(8), nullable=False)
    src_ip: Mapped[str] = mapped_column(INET, nullable=False)
    payload: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, server_default=text("'{}'::jsonb")
    )
    schema_ver: Mapped[str] = mapped_column(
        String(8), nullable=False, server_default=text("'1.0'")
    )
    ts: Mapped[datetime] = mapped_column(
        _TS, nullable=False, server_default=func.now()
    )


class Fingerprint(Base):
    __tablename__ = "fingerprints"
    __table_args__ = (
        CheckConstraint(
            "abuse_score IS NULL OR abuse_score BETWEEN 0 AND 100",
            name="ck_fingerprint_abuse_score",
        ),
        CheckConstraint(
            "timing_pattern IS NULL OR timing_pattern IN "
            "('burst','slow','random','unknown')",
            name="ck_fingerprint_timing_pattern",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()")
    )
    session_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("sessions.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
    )
    ip: Mapped[str] = mapped_column(INET, nullable=False)
    country_iso: Mapped[str | None] = mapped_column(CHAR(2))
    country_name: Mapped[str | None] = mapped_column(String(100))
    city: Mapped[str | None] = mapped_column(String(100))
    lat: Mapped[float | None] = mapped_column(DOUBLE_PRECISION)
    lon: Mapped[float | None] = mapped_column(DOUBLE_PRECISION)
    asn: Mapped[int | None] = mapped_column(Integer)
    org: Mapped[str | None] = mapped_column(String(200))
    abuse_score: Mapped[int | None] = mapped_column(SmallInteger)
    abuse_reports: Mapped[int | None] = mapped_column(Integer)
    tool_signatures: Mapped[list[dict[str, Any]]] = mapped_column(
        JSONB, nullable=False, server_default=text("'[]'::jsonb")
    )
    ja3_hash: Mapped[str | None] = mapped_column(CHAR(32))
    timing_pattern: Mapped[str | None] = mapped_column(String(16))
    attempt_rate_rpm: Mapped[float | None] = mapped_column(Numeric(8, 2))
    raw_enrichment: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, server_default=text("'{}'::jsonb")
    )
    created_at: Mapped[datetime] = mapped_column(
        _TS, nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        _TS, nullable=False, server_default=func.now()
    )


class TTPMatch(Base):
    __tablename__ = "ttp_matches"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()")
    )
    session_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("sessions.id", ondelete="CASCADE"),
        nullable=False,
    )
    technique_id: Mapped[str] = mapped_column(String(16), nullable=False)
    technique_name: Mapped[str] = mapped_column(String(200), nullable=False)
    tactic: Mapped[str] = mapped_column(String(100), nullable=False)
    confidence: Mapped[float] = mapped_column(Numeric(4, 3), nullable=False)
    trigger_event_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("events.id", ondelete="SET NULL")
    )
    matched_at: Mapped[datetime] = mapped_column(
        _TS, nullable=False, server_default=func.now()
    )


class MLAnomalyScore(Base):
    __tablename__ = "ml_anomaly_scores"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()")
    )
    session_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("sessions.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
    )
    anomaly_score: Mapped[float] = mapped_column(Numeric(6, 4), nullable=False)
    is_anomaly: Mapped[bool] = mapped_column(nullable=False)
    model_version: Mapped[str] = mapped_column(String(32), nullable=False)
    features: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, server_default=text("'{}'::jsonb")
    )
    scored_at: Mapped[datetime] = mapped_column(
        _TS, nullable=False, server_default=func.now()
    )


class Report(Base):
    __tablename__ = "reports"
    __table_args__ = (
        CheckConstraint("format IN ('pdf','html')", name="ck_report_format"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()")
    )
    session_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("sessions.id", ondelete="CASCADE"),
        nullable=False,
    )
    format: Mapped[str] = mapped_column(String(8), nullable=False)
    file_path: Mapped[str | None] = mapped_column()      # NULL once expired
    file_size_bytes: Mapped[int | None] = mapped_column(Integer)
    threat_score_snapshot: Mapped[int] = mapped_column(SmallInteger, nullable=False)
    generated_at: Mapped[datetime] = mapped_column(
        _TS, nullable=False, server_default=func.now()
    )
    expires_at: Mapped[datetime] = mapped_column(_TS, nullable=False)


class Alert(Base):
    __tablename__ = "alerts"
    __table_args__ = (
        CheckConstraint(
            "channel IN ('telegram','email','slack','log')", name="ck_alert_channel"
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()")
    )
    session_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("sessions.id", ondelete="CASCADE"),
        nullable=False,
    )
    channel: Mapped[str] = mapped_column(String(16), nullable=False)
    severity: Mapped[str] = mapped_column(String(8), nullable=False)
    threat_score: Mapped[int] = mapped_column(SmallInteger, nullable=False)
    payload: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, server_default=text("'{}'::jsonb")
    )
    dispatched_at: Mapped[datetime] = mapped_column(
        _TS, nullable=False, server_default=func.now()
    )
    acknowledged_at: Mapped[datetime | None] = mapped_column(_TS)


class User(Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()")
    )
    username: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    password_hash: Mapped[str] = mapped_column(nullable=False)
    is_active: Mapped[bool] = mapped_column(
        nullable=False, server_default=text("TRUE")
    )
    last_login_at: Mapped[datetime | None] = mapped_column(_TS)
    created_at: Mapped[datetime] = mapped_column(
        _TS, nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        _TS, nullable=False, server_default=func.now()
    )
