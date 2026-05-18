"""initial schema — sessions, events, fingerprints, ttp_matches, reports, alerts, geo_cache, ml_anomaly_scores, users

Revision ID: 001_initial
Revises:
Create Date: 2026-05-16

Mirrors `docs/04_PostgreSQL_Schema.sql` + `docs/05_Indexes_and_Partitioning.sql`,
with two intentional deviations:

  1. Adds a `users` table for dashboard authentication (argon2 hashes).
     The schema doc has been patched to match.
  2. `reports.file_path` is NULLABLE so the retention cron can clear paths
     after file expiry (per `docs/06_Data_Retention_Matrix.md`).

NOTE: every op.execute() contains EXACTLY ONE SQL statement. The asyncpg
driver cannot prepare multi-command statements, so DDL + COMMENT are split.
"""
from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "001_initial"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute('CREATE EXTENSION IF NOT EXISTS "pgcrypto"')
    op.execute('CREATE EXTENSION IF NOT EXISTS "pg_trgm"')

    # -------------------------------------------------------------------------
    # users — dashboard authentication
    # -------------------------------------------------------------------------
    op.execute("""
        CREATE TABLE users (
            id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
            username        VARCHAR(64) NOT NULL UNIQUE,
            password_hash   TEXT        NOT NULL,
            is_active       BOOLEAN     NOT NULL DEFAULT TRUE,
            last_login_at   TIMESTAMPTZ,
            created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    """)
    op.execute(
        "COMMENT ON TABLE users IS "
        "'Dashboard operator accounts. Seeded from ADMIN_USERNAME/ADMIN_PASSWORD on first boot.'"
    )

    # -------------------------------------------------------------------------
    # sessions
    # -------------------------------------------------------------------------
    op.execute("""
        CREATE TABLE sessions (
            id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
            src_ip          INET        NOT NULL,
            src_port        INTEGER     NOT NULL,
            service         VARCHAR(8)  NOT NULL CHECK (service IN ('ssh','http','ftp','rdp')),
            state           VARCHAR(16) NOT NULL DEFAULT 'OPEN'
                                        CHECK (state IN ('OPEN','CLOSED','TIMEOUT')),
            threat_score    SMALLINT    NOT NULL DEFAULT 0 CHECK (threat_score BETWEEN 0 AND 100),
            severity        VARCHAR(8)  NOT NULL DEFAULT 'low'
                                        CHECK (severity IN ('low','medium','high','critical')),
            duration_ms     INTEGER,
            event_count     INTEGER     NOT NULL DEFAULT 0,
            started_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            ended_at        TIMESTAMPTZ,
            created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    """)
    op.execute(
        "COMMENT ON TABLE sessions IS "
        "'One row per inbound attacker connection lifecycle'"
    )

    # -------------------------------------------------------------------------
    # events  (append-only)
    # -------------------------------------------------------------------------
    op.execute("""
        CREATE TABLE events (
            id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
            session_id  UUID        NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
            event_type  VARCHAR(32) NOT NULL,
            service     VARCHAR(8)  NOT NULL,
            src_ip      INET        NOT NULL,
            payload     JSONB       NOT NULL DEFAULT '{}',
            schema_ver  VARCHAR(8)  NOT NULL DEFAULT '1.0',
            ts          TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    """)
    op.execute(
        "COMMENT ON TABLE events IS "
        "'Immutable raw event log. Never update or delete rows.'"
    )

    # -------------------------------------------------------------------------
    # fingerprints
    # -------------------------------------------------------------------------
    op.execute("""
        CREATE TABLE fingerprints (
            id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
            session_id      UUID        NOT NULL UNIQUE REFERENCES sessions(id) ON DELETE CASCADE,
            ip              INET        NOT NULL,
            country_iso     CHAR(2),
            country_name    VARCHAR(100),
            city            VARCHAR(100),
            lat             DOUBLE PRECISION,
            lon             DOUBLE PRECISION,
            asn             INTEGER,
            org             VARCHAR(200),
            abuse_score     SMALLINT    CHECK (abuse_score BETWEEN 0 AND 100),
            abuse_reports   INTEGER,
            tool_signatures JSONB       NOT NULL DEFAULT '[]',
            ja3_hash        CHAR(32),
            timing_pattern  VARCHAR(16) CHECK (timing_pattern IN ('burst','slow','random','unknown')),
            attempt_rate_rpm NUMERIC(8,2),
            raw_enrichment  JSONB       NOT NULL DEFAULT '{}',
            created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    """)
    op.execute(
        "COMMENT ON TABLE fingerprints IS 'Enriched attacker profile — one per session'"
    )

    # -------------------------------------------------------------------------
    # ttp_matches
    # -------------------------------------------------------------------------
    op.execute("""
        CREATE TABLE ttp_matches (
            id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
            session_id      UUID        NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
            technique_id    VARCHAR(16) NOT NULL,
            technique_name  VARCHAR(200) NOT NULL,
            tactic          VARCHAR(100) NOT NULL,
            confidence      NUMERIC(4,3) NOT NULL CHECK (confidence BETWEEN 0 AND 1),
            trigger_event_id UUID       REFERENCES events(id) ON DELETE SET NULL,
            matched_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    """)
    op.execute(
        "COMMENT ON TABLE ttp_matches IS 'MITRE ATT&CK technique matches per session'"
    )

    # -------------------------------------------------------------------------
    # reports — file_path nullable per retention policy
    # -------------------------------------------------------------------------
    op.execute("""
        CREATE TABLE reports (
            id                    UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
            session_id            UUID        NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
            format                VARCHAR(8)  NOT NULL CHECK (format IN ('pdf','html')),
            file_path             TEXT,
            file_size_bytes       INTEGER,
            threat_score_snapshot SMALLINT    NOT NULL,
            generated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            expires_at            TIMESTAMPTZ NOT NULL DEFAULT (NOW() + INTERVAL '180 days')
        )
    """)
    op.execute(
        "COMMENT ON TABLE reports IS 'Metadata for generated threat intel reports'"
    )

    # -------------------------------------------------------------------------
    # alerts
    # -------------------------------------------------------------------------
    op.execute("""
        CREATE TABLE alerts (
            id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
            session_id      UUID        NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
            channel         VARCHAR(16) NOT NULL CHECK (channel IN ('telegram','email','slack')),
            severity        VARCHAR(8)  NOT NULL,
            threat_score    SMALLINT    NOT NULL,
            payload         JSONB       NOT NULL DEFAULT '{}',
            dispatched_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            acknowledged_at TIMESTAMPTZ
        )
    """)
    op.execute(
        "COMMENT ON TABLE alerts IS 'Audit log of all outbound alert dispatches'"
    )

    # -------------------------------------------------------------------------
    # geo_cache
    # -------------------------------------------------------------------------
    op.execute("""
        CREATE TABLE geo_cache (
            ip          INET        PRIMARY KEY,
            country_iso CHAR(2),
            city        VARCHAR(100),
            lat         DOUBLE PRECISION,
            lon         DOUBLE PRECISION,
            asn         INTEGER,
            org         VARCHAR(200),
            cached_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            expires_at  TIMESTAMPTZ NOT NULL DEFAULT (NOW() + INTERVAL '24 hours')
        )
    """)

    # -------------------------------------------------------------------------
    # ml_anomaly_scores (stretch)
    # -------------------------------------------------------------------------
    op.execute("""
        CREATE TABLE ml_anomaly_scores (
            id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
            session_id      UUID        NOT NULL UNIQUE REFERENCES sessions(id) ON DELETE CASCADE,
            anomaly_score   NUMERIC(6,4) NOT NULL,
            is_anomaly      BOOLEAN     NOT NULL,
            model_version   VARCHAR(32) NOT NULL,
            features        JSONB       NOT NULL DEFAULT '{}',
            scored_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    """)

    # -------------------------------------------------------------------------
    # updated_at trigger
    # -------------------------------------------------------------------------
    op.execute("""
        CREATE OR REPLACE FUNCTION set_updated_at()
        RETURNS TRIGGER LANGUAGE plpgsql AS $$
        BEGIN NEW.updated_at = NOW(); RETURN NEW; END;
        $$
    """)
    for table in ("sessions", "fingerprints", "users"):
        op.execute(f"""
            CREATE TRIGGER trg_{table}_updated_at
                BEFORE UPDATE ON {table}
                FOR EACH ROW EXECUTE FUNCTION set_updated_at()
        """)

    # =========================================================================
    # Indexes — mirrors docs/05_Indexes_and_Partitioning.sql
    # =========================================================================

    # sessions
    op.execute("CREATE INDEX idx_sessions_src_ip ON sessions USING btree (src_ip)")
    op.execute("CREATE INDEX idx_sessions_started_at ON sessions USING btree (started_at DESC)")
    op.execute("CREATE INDEX idx_sessions_threat_score ON sessions USING btree (threat_score DESC)")
    op.execute("CREATE INDEX idx_sessions_service_state ON sessions USING btree (service, state)")
    op.execute("CREATE INDEX idx_sessions_severity ON sessions USING btree (severity)")
    op.execute("""
        CREATE INDEX idx_sessions_open ON sessions USING btree (started_at DESC)
        WHERE state = 'OPEN'
    """)

    # events
    op.execute("CREATE INDEX idx_events_session_id ON events USING btree (session_id)")
    op.execute("CREATE INDEX idx_events_ts ON events USING btree (ts DESC)")
    op.execute("CREATE INDEX idx_events_type_ts ON events USING btree (event_type, ts DESC)")
    op.execute("CREATE INDEX idx_events_payload_gin ON events USING gin (payload)")

    # fingerprints
    op.execute("CREATE INDEX idx_fingerprints_ip ON fingerprints USING btree (ip)")
    op.execute("CREATE INDEX idx_fingerprints_country ON fingerprints USING btree (country_iso)")
    op.execute("CREATE INDEX idx_fingerprints_abuse_score ON fingerprints USING btree (abuse_score DESC NULLS LAST)")
    op.execute("CREATE INDEX idx_fingerprints_asn ON fingerprints USING btree (asn)")

    # ttp_matches
    op.execute("CREATE INDEX idx_ttp_matches_session_id ON ttp_matches USING btree (session_id)")
    op.execute("CREATE INDEX idx_ttp_matches_technique_id ON ttp_matches USING btree (technique_id)")
    op.execute("CREATE INDEX idx_ttp_matches_tactic ON ttp_matches USING btree (tactic)")
    op.execute("CREATE INDEX idx_ttp_matches_matched_at ON ttp_matches USING btree (matched_at DESC)")

    # reports
    op.execute("CREATE INDEX idx_reports_session_id ON reports USING btree (session_id)")
    op.execute("CREATE INDEX idx_reports_generated_at ON reports USING btree (generated_at DESC)")
    op.execute("CREATE INDEX idx_reports_expires_at ON reports USING btree (expires_at)")

    # alerts
    op.execute("CREATE INDEX idx_alerts_session_id ON alerts USING btree (session_id)")
    op.execute("CREATE INDEX idx_alerts_dispatched_at ON alerts USING btree (dispatched_at DESC)")
    op.execute("CREATE INDEX idx_alerts_severity ON alerts USING btree (severity)")

    # autovacuum tuning
    op.execute("""
        ALTER TABLE events SET (
            autovacuum_vacuum_scale_factor = 0.1,
            autovacuum_analyze_scale_factor = 0.05
        )
    """)
    op.execute("""
        ALTER TABLE sessions SET (
            autovacuum_vacuum_scale_factor = 0.02,
            autovacuum_analyze_scale_factor = 0.01
        )
    """)


def downgrade() -> None:
    for table in (
        "ml_anomaly_scores",
        "geo_cache",
        "alerts",
        "reports",
        "ttp_matches",
        "fingerprints",
        "events",
        "sessions",
        "users",
    ):
        op.execute(f"DROP TABLE IF EXISTS {table} CASCADE")
    op.execute("DROP FUNCTION IF EXISTS set_updated_at() CASCADE")
