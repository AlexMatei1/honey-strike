-- HoneyStrike — PostgreSQL 16 Production Schema
-- Run via: alembic upgrade head
-- All timestamps: UTC. All UUIDs: gen_random_uuid().

CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";

-- ============================================================
-- users  (dashboard authentication — seeded from ADMIN_USERNAME/ADMIN_PASSWORD)
-- ============================================================
CREATE TABLE users (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    username        VARCHAR(64) NOT NULL UNIQUE,
    password_hash   TEXT        NOT NULL,
    is_active       BOOLEAN     NOT NULL DEFAULT TRUE,
    last_login_at   TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

COMMENT ON TABLE users IS 'Dashboard operator accounts. Seeded from ADMIN_USERNAME/ADMIN_PASSWORD on first boot.';

-- ============================================================
-- sessions
-- ============================================================
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
);

COMMENT ON TABLE sessions IS 'One row per inbound attacker connection lifecycle';

-- ============================================================
-- events  (append-only — never UPDATE or DELETE)
-- ============================================================
CREATE TABLE events (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id  UUID        NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    event_type  VARCHAR(32) NOT NULL,
    service     VARCHAR(8)  NOT NULL,
    src_ip      INET        NOT NULL,
    payload     JSONB       NOT NULL DEFAULT '{}',
    schema_ver  VARCHAR(8)  NOT NULL DEFAULT '1.0',
    ts          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

COMMENT ON TABLE events IS 'Immutable raw event log. Never update or delete rows.';

-- ============================================================
-- fingerprints
-- ============================================================
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
);

COMMENT ON TABLE fingerprints IS 'Enriched attacker profile — one per session';

-- ============================================================
-- ttp_matches
-- ============================================================
CREATE TABLE ttp_matches (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id      UUID        NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    technique_id    VARCHAR(16) NOT NULL,
    technique_name  VARCHAR(200) NOT NULL,
    tactic          VARCHAR(100) NOT NULL,
    confidence      NUMERIC(4,3) NOT NULL CHECK (confidence BETWEEN 0 AND 1),
    trigger_event_id UUID       REFERENCES events(id) ON DELETE SET NULL,
    matched_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

COMMENT ON TABLE ttp_matches IS 'MITRE ATT&CK technique matches per session';

-- ============================================================
-- reports
-- ============================================================
CREATE TABLE reports (
    id                    UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id            UUID        NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    format                VARCHAR(8)  NOT NULL CHECK (format IN ('pdf','html')),
    -- NULLABLE: the retention cron (docs/06) nulls file_path after the file is
    -- deleted on disk; metadata row is retained for audit.
    file_path             TEXT,
    file_size_bytes       INTEGER,
    threat_score_snapshot SMALLINT    NOT NULL,
    generated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at            TIMESTAMPTZ NOT NULL DEFAULT (NOW() + INTERVAL '180 days')
);

COMMENT ON TABLE reports IS 'Metadata for generated threat intel reports';

-- ============================================================
-- alerts
-- ============================================================
CREATE TABLE alerts (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id      UUID        NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    channel         VARCHAR(16) NOT NULL CHECK (channel IN ('telegram','email','slack')),
    severity        VARCHAR(8)  NOT NULL,
    threat_score    SMALLINT    NOT NULL,
    payload         JSONB       NOT NULL DEFAULT '{}',
    dispatched_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    acknowledged_at TIMESTAMPTZ
);

COMMENT ON TABLE alerts IS 'Audit log of all outbound alert dispatches';

-- ============================================================
-- geo_cache  (mirrors Redis geo cache for analytics queries)
-- ============================================================
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
);

-- ============================================================
-- ml_anomaly_scores  (stretch goal)
-- ============================================================
CREATE TABLE ml_anomaly_scores (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id      UUID        NOT NULL UNIQUE REFERENCES sessions(id) ON DELETE CASCADE,
    anomaly_score   NUMERIC(6,4) NOT NULL,
    is_anomaly      BOOLEAN     NOT NULL,
    model_version   VARCHAR(32) NOT NULL,
    features        JSONB       NOT NULL DEFAULT '{}',
    scored_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ============================================================
-- updated_at trigger (applied to sessions + fingerprints + users)
-- ============================================================
CREATE OR REPLACE FUNCTION set_updated_at()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN NEW.updated_at = NOW(); RETURN NEW; END;
$$;

CREATE TRIGGER trg_sessions_updated_at
    BEFORE UPDATE ON sessions
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TRIGGER trg_fingerprints_updated_at
    BEFORE UPDATE ON fingerprints
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TRIGGER trg_users_updated_at
    BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();
