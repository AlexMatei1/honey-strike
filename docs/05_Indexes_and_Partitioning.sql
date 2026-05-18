-- HoneyStrike — Indexes and Partitioning Strategy
-- Apply after 04_PostgreSQL_Schema.sql

-- ============================================================
-- sessions indexes
-- ============================================================
CREATE INDEX idx_sessions_src_ip
    ON sessions USING btree (src_ip);

CREATE INDEX idx_sessions_started_at
    ON sessions USING btree (started_at DESC);

CREATE INDEX idx_sessions_threat_score
    ON sessions USING btree (threat_score DESC);

CREATE INDEX idx_sessions_service_state
    ON sessions USING btree (service, state);

CREATE INDEX idx_sessions_severity
    ON sessions USING btree (severity);

-- Partial index for open sessions (small set, frequently queried)
CREATE INDEX idx_sessions_open
    ON sessions USING btree (started_at DESC)
    WHERE state = 'OPEN';

-- ============================================================
-- events indexes
-- ============================================================
CREATE INDEX idx_events_session_id
    ON events USING btree (session_id);

CREATE INDEX idx_events_ts
    ON events USING btree (ts DESC);

CREATE INDEX idx_events_type_ts
    ON events USING btree (event_type, ts DESC);

-- JSONB GIN index for payload queries (e.g. search by username)
CREATE INDEX idx_events_payload_gin
    ON events USING gin (payload);

-- ============================================================
-- fingerprints indexes
-- ============================================================
CREATE INDEX idx_fingerprints_ip
    ON fingerprints USING btree (ip);

CREATE INDEX idx_fingerprints_country
    ON fingerprints USING btree (country_iso);

CREATE INDEX idx_fingerprints_abuse_score
    ON fingerprints USING btree (abuse_score DESC NULLS LAST);

CREATE INDEX idx_fingerprints_asn
    ON fingerprints USING btree (asn);

-- ============================================================
-- ttp_matches indexes
-- ============================================================
CREATE INDEX idx_ttp_matches_session_id
    ON ttp_matches USING btree (session_id);

CREATE INDEX idx_ttp_matches_technique_id
    ON ttp_matches USING btree (technique_id);

CREATE INDEX idx_ttp_matches_tactic
    ON ttp_matches USING btree (tactic);

CREATE INDEX idx_ttp_matches_matched_at
    ON ttp_matches USING btree (matched_at DESC);

-- ============================================================
-- reports indexes
-- ============================================================
CREATE INDEX idx_reports_session_id
    ON reports USING btree (session_id);

CREATE INDEX idx_reports_generated_at
    ON reports USING btree (generated_at DESC);

-- Plain index on expires_at. Note: a partial `WHERE expires_at < NOW()` index
-- is NOT allowed in PostgreSQL (NOW() is not IMMUTABLE in an index predicate);
-- the cleanup cron filters on expires_at < CURRENT_TIMESTAMP at query time.
CREATE INDEX idx_reports_expires_at
    ON reports USING btree (expires_at);

-- ============================================================
-- alerts indexes
-- ============================================================
CREATE INDEX idx_alerts_session_id
    ON alerts USING btree (session_id);

CREATE INDEX idx_alerts_dispatched_at
    ON alerts USING btree (dispatched_at DESC);

CREATE INDEX idx_alerts_severity
    ON alerts USING btree (severity);

-- ============================================================
-- PARTITIONING STRATEGY (future — activate at ~1M events/month)
-- ============================================================
-- The events table becomes the highest-volume table.
-- When daily event count consistently exceeds 500k, migrate to
-- RANGE partitioning by month on the ts column.
--
-- Migration plan (do not run now):
--
-- 1. Rename existing table:
--    ALTER TABLE events RENAME TO events_legacy;
--
-- 2. Create partitioned parent:
--    CREATE TABLE events (LIKE events_legacy INCLUDING ALL)
--    PARTITION BY RANGE (ts);
--
-- 3. Create monthly partitions (automate with pg_partman):
--    CREATE TABLE events_2026_05 PARTITION OF events
--    FOR VALUES FROM ('2026-05-01') TO ('2026-06-01');
--
-- 4. Migrate data:
--    INSERT INTO events SELECT * FROM events_legacy;
--
-- 5. Drop legacy:
--    DROP TABLE events_legacy;
--
-- Recommended: use pg_partman extension + background maintenance worker.
-- Partition retention: detach and drop partitions > 90 days (events archival).

-- ============================================================
-- VACUUM and ANALYZE settings
-- ============================================================
-- events is append-only — aggressive autovacuum not needed
ALTER TABLE events SET (
    autovacuum_vacuum_scale_factor = 0.1,
    autovacuum_analyze_scale_factor = 0.05
);

-- sessions is frequently updated — more aggressive
ALTER TABLE sessions SET (
    autovacuum_vacuum_scale_factor = 0.02,
    autovacuum_analyze_scale_factor = 0.01
);
