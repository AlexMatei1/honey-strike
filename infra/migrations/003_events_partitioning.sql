-- HoneyStrike — events table → monthly RANGE partitioning
--
-- Operational migration, NOT part of the regular Alembic chain. Run by hand
-- once daily event volume consistently exceeds 500k (`docs/05`).
--
-- Pre-flight: take a fresh pg_dump, schedule a maintenance window, and warn
-- every honeypot that they'll see brief INSERT pauses (~minutes per million
-- rows in the data move).
--
-- Usage:
--   docker exec -i honeystrike-db psql -U honeystrike -d honeystrike \
--     < infra/migrations/003_events_partitioning.sql
--
-- After this runs, future-month partitions are created by
-- `python -m honeystrike.workers.maintenance.partition_events`.

BEGIN;

-- 1. Park the existing table.
ALTER TABLE events RENAME TO events_legacy;

-- 2. Create the partitioned parent with the same column shape + indexes.
CREATE TABLE events (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id    uuid NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    event_type    varchar(32) NOT NULL,
    service       varchar(8)  NOT NULL,
    src_ip        inet        NOT NULL,
    payload       jsonb       NOT NULL DEFAULT '{}'::jsonb,
    schema_ver    varchar(8)  NOT NULL DEFAULT '1.0',
    ts            timestamptz NOT NULL DEFAULT now()
) PARTITION BY RANGE (ts);

-- 3. Indexes mirror the legacy table. Re-applied per-partition automatically.
CREATE INDEX idx_events_session_id    ON events USING btree (session_id);
CREATE INDEX idx_events_ts            ON events USING btree (ts DESC);
CREATE INDEX idx_events_type_ts       ON events USING btree (event_type, ts DESC);
CREATE INDEX idx_events_payload_gin   ON events USING gin   (payload);

ALTER TABLE events SET (
    autovacuum_vacuum_scale_factor  = 0.1,
    autovacuum_analyze_scale_factor = 0.05
);

-- 4. Bootstrap partitions: a default catches anything outside the bracket,
-- and one partition per month from 6 months back to 3 months ahead. Operator
-- can also call partition_events.create_future_partitions() after this.
DO $$
DECLARE
    start_month date := date_trunc('month', now() - interval '6 months')::date;
    end_month   date := date_trunc('month', now() + interval '3 months')::date;
    m           date;
    p_name      text;
BEGIN
    m := start_month;
    WHILE m <= end_month LOOP
        p_name := format('events_%s', to_char(m, 'YYYY_MM'));
        EXECUTE format(
            'CREATE TABLE IF NOT EXISTS %I PARTITION OF events FOR VALUES FROM (%L) TO (%L)',
            p_name, m, m + interval '1 month'
        );
        m := m + interval '1 month';
    END LOOP;
    EXECUTE 'CREATE TABLE IF NOT EXISTS events_default PARTITION OF events DEFAULT';
END $$;

-- 5. Move the data. For a multi-million row legacy table consider running
-- this in batches via the operator script instead.
INSERT INTO events
    (id, session_id, event_type, service, src_ip, payload, schema_ver, ts)
SELECT id, session_id, event_type, service, src_ip, payload, schema_ver, ts
FROM events_legacy;

-- 6. Sanity-check the row count before dropping the legacy table.
DO $$
DECLARE
    legacy_count bigint;
    parent_count bigint;
BEGIN
    SELECT count(*) INTO legacy_count FROM events_legacy;
    SELECT count(*) INTO parent_count FROM events;
    IF legacy_count <> parent_count THEN
        RAISE EXCEPTION
            'events partition migration aborted: legacy=% parent=%',
            legacy_count, parent_count;
    END IF;
END $$;

-- 7. Drop the parked table. Cascade isn't needed — sessions FK now points at
-- the partitioned parent.
DROP TABLE events_legacy;

COMMIT;
