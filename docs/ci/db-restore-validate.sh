#!/bin/bash
# HoneyStrike — Database Backup Restore Validation
# Run: ./ci/db-restore-validate.sh
# Used in: CI pipeline (weekly) and manual DR drills

set -euo pipefail

BACKUP_DIR="${BACKUP_DIR:-/backups/daily}"
DB_CONTAINER="${DB_CONTAINER:-honeystrike-db}"
DB_USER="${DB_USER:-honeystrike}"
DRILL_DB="honeystrike_drill_$$"
LOG_PREFIX="[db-restore-validate]"

log()  { echo "${LOG_PREFIX} $*"; }
fail() { echo "${LOG_PREFIX} FAIL: $*" >&2; exit 1; }

# ── 1. Find latest backup ─────────────────────────────────────────────────────
log "Scanning ${BACKUP_DIR} for latest backup..."
LATEST=$(ls -t "${BACKUP_DIR}"/*.sql.gz 2>/dev/null | head -1)
[[ -z "${LATEST}" ]] && fail "No backup files found in ${BACKUP_DIR}"
log "Using backup: ${LATEST}"

BACKUP_AGE_H=$(( ($(date +%s) - $(stat -c %Y "${LATEST}")) / 3600 ))
log "Backup age: ${BACKUP_AGE_H} hours"
if [[ ${BACKUP_AGE_H} -gt 26 ]]; then
  fail "Backup is older than 26 hours (expected daily). Possible backup failure."
fi

# ── 2. Verify backup file integrity ──────────────────────────────────────────
log "Verifying gzip integrity..."
gunzip -t "${LATEST}" || fail "Backup file is corrupt (gzip test failed)"
log "Gzip integrity: OK"

BACKUP_LINES=$(gunzip -c "${LATEST}" | wc -l)
log "Backup SQL line count: ${BACKUP_LINES}"
[[ ${BACKUP_LINES} -lt 100 ]] && fail "Backup file suspiciously small (${BACKUP_LINES} lines)"

# ── 3. Create isolated drill database ─────────────────────────────────────────
log "Creating drill database: ${DRILL_DB}"
docker exec "${DB_CONTAINER}" psql -U postgres \
  -c "DROP DATABASE IF EXISTS ${DRILL_DB};" 2>/dev/null || true
docker exec "${DB_CONTAINER}" psql -U postgres \
  -c "CREATE DATABASE ${DRILL_DB};" \
  || fail "Could not create drill database"

# ── 4. Restore backup into drill DB ──────────────────────────────────────────
log "Restoring backup into ${DRILL_DB}..."
gunzip -c "${LATEST}" | \
  docker exec -i "${DB_CONTAINER}" psql -U "${DB_USER}" "${DRILL_DB}" \
  > /tmp/restore_output.log 2>&1 \
  || fail "Restore failed. Check /tmp/restore_output.log"
log "Restore completed"

# ── 5. Validate row counts ────────────────────────────────────────────────────
log "Validating row counts..."

run_query() {
  docker exec "${DB_CONTAINER}" psql -U "${DB_USER}" "${DRILL_DB}" -t -A -c "$1"
}

SESSIONS=$(run_query "SELECT count(*) FROM sessions;")
EVENTS=$(run_query "SELECT count(*) FROM events;")
FINGERPRINTS=$(run_query "SELECT count(*) FROM fingerprints;")
TTP_MATCHES=$(run_query "SELECT count(*) FROM ttp_matches;")

log "  sessions:     ${SESSIONS}"
log "  events:       ${EVENTS}"
log "  fingerprints: ${FINGERPRINTS}"
log "  ttp_matches:  ${TTP_MATCHES}"

[[ ${SESSIONS} -lt 1 ]] && fail "No sessions in restored DB — backup may be empty"

# ── 6. Validate latest session timestamp ─────────────────────────────────────
log "Validating latest session timestamp..."
LATEST_SESSION=$(run_query "SELECT max(started_at) FROM sessions;")
log "  Latest session: ${LATEST_SESSION}"

# Check it's within the last 48 hours (allow for quiet periods)
LATEST_EPOCH=$(docker exec "${DB_CONTAINER}" psql -U "${DB_USER}" "${DRILL_DB}" -t -A -c \
  "SELECT EXTRACT(EPOCH FROM max(started_at))::bigint FROM sessions;")
NOW_EPOCH=$(date +%s)
AGE_H=$(( (NOW_EPOCH - LATEST_EPOCH) / 3600 ))
log "  Latest session age: ${AGE_H} hours"
if [[ ${AGE_H} -gt 48 ]]; then
  log "WARNING: Latest session is older than 48h. Possible quiet period or data issue."
fi

# ── 7. Validate schema version (alembic) ─────────────────────────────────────
log "Checking alembic version..."
ALEMBIC_VER=$(run_query "SELECT version_num FROM alembic_version;" 2>/dev/null || echo "NONE")
log "  Alembic version: ${ALEMBIC_VER}"
[[ "${ALEMBIC_VER}" == "NONE" ]] && fail "alembic_version table missing — schema may be corrupted"

# ── 8. Cleanup ────────────────────────────────────────────────────────────────
log "Cleaning up drill database..."
docker exec "${DB_CONTAINER}" psql -U postgres \
  -c "DROP DATABASE ${DRILL_DB};" \
  || log "WARNING: Could not drop drill DB — manual cleanup needed"

# ── 9. Report ─────────────────────────────────────────────────────────────────
log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
log "RESULT: PASS"
log "Backup: ${LATEST}"
log "Age: ${BACKUP_AGE_H}h  Sessions: ${SESSIONS}  Events: ${EVENTS}"
log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

exit 0
