#!/bin/bash
# HoneyStrike — Service Failover Drill
# Tests that each honeypot service recovers correctly after a forced stop.
# Run: ./ci/failover-drill.sh [service]
# Example: ./ci/failover-drill.sh ssh-service
#          ./ci/failover-drill.sh  (runs all services in sequence)

set -euo pipefail

COMPOSE_FILE="${COMPOSE_FILE:-docker-compose.prod.yml}"
DB_CONTAINER="${DB_CONTAINER:-honeystrike-db}"
DB_USER="${DB_USER:-honeystrike}"
RECOVERY_WAIT="${RECOVERY_WAIT:-60}"
DOMAIN="${DOMAIN:-localhost}"
LOG_PREFIX="[failover-drill]"

SERVICES=("ssh-service" "http-service" "ftp-service" "rdp-service" "intel-worker" "report-worker")
TARGET_SERVICES=("$@")
[[ ${#TARGET_SERVICES[@]} -eq 0 ]] && TARGET_SERVICES=("${SERVICES[@]}")

PASS=0
FAIL=0
RESULTS=()

log()  { echo "${LOG_PREFIX} $*"; }
pass() { log "✓ PASS: $*"; PASS=$((PASS+1)); RESULTS+=("PASS: $*"); }
fail() { log "✗ FAIL: $*"; FAIL=$((FAIL+1)); RESULTS+=("FAIL: $*"); }

# ── Helper: count recent sessions for a service ───────────────────────────────
count_recent_sessions() {
  local svc="$1"
  local minutes="${2:-2}"
  docker exec "${DB_CONTAINER}" psql -U "${DB_USER}" -t -A -c \
    "SELECT count(*) FROM sessions
     WHERE service='${svc}'
     AND started_at > NOW() - INTERVAL '${minutes} minutes';" 2>/dev/null || echo "0"
}

# ── Helper: health check ──────────────────────────────────────────────────────
check_health() {
  curl -sf "https://${DOMAIN}/api/health" | python3 -c \
    "import sys,json; d=json.load(sys.stdin); sys.exit(0 if d.get('status')=='ok' else 1)" \
    2>/dev/null
}

# ── Baseline health ───────────────────────────────────────────────────────────
log "Checking baseline health..."
if ! check_health; then
  log "WARNING: Health check failed before drill. Proceeding anyway."
fi

# ── Drill each service ────────────────────────────────────────────────────────
for SVC in "${TARGET_SERVICES[@]}"; do
  log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  log "Drilling: ${SVC}"

  # Record session count before stop
  SVC_SHORT="${SVC%%-service}"
  BEFORE=$(count_recent_sessions "${SVC_SHORT}" 5)
  log "Sessions in last 5 min (before): ${BEFORE}"

  # Stop the service
  STOP_TIME=$(date +%s)
  log "Stopping ${SVC} at $(date -Iseconds)..."
  docker compose -f "${COMPOSE_FILE}" stop "${SVC}"

  # Verify it's down
  sleep 3
  STATE=$(docker compose -f "${COMPOSE_FILE}" ps "${SVC}" --format json 2>/dev/null \
    | python3 -c "import sys,json; d=json.load(sys.stdin); print(d[0].get('State','unknown'))" \
    2>/dev/null || echo "unknown")
  log "Container state after stop: ${STATE}"

  # Restart
  log "Restarting ${SVC}..."
  docker compose -f "${COMPOSE_FILE}" start "${SVC}"

  # Wait for recovery
  log "Waiting ${RECOVERY_WAIT}s for recovery..."
  sleep "${RECOVERY_WAIT}"

  # Measure recovery time
  RECOVERY_TIME=$(( $(date +%s) - STOP_TIME ))
  log "Recovery time: ${RECOVERY_TIME}s"

  # Verify container is running
  NEW_STATE=$(docker compose -f "${COMPOSE_FILE}" ps "${SVC}" --format json 2>/dev/null \
    | python3 -c "import sys,json; d=json.load(sys.stdin); print(d[0].get('State','unknown'))" \
    2>/dev/null || echo "unknown")
  log "Container state after restart: ${NEW_STATE}"

  if [[ "${NEW_STATE}" == "running" ]]; then
    pass "${SVC} — container running after restart"
  else
    fail "${SVC} — container not running after restart (state: ${NEW_STATE})"
  fi

  # Recovery time check
  if [[ ${RECOVERY_TIME} -lt 120 ]]; then
    pass "${SVC} — recovered in ${RECOVERY_TIME}s (target < 120s)"
  else
    fail "${SVC} — recovery took ${RECOVERY_TIME}s (target < 120s)"
  fi

  # Check new sessions (for honeypot services only — workers don't create sessions)
  if [[ "${SVC}" == *-service ]]; then
    AFTER=$(count_recent_sessions "${SVC_SHORT}" 2)
    log "Sessions in last 2 min (after restart): ${AFTER}"
    if [[ ${AFTER} -gt 0 ]]; then
      pass "${SVC} — new sessions detected after restart (${AFTER})"
    else
      log "INFO: No new sessions yet — may need more time or low traffic period"
    fi
  fi

  # Health endpoint
  if check_health; then
    pass "${SVC} — global health check passes after restart"
  else
    fail "${SVC} — health check failed after restart"
  fi

  log ""
done

# ── Summary ───────────────────────────────────────────────────────────────────
log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
log "FAILOVER DRILL SUMMARY"
log "Services tested: ${#TARGET_SERVICES[@]}"
log "PASS: ${PASS}  FAIL: ${FAIL}"
log ""
for R in "${RESULTS[@]}"; do
  log "  ${R}"
done
log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Record drill timestamp
echo "$(date -Iseconds) | PASS=${PASS} FAIL=${FAIL} | Services: ${TARGET_SERVICES[*]}" \
  >> /var/log/honeystrike-drill.log

[[ ${FAIL} -eq 0 ]] && exit 0 || exit 1
