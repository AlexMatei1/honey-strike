#!/bin/bash
# HoneyStrike — Release Gate
# Runs all CI quality and security checks in sequence.
# All gates must pass for release to proceed.
# Run: ./ci/release-gate.sh
# Used in: GitHub Actions (release branch merges to main)

set -uo pipefail

LOG_PREFIX="[release-gate]"
PASS=0
FAIL=0
SKIP=0
GATE_LOG="/tmp/honeystrike-release-gate-$(date +%Y%m%d_%H%M%S).log"
COVERAGE_MIN="${COVERAGE_MIN:-80}"
IMAGE_NAME="${IMAGE_NAME:-honeystrike}"

log()  { echo "${LOG_PREFIX} $*" | tee -a "${GATE_LOG}"; }
pass() { log "✓  $*"; PASS=$((PASS+1)); }
fail() { log "✗  $*"; FAIL=$((FAIL+1)); }
skip() { log "⊘  $*"; SKIP=$((SKIP+1)); }
sep()  { log "────────────────────────────────────────"; }

log "HoneyStrike Release Gate — $(date -Iseconds)"
log "Log: ${GATE_LOG}"
sep

# ── Gate 1: Type checking ─────────────────────────────────────────────────────
log "GATE 1: mypy --strict"
if mypy --strict src/honeystrike/ >> "${GATE_LOG}" 2>&1; then
  pass "mypy — zero type errors"
else
  fail "mypy — type errors found (see log)"
fi
sep

# ── Gate 2: Linting ───────────────────────────────────────────────────────────
log "GATE 2: ruff"
if ruff check src/ tests/ >> "${GATE_LOG}" 2>&1; then
  pass "ruff — zero violations"
else
  fail "ruff — violations found"
fi
sep

# ── Gate 3: Formatting ────────────────────────────────────────────────────────
log "GATE 3: black"
if black --check src/ tests/ >> "${GATE_LOG}" 2>&1; then
  pass "black — formatting OK"
else
  fail "black — formatting issues found (run: black src/ tests/)"
fi
sep

# ── Gate 4: Security scan ─────────────────────────────────────────────────────
log "GATE 4: bandit"
if bandit -r src/honeystrike/ -ll -q >> "${GATE_LOG}" 2>&1; then
  pass "bandit — no HIGH/MEDIUM security issues"
else
  fail "bandit — security issues found"
fi
sep

# ── Gate 5: Dependency audit ──────────────────────────────────────────────────
log "GATE 5: pip-audit"
if pip-audit -r requirements.txt >> "${GATE_LOG}" 2>&1; then
  pass "pip-audit — no known vulnerable dependencies"
else
  fail "pip-audit — vulnerable dependencies found"
fi
sep

# ── Gate 6: Unit tests + coverage ────────────────────────────────────────────
log "GATE 6: pytest + coverage (min: ${COVERAGE_MIN}%)"
if pytest \
    --cov=src/honeystrike \
    --cov-report=term-missing \
    --cov-report=json:/tmp/coverage.json \
    --cov-fail-under="${COVERAGE_MIN}" \
    -q >> "${GATE_LOG}" 2>&1; then
  COVERAGE=$(python3 -c "import json; d=json.load(open('/tmp/coverage.json')); print(round(d['totals']['percent_covered'],1))" 2>/dev/null || echo "?")
  pass "pytest — all tests pass, coverage: ${COVERAGE}%"
else
  fail "pytest — tests failed or coverage below ${COVERAGE_MIN}%"
fi
sep

# ── Gate 7: Integration tests ─────────────────────────────────────────────────
log "GATE 7: integration tests"
if pytest tests/integration/ -q --tb=short >> "${GATE_LOG}" 2>&1; then
  pass "integration tests — all pass"
else
  fail "integration tests — failures found"
fi
sep

# ── Gate 8: Container build ───────────────────────────────────────────────────
log "GATE 8: docker build"
if docker compose -f docker-compose.prod.yml build >> "${GATE_LOG}" 2>&1; then
  pass "docker build — all images built successfully"
else
  fail "docker build — build failed"
fi
sep

# ── Gate 9: Container CVE scan ───────────────────────────────────────────────
log "GATE 9: trivy — CVE scan (CRITICAL)"
if command -v trivy &>/dev/null; then
  TRIVY_FAIL=0
  for SVC in ssh-service http-service ftp-service rdp-service intel-worker report-worker dashboard-api; do
    if trivy image \
        --exit-code 1 \
        --severity CRITICAL \
        --quiet \
        "${IMAGE_NAME}-${SVC}:latest" >> "${GATE_LOG}" 2>&1; then
      log "  ${SVC}: no CRITICAL CVEs"
    else
      log "  ${SVC}: CRITICAL CVEs found"
      TRIVY_FAIL=1
    fi
  done
  if [[ ${TRIVY_FAIL} -eq 0 ]]; then
    pass "trivy — zero CRITICAL CVEs across all images"
  else
    fail "trivy — CRITICAL CVEs found (see log)"
  fi
else
  skip "trivy — not installed (install: https://aquasecurity.github.io/trivy)"
fi
sep

# ── Gate 10: Migration dry-run ────────────────────────────────────────────────
log "GATE 10: alembic migration check"
if docker compose -f docker-compose.prod.yml run --rm dashboard-api \
    alembic check >> "${GATE_LOG}" 2>&1; then
  pass "alembic — no pending migrations (schema matches models)"
else
  fail "alembic — pending migrations detected (run: alembic upgrade head)"
fi
sep

# ── Gate 11: Secrets scan ─────────────────────────────────────────────────────
log "GATE 11: secrets scan"
SECRETS_FOUND=0
# Check for common secret patterns in committed files
for pattern in "password\s*=" "api_key\s*=" "secret_key\s*=" "token\s*="; do
  if git log --all -S "${pattern}" --oneline 2>/dev/null | grep -qv "\.example\|test\|mock"; then
    log "  WARNING: possible secret pattern '${pattern}' in git history"
    SECRETS_FOUND=1
  fi
done
# Check .env files are not tracked
if git ls-files | grep -q "\.env\.production\|\.env\.local"; then
  log "  FAIL: .env files are tracked in git"
  SECRETS_FOUND=1
fi
if [[ ${SECRETS_FOUND} -eq 0 ]]; then
  pass "secrets scan — no secrets detected in git history or tracked files"
else
  fail "secrets scan — potential secrets found (review log)"
fi
sep

# ── Summary ───────────────────────────────────────────────────────────────────
TOTAL=$((PASS + FAIL + SKIP))
log ""
log "════════════════════════════════════════"
log "RELEASE GATE SUMMARY"
log "Total gates: ${TOTAL}  PASS: ${PASS}  FAIL: ${FAIL}  SKIP: ${SKIP}"
log "Full log: ${GATE_LOG}"

if [[ ${FAIL} -eq 0 ]]; then
  log ""
  log "  ✅  ALL GATES PASSED — release may proceed"
  log "════════════════════════════════════════"
  exit 0
else
  log ""
  log "  ❌  ${FAIL} GATE(S) FAILED — fix before release"
  log "════════════════════════════════════════"
  exit 1
fi
