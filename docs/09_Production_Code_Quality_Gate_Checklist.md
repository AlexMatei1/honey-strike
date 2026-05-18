# HoneyStrike — Production Code Quality Gate Checklist

All items must pass before a PR is merged to `main`. CI enforces gates 1–7 automatically.

---

## Gate 1 — Type Checking (mypy)

```bash
mypy --strict src/honeystrike/
```

- [ ] Zero mypy errors on `--strict` mode
- [ ] All public interfaces have full type annotations
- [ ] `AttackEvent`, `AttackerFingerprint`, `TTPRule` dataclasses fully annotated

---

## Gate 2 — Linting (ruff)

```bash
ruff check src/ tests/
```

- [ ] Zero ruff violations
- [ ] No unused imports
- [ ] No f-string formatting in log calls (use `structlog` bound values)
- [ ] No `print()` statements (use `structlog.get_logger()`)

---

## Gate 3 — Formatting (black)

```bash
black --check src/ tests/
```

- [ ] All files pass black formatting check (line length 88)

---

## Gate 4 — Test Coverage (pytest + pytest-cov)

```bash
pytest --cov=src/honeystrike --cov-report=term-missing --cov-fail-under=80
```

- [ ] Overall coverage ≥ 80%
- [ ] Critical paths must be ≥ 90%:
  - [ ] `FingerprintEngine` — enrichment logic
  - [ ] `TTPMapper` — all rules tested individually
  - [ ] `ThreatScorer` — scoring formula
  - [ ] `ReportGenerator` — PDF + HTML output
  - [ ] API endpoints — all happy + error paths
- [ ] Integration tests pass for all 4 honeypot services (real client connections)

---

## Gate 5 — Security Scan (bandit)

```bash
bandit -r src/honeystrike/ -ll
```

- [ ] Zero HIGH severity findings
- [ ] Zero MEDIUM severity findings that relate to:
  - SQL injection
  - Command injection
  - Hardcoded secrets

---

## Gate 6 — Container CVE Scan (trivy)

```bash
trivy image --exit-code 1 --severity CRITICAL honeystrike:latest
```

- [ ] Zero CRITICAL CVEs in any container image
- [ ] HIGH CVEs documented and acknowledged in `SECURITY.md` if unavoidable

---

## Gate 7 — Dependency Audit (pip-audit)

```bash
pip-audit -r requirements.txt
```

- [ ] No known vulnerabilities in any pinned dependency

---

## Gate 8 — Manual Review Checklist (PR Author)

- [ ] No secrets, API keys, or passwords in code or test fixtures
- [ ] All new attacker-data-handling code goes through sanitisation layer
- [ ] Any new external API call is covered by a circuit breaker / fallback
- [ ] New database queries use parameterised statements only
- [ ] New Jinja2 templates have autoescaping enabled
- [ ] Docker Compose changes maintain network isolation (honeypot-net vs internal-net)
- [ ] `.env.example` updated if new environment variables added
- [ ] `CHANGELOG.md` entry added (Conventional Commits format)

---

## Gate 9 — Performance Regression Check

Run before any merge that touches event processing or database queries:

```bash
pytest tests/perf/ --benchmark-compare --benchmark-fail-max-time=0.05
```

- [ ] `FingerprintEngine.enrich()` p99 < 50ms (mocked external calls)
- [ ] `TTPMapper.evaluate()` p99 < 5ms
- [ ] `ThreatScorer.score()` p99 < 1ms
- [ ] API `GET /api/sessions` p95 < 200ms (test DB with 10k sessions)

---

## CI Pipeline Summary

```yaml
# .github/workflows/ci.yml gates (in order)
jobs:
  quality:
    steps:
      - mypy --strict
      - ruff check
      - black --check
      - bandit -ll
      - pip-audit
  test:
    steps:
      - pytest --cov --cov-fail-under=80
      - pytest tests/integration/
  security:
    steps:
      - docker build
      - trivy image --exit-code 1 --severity CRITICAL
  release-gate:
    needs: [quality, test, security]
    steps:
      - ./ci/release-gate.sh
```
