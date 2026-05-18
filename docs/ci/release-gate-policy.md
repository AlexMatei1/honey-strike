# HoneyStrike — Release Gate Policy

**Version:** 1.0  **Applies to:** All merges from `develop` → `main`

---

## Purpose

This policy defines the mandatory automated and manual quality gates that must pass before any code is merged to the `main` branch and released to production. It exists to protect the deployed honeypot system from regressions, security vulnerabilities, and data integrity issues.

---

## Gate Summary

| # | Gate | Tool | Blocking? | Threshold |
|---|------|------|-----------|-----------|
| 1 | Type checking | mypy --strict | Yes | Zero errors |
| 2 | Linting | ruff | Yes | Zero violations |
| 3 | Formatting | black | Yes | Zero diffs |
| 4 | Security scan | bandit | Yes | Zero HIGH/MEDIUM |
| 5 | Dependency audit | pip-audit | Yes | Zero known CVEs |
| 6 | Unit tests + coverage | pytest + pytest-cov | Yes | ≥ 80% coverage |
| 7 | Integration tests | pytest tests/integration/ | Yes | 100% pass |
| 8 | Container build | docker compose build | Yes | Zero errors |
| 9 | Container CVE scan | trivy | Yes | Zero CRITICAL |
| 10 | Migration check | alembic check | Yes | No pending migrations |
| 11 | Secrets scan | git log + git ls-files | Yes | Zero secrets found |

All 11 gates are blocking. A PR cannot be merged if any gate fails.

---

## Branch Strategy

```
main          ← production. Protected. Never push directly.
  ↑ PR + all gates pass
develop       ← integration branch. CI runs on every push.
  ↑ feature branches merged here first
feature/*     ← individual feature development
hotfix/*      ← emergency fixes (bypass develop, go direct to main with approval)
```

### Hotfix exception

Hotfixes for CRITICAL security vulnerabilities may bypass the `develop` branch and go directly to `main` provided:

1. At minimum, gates 4 (bandit), 5 (pip-audit), 6 (tests), and 9 (trivy) pass
2. A second reviewer approves the PR
3. A post-merge regression test is run within 24 hours

---

## CI Enforcement (GitHub Actions)

The release gate script (`ci/release-gate.sh`) is called by:

```yaml
# .github/workflows/release.yml
on:
  pull_request:
    branches: [main]

jobs:
  release-gate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run release gate
        run: ./ci/release-gate.sh
```

PRs to `main` require:
- All CI checks passing
- At least 1 approved review
- No unresolved review comments
- Branch up to date with `main`

Branch protection rules are enforced via GitHub repo settings — they cannot be bypassed by maintainers.

---

## Coverage Thresholds

| Module | Minimum coverage |
|--------|-----------------|
| Overall | 80% |
| `core/events.py` | 95% |
| `workers/intel/fingerprint.py` | 90% |
| `workers/intel/ttp_rules.py` | 95% |
| `workers/intel/scorer.py` | 95% |
| `workers/reports/generator.py` | 85% |
| `api/routers/` | 85% |
| `services/*/server.py` | 80% |

Coverage is enforced via `pytest --cov-fail-under=80`. Per-module thresholds are checked via a custom `pytest` plugin defined in `conftest.py`.

---

## What Skipped Gates Mean

A gate marked `SKIP` (not `FAIL`) means the required tool is not installed in the CI environment. This is only acceptable for:
- `trivy` — acceptable if a separate weekly Trivy scan is scheduled
- `pip-audit` — never acceptable to skip on a release gate

If `trivy` is skipped, the release can proceed only if:
- The last scheduled Trivy scan (≤ 7 days ago) passed
- The scan result is linked in the PR description

---

## Exemption Process

No gate can be permanently disabled. Temporary exemptions for a single release require:

1. Written justification in the PR description
2. A GitHub issue created to track the underlying problem
3. A deadline (≤ 14 days) by which the exempted gate will pass
4. Second reviewer approval

---

## Post-Release Validation

Within 2 hours of a production deployment, the operator must verify:

- [ ] `curl https://your-domain.com/api/health` returns all services "running"
- [ ] At least one new session captured since deployment
- [ ] No critical errors in `docker compose logs` since deployment
- [ ] Telegram alerts still functioning (send a test connection)

If post-release validation fails, roll back immediately:

```bash
git checkout main~1
docker compose -f docker-compose.prod.yml build
docker compose -f docker-compose.prod.yml up -d
```
