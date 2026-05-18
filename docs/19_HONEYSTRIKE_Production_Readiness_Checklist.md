# HoneyStrike — Production Readiness Checklist

Final pre-launch gate. All items must be PASS before traffic is allowed.  
**Reviewer:** _____________  **Date:** _____________  **Version:** v1.0.0

---

## 1. Code Quality

| Item | Status | Notes |
|------|--------|-------|
| `mypy --strict` passes with zero errors | | |
| `ruff check` passes with zero violations | | |
| `black --check` passes | | |
| `bandit` — zero HIGH/MEDIUM security findings | | |
| `pip-audit` — zero known dependency vulnerabilities | | |
| Test coverage ≥ 80% (overall) | | |
| Test coverage ≥ 90% on critical paths (TTP mapper, scorer, report gen) | | |
| All integration tests pass (real client connections) | | |
| Trivy — zero CRITICAL CVEs in all images | | |
| Performance benchmarks pass (fingerprint < 50ms p99, API < 200ms p95) | | |

---

## 2. Security Hardening

| Item | Status | Notes |
|------|--------|-------|
| All containers run as non-root UID 1000 | | |
| Read-only rootfs on all service containers | | |
| `cap_drop: ALL` + only `NET_BIND_SERVICE` where needed | | |
| Two Docker networks: honeypot-net (public) + internal-net (private) | | |
| PostgreSQL not reachable from honeypot-net | | |
| Redis not reachable from honeypot-net | | |
| Dashboard API not reachable except via Caddy proxy | | |
| No secrets in Docker image layers (`docker history` checked) | | |
| JWT RS256 secret is cryptographically random (≥ 32 bytes) | | |
| Admin password is strong (≥ 16 chars, not a wordlist entry) | | |
| SSH management port is NOT 22 (honeypot conflict) | | |
| UFW rules verified with `ufw status verbose` | | |
| `PermitRootLogin no` in sshd_config | | |
| `PasswordAuthentication no` in sshd_config | | |

---

## 3. Data Pipeline

| Item | Status | Notes |
|------|--------|-------|
| All 4 honeypot services accepting connections | | |
| Events appearing in Redis stream (`XLEN honeystrike:events > 0`) | | |
| Sessions being created in PostgreSQL | | |
| FingerprintWorker enriching sessions (country/ASN populated) | | |
| TTPMapperWorker matching rules (ttp_matches rows created) | | |
| AlertingWorker dispatching to Telegram | | |
| ReportWorker generating PDF (test trigger successful) | | |
| HTML report self-contained and opens in browser | | |

---

## 4. Dashboard and API

| Item | Status | Notes |
|------|--------|-------|
| Dashboard accessible at `https://your-domain.com` | | |
| Login flow works (admin credentials set correctly) | | |
| JWT token issued and accepted by API | | |
| Sessions list renders with real data | | |
| Session detail page shows fingerprint + TTPs | | |
| Live attack map loads (Leaflet.js markers visible) | | |
| WebSocket connected (green status in browser) | | |
| Analytics charts render (TTP frequency, timeline) | | |
| `/api/health` returns all services as "running" | | |
| OpenAPI spec accessible at `/docs` | | |

---

## 5. Infrastructure and Operations

| Item | Status | Notes |
|------|--------|-------|
| Daily DB backup cron running (`crontab -l` verified) | | |
| Events archival cron running | | |
| MaxMind weekly update cron running | | |
| Report file cleanup cron running | | |
| Backup restore drill completed successfully | | |
| Service failover drill completed (RB-02 in runbooks) | | |
| Let's Encrypt TLS certificate valid and auto-renewing | | |
| HSTS header present in HTTPS responses | | |
| Prometheus metrics endpoint responding | | |
| Structured logs in JSON format (sample output verified) | | |
| `docker compose ps` — all 9 containers healthy | | |
| `restart: unless-stopped` set on all services | | |

---

## 6. Documentation

| Item | Status | Notes |
|------|--------|-------|
| 00_README.md complete and accurate | | |
| 07_Compliance_and_Legal_Packet.md reviewed | | |
| 18_HONEYSTRIKE_Compliance_Checklist.md completed | | |
| All runbooks tested at least once | | |
| `.env.example` matches all variables in `.env.production` | | |
| CHANGELOG.md has v1.0.0 entry | | |
| GitHub repo README includes: demo screenshot, quick start, tech stack | | |
| Sample PDF report committed to `/demo/` in repo | | |

---

## 7. Portfolio / CV Readiness

| Item | Status | Notes |
|------|--------|-------|
| Live VPS has real attack data (deployed ≥ 48h) | | |
| At least one session with score ≥ 60 (auto-generated report) | | |
| Demo video/GIF recorded showing: dashboard, live map, alert, PDF report | | |
| GitHub repo is public with complete README | | |
| MITRE ATT&CK attribution present in all sample reports | | |
| OpenAPI JSON exported and committed (`/docs/openapi.json`) | | |

---

## Final Sign-Off

| Section | PASS / FAIL | Signature |
|---------|------------|-----------|
| 1 — Code Quality | | |
| 2 — Security Hardening | | |
| 3 — Data Pipeline | | |
| 4 — Dashboard and API | | |
| 5 — Infrastructure | | |
| 6 — Documentation | | |
| 7 — Portfolio Readiness | | |

**Production launch authorised:** YES / NO

**Outstanding issues before launch (if any):**

1.
2.
3.

**Target launch date:** _____________
