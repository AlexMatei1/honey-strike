# HoneyStrike — 90-Day (18-Week) Delivery Plan

---

## Phase 1 — Foundation & Architecture (Weeks 1–2)

**Goal:** Project skeleton, Docker environment, CI pipeline, database schema.

| Week | Task | Deliverable |
|------|------|-------------|
| 1 | System architecture diagram (draw.io) | `/docs/architecture.drawio` |
| 1 | Monorepo scaffold: `/core`, `/services`, `/workers`, `/api`, `/reports`, `/infra` | `pyproject.toml` (Poetry) |
| 1 | Docker Compose dev stack: postgres, redis, placeholder services | `docker-compose.dev.yml` |
| 1 | GitHub Actions CI: mypy, ruff, black, pytest | `.github/workflows/ci.yml` |
| 2 | PostgreSQL schema + Alembic initial migration | `alembic/versions/001_initial.py` |
| 2 | Domain event types + `AttackEvent` dataclass | `core/events.py` |
| 2 | Pre-commit hooks: black, ruff, mypy | `.pre-commit-config.yaml` |
| 2 | `.env.example` with all required variables documented | `.env.example` |

**Milestone gate:** `docker compose up` starts all containers without errors.

---

## Phase 2 — Core Honeypot Engine (Weeks 3–6)

**Goal:** All 4 fake service listeners capturing real data.

| Week | Task | Deliverable |
|------|------|-------------|
| 3 | SSH honeypot: Paramiko server, banner, KEX, auth capture | `services/ssh/server.py` |
| 3 | SSH post-auth fake shell with command capture | `services/ssh/shell.py` |
| 4 | HTTP honeypot: FastAPI fake admin panels (/wp-admin, /phpmyadmin) | `services/http/server.py` |
| 4 | HTTP scanner detection: User-Agent matching, SQLi pattern regex | `services/http/detectors.py` |
| 4 | HTTPS + JA3 fingerprint extraction | `services/http/tls.py` |
| 5 | FTP honeypot: pyftpdlib, command capture, fake directory listing | `services/ftp/server.py` |
| 5 | RDP honeypot: asyncio raw socket, PDU parsing, CredSSP capture | `services/rdp/server.py` |
| 6 | Session manager: create/update/close sessions, Redis Streams publish | `core/session_manager.py` |
| 6 | Integration tests: real client connections to all 4 services | `tests/integration/` |
| 6 | Deploy to VPS (partial stack) — begin collecting real attack data | Live on Hetzner CX21 |

**Milestone gate:** SSH, HTTP, FTP, RDP all accepting connections; events appearing in Redis stream.

---

## Phase 3 — Intelligence Layer (Weeks 7–10)

**Goal:** Fingerprinting, TTP mapping, alerting, threat scoring.

| Week | Task | Deliverable |
|------|------|-------------|
| 7 | MaxMind GeoLite2 integration: city + ASN database, Redis cache | `workers/intel/geo.py` |
| 7 | AbuseIPDB client: async httpx, rate limiting, 6h Redis cache | `workers/intel/abuseipdb.py` |
| 7 | Tool signature library: Hydra, Medusa, Masscan, Nmap, sqlmap, Nikto | `workers/intel/signatures.py` |
| 8 | `FingerprintWorker`: consumes events, assembles `AttackerFingerprint` | `workers/intel/fingerprint.py` |
| 8 | `TTPRule` dataclass + MITRE ATT&CK STIX data loader | `workers/intel/ttp_rules.py` |
| 9 | All 7 built-in TTP rules implemented and unit tested | `tests/unit/test_ttp_rules.py` |
| 9 | `TTPMapperWorker`: rule evaluation, `TTPMatch` persistence | `workers/intel/ttp_mapper.py` |
| 9 | Threat scoring algorithm: formula implementation + unit tests | `workers/intel/scorer.py` |
| 10 | `AlertingWorker`: Telegram bot, email (smtplib), Slack webhook | `workers/intel/alerting.py` |
| 10 | Duplicate suppression: Redis cooldown key per IP | `workers/intel/alerting.py` |
| 10 | End-to-end test: attacker → event → fingerprint → TTP → alert | `tests/e2e/test_attack_flow.py` |

**Milestone gate:** Full pipeline live on VPS — real attack generates Telegram alert with TTP info.

---

## Phase 4 — Dashboard & Reports (Weeks 11–14)

**Goal:** Live attack map, admin dashboard, PDF/HTML reports.

| Week | Task | Deliverable |
|------|------|-------------|
| 11 | Analytics REST API: all `/api/stats/*` endpoints | `api/routers/stats.py` |
| 11 | Sessions API: list, detail, events, report endpoints | `api/routers/sessions.py` |
| 11 | JWT authentication: login, refresh, middleware | `api/auth.py` |
| 12 | WebSocket live event broadcaster | `api/ws.py` |
| 12 | Leaflet.js attack map: animated markers, session sidebar | `api/static/map.js` |
| 12 | HTMX dashboard: sessions table, session detail page | `api/templates/` |
| 13 | Analytics charts: TTP frequency (Chart.js), top IPs, timeline | `api/templates/analytics.html` |
| 13 | Jinja2 PDF report template (CSS-styled) | `reports/templates/report.html.j2` |
| 14 | WeasyPrint PDF generation: `ReportWorker`, async generation | `workers/reports/generator.py` |
| 14 | Self-contained HTML report: collapsible sections, embedded map | `reports/templates/report_html.j2` |
| 14 | Manual + auto report trigger (score ≥ 60) | `workers/reports/trigger.py` |

**Milestone gate:** Full dashboard accessible; demo session generates downloadable PDF report.

---

## Phase 5 — Hardening, Testing & Deployment (Weeks 15–18)

**Goal:** Production-grade security, full test suite, VPS hardening, stretch goals.

| Week | Task | Deliverable |
|------|------|-------------|
| 15 | Full unit test suite + coverage ≥ 80% | `tests/unit/` |
| 15 | bandit + pip-audit + trivy integration in CI | `.github/workflows/ci.yml` |
| 15 | Container hardening: non-root, read-only rootfs, cap_drop:ALL | `docker-compose.prod.yml` |
| 15 | Docker network isolation: honeypot-net vs internal-net | `docker-compose.prod.yml` |
| 16 | Production Compose file + Caddy TLS config | `Caddyfile` |
| 16 | UFW rules, Fail2Ban on dashboard port only | `infra/setup.sh` |
| 16 | Alembic migrations tested on clean DB | CI migration test |
| 16 | Backup script: daily pg_dump + 30-day rolling retention | `infra/backup.sh` |
| 17 | Stretch: Isolation Forest ML anomaly detection (scikit-learn) | `workers/intel/ml_anomaly.py` |
| 17 | Stretch: python-stix2 STIX 2.1 Bundle export | `api/routers/stix.py` |
| 17 | Stretch: TAXII 2.1 server endpoint | `api/routers/taxii.py` |
| 18 | Grafana dashboard JSON export + Loki log config | `infra/grafana/` |
| 18 | Full DR drill: backup → restore → verify (see DR Playbook) | DR drill record |
| 18 | `17_V1.0_Release_Notes.md` finalised | Docs |
| 18 | GitHub repo cleaned: README, DEMO.md, sample report, OpenAPI JSON | Public repo |

**Milestone gate:** All CI gates green; live VPS with real attack data; PDF demo report in repo.

---

## Phase 6 — Interactive CLI & Multiplayer Game Mode (Weeks 19–22)

**Goal:** Turn HoneyStrike into a playable two-player attack/defend game. Each player runs their own HoneyStrike instance and reaches the other over the public internet. A shared lobby service brokers invites; a shared Discord webhook posts match summaries.

| Week | Task | Deliverable |
|------|------|-------------|
| 19 | Single `honeystrike` CLI scaffold (`typer`), auth token cache, `login`, `register` | `src/honeystrike/cli/__init__.py`, `cli/auth.py`, `[tool.poetry.scripts]` entry |
| 19 | Attacker scenarios (10): `ssh-hydra`, `http-sqlmap`, `http-log4shell`, `http-traversal`, `http-recon`, `ftp-hydra`, `rdp-scan`, `tls-fingerprint`, `multi-service`, `full-compromise` | `cli/attack/runners.py`, `cli/attack/scenarios.py` |
| 19 | Defender snapshot commands: `recent`, `show`, `top-attackers`, `top-ttps`, `alerts`, `report`, `stats` | `cli/defend/snapshot.py` |
| 20 | Campaign playbooks (`apt28`, `fin7`, `ransomware-deployer`, `script-kiddie`) + `defend campaign-score` | `cli/attack/campaigns.py`, `cli/defend/campaign_score.py` |
| 20 | CTF canaries seeded in HTTP templates + SSH fake-shell + `defend flags-found` | patches to `services/http/templates.py`, `services/ssh/shell.py`, `cli/defend/flags.py` |
| 20 | Live tail + narrator via existing `/api/ws/live` | `cli/defend/tail.py`, `cli/defend/narrate.py` |
| 21 | Lobby API service (FastAPI + SQLite, port 8002) | `src/honeystrike/lobby/`, new compose service |
| 21 | Multiplayer CLI: `register`, `players`, `challenge`, `defend listen`, `defend label` | `cli/lobby/`, `cli/defend/label.py` |
| 21 | Blocking mechanic (Redis blocklist + per-listener accept hook) | `core/blocklist.py`, patches to all 5 listeners + new `POST /api/defender/block` |
| 22 | `DiscordChannel` for alerts + Alembic 004 (extend `alerts.channel` CHECK) | `workers/alerting/channels.py`, `alembic/versions/004_alerts_discord_channel.py` |
| 22 | Match-summary post to Discord (`lobby/match/{id}/finish`) | `lobby/app.py` |
| 22 | Tests (unit + integration for CLI, lobby, blocking) + DEMO.md multiplayer walkthrough + TESTING.md updates | comprehensive |

**Milestone gate:** Two operators on separate VPS register with the same lobby; one challenges the other with `honeystrike challenge bob --scenario apt28`; the defender labels TTPs interactively, correct labels block the attacker's IP for 5 minutes, and a match summary lands in a shared Discord channel.

**Out of scope:**
- NAT / tunnel solutions for friends behind CGNAT — documented in `DEMO.md`, not solved in code.
- Global leaderboard or rating system — casual play only.
- Anti-cheat / abuse mitigation — friend-vs-friend trust model.
