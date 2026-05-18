# Deliverables — spec vs. actual

Each row in [`docs/10_90_Day_Delivery_Plan.md`](docs/10_90_Day_Delivery_Plan.md) points at a deliverable. Some shipped at exactly the named path; others took a structurally better shape during the build. This file is the mapping so anyone reading the spec can find the actual code.

## Phase 1 — Foundation & Architecture

| Plan path | Ships as | Notes |
|---|---|---|
| `docs/architecture.drawio` | [`docs/architecture.md`](docs/architecture.md) | Mermaid (component / sequence / network-isolation). Diffable in git, renders inline on GitHub. |
| `pyproject.toml` | [`pyproject.toml`](pyproject.toml) | — |
| `docker-compose.dev.yml` | [`docker-compose.dev.yml`](docker-compose.dev.yml) | — |
| `.github/workflows/ci.yml` | [`.github/workflows/ci.yml`](.github/workflows/ci.yml) | quality + unit + integration + migrations + dep-audit + container-scan |
| `alembic/versions/001_initial.py` | [`alembic/versions/001_initial.py`](alembic/versions/001_initial.py) | Plus `002_alerts_log_channel.py`, `003_tls_service.py` |
| `core/events.py` | [`src/honeystrike/core/events.py`](src/honeystrike/core/events.py) | — |
| `.pre-commit-config.yaml` | [`.pre-commit-config.yaml`](.pre-commit-config.yaml) | — |
| `.env.example` | [`.env.example`](.env.example) | — |

## Phase 2 — Honeypot listeners

| Plan path | Ships as | Notes |
|---|---|---|
| `services/ssh/server.py` | [`src/honeystrike/services/ssh/server.py`](src/honeystrike/services/ssh/server.py) | + `__main__.py` listener, `attempt_counter.py`, `host_key.py` |
| `services/ssh/shell.py` | [`src/honeystrike/services/ssh/shell.py`](src/honeystrike/services/ssh/shell.py) | — |
| `services/http/server.py` | [`src/honeystrike/services/http/server.py`](src/honeystrike/services/http/server.py) | — |
| `services/http/detectors.py` | [`src/honeystrike/services/http/detectors.py`](src/honeystrike/services/http/detectors.py) | — |
| `services/http/tls.py` | [`src/honeystrike/services/http/ja3.py`](src/honeystrike/services/http/ja3.py) | JA3-only — TLS termination lives in Caddy in prod, so the file is named for what it does (parses ClientHello → JA3) rather than a generic "tls". |
| `services/ftp/server.py` | [`src/honeystrike/services/ftp/handler.py`](src/honeystrike/services/ftp/handler.py) + [`__main__.py`](src/honeystrike/services/ftp/__main__.py) | Split: pyftpdlib `FTPHandler` subclass vs. the listener entrypoint. |
| `services/rdp/server.py` | [`src/honeystrike/services/rdp/pdu.py`](src/honeystrike/services/rdp/pdu.py) + [`__main__.py`](src/honeystrike/services/rdp/__main__.py) | Split: TPKT/X.224 parser vs. listener. |
| `core/session_manager.py` | [`src/honeystrike/core/session_manager.py`](src/honeystrike/core/session_manager.py) | — |
| `tests/integration/` | [`tests/integration/`](tests/integration/) | 34 live tests at last run |

## Phase 3 — Intelligence layer

| Plan path | Ships as | Notes |
|---|---|---|
| `workers/intel/geo.py` | [`src/honeystrike/workers/intel/geo.py`](src/honeystrike/workers/intel/geo.py) | — |
| `workers/intel/abuseipdb.py` | [`src/honeystrike/workers/intel/abuseipdb.py`](src/honeystrike/workers/intel/abuseipdb.py) | — |
| `workers/intel/signatures.py` | [`src/honeystrike/workers/intel/signatures.py`](src/honeystrike/workers/intel/signatures.py) | 7 tool signature rules |
| `workers/intel/fingerprint.py` | [`src/honeystrike/workers/intel/fingerprint.py`](src/honeystrike/workers/intel/fingerprint.py) | + the aggregator [`aggregator.py`](src/honeystrike/workers/intel/aggregator.py) |
| `workers/intel/ttp_rules.py` | [`src/honeystrike/workers/intel/ttp_rules.py`](src/honeystrike/workers/intel/ttp_rules.py) | 7 built-in MITRE ATT&CK rules + STIX bundle loader |
| `workers/intel/ttp_mapper.py` | folded into [`workers/intel/fingerprint.py`](src/honeystrike/workers/intel/fingerprint.py) (`_replace_ttp_matches`) | One worker, one transaction — fingerprint + TTP rows land atomically. |
| `workers/intel/scorer.py` | [`workers/intel/threat_scoring.py`](src/honeystrike/workers/intel/threat_scoring.py) | Renamed for clarity (it computes a `ThreatScore`, not "scores" things). |
| `workers/intel/alerting.py` | [`workers/alerting/worker.py`](src/honeystrike/workers/alerting/worker.py) + [`channels.py`](src/honeystrike/workers/alerting/channels.py) | Split into its own package — worker + the four `Channel` impls. |
| `tests/e2e/test_attack_flow.py` | [`tests/integration/test_alerting_live.py`](tests/integration/test_alerting_live.py) | E2E (probe → score → alert row) lives with the rest of the integration suite. |

## Phase 4 — Dashboard & reports

| Plan path | Ships as | Notes |
|---|---|---|
| `api/routers/stats.py` | [`src/honeystrike/api/routers/stats.py`](src/honeystrike/api/routers/stats.py) | — |
| `api/routers/sessions.py` | [`src/honeystrike/api/routers/sessions.py`](src/honeystrike/api/routers/sessions.py) | + the report download/trigger endpoints |
| `api/auth.py` | [`src/honeystrike/api/auth.py`](src/honeystrike/api/auth.py) | — |
| `api/ws.py` | [`src/honeystrike/api/ws.py`](src/honeystrike/api/ws.py) | — |
| `api/static/map.js` | [`src/honeystrike/api/static/dashboard.js`](src/honeystrike/api/static/dashboard.js) | Renamed — the page IS the map; not a separate "map.js". |
| `api/templates/` | [`src/honeystrike/api/templates/`](src/honeystrike/api/templates/) | `_base`, `login`, `dashboard`, `sessions`, `session_detail`, `analytics` |
| `api/templates/analytics.html` | [`src/honeystrike/api/templates/analytics.html`](src/honeystrike/api/templates/analytics.html) | + [`static/analytics.js`](src/honeystrike/api/static/analytics.js) |
| `reports/templates/report.html.j2` | [`src/honeystrike/workers/reports/templates/report.html.j2`](src/honeystrike/workers/reports/templates/report.html.j2) | Lives next to the renderer that uses it. |
| `reports/templates/report_html.j2` | [`workers/reports/templates/report.html.j2`](src/honeystrike/workers/reports/templates/report.html.j2) | One template serves the standalone-HTML output too; the PDF stage uses a separate [`report.pdf.html.j2`](src/honeystrike/workers/reports/templates/report.pdf.html.j2). |
| `workers/reports/generator.py` | [`workers/reports/worker.py`](src/honeystrike/workers/reports/worker.py) + [`renderer.py`](src/honeystrike/workers/reports/renderer.py) | Split: stream consumer vs. pure-Python renderer. |
| `workers/reports/trigger.py` | manual: API endpoint `POST /api/sessions/{id}/report`; auto: [`FingerprintWorker`](src/honeystrike/workers/intel/fingerprint.py) when score ≥ `report_auto_trigger_score`. | A dedicated trigger module would have just been a one-line wrapper around `publish_report_job`. |

## Phase 5 — Hardening + stretch

| Plan path | Ships as | Notes |
|---|---|---|
| `tests/unit/` ≥ 80% | [`tests/unit/`](tests/unit/) — gated at `--cov-fail-under=80` in CI | 84% as of last run |
| `.github/workflows/ci.yml` (bandit + pip-audit + trivy) | [`.github/workflows/ci.yml`](.github/workflows/ci.yml) | All three plus migration round-trip + coverage gate |
| `docker-compose.prod.yml` | [`docker-compose.prod.yml`](docker-compose.prod.yml) | — |
| `Caddyfile` | [`Caddyfile`](Caddyfile) | — |
| `infra/setup.sh` | [`infra/setup.sh`](infra/setup.sh) | — |
| `infra/backup.sh` | [`infra/backup.sh`](infra/backup.sh) | + [`update_maxmind.sh`](infra/update_maxmind.sh), [`deploy.sh`](infra/deploy.sh) |
| `workers/intel/ml_anomaly.py` | [`src/honeystrike/workers/intel/ml_anomaly.py`](src/honeystrike/workers/intel/ml_anomaly.py) | — |
| `api/routers/stix.py` | [`src/honeystrike/api/stix.py`](src/honeystrike/api/stix.py) | Top-level `api/` rather than `api/routers/` since it bundles `stix2` SDOs + a custom serialiser — closer to a feature module than a thin router. |
| `api/routers/taxii.py` | [`src/honeystrike/api/taxii.py`](src/honeystrike/api/taxii.py) | Same reasoning — owns the TAXII discovery + collection responses. |
| `infra/grafana/` | [`infra/grafana/`](infra/grafana/) | Dashboard JSON + datasource + dashboard provisioning |
| `17_V1.0_Release_Notes.md` | [`docs/17_V1.0_Release_Notes.md`](docs/17_V1.0_Release_Notes.md) | — |
| README | [`README.md`](README.md) | — |
| DEMO.md | [`DEMO.md`](DEMO.md) | 10-step walkthrough |
| sample report | [`samples/sample-session-report.pdf`](samples/sample-session-report.pdf) + [`.html`](samples/sample-session-report.html) | Generated against live attacker data |
| OpenAPI JSON | [`openapi.json`](openapi.json) | Pretty-printed export of the live `/api/openapi.json` |

## Beyond the plan — also shipped

| Item | Where |
|---|---|
| Loki + Promtail config | [`infra/loki/`](infra/loki/) |
| Events partition migration (operator-triggered) | [`infra/migrations/003_events_partitioning.sql`](infra/migrations/003_events_partitioning.sql) + [`workers/maintenance/partition_events.py`](src/honeystrike/workers/maintenance/partition_events.py) |
| TLS-fingerprint honeypot (JA3 sniffer) | [`services/tls_sniffer/`](src/honeystrike/services/tls_sniffer/) — fifth listener on `:8443` |
| Alembic 002 — `log` alert channel | [`alembic/versions/002_alerts_log_channel.py`](alembic/versions/002_alerts_log_channel.py) |
| Alembic 003 — `tls` session service | [`alembic/versions/003_tls_service.py`](alembic/versions/003_tls_service.py) |
