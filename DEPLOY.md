# Deploying HoneyStrike

This document walks an operator through the **partial-stack** deploy: Postgres + Redis + the four honeypot listeners. It is the foundation that Phase 3 (intel/alerting) and Phase 4 (dashboard/reports) build on top of.

> **Status as of writing:** every phase of the 18-week plan has shipped. The partial-stack collects raw events and (with `--profile intel`) fingerprints every closed session, maps it to MITRE ATT&CK techniques, assigns a 0–100 threat score, and pages a configurable set of channels (Telegram, email, Slack). The `--profile dashboard` adds the JSON API, the Leaflet attack map with live WebSocket updates, the Sessions browser + Analytics charts, the per-session detail page, the PDF/HTML report pipeline, and a Caddy reverse proxy with automatic Let's Encrypt TLS. Phase 5 stretch goals are in too: an Isolation-Forest anomaly worker, a STIX 2.1 bundle exporter, a read-only TAXII 2.1 server, a Grafana dashboard JSON, and a Loki + Promtail log-shipping config. Hardening: CI runs ruff + mypy + bandit + pip-audit + Trivy + a clean-DB Alembic round-trip; unit coverage is gated at ≥80% (current: 85%).

---

## 1. Prerequisites

| Item | Notes |
|---|---|
| VPS | 2 vCPU / 4 GB RAM minimum. Hetzner CX21, Ubuntu 24.04 LTS recommended (`docs/11_Infrastructure_Topology.md`). |
| Public IPv4 | Required. Most attackers scan IPv4. |
| Domain (optional) | Only needed in Phase 4 for the dashboard. Set a placeholder in `.env.production` until then. |
| Operator's static IP | Used to lock down the management SSH port via UFW. |
| SSH key | Pubkey added to the VPS's `~/.ssh/authorized_keys` for your operator user before running setup. |

**Hosting-provider check:** confirm your provider permits honeypot operations. Hetzner's ToS explicitly allow security research honeypots; inbound abuse reports are dismissed. Other providers vary — see `docs/07_Compliance_and_Legal_Packet.md` §5.

---

## 2. VPS bootstrap (run once)

SSH in as root over the cloud provider's console-issued password (you'll harden auth in the next step).

```bash
# Replace OPERATOR_IP with your static public IP. Get it wrong and you
# lock yourself out — open a second terminal to test the new port before
# closing this one.
curl -fsSL https://raw.githubusercontent.com/<you>/honeystrike/main/infra/setup.sh \
  | MGMT_SSH_PORT=2222 OPERATOR_IP=203.0.113.7 bash
```

What that does (idempotently):

1. `apt update + upgrade` + unattended-upgrades.
2. Installs Docker Engine + Compose v2, ufw, fail2ban.
3. Moves the management `sshd` to port 2222, disables root login, disables password auth.
4. UFW: deny inbound by default; allow 21/22/80/443/3389 from anywhere; allow 2222 from `OPERATOR_IP` only.
5. fail2ban guards the management SSH port (not 22 — that's the honeypot).
6. Creates `/opt/honeystrike` and `/backups/daily`.

**Verify in a second terminal before closing the first:**
```bash
ssh -p 2222 <user>@<your-vps>
```

---

## 3. Pull the code

```bash
cd /opt/honeystrike
git clone https://github.com/<you>/honeystrike .
```

---

## 4. Configure secrets

```bash
cp .env.production.example .env.production
$EDITOR .env.production
```

Generate strong values where the template says `GENERATE_ME_…`:

```bash
python3 -c "import secrets; print(secrets.token_hex(32))"      # SECRET_KEY
python3 -c "import secrets; print(secrets.token_urlsafe(24))"  # POSTGRES_PASSWORD / ADMIN_PASSWORD
```

Update `DATABASE_URL` so its password matches `POSTGRES_PASSWORD`.

> Phase 3 / Phase 4 fields (`TELEGRAM_TOKEN`, `ABUSEIPDB_KEY`, `MAXMIND_*`) can be left blank for the partial-stack. The listeners do not need them.

---

## 5. Build the image and migrate the database

```bash
docker compose -f docker-compose.prod.yml --env-file .env.production \
  --profile capture build

docker compose -f docker-compose.prod.yml --env-file .env.production \
  --profile migrate run --rm migrate
```

The migrate container exits after applying `alembic upgrade head`.

---

## 6. Start the partial-stack

```bash
docker compose -f docker-compose.prod.yml --env-file .env.production \
  --profile capture up -d
```

Verify:

```bash
docker compose -f docker-compose.prod.yml --env-file .env.production ps

# Each honeypot should reach the listener log line:
docker compose -f docker-compose.prod.yml logs ssh-honeypot  | tail
docker compose -f docker-compose.prod.yml logs http-honeypot | tail
docker compose -f docker-compose.prod.yml logs ftp-honeypot  | tail
docker compose -f docker-compose.prod.yml logs rdp-honeypot  | tail
```

Real attack traffic will start showing up within minutes; check with:

```bash
docker exec honeystrike-db psql -U honeystrike -d honeystrike \
  -c "SELECT service, count(*) FROM sessions
      WHERE started_at > NOW() - INTERVAL '1 hour'
      GROUP BY service ORDER BY count DESC;"
```

---

## 7. Install the backup cron

```bash
sudo tee /etc/cron.d/honeystrike-backup <<'EOF'
0 1 * * * root /opt/honeystrike/infra/backup.sh >> /var/log/honeystrike-backup.log 2>&1
EOF
```

Confirm with a manual run:

```bash
sudo bash /opt/honeystrike/infra/backup.sh
ls -lh /backups/daily/
```

`docs/14_DR_Playbook_and_Drills.md` covers the restore-validation drill — run it once before relying on the backups.

---

## 8. Day-2 operations

### Updates

```bash
sudo bash /opt/honeystrike/infra/deploy.sh capture
```

Pulls, builds, migrates, restarts in place.

### Adding intel / dashboard later

When Phase 3 lands, swap profile:

```bash
docker compose -f docker-compose.prod.yml --env-file .env.production \
  --profile intel up -d
```

Phase 4 adds Caddy + the dashboard with:

```bash
docker compose -f docker-compose.prod.yml --env-file .env.production \
  --profile dashboard up -d
```

The compose file is forwards-compatible by design — no rewrite needed.

### FingerprintWorker (Phase 3, Weeks 8–9)

The `fingerprint-worker` container subscribes to the `honeystrike:events` Redis stream under the `intel` consumer group and writes, for every closed session, one `fingerprints` row, 0..n `ttp_matches` rows, and an updated `threat_score` + `severity` on the parent `sessions` row. It does not bind any ports.

Pre-flight before first start:

1. Drop the MaxMind GeoLite2 City + ASN `.mmdb` files into the `maxmind_db` volume. The included `infra/update_maxmind.sh` automates this — point it at your MaxMind license key first.
2. (Optional) Set `ABUSEIPDB_KEY` in `.env.production`. Leaving it empty turns the AbuseIPDB lookup into a no-op; the rest of the enrichment still runs. The worker is fail-open on every external dependency.

Verifying the worker is healthy:

```bash
# Should log fingerprint.worker_started + fingerprint.consumer_group_created
docker compose -f docker-compose.prod.yml logs fingerprint-worker | tail

# Spot-check a recent fingerprint + TTP attribution:
docker exec honeystrike-db psql -U honeystrike -d honeystrike -c "
  SELECT s.id, s.service, s.threat_score, s.severity,
         jsonb_array_length(f.tool_signatures) AS tools,
         count(t.id) AS ttps
  FROM sessions s
  LEFT JOIN fingerprints f ON f.session_id = s.id
  LEFT JOIN ttp_matches t ON t.session_id = s.id
  WHERE s.started_at > NOW() - INTERVAL '1 hour'
  GROUP BY s.id, f.tool_signatures
  ORDER BY s.threat_score DESC LIMIT 10;"
```

Threat score & severity:

The worker writes a 0–100 `threat_score` and a `severity` bucket (`low` / `medium` / `high` / `critical`) onto every session. The formula combines four components and is stable enough that an operator can sanity-check a flagged session by reading the row:

| Component | Range | What contributes |
|---|---|---|
| Abuse | 0–40 | `round(abuse_score × 0.40)` from AbuseIPDB |
| Tool  | 0–30 | 15 per tool signature with confidence ≥ 0.70 |
| TTP   | 0–50 | `round(50 × mean(ttp confidences))` |
| Privilege | 0 or 25 | +25 if the session is attributed to T1078 (Valid Accounts) |

Severity thresholds: `<20 low`, `<50 medium`, `<80 high`, otherwise `critical`. Weights live in [`threat_scoring.py`](src/honeystrike/workers/intel/threat_scoring.py) and have unit tests pinning the boundary behaviour.

### AlertingWorker (Phase 3, Week 10)

The `alerting-worker` container subscribes to a separate `honeystrike:alerts` Redis stream under the `alerting` consumer group. The FingerprintWorker pushes onto that stream whenever a freshly-scored session clears `ALERT_THRESHOLD_HIGH` (default `60`). Each alert envelope carries the session id, source IP, severity, threat score, tool signatures, and TTP techniques — the worker formats one message and fans out to every enabled channel.

Channels enabled by config:

| Channel | Requires | Notes |
|---|---|---|
| `log` | Always on | Structured log line; backstop when nothing else is configured. |
| `telegram` | `TELEGRAM_TOKEN` + `TELEGRAM_CHAT_ID` | `sendMessage` Markdown payload. |
| `slack` | `SLACK_WEBHOOK_URL` | Incoming-webhook POST. |
| `email` | `SMTP_HOST` + `SMTP_TO` | STARTTLS; runs on a worker thread so the loop never blocks. |

Failure mode is fail-open per channel: a misconfigured or unreachable transport is logged but never blocks the others, and only the channels that actually succeeded are recorded in `alerts`.

Dedup: a Redis `SET NX` key `alert:dedup:{ip}:{severity}` with TTL `ALERT_COOLDOWN_SECONDS` (default 1800 = 30 min) suppresses repeat alerts from the same IP at the same severity within the window. Lower the cooldown if you prefer noisier alerts; raise it if a chatty scanner is generating too many pages.

Spot-check:

```bash
docker compose -f docker-compose.prod.yml logs alerting-worker | tail
docker exec honeystrike-db psql -U honeystrike -d honeystrike -c "
  SELECT a.channel, a.severity, a.threat_score, a.payload->>'subject' AS subject
  FROM alerts a
  WHERE a.dispatched_at > NOW() - INTERVAL '1 hour'
  ORDER BY a.dispatched_at DESC LIMIT 10;"
```

### Dashboard API (Phase 4, Week 11)

The `dashboard-api` container exposes a read-only FastAPI on container port 8000 (host port `8001` in dev, bound to `127.0.0.1` only in prod so a reverse proxy can terminate TLS).

Bring it up:

```bash
docker compose -f docker-compose.prod.yml --env-file .env.production \
  --profile dashboard up -d
```

First-time setup — create the admin user:

```bash
docker compose -f docker-compose.prod.yml --env-file .env.production \
  run --rm dashboard-api python -m honeystrike.api.bootstrap
```

The script reads `ADMIN_USERNAME` / `ADMIN_PASSWORD` from the env and is idempotent: re-running it rotates the password rather than failing.

Smoke-check:

```bash
curl http://127.0.0.1:8001/api/health
TOKEN=$(curl -s -X POST http://127.0.0.1:8001/api/auth/login \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"$ADMIN_USERNAME\",\"password\":\"$ADMIN_PASSWORD\"}" \
  | jq -r .access_token)
curl -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8001/api/stats/overview
```

Routes follow [docs/02_API_Contracts.md](docs/02_API_Contracts.md):

| Path | Description |
|---|---|
| `POST /api/auth/login` | Issue access token + set refresh cookie |
| `POST /api/auth/refresh` | New access token from refresh cookie |
| `POST /api/auth/logout` | Clear refresh cookie |
| `GET /api/sessions` | Paginated session list with filters |
| `GET /api/sessions/{id}` | Full session detail incl. fingerprint, TTPs, events preview, alerts |
| `GET /api/sessions/{id}/events` | Raw event log |
| `GET /api/stats/overview` | Aggregate dashboard rollup over `days` (default 7) |
| `GET /api/stats/ttps` | Top MITRE techniques over `days` |
| `GET /api/stats/geo` | Country breakdown over `days` |
| `GET /api/stats/timeline` | Session count + avg score, bucketed by hour or day |
| `GET /api/health` | DB + Redis liveness (no auth) |

Auth: HS256 JWT with `settings.secret_key`. Rotate by setting a fresh `SECRET_KEY` in `.env.production` and restarting. Existing tokens become invalid; users must re-login.

### Dashboard UI + WebSocket live feed (Phase 4, Week 12)

The `dashboard-api` container also serves the browser UI on the same port:

| Path | What it is |
|---|---|
| `/login` | Username + password form, POSTs to `/api/auth/login`, stores the access token in `sessionStorage`. |
| `/` | Live attack map (Leaflet, CartoDB dark tiles), 24-hour overview cards, rolling "recent sessions" sidebar. |
| `/sessions/{id}` | Per-session detail: source, fingerprint, MITRE TTPs, event preview, dispatched alerts. |
| `/api/ws/live?token=…` | WebSocket. Sends the most-recent 25 scored sessions as an initial seed (`type: "session"` per row, then `type: "seed_complete"`), then streams new fingerprints every 2 s. |

The WS handler polls the `fingerprints` table since its per-connection cursor — it does NOT introduce a third Redis stream. Latency is roughly `poll` seconds (default `2`, range `[0.5, 30]`). Browsers can't attach an `Authorization` header to a WebSocket handshake, so the client passes its access token as a query parameter; tokens stay short-lived to mitigate the leak surface.

To smoke-check the UI in dev:

```bash
# Open in a browser:
xdg-open http://localhost:8001/login
# Then sign in with $ADMIN_USERNAME / $ADMIN_PASSWORD.
```

In prod the API binds to `127.0.0.1:8001` only — terminate TLS in front of it with the [Caddyfile](Caddyfile) template that ships with the repo (Phase 5 hardening).

### Report worker (Phase 4, Week 14)

The `report-worker` container consumes `honeystrike:report_jobs` (consumer group `reports`) and renders one of two output formats per job:

| Format | Pipeline |
|---|---|
| `pdf` | Jinja → HTML → [WeasyPrint](https://weasyprint.org/) → PDF (A4, dark-on-light, paginated). |
| `html` | Jinja → self-contained HTML (collapsible sections, dark theme matching the dashboard). |

Producers:

- **`POST /api/sessions/{id}/report?format=pdf|html`** — returns 202 with a queued status; poll `GET /api/sessions/{id}/report?format=…` until it returns the file (404 until ready, 410 if expired).
- **FingerprintWorker auto-trigger** — every session that scores ≥ `REPORT_AUTO_TRIGGER_SCORE` (default 60) automatically gets a PDF queued at fingerprint time. Idempotent: re-runs overwrite the file and update the existing `reports` row, so re-delivery never piles up duplicates on disk.

Files land at `${REPORTS_DIR}/session-{uuid}.{pdf|html}` (default `/reports/…`). Retention follows `REPORTS_RETENTION_DAYS` (default 180): the [retention sweep](docs/06_Data_Retention_Matrix.md) Phase 5 cron deletes expired files and clears `reports.file_path`.

Spot-check:

```bash
docker compose -f docker-compose.prod.yml logs report-worker | tail
docker exec honeystrike-db psql -U honeystrike -d honeystrike -c "
  SELECT r.session_id, r.format, r.file_size_bytes, r.generated_at, r.expires_at
  FROM reports r
  ORDER BY r.generated_at DESC LIMIT 10;"
```

Security note: the templates render attacker-controlled fields (URI, headers, command tokens, payload preview). Jinja autoescape is forced on for `.html.j2` templates so an attacker that sticks `<script>` into a captured payload can't break out of the report's HTML — exercised by `test_render_html_escapes_attacker_payloads`.

### Caddy + TLS (Phase 4 Week 14 / Phase 5 Week 16)

Once `DOMAIN` is set in `.env.production` and the DNS record points at the VPS, bring the dashboard up with TLS:

```bash
docker compose -f docker-compose.prod.yml --env-file .env.production \
  --profile dashboard up -d
```

`caddy` does the heavy lifting:

- Listens on `80`, `443` (TCP + UDP/HTTP3) on the host.
- Auto-provisions a Let's Encrypt cert for `${DOMAIN}` on first start.
- Forwards everything to `dashboard-api:8000` over the internal Docker network.
- Adds HSTS, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy, and a Content-Security-Policy that whitelists only the Leaflet / Chart.js / CartoDB CDNs the UI needs.
- Detects WebSocket upgrades on `/api/ws/*` automatically.

The dashboard-api in prod no longer publishes a host port; only Caddy sees it. To rotate the cert, restart the `caddy` container — Caddy renews automatically about 30 days before expiry.

### Stretch goals (Phase 5 Weeks 17–18)

**Isolation-Forest anomaly detection** ([`workers/intel/ml_anomaly.py`](src/honeystrike/workers/intel/ml_anomaly.py)) — fits scikit-learn's `IsolationForest` on session-level features (`threat_score`, `abuse_score`, `tool_count`, `ttp_count`, `attempt_rate_rpm`, `event_count`, `duration_ms`, `is_high_severity`) over the last 24 h and writes `ml_anomaly_scores` rows. Run hourly from cron:

```bash
0 * * * * docker exec honeystrike-app python -m honeystrike.workers.intel.ml_anomaly
```

The detector is deliberately a batch job, not a per-session evaluator — Isolation Forest is most useful against a freshly-sampled baseline of recent traffic. `model_version` includes a hash of the feature names so an operator can tell at a glance which feature set produced which row.

**STIX 2.1 export** ([`api/stix.py`](src/honeystrike/api/stix.py)) — `GET /api/stix/bundle?days=7&min_score=60` returns a valid STIX 2.1 bundle of indicators / observed-data / sightings, ingestable by MISP, OpenCTI, and most SIEMs. `GET /api/stix/stats` gives a pre-flight bundle-size estimate.

**TAXII 2.1 read-only server** ([`api/taxii.py`](src/honeystrike/api/taxii.py)) — exposes the same bundle through the TAXII 2.1 discovery layout:

| Path | What |
|---|---|
| `GET /taxii2/` | Server discovery |
| `GET /taxii2/v1/` | API root metadata |
| `GET /taxii2/v1/collections/` | Collection list |
| `GET /taxii2/v1/collections/honeystrike-high-severity/` | Collection metadata |
| `GET /taxii2/v1/collections/honeystrike-high-severity/objects/?days=7&min_score=60` | STIX bundle |

Auth is the same Bearer JWT as the rest of the dashboard. Configure your TAXII client (`taxii2-client`, MISP TAXII module, etc.) to point at this URL with the access token in `Authorization`.

**Grafana dashboard** ([`infra/grafana/`](infra/grafana/)) — drop the JSON dashboard + datasource provisioning into a Grafana install pointed at the HoneyStrike Postgres. The dashboard has 13 panels (overview cards, sessions-per-hour by service, average threat score, severity pie, top TTPs, top countries, top IPs, recent alerts). DS_POSTGRES_PASSWORD must be set in the Grafana env.

**Loki + Promtail** ([`infra/loki/`](infra/loki/)) — minimal single-node Loki config + a Promtail scrape config that ships container stdout/stderr to Loki with `container`, `service`, `level`, `event`, `severity` labels. The JSON pipeline-stage extracts those labels from the structlog JSON output the production workers emit, so `{event="alert.dispatched"}` and `{severity="critical"}` queries work out of the box.

**`events` partition migration** ([`infra/migrations/003_events_partitioning.sql`](infra/migrations/003_events_partitioning.sql)) — operator-triggered (not on the Alembic chain). Convert the `events` table to monthly RANGE partitioning when daily volume exceeds 500k rows. Pre-creates 6 months back + 3 months ahead in one transaction and DROPs the legacy table only after a row-count sanity check passes. After this runs, schedule [`workers/maintenance/partition_events.py`](src/honeystrike/workers/maintenance/partition_events.py) daily to roll new monthly partitions forward.

### TLS-fingerprint honeypot (Phase 5 stretch — JA3)

The `tls-honeypot` container is a standalone JA3 sniffer:

- Listens on `:8443` (default; override with `HONEYPOT_TLS_HOST_PORT`).
- Reads the first TLS record, parses the ClientHello via [`services/http/ja3.py`](src/honeystrike/services/http/ja3.py).
- Opens a `service='tls'` session, emits a `TLS_CLIENT_HELLO` event containing the JA3 hash + SNI + cipher list, then closes with a `close_notify` alert.
- The FingerprintWorker recognises `TLS_CLIENT_HELLO` events via [`_extract_ja3_hash`](src/honeystrike/workers/intel/fingerprint.py) and persists the hash onto `fingerprints.ja3_hash` for the session.

Why a separate listener and not "in front of" Caddy: reverse proxies that terminate TLS consume the ClientHello bytes themselves and don't expose them downstream. The standalone sniffer captures the exact traffic we care about — attackers running TLS scanners against random ports — without slowing the dashboard's hot path.

Spot-check:

```bash
# From the host:
curl -sk --max-time 5 https://localhost:8443/

# Then:
docker exec honeystrike-db psql -U honeystrike -d honeystrike -c "
  SELECT s.id, f.ja3_hash, e.payload->>'sni' AS sni,
         jsonb_array_length(e.payload->'ciphers') AS ciphers
  FROM sessions s
  JOIN events e ON e.session_id = s.id AND e.event_type = 'TLS_CLIENT_HELLO'
  JOIN fingerprints f ON f.session_id = s.id
  WHERE s.service = 'tls'
  ORDER BY s.started_at DESC LIMIT 5;"
```

Operational notes:

- The worker reads in batches of 100 stream entries with a 5 s block timeout; sessions also get flushed when their idle timer expires (30 s) so short connections still produce fingerprints quickly.
- Re-delivery is safe: `fingerprints` has `ON CONFLICT (session_id) DO UPDATE`, so restart-after-crash never duplicates rows.
- Pending-list growth on the `intel` consumer group is the canary for the worker being stuck. Watch with:
  ```bash
  docker exec honeystrike-cache redis-cli XPENDING honeystrike:events intel
  ```
- Multi-service-scan signatures rely on the worker querying same-IP sibling sessions inside ±60 s. If you scale the workers horizontally, the query stays correct because every replica reads from the same Postgres view.

### Runbooks

For incident response see `docs/12_Production_Runbooks.md`. The relevant ones for partial-stack are:

- **RB-01** restart a crashed service
- **RB-03** Postgres disk-space warning
- **RB-07** manual database backup
- **RB-08** view live attack traffic

---

## 9. What's intentionally NOT here yet

| Item | Phase | Reason |
|---|---|---|
_None — every item from the 18-week plan has shipped. See `docs/architecture.md` for the system overview; the architecture diagram lives there as Mermaid (renders inline on GitHub, diffable in git) rather than as a binary `.drawio` file._
| JA3 wired to a live TLS listener | 5 | Needs Caddy + a raw TLS sniffer in front of port 443. |
| `events` partition migration | when `events` exceeds ~500k/day | See `docs/05_Indexes_and_Partitioning.sql`. |

---

## 10. Going-live checklist

Before pointing public DNS at the VPS or telling anyone the IP:

- [ ] Management SSH lives on a port other than 22 and is locked to `OPERATOR_IP`.
- [ ] `PermitRootLogin no` + `PasswordAuthentication no` confirmed in `sshd -T | grep -E 'permitrootlogin|passwordauth'`.
- [ ] UFW status shows the expected allow rules and nothing else.
- [ ] `docker compose ps` shows every container healthy.
- [ ] One successful manual backup exists in `/backups/daily/`.
- [ ] You've read `docs/18_HONEYSTRIKE_Compliance_Checklist.md` and the legal basis applies in your jurisdiction.
- [ ] You've accepted that without Phase 3, attacks are logged but **nobody is paged** — checking the dashboard manually is your only signal.
