# HoneyStrike — Production Readiness Verification

Complete this document before going live. Every item must be checked.  
**Verified by:** _____________  **Date:** _____________

---

## Section 1: Infrastructure

- [ ] VPS provisioned (Hetzner CX21 or equivalent, Ubuntu 24.04 LTS)
- [ ] Docker Engine + Compose v2 installed
- [ ] Real SSH management port moved off port 22 (e.g. 2222)
- [ ] UFW configured: allow 21, 22, 80, 443, 3389 inbound; deny all others
- [ ] Management SSH restricted to operator IP only
- [ ] Root login disabled (`PermitRootLogin no` in sshd_config)
- [ ] Unattended-upgrades installed and configured for security patches
- [ ] NTP synchronized (`timedatectl status` shows synchronized)
- [ ] Disk space confirmed: ≥ 30 GB free on volume hosting Docker and /backups

---

## Section 2: Secrets and Configuration

- [ ] `.env.production` created from `.env.example`
- [ ] `DATABASE_URL` set to production PostgreSQL connection string
- [ ] `SECRET_KEY` set to a cryptographically random value (≥ 32 bytes)
- [ ] `TELEGRAM_TOKEN` and `TELEGRAM_CHAT_ID` configured and tested
- [ ] `ABUSEIPDB_KEY` configured (AbuseIPDB account created)
- [ ] `MAXMIND_LICENSE_KEY` configured (free account created)
- [ ] `SMTP_*` variables configured if email alerting is used
- [ ] `SLACK_WEBHOOK_URL` configured if Slack alerting is used
- [ ] No secrets committed to git (run: `git log --all -S "password" --oneline`)
- [ ] `.env.production` is in `.gitignore`

---

## Section 3: Database

- [ ] `alembic upgrade head` completed without errors on production DB
- [ ] All tables present: sessions, events, fingerprints, ttp_matches, reports, alerts
- [ ] All indexes created (verify with `\di` in psql)
- [ ] PostgreSQL reachable only on internal Docker network (not on public interface)
- [ ] Daily backup cron configured (`/etc/cron.d/honeystrike-backup`)
- [ ] Backup restore drill completed at least once (`ci/db-restore-validate.sh`)
- [ ] `/backups/daily/` directory exists with correct permissions

---

## Section 4: Docker Stack

- [ ] `docker compose -f docker-compose.prod.yml build` completes without errors
- [ ] `docker compose -f docker-compose.prod.yml up -d` starts all 9 containers
- [ ] `docker compose ps` shows all containers as "running" (not "restarting")
- [ ] `restart: unless-stopped` set on all services in docker-compose.prod.yml
- [ ] Docker networks verified: honeypot-net and internal-net exist
- [ ] Honeypot services are on honeypot-net only (not directly reachable on internal-net)
- [ ] PostgreSQL and Redis not exposed on any public interface

---

## Section 5: Security Hardening

- [ ] All containers run as non-root (UID 1000)
- [ ] Container rootfs is read-only where possible
- [ ] `cap_drop: ALL` set; only `NET_BIND_SERVICE` added where needed
- [ ] Trivy scan passed: zero CRITICAL CVEs in all images
- [ ] No hardcoded credentials anywhere in Docker image layers (`docker history`)
- [ ] Caddy reverse proxy is the only entry point to the dashboard API
- [ ] Dashboard not accessible via direct IP:8000 from outside
- [ ] JWT secret is set and is ≥ 32 random characters

---

## Section 6: TLS and Domain

- [ ] Domain A record points to VPS IP
- [ ] Caddy starts and provisions Let's Encrypt certificate automatically
- [ ] `curl -vI https://your-domain.com` shows valid certificate
- [ ] Certificate expiry is > 60 days from now
- [ ] HTTP → HTTPS redirect working (`curl -I http://your-domain.com` returns 301)
- [ ] HSTS header present in response

---

## Section 7: Honeypot Services

- [ ] SSH service: `ssh root@your-domain.com` connects and shows fake banner
- [ ] HTTP service: `curl http://your-domain.com/wp-admin` returns fake admin page
- [ ] FTP service: `ftp your-domain.com` connects and shows banner
- [ ] RDP service: TCP connection to port 3389 returns RDP preamble
- [ ] All 4 connection tests generated events in Redis stream
- [ ] All 4 connection tests generated session rows in PostgreSQL

---

## Section 8: Intelligence Pipeline

- [ ] MaxMind database files present in `/maxmind/` volume (GeoLite2-City.mmdb, GeoLite2-ASN.mmdb)
- [ ] Geolocation test: query a known IP returns correct country
- [ ] AbuseIPDB test: query returns HTTP 200 (not 429 rate-limited)
- [ ] TTP rules file loads without errors (check intel-worker startup log)
- [ ] MITRE ATT&CK STIX bundle present and loaded

---

## Section 9: Alerting

- [ ] Telegram: send test alert via API (`RB-05` in runbooks) — message received in Telegram
- [ ] Email: send test email — received without spam filter issues
- [ ] Alert cooldown working: duplicate alert suppressed within 30-min window
- [ ] Alert log visible in dashboard

---

## Section 10: Dashboard and Reports

- [ ] Dashboard accessible at `https://your-domain.com`
- [ ] Login works with configured admin credentials
- [ ] Sessions list shows at least one session (from pre-launch test connection)
- [ ] Live attack map loads and shows marker for test session
- [ ] WebSocket connection established (browser DevTools → Network → WS tab)
- [ ] Analytics charts render correctly
- [ ] PDF report: trigger generation for a test session — PDF downloads successfully
- [ ] HTML report: trigger generation — opens in browser correctly

---

## Section 11: Observability

- [ ] Structured logs visible: `docker compose logs intel-worker | python3 -m json.tool`
- [ ] Prometheus metrics endpoint responds: `curl http://localhost:9090/metrics`
- [ ] Grafana (if deployed): dashboard loads and shows data

---

## Section 12: Final Sign-Off

| Check | Result | Signed off by |
|-------|--------|-------------|
| All items above checked | PASS / FAIL | |
| DR drill completed | PASS / FAIL | |
| Test attack session generated full pipeline (session → fingerprint → TTP → alert → report) | PASS / FAIL | |
| Portfolio demo session recorded (screenshot / video) | DONE / PENDING | |

**Go-live authorised:** YES / NO

**Notes:**
