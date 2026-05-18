# HoneyStrike — Master Specification

**Version:** 1.0  **Status:** Baseline  **Date:** May 2026

---

## 1. Purpose

HoneyStrike is an active honeypot platform designed to:

- Attract and capture real internet attacker interactions via convincing fake service listeners
- Fingerprint threat actors using IP reputation, geolocation, tool signatures, and TLS fingerprints
- Map observed attacker behaviour to MITRE ATT&CK techniques automatically
- Emit real-time alerts via Telegram, email, and Slack
- Generate professional PDF and HTML threat intelligence reports per attacker session
- Provide a live web dashboard with an attack map and analytics

---

## 2. Design Goals

| Goal | Requirement |
|------|-------------|
| Realism | Honeypot services must respond correctly enough to advance past first-connection scanners |
| Modularity | Each subsystem behind a typed Python Protocol interface; independently replaceable |
| Observability | Structured JSON logs (structlog), Prometheus metrics, Grafana dashboard |
| Zero-trust data | All attacker-supplied input treated as untrusted; sanitised before any persistence |
| Deployability | Full stack runs on a 2 vCPU / 4 GB RAM VPS with a single `docker compose up -d` |

---

## 3. System Modules

### M1 — Honeypot Services (Capture Layer)

| Service | Port | Protocol | Library |
|---------|------|----------|---------|
| SSH | 22 | TCP | Paramiko |
| HTTP/HTTPS | 80 / 443 | TCP | FastAPI (separate instance) |
| FTP | 21 | TCP | pyftpdlib |
| RDP | 3389 | TCP | Raw asyncio socket |

**SSH service:** Banner spoofing (configurable version string), KEX algorithm capture, username/password/key capture, post-auth shell with command logging. Session cap: 300s.

**HTTP/HTTPS service:** Serves fake `/wp-admin`, `/phpmyadmin`, `/admin` panels. Captures full HTTP request (method, URI, headers, body, User-Agent). Detects SQLi patterns, path traversal, scanner User-Agent strings (Masscan, Nikto, sqlmap, Hydra). JA3 fingerprint on HTTPS.

**FTP service:** Configurable banner. Captures AUTH/USER/PASS/LIST/RETR/STOR sequences. Records filenames attackers attempt to retrieve. Session cap: 120s.

**RDP service:** Responds with valid RDP Connection Confirm PDU + NLA negotiation. Captures client build number, protocol flags, CredSSP TSRequest (domain, username). Drops after NLA exchange.

---

### M2 — Fingerprint Engine

- **Geolocation:** MaxMind GeoLite2-City + ASN local database. Output: country, city, lat/lon, ASN, org. Redis cache TTL: 24h.
- **Tool signatures:** Rule-based matching on User-Agent, SSH KEX order, timing patterns, command sequences. Detects: Hydra, Medusa, Masscan, Nmap, sqlmap, Nikto, Metasploit. Returns `{tool_name, confidence}`.
- **AbuseIPDB:** v2 API enrichment — abuse confidence score, total reports. Rate-limited (1000 req/day free tier), Redis cache 6h TTL. Non-blocking on failure.
- **JA3 TLS fingerprint:** MD5 of ClientHello (cipher suites, extensions, elliptic curves). Identifies attacker TLS library.
- **Timing pattern:** Classifies session as `burst` / `slow` / `random` based on inter-event timing.

---

### M3 — TTP Mapper

Uses `mitreattack-python` STIX 2.1 data bundle. Rule-based mapper: each rule is a Python dataclass with a `match_fn(AttackEvent) -> bool` and output `(technique_id, tactic, confidence)`.

**Built-in rules (v1.0):**

| Technique | Trigger | Confidence |
|-----------|---------|-----------|
| T1110.001 — Password Guessing | SSH/FTP auth attempts > 5 | 0.90 |
| T1110.004 — Credential Stuffing | > 10 distinct username/pw pairs | 0.85 |
| T1190 — Exploit Public-Facing App | CVE signatures in HTTP URI/body | 0.80 |
| T1083 — File & Directory Discovery | FTP LIST+RETR or HTTP path enum | 0.75 |
| T1595.001 — Scanning IP Blocks | Single IP hits > 2 services in 60s | 0.95 |
| T1592 — Gather Victim Host Info | SSH banner grab + immediate disconnect | 0.70 |
| T1078 — Valid Accounts | Post-auth honeypot grant | 0.60 |

---

### M4 — Alerting Engine

**Threat score formula (0–100):**

```
score  = min(abuse_score * 0.2, 20)   # AbuseIPDB
score += len(ttps_matched) * 12        # Per TTP matched
score += tool_confidence * 15          # Tool signature
score += (attempt_rate_rpm > 50) * 10  # High rate
score += (multi_service_hit) * 10      # Multi-service
score  = min(round(score), 100)
```

**Severity thresholds:**

| Score | Severity | Action |
|-------|---------|--------|
| 0–29 | Low | Log only |
| 30–59 | Medium | Telegram + email |
| 60–79 | High | All channels + auto-generate report |
| 80–100 | Critical | All channels + Slack + priority report |

Duplicate suppression: same IP re-alerts only after 30-min cooldown or score increase ≥ 20.

---

### M5 — Report Generator

- **PDF:** WeasyPrint + Jinja2 CSS template. Sections: executive summary, attacker profile card, geolocation, TTPs (with MITRE descriptions), raw event log (truncated to 50 lines), threat score gauge.
- **HTML:** Self-contained single-file report. Same content as PDF with collapsible sections and sortable event log. Embeds a mini attack map snippet.
- Triggered automatically for sessions with score ≥ 60. Manual trigger available via API.

---

### M6 — Dashboard & Analytics API

- **Live attack map:** Leaflet.js + FastAPI WebSocket. Animated dot markers coloured by threat score (green → amber → red). Click-to-expand session detail sidebar.
- **Admin dashboard:** HTMX-driven (no heavy JS framework). Pages: Sessions list, Session detail, TTP frequency chart, Top attacker IPs, Alerts log.
- **Analytics endpoints:** `/api/stats/overview`, `/api/stats/ttps`, `/api/stats/geo`, `/api/stats/timeline`. Date-range filtering supported.
- Auth: JWT RS256. 1h access token + 7d refresh in HttpOnly cookie.

---

### Stretch — ML Anomaly Detection

Isolation Forest (scikit-learn) trained on: timing patterns, attempt counts, command sequences, geo clustering. Anomaly score threshold configurable. Weekly retraining cron job on accumulated session data.

### Stretch — STIX/TAXII Export

`python-stix2` exports attacker profiles + TTP matches as STIX 2.1 Bundles. TAXII 2.1 server endpoint for threat intel sharing with compatible platforms.

---

## 4. Non-Functional Requirements

| Requirement | Target |
|------------|--------|
| Event ingestion | 500 events/sec sustained |
| Fingerprint enrichment | < 50ms p99 |
| API response | < 200ms p95 |
| PDF report generation | < 5s |
| Alerting latency | < 30s from event to Telegram |
| Uptime (honeypot services) | 99.9% |
| Test coverage | ≥ 80% |
| Container CVEs | Zero CRITICAL in CI |

---

## 5. Out of Scope (v1.0)

- Full protocol specification compliance
- Active deception / moving target defence
- Multi-tenancy
- Windows honeypot services
- Kubernetes deployment (v2 consideration)
