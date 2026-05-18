# HoneyStrike — Architecture

Authored as Mermaid in lieu of `architecture.drawio` (a binary editor artefact); these diagrams render natively in GitHub, are diffable in git, and stay in sync with the code far more reliably than an exported PNG.

For prose, see [`01_SPEC_Master.md`](01_SPEC_Master.md) and [`11_Infrastructure_Topology.md`](11_Infrastructure_Topology.md).

---

## 1. Component view

```mermaid
flowchart LR
    %% --- styling -----------------------------------------------------------
    classDef honeypot fill:#1f2530,stroke:#f0883e,color:#e6edf3
    classDef worker   fill:#1f2530,stroke:#58a6ff,color:#e6edf3
    classDef api      fill:#1f2530,stroke:#5fb878,color:#e6edf3
    classDef store    fill:#161b22,stroke:#8b949e,color:#e6edf3,stroke-dasharray: 5 5
    classDef channel  fill:#1f2530,stroke:#d29922,color:#e6edf3

    %% --- attackers ---------------------------------------------------------
    Attacker[/" Internet attacker "/]

    %% --- honeypot listeners ------------------------------------------------
    subgraph Honeypots["honeypot-net"]
      SSH["ssh-honeypot<br/>(Paramiko, :22)"]:::honeypot
      HTTP["http-honeypot<br/>(FastAPI, :80)"]:::honeypot
      FTP["ftp-honeypot<br/>(pyftpdlib, :21)"]:::honeypot
      RDP["rdp-honeypot<br/>(asyncio raw, :3389)"]:::honeypot
      TLS["tls-honeypot<br/>(JA3 sniffer, :443)"]:::honeypot
    end

    %% --- stores ------------------------------------------------------------
    subgraph Stores["internal-net"]
      Redis[("Redis 7<br/>streams + cache")]:::store
      Postgres[("Postgres 16<br/>events, fingerprints,<br/>ttp_matches, alerts,<br/>reports, ml_anomaly_scores")]:::store
    end

    %% --- workers -----------------------------------------------------------
    subgraph Workers["intel + alerting + reports"]
      Fingerprint["FingerprintWorker<br/>(consumer-group: intel)"]:::worker
      Alerting["AlertingWorker<br/>(consumer-group: alerting)"]:::worker
      Reports["ReportWorker<br/>(consumer-group: reports)"]:::worker
      ML["MLAnomalyWorker<br/>(cron-driven)"]:::worker
    end

    %% --- API / UI ----------------------------------------------------------
    subgraph Dashboard["dashboard profile"]
      Caddy["Caddy<br/>(Let's Encrypt TLS, :443)"]:::api
      Dash["dashboard-api<br/>(FastAPI :8000)"]:::api
      UI["Leaflet map · Sessions · Analytics · Detail · Login<br/>(static Jinja templates)"]:::api
      STIX["STIX 2.1 + TAXII 2.1"]:::api
      WS["WebSocket live feed<br/>(/api/ws/live)"]:::api
    end

    %% --- alert channels ----------------------------------------------------
    subgraph Channels["alert dispatch"]
      Telegram["Telegram"]:::channel
      Email["SMTP"]:::channel
      Slack["Slack webhook"]:::channel
      LogCh["log channel<br/>(always on)"]:::channel
    end

    %% --- operator + SIEM ---------------------------------------------------
    Operator[/" Operator browser "/]
    SIEM[/" SIEM / MISP / OpenCTI "/]
    Grafana[/" Grafana + Loki "/]

    %% --- flows -------------------------------------------------------------
    Attacker -->|ssh| SSH
    Attacker -->|http| HTTP
    Attacker -->|ftp| FTP
    Attacker -->|rdp| RDP
    Attacker -->|tls handshake| TLS

    SSH  --> Postgres
    HTTP --> Postgres
    FTP  --> Postgres
    RDP  --> Postgres
    TLS  --> Postgres
    SSH  --> Redis
    HTTP --> Redis
    FTP  --> Redis
    RDP  --> Redis
    TLS  --> Redis

    Redis -->|honeystrike:events| Fingerprint
    Fingerprint -->|fingerprints, ttp_matches,<br/>session threat_score| Postgres
    Fingerprint -->|honeystrike:alerts| Redis
    Fingerprint -->|honeystrike:report_jobs| Redis

    Redis -->|honeystrike:alerts| Alerting
    Alerting -->|alerts rows| Postgres
    Alerting --> Telegram
    Alerting --> Email
    Alerting --> Slack
    Alerting --> LogCh

    Redis -->|honeystrike:report_jobs| Reports
    Reports -->|reports rows + PDF/HTML files| Postgres
    Reports -->|/reports volume| Dash

    Postgres -->|session features| ML
    ML -->|ml_anomaly_scores| Postgres

    Operator -->|HTTPS| Caddy
    Caddy --> Dash
    Dash <--> Postgres
    Dash <-->|live updates| WS
    WS --> Operator
    Dash --> UI
    UI --> Operator
    SIEM -->|HTTPS| Caddy
    Caddy --> STIX
    STIX --> Postgres
    Grafana -->|read-only SQL| Postgres
```

---

## 2. Per-session lifecycle

```mermaid
sequenceDiagram
    autonumber
    actor Attacker
    participant Listener as Honeypot listener
    participant SM as SessionManager
    participant PG as Postgres
    participant R as Redis stream
    participant FW as FingerprintWorker
    participant AW as AlertingWorker
    participant RW as ReportWorker

    Attacker->>Listener: TCP connect / handshake
    Listener->>SM: open(service, src_ip, src_port)
    SM->>PG: INSERT sessions (state=OPEN)
    SM->>R: XADD SESSION_OPEN

    loop attack events
        Attacker->>Listener: command / request / packet
        Listener->>SM: record_event(event_type, payload)
        SM->>PG: INSERT events
        SM->>R: XADD <event_type>
    end

    Attacker--xListener: disconnect / timeout
    Listener->>SM: close(event_count, duration_ms, reason)
    SM->>PG: UPDATE sessions (state=CLOSED, …)
    SM->>R: XADD SESSION_CLOSE

    R-->>FW: drain via XREADGROUP (group=intel)
    FW->>PG: SELECT geo · sibling_sessions
    FW->>FW: tool sigs + TTP rules + threat score
    FW->>PG: UPSERT fingerprints, REPLACE ttp_matches,<br/>UPDATE sessions.threat_score
    Note over FW: if score ≥ ALERT_THRESHOLD_HIGH<br/>publish to honeystrike:alerts
    Note over FW: if score ≥ REPORT_AUTO_TRIGGER_SCORE<br/>publish to honeystrike:report_jobs

    R-->>AW: XREADGROUP (group=alerting)
    AW->>R: SET NX alert:dedup:{ip}:{severity}
    AW->>AW: fan-out: telegram / email / slack / log
    AW->>PG: INSERT alerts (one row per channel)

    R-->>RW: XREADGROUP (group=reports)
    RW->>PG: SELECT session + fingerprint + ttps + events + alerts
    RW->>RW: Jinja → HTML → WeasyPrint → PDF
    RW->>PG: REPLACE reports row
    RW->>RW: write file to /reports
```

---

## 3. Network isolation (prod, --profile dashboard)

```mermaid
flowchart LR
    classDef pub fill:#1f2530,stroke:#f85149,color:#e6edf3
    classDef ho  fill:#1f2530,stroke:#f0883e,color:#e6edf3
    classDef int fill:#1f2530,stroke:#58a6ff,color:#e6edf3
    classDef store fill:#161b22,stroke:#8b949e,color:#e6edf3,stroke-dasharray: 5 5

    Internet[/" Internet "/]:::pub

    subgraph HoneypotNet["honeypot-net (172.20.0.0/24, public-facing)"]
      SSH:::ho
      HTTP:::ho
      FTP:::ho
      RDP:::ho
      TLS:::ho
      Caddy:::ho
    end

    subgraph InternalNet["internal-net (172.21.0.0/24, no inbound from internet)"]
      Dash["dashboard-api"]:::int
      FW["fingerprint-worker"]:::int
      AW["alerting-worker"]:::int
      RW["report-worker"]:::int
      Redis[("Redis")]:::store
      Postgres[("Postgres")]:::store
    end

    Internet --> SSH
    Internet --> HTTP
    Internet --> FTP
    Internet --> RDP
    Internet --> TLS
    Internet --> Caddy

    SSH --> Redis
    HTTP --> Redis
    FTP --> Redis
    RDP --> Redis
    TLS --> Redis
    SSH --> Postgres
    HTTP --> Postgres
    FTP --> Postgres
    RDP --> Postgres
    TLS --> Postgres

    Caddy --> Dash
    Dash <--> Postgres
    Dash <--> Redis
    FW <--> Postgres
    FW <--> Redis
    AW <--> Postgres
    AW <--> Redis
    RW <--> Postgres
    RW <--> Redis
```

Postgres and Redis are never on `honeypot-net` — a compromised honeypot process can publish to Redis and call into Postgres via SQLAlchemy on `internal-net`, but cannot serve those datastores publicly. UFW on the VPS only opens 22 / 80 / 443 / 21 / 3389 / 8443 inbound; the management SSH port is locked to the operator IP.

---

## 4. Streams + consumer groups

| Stream | Producer(s) | Consumer group | Consumer |
|---|---|---|---|
| `honeystrike:events` | every honeypot listener (via `SessionManager`) | `intel` | FingerprintWorker |
| `honeystrike:alerts` | FingerprintWorker (when score ≥ threshold) | `alerting` | AlertingWorker |
| `honeystrike:report_jobs` | FingerprintWorker auto-trigger + `POST /api/sessions/{id}/report` | `reports` | ReportWorker |

Streams use Redis's `XADD … MAXLEN ~` cap so the backlog is bounded; consumer groups give every worker exactly-once semantics under graceful restart. Re-delivery during crash recovery is idempotent because every persistence path (`fingerprints`, `ttp_matches`, `reports`) uses `ON CONFLICT (session_id) DO UPDATE` or `DELETE + INSERT`.
