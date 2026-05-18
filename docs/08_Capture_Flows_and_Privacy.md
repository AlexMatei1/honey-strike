# HoneyStrike — Capture Flows and Privacy Controls

---

## 1. Data Capture Flow Per Service

### SSH Capture Flow

```
Attacker TCP connect → session_id created → SESSION_OPEN emitted
    │
    ├─ Client sends SSH version string → captured as client_version
    ├─ KEX negotiation → cipher suites captured
    │
    ├─ AUTH ATTEMPT (password)
    │     username → captured raw
    │     password → captured raw (max 256 chars, truncated)
    │     → SSH_AUTH_ATTEMPT event emitted
    │
    ├─ AUTH ATTEMPT (publickey)
    │     username → captured
    │     key fingerprint → captured (not the key itself)
    │     → SSH_AUTH_ATTEMPT event emitted
    │
    ├─ Honeypot grants login after N attempts (configurable)
    │
    ├─ POST-AUTH SHELL
    │     Each command → SSH_COMMAND event
    │     Raw output not sent (no real shell — fake prompt)
    │     Max session: 300s
    │
    └─ Disconnect → SESSION_CLOSE emitted
```

### HTTP Capture Flow

```
Attacker TCP connect → SESSION_OPEN
    │
    ├─ HTTP request received
    │     Method, URI, HTTP version → captured
    │     All headers → captured (including cookies)
    │     Request body → captured up to 64KB, truncated with flag
    │     User-Agent → matched against scanner signatures
    │     URI → matched against CVE pattern library
    │     Body → scanned for SQLi/XSS patterns (regex, non-blocking)
    │
    ├─ Honeypot responds with realistic fake page (200 OK + HTML)
    │
    └─ Connection close or keep-alive next request
```

### FTP Capture Flow

```
TCP connect → SESSION_OPEN
    │
    ├─ Banner sent: "220 FTP server ready"
    ├─ AUTH → ignored (legacy FTP)
    ├─ USER <username> → captured
    ├─ PASS <password> → captured (max 256 chars)
    ├─ Honeypot responds 230 Login successful
    │
    ├─ Command sequence:
    │     LIST → captured (returns fake directory listing)
    │     RETR <path> → path captured → 550 No such file
    │     STOR <path> → path captured → 553 Permission denied
    │
    └─ Disconnect → SESSION_CLOSE (max 120s)
```

### RDP Capture Flow

```
TCP connect on 3389 → SESSION_OPEN
    │
    ├─ RDP Connection Request PDU → captured
    │     Cookie (mstshash=username) → captured
    ├─ RDP Connection Confirm PDU sent (server response)
    │
    ├─ NLA Negotiation (CredSSP TSRequest)
    │     Domain → captured
    │     Username → captured
    │     Password hash → NOT captured (NTS hash not broken in real-time)
    │
    └─ Connection dropped after NLA exchange
```

---

## 2. PII Handling and Sanitisation

### What constitutes PII in captured data

| Data item | PII? | Handling |
|-----------|------|---------|
| IP address | Yes (EU) | Retained per retention matrix; never published raw |
| Username | Possibly | Stored as-is — usually "root", "admin", "oracle" |
| Password | Possibly | Stored as-is — usually wordlist entries; never cracked or used |
| Email in HTTP body | Possibly | Stored as part of body JSONB; not extracted separately |
| Domain/username (RDP) | Possibly | Stored as-is |
| Geolocation (city) | Derived | Retained; not published at city level externally |

### Sanitisation rules enforced at the application layer

1. **SQL injection prevention:** All captured data is inserted via SQLAlchemy parameterised queries. Attacker payloads that contain SQL are stored as inert string data.

2. **XSS prevention in reports:** Jinja2 autoescaping is enabled on all report templates. Attacker payloads are `|e` escaped before HTML rendering.

3. **Size limits:** All payload fields are truncated at ingestion:
   - Password fields: 256 characters
   - HTTP body: 64 KB
   - SSH commands: 4 KB
   - FTP paths: 1 KB
   - RDP domain/username: 256 characters

4. **No execution:** Captured commands (SSH, FTP) are stored as strings. They are never passed to any shell, eval, or interpreter.

5. **No outbound data to attackers:** The fingerprint enrichment pipeline only makes outbound calls to MaxMind (local database, no outbound) and AbuseIPDB. No data is sent back to the attacker's IP.

---

## 3. Operator Data Access Controls

- Dashboard access requires JWT authentication (no public endpoints expose raw session data)
- Reports contain full attacker data — treat as sensitive; do not share publicly without anonymisation
- API access logs are written to the `alerts` table (operator IP + action + timestamp)
- Redis event stream: access restricted to internal Docker network only
