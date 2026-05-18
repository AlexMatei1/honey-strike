# HoneyStrike — API Contracts

**Version:** 1.0  **Base URL:** `https://{your-domain}/api`  **Auth:** Bearer JWT (RS256)

---

## Authentication

### `POST /api/auth/login`

```json
Request:
{ "username": "admin", "password": "string" }

Response 200:
{
  "access_token": "eyJ...",
  "token_type": "bearer",
  "expires_in": 3600
}
```

Refresh token set as HttpOnly cookie `hs_refresh`. Access token must be sent as `Authorization: Bearer {token}` on all protected endpoints.

---

## Sessions

### `GET /api/sessions`

List sessions, paginated and filterable.

**Query params:**

| Param | Type | Default | Description |
|-------|------|---------|-------------|
| page | int | 1 | Page number |
| limit | int | 50 | Max 200 |
| service | string | — | ssh \| http \| ftp \| rdp |
| min_score | int | — | Filter by minimum threat score |
| from_ts | ISO8601 | — | Start of time window |
| to_ts | ISO8601 | — | End of time window |

**Response 200:**
```json
{
  "total": 1402,
  "page": 1,
  "limit": 50,
  "items": [
    {
      "id": "uuid",
      "src_ip": "192.168.1.1",
      "service": "ssh",
      "state": "CLOSED",
      "threat_score": 74,
      "severity": "high",
      "country_iso": "RU",
      "started_at": "2026-05-16T14:22:00Z",
      "ended_at": "2026-05-16T14:22:45Z",
      "duration_ms": 45000,
      "ttp_count": 3
    }
  ]
}
```

---

### `GET /api/sessions/{id}`

Full session detail including fingerprint, TTPs, events (truncated), and alerts.

**Response 200:**
```json
{
  "id": "uuid",
  "src_ip": "1.2.3.4",
  "service": "ssh",
  "state": "CLOSED",
  "threat_score": 74,
  "severity": "high",
  "fingerprint": {
    "country_iso": "CN",
    "city": "Beijing",
    "lat": 39.9042,
    "lon": 116.4074,
    "asn": 4134,
    "org": "CHINANET-BACKBONE",
    "abuse_score": 82,
    "tool_signatures": [{ "name": "Hydra", "confidence": 0.92 }],
    "ja3_hash": "a0e9f5d64349fb13191bc781f81f42e1",
    "timing_pattern": "burst",
    "attempt_rate_rpm": 240.5
  },
  "ttps": [
    {
      "technique_id": "T1110.001",
      "name": "Brute Force: Password Guessing",
      "tactic": "Credential Access",
      "confidence": 0.90,
      "matched_at": "2026-05-16T14:22:15Z"
    }
  ],
  "events": { "total": 312, "preview": [...] },
  "alerts": [
    {
      "channel": "telegram",
      "severity": "high",
      "dispatched_at": "2026-05-16T14:22:20Z"
    }
  ]
}
```

---

### `GET /api/sessions/{id}/events`

Raw event log for a session.

**Query params:** `event_type` (optional filter), `limit` (default 100, max 1000), `offset`

**Response 200:**
```json
{
  "total": 312,
  "items": [
    {
      "id": "uuid",
      "event_type": "AUTH_ATTEMPT",
      "service": "ssh",
      "timestamp": "2026-05-16T14:22:05Z",
      "payload": {
        "username": "root",
        "password": "123456",
        "auth_type": "password"
      }
    }
  ]
}
```

---

### `GET /api/sessions/{id}/report`

Download generated threat intel report.

**Query params:** `format=pdf|html` (required)

**Response:** File download (`Content-Type: application/pdf` or `text/html`)

**Response 404:** If report not yet generated for this session.

---

### `POST /api/sessions/{id}/report`

Trigger report generation asynchronously.

**Response 202:**
```json
{ "report_id": "uuid", "status": "queued", "estimated_seconds": 5 }
```

---

## Analytics

### `GET /api/stats/overview`

**Query params:** `days=7` (default)

**Response 200:**
```json
{
  "period_days": 7,
  "total_sessions": 892,
  "unique_ips": 441,
  "sessions_by_service": { "ssh": 612, "http": 180, "ftp": 72, "rdp": 28 },
  "severity_breakdown": { "low": 310, "medium": 412, "high": 148, "critical": 22 },
  "top_countries": [{ "iso": "CN", "count": 201 }, { "iso": "RU", "count": 112 }],
  "top_ttps": [{ "technique_id": "T1110.001", "count": 534 }],
  "avg_threat_score": 41.2
}
```

### `GET /api/stats/ttps`

**Query params:** `limit=20`, `days=30`

**Response 200:**
```json
[{ "technique_id": "T1110.001", "name": "Password Guessing", "tactic": "Credential Access", "count": 892, "pct": 63.1 }]
```

### `GET /api/stats/geo`

**Response 200:**
```json
[{ "country_iso": "CN", "country_name": "China", "count": 440, "pct": 31.2 }]
```

### `GET /api/stats/timeline`

**Query params:** `days=7`, `bucket=hour` (hour \| day)

**Response 200:**
```json
[{ "bucket": "2026-05-16T14:00:00Z", "count": 42, "avg_score": 38.1 }]
```

---

## Health

### `GET /api/health`

No auth required.

**Response 200:**
```json
{
  "status": "ok",
  "services": {
    "ssh": "running",
    "http": "running",
    "ftp": "running",
    "rdp": "running",
    "intel_worker": "running",
    "report_worker": "running"
  },
  "db": "connected",
  "redis": "connected",
  "version": "1.0.0"
}
```

---

## WebSocket — Live Event Feed

**Endpoint:** `wss://{domain}/ws/events?token={jwt}`

### Server → Client messages

```json
{ "type": "session_open",   "data": { /* SessionSummary */ } }
{ "type": "session_update", "data": { /* SessionSummary */ } }
{ "type": "session_close",  "data": { /* SessionSummary */ } }
{ "type": "alert",          "data": { "session_id": "uuid", "severity": "high", "score": 74 } }
{ "type": "pong" }
```

### Client → Server messages

```json
{ "type": "ping" }
```

Heartbeat: server pings every 30s. Client must respond within 10s or connection closes.

---

## Error Contract

All errors:
```json
{
  "error": "RESOURCE_NOT_FOUND",
  "message": "Session abc123 not found",
  "status": 404,
  "request_id": "uuid"
}
```

**Error codes used:**

| Code | HTTP | When |
|------|------|------|
| UNAUTHORIZED | 401 | Missing or invalid JWT |
| RESOURCE_NOT_FOUND | 404 | Session, report, or resource not found |
| VALIDATION_ERROR | 422 | Invalid query params or request body |
| RATE_LIMITED | 429 | Too many requests (dashboard API rate limit) |
| INTERNAL_ERROR | 500 | Unexpected server error |
