# HoneyStrike — Domain Events

**Transport:** Redis 7 Streams  **Stream name:** `honeystrike:events`

---

## Consumer Groups

| Group | Members | Consumes |
|-------|---------|---------|
| `intel` | FingerprintWorker, TTPMapperWorker, AlertingWorker | All event types |
| `report` | ReportWorker | `SESSION_CLOSE` only |
| `dashboard` | DashboardBroadcaster | `SESSION_OPEN`, `SESSION_CLOSE`, `SESSION_UPDATE` |

---

## Event Envelope

Every event written to the stream has this envelope:

```python
@dataclass
class EventEnvelope:
    id:          str       # UUID4 — also the Redis stream entry ID seed
    event_type:  str       # See catalogue below
    session_id:  str       # UUID4 — groups all events per connection
    service:     str       # "ssh" | "http" | "ftp" | "rdp"
    src_ip:      str       # Raw IPv4 or IPv6
    src_port:    int
    timestamp:   str       # ISO 8601 UTC, microsecond precision
    payload:     str       # JSON-encoded, service-specific (see below)
    schema_ver:  str       # "1.0" — for forward compatibility
```

---

## Event Catalogue

### `SESSION_OPEN`

Emitted immediately when a TCP connection is accepted.

```json
{
  "event_type": "SESSION_OPEN",
  "payload": {
    "service": "ssh",
    "remote_addr": "1.2.3.4:58221",
    "local_port": 22
  }
}
```

---

### `SSH_BANNER_GRAB`

Emitted when a client connects to SSH but does not attempt authentication.

```json
{
  "event_type": "SSH_BANNER_GRAB",
  "payload": {
    "client_version": "SSH-2.0-libssh_0.9.6",
    "kex_algorithms": ["curve25519-sha256", "diffie-hellman-group14-sha256"]
  }
}
```

---

### `SSH_AUTH_ATTEMPT`

Emitted on every authentication attempt.

```json
{
  "event_type": "SSH_AUTH_ATTEMPT",
  "payload": {
    "auth_type": "password",
    "username": "root",
    "password": "123456",
    "attempt_number": 3,
    "success": false
  }
}
```

---

### `SSH_COMMAND`

Emitted for each command token after honeypot grants shell access.

```json
{
  "event_type": "SSH_COMMAND",
  "payload": {
    "raw": "cat /etc/passwd",
    "tokens": ["cat", "/etc/passwd"]
  }
}
```

---

### `HTTP_REQUEST`

Emitted for every HTTP request to the honeypot HTTP service.

```json
{
  "event_type": "HTTP_REQUEST",
  "payload": {
    "method": "POST",
    "uri": "/wp-admin/admin-ajax.php",
    "http_version": "HTTP/1.1",
    "headers": { "User-Agent": "sqlmap/1.7.8", "Content-Type": "application/x-www-form-urlencoded" },
    "body_truncated": "action=heartbeat&_nonce=...",
    "body_bytes": 412,
    "scanner_detected": "sqlmap",
    "sqli_pattern": true
  }
}
```

---

### `FTP_COMMAND`

Emitted per FTP command.

```json
{
  "event_type": "FTP_COMMAND",
  "payload": {
    "command": "RETR",
    "argument": "/etc/passwd",
    "response_code": 550
  }
}
```

---

### `RDP_CONNECT`

Emitted when RDP handshake data is captured.

```json
{
  "event_type": "RDP_CONNECT",
  "payload": {
    "client_build": "2600",
    "protocol_flags": "0x00000003",
    "neg_req_type": "TYPE_RDP",
    "credssp_domain": "WORKGROUP",
    "credssp_username": "Administrator"
  }
}
```

---

### `TTP_MATCHED`

Emitted by TTPMapperWorker when a technique is matched.

```json
{
  "event_type": "TTP_MATCHED",
  "payload": {
    "technique_id": "T1110.001",
    "technique_name": "Brute Force: Password Guessing",
    "tactic": "Credential Access",
    "confidence": 0.90,
    "trigger_event_id": "uuid-of-ssh-auth-event"
  }
}
```

---

### `ALERT_DISPATCHED`

Emitted by AlertingWorker after sending an alert.

```json
{
  "event_type": "ALERT_DISPATCHED",
  "payload": {
    "channel": "telegram",
    "severity": "high",
    "threat_score": 74,
    "message_id": "tg-message-id"
  }
}
```

---

### `SESSION_CLOSE`

Emitted when a connection closes (client disconnect, timeout, or service close).

```json
{
  "event_type": "SESSION_CLOSE",
  "payload": {
    "duration_ms": 45200,
    "event_count": 312,
    "final_threat_score": 74,
    "close_reason": "client_disconnect"
  }
}
```

---

## Event Bus Guarantees

| Property | Behaviour |
|---------|-----------|
| Delivery | At-least-once (Redis consumer group ACK model) |
| Ordering | Per-session ordering guaranteed (same stream) |
| Persistence | Redis AOF — events survive Redis restart |
| Replay | Consumer can XREAD from any offset; supports replay from `0-0` |
| Max lag | Workers must ACK within 60s or event is redelivered |
| Backpressure | Stream max length: 100,000 entries (MAXLEN ~). Older entries trimmed. |

---

## Schema Versioning

All events include `"schema_ver": "1.0"`. When the event schema changes:
- Minor changes (new optional fields): bump patch in schema_ver
- Breaking changes: bump minor, maintain backward-compatible consumer logic for 2 versions
