# HoneyStrike — Infrastructure Topology

---

## VPS Specification

| Property | Value |
|---------|-------|
| Provider | Hetzner Cloud (recommended) |
| Plan | CX21 (2 vCPU, 4 GB RAM, 40 GB NVMe) |
| OS | Ubuntu 24.04 LTS |
| Location | Nuremberg / Helsinki (low latency from Romania) |
| Monthly cost | ~€4 |
| Optional upgrade | CX31 (4 vCPU, 8 GB) if Grafana + Loki added |

---

## Network Topology

```
INTERNET
    │
    │  Inbound: TCP 21, 22, 80, 443, 3389
    │
    ▼
┌─────────────────────────────────────────────────────┐
│  VPS PUBLIC INTERFACE (eth0)                        │
│                                                     │
│  ┌───────────────────────────────────────────────┐  │
│  │  UFW Firewall                                 │  │
│  │  ALLOW IN: 21, 22, 80, 443, 3389              │  │
│  │  ALLOW IN: SSH management (custom port)       │  │
│  │  DENY ALL other inbound                       │  │
│  └───────────────────────────────────────────────┘  │
│                                                     │
│  ┌─────────────────────────────────────────────────┐│
│  │  Docker: honeypot-net (172.20.0.0/24)           ││
│  │                                                 ││
│  │  ┌──────────┐ ┌──────────┐ ┌───────┐ ┌───────┐ ││
│  │  │ssh:22    │ │http:80   │ │ftp:21 │ │rdp:   │ ││
│  │  │          │ │    :443  │ │       │ │3389   │ ││
│  │  └────┬─────┘ └────┬─────┘ └───┬───┘ └───┬───┘ ││
│  └───────┼────────────┼───────────┼──────────┼─────┘│
│          │            │           │          │       │
│  ┌───────▼────────────▼───────────▼──────────▼─────┐│
│  │  Docker: internal-net (172.21.0.0/24)           ││
│  │                                                 ││
│  │  ┌──────────┐  ┌──────────┐  ┌──────────────┐  ││
│  │  │redis:6379│  │postgres  │  │intel-worker  │  ││
│  │  │          │  │:5432     │  │report-worker │  ││
│  │  └──────────┘  └──────────┘  └──────────────┘  ││
│  │                                                 ││
│  │  ┌──────────────────────────────────────────┐   ││
│  │  │dashboard-api :8000 (127.0.0.1 only)      │   ││
│  │  └───────────────────┬──────────────────────┘   ││
│  │                      │                          ││
│  │  ┌───────────────────▼──────────────────────┐   ││
│  │  │caddy :80/:443  (public, TLS termination) │   ││
│  │  └──────────────────────────────────────────┘   ││
│  └─────────────────────────────────────────────────┘│
│                                                     │
└─────────────────────────────────────────────────────┘

OUTBOUND (from internal-net only):
  intel-worker → AbuseIPDB API (HTTPS 443)
  alerting-worker → Telegram API (HTTPS 443)
  alerting-worker → SMTP relay (port 587)
  alerting-worker → Slack webhook (HTTPS 443)
  maxmind-update-cron → MaxMind update server (weekly)
```

---

## Docker Networks

| Network | Subnet | Members |
|---------|--------|---------|
| `honeypot-net` | 172.20.0.0/24 | ssh-service, http-service, ftp-service, rdp-service |
| `internal-net` | 172.21.0.0/24 | All services + postgres + redis + workers + api + caddy |

**Rule:** Honeypot services are on `honeypot-net` only. They can publish to Redis (via internal-net Redis port exposed only on internal-net). They cannot reach postgres or the API directly.

---

## Port Map

| Port | Protocol | Exposed | Service | Public? |
|------|---------|---------|---------|---------|
| 21 | TCP | 0.0.0.0 | FTP honeypot | Yes |
| 22 | TCP | 0.0.0.0 | SSH honeypot | Yes |
| 80 | TCP | 0.0.0.0 | Caddy (HTTP → redirect) | Yes |
| 443 | TCP | 0.0.0.0 | Caddy (HTTPS → API/dashboard) | Yes |
| 3389 | TCP | 0.0.0.0 | RDP honeypot | Yes |
| 2222 | TCP | 0.0.0.0 | Real SSH management (change from 22) | Yes (firewall restricted) |
| 5432 | TCP | internal only | PostgreSQL | No |
| 6379 | TCP | internal only | Redis | No |
| 8000 | TCP | 127.0.0.1 | Dashboard API | No (Caddy only) |
| 9090 | TCP | 127.0.0.1 | Prometheus metrics | No |
| 3000 | TCP | 127.0.0.1 | Grafana (optional) | No |

---

## Volume Map

| Volume name | Mounted in | Purpose |
|-------------|----------|---------|
| `postgres_data` | postgres:/var/lib/postgresql/data | Database files |
| `redis_data` | redis:/data | AOF + RDB files |
| `report_files` | report-worker:/reports, api:/reports | Generated PDF/HTML reports |
| `maxmind_db` | intel-worker:/maxmind | GeoLite2 .mmdb files |
| `caddy_data` | caddy:/data | TLS certificate storage |
| `backup_data` | Host:/backups | PostgreSQL dumps |
| `archive_data` | Host:/archive | Event NDJSON archives |

---

## Management SSH

**Critical:** The real SSH management port must not be 22 (occupied by SSH honeypot).

```bash
# In /etc/ssh/sshd_config on the VPS:
Port 2222
PermitRootLogin no
PubkeyAuthentication yes
PasswordAuthentication no

# UFW: allow management SSH from your IP only
ufw allow from <your-static-ip> to any port 2222
```
