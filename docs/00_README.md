# HoneyStrike — Project Documentation Index

> **Version:** v1.0.0-alpha  
> **Last updated:** May 2026  
> **Maintainer:** Operator / Solo Dev  
> **Status:** Active Development

---

## What is HoneyStrike?

HoneyStrike is a deployable, containerised active honeypot system that simulates vulnerable network services (SSH, HTTP, FTP, RDP), captures attacker interactions, fingerprints threat actors, maps observed behaviour to the MITRE ATT&CK framework, and auto-generates structured threat intelligence reports — all packaged in a Docker Compose stack deployable on a €4/month VPS.

---

## Document Index

| # | Document | Description |
|---|----------|-------------|
| 01 | [SPEC_Master](./01_SPEC_Master.md) | Full system specification, goals, scope, constraints |
| 02 | [API_Contracts](./02_API_Contracts.md) | REST + WebSocket API contracts, request/response schemas |
| 03 | [Domain_Events](./03_Domain_Events.md) | Event bus schema, Redis Streams event catalogue |
| 04 | [PostgreSQL_Schema.sql](./04_PostgreSQL_Schema.sql) | Full DDL for all production tables |
| 05 | [Indexes_and_Partitioning.sql](./05_Indexes_and_Partitioning.sql) | Index strategy and partition definitions |
| 06 | [Data_Retention_Matrix](./06_Data_Retention_Matrix.md) | Retention rules, archival policies, GDPR notes |
| 07 | [Compliance_and_Legal_Packet](./07_Compliance_and_Legal_Packet.md) | Legal basis for deployment, responsible disclosure |
| 08 | [Capture_Flows_and_Privacy](./08_Capture_Flows_and_Privacy.md) | Data capture flows, PII handling, sanitisation |
| 09 | [Production_Code_Quality_Gate](./09_Production_Code_Quality_Gate_Checklist.md) | CI quality gates, coverage thresholds, linting |
| 10 | [90_Day_Delivery_Plan](./10_90_Day_Delivery_Plan.md) | Phased milestone plan across 18 weeks |
| 11 | [Infrastructure_Topology](./11_Infrastructure_Topology.md) | Network diagram, Docker networks, VPS layout |
| 12 | [Production_Runbooks](./12_Production_Runbooks.md) | Operational runbooks for common scenarios |
| 13 | [Disaster_Recovery_Playbook](./13_Disaster_Recovery_Playbook.md) | DR procedures, RTO/RPO targets, drill schedule |
| 14 | [DR_Playbook_and_Drills](./14_DR_Playbook_and_Drills.md) | Hands-on drill scripts and validation steps |
| 15 | [Production_Readiness_Verification](./15_Production_Readiness_Verification.md) | Full go-live verification checklist |
| 16 | [Launch_Runbook](./16_Launch_Runbook.md) | Step-by-step first deployment instructions |
| 17 | [V1.0_Release_Notes](./17_V1.0_Release_Notes.md) | What ships in v1.0, known gaps, v2 roadmap |
| 18 | [HONEYSTRIKE_Compliance_Checklist](./18_HONEYSTRIKE_Compliance_Checklist.md) | Compliance + legal self-audit checklist |
| 19 | [HONEYSTRIKE_Production_Readiness](./19_HONEYSTRIKE_Production_Readiness_Checklist.md) | Pre-launch production readiness checklist |

### CI Scripts (`/ci`)

| File | Purpose |
|------|---------|
| [db-restore-validate.sh](./ci/db-restore-validate.sh) | Validate PostgreSQL backup restore integrity |
| [failover-drill.sh](./ci/failover-drill.sh) | Simulate service failover and verify recovery |
| [release-gate.sh](./ci/release-gate.sh) | CI release gate: tests, coverage, CVE scan |
| [release-gate-policy.md](./ci/release-gate-policy.md) | Human-readable release gate policy |

---

## Quick Start

```bash
git clone https://github.com/yourname/honeystrike
cd honeystrike
cp .env.example .env.production
# Fill in secrets — see 16_Launch_Runbook.md
docker compose -f docker-compose.prod.yml up -d
```

## Tech Stack Summary

| Layer | Technology |
|-------|-----------|
| Honeypot services | Python 3.13 + Paramiko + pyftpdlib |
| Event bus | Redis 7 Streams |
| Intelligence | mitreattack-python, MaxMind GeoLite2, AbuseIPDB |
| API / Dashboard | FastAPI + HTMX + Leaflet.js |
| Reports | WeasyPrint (PDF) + Jinja2 (HTML) |
| Database | PostgreSQL 16 + SQLAlchemy 2.0 async |
| Proxy / TLS | Caddy 2 |
| Observability | structlog + Prometheus + Grafana + Loki |
| Containers | Docker Compose v2 |

---

> **Legal note:** Deploying honeypots on public IP addresses is legal in most jurisdictions when operated by the system owner. Review [07_Compliance_and_Legal_Packet.md](./07_Compliance_and_Legal_Packet.md) before going live.
