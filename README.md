# HoneyStrike

> Active honeypot platform — captures attacker interactions across SSH/HTTP/FTP/RDP, fingerprints threat actors, maps behaviour to MITRE ATT&CK, and generates threat-intelligence reports. Deployable to a €4/month VPS via `docker compose up -d`.

**Status:** Phase 1 — Foundation (in progress).  Full spec: [`docs/00_README.md`](docs/00_README.md).

---

## Quick start (development)

```powershell
# 1. Copy environment template and edit
Copy-Item .env.example .env

# 2. Start Postgres + Redis
docker compose -f docker-compose.dev.yml up -d postgres redis

# 3. Install Python deps (Python 3.13 + Poetry)
poetry install

# 4. Apply database migrations
poetry run alembic upgrade head

# 5. Run tests
poetry run pytest
```

Honeypot service containers (SSH/HTTP/FTP/RDP) land in Phase 2 — see [`docs/10_90_Day_Delivery_Plan.md`](docs/10_90_Day_Delivery_Plan.md).

## Documentation

All design docs are in [`docs/`](docs/). Start at [`docs/00_README.md`](docs/00_README.md).

## Tech stack

Python 3.13 · FastAPI · Paramiko · pyftpdlib · SQLAlchemy 2.0 async · PostgreSQL 16 · Redis 7 Streams · WeasyPrint · Caddy · structlog · Prometheus · Docker Compose v2.

## License

MIT. See [`SECURITY.md`](SECURITY.md) for responsible-disclosure policy.

---

*This product uses the MITRE ATT&CK® framework. © The MITRE Corporation.*
