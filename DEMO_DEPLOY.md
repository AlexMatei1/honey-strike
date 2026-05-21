# Hosting a public HoneyStrike demo

This guide stands up a **read-only, synthetic-data** instance of the
HoneyStrike dashboard so people can click around the live map, the lessons,
the war room, and the profile without deploying the whole capture stack.

It runs only **Postgres + Redis + the dashboard API**, plus a one-shot job
that applies migrations and seeds ~250 synthetic attacker sessions
([`scripts/seed_demo.py`](scripts/seed_demo.py)). No honeypot listeners are
exposed — a public demo shouldn't open live capture ports, and the data is
fictional (RFC 5737 documentation IP ranges).

> For a **real capture deployment**, use [`DEPLOY.md`](DEPLOY.md) +
> `docker-compose.prod.yml` instead.

---

## Option A — any VPS / local (Docker Compose) — easiest

```bash
git clone https://github.com/AlexMatei1/honey-strike.git
cd honey-strike
cp .env.demo.example .env.demo
# Edit .env.demo: set ADMIN_PASSWORD and a fresh JWT_SECRET (openssl rand -hex 32)

docker compose -f docker-compose.demo.yml up -d --build
# init runs migrations + seed, then the API starts.
# Open http://<host>:8001/login   (admin / your ADMIN_PASSWORD)
```

To re-seed later: `docker compose -f docker-compose.demo.yml run --rm init`.

A 1 GB / 1 vCPU box is plenty (no honeypots, no workers).

---

## Option B — Render.com (managed, free tier) — one-click

A [`render.yaml`](render.yaml) blueprint is included. It provisions the
dashboard web service + managed Postgres + managed Key Value (Redis), and
runs migrations + seed via the pre-deploy command.

1. Push this repo to your GitHub.
2. Render → **New +** → **Blueprint** → pick the repo.
3. When prompted, set **`ADMIN_PASSWORD`** (`JWT_SECRET` is auto-generated).
4. Deploy. The dashboard comes up at the service's `onrender.com` URL.

**Scheme gotcha:** Render's `connectionString` is `postgres://…`. HoneyStrike
needs the async driver. If the app fails to connect, override `DATABASE_URL`
in the Render dashboard with the `postgresql+asyncpg://…` form (same host /
user / pass / db).

---

## Option C — Fly.io

A [`fly.toml`](fly.toml) is included (web process + release command for
migrate + seed). You supply Postgres and Redis:

```bash
fly launch --no-deploy
fly postgres create && fly postgres attach <pg-app>
# DATABASE_URL is set with postgres:// — re-set it with the async driver:
fly secrets set DATABASE_URL="postgresql+asyncpg://USER:PASS@HOST:5432/DB"
fly redis create                       # or any Redis URL (Upstash works)
fly secrets set REDIS_URL="redis://…" ADMIN_PASSWORD="…" JWT_SECRET="$(openssl rand -hex 32)"
fly deploy
```

---

## Hardening a public demo

- **Change `ADMIN_PASSWORD`** and use a fresh **`JWT_SECRET`** — the
  `.env.demo.example` values are placeholders.
- The demo is login-gated; only the login page is public. If you want a truly
  open demo, you can publish the read-only credentials in the UI footer — but
  remember anyone logged in can POST `/api/play/attack` (rate-limited to
  3 concurrent / 12 per minute) and `/api/defender/block`. Those only affect
  the demo's own Redis/synthetic state, never real infrastructure.
- Put it behind the platform's TLS (Render/Fly do this automatically; on a
  VPS, front it with Caddy as in `DEPLOY.md`).

---

## Regenerating the screenshots

The README images come from the Playwright suite, pointed at any running
instance (including a demo):

```bash
cd tests/e2e
npm install && npm run install-browser
E2E_BASE_URL=https://your-demo-url npm run shots
```
