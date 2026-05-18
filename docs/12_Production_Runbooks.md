# HoneyStrike — Production Runbooks

---

## RB-01: Restart a crashed service

```bash
# Check which container is down
docker compose -f docker-compose.prod.yml ps

# Restart specific service
docker compose -f docker-compose.prod.yml restart ssh-service

# View last 100 lines of logs
docker compose -f docker-compose.prod.yml logs --tail=100 ssh-service

# If restart loops, inspect and rebuild
docker compose -f docker-compose.prod.yml stop ssh-service
docker compose -f docker-compose.prod.yml build ssh-service
docker compose -f docker-compose.prod.yml up -d ssh-service
```

**Expected outcome:** Service reports "Started" in logs and begins accepting connections.

---

## RB-02: Redis event bus lag — worker falling behind

Symptoms: Alerts delayed > 60s, large pending count in stream.

```bash
# Check stream length and pending messages
docker exec honeystrike-cache redis-cli XLEN honeystrike:events
docker exec honeystrike-cache redis-cli XPENDING honeystrike:events intel - + 100

# Check intel-worker health
docker compose -f docker-compose.prod.yml logs --tail=200 intel-worker

# Increase worker concurrency (edit .env, then restart)
# WORKER_CONCURRENCY=8
docker compose -f docker-compose.prod.yml up -d intel-worker

# If stream is too large (> 200k entries), trim oldest
docker exec honeystrike-cache redis-cli XTRIM honeystrike:events MAXLEN 100000
```

---

## RB-03: PostgreSQL disk space warning

```bash
# Check DB size
docker exec honeystrike-db psql -U honeystrike -c \
  "SELECT pg_size_pretty(pg_database_size('honeystrike'));"

# Check table sizes
docker exec honeystrike-db psql -U honeystrike -c \
  "SELECT relname, pg_size_pretty(pg_total_relation_size(relid))
   FROM pg_stat_user_tables ORDER BY pg_total_relation_size(relid) DESC;"

# Run events archival immediately (don't wait for cron)
docker exec honeystrike-reports /scripts/archive_events.sh

# VACUUM ANALYZE after large deletion
docker exec honeystrike-db psql -U honeystrike -c "VACUUM ANALYZE events;"
```

---

## RB-04: TLS certificate renewal failed (Caddy)

```bash
# Check Caddy logs
docker compose -f docker-compose.prod.yml logs caddy | grep -i "cert\|tls\|acme"

# Force renewal
docker compose -f docker-compose.prod.yml restart caddy

# Verify certificate
curl -vI https://your-domain.com 2>&1 | grep -A5 "SSL certificate"

# If Let's Encrypt rate limited (5 failures/week), wait or use staging:
# In Caddyfile, add: acme_ca https://acme-staging-v02.api.letsencrypt.org/directory
```

---

## RB-05: Alerting not sending (Telegram)

```bash
# Test Telegram bot token
curl "https://api.telegram.org/bot${TELEGRAM_TOKEN}/getMe"

# Test send to chat
curl -X POST "https://api.telegram.org/bot${TELEGRAM_TOKEN}/sendMessage" \
  -d "chat_id=${TELEGRAM_CHAT_ID}&text=HoneyStrike+test+alert"

# Check intel-worker alerting logs
docker compose -f docker-compose.prod.yml logs intel-worker | grep -i "telegram\|alert"

# Common fix: cooldown key stuck in Redis
docker exec honeystrike-cache redis-cli KEYS "alert:cooldown:*"
docker exec honeystrike-cache redis-cli DEL "alert:cooldown:1.2.3.4"
```

---

## RB-06: Manual report generation

```bash
# Trigger via API
curl -X POST https://your-domain.com/api/sessions/{session_id}/report \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/json"

# Check report worker queue
docker compose -f docker-compose.prod.yml logs report-worker | tail -50

# Direct generation (emergency)
docker exec honeystrike-reports python -m reports.generator --session-id={id} --format=pdf
```

---

## RB-07: Database backup (manual)

```bash
# Full dump
docker exec honeystrike-db pg_dump -U honeystrike honeystrike \
  | gzip > /backups/manual/honeystrike_$(date +%Y%m%d_%H%M%S).sql.gz

# Verify dump
gunzip -c /backups/manual/honeystrike_*.sql.gz | head -20

# List existing backups
ls -lh /backups/daily/ | tail -10
```

---

## RB-08: View live attack traffic

```bash
# Stream all events from Redis in real time
docker exec honeystrike-cache redis-cli \
  XREAD COUNT 0 BLOCK 0 STREAMS honeystrike:events '$'

# Count sessions in last hour
docker exec honeystrike-db psql -U honeystrike -c \
  "SELECT service, count(*) FROM sessions
   WHERE started_at > NOW() - INTERVAL '1 hour'
   GROUP BY service ORDER BY count DESC;"

# Top attacking IPs today
docker exec honeystrike-db psql -U honeystrike -c \
  "SELECT src_ip::text, count(*), max(threat_score) as max_score
   FROM sessions WHERE started_at > CURRENT_DATE
   GROUP BY src_ip ORDER BY count DESC LIMIT 20;"
```

---

## RB-09: Rolling update (zero downtime)

```bash
# Build new image
docker compose -f docker-compose.prod.yml build intel-worker

# Update worker without stopping honeypot services
docker compose -f docker-compose.prod.yml up -d --no-deps intel-worker

# Run migrations if schema changed
docker compose -f docker-compose.prod.yml run --rm dashboard-api \
  alembic upgrade head

# Verify health
curl https://your-domain.com/api/health
```
