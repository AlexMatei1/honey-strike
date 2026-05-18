# HoneyStrike — Disaster Recovery Playbook

---

## RTO / RPO Targets

| Scenario | RTO (Recovery Time) | RPO (Recovery Point) |
|---------|--------------------|--------------------|
| Single container crash | 2 minutes | 0 (event bus AOF) |
| Full VPS reboot | 5 minutes | 0 (all data on volumes) |
| VPS total loss (hardware failure) | 4 hours | 24 hours (last daily backup) |
| Accidental DB deletion | 2 hours | 24 hours (last daily backup) |
| Ransomware / data corruption | 6 hours | 24 hours (offsite backup) |

---

## Scenario 1: Single Container Crash

**Detection:** Prometheus alert or `docker compose ps` shows unhealthy container.

**Recovery:**
```bash
docker compose -f docker-compose.prod.yml restart <service-name>
# Wait 30s, verify:
docker compose -f docker-compose.prod.yml ps
curl https://your-domain.com/api/health
```

**Root cause investigation:**
```bash
docker compose -f docker-compose.prod.yml logs --tail=200 <service-name>
```

---

## Scenario 2: Full VPS Reboot (Planned or Unplanned)

All containers have `restart: unless-stopped` — they come back automatically.

**Post-reboot checklist:**
- [ ] `docker compose ps` — all containers Running
- [ ] `curl https://your-domain.com/api/health` — all services "running"
- [ ] Redis stream intact: `docker exec honeystrike-cache redis-cli XLEN honeystrike:events`
- [ ] Last DB backup completed: `ls -la /backups/daily/ | tail -5`
- [ ] Caddy TLS certificates valid: `curl -vI https://your-domain.com 2>&1 | grep "expire date"`

---

## Scenario 3: VPS Total Loss

### Step 1 — Provision new VPS (30 min)

```bash
# Hetzner Cloud Console: create new CX21, Ubuntu 24.04
# Copy SSH public key to new server
ssh-copy-id root@<new-ip>

# Install Docker
curl -fsSL https://get.docker.com | sh
usermod -aG docker $USER
```

### Step 2 — Restore from offsite backup (60 min)

```bash
# Download latest backup from offsite storage (S3, Backblaze, etc.)
rclone copy remote:honeystrike-backups/daily/ /backups/daily/

# Copy latest to restore point
cp /backups/daily/honeystrike_LATEST.sql.gz /tmp/restore.sql.gz
```

### Step 3 — Clone repository and configure (30 min)

```bash
git clone https://github.com/yourname/honeystrike
cd honeystrike
cp .env.example .env.production
# Restore all secrets from password manager
nano .env.production
```

### Step 4 — Start stack and restore DB (60 min)

```bash
# Start only DB container first
docker compose -f docker-compose.prod.yml up -d postgres

# Wait for postgres to be ready
sleep 10

# Restore dump
gunzip -c /tmp/restore.sql.gz | \
  docker exec -i honeystrike-db psql -U honeystrike honeystrike

# Run any pending migrations
docker compose -f docker-compose.prod.yml run --rm dashboard-api \
  alembic upgrade head

# Start full stack
docker compose -f docker-compose.prod.yml up -d

# Verify
curl https://<new-domain>/api/health
```

### Step 5 — Update DNS and verify (30 min)

```bash
# Update A record at DNS provider to <new-ip>
# DNS TTL: set to 300s before disaster; propagation ~ 5 min at 300s TTL

# Verify TLS
curl -vI https://your-domain.com 2>&1 | grep "expire date"
```

---

## Scenario 4: Accidental DB Deletion or Corruption

```bash
# STOP all writes immediately
docker compose -f docker-compose.prod.yml stop intel-worker report-worker

# Identify clean restore point
ls -lht /backups/daily/

# Create a recovery DB
docker exec honeystrike-db psql -U postgres \
  -c "CREATE DATABASE honeystrike_recovery;"

# Restore into recovery DB
gunzip -c /backups/daily/honeystrike_CHOSEN.sql.gz | \
  docker exec -i honeystrike-db psql -U honeystrike honeystrike_recovery

# Verify row counts match expectations
docker exec honeystrike-db psql -U honeystrike honeystrike_recovery \
  -c "SELECT 'sessions', count(*) FROM sessions
      UNION ALL SELECT 'events', count(*) FROM events
      UNION ALL SELECT 'fingerprints', count(*) FROM fingerprints;"

# Swap databases
docker exec honeystrike-db psql -U postgres \
  -c "ALTER DATABASE honeystrike RENAME TO honeystrike_corrupt;"
docker exec honeystrike-db psql -U postgres \
  -c "ALTER DATABASE honeystrike_recovery RENAME TO honeystrike;"

# Restart workers
docker compose -f docker-compose.prod.yml start intel-worker report-worker
```

---

## Offsite Backup Configuration

Configure `rclone` to sync daily backups to an offsite location:

```bash
# /etc/cron.d/honeystrike-offsite-backup
30 2 * * * root rclone sync /backups/daily remote:honeystrike-backups/daily \
  --max-age 30d --log-file /var/log/honeystrike-backup.log
```

Recommended offsite providers: Backblaze B2 (cheapest), AWS S3, or a second Hetzner Volume in a different datacenter.

---

## DR Contact List

| Role | Contact | When to call |
|------|---------|-------------|
| Operator (you) | — | Always primary |
| Hetzner Support | support.hetzner.com | Hardware failure, network issues |
| CERT-RO | cert.ro | If attack data reveals imminent threat to Romanian infrastructure |
