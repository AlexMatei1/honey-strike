# HoneyStrike — DR Playbook and Drills

Run these drills quarterly. Record results in the table at the bottom.

---

## Drill 1: Database Backup Restore Validation

**Script:** `ci/db-restore-validate.sh`  
**Frequency:** Weekly (automated in CI)  
**Duration:** ~10 minutes

### Manual steps

```bash
# 1. Copy latest backup to temp location
cp /backups/daily/$(ls /backups/daily/ | tail -1) /tmp/drill_restore.sql.gz

# 2. Create isolated drill DB
docker exec honeystrike-db psql -U postgres \
  -c "DROP DATABASE IF EXISTS honeystrike_drill;"
docker exec honeystrike-db psql -U postgres \
  -c "CREATE DATABASE honeystrike_drill;"

# 3. Restore
gunzip -c /tmp/drill_restore.sql.gz | \
  docker exec -i honeystrike-db psql -U honeystrike honeystrike_drill

# 4. Validate row counts
docker exec honeystrike-db psql -U honeystrike honeystrike_drill -c \
  "SELECT
     (SELECT count(*) FROM sessions)     AS sessions,
     (SELECT count(*) FROM events)       AS events,
     (SELECT count(*) FROM fingerprints) AS fingerprints,
     (SELECT count(*) FROM ttp_matches)  AS ttp_matches;"

# 5. Validate latest session timestamp (should be within last 24h)
docker exec honeystrike-db psql -U honeystrike honeystrike_drill -c \
  "SELECT max(started_at) AS latest_session FROM sessions;"

# 6. Cleanup
docker exec honeystrike-db psql -U postgres \
  -c "DROP DATABASE honeystrike_drill;"
rm /tmp/drill_restore.sql.gz

echo "Drill 1 PASSED"
```

**Pass criteria:** Row counts match production (within 5%); latest session within 24h of drill time.

---

## Drill 2: Service Failover Drill

**Script:** `ci/failover-drill.sh`  
**Frequency:** Monthly  
**Duration:** ~15 minutes

### Manual steps

```bash
# 1. Record baseline
BEFORE=$(docker exec honeystrike-db psql -U honeystrike -t -c \
  "SELECT count(*) FROM sessions WHERE started_at > NOW() - INTERVAL '5 min';")

# 2. Kill ssh-service
docker compose -f docker-compose.prod.yml stop ssh-service
echo "SSH service stopped at $(date)"

# 3. Wait 30s — verify sessions still accumulating on other services
sleep 30
docker compose -f docker-compose.prod.yml logs intel-worker | tail -20

# 4. Restart ssh-service
docker compose -f docker-compose.prod.yml start ssh-service
echo "SSH service restarted at $(date)"

# 5. Verify recovery (60s)
sleep 60
AFTER=$(docker exec honeystrike-db psql -U honeystrike -t -c \
  "SELECT count(*) FROM sessions WHERE service='ssh' AND started_at > NOW() - INTERVAL '2 min';")

echo "SSH sessions in last 2 min: ${AFTER}"
echo "Expected: > 0 (real traffic should resume)"

# 6. Full health check
curl -s https://your-domain.com/api/health | python3 -m json.tool
```

**Pass criteria:** SSH service restarts within 60s; new SSH sessions appear within 2 minutes; health endpoint shows all services running.

---

## Drill 3: Redis Restart (Event Bus Recovery)

**Frequency:** Quarterly  
**Duration:** ~5 minutes

```bash
# 1. Record stream length before
BEFORE=$(docker exec honeystrike-cache redis-cli XLEN honeystrike:events)

# 2. Restart Redis
docker compose -f docker-compose.prod.yml restart redis
echo "Redis restarted at $(date)"
sleep 10

# 3. Verify AOF recovered stream
AFTER=$(docker exec honeystrike-cache redis-cli XLEN honeystrike:events)
echo "Stream length before: ${BEFORE}, after: ${AFTER}"
echo "Expected: AFTER >= BEFORE (no events lost)"

# 4. Verify workers reconnected
docker compose -f docker-compose.prod.yml logs intel-worker | grep -i "redis\|connect" | tail -10
```

**Pass criteria:** Stream length after restart ≥ stream length before restart. No events lost.

---

## Drill 4: Full VPS Restore Simulation (Annual)

Run on a fresh VPS (not the production one). Follow Scenario 3 in `13_Disaster_Recovery_Playbook.md` end-to-end. Record time taken at each step.

**Pass criteria:** Full stack operational within 4 hours; all health checks green; report generation works.

---

## Drill Log

| Date | Drill | Operator | Passed? | RTO Achieved | Notes |
|------|-------|---------|---------|-------------|-------|
| — | — | — | — | — | Not yet run |

Record results here after each drill. If a drill fails, open a GitHub issue and fix before next release.
