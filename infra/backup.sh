#!/usr/bin/env bash
# =============================================================================
# HoneyStrike — daily PostgreSQL backup
#
# - Runs `pg_dump` inside the running honeystrike-db container
# - Gzips the dump to /backups/daily/honeystrike_YYYY-MM-DD.sql.gz
# - Prunes anything older than $RETENTION_DAYS (default 30)
# - Exits non-zero on dump failure so cron emails the operator
#
# Install via cron:
#   cat > /etc/cron.d/honeystrike-backup <<EOF
#   0 1 * * * root /opt/honeystrike/infra/backup.sh >> /var/log/honeystrike-backup.log 2>&1
#   EOF
# =============================================================================

set -euo pipefail

BACKUP_DIR="${BACKUP_DIR:-/backups/daily}"
RETENTION_DAYS="${RETENTION_DAYS:-30}"
CONTAINER="${CONTAINER:-honeystrike-db}"
DB_USER="${DB_USER:-honeystrike}"
DB_NAME="${DB_NAME:-honeystrike}"

log() { printf '\033[1;36m[backup]\033[0m %s\n' "$*"; }
die() { printf '\033[1;31m[backup error]\033[0m %s\n' "$*" >&2; exit 1; }

mkdir -p "$BACKUP_DIR"

if ! docker ps --format '{{.Names}}' | grep -q "^${CONTAINER}$"; then
  die "Container $CONTAINER is not running."
fi

TS="$(date -u +%Y-%m-%dT%H-%M-%SZ)"
OUTFILE="${BACKUP_DIR}/honeystrike_${TS}.sql.gz"

log "Dumping $DB_NAME → $OUTFILE"
if ! docker exec "$CONTAINER" pg_dump -U "$DB_USER" -d "$DB_NAME" --no-owner --no-acl \
       | gzip > "$OUTFILE"; then
  rm -f "$OUTFILE"
  die "pg_dump failed."
fi

if [[ ! -s "$OUTFILE" ]]; then
  rm -f "$OUTFILE"
  die "Dump file is empty — refusing to keep."
fi

SIZE=$(du -h "$OUTFILE" | cut -f1)
log "Dump OK ($SIZE)"

# Prune older daily dumps.
log "Pruning dumps older than ${RETENTION_DAYS} days from $BACKUP_DIR"
find "$BACKUP_DIR" -maxdepth 1 -name 'honeystrike_*.sql.gz' -mtime +"$RETENTION_DAYS" -print -delete

log "Done."
