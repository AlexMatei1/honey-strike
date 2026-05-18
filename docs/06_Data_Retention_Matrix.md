# HoneyStrike — Data Retention Matrix

---

## Retention Rules by Table

| Table | Hot retention (PostgreSQL) | Archive action | Delete after |
|-------|---------------------------|----------------|-------------|
| `sessions` | 365 days | Summarise to `sessions_archive` table | Never (summaries kept) |
| `events` | 90 days | Export to compressed NDJSON → `/archive/events/YYYY-MM/` | 90 days (raw rows) |
| `fingerprints` | 365 days | None — retained as threat intel corpus | Never |
| `ttp_matches` | 365 days | None | Never |
| `reports` (metadata) | 365 days | None | Never |
| `reports` (files on disk) | 180 days | Operator-managed | 180 days |
| `alerts` | 365 days | None — audit trail | Never |
| `geo_cache` | TTL-based | Automatic Redis expiry (24h) + PG cleanup cron | 48h |
| `ml_anomaly_scores` | 180 days | None | 180 days |

---

## Archival Procedures

### Events archival cron (run daily at 02:00 UTC)

```bash
#!/bin/bash
# Archive events older than 90 days to NDJSON
ARCHIVE_DATE=$(date -d "90 days ago" +%Y-%m-%d)
MONTH=$(date -d "90 days ago" +%Y-%m)
OUTDIR="/archive/events/${MONTH}"
mkdir -p "${OUTDIR}"

psql "${DATABASE_URL}" -c \
  "COPY (
    SELECT row_to_json(e) FROM events e
    WHERE ts < '${ARCHIVE_DATE}'::timestamptz
  ) TO STDOUT" \
  | gzip > "${OUTDIR}/events_up_to_${ARCHIVE_DATE}.ndjson.gz"

# Verify archive file is non-empty before deleting
if [ -s "${OUTDIR}/events_up_to_${ARCHIVE_DATE}.ndjson.gz" ]; then
  psql "${DATABASE_URL}" -c \
    "DELETE FROM events WHERE ts < '${ARCHIVE_DATE}'::timestamptz"
  echo "Archived and deleted events older than ${ARCHIVE_DATE}"
else
  echo "ERROR: Archive file is empty. Skipping deletion."
  exit 1
fi
```

### Report file cleanup cron (run daily at 03:00 UTC)

```bash
# Delete report files older than 180 days
psql "${DATABASE_URL}" -c \
  "SELECT file_path FROM reports WHERE expires_at < NOW()" \
  | tail -n +3 | head -n -2 \
  | xargs -I{} rm -f "{}"

# Nullify file_path on expired records (keep metadata)
psql "${DATABASE_URL}" -c \
  "UPDATE reports SET file_path = NULL WHERE expires_at < NOW()"
```

---

## GDPR / Privacy Notes

HoneyStrike captures data from entities who are **initiating unsolicited hostile connections** to systems the operator owns or controls. Key legal basis considerations:

| Data item | GDPR relevance | Justification |
|-----------|---------------|---------------|
| IP addresses | Personal data in EU | Legitimate interest (security monitoring) |
| Credentials captured | Attacker-supplied false data | Not the attacker's legitimate credentials |
| Geolocation | Derived from IP | Same as IP — legitimate interest |
| Tool signatures | Behavioural data | Security research basis |

**Recommendations:**
- Retain raw IPs for a maximum of 12 months unless required for ongoing legal proceedings
- Do not cross-reference honeypot IPs with any personal data from other systems
- Do not publish raw IP lists without appropriate anonymisation (subnetting to /24 minimum)
- Add a `robots.txt` and appropriate headers to the dashboard to discourage indexing

---

## Backup Schedule

| Backup type | Frequency | Retention | Storage |
|-------------|-----------|-----------|---------|
| Full PostgreSQL dump (`pg_dump`) | Daily 01:00 UTC | 30 days | `/backups/daily/` |
| Weekly consolidated dump | Weekly Sunday 01:30 UTC | 12 weeks | `/backups/weekly/` |
| Event NDJSON archives | Daily (see above) | Indefinite | `/archive/events/` |
| Redis RDB snapshot | Every 15 min (Redis AOF+RDB) | Last 7 snapshots | Docker volume |

Backup verification: see `ci/db-restore-validate.sh`.
