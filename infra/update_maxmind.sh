#!/usr/bin/env bash
# =============================================================================
# HoneyStrike — refresh MaxMind GeoLite2 databases
#
# Uses the official `maxmindinc/geoipupdate` image so the operator does not
# need any MaxMind tools installed on the host. Drops `GeoLite2-City.mmdb`
# and `GeoLite2-ASN.mmdb` into the `maxmind_db` Docker volume that the
# compose stack mounts at /maxmind.
#
# Usage:
#   sudo MAXMIND_ACCOUNT_ID=... MAXMIND_LICENSE_KEY=... \
#        bash infra/update_maxmind.sh [dev|prod]
#
# Install as a weekly cron after the first manual run succeeds:
#   0 3 * * 0 root /opt/honeystrike/infra/update_maxmind.sh prod \
#     >> /var/log/honeystrike-maxmind.log 2>&1
# =============================================================================

set -euo pipefail

STACK="${1:-dev}"
case "$STACK" in
  dev)  VOLUME_NAME="honey_strike_v1_maxmind_db"  ;;
  prod) VOLUME_NAME="honey_strike_v1_maxmind_db"  ;;
  *) echo "usage: $0 [dev|prod]" >&2; exit 2 ;;
esac

: "${MAXMIND_ACCOUNT_ID:?MAXMIND_ACCOUNT_ID is required}"
: "${MAXMIND_LICENSE_KEY:?MAXMIND_LICENSE_KEY is required}"

log() { printf '\033[1;36m[maxmind]\033[0m %s\n' "$*"; }

# Make sure the volume exists (create it on first run).
if ! docker volume inspect "$VOLUME_NAME" >/dev/null 2>&1; then
  log "Creating docker volume $VOLUME_NAME"
  docker volume create "$VOLUME_NAME" >/dev/null
fi

log "Running geoipupdate against $VOLUME_NAME"
docker run --rm \
  -e GEOIPUPDATE_ACCOUNT_ID="${MAXMIND_ACCOUNT_ID}" \
  -e GEOIPUPDATE_LICENSE_KEY="${MAXMIND_LICENSE_KEY}" \
  -e GEOIPUPDATE_EDITION_IDS="GeoLite2-City GeoLite2-ASN" \
  -v "${VOLUME_NAME}":/usr/share/GeoIP \
  maxmindinc/geoipupdate

log "Verifying database files"
docker run --rm \
  -v "${VOLUME_NAME}":/usr/share/GeoIP \
  alpine \
  sh -c 'ls -lh /usr/share/GeoIP/GeoLite2-{City,ASN}.mmdb'

log "Done."
