#!/usr/bin/env bash
# =============================================================================
# HoneyStrike — pull, build, migrate, restart the partial-stack
#
# Idempotent. Safe to run after `git pull`. Honours profiles so the same
# script will deploy the intel/dashboard profiles once those phases ship.
#
# Usage:
#   sudo bash infra/deploy.sh [profile]   # profile defaults to 'capture'
# =============================================================================

set -euo pipefail

PROFILE="${1:-capture}"
INSTALL_PREFIX="${INSTALL_PREFIX:-/opt/honeystrike}"
ENV_FILE="${ENV_FILE:-${INSTALL_PREFIX}/.env.production}"
COMPOSE_FILE="${INSTALL_PREFIX}/docker-compose.prod.yml"

log() { printf '\033[1;36m[deploy]\033[0m %s\n' "$*"; }
die() { printf '\033[1;31m[deploy error]\033[0m %s\n' "$*" >&2; exit 1; }

[[ -f "$ENV_FILE" ]] || die "Missing $ENV_FILE — run setup.sh and fill secrets first."
[[ -f "$COMPOSE_FILE" ]] || die "Missing $COMPOSE_FILE."

cd "$INSTALL_PREFIX"

log "Pulling latest source"
git pull --ff-only

log "Building images (profile=$PROFILE)"
docker compose -f "$COMPOSE_FILE" --env-file "$ENV_FILE" \
  --profile "$PROFILE" build

log "Running database migrations"
docker compose -f "$COMPOSE_FILE" --env-file "$ENV_FILE" \
  --profile migrate run --rm migrate

log "Rolling restart (profile=$PROFILE)"
docker compose -f "$COMPOSE_FILE" --env-file "$ENV_FILE" \
  --profile "$PROFILE" up -d --remove-orphans

sleep 5
log "Status:"
docker compose -f "$COMPOSE_FILE" --env-file "$ENV_FILE" ps

log "Done."
