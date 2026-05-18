#!/usr/bin/env bash
# =============================================================================
# HoneyStrike — one-shot VPS bootstrap
#
# Idempotent. Re-running it after a half-finished setup is safe.
#
# What it does:
#   1. apt update + unattended-upgrades for security patches
#   2. Installs Docker + Compose v2 + utilities (curl, jq, ufw, fail2ban)
#   3. Moves the OS sshd off port 22 (default to 2222; tweak via $MGMT_SSH_PORT)
#   4. Configures UFW: deny all, allow honeypot ports + management SSH
#   5. Hardens sshd: no root login, no password auth
#   6. Creates the `/opt/honeystrike` dir tree expected by the compose stack
#   7. Prints next-step instructions (clone repo, fill .env.production)
#
# Usage on a fresh Ubuntu 24.04 VPS (run AS ROOT, before deploying):
#   curl -fsSL https://raw.githubusercontent.com/<you>/honeystrike/main/infra/setup.sh \
#     | MGMT_SSH_PORT=2222 OPERATOR_IP=203.0.113.7 bash
# OR after cloning:
#   sudo MGMT_SSH_PORT=2222 OPERATOR_IP=203.0.113.7 bash infra/setup.sh
#
# CRITICAL: $OPERATOR_IP locks SSH management to your IP only. Get it wrong
# and you lock yourself out. Open a SECOND terminal and test the new port
# before closing the first.
# =============================================================================

set -euo pipefail

MGMT_SSH_PORT="${MGMT_SSH_PORT:-2222}"
OPERATOR_IP="${OPERATOR_IP:-}"
INSTALL_PREFIX="${INSTALL_PREFIX:-/opt/honeystrike}"

log() { printf '\033[1;36m[setup]\033[0m %s\n' "$*"; }
die() { printf '\033[1;31m[setup error]\033[0m %s\n' "$*" >&2; exit 1; }

if [[ "$(id -u)" -ne 0 ]]; then
  die "Run as root (sudo bash infra/setup.sh)."
fi
if [[ -z "$OPERATOR_IP" ]]; then
  die "Set OPERATOR_IP=<your.public.ip> so management SSH stays reachable."
fi

# ---------------------------------------------------------------------------
# 1. System updates
# ---------------------------------------------------------------------------
log "apt update + upgrade"
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get upgrade -y
apt-get install -y --no-install-recommends \
  ca-certificates curl gnupg jq lsb-release \
  ufw fail2ban unattended-upgrades \
  netcat-openbsd

# Enable unattended security upgrades.
dpkg-reconfigure -plow unattended-upgrades || true

# ---------------------------------------------------------------------------
# 2. Docker Engine + Compose v2 (skip if already installed)
# ---------------------------------------------------------------------------
if ! command -v docker >/dev/null 2>&1; then
  log "Installing Docker Engine"
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
    | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
  chmod a+r /etc/apt/keyrings/docker.gpg
  echo \
    "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
     https://download.docker.com/linux/ubuntu \
     $(. /etc/os-release && echo "$VERSION_CODENAME") stable" \
    > /etc/apt/sources.list.d/docker.list
  apt-get update -y
  apt-get install -y docker-ce docker-ce-cli containerd.io \
    docker-buildx-plugin docker-compose-plugin
  systemctl enable --now docker
else
  log "Docker already present: $(docker --version)"
fi

# ---------------------------------------------------------------------------
# 3. Move the OS sshd to MGMT_SSH_PORT
# ---------------------------------------------------------------------------
SSHD_CONFIG=/etc/ssh/sshd_config.d/99-honeystrike.conf
log "Writing $SSHD_CONFIG (mgmt port $MGMT_SSH_PORT, no root, no password auth)"
cat > "$SSHD_CONFIG" <<EOF
# Managed by infra/setup.sh
Port ${MGMT_SSH_PORT}
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
ChallengeResponseAuthentication no
UsePAM yes
EOF

# Sanity-check sshd_config before restarting — a syntax error here locks you out.
sshd -t -f /etc/ssh/sshd_config
systemctl restart ssh || systemctl restart sshd

# ---------------------------------------------------------------------------
# 4. UFW: deny all inbound by default, then open only what we need.
# ---------------------------------------------------------------------------
log "Configuring UFW (deny incoming, allow honeypot ports + mgmt SSH from $OPERATOR_IP)"
ufw --force reset
ufw default deny incoming
ufw default allow outgoing
# Management SSH locked to operator IP.
ufw allow from "$OPERATOR_IP" to any port "$MGMT_SSH_PORT" proto tcp comment 'honeystrike-mgmt'
# Honeypot listeners — public.
for port in 21 22 80 443 3389; do
  ufw allow "$port"/tcp comment "honeystrike-public-$port"
done
ufw --force enable
ufw status verbose

# ---------------------------------------------------------------------------
# 5. fail2ban — protect the management SSH port (NOT 22, that's the honeypot)
# ---------------------------------------------------------------------------
cat > /etc/fail2ban/jail.d/honeystrike-sshd.conf <<EOF
[sshd]
enabled = true
port = ${MGMT_SSH_PORT}
filter = sshd
logpath = /var/log/auth.log
maxretry = 5
findtime = 600
bantime = 3600
EOF
systemctl enable --now fail2ban
systemctl restart fail2ban

# ---------------------------------------------------------------------------
# 6. Directory tree for the compose stack
# ---------------------------------------------------------------------------
log "Creating $INSTALL_PREFIX layout"
install -d -m 0750 "$INSTALL_PREFIX"
install -d -m 0750 /backups/daily /backups/manual
install -d -m 0750 /archive/events

# Make Docker volumes use a predictable host path so backups are easier to grab.
# (Compose default is /var/lib/docker/volumes/...; we leave that alone — the
#  backup script exports via pg_dump rather than copying volume files.)

# ---------------------------------------------------------------------------
# 7. Next steps
# ---------------------------------------------------------------------------
cat <<NEXT

\033[1;32m✓ setup.sh complete.\033[0m

  1. Open a NEW terminal and verify the management SSH works:
        ssh -p ${MGMT_SSH_PORT} <user>@<this-vps>
     Do not close this session until that succeeds.

  2. Clone the repository:
        cd ${INSTALL_PREFIX}
        git clone https://github.com/<you>/honeystrike .

  3. Configure environment:
        cp .env.production.example .env.production
        \$EDITOR .env.production

  4. Build and migrate:
        docker compose -f docker-compose.prod.yml --env-file .env.production \\
          --profile capture build
        docker compose -f docker-compose.prod.yml --env-file .env.production \\
          --profile migrate run --rm migrate

  5. Start the partial-stack (capture profile):
        docker compose -f docker-compose.prod.yml --env-file .env.production \\
          --profile capture up -d

  6. Install the backup cron (see infra/backup.sh).

NEXT
