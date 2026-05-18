# HoneyStrike — Launch Runbook

Step-by-step first deployment. Estimated time: 2–3 hours.

---

## Prerequisites

- [ ] VPS provisioned (Hetzner CX21, Ubuntu 24.04 LTS)
- [ ] Domain name with DNS A record pointing to VPS IP
- [ ] Accounts created: AbuseIPDB (free), MaxMind (free), Telegram bot
- [ ] SSH key access to VPS
- [ ] Local machine: git, ssh

---

## Step 1: VPS Initial Setup (~20 min)

```bash
# Connect to VPS
ssh root@<vps-ip>

# Update system
apt update && apt upgrade -y

# Install Docker
curl -fsSL https://get.docker.com | sh
usermod -aG docker ubuntu  # or your non-root user

# Install utils
apt install -y ufw fail2ban unattended-upgrades git curl jq

# Move SSH to port 2222
sed -i 's/#Port 22/Port 2222/' /etc/ssh/sshd_config
sed -i 's/PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
echo "PasswordAuthentication no" >> /etc/ssh/sshd_config
systemctl restart sshd

# Open new terminal and verify new port works BEFORE continuing!
# ssh -p 2222 ubuntu@<vps-ip>
```

---

## Step 2: Firewall Configuration (~5 min)

```bash
ufw default deny incoming
ufw default allow outgoing
ufw allow 2222/tcp   # Management SSH (new port)
ufw allow 21/tcp     # FTP honeypot
ufw allow 22/tcp     # SSH honeypot
ufw allow 80/tcp     # HTTP (Caddy → redirect)
ufw allow 443/tcp    # HTTPS (Caddy → dashboard)
ufw allow 3389/tcp   # RDP honeypot
ufw enable
ufw status
```

---

## Step 3: Clone Repository (~5 min)

```bash
cd /opt
git clone https://github.com/yourname/honeystrike
cd honeystrike
```

---

## Step 4: Configure Environment (~15 min)

```bash
cp .env.example .env.production
nano .env.production
```

Fill in every variable:

```bash
# Database
DATABASE_URL=postgresql+asyncpg://honeystrike:STRONG_PASSWORD@postgres:5432/honeystrike
POSTGRES_PASSWORD=STRONG_PASSWORD

# Security
SECRET_KEY=<run: python3 -c "import secrets; print(secrets.token_hex(32))">
ADMIN_USERNAME=admin
ADMIN_PASSWORD=<strong password>

# Telegram
TELEGRAM_TOKEN=<from @BotFather>
TELEGRAM_CHAT_ID=<your chat ID>

# AbuseIPDB
ABUSEIPDB_KEY=<from abuseipdb.com/account/api>

# MaxMind
MAXMIND_ACCOUNT_ID=<from maxmind.com>
MAXMIND_LICENSE_KEY=<from maxmind.com>

# Domain
DOMAIN=your-domain.com

# Alerting thresholds
ALERT_THRESHOLD_MEDIUM=30
ALERT_THRESHOLD_HIGH=60
ALERT_THRESHOLD_CRITICAL=80
WORKER_CONCURRENCY=4
```

---

## Step 5: Download MaxMind Databases (~5 min)

```bash
mkdir -p /opt/honeystrike/data/maxmind
docker run --rm \
  -e GEOIPUPDATE_ACCOUNT_ID=${MAXMIND_ACCOUNT_ID} \
  -e GEOIPUPDATE_LICENSE_KEY=${MAXMIND_LICENSE_KEY} \
  -e GEOIPUPDATE_EDITION_IDS="GeoLite2-City GeoLite2-ASN" \
  -v /opt/honeystrike/data/maxmind:/usr/share/GeoIP \
  maxmindinc/geoipupdate
ls /opt/honeystrike/data/maxmind/
# Should show: GeoLite2-City.mmdb  GeoLite2-ASN.mmdb
```

---

## Step 6: Configure Caddyfile (~3 min)

```bash
cat > /opt/honeystrike/Caddyfile << EOF
your-domain.com {
    reverse_proxy localhost:8000
    encode gzip
    header {
        Strict-Transport-Security "max-age=31536000"
        X-Content-Type-Options "nosniff"
        X-Frame-Options "DENY"
    }
}
EOF
```

---

## Step 7: Build and Start Stack (~15 min)

```bash
cd /opt/honeystrike

# Build all images
docker compose -f docker-compose.prod.yml build

# Start database first
docker compose -f docker-compose.prod.yml up -d postgres redis
sleep 15

# Run migrations
docker compose -f docker-compose.prod.yml run --rm dashboard-api \
  alembic upgrade head

# Start full stack
docker compose -f docker-compose.prod.yml up -d

# Verify all containers running
docker compose -f docker-compose.prod.yml ps
```

---

## Step 8: Verification (~10 min)

```bash
# Health check
curl -s https://your-domain.com/api/health | python3 -m json.tool

# Test SSH honeypot (from another terminal)
ssh root@your-domain.com  # Should show fake banner

# Test HTTP honeypot
curl -s https://your-domain.com/wp-admin | head -20

# Verify session was captured
sleep 5
docker exec honeystrike-db psql -U honeystrike -c \
  "SELECT src_ip, service, threat_score FROM sessions ORDER BY started_at DESC LIMIT 5;"

# Check Telegram for alert (if score >= 30)
```

---

## Step 9: Set Up Cron Jobs (~5 min)

```bash
cat > /etc/cron.d/honeystrike << EOF
# Daily DB backup at 01:00 UTC
0 1 * * * root /opt/honeystrike/infra/backup.sh >> /var/log/honeystrike-backup.log 2>&1

# Events archival at 02:00 UTC
0 2 * * * root /opt/honeystrike/infra/archive_events.sh >> /var/log/honeystrike-archive.log 2>&1

# MaxMind DB update weekly (Sunday 03:00 UTC)
0 3 * * 0 root /opt/honeystrike/infra/update_maxmind.sh >> /var/log/honeystrike-maxmind.log 2>&1

# Report file cleanup daily at 03:30 UTC
30 3 * * * root /opt/honeystrike/infra/cleanup_reports.sh >> /var/log/honeystrike-cleanup.log 2>&1
EOF
```

---

## Step 10: Complete Production Readiness Checklist

Go through `15_Production_Readiness_Verification.md` and check every item.

**Launch authorised when:** All 12 sections pass. 🎉
