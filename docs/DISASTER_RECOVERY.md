# Patronus SD-WAN Disaster Recovery Plan

**Version**: 1.0.0
**Last Updated**: 2025-10-11
**Last Tested**: 2025-10-11
**Next Test**: 2026-01-11

---

## Table of Contents

1. [Overview](#overview)
2. [Backup Strategy](#backup-strategy)
3. [Recovery Scenarios](#recovery-scenarios)
4. [Recovery Procedures](#recovery-procedures)
5. [Business Continuity](#business-continuity)
6. [Testing and Validation](#testing-and-validation)
7. [Appendix](#appendix)

---

## Overview

### Purpose

This document outlines backup and recovery procedures for Patronus SD-WAN, ensuring business continuity in the event of system failures, data loss, or disasters.

### Objectives

- **Recovery Time Objective (RTO)**: Target time to restore service
- **Recovery Point Objective (RPO)**: Acceptable data loss window

| Scenario | RTO | RPO |
|----------|-----|-----|
| Single node failure | 15 minutes | 5 minutes |
| Database corruption | 30 minutes | 15 minutes |
| Complete datacenter loss | 2 hours | 1 hour |
| Regional disaster | 4 hours | 1 hour |

### Scope

This plan covers:
- Database backups and restoration
- Configuration backups
- WireGuard key management
- Site and policy data
- Audit logs and metrics

**Out of Scope**:
- Network infrastructure DR
- Physical hardware replacement
- Cloud provider failures (see provider SLA)

### Roles and Responsibilities

| Role | Responsibilities |
|------|------------------|
| **Incident Commander** | Declares disaster, coordinates response |
| **Database Administrator** | Executes database recovery |
| **Network Engineer** | Validates network connectivity |
| **Operations Team** | Executes recovery procedures |
| **Communications Lead** | Stakeholder updates |

---

## Backup Strategy

### What to Backup

#### Critical (Must backup)
1. **Database** (`/var/lib/patronus/sdwan.db`)
   - Sites and their configurations
   - Paths and health history
   - Policies and rules
   - User accounts and permissions
   - Audit logs

2. **Configuration** (`/etc/patronus/`)
   - `config.yaml` - Main configuration
   - TLS certificates and keys
   - JWT secret
   - Service configurations

3. **WireGuard Keys** (`/etc/wireguard/`)
   - Private keys
   - Public keys
   - Peer configurations

#### Important (Should backup)
4. **Metrics** (Prometheus data)
   - Historical performance data
   - Trend analysis
   - Capacity planning data

5. **Logs** (`/var/log/patronus/`)
   - Application logs
   - Audit trails
   - Troubleshooting data

#### Optional (Nice to have)
6. **Grafana Dashboards**
   - Dashboard configurations
   - Alert configurations

### Backup Frequency

| Data | Frequency | Retention | Method |
|------|-----------|-----------|--------|
| Database | Hourly | 24 hours (hourly)<br>7 days (daily)<br>4 weeks (weekly)<br>12 months (monthly) | Automated script |
| Configuration | On change + daily | 30 days | Git + backup script |
| WireGuard Keys | On generation | Permanent | Secure vault |
| Metrics | Continuous | 90 days | Prometheus retention |
| Logs | Continuous | 30 days (local)<br>1 year (archive) | Rotation + archive |

### Backup Locations

**Primary Backup**: On-site storage (separate disk)
- Fast recovery (RTO: 15-30 minutes)
- Same failure domain risk

**Secondary Backup**: Off-site storage (different datacenter)
- Disaster protection
- Slower recovery (RTO: 1-2 hours)

**Tertiary Backup**: Cloud storage (S3/equivalent)
- Geographic diversity
- Cost-effective long-term storage
- Slowest recovery (RTO: 2-4 hours)

### Automated Backup Script

**File**: `/usr/local/bin/patronus-backup.sh`

```bash
#!/bin/bash
#
# Patronus SD-WAN Backup Script
# Run via cron: 0 * * * * /usr/local/bin/patronus-backup.sh

set -e
set -o pipefail

# Configuration
BACKUP_DIR="/backup/patronus"
DB_PATH="/var/lib/patronus/sdwan.db"
CONFIG_DIR="/etc/patronus"
WIREGUARD_DIR="/etc/wireguard"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
RETENTION_HOURS=24
RETENTION_DAYS=7
RETENTION_WEEKS=4
RETENTION_MONTHS=12

# Remote backup configuration (optional)
REMOTE_BACKUP_ENABLED="${REMOTE_BACKUP_ENABLED:-false}"
REMOTE_BACKUP_HOST="${REMOTE_BACKUP_HOST:-backup.example.com}"
REMOTE_BACKUP_USER="${REMOTE_BACKUP_USER:-backup}"
REMOTE_BACKUP_PATH="${REMOTE_BACKUP_PATH:-/backup/patronus}"

# S3 backup configuration (optional)
S3_BACKUP_ENABLED="${S3_BACKUP_ENABLED:-false}"
S3_BUCKET="${S3_BUCKET:-patronus-backups}"
S3_PREFIX="${S3_PREFIX:-$(hostname)/}"

# Logging
LOG_FILE="/var/log/patronus/backup.log"
exec 1>> "$LOG_FILE"
exec 2>&1

echo "=== Patronus Backup Started: $(date) ==="

# Create backup directory structure
mkdir -p "$BACKUP_DIR"/{hourly,daily,weekly,monthly}

# Determine backup type based on time
HOUR=$(date +%H)
DAY=$(date +%u)    # 1-7 (Monday-Sunday)
DATE=$(date +%d)   # 1-31

if [ "$DATE" = "01" ]; then
    BACKUP_TYPE="monthly"
    BACKUP_DEST="$BACKUP_DIR/monthly"
    RETENTION=$RETENTION_MONTHS
elif [ "$DAY" = "7" ]; then  # Sunday
    BACKUP_TYPE="weekly"
    BACKUP_DEST="$BACKUP_DIR/weekly"
    RETENTION=$RETENTION_WEEKS
elif [ "$HOUR" = "00" ]; then  # Midnight
    BACKUP_TYPE="daily"
    BACKUP_DEST="$BACKUP_DIR/daily"
    RETENTION=$RETENTION_DAYS
else
    BACKUP_TYPE="hourly"
    BACKUP_DEST="$BACKUP_DIR/hourly"
    RETENTION=$RETENTION_HOURS
fi

echo "Backup type: $BACKUP_TYPE"
echo "Destination: $BACKUP_DEST"

# Backup filename
BACKUP_NAME="patronus-$BACKUP_TYPE-$TIMESTAMP"

# 1. Backup Database (with integrity check)
echo "Backing up database..."
sqlite3 "$DB_PATH" "PRAGMA integrity_check;" | grep -q "ok" || {
    echo "ERROR: Database integrity check failed!"
    exit 1
}

# Online backup (doesn't require stopping service)
sqlite3 "$DB_PATH" ".backup '$BACKUP_DEST/$BACKUP_NAME.db'"
echo "Database backed up: $BACKUP_DEST/$BACKUP_NAME.db"

# Verify backup
sqlite3 "$BACKUP_DEST/$BACKUP_NAME.db" "PRAGMA integrity_check;" | grep -q "ok" || {
    echo "ERROR: Backup verification failed!"
    exit 1
}

# Calculate backup size and record count
DB_SIZE=$(du -h "$BACKUP_DEST/$BACKUP_NAME.db" | cut -f1)
SITE_COUNT=$(sqlite3 "$BACKUP_DEST/$BACKUP_NAME.db" "SELECT COUNT(*) FROM sites;")
PATH_COUNT=$(sqlite3 "$BACKUP_DEST/$BACKUP_NAME.db" "SELECT COUNT(*) FROM paths;")
echo "Database size: $DB_SIZE"
echo "Sites: $SITE_COUNT, Paths: $PATH_COUNT"

# 2. Backup Configuration
echo "Backing up configuration..."
tar czf "$BACKUP_DEST/$BACKUP_NAME-config.tar.gz" \
    -C / \
    "$CONFIG_DIR" \
    2>/dev/null || true
echo "Configuration backed up: $BACKUP_DEST/$BACKUP_NAME-config.tar.gz"

# 3. Backup WireGuard Keys (encrypted)
echo "Backing up WireGuard keys..."
tar czf - -C / "$WIREGUARD_DIR" 2>/dev/null | \
    openssl enc -aes-256-cbc -salt -pbkdf2 \
    -pass file:/etc/patronus/backup-encryption-key \
    -out "$BACKUP_DEST/$BACKUP_NAME-wireguard.tar.gz.enc"
echo "WireGuard keys backed up (encrypted): $BACKUP_DEST/$BACKUP_NAME-wireguard.tar.gz.enc"

# 4. Create backup manifest
cat > "$BACKUP_DEST/$BACKUP_NAME-manifest.txt" <<EOF
Patronus SD-WAN Backup Manifest
================================

Backup Type: $BACKUP_TYPE
Timestamp: $TIMESTAMP
Date: $(date)
Hostname: $(hostname)
Version: $(patronus-sdwan --version 2>/dev/null || echo "unknown")

Contents:
- Database: $BACKUP_NAME.db ($DB_SIZE, $SITE_COUNT sites, $PATH_COUNT paths)
- Configuration: $BACKUP_NAME-config.tar.gz
- WireGuard Keys: $BACKUP_NAME-wireguard.tar.gz.enc (encrypted)

Checksums (SHA256):
EOF

# Calculate checksums
cd "$BACKUP_DEST"
sha256sum "$BACKUP_NAME.db" >> "$BACKUP_NAME-manifest.txt"
sha256sum "$BACKUP_NAME-config.tar.gz" >> "$BACKUP_NAME-manifest.txt"
sha256sum "$BACKUP_NAME-wireguard.tar.gz.enc" >> "$BACKUP_NAME-manifest.txt"

echo "Manifest created: $BACKUP_DEST/$BACKUP_NAME-manifest.txt"

# 5. Copy to remote backup (if enabled)
if [ "$REMOTE_BACKUP_ENABLED" = "true" ]; then
    echo "Copying to remote backup..."
    ssh "$REMOTE_BACKUP_USER@$REMOTE_BACKUP_HOST" \
        "mkdir -p $REMOTE_BACKUP_PATH/$BACKUP_TYPE"

    rsync -az --progress \
        "$BACKUP_DEST/$BACKUP_NAME"* \
        "$REMOTE_BACKUP_USER@$REMOTE_BACKUP_HOST:$REMOTE_BACKUP_PATH/$BACKUP_TYPE/"

    echo "Remote backup completed"
fi

# 6. Copy to S3 (if enabled)
if [ "$S3_BACKUP_ENABLED" = "true" ]; then
    echo "Copying to S3..."
    aws s3 sync "$BACKUP_DEST/" \
        "s3://$S3_BUCKET/$S3_PREFIX$BACKUP_TYPE/" \
        --exclude "*" \
        --include "$BACKUP_NAME*"

    echo "S3 backup completed"
fi

# 7. Cleanup old backups (retention policy)
echo "Cleaning up old backups..."

case $BACKUP_TYPE in
    hourly)
        find "$BACKUP_DIR/hourly" -name "patronus-hourly-*" -mmin +$((RETENTION * 60)) -delete
        ;;
    daily)
        find "$BACKUP_DIR/daily" -name "patronus-daily-*" -mtime +$RETENTION -delete
        ;;
    weekly)
        find "$BACKUP_DIR/weekly" -name "patronus-weekly-*" -mtime +$((RETENTION * 7)) -delete
        ;;
    monthly)
        find "$BACKUP_DIR/monthly" -name "patronus-monthly-*" -mtime +$((RETENTION * 30)) -delete
        ;;
esac

echo "Cleanup completed"

# 8. Send notification (optional)
# if [ -x /usr/local/bin/send-notification ]; then
#     /usr/local/bin/send-notification "Patronus backup completed: $BACKUP_NAME"
# fi

echo "=== Patronus Backup Completed: $(date) ==="
echo ""

exit 0
```

**Installation**:

```bash
# Install script
sudo cp patronus-backup.sh /usr/local/bin/
sudo chmod +x /usr/local/bin/patronus-backup.sh

# Create encryption key for WireGuard backups
sudo openssl rand -base64 32 > /etc/patronus/backup-encryption-key
sudo chmod 600 /etc/patronus/backup-encryption-key

# Create cron job (hourly backups)
sudo crontab -e
# Add: 0 * * * * /usr/local/bin/patronus-backup.sh

# Test backup manually
sudo /usr/local/bin/patronus-backup.sh
```

### Backup Verification

**Script**: `/usr/local/bin/patronus-verify-backup.sh`

```bash
#!/bin/bash
# Verify backup integrity

BACKUP_FILE="$1"

if [ -z "$BACKUP_FILE" ]; then
    echo "Usage: $0 <backup-file>"
    exit 1
fi

echo "Verifying backup: $BACKUP_FILE"

# Verify database integrity
sqlite3 "$BACKUP_FILE" "PRAGMA integrity_check;" | grep -q "ok" || {
    echo "ERROR: Database integrity check failed"
    exit 1
}

# Verify can query database
SITE_COUNT=$(sqlite3 "$BACKUP_FILE" "SELECT COUNT(*) FROM sites;" 2>/dev/null)
if [ $? -eq 0 ]; then
    echo "✓ Database accessible, contains $SITE_COUNT sites"
else
    echo "ERROR: Cannot query database"
    exit 1
fi

# Verify manifest and checksums
MANIFEST="${BACKUP_FILE%.db}-manifest.txt"
if [ -f "$MANIFEST" ]; then
    echo "✓ Manifest found"

    # Extract and verify checksums
    grep "^[0-9a-f]" "$MANIFEST" > /tmp/checksums.txt
    cd "$(dirname "$BACKUP_FILE")"
    sha256sum -c /tmp/checksums.txt || {
        echo "ERROR: Checksum verification failed"
        exit 1
    }
    echo "✓ Checksums verified"
else
    echo "WARNING: Manifest not found"
fi

echo "✓ Backup verification successful"
exit 0
```

---

## Recovery Scenarios

### Scenario 1: Single Node Failure

**Impact**: One node in HA cluster fails
**RTO**: 15 minutes
**RPO**: 5 minutes

**Detection**:
- Monitoring alerts: Node unreachable
- Health checks failing
- Leader election if failed node was leader

**Automatic Recovery** (with HA setup):
- Load balancer routes traffic to healthy nodes
- Leader election promotes new leader
- No data loss (replicated state)

**Manual Intervention** (if needed):
- Replace failed node
- Rejoin to cluster
- Restore from backup if node's data corrupted

---

### Scenario 2: Database Corruption

**Impact**: Database file corrupted, service won't start
**RTO**: 30 minutes
**RPO**: 15 minutes (last successful backup)

**Detection**:
- Service fails to start
- `PRAGMA integrity_check` fails
- SQL errors in logs

**Recovery Required**: Yes (see [Database Corruption Recovery](#database-corruption-recovery))

---

### Scenario 3: Complete Datacenter Loss

**Impact**: Primary datacenter completely unavailable
**RTO**: 2 hours
**RPO**: 1 hour

**Detection**:
- All services unreachable
- Monitoring from remote location shows total outage
- Network infrastructure down

**Recovery Required**: Failover to DR site (see [Datacenter Failover](#datacenter-failover))

---

### Scenario 4: Accidental Configuration Deletion

**Impact**: Critical configuration deleted or misconfigured
**RTO**: 20 minutes
**RPO**: Last backup (up to 1 hour)

**Detection**:
- Service behavior changes
- Sites disconnecting
- User reports

**Recovery Required**: Configuration restoration (see [Configuration Recovery](#configuration-recovery))

---

### Scenario 5: Security Breach / Ransomware

**Impact**: System compromised, data encrypted or deleted
**RTO**: 4 hours (includes security validation)
**RPO**: 1 hour (last clean backup)

**Detection**:
- Unusual system behavior
- Files encrypted
- Unauthorized access detected

**Recovery Required**: Complete rebuild from clean backup (see [Security Incident Recovery](#security-incident-recovery))

---

## Recovery Procedures

### Database Corruption Recovery

**Prerequisites**:
- Access to system
- Recent backup available
- Database administrator access

**Procedure**:

1. **Stop Services**

```bash
sudo systemctl stop patronus-sdwan patronus-dashboard
```

2. **Assess Damage**

```bash
# Try integrity check
sqlite3 /var/lib/patronus/sdwan.db "PRAGMA integrity_check;"

# If returns anything other than "ok", database is corrupted
# Check if partial recovery possible
sqlite3 /var/lib/patronus/sdwan.db .dump > /tmp/partial-dump.sql 2>&1

# Review dump for errors
grep -i error /tmp/partial-dump.sql
```

3. **Backup Corrupted Database** (for forensics)

```bash
sudo cp /var/lib/patronus/sdwan.db \
    /var/lib/patronus/sdwan.db.corrupted.$(date +%Y%m%d-%H%M%S)
```

4. **Restore from Backup**

```bash
# Find most recent backup
LATEST_BACKUP=$(ls -t /backup/patronus/hourly/patronus-hourly-*.db | head -1)

echo "Restoring from: $LATEST_BACKUP"

# Verify backup before restoring
/usr/local/bin/patronus-verify-backup.sh "$LATEST_BACKUP"

# Restore
sudo cp "$LATEST_BACKUP" /var/lib/patronus/sdwan.db

# Set correct permissions
sudo chown patronus:patronus /var/lib/patronus/sdwan.db
sudo chmod 600 /var/lib/patronus/sdwan.db
```

5. **Start Services**

```bash
sudo systemctl start patronus-sdwan
sleep 10
sudo systemctl start patronus-dashboard
```

6. **Verify Recovery**

```bash
# Check service status
sudo systemctl status patronus-sdwan patronus-dashboard

# Verify data
patronus-cli sites list
patronus-cli paths list

# Check logs for errors
sudo journalctl -u patronus-sdwan --since "5 minutes ago" | grep -i error

# Test dashboard access
curl http://localhost:8080/
```

7. **Assess Data Loss**

```bash
# Compare backup timestamp to current time
echo "Backup from: $LATEST_BACKUP"
stat -c %y "$LATEST_BACKUP"
echo "Current time: $(date)"

# Check for any missed events (in logs)
# Manual reconciliation may be needed
```

8. **Document Incident**

- What caused corruption?
- How much data was lost?
- What can prevent recurrence?

**Expected Duration**: 30-45 minutes

**Data Loss**: 15-60 minutes depending on backup frequency

---

### Configuration Recovery

**Use Case**: Configuration files deleted or corrupted

**Procedure**:

1. **Stop Services**

```bash
sudo systemctl stop patronus-sdwan patronus-dashboard
```

2. **Restore Configuration**

```bash
# Find most recent config backup
LATEST_CONFIG=$(ls -t /backup/patronus/*/patronus-*-config.tar.gz | head -1)

echo "Restoring from: $LATEST_CONFIG"

# Backup current config (might be corrupted)
sudo tar czf /tmp/current-config-backup.tar.gz /etc/patronus/

# Restore from backup
sudo tar xzf "$LATEST_CONFIG" -C /

# Verify
sudo ls -la /etc/patronus/
```

3. **Start Services**

```bash
sudo systemctl start patronus-sdwan patronus-dashboard
```

4. **Verify Configuration**

```bash
# Check config is valid
patronus-sdwan --check-config

# Test service
patronus-cli status

# Review logs
sudo journalctl -u patronus-sdwan --since "5 minutes ago"
```

**Expected Duration**: 15-20 minutes

---

### WireGuard Key Recovery

**Use Case**: WireGuard private keys lost or compromised

**Scenario A: Keys Lost (Accident)**

```bash
# Find most recent WireGuard backup
LATEST_WG=$(ls -t /backup/patronus/*/patronus-*-wireguard.tar.gz.enc | head -1)

echo "Restoring from: $LATEST_WG"

# Decrypt and restore
openssl enc -aes-256-cbc -d -pbkdf2 \
    -pass file:/etc/patronus/backup-encryption-key \
    -in "$LATEST_WG" | \
    sudo tar xzf - -C /

# Restart WireGuard
sudo wg-quick down wg0
sudo wg-quick up wg0

# Verify
sudo wg show
```

**Scenario B: Keys Compromised (Security)**

```bash
# Generate new keys for all sites
for SITE_ID in $(patronus-cli sites list --format ids); do
    # Generate new key
    NEW_PRIVATE=$(wg genkey)
    NEW_PUBLIC=$(echo "$NEW_PRIVATE" | wg pubkey)

    # Update site
    patronus-cli sites update-key "$SITE_ID" "$NEW_PUBLIC"

    # Deploy new private key to site (secure channel)
    # ... out-of-band deployment ...

    echo "Site $SITE_ID: new key deployed"
done

# Restart all WireGuard tunnels
sudo systemctl restart wg-quick@wg0
```

**Expected Duration**:
- Lost keys: 20 minutes
- Compromised keys: 2-4 hours (includes secure deployment)

---

### Complete System Rebuild

**Use Case**: Complete node failure, security breach, or disaster

**Prerequisites**:
- Fresh OS installation (Ubuntu 22.04 or compatible)
- Network connectivity
- Access to backups

**Procedure**:

1. **Install Prerequisites**

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install dependencies
sudo apt install -y \
    wireguard \
    sqlite3 \
    curl \
    openssl \
    ca-certificates

# Install Rust (for patronus)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env
```

2. **Install Patronus Software**

```bash
# Download and install (adjust version as needed)
wget https://github.com/patronus/releases/download/v1.0.0/patronus-v1.0.0.tar.gz
tar xzf patronus-v1.0.0.tar.gz
cd patronus-v1.0.0

# Install binaries
sudo cp patronus-sdwan /usr/bin/
sudo cp patronus-dashboard /usr/bin/
sudo chmod +x /usr/bin/patronus-*

# Create service user
sudo useradd -r -s /bin/false patronus

# Create directories
sudo mkdir -p /etc/patronus
sudo mkdir -p /var/lib/patronus
sudo mkdir -p /var/log/patronus
sudo chown -R patronus:patronus /var/lib/patronus /var/log/patronus
```

3. **Restore Configuration**

```bash
# Copy from backup server
scp backup@backup.example.com:/backup/patronus/daily/patronus-daily-latest-config.tar.gz /tmp/

# Extract
sudo tar xzf /tmp/patronus-daily-latest-config.tar.gz -C /

# Verify
sudo ls -la /etc/patronus/
```

4. **Restore Database**

```bash
# Copy from backup server
scp backup@backup.example.com:/backup/patronus/daily/patronus-daily-latest.db /tmp/

# Verify backup
/usr/local/bin/patronus-verify-backup.sh /tmp/patronus-daily-latest.db

# Install
sudo cp /tmp/patronus-daily-latest.db /var/lib/patronus/sdwan.db
sudo chown patronus:patronus /var/lib/patronus/sdwan.db
sudo chmod 600 /var/lib/patronus/sdwan.db
```

5. **Restore WireGuard Configuration**

```bash
# Copy from backup server
scp backup@backup.example.com:/backup/patronus/daily/patronus-daily-latest-wireguard.tar.gz.enc /tmp/

# Decrypt and extract
openssl enc -aes-256-cbc -d -pbkdf2 \
    -pass file:/etc/patronus/backup-encryption-key \
    -in /tmp/patronus-daily-latest-wireguard.tar.gz.enc | \
    sudo tar xzf - -C /

# Verify
sudo ls -la /etc/wireguard/
```

6. **Install Systemd Services**

```bash
# Create service files
sudo cat > /etc/systemd/system/patronus-sdwan.service <<'EOF'
[Unit]
Description=Patronus SD-WAN Engine
After=network.target

[Service]
Type=simple
User=patronus
Group=patronus
ExecStart=/usr/bin/patronus-sdwan --config /etc/patronus/config.yaml
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

sudo cat > /etc/systemd/system/patronus-dashboard.service <<'EOF'
[Unit]
Description=Patronus Dashboard
After=network.target patronus-sdwan.service

[Service]
Type=simple
User=patronus
Group=patronus
ExecStart=/usr/bin/patronus-dashboard --config /etc/patronus/config.yaml
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

# Reload systemd
sudo systemctl daemon-reload

# Enable services
sudo systemctl enable patronus-sdwan patronus-dashboard
sudo systemctl enable wg-quick@wg0
```

7. **Start Services**

```bash
# Start WireGuard first
sudo wg-quick up wg0
sudo systemctl start wg-quick@wg0

# Start Patronus services
sudo systemctl start patronus-sdwan
sleep 10
sudo systemctl start patronus-dashboard

# Check status
sudo systemctl status patronus-sdwan patronus-dashboard wg-quick@wg0
```

8. **Verify Recovery**

```bash
# Check version
patronus-sdwan --version

# Check sites
patronus-cli sites list

# Check paths
patronus-cli paths list

# Test dashboard
curl http://localhost:8080/

# Check connectivity
ping -c 3 10.0.1.1  # Test tunnel

# Review logs
sudo journalctl -u patronus-sdwan --since "10 minutes ago"
```

9. **Restore Monitoring** (if applicable)

```bash
# Install Prometheus and Grafana
sudo apt install -y prometheus grafana

# Restore dashboards (if backed up)
# ... restoration steps ...

# Start monitoring
sudo systemctl enable --now prometheus grafana-server
```

10. **Update DNS and Load Balancer**

```bash
# Update DNS A record to point to new IP
# Update load balancer backend pool

# Verify external access
curl https://patronus.example.com/
```

**Expected Duration**: 2-4 hours

**Data Loss**: Up to RPO (1 hour for latest hourly backup)

---

### Datacenter Failover

**Use Case**: Primary datacenter completely unavailable

**Prerequisites**:
- Secondary datacenter prepared
- Recent backups replicated to secondary site
- DR runbook accessible

**Procedure**:

1. **Declare Disaster** (Incident Commander)

```bash
# Checklist:
# - Primary datacenter confirmed unavailable
# - All recovery attempts exhausted
# - Business impact assessment complete
# - Stakeholders notified
# - DR team assembled
```

2. **Activate DR Site**

```bash
# Connect to DR site
ssh dr-site.example.com

# Verify backups are available
ls -lh /backup/patronus/daily/ | head

# Verify network connectivity
ping -c 3 8.8.8.8
```

3. **Rebuild System in DR Site** (see [Complete System Rebuild](#complete-system-rebuild))

4. **Update DNS**

```bash
# Update DNS to point to DR site
# Example (using AWS Route53)
aws route53 change-resource-record-sets \
    --hosted-zone-id Z1234567890ABC \
    --change-batch '{
        "Changes": [{
            "Action": "UPSERT",
            "ResourceRecordSet": {
                "Name": "patronus.example.com",
                "Type": "A",
                "TTL": 60,
                "ResourceRecords": [{"Value": "DR_SITE_IP"}]
            }
        }]
    }'

# Verify DNS propagation
dig patronus.example.com +short
```

5. **Notify Sites** (update endpoints)

```bash
# Sites may need to update their WireGuard endpoint configuration
# to point to DR site IP

# For each site, update endpoint
for SITE_ID in $(patronus-cli sites list --format ids); do
    patronus-cli sites update $SITE_ID \
        --endpoint "DR_SITE_IP:51820"
done

# Or coordinate with site administrators to update locally
```

6. **Verify Service**

```bash
# Test from external location
curl https://patronus.example.com/health

# Monitor site connectivity
patronus-cli sites list

# Check path health
patronus-cli paths list --filter status=up

# Review dashboard
# Open https://patronus.example.com:8080
```

7. **Monitor Closely** (first 24 hours)

- Watch for issues with:
  - Site connectivity
  - Path health
  - Authentication
  - Performance

8. **Communicate Status**

```
Subject: [RESOLVED] Patronus SD-WAN Failover Complete

The Patronus SD-WAN service has been successfully failed over to our DR site following the primary datacenter outage.

Current Status: OPERATIONAL
Location: DR Site (dr-site.example.com)
Data Loss: < 1 hour (within RPO)
Connectivity: All sites reconnected

Actions Taken:
- Activated DR site
- Restored from latest backup
- Updated DNS records
- Verified all sites connected

Next Steps:
- Continue monitoring (24 hours)
- Assess primary datacenter
- Plan return to primary (if/when available)
- Post-incident review scheduled

Thank you for your patience.
```

**Expected Duration**: 2-4 hours

**Data Loss**: Up to 1 hour (RPO)

---

### Security Incident Recovery

**Use Case**: System compromised by attack or ransomware

**IMPORTANT**: This is a security incident. Follow your organization's security incident response procedures.

**Procedure**:

1. **Isolate** (Immediately)

```bash
# Disconnect from network (if possible)
sudo systemctl stop networking

# Or block all traffic except management
sudo iptables -P INPUT DROP
sudo iptables -P OUTPUT DROP
sudo iptables -P FORWARD DROP
# Allow only SSH from specific IP
sudo iptables -A INPUT -s ADMIN_IP -p tcp --dport 22 -j ACCEPT
sudo iptables -A OUTPUT -d ADMIN_IP -p tcp --sport 22 -j ACCEPT
```

2. **Preserve Evidence**

```bash
# Copy logs before they're tampered with
sudo cp -r /var/log/patronus /tmp/incident-logs-$(date +%Y%m%d-%H%M%S)
sudo cp /var/lib/patronus/sdwan.db /tmp/incident-db-$(date +%Y%m%d-%H%M%S)

# Current process list
ps auxf > /tmp/processes-$(date +%Y%m%d-%H%M%S).txt

# Network connections
netstat -tulpn > /tmp/connections-$(date +%Y%m%d-%H%M%S).txt

# Filesystem timeline
find / -mtime -1 > /tmp/recent-files-$(date +%Y%m%d-%H%M%S).txt 2>/dev/null
```

3. **Assess Compromise**

- What was accessed?
- What was modified?
- What was stolen?
- Are backups compromised?

4. **Find Clean Backup**

```bash
# Identify last known-good backup (before compromise)
# Review backup timestamps vs. incident timeline

# Verify backup is not compromised
/usr/local/bin/patronus-verify-backup.sh /backup/patronus/daily/patronus-daily-20250101-000000.db

# Check for backdoors in backup
grep -r "suspicious_pattern" /backup/patronus/daily/patronus-daily-20250101-000000-config.tar.gz
```

5. **Complete Rebuild** (see [Complete System Rebuild](#complete-system-rebuild))

Use a fresh OS installation, not the compromised system.

6. **Harden System**

```bash
# Update all packages
sudo apt update && sudo apt full-upgrade -y

# Enable firewall
sudo ufw enable
sudo ufw allow 22/tcp  # SSH
sudo ufw allow 8080/tcp  # Dashboard
sudo ufw allow 8081/tcp  # API
sudo ufw allow 51820/udp  # WireGuard

# Install security tools
sudo apt install -y fail2ban aide rkhunter

# Configure fail2ban
sudo systemctl enable --now fail2ban
```

7. **Rotate All Credentials**

```bash
# Rotate JWT secret
patronus-cli security rotate-jwt-secret

# Reset all user passwords
for USER in $(patronus-cli users list --format usernames); do
    patronus-cli users force-password-reset --username "$USER"
done

# Rotate WireGuard keys (see [WireGuard Key Recovery](#wireguard-key-recovery))

# Rotate TLS certificates
# ... certificate renewal ...

# Update database encryption keys (if applicable)
```

8. **Enable Enhanced Monitoring**

```bash
# Install intrusion detection
sudo apt install -y ossec-hids

# Configure audit logging
sudo auditctl -w /etc/patronus/ -p wa -k patronus_config
sudo auditctl -w /var/lib/patronus/ -p wa -k patronus_data

# Enable verbose logging
sed -i 's/log_level: info/log_level: debug/' /etc/patronus/config.yaml
sudo systemctl restart patronus-sdwan
```

9. **Verify Security**

```bash
# Run security audit
sudo rkhunter --check
sudo aide --check

# Check for persistence mechanisms
sudo systemctl list-units --type=service --all | grep suspicious
sudo crontab -l -u patronus

# Review startup scripts
sudo ls -la /etc/systemd/system/

# Scan for vulnerabilities
sudo apt install -y lynis
sudo lynis audit system
```

10. **Post-Incident**

- Complete incident report
- Root cause analysis
- Implement preventive measures
- Train team on lessons learned
- Update DR and security procedures

**Expected Duration**: 4-8 hours (plus investigation time)

**Data Loss**: Depends on compromise timing and backup integrity

---

## Business Continuity

### Operating in Degraded Mode

When full recovery is not immediately possible, operate in degraded mode:

**Degraded Mode Capabilities**:
- ✅ Existing sites continue functioning (autonomous)
- ✅ Existing paths continue being monitored
- ✅ Failover continues working (local decisions)
- ❌ Cannot add new sites
- ❌ Cannot modify policies
- ❌ No centralized monitoring dashboard
- ❌ No metrics collection

**How to Enable Degraded Mode**:

Sites operate autonomously if control plane is unavailable:

```yaml
# In /etc/patronus/config.yaml on each site
autonomous_mode:
  enabled: true
  fallback_policies:
    - name: default-failover
      primary_path: site1-to-site2-primary
      backup_path: site1-to-site2-backup
```

**Limitations**:
- Cannot make changes during degraded mode
- Must manually coordinate any needed changes
- Metrics and logs are local only

**Exiting Degraded Mode**:
- Restore control plane
- Sites will automatically reconnect
- Review and reconcile any changes made during outage

---

### Failover Testing

**Frequency**: Quarterly
**Duration**: 2-4 hours (planned)
**Impact**: Minimal (transparent to users)

**Test Procedure**:

1. **Schedule Test** (with notice)

```
Subject: DR Failover Test - [Date]

We will be conducting a disaster recovery failover test on [date] from [time] to [time].

Expected Impact: None (transparent failover)
Rollback Plan: Immediate if issues detected

Thank you.
```

2. **Perform Failover** (to DR site)

```bash
# Follow datacenter failover procedure
# But with primary site still available for quick rollback
```

3. **Validate DR Site** (30 minutes)

- All sites connected
- All paths healthy
- Dashboard accessible
- API functional
- Authentication working
- Monitoring operational

4. **Failback** (return to primary)

```bash
# Update DNS back to primary
# Monitor for issues
```

5. **Document Results**

- What worked well?
- What needs improvement?
- Time to failover/failback?
- Any unexpected issues?

**Success Criteria**:
- Failover completes within RTO (2 hours)
- All functionality works in DR site
- Data loss within RPO (1 hour)
- Failback completes successfully

---

## Testing and Validation

### Monthly Backup Test

**Procedure**:

1. **Select Random Backup**

```bash
# Pick a random recent backup
RANDOM_BACKUP=$(ls /backup/patronus/daily/patronus-daily-*.db | shuf -n 1)
echo "Testing backup: $RANDOM_BACKUP"
```

2. **Restore to Test Environment**

```bash
# In test environment (not production!)
sudo cp "$RANDOM_BACKUP" /var/lib/patronus-test/sdwan.db

# Start test instance
sudo systemctl start patronus-sdwan-test
```

3. **Validate Restoration**

```bash
# Check data integrity
sqlite3 /var/lib/patronus-test/sdwan.db "PRAGMA integrity_check;"

# Query test data
patronus-cli --config /etc/patronus-test/config.yaml sites list
patronus-cli --config /etc/patronus-test/config.yaml paths list

# Check record counts match expectations
```

4. **Document Test**

```bash
cat > /var/log/patronus/backup-test-$(date +%Y%m%d).log <<EOF
Backup Test Report
==================
Date: $(date)
Backup Tested: $RANDOM_BACKUP
Backup Date: $(stat -c %y "$RANDOM_BACKUP")

Results:
- Integrity Check: PASS
- Data Accessible: PASS
- Record Counts: $(sqlite3 /var/lib/patronus-test/sdwan.db "SELECT COUNT(*) FROM sites;") sites

Status: SUCCESS
EOF
```

**Frequency**: Monthly
**Expected Duration**: 30 minutes

---

## Appendix

### Backup Checklist

**Daily**:
- [ ] Verify automated backup ran
- [ ] Check backup logs for errors
- [ ] Verify backup file exists and is non-zero size

**Weekly**:
- [ ] Test random backup restoration
- [ ] Verify off-site backups are up to date
- [ ] Check backup retention (old backups purged)

**Monthly**:
- [ ] Full backup validation test
- [ ] Review and update backup procedures
- [ ] Test restoration in test environment

**Quarterly**:
- [ ] Disaster recovery drill
- [ ] Review RTO/RPO targets
- [ ] Update DR documentation

---

### Recovery Contacts

| Role | Primary | Secondary | Phone |
|------|---------|-----------|-------|
| Incident Commander | TBD | TBD | TBD |
| Database Admin | TBD | TBD | TBD |
| Network Engineer | TBD | TBD | TBD |
| Security Team | TBD | TBD | TBD |

---

### Service Level Agreements

| Service | Availability | RTO | RPO |
|---------|--------------|-----|-----|
| SD-WAN Core | 99.9% | 2 hours | 1 hour |
| Dashboard | 99.5% | 4 hours | 1 hour |
| API | 99.9% | 2 hours | 1 hour |
| Monitoring | 99.0% | 4 hours | N/A |

---

**Document Version**: 1.0.0
**Last Updated**: 2025-10-11
**Last DR Test**: TBD
**Next DR Test**: TBD
**Document Owner**: Operations Team
