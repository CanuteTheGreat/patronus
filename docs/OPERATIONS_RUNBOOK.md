# Patronus SD-WAN Operations Runbook

**Version**: 1.0.0
**Last Updated**: 2025-10-11
**Applies To**: Patronus SD-WAN v1.0+

---

## Table of Contents

1. [Overview](#overview)
2. [Daily Operations](#daily-operations)
3. [Common Tasks](#common-tasks)
4. [Troubleshooting](#troubleshooting)
5. [Incident Response](#incident-response)
6. [Maintenance](#maintenance)
7. [Monitoring & Alerts](#monitoring--alerts)
8. [Emergency Procedures](#emergency-procedures)

---

## Overview

### Purpose

This runbook provides step-by-step procedures for operating and troubleshooting Patronus SD-WAN in production. It is intended for operations teams, SREs, and on-call engineers.

### Prerequisites

- Access to production systems
- kubectl configured (if using Kubernetes)
- Database access credentials
- Monitoring dashboard access (Grafana)
- Understanding of SD-WAN concepts

### System Architecture Quick Reference

```
┌─────────────────────────────────────────────┐
│           Patronus SD-WAN Stack             │
├─────────────────────────────────────────────┤
│  Dashboard (8080)  │  API (8081)            │
│  ─────────────────────────────────────────  │
│  Control Plane     │  Health Monitor        │
│  ─────────────────────────────────────────  │
│  Mesh Engine       │  Failover Engine       │
│  ─────────────────────────────────────────  │
│  Database (SQLite) │  Metrics (Prometheus)  │
└─────────────────────────────────────────────┘
```

### Key Ports

| Port | Service | Purpose |
|------|---------|---------|
| 8080 | Dashboard | Web UI |
| 8081 | API | REST/GraphQL API |
| 9090 | Prometheus | Metrics collection |
| 3000 | Grafana | Monitoring dashboards |
| 51820 | WireGuard | VPN tunnels |

---

## Daily Operations

### Morning Health Check (15 minutes)

**Frequency**: Every business day
**Owner**: Operations team

#### Step 1: Check System Status

```bash
# Check all services are running
systemctl status patronus-sdwan
systemctl status patronus-dashboard
systemctl status prometheus
systemctl status grafana

# Expected output: all services "active (running)"
```

#### Step 2: Review Dashboards

1. Open Grafana: `http://grafana.example.com:3000`
2. Navigate to "Patronus Overview" dashboard
3. Check key metrics:
   - ✅ All sites connected (green)
   - ✅ Path health >80% (no red paths)
   - ✅ Packet loss <1%
   - ✅ Latency <100ms
   - ✅ No active alerts

#### Step 3: Review Logs

```bash
# Check for errors in last 24 hours
journalctl -u patronus-sdwan --since "24 hours ago" | grep -i error

# Check for authentication failures
journalctl -u patronus-dashboard --since "24 hours ago" | grep -i "auth failed"

# Expected: Few or no errors
```

#### Step 4: Database Health

```bash
# Check database size and integrity
sqlite3 /var/lib/patronus/sdwan.db <<EOF
.dbinfo
PRAGMA integrity_check;
SELECT COUNT(*) as sites FROM sites WHERE status='active';
SELECT COUNT(*) as paths FROM paths;
EOF

# Expected: integrity_check = ok, reasonable counts
```

#### Step 5: Certificate Expiry

```bash
# Check WireGuard key rotation status
patronus-cli keys status

# Check TLS certificate expiry
openssl x509 -in /etc/patronus/tls/cert.pem -noout -dates

# Alert if expiring in <30 days
```

#### Step 6: Disk Space

```bash
# Check available disk space
df -h /var/lib/patronus
df -h /var/log

# Alert if >80% used
```

**Decision Point**: If all checks pass, proceed with normal operations. If any check fails, see [Troubleshooting](#troubleshooting).

---

### Weekly Review (30 minutes)

**Frequency**: Every Monday
**Owner**: Team lead

1. **Performance Trends**
   - Review 7-day latency trends
   - Check for degrading paths
   - Review packet loss patterns

2. **Capacity Planning**
   - Database growth rate
   - Memory usage trends
   - CPU utilization

3. **Security Review**
   - Failed authentication attempts
   - Unusual API activity
   - Audit log review

4. **Backup Verification**
   - Verify backups completed
   - Test random backup restoration
   - Check backup retention policy

---

## Common Tasks

### Adding a New Site

**Duration**: 10-15 minutes
**Prerequisites**: Site network configured, firewall rules in place

#### Procedure

1. **Generate WireGuard Keys**

```bash
# On the new site
wg genkey | tee privatekey | wg pubkey > publickey

# Save private key securely
PRIVATE_KEY=$(cat privatekey)
PUBLIC_KEY=$(cat publickey)
```

2. **Add Site via API**

```bash
curl -X POST http://localhost:8081/v1/sites \
  -H "Authorization: Bearer $AUTH_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "branch-office-seattle",
    "location": "Seattle, WA",
    "public_key": "'$PUBLIC_KEY'",
    "endpoints": ["203.0.113.50:51820"]
  }'

# Save the returned site_id
SITE_ID="<returned-id>"
```

3. **Configure Site**

```bash
# On the new site, create WireGuard config
cat > /etc/wireguard/wg0.conf <<EOF
[Interface]
PrivateKey = $PRIVATE_KEY
Address = 10.0.100.5/24
ListenPort = 51820

[Peer]
# Hub site
PublicKey = <hub-public-key>
Endpoint = hub.example.com:51820
AllowedIPs = 10.0.0.0/8
PersistentKeepalive = 25
EOF

# Start WireGuard
wg-quick up wg0
systemctl enable wg-quick@wg0
```

4. **Verify Connectivity**

```bash
# Test ping through tunnel
ping -c 3 10.0.0.1

# Check site status
patronus-cli sites show $SITE_ID

# Expected: status=active, last_seen <1 minute ago
```

5. **Add to Monitoring**

```bash
# Dashboard will auto-discover, but verify
curl http://localhost:8081/v1/sites/$SITE_ID/health

# Expected: health_score >80
```

**Rollback**: If connectivity fails, remove site:

```bash
curl -X DELETE http://localhost:8081/v1/sites/$SITE_ID \
  -H "Authorization: Bearer $AUTH_TOKEN"
```

---

### Creating a Routing Policy

**Duration**: 5-10 minutes

#### Procedure

1. **Define Policy Requirements**

Example: Route video traffic over high-bandwidth path

```bash
# Identify application
APP="video-conferencing"
DSCP="46"  # EF (Expedited Forwarding)

# Identify preferred path
PRIMARY_PATH="site1-to-site2-fiber"
BACKUP_PATH="site1-to-site2-lte"
```

2. **Create Policy**

```bash
curl -X POST http://localhost:8081/v1/policies \
  -H "Authorization: Bearer $AUTH_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "video-priority-path",
    "priority": 100,
    "match_criteria": {
      "dscp": 46,
      "protocol": "udp",
      "dest_port_range": "3478-3497"
    },
    "action": {
      "type": "route",
      "primary_path_id": "'$PRIMARY_PATH'",
      "backup_path_id": "'$BACKUP_PATH'",
      "failover_threshold": 70
    }
  }'
```

3. **Verify Policy**

```bash
# Check policy is active
patronus-cli policies list

# Test policy with sample traffic
patronus-cli test-traffic \
  --src 10.0.1.100 \
  --dst 10.0.2.100 \
  --protocol udp \
  --dport 3478

# Expected: Shows selected path matches policy
```

4. **Monitor Policy Performance**

```bash
# Check policy statistics
patronus-cli policies stats video-priority-path

# Review in Grafana: "Policy Performance" dashboard
```

---

### Rotating WireGuard Keys

**Duration**: 30-45 minutes (all sites)
**Frequency**: Every 90 days
**Risk**: Low (graceful rotation)

#### Procedure

1. **Schedule Maintenance Window** (optional, no downtime needed)

2. **Rotate Keys Site-by-Site**

```bash
# For each site
for SITE_ID in $(patronus-cli sites list --format ids); do
  echo "Rotating keys for site $SITE_ID"

  # Generate new keypair
  wg genkey | tee site-$SITE_ID-privatekey | wg pubkey > site-$SITE_ID-publickey
  NEW_PUBLIC_KEY=$(cat site-$SITE_ID-publickey)

  # Update site in database (adds new key, keeps old)
  curl -X PUT http://localhost:8081/v1/sites/$SITE_ID/keys \
    -H "Authorization: Bearer $AUTH_TOKEN" \
    -d "{\"public_key\": \"$NEW_PUBLIC_KEY\"}"

  # Deploy new private key to site (out of band - SSH, config management)
  # ... deployment steps ...

  # After site updates its config, remove old key
  curl -X DELETE http://localhost:8081/v1/sites/$SITE_ID/keys/old \
    -H "Authorization: Bearer $AUTH_TOKEN"

  echo "Site $SITE_ID rotated successfully"
  sleep 60  # Wait between sites
done
```

3. **Verify All Sites**

```bash
# Check all sites still connected
patronus-cli sites list --filter status=active

# Check for key rotation alerts
patronus-cli alerts list --filter type=key_rotation
```

**Troubleshooting**: If a site loses connectivity during rotation:
- Old key is still valid for 24 hours
- Revert to old private key on site
- Investigate and retry

---

### Database Maintenance

**Duration**: 10-20 minutes
**Frequency**: Weekly
**Risk**: Low (read-only operations)

#### Procedure

1. **Vacuum Database**

```bash
# Stop services (optional, but recommended)
systemctl stop patronus-sdwan

# Vacuum to reclaim space and optimize
sqlite3 /var/lib/patronus/sdwan.db "VACUUM;"

# Restart services
systemctl start patronus-sdwan

# Check database size
du -h /var/lib/patronus/sdwan.db
```

2. **Analyze and Optimize**

```bash
sqlite3 /var/lib/patronus/sdwan.db <<EOF
ANALYZE;
.schema
.stats on
SELECT * FROM sqlite_stat1 LIMIT 10;
EOF
```

3. **Cleanup Old Data**

```bash
# Remove health records older than 90 days
sqlite3 /var/lib/patronus/sdwan.db <<EOF
DELETE FROM sdwan_path_health
WHERE timestamp < strftime('%s', 'now', '-90 days');
EOF

# Remove old audit logs (keep 1 year)
sqlite3 /var/lib/patronus/sdwan.db <<EOF
DELETE FROM audit_logs
WHERE timestamp < strftime('%s', 'now', '-365 days');
EOF
```

4. **Verify Integrity**

```bash
sqlite3 /var/lib/patronus/sdwan.db "PRAGMA integrity_check;"

# Expected: ok
```

---

### Updating TLS Certificates

**Duration**: 15-20 minutes
**Frequency**: Before expiry (90 days for Let's Encrypt)
**Risk**: Medium (brief service interruption)

#### Procedure

1. **Backup Current Certificates**

```bash
cp /etc/patronus/tls/cert.pem /etc/patronus/tls/cert.pem.backup
cp /etc/patronus/tls/key.pem /etc/patronus/tls/key.pem.backup
```

2. **Obtain New Certificate**

```bash
# Using Let's Encrypt (certbot)
certbot certonly --standalone \
  -d patronus.example.com \
  --pre-hook "systemctl stop patronus-dashboard" \
  --post-hook "systemctl start patronus-dashboard"

# Or using existing CSR
openssl req -new -key /etc/patronus/tls/key.pem -out request.csr
# ... submit CSR to CA, receive certificate ...
```

3. **Install New Certificate**

```bash
# Copy new certificate
cp /etc/letsencrypt/live/patronus.example.com/fullchain.pem \
   /etc/patronus/tls/cert.pem
cp /etc/letsencrypt/live/patronus.example.com/privkey.pem \
   /etc/patronus/tls/key.pem

# Set permissions
chmod 600 /etc/patronus/tls/key.pem
chmod 644 /etc/patronus/tls/cert.pem
chown patronus:patronus /etc/patronus/tls/*
```

4. **Reload Services**

```bash
# Reload without full restart
systemctl reload patronus-dashboard

# Or restart if reload not supported
systemctl restart patronus-dashboard
```

5. **Verify New Certificate**

```bash
# Check certificate details
openssl x509 -in /etc/patronus/tls/cert.pem -noout -dates -subject

# Test HTTPS connection
curl -v https://patronus.example.com:8080 2>&1 | grep "server certificate"

# Check in browser (no warnings)
```

**Rollback**: If new certificate fails:

```bash
mv /etc/patronus/tls/cert.pem.backup /etc/patronus/tls/cert.pem
mv /etc/patronus/tls/key.pem.backup /etc/patronus/tls/key.pem
systemctl restart patronus-dashboard
```

---

## Troubleshooting

### Path Down / Connectivity Issues

**Symptoms**: Path showing as "down" in dashboard, sites cannot communicate

#### Diagnostic Steps

1. **Verify Path Status**

```bash
# Check path health
patronus-cli paths show $PATH_ID

# Expected info: health_score, last_check, packet_loss, latency
```

2. **Test Network Connectivity**

```bash
# On source site, test connectivity
ping -c 5 <dest-site-ip>

# Test WireGuard tunnel
wg show wg0

# Expected: latest handshake <3 minutes ago
```

3. **Check Firewall Rules**

```bash
# Verify UDP port 51820 is allowed
iptables -L -n -v | grep 51820

# Test with tcpdump
tcpdump -i any udp port 51820

# Expected: See WireGuard packets
```

4. **Review Logs**

```bash
# Check for WireGuard errors
journalctl -u wg-quick@wg0 --since "1 hour ago"

# Check for routing errors
journalctl -u patronus-sdwan --since "1 hour ago" | grep -i path
```

#### Common Causes and Solutions

**Cause**: Firewall blocking traffic
```bash
# Solution: Add firewall rule
iptables -A INPUT -p udp --dport 51820 -j ACCEPT
iptables -A OUTPUT -p udp --dport 51820 -j ACCEPT

# Persist rules
iptables-save > /etc/iptables/rules.v4
```

**Cause**: WireGuard key mismatch
```bash
# Solution: Verify keys match
wg show wg0 | grep "public key"
patronus-cli sites show $SITE_ID | grep public_key

# If mismatch, update site config
```

**Cause**: Network path MTU issues
```bash
# Solution: Reduce MTU
ip link set dev wg0 mtu 1420

# Test with different packet sizes
ping -M do -s 1400 <dest-ip>
```

**Cause**: ISP routing issues
```bash
# Solution: Traceroute to identify black hole
traceroute <dest-ip>

# Use alternative endpoint if available
patronus-cli paths update $PATH_ID --endpoint <alternative-ip>
```

---

### High Latency

**Symptoms**: Path latency >100ms, degraded status

#### Diagnostic Steps

1. **Measure Latency Components**

```bash
# Direct ping (no tunnel)
ping -c 10 <dest-public-ip>

# Through WireGuard tunnel
ping -c 10 <dest-tunnel-ip>

# Compare: tunnel overhead should be <5ms
```

2. **Check Path Health History**

```bash
# View latency trends
patronus-cli paths history $PATH_ID --since "24 hours ago"

# View in Grafana for visual trends
```

3. **Identify Bottleneck**

```bash
# MTR for detailed path analysis
mtr --report --report-cycles 100 <dest-ip>

# Check local CPU and network load
top
sar -n DEV 1 10
```

#### Common Causes and Solutions

**Cause**: Network congestion
```bash
# Solution: Implement QoS
# Set DSCP on WireGuard interface
iptables -t mangle -A POSTROUTING -o eth0 -p udp --dport 51820 \
  -j DSCP --set-dscp-class EF
```

**Cause**: CPU overload (encryption)
```bash
# Solution: Check CPU usage
top -H -p $(pgrep wg)

# If high, consider hardware acceleration or upgrade CPU
```

**Cause**: ISP throttling
```bash
# Solution: Test with different port
# Change WireGuard port to 443 or 80 (common ports)
```

---

### Packet Loss

**Symptoms**: Packet loss >1%, applications experiencing issues

#### Diagnostic Steps

1. **Measure Packet Loss**

```bash
# Extended ping test
ping -c 1000 -i 0.1 <dest-ip> | tail -3

# Note: % packet loss
```

2. **Check Interface Statistics**

```bash
# Look for errors, drops, overruns
ip -s link show wg0
ifconfig wg0

# Expected: minimal errors/drops
```

3. **Test Different Paths**

```bash
# If multiple paths available, test each
for PATH in $(patronus-cli paths list --format ids); do
  echo "Testing path $PATH"
  patronus-cli paths test $PATH
done
```

#### Common Causes and Solutions

**Cause**: Buffer overruns
```bash
# Solution: Increase buffer sizes
sysctl -w net.core.rmem_max=16777216
sysctl -w net.core.wmem_max=16777216

# Persist
echo "net.core.rmem_max=16777216" >> /etc/sysctl.conf
echo "net.core.wmem_max=16777216" >> /etc/sysctl.conf
```

**Cause**: MTU mismatch / fragmentation
```bash
# Solution: Path MTU discovery
ip route get <dest-ip> | grep mtu

# Set appropriate MTU
ip link set wg0 mtu <discovered-mtu>
```

---

### Failover Not Triggering

**Symptoms**: Primary path down, but traffic not failing over to backup

#### Diagnostic Steps

1. **Check Failover Policy**

```bash
# Verify policy configuration
patronus-cli policies show <policy-id>

# Check failover_threshold
# Expected: threshold appropriate (e.g., 70)
```

2. **Check Path Health Scores**

```bash
# View all path health scores
patronus-cli paths list --show-health

# Backup path must have health_score > threshold
```

3. **Review Failover Logs**

```bash
journalctl -u patronus-sdwan --since "1 hour ago" | grep -i failover

# Expected: See failover trigger messages
```

4. **Test Failover Manually**

```bash
# Force failover for testing
patronus-cli failover trigger --policy <policy-id> --path <backup-path-id>

# Verify traffic switches
```

#### Common Causes and Solutions

**Cause**: Backup path also unhealthy
```bash
# Solution: Check why backup path is down
patronus-cli paths show <backup-path-id>

# Fix backup path issues first
```

**Cause**: Failover threshold too low
```bash
# Solution: Adjust threshold
patronus-cli policies update <policy-id> --failover-threshold 80

# Prevents flapping while ensuring failover
```

**Cause**: Health checks not running
```bash
# Solution: Verify health monitor is running
systemctl status patronus-health-monitor

# Check health check interval
grep check_interval /etc/patronus/config.yaml
```

---

### Database Corruption

**Symptoms**: SQL errors, service fails to start, integrity check fails

#### Diagnostic Steps

1. **Check Database Integrity**

```bash
sqlite3 /var/lib/patronus/sdwan.db "PRAGMA integrity_check;"

# If not "ok", database is corrupted
```

2. **Check Disk Space and Errors**

```bash
df -h /var/lib/patronus
dmesg | grep -i error | tail -20

# Look for I/O errors, disk full
```

3. **Assess Corruption Extent**

```bash
# Dump what we can
sqlite3 /var/lib/patronus/sdwan.db .dump > /tmp/dump.sql 2>&1

# Check dump for errors
grep -i error /tmp/dump.sql
```

#### Recovery Procedures

**Option 1: Restore from Backup** (Preferred)

```bash
# Stop service
systemctl stop patronus-sdwan

# Restore from most recent backup
cp /backup/patronus/sdwan.db.$(date +%Y%m%d) \
   /var/lib/patronus/sdwan.db

# Verify integrity
sqlite3 /var/lib/patronus/sdwan.db "PRAGMA integrity_check;"

# Start service
systemctl start patronus-sdwan

# Verify operation
patronus-cli status
```

**Option 2: Partial Recovery**

```bash
# Stop service
systemctl stop patronus-sdwan

# Rename corrupted database
mv /var/lib/patronus/sdwan.db /var/lib/patronus/sdwan.db.corrupted

# Create new database
patronus-sdwan --init-db

# Import what's recoverable from dump
sqlite3 /var/lib/patronus/sdwan.db < /tmp/dump.sql

# Manually recreate critical data (sites, policies)
# ... manual recreation steps ...

# Start service
systemctl start patronus-sdwan
```

**Option 3: Complete Rebuild** (Last Resort)

```bash
# Stop service
systemctl stop patronus-sdwan

# Remove corrupted database
rm /var/lib/patronus/sdwan.db

# Initialize new database
patronus-sdwan --init-db

# Rediscover sites (if auto-discovery enabled)
patronus-cli discover-sites

# Or manually recreate all configuration
# ... manual steps ...

# Start service
systemctl start patronus-sdwan
```

**Prevention**:
- Enable automated backups (see [Disaster Recovery](DISASTER_RECOVERY.md))
- Use database replication for HA setups
- Monitor disk health regularly

---

### Authentication Failures

**Symptoms**: Users cannot log in, API calls return 401

#### Diagnostic Steps

1. **Verify Credentials**

```bash
# Test login with curl
curl -X POST http://localhost:8081/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"correct-password"}'

# Should return access_token
```

2. **Check Audit Logs**

```bash
# Review failed authentication attempts
sqlite3 /var/lib/patronus/sdwan.db <<EOF
SELECT timestamp, username, event_type, details
FROM audit_logs
WHERE event_type='login_failed'
ORDER BY timestamp DESC
LIMIT 20;
EOF
```

3. **Verify JWT Configuration**

```bash
# Check JWT secret is configured
grep jwt_secret /etc/patronus/config.yaml

# Verify not empty or default value
```

#### Common Causes and Solutions

**Cause**: Expired password
```bash
# Solution: Reset password
patronus-cli users password-reset --username <user>

# Or via database (hash with Argon2id)
```

**Cause**: Account locked due to failed attempts
```bash
# Solution: Unlock account
patronus-cli users unlock --username <user>

# Or via database
sqlite3 /var/lib/patronus/sdwan.db <<EOF
UPDATE users SET locked=0, failed_attempts=0 WHERE username='<user>';
EOF
```

**Cause**: JWT secret changed
```bash
# Solution: All users must re-authenticate
# Notify users, no other action needed
```

**Cause**: Clock skew (JWT expiry issues)
```bash
# Solution: Sync system time
ntpdate pool.ntp.org

# Or configure NTP
systemctl enable ntp
systemctl start ntp
```

---

## Incident Response

### Incident Severity Levels

| Level | Impact | Response Time | Examples |
|-------|--------|---------------|----------|
| **P0 - Critical** | Complete outage | 15 minutes | All sites down, database corrupted |
| **P1 - High** | Major functionality impaired | 1 hour | Multiple sites down, dashboard unavailable |
| **P2 - Medium** | Degraded performance | 4 hours | Single site down, high latency |
| **P3 - Low** | Minor issue | 1 business day | Cosmetic bug, minor feature not working |

### P0 - Critical Incident Procedure

1. **Acknowledge** (0-5 minutes)
   - Acknowledge alert in monitoring system
   - Post in incident channel: "P0 incident, investigating"
   - Page on-call engineer if not already paged

2. **Assess** (5-15 minutes)
   - Determine scope: How many sites/users affected?
   - Identify symptoms: What's broken?
   - Check monitoring: What alerts are firing?
   - Review recent changes: Any recent deployments?

3. **Communicate** (15 minutes)
   ```
   Template:
   INCIDENT: P0 - [Brief description]
   IMPACT: [Scope and affected services]
   STATUS: Investigating
   ACTIONS: [What we're doing]
   NEXT UPDATE: [Timeframe]
   ```

4. **Mitigate** (15+ minutes)
   - Apply immediate workarounds
   - Common actions:
     - Rollback recent deployment
     - Restart failed services
     - Failover to backup systems
     - Restore from backup

5. **Resolve** (varies)
   - Implement permanent fix
   - Verify resolution with monitoring
   - Confirm with affected users
   - Post-incident communication

6. **Post-Mortem** (within 48 hours)
   - Document timeline
   - Root cause analysis
   - Action items to prevent recurrence
   - Share learnings with team

### Communication Templates

**Initial Notification**:
```
Subject: [INCIDENT] Patronus SD-WAN - [Brief Description]

Status: INVESTIGATING
Severity: P[0-3]
Start Time: YYYY-MM-DD HH:MM UTC

Impact:
- [Who/what is affected]
- [What functionality is unavailable]

Actions:
- [What we're doing now]

Next Update: [Timeframe]

Incident Commander: [Name]
```

**Update**:
```
Subject: [UPDATE] Patronus SD-WAN - [Brief Description]

Status: [INVESTIGATING/IDENTIFIED/MITIGATED/RESOLVED]
Update #: [N]
Current Time: YYYY-MM-DD HH:MM UTC

Progress:
- [What we've learned]
- [What we've tried]

Impact: [Any change to impact]

Actions:
- [Next steps]

Next Update: [Timeframe]
```

**Resolution**:
```
Subject: [RESOLVED] Patronus SD-WAN - [Brief Description]

Status: RESOLVED
Duration: [Start] to [End] ([Duration])

Root Cause: [Brief explanation]

Resolution:
- [What fixed it]

Impact:
- [Final assessment of impact]

Follow-up:
- Post-mortem scheduled for [date]
- [Any outstanding concerns]

Thank you for your patience.
```

---

## Maintenance

### Upgrading Patronus SD-WAN

**Duration**: 1-2 hours (including rollback buffer)
**Risk**: Medium-High
**Schedule**: Maintenance window recommended

#### Pre-Upgrade Checklist

- [ ] Review release notes for breaking changes
- [ ] Schedule maintenance window
- [ ] Notify stakeholders
- [ ] Backup database and configuration
- [ ] Verify rollback plan
- [ ] Test upgrade in staging environment

#### Upgrade Procedure

1. **Backup Everything**

```bash
# Stop services (prevents changes during backup)
systemctl stop patronus-sdwan patronus-dashboard

# Backup database
cp /var/lib/patronus/sdwan.db \
   /backup/patronus/sdwan.db.$(date +%Y%m%d-%H%M%S)

# Backup configuration
tar czf /backup/patronus/config.$(date +%Y%m%d-%H%M%S).tar.gz \
   /etc/patronus/

# Backup binaries (for rollback)
cp /usr/bin/patronus-sdwan /backup/patronus/patronus-sdwan.old
cp /usr/bin/patronus-dashboard /backup/patronus/patronus-dashboard.old
```

2. **Download New Version**

```bash
# Download release
wget https://github.com/patronus/releases/download/v1.1.0/patronus-v1.1.0.tar.gz

# Verify checksum
sha256sum -c patronus-v1.1.0.tar.gz.sha256

# Extract
tar xzf patronus-v1.1.0.tar.gz
```

3. **Install New Version**

```bash
# Copy new binaries
cp patronus-v1.1.0/patronus-sdwan /usr/bin/
cp patronus-v1.1.0/patronus-dashboard /usr/bin/

# Set permissions
chmod +x /usr/bin/patronus-sdwan /usr/bin/patronus-dashboard
```

4. **Run Database Migrations**

```bash
# Check for required migrations
patronus-sdwan --check-migrations

# Run migrations
patronus-sdwan --migrate

# Verify
patronus-sdwan --migration-status
```

5. **Start Services**

```bash
# Start in order
systemctl start patronus-sdwan
sleep 10

systemctl start patronus-dashboard
sleep 10

# Check status
systemctl status patronus-sdwan patronus-dashboard
```

6. **Verify Upgrade**

```bash
# Check version
patronus-sdwan --version
patronus-dashboard --version

# Test API
curl http://localhost:8081/v1/health

# Test dashboard
curl http://localhost:8080/

# Check logs for errors
journalctl -u patronus-sdwan --since "5 minutes ago" | grep -i error
```

7. **Monitor Closely** (30 minutes)

- Watch Grafana dashboards
- Check all sites connected
- Verify path health
- Test key workflows

#### Rollback Procedure

If upgrade fails or causes issues:

```bash
# Stop new version
systemctl stop patronus-sdwan patronus-dashboard

# Restore old binaries
cp /backup/patronus/patronus-sdwan.old /usr/bin/patronus-sdwan
cp /backup/patronus/patronus-dashboard.old /usr/bin/patronus-dashboard

# Restore database (if migrations ran)
cp /backup/patronus/sdwan.db.<timestamp> /var/lib/patronus/sdwan.db

# Restore configuration (if changed)
rm -rf /etc/patronus/
tar xzf /backup/patronus/config.<timestamp>.tar.gz -C /

# Start old version
systemctl start patronus-sdwan patronus-dashboard

# Verify
patronus-sdwan --version
patronus-cli status
```

---

## Monitoring & Alerts

### Key Metrics to Monitor

#### System Health

| Metric | Warning | Critical | Action |
|--------|---------|----------|--------|
| CPU Usage | >70% | >90% | Investigate load, scale up |
| Memory Usage | >80% | >95% | Check for leaks, scale up |
| Disk Space | >80% | >90% | Clean old data, add storage |
| Service Uptime | Down >1min | Down >5min | Restart, investigate |

#### SD-WAN Health

| Metric | Warning | Critical | Action |
|--------|---------|----------|--------|
| Sites Down | 1 site | >2 sites | Check connectivity |
| Path Health Score | <70 | <50 | Investigate path issues |
| Packet Loss | >1% | >5% | Check network quality |
| Latency | >100ms | >200ms | Investigate delays |
| Failover Time | >500ms | >1s | Check health monitor |

#### Application Health

| Metric | Warning | Critical | Action |
|--------|---------|----------|--------|
| API Error Rate | >1% | >5% | Check logs |
| API Response Time | >500ms | >2s | Check database |
| Auth Failures | >10/min | >50/min | Potential attack |
| Database Connections | >80% pool | >95% pool | Scale connections |

### Alert Configuration

Example Prometheus alert rules (in `alerts.yml`):

```yaml
groups:
  - name: patronus_critical
    interval: 30s
    rules:
      - alert: PatronusServiceDown
        expr: up{job="patronus-sdwan"} == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "Patronus SD-WAN service is down"
          description: "Service {{ $labels.instance }} has been down for more than 1 minute"

      - alert: MultipleSitesDown
        expr: sum(patronus_site_status{status="down"}) > 2
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "Multiple sites are down"
          description: "{{ $value }} sites are currently down"

      - alert: HighPacketLoss
        expr: patronus_path_packet_loss_pct > 5
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "High packet loss on path {{ $labels.path_id }}"
          description: "Packet loss is {{ $value }}%"

      - alert: DatabaseConnectionPoolExhausted
        expr: patronus_db_connections_active / patronus_db_connections_max > 0.95
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "Database connection pool nearly exhausted"
          description: "Using {{ $value | humanizePercentage }} of connection pool"
```

### Dashboard Review Checklist

Daily review (5 minutes):
- [ ] All services green in "System Overview"
- [ ] No critical alerts firing
- [ ] All sites connected
- [ ] Path health >80%
- [ ] No spikes in error rates

Weekly review (15 minutes):
- [ ] Review 7-day trends
- [ ] Check capacity metrics
- [ ] Review alert history
- [ ] Check backup status
- [ ] Review audit logs for anomalies

---

## Emergency Procedures

### Complete System Outage

**Scenario**: All services down, no monitoring

1. **Access System**
   - Console access or SSH to server
   - Verify you can log in

2. **Check System Status**
   ```bash
   # Check if system is up
   uptime

   # Check disk space
   df -h

   # Check for obvious errors
   dmesg | tail -50
   ```

3. **Check Services**
   ```bash
   systemctl status patronus-sdwan
   systemctl status patronus-dashboard
   systemctl status prometheus
   systemctl status grafana
   ```

4. **Review Logs**
   ```bash
   journalctl -xeu patronus-sdwan --since "30 minutes ago"
   journalctl -xeu patronus-dashboard --since "30 minutes ago"
   ```

5. **Restart Services**
   ```bash
   systemctl restart patronus-sdwan
   sleep 10
   systemctl restart patronus-dashboard
   ```

6. **Verify Recovery**
   ```bash
   curl http://localhost:8081/v1/health
   curl http://localhost:8080/
   ```

7. **If Still Down**: Restore from backup (see [Disaster Recovery](DISASTER_RECOVERY.md))

---

### Security Incident Response

**Scenario**: Suspected compromise, unusual activity

1. **Isolate**
   - Disconnect compromised systems from network
   - Block suspicious IP addresses at firewall

2. **Preserve Evidence**
   ```bash
   # Copy logs before they rotate
   cp -r /var/log/patronus /tmp/incident-logs-$(date +%Y%m%d)

   # Dump current connections
   netstat -tulpn > /tmp/connections-$(date +%Y%m%d).txt

   # Process list
   ps auxf > /tmp/processes-$(date +%Y%m%d).txt
   ```

3. **Revoke Access**
   ```bash
   # Disable compromised accounts
   patronus-cli users disable --username <compromised-user>

   # Rotate JWT secret (invalidates all tokens)
   patronus-cli security rotate-jwt-secret

   # Force all users to re-authenticate
   ```

4. **Investigate**
   - Review audit logs for unauthorized actions
   - Check for unauthorized configuration changes
   - Review firewall logs for unusual traffic

5. **Remediate**
   - Apply security patches
   - Change all credentials
   - Restore from known-good backup if needed

6. **Document**
   - Timeline of events
   - Actions taken
   - Evidence collected
   - Lessons learned

---

## Appendix

### Useful Commands Reference

```bash
# Service management
systemctl start|stop|restart|status patronus-sdwan
systemctl enable patronus-sdwan  # Start on boot

# Logs
journalctl -u patronus-sdwan -f  # Follow logs
journalctl -u patronus-sdwan --since "1 hour ago"
journalctl -u patronus-sdwan | grep ERROR

# Database
sqlite3 /var/lib/patronus/sdwan.db  # Interactive
sqlite3 /var/lib/patronus/sdwan.db ".tables"  # List tables
sqlite3 /var/lib/patronus/sdwan.db "SELECT * FROM sites;"

# Network
wg show wg0  # WireGuard status
wg show wg0 dump  # Detailed info
ping -c 5 <ip>  # Connectivity test
traceroute <ip>  # Path trace
mtr <ip>  # Combined ping/traceroute
tcpdump -i wg0  # Packet capture

# Performance
top  # CPU and memory
iotop  # Disk I/O
iftop  # Network bandwidth
ss -tulpn  # Socket statistics

# CLI tool
patronus-cli --help
patronus-cli sites list
patronus-cli paths list
patronus-cli policies list
patronus-cli status
```

### Configuration File Locations

| File | Purpose |
|------|---------|
| `/etc/patronus/config.yaml` | Main configuration |
| `/etc/patronus/tls/` | TLS certificates |
| `/etc/wireguard/wg0.conf` | WireGuard config |
| `/var/lib/patronus/sdwan.db` | Database |
| `/var/log/patronus/` | Log files |
| `/etc/systemd/system/patronus-*.service` | Service definitions |

### External Resources

- [Project Documentation](../README.md)
- [Architecture Overview](ARCHITECTURE.md)
- [API Reference](api/openapi.yaml)
- [Security Guide](SECURITY.md)
- [Disaster Recovery](DISASTER_RECOVERY.md)
- [Performance Tuning](PERFORMANCE_TUNING.md)

---

**Document Version**: 1.0.0
**Last Updated**: 2025-10-11
**Maintainer**: Operations Team
**Review Frequency**: Quarterly
**Next Review**: 2026-01-11
