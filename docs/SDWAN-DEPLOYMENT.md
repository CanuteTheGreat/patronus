# SD-WAN Deployment Guide

**Patronus SD-WAN** - Intelligent Multi-Path Networking

---

## Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Prerequisites](#prerequisites)
4. [Quick Start](#quick-start)
5. [Multi-Site Deployment](#multi-site-deployment)
6. [Configuration](#configuration)
7. [Monitoring](#monitoring)
8. [Troubleshooting](#troubleshooting)
9. [Production Considerations](#production-considerations)

---

## Overview

Patronus SD-WAN provides enterprise-grade software-defined networking with:

- **Automatic Site Discovery**: Zero-config mesh networking via multicast announcements
- **WireGuard VPN Tunnels**: Encrypted peer-to-peer connections
- **Intelligent Path Selection**: Application-aware routing based on latency, jitter, and packet loss
- **Automatic Failover**: Sub-10-second failover on path degradation
- **Real-time Monitoring**: Continuous path quality measurement

### Key Features

| Feature | Description | Benefit |
|---------|-------------|---------|
| **Zero-Touch Peering** | Sites automatically discover and connect | Minimal configuration |
| **Path Monitoring** | UDP probes every 5s measure RTT, jitter, loss | Real-time quality metrics |
| **Quality Scoring** | 0-100 scale (40% latency, 30% jitter, 30% loss) | Objective path comparison |
| **Policy-Based Routing** | VoIP, Gaming, Bulk, Default policies | Application-aware QoS |
| **Bandwidth Testing** | 5-second UDP bulk transfer every 60s | Capacity planning |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         Patronus SD-WAN                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐         │
│  │ MeshManager  │  │ PathMonitor  │  │ RoutingEngine│         │
│  │              │  │              │  │              │         │
│  │ • Discovery  │  │ • Probes     │  │ • Policies   │         │
│  │ • Multicast  │  │ • Metrics    │  │ • Selection  │         │
│  │ • Auth       │  │ • Bandwidth  │  │ • Failover   │         │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘         │
│         │                 │                  │                  │
│         └─────────────────┴──────────────────┘                  │
│                           │                                     │
│                  ┌────────▼────────┐                            │
│                  │ PeeringManager  │                            │
│                  │                 │                            │
│                  │ • WireGuard     │                            │
│                  │ • Interface Mgmt│                            │
│                  │ • Tunnels       │                            │
│                  └────────┬────────┘                            │
│                           │                                     │
│                  ┌────────▼────────┐                            │
│                  │    Database     │                            │
│                  │                 │                            │
│                  │ • Sites         │                            │
│                  │ • Paths         │                            │
│                  │ • Metrics       │                            │
│                  └─────────────────┘                            │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## Prerequisites

### System Requirements

- **OS**: Linux (kernel 5.6+) with WireGuard support
- **CPU**: 1 core minimum, 2+ recommended
- **RAM**: 512MB minimum, 2GB+ recommended
- **Network**: Multiple network interfaces for multi-path

### Required Packages

```bash
# Debian/Ubuntu
sudo apt update
sudo apt install -y wireguard-tools iproute2 iptables

# RHEL/CentOS/Fedora
sudo dnf install -y wireguard-tools iproute iptables

# Arch Linux
sudo pacman -S wireguard-tools iproute2 iptables
```

### Required Capabilities

The SD-WAN daemon requires elevated privileges for:
- Creating WireGuard interfaces (`wg-sdwan`)
- Configuring network interfaces (ip link, ip addr)
- Sending raw UDP packets

**Option 1: Run as root**
```bash
sudo ./patronus-sdwan
```

**Option 2: Grant capabilities (recommended)**
```bash
sudo setcap cap_net_admin,cap_net_raw+ep /path/to/patronus-sdwan
./patronus-sdwan
```

---

## Quick Start

### Single Site Setup (Development)

1. **Build the project**:
```bash
cargo build --release -p patronus-sdwan
```

2. **Initialize database**:
```bash
# Database is auto-created on first run
# Default location: ./patronus-sdwan.db
```

3. **Start the SD-WAN service**:
```bash
# Run with sudo for network interface management
sudo target/release/patronus-sdwan \
  --site-name "headquarters" \
  --listen-port 51820
```

4. **Verify WireGuard interface**:
```bash
ip addr show wg-sdwan
wg show wg-sdwan

# Should see:
# - Interface with IP 10.99.X.X/16
# - Listen port 51820
```

---

## Multi-Site Deployment

### Scenario: 3-Site Mesh (HQ + 2 Branches)

#### Network Topology

```
┌────────────────┐
│ Headquarters   │  ISP-A: 203.0.113.10
│ Site: hq       │  ISP-B: 198.51.100.20
│ 10.99.1.1/16   │
└────┬───────┬───┘
     │       │
     │       └─────────────────────┐
     │                             │
┌────▼────────┐             ┌──────▼──────┐
│ Branch-East │             │ Branch-West │
│ Site: east  │             │ Site: west  │
│ 10.99.2.1/16│             │ 10.99.3.1/16│
└─────────────┘             └─────────────┘
```

#### Site 1: Headquarters

```bash
# HQ has dual WAN (ISP-A primary, ISP-B backup)
sudo patronus-sdwan \
  --site-name "headquarters" \
  --site-id "00000000-0000-0000-0000-000000000001" \
  --listen-port 51820 \
  --interface wg-sdwan \
  --database /var/lib/patronus/hq.db \
  --multicast-group 239.255.42.1:51821
```

**Expected Output**:
```
[INFO] Starting mesh manager (site: headquarters)
[INFO] Initializing WireGuard interface for SD-WAN
[INFO] WireGuard interface initialized (address: 10.99.1.1/16)
[INFO] Starting announcement broadcaster
[INFO] Starting announcement listener
[INFO] Starting auto-peering worker
[INFO] Starting path monitor
[INFO] Starting routing engine
```

#### Site 2: Branch East

```bash
sudo patronus-sdwan \
  --site-name "branch-east" \
  --site-id "00000000-0000-0000-0000-000000000002" \
  --listen-port 51820 \
  --interface wg-sdwan \
  --database /var/lib/patronus/east.db \
  --multicast-group 239.255.42.1:51821
```

#### Site 3: Branch West

```bash
sudo patronus-sdwan \
  --site-name "branch-west" \
  --site-id "00000000-0000-0000-0000-000000000003" \
  --listen-port 51820 \
  --interface wg-sdwan \
  --database /var/lib/patronus/west.db \
  --multicast-group 239.255.42.1:51821
```

### Verification

#### 1. Check Site Discovery (after ~30 seconds)

```bash
# Query database for discovered sites
sqlite3 /var/lib/patronus/hq.db "SELECT * FROM sdwan_sites;"
```

**Expected**:
```
site_id                              | site_name     | status
-------------------------------------|---------------|--------
00000000-0000-0000-0000-000000000002 | branch-east   | active
00000000-0000-0000-0000-000000000003 | branch-west   | active
```

#### 2. Verify WireGuard Tunnels

```bash
wg show wg-sdwan

# Should show peers for branch-east and branch-west
```

#### 3. Check Path Monitoring

```bash
# View path metrics
sqlite3 /var/lib/patronus/hq.db "
SELECT path_id, latency_ms, jitter_ms, packet_loss_pct, score
FROM sdwan_path_metrics
ORDER BY timestamp DESC
LIMIT 10;
"
```

#### 4. Test Connectivity

```bash
# From HQ, ping branch sites
ping -c 4 10.99.2.1  # Branch East
ping -c 4 10.99.3.1  # Branch West

# Check routing table
ip route show table all | grep wg-sdwan
```

---

## Configuration

### Command-Line Options

```bash
patronus-sdwan [OPTIONS]

OPTIONS:
  --site-name <NAME>          Human-readable site name (default: hostname)
  --site-id <UUID>            Unique site identifier (default: auto-generated)
  --listen-port <PORT>        WireGuard listen port (default: 51820)
  --interface <NAME>          WireGuard interface name (default: wg-sdwan)
  --database <PATH>           SQLite database path (default: ./patronus-sdwan.db)
  --multicast-group <ADDR>    Multicast discovery address (default: 239.255.42.1:51821)
  --probe-interval <SECS>     Path probe interval (default: 5)
  --bandwidth-interval <SECS> Bandwidth test interval (default: 60)
  --log-level <LEVEL>         Logging level: error|warn|info|debug|trace (default: info)
```

### Routing Policies

#### Default Policies (Auto-Loaded)

| Priority | Name | Match Rules | Preference | Use Case |
|----------|------|-------------|------------|----------|
| 1 | VoIP/Video | UDP 5060-5061 (SIP) | Latency-sensitive | Real-time communications |
| 2 | Gaming | UDP 27000-28000 | Lowest latency | Online gaming |
| 3 | Bulk Transfers | TCP 20-21 (FTP) | Highest bandwidth | File transfers |
| 100 | Default | All traffic | Balanced | General traffic |

#### Custom Policy Example

```rust
use patronus_sdwan::{RoutingPolicy, PathPreference, MatchRules};

let custom_policy = RoutingPolicy {
    id: 50,
    name: "Database Replication".to_string(),
    priority: 50,
    match_rules: MatchRules {
        dst_port_range: Some((3306, 3306)), // MySQL
        protocol: Some(6), // TCP
        ..Default::default()
    },
    path_preference: PathPreference::Custom(PathScoringWeights {
        latency_weight: 0.2,
        jitter_weight: 0.1,
        loss_weight: 0.5,  // Prioritize reliability
        bandwidth_weight: 0.2,
        cost_weight: 0.0,
    }),
    enabled: true,
};

// Add via API (when implemented)
// router.add_policy(custom_policy).await?;
```

### Environment Variables

```bash
# Logging
export RUST_LOG=patronus_sdwan=debug

# Database location
export PATRONUS_DB=/var/lib/patronus/sdwan.db

# WireGuard interface
export PATRONUS_WG_INTERFACE=wg-sdwan
```

---

## Monitoring

### Path Quality Metrics

```sql
-- Real-time path quality
SELECT
    p.path_id,
    s1.site_name as source,
    s2.site_name as destination,
    m.latency_ms,
    m.jitter_ms,
    m.packet_loss_pct,
    m.bandwidth_mbps,
    m.score,
    p.status
FROM sdwan_paths p
JOIN sdwan_sites s1 ON p.src_site_id = s1.site_id
JOIN sdwan_sites s2 ON p.dst_site_id = s2.site_id
LEFT JOIN (
    SELECT path_id, latency_ms, jitter_ms, packet_loss_pct, bandwidth_mbps, score
    FROM sdwan_path_metrics
    WHERE timestamp = (SELECT MAX(timestamp) FROM sdwan_path_metrics)
) m ON p.path_id = m.path_id;
```

### Active Flows

```sql
-- View routing decisions
SELECT
    src_ip, dst_ip, src_port, dst_port, protocol, path_id
FROM sdwan_active_flows
ORDER BY last_activity DESC
LIMIT 20;
```

### Health Checks

```bash
# Check if SD-WAN is running
systemctl status patronus-sdwan

# View logs
journalctl -u patronus-sdwan -f

# Check WireGuard status
wg show wg-sdwan

# Monitor path probes
tcpdump -i any port 51822 -nn
```

---

## Troubleshooting

### Issue: Sites Not Discovering Each Other

**Symptoms**: No peers in `wg show`, empty `sdwan_sites` table

**Diagnosis**:
```bash
# Check multicast traffic
tcpdump -i any net 239.255.42.1 -nn

# Verify firewall allows multicast
sudo iptables -L -n | grep 239.255.42.1
```

**Solutions**:
1. **Multicast not routed**: Sites must be on same L2 network or have multicast routing
2. **Firewall blocking**: Allow UDP 51821 (multicast)
   ```bash
   sudo iptables -A INPUT -p udp --dport 51821 -j ACCEPT
   sudo iptables -A OUTPUT -p udp --dport 51821 -j ACCEPT
   ```
3. **Wrong multicast group**: Ensure all sites use same `--multicast-group`

### Issue: High Packet Loss

**Symptoms**: `packet_loss_pct > 10%` in metrics

**Diagnosis**:
```bash
# Check path MTU
ping -M do -s 1472 10.99.X.X  # Should succeed
ping -M do -s 1500 10.99.X.X  # May fail (fragmentation needed)

# Check for congestion
iperf3 -c 10.99.X.X -t 60
```

**Solutions**:
1. **MTU mismatch**: Configure WireGuard MTU
   ```bash
   ip link set mtu 1420 dev wg-sdwan
   ```
2. **Network congestion**: Implement traffic shaping
3. **Path degradation**: Check if ISP has issues

### Issue: Failover Not Triggering

**Symptoms**: Traffic still using degraded path

**Diagnosis**:
```sql
-- Check path status
SELECT path_id, status, score FROM sdwan_paths;
```

**Solutions**:
1. **Score threshold**: Path score must drop below 50 for degraded status
2. **Manual failover**: Force re-evaluation
   ```rust
   router.reevaluate_all_flows().await?;
   ```

---

## Production Considerations

### 1. High Availability

#### Active-Passive Setup
```bash
# Primary node
patronus-sdwan --site-name "hq-primary" --priority 100

# Backup node
patronus-sdwan --site-name "hq-backup" --priority 50
```

#### Load Balancing
- Deploy multiple SD-WAN instances per site
- Use ECMP (Equal-Cost Multi-Path) routing
- Distribute flows across instances

### 2. Security

#### WireGuard Key Rotation
```bash
# Generate new keys
wg genkey | tee private.key | wg pubkey > public.key

# Update configuration (requires restart)
wg set wg-sdwan private-key private.key
```

#### Database Encryption
```bash
# Use sqlcipher for encrypted database
cargo add sqlcipher
```

#### Network Segmentation
```bash
# Isolate SD-WAN management traffic
ip route add 239.255.42.0/24 via 192.168.100.1 dev eth1
```

### 3. Performance Tuning

#### Linux Kernel Parameters
```bash
# /etc/sysctl.conf
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
net.ipv4.udp_mem = 102400 873800 16777216
net.ipv4.tcp_rmem = 4096 87380 134217728
net.ipv4.tcp_wmem = 4096 65536 134217728
net.core.netdev_max_backlog = 5000

# Apply
sudo sysctl -p
```

#### WireGuard Optimization
```bash
# Increase MTU (if network supports)
ip link set mtu 1500 dev wg-sdwan

# Disable offloading on WireGuard interface
ethtool -K wg-sdwan tx off rx off
```

### 4. Monitoring & Alerting

#### Prometheus Metrics (Future)
```yaml
# metrics endpoint: http://localhost:9090/metrics
- patronus_sdwan_path_latency_ms
- patronus_sdwan_path_jitter_ms
- patronus_sdwan_path_loss_pct
- patronus_sdwan_path_score
- patronus_sdwan_active_flows
- patronus_sdwan_sites_discovered
```

#### Alerting Rules
```yaml
# Prometheus alert example
- alert: HighPacketLoss
  expr: patronus_sdwan_path_loss_pct > 5
  for: 5m
  annotations:
    summary: "High packet loss on path {{ $labels.path_id }}"
```

### 5. Backup & Disaster Recovery

#### Database Backup
```bash
# Hot backup (while service running)
sqlite3 /var/lib/patronus/sdwan.db ".backup /backup/sdwan-$(date +%Y%m%d).db"

# Scheduled backup (cron)
0 2 * * * sqlite3 /var/lib/patronus/sdwan.db ".backup /backup/sdwan-$(date +\%Y\%m\%d).db"
```

#### Configuration Backup
```bash
# Export routing policies
sqlite3 /var/lib/patronus/sdwan.db "SELECT * FROM sdwan_routing_policies;" > policies.csv

# Restore
sqlite3 /var/lib/patronus/sdwan.db ".import policies.csv sdwan_routing_policies"
```

---

## Systemd Service

### Service File: `/etc/systemd/system/patronus-sdwan.service`

```ini
[Unit]
Description=Patronus SD-WAN Service
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/patronus-sdwan \
  --site-name %H \
  --database /var/lib/patronus/sdwan.db \
  --log-level info
Restart=on-failure
RestartSec=5s
LimitNOFILE=65535

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/patronus

[Install]
WantedBy=multi-user.target
```

### Enable & Start

```bash
sudo systemctl daemon-reload
sudo systemctl enable patronus-sdwan
sudo systemctl start patronus-sdwan
sudo systemctl status patronus-sdwan
```

---

## Next Steps

1. **Scale Testing**: Deploy 5+ sites to test full mesh scalability
2. **Kubernetes Integration**: CNI plugin for Pod networking
3. **Web Dashboard**: Real-time topology visualization
4. **Advanced QoS**: DSCP marking and traffic shaping
5. **Multi-Vendor**: Support for Cisco/Fortinet integration

---

## References

- [WireGuard Documentation](https://www.wireguard.com/)
- [RFC 4821: PMTUD](https://tools.ietf.org/html/rfc4821)
- [SD-WAN Best Practices](https://www.cisco.com/c/en/us/solutions/enterprise-networks/sd-wan/index.html)

---

**Version**: 1.0.0
**Last Updated**: 2025-10-09
**License**: MIT
