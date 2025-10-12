# Patronus SD-WAN Performance Tuning Guide

**Version**: 1.0.0
**Last Updated**: 2025-10-11
**Applies To**: Patronus SD-WAN v1.0+

---

## Table of Contents

1. [Overview](#overview)
2. [System Requirements](#system-requirements)
3. [Kernel Tuning](#kernel-tuning)
4. [Network Optimization](#network-optimization)
5. [Application Tuning](#application-tuning)
6. [Database Optimization](#database-optimization)
7. [Monitoring Performance](#monitoring-performance)
8. [Benchmarking](#benchmarking)
9. [Troubleshooting Performance Issues](#troubleshooting-performance-issues)
10. [Scale-Specific Tuning](#scale-specific-tuning)

---

## Overview

### Performance Targets

| Metric | Target | Notes |
|--------|--------|-------|
| Path Selection | <50μs | Critical for low latency |
| Packet Processing | >1 Gbps | Per core with eBPF |
| Control Plane Latency | <100ms | API response time |
| Memory per Site | <1MB | Enables large deployments |
| Health Check Interval | 10s | Configurable |
| Failover Time | <100ms | From detection to switch |
| Dashboard Load Time | <2s | Initial page load |
| Metrics Export | <100ms | For 1000 paths |

### Performance Philosophy

1. **Measure First**: Don't optimize blindly
2. **Profile**: Find actual bottlenecks
3. **Test**: Verify improvements
4. **Document**: Track changes and results
5. **Monitor**: Ensure sustained performance

### Performance Layers

```
┌─────────────────────────────────────┐
│     Application (Rust/Tokio)       │  ← Application tuning
├─────────────────────────────────────┤
│     Network Stack (Linux)           │  ← Kernel tuning
├─────────────────────────────────────┤
│     Hardware (CPU/Memory/Network)   │  ← Right-sizing
└─────────────────────────────────────┘
```

---

## System Requirements

### Minimum Requirements

**Small Deployment** (1-50 sites):
- **CPU**: 2 vCPU (2.0 GHz+)
- **Memory**: 4 GB RAM
- **Network**: 100 Mbps
- **Storage**: 20 GB SSD
- **OS**: Ubuntu 22.04 LTS, Kernel 5.15+

**Expected Performance**:
- Path selection: ~100μs
- Throughput: ~500 Mbps
- Concurrent connections: ~5,000

### Recommended Production

**Medium Deployment** (50-500 sites):
- **CPU**: 4 vCPU (2.5 GHz+)
- **Memory**: 8 GB RAM
- **Network**: 1 Gbps
- **Storage**: 50 GB SSD (NVMe preferred)
- **OS**: Ubuntu 22.04 LTS, Kernel 5.15+

**Expected Performance**:
- Path selection: ~50μs
- Throughput: ~2 Gbps
- Concurrent connections: ~50,000

### Large Scale

**Large Deployment** (500-2000 sites):
- **CPU**: 8 vCPU (3.0 GHz+)
- **Memory**: 16 GB RAM
- **Network**: 10 Gbps
- **Storage**: 100 GB NVMe SSD
- **OS**: Ubuntu 22.04 LTS, Kernel 5.15+

**Expected Performance**:
- Path selection: ~30μs
- Throughput: >5 Gbps
- Concurrent connections: >100,000

### Hardware Recommendations

**CPU**:
- Prefer higher clock speed over more cores (for single-thread performance)
- Intel Xeon or AMD EPYC for server deployments
- AES-NI support for WireGuard encryption
- AVX2 support for cryptographic operations

**Memory**:
- ECC RAM for production (data integrity)
- Minimum 2GB per 500 sites
- Additional memory for metrics and logs

**Network**:
- Multiple NICs for separation of concerns:
  - Management (SSH, monitoring)
  - WireGuard tunnels
  - Dashboard/API
- SR-IOV support for VM deployments
- Hardware offload support (TSO, GSO, GRO)

**Storage**:
- SSD required (NVMe preferred)
- Separate disk for database if possible
- RAID 1 for redundancy (production)
- Consider:
  - Database: NVMe SSD (low latency)
  - Logs: Regular SSD (cost-effective)

---

## Kernel Tuning

### Network Stack Optimization

**File**: `/etc/sysctl.d/99-patronus-network.conf`

```bash
# Network buffer sizes
net.core.rmem_default = 16777216    # 16 MB default receive buffer
net.core.rmem_max = 134217728       # 128 MB max receive buffer
net.core.wmem_default = 16777216    # 16 MB default send buffer
net.core.wmem_max = 134217728       # 128 MB max send buffer

# TCP buffer sizes
net.ipv4.tcp_rmem = 4096 87380 134217728   # min default max (128MB)
net.ipv4.tcp_wmem = 4096 65536 134217728   # min default max (128MB)
net.ipv4.tcp_mem = 134217728 134217728 134217728

# UDP buffer sizes
net.ipv4.udp_rmem_min = 16384
net.ipv4.udp_wmem_min = 16384

# Connection tracking
net.netfilter.nf_conntrack_max = 1048576   # 1M connections
net.netfilter.nf_conntrack_tcp_timeout_established = 86400  # 24 hours
net.netfilter.nf_conntrack_udp_timeout = 300  # 5 minutes
net.netfilter.nf_conntrack_buckets = 262144

# Network device settings
net.core.netdev_max_backlog = 50000    # Queue size for network device
net.core.netdev_budget = 600           # Packets per NAPI poll
net.core.netdev_budget_usecs = 8000    # Microseconds per NAPI poll

# TCP optimization
net.ipv4.tcp_congestion_control = bbr   # Google BBR congestion control
net.ipv4.tcp_fastopen = 3               # Enable TCP Fast Open
net.ipv4.tcp_slow_start_after_idle = 0  # Disable slow start after idle
net.ipv4.tcp_tw_reuse = 1               # Reuse TIME_WAIT connections
net.ipv4.tcp_fin_timeout = 15           # Reduce FIN timeout
net.ipv4.tcp_keepalive_time = 300       # Send keepalive every 5 min
net.ipv4.tcp_keepalive_intvl = 30       # Interval between keepalives
net.ipv4.tcp_keepalive_probes = 3       # Number of probes before timeout

# TCP window scaling
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_timestamps = 1
net.ipv4.tcp_sack = 1

# Queue discipline
net.core.default_qdisc = fq             # Fair Queue for BBR

# IPv4 routing
net.ipv4.ip_forward = 1                 # Required for SD-WAN
net.ipv4.conf.all.forwarding = 1
net.ipv4.conf.default.forwarding = 1

# Reduce latency
net.ipv4.tcp_low_latency = 1
net.ipv4.tcp_no_metrics_save = 1

# Security (DoS protection)
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 8192
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1

# Local port range (more ephemeral ports)
net.ipv4.ip_local_port_range = 10000 65535

# File descriptor limits
fs.file-max = 2097152

# ARP cache
net.ipv4.neigh.default.gc_thresh1 = 1024
net.ipv4.neigh.default.gc_thresh2 = 4096
net.ipv4.neigh.default.gc_thresh3 = 8192

# Virtual memory
vm.swappiness = 10                      # Reduce swap usage
vm.dirty_ratio = 15                     # Start writing at 15%
vm.dirty_background_ratio = 5           # Background write at 5%
```

**Apply settings**:

```bash
# Load new settings
sudo sysctl -p /etc/sysctl.d/99-patronus-network.conf

# Verify
sysctl net.core.rmem_max
sysctl net.ipv4.tcp_congestion_control
```

### eBPF Optimization

**Increase eBPF map sizes** (if using eBPF data plane):

```bash
# /etc/sysctl.d/99-patronus-ebpf.conf

# eBPF limits
kernel.bpf_stats_enabled = 1            # Enable BPF statistics
net.core.bpf_jit_enable = 1             # Enable JIT compiler
net.core.bpf_jit_harden = 0             # Disable hardening for performance
net.core.bpf_jit_kallsyms = 1           # Export JIT symbols
net.core.bpf_jit_limit = 268435456      # 256 MB JIT limit
```

### Process Limits

**File**: `/etc/security/limits.d/99-patronus.conf`

```bash
# File descriptor limits for patronus user
patronus soft nofile 1048576
patronus hard nofile 1048576

# Process limits
patronus soft nproc 65536
patronus hard nproc 65536

# Memory lock (for eBPF)
patronus soft memlock unlimited
patronus hard memlock unlimited
```

**Verify**:

```bash
# Switch to patronus user
sudo su - patronus

# Check limits
ulimit -n    # File descriptors
ulimit -u    # Processes
ulimit -l    # Memory lock
```

---

## Network Optimization

### Network Interface Tuning

**Increase ring buffer sizes**:

```bash
# Check current ring buffer sizes
ethtool -g eth0

# Increase to maximum
sudo ethtool -G eth0 rx 4096 tx 4096

# Make persistent (create script in /etc/network/if-up.d/)
cat <<'EOF' | sudo tee /etc/network/if-up.d/patronus-tuning
#!/bin/bash
[ "$IFACE" = "eth0" ] || exit 0
ethtool -G eth0 rx 4096 tx 4096
EOF

sudo chmod +x /etc/network/if-up.d/patronus-tuning
```

**Enable hardware offloads**:

```bash
# Check current offload settings
ethtool -k eth0

# Enable offloads (if supported)
sudo ethtool -K eth0 tso on        # TCP Segmentation Offload
sudo ethtool -K eth0 gso on        # Generic Segmentation Offload
sudo ethtool -K eth0 gro on        # Generic Receive Offload
sudo ethtool -K eth0 lro on        # Large Receive Offload
sudo ethtool -K eth0 sg on         # Scatter-Gather
sudo ethtool -K eth0 tx-checksumming on
sudo ethtool -K eth0 rx-checksumming on

# Make persistent
cat <<'EOF' | sudo tee /etc/network/if-up.d/patronus-offloads
#!/bin/bash
[ "$IFACE" = "eth0" ] || exit 0
ethtool -K eth0 tso on gso on gro on lro on sg on
ethtool -K eth0 tx-checksumming on rx-checksumming on
EOF

sudo chmod +x /etc/network/if-up.d/patronus-offloads
```

**Configure interrupt coalescing** (reduce interrupt rate):

```bash
# Check current settings
ethtool -c eth0

# Reduce interrupts (adaptive)
sudo ethtool -C eth0 adaptive-rx on adaptive-tx on

# Or set specific values
sudo ethtool -C eth0 rx-usecs 50 tx-usecs 50
```

**Multi-queue NIC optimization** (if available):

```bash
# Check number of queues
ethtool -l eth0

# Set to number of CPUs
NCPUS=$(nproc)
sudo ethtool -L eth0 combined $NCPUS

# Enable Receive Packet Steering (RPS)
for i in /sys/class/net/eth0/queues/rx-*/rps_cpus; do
    echo fff > $i  # Use all CPUs
done

# Enable Receive Flow Steering (RFS)
echo 32768 > /proc/sys/net/core/rps_sock_flow_entries
for i in /sys/class/net/eth0/queues/rx-*/rps_flow_cnt; do
    echo 2048 > $i
done
```

### MTU Optimization

**Find optimal MTU**:

```bash
# Test MTU sizes (from site to site)
for MTU in 1500 1450 1400 1350 1300; do
    echo "Testing MTU $MTU"
    ping -M do -s $((MTU - 28)) -c 5 remote-site-ip && break
done

echo "Optimal MTU: $MTU"
```

**Set MTU for WireGuard**:

```bash
# In /etc/wireguard/wg0.conf
[Interface]
MTU = 1420  # Typically 80 bytes less than interface MTU

# Verify
ip link show wg0
```

### Quality of Service (QoS)

**Traffic shaping with tc** (traffic control):

```bash
#!/bin/bash
# QoS script for Patronus traffic

IFACE="eth0"
BANDWIDTH="1gbit"  # Total bandwidth

# Clear existing rules
tc qdisc del dev $IFACE root 2>/dev/null || true

# Root qdisc (HTB - Hierarchical Token Bucket)
tc qdisc add dev $IFACE root handle 1: htb default 30

# Root class (total bandwidth)
tc class add dev $IFACE parent 1: classid 1:1 htb rate $BANDWIDTH

# High priority class (WireGuard control, health checks)
tc class add dev $IFACE parent 1:1 classid 1:10 htb rate 100mbit ceil $BANDWIDTH prio 1

# Medium priority class (WireGuard data)
tc class add dev $IFACE parent 1:1 classid 1:20 htb rate 800mbit ceil $BANDWIDTH prio 2

# Low priority class (Dashboard, API)
tc class add dev $IFACE parent 1:1 classid 1:30 htb rate 100mbit ceil $BANDWIDTH prio 3

# Fair queuing within each class
tc qdisc add dev $IFACE parent 1:10 handle 10: sfq perturb 10
tc qdisc add dev $IFACE parent 1:20 handle 20: sfq perturb 10
tc qdisc add dev $IFACE parent 1:30 handle 30: sfq perturb 10

# Filters (match traffic to classes)

# High priority: ICMP (health checks)
tc filter add dev $IFACE parent 1:0 protocol ip prio 1 u32 \
    match ip protocol 1 0xff \
    flowid 1:10

# Medium priority: WireGuard (UDP port 51820)
tc filter add dev $IFACE parent 1:0 protocol ip prio 2 u32 \
    match ip protocol 17 0xff \
    match ip dport 51820 0xffff \
    flowid 1:20

# Low priority: Dashboard/API (TCP 8080, 8081)
tc filter add dev $IFACE parent 1:0 protocol ip prio 3 u32 \
    match ip protocol 6 0xff \
    match ip dport 8080 0xffff \
    flowid 1:30

tc filter add dev $IFACE parent 1:0 protocol ip prio 3 u32 \
    match ip protocol 6 0xff \
    match ip dport 8081 0xffff \
    flowid 1:30

echo "QoS configured on $IFACE"

# View configuration
tc -s qdisc show dev $IFACE
tc -s class show dev $IFACE
```

**DSCP marking** (for upstream QoS):

```bash
# Mark WireGuard traffic with EF (Expedited Forwarding)
sudo iptables -t mangle -A POSTROUTING -p udp --dport 51820 \
    -j DSCP --set-dscp-class EF

# Mark health check ICMP with EF
sudo iptables -t mangle -A POSTROUTING -p icmp \
    -j DSCP --set-dscp-class EF

# Save iptables rules
sudo iptables-save > /etc/iptables/rules.v4
```

---

## Application Tuning

### Tokio Runtime Configuration

**Environment variables** (in systemd service file):

```ini
# /etc/systemd/system/patronus-sdwan.service

[Service]
# Tokio worker threads (typically = number of CPU cores)
Environment="TOKIO_WORKER_THREADS=8"

# Thread stack size (reduce if memory constrained)
Environment="RUST_MIN_STACK=2097152"  # 2 MB

# Backtrace (disable in production for performance)
Environment="RUST_BACKTRACE=0"

# Logging (use info or warn in production)
Environment="RUST_LOG=patronus_sdwan=info,patronus_dashboard=info"

# Allocator (jemalloc for better performance)
Environment="LD_PRELOAD=/usr/lib/x86_64-linux-gnu/libjemalloc.so.2"
```

**Reload systemd**:

```bash
sudo systemctl daemon-reload
sudo systemctl restart patronus-sdwan
```

### Configuration File Tuning

**File**: `/etc/patronus/config.yaml`

```yaml
# Performance-oriented configuration

# Health monitoring
health:
  check_interval_secs: 10        # Balance between responsiveness and load
  probes_per_check: 5            # More probes = more accurate but slower
  probe_timeout_ms: 1000         # 1 second timeout
  persist_to_db: true
  db_persist_interval: 6         # Persist every 6 checks (1 minute)

# Database
database:
  path: /var/lib/patronus/sdwan.db
  connection_pool_size: 32       # Increase for high concurrency
  max_connections: 64
  statement_cache_size: 100      # Cache prepared statements
  busy_timeout_ms: 5000          # SQLite busy timeout
  journal_mode: WAL              # Write-Ahead Logging for concurrency
  synchronous: NORMAL            # Balance between durability and speed
  cache_size: -65536             # 64 MB cache (negative = KB)
  mmap_size: 268435456           # 256 MB memory-mapped I/O
  page_size: 4096                # Match filesystem page size

# API server
api:
  bind: 0.0.0.0:8081
  workers: 8                     # Number of worker threads
  max_connections: 10000         # Concurrent connections
  keep_alive: 75                 # TCP keep-alive (seconds)
  request_timeout: 30            # Request timeout (seconds)
  max_request_size: 1048576      # 1 MB max request size

# Dashboard
dashboard:
  bind: 0.0.0.0:8080
  workers: 4                     # Fewer workers (less critical)
  max_connections: 5000
  static_cache_ttl: 3600         # Cache static assets for 1 hour

# Metrics
metrics:
  enabled: true
  export_interval_secs: 10       # Export every 10 seconds
  retention_seconds: 7776000     # 90 days
  aggregation_enabled: true
  aggregation_interval_secs: 300 # Aggregate every 5 minutes

# Logging
logging:
  level: info                    # Use warn in production if I/O bound
  format: json                   # JSON for structured logging
  rotation: daily                # Rotate logs daily
  retention_days: 30             # Keep 30 days
  max_size_mb: 100               # Max size per log file

# Failover
failover:
  detection_threshold: 3         # Failures before marking down
  detection_interval_secs: 5     # Check every 5 seconds
  cooldown_period_secs: 60       # Wait 60s before failing back
  parallel_checks: true          # Check paths in parallel

# WireGuard
wireguard:
  persistent_keepalive: 25       # Keep NAT mappings alive
  allowed_ips_batch_size: 100    # Batch allowed IPs updates
```

**Reload configuration**:

```bash
sudo systemctl reload patronus-sdwan
```

### Memory Allocator

**Use jemalloc** (better performance than glibc malloc):

```bash
# Install jemalloc
sudo apt install -y libjemalloc2

# Configure in systemd service
Environment="LD_PRELOAD=/usr/lib/x86_64-linux-gnu/libjemalloc.so.2"

# Reload and restart
sudo systemctl daemon-reload
sudo systemctl restart patronus-sdwan

# Verify
sudo systemctl status patronus-sdwan | grep jemalloc
```

**Jemalloc tuning** (environment variables):

```ini
# /etc/systemd/system/patronus-sdwan.service

[Service]
# jemalloc tuning
Environment="MALLOC_CONF=background_thread:true,metadata_thp:auto,dirty_decay_ms:30000,muzzy_decay_ms:30000"
```

### CPU Affinity (NUMA systems)

**Pin to specific NUMA node**:

```bash
# Check NUMA topology
numactl --hardware

# Pin to NUMA node 0
sudo systemctl edit patronus-sdwan

# Add:
[Service]
ExecStart=
ExecStart=/usr/bin/numactl --cpunodebind=0 --membind=0 /usr/bin/patronus-sdwan --config /etc/patronus/config.yaml
```

---

## Database Optimization

### SQLite Tuning

**Optimal settings** (already in config.yaml above):

```sql
-- These are set via config, but can also be run manually

PRAGMA journal_mode = WAL;           -- Write-Ahead Logging
PRAGMA synchronous = NORMAL;         -- Faster commits
PRAGMA cache_size = -65536;          -- 64 MB cache
PRAGMA page_size = 4096;             -- 4 KB pages
PRAGMA mmap_size = 268435456;        -- 256 MB mmap
PRAGMA temp_store = MEMORY;          -- Temp tables in memory
PRAGMA locking_mode = NORMAL;        -- Allow multiple readers
PRAGMA auto_vacuum = INCREMENTAL;    -- Incremental vacuuming
```

**Apply settings**:

```bash
sqlite3 /var/lib/patronus/sdwan.db <<EOF
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA cache_size = -65536;
PRAGMA mmap_size = 268435456;
PRAGMA temp_store = MEMORY;
EOF
```

**Verify settings**:

```bash
sqlite3 /var/lib/patronus/sdwan.db <<EOF
PRAGMA journal_mode;
PRAGMA synchronous;
PRAGMA cache_size;
PRAGMA page_size;
PRAGMA mmap_size;
EOF
```

### Database Maintenance

**Regular maintenance** (cron job):

```bash
# /etc/cron.weekly/patronus-db-maintenance

#!/bin/bash
# Weekly database maintenance

DB_PATH="/var/lib/patronus/sdwan.db"

echo "Starting database maintenance: $(date)"

# Stop write-heavy services temporarily
systemctl stop patronus-sdwan

# Analyze (update query planner statistics)
sqlite3 "$DB_PATH" "ANALYZE;"

# Incremental vacuum (reclaim space)
sqlite3 "$DB_PATH" "PRAGMA incremental_vacuum;"

# Optimize
sqlite3 "$DB_PATH" "PRAGMA optimize;"

# Integrity check
sqlite3 "$DB_PATH" "PRAGMA integrity_check;" | grep -v "ok" && {
    echo "ERROR: Database integrity check failed!"
    exit 1
}

# Restart services
systemctl start patronus-sdwan

echo "Database maintenance complete: $(date)"
```

### Indexing

**Ensure indexes exist** (should be created by migrations):

```sql
-- Critical indexes for performance

-- Sites
CREATE INDEX IF NOT EXISTS idx_sites_status ON sites(status);
CREATE INDEX IF NOT EXISTS idx_sites_last_seen ON sites(last_seen);

-- Paths
CREATE INDEX IF NOT EXISTS idx_paths_src_dest ON paths(source_site_id, dest_site_id);
CREATE INDEX IF NOT EXISTS idx_paths_status ON paths(status);

-- Path health (for time-series queries)
CREATE INDEX IF NOT EXISTS idx_path_health_path_time
    ON sdwan_path_health(path_id, timestamp);
CREATE INDEX IF NOT EXISTS idx_path_health_time
    ON sdwan_path_health(timestamp);

-- Policies
CREATE INDEX IF NOT EXISTS idx_policies_priority ON policies(priority);

-- Audit logs (for security queries)
CREATE INDEX IF NOT EXISTS idx_audit_logs_user_time
    ON audit_logs(username, timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_logs_event_time
    ON audit_logs(event_type, timestamp);

-- Traffic statistics
CREATE INDEX IF NOT EXISTS idx_traffic_stats_policy_time
    ON traffic_stats(policy_id, timestamp);
```

**Check index usage**:

```bash
sqlite3 /var/lib/patronus/sdwan.db <<EOF
.eqp on
EXPLAIN QUERY PLAN SELECT * FROM paths WHERE source_site_id = '123';
EXPLAIN QUERY PLAN SELECT * FROM sdwan_path_health WHERE path_id = '456' AND timestamp > 1000;
EOF
```

---

## Monitoring Performance

### Key Metrics to Watch

**System Metrics**:

```bash
# CPU usage
top -b -n 1 | grep patronus

# Memory usage
ps aux | grep patronus | awk '{sum+=$6} END {print sum/1024 " MB"}'

# I/O wait
iostat -x 1 10

# Network throughput
sar -n DEV 1 10

# Context switches (high = contention)
vmstat 1 10
```

**Application Metrics** (Prometheus):

```promql
# Path selection latency (p99)
histogram_quantile(0.99,
  rate(patronus_path_selection_duration_seconds_bucket[5m]))

# Health check latency
histogram_quantile(0.99,
  rate(patronus_health_check_duration_seconds_bucket[5m]))

# Failover time
histogram_quantile(0.99,
  rate(patronus_failover_duration_seconds_bucket[5m]))

# Database query latency
histogram_quantile(0.99,
  rate(patronus_db_query_duration_seconds_bucket[5m]))

# Memory usage
patronus_memory_usage_bytes

# Request rate
rate(patronus_http_requests_total[5m])

# Error rate
rate(patronus_http_requests_total{status=~"5.."}[5m])
```

### Performance Dashboard (Grafana)

**Import dashboard** (JSON):

```json
{
  "dashboard": {
    "title": "Patronus Performance",
    "panels": [
      {
        "title": "Path Selection Latency (p99)",
        "targets": [{
          "expr": "histogram_quantile(0.99, rate(patronus_path_selection_duration_seconds_bucket[5m]))"
        }],
        "alert": {
          "conditions": [{
            "evaluator": { "type": "gt", "params": [0.0005] }
          }]
        }
      },
      {
        "title": "Memory Usage",
        "targets": [{
          "expr": "patronus_memory_usage_bytes"
        }]
      },
      {
        "title": "Database Connections",
        "targets": [{
          "expr": "patronus_db_connections_active / patronus_db_connections_max"
        }]
      }
    ]
  }
}
```

---

## Benchmarking

### Baseline Performance Test

**Script**: `/usr/local/bin/patronus-benchmark.sh`

```bash
#!/bin/bash
# Patronus performance benchmark

set -e

echo "=== Patronus Performance Benchmark ==="
echo "Date: $(date)"
echo "Hostname: $(hostname)"
echo "CPUs: $(nproc)"
echo "Memory: $(free -h | grep Mem | awk '{print $2}')"
echo ""

# 1. Path selection latency
echo "1. Path Selection Latency"
patronus-cli bench path-selection --iterations 10000 --concurrent 100

# 2. Health check latency
echo ""
echo "2. Health Check Latency"
patronus-cli bench health-check --targets 100 --iterations 100

# 3. Failover latency
echo ""
echo "3. Failover Latency"
patronus-cli bench failover --iterations 100

# 4. API throughput
echo ""
echo "4. API Throughput"
echo "Running Apache Bench..."
ab -n 10000 -c 100 -H "Authorization: Bearer $AUTH_TOKEN" \
    http://localhost:8081/v1/sites

# 5. Database performance
echo ""
echo "5. Database Query Performance"
time sqlite3 /var/lib/patronus/sdwan.db <<EOF
SELECT COUNT(*) FROM sites;
SELECT COUNT(*) FROM paths;
SELECT COUNT(*) FROM sdwan_path_health;
EOF

# 6. Memory usage
echo ""
echo "6. Memory Usage"
ps aux | grep patronus | awk '{print $11, $6/1024 " MB"}'

# 7. Network throughput (iperf3 between sites)
echo ""
echo "7. Network Throughput (if iperf3 available)"
if command -v iperf3 &> /dev/null; then
    # Run on server side first: iperf3 -s
    # iperf3 -c remote-site-ip -t 10
    echo "Run: iperf3 -c <remote-site> -t 10"
else
    echo "iperf3 not installed"
fi

echo ""
echo "=== Benchmark Complete ==="
```

### Load Testing

**Script**: `tests/load_test.rs`

```rust
// Simplified load test example

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use patronus_sdwan::*;

fn bench_path_selection_1000_paths(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let engine = rt.block_on(async {
        let engine = PathSelectionEngine::new();
        // Add 1000 paths
        for i in 0..1000 {
            engine.add_path(create_test_path(i)).await;
        }
        engine
    });

    c.bench_function("path_selection_1000", |b| {
        b.iter(|| {
            rt.block_on(async {
                black_box(engine.select_path().await)
            })
        })
    });
}

criterion_group!(benches, bench_path_selection_1000_paths);
criterion_main!(benches);
```

**Run benchmarks**:

```bash
# Cargo bench
cargo bench --all-features

# Results in target/criterion/
ls -la target/criterion/
```

---

## Troubleshooting Performance Issues

### High CPU Usage

**Diagnosis**:

```bash
# Top CPU consuming threads
top -H -p $(pgrep patronus-sdwan)

# Profile with perf
sudo perf record -g -p $(pgrep patronus-sdwan) -- sleep 30
sudo perf report

# Check for busy loops
strace -c -p $(pgrep patronus-sdwan)
```

**Common Causes**:

1. **Excessive health checks**: Reduce `check_interval` or `probes_per_check`
2. **Too many paths**: Optimize path selection algorithm
3. **Database queries**: Add indexes, optimize queries
4. **Logging**: Reduce log level from debug to info/warn

### High Memory Usage

**Diagnosis**:

```bash
# Memory breakdown
pmap -x $(pgrep patronus-sdwan)

# Check for leaks (valgrind)
valgrind --leak-check=full --show-leak-kinds=all patronus-sdwan

# Heap profiling (with jemalloc)
MALLOC_CONF=prof:true,prof_prefix:jeprof.out patronus-sdwan
```

**Common Causes**:

1. **Metrics accumulation**: Reduce retention period
2. **Log accumulation**: Enable log rotation
3. **Database cache**: Reduce `cache_size`
4. **Memory leak**: Profile and fix (file bug report)

### Database Slowness

**Diagnosis**:

```bash
# Enable query logging
sqlite3 /var/lib/patronus/sdwan.db "PRAGMA vdbe_debug=ON;"

# Check locks
lsof | grep sdwan.db

# Check I/O wait
iostat -x 1 10 | grep -A1 sda

# Analyze slow queries
sqlite3 /var/lib/patronus/sdwan.db <<EOF
.timer on
SELECT * FROM sdwan_path_health WHERE timestamp > strftime('%s', 'now', '-1 hour');
EOF
```

**Common Fixes**:

1. **Missing index**: Add index on queried columns
2. **Database locked**: Enable WAL mode
3. **Slow disk**: Move database to NVMe SSD
4. **Large database**: Archive old data, run VACUUM

### Network Latency

**Diagnosis**:

```bash
# Measure latency at each layer
ping <remote-site>          # ICMP
mtr --report <remote-site>  # Path analysis
curl -w "@curl-format.txt" http://remote-site:8081/health

# curl-format.txt:
time_namelookup:  %{time_namelookup}\n
time_connect:  %{time_connect}\n
time_starttransfer:  %{time_starttransfer}\n
time_total:  %{time_total}\n
```

**Common Causes**:

1. **Network congestion**: Enable QoS, increase bandwidth
2. **MTU issues**: Reduce MTU, enable PMTUD
3. **ISP routing**: Use alternative paths
4. **CPU throttling**: Check for thermal throttling

---

## Scale-Specific Tuning

### 1-50 Sites (Small)

**Focus**: Simplicity and reliability

```yaml
# config.yaml
health:
  check_interval_secs: 10
  probes_per_check: 5

database:
  connection_pool_size: 8
  cache_size: -16384  # 16 MB

api:
  workers: 4
  max_connections: 1000
```

**Resources**: 2 vCPU, 4 GB RAM

### 50-500 Sites (Medium)

**Focus**: Balance performance and cost

```yaml
# config.yaml
health:
  check_interval_secs: 10
  probes_per_check: 5
  persist_to_db: true
  db_persist_interval: 6

database:
  connection_pool_size: 32
  cache_size: -65536  # 64 MB
  journal_mode: WAL

api:
  workers: 8
  max_connections: 5000

metrics:
  aggregation_enabled: true
  aggregation_interval_secs: 300
```

**Resources**: 4-8 vCPU, 8-16 GB RAM
**Storage**: NVMe SSD recommended

### 500-2000 Sites (Large)

**Focus**: Maximum performance

```yaml
# config.yaml
health:
  check_interval_secs: 15    # Reduce frequency at scale
  probes_per_check: 3        # Fewer probes
  persist_to_db: true
  db_persist_interval: 12    # Persist less frequently

database:
  connection_pool_size: 64
  cache_size: -131072        # 128 MB
  mmap_size: 536870912       # 512 MB
  journal_mode: WAL

api:
  workers: 16
  max_connections: 20000

metrics:
  aggregation_enabled: true
  aggregation_interval_secs: 600  # Aggregate less frequently
  retention_seconds: 2592000      # 30 days (reduce retention)
```

**Resources**: 8-16 vCPU, 16-32 GB RAM
**Storage**: NVMe SSD required
**Network**: 10 Gbps recommended
**Consider**: Horizontal scaling with HA setup

### 2000+ Sites (Very Large)

**Recommendations**:

1. **Horizontal Scaling**: Multiple instances with load balancing
2. **Database Sharding**: Separate databases by region/tenant
3. **Caching Layer**: Redis for frequently accessed data
4. **CDN**: For dashboard static assets
5. **Dedicated Monitoring**: Separate Prometheus/Grafana servers

---

## Appendix

### Performance Checklist

**Before Deployment**:
- [ ] Kernel tuned (/etc/sysctl.d/)
- [ ] Network interfaces optimized (ring buffers, offloads)
- [ ] Process limits increased
- [ ] Database optimized (WAL mode, indexes)
- [ ] Configuration tuned for scale
- [ ] Monitoring configured
- [ ] Baseline performance test completed

**After Deployment**:
- [ ] Monitor CPU usage (<70%)
- [ ] Monitor memory usage (<80%)
- [ ] Monitor disk I/O (<80%)
- [ ] Monitor network bandwidth (<80%)
- [ ] Review slow query logs
- [ ] Check for errors in logs
- [ ] Validate metrics targets met

### Quick Wins

**Easiest Performance Improvements**:

1. **Enable WAL mode**: `PRAGMA journal_mode=WAL;` (10-20% improvement)
2. **Increase database cache**: `PRAGMA cache_size=-65536;` (5-10% improvement)
3. **Use jemalloc**: `LD_PRELOAD=libjemalloc.so` (5-15% improvement)
4. **Increase network buffers**: `net.core.rmem_max` (reduce packet loss)
5. **Enable hardware offloads**: `ethtool -K` (10-30% improvement)

### Performance Testing Schedule

| Test | Frequency | Duration |
|------|-----------|----------|
| Baseline benchmark | After changes | 30 min |
| Load test | Weekly | 1 hour |
| Stress test | Monthly | 2 hours |
| Soak test | Quarterly | 24 hours |

---

**Document Version**: 1.0.0
**Last Updated**: 2025-10-11
**Next Review**: 2026-01-11
**Maintainer**: Performance Engineering Team
