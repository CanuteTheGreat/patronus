# Patronus SD-WAN CLI Example

This example demonstrates the complete Patronus SD-WAN functionality in a standalone CLI application.

## Features Demonstrated

✅ **Automatic Site Discovery** - Sites discover each other via multicast announcements
✅ **WireGuard Auto-Peering** - Automatic VPN tunnel establishment between sites
✅ **Path Quality Monitoring** - Real-time measurement of latency, jitter, packet loss, and bandwidth
✅ **Intelligent Routing** - Application-aware path selection based on QoS policies
✅ **Automatic Failover** - Sub-second failover when paths degrade
✅ **Multi-Path Support** - Load balancing across multiple network paths

## Prerequisites

### System Requirements

- **Linux** (tested on Ubuntu 22.04+, Debian 12+)
- **Root privileges** (required for WireGuard interface management)
- **Rust 1.85+**
- **WireGuard tools** installed:
  ```bash
  sudo apt install wireguard-tools  # Debian/Ubuntu
  sudo dnf install wireguard-tools  # Fedora/RHEL
  ```

### Network Requirements

- **IP multicast** enabled on your network interfaces
- **UDP port 51820** available for WireGuard (default, configurable)
- **UDP port 51821** available for multicast discovery (default, configurable)
- **Root access** to create network interfaces

## Building the Example

```bash
cd crates/patronus-sdwan
cargo build --example sdwan_cli --features cli --release
```

## Quick Start: Single Site (Testing)

Test the SD-WAN on a single machine:

```bash
sudo -E cargo run --example sdwan_cli --features cli -- \
  --site-name "test-site" \
  --database /tmp/sdwan-test.db \
  --debug
```

This will:
1. Initialize a local database at `/tmp/sdwan-test.db`
2. Create WireGuard interface `wg-sdwan`
3. Start multicast site discovery
4. Begin path monitoring
5. Load default routing policies

Press `Ctrl+C` to stop.

## Multi-Site Deployment

### Scenario: 3-Site Mesh Network

#### Site 1: Headquarters (192.168.1.10)

```bash
# On headquarters server
sudo -E cargo run --example sdwan_cli --features cli -- \
  --site-name "headquarters" \
  --listen-port 51820 \
  --database /var/lib/patronus/hq.db \
  --interface wg-hq
```

#### Site 2: Branch East (192.168.2.10)

```bash
# On branch-east server
sudo -E cargo run --example sdwan_cli --features cli -- \
  --site-name "branch-east" \
  --listen-port 51820 \
  --database /var/lib/patronus/east.db \
  --interface wg-east
```

#### Site 3: Branch West (192.168.3.10)

```bash
# On branch-west server
sudo -E cargo run --example sdwan_cli --features cli -- \
  --site-name "branch-west" \
  --listen-port 51820 \
  --database /var/lib/patronus/west.db \
  --interface wg-west
```

### What Happens Next

1. **Discovery (0-60s)**: Sites send multicast announcements and discover each other
2. **Peering (60-120s)**: WireGuard tunnels are automatically established between all sites
3. **Monitoring (120s+)**: Path quality metrics are continuously measured
4. **Routing (ongoing)**: Traffic is intelligently routed based on application requirements and path quality

## Monitoring Your SD-WAN Network

### View Discovered Sites

```bash
sqlite3 /var/lib/patronus/hq.db "SELECT * FROM sites;"
```

Example output:
```
id                                    | name         | status | last_seen
--------------------------------------|--------------|--------|----------------------
550e8400-e29b-41d4-a716-446655440001 | headquarters | active | 2025-10-09 14:32:15
550e8400-e29b-41d4-a716-446655440002 | branch-east  | active | 2025-10-09 14:32:18
550e8400-e29b-41d4-a716-446655440003 | branch-west  | active | 2025-10-09 14:32:20
```

### View Active Paths

```bash
sqlite3 /var/lib/patronus/hq.db "SELECT src_site, dst_site, status, wg_interface FROM paths;"
```

### View Path Quality Metrics

```bash
sqlite3 /var/lib/patronus/hq.db "
  SELECT
    path_id,
    latency_ms,
    jitter_ms,
    packet_loss_pct,
    bandwidth_mbps,
    score,
    measured_at
  FROM path_metrics
  ORDER BY measured_at DESC
  LIMIT 10;
"
```

Example output:
```
path_id | latency_ms | jitter_ms | packet_loss_pct | bandwidth_mbps | score | measured_at
--------|------------|-----------|-----------------|----------------|-------|----------------------
1       | 12.5       | 2.1       | 0.05            | 987.3          | 98    | 2025-10-09 14:35:42
2       | 45.3       | 8.7       | 0.8             | 234.1          | 72    | 2025-10-09 14:35:40
```

### View Routing Policies

```bash
sqlite3 /var/lib/patronus/hq.db "SELECT * FROM policies ORDER BY priority;"
```

### View WireGuard Status

```bash
sudo wg show wg-hq
```

Example output:
```
interface: wg-hq
  public key: xK8tVz...
  private key: (hidden)
  listening port: 51820

peer: yL9uWa...
  endpoint: 192.168.2.10:51820
  allowed ips: 10.99.15.32/32
  latest handshake: 23 seconds ago
  transfer: 145.2 KiB received, 89.7 KiB sent
  persistent keepalive: every 25 seconds
```

## Network Status Reports

The CLI automatically prints network status reports every 30 seconds:

```
═══════════════════════════════════════════════════════
Network Status Report
═══════════════════════════════════════════════════════
Active sites: 2
  • branch-east (ID: 550e8400-e29b-41d4-a716-446655440002)
    - Endpoint: 192.168.2.10:51820 (ethernet)
  • branch-west (ID: 550e8400-e29b-41d4-a716-446655440003)
    - Endpoint: 192.168.3.10:51820 (ethernet)

Active paths: 4 (Up: 3, Degraded: 1, Down: 0)
  Best path: HQ → East (score: 98, latency: 12.5ms, loss: 0.05%)
  Worst path: HQ → West (score: 68, latency: 78.3ms, loss: 1.2%)
═══════════════════════════════════════════════════════
```

## Testing Path Selection

### Simulate VoIP Traffic

VoIP traffic (UDP port 5060, 5061) is automatically routed via the lowest-latency path:

```bash
# From headquarters
ping -I wg-hq 10.99.15.32  # IP of branch-east WireGuard interface
```

The routing engine will select the path with the best latency/jitter metrics.

### Simulate Bulk Transfer

FTP/rsync traffic (TCP port 20, 21, 873) is routed via highest-bandwidth path:

```bash
# Test with netcat
nc -vz 10.99.15.32 873  # rsync port
```

### Test Failover

1. **Check current best path**:
   ```bash
   sqlite3 hq.db "SELECT * FROM paths WHERE status='up' ORDER BY score DESC LIMIT 1;"
   ```

2. **Simulate path degradation** (on the remote site, block traffic temporarily):
   ```bash
   # On branch-east
   sudo iptables -A INPUT -p udp --dport 51820 -j DROP
   ```

3. **Observe failover** (within 2-3 seconds, traffic should switch to alternate path)

4. **Restore path**:
   ```bash
   sudo iptables -D INPUT -p udp --dport 51820 -j DROP
   ```

## Command-Line Options

```
Options:
  --site-name <name>              Name of this site (required)
  --listen-port <port>            WireGuard listen port (default: 51820)
  --database <path>               Database file path (default: sdwan.db)
  --interface <name>              WireGuard interface name (default: wg-sdwan)
  --multicast-group <addr>        Multicast group for discovery (default: 239.255.77.77:51821)
  --debug                         Enable debug logging
  --help                          Show help message
```

## Troubleshooting

### "Permission denied" errors

**Problem**: The program needs root privileges to manage WireGuard interfaces.

**Solution**: Run with `sudo -E` to preserve environment variables:
```bash
sudo -E cargo run --example sdwan_cli --features cli -- --site-name mysite
```

### Sites not discovering each other

**Problem**: Multicast traffic may be blocked by firewall or network configuration.

**Solutions**:
1. Check firewall allows UDP 51821:
   ```bash
   sudo ufw allow 51821/udp
   ```

2. Verify multicast routing:
   ```bash
   ip route show | grep 239.255
   ```

3. Check interface supports multicast:
   ```bash
   ip link show | grep MULTICAST
   ```

### WireGuard interface creation fails

**Problem**: Interface already exists or permission issue.

**Solutions**:
1. Remove existing interface:
   ```bash
   sudo ip link delete wg-sdwan
   ```

2. Check kernel module loaded:
   ```bash
   lsmod | grep wireguard
   sudo modprobe wireguard
   ```

### No path metrics showing

**Problem**: ICMP or UDP traffic may be blocked.

**Solutions**:
1. Allow ICMP echo (ping):
   ```bash
   sudo ufw allow from 10.99.0.0/16 to any proto icmp
   ```

2. Allow UDP bandwidth test port (51823):
   ```bash
   sudo ufw allow 51823/udp
   ```

### Database locked errors

**Problem**: Multiple processes trying to access same database.

**Solution**: Use separate database files per site:
```bash
--database /var/lib/patronus/site-$HOSTNAME.db
```

## Architecture

```
┌─────────────────────────────────────────────────┐
│              SD-WAN CLI Application             │
├─────────────────────────────────────────────────┤
│                                                 │
│  ┌──────────────┐    ┌─────────────────────┐   │
│  │    Mesh      │───▶│  Path Monitoring    │   │
│  │   Manager    │    │  (ICMP/UDP probes)  │   │
│  │              │    └─────────────────────┘   │
│  │ - Discovery  │              │               │
│  │ - Peering    │              ▼               │
│  └──────────────┘    ┌─────────────────────┐   │
│         │            │  Routing Engine     │   │
│         │            │  (QoS Policies)     │   │
│         │            └─────────────────────┘   │
│         ▼                      │               │
│  ┌──────────────────────────────────────────┐  │
│  │           SQLite Database                │  │
│  │  (Sites, Paths, Metrics, Policies)       │  │
│  └──────────────────────────────────────────┘  │
│                                                 │
└─────────────────────────────────────────────────┘
                       │
                       ▼
         ┌─────────────────────────────┐
         │   WireGuard Kernel Module   │
         │   (Encrypted VPN Tunnels)   │
         └─────────────────────────────┘
```

## Production Deployment

For production use, consider:

1. **Use systemd service** (see `/docs/SDWAN-DEPLOYMENT.md` for systemd unit files)
2. **Persistent database location** (e.g., `/var/lib/patronus/`)
3. **Log rotation** for tracing output
4. **Monitoring integration** (export metrics to Prometheus)
5. **High availability** (run on multiple paths with failover)
6. **Security hardening** (restrict multicast group, use firewall rules)

## Next Steps

- 📖 Read the [SD-WAN Deployment Guide](../docs/SDWAN-DEPLOYMENT.md)
- 🏗️ Integrate with Kubernetes via CNI plugin (coming soon)
- 🎯 Customize routing policies for your applications
- 📊 Export metrics to monitoring systems
- 🔒 Add mTLS for control plane security

## License

MIT - See LICENSE file in repository root.
