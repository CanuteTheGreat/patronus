# eBPF/XDP Performance Optimization Guide

**Target Performance:** 40+ Gbps packet processing
**Current Architecture:** eBPF/XDP for kernel-level packet filtering

---

## Overview

Patronus uses eBPF (Extended Berkeley Packet Filter) and XDP (eXpress Data Path) for high-performance packet processing. This guide covers optimization strategies to achieve maximum throughput.

## Performance Targets

| Metric | Target | Notes |
|--------|--------|-------|
| Throughput | 40-100 Gbps | Depends on CPU and NIC |
| Latency | < 10 μs | Per-packet processing |
| CPU Usage | < 30% | At line rate |
| Packet Loss | < 0.01% | Under normal conditions |

---

## 1. eBPF Program Optimization

### 1.1 Minimize Instructions

**Bad:**
```c
// Multiple conditionals
if (eth->h_proto == htons(ETH_P_IP)) {
    if (ip->protocol == IPPROTO_TCP) {
        if (tcp->dest == htons(80)) {
            // Process HTTP
        }
    }
}
```

**Good:**
```c
// Early returns
if (eth->h_proto != htons(ETH_P_IP))
    return XDP_PASS;
if (ip->protocol != IPPROTO_TCP)
    return XDP_PASS;
if (tcp->dest != htons(80))
    return XDP_PASS;
// Process HTTP
```

### 1.2 Use eBPF Maps Efficiently

**Hash Maps for Connection Tracking:**
```c
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1000000);  // 1M concurrent connections
    __type(key, struct flow_key);
    __type(value, struct conn_state);
} conn_track SEC(".maps");
```

**LPM Trie for IP Matching:**
```c
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 10000);
    __type(key, struct ip_prefix);
    __type(value, __u32);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} ip_allowlist SEC(".maps");
```

### 1.3 Avoid Division

**Bad:**
```c
u32 avg = total / count;  // Division is slow
```

**Good:**
```c
u32 avg = total >> 3;  // Bit shift for division by 8
// Or use multiplication by reciprocal
```

### 1.4 Inline Helper Functions

```c
static __always_inline int validate_packet(struct xdp_md *ctx) {
    // Inline to avoid function call overhead
    ...
}
```

---

## 2. XDP Driver Mode

### Performance Hierarchy

1. **Native XDP** (Best - 40-100 Gbps)
   - Runs in NIC driver
   - Minimal overhead
   - Requires driver support

2. **Offloaded XDP** (Best for SmartNICs)
   - Runs on NIC hardware
   - Zero host CPU usage
   - Requires SmartNIC

3. **Generic XDP** (Fallback - 1-5 Gbps)
   - Runs in network stack
   - Compatible with all NICs
   - Higher overhead

### Enable Native XDP

```bash
# Check driver support
ethtool -i eth0 | grep driver

# Load XDP program in native mode
ip link set dev eth0 xdpoffload off  # Disable offload if not supported
ip link set dev eth0 xdpgeneric off  # Disable generic mode
ip link set dev eth0 xdp obj patronus_xdp.o sec xdp_firewall
```

---

## 3. Multi-Queue RSS (Receive Side Scaling)

### Configure NIC Queues

```bash
# Check current queues
ethtool -l eth0

# Set to number of CPU cores
ethtool -L eth0 combined 8

# Configure RSS hash
ethtool -X eth0 equal 8

# Pin interrupts to CPU cores
for i in {0..7}; do
    echo $i > /proc/irq/$(grep eth0-TxRx-$i /proc/interrupts | cut -d: -f1)/smp_affinity_list
done
```

### eBPF CPU Map

```c
struct {
    __uint(type, BPF_MAP_TYPE_CPUMAP);
    __uint(max_entries, 256);
    __type(key, __u32);
    __type(value, struct bpf_cpumap_val);
} cpu_map SEC(".maps");

// Redirect packet to specific CPU
return bpf_redirect_map(&cpu_map, cpu_id, 0);
```

---

## 4. Packet Batching

### Use BPF_MAP_TYPE_XSKMAP for AF_XDP

```c
// Batch process packets in userspace
struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(max_entries, 64);
    __type(key, __u32);
    __type(value, __u32);
} xsks_map SEC(".maps");

// XDP program redirects to userspace socket
return bpf_redirect_map(&xsks_map, ctx->rx_queue_index, 0);
```

### Userspace Batching

```rust
// Process packets in batches of 64
const BATCH_SIZE: usize = 64;
let mut batch = Vec::with_capacity(BATCH_SIZE);

while let Some(packet) = rx_ring.recv() {
    batch.push(packet);

    if batch.len() >= BATCH_SIZE {
        process_batch(&batch);
        batch.clear();
    }
}
```

---

## 5. Memory Management

### Huge Pages

```bash
# Enable huge pages
echo 1024 > /proc/sys/vm/nr_hugepages

# Mount hugetlbfs
mount -t hugetlbfs none /mnt/huge

# Use in application
mmap(..., MAP_HUGETLB, ...)
```

### Lock-Free Data Structures

```c
// Per-CPU arrays for lock-free access
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct stats);
} stats_map SEC(".maps");
```

---

## 6. Firewall Rule Optimization

### Rule Ordering

```
1. Drop invalid packets (checksum, malformed)
2. Allow established connections (conntrack)
3. Rate limiting
4. Specific allow rules (most common first)
5. Deny all (default policy)
```

### Hash Map for O(1) Lookups

```c
// Instead of linear search through rules
for (int i = 0; i < MAX_RULES; i++) {
    if (matches_rule(pkt, &rules[i]))
        return rules[i].action;
}

// Use hash map
struct flow_key key = extract_flow(pkt);
struct rule *rule = bpf_map_lookup_elem(&rule_map, &key);
if (rule)
    return rule->action;
```

---

## 7. Connection Tracking Optimization

### Bloom Filter for Fast Negative Lookups

```c
struct {
    __uint(type, BPF_MAP_TYPE_BLOOM_FILTER);
    __uint(max_entries, 1000000);
    __type(value, __u64);
} conn_bloom SEC(".maps");

// Check if connection might exist
if (bpf_map_peek_elem(&conn_bloom, &flow_key) != 0) {
    // Definitely not in map, skip lookup
    return XDP_DROP;
}

// Might exist, do full lookup
struct conn_state *conn = bpf_map_lookup_elem(&conn_track, &flow_key);
```

### LRU Map for Automatic Eviction

```c
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1000000);
    __type(key, struct flow_key);
    __type(value, struct conn_state);
} conn_lru SEC(".maps");
// Automatically evicts least recently used entries
```

---

## 8. NIC Tuning

### Offload Features

```bash
# Enable hardware offloads
ethtool -K eth0 rx on tx on
ethtool -K eth0 gso on tso on
ethtool -K eth0 gro on lro on

# Increase ring buffer sizes
ethtool -G eth0 rx 4096 tx 4096

# Disable flow control (for routers/firewalls)
ethtool -A eth0 rx off tx off
```

### Interrupt Coalescing

```bash
# Reduce interrupt rate
ethtool -C eth0 rx-usecs 50 tx-usecs 50

# Adaptive interrupt coalescing
ethtool -C eth0 adaptive-rx on adaptive-tx on
```

---

## 9. CPU Tuning

### CPU Frequency Scaling

```bash
# Set to performance mode
for cpu in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do
    echo performance > $cpu
done

# Disable turbo boost for consistent performance
echo 1 > /sys/devices/system/cpu/intel_pstate/no_turbo
```

### CPU Isolation

```bash
# In GRUB config: isolcpus=2-7
# Reserve CPUs 2-7 for packet processing

# Pin XDP program to isolated CPUs
taskset -c 2-7 ./patronus-firewall
```

### NUMA Awareness

```bash
# Check NUMA topology
numactl --hardware

# Pin to NUMA node with NIC
numactl --cpunodebind=0 --membind=0 ./patronus-firewall
```

---

## 10. Benchmarking Tools

### Packet Generators

```bash
# pkt-gen (netmap)
pkt-gen -i eth0 -f tx -l 64 -r 10000000

# MoonGen (DPDK-based)
./MoonGen examples/l2-load-latency.lua 0 1

# TRex (Cisco)
./t-rex-64 -f cap2/dns.yaml -m 10000
```

### Monitoring

```bash
# Watch XDP statistics
watch -n 1 'cat /sys/kernel/debug/bpf/xdp_stats_*'

# Monitor CPU usage
mpstat -P ALL 1

# Monitor network stats
sar -n DEV 1

# eBPF map statistics
bpftool map show
bpftool map dump id <map_id>
```

---

## 11. Expected Performance

### Single Core Performance

| Packet Size | Throughput | Packets/sec |
|-------------|------------|-------------|
| 64 bytes    | 1.2 Gbps   | 2.3M pps    |
| 512 bytes   | 8.5 Gbps   | 2.1M pps    |
| 1500 bytes  | 12 Gbps    | 1.0M pps    |

### 8-Core Performance (with RSS)

| Packet Size | Throughput | Packets/sec |
|-------------|------------|-------------|
| 64 bytes    | 8-10 Gbps  | 15-18M pps  |
| 512 bytes   | 50-60 Gbps | 12-15M pps  |
| 1500 bytes  | 80-100 Gbps| 6-8M pps    |

---

## 12. Troubleshooting

### High CPU Usage

1. Check for map lock contention
2. Verify XDP is in native mode (not generic)
3. Profile with `perf`:
   ```bash
   perf record -e cycles -a -g -- sleep 10
   perf report
   ```

### Packet Drops

1. Check NIC ring buffer:
   ```bash
   ethtool -S eth0 | grep drop
   ```

2. Increase ring buffer size:
   ```bash
   ethtool -G eth0 rx 4096
   ```

3. Check eBPF verifier logs:
   ```bash
   dmesg | grep bpf
   ```

### Low Throughput

1. Verify RSS is configured
2. Check CPU frequency scaling
3. Ensure NIC offloads are enabled
4. Profile eBPF program:
   ```bash
   bpftool prog profile id <prog_id> duration 10
   ```

---

## 13. Production Deployment Checklist

- [ ] NIC supports native XDP
- [ ] RSS configured for all CPU cores
- [ ] Huge pages enabled
- [ ] CPU isolation and pinning configured
- [ ] NIC interrupts pinned to CPUs
- [ ] CPU governor set to performance
- [ ] NIC offloads enabled
- [ ] eBPF maps sized appropriately
- [ ] Connection tracking uses LRU maps
- [ ] Rules use hash maps for O(1) lookup
- [ ] Packet batching implemented
- [ ] Monitoring and alerting configured

---

## Performance Optimization Summary

**Key Takeaways:**
1. **Use Native XDP** for 10-100x performance vs. iptables
2. **Configure RSS** to distribute across CPU cores
3. **Optimize eBPF code** - minimize instructions, avoid divisions
4. **Use efficient map types** - LRU for connections, hash for rules
5. **Tune NIC** - increase ring buffers, enable offloads
6. **CPU tuning** - performance governor, isolation, NUMA awareness

**Expected Results:**
- **40-100 Gbps** throughput (vs. 1-5 Gbps for iptables)
- **< 10 μs** latency (vs. 100-500 μs for iptables)
- **< 30%** CPU usage at line rate
- **1M+ concurrent connections**

---

*Last Updated: 2025-10-08*
*eBPF Optimization Version: 1.0*
