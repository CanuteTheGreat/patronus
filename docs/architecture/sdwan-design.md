# Patronus SD-WAN Architecture Design

**Version:** 1.0
**Status:** Design Phase
**Author:** Patronus Project
**Date:** October 9, 2025

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Problem Statement](#problem-statement)
3. [Architecture Overview](#architecture-overview)
4. [Core Components](#core-components)
5. [Mesh Topology](#mesh-topology)
6. [Path Selection Algorithm](#path-selection-algorithm)
7. [Data Structures](#data-structures)
8. [API Design](#api-design)
9. [Implementation Phases](#implementation-phases)
10. [Security Considerations](#security-considerations)
11. [Performance Targets](#performance-targets)
12. [Testing Strategy](#testing-strategy)

---

## Executive Summary

**Goal:** Transform Patronus from a single-node firewall into a distributed SD-WAN platform capable of intelligent multi-site routing.

**Key Features:**
- Automatic mesh VPN peering between sites
- Real-time path quality monitoring (latency, jitter, packet loss)
- Application-aware routing policies
- Automatic failover and load balancing
- Zero-touch provisioning for new sites

**Use Cases:**
- **Enterprise:** Connect branch offices with intelligent routing
- **Multi-cloud:** Route between AWS, Azure, GCP with optimal paths
- **Homelab:** Build redundant home network with failover
- **ISP:** Offer SD-WAN service to customers

**Differentiators vs. Commercial SD-WAN:**
- Open source (no vendor lock-in)
- eBPF-powered data plane (extreme performance)
- Rust implementation (memory safety)
- Built on WireGuard (modern cryptography)
- Free (no per-site licensing)

---

## Problem Statement

### Current Limitations

**Traditional VPN:**
```
Site A ←→ VPN Server ←→ Site B
         (single path, no failover)
```

**Problems:**
1. Single point of failure (VPN server down = all sites disconnected)
2. Suboptimal routing (all traffic through hub)
3. No path quality awareness (uses same path even if degraded)
4. Manual configuration for each site pair
5. No automatic failover

### SD-WAN Solution

**Patronus SD-WAN:**
```
        Site A
       /  |  \
      /   |   \
    Site B -- Site C
      \   |   /
       \  |  /
        Site D

- Automatic mesh peering
- Multiple paths between sites
- Real-time path monitoring
- Intelligent routing decisions
- Automatic failover (<1 second)
```

**Benefits:**
1. ✅ No single point of failure (fully meshed)
2. ✅ Optimal routing (direct site-to-site)
3. ✅ Path quality monitoring (choose best path)
4. ✅ Zero-touch config (automatic peering)
5. ✅ Sub-second failover (eBPF fast-path)

---

## Architecture Overview

### High-Level Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Patronus SD-WAN                         │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌────────────────┐    ┌─────────────────┐                 │
│  │  Control Plane │    │   Data Plane    │                 │
│  │                │    │                 │                 │
│  │ - Mesh Mgmt    │    │ - eBPF Routing  │                 │
│  │ - Path Monitor │    │ - WireGuard VPN │                 │
│  │ - Policy Eval  │───▶│ - Fast Failover │                 │
│  │ - Auto-Peer    │    │                 │                 │
│  └────────────────┘    └─────────────────┘                 │
│         │                      │                            │
│         ▼                      ▼                            │
│  ┌────────────────────────────────────┐                    │
│  │         SD-WAN Database            │                    │
│  │  - Sites, Peers, Paths, Policies   │                    │
│  └────────────────────────────────────┘                    │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### Component Interaction Flow

```
1. Site Discovery
   ┌──────┐                    ┌──────┐
   │Site A│───(announce)──────▶│Site B│
   └──────┘                    └──────┘
        │                           │
        └──(auto-establish VPN)────┘

2. Path Monitoring
   ┌──────┐                    ┌──────┐
   │Site A│───(probe ping)────▶│Site B│
   └──────┘◀──(metrics reply)──└──────┘
        │
        └─▶(update path database)

3. Traffic Routing
   Application Traffic
        │
        ▼
   ┌─────────────┐
   │ eBPF Policy │───(select best path)
   └─────────────┘
        │
        ▼
   ┌─────────────┐
   │  WireGuard  │───(encapsulate)──▶ Destination
   └─────────────┘
```

---

## Core Components

### 1. Mesh Manager (`patronus-sdwan-mesh`)

**Responsibility:** Automatic site discovery and VPN peering.

**Features:**
- Gossip-based site announcement
- Automatic WireGuard tunnel establishment
- Peer authentication via PKI
- Topology change detection

**Data Flow:**
```rust
// Site announces itself to mesh
pub struct SiteAnnouncement {
    site_id: Uuid,
    public_key: WireGuardPublicKey,
    endpoints: Vec<SocketAddr>, // Multiple paths (ISP1, ISP2, etc.)
    capabilities: SiteCapabilities,
    timestamp: SystemTime,
}

// Other sites auto-peer
async fn handle_announcement(announcement: SiteAnnouncement) {
    if !already_peered(announcement.site_id) {
        let tunnel = establish_wireguard_tunnel(
            announcement.public_key,
            announcement.endpoints
        ).await?;

        add_to_mesh(announcement.site_id, tunnel);
        start_path_monitoring(announcement.site_id);
    }
}
```

**Configuration Example:**
```toml
[sdwan.mesh]
enabled = true
site_id = "hq-chicago"
site_name = "Chicago HQ"

# Seed sites (bootstrap)
seeds = [
    "1.2.3.4:51820",  # HQ
    "5.6.7.8:51820",  # DR Site
]

# Authentication
pki_root_ca = "/etc/patronus/sdwan/ca.crt"
site_cert = "/etc/patronus/sdwan/site.crt"
site_key = "/etc/patronus/sdwan/site.key"
```

---

### 2. Path Monitor (`patronus-sdwan-monitor`)

**Responsibility:** Real-time path quality measurement.

**Metrics Collected:**
- **Latency:** Round-trip time (RTT)
- **Jitter:** Variance in latency
- **Packet Loss:** % of lost probes
- **Bandwidth:** Available throughput
- **Path MTU:** Maximum transmission unit

**Monitoring Protocol:**
```rust
// Probe packet (every 1 second)
pub struct PathProbe {
    sequence: u64,
    timestamp: SystemTime,
    probe_type: ProbeType, // ICMP, UDP, TCP
}

// Metrics response
pub struct PathMetrics {
    latency_ms: f64,
    jitter_ms: f64,
    packet_loss_pct: f64,
    bandwidth_mbps: f64,
    mtu: u16,
    measured_at: SystemTime,
}

// Path quality score (0-100)
fn calculate_path_score(metrics: &PathMetrics) -> u8 {
    let latency_score = (200.0 - metrics.latency_ms.min(200.0)) / 2.0;
    let jitter_score = (50.0 - metrics.jitter_ms.min(50.0)) / 0.5;
    let loss_score = (100.0 - metrics.packet_loss_pct) / 1.0;

    ((latency_score + jitter_score + loss_score) / 3.0) as u8
}
```

**Probe Types:**
1. **Active Probes:** Dedicated ping packets (1/sec)
2. **Passive Monitoring:** Analyze real traffic statistics
3. **Hybrid:** Active when idle, passive when busy

**Storage:**
```rust
pub struct PathState {
    site_id: Uuid,
    endpoint: SocketAddr,
    metrics: PathMetrics,
    history: VecDeque<PathMetrics>, // Last 60 measurements
    score: u8,
    status: PathStatus, // Up, Down, Degraded
}
```

---

### 3. Routing Engine (`patronus-sdwan-routing`)

**Responsibility:** Select best path for each packet/flow.

**Routing Modes:**

**1. Application-Aware Routing:**
```rust
pub struct RoutingPolicy {
    name: String,
    match_rules: MatchRules,
    path_preference: PathPreference,
}

// Example: VoIP needs low latency
let voip_policy = RoutingPolicy {
    name: "VoIP Priority".to_string(),
    match_rules: MatchRules {
        dst_port: Some(5060..5061), // SIP
        protocol: Some(Protocol::Udp),
    },
    path_preference: PathPreference::LowestLatency,
};

// Example: Backup traffic can use slower path
let backup_policy = RoutingPolicy {
    name: "Backup Traffic".to_string(),
    match_rules: MatchRules {
        dst_port: Some(873), // rsync
    },
    path_preference: PathPreference::LowestCost,
};
```

**2. Load Balancing:**
```rust
pub enum LoadBalancingMode {
    RoundRobin,           // Equal distribution
    WeightedRoundRobin,   // Based on bandwidth
    LeastConnections,     // Least active flows
    FlowHash,             // Consistent per-flow
}
```

**3. Failover:**
```rust
pub struct FailoverConfig {
    primary_path: PathId,
    backup_paths: Vec<PathId>,
    failover_threshold: PathScore, // Switch if score < threshold
    failback_hysteresis: Duration, // Wait before switching back
}

// Automatic failover
async fn monitor_paths() {
    loop {
        for path in active_paths {
            if path.score < config.failover_threshold {
                let backup = select_best_backup_path();
                switch_traffic_to_path(backup).await;
                alert_admin("Path degraded, failed over to backup");
            }
        }
        sleep(Duration::from_secs(1)).await;
    }
}
```

**4. eBPF Fast-Path Routing:**
```c
// XDP program for path selection
SEC("xdp")
int xdp_sdwan_router(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    // Lookup routing policy
    struct flow_key key = {
        .src_ip = ip->saddr,
        .dst_ip = ip->daddr,
        .protocol = ip->protocol,
    };

    struct path_id *path = bpf_map_lookup_elem(&routing_table, &key);
    if (!path)
        return XDP_PASS; // Use default path

    // Redirect to WireGuard interface for selected path
    return bpf_redirect_map(&wg_interfaces, *path, 0);
}
```

---

### 4. Policy Engine (`patronus-sdwan-policy`)

**Responsibility:** Define and enforce routing policies.

**Policy Types:**

**1. QoS Policies:**
```rust
pub struct QosPolicy {
    name: String,
    applications: Vec<ApplicationClass>,
    latency_requirement: Option<Duration>,
    jitter_requirement: Option<Duration>,
    bandwidth_requirement: Option<u64>, // bps
    priority: u8, // 0-255
}

// Example policies
let realtime = QosPolicy {
    name: "Real-Time".to_string(),
    applications: vec![
        ApplicationClass::VoIP,
        ApplicationClass::VideoConference,
    ],
    latency_requirement: Some(Duration::from_millis(50)),
    jitter_requirement: Some(Duration::from_millis(10)),
    priority: 200,
};

let bulk = QosPolicy {
    name: "Bulk Data".to_string(),
    applications: vec![
        ApplicationClass::Backup,
        ApplicationClass::FileTransfer,
    ],
    latency_requirement: None,
    priority: 50,
};
```

**2. Security Policies:**
```rust
pub struct SecurityPolicy {
    name: String,
    required_encryption: EncryptionLevel,
    allowed_sites: Vec<SiteId>,
    geo_restrictions: Option<GeoPolicy>,
}

// Example: PCI compliance requires specific paths
let pci_policy = SecurityPolicy {
    name: "PCI Compliance".to_string(),
    required_encryption: EncryptionLevel::AES256,
    allowed_sites: vec![
        SiteId::new("hq-datacenter"),
        SiteId::new("dr-datacenter"),
    ],
    geo_restrictions: Some(GeoPolicy::UsOnly),
};
```

**3. Cost Policies:**
```rust
pub struct CostPolicy {
    name: String,
    max_cost_per_gb: f64,
    prefer_unmetered: bool,
    cost_table: HashMap<PathId, f64>,
}

// Example: Prefer cheaper paths for non-critical traffic
let cost_aware = CostPolicy {
    name: "Cost Optimization".to_string(),
    max_cost_per_gb: 0.05,
    prefer_unmetered: true,
    cost_table: hashmap! {
        fiber_path => 0.01,
        lte_path => 0.10,
        starlink_path => 0.05,
    },
};
```

---

## Mesh Topology

### Topology Types

**1. Full Mesh (Default):**
```
Site A ←→ Site B
  ↕        ↕
Site C ←→ Site D

Pros: Direct paths, no single point of failure
Cons: O(n²) tunnels (doesn't scale beyond ~50 sites)
```

**2. Hub-and-Spoke:**
```
        HUB
       / | \
      /  |  \
  Site A B  C

Pros: O(n) tunnels, centralized control
Cons: Single point of failure, suboptimal routing
```

**3. Hierarchical Mesh:**
```
     Hub 1 ←→ Hub 2
     /  \      /  \
  A  B  C    D  E  F

Pros: Scales to 100+ sites, balanced trade-offs
Cons: Moderate complexity
```

**4. Hybrid (Recommended):**
```
Critical sites: Full mesh
Branch offices: Hub-and-spoke to regional hub
Regional hubs: Full mesh with each other

Example:
HQ ←→ DR Site (full mesh, critical)
 ↕      ↕
Branch offices (spoke)
```

### Topology Configuration

```toml
[sdwan.topology]
mode = "hybrid"

# Full mesh sites (critical infrastructure)
full_mesh_sites = [
    "hq-chicago",
    "dr-denver",
    "datacenter-aws-us-east",
]

# Hub sites (regional aggregation)
hub_sites = [
    "regional-west",
    "regional-east",
    "regional-europe",
]

# Auto-peer rules
[sdwan.topology.auto_peer]
# New sites automatically peer with nearest hub
nearest_hub = true

# Sites in same region auto-peer (regional mesh)
same_region_mesh = true

# Maximum peers per site (prevent O(n²) explosion)
max_peers = 20
```

---

## Path Selection Algorithm

### Multi-Factor Path Scoring

**Path Score = Weighted sum of multiple factors:**

```rust
pub struct PathScoringWeights {
    latency_weight: f64,      // 0.0 - 1.0
    jitter_weight: f64,       // 0.0 - 1.0
    loss_weight: f64,         // 0.0 - 1.0
    bandwidth_weight: f64,    // 0.0 - 1.0
    cost_weight: f64,         // 0.0 - 1.0
}

impl PathScoringWeights {
    // Preset profiles
    pub fn latency_sensitive() -> Self {
        Self {
            latency_weight: 0.5,
            jitter_weight: 0.3,
            loss_weight: 0.2,
            bandwidth_weight: 0.0,
            cost_weight: 0.0,
        }
    }

    pub fn throughput_focused() -> Self {
        Self {
            latency_weight: 0.1,
            jitter_weight: 0.0,
            loss_weight: 0.2,
            bandwidth_weight: 0.7,
            cost_weight: 0.0,
        }
    }

    pub fn cost_optimized() -> Self {
        Self {
            latency_weight: 0.2,
            jitter_weight: 0.1,
            loss_weight: 0.2,
            bandwidth_weight: 0.0,
            cost_weight: 0.5,
        }
    }
}

fn score_path(
    metrics: &PathMetrics,
    weights: &PathScoringWeights,
) -> f64 {
    let latency_score = normalize_latency(metrics.latency_ms);
    let jitter_score = normalize_jitter(metrics.jitter_ms);
    let loss_score = 100.0 - metrics.packet_loss_pct;
    let bandwidth_score = normalize_bandwidth(metrics.bandwidth_mbps);
    let cost_score = normalize_cost(metrics.cost_per_gb);

    weights.latency_weight * latency_score +
    weights.jitter_weight * jitter_score +
    weights.loss_weight * loss_score +
    weights.bandwidth_weight * bandwidth_score +
    weights.cost_weight * cost_score
}
```

### Path Selection Decision Tree

```
                    ┌─────────────┐
                    │ New Packet  │
                    └──────┬──────┘
                           │
                    ┌──────▼──────────┐
                    │ Application     │
                    │ Classification  │
                    └──────┬──────────┘
                           │
                ┌──────────┴──────────┐
                │                     │
        ┌───────▼────────┐   ┌────────▼────────┐
        │ VoIP/RTC       │   │ Bulk/Best Effort│
        │ (low latency)  │   │ (high bandwidth)│
        └───────┬────────┘   └────────┬────────┘
                │                     │
        ┌───────▼────────┐   ┌────────▼────────┐
        │ Score paths    │   │ Score paths     │
        │ (latency focus)│   │ (throughput)    │
        └───────┬────────┘   └────────┬────────┘
                │                     │
                └──────────┬──────────┘
                           │
                    ┌──────▼──────────┐
                    │ Select Best Path│
                    └──────┬──────────┘
                           │
                    ┌──────▼──────────┐
                    │ Route via eBPF  │
                    └─────────────────┘
```

---

## Data Structures

### Core Database Schema (SQLite)

```sql
-- Sites in the mesh
CREATE TABLE sdwan_sites (
    site_id TEXT PRIMARY KEY,
    site_name TEXT NOT NULL,
    public_key TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP,
    status TEXT CHECK(status IN ('active', 'inactive', 'degraded'))
);

-- Endpoints for each site (multi-homing)
CREATE TABLE sdwan_endpoints (
    endpoint_id INTEGER PRIMARY KEY AUTOINCREMENT,
    site_id TEXT NOT NULL,
    address TEXT NOT NULL,  -- IP:port
    interface_type TEXT,    -- fiber, lte, starlink, etc.
    cost_per_gb REAL,
    FOREIGN KEY (site_id) REFERENCES sdwan_sites(site_id)
);

-- Paths between sites
CREATE TABLE sdwan_paths (
    path_id INTEGER PRIMARY KEY AUTOINCREMENT,
    src_site_id TEXT NOT NULL,
    dst_site_id TEXT NOT NULL,
    src_endpoint_id INTEGER NOT NULL,
    dst_endpoint_id INTEGER NOT NULL,
    wg_interface TEXT,      -- wg-mesh-001, etc.
    status TEXT CHECK(status IN ('up', 'down', 'degraded')),
    FOREIGN KEY (src_site_id) REFERENCES sdwan_sites(site_id),
    FOREIGN KEY (dst_site_id) REFERENCES sdwan_sites(site_id),
    UNIQUE(src_site_id, dst_site_id, src_endpoint_id, dst_endpoint_id)
);

-- Path metrics history
CREATE TABLE sdwan_path_metrics (
    metric_id INTEGER PRIMARY KEY AUTOINCREMENT,
    path_id INTEGER NOT NULL,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    latency_ms REAL,
    jitter_ms REAL,
    packet_loss_pct REAL,
    bandwidth_mbps REAL,
    score INTEGER,
    FOREIGN KEY (path_id) REFERENCES sdwan_paths(path_id)
);
CREATE INDEX idx_path_metrics_time ON sdwan_path_metrics(path_id, timestamp);

-- Routing policies
CREATE TABLE sdwan_policies (
    policy_id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    priority INTEGER NOT NULL,
    match_rules TEXT,  -- JSON: {dst_port, protocol, etc.}
    path_preference TEXT,  -- lowest_latency, highest_bandwidth, etc.
    enabled BOOLEAN DEFAULT 1
);

-- Active flows (in-memory, cached)
CREATE TABLE sdwan_flows (
    flow_id TEXT PRIMARY KEY,
    src_ip TEXT NOT NULL,
    dst_ip TEXT NOT NULL,
    src_port INTEGER,
    dst_port INTEGER,
    protocol INTEGER,
    selected_path_id INTEGER,
    started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_packet_at TIMESTAMP,
    bytes_tx INTEGER DEFAULT 0,
    bytes_rx INTEGER DEFAULT 0,
    FOREIGN KEY (selected_path_id) REFERENCES sdwan_paths(path_id)
);
```

### In-Memory Structures (Rust)

```rust
// Global mesh state
pub struct MeshState {
    sites: DashMap<SiteId, Site>,
    paths: DashMap<PathId, Path>,
    policies: Arc<RwLock<Vec<RoutingPolicy>>>,
    active_flows: DashMap<FlowKey, FlowState>,
}

// Per-site information
pub struct Site {
    id: SiteId,
    name: String,
    public_key: WireGuardPublicKey,
    endpoints: Vec<Endpoint>,
    last_seen: SystemTime,
    status: SiteStatus,
}

// Network path between two sites
pub struct Path {
    id: PathId,
    src_site: SiteId,
    dst_site: SiteId,
    src_endpoint: EndpointId,
    dst_endpoint: EndpointId,
    wg_interface: String,
    metrics: PathMetrics,
    history: VecDeque<PathMetrics>,  // Rolling 60-second window
    score: AtomicU8,
    status: AtomicU8,  // PathStatus encoded
}

// Active flow tracking
pub struct FlowState {
    key: FlowKey,
    selected_path: PathId,
    policy_applied: PolicyId,
    started_at: Instant,
    last_packet: Instant,
    stats: FlowStats,
}

#[derive(Hash, Eq, PartialEq)]
pub struct FlowKey {
    src_ip: IpAddr,
    dst_ip: IpAddr,
    src_port: u16,
    dst_port: u16,
    protocol: IpProtocol,
}
```

---

## API Design

### REST API Endpoints

```rust
// Site Management
GET    /api/sdwan/sites                    // List all sites
POST   /api/sdwan/sites                    // Add site manually
GET    /api/sdwan/sites/:id                // Get site details
DELETE /api/sdwan/sites/:id                // Remove site from mesh

// Path Management
GET    /api/sdwan/paths                    // List all paths
GET    /api/sdwan/paths/:id                // Get path details
GET    /api/sdwan/paths/:id/metrics        // Get path metrics history
POST   /api/sdwan/paths/:id/test           // Trigger path test

// Routing Policies
GET    /api/sdwan/policies                 // List policies
POST   /api/sdwan/policies                 // Create policy
PUT    /api/sdwan/policies/:id             // Update policy
DELETE /api/sdwan/policies/:id             // Delete policy

// Active Flows
GET    /api/sdwan/flows                    // List active flows
GET    /api/sdwan/flows/:id                // Get flow details

// Topology
GET    /api/sdwan/topology                 // Get mesh topology (graph)
POST   /api/sdwan/topology/optimize        // Trigger topology optimization
```

### WebSocket Events

```rust
// Real-time SD-WAN events
pub enum SdwanEvent {
    // Site events
    SiteJoined { site_id: SiteId, site_name: String },
    SiteLeft { site_id: SiteId },
    SiteStatusChanged { site_id: SiteId, status: SiteStatus },

    // Path events
    PathEstablished { path_id: PathId, src: SiteId, dst: SiteId },
    PathFailed { path_id: PathId, reason: String },
    PathDegraded { path_id: PathId, metrics: PathMetrics },

    // Routing events
    FailoverTriggered { from_path: PathId, to_path: PathId, reason: String },
    PolicyApplied { flow_id: FlowId, policy: PolicyId, path: PathId },

    // Metrics updates
    PathMetrics { path_id: PathId, metrics: PathMetrics },
    TopologyChanged { change_type: TopologyChange },
}

// WebSocket endpoint
GET /ws/sdwan  // Subscribe to SD-WAN events
```

---

## Implementation Phases

### Phase 4.1: Foundation (Week 1-2)

**Goal:** Basic mesh functionality

**Tasks:**
- [ ] Create `patronus-sdwan` crate
- [ ] Implement site announcement protocol
- [ ] Automatic WireGuard tunnel establishment
- [ ] Basic path monitoring (latency only)
- [ ] SQLite schema and migrations
- [ ] REST API for site management

**Deliverable:** Two Patronus instances can auto-peer and establish VPN

---

### Phase 4.2: Path Monitoring (Week 3-4)

**Goal:** Comprehensive path quality measurement

**Tasks:**
- [ ] Multi-metric path monitoring (latency, jitter, loss, bandwidth)
- [ ] Path history tracking (60-second rolling window)
- [ ] Path scoring algorithm
- [ ] Metrics visualization in web UI
- [ ] Alerting on path degradation

**Deliverable:** Real-time path quality dashboard

---

### Phase 4.3: Intelligent Routing (Week 5-6)

**Goal:** Application-aware path selection

**Tasks:**
- [ ] Policy engine implementation
- [ ] Application classification (DPI-lite)
- [ ] eBPF routing program
- [ ] Path selection algorithm
- [ ] Flow tracking

**Deliverable:** Different applications use different paths based on policy

---

### Phase 4.4: Failover & Load Balancing (Week 7-8)

**Goal:** High availability and performance

**Tasks:**
- [ ] Automatic failover on path degradation
- [ ] Load balancing across multiple paths
- [ ] Flow-based load balancing (sticky sessions)
- [ ] Sub-second failover with eBPF
- [ ] Failback with hysteresis

**Deliverable:** Zero-downtime failover when path fails

---

### Phase 4.5: Advanced Features (Week 9-10)

**Goal:** Production-ready SD-WAN

**Tasks:**
- [ ] Multi-homing support (multiple ISPs per site)
- [ ] Topology optimization algorithm
- [ ] Cost-aware routing
- [ ] QoS enforcement
- [ ] SD-WAN statistics and reporting

**Deliverable:** Enterprise-grade SD-WAN platform

---

## Security Considerations

### Authentication & Authorization

**Site Authentication:**
```rust
// PKI-based site authentication
pub struct SiteIdentity {
    certificate: X509Certificate,
    private_key: PrivateKey,
    ca_chain: Vec<X509Certificate>,
}

// Mutual TLS for control plane
async fn authenticate_site(cert: &X509Certificate) -> Result<SiteId> {
    // Verify certificate chain
    verify_certificate_chain(cert, &CA_ROOT)?;

    // Check certificate not revoked
    check_crl(cert)?;

    // Extract site_id from certificate CN
    let site_id = cert.subject_common_name()?;

    Ok(SiteId::from_str(&site_id)?)
}
```

**Data Plane Security:**
- All traffic encrypted with WireGuard (ChaCha20-Poly1305)
- Perfect forward secrecy (PFS) with key rotation
- Optional double encryption for sensitive traffic

### Attack Surface Mitigation

**1. Control Plane Protection:**
```rust
// Rate limiting on site announcements
#[derive(Clone)]
pub struct RateLimiter {
    max_announcements_per_minute: u32,
    announcement_counts: Arc<Mutex<HashMap<SiteId, (u32, Instant)>>>,
}

impl RateLimiter {
    pub async fn allow_announcement(&self, site_id: &SiteId) -> bool {
        let mut counts = self.announcement_counts.lock().await;
        let (count, last_reset) = counts.entry(*site_id)
            .or_insert((0, Instant::now()));

        if last_reset.elapsed() > Duration::from_secs(60) {
            *count = 0;
            *last_reset = Instant::now();
        }

        if *count >= self.max_announcements_per_minute {
            return false;  // Rate limited
        }

        *count += 1;
        true
    }
}
```

**2. Path Probe Protection:**
- HMAC-signed probes (prevent spoofing)
- Nonce tracking (prevent replay attacks)
- Rate limiting per peer

**3. Topology Manipulation Prevention:**
- Site announcements must be signed
- Certificate pinning for known sites
- Anomaly detection on topology changes

---

## Performance Targets

### Latency Targets

| Operation | Target | Stretch Goal |
|-----------|--------|--------------|
| Path failover | <1s | <100ms |
| New site join | <5s | <2s |
| Path probe interval | 1s | 100ms |
| Policy evaluation | <1μs | <100ns |
| eBPF routing decision | <10μs | <1μs |

### Throughput Targets

| Metric | Target | Hardware |
|--------|--------|----------|
| Per-path throughput | 10 Gbps | Single 10GbE NIC |
| Total mesh throughput | 100 Gbps | 10x 10GbE NICs |
| Packets per second | 10M pps | AMD EPYC 7763 |
| Concurrent flows | 100K | 32GB RAM |

### Scalability Targets

| Dimension | Target | Notes |
|-----------|--------|-------|
| Sites in full mesh | 50 | O(n²) limit |
| Sites in hierarchical mesh | 500 | With regional hubs |
| Paths per site | 20 | Configurable limit |
| Policies | 1000 | LPM trie lookup |
| Active flows | 1M | Flow table size |

---

## Testing Strategy

### Unit Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_path_scoring() {
        let metrics = PathMetrics {
            latency_ms: 25.0,
            jitter_ms: 5.0,
            packet_loss_pct: 0.1,
            bandwidth_mbps: 1000.0,
            ..Default::default()
        };

        let weights = PathScoringWeights::latency_sensitive();
        let score = score_path(&metrics, &weights);

        assert!(score > 80.0); // Good path
    }

    #[tokio::test]
    async fn test_automatic_failover() {
        let mut mesh = MeshState::new();

        // Setup two paths
        let primary = add_path(&mut mesh, "siteA", "siteB", "isp1").await;
        let backup = add_path(&mut mesh, "siteA", "siteB", "isp2").await;

        // Degrade primary path
        degrade_path(&mut mesh, primary, PathScore(30)).await;

        // Trigger failover check
        check_failover(&mesh).await;

        // Verify traffic moved to backup
        let active_path = mesh.get_active_path("siteA", "siteB");
        assert_eq!(active_path, backup);
    }
}
```

### Integration Tests

```rust
#[tokio::test]
async fn test_three_site_mesh() {
    // Spin up 3 Patronus instances
    let site_a = spawn_patronus_instance("siteA", 51820).await;
    let site_b = spawn_patronus_instance("siteB", 51821).await;
    let site_c = spawn_patronus_instance("siteC", 51822).await;

    // Configure mesh
    site_a.configure_sdwan(vec!["127.0.0.1:51821", "127.0.0.1:51822"]).await;

    // Wait for mesh formation
    tokio::time::sleep(Duration::from_secs(5)).await;

    // Verify full mesh established
    assert_eq!(site_a.peer_count().await, 2);
    assert_eq!(site_b.peer_count().await, 2);
    assert_eq!(site_c.peer_count().await, 2);

    // Test traffic routing
    let result = site_a.ping("siteC", "10.0.0.3").await;
    assert!(result.is_ok());
}
```

### Performance Tests

```rust
#[tokio::test]
async fn bench_path_selection() {
    let mesh = setup_mesh_with_100_paths().await;

    let start = Instant::now();
    for _ in 0..1_000_000 {
        let _path = select_best_path(&mesh, &flow_key);
    }
    let elapsed = start.elapsed();

    let ops_per_sec = 1_000_000.0 / elapsed.as_secs_f64();
    println!("Path selection: {:.0} ops/sec", ops_per_sec);

    assert!(ops_per_sec > 1_000_000.0); // >1M ops/sec
}
```

### Chaos Testing

```rust
#[tokio::test]
async fn chaos_test_path_failures() {
    let mesh = setup_10_site_mesh().await;

    // Randomly fail paths
    for _ in 0..100 {
        let path = mesh.random_path();
        path.set_status(PathStatus::Down).await;
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Verify mesh still functional
        assert!(mesh.verify_connectivity().await);
    }
}
```

---

## Future Enhancements

### Phase 5: Advanced Features

**1. Cloud Integration:**
- Auto-discover cloud VPCs (AWS, Azure, GCP)
- Managed SD-WAN service
- Cloud cost optimization

**2. AI-Powered Routing:**
- ML-based path prediction
- Proactive failover before degradation
- Traffic pattern learning

**3. Multi-Protocol Support:**
- MPLS integration
- IPsec fallback
- BGP peering

**4. Telemetry & Analytics:**
- Prometheus exporter
- Grafana dashboards
- NetFlow export

---

## Conclusion

This SD-WAN architecture design provides:

✅ **Automatic mesh networking** - Zero-touch site onboarding
✅ **Intelligent routing** - Application-aware path selection
✅ **High availability** - Sub-second failover
✅ **Performance** - eBPF-powered data plane
✅ **Security** - PKI authentication, WireGuard encryption
✅ **Scalability** - Hierarchical mesh to 500+ sites

**Next Steps:**
1. Review this design document
2. Begin Phase 4.1 implementation
3. Build MVP with 2-site auto-mesh
4. Iterate based on real-world testing

---

🤖 *Generated with [Claude Code](https://claude.com/claude-code)*

**Status:** Design Complete - Ready for Implementation 🚀
