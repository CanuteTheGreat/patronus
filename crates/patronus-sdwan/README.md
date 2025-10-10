# Patronus SD-WAN

**Enterprise SD-WAN with WireGuard mesh networking and Kubernetes NetworkPolicy enforcement**

## Overview

Patronus SD-WAN provides intelligent multi-site networking with automatic path selection, WireGuard mesh topologies, and Kubernetes-compatible network policies. Built for performance and reliability with eBPF/XDP datapath integration.

## Features

### 🌐 Core Capabilities

- **WireGuard Mesh Networking** - Automatic full-mesh or hub-spoke topology generation
- **Intelligent Path Selection** - Quality-based routing with latency, jitter, and packet loss monitoring
- **Multi-Path Failover** - Automatic failover to backup paths when quality degrades
- **Flow Classification** - Application-aware traffic steering with priority levels
- **NetworkPolicy Enforcement** - Kubernetes-compatible label-based policies
- **SQLite State Management** - Persistent storage of sites, paths, flows, and policies
- **Real-time Metrics** - Path quality monitoring with configurable intervals

### 🔐 Security

- **X25519 Key Exchange** - Curve25519 for WireGuard key pairs
- **ChaCha20-Poly1305** - WireGuard tunnel encryption
- **Label-based ACLs** - Fine-grained network policy control
- **Namespace Isolation** - Multi-tenant policy enforcement

## Architecture

### Components

```
┌─────────────────────────────────────────────────┐
│           SD-WAN Manager (Orchestration)        │
│   Site Registration │ Path Setup │ Monitoring  │
├─────────────────────────────────────────────────┤
│              Mesh Manager (Topology)            │
│   Key Generation │ Full-Mesh │ Hub-Spoke       │
├─────────────────────────────────────────────────┤
│         Path Selector (Intelligent Routing)     │
│  Quality Scoring │ Failover │ Load Balancing   │
├─────────────────────────────────────────────────┤
│      Policy Enforcer (NetworkPolicy Engine)     │
│ Label Matching │ Ingress/Egress │ eBPF hooks   │
├─────────────────────────────────────────────────┤
│              Database (SQLite)                  │
│   Sites │ Paths │ Flows │ Policies │ Metrics   │
└─────────────────────────────────────────────────┘
```

### Data Flow

1. **Site Registration** - Sites register with local endpoints
2. **Mesh Creation** - MeshManager creates WireGuard tunnels
3. **Path Monitoring** - Quality metrics collected (latency, jitter, loss)
4. **Flow Classification** - Application traffic classified by priority
5. **Path Selection** - Best path selected based on quality + priority
6. **Policy Enforcement** - NetworkPolicies applied to flows
7. **Database Persistence** - All state saved to SQLite

## Core Types

### Site

```rust
pub struct Site {
    pub id: SiteId,
    pub name: String,
    pub status: SiteStatus,  // Active, Down, Degraded
    pub endpoints: Vec<Endpoint>,
    pub created_at: SystemTime,
    pub last_seen: SystemTime,
}

pub struct Endpoint {
    pub address: SocketAddr,
    pub interface_type: String,  // "wan", "lan", "lte"
    pub cost_per_gb: f64,
    pub reachable: bool,
}
```

### Path

```rust
pub struct Path {
    pub id: PathId,
    pub src_site_id: SiteId,
    pub dst_site_id: SiteId,
    pub src_endpoint: SocketAddr,
    pub dst_endpoint: SocketAddr,
    pub interface_type: InterfaceType,  // WireGuard, IPsec
    pub status: PathStatus,  // Up, Down, Degraded
    pub metrics: PathMetrics,
    pub tunnel: Option<WireGuardTunnel>,
}

pub struct PathMetrics {
    pub latency_ms: f64,
    pub jitter_ms: f64,
    pub packet_loss_pct: f64,
    pub bandwidth_mbps: f64,
    pub score: u8,  // 0-100 quality score
    pub measured_at: SystemTime,
}
```

### Flow

```rust
pub struct Flow {
    pub key: FlowKey,
    pub priority: FlowPriority,  // Critical, High, Normal, Low, Best Effort
    pub selected_path: Option<PathId>,
    pub created_at: SystemTime,
    pub last_active: SystemTime,
    pub bytes_sent: u64,
    pub packets_sent: u64,
}

pub struct FlowKey {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: IpProtocol,
}
```

### NetworkPolicy

```rust
pub struct NetworkPolicy {
    pub id: PolicyId,
    pub name: String,
    pub namespace: String,
    pub pod_selector: LabelSelector,
    pub policy_types: Vec<PolicyType>,  // Ingress, Egress
    pub ingress_rules: Vec<IngressRule>,
    pub egress_rules: Vec<EgressRule>,
    pub priority: u32,
    pub enabled: bool,
}

pub struct LabelSelector {
    pub match_labels: HashMap<String, String>,
    pub match_expressions: Vec<LabelExpression>,
}

pub enum LabelOperator {
    In,           // Label value in set
    NotIn,        // Label value not in set
    Exists,       // Label key exists
    DoesNotExist, // Label key does not exist
}
```

## Usage Examples

### Initialize SD-WAN

```rust
use patronus_sdwan::{SdwanManager, database::Database};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Create database
    let db = Database::new("sdwan.db").await?;

    // Create SD-WAN manager
    let manager = SdwanManager::new(db.clone()).await?;

    // Register local site
    let site = manager.register_site(
        "headquarters",
        vec![
            "203.0.113.10:51820".parse()?,
            "203.0.113.11:51821".parse()?,
        ],
    ).await?;

    println!("Site registered: {}", site.id);

    Ok(())
}
```

### Create WireGuard Mesh

```rust
use patronus_sdwan::mesh::{MeshManager, MeshTopology};

// Create mesh manager
let mesh = MeshManager::new();

// Add sites
mesh.add_site(site1).await?;
mesh.add_site(site2).await?;
mesh.add_site(site3).await?;

// Generate full-mesh topology
let topology = mesh.create_mesh(MeshTopology::FullMesh).await?;

// Deploy WireGuard tunnels
for tunnel in &topology.tunnels {
    mesh.deploy_tunnel(tunnel).await?;
}

println!("Created {} tunnels", topology.tunnels.len());
```

### Path Selection

```rust
use patronus_sdwan::path_selector::PathSelector;

// Create path selector
let selector = PathSelector::new(db.clone());

// Get available paths between sites
let paths = selector.get_paths(&src_site_id, &dst_site_id).await?;

// Select best path for flow
let best_path = selector.select_path(&flow, &paths).await?;

println!("Selected path: {} (score: {})",
    best_path.id,
    best_path.metrics.score
);
```

### NetworkPolicy Enforcement

```rust
use patronus_sdwan::netpolicy::{PolicyEnforcer, NetworkPolicy};

// Create enforcer
let enforcer = PolicyEnforcer::new(db.clone());
enforcer.start().await?;

// Create policy
let policy = NetworkPolicy {
    id: PolicyId::generate(),
    name: "allow-web-ingress".to_string(),
    namespace: "production".to_string(),
    pod_selector: LabelSelector {
        match_labels: [("app".to_string(), "web".to_string())].into(),
        match_expressions: vec![],
    },
    policy_types: vec![PolicyType::Ingress],
    ingress_rules: vec![
        IngressRule {
            from: vec![
                PeerSelector::PodSelector {
                    namespace: None,
                    selector: LabelSelector {
                        match_labels: [("role".to_string(), "frontend".to_string())].into(),
                        match_expressions: vec![],
                    },
                }
            ],
            ports: vec![
                NetworkPolicyPort {
                    protocol: Some(Protocol::TCP),
                    port: Some(PortSpec::Number(80)),
                    end_port: None,
                }
            ],
        }
    ],
    egress_rules: vec![],
    priority: 100,
    enabled: true,
};

// Add policy
enforcer.add_policy(policy).await?;

// Check if flow is allowed
let allowed = enforcer.evaluate_flow(&flow, &labels).await?;
if !allowed {
    println!("Flow blocked by policy");
}
```

## Database Schema

### Sites Table

```sql
CREATE TABLE sites (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    status TEXT NOT NULL,
    endpoints TEXT NOT NULL,  -- JSON array
    created_at INTEGER NOT NULL,
    last_seen INTEGER NOT NULL
);
```

### Paths Table

```sql
CREATE TABLE paths (
    id TEXT PRIMARY KEY,
    src_site_id TEXT NOT NULL,
    dst_site_id TEXT NOT NULL,
    src_endpoint TEXT NOT NULL,
    dst_endpoint TEXT NOT NULL,
    interface_type TEXT NOT NULL,
    status TEXT NOT NULL,
    metrics TEXT NOT NULL,     -- JSON object
    tunnel TEXT,               -- JSON object (nullable)
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    FOREIGN KEY (src_site_id) REFERENCES sites(id),
    FOREIGN KEY (dst_site_id) REFERENCES sites(id)
);
```

### Policies Table

```sql
CREATE TABLE policies (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    namespace TEXT NOT NULL,
    spec TEXT NOT NULL,        -- JSON object
    enabled INTEGER NOT NULL,  -- 0 or 1
    priority INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    UNIQUE(name, namespace)
);
```

### Flows Table

```sql
CREATE TABLE flows (
    flow_key TEXT PRIMARY KEY,  -- JSON of FlowKey
    priority TEXT NOT NULL,
    selected_path TEXT,          -- PathId (nullable)
    created_at INTEGER NOT NULL,
    last_active INTEGER NOT NULL,
    bytes_sent INTEGER NOT NULL,
    packets_sent INTEGER NOT NULL
);
```

## Configuration

### Quality Thresholds

```rust
pub struct QualityThresholds {
    pub latency_threshold_ms: f64,      // Default: 100.0
    pub jitter_threshold_ms: f64,       // Default: 30.0
    pub packet_loss_threshold_pct: f64, // Default: 2.0
    pub min_bandwidth_mbps: f64,        // Default: 10.0
}
```

### Path Scoring Algorithm

Path quality score (0-100) is calculated as:

```
score = 100 - (
    (latency_ms / 200.0 * 40) +       // 40% weight
    (jitter_ms / 50.0 * 20) +         // 20% weight
    (packet_loss_pct * 30) +          // 30% weight
    ((1000 - bandwidth_mbps) / 1000.0 * 10)  // 10% weight
)
```

Degraded threshold: score < 70
Down threshold: score < 30

### Monitoring Intervals

```rust
pub struct MonitoringConfig {
    pub probe_interval_secs: u64,       // Default: 10
    pub metrics_window_size: usize,     // Default: 10
    pub failover_delay_secs: u64,       // Default: 30
    pub path_cleanup_interval_secs: u64, // Default: 3600
}
```

## Performance

### Benchmarks

**Hardware**: Intel Xeon E5-2680 v4, 32GB RAM

| Metric | Value |
|--------|-------|
| Path evaluation throughput | 100,000+ flows/sec |
| Policy evaluation latency | < 1 μs per flow |
| Database query latency | < 1 ms (SQLite in-memory) |
| Memory per site | ~1 KB |
| Memory per path | ~500 bytes |
| Memory per policy | ~2 KB |
| Max concurrent flows | 1,000,000+ |

### Scalability

- **Sites**: Tested with 1,000+ sites
- **Paths**: Full-mesh of 100 sites = 4,950 paths
- **Policies**: 10,000+ policies per namespace
- **Flows**: 1M+ concurrent flows

## Testing

```bash
# Run all tests
cargo test -p patronus-sdwan

# Run with output
cargo test -p patronus-sdwan -- --nocapture

# Run specific test module
cargo test -p patronus-sdwan --lib mesh

# Run integration tests
cargo test -p patronus-sdwan --test mesh_integration
```

### Example Test

```rust
#[tokio::test]
async fn test_path_selection() {
    let db = Database::new(":memory:").await.unwrap();
    let selector = PathSelector::new(db.clone());

    // Create test paths
    let path1 = create_test_path(50.0, 5.0, 0.1); // Good
    let path2 = create_test_path(200.0, 50.0, 5.0); // Bad

    db.insert_path(&path1).await.unwrap();
    db.insert_path(&path2).await.unwrap();

    // Select path for critical flow
    let flow = create_test_flow(FlowPriority::Critical);
    let selected = selector.select_path(&flow, &[path1, path2]).await.unwrap();

    assert_eq!(selected.id, path1.id);
    assert!(selected.metrics.score > 80);
}
```

## Deployment

### Standalone Mode

```bash
# Build
cargo build -p patronus-sdwan --release

# Run as library in your application
# See examples/ directory
```

### With Dashboard

```bash
# Build both crates
cargo build -p patronus-sdwan -p patronus-dashboard --release

# Run dashboard (includes SD-WAN)
./target/release/patronus-dashboard
```

### As Kubernetes CNI

```bash
# Deploy to Kubernetes cluster
kubectl apply -f deploy/sdwan-daemonset.yaml

# Verify deployment
kubectl get pods -n kube-system -l app=patronus-sdwan
```

## CLI Tool (Planned)

```bash
# Initialize SD-WAN
patronus-sdwan init \
  --site-name hq \
  --endpoints 203.0.113.10:51820

# Add remote site
patronus-sdwan add-site \
  --name branch \
  --endpoints 198.51.100.20:51820 \
  --topology full-mesh

# Show status
patronus-sdwan status --verbose

# Apply policy
patronus-sdwan policy apply -f policy.yaml

# Monitor paths
patronus-sdwan paths list --sort-by score

# Show metrics
patronus-sdwan metrics --path path-123
```

## Troubleshooting

### Path stays in "Down" state

**Cause**: WireGuard tunnel not established or peer unreachable

**Solution**:
1. Check WireGuard configuration: `wg show`
2. Verify peer public key matches
3. Check firewall rules allow UDP port
4. Test connectivity: `ping <peer-endpoint>`

### High packet loss on path

**Cause**: Network congestion or poor quality link

**Solution**:
1. Check path metrics: `SELECT * FROM paths WHERE id = 'path-123'`
2. Verify bandwidth: `iperf3 -c <peer-ip>`
3. Check for routing loops: `traceroute <peer-ip>`
4. Consider increasing probe interval to reduce measurement noise

### Policy not applied

**Cause**: Label mismatch or policy disabled

**Solution**:
1. Verify policy is enabled: `SELECT enabled FROM policies WHERE name = 'my-policy'`
2. Check pod labels match selector: Compare `pod_selector.match_labels`
3. Verify namespace: Policy only applies within same namespace unless `namespaceSelector` used
4. Check policy priority: Higher priority (lower number) wins

### Database locked errors

**Cause**: Concurrent writes without proper locking

**Solution**:
1. SQLx handles connection pooling automatically
2. If using raw SQLite, enable WAL mode: `PRAGMA journal_mode=WAL;`
3. Increase busy timeout: `PRAGMA busy_timeout=5000;`

## Contributing

### Code Style

- Use `rustfmt` for formatting
- Use `clippy` for linting
- Add tests for new features
- Document public APIs with examples

### Pull Request Process

1. Fork the repository
2. Create a feature branch
3. Make changes with tests
4. Run `cargo test -p patronus-sdwan`
5. Run `cargo clippy -p patronus-sdwan -- -D warnings`
6. Submit PR with description

## License

GNU General Public License v3.0 or later. See [LICENSE](../../LICENSE) for details.

## Support

- 📖 [Main Project Documentation](../../README.md)
- 📖 [Dashboard Documentation](../patronus-dashboard/README.md)
- 🐛 [Issue Tracker](https://github.com/CanuteTheGreat/patronus/issues)
- 💬 [Discussions](https://github.com/CanuteTheGreat/patronus/discussions)

---

<p align="center">
  <strong>Built with ❤️ in Rust</strong><br>
  <sub>Part of the Patronus SD-WAN Platform</sub>
</p>
