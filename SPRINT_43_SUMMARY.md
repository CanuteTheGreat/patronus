# Sprint 43: Cloud-Native & Advanced Features

**Sprint Duration**: October 13, 2025
**Status**: 🔄 In Progress (25% Complete)
**Focus**: Kubernetes operator, monitoring, advanced SD-WAN features, and polish

---

## Sprint Objectives

This sprint tackles 4 major areas:
1. **Option 2**: Kubernetes Operator for cloud-native deployment
2. **Option 3**: Grafana dashboards and Prometheus alerts
3. **Option 5**: Advanced SD-WAN features (DPI, dynamic path selection, QoS)
4. **Option 8**: Bug fixes and polish

---

## Completed Work

### 1. ✅ Dashboard Compilation Fixed (Option 8)

**Problem**: Axum version conflicts between 0.7 and 0.8
- `async-graphql-axum` 7.0.17 requires axum 0.8
- Dashboard was trying to use axum 0.7
- Multiple axum-core versions in dependency tree

**Solution**:
- Updated to axum 0.8.6 (matching async-graphql-axum requirement)
- Updated tower-http to 0.6 (compatible with axum 0.8)
- Temporarily disabled OpenTelemetry (dependency conflicts)
- Dashboard now compiles cleanly ✅

**Files Modified**:
- `crates/patronus-dashboard/Cargo.toml`:
  ```toml
  axum = { version = "0.8", features = ["ws", "macros"] }
  tower-http = { version = "0.6", features = ["fs", "trace", "cors", "set-header"] }
  async-graphql-axum = "7.0"  # Uses axum 0.8
  ```

**Status**: ✅ Complete
- Dashboard compiles successfully
- 69 warnings (mostly unused imports/dead code - non-blocking)
- OpenTelemetry can be re-enabled in future sprint

---

## Architecture & Design Documents

### 2. 🔄 Kubernetes Operator (Option 2)

**Current State**:
- Helm charts exist in `/operator/helm/patronus-operator/`
- No Rust operator implementation yet
- Scaffolding created in previous sprints

**Proposed Architecture**:

```
┌─────────────────────────────────────────────┐
│         Kubernetes API Server                │
└──────────────┬──────────────────────────────┘
               │ Watch CRDs
        ┌──────▼────────┐
        │   Patronus    │
        │   Operator    │
        │  (Rust/Kube)  │
        └──────┬────────┘
               │ Reconcile
        ┌──────▼────────────────────────┐
        │                               │
   ┌────▼─────┐  ┌────▼─────┐  ┌───▼──────┐
   │   Site   │  │  Policy  │  │   Peer   │
   │   CRDs   │  │   CRDs   │  │   CRDs   │
   └──────────┘  └──────────┘  └──────────┘
```

#### Custom Resource Definitions (CRDs)

**1. Site Resource** (`patronus.io/v1/Site`):
```yaml
apiVersion: patronus.io/v1
kind: Site
metadata:
  name: site-nyc-prod
spec:
  siteId: "site-123"
  displayName: "New York Production"
  region: "us-east-1"
  tunnelEndpoint:
    address: "203.0.113.10"
    port: 51822
  peers:
    - siteId: "site-456"
      address: "203.0.113.20"
status:
  phase: Active
  tunnelsUp: 3
  lastHealthCheck: "2025-10-13T10:00:00Z"
```

**2. Policy Resource** (`patronus.io/v1/Policy`):
```yaml
apiVersion: patronus.io/v1
kind: Policy
metadata:
  name: prefer-low-latency
spec:
  siteSelector:
    matchLabels:
      tier: production
  rules:
    - action: route
      priority: high
      conditions:
        - type: application
          value: "video-streaming"
      pathSelection:
        strategy: lowest-latency
        thresholds:
          maxLatencyMs: 50
```

**3. Peer Resource** (`patronus.io/v1/Peer`):
```yaml
apiVersion: patronus.io/v1
kind: Peer
metadata:
  name: peer-aws-site
spec:
  siteId: "site-789"
  endpoint:
    address: "10.0.1.100"
    port: 51822
  wireguard:
    publicKey: "base64-encoded-key"
  compression: true
  bfdEnabled: true
status:
  connected: true
  latencyMs: 25.3
  packetLoss: 0.1
```

#### Implementation Plan

**Phase 1: CRD Definitions** (Rust)
```rust
// crates/patronus-operator/src/crd/site.rs
use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(CustomResource, Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[kube(
    group = "patronus.io",
    version = "v1",
    kind = "Site",
    namespaced
)]
pub struct SiteSpec {
    pub site_id: String,
    pub display_name: String,
    pub region: String,
    pub tunnel_endpoint: TunnelEndpoint,
    pub peers: Vec<PeerReference>,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
pub struct TunnelEndpoint {
    pub address: String,
    pub port: u16,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
pub struct SiteStatus {
    pub phase: SitePhase,
    pub tunnels_up: u32,
    pub last_health_check: String,
}
```

**Phase 2: Reconciliation Loop**
```rust
// crates/patronus-operator/src/controller/site.rs
use kube::{
    api::{Api, ListParams, Patch, PatchParams},
    runtime::controller::{Action, Controller},
    Client, ResourceExt,
};

pub async fn reconcile_site(site: Arc<Site>, ctx: Arc<Context>) -> Result<Action> {
    let client = ctx.client.clone();
    let name = site.name_any();

    // 1. Ensure SD-WAN agent is running
    ensure_sdwan_agent(&client, &site).await?;

    // 2. Configure tunnels to peers
    configure_tunnels(&client, &site).await?;

    // 3. Update status
    update_site_status(&client, &name, &site).await?;

    // Requeue after 5 minutes
    Ok(Action::requeue(Duration::from_secs(300)))
}

async fn ensure_sdwan_agent(client: &Client, site: &Site) -> Result<()> {
    let deployment_api: Api<Deployment> = Api::namespaced(client.clone(), &site.namespace().unwrap());

    let deployment = Deployment {
        metadata: ObjectMeta {
            name: Some(format!("patronus-agent-{}", site.spec.site_id)),
            labels: Some(labels_for_site(site)),
            ..Default::default()
        },
        spec: Some(DeploymentSpec {
            replicas: Some(1),
            selector: LabelSelector {
                match_labels: Some(labels_for_site(site)),
                ..Default::default()
            },
            template: PodTemplateSpec {
                spec: Some(PodSpec {
                    containers: vec![Container {
                        name: "patronus-sdwan".to_string(),
                        image: Some("patronus/sdwan:latest".to_string()),
                        env: Some(vec![
                            EnvVar {
                                name: "SITE_ID".to_string(),
                                value: Some(site.spec.site_id.clone()),
                                ..Default::default()
                            },
                        ]),
                        ..Default::default()
                    }],
                    ..Default::default()
                }),
                ..Default::default()
            },
            ..Default::default()
        }),
        ..Default::default()
    };

    deployment_api.patch(&deployment.metadata.name.unwrap(), &PatchParams::apply("patronus-operator"), &Patch::Apply(&deployment)).await?;
    Ok(())
}
```

**Phase 3: Helm Chart Updates**
Already have basic Helm charts in `/operator/helm/patronus-operator/`. Need to add:
- CRD definitions in `crds/` directory
- Operator deployment with RBAC
- ServiceMonitor for Prometheus
- Webhook configurations (if needed)

**Benefits**:
- **Declarative Configuration**: GitOps-friendly
- **Auto-Scaling**: HPA based on metrics
- **Self-Healing**: Automatic recovery
- **Cloud-Native**: Native Kubernetes integration

---

### 3. 📊 Monitoring & Alerting (Option 3)

**Current State**:
- Prometheus metrics already exported (Sprint 41)
- No Grafana dashboards yet
- No alert rules configured

#### Grafana Dashboards

**Dashboard 1: Network Topology**
```json
{
  "dashboard": {
    "title": "Patronus SD-WAN Topology",
    "panels": [
      {
        "title": "Site Connectivity Map",
        "type": "nodeGraph",
        "targets": [
          {
            "expr": "patronus_tunnel_status{}"
          }
        ]
      },
      {
        "title": "Path Health Heatmap",
        "type": "heatmap",
        "targets": [
          {
            "expr": "patronus_path_health_score{}"
          }
        ]
      },
      {
        "title": "Active Tunnels",
        "type": "stat",
        "targets": [
          {
            "expr": "sum(patronus_tunnel_status{status=\"up\"})"
          }
        ]
      }
    ]
  }
}
```

**Dashboard 2: Performance Metrics**
- **Latency**: p50, p95, p99 percentiles per path
- **Packet Loss**: Time series graph
- **Throughput**: Bytes/sec per tunnel
- **Compression Ratio**: Current compression effectiveness
- **BFD Session Status**: Up/Down per path

**Dashboard 3: Failover Events**
- **Failover Timeline**: When failovers occurred
- **Failover Reasons**: Why failovers happened
- **MTTR**: Mean time to recovery
- **Path Quality**: Before and after failover

#### Prometheus Alert Rules

```yaml
# /operator/helm/patronus-operator/files/alerts.yaml
groups:
  - name: patronus-sdwan
    interval: 30s
    rules:
      # Path down alert
      - alert: PathDown
        expr: patronus_path_health_score < 50
        for: 2m
        labels:
          severity: warning
        annotations:
          summary: "Path {{ $labels.path_id }} is down"
          description: "Health score: {{ $value }}"

      # High packet loss
      - alert: HighPacketLoss
        expr: patronus_path_packet_loss_pct > 5
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High packet loss on path {{ $labels.path_id }}"
          description: "Packet loss: {{ $value }}%"

      # BFD session down
      - alert: BfdSessionDown
        expr: patronus_bfd_session_status{state="down"} == 1
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "BFD session down for path {{ $labels.path_id }}"

      # Compression degradation
      - alert: CompressionRatioDegraded
        expr: patronus_compression_ratio < 1.5
        for: 10m
        labels:
          severity: info
        annotations:
          summary: "Compression ratio below 1.5x"
          description: "Current ratio: {{ $value }}"

      # Failover loop detection
      - alert: FailoverLoop
        expr: rate(patronus_failover_events_total[5m]) > 0.1
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "Failover loop detected for policy {{ $labels.policy_id }}"
          description: "Too many failovers in short time"
```

#### Log Aggregation (ELK/Loki)

**Loki Configuration**:
```yaml
# Add to Helm values
loki:
  enabled: true
  persistence:
    size: 10Gi

promtail:
  enabled: true
  config:
    clients:
      - url: http://loki:3100/loki/api/v1/push
    scrapeConfigs:
      - job_name: patronus-sdwan
        kubernetes_sd_configs:
          - role: pod
        relabel_configs:
          - source_labels: [__meta_kubernetes_pod_label_app]
            target_label: app
          - source_labels: [__meta_kubernetes_pod_name]
            target_label: pod
```

---

### 4. 🚀 Advanced SD-WAN Features (Option 5)

#### 4.1 Application-Aware Routing with DPI

**Architecture**:
```
┌─────────────────────────────────────────┐
│         Packet Capture                   │
│  (captures first N packets of flow)      │
└──────────────┬──────────────────────────┘
               │
        ┌──────▼────────┐
        │  DPI Engine   │
        │  - HTTP/HTTPS │
        │  - DNS        │
        │  - Video      │
        │  - VoIP       │
        └──────┬────────┘
               │
        ┌──────▼────────────┐
        │  Application Map  │
        │  Flow -> App Type │
        └──────┬────────────┘
               │
        ┌──────▼───────────┐
        │  Policy Engine   │
        │  App -> Path     │
        └──────┬───────────┘
               │
        ┌──────▼────────┐
        │ Data Plane    │
        │ Forward packet│
        └───────────────┘
```

**Implementation Sketch**:
```rust
// crates/patronus-sdwan/src/dpi/mod.rs
pub mod classifier;
pub mod signatures;

use crate::types::FlowKey;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApplicationType {
    Web,              // HTTP/HTTPS
    Video,            // YouTube, Netflix, etc.
    VoIP,             // SIP, RTP
    Gaming,           // Low-latency gaming
    FileTransfer,     // FTP, SCP
    Database,         // MySQL, PostgreSQL
    Unknown,
}

pub struct DpiEngine {
    classifiers: Vec<Box<dyn Classifier>>,
    flow_cache: Arc<RwLock<HashMap<FlowKey, ApplicationType>>>,
}

impl DpiEngine {
    pub fn classify_packet(&self, packet: &[u8], flow: &FlowKey) -> ApplicationType {
        // Check cache first
        if let Some(app_type) = self.flow_cache.read().unwrap().get(flow) {
            return app_type.clone();
        }

        // Run classifiers
        for classifier in &self.classifiers {
            if let Some(app_type) = classifier.classify(packet) {
                // Cache result
                self.flow_cache.write().unwrap().insert(flow.clone(), app_type.clone());
                return app_type;
            }
        }

        ApplicationType::Unknown
    }
}

// HTTP classifier
pub struct HttpClassifier;

impl Classifier for HttpClassifier {
    fn classify(&self, packet: &[u8]) -> Option<ApplicationType> {
        // Check for HTTP methods
        if packet.starts_with(b"GET ") || packet.starts_with(b"POST ") {
            return Some(ApplicationType::Web);
        }

        // Check for video streaming patterns
        if packet.windows(10).any(|w| w == b"video/mp4" || w == b"youtube") {
            return Some(ApplicationType::Video);
        }

        None
    }
}
```

**Policy Integration**:
```rust
// Application-specific policies
pub struct AppAwarePolicy {
    pub app_type: ApplicationType,
    pub path_strategy: PathStrategy,
    pub qos_class: QosClass,
}

impl AppAwarePolicy {
    pub fn select_path(&self, available_paths: &[PathHealth]) -> PathId {
        match self.path_strategy {
            PathStrategy::LowestLatency => {
                available_paths.iter()
                    .min_by(|a, b| a.latency_ms.partial_cmp(&b.latency_ms).unwrap())
                    .map(|p| p.path_id.clone())
                    .unwrap()
            }
            PathStrategy::HighestBandwidth => {
                // Select path with most available bandwidth
                // ...
            }
            PathStrategy::LeastCost => {
                // Select cheapest path
                // ...
            }
        }
    }
}
```

#### 4.2 Dynamic Path Selection with SLA Measurement

**Real-Time SLA Tracking**:
```rust
// crates/patronus-sdwan/src/sla/mod.rs
use std::time::{Duration, Instant};

pub struct SlaMonitor {
    measurements: Arc<RwLock<HashMap<PathId, SlaMetrics>>>,
    config: SlaConfig,
}

#[derive(Debug, Clone)]
pub struct SlaMetrics {
    pub latency_p50: f64,
    pub latency_p95: f64,
    pub latency_p99: f64,
    pub packet_loss: f64,
    pub jitter: f64,
    pub availability: f64,  // Uptime percentage
    pub last_update: Instant,
}

#[derive(Debug, Clone)]
pub struct SlaConfig {
    pub max_latency_ms: f64,
    pub max_packet_loss_pct: f64,
    pub max_jitter_ms: f64,
    pub min_availability_pct: f64,
}

impl SlaMonitor {
    pub async fn check_sla_compliance(&self, path_id: &PathId) -> bool {
        let metrics = self.measurements.read().await;

        if let Some(m) = metrics.get(path_id) {
            m.latency_p95 <= self.config.max_latency_ms
                && m.packet_loss <= self.config.max_packet_loss_pct
                && m.jitter <= self.config.max_jitter_ms
                && m.availability >= self.config.min_availability_pct
        } else {
            false
        }
    }

    pub async fn get_sla_violations(&self) -> Vec<(PathId, Vec<String>)> {
        let metrics = self.measurements.read().await;
        let mut violations = Vec::new();

        for (path_id, m) in metrics.iter() {
            let mut reasons = Vec::new();

            if m.latency_p95 > self.config.max_latency_ms {
                reasons.push(format!("Latency {} > {}", m.latency_p95, self.config.max_latency_ms));
            }

            if m.packet_loss > self.config.max_packet_loss_pct {
                reasons.push(format!("Packet loss {}% > {}%", m.packet_loss, self.config.max_packet_loss_pct));
            }

            if !reasons.is_empty() {
                violations.push((path_id.clone(), reasons));
            }
        }

        violations
    }
}
```

#### 4.3 QoS and Traffic Shaping

**Traffic Classes**:
```rust
// crates/patronus-sdwan/src/qos/mod.rs
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum QosClass {
    RealTime = 0,      // VoIP, gaming - highest priority
    Interactive = 1,   // Video conferencing
    Streaming = 2,     // Video streaming
    Standard = 3,      // Web browsing
    Bulk = 4,          // File transfers - lowest priority
}

pub struct QosManager {
    queues: Arc<RwLock<HashMap<QosClass, PacketQueue>>>,
    config: QosConfig,
}

#[derive(Debug, Clone)]
pub struct QosConfig {
    pub bandwidth_limit_mbps: u64,
    pub class_weights: HashMap<QosClass, u32>,
}

impl QosManager {
    pub async fn enqueue_packet(&self, packet: Packet, qos_class: QosClass) -> Result<()> {
        let mut queues = self.queues.write().await;

        let queue = queues.entry(qos_class).or_insert_with(|| PacketQueue::new(qos_class));

        if queue.len() >= queue.max_size() {
            // Drop packet (tail drop)
            return Err(QosError::QueueFull);
        }

        queue.push(packet);
        Ok(())
    }

    pub async fn dequeue_packet(&self) -> Option<(Packet, QosClass)> {
        let mut queues = self.queues.write().await;

        // Weighted round-robin scheduling
        for qos_class in [
            QosClass::RealTime,
            QosClass::Interactive,
            QosClass::Streaming,
            QosClass::Standard,
            QosClass::Bulk,
        ] {
            if let Some(queue) = queues.get_mut(&qos_class) {
                if let Some(packet) = queue.pop() {
                    return Some((packet, qos_class));
                }
            }
        }

        None
    }
}
```

**Traffic Shaping**:
```rust
// Token bucket algorithm for rate limiting
pub struct TokenBucket {
    capacity: u64,      // Maximum tokens
    tokens: Arc<RwLock<u64>>,  // Current tokens
    refill_rate: u64,   // Tokens per second
    last_refill: Arc<RwLock<Instant>>,
}

impl TokenBucket {
    pub async fn consume(&self, tokens: u64) -> bool {
        self.refill().await;

        let mut current = self.tokens.write().await;
        if *current >= tokens {
            *current -= tokens;
            true
        } else {
            false
        }
    }

    async fn refill(&self) {
        let mut last = self.last_refill.write().await;
        let now = Instant::now();
        let elapsed = now.duration_since(*last);

        let new_tokens = (elapsed.as_secs_f64() * self.refill_rate as f64) as u64;

        if new_tokens > 0 {
            let mut tokens = self.tokens.write().await;
            *tokens = (*tokens + new_tokens).min(self.capacity);
            *last = now;
        }
    }
}
```

---

## Sprint Status Summary

### Completed (25%)
✅ Dashboard compilation fixed (axum version conflicts resolved)

### In Progress (0%)
🔄 Kubernetes Operator - Architecture designed, implementation pending
🔄 Monitoring & Alerting - Design complete, implementation pending
🔄 Advanced SD-WAN - Architecture designed, implementation pending

### Pending (75%)
- Kubernetes Operator implementation
- CRD generation and registration
- Reconciliation loop
- Grafana dashboard creation
- Prometheus alert rules
- DPI engine implementation
- SLA monitoring
- QoS and traffic shaping

---

## Next Steps

### Immediate (Next Session)
1. Implement Kubernetes CRDs in Rust
2. Create basic reconciliation controller
3. Generate Grafana dashboard JSON
4. Add Prometheus alert rules to Helm chart

### Short-term (Sprint 43 Continuation)
1. Complete K8s operator with full reconciliation
2. Deploy Grafana dashboards
3. Test Prometheus alerts
4. Begin DPI classifier implementation

### Medium-term (Sprint 44+)
1. Complete DPI engine with multiple classifiers
2. Implement SLA monitoring
3. Add QoS and traffic shaping
4. Performance testing of all features

---

## Code Metrics

- **Files Modified**: 3
- **Dependencies Updated**: 2
- **Compilation Status**: ✅ Working
- **Warnings**: 69 (non-blocking, mostly unused code)

---

## Architecture Decisions

### Decision 1: Kubernetes Operator in Rust
**Rationale**:
- Consistency with rest of codebase
- Type safety for CRD handling
- Performance benefits
- `kube-rs` is mature and well-supported

### Decision 2: Separate DPI Module
**Rationale**:
- Keep data plane focused on forwarding
- DPI can be optional feature
- Easier to test and maintain

### Decision 3: Token Bucket for Traffic Shaping
**Rationale**:
- Industry-standard algorithm
- Simple and efficient
- Supports burst traffic well

---

## Conclusion

Sprint 43 began with fixing critical compilation issues in the dashboard (✅ complete). The remaining work involves:

1. **Kubernetes Operator**: Full implementation with CRDs and reconciliation
2. **Monitoring**: Grafana dashboards and Prometheus alerts
3. **Advanced Routing**: DPI, SLA monitoring, QoS

These features will make Patronus a production-ready, cloud-native SD-WAN solution with enterprise-grade observability and advanced traffic management.

**Estimated Completion**: Sprint 43 will continue into the next session to complete the Kubernetes operator and monitoring implementation.
