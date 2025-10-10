# Patronus SD-WAN Enterprise Dashboard Architecture

## Executive Summary

The Patronus SD-WAN Enterprise Dashboard provides centralized visibility and management for multi-site SD-WAN deployments. It aggregates real-time metrics from all sites, visualizes network topology, enforces policies, and enables administrators to monitor and control the entire mesh network from a single interface.

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                     Browser (Web UI)                            │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐         │
│  │  Topology    │  │   Metrics    │  │   Policies   │         │
│  │  Viewer      │  │  Dashboard   │  │   Editor     │         │
│  └──────────────┘  └──────────────┘  └──────────────┘         │
└─────────────────────────────┬───────────────────────────────────┘
                              │ WebSocket + REST API
                              │
┌─────────────────────────────▼───────────────────────────────────┐
│              Patronus Dashboard Server (Rust/Axum)              │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │                    API Layer                             │  │
│  │  - REST endpoints (/api/sites, /api/paths, /api/flows)  │  │
│  │  - WebSocket streams (real-time metrics)                │  │
│  │  - GraphQL (optional, for complex queries)              │  │
│  └──────────────────────────────────────────────────────────┘  │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │              Aggregation Engine                          │  │
│  │  - Multi-site metrics collection                        │  │
│  │  - Time-series data storage (InfluxDB/TimescaleDB)      │  │
│  │  - Alert evaluation                                     │  │
│  └──────────────────────────────────────────────────────────┘  │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │            Control Plane (Configuration)                 │  │
│  │  - Policy distribution                                   │  │
│  │  - Site registration                                     │  │
│  │  - Cluster coordination                                  │  │
│  └──────────────────────────────────────────────────────────┘  │
└─────────────────────────────┬───────────────────────────────────┘
                              │
        ┌─────────────────────┼─────────────────────┐
        │                     │                     │
        ▼                     ▼                     ▼
┌────────────────┐    ┌────────────────┐    ┌────────────────┐
│   Site 1 (HQ)  │    │ Site 2 (East)  │    │ Site 3 (West)  │
│  - SD-WAN Agent│    │ - SD-WAN Agent │    │ - SD-WAN Agent │
│  - Metrics     │    │ - Metrics      │    │ - Metrics      │
│  - WireGuard   │    │ - WireGuard    │    │ - WireGuard    │
└────────────────┘    └────────────────┘    └────────────────┘
```

## Core Components

### 1. Web Frontend

**Technology Stack:**
- **Framework**: Vanilla JavaScript + Web Components (lightweight, no build step)
- **Charts**: Chart.js (already integrated)
- **Topology**: D3.js or Cytoscape.js (network graphs)
- **Real-time**: Native WebSocket API
- **Styling**: Tailwind CSS (utility-first, consistent with existing UI)

**Key Pages:**

#### 1.1 Dashboard Overview (`/dashboard`)
```
┌─────────────────────────────────────────────────────────────┐
│  Patronus SD-WAN Dashboard                       Admin ▼   │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │
│  │ Total Sites  │  │ Active Paths │  │ Avg Latency  │     │
│  │     42       │  │     156      │  │   12.3 ms    │     │
│  └──────────────┘  └──────────────┘  └──────────────┘     │
│                                                             │
│  Network Topology                                           │
│  ┌───────────────────────────────────────────────────────┐ │
│  │         [Site-HQ]                                     │ │
│  │            │ \  \                                      │ │
│  │            │  \  \____                                 │ │
│  │            │   \      \____                            │ │
│  │            │    \          \                           │ │
│  │       [Site-East] [Site-West] [Site-Cloud]           │ │
│  │                                                        │ │
│  │  Legend: Green=Up  Yellow=Degraded  Red=Down         │ │
│  └───────────────────────────────────────────────────────┘ │
│                                                             │
│  Recent Events                    Active Flows (Top 10)    │
│  ┌──────────────────────────┐    ┌─────────────────────┐  │
│  │ 14:32 Path HQ→East UP    │    │ 10.1.1.5→10.2.1.3  │  │
│  │ 14:28 Policy added       │    │ 10.1.1.7→10.3.2.1  │  │
│  │ 14:15 Site-Cloud joined  │    │ ...                 │  │
│  └──────────────────────────┘    └─────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

#### 1.2 Network Topology (`/topology`)
Interactive graph visualization:
- **Nodes**: Sites (size based on # of paths)
- **Edges**: WireGuard tunnels (color = quality, width = bandwidth)
- **Interactions**:
  - Click site → show details panel
  - Click path → show metrics graph
  - Hover → tooltip with real-time stats
  - Drag to rearrange layout
- **Filters**: By site, by path status, by cluster

#### 1.3 Path Metrics (`/metrics`)
```
Site: [Headquarters ▼]  Path: [All Paths ▼]  Time: [Last 1 Hour ▼]

┌─────────────────────────────────────────────────────────────┐
│  Latency (ms)                                               │
│  100 │                                                       │
│   75 │     ╱╲                                                │
│   50 │────╱  ╲──────╱╲───────                               │
│   25 │              ╱  ╲──────╲                              │
│    0 └───────────────────────────────────────────────────── │
│      14:00  14:15  14:30  14:45  15:00                      │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│  Packet Loss (%)                                            │
│  [Similar chart]                                            │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│  Bandwidth (Mbps)                                           │
│  [Similar chart]                                            │
└─────────────────────────────────────────────────────────────┘
```

#### 1.4 Flow Analytics (`/flows`)
Real-time flow table with filtering:

| Source IP   | Dest IP     | Protocol | Port | Path        | Policy      | Status |
|-------------|-------------|----------|------|-------------|-------------|--------|
| 10.1.1.5    | 10.2.3.10   | TCP      | 443  | HQ→East     | Default     | Active |
| 10.1.1.7    | 10.3.2.5    | UDP      | 5060 | HQ→West     | VoIP/Video  | Active |
| 10.2.1.3    | 10.1.5.2    | TCP      | 8080 | East→HQ     | Denied      | Blocked|

**Features:**
- Search by IP, port, protocol
- Filter by policy, path, status
- Export to CSV
- Click flow → show routing decision details

#### 1.5 Policy Management (`/policies`)
```
NetworkPolicies                                      [+ New Policy]

┌─────────────────────────────────────────────────────────────┐
│  backend-ingress-policy               Enabled ▼  [Edit] [×] │
│  ─────────────────────────────────────────────────────────  │
│  Namespace: default                                         │
│  Pod Selector: app=backend                                  │
│  Type: Ingress                                              │
│  Rules: Allow from app=frontend on port 8080               │
│                                                             │
│  Applied to: 12 pods    Blocks: 47 flows (last 1h)         │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│  database-egress-policy              Disabled   [Edit] [×] │
│  ...                                                        │
└─────────────────────────────────────────────────────────────┘
```

**Policy Editor** (modal):
```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: backend-policy
  namespace: default
spec:
  podSelector:
    matchLabels:
      app: backend
  policyTypes:
  - Ingress
  ingress:
  - from:
    - podSelector:
        matchLabels:
          app: frontend
    ports:
    - protocol: TCP
      port: 8080
```

**Features:**
- YAML editor with syntax highlighting
- Visual policy builder (drag-and-drop)
- Policy simulation (test before apply)
- Conflict detection

#### 1.6 Multi-Cluster View (`/clusters`)
For Kubernetes deployments:

```
Clusters                                          [+ Add Cluster]

┌─────────────────────────────────────────────────────────────┐
│  aws-us-west-2                          Status: Connected   │
│  ─────────────────────────────────────────────────────────  │
│  Provider: AWS EKS                                          │
│  Nodes: 15      Pods: 247      Services: 42                │
│  CIDR: 10.244.0.0/16                                        │
│  Endpoints: 3.12.45.67:51820, 3.12.45.68:51820             │
│                                                             │
│  Cross-Cluster Traffic:                                     │
│  → gcp-us-central1:  145 Mbps  (12ms latency)              │
│  → onprem-dc1:        87 Mbps  (45ms latency)              │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│  gcp-us-central1                        Status: Connected   │
│  ...                                                        │
└─────────────────────────────────────────────────────────────┘
```

#### 1.7 Configuration (`/config`)
Global SD-WAN settings:
- Default routing policies
- Path quality thresholds
- Failover timers
- Monitoring intervals
- Alert rules

### 2. Backend API Server

**Technology:** Rust + Axum (consistent with existing Patronus web)

#### 2.1 REST API Endpoints

**Sites:**
```rust
GET    /api/v1/sites              // List all sites
GET    /api/v1/sites/:id          // Get site details
POST   /api/v1/sites              // Register new site
PUT    /api/v1/sites/:id          // Update site
DELETE /api/v1/sites/:id          // Remove site
```

**Paths:**
```rust
GET    /api/v1/paths              // List all paths
GET    /api/v1/paths/:id          // Get path details
GET    /api/v1/paths/:id/metrics  // Get path metrics history
POST   /api/v1/paths/:id/test     // Trigger manual path test
```

**Flows:**
```rust
GET    /api/v1/flows              // List active flows
GET    /api/v1/flows/:flow_key    // Get flow details
DELETE /api/v1/flows/:flow_key    // Remove flow (force re-eval)
```

**Policies:**
```rust
GET    /api/v1/policies           // List NetworkPolicies
GET    /api/v1/policies/:id       // Get policy details
POST   /api/v1/policies           // Create policy
PUT    /api/v1/policies/:id       // Update policy
DELETE /api/v1/policies/:id       // Delete policy
POST   /api/v1/policies/:id/simulate  // Simulate policy
```

**Routing Policies:**
```rust
GET    /api/v1/routing-policies   // List routing policies
POST   /api/v1/routing-policies   // Add routing policy
PUT    /api/v1/routing-policies/:id  // Update routing policy
DELETE /api/v1/routing-policies/:id  // Delete routing policy
```

**Clusters (Kubernetes):**
```rust
GET    /api/v1/clusters           // List all clusters
GET    /api/v1/clusters/:id       // Get cluster details
POST   /api/v1/clusters           // Register cluster
DELETE /api/v1/clusters/:id       // Unregister cluster
```

**Metrics Aggregation:**
```rust
GET    /api/v1/metrics/summary    // Dashboard summary stats
GET    /api/v1/metrics/timeseries // Time-series data
  ?metric=latency&site=hq&duration=1h
```

#### 2.2 WebSocket Streams

Real-time updates via WebSocket:

```rust
// WebSocket endpoint: /ws/metrics
WS /ws/metrics
  → Subscribe to real-time metric updates
  ← JSON stream of metric updates

// Message format:
{
  "type": "path_metric",
  "timestamp": "2025-10-09T14:32:15Z",
  "path_id": "path-123",
  "metrics": {
    "latency_ms": 12.3,
    "jitter_ms": 2.1,
    "packet_loss_pct": 0.05,
    "bandwidth_mbps": 987.5,
    "score": 98
  }
}

// WebSocket endpoint: /ws/events
WS /ws/events
  → Subscribe to system events
  ← JSON stream of events

// Event types:
{
  "type": "site_joined",
  "timestamp": "2025-10-09T14:30:00Z",
  "site_id": "site-abc",
  "site_name": "branch-west"
}

{
  "type": "path_status_change",
  "timestamp": "2025-10-09T14:32:15Z",
  "path_id": "path-123",
  "old_status": "Up",
  "new_status": "Degraded",
  "reason": "High packet loss (2.3%)"
}

{
  "type": "policy_block",
  "timestamp": "2025-10-09T14:35:42Z",
  "flow": {"src": "10.1.1.5", "dst": "10.2.3.10", "port": 22},
  "policy_id": "policy-ssh-block",
  "policy_name": "Block SSH"
}
```

#### 2.3 GraphQL API (Optional)

For complex queries:

```graphql
query DashboardOverview {
  sites {
    id
    name
    status
    paths {
      id
      destination {
        id
        name
      }
      metrics {
        latency_ms
        score
      }
      status
    }
  }

  flowStats(last: "1h") {
    totalFlows
    blockedFlows
    topTalkers {
      sourceIp
      bytes
    }
  }
}
```

### 3. Metrics Aggregation Engine

**Architecture:**

```rust
pub struct MetricsAggregator {
    db: Arc<Database>,
    timeseries_db: Arc<TimeSeriesStore>,
    collectors: Vec<Arc<SiteCollector>>,
    running: Arc<RwLock<bool>>,
}

impl MetricsAggregator {
    pub async fn start(&self) -> Result<()> {
        // Start collection tasks
        for collector in &self.collectors {
            collector.start().await?;
        }

        // Start aggregation task
        tokio::spawn(self.aggregate_metrics());

        Ok(())
    }

    async fn aggregate_metrics(&self) {
        let mut interval = tokio::time::interval(Duration::from_secs(10));

        loop {
            interval.tick().await;

            // Collect from all sites
            let metrics = self.collect_all_sites().await;

            // Store in time-series DB
            self.timeseries_db.insert_batch(metrics).await;

            // Evaluate alerts
            self.check_alerts().await;
        }
    }
}
```

**Time-Series Storage Options:**

**Option A: InfluxDB** (recommended for large deployments)
- Optimized for time-series data
- Built-in downsampling and retention policies
- Powerful query language (Flux)
- Grafana integration

**Option B: TimescaleDB** (PostgreSQL extension)
- SQL interface (easier integration)
- Excellent compression
- Continuous aggregates
- Hybrid relational + time-series

**Option C: Embedded (SQLite + custom)**
- Lightweight, no external dependencies
- Good for small deployments (<50 sites)
- Limited query performance at scale

**Recommendation**: Start with SQLite (Option C) for simplicity, provide migration path to InfluxDB/TimescaleDB for large deployments.

### 4. Alert System

**Alert Rules:**

```rust
pub struct AlertRule {
    pub id: String,
    pub name: String,
    pub condition: AlertCondition,
    pub severity: AlertSeverity,
    pub notification: NotificationConfig,
}

pub enum AlertCondition {
    PathLatency { threshold_ms: f64, duration: Duration },
    PathLoss { threshold_pct: f64, duration: Duration },
    PathDown { path_id: PathId },
    SiteUnreachable { site_id: SiteId, duration: Duration },
    PolicyViolation { policy_id: PolicyId, count: u64, window: Duration },
}

pub enum AlertSeverity {
    Info,
    Warning,
    Critical,
}

pub struct NotificationConfig {
    pub email: Option<Vec<String>>,
    pub webhook: Option<String>,
    pub slack: Option<SlackConfig>,
    pub pagerduty: Option<PagerDutyConfig>,
}
```

**Alert Examples:**

```yaml
# High Latency Alert
- name: "High Latency - HQ to East"
  condition:
    type: PathLatency
    path_id: path-hq-east
    threshold_ms: 50
    duration: 5m
  severity: Warning
  notification:
    email: ["ops@example.com"]
    slack:
      channel: "#sd-wan-alerts"

# Path Down Alert
- name: "Path Down"
  condition:
    type: PathDown
  severity: Critical
  notification:
    pagerduty:
      service_key: "abc123"
```

### 5. Control Plane

Centralized configuration management:

```rust
pub struct ControlPlane {
    db: Arc<Database>,
    sites: Arc<RwLock<HashMap<SiteId, SiteAgent>>>,
}

impl ControlPlane {
    /// Distribute policy to all sites
    pub async fn distribute_policy(&self, policy: NetworkPolicy) -> Result<()> {
        let sites = self.sites.read().await;

        for (site_id, agent) in sites.iter() {
            agent.send_policy(&policy).await?;
        }

        Ok(())
    }

    /// Coordinate cluster-wide operations
    pub async fn coordinate_failover(&self, failed_path: PathId) -> Result<()> {
        // Identify affected flows
        let flows = self.db.get_flows_on_path(failed_path).await?;

        // Trigger re-routing on all affected sites
        for flow in flows {
            if let Some(agent) = self.sites.read().await.get(&flow.site_id) {
                agent.reroute_flow(&flow.key).await?;
            }
        }

        Ok(())
    }
}
```

## Data Models

### Dashboard-Specific Schemas

**Dashboard State:**
```sql
CREATE TABLE dashboard_config (
    id INTEGER PRIMARY KEY,
    user_id TEXT NOT NULL,
    layout JSON,  -- Saved dashboard layout
    preferences JSON,  -- User preferences
    created_at TIMESTAMP,
    updated_at TIMESTAMP
);
```

**Metrics History** (Time-Series):
```sql
-- For SQLite option (simplified)
CREATE TABLE metrics_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    path_id INTEGER NOT NULL,
    timestamp TIMESTAMP NOT NULL,
    latency_ms REAL,
    jitter_ms REAL,
    packet_loss_pct REAL,
    bandwidth_mbps REAL,
    score INTEGER,
    FOREIGN KEY (path_id) REFERENCES paths(id)
);

CREATE INDEX idx_metrics_timestamp ON metrics_history(timestamp DESC);
CREATE INDEX idx_metrics_path_time ON metrics_history(path_id, timestamp DESC);
```

**Events Log:**
```sql
CREATE TABLE events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TIMESTAMP NOT NULL,
    event_type TEXT NOT NULL,  -- site_joined, path_down, policy_block, etc.
    severity TEXT NOT NULL,     -- info, warning, critical
    source_id TEXT,             -- site_id, path_id, policy_id
    data JSON,                  -- Event-specific data
    acknowledged BOOLEAN DEFAULT FALSE,
    acknowledged_at TIMESTAMP,
    acknowledged_by TEXT
);

CREATE INDEX idx_events_timestamp ON events(timestamp DESC);
CREATE INDEX idx_events_type ON events(event_type);
```

**Alerts:**
```sql
CREATE TABLE alert_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    condition_type TEXT NOT NULL,
    condition_params JSON NOT NULL,
    severity TEXT NOT NULL,
    notification_config JSON NOT NULL,
    enabled BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP,
    updated_at TIMESTAMP
);

CREATE TABLE alert_instances (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id INTEGER NOT NULL,
    triggered_at TIMESTAMP NOT NULL,
    resolved_at TIMESTAMP,
    state TEXT NOT NULL,  -- triggered, acknowledged, resolved
    message TEXT,
    FOREIGN KEY (rule_id) REFERENCES alert_rules(id)
);
```

## Implementation Phases

### Phase 1: Core Dashboard (Sprint 16) ✅
**Goal**: Basic visibility into SD-WAN network

**Deliverables:**
- Dashboard server skeleton (Axum)
- REST API for sites, paths, metrics
- Simple web UI (overview + path metrics)
- SQLite time-series storage
- WebSocket real-time updates

**Acceptance Criteria:**
- View all sites and paths
- Real-time latency/jitter/loss graphs
- Site status indicators (up/down/degraded)

### Phase 2: Policy Management (Sprint 17)
**Goal**: Manage NetworkPolicies via UI

**Deliverables:**
- Policy CRUD API endpoints
- Policy editor UI (YAML + visual)
- Policy simulation/testing
- Flow analytics view

**Acceptance Criteria:**
- Create/edit/delete NetworkPolicies
- View policy enforcement stats
- Search and filter flows

### Phase 3: Topology & Alerts (Sprint 18)
**Goal**: Network visualization and monitoring

**Deliverables:**
- Interactive topology graph (D3.js/Cytoscape)
- Alert rule configuration
- Event log viewer
- Email/webhook notifications

**Acceptance Criteria:**
- Visual network map with real-time updates
- Configurable alert rules
- Alert notifications working

### Phase 4: Multi-Cluster (Sprint 19)
**Goal**: Kubernetes integration

**Deliverables:**
- Cluster management API
- Cross-cluster traffic view
- Service export/import UI
- Prometheus metrics export

**Acceptance Criteria:**
- Register multiple K8s clusters
- View cross-cluster traffic
- Export metrics to Prometheus

### Phase 5: Enterprise Features (Sprint 20+)
**Goal**: Production-ready features

**Deliverables:**
- RBAC (Role-Based Access Control)
- Audit logging
- Configuration backup/restore
- High availability (multi-master)
- Advanced analytics (ML-based anomaly detection)

## Technology Decisions

### Frontend Stack

**Framework Choice: Web Components + Vanilla JS**

**Rationale:**
- No build step required
- Lightweight (fast page loads)
- Future-proof (web standards)
- Easier to maintain long-term
- Consistent with existing Patronus web UI philosophy

**Alternative Considered**: React/Vue
- Rejected: Adds build complexity, larger bundle size

### Backend Stack

**Framework: Axum (Rust)**

**Rationale:**
- Consistent with existing codebase
- Excellent performance
- Type safety
- WebSocket support built-in
- Easy integration with SD-WAN modules

### Charting Library

**Choice: Chart.js**

**Rationale:**
- Already integrated in Patronus web
- Simple API
- Good performance for our use case
- Responsive design

**Alternative Considered**: D3.js
- Use D3.js specifically for topology graph (more flexible)
- Chart.js for standard charts (easier)

### Real-Time Communication

**Choice: WebSocket**

**Rationale:**
- Bidirectional communication
- Low latency (<10ms)
- Efficient for continuous metric streams
- Native browser support

**Alternative Considered**: Server-Sent Events (SSE)
- Rejected: Unidirectional only, less flexible

### Time-Series Storage

**Phase 1: SQLite** (embedded)
**Phase 2+: Optional InfluxDB/TimescaleDB**

**Rationale:**
- Start simple (SQLite)
- Migrate to specialized DB as needed
- Provide flexibility for different deployment sizes

## Security Considerations

### Authentication

**Method**: Session-based + JWT

```rust
POST /api/v1/auth/login
{
  "username": "admin",
  "password": "***"
}

Response:
{
  "token": "eyJhbGciOiJIUzI1NiIs...",
  "expires_at": "2025-10-10T14:00:00Z"
}

// All subsequent requests:
Authorization: Bearer eyJhbGciOiJIUzI1NiIs...
```

### Authorization (RBAC)

**Roles:**
- **Admin**: Full access (read/write/delete)
- **Operator**: Read/write (no delete)
- **Viewer**: Read-only

**Permissions:**
```rust
pub enum Permission {
    ViewSites,
    ManageSites,
    ViewPaths,
    TestPaths,
    ViewFlows,
    DeleteFlows,
    ViewPolicies,
    ManagePolicies,
    ViewMetrics,
    ManageAlerts,
    ViewConfig,
    ManageConfig,
}
```

### API Rate Limiting

```rust
// Per-user rate limits
const RATE_LIMIT_REQUESTS_PER_MINUTE: u32 = 100;
const RATE_LIMIT_WEBSOCKET_MESSAGES_PER_SECOND: u32 = 50;
```

### TLS/HTTPS

**Required for production:**
- Dashboard server HTTPS only
- WebSocket over WSS
- Certificate management (Let's Encrypt)

### Audit Logging

All administrative actions logged:

```sql
CREATE TABLE audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TIMESTAMP NOT NULL,
    user_id TEXT NOT NULL,
    action TEXT NOT NULL,  -- create_policy, delete_site, etc.
    resource_type TEXT NOT NULL,
    resource_id TEXT,
    changes JSON,  -- Before/after state
    ip_address TEXT,
    user_agent TEXT
);
```

## Deployment Architecture

### Single-Server Deployment (Small)

```
┌─────────────────────────────────┐
│   Dashboard Server (Port 8443)  │
│   - Axum HTTP/WebSocket         │
│   - SQLite database             │
│   - Static file serving         │
└────────────┬────────────────────┘
             │
    ┌────────┴────────┐
    ▼                 ▼
[Site 1]          [Site 2]
```

### Multi-Server Deployment (Large)

```
       ┌──────────────────┐
       │  Load Balancer   │
       │  (nginx/HAProxy) │
       └────────┬─────────┘
                │
        ┌───────┴────────┐
        │                │
        ▼                ▼
┌──────────────┐  ┌──────────────┐
│ Dashboard #1 │  │ Dashboard #2 │
│ (Active)     │  │ (Standby)    │
└──────┬───────┘  └──────┬───────┘
       │                 │
       └────────┬────────┘
                │
         ┌──────▼──────┐
         │  PostgreSQL │
         │ (TimescaleDB)│
         └─────────────┘
                │
         ┌──────▼──────┐
         │  InfluxDB   │
         │ (Metrics)   │
         └─────────────┘
```

## Performance Targets

| Metric | Target | Measurement |
|--------|--------|-------------|
| Page Load Time | < 1s | First contentful paint |
| API Response Time | < 100ms | p95 latency |
| WebSocket Latency | < 50ms | Message delivery time |
| Dashboard Refresh | 1-5s | Configurable interval |
| Max Concurrent Users | 100+ | Load testing |
| Max Sites Managed | 1000+ | Stress testing |
| Metrics Retention | 90 days | Configurable |

## Monitoring & Observability

### Dashboard Metrics (Self-Monitoring)

Export Prometheus metrics about the dashboard itself:

```
# HTTP request metrics
dashboard_http_requests_total{method="GET",path="/api/v1/sites",status="200"}
dashboard_http_request_duration_seconds{method="GET",path="/api/v1/sites"}

# WebSocket metrics
dashboard_websocket_connections{type="metrics"}
dashboard_websocket_messages_total{type="metrics",direction="inbound"}

# Database metrics
dashboard_db_query_duration_seconds{query="list_sites"}
dashboard_db_connections_active

# Business metrics
dashboard_sites_total
dashboard_paths_total
dashboard_active_flows_total
dashboard_policies_total
```

## Migration Path

### From Standalone SD-WAN to Dashboard

**Step 1**: Deploy dashboard server
**Step 2**: Register existing sites (auto-discovery or manual)
**Step 3**: Start collecting metrics
**Step 4**: Migrate policies (optional, or manage both)

**Backward Compatibility**: Dashboard is optional. SD-WAN sites continue to work independently if dashboard is down.

## Future Enhancements

### AI/ML Features
- Anomaly detection (unusual traffic patterns)
- Predictive path quality forecasting
- Auto-tuning of routing policies
- Capacity planning recommendations

### Advanced Analytics
- Flow correlation analysis
- Security threat detection
- Cost optimization (cloud egress)
- SLA compliance reporting

### Integration Ecosystem
- Prometheus/Grafana (metrics)
- Elastic Stack (log aggregation)
- ServiceNow/Jira (ticketing)
- Slack/Teams (ChatOps)
- Terraform (IaC)

## Conclusion

The Patronus SD-WAN Enterprise Dashboard provides a comprehensive management interface that scales from small deployments (3-5 sites) to enterprise deployments (100+ sites, multiple Kubernetes clusters). The phased implementation approach allows incremental delivery of value while maintaining architectural flexibility for future growth.

**Next Steps:**
1. Implement Phase 1 (Core Dashboard) in Sprint 16
2. Gather user feedback from initial deployment
3. Iterate on UI/UX based on real-world usage
4. Expand to Phases 2-5 based on customer priorities

---

**Document Version**: 1.0
**Last Updated**: October 9, 2025
**Author**: Patronus Project (with Claude Code)
