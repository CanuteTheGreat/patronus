# Sprint 31 API Reference

Complete API documentation for health monitoring, automatic failover, and metrics export features.

## Table of Contents

1. [Health Monitoring API](#health-monitoring-api)
2. [Failover API](#failover-api)
3. [Export API](#export-api)
4. [Types Reference](#types-reference)

---

## Health Monitoring API

### HealthMonitor

Main interface for path health monitoring.

#### Constructor

```rust
pub async fn new(
    db: Arc<Database>,
    config: HealthConfig,
) -> Result<Self, Box<dyn std::error::Error + Send + Sync>>
```

Creates a new health monitor with the specified configuration.

**Parameters**:
- `db` - Database connection for persistence
- `config` - Health monitoring configuration

**Returns**: `Result<HealthMonitor>`

**Example**:
```rust
let config = HealthConfig::default();
let monitor = HealthMonitor::new(db, config).await?;
```

#### check_path_health

```rust
pub async fn check_path_health(
    &self,
    path_id: &PathId,
    target: IpAddr,
) -> Result<PathHealth, Box<dyn std::error::Error + Send + Sync>>
```

Performs health check on a specific path.

**Parameters**:
- `path_id` - Identifier for the path
- `target` - Target IP address to probe

**Returns**: `Result<PathHealth>` containing current health metrics

**Example**:
```rust
let health = monitor.check_path_health(&path_id, "8.8.8.8".parse()?).await?;
println!("Health score: {}", health.health_score);
```

#### get_path_health

```rust
pub async fn get_path_health(&self, path_id: &PathId) -> Option<PathHealth>
```

Gets cached health data for a path.

**Parameters**:
- `path_id` - Identifier for the path

**Returns**: `Option<PathHealth>` - `None` if path hasn't been checked

**Example**:
```rust
if let Some(health) = monitor.get_path_health(&path_id).await {
    println!("Cached health: {}", health.health_score);
}
```

#### get_all_health

```rust
pub async fn get_all_health(&self) -> HashMap<PathId, PathHealth>
```

Gets health data for all monitored paths.

**Returns**: `HashMap<PathId, PathHealth>` with all current health data

**Example**:
```rust
let all_health = monitor.get_all_health().await;
for (path_id, health) in all_health {
    println!("Path {}: {}", path_id, health.status.as_str());
}
```

#### get_health_history

```rust
pub async fn get_health_history(
    &self,
    path_id: &PathId,
    since: SystemTime,
    until: Option<SystemTime>,
) -> Result<Vec<PathHealth>, Box<dyn std::error::Error + Send + Sync>>
```

Retrieves historical health data from database.

**Parameters**:
- `path_id` - Identifier for the path
- `since` - Start time for history query
- `until` - Optional end time (defaults to now)

**Returns**: `Result<Vec<PathHealth>>` with historical records

**Example**:
```rust
let since = SystemTime::now() - Duration::from_secs(3600);
let history = monitor.get_health_history(&path_id, since, None).await?;
println!("Found {} historical records", history.len());
```

#### start_monitoring

```rust
pub fn start_monitoring(
    self: Arc<Self>,
    paths: HashMap<PathId, IpAddr>,
) -> tokio::task::JoinHandle<()>
```

Starts continuous background monitoring of paths.

**Parameters**:
- `paths` - Map of path IDs to target IP addresses

**Returns**: `JoinHandle` for the monitoring task

**Example**:
```rust
let mut paths = HashMap::new();
paths.insert(path1_id, "8.8.8.8".parse()?);
paths.insert(path2_id, "1.1.1.1".parse()?);

let handle = Arc::new(monitor).start_monitoring(paths);
```

#### get_stats

```rust
pub async fn get_stats(&self) -> HealthMonitorStats
```

Gets statistics about monitored paths.

**Returns**: `HealthMonitorStats` with path counts by status

**Example**:
```rust
let stats = monitor.get_stats().await;
println!("Total paths: {}", stats.total_paths);
println!("Healthy: {}", stats.healthy_paths);
```

### HealthConfig

Configuration for health monitoring.

```rust
pub struct HealthConfig {
    /// Interval between health checks in seconds
    pub check_interval_secs: u64,

    /// Number of probes per health check
    pub probes_per_check: usize,

    /// Timeout for each probe in milliseconds
    pub probe_timeout_ms: u64,

    /// Whether to persist health data to database
    pub persist_to_db: bool,

    /// Persist to DB every N checks (if persist_to_db is true)
    pub db_persist_interval: usize,
}
```

**Default values**:
```rust
HealthConfig {
    check_interval_secs: 10,
    probes_per_check: 5,
    probe_timeout_ms: 1000,
    persist_to_db: false,
    db_persist_interval: 10,
}
```

### PathHealth

Health metrics for a network path.

```rust
pub struct PathHealth {
    pub path_id: PathId,
    pub latency_ms: f64,
    pub packet_loss_pct: f64,
    pub jitter_ms: f64,
    pub health_score: f64,
    pub status: PathStatus,
    pub last_checked: SystemTime,
}
```

**Fields**:
- `path_id` - Path identifier
- `latency_ms` - Round-trip latency in milliseconds
- `packet_loss_pct` - Packet loss percentage (0-100)
- `jitter_ms` - Jitter (latency variance) in milliseconds
- `health_score` - Composite health score (0-100)
- `status` - Path status classification
- `last_checked` - Timestamp of last check

### PathStatus

Path health status classification.

```rust
pub enum PathStatus {
    Up,        // Health score 80-100
    Degraded,  // Health score 50-79
    Down,      // Health score 0-49
}
```

**Methods**:
```rust
pub fn as_str(&self) -> &'static str  // Returns "up", "degraded", or "down"
pub fn from_str(s: &str) -> Option<Self>  // Parse from string
```

---

## Failover API

### FailoverEngine

Main interface for automatic failover management.

#### Constructor

```rust
pub fn new(
    db: Arc<Database>,
    health_monitor: Arc<HealthMonitor>,
) -> Self
```

Creates a new failover engine.

**Parameters**:
- `db` - Database connection
- `health_monitor` - Health monitor for path quality data

**Returns**: `FailoverEngine`

**Example**:
```rust
let engine = FailoverEngine::new(db, health_monitor);
```

#### add_policy

```rust
pub async fn add_policy(
    &self,
    policy: FailoverPolicy,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
```

Adds a new failover policy.

**Parameters**:
- `policy` - Failover policy configuration

**Returns**: `Result<()>`

**Errors**: Returns error if policy validation fails

**Example**:
```rust
let policy = FailoverPolicy::new(
    1,
    "critical-traffic".to_string(),
    primary_path,
    vec![backup1, backup2],
);

engine.add_policy(policy).await?;
```

#### remove_policy

```rust
pub async fn remove_policy(
    &self,
    policy_id: u64,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
```

Removes a failover policy.

**Parameters**:
- `policy_id` - ID of policy to remove

**Returns**: `Result<()>`

**Example**:
```rust
engine.remove_policy(1).await?;
```

#### get_state

```rust
pub async fn get_state(&self, policy_id: u64) -> Option<FailoverState>
```

Gets current failover state for a policy.

**Parameters**:
- `policy_id` - Policy ID

**Returns**: `Option<FailoverState>` - `None` if policy doesn't exist

**Example**:
```rust
if let Some(state) = engine.get_state(1).await {
    println!("Using primary: {}", state.using_primary);
    println!("Failover count: {}", state.failover_count);
}
```

#### get_policies

```rust
pub async fn get_policies(&self) -> Vec<FailoverPolicy>
```

Gets all active failover policies.

**Returns**: `Vec<FailoverPolicy>` with all policies

**Example**:
```rust
let policies = engine.get_policies().await;
for policy in policies {
    println!("Policy {}: {}", policy.policy_id, policy.name);
}
```

#### start_monitoring

```rust
pub fn start_monitoring(self: Arc<Self>) -> tokio::task::JoinHandle<()>
```

Starts continuous failover monitoring loop.

**Returns**: `JoinHandle` for the monitoring task

**Example**:
```rust
let handle = Arc::new(engine).start_monitoring();
```

### FailoverPolicy

Failover policy configuration.

```rust
pub struct FailoverPolicy {
    pub policy_id: u64,
    pub name: String,
    pub primary_path_id: PathId,
    pub backup_path_ids: Vec<PathId>,
    pub failover_threshold: f64,
    pub failback_threshold: f64,
    pub failback_delay_secs: u64,
    pub enabled: bool,
}
```

**Constructor**:
```rust
pub fn new(
    policy_id: u64,
    name: String,
    primary_path_id: PathId,
    backup_path_ids: Vec<PathId>,
) -> Self
```

Creates a new policy with default thresholds:
- `failover_threshold`: 50.0
- `failback_threshold`: 80.0
- `failback_delay_secs`: 60

**Methods**:

```rust
pub fn should_failover(&self, primary_health_score: f64) -> bool
```
Returns `true` if health score triggers failover.

```rust
pub fn should_failback(&self, primary_health_score: f64) -> bool
```
Returns `true` if health score allows failback.

```rust
pub fn get_best_backup(&self, backup_health: &[(PathId, f64)]) -> Option<PathId>
```
Selects best available backup path based on health.

```rust
pub fn validate(&self) -> Result<(), String>
```
Validates policy configuration.

### FailoverState

Runtime state of a failover policy.

```rust
pub struct FailoverState {
    pub policy_id: u64,
    pub active_path_id: PathId,
    pub using_primary: bool,
    pub last_failover: Option<SystemTime>,
    pub primary_healthy_since: Option<SystemTime>,
    pub failover_count: u64,
}
```

**Methods**:

```rust
pub fn can_failback(&self, delay_secs: u64) -> bool
```
Checks if enough time has passed for failback.

```rust
pub fn mark_primary_healthy(&mut self)
```
Records that primary became healthy.

```rust
pub fn mark_primary_unhealthy(&mut self)
```
Records that primary became unhealthy.

### FailoverEvent

Audit record for failover events.

```rust
pub struct FailoverEvent {
    pub event_id: Option<u64>,
    pub policy_id: u64,
    pub event_type: FailoverEventType,
    pub from_path_id: Option<PathId>,
    pub to_path_id: Option<PathId>,
    pub reason: String,
    pub primary_health_score: Option<f64>,
    pub backup_health_score: Option<f64>,
    pub timestamp: SystemTime,
}
```

**Event Types**:
```rust
pub enum FailoverEventType {
    Triggered,       // Switched to backup
    Completed,       // Returned to primary
    Failed,          // No healthy backup available
    PolicyEnabled,   // Policy was enabled
    PolicyDisabled,  // Policy was disabled
}
```

**Constructor Methods**:
```rust
pub fn triggered(policy_id, from_path, to_path, primary_health, backup_health, reason) -> Self
pub fn completed(policy_id, to_path, primary_health, reason) -> Self
pub fn failed(policy_id, reason) -> Self
pub fn policy_enabled(policy_id) -> Self
pub fn policy_disabled(policy_id) -> Self
```

---

## Export API

### ExportManager

Unified interface for all export formats.

#### Constructor

```rust
pub fn new(
    db: Arc<Database>,
    health_monitor: Arc<HealthMonitor>,
    failover_engine: Arc<FailoverEngine>,
) -> Self
```

Creates a new export manager.

**Returns**: `ExportManager`

**Example**:
```rust
let export_mgr = ExportManager::new(db, health_monitor, failover_engine);
```

#### Accessors

```rust
pub fn prometheus(&self) -> &Arc<PrometheusExporter>
pub fn json(&self) -> &Arc<JsonExporter>
pub fn aggregator(&self) -> &Arc<MetricsAggregator>
```

Get references to individual exporters.

### PrometheusExporter

Prometheus metrics export.

#### export_metrics

```rust
pub async fn export_metrics(&self) -> String
```

Generates Prometheus metrics in exposition format.

**Returns**: `String` with Prometheus metrics

**Example**:
```rust
let prometheus = export_mgr.prometheus();
let metrics = prometheus.export_metrics().await;
println!("{}", metrics);
```

**Output Format**:
```
# HELP patronus_sdwan_path_health_score Path health score (0-100)
# TYPE patronus_sdwan_path_health_score gauge
patronus_sdwan_path_health_score{path_id="1"} 85.50

# HELP patronus_sdwan_path_latency_ms Path latency in milliseconds
# TYPE patronus_sdwan_path_latency_ms gauge
patronus_sdwan_path_latency_ms{path_id="1"} 25.30
```

### JsonExporter

JSON format export for REST APIs.

#### get_health_snapshot

```rust
pub async fn get_health_snapshot(&self) -> HealthSnapshot
```

Gets current health snapshot for all paths.

**Returns**: `HealthSnapshot` with timestamp and all path health data

**Example**:
```rust
let json_exporter = export_mgr.json();
let snapshot = json_exporter.get_health_snapshot().await;

let json = serde_json::to_string_pretty(&snapshot)?;
println!("{}", json);
```

**Output Format**:
```json
{
  "timestamp": 1633024800,
  "paths": [
    {
      "path_id": "1",
      "latency_ms": 25.3,
      "packet_loss_pct": 0.5,
      "jitter_ms": 2.1,
      "health_score": 85.5,
      "status": "up",
      "last_checked": 1633024800
    }
  ]
}
```

#### get_path_health_history

```rust
pub async fn get_path_health_history(
    &self,
    path_id: &PathId,
    since: SystemTime,
    until: Option<SystemTime>,
) -> Result<Vec<PathHealthJson>, Box<dyn std::error::Error + Send + Sync>>
```

Gets historical health data for a path.

**Parameters**:
- `path_id` - Path identifier
- `since` - Start time
- `until` - Optional end time

**Returns**: `Result<Vec<PathHealthJson>>`

#### get_failover_snapshot

```rust
pub async fn get_failover_snapshot(&self) -> FailoverSnapshot
```

Gets current failover snapshot with all policies and states.

**Returns**: `FailoverSnapshot` with policies and runtime state

**Output Format**:
```json
{
  "timestamp": 1633024800,
  "policies": [
    {
      "policy_id": 1,
      "name": "critical-traffic",
      "primary_path_id": "10",
      "backup_path_ids": ["20", "30"],
      "failover_threshold": 50.0,
      "failback_threshold": 80.0,
      "failback_delay_secs": 60,
      "enabled": true,
      "active_path_id": "10",
      "using_primary": true,
      "failover_count": 3
    }
  ]
}
```

#### get_failover_events

```rust
pub async fn get_failover_events(
    &self,
    policy_id: Option<u64>,
    limit: usize,
) -> Result<FailoverEventHistory, Box<dyn std::error::Error + Send + Sync>>
```

Gets failover event history.

**Parameters**:
- `policy_id` - Optional policy filter (None = all policies)
- `limit` - Maximum number of events to return

**Returns**: `Result<FailoverEventHistory>`

**Example**:
```rust
let history = json_exporter.get_failover_events(Some(1), 100).await?;
for event in history.events {
    println!("{}: {}", event.event_type, event.reason);
}
```

### MetricsAggregator

Time-series aggregation.

#### aggregate_path_metrics

```rust
pub async fn aggregate_path_metrics(
    &self,
    path_id: &PathId,
    period: AggregationPeriod,
) -> Result<AggregatedMetrics, Box<dyn std::error::Error + Send + Sync>>
```

Aggregates metrics for a path over time period.

**Parameters**:
- `path_id` - Path identifier
- `period` - Aggregation period

**Returns**: `Result<AggregatedMetrics>`

**Example**:
```rust
use patronus_sdwan::export::AggregationPeriod;

let aggregator = export_mgr.aggregator();
let metrics = aggregator.aggregate_path_metrics(
    &path_id,
    AggregationPeriod::Day
).await?;

println!("Sample count: {}", metrics.sample_count);
println!("Average latency: {:.2}ms", metrics.latency_avg);
println!("P95 latency: {:.2}ms", metrics.latency_p95);
println!("Uptime: {:.1}%", metrics.uptime_pct);
```

#### aggregate_all_paths

```rust
pub async fn aggregate_all_paths(
    &self,
    period: AggregationPeriod,
) -> Result<Vec<AggregatedMetrics>, Box<dyn std::error::Error + Send + Sync>>
```

Aggregates metrics for all paths.

**Parameters**:
- `period` - Aggregation period

**Returns**: `Result<Vec<AggregatedMetrics>>`

### AggregationPeriod

Time period for aggregation.

```rust
pub enum AggregationPeriod {
    Hour,                  // Last 60 minutes
    Day,                   // Last 24 hours
    Week,                  // Last 7 days
    Month,                 // Last 30 days
    Custom(u64),           // Custom duration in seconds
}
```

**Methods**:
```rust
pub fn duration(&self) -> Duration       // Get duration
pub fn as_str(&self) -> &'static str     // Get name
```

### AggregatedMetrics

Aggregated statistics for a path.

```rust
pub struct AggregatedMetrics {
    pub path_id: String,
    pub period: String,
    pub start_time: u64,
    pub end_time: u64,
    pub sample_count: u64,
    pub latency_avg: f64,
    pub latency_min: f64,
    pub latency_max: f64,
    pub latency_p95: f64,
    pub packet_loss_avg: f64,
    pub packet_loss_max: f64,
    pub jitter_avg: f64,
    pub jitter_max: f64,
    pub health_score_avg: f64,
    pub health_score_min: f64,
    pub uptime_pct: f64,
}
```

---

## Types Reference

### PathId

Unique identifier for a network path.

```rust
pub struct PathId(u64);

impl PathId {
    pub fn new(id: u64) -> Self
    pub fn as_u64(&self) -> u64
    pub fn from_string(s: &str) -> Result<Self, ParseIntError>
}

impl Display for PathId  // Converts to string
```

### SiteId

Unique identifier for a site (UUID-based).

```rust
pub struct SiteId(Uuid);

impl SiteId {
    pub fn generate() -> Self
    pub fn from_uuid(uuid: Uuid) -> Self
    pub fn as_uuid(&self) -> &Uuid
}

impl FromStr for SiteId  // Parse from string
impl Display for SiteId  // Convert to string
```

---

## Error Handling

All async methods return `Result<T, Box<dyn std::error::Error + Send + Sync>>`.

Common error scenarios:

1. **Database Errors**: SQLite connection or query failures
2. **Validation Errors**: Invalid policy configuration
3. **Network Errors**: Probe timeouts or failures (future)
4. **Serialization Errors**: JSON encoding/decoding failures

**Example Error Handling**:
```rust
match engine.add_policy(policy).await {
    Ok(()) => println!("Policy added successfully"),
    Err(e) => {
        if e.to_string().contains("validation") {
            eprintln!("Invalid policy configuration: {}", e);
        } else {
            eprintln!("Database error: {}", e);
        }
    }
}
```

---

## Thread Safety

All major types are designed for concurrent access:

- `HealthMonitor` - Thread-safe via `Arc<RwLock<>>`
- `FailoverEngine` - Thread-safe via `Arc<RwLock<>>`
- `ExportManager` - Thread-safe (read-only after creation)
- `Database` - Thread-safe via connection pooling

**Example Concurrent Usage**:
```rust
let monitor = Arc::new(HealthMonitor::new(db, config).await?);

// Multiple tasks can share the monitor
let monitor1 = Arc::clone(&monitor);
let monitor2 = Arc::clone(&monitor);

tokio::spawn(async move {
    monitor1.check_path_health(&path1, target1).await
});

tokio::spawn(async move {
    monitor2.check_path_health(&path2, target2).await
});
```

---

*API Reference v0.2.0-sprint31*
*Generated with [Claude Code](https://claude.com/claude-code)*
