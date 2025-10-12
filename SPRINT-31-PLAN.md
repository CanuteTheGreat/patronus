# Sprint 31: High Availability & Monitoring

**Sprint**: 31
**Focus**: High Availability Features
**Option**: A (High Availability Focus)
**Status**: 🟡 Planning → In Progress
**Start Date**: October 11, 2025

---

## Overview

Sprint 31 builds on Sprint 30's traffic statistics foundation to add production-grade high availability features. This sprint focuses on automatic failover, path health monitoring, and metrics export.

**Building on Sprint 30**:
- ✅ Traffic statistics infrastructure (Sprint 30)
- ✅ Flow tracking and counters (Sprint 30)
- ✅ Database persistence (Sprint 30)
- 🆕 Path health monitoring (Sprint 31)
- 🆕 Automatic failover (Sprint 31)
- 🆕 Metrics export (Sprint 31)

---

## Sprint Goals

### Primary Goals

1. **Path Health Monitoring**
   - Track per-path latency, packet loss, and jitter
   - Implement health scoring algorithm
   - Detect and log path degradation
   - Store historical health data

2. **Automatic Routing Failover**
   - Switch to backup path on primary failure
   - Configurable health thresholds
   - Automatic failback when primary recovers
   - Event logging and notifications

3. **Traffic Statistics Export**
   - Prometheus metrics endpoint
   - JSON export API
   - Historical data queries
   - Grafana-compatible format

### Success Criteria

- ✅ Path health monitoring operational with <500ms overhead
- ✅ Failover triggers within 5 seconds of path failure
- ✅ Prometheus metrics endpoint functional
- ✅ 20+ comprehensive tests passing (100%)
- ✅ Full documentation delivered
- ✅ Zero regressions from Sprint 30

---

## Features Breakdown

### Feature 1: Path Health Monitoring

**Description**: Real-time monitoring of network path health with automated detection of degradation.

**Components**:

1. **Health Metrics Collection**
   ```rust
   pub struct PathHealth {
       pub path_id: PathId,
       pub latency_ms: f64,           // RTT latency
       pub packet_loss_pct: f64,      // Packet loss percentage
       pub jitter_ms: f64,            // Jitter (variance in latency)
       pub health_score: f64,         // 0.0-100.0 composite score
       pub last_checked: SystemTime,
       pub status: PathStatus,        // Up, Degraded, Down
   }

   pub enum PathStatus {
       Up,        // Healthy, meeting thresholds
       Degraded,  // Performance issues but usable
       Down,      // Failed health checks
   }
   ```

2. **Health Check Engine**
   - Periodic ICMP/UDP probes to measure latency
   - Packet loss detection via sequence tracking
   - Jitter calculation from latency variance
   - Configurable check intervals (default: 10s)

3. **Health Scoring Algorithm**
   ```
   score = 100.0

   if latency > threshold_latency:
       score -= (latency / threshold_latency) * 30

   if packet_loss > threshold_loss:
       score -= (packet_loss / threshold_loss) * 40

   if jitter > threshold_jitter:
       score -= (jitter / threshold_jitter) * 30

   score = max(0.0, score)

   Status:
     score >= 80.0: Up
     score >= 50.0: Degraded
     score < 50.0:  Down
   ```

4. **Database Schema**
   ```sql
   CREATE TABLE sdwan_path_health (
       health_id INTEGER PRIMARY KEY AUTOINCREMENT,
       path_id TEXT NOT NULL,
       timestamp INTEGER NOT NULL,
       latency_ms REAL NOT NULL,
       packet_loss_pct REAL NOT NULL,
       jitter_ms REAL NOT NULL,
       health_score REAL NOT NULL,
       status TEXT NOT NULL,
       FOREIGN KEY (path_id) REFERENCES sdwan_paths(path_id)
   );

   CREATE INDEX idx_path_health_path_time
       ON sdwan_path_health(path_id, timestamp);
   ```

**GraphQL API**:
```graphql
type PathHealth {
  pathId: ID!
  latencyMs: Float!
  packetLossPct: Float!
  jitterMs: Float!
  healthScore: Float!
  status: PathStatus!
  lastChecked: String!
}

enum PathStatus {
  UP
  DEGRADED
  DOWN
}

type Query {
  pathHealth(pathId: ID!): PathHealth
  allPathsHealth: [PathHealth!]!
  pathHealthHistory(
    pathId: ID!
    since: String!
    until: String
  ): [PathHealth!]!
}
```

**Performance Requirements**:
- Health check overhead: <500ms per path
- Database writes: Batched every 60s
- Memory: <1MB per 100 paths
- Query response: <100ms for current health

---

### Feature 2: Automatic Routing Failover

**Description**: Automatic path switching based on health status with configurable policies.

**Components**:

1. **Failover Policy**
   ```rust
   pub struct FailoverPolicy {
       pub policy_id: u64,
       pub name: String,
       pub primary_path_id: PathId,
       pub backup_path_ids: Vec<PathId>,
       pub failover_threshold: f64,    // Health score trigger
       pub failback_threshold: f64,    // Recovery threshold
       pub failback_delay_secs: u64,   // Delay before failback
       pub enabled: bool,
   }
   ```

2. **Failover Engine**
   - Monitor primary path health continuously
   - Trigger failover when health < failover_threshold
   - Select best backup path by health score
   - Update routing tables atomically
   - Log failover events

3. **Failback Logic**
   - Monitor primary path recovery
   - Wait for stabilization period (failback_delay_secs)
   - Ensure sustained health > failback_threshold
   - Automatic revert to primary path
   - Prevent flapping with hysteresis

4. **Event System**
   ```rust
   pub enum FailoverEvent {
       FailoverTriggered {
           policy_id: u64,
           from_path: PathId,
           to_path: PathId,
           reason: String,
           timestamp: SystemTime,
       },
       FailbackCompleted {
           policy_id: u64,
           to_path: PathId,
           timestamp: SystemTime,
       },
       FailoverFailed {
           policy_id: u64,
           reason: String,
           timestamp: SystemTime,
       },
   }
   ```

5. **Database Schema**
   ```sql
   CREATE TABLE sdwan_failover_policies (
       policy_id INTEGER PRIMARY KEY AUTOINCREMENT,
       name TEXT NOT NULL,
       primary_path_id TEXT NOT NULL,
       backup_path_ids TEXT NOT NULL,  -- JSON array
       failover_threshold REAL NOT NULL DEFAULT 50.0,
       failback_threshold REAL NOT NULL DEFAULT 80.0,
       failback_delay_secs INTEGER NOT NULL DEFAULT 60,
       enabled INTEGER NOT NULL DEFAULT 1,
       FOREIGN KEY (primary_path_id) REFERENCES sdwan_paths(path_id)
   );

   CREATE TABLE sdwan_failover_events (
       event_id INTEGER PRIMARY KEY AUTOINCREMENT,
       policy_id INTEGER NOT NULL,
       event_type TEXT NOT NULL,
       from_path_id TEXT,
       to_path_id TEXT,
       reason TEXT,
       timestamp INTEGER NOT NULL,
       FOREIGN KEY (policy_id) REFERENCES sdwan_failover_policies(policy_id)
   );
   ```

**GraphQL API**:
```graphql
type FailoverPolicy {
  policyId: ID!
  name: String!
  primaryPathId: ID!
  backupPathIds: [ID!]!
  failoverThreshold: Float!
  failbackThreshold: Float!
  failbackDelaySecs: Int!
  enabled: Boolean!
}

type FailoverEvent {
  eventId: ID!
  policyId: ID!
  eventType: String!
  fromPathId: ID
  toPathId: ID
  reason: String
  timestamp: String!
}

type Mutation {
  createFailoverPolicy(
    name: String!
    primaryPathId: ID!
    backupPathIds: [ID!]!
    failoverThreshold: Float
    failbackThreshold: Float
    failbackDelaySecs: Int
  ): FailoverPolicy!

  updateFailoverPolicy(
    policyId: ID!
    enabled: Boolean
    failoverThreshold: Float
    failbackThreshold: Float
  ): FailoverPolicy!

  deleteFailoverPolicy(policyId: ID!): Boolean!
}

type Query {
  failoverPolicy(policyId: ID!): FailoverPolicy
  allFailoverPolicies: [FailoverPolicy!]!
  failoverEvents(
    policyId: ID
    since: String!
    limit: Int
  ): [FailoverEvent!]!
}
```

**Performance Requirements**:
- Failover detection: <5 seconds from path failure
- Routing table update: <100ms (atomic)
- Event logging: Async, no blocking
- Policy evaluation: <10ms per policy

---

### Feature 3: Traffic Statistics Export

**Description**: Export traffic statistics and health metrics in industry-standard formats.

**Components**:

1. **Prometheus Metrics Endpoint**
   ```
   # HELP patronus_path_latency_ms Path latency in milliseconds
   # TYPE patronus_path_latency_ms gauge
   patronus_path_latency_ms{path_id="path-1",site="site-a"} 45.2

   # HELP patronus_path_packet_loss Path packet loss percentage
   # TYPE patronus_path_packet_loss gauge
   patronus_path_packet_loss{path_id="path-1",site="site-a"} 0.5

   # HELP patronus_path_health_score Path health score (0-100)
   # TYPE patronus_path_health_score gauge
   patronus_path_health_score{path_id="path-1",site="site-a"} 92.5

   # HELP patronus_policy_bytes_total Total bytes matched by policy
   # TYPE patronus_policy_bytes_total counter
   patronus_policy_bytes_total{policy_id="1",name="web-traffic"} 1234567890

   # HELP patronus_policy_packets_total Total packets matched by policy
   # TYPE patronus_policy_packets_total counter
   patronus_policy_packets_total{policy_id="1",name="web-traffic"} 987654

   # HELP patronus_failover_events_total Total failover events
   # TYPE patronus_failover_events_total counter
   patronus_failover_events_total{policy_id="1",type="triggered"} 5
   ```

2. **JSON Export API**
   ```json
   {
     "paths": [
       {
         "path_id": "path-1",
         "health": {
           "latency_ms": 45.2,
           "packet_loss_pct": 0.5,
           "jitter_ms": 2.1,
           "health_score": 92.5,
           "status": "up",
           "last_checked": "2025-10-11T12:00:00Z"
         },
         "traffic": {
           "bytes_total": 1234567890,
           "packets_total": 987654,
           "active_flows": 42
         }
       }
     ],
     "policies": [
       {
         "policy_id": 1,
         "name": "web-traffic",
         "bytes_matched": 1234567890,
         "packets_matched": 987654,
         "active_flows": 42
       }
     ],
     "failovers": [
       {
         "event_id": 1,
         "policy_id": 1,
         "type": "triggered",
         "from_path": "path-1",
         "to_path": "path-2",
         "timestamp": "2025-10-11T11:30:00Z"
       }
     ]
   }
   ```

3. **REST Endpoints**
   ```
   GET /api/v1/metrics/export          (Prometheus format)
   GET /api/v1/metrics/export/json     (JSON format)
   GET /api/v1/metrics/health          (Health metrics only)
   GET /api/v1/metrics/traffic         (Traffic stats only)
   GET /api/v1/metrics/failovers       (Failover events only)
   ```

4. **GraphQL Export Query**
   ```graphql
   type MetricsExport {
     paths: [PathMetricsExport!]!
     policies: [PolicyMetricsExport!]!
     failovers: [FailoverEvent!]!
     exportedAt: String!
   }

   type PathMetricsExport {
     pathId: ID!
     health: PathHealth!
     traffic: PathTraffic!
   }

   type PolicyMetricsExport {
     policyId: ID!
     name: String!
     bytesMatched: Int!
     packetsMatched: Int!
     activeFlows: Int!
   }

   type Query {
     exportMetrics(
       format: ExportFormat!
       since: String
     ): MetricsExport!
   }

   enum ExportFormat {
     JSON
     PROMETHEUS
   }
   ```

**Performance Requirements**:
- Metrics endpoint response: <200ms
- JSON export generation: <500ms for 1000 paths
- Prometheus scrape: <1s total
- No impact on routing performance

---

## Technical Architecture

### New Modules

```
crates/patronus-sdwan/src/
├── health/
│   ├── mod.rs              (Health monitoring core)
│   ├── checker.rs          (Health check engine)
│   ├── scoring.rs          (Health scoring algorithm)
│   └── probe.rs            (ICMP/UDP probing)
├── failover/
│   ├── mod.rs              (Failover engine core)
│   ├── policy.rs           (Failover policy logic)
│   ├── engine.rs           (Failover execution)
│   └── events.rs           (Event system)
└── export/
    ├── mod.rs              (Export core)
    ├── prometheus.rs       (Prometheus format)
    └── json.rs             (JSON format)

crates/patronus-dashboard/src/
└── graphql/
    ├── health.rs           (Health GraphQL schema)
    ├── failover.rs         (Failover GraphQL schema)
    └── export.rs           (Export GraphQL schema)
```

### Database Migrations

**Migration 6: Path Health Tracking**
```sql
CREATE TABLE sdwan_path_health (...);
CREATE INDEX idx_path_health_path_time ...;
```

**Migration 7: Failover Policies**
```sql
CREATE TABLE sdwan_failover_policies (...);
CREATE TABLE sdwan_failover_events (...);
CREATE INDEX idx_failover_events_policy_time ...;
```

### Integration Points

1. **Sprint 30 Traffic Stats** → Health scoring input
2. **Path Manager** → Failover routing updates
3. **Database** → Historical data persistence
4. **GraphQL** → API exposure
5. **Metrics** → Prometheus export

---

## Implementation Plan

### Phase 1: Path Health Monitoring (Days 1-5)

**Tasks**:
1. Create `health` module structure
2. Implement `PathHealth` types and database schema
3. Build health check engine with ICMP/UDP probes
4. Implement health scoring algorithm
5. Add database persistence and queries
6. Create GraphQL API for health queries
7. Write comprehensive tests (target: 8-10 tests)

**Deliverables**:
- ✅ Health monitoring operational
- ✅ GraphQL API functional
- ✅ Tests passing
- ✅ Documentation complete

### Phase 2: Automatic Failover (Days 6-10)

**Tasks**:
1. Create `failover` module structure
2. Implement failover policy types and database schema
3. Build failover engine with policy evaluation
4. Implement failback logic with hysteresis
5. Add event logging and notifications
6. Create GraphQL mutations and queries
7. Integrate with path manager for routing updates
8. Write comprehensive tests (target: 8-10 tests)

**Deliverables**:
- ✅ Failover engine operational
- ✅ Policy management via GraphQL
- ✅ Event logging functional
- ✅ Tests passing
- ✅ Documentation complete

### Phase 3: Metrics Export (Days 11-14)

**Tasks**:
1. Create `export` module structure
2. Implement Prometheus metrics format
3. Build JSON export functionality
4. Add REST endpoints for export
5. Create GraphQL export queries
6. Optimize for performance (<200ms response)
7. Write comprehensive tests (target: 4-6 tests)
8. Create Grafana dashboard examples

**Deliverables**:
- ✅ Prometheus endpoint functional
- ✅ JSON export working
- ✅ GraphQL export queries operational
- ✅ Tests passing
- ✅ Grafana examples provided
- ✅ Documentation complete

### Phase 4: Integration & Testing (Days 15-16)

**Tasks**:
1. Integration testing across all features
2. Performance testing and optimization
3. Regression testing for Sprint 30
4. Documentation review and completion
5. Code review and cleanup
6. Final verification

**Deliverables**:
- ✅ All 20+ tests passing
- ✅ No Sprint 30 regressions
- ✅ Performance targets met
- ✅ Documentation complete

---

## Testing Strategy

### Unit Tests (Target: 12-15 tests)

- Health check engine functionality
- Health scoring algorithm accuracy
- Failover policy evaluation
- Failback logic with hysteresis
- Prometheus format generation
- JSON export formatting

### Integration Tests (Target: 8-10 tests)

- End-to-end health monitoring
- Failover triggering and execution
- Metrics export with real data
- GraphQL API integration
- Database persistence

### Performance Tests

- Health check overhead measurement
- Failover latency verification
- Export endpoint response time
- Database query performance

### Regression Tests

- All Sprint 30 tests must pass
- No performance degradation
- API compatibility maintained

---

## Documentation Deliverables

1. **SPRINT-31.md** - Technical documentation
2. **SPRINT-31-SUMMARY.md** - Executive summary
3. **docs/SPRINT_31_QUICK_REFERENCE.md** - Developer quick reference
4. **SPRINT-31-VERIFICATION.md** - Verification checklist
5. **Grafana dashboard examples** - JSON configs
6. **Prometheus configuration** - Scrape config examples

---

## Success Metrics

### Functionality

- ✅ Path health monitoring: Latency, loss, jitter tracked
- ✅ Health scoring: Accurate status determination
- ✅ Failover: <5s detection and execution
- ✅ Failback: Automatic with hysteresis
- ✅ Export: Prometheus + JSON functional

### Performance

- ✅ Health check overhead: <500ms per path
- ✅ Failover execution: <100ms routing update
- ✅ Metrics endpoint: <200ms response
- ✅ No Sprint 30 performance regression

### Quality

- ✅ 20+ tests passing (100%)
- ✅ Zero critical bugs
- ✅ Comprehensive documentation
- ✅ Production-ready code

---

## Risks & Mitigations

### Risk 1: Health Check Overhead

**Risk**: Too many health checks could impact performance
**Mitigation**:
- Configurable check intervals (default 10s)
- Async execution with tokio
- Batched database writes

### Risk 2: Failover Flapping

**Risk**: Rapid failover/failback cycling
**Mitigation**:
- Hysteresis with different thresholds
- Configurable failback delay
- Sustained health requirement

### Risk 3: Export Performance

**Risk**: Metrics export could be slow with many paths
**Mitigation**:
- Caching with TTL
- Pagination for large datasets
- Async generation

---

## Dependencies

### Sprint 30 (Complete)

- ✅ Traffic statistics infrastructure
- ✅ Flow tracking
- ✅ Database persistence
- ✅ GraphQL API foundation

### External Crates

- `tokio` - Async runtime (already used)
- `prometheus` - Metrics format (new)
- `pnet` - ICMP/UDP probes (new)
- `sqlx` - Database (already used)

---

## Timeline

**Estimated Duration**: 14-16 days
**Target Completion**: ~October 27, 2025

**Breakdown**:
- Phase 1 (Health): 5 days
- Phase 2 (Failover): 5 days
- Phase 3 (Export): 4 days
- Phase 4 (Integration): 2 days

---

## Post-Sprint 31

### What's Next?

**Sprint 32 Options**:
1. Advanced monitoring (bandwidth prediction, anomaly detection)
2. Multi-region support (geographic routing)
3. Enhanced security (DDoS mitigation, rate limiting)

**Long-term Goals**:
- Full eBPF integration
- Kubernetes operator
- Multi-cloud orchestration

---

**Version**: v0.2.0-sprint31 (planned)
**Status**: 🟡 In Progress
**Quality Target**: ⭐⭐⭐⭐⭐ Enterprise Grade
