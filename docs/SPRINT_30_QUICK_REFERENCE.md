# Sprint 30 Quick Reference Guide

## Quick Start

Sprint 30 adds three major features:
1. Traffic Statistics & Flow Tracking
2. Site Deletion with Cascade
3. Cache Management System

## Traffic Statistics

### Basic Usage

```rust
use patronus_sdwan::traffic_stats::TrafficStatsCollector;
use patronus_sdwan::types::FlowKey;

// Create collector (usually in AppState)
let collector = TrafficStatsCollector::new(Some(db));

// Record a packet
let flow = FlowKey {
    src_ip: "192.168.1.1".parse().unwrap(),
    dst_ip: "10.0.0.1".parse().unwrap(),
    src_port: 12345,
    dst_port: 80,
    protocol: 6, // TCP
};
collector.record_packet(policy_id, flow, packet_size).await;

// Get statistics
let stats = collector.get_policy_stats(policy_id).await.unwrap();
println!("Packets: {}, Bytes: {}",
    stats.packets_matched,
    stats.bytes_matched);
```

### Common Operations

```rust
// Get all policy statistics
let all_stats = collector.get_all_policy_stats().await;

// Get active flow count for a policy
let flow_count = collector.get_active_flow_count(policy_id).await;

// Update flow counts (call periodically)
collector.update_flow_counts().await;

// Cleanup stale flows (>5 minutes old)
let removed = collector.cleanup_stale_flows(
    Duration::from_secs(300)
).await;

// Store snapshot to database
collector.store_snapshot().await?;

// Reset specific policy stats
collector.reset_policy_stats(policy_id).await;

// Reset all statistics
collector.reset_all_stats().await;

// Get global totals
let total_packets = collector.get_total_packets().await;
let total_bytes = collector.get_total_bytes().await;
let total_flows = collector.get_total_active_flows().await;
```

### Periodic Tasks

```rust
// Recommended: Run cleanup every 5 minutes
tokio::spawn({
    let collector = traffic_stats.clone();
    async move {
        let mut interval = tokio::time::interval(Duration::from_secs(300));
        loop {
            interval.tick().await;
            collector.cleanup_stale_flows(Duration::from_secs(300)).await;
        }
    }
});

// Recommended: Snapshot to database every 1 minute
tokio::spawn({
    let collector = traffic_stats.clone();
    async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        loop {
            interval.tick().await;
            let _ = collector.store_snapshot().await;
        }
    }
});
```

## Cache Management

### Basic Usage

```rust
use patronus_dashboard::cache::{Cache, MetricsCache, RoutingCache};
use std::time::Duration;

// Create cache with 60-second TTL
let cache: Cache<String, String> = Cache::new(Duration::from_secs(60));

// Insert value
cache.insert("key".to_string(), "value".to_string()).await;

// Get value
if let Some(value) = cache.get(&"key".to_string()).await {
    println!("Found: {}", value);
} else {
    println!("Cache miss");
}

// Remove value
cache.remove(&"key".to_string()).await;
```

### Custom TTL

```rust
// Insert with custom 30-second TTL
cache.insert_with_ttl(
    key,
    value,
    Duration::from_secs(30)
).await;
```

### Cache Maintenance

```rust
// Clean up expired entries
let removed = cache.cleanup_expired().await;
println!("Removed {} expired entries", removed);

// Clear all entries
let cleared = cache.clear().await;
println!("Cleared {} entries", cleared);

// Get statistics
let stats = cache.stats().await;
println!("Total: {}, Active: {}, Expired: {}",
    stats.total_entries,
    stats.active_entries,
    stats.expired_entries);
```

### MetricsCache Example

```rust
use patronus_sdwan::types::PathMetrics;

let metrics_cache: MetricsCache = Cache::new(Duration::from_secs(60));

// Cache path metrics
let metrics = PathMetrics {
    latency_ms: 5.0,
    jitter_ms: 0.1,
    packet_loss_pct: 0.5,
    bandwidth_mbps: 100.0,
    mtu: 1500,
    measured_at: SystemTime::now(),
    score: 95,
};

metrics_cache.insert(path_id, metrics).await;

// Retrieve from cache
if let Some(cached_metrics) = metrics_cache.get(&path_id).await {
    println!("Latency: {}ms", cached_metrics.latency_ms);
} else {
    // Cache miss - query database
}
```

### RoutingCache Example

```rust
use patronus_dashboard::cache::RoutingDecision;

let routing_cache: RoutingCache = Cache::new(Duration::from_secs(30));

// Cache routing decision
let decision = RoutingDecision {
    selected_path_id: 123,
    reason: "Best latency".to_string(),
    timestamp: SystemTime::now(),
};

routing_cache.insert("flow-key".to_string(), decision).await;

// Use cached decision
if let Some(cached) = routing_cache.get(&"flow-key".to_string()).await {
    println!("Use path: {}", cached.selected_path_id);
}
```

## Site Deletion

### GraphQL Mutation

```graphql
mutation DeleteSite {
  deleteSite(site_id: "550e8400-e29b-41d4-a716-446655440000") {
    success
    message
    audit_id
  }
}
```

### Rust Code

```rust
use patronus_sdwan::types::SiteId;

// Delete site (cascade deletes paths and endpoints)
let site_id = SiteId::from_str("550e8400-e29b-41d4-a716-446655440000")?;

// Check dependencies first (optional)
let path_count = db.count_site_paths(&site_id).await?;
if path_count > 0 {
    println!("Warning: Site has {} paths that will be deleted", path_count);
}

// Delete site
let rows_affected = db.delete_site(&site_id).await?;
println!("Deleted {} rows", rows_affected);
```

## GraphQL Queries

### Query Policies with Traffic Stats

```graphql
query GetPolicies {
  policies {
    id
    priority
    packets_matched    # Real-time from TrafficStatsCollector
    bytes_matched      # Real-time from TrafficStatsCollector
    matchCriteria {
      protocol
      destPort
    }
    actions {
      setPath
      drop
    }
  }
}
```

### Query Single Policy

```graphql
query GetPolicy {
  policy(id: "1") {
    id
    priority
    packets_matched
    bytes_matched
    matchCriteria {
      sourceIp
      destIp
    }
  }
}
```

### Clear Cache

```graphql
mutation ClearCache {
  clearCache {
    success
    message
    cleared_entries
  }
}
```

## AppState Integration

### Initialization

```rust
use patronus_dashboard::state::AppState;

// Create app state (includes traffic stats and caches)
let state = AppState::new("dashboard.db").await?;

// Access traffic statistics
let stats = state.traffic_stats.get_policy_stats(1).await;

// Access metrics cache
let metrics = state.metrics_cache.get(&path_id).await;

// Access routing cache
let decision = state.routing_cache.get(&flow_key).await;
```

### In Request Handlers

```rust
async fn handler(
    State(state): State<Arc<AppState>>,
) -> Result<impl IntoResponse> {
    // Record traffic
    state.traffic_stats.record_packet(
        policy_id,
        flow_key,
        packet_size
    ).await;

    // Check cache
    if let Some(metrics) = state.metrics_cache.get(&path_id).await {
        return Ok(Json(metrics));
    }

    // Cache miss - query database
    let metrics = state.db.get_path_metrics(path_id).await?;
    state.metrics_cache.insert(path_id, metrics.clone()).await;

    Ok(Json(metrics))
}
```

## Database Schema

### Traffic Statistics Table

```sql
CREATE TABLE IF NOT EXISTS sdwan_policy_stats (
    stat_id INTEGER PRIMARY KEY AUTOINCREMENT,
    policy_id INTEGER NOT NULL,
    timestamp INTEGER NOT NULL,
    packets_matched INTEGER NOT NULL,
    bytes_matched INTEGER NOT NULL,
    active_flows INTEGER NOT NULL,
    FOREIGN KEY (policy_id) REFERENCES sdwan_policies(policy_id)
);
```

### Querying Statistics

```rust
// Store snapshot
db.store_policy_stats(&policy_stats).await?;

// Get latest stats
let stats = db.get_latest_policy_stats(policy_id).await?;

// Get historical stats
let history = db.get_policy_stats_history(
    policy_id,
    from_time,
    to_time
).await?;
```

## Common Patterns

### Pattern 1: Cache-Aside

```rust
// Check cache first
if let Some(value) = cache.get(&key).await {
    return Ok(value);
}

// Cache miss - query database
let value = db.query(&key).await?;

// Update cache
cache.insert(key, value.clone()).await;

Ok(value)
```

### Pattern 2: Write-Through Cache

```rust
// Update database
db.update(&key, &value).await?;

// Invalidate cache
cache.remove(&key).await;

// Or update cache
cache.insert(key, value).await;
```

### Pattern 3: Periodic Statistics

```rust
// Background task for stats collection
tokio::spawn({
    let collector = traffic_stats.clone();
    async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        loop {
            interval.tick().await;

            // Update flow counts
            collector.update_flow_counts().await;

            // Store snapshot
            let _ = collector.store_snapshot().await;

            // Cleanup old flows
            collector.cleanup_stale_flows(Duration::from_secs(300)).await;
        }
    }
});
```

## Testing

### Unit Tests

```rust
#[tokio::test]
async fn test_traffic_stats() {
    let collector = TrafficStatsCollector::new(None);

    let flow = FlowKey {
        src_ip: "192.168.1.1".parse().unwrap(),
        dst_ip: "10.0.0.1".parse().unwrap(),
        src_port: 12345,
        dst_port: 80,
        protocol: 6,
    };

    collector.record_packet(1, flow, 1500).await;

    let stats = collector.get_policy_stats(1).await.unwrap();
    assert_eq!(stats.packets_matched, 1);
    assert_eq!(stats.bytes_matched, 1500);
}
```

### Integration Tests

```rust
#[tokio::test]
async fn test_cache_expiration() {
    let cache = Cache::new(Duration::from_millis(100));

    cache.insert("key".to_string(), "value".to_string()).await;
    assert!(cache.get(&"key".to_string()).await.is_some());

    tokio::time::sleep(Duration::from_millis(150)).await;
    assert!(cache.get(&"key".to_string()).await.is_none());
}
```

## Performance Tips

### Traffic Statistics

1. **Batch snapshots** - Don't store every packet to database
2. **Periodic cleanup** - Run cleanup every 5-10 minutes
3. **Update flow counts** - Call before reading active_flows
4. **Reset wisely** - Only reset when necessary

### Caching

1. **Choose appropriate TTL** - Balance freshness vs hit rate
2. **Monitor hit rates** - Use stats() to track performance
3. **Cleanup periodically** - Prevent memory growth
4. **Cache hot paths** - Focus on frequently accessed data

### Site Deletion

1. **Check dependencies first** - Use count_site_paths()
2. **Delete off-peak** - Large sites take time
3. **Transaction safety** - Let database handle atomicity

## Troubleshooting

### Traffic Stats Not Updating

```rust
// Make sure flow counts are updated
collector.update_flow_counts().await;

// Check if data is being recorded
let total = collector.get_total_packets().await;
println!("Total packets: {}", total);
```

### Cache Always Missing

```rust
// Check TTL
let stats = cache.stats().await;
println!("Stats: {:?}", stats);

// Verify insert
cache.insert(key.clone(), value.clone()).await;
let result = cache.get(&key).await;
assert!(result.is_some(), "Insert failed");
```

### Site Deletion Fails

```rust
// Check dependencies
let count = db.count_site_paths(&site_id).await?;
println!("Site has {} paths", count);

// Verify site exists
let site = db.get_site(&site_id).await?;
if site.is_none() {
    println!("Site not found");
}
```

## Monitoring

### Metrics to Track

```rust
// Traffic statistics
- Total packets/bytes across all policies
- Active flows per policy
- Flow cleanup rate

// Cache performance
- Hit rate (gets vs misses)
- Entry count (active vs expired)
- Cleanup frequency

// Site deletions
- Deletion rate
- Average deletion time
- Failed deletions
```

### Example Monitoring

```rust
// Periodic metrics collection
tokio::spawn(async move {
    let mut interval = tokio::time::interval(Duration::from_secs(10));
    loop {
        interval.tick().await;

        // Traffic stats metrics
        let total_packets = traffic_stats.get_total_packets().await;
        let total_flows = traffic_stats.get_total_active_flows().await;
        metrics::gauge!("traffic.total_packets", total_packets as f64);
        metrics::gauge!("traffic.active_flows", total_flows as f64);

        // Cache metrics
        let cache_stats = metrics_cache.stats().await;
        metrics::gauge!("cache.total_entries", cache_stats.total_entries as f64);
        metrics::gauge!("cache.active_entries", cache_stats.active_entries as f64);
    }
});
```

## Additional Resources

- Full documentation: `SPRINT_30.md`
- Deployment guide: `SPRINT_30_SUMMARY.md`
- API documentation: Run `cargo doc --open`
- Integration tests: `crates/patronus-dashboard/tests/`

## Support

For questions or issues:
1. Check the comprehensive docs in `SPRINT_30.md`
2. Review integration tests for usage examples
3. Check inline documentation with `cargo doc`

