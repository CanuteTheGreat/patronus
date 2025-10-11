//! Integration tests for cache system (Sprint 30)

use patronus_dashboard::cache::{Cache, CachedEntry, MetricsCache, RoutingCache, RoutingDecision};
use patronus_sdwan::types::PathMetrics;
use std::time::{Duration, SystemTime};
use tokio::time::sleep;

#[tokio::test]
async fn test_cache_basic_operations() {
    let cache: Cache<String, String> = Cache::new(Duration::from_secs(60));

    // Insert and retrieve
    cache.insert("key1".to_string(), "value1".to_string()).await;

    let value = cache.get(&"key1".to_string()).await;
    assert_eq!(value, Some("value1".to_string()));

    // Non-existent key
    let value = cache.get(&"nonexistent".to_string()).await;
    assert_eq!(value, None);
}

#[tokio::test]
async fn test_cache_expiration() {
    let cache: Cache<String, String> = Cache::new(Duration::from_millis(100));

    // Insert with default TTL
    cache.insert("key1".to_string(), "value1".to_string()).await;

    // Should be available immediately
    assert!(cache.get(&"key1".to_string()).await.is_some());

    // Sleep past expiration
    sleep(Duration::from_millis(150)).await;

    // Should be expired
    assert!(cache.get(&"key1".to_string()).await.is_none());
}

#[tokio::test]
async fn test_cache_custom_ttl() {
    let cache: Cache<String, String> = Cache::new(Duration::from_secs(60));

    // Insert with custom short TTL
    cache.insert_with_ttl("key1".to_string(), "value1".to_string(), Duration::from_millis(50)).await;

    // Should be available immediately
    assert!(cache.get(&"key1".to_string()).await.is_some());

    // Sleep past custom TTL
    sleep(Duration::from_millis(100)).await;

    // Should be expired
    assert!(cache.get(&"key1".to_string()).await.is_none());
}

#[tokio::test]
async fn test_cache_remove() {
    let cache: Cache<String, String> = Cache::new(Duration::from_secs(60));

    cache.insert("key1".to_string(), "value1".to_string()).await;
    cache.insert("key2".to_string(), "value2".to_string()).await;

    // Remove key1
    let removed = cache.remove(&"key1".to_string()).await;
    assert_eq!(removed, Some("value1".to_string()));

    // Key1 should be gone
    assert!(cache.get(&"key1".to_string()).await.is_none());

    // Key2 should still exist
    assert!(cache.get(&"key2".to_string()).await.is_some());

    // Removing nonexistent key
    let removed = cache.remove(&"nonexistent".to_string()).await;
    assert_eq!(removed, None);
}

#[tokio::test]
async fn test_cache_cleanup_expired() {
    let cache: Cache<String, String> = Cache::new(Duration::from_millis(100));

    // Insert multiple entries
    cache.insert("key1".to_string(), "value1".to_string()).await;
    cache.insert("key2".to_string(), "value2".to_string()).await;
    cache.insert("key3".to_string(), "value3".to_string()).await;

    // Wait for expiration
    sleep(Duration::from_millis(150)).await;

    // Clean up expired entries
    let removed = cache.cleanup_expired().await;
    assert_eq!(removed, 3);

    // Cache should be empty (verify via stats)
    let stats = cache.stats().await;
    assert_eq!(stats.total_entries, 0);
}

#[tokio::test]
async fn test_cache_cleanup_partial() {
    let cache: Cache<String, String> = Cache::new(Duration::from_secs(60));

    // Insert with different TTLs
    cache.insert_with_ttl("key1".to_string(), "value1".to_string(), Duration::from_millis(50)).await;
    cache.insert_with_ttl("key2".to_string(), "value2".to_string(), Duration::from_millis(200)).await;
    cache.insert_with_ttl("key3".to_string(), "value3".to_string(), Duration::from_millis(50)).await;

    // Wait for short TTLs to expire
    sleep(Duration::from_millis(100)).await;

    // Clean up expired entries
    let removed = cache.cleanup_expired().await;
    assert_eq!(removed, 2); // key1 and key3

    // Only key2 should remain
    let stats = cache.stats().await;
    assert_eq!(stats.total_entries, 1);
    assert!(cache.get(&"key2".to_string()).await.is_some());
    assert!(cache.get(&"key1".to_string()).await.is_none());
    assert!(cache.get(&"key3".to_string()).await.is_none());
}

#[tokio::test]
async fn test_cache_clear() {
    let cache: Cache<String, String> = Cache::new(Duration::from_secs(60));

    // Insert multiple entries
    cache.insert("key1".to_string(), "value1".to_string()).await;
    cache.insert("key2".to_string(), "value2".to_string()).await;
    cache.insert("key3".to_string(), "value3".to_string()).await;

    let stats = cache.stats().await;
    assert_eq!(stats.total_entries, 3);

    // Clear all
    let cleared = cache.clear().await;
    assert_eq!(cleared, 3);

    // Cache should be empty
    let stats = cache.stats().await;
    assert_eq!(stats.total_entries, 0);
    assert!(cache.get(&"key1".to_string()).await.is_none());
}

#[tokio::test]
async fn test_cache_stats() {
    let cache: Cache<String, String> = Cache::new(Duration::from_millis(100));

    // Insert entries with different TTLs
    cache.insert("key1".to_string(), "value1".to_string()).await;
    cache.insert_with_ttl("key2".to_string(), "value2".to_string(), Duration::from_millis(50)).await;
    cache.insert("key3".to_string(), "value3".to_string()).await;

    // Get stats
    let stats = cache.stats().await;
    assert_eq!(stats.total_entries, 3);
    assert_eq!(stats.expired_entries, 0);

    // Wait for key2 to expire
    sleep(Duration::from_millis(75)).await;

    // Get stats again
    let stats = cache.stats().await;
    assert_eq!(stats.total_entries, 3);
    assert_eq!(stats.expired_entries, 1);

    // Wait for all to expire
    sleep(Duration::from_millis(50)).await;

    let stats = cache.stats().await;
    assert_eq!(stats.total_entries, 3);
    assert_eq!(stats.expired_entries, 3);
}

#[tokio::test]
async fn test_metrics_cache() {
    let cache: MetricsCache = Cache::new(Duration::from_secs(60));

    let metrics = PathMetrics {
        latency_ms: 5.0,
        jitter_ms: 0.1,
        packet_loss_pct: 0.5,
        bandwidth_mbps: 100.0,
        mtu: 1500,
        measured_at: SystemTime::now(),
        score: 95,
    };

    // Insert metrics
    cache.insert(123u64, metrics.clone()).await;

    // Retrieve metrics
    let retrieved = cache.get(&123u64).await;
    assert!(retrieved.is_some());
    let retrieved = retrieved.unwrap();
    assert_eq!(retrieved.latency_ms, 5.0);
    assert_eq!(retrieved.bandwidth_mbps, 100.0);
    assert_eq!(retrieved.score, 95);
}

#[tokio::test]
async fn test_routing_cache() {
    let cache: RoutingCache = Cache::new(Duration::from_secs(30));

    let decision = RoutingDecision {
        selected_path_id: 123,
        reason: "Best available path".to_string(),
        timestamp: SystemTime::now(),
    };

    // Insert routing decision
    cache.insert("flow-key-1".to_string(), decision.clone()).await;

    // Retrieve decision
    let retrieved = cache.get(&"flow-key-1".to_string()).await;
    assert!(retrieved.is_some());
    let retrieved = retrieved.unwrap();
    assert_eq!(retrieved.selected_path_id, 123);
    assert_eq!(retrieved.reason, "Best available path");
}

#[tokio::test]
async fn test_cache_overwrite() {
    let cache: Cache<String, String> = Cache::new(Duration::from_secs(60));

    // Insert initial value
    cache.insert("key1".to_string(), "value1".to_string()).await;
    assert_eq!(cache.get(&"key1".to_string()).await, Some("value1".to_string()));

    // Overwrite with new value
    cache.insert("key1".to_string(), "value2".to_string()).await;
    assert_eq!(cache.get(&"key1".to_string()).await, Some("value2".to_string()));

    // Size should still be 1
    let stats = cache.stats().await;
    assert_eq!(stats.total_entries, 1);
}

#[tokio::test]
async fn test_cached_entry() {
    let entry = CachedEntry {
        value: "test".to_string(),
        expires_at: SystemTime::now() + Duration::from_secs(10),
    };

    // Should not be expired
    assert!(!entry.is_expired());

    // Entry with past expiration
    let expired_entry = CachedEntry {
        value: "test".to_string(),
        expires_at: SystemTime::now() - Duration::from_secs(1),
    };

    // Should be expired
    assert!(expired_entry.is_expired());
}
