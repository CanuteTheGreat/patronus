//! Cache management system (Sprint 30)
//!
//! Provides in-memory caching for metrics and routing decisions
//! to reduce database load and improve response times.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::RwLock;

/// Cached entry with expiration time
#[derive(Debug, Clone)]
pub struct CachedEntry<T> {
    pub value: T,
    pub expires_at: SystemTime,
}

impl<T> CachedEntry<T> {
    /// Create a new cached entry with TTL
    pub fn new(value: T, ttl: Duration) -> Self {
        Self {
            value,
            expires_at: SystemTime::now() + ttl,
        }
    }

    /// Check if entry is expired
    pub fn is_expired(&self) -> bool {
        SystemTime::now() > self.expires_at
    }
}

/// Generic cache with TTL support
pub struct Cache<K, V>
where
    K: Eq + std::hash::Hash,
{
    entries: Arc<RwLock<HashMap<K, CachedEntry<V>>>>,
    default_ttl: Duration,
}

impl<K, V> Cache<K, V>
where
    K: Eq + std::hash::Hash + Clone,
    V: Clone,
{
    /// Create a new cache with default TTL
    pub fn new(default_ttl: Duration) -> Self {
        Self {
            entries: Arc::new(RwLock::new(HashMap::new())),
            default_ttl,
        }
    }

    /// Get a value from cache
    pub async fn get(&self, key: &K) -> Option<V> {
        let entries = self.entries.read().await;
        if let Some(entry) = entries.get(key) {
            if !entry.is_expired() {
                return Some(entry.value.clone());
            }
        }
        None
    }

    /// Insert a value into cache with default TTL
    pub async fn insert(&self, key: K, value: V) {
        let mut entries = self.entries.write().await;
        entries.insert(key, CachedEntry::new(value, self.default_ttl));
    }

    /// Insert a value into cache with custom TTL
    pub async fn insert_with_ttl(&self, key: K, value: V, ttl: Duration) {
        let mut entries = self.entries.write().await;
        entries.insert(key, CachedEntry::new(value, ttl));
    }

    /// Remove a value from cache
    pub async fn remove(&self, key: &K) -> Option<V> {
        let mut entries = self.entries.write().await;
        entries.remove(key).map(|entry| entry.value)
    }

    /// Clear all expired entries
    pub async fn cleanup_expired(&self) -> usize {
        let mut entries = self.entries.write().await;
        let initial_count = entries.len();
        entries.retain(|_, entry| !entry.is_expired());
        initial_count - entries.len()
    }

    /// Clear all entries
    pub async fn clear(&self) -> usize {
        let mut entries = self.entries.write().await;
        let count = entries.len();
        entries.clear();
        count
    }

    /// Get cache statistics
    pub async fn stats(&self) -> CacheStats {
        let entries = self.entries.read().await;
        let total_entries = entries.len();
        let expired_entries = entries.values().filter(|e| e.is_expired()).count();

        CacheStats {
            total_entries,
            active_entries: total_entries - expired_entries,
            expired_entries,
        }
    }
}

/// Cache statistics
#[derive(Debug, Clone)]
pub struct CacheStats {
    pub total_entries: usize,
    pub active_entries: usize,
    pub expired_entries: usize,
}

/// Metrics cache for path metrics
pub type MetricsCache = Cache<u64, patronus_sdwan::types::PathMetrics>;

/// Routing cache for path selection decisions
#[derive(Debug, Clone)]
pub struct RoutingDecision {
    pub selected_path_id: u64,
    pub reason: String,
    pub timestamp: SystemTime,
}

pub type RoutingCache = Cache<String, RoutingDecision>;

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::sleep;

    #[tokio::test]
    async fn test_cache_insert_and_get() {
        let cache: Cache<String, i32> = Cache::new(Duration::from_secs(60));

        cache.insert("key1".to_string(), 42).await;
        let value = cache.get(&"key1".to_string()).await;

        assert_eq!(value, Some(42));
    }

    #[tokio::test]
    async fn test_cache_expiration() {
        let cache: Cache<String, i32> = Cache::new(Duration::from_millis(100));

        cache.insert("key1".to_string(), 42).await;

        // Value should be present immediately
        assert_eq!(cache.get(&"key1".to_string()).await, Some(42));

        // Wait for expiration
        sleep(Duration::from_millis(150)).await;

        // Value should be expired
        assert_eq!(cache.get(&"key1".to_string()).await, None);
    }

    #[tokio::test]
    async fn test_cache_cleanup() {
        let cache: Cache<String, i32> = Cache::new(Duration::from_millis(100));

        cache.insert("key1".to_string(), 1).await;
        cache.insert("key2".to_string(), 2).await;
        cache.insert("key3".to_string(), 3).await;

        // Wait for expiration
        sleep(Duration::from_millis(150)).await;

        // Cleanup expired entries
        let removed = cache.cleanup_expired().await;
        assert_eq!(removed, 3);

        // Stats should show 0 entries
        let stats = cache.stats().await;
        assert_eq!(stats.total_entries, 0);
    }

    #[tokio::test]
    async fn test_cache_clear() {
        let cache: Cache<String, i32> = Cache::new(Duration::from_secs(60));

        cache.insert("key1".to_string(), 1).await;
        cache.insert("key2".to_string(), 2).await;

        let cleared = cache.clear().await;
        assert_eq!(cleared, 2);

        assert_eq!(cache.get(&"key1".to_string()).await, None);
    }

    #[tokio::test]
    async fn test_cache_stats() {
        let cache: Cache<String, i32> = Cache::new(Duration::from_secs(60));

        cache.insert("key1".to_string(), 1).await;
        cache.insert("key2".to_string(), 2).await;

        let stats = cache.stats().await;
        assert_eq!(stats.total_entries, 2);
        assert_eq!(stats.active_entries, 2);
        assert_eq!(stats.expired_entries, 0);
    }
}
