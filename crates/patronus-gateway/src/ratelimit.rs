//! Rate Limiting with Token Bucket Algorithm

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    pub requests_per_second: u32,
    pub burst_size: u32,
}

struct TokenBucket {
    tokens: f64,
    last_refill: Instant,
    capacity: f64,
    refill_rate: f64, // tokens per second
}

pub struct RateLimiter {
    config: RateLimitConfig,
    buckets: Arc<RwLock<HashMap<String, TokenBucket>>>,
}

impl RateLimiter {
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            config,
            buckets: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn check_rate_limit(&self, key: &str) -> bool {
        let mut buckets = self.buckets.write().await;

        let bucket = buckets.entry(key.to_string()).or_insert_with(|| {
            TokenBucket {
                tokens: self.config.burst_size as f64,
                last_refill: Instant::now(),
                capacity: self.config.burst_size as f64,
                refill_rate: self.config.requests_per_second as f64,
            }
        });

        // Refill tokens based on elapsed time
        let now = Instant::now();
        let elapsed = now.duration_since(bucket.last_refill).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * bucket.refill_rate).min(bucket.capacity);
        bucket.last_refill = now;

        // Check if we have tokens
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    pub async fn cleanup_old_buckets(&self, max_age: Duration) {
        let mut buckets = self.buckets.write().await;
        let now = Instant::now();

        buckets.retain(|_, bucket| {
            now.duration_since(bucket.last_refill) < max_age
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_rate_limiter_allows() {
        let config = RateLimitConfig {
            requests_per_second: 10,
            burst_size: 20,
        };

        let limiter = RateLimiter::new(config);

        // First request should be allowed
        assert!(limiter.check_rate_limit("user1").await);
    }

    #[tokio::test]
    async fn test_rate_limiter_burst() {
        let config = RateLimitConfig {
            requests_per_second: 10,
            burst_size: 5,
        };

        let limiter = RateLimiter::new(config);

        // Allow burst
        for _ in 0..5 {
            assert!(limiter.check_rate_limit("user1").await);
        }

        // Should be rate limited
        assert!(!limiter.check_rate_limit("user1").await);
    }

    #[tokio::test]
    async fn test_rate_limiter_refill() {
        let config = RateLimitConfig {
            requests_per_second: 10,
            burst_size: 1,
        };

        let limiter = RateLimiter::new(config);

        assert!(limiter.check_rate_limit("user1").await);
        assert!(!limiter.check_rate_limit("user1").await);

        // Wait for refill (>100ms = 1 token)
        tokio::time::sleep(Duration::from_millis(150)).await;

        assert!(limiter.check_rate_limit("user1").await);
    }
}
