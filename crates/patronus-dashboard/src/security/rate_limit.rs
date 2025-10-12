//! Rate limiting implementation using token bucket algorithm

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

/// Rate limit configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    /// Maximum requests per window
    pub max_requests: u32,
    /// Time window duration in seconds
    pub window_secs: u64,
    /// Burst allowance (extra requests allowed in short bursts)
    pub burst: u32,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            max_requests: 100,
            window_secs: 60,
            burst: 10,
        }
    }
}

/// Token bucket for rate limiting
#[derive(Debug, Clone)]
struct TokenBucket {
    /// Number of tokens available
    tokens: f64,
    /// Maximum tokens (capacity)
    capacity: f64,
    /// Token refill rate per second
    refill_rate: f64,
    /// Last refill time
    last_refill: Instant,
}

impl TokenBucket {
    fn new(capacity: u32, refill_rate: f64) -> Self {
        Self {
            tokens: capacity as f64,
            capacity: capacity as f64,
            refill_rate,
            last_refill: Instant::now(),
        }
    }

    /// Refill tokens based on elapsed time
    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();

        self.tokens = (self.tokens + elapsed * self.refill_rate).min(self.capacity);
        self.last_refill = now;
    }

    /// Try to consume tokens
    fn try_consume(&mut self, tokens: f64) -> bool {
        self.refill();

        if self.tokens >= tokens {
            self.tokens -= tokens;
            true
        } else {
            false
        }
    }

    /// Get remaining tokens
    fn remaining(&mut self) -> u32 {
        self.refill();
        self.tokens as u32
    }
}

/// Rate limiter using token bucket algorithm
pub struct RateLimiter {
    /// IP-based rate limits
    ip_buckets: Arc<RwLock<HashMap<IpAddr, TokenBucket>>>,
    /// User-based rate limits
    user_buckets: Arc<RwLock<HashMap<String, TokenBucket>>>,
    /// Configuration
    config: RateLimitConfig,
    /// Cleanup interval
    cleanup_interval: Duration,
    /// Last cleanup time
    last_cleanup: Arc<RwLock<Instant>>,
}

impl RateLimiter {
    /// Create a new rate limiter
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            ip_buckets: Arc::new(RwLock::new(HashMap::new())),
            user_buckets: Arc::new(RwLock::new(HashMap::new())),
            config,
            cleanup_interval: Duration::from_secs(300), // 5 minutes
            last_cleanup: Arc::new(RwLock::new(Instant::now())),
        }
    }

    /// Check if IP is allowed to make a request
    pub fn check_ip(&self, ip: IpAddr) -> bool {
        self.cleanup_if_needed();

        let mut buckets = self.ip_buckets.write();
        let bucket = buckets.entry(ip).or_insert_with(|| {
            let capacity = self.config.max_requests + self.config.burst;
            let refill_rate = self.config.max_requests as f64 / self.config.window_secs as f64;
            TokenBucket::new(capacity, refill_rate)
        });

        bucket.try_consume(1.0)
    }

    /// Check if user is allowed to make a request
    pub fn check_user(&self, user_id: &str) -> bool {
        self.cleanup_if_needed();

        let mut buckets = self.user_buckets.write();
        let bucket = buckets.entry(user_id.to_string()).or_insert_with(|| {
            let capacity = self.config.max_requests + self.config.burst;
            let refill_rate = self.config.max_requests as f64 / self.config.window_secs as f64;
            TokenBucket::new(capacity, refill_rate)
        });

        bucket.try_consume(1.0)
    }

    /// Get remaining requests for IP
    pub fn remaining_ip(&self, ip: IpAddr) -> u32 {
        let mut buckets = self.ip_buckets.write();
        if let Some(bucket) = buckets.get_mut(&ip) {
            bucket.remaining()
        } else {
            self.config.max_requests + self.config.burst
        }
    }

    /// Get remaining requests for user
    pub fn remaining_user(&self, user_id: &str) -> u32 {
        let mut buckets = self.user_buckets.write();
        if let Some(bucket) = buckets.get_mut(user_id) {
            bucket.remaining()
        } else {
            self.config.max_requests + self.config.burst
        }
    }

    /// Clean up old entries
    fn cleanup_if_needed(&self) {
        let mut last_cleanup = self.last_cleanup.write();
        if last_cleanup.elapsed() > self.cleanup_interval {
            // Clean up IP buckets with full tokens (inactive)
            self.ip_buckets.write().retain(|_, bucket| {
                bucket.tokens < bucket.capacity
            });

            // Clean up user buckets with full tokens (inactive)
            self.user_buckets.write().retain(|_, bucket| {
                bucket.tokens < bucket.capacity
            });

            *last_cleanup = Instant::now();
        }
    }

    /// Reset rate limit for IP
    pub fn reset_ip(&self, ip: IpAddr) {
        self.ip_buckets.write().remove(&ip);
    }

    /// Reset rate limit for user
    pub fn reset_user(&self, user_id: &str) {
        self.user_buckets.write().remove(user_id);
    }

    /// Get current configuration
    pub fn config(&self) -> &RateLimitConfig {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use std::thread;

    #[test]
    fn test_token_bucket_basic() {
        let mut bucket = TokenBucket::new(10, 1.0);

        // Should allow 10 requests
        for _ in 0..10 {
            assert!(bucket.try_consume(1.0));
        }

        // 11th request should fail
        assert!(!bucket.try_consume(1.0));
    }

    #[test]
    fn test_token_bucket_refill() {
        let mut bucket = TokenBucket::new(5, 10.0); // 10 tokens per second

        // Consume all tokens
        for _ in 0..5 {
            assert!(bucket.try_consume(1.0));
        }

        // Should be empty
        assert!(!bucket.try_consume(1.0));

        // Wait for refill (100ms = 1 token at 10/sec)
        thread::sleep(Duration::from_millis(100));

        // Should have at least 1 token now
        assert!(bucket.try_consume(1.0));
    }

    #[test]
    fn test_rate_limiter_ip() {
        let config = RateLimitConfig {
            max_requests: 5,
            window_secs: 1,
            burst: 2,
        };
        let limiter = RateLimiter::new(config);
        let ip: IpAddr = "192.168.1.1".parse().unwrap();

        // Should allow 7 requests (5 + 2 burst)
        for i in 0..7 {
            assert!(limiter.check_ip(ip), "Request {} should succeed", i + 1);
        }

        // 8th request should fail
        assert!(!limiter.check_ip(ip));
    }

    #[test]
    fn test_rate_limiter_user() {
        let config = RateLimitConfig {
            max_requests: 10,
            window_secs: 1,
            burst: 5,
        };
        let limiter = RateLimiter::new(config);

        // Should allow 15 requests (10 + 5 burst)
        for _ in 0..15 {
            assert!(limiter.check_user("user123"));
        }

        // 16th request should fail
        assert!(!limiter.check_user("user123"));
    }

    #[test]
    fn test_remaining_count() {
        let config = RateLimitConfig {
            max_requests: 10,
            window_secs: 1,
            burst: 0,
        };
        let limiter = RateLimiter::new(config);
        let ip: IpAddr = "10.0.0.1".parse().unwrap();

        assert_eq!(limiter.remaining_ip(ip), 10);

        limiter.check_ip(ip);
        assert_eq!(limiter.remaining_ip(ip), 9);

        limiter.check_ip(ip);
        limiter.check_ip(ip);
        assert_eq!(limiter.remaining_ip(ip), 7);
    }

    #[test]
    fn test_reset() {
        let config = RateLimitConfig::default();
        let limiter = RateLimiter::new(config);
        let ip: IpAddr = "172.16.0.1".parse().unwrap();

        // Consume some tokens
        limiter.check_ip(ip);
        limiter.check_ip(ip);

        let remaining = limiter.remaining_ip(ip);

        // Reset
        limiter.reset_ip(ip);

        // Should be back to full capacity
        assert!(limiter.remaining_ip(ip) > remaining);
    }
}
