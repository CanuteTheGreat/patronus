//! Quality of Service (QoS) and Traffic Shaping
//!
//! Implements priority queuing and rate limiting for different traffic classes.

use crate::dpi::ApplicationType;
use crate::types::FlowKey;
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tracing::{debug, trace, warn};

/// QoS class priority levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum QosClass {
    /// Real-time traffic (VoIP, gaming) - highest priority
    RealTime = 0,

    /// Interactive traffic (SSH, RDP, video calls)
    Interactive = 1,

    /// Streaming (video streaming, music)
    Streaming = 2,

    /// Standard (web browsing, email)
    Standard = 3,

    /// Bulk (file transfers, backups) - lowest priority
    Bulk = 4,
}

impl QosClass {
    /// Get QoS class for application type
    pub fn from_app_type(app_type: ApplicationType) -> Self {
        match app_type {
            ApplicationType::VoIP | ApplicationType::Gaming => QosClass::RealTime,
            ApplicationType::Video => QosClass::Streaming,
            ApplicationType::Web => QosClass::Standard,
            ApplicationType::FileTransfer => QosClass::Bulk,
            ApplicationType::Database => QosClass::Interactive,
            ApplicationType::Unknown => QosClass::Standard,
        }
    }

    /// Get human-readable name
    pub fn as_str(&self) -> &'static str {
        match self {
            QosClass::RealTime => "RealTime",
            QosClass::Interactive => "Interactive",
            QosClass::Streaming => "Streaming",
            QosClass::Standard => "Standard",
            QosClass::Bulk => "Bulk",
        }
    }

    /// Get target maximum latency for this class (milliseconds)
    pub fn target_latency_ms(&self) -> u32 {
        match self {
            QosClass::RealTime => 50,
            QosClass::Interactive => 150,
            QosClass::Streaming => 300,
            QosClass::Standard => 500,
            QosClass::Bulk => 1000,
        }
    }
}

/// Packet queued for transmission
#[derive(Clone)]
pub struct QueuedPacket {
    /// Packet data
    pub data: Vec<u8>,

    /// Flow key
    pub flow: FlowKey,

    /// QoS class
    pub qos_class: QosClass,

    /// Timestamp when packet was queued
    pub queued_at: Instant,
}

/// Queue configuration
#[derive(Debug, Clone)]
pub struct QueueConfig {
    /// Maximum queue size (packets)
    pub max_size: usize,

    /// Bandwidth limit (bytes per second)
    pub bandwidth_limit: Option<u64>,
}

impl Default for QueueConfig {
    fn default() -> Self {
        Self {
            max_size: 1000,
            bandwidth_limit: None,
        }
    }
}

/// Priority queue for a single QoS class
struct PriorityQueue {
    queue: VecDeque<QueuedPacket>,
    config: QueueConfig,
    bytes_queued: usize,
    packets_dropped: u64,
    buffer_overflows: u64,
}

impl PriorityQueue {
    fn new(config: QueueConfig) -> Self {
        Self {
            queue: VecDeque::with_capacity(config.max_size),
            config,
            bytes_queued: 0,
            packets_dropped: 0,
            buffer_overflows: 0,
        }
    }

    fn enqueue(&mut self, packet: QueuedPacket) -> bool {
        if self.queue.len() >= self.config.max_size {
            warn!("Queue full for class {}, dropping packet", packet.qos_class.as_str());
            self.packets_dropped += 1;
            self.buffer_overflows += 1;
            return false;
        }

        self.bytes_queued += packet.data.len();
        self.queue.push_back(packet);
        true
    }

    fn dequeue(&mut self) -> Option<QueuedPacket> {
        if let Some(packet) = self.queue.pop_front() {
            self.bytes_queued = self.bytes_queued.saturating_sub(packet.data.len());
            Some(packet)
        } else {
            None
        }
    }

    fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    fn len(&self) -> usize {
        self.queue.len()
    }
}

/// Token bucket for rate limiting
struct TokenBucket {
    /// Capacity (bytes)
    capacity: u64,

    /// Current tokens (bytes)
    tokens: u64,

    /// Refill rate (bytes per second)
    refill_rate: u64,

    /// Last refill timestamp
    last_refill: Instant,
}

impl TokenBucket {
    fn new(rate_bps: u64) -> Self {
        // Bucket capacity is 1 second worth of data
        let capacity = rate_bps;

        Self {
            capacity,
            tokens: capacity,
            refill_rate: rate_bps,
            last_refill: Instant::now(),
        }
    }

    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill);

        // Calculate tokens to add based on elapsed time
        let tokens_to_add = (elapsed.as_secs_f64() * self.refill_rate as f64) as u64;

        if tokens_to_add > 0 {
            self.tokens = (self.tokens + tokens_to_add).min(self.capacity);
            self.last_refill = now;
        }
    }

    fn consume(&mut self, bytes: usize) -> bool {
        self.refill();

        if self.tokens >= bytes as u64 {
            self.tokens -= bytes as u64;
            true
        } else {
            false
        }
    }

    fn available(&self) -> u64 {
        self.tokens
    }
}

/// QoS scheduler manages multiple priority queues and traffic shaping
pub struct QosScheduler {
    /// Priority queues (one per QoS class)
    queues: Arc<Mutex<HashMap<QosClass, PriorityQueue>>>,

    /// Token bucket for rate limiting
    rate_limiter: Arc<Mutex<Option<TokenBucket>>>,

    /// Statistics
    stats: Arc<Mutex<QosStats>>,
}

/// QoS statistics
#[derive(Default, Clone)]
pub struct QosStats {
    pub packets_enqueued: u64,
    pub packets_dequeued: u64,
    pub packets_dropped: u64,
    pub buffer_overflows: u64,
    pub bytes_transmitted: u64,
    pub by_class: HashMap<QosClass, ClassStats>,
}

#[derive(Default, Clone)]
pub struct ClassStats {
    pub packets: u64,
    pub bytes: u64,
    pub drops: u64,
    pub avg_queue_time_ms: f64,
}

impl QosScheduler {
    /// Create a new QoS scheduler
    pub fn new() -> Self {
        let mut queues = HashMap::new();

        // Create a queue for each QoS class
        for class in [
            QosClass::RealTime,
            QosClass::Interactive,
            QosClass::Streaming,
            QosClass::Standard,
            QosClass::Bulk,
        ] {
            queues.insert(class, PriorityQueue::new(QueueConfig::default()));
        }

        Self {
            queues: Arc::new(Mutex::new(queues)),
            rate_limiter: Arc::new(Mutex::new(None)),
            stats: Arc::new(Mutex::new(QosStats::default())),
        }
    }

    /// Configure rate limiting (bytes per second)
    pub fn set_rate_limit(&self, rate_bps: u64) {
        debug!("Setting rate limit to {} bps", rate_bps);
        *self.rate_limiter.lock().unwrap() = Some(TokenBucket::new(rate_bps));
    }

    /// Remove rate limiting
    pub fn remove_rate_limit(&self) {
        *self.rate_limiter.lock().unwrap() = None;
    }

    /// Enqueue a packet
    pub fn enqueue(&self, packet: QueuedPacket) -> bool {
        let class = packet.qos_class;
        let mut queues = self.queues.lock().unwrap();

        if let Some(queue) = queues.get_mut(&class) {
            let success = queue.enqueue(packet);

            if success {
                let mut stats = self.stats.lock().unwrap();
                stats.packets_enqueued += 1;
            } else {
                let mut stats = self.stats.lock().unwrap();
                stats.packets_dropped += 1;
                stats.buffer_overflows += 1;
            }

            success
        } else {
            false
        }
    }

    /// Dequeue the next packet (priority scheduling)
    pub fn dequeue(&self) -> Option<QueuedPacket> {
        let mut queues = self.queues.lock().unwrap();

        // Try each queue in priority order
        for class in [
            QosClass::RealTime,
            QosClass::Interactive,
            QosClass::Streaming,
            QosClass::Standard,
            QosClass::Bulk,
        ] {
            if let Some(queue) = queues.get_mut(&class) {
                if !queue.is_empty() {
                    // Check rate limiter
                    if let Some(rate_limiter) = self.rate_limiter.lock().unwrap().as_mut() {
                        // Peek at packet size
                        if let Some(packet) = queue.queue.front() {
                            if !rate_limiter.consume(packet.data.len()) {
                                trace!("Rate limit reached, deferring packet");
                                return None;
                            }
                        }
                    }

                    if let Some(packet) = queue.dequeue() {
                        let queue_time = packet.queued_at.elapsed();

                        // Update statistics
                        let mut stats = self.stats.lock().unwrap();
                        stats.packets_dequeued += 1;
                        stats.bytes_transmitted += packet.data.len() as u64;

                        let class_stats = stats.by_class.entry(class).or_insert_with(ClassStats::default);
                        class_stats.packets += 1;
                        class_stats.bytes += packet.data.len() as u64;

                        // Update rolling average queue time
                        let alpha = 0.1; // Exponential moving average factor
                        class_stats.avg_queue_time_ms = class_stats.avg_queue_time_ms * (1.0 - alpha)
                            + queue_time.as_secs_f64() * 1000.0 * alpha;

                        trace!(
                            "Dequeued {} class packet, queue time: {:?}",
                            class.as_str(),
                            queue_time
                        );

                        return Some(packet);
                    }
                }
            }
        }

        None
    }

    /// Get number of queued packets for a class
    pub fn queue_depth(&self, class: QosClass) -> usize {
        let queues = self.queues.lock().unwrap();
        queues.get(&class).map(|q| q.len()).unwrap_or(0)
    }

    /// Get total number of queued packets across all classes
    pub fn total_queue_depth(&self) -> usize {
        let queues = self.queues.lock().unwrap();
        queues.values().map(|q| q.len()).sum()
    }

    /// Get statistics
    pub fn get_stats(&self) -> QosStats {
        self.stats.lock().unwrap().clone()
    }

    /// Clear all queues (for testing)
    pub fn clear(&self) {
        let mut queues = self.queues.lock().unwrap();
        for queue in queues.values_mut() {
            queue.queue.clear();
            queue.bytes_queued = 0;
        }
    }
}

impl Default for QosScheduler {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::thread;

    fn create_test_packet(qos_class: QosClass, size: usize) -> QueuedPacket {
        use std::net::IpAddr;
        QueuedPacket {
            data: vec![0u8; size],
            flow: FlowKey {
                src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
                dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                src_port: 50000,
                dst_port: 443,
                protocol: 6,
            },
            qos_class,
            queued_at: Instant::now(),
        }
    }

    #[test]
    fn test_qos_class_from_app_type() {
        assert_eq!(QosClass::from_app_type(ApplicationType::VoIP), QosClass::RealTime);
        assert_eq!(QosClass::from_app_type(ApplicationType::Gaming), QosClass::RealTime);
        assert_eq!(QosClass::from_app_type(ApplicationType::Video), QosClass::Streaming);
        assert_eq!(QosClass::from_app_type(ApplicationType::Web), QosClass::Standard);
        assert_eq!(QosClass::from_app_type(ApplicationType::FileTransfer), QosClass::Bulk);
    }

    #[test]
    fn test_qos_scheduler_enqueue_dequeue() {
        let scheduler = QosScheduler::new();

        let packet = create_test_packet(QosClass::Standard, 100);
        assert!(scheduler.enqueue(packet));

        assert_eq!(scheduler.queue_depth(QosClass::Standard), 1);

        let dequeued = scheduler.dequeue();
        assert!(dequeued.is_some());
        assert_eq!(dequeued.unwrap().qos_class, QosClass::Standard);

        assert_eq!(scheduler.queue_depth(QosClass::Standard), 0);
    }

    #[test]
    fn test_qos_priority_scheduling() {
        let scheduler = QosScheduler::new();

        // Enqueue packets in reverse priority order
        scheduler.enqueue(create_test_packet(QosClass::Bulk, 100));
        scheduler.enqueue(create_test_packet(QosClass::Standard, 100));
        scheduler.enqueue(create_test_packet(QosClass::RealTime, 100));

        // Should dequeue in priority order
        assert_eq!(scheduler.dequeue().unwrap().qos_class, QosClass::RealTime);
        assert_eq!(scheduler.dequeue().unwrap().qos_class, QosClass::Standard);
        assert_eq!(scheduler.dequeue().unwrap().qos_class, QosClass::Bulk);
    }

    #[test]
    fn test_rate_limiting() {
        let scheduler = QosScheduler::new();

        // Set rate limit to 1000 bytes per second
        scheduler.set_rate_limit(1000);

        // Enqueue 15 packets of 100 bytes each (1500 bytes total)
        for _ in 0..15 {
            scheduler.enqueue(create_test_packet(QosClass::Standard, 100));
        }

        // Should be able to dequeue ~10 packets immediately (1000 bytes)
        let mut dequeued_count = 0;
        while scheduler.dequeue().is_some() {
            dequeued_count += 1;
        }

        assert!(dequeued_count >= 9 && dequeued_count <= 11);

        // Wait for bucket to refill
        thread::sleep(Duration::from_millis(200));

        // Should be able to dequeue a couple more packets
        let more = scheduler.dequeue().is_some();
        assert!(more);
    }

    #[test]
    fn test_token_bucket() {
        let mut bucket = TokenBucket::new(1000); // 1000 bytes per second

        // Should be able to consume up to capacity
        assert!(bucket.consume(1000));
        assert!(!bucket.consume(1)); // No tokens left

        // Wait for refill
        thread::sleep(Duration::from_millis(100));

        // Should have ~100 bytes worth of tokens
        assert!(bucket.consume(50));
        assert!(bucket.consume(50));
    }

    #[test]
    fn test_queue_overflow() {
        let scheduler = QosScheduler::new();

        // Fill up the queue (default max size is 1000)
        for i in 0..1001 {
            let success = scheduler.enqueue(create_test_packet(QosClass::Standard, 100));
            if i < 1000 {
                assert!(success, "Should succeed up to max size");
            } else {
                assert!(!success, "Should fail when queue is full");
            }
        }

        let stats = scheduler.get_stats();
        assert_eq!(stats.packets_dropped, 1);
        assert_eq!(stats.buffer_overflows, 1);
    }

    #[test]
    fn test_statistics() {
        let scheduler = QosScheduler::new();

        scheduler.enqueue(create_test_packet(QosClass::RealTime, 100));
        scheduler.enqueue(create_test_packet(QosClass::Standard, 200));

        scheduler.dequeue();
        scheduler.dequeue();

        let stats = scheduler.get_stats();
        assert_eq!(stats.packets_enqueued, 2);
        assert_eq!(stats.packets_dequeued, 2);
        assert_eq!(stats.bytes_transmitted, 300);
    }
}
