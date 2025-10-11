//! Traffic statistics tracking (Sprint 30)
//!
//! This module tracks packets and bytes matched by routing policies,
//! enabling visibility into policy effectiveness and network utilization.

use crate::{types::FlowKey, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::SystemTime;
use tokio::sync::RwLock;

/// Traffic statistics for a routing policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyStats {
    /// Policy ID
    pub policy_id: u64,

    /// Number of packets matched
    pub packets_matched: u64,

    /// Number of bytes matched
    pub bytes_matched: u64,

    /// Number of active flows matched
    pub active_flows: u64,

    /// Last updated timestamp
    pub last_updated: SystemTime,

    /// First seen timestamp
    pub first_seen: SystemTime,
}

impl Default for PolicyStats {
    fn default() -> Self {
        Self {
            policy_id: 0,
            packets_matched: 0,
            bytes_matched: 0,
            active_flows: 0,
            last_updated: SystemTime::now(),
            first_seen: SystemTime::now(),
        }
    }
}

/// Flow statistics entry
#[derive(Debug, Clone)]
pub struct FlowStats {
    /// Flow key
    pub flow_key: FlowKey,

    /// Matched policy ID
    pub policy_id: u64,

    /// Packet count
    pub packets: u64,

    /// Byte count
    pub bytes: u64,

    /// Last seen timestamp
    pub last_seen: SystemTime,
}

/// Traffic statistics collector
pub struct TrafficStatsCollector {
    /// Per-policy statistics
    policy_stats: Arc<RwLock<HashMap<u64, PolicyStats>>>,

    /// Active flows
    active_flows: Arc<RwLock<HashMap<FlowKey, FlowStats>>>,

    /// Database connection (for periodic snapshots)
    db: Option<Arc<crate::database::Database>>,
}

impl TrafficStatsCollector {
    /// Create a new traffic stats collector
    pub fn new(db: Option<Arc<crate::database::Database>>) -> Self {
        Self {
            policy_stats: Arc::new(RwLock::new(HashMap::new())),
            active_flows: Arc::new(RwLock::new(HashMap::new())),
            db,
        }
    }

    /// Record a packet match for a policy
    pub async fn record_packet(&self, policy_id: u64, flow: FlowKey, packet_size: u64) {
        let now = SystemTime::now();

        // Update policy stats
        {
            let mut stats = self.policy_stats.write().await;
            let policy_stat = stats.entry(policy_id).or_insert_with(|| PolicyStats {
                policy_id,
                packets_matched: 0,
                bytes_matched: 0,
                active_flows: 0,
                last_updated: now,
                first_seen: now,
            });

            policy_stat.packets_matched += 1;
            policy_stat.bytes_matched += packet_size;
            policy_stat.last_updated = now;
        }

        // Update flow stats
        {
            let mut flows = self.active_flows.write().await;
            let flow_stat = flows.entry(flow.clone()).or_insert_with(|| FlowStats {
                flow_key: flow.clone(),
                policy_id,
                packets: 0,
                bytes: 0,
                last_seen: now,
            });

            flow_stat.packets += 1;
            flow_stat.bytes += packet_size;
            flow_stat.last_seen = now;
        }
    }

    /// Get statistics for a specific policy
    pub async fn get_policy_stats(&self, policy_id: u64) -> Option<PolicyStats> {
        let stats = self.policy_stats.read().await;
        stats.get(&policy_id).cloned()
    }

    /// Get statistics for all policies
    pub async fn get_all_policy_stats(&self) -> HashMap<u64, PolicyStats> {
        self.policy_stats.read().await.clone()
    }

    /// Get active flow count for a policy
    pub async fn get_active_flow_count(&self, policy_id: u64) -> u64 {
        let flows = self.active_flows.read().await;
        flows.values().filter(|f| f.policy_id == policy_id).count() as u64
    }

    /// Update active flow count in policy stats
    pub async fn update_flow_counts(&self) {
        let flows = self.active_flows.read().await;
        let mut stats = self.policy_stats.write().await;

        // Count flows per policy
        let mut flow_counts: HashMap<u64, u64> = HashMap::new();
        for flow_stat in flows.values() {
            *flow_counts.entry(flow_stat.policy_id).or_insert(0) += 1;
        }

        // Update policy stats - set to 0 if no flows, otherwise update count
        for (policy_id, stat) in stats.iter_mut() {
            stat.active_flows = *flow_counts.get(policy_id).unwrap_or(&0);
        }
    }

    /// Clean up stale flows (not seen in the last `timeout` duration)
    pub async fn cleanup_stale_flows(&self, timeout: std::time::Duration) -> u64 {
        let mut flows = self.active_flows.write().await;
        let now = SystemTime::now();
        let mut removed = 0;

        flows.retain(|_, flow_stat| {
            let age = now.duration_since(flow_stat.last_seen).unwrap_or_default();
            let keep = age < timeout;
            if !keep {
                removed += 1;
            }
            keep
        });

        // Update flow counts after cleanup
        drop(flows);
        self.update_flow_counts().await;

        removed
    }

    /// Store statistics snapshot to database
    pub async fn store_snapshot(&self) -> Result<()> {
        if let Some(db) = &self.db {
            let stats = self.policy_stats.read().await;
            for policy_stat in stats.values() {
                db.store_policy_stats(policy_stat).await?;
            }
        }
        Ok(())
    }

    /// Reset statistics for a specific policy
    pub async fn reset_policy_stats(&self, policy_id: u64) {
        let mut stats = self.policy_stats.write().await;
        stats.remove(&policy_id);

        // Remove flows associated with this policy
        let mut flows = self.active_flows.write().await;
        flows.retain(|_, flow_stat| flow_stat.policy_id != policy_id);
    }

    /// Reset all statistics
    pub async fn reset_all_stats(&self) {
        let mut stats = self.policy_stats.write().await;
        stats.clear();

        let mut flows = self.active_flows.write().await;
        flows.clear();
    }

    /// Get total active flows
    pub async fn get_total_active_flows(&self) -> u64 {
        self.active_flows.read().await.len() as u64
    }

    /// Get total packets across all policies
    pub async fn get_total_packets(&self) -> u64 {
        let stats = self.policy_stats.read().await;
        stats.values().map(|s| s.packets_matched).sum()
    }

    /// Get total bytes across all policies
    pub async fn get_total_bytes(&self) -> u64 {
        let stats = self.policy_stats.read().await;
        stats.values().map(|s| s.bytes_matched).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    #[tokio::test]
    async fn test_traffic_stats_collection() {
        let collector = TrafficStatsCollector::new(None);

        let flow = FlowKey {
            src_ip: "192.168.1.1".parse().unwrap(),
            dst_ip: "10.0.0.1".parse().unwrap(),
            src_port: 12345,
            dst_port: 80,
            protocol: 6, // TCP
        };

        // Record some packets
        collector.record_packet(1, flow.clone(), 1500).await;
        collector.record_packet(1, flow.clone(), 1500).await;
        collector.record_packet(1, flow.clone(), 1500).await;

        // Check stats
        let stats = collector.get_policy_stats(1).await.unwrap();
        assert_eq!(stats.packets_matched, 3);
        assert_eq!(stats.bytes_matched, 4500);
    }

    #[tokio::test]
    async fn test_multiple_policies() {
        let collector = TrafficStatsCollector::new(None);

        let flow1 = FlowKey {
            src_ip: "192.168.1.1".parse().unwrap(),
            dst_ip: "10.0.0.1".parse().unwrap(),
            src_port: 12345,
            dst_port: 80,
            protocol: 6,
        };

        let flow2 = FlowKey {
            src_ip: "192.168.1.2".parse().unwrap(),
            dst_ip: "10.0.0.2".parse().unwrap(),
            src_port: 54321,
            dst_port: 443,
            protocol: 6,
        };

        // Record packets for different policies
        collector.record_packet(1, flow1.clone(), 1500).await;
        collector.record_packet(2, flow2.clone(), 1400).await;
        collector.record_packet(1, flow1.clone(), 1500).await;

        // Check stats for policy 1
        let stats1 = collector.get_policy_stats(1).await.unwrap();
        assert_eq!(stats1.packets_matched, 2);
        assert_eq!(stats1.bytes_matched, 3000);

        // Check stats for policy 2
        let stats2 = collector.get_policy_stats(2).await.unwrap();
        assert_eq!(stats2.packets_matched, 1);
        assert_eq!(stats2.bytes_matched, 1400);
    }

    #[tokio::test]
    async fn test_flow_cleanup() {
        use std::time::Duration;
        use tokio::time::sleep;

        let collector = TrafficStatsCollector::new(None);

        let flow = FlowKey {
            src_ip: "192.168.1.1".parse().unwrap(),
            dst_ip: "10.0.0.1".parse().unwrap(),
            src_port: 12345,
            dst_port: 80,
            protocol: 6,
        };

        // Record a packet
        collector.record_packet(1, flow.clone(), 1500).await;

        // Update flow counts
        collector.update_flow_counts().await;
        let stats = collector.get_policy_stats(1).await.unwrap();
        assert_eq!(stats.active_flows, 1);

        // Sleep to make flow stale
        sleep(Duration::from_millis(100)).await;

        // Cleanup stale flows (timeout = 50ms, so our flow should be removed)
        let removed = collector.cleanup_stale_flows(Duration::from_millis(50)).await;
        assert_eq!(removed, 1);

        // Active flows should be 0 now
        let stats = collector.get_policy_stats(1).await.unwrap();
        assert_eq!(stats.active_flows, 0);
    }

    #[tokio::test]
    async fn test_stats_reset() {
        let collector = TrafficStatsCollector::new(None);

        let flow = FlowKey {
            src_ip: "192.168.1.1".parse().unwrap(),
            dst_ip: "10.0.0.1".parse().unwrap(),
            src_port: 12345,
            dst_port: 80,
            protocol: 6,
        };

        // Record some packets
        collector.record_packet(1, flow.clone(), 1500).await;
        collector.record_packet(2, flow.clone(), 1400).await;

        // Reset policy 1
        collector.reset_policy_stats(1).await;

        // Policy 1 should be gone
        assert!(collector.get_policy_stats(1).await.is_none());

        // Policy 2 should still exist
        assert!(collector.get_policy_stats(2).await.is_some());

        // Reset all
        collector.reset_all_stats().await;
        assert!(collector.get_policy_stats(2).await.is_none());
    }
}
