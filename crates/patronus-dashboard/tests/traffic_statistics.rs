//! Integration tests for traffic statistics (Sprint 30)

use patronus_sdwan::{traffic_stats::TrafficStatsCollector, types::FlowKey};
use std::time::Duration;
use tokio::time::sleep;

#[tokio::test]
async fn test_traffic_stats_end_to_end() {
    // Create traffic stats collector without database
    let collector = TrafficStatsCollector::new(None);

    // Create test flow
    let flow = FlowKey {
        src_ip: "192.168.1.10".parse().unwrap(),
        dst_ip: "10.0.0.5".parse().unwrap(),
        src_port: 45678,
        dst_port: 443,
        protocol: 6, // TCP
    };

    // Record some traffic
    collector.record_packet(1, flow.clone(), 1500).await;
    collector.record_packet(1, flow.clone(), 1400).await;
    collector.record_packet(1, flow.clone(), 1600).await;

    // Get stats
    let stats = collector.get_policy_stats(1).await
        .expect("Should have stats for policy 1");

    assert_eq!(stats.policy_id, 1);
    assert_eq!(stats.packets_matched, 3);
    assert_eq!(stats.bytes_matched, 4500);

    // Update flow counts
    collector.update_flow_counts().await;
    let stats = collector.get_policy_stats(1).await.unwrap();
    assert_eq!(stats.active_flows, 1);
}

#[tokio::test]
async fn test_traffic_stats_multiple_policies() {
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
    collector.record_packet(1, flow1.clone(), 1000).await;
    collector.record_packet(2, flow2.clone(), 2000).await;
    collector.record_packet(1, flow1.clone(), 1000).await;

    // Check policy 1
    let stats1 = collector.get_policy_stats(1).await.unwrap();
    assert_eq!(stats1.packets_matched, 2);
    assert_eq!(stats1.bytes_matched, 2000);

    // Check policy 2
    let stats2 = collector.get_policy_stats(2).await.unwrap();
    assert_eq!(stats2.packets_matched, 1);
    assert_eq!(stats2.bytes_matched, 2000);

    // Get all stats
    let all_stats = collector.get_all_policy_stats().await;
    assert_eq!(all_stats.len(), 2);
    assert!(all_stats.contains_key(&1));
    assert!(all_stats.contains_key(&2));
}

#[tokio::test]
async fn test_traffic_stats_flow_cleanup() {
    let collector = TrafficStatsCollector::new(None);

    let flow = FlowKey {
        src_ip: "192.168.1.1".parse().unwrap(),
        dst_ip: "10.0.0.1".parse().unwrap(),
        src_port: 12345,
        dst_port: 80,
        protocol: 6,
    };

    // Record packet
    collector.record_packet(1, flow.clone(), 1500).await;

    // Update flow counts
    collector.update_flow_counts().await;
    let stats = collector.get_policy_stats(1).await.unwrap();
    assert_eq!(stats.active_flows, 1);

    // Sleep to make flow stale
    sleep(Duration::from_millis(100)).await;

    // Cleanup stale flows (50ms timeout, so our 100ms old flow should be removed)
    let removed = collector.cleanup_stale_flows(Duration::from_millis(50)).await;
    assert_eq!(removed, 1);

    // Active flows should be 0 now
    let stats = collector.get_policy_stats(1).await.unwrap();
    assert_eq!(stats.active_flows, 0);

    // Total active flows should be 0
    let total = collector.get_total_active_flows().await;
    assert_eq!(total, 0);
}

#[tokio::test]
async fn test_traffic_stats_reset() {
    let collector = TrafficStatsCollector::new(None);

    let flow = FlowKey {
        src_ip: "192.168.1.1".parse().unwrap(),
        dst_ip: "10.0.0.1".parse().unwrap(),
        src_port: 12345,
        dst_port: 80,
        protocol: 6,
    };

    // Record packets for multiple policies
    collector.record_packet(1, flow.clone(), 1500).await;
    collector.record_packet(2, flow.clone(), 1400).await;

    // Verify stats exist
    assert!(collector.get_policy_stats(1).await.is_some());
    assert!(collector.get_policy_stats(2).await.is_some());

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

#[tokio::test]
async fn test_traffic_stats_totals() {
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

    // Record packets
    collector.record_packet(1, flow1.clone(), 1000).await;
    collector.record_packet(2, flow2.clone(), 2000).await;
    collector.record_packet(1, flow1.clone(), 1500).await;

    // Check totals
    let total_packets = collector.get_total_packets().await;
    assert_eq!(total_packets, 3);

    let total_bytes = collector.get_total_bytes().await;
    assert_eq!(total_bytes, 4500);

    // Update flow counts
    collector.update_flow_counts().await;

    let total_flows = collector.get_total_active_flows().await;
    assert_eq!(total_flows, 2);
}
