//! Tunnel Management for Traffic Engineering

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;
use chrono::{DateTime, Utc};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TunnelState {
    Down,
    Up,
    Degraded,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelMetrics {
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub packets_sent: u64,
    pub packets_received: u64,
    pub errors: u64,
    pub last_updated: DateTime<Utc>,
}

impl TunnelMetrics {
    pub fn new() -> Self {
        Self {
            bytes_sent: 0,
            bytes_received: 0,
            packets_sent: 0,
            packets_received: 0,
            errors: 0,
            last_updated: Utc::now(),
        }
    }

    pub fn update_sent(&mut self, bytes: u64, packets: u64) {
        self.bytes_sent += bytes;
        self.packets_sent += packets;
        self.last_updated = Utc::now();
    }

    pub fn update_received(&mut self, bytes: u64, packets: u64) {
        self.bytes_received += bytes;
        self.packets_received += packets;
        self.last_updated = Utc::now();
    }

    pub fn record_error(&mut self) {
        self.errors += 1;
        self.last_updated = Utc::now();
    }

    pub fn total_traffic(&self) -> u64 {
        self.bytes_sent + self.bytes_received
    }
}

impl Default for TunnelMetrics {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tunnel {
    pub id: Uuid,
    pub name: String,
    pub source: String,
    pub destination: String,
    pub path: Vec<String>,
    pub bandwidth_mbps: f64,
    pub reserved_bandwidth: f64,
    pub state: TunnelState,
    pub priority: u8,
    pub metrics: TunnelMetrics,
    pub created_at: DateTime<Utc>,
}

impl Tunnel {
    pub fn new(
        name: String,
        source: String,
        destination: String,
        path: Vec<String>,
        bandwidth_mbps: f64,
        priority: u8,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            name,
            source,
            destination,
            path,
            bandwidth_mbps,
            reserved_bandwidth: bandwidth_mbps,
            state: TunnelState::Down,
            priority,
            metrics: TunnelMetrics::new(),
            created_at: Utc::now(),
        }
    }

    pub fn bring_up(&mut self) {
        self.state = TunnelState::Up;
    }

    pub fn bring_down(&mut self) {
        self.state = TunnelState::Down;
    }

    pub fn degrade(&mut self) {
        self.state = TunnelState::Degraded;
    }

    pub fn is_operational(&self) -> bool {
        matches!(self.state, TunnelState::Up | TunnelState::Degraded)
    }

    pub fn hop_count(&self) -> usize {
        self.path.len().saturating_sub(1)
    }

    pub fn utilization_percent(&self) -> f64 {
        if self.reserved_bandwidth == 0.0 {
            return 0.0;
        }

        // Simplified utilization based on recent traffic
        // In production, this would be more sophisticated
        let recent_mbps = (self.metrics.total_traffic() as f64 * 8.0) / (1_000_000.0 * 60.0);
        (recent_mbps / self.reserved_bandwidth) * 100.0
    }
}

pub struct TunnelManager {
    tunnels: Arc<RwLock<HashMap<Uuid, Tunnel>>>,
}

impl TunnelManager {
    pub fn new() -> Self {
        Self {
            tunnels: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn create_tunnel(
        &self,
        name: String,
        source: String,
        destination: String,
        path: Vec<String>,
        bandwidth_mbps: f64,
        priority: u8,
    ) -> Uuid {
        let tunnel = Tunnel::new(name, source, destination, path, bandwidth_mbps, priority);
        let id = tunnel.id;

        let mut tunnels = self.tunnels.write().await;
        tunnels.insert(id, tunnel);

        id
    }

    pub async fn get_tunnel(&self, id: &Uuid) -> Option<Tunnel> {
        let tunnels = self.tunnels.read().await;
        tunnels.get(id).cloned()
    }

    pub async fn update_tunnel_state(&self, id: &Uuid, state: TunnelState) -> bool {
        let mut tunnels = self.tunnels.write().await;

        if let Some(tunnel) = tunnels.get_mut(id) {
            tunnel.state = state;
            true
        } else {
            false
        }
    }

    pub async fn bring_tunnel_up(&self, id: &Uuid) -> bool {
        let mut tunnels = self.tunnels.write().await;

        if let Some(tunnel) = tunnels.get_mut(id) {
            tunnel.bring_up();
            true
        } else {
            false
        }
    }

    pub async fn bring_tunnel_down(&self, id: &Uuid) -> bool {
        let mut tunnels = self.tunnels.write().await;

        if let Some(tunnel) = tunnels.get_mut(id) {
            tunnel.bring_down();
            true
        } else {
            false
        }
    }

    pub async fn delete_tunnel(&self, id: &Uuid) -> bool {
        let mut tunnels = self.tunnels.write().await;
        tunnels.remove(id).is_some()
    }

    pub async fn list_tunnels(&self) -> Vec<Tunnel> {
        let tunnels = self.tunnels.read().await;
        tunnels.values().cloned().collect()
    }

    pub async fn get_operational_tunnels(&self) -> Vec<Tunnel> {
        let tunnels = self.tunnels.read().await;
        tunnels.values()
            .filter(|t| t.is_operational())
            .cloned()
            .collect()
    }

    pub async fn get_tunnels_by_path(&self, source: &str, destination: &str) -> Vec<Tunnel> {
        let tunnels = self.tunnels.read().await;
        tunnels.values()
            .filter(|t| t.source == source && t.destination == destination)
            .cloned()
            .collect()
    }

    pub async fn update_tunnel_metrics(
        &self,
        id: &Uuid,
        bytes_sent: u64,
        bytes_received: u64,
        packets_sent: u64,
        packets_received: u64,
    ) -> bool {
        let mut tunnels = self.tunnels.write().await;

        if let Some(tunnel) = tunnels.get_mut(id) {
            tunnel.metrics.update_sent(bytes_sent, packets_sent);
            tunnel.metrics.update_received(bytes_received, packets_received);
            true
        } else {
            false
        }
    }

    pub async fn record_tunnel_error(&self, id: &Uuid) -> bool {
        let mut tunnels = self.tunnels.write().await;

        if let Some(tunnel) = tunnels.get_mut(id) {
            tunnel.metrics.record_error();

            // Auto-degrade tunnel if too many errors
            if tunnel.metrics.errors > 10 {
                tunnel.degrade();
            }

            true
        } else {
            false
        }
    }

    pub async fn get_total_bandwidth(&self) -> f64 {
        let tunnels = self.tunnels.read().await;
        tunnels.values()
            .filter(|t| t.is_operational())
            .map(|t| t.reserved_bandwidth)
            .sum()
    }

    pub async fn get_tunnel_count(&self) -> usize {
        let tunnels = self.tunnels.read().await;
        tunnels.len()
    }

    pub async fn get_high_priority_tunnels(&self) -> Vec<Tunnel> {
        let tunnels = self.tunnels.read().await;
        tunnels.values()
            .filter(|t| t.priority >= 5)
            .cloned()
            .collect()
    }

    /// Reroute a tunnel through a new path
    pub async fn reroute_tunnel(&self, id: &Uuid, new_path: Vec<String>) -> bool {
        let mut tunnels = self.tunnels.write().await;

        if let Some(tunnel) = tunnels.get_mut(id) {
            tunnel.path = new_path;
            true
        } else {
            false
        }
    }

    /// Adjust tunnel bandwidth reservation
    pub async fn adjust_bandwidth(&self, id: &Uuid, new_bandwidth: f64) -> bool {
        let mut tunnels = self.tunnels.write().await;

        if let Some(tunnel) = tunnels.get_mut(id) {
            tunnel.reserved_bandwidth = new_bandwidth;
            true
        } else {
            false
        }
    }
}

impl Default for TunnelManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tunnel_metrics_creation() {
        let metrics = TunnelMetrics::new();

        assert_eq!(metrics.bytes_sent, 0);
        assert_eq!(metrics.bytes_received, 0);
        assert_eq!(metrics.errors, 0);
    }

    #[test]
    fn test_tunnel_metrics_update() {
        let mut metrics = TunnelMetrics::new();

        metrics.update_sent(1000, 10);
        metrics.update_received(2000, 20);

        assert_eq!(metrics.bytes_sent, 1000);
        assert_eq!(metrics.bytes_received, 2000);
        assert_eq!(metrics.packets_sent, 10);
        assert_eq!(metrics.packets_received, 20);
        assert_eq!(metrics.total_traffic(), 3000);
    }

    #[test]
    fn test_tunnel_metrics_errors() {
        let mut metrics = TunnelMetrics::new();

        metrics.record_error();
        metrics.record_error();

        assert_eq!(metrics.errors, 2);
    }

    #[test]
    fn test_tunnel_creation() {
        let tunnel = Tunnel::new(
            "test-tunnel".to_string(),
            "A".to_string(),
            "B".to_string(),
            vec!["A".to_string(), "B".to_string()],
            1000.0,
            5,
        );

        assert_eq!(tunnel.name, "test-tunnel");
        assert_eq!(tunnel.source, "A");
        assert_eq!(tunnel.destination, "B");
        assert_eq!(tunnel.bandwidth_mbps, 1000.0);
        assert_eq!(tunnel.priority, 5);
        assert_eq!(tunnel.state, TunnelState::Down);
    }

    #[test]
    fn test_tunnel_state_transitions() {
        let mut tunnel = Tunnel::new(
            "test".to_string(),
            "A".to_string(),
            "B".to_string(),
            vec!["A".to_string(), "B".to_string()],
            1000.0,
            5,
        );

        assert_eq!(tunnel.state, TunnelState::Down);
        assert!(!tunnel.is_operational());

        tunnel.bring_up();
        assert_eq!(tunnel.state, TunnelState::Up);
        assert!(tunnel.is_operational());

        tunnel.degrade();
        assert_eq!(tunnel.state, TunnelState::Degraded);
        assert!(tunnel.is_operational());

        tunnel.bring_down();
        assert_eq!(tunnel.state, TunnelState::Down);
        assert!(!tunnel.is_operational());
    }

    #[test]
    fn test_tunnel_hop_count() {
        let tunnel = Tunnel::new(
            "test".to_string(),
            "A".to_string(),
            "C".to_string(),
            vec!["A".to_string(), "B".to_string(), "C".to_string()],
            1000.0,
            5,
        );

        assert_eq!(tunnel.hop_count(), 2);
    }

    #[tokio::test]
    async fn test_tunnel_manager_creation() {
        let manager = TunnelManager::new();
        assert_eq!(manager.get_tunnel_count().await, 0);
    }

    #[tokio::test]
    async fn test_create_tunnel() {
        let manager = TunnelManager::new();

        let id = manager.create_tunnel(
            "test-tunnel".to_string(),
            "A".to_string(),
            "B".to_string(),
            vec!["A".to_string(), "B".to_string()],
            1000.0,
            5,
        ).await;

        let tunnel = manager.get_tunnel(&id).await;
        assert!(tunnel.is_some());
        assert_eq!(tunnel.unwrap().name, "test-tunnel");
    }

    #[tokio::test]
    async fn test_list_tunnels() {
        let manager = TunnelManager::new();

        manager.create_tunnel(
            "tunnel1".to_string(),
            "A".to_string(),
            "B".to_string(),
            vec!["A".to_string(), "B".to_string()],
            1000.0,
            5,
        ).await;

        manager.create_tunnel(
            "tunnel2".to_string(),
            "B".to_string(),
            "C".to_string(),
            vec!["B".to_string(), "C".to_string()],
            500.0,
            3,
        ).await;

        let tunnels = manager.list_tunnels().await;
        assert_eq!(tunnels.len(), 2);
    }

    #[tokio::test]
    async fn test_bring_tunnel_up_down() {
        let manager = TunnelManager::new();

        let id = manager.create_tunnel(
            "test".to_string(),
            "A".to_string(),
            "B".to_string(),
            vec!["A".to_string(), "B".to_string()],
            1000.0,
            5,
        ).await;

        assert!(manager.bring_tunnel_up(&id).await);
        let tunnel = manager.get_tunnel(&id).await.unwrap();
        assert_eq!(tunnel.state, TunnelState::Up);

        assert!(manager.bring_tunnel_down(&id).await);
        let tunnel = manager.get_tunnel(&id).await.unwrap();
        assert_eq!(tunnel.state, TunnelState::Down);
    }

    #[tokio::test]
    async fn test_delete_tunnel() {
        let manager = TunnelManager::new();

        let id = manager.create_tunnel(
            "test".to_string(),
            "A".to_string(),
            "B".to_string(),
            vec!["A".to_string(), "B".to_string()],
            1000.0,
            5,
        ).await;

        assert!(manager.delete_tunnel(&id).await);
        assert!(manager.get_tunnel(&id).await.is_none());
    }

    #[tokio::test]
    async fn test_get_operational_tunnels() {
        let manager = TunnelManager::new();

        let id1 = manager.create_tunnel(
            "up".to_string(),
            "A".to_string(),
            "B".to_string(),
            vec!["A".to_string(), "B".to_string()],
            1000.0,
            5,
        ).await;

        let _id2 = manager.create_tunnel(
            "down".to_string(),
            "B".to_string(),
            "C".to_string(),
            vec!["B".to_string(), "C".to_string()],
            500.0,
            3,
        ).await;

        manager.bring_tunnel_up(&id1).await;
        // id2 stays down

        let operational = manager.get_operational_tunnels().await;
        assert_eq!(operational.len(), 1);
        assert_eq!(operational[0].name, "up");
    }

    #[tokio::test]
    async fn test_get_tunnels_by_path() {
        let manager = TunnelManager::new();

        manager.create_tunnel(
            "t1".to_string(),
            "A".to_string(),
            "B".to_string(),
            vec!["A".to_string(), "B".to_string()],
            1000.0,
            5,
        ).await;

        manager.create_tunnel(
            "t2".to_string(),
            "A".to_string(),
            "B".to_string(),
            vec!["A".to_string(), "X".to_string(), "B".to_string()],
            500.0,
            3,
        ).await;

        manager.create_tunnel(
            "t3".to_string(),
            "B".to_string(),
            "C".to_string(),
            vec!["B".to_string(), "C".to_string()],
            800.0,
            4,
        ).await;

        let tunnels = manager.get_tunnels_by_path("A", "B").await;
        assert_eq!(tunnels.len(), 2);
    }

    #[tokio::test]
    async fn test_update_tunnel_metrics() {
        let manager = TunnelManager::new();

        let id = manager.create_tunnel(
            "test".to_string(),
            "A".to_string(),
            "B".to_string(),
            vec!["A".to_string(), "B".to_string()],
            1000.0,
            5,
        ).await;

        assert!(manager.update_tunnel_metrics(&id, 1000, 2000, 10, 20).await);

        let tunnel = manager.get_tunnel(&id).await.unwrap();
        assert_eq!(tunnel.metrics.bytes_sent, 1000);
        assert_eq!(tunnel.metrics.bytes_received, 2000);
    }

    #[tokio::test]
    async fn test_record_tunnel_error_auto_degrade() {
        let manager = TunnelManager::new();

        let id = manager.create_tunnel(
            "test".to_string(),
            "A".to_string(),
            "B".to_string(),
            vec!["A".to_string(), "B".to_string()],
            1000.0,
            5,
        ).await;

        manager.bring_tunnel_up(&id).await;

        // Record enough errors to trigger auto-degradation
        for _ in 0..11 {
            manager.record_tunnel_error(&id).await;
        }

        let tunnel = manager.get_tunnel(&id).await.unwrap();
        assert_eq!(tunnel.state, TunnelState::Degraded);
    }

    #[tokio::test]
    async fn test_get_total_bandwidth() {
        let manager = TunnelManager::new();

        let id1 = manager.create_tunnel(
            "t1".to_string(),
            "A".to_string(),
            "B".to_string(),
            vec!["A".to_string(), "B".to_string()],
            1000.0,
            5,
        ).await;

        let id2 = manager.create_tunnel(
            "t2".to_string(),
            "B".to_string(),
            "C".to_string(),
            vec!["B".to_string(), "C".to_string()],
            500.0,
            3,
        ).await;

        manager.bring_tunnel_up(&id1).await;
        manager.bring_tunnel_up(&id2).await;

        let total = manager.get_total_bandwidth().await;
        assert_eq!(total, 1500.0);
    }

    #[tokio::test]
    async fn test_get_high_priority_tunnels() {
        let manager = TunnelManager::new();

        manager.create_tunnel(
            "high1".to_string(),
            "A".to_string(),
            "B".to_string(),
            vec!["A".to_string(), "B".to_string()],
            1000.0,
            6,
        ).await;

        manager.create_tunnel(
            "low".to_string(),
            "B".to_string(),
            "C".to_string(),
            vec!["B".to_string(), "C".to_string()],
            500.0,
            2,
        ).await;

        manager.create_tunnel(
            "high2".to_string(),
            "C".to_string(),
            "D".to_string(),
            vec!["C".to_string(), "D".to_string()],
            800.0,
            7,
        ).await;

        let high_priority = manager.get_high_priority_tunnels().await;
        assert_eq!(high_priority.len(), 2);
    }

    #[tokio::test]
    async fn test_reroute_tunnel() {
        let manager = TunnelManager::new();

        let id = manager.create_tunnel(
            "test".to_string(),
            "A".to_string(),
            "C".to_string(),
            vec!["A".to_string(), "B".to_string(), "C".to_string()],
            1000.0,
            5,
        ).await;

        let new_path = vec!["A".to_string(), "X".to_string(), "Y".to_string(), "C".to_string()];
        assert!(manager.reroute_tunnel(&id, new_path.clone()).await);

        let tunnel = manager.get_tunnel(&id).await.unwrap();
        assert_eq!(tunnel.path, new_path);
    }

    #[tokio::test]
    async fn test_adjust_bandwidth() {
        let manager = TunnelManager::new();

        let id = manager.create_tunnel(
            "test".to_string(),
            "A".to_string(),
            "B".to_string(),
            vec!["A".to_string(), "B".to_string()],
            1000.0,
            5,
        ).await;

        assert!(manager.adjust_bandwidth(&id, 1500.0).await);

        let tunnel = manager.get_tunnel(&id).await.unwrap();
        assert_eq!(tunnel.reserved_bandwidth, 1500.0);
    }
}
