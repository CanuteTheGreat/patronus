//! Cluster configuration and node management

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use parking_lot::RwLock;
use uuid::Uuid;

/// Node role in the cluster
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NodeRole {
    Leader,
    Follower,
    Candidate,
}

/// Cluster node information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterNode {
    pub id: String,
    pub addr: SocketAddr,
    pub role: NodeRole,
    pub last_heartbeat: chrono::DateTime<chrono::Utc>,
    pub healthy: bool,
}

/// Cluster configuration
#[derive(Debug, Clone)]
pub struct ClusterConfig {
    /// This node's ID
    pub node_id: String,
    /// This node's address
    pub node_addr: SocketAddr,
    /// Peer node addresses
    pub peers: Vec<SocketAddr>,
    /// Heartbeat interval in seconds
    pub heartbeat_interval: u64,
    /// Election timeout in seconds
    pub election_timeout: u64,
    /// Data directory for raft logs
    pub data_dir: String,
}

impl Default for ClusterConfig {
    fn default() -> Self {
        Self {
            node_id: Uuid::new_v4().to_string(),
            node_addr: "127.0.0.1:8443".parse().unwrap(),
            peers: Vec::new(),
            heartbeat_interval: 1,
            election_timeout: 5,
            data_dir: "./data/raft".to_string(),
        }
    }
}

/// Cluster state manager
pub struct ClusterState {
    nodes: Arc<RwLock<HashMap<String, ClusterNode>>>,
    local_node_id: String,
}

impl ClusterState {
    pub fn new(node_id: String) -> Self {
        Self {
            nodes: Arc::new(RwLock::new(HashMap::new())),
            local_node_id: node_id,
        }
    }

    /// Add or update a node in the cluster
    pub fn update_node(&self, node: ClusterNode) {
        self.nodes.write().insert(node.id.clone(), node);
    }

    /// Remove a node from the cluster
    pub fn remove_node(&self, node_id: &str) {
        self.nodes.write().remove(node_id);
    }

    /// Get all nodes in the cluster
    pub fn get_nodes(&self) -> Vec<ClusterNode> {
        self.nodes.read().values().cloned().collect()
    }

    /// Get a specific node
    pub fn get_node(&self, node_id: &str) -> Option<ClusterNode> {
        self.nodes.read().get(node_id).cloned()
    }

    /// Get the current leader node
    pub fn get_leader(&self) -> Option<ClusterNode> {
        self.nodes
            .read()
            .values()
            .find(|n| n.role == NodeRole::Leader)
            .cloned()
    }

    /// Check if this node is the leader
    pub fn is_leader(&self) -> bool {
        self.get_node(&self.local_node_id)
            .map(|n| n.role == NodeRole::Leader)
            .unwrap_or(false)
    }

    /// Get healthy node count
    pub fn healthy_count(&self) -> usize {
        self.nodes.read().values().filter(|n| n.healthy).count()
    }

    /// Get total node count
    pub fn total_count(&self) -> usize {
        self.nodes.read().len()
    }

    /// Update node health status
    pub fn update_health(&self, node_id: &str, healthy: bool) {
        if let Some(node) = self.nodes.write().get_mut(node_id) {
            node.healthy = healthy;
            node.last_heartbeat = chrono::Utc::now();
        }
    }

    /// Check for stale nodes (no heartbeat)
    pub fn check_stale_nodes(&self, timeout_secs: u64) -> Vec<String> {
        let cutoff = chrono::Utc::now() - chrono::Duration::seconds(timeout_secs as i64);
        self.nodes
            .read()
            .values()
            .filter(|n| n.last_heartbeat < cutoff)
            .map(|n| n.id.clone())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cluster_state() {
        let state = ClusterState::new("node1".to_string());

        let node = ClusterNode {
            id: "node1".to_string(),
            addr: "127.0.0.1:8443".parse().unwrap(),
            role: NodeRole::Leader,
            last_heartbeat: chrono::Utc::now(),
            healthy: true,
        };

        state.update_node(node.clone());

        assert_eq!(state.total_count(), 1);
        assert_eq!(state.healthy_count(), 1);
        assert!(state.is_leader());
        assert!(state.get_leader().is_some());
    }

    #[test]
    fn test_stale_nodes() {
        let state = ClusterState::new("node1".to_string());

        let old_node = ClusterNode {
            id: "old".to_string(),
            addr: "127.0.0.1:8443".parse().unwrap(),
            role: NodeRole::Follower,
            last_heartbeat: chrono::Utc::now() - chrono::Duration::seconds(100),
            healthy: true,
        };

        state.update_node(old_node);

        let stale = state.check_stale_nodes(10);
        assert_eq!(stale.len(), 1);
        assert_eq!(stale[0], "old");
    }
}
