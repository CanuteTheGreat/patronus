//! Leader election using simplified Raft-like algorithm

use super::cluster::{ClusterNode, ClusterState, NodeRole};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tokio::time::{interval, sleep};
use tracing::{info, warn};

/// Leader election manager
pub struct LeaderElection {
    cluster_state: Arc<ClusterState>,
    node_id: String,
    node_addr: SocketAddr,
    election_timeout: Duration,
    heartbeat_interval: Duration,
    current_term: Arc<RwLock<u64>>,
    voted_for: Arc<RwLock<Option<String>>>,
}

impl LeaderElection {
    pub fn new(
        cluster_state: Arc<ClusterState>,
        node_id: String,
        node_addr: SocketAddr,
        election_timeout_secs: u64,
        heartbeat_interval_secs: u64,
    ) -> Self {
        Self {
            cluster_state,
            node_id,
            node_addr,
            election_timeout: Duration::from_secs(election_timeout_secs),
            heartbeat_interval: Duration::from_secs(heartbeat_interval_secs),
            current_term: Arc::new(RwLock::new(0)),
            voted_for: Arc::new(RwLock::new(None)),
        }
    }

    /// Create with default address (for backward compatibility)
    pub fn new_with_defaults(
        cluster_state: Arc<ClusterState>,
        node_id: String,
        election_timeout_secs: u64,
        heartbeat_interval_secs: u64,
    ) -> Self {
        let default_addr: SocketAddr = "127.0.0.1:8443".parse()
            .expect("Default address is valid");
        Self::new(cluster_state, node_id, default_addr, election_timeout_secs, heartbeat_interval_secs)
    }

    /// Start the leader election process
    pub async fn start(&self) {
        info!("Starting leader election for node {}", self.node_id);

        // Initially start as follower
        self.become_follower().await;

        // Spawn election timeout checker
        let election_handle = self.spawn_election_timeout();

        // Spawn heartbeat sender (if leader)
        let heartbeat_handle = self.spawn_heartbeat_sender();

        // Wait for both tasks
        tokio::select! {
            _ = election_handle => {}
            _ = heartbeat_handle => {}
        }
    }

    /// Become a follower
    async fn become_follower(&self) {
        info!("Node {} becoming follower", self.node_id);
        self.update_role(NodeRole::Follower).await;
    }

    /// Become a candidate and start election
    async fn become_candidate(&self) {
        info!("Node {} becoming candidate", self.node_id);
        self.update_role(NodeRole::Candidate).await;

        // Increment term
        let mut term = self.current_term.write().await;
        *term += 1;
        let current_term = *term;
        drop(term);

        // Vote for self
        *self.voted_for.write().await = Some(self.node_id.clone());

        // In a real implementation, we would request votes from other nodes
        // For now, simplified: become leader if no other leader exists
        if self.cluster_state.get_leader().is_none() {
            self.become_leader(current_term).await;
        }
    }

    /// Become the leader
    async fn become_leader(&self, term: u64) {
        info!("Node {} becoming leader for term {}", self.node_id, term);
        self.update_role(NodeRole::Leader).await;
    }

    /// Update this node's role in cluster state
    async fn update_role(&self, role: NodeRole) {
        let node = ClusterNode {
            id: self.node_id.clone(),
            addr: self.node_addr,
            role,
            last_heartbeat: chrono::Utc::now(),
            healthy: true,
        };
        self.cluster_state.update_node(node);
    }

    /// Spawn task to check election timeout
    fn spawn_election_timeout(&self) -> tokio::task::JoinHandle<()> {
        let cluster_state = self.cluster_state.clone();
        let node_id = self.node_id.clone();
        let election_timeout = self.election_timeout;
        let current_term = self.current_term.clone();
        let voted_for = self.voted_for.clone();

        tokio::spawn(async move {
            let mut interval_timer = interval(election_timeout / 2);

            loop {
                interval_timer.tick().await;

                // Check if we're a follower with no leader
                if let Some(node) = cluster_state.get_node(&node_id) {
                    if node.role == NodeRole::Follower && cluster_state.get_leader().is_none() {
                        // No leader detected, start election
                        warn!("No leader detected, starting election");

                        // Increment term
                        let mut term = current_term.write().await;
                        *term += 1;
                        drop(term);

                        // Vote for self
                        *voted_for.write().await = Some(node_id.clone());

                        // Become candidate
                        let candidate_node = ClusterNode {
                            id: node_id.clone(),
                            addr: node.addr,
                            role: NodeRole::Candidate,
                            last_heartbeat: chrono::Utc::now(),
                            healthy: true,
                        };
                        cluster_state.update_node(candidate_node);

                        // In simplified version, become leader immediately
                        sleep(Duration::from_millis(100)).await;

                        let leader_node = ClusterNode {
                            id: node_id.clone(),
                            addr: node.addr,
                            role: NodeRole::Leader,
                            last_heartbeat: chrono::Utc::now(),
                            healthy: true,
                        };
                        cluster_state.update_node(leader_node);
                        info!("Node {} elected as leader", node_id);
                    }
                }
            }
        })
    }

    /// Spawn task to send heartbeats (if leader)
    fn spawn_heartbeat_sender(&self) -> tokio::task::JoinHandle<()> {
        let cluster_state = self.cluster_state.clone();
        let node_id = self.node_id.clone();
        let heartbeat_interval = self.heartbeat_interval;

        tokio::spawn(async move {
            let mut interval_timer = interval(heartbeat_interval);

            loop {
                interval_timer.tick().await;

                if cluster_state.is_leader() {
                    // Send heartbeat (update last_heartbeat timestamp)
                    cluster_state.update_health(&node_id, true);

                    // In a real implementation, we would send heartbeats to followers
                    // For now, just log
                    info!("Leader {} sending heartbeat", node_id);
                }
            }
        })
    }

    /// Get current role
    pub fn get_role(&self) -> NodeRole {
        self.cluster_state
            .get_node(&self.node_id)
            .map(|n| n.role)
            .unwrap_or(NodeRole::Follower)
    }

    /// Check if this node is the leader
    pub fn is_leader(&self) -> bool {
        self.cluster_state.is_leader()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_election_creation() {
        let state = Arc::new(ClusterState::new("test-node".to_string()));
        let election = LeaderElection::new_with_defaults(state, "test-node".to_string(), 5, 1);

        assert_eq!(election.get_role(), NodeRole::Follower);
    }

    #[tokio::test]
    async fn test_become_follower() {
        let state = Arc::new(ClusterState::new("test-node".to_string()));
        let election = LeaderElection::new_with_defaults(state.clone(), "test-node".to_string(), 5, 1);

        election.become_follower().await;

        assert_eq!(election.get_role(), NodeRole::Follower);
        assert!(!election.is_leader());
    }
}
