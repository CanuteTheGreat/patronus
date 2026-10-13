//! Leader election: majority-heartbeat-based (practical Raft-lite) algorithm.
//!
//! Real cross-node coordination: each node runs a randomized election
//! timeout; if no heartbeat is seen from a leader within that window, the
//! node becomes a candidate, bumps its term, votes for itself, and requests
//! votes from every configured peer over HTTP (`POST /ha/vote`). A node that
//! wins a majority of the cluster (including itself) becomes leader and
//! starts sending periodic heartbeats (`POST /ha/heartbeat`) to all peers.
//! Any node that observes a higher term (via a vote request or a heartbeat)
//! immediately steps down to follower. This is deliberately NOT textbook-
//! perfect Raft (no persistent log replication / commit index) but it is a
//! real, live, majority-quorum leader election and failover mechanism.

use super::cluster::{ClusterNode, ClusterState, NodeRole};
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tokio::time::sleep;
use tracing::{debug, info, warn};

/// Vote request RPC body, sent candidate -> peer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VoteRequest {
    pub term: u64,
    pub candidate_id: String,
}

/// Vote request RPC response, peer -> candidate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VoteResponse {
    pub term: u64,
    pub vote_granted: bool,
}

/// Heartbeat (AppendEntries-lite) RPC body, leader -> peer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeartbeatRequest {
    pub term: u64,
    pub leader_id: String,
}

/// Heartbeat RPC response, peer -> leader.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeartbeatResponse {
    pub term: u64,
    pub success: bool,
}

/// Public status snapshot, served at `/ha/status`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HaStatus {
    pub node_id: String,
    pub role: NodeRole,
    pub term: u64,
    pub leader_id: Option<String>,
    pub voted_for: Option<String>,
    pub peers: Vec<String>,
    pub cluster_size: usize,
}

/// Leader election manager
pub struct LeaderElection {
    cluster_state: Arc<ClusterState>,
    node_id: String,
    node_addr: SocketAddr,
    /// Peer advertise addresses, e.g. "dashboard2:8443" (resolved by the
    /// HTTP client at request time, so hostnames work fine in Docker).
    peers: Vec<String>,
    election_timeout: Duration,
    heartbeat_interval: Duration,
    current_term: Arc<AtomicU64>,
    voted_for: Arc<RwLock<Option<String>>>,
    leader_id: Arc<RwLock<Option<String>>>,
    /// Last time this node observed a heartbeat from a real leader, or
    /// granted a vote. Used to drive the randomized election timeout.
    last_contact: Arc<RwLock<Instant>>,
    http_client: reqwest::Client,
}

impl LeaderElection {
    pub fn new(
        cluster_state: Arc<ClusterState>,
        node_id: String,
        node_addr: SocketAddr,
        peers: Vec<String>,
        election_timeout_secs: u64,
        heartbeat_interval_secs: u64,
    ) -> Self {
        let http_client = reqwest::Client::builder()
            .timeout(Duration::from_secs(election_timeout_secs.max(1)))
            .build()
            .expect("failed to build HA HTTP client");

        Self {
            cluster_state,
            node_id,
            node_addr,
            peers,
            election_timeout: Duration::from_secs(election_timeout_secs),
            heartbeat_interval: Duration::from_secs(heartbeat_interval_secs),
            current_term: Arc::new(AtomicU64::new(0)),
            voted_for: Arc::new(RwLock::new(None)),
            leader_id: Arc::new(RwLock::new(None)),
            last_contact: Arc::new(RwLock::new(Instant::now())),
            http_client,
        }
    }

    /// Create with default address and no peers (for backward compatibility
    /// / unit tests exercising single-node behavior).
    pub fn new_with_defaults(
        cluster_state: Arc<ClusterState>,
        node_id: String,
        election_timeout_secs: u64,
        heartbeat_interval_secs: u64,
    ) -> Self {
        let default_addr: SocketAddr = "127.0.0.1:8443".parse().expect("Default address is valid");
        Self::new(
            cluster_state,
            node_id,
            default_addr,
            Vec::new(),
            election_timeout_secs,
            heartbeat_interval_secs,
        )
    }

    fn total_nodes(&self) -> usize {
        self.peers.len() + 1
    }

    fn majority(&self) -> usize {
        self.total_nodes() / 2 + 1
    }

    /// Randomized election timeout (base..2x base) to reduce split votes.
    fn randomized_timeout(&self) -> Duration {
        let base_ms = self.election_timeout.as_millis().max(1) as u64;
        let jitter_ms = rand::thread_rng().gen_range(0..=base_ms);
        Duration::from_millis(base_ms + jitter_ms)
    }

    /// Start the election + heartbeat loops. Must be called on an
    /// `Arc<LeaderElection>` so the spawned tasks and the RPC handlers
    /// (invoked from axum) share the exact same in-memory state.
    pub fn start(self: Arc<Self>) {
        info!(node_id = %self.node_id, peers = ?self.peers, "Starting HA leader election");

        // Initial state: follower, no leader known yet.
        {
            let this = self.clone();
            tokio::spawn(async move {
                this.become_follower().await;
            });
        }

        let election_loop = self.clone();
        tokio::spawn(async move {
            election_loop.run_election_loop().await;
        });

        let heartbeat_loop = self.clone();
        tokio::spawn(async move {
            heartbeat_loop.run_heartbeat_loop().await;
        });
    }

    /// Become a follower
    async fn become_follower(&self) {
        info!(node_id = %self.node_id, "Node becoming follower");
        self.update_role(NodeRole::Follower).await;
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

    async fn reset_timeout(&self) {
        *self.last_contact.write().await = Instant::now();
    }

    /// Main election-timeout watchdog: if no leader heartbeat/vote grant is
    /// seen within the (randomized) election timeout, start a real election.
    async fn run_election_loop(self: Arc<Self>) {
        loop {
            let deadline = self.randomized_timeout();
            sleep(Duration::from_millis(100)).await;

            let elapsed = self.last_contact.read().await.elapsed();
            let is_leader = self.cluster_state.is_leader();

            if !is_leader && elapsed >= deadline {
                self.run_election().await;
            }
        }
    }

    /// Run one real election round: bump term, vote for self, request votes
    /// from every peer concurrently over HTTP, and become leader on a real
    /// majority.
    async fn run_election(self: &Arc<Self>) {
        let new_term = self.current_term.fetch_add(1, Ordering::SeqCst) + 1;
        *self.voted_for.write().await = Some(self.node_id.clone());
        *self.leader_id.write().await = None;
        self.reset_timeout().await;
        self.update_role(NodeRole::Candidate).await;

        warn!(
            node_id = %self.node_id,
            term = new_term,
            "Election timeout elapsed with no leader -- starting election"
        );

        let mut votes: usize = 1; // vote for self
        let mut futures = Vec::new();
        for peer in &self.peers {
            let client = self.http_client.clone();
            let peer = peer.clone();
            let node_id = self.node_id.clone();
            futures.push(tokio::spawn(async move {
                let url = format!("http://{}/ha/vote", peer);
                let body = VoteRequest {
                    term: new_term,
                    candidate_id: node_id,
                };
                client
                    .post(&url)
                    .json(&body)
                    .send()
                    .await
                    .ok()?
                    .json::<VoteResponse>()
                    .await
                    .ok()
            }));
        }

        for fut in futures {
            if let Ok(Some(resp)) = fut.await {
                if resp.term > new_term {
                    // Someone is ahead of us -- step down immediately.
                    self.step_down(resp.term).await;
                    return;
                }
                if resp.vote_granted {
                    votes += 1;
                }
            }
        }

        let needed = self.majority();
        info!(
            node_id = %self.node_id,
            term = new_term,
            votes,
            needed,
            total = self.total_nodes(),
            "Election round complete"
        );

        // Someone else may have already won this term and sent us a
        // heartbeat while we were collecting votes -- don't override that.
        if self.current_term.load(Ordering::SeqCst) != new_term {
            return;
        }

        if votes >= needed {
            self.become_leader(new_term).await;
        }
    }

    /// Become the leader
    async fn become_leader(&self, term: u64) {
        info!(node_id = %self.node_id, term, "Node elected as LEADER");
        *self.leader_id.write().await = Some(self.node_id.clone());
        self.update_role(NodeRole::Leader).await;
        // Assert leadership immediately rather than waiting for the next
        // heartbeat tick, so followers converge fast.
        self.send_heartbeats(term).await;
    }

    /// Step down to follower because we observed a higher term elsewhere.
    async fn step_down(&self, term: u64) {
        self.current_term.store(term, Ordering::SeqCst);
        *self.voted_for.write().await = None;
        self.update_role(NodeRole::Follower).await;
        self.reset_timeout().await;
    }

    /// Leader heartbeat loop: only actually sends while this node is leader.
    async fn run_heartbeat_loop(self: Arc<Self>) {
        let mut interval_timer = tokio::time::interval(self.heartbeat_interval);
        loop {
            interval_timer.tick().await;

            if self.cluster_state.is_leader() {
                let term = self.current_term.load(Ordering::SeqCst);
                self.cluster_state.update_health(&self.node_id, true);
                self.send_heartbeats(term).await;
            }
        }
    }

    /// Send a heartbeat to every peer; step down if any peer reports a
    /// higher term (we've been superseded).
    async fn send_heartbeats(&self, term: u64) {
        let mut futures = Vec::new();
        for peer in &self.peers {
            let client = self.http_client.clone();
            let peer_url = peer.clone();
            let node_id = self.node_id.clone();
            futures.push(tokio::spawn(async move {
                let url = format!("http://{}/ha/heartbeat", peer_url);
                let body = HeartbeatRequest {
                    term,
                    leader_id: node_id,
                };
                client
                    .post(&url)
                    .json(&body)
                    .send()
                    .await
                    .ok()?
                    .json::<HeartbeatResponse>()
                    .await
                    .ok()
            }));
        }

        for fut in futures {
            if let Ok(Some(resp)) = fut.await {
                if resp.term > term {
                    self.step_down(resp.term).await;
                    return;
                }
            }
        }

        debug!(node_id = %self.node_id, term, "Leader heartbeat round sent");
    }

    /// Handle an incoming `/ha/vote` RPC from a candidate peer.
    pub async fn handle_vote_request(&self, req: VoteRequest) -> VoteResponse {
        let current = self.current_term.load(Ordering::SeqCst);

        if req.term < current {
            return VoteResponse {
                term: current,
                vote_granted: false,
            };
        }

        if req.term > current {
            self.current_term.store(req.term, Ordering::SeqCst);
            *self.voted_for.write().await = None;
            *self.leader_id.write().await = None;
            self.update_role(NodeRole::Follower).await;
        }

        let mut voted_for = self.voted_for.write().await;
        let can_vote =
            voted_for.is_none() || voted_for.as_deref() == Some(req.candidate_id.as_str());

        if can_vote {
            *voted_for = Some(req.candidate_id.clone());
            drop(voted_for);
            self.reset_timeout().await;
            info!(node_id = %self.node_id, term = req.term, candidate = %req.candidate_id, "Granting vote");
            VoteResponse {
                term: req.term,
                vote_granted: true,
            }
        } else {
            let term = self.current_term.load(Ordering::SeqCst);
            VoteResponse {
                term,
                vote_granted: false,
            }
        }
    }

    /// Handle an incoming `/ha/heartbeat` RPC from the current leader.
    pub async fn handle_heartbeat(&self, req: HeartbeatRequest) -> HeartbeatResponse {
        let current = self.current_term.load(Ordering::SeqCst);

        if req.term < current {
            // Stale leader from an old term -- reject.
            return HeartbeatResponse {
                term: current,
                success: false,
            };
        }

        self.current_term.store(req.term, Ordering::SeqCst);
        *self.leader_id.write().await = Some(req.leader_id.clone());
        self.reset_timeout().await;

        if self.cluster_state.get_node(&self.node_id).map(|n| n.role) != Some(NodeRole::Follower) {
            self.update_role(NodeRole::Follower).await;
        } else {
            // Still touch last_heartbeat so stale-node checks stay accurate.
            self.cluster_state.update_health(&self.node_id, true);
        }

        debug!(node_id = %self.node_id, leader = %req.leader_id, term = req.term, "Heartbeat accepted");

        HeartbeatResponse {
            term: req.term,
            success: true,
        }
    }

    /// Current role as tracked for this node.
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

    /// Build the `/ha/status` response.
    pub async fn status(&self) -> HaStatus {
        HaStatus {
            node_id: self.node_id.clone(),
            role: self.get_role(),
            term: self.current_term.load(Ordering::SeqCst),
            leader_id: self.leader_id.read().await.clone(),
            voted_for: self.voted_for.read().await.clone(),
            peers: self.peers.clone(),
            cluster_size: self.total_nodes(),
        }
    }

    /// Expose become_follower for unit tests (kept same name/behavior as
    /// before the rewrite).
    #[cfg(test)]
    pub async fn become_follower_for_test(&self) {
        self.become_follower().await;
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
        let election =
            LeaderElection::new_with_defaults(state.clone(), "test-node".to_string(), 5, 1);

        election.become_follower_for_test().await;

        assert_eq!(election.get_role(), NodeRole::Follower);
        assert!(!election.is_leader());
    }

    #[tokio::test]
    async fn test_single_node_wins_own_vote_majority() {
        // With zero peers, majority is 1 -- a lone node should be able to
        // elect itself real quorum-counted leader (not the old
        // "no leader exists yet" shortcut).
        let state = Arc::new(ClusterState::new("solo".to_string()));
        let election = Arc::new(LeaderElection::new_with_defaults(
            state,
            "solo".to_string(),
            5,
            1,
        ));
        assert_eq!(election.majority(), 1);
        election.run_election().await;
        assert!(election.is_leader());
    }

    #[tokio::test]
    async fn test_vote_request_rejects_stale_term() {
        let state = Arc::new(ClusterState::new("node1".to_string()));
        let election = LeaderElection::new_with_defaults(state, "node1".to_string(), 5, 1);
        election.current_term.store(5, Ordering::SeqCst);

        let resp = election
            .handle_vote_request(VoteRequest {
                term: 3,
                candidate_id: "node2".to_string(),
            })
            .await;

        assert!(!resp.vote_granted);
        assert_eq!(resp.term, 5);
    }

    #[tokio::test]
    async fn test_heartbeat_steps_down_candidate() {
        let state = Arc::new(ClusterState::new("node1".to_string()));
        let election = LeaderElection::new_with_defaults(state, "node1".to_string(), 5, 1);
        election.update_role(NodeRole::Candidate).await;

        let resp = election
            .handle_heartbeat(HeartbeatRequest {
                term: 1,
                leader_id: "node2".to_string(),
            })
            .await;

        assert!(resp.success);
        assert_eq!(election.get_role(), NodeRole::Follower);
    }
}
