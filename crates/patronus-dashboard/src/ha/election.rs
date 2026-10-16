//! Leader election + log replication (Raft-style) for the HA dashboard.
//!
//! Each node runs a randomized election timeout; if no heartbeat is seen
//! from a leader within that window, the node becomes a candidate, bumps its
//! term, votes for itself, and requests votes from every configured peer over
//! HTTP (`POST /ha/vote`). A node that wins a majority of the cluster
//! (including itself) becomes leader and sends periodic heartbeats
//! (`POST /ha/heartbeat`). Any node that observes a higher term immediately
//! steps down to follower.
//!
//! When a [`ReplicationLog`] + [`StateMachine`] are attached
//! ([`LeaderElection::with_replication`]), heartbeats double as Raft
//! AppendEntries: they carry log entries, the prev-log consistency check and
//! the leader commit index, and votes are only granted to candidates whose
//! log is at least as up to date as the voter's. Writes go through
//! [`LeaderElection::submit`]: the leader commits them on a majority before
//! applying; followers forward them to the leader (`POST /ha/submit`).
//! All node-to-node RPCs carry the cluster token derived from the shared
//! signing secret (see `auth::jwt::cluster_rpc_token`).

use super::cluster::{ClusterNode, ClusterState, NodeRole};
use super::replication::{LogEntry, ReplicatedOp, ReplicationLog, StateMachine};
use crate::auth::jwt::{cluster_rpc_token, CLUSTER_TOKEN_HEADER};
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{watch, Mutex, RwLock};
use tokio::time::sleep;
use tracing::{debug, error, info, warn};

/// Max entries shipped per AppendEntries RPC.
const MAX_BATCH: usize = 256;

/// Vote request RPC body, sent candidate -> peer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VoteRequest {
    pub term: u64,
    pub candidate_id: String,
    #[serde(default)]
    pub last_log_index: u64,
    #[serde(default)]
    pub last_log_term: u64,
}

/// Vote request RPC response, peer -> candidate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VoteResponse {
    pub term: u64,
    pub vote_granted: bool,
}

/// Heartbeat / AppendEntries RPC body, leader -> peer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeartbeatRequest {
    pub term: u64,
    pub leader_id: String,
    /// Address peers use to reach the leader (for write forwarding).
    #[serde(default)]
    pub leader_addr: String,
    #[serde(default)]
    pub prev_log_index: u64,
    #[serde(default)]
    pub prev_log_term: u64,
    #[serde(default)]
    pub entries: Vec<LogEntry>,
    #[serde(default)]
    pub leader_commit: u64,
}

impl HeartbeatRequest {
    /// Plain heartbeat with no log payload.
    pub fn simple(term: u64, leader_id: impl Into<String>) -> Self {
        Self {
            term,
            leader_id: leader_id.into(),
            leader_addr: String::new(),
            prev_log_index: 0,
            prev_log_term: 0,
            entries: Vec::new(),
            leader_commit: 0,
        }
    }
}

/// Heartbeat RPC response, peer -> leader.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeartbeatResponse {
    pub term: u64,
    pub success: bool,
    /// Highest index known to match the leader (on success).
    #[serde(default)]
    pub match_index: u64,
    /// Follower's last log index (hint for the leader on failure).
    #[serde(default)]
    pub last_log_index: u64,
}

/// `/ha/submit` body: a follower forwarding a write to the leader.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmitRequest {
    pub op: ReplicatedOp,
}

/// `/ha/submit` response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmitResponse {
    pub index: u64,
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
    /// Last log index on this node.
    #[serde(default)]
    pub log_index: u64,
    /// Highest committed index known to this node.
    #[serde(default)]
    pub commit_index: u64,
    /// Highest index applied to this node's database.
    #[serde(default)]
    pub applied_index: u64,
}

/// Errors from [`LeaderElection::submit`].
#[derive(Debug, thiserror::Error)]
pub enum SubmitError {
    #[error("no leader is currently elected; retry shortly")]
    NoLeader,
    #[error("write was not committed by a majority of the cluster in time")]
    NotCommitted,
    #[error("leadership changed before the write committed; retry")]
    LeadershipLost,
    #[error("forwarding the write to the leader failed: {0}")]
    Forward(String),
    #[error("failed to apply the write: {0}")]
    Apply(String),
}

/// Replication state attached to a node.
struct Replication {
    log: ReplicationLog,
    sm: Arc<StateMachine>,
    commit_index: AtomicU64,
    applied_tx: watch::Sender<u64>,
    /// Leader-side per-peer progress.
    next_index: Mutex<HashMap<String, u64>>,
    match_index: Mutex<HashMap<String, u64>>,
    /// Serialises log mutation.
    log_lock: Mutex<()>,
    /// Serialises applying committed entries.
    apply_lock: Mutex<()>,
}

/// Leader election manager
pub struct LeaderElection {
    cluster_state: Arc<ClusterState>,
    node_id: String,
    node_addr: SocketAddr,
    /// Address peers use to reach this node (`PATRONUS_ADVERTISE_ADDR`).
    advertise_addr: String,
    /// Peer advertise addresses, e.g. "dashboard2:8443" (resolved by the
    /// HTTP client at request time, so hostnames work fine in Docker).
    peers: Vec<String>,
    election_timeout: Duration,
    heartbeat_interval: Duration,
    current_term: Arc<AtomicU64>,
    voted_for: Arc<RwLock<Option<String>>>,
    leader_id: Arc<RwLock<Option<String>>>,
    leader_addr: Arc<RwLock<Option<String>>>,
    /// Last time this node observed a heartbeat from a real leader, or
    /// granted a vote. Used to drive the randomized election timeout.
    last_contact: Arc<RwLock<Instant>>,
    http_client: reqwest::Client,
    repl: Option<Arc<Replication>>,
    /// One replication round at a time (keeps per-peer progress coherent).
    round_lock: Mutex<()>,
    stopped: AtomicBool,
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
        Self::new_with_durations(
            cluster_state,
            node_id,
            node_addr,
            peers,
            Duration::from_secs(election_timeout_secs),
            Duration::from_secs(heartbeat_interval_secs),
        )
    }

    /// Same as [`new`](Self::new) with sub-second timing (used by tests).
    pub fn new_with_durations(
        cluster_state: Arc<ClusterState>,
        node_id: String,
        node_addr: SocketAddr,
        peers: Vec<String>,
        election_timeout: Duration,
        heartbeat_interval: Duration,
    ) -> Self {
        let http_client = reqwest::Client::builder()
            .timeout(election_timeout.max(Duration::from_millis(500)))
            .build()
            .expect("failed to build HA HTTP client");
        let advertise_addr = format!("{}:{}", node_id, node_addr.port());

        Self {
            cluster_state,
            node_id,
            node_addr,
            advertise_addr,
            peers,
            election_timeout,
            heartbeat_interval,
            current_term: Arc::new(AtomicU64::new(0)),
            voted_for: Arc::new(RwLock::new(None)),
            leader_id: Arc::new(RwLock::new(None)),
            leader_addr: Arc::new(RwLock::new(None)),
            last_contact: Arc::new(RwLock::new(Instant::now())),
            http_client,
            repl: None,
            round_lock: Mutex::new(()),
            stopped: AtomicBool::new(false),
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

    /// Set the address peers should use to reach this node.
    pub fn with_advertise_addr(mut self, addr: impl Into<String>) -> Self {
        self.advertise_addr = addr.into();
        self
    }

    /// Attach the replicated log + state machine (enables data replication).
    pub fn with_replication(mut self, log: ReplicationLog, sm: Arc<StateMachine>) -> Self {
        let applied = log.applied_index();
        let saved_term = log.saved_term().max(log.last().1);
        self.current_term.store(saved_term, Ordering::SeqCst);
        let (applied_tx, _) = watch::channel(applied);
        self.repl = Some(Arc::new(Replication {
            log,
            sm,
            commit_index: AtomicU64::new(applied),
            applied_tx,
            next_index: Mutex::new(HashMap::new()),
            match_index: Mutex::new(HashMap::new()),
            log_lock: Mutex::new(()),
            apply_lock: Mutex::new(()),
        }));
        self
    }

    /// Whether a replicated log is attached.
    pub fn has_replication(&self) -> bool {
        self.repl.is_some()
    }

    pub fn node_id(&self) -> &str {
        &self.node_id
    }

    fn total_nodes(&self) -> usize {
        self.peers.len() + 1
    }

    fn majority(&self) -> usize {
        self.total_nodes() / 2 + 1
    }

    fn set_term(&self, term: u64) {
        self.current_term.store(term, Ordering::SeqCst);
        if let Some(r) = &self.repl {
            if let Err(e) = r.log.save_term(term) {
                warn!("failed to persist HA term: {e}");
            }
        }
    }

    fn last_log(&self) -> (u64, u64) {
        self.repl.as_ref().map(|r| r.log.last()).unwrap_or((0, 0))
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

        {
            let this = self.clone();
            tokio::spawn(async move {
                this.become_follower().await;
                // Re-apply anything committed but not yet applied before a restart.
                this.apply_committed().await;
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

    /// Stop the background loops and refuse further RPCs (simulates a node
    /// crash in tests; also used for orderly shutdown).
    pub fn stop(&self) {
        self.stopped.store(true, Ordering::SeqCst);
    }

    pub fn is_stopped(&self) -> bool {
        self.stopped.load(Ordering::SeqCst)
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
            sleep(Duration::from_millis(50)).await;
            if self.is_stopped() {
                return;
            }

            let elapsed = self.last_contact.read().await.elapsed();
            let is_leader = self.cluster_state.is_leader();

            if !is_leader && elapsed >= deadline {
                self.run_election().await;
            }
        }
    }

    fn post<T: Serialize + ?Sized>(&self, url: String, body: &T) -> reqwest::RequestBuilder {
        self.http_client
            .post(url)
            .header(CLUSTER_TOKEN_HEADER, cluster_rpc_token())
            .json(body)
    }

    /// Run one real election round: bump term, vote for self, request votes
    /// from every peer concurrently over HTTP, and become leader on a real
    /// majority.
    async fn run_election(self: &Arc<Self>) {
        let new_term = self.current_term.load(Ordering::SeqCst) + 1;
        self.set_term(new_term);
        *self.voted_for.write().await = Some(self.node_id.clone());
        *self.leader_id.write().await = None;
        *self.leader_addr.write().await = None;
        self.reset_timeout().await;
        self.update_role(NodeRole::Candidate).await;

        warn!(
            node_id = %self.node_id,
            term = new_term,
            "Election timeout elapsed with no leader -- starting election"
        );

        let (last_log_index, last_log_term) = self.last_log();
        let mut votes: usize = 1; // vote for self
        let mut futures = Vec::new();
        for peer in &self.peers {
            let body = VoteRequest {
                term: new_term,
                candidate_id: self.node_id.clone(),
                last_log_index,
                last_log_term,
            };
            let req = self.post(format!("http://{}/ha/vote", peer), &body);
            futures.push(tokio::spawn(async move {
                req.send().await.ok()?.json::<VoteResponse>().await.ok()
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
        if self.current_term.load(Ordering::SeqCst) != new_term
            || self.get_role() != NodeRole::Candidate
        {
            return;
        }

        if votes >= needed {
            self.become_leader(new_term).await;
        }
    }

    /// Become the leader
    async fn become_leader(self: &Arc<Self>, term: u64) {
        info!(node_id = %self.node_id, term, "Node elected as LEADER");
        *self.leader_id.write().await = Some(self.node_id.clone());
        *self.leader_addr.write().await = Some(self.advertise_addr.clone());
        if let Some(r) = &self.repl {
            let (last, _) = r.log.last();
            let mut next = r.next_index.lock().await;
            let mut matched = r.match_index.lock().await;
            for p in &self.peers {
                next.insert(p.clone(), last + 1);
                matched.insert(p.clone(), 0);
            }
            drop((next, matched));
            // A no-op in the new term lets earlier entries commit (Raft 5.4.2).
            let _g = r.log_lock.lock().await;
            if let Err(e) = r.log.append(&LogEntry {
                index: last + 1,
                term,
                op: ReplicatedOp::Noop,
            }) {
                error!("failed to append leader no-op: {e}");
            }
        }
        self.update_role(NodeRole::Leader).await;
        // Assert leadership immediately rather than waiting for the next
        // heartbeat tick, so followers converge fast.
        self.replicate_round(term).await;
    }

    /// Step down to follower because we observed a higher term elsewhere.
    async fn step_down(&self, term: u64) {
        self.set_term(term);
        *self.voted_for.write().await = None;
        self.update_role(NodeRole::Follower).await;
        self.reset_timeout().await;
    }

    /// Leader heartbeat loop: only actually sends while this node is leader.
    async fn run_heartbeat_loop(self: Arc<Self>) {
        let mut interval_timer = tokio::time::interval(self.heartbeat_interval);
        loop {
            interval_timer.tick().await;
            if self.is_stopped() {
                return;
            }

            if self.cluster_state.is_leader() {
                let term = self.current_term.load(Ordering::SeqCst);
                self.cluster_state.update_health(&self.node_id, true);
                self.replicate_round(term).await;
            }
        }
    }

    /// One heartbeat / AppendEntries round to every peer, then advance the
    /// commit index and apply. Steps down if superseded.
    async fn replicate_round(self: &Arc<Self>, term: u64) {
        let _round = self.round_lock.lock().await;
        if self.is_stopped() || !self.cluster_state.is_leader() {
            return;
        }
        let commit = self
            .repl
            .as_ref()
            .map(|r| r.commit_index.load(Ordering::SeqCst))
            .unwrap_or(0);

        let mut futures = Vec::new();
        for peer in &self.peers {
            let mut body = HeartbeatRequest::simple(term, self.node_id.clone());
            body.leader_addr = self.advertise_addr.clone();
            body.leader_commit = commit;
            if let Some(r) = &self.repl {
                let (last, _) = r.log.last();
                let next = *r.next_index.lock().await.get(peer).unwrap_or(&(last + 1));
                let next = next.clamp(1, last + 1);
                body.prev_log_index = next - 1;
                body.prev_log_term = r.log.term_at(next - 1).unwrap_or(0);
                body.entries = r.log.range(next, MAX_BATCH);
            }
            let sent = body.prev_log_index + body.entries.len() as u64;
            let prev = body.prev_log_index;
            let req = self.post(format!("http://{}/ha/heartbeat", peer), &body);
            let peer = peer.clone();
            futures.push(tokio::spawn(async move {
                let resp = req
                    .send()
                    .await
                    .ok()?
                    .json::<HeartbeatResponse>()
                    .await
                    .ok()?;
                Some((peer, prev, sent, resp))
            }));
        }

        for fut in futures {
            if let Ok(Some((peer, prev, sent, resp))) = fut.await {
                if resp.term > term {
                    self.step_down(resp.term).await;
                    return;
                }
                if let Some(r) = &self.repl {
                    if resp.success {
                        let _ = sent;
                        let m = resp.match_index;
                        r.match_index.lock().await.insert(peer.clone(), m);
                        r.next_index.lock().await.insert(peer, m + 1);
                    } else {
                        // Back off towards the follower's log end.
                        let hint = resp.last_log_index + 1;
                        let next = hint.min(prev.max(1)).max(1);
                        r.next_index.lock().await.insert(peer, next);
                    }
                }
            }
        }

        if let Some(r) = &self.repl {
            // Highest N replicated on a majority with an entry from this term.
            let (last, _) = r.log.last();
            let matched = r.match_index.lock().await.clone();
            let mut new_commit = r.commit_index.load(Ordering::SeqCst);
            let mut n = last;
            while n > new_commit {
                if r.log.term_at(n) == Some(term) {
                    let count = 1 + self
                        .peers
                        .iter()
                        .filter(|p| matched.get(*p).copied().unwrap_or(0) >= n)
                        .count();
                    if count >= self.majority() {
                        new_commit = n;
                        break;
                    }
                }
                n -= 1;
            }
            if new_commit > r.commit_index.load(Ordering::SeqCst) {
                r.commit_index.store(new_commit, Ordering::SeqCst);
            }
        }
        drop(_round);
        self.apply_committed().await;
        debug!(node_id = %self.node_id, term, "Leader heartbeat round sent");
    }

    /// Apply every committed-but-unapplied entry, in order.
    async fn apply_committed(&self) {
        let Some(r) = &self.repl else { return };
        let _g = r.apply_lock.lock().await;
        let commit = r.commit_index.load(Ordering::SeqCst);
        let mut applied = r.log.applied_index();
        while applied < commit {
            let idx = applied + 1;
            match r.log.get(idx) {
                Some(entry) => {
                    if let Err(e) = r.sm.apply(&entry.op).await {
                        // Deterministic on every node; log and move on so one
                        // bad entry can't wedge replication forever.
                        error!(index = idx, "failed to apply replicated op: {e}");
                    }
                }
                None => break,
            }
            applied = idx;
            if let Err(e) = r.log.set_applied_index(applied) {
                error!("failed to persist applied index: {e}");
            }
            r.applied_tx.send_replace(applied);
        }
    }

    /// Wait until this node has applied `index` (bounded).
    async fn wait_applied(&self, index: u64, timeout: Duration) -> bool {
        let Some(r) = &self.repl else { return true };
        let mut rx = r.applied_tx.subscribe();
        let fut = async {
            loop {
                if *rx.borrow_and_update() >= index {
                    return;
                }
                if rx.changed().await.is_err() {
                    return;
                }
            }
        };
        tokio::time::timeout(timeout, fut).await.is_ok()
    }

    fn commit_timeout(&self) -> Duration {
        self.election_timeout * 2 + Duration::from_secs(2)
    }

    /// Replicate a write. On the leader: append, commit on a majority, apply.
    /// On a follower: forward to the leader and wait until this node has
    /// applied it too (read-your-writes through the load balancer).
    pub async fn submit(self: &Arc<Self>, op: ReplicatedOp) -> Result<u64, SubmitError> {
        let Some(r) = self.repl.clone() else {
            return Err(SubmitError::Apply("replication not configured".into()));
        };
        if self.cluster_state.is_leader() {
            return self.submit_as_leader(&r, op).await;
        }

        // Follower: forward to the current leader (wait briefly for one to
        // be elected if a failover is in progress).
        let deadline = Instant::now() + self.commit_timeout();
        loop {
            if self.cluster_state.is_leader() {
                return self.submit_as_leader(&r, op).await;
            }
            let addr = self.leader_addr.read().await.clone();
            if let Some(addr) = addr {
                let resp = self
                    .post(
                        format!("http://{}/ha/submit", addr),
                        &SubmitRequest { op: op.clone() },
                    )
                    .timeout(self.commit_timeout())
                    .send()
                    .await
                    .map_err(|e| SubmitError::Forward(e.to_string()))?;
                if resp.status().is_success() {
                    let body: SubmitResponse = resp
                        .json()
                        .await
                        .map_err(|e| SubmitError::Forward(e.to_string()))?;
                    if !self.wait_applied(body.index, self.commit_timeout()).await {
                        warn!(
                            index = body.index,
                            "forwarded write committed but not yet applied locally"
                        );
                    }
                    return Ok(body.index);
                }
                let status = resp.status();
                let text = resp.text().await.unwrap_or_default();
                if status != reqwest::StatusCode::MISDIRECTED_REQUEST {
                    return Err(SubmitError::Forward(format!("{status}: {text}")));
                }
            }
            if Instant::now() >= deadline {
                return Err(SubmitError::NoLeader);
            }
            sleep(Duration::from_millis(100)).await;
        }
    }

    async fn submit_as_leader(
        self: &Arc<Self>,
        r: &Arc<Replication>,
        op: ReplicatedOp,
    ) -> Result<u64, SubmitError> {
        let term = self.current_term.load(Ordering::SeqCst);
        let index = {
            let _g = r.log_lock.lock().await;
            let (last, _) = r.log.last();
            let entry = LogEntry {
                index: last + 1,
                term,
                op,
            };
            r.log
                .append(&entry)
                .map_err(|e| SubmitError::Apply(e.to_string()))?;
            entry.index
        };

        let deadline = Instant::now() + self.commit_timeout();
        loop {
            self.replicate_round(term).await;
            if r.commit_index.load(Ordering::SeqCst) >= index {
                break;
            }
            if !self.cluster_state.is_leader() || self.current_term.load(Ordering::SeqCst) != term {
                return Err(SubmitError::LeadershipLost);
            }
            if Instant::now() >= deadline {
                return Err(SubmitError::NotCommitted);
            }
            sleep(Duration::from_millis(50)).await;
        }
        if r.log.term_at(index) != Some(term) {
            return Err(SubmitError::LeadershipLost);
        }
        self.apply_committed().await;
        self.wait_applied(index, self.commit_timeout()).await;
        // Push the new commit index out right away so followers apply now
        // rather than on the next heartbeat tick.
        let this = self.clone();
        tokio::spawn(async move { this.replicate_round(term).await });
        Ok(index)
    }

    /// Handle an incoming `/ha/submit` (follower forwarding a write).
    pub async fn handle_submit(
        self: &Arc<Self>,
        req: SubmitRequest,
    ) -> Result<SubmitResponse, SubmitError> {
        if !self.cluster_state.is_leader() {
            return Err(SubmitError::NoLeader);
        }
        let r = self.repl.clone().ok_or(SubmitError::NoLeader)?;
        let index = self.submit_as_leader(&r, req.op).await?;
        Ok(SubmitResponse { index })
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
            self.set_term(req.term);
            *self.voted_for.write().await = None;
            *self.leader_id.write().await = None;
            *self.leader_addr.write().await = None;
            self.update_role(NodeRole::Follower).await;
        }

        // Raft election restriction: never elect a node missing entries we
        // hold (it could be missing committed writes).
        let (my_index, my_term) = self.last_log();
        let up_to_date = req.last_log_term > my_term
            || (req.last_log_term == my_term && req.last_log_index >= my_index);

        let mut voted_for = self.voted_for.write().await;
        let can_vote =
            voted_for.is_none() || voted_for.as_deref() == Some(req.candidate_id.as_str());

        if can_vote && up_to_date {
            *voted_for = Some(req.candidate_id.clone());
            drop(voted_for);
            self.reset_timeout().await;
            info!(node_id = %self.node_id, term = req.term, candidate = %req.candidate_id, "Granting vote");
            VoteResponse {
                term: req.term,
                vote_granted: true,
            }
        } else {
            if !up_to_date {
                info!(node_id = %self.node_id, candidate = %req.candidate_id, "Refusing vote: candidate log is behind");
            }
            let term = self.current_term.load(Ordering::SeqCst);
            VoteResponse {
                term,
                vote_granted: false,
            }
        }
    }

    /// Handle an incoming `/ha/heartbeat` (AppendEntries) RPC from the leader.
    pub async fn handle_heartbeat(&self, req: HeartbeatRequest) -> HeartbeatResponse {
        let current = self.current_term.load(Ordering::SeqCst);
        let (my_last, _) = self.last_log();

        if req.term < current {
            // Stale leader from an old term -- reject.
            return HeartbeatResponse {
                term: current,
                success: false,
                match_index: 0,
                last_log_index: my_last,
            };
        }

        if req.term > current {
            self.set_term(req.term);
            *self.voted_for.write().await = None;
        }
        *self.leader_id.write().await = Some(req.leader_id.clone());
        if !req.leader_addr.is_empty() {
            *self.leader_addr.write().await = Some(req.leader_addr.clone());
        }
        self.reset_timeout().await;

        if self.cluster_state.get_node(&self.node_id).map(|n| n.role) != Some(NodeRole::Follower) {
            self.update_role(NodeRole::Follower).await;
        } else {
            // Still touch last_heartbeat so stale-node checks stay accurate.
            self.cluster_state.update_health(&self.node_id, true);
        }

        debug!(node_id = %self.node_id, leader = %req.leader_id, term = req.term, "Heartbeat accepted");

        let Some(r) = &self.repl else {
            return HeartbeatResponse {
                term: req.term,
                success: true,
                match_index: 0,
                last_log_index: 0,
            };
        };

        let match_index = {
            let _g = r.log_lock.lock().await;
            let (last, _) = r.log.last();
            // Consistency check on the entry preceding the new ones.
            if req.prev_log_index > last
                || r.log.term_at(req.prev_log_index) != Some(req.prev_log_term)
            {
                return HeartbeatResponse {
                    term: req.term,
                    success: false,
                    match_index: 0,
                    last_log_index: last.min(req.prev_log_index.saturating_sub(1)),
                };
            }
            for entry in &req.entries {
                match r.log.term_at(entry.index) {
                    Some(t) if t == entry.term => continue,
                    Some(_) => {
                        if let Err(e) = r.log.truncate_from(entry.index) {
                            error!("log truncate failed: {e}");
                        }
                    }
                    None => {}
                }
                if let Err(e) = r.log.append(entry) {
                    error!("log append failed: {e}");
                    return HeartbeatResponse {
                        term: req.term,
                        success: false,
                        match_index: 0,
                        last_log_index: r.log.last().0,
                    };
                }
            }
            req.prev_log_index + req.entries.len() as u64
        };

        let new_commit = req.leader_commit.min(match_index);
        if new_commit > r.commit_index.load(Ordering::SeqCst) {
            r.commit_index.store(new_commit, Ordering::SeqCst);
        }
        self.apply_committed().await;

        HeartbeatResponse {
            term: req.term,
            success: true,
            match_index,
            last_log_index: r.log.last().0,
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
        let (log_index, commit_index, applied_index) = match &self.repl {
            Some(r) => (
                r.log.last().0,
                r.commit_index.load(Ordering::SeqCst),
                r.log.applied_index(),
            ),
            None => (0, 0, 0),
        };
        HaStatus {
            node_id: self.node_id.clone(),
            role: self.get_role(),
            term: self.current_term.load(Ordering::SeqCst),
            leader_id: self.leader_id.read().await.clone(),
            voted_for: self.voted_for.read().await.clone(),
            peers: self.peers.clone(),
            cluster_size: self.total_nodes(),
            log_index,
            commit_index,
            applied_index,
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
                last_log_index: 0,
                last_log_term: 0,
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
            .handle_heartbeat(HeartbeatRequest::simple(1, "node2"))
            .await;

        assert!(resp.success);
        assert_eq!(election.get_role(), NodeRole::Follower);
    }
}
