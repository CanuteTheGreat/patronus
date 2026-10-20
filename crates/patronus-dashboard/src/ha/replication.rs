//! HA data replication: the leader ships its database to every follower.
//!
//! Each dashboard node keeps its own SQLite file. Before this module existed,
//! leader election picked a leader but nothing copied data between nodes, and
//! every node accepted writes. A site created on one node was missing on the
//! others, and after a failover the new leader served a different data set
//! (found by the 2026-10-16 HA failover QA run: three nodes, three different
//! site lists).
//!
//! How it works now:
//!
//! * Only the leader serves `/api/*`. Followers forward those requests to it
//!   (see `ha::gate`), and haproxy only routes to the node whose
//!   `/ha/leader` returns 200.
//! * After the leader handles a request that changed the database, it takes
//!   a consistent snapshot (`VACUUM INTO`), encrypts it with a key derived
//!   from the cluster's shared secret, and POSTs it to every follower's
//!   `/ha/replicate`. The request only succeeds once a majority of the
//!   cluster (leader included) holds the new data. Otherwise the caller gets
//!   a 503 rather than a success that a failover could silently undo.
//! * A background loop also pushes every couple of seconds when the database
//!   changed for another reason (metrics collectors etc.), and periodically
//!   regardless, so a follower that was down catches up after it rejoins.
//! * Every snapshot carries a monotonically increasing generation number.
//!   Followers persist the generation they hold, and voters refuse a
//!   candidate whose generation is older than theirs. A node that missed
//!   committed writes can't become leader.
//!
//! Full-snapshot shipping is deliberately simple: the dashboard database is
//! small (sites, policies, users, audit rows), and copying the whole thing
//! avoids a hand-rolled change log that could drift from the schema.

use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use rand::RngCore;
use sqlx::{Connection, SqliteConnection, SqlitePool};
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

use super::election::{HeartbeatRequest, LeaderElection, CLUSTER_AUTH_HEADER};

pub const TERM_HEADER: &str = "x-patronus-term";
pub const GENERATION_HEADER: &str = "x-patronus-generation";
pub const LEADER_HEADER: &str = "x-patronus-leader";
pub const LEADER_ADDR_HEADER: &str = "x-patronus-leader-addr";

/// Tables that stay node-local (schema bookkeeping).
const LOCAL_ONLY_TABLES: &[&str] = &["_sqlx_migrations"];

/// Envelope magic for an encrypted snapshot.
const SEALED_MAGIC: &[u8; 5] = b"PSNP1";
/// Envelope magic for a plaintext snapshot (only when no cluster key is
/// configured, i.e. unit tests).
const PLAIN_MAGIC: &[u8; 5] = b"PSNP0";

/// How often the background loop checks for unreplicated changes.
const LOOP_INTERVAL: Duration = Duration::from_secs(2);
/// Every Nth loop tick pushes even without local changes, so a follower that
/// was down or restarted catches up.
const FORCE_EVERY_TICKS: u64 = 5;

#[derive(Debug)]
pub enum ReplicationError {
    /// This node isn't the leader.
    NotLeader,
    /// Fewer than a majority of nodes confirmed the snapshot.
    NoQuorum { acks: usize, needed: usize },
    /// Taking, sealing or applying a snapshot failed.
    Snapshot(String),
}

impl fmt::Display for ReplicationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotLeader => write!(f, "this node is not the HA leader"),
            Self::NoQuorum { acks, needed } => write!(
                f,
                "change was not confirmed by a quorum of HA nodes ({} of {} needed)",
                acks, needed
            ),
            Self::Snapshot(e) => write!(f, "snapshot error: {}", e),
        }
    }
}

impl std::error::Error for ReplicationError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplicationOutcome {
    /// Single-node cluster, nothing to replicate to.
    Standalone,
    /// No change since the last confirmed push.
    UpToDate,
    /// A snapshot reached a quorum.
    Replicated { generation: u64, acks: usize },
}

/// Why a follower refused a snapshot (mapped to an HTTP status by the RPC).
#[derive(Debug, PartialEq, Eq)]
pub enum ApplyError {
    /// Sender's term is older than ours (or we lead this same term).
    StaleTerm { ours: u64 },
    /// Envelope failed to decrypt/authenticate.
    BadEnvelope,
    /// Local failure applying a valid snapshot.
    Internal(String),
}

struct PushState {
    /// Dedicated connection used only to read `PRAGMA data_version`, which
    /// changes whenever ANOTHER connection commits.
    monitor: Option<SqliteConnection>,
    /// `data_version` at the last snapshot a quorum confirmed.
    last_pushed_version: Option<i64>,
}

pub struct Replicator {
    election: Arc<LeaderElection>,
    pool: SqlitePool,
    db_path: String,
    data_dir: PathBuf,
    generation: Arc<AtomicU64>,
    key: Option<[u8; 32]>,
    push: Mutex<PushState>,
    apply_lock: Mutex<()>,
    client: reqwest::Client,
    after_apply: Option<AfterApply>,
}

/// Hook run after a follower applied a snapshot, to refresh in-memory state
/// that is loaded from the database (e.g. the NetworkPolicy enforcer).
pub type AfterApply = Arc<dyn Fn() -> futures::future::BoxFuture<'static, ()> + Send + Sync>;

impl Replicator {
    /// `generation` must be the same counter given to the election via
    /// `LeaderElection::with_generation` (see [`Replicator::load_generation`]).
    pub fn new(
        election: Arc<LeaderElection>,
        pool: SqlitePool,
        db_path: &str,
        data_dir: &Path,
        generation: Arc<AtomicU64>,
        key: Option<[u8; 32]>,
    ) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .expect("failed to build HA replication HTTP client");
        Self {
            election,
            pool,
            db_path: db_path.to_string(),
            data_dir: data_dir.to_path_buf(),
            generation,
            key,
            push: Mutex::new(PushState {
                monitor: None,
                last_pushed_version: None,
            }),
            apply_lock: Mutex::new(()),
            client,
            after_apply: None,
        }
    }

    pub fn with_after_apply(mut self, hook: AfterApply) -> Self {
        self.after_apply = Some(hook);
        self
    }

    fn generation_file(data_dir: &Path) -> PathBuf {
        data_dir.join("replication_generation")
    }

    /// Read the persisted generation for this node's data (0 if none yet).
    pub fn load_generation(data_dir: &Path) -> u64 {
        std::fs::read_to_string(Self::generation_file(data_dir))
            .ok()
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(0)
    }

    fn store_generation(&self, generation: u64) {
        self.generation.store(generation, Ordering::SeqCst);
        let path = Self::generation_file(&self.data_dir);
        let tmp = path.with_extension("tmp");
        let res = std::fs::write(&tmp, generation.to_string()).and_then(|_| std::fs::rename(&tmp, &path));
        if let Err(e) = res {
            warn!(path = %path.display(), error = %e, "Failed to persist HA replication generation");
        }
    }

    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::SeqCst)
    }

    /// Run the background push loop (leader only; no-op on followers).
    pub fn start(self: Arc<Self>) {
        tokio::spawn(async move {
            let mut tick: u64 = 0;
            let mut timer = tokio::time::interval(LOOP_INTERVAL);
            loop {
                timer.tick().await;
                tick = tick.wrapping_add(1);
                let force = tick.is_multiple_of(FORCE_EVERY_TICKS);
                match self.replicate(force).await {
                    Ok(ReplicationOutcome::Replicated { generation, acks }) => {
                        debug!(generation, acks, "Background HA replication push confirmed")
                    }
                    Ok(_) | Err(ReplicationError::NotLeader) => {}
                    Err(e) => warn!(error = %e, "Background HA replication push failed"),
                }
            }
        });
    }

    async fn data_version(&self, st: &mut PushState) -> Result<i64, ReplicationError> {
        if st.monitor.is_none() {
            let url = format!("sqlite:{}?mode=rwc", self.db_path);
            let conn = SqliteConnection::connect(&url)
                .await
                .map_err(|e| ReplicationError::Snapshot(format!("monitor connection: {}", e)))?;
            st.monitor = Some(conn);
        }
        let conn = st.monitor.as_mut().expect("monitor connection set above");
        let v: i64 = sqlx::query_scalar("PRAGMA data_version")
            .fetch_one(&mut *conn)
            .await
            .map_err(|e| ReplicationError::Snapshot(format!("data_version: {}", e)))?;
        Ok(v)
    }

    /// Push the current database to all followers if it changed since the
    /// last confirmed push (or unconditionally with `force`), and wait for a
    /// quorum. Only the leader replicates.
    pub async fn replicate(&self, force: bool) -> Result<ReplicationOutcome, ReplicationError> {
        if self.election.peers().is_empty() {
            return Ok(ReplicationOutcome::Standalone);
        }
        let mut st = self.push.lock().await;
        if !self.election.is_leader() {
            // Forget push state: whenever we (re)gain leadership the first
            // tick re-pushes, so followers converge on the new leader's data.
            st.last_pushed_version = None;
            return Err(ReplicationError::NotLeader);
        }

        let version = self.data_version(&mut st).await?;
        if !force && st.last_pushed_version == Some(version) {
            return Ok(ReplicationOutcome::UpToDate);
        }

        let generation = self.generation() + 1;
        let term = self.election.current_term();
        let snapshot = self.take_snapshot(generation).await?;
        let body = seal(
            self.key.as_ref(),
            &snapshot,
            &aad(term, generation, self.election.node_id()),
        )?;
        // The local data now corresponds to this generation whether or not
        // the push reaches a quorum.
        self.store_generation(generation);

        let acks = 1 + self.push_to_peers(body, term, generation).await;
        let needed = self.election.majority_size();
        if acks >= needed {
            st.last_pushed_version = Some(version);
            Ok(ReplicationOutcome::Replicated { generation, acks })
        } else {
            Err(ReplicationError::NoQuorum { acks, needed })
        }
    }

    async fn take_snapshot(&self, generation: u64) -> Result<Vec<u8>, ReplicationError> {
        std::fs::create_dir_all(&self.data_dir)
            .map_err(|e| ReplicationError::Snapshot(format!("data dir: {}", e)))?;
        let path = self.data_dir.join(format!(".snapshot-out-{}.db", generation));
        let _ = std::fs::remove_file(&path);
        let path_str = path.to_string_lossy().to_string();
        let res = sqlx::query("VACUUM INTO ?")
            .bind(&path_str)
            .execute(&self.pool)
            .await;
        let bytes = res
            .map_err(|e| ReplicationError::Snapshot(format!("VACUUM INTO: {}", e)))
            .and_then(|_| {
                std::fs::read(&path).map_err(|e| ReplicationError::Snapshot(format!("read snapshot: {}", e)))
            });
        let _ = std::fs::remove_file(&path);
        bytes
    }

    /// Send the sealed snapshot to every peer; returns how many confirmed.
    async fn push_to_peers(&self, body: Vec<u8>, term: u64, generation: u64) -> usize {
        let body = axum::body::Bytes::from(body);
        let mut tasks = Vec::new();
        for peer in self.election.peers() {
            let mut req = self
                .client
                .post(format!("http://{}/ha/replicate", peer))
                .header(TERM_HEADER, term.to_string())
                .header(GENERATION_HEADER, generation.to_string())
                .header(LEADER_HEADER, self.election.node_id())
                .header(LEADER_ADDR_HEADER, self.election.advertise_addr())
                .header("content-type", "application/octet-stream")
                .body(body.clone());
            if let Some(t) = self.election.rpc_token() {
                req = req.header(CLUSTER_AUTH_HEADER, t);
            }
            let peer = peer.clone();
            tasks.push(tokio::spawn(async move {
                match req.send().await {
                    Ok(resp) if resp.status().is_success() => true,
                    Ok(resp) => {
                        warn!(peer = %peer, status = %resp.status(), "Follower refused HA snapshot");
                        false
                    }
                    Err(e) => {
                        debug!(peer = %peer, error = %e, "HA snapshot push failed");
                        false
                    }
                }
            }));
        }
        let mut acks = 0;
        for t in tasks {
            if matches!(t.await, Ok(true)) {
                acks += 1;
            }
        }
        acks
    }

    /// Follower side of `/ha/replicate`: accept the leader's snapshot and
    /// replace local data with it. Returns the generation now held.
    pub async fn apply(
        &self,
        term: u64,
        leader_id: &str,
        leader_addr: Option<String>,
        generation: u64,
        body: &[u8],
    ) -> Result<u64, ApplyError> {
        let ours = self.election.current_term();
        if term < ours || (term == ours && self.election.is_leader()) {
            return Err(ApplyError::StaleTerm { ours });
        }
        let snapshot = open(self.key.as_ref(), body, &aad(term, generation, leader_id))
            .ok_or(ApplyError::BadEnvelope)?;

        // A snapshot is also proof of a live leader for this term.
        let hb = self
            .election
            .handle_heartbeat(HeartbeatRequest {
                term,
                leader_id: leader_id.to_string(),
                leader_addr,
            })
            .await;
        if !hb.success {
            return Err(ApplyError::StaleTerm { ours: hb.term });
        }

        let _guard = self.apply_lock.lock().await;
        std::fs::create_dir_all(&self.data_dir)
            .map_err(|e| ApplyError::Internal(format!("data dir: {}", e)))?;
        let path = self.data_dir.join(format!(".snapshot-in-{}.db", generation));
        std::fs::write(&path, &snapshot)
            .map_err(|e| ApplyError::Internal(format!("write snapshot: {}", e)))?;
        let res = copy_from_snapshot(&self.pool, &path).await;
        let _ = std::fs::remove_file(&path);
        res.map_err(|e| ApplyError::Internal(format!("apply snapshot: {}", e)))?;

        self.store_generation(generation);
        if let Some(hook) = &self.after_apply {
            hook().await;
        }
        info!(generation, term, leader = %leader_id, "Applied HA snapshot from leader");
        Ok(generation)
    }
}

fn aad(term: u64, generation: u64, leader_id: &str) -> Vec<u8> {
    format!("patronus-ha-snapshot:{}:{}:{}", term, generation, leader_id).into_bytes()
}

/// Encrypt+authenticate a snapshot (`PSNP1 | nonce | ciphertext`), or wrap
/// it unencrypted when no cluster key is configured.
pub fn seal(key: Option<&[u8; 32]>, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, ReplicationError> {
    let Some(key) = key else {
        let mut out = PLAIN_MAGIC.to_vec();
        out.extend_from_slice(plaintext);
        return Ok(out);
    };
    let cipher = ChaCha20Poly1305::new(key.into());
    let mut nonce = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let ct = cipher
        .encrypt(Nonce::from_slice(&nonce), Payload { msg: plaintext, aad })
        .map_err(|_| ReplicationError::Snapshot("encryption failed".into()))?;
    let mut out = SEALED_MAGIC.to_vec();
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Inverse of [`seal`]. `None` if the envelope is malformed, was sealed for
/// a different term/generation/leader, or a key mismatch.
pub fn open(key: Option<&[u8; 32]>, envelope: &[u8], aad: &[u8]) -> Option<Vec<u8>> {
    match key {
        None => envelope.strip_prefix(PLAIN_MAGIC).map(|b| b.to_vec()),
        Some(key) => {
            let rest = envelope.strip_prefix(SEALED_MAGIC)?;
            if rest.len() < 12 {
                return None;
            }
            let (nonce, ct) = rest.split_at(12);
            ChaCha20Poly1305::new(key.into())
                .decrypt(Nonce::from_slice(nonce), Payload { msg: ct, aad })
                .ok()
        }
    }
}

fn quote_ident(name: &str) -> String {
    format!("\"{}\"", name.replace('"', "\"\""))
}

/// Replace the contents of every table in the live database with the
/// snapshot's rows, in one transaction, on one pooled connection.
pub async fn copy_from_snapshot(pool: &SqlitePool, snapshot: &Path) -> Result<(), sqlx::Error> {
    let mut conn = pool.acquire().await?;
    sqlx::query("ATTACH DATABASE ? AS snap")
        .bind(snapshot.to_string_lossy().to_string())
        .execute(&mut *conn)
        .await?;
    let result = copy_tables_in_tx(&mut conn).await;
    let detach = sqlx::query("DETACH DATABASE snap").execute(&mut *conn).await;
    result?;
    detach?;
    Ok(())
}

async fn copy_tables_in_tx(conn: &mut SqliteConnection) -> Result<(), sqlx::Error> {
    sqlx::query("BEGIN IMMEDIATE").execute(&mut *conn).await?;
    match copy_tables(conn).await {
        Ok(()) => {
            sqlx::query("COMMIT").execute(&mut *conn).await?;
            Ok(())
        }
        Err(e) => {
            let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
            Err(e)
        }
    }
}

async fn table_columns(
    conn: &mut SqliteConnection,
    schema: &str,
    table: &str,
) -> Result<Vec<String>, sqlx::Error> {
    sqlx::query_scalar("SELECT name FROM pragma_table_info(?1, ?2) ORDER BY cid")
        .bind(table)
        .bind(schema)
        .fetch_all(&mut *conn)
        .await
}

async fn copy_tables(conn: &mut SqliteConnection) -> Result<(), sqlx::Error> {
    sqlx::query("PRAGMA defer_foreign_keys = ON")
        .execute(&mut *conn)
        .await?;

    let tables: Vec<String> = sqlx::query_scalar(
        "SELECT name FROM snap.sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name",
    )
    .fetch_all(&mut *conn)
    .await?;

    for table in tables {
        if LOCAL_ONLY_TABLES.contains(&table.as_str()) {
            continue;
        }
        let main_cols = table_columns(conn, "main", &table).await?;
        if main_cols.is_empty() {
            // Table doesn't exist locally (newer leader schema): skip rather
            // than invent it; it appears once this node runs the same build.
            warn!(table = %table, "HA snapshot table missing locally, skipping");
            continue;
        }
        let snap_cols = table_columns(conn, "snap", &table).await?;
        let cols: Vec<String> = main_cols
            .into_iter()
            .filter(|c| snap_cols.contains(c))
            .map(|c| quote_ident(&c))
            .collect();
        let t = quote_ident(&table);
        sqlx::query(&format!("DELETE FROM main.{}", t))
            .execute(&mut *conn)
            .await?;
        if !cols.is_empty() {
            let list = cols.join(", ");
            sqlx::query(&format!(
                "INSERT INTO main.{t} ({list}) SELECT {list} FROM snap.{t}"
            ))
            .execute(&mut *conn)
            .await?;
        }
    }

    // Keep AUTOINCREMENT counters in step with the copied rows.
    let has_seq = |schema: &'static str| {
        format!(
            "SELECT count(*) FROM {}.sqlite_master WHERE name = 'sqlite_sequence'",
            schema
        )
    };
    let snap_seq: i64 = sqlx::query_scalar(&has_seq("snap"))
        .fetch_one(&mut *conn)
        .await?;
    let main_seq: i64 = sqlx::query_scalar(&has_seq("main"))
        .fetch_one(&mut *conn)
        .await?;
    if snap_seq > 0 && main_seq > 0 {
        sqlx::query("DELETE FROM main.sqlite_sequence")
            .execute(&mut *conn)
            .await?;
        sqlx::query("INSERT INTO main.sqlite_sequence (name, seq) SELECT name, seq FROM snap.sqlite_sequence")
            .execute(&mut *conn)
            .await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::sqlite::SqlitePoolOptions;

    async fn file_pool(path: &Path) -> SqlitePool {
        SqlitePoolOptions::new()
            .max_connections(2)
            .connect(&format!("sqlite:{}?mode=rwc", path.display()))
            .await
            .unwrap()
    }

    #[test]
    fn seal_open_roundtrip_and_tamper_detection() {
        let key = [7u8; 32];
        let aad1 = aad(3, 9, "dashboard1");
        let sealed = seal(Some(&key), b"hello", &aad1).unwrap();
        assert_eq!(open(Some(&key), &sealed, &aad1).as_deref(), Some(&b"hello"[..]));
        // Replaying it as a different generation/term/leader must fail.
        assert!(open(Some(&key), &sealed, &aad(3, 10, "dashboard1")).is_none());
        assert!(open(Some(&key), &sealed, &aad(3, 9, "dashboard2")).is_none());
        // Wrong key must fail.
        assert!(open(Some(&[8u8; 32]), &sealed, &aad1).is_none());
        // An unencrypted envelope is never accepted when a key is configured.
        let plain = seal(None, b"hello", &aad1).unwrap();
        assert!(open(Some(&key), &plain, &aad1).is_none());
    }

    #[tokio::test]
    async fn snapshot_copy_replaces_follower_rows() {
        let dir = tempfile::tempdir().unwrap();
        let leader = file_pool(&dir.path().join("leader.db")).await;
        let follower = file_pool(&dir.path().join("follower.db")).await;
        for pool in [&leader, &follower] {
            sqlx::query("CREATE TABLE sites (id TEXT PRIMARY KEY, name TEXT NOT NULL)")
                .execute(pool)
                .await
                .unwrap();
            sqlx::query("CREATE TABLE events (id INTEGER PRIMARY KEY AUTOINCREMENT, msg TEXT)")
                .execute(pool)
                .await
                .unwrap();
        }
        sqlx::query("INSERT INTO sites VALUES ('a', 'created-on-leader')")
            .execute(&leader)
            .await
            .unwrap();
        sqlx::query("INSERT INTO events (msg) VALUES ('one'), ('two')")
            .execute(&leader)
            .await
            .unwrap();
        // Divergent row written on the follower before it was fenced.
        sqlx::query("INSERT INTO sites VALUES ('z', 'written-to-follower')")
            .execute(&follower)
            .await
            .unwrap();

        let snap = dir.path().join("snap.db");
        sqlx::query("VACUUM INTO ?")
            .bind(snap.to_string_lossy().to_string())
            .execute(&leader)
            .await
            .unwrap();
        copy_from_snapshot(&follower, &snap).await.unwrap();

        let names: Vec<String> = sqlx::query_scalar("SELECT name FROM sites ORDER BY id")
            .fetch_all(&follower)
            .await
            .unwrap();
        assert_eq!(names, vec!["created-on-leader".to_string()]);
        let seq: i64 = sqlx::query_scalar("SELECT seq FROM sqlite_sequence WHERE name = 'events'")
            .fetch_one(&follower)
            .await
            .unwrap();
        assert_eq!(seq, 2);
        // The snapshot is detached again: the connection is reusable.
        copy_from_snapshot(&follower, &snap).await.unwrap();
    }

    #[test]
    fn generation_file_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(Replicator::load_generation(dir.path()), 0);
        std::fs::write(Replicator::generation_file(dir.path()), "42\n").unwrap();
        assert_eq!(Replicator::load_generation(dir.path()), 42);
    }
}
