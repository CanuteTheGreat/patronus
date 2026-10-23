//! Replicated operation log for the HA dashboard.
//!
//! Before this module the three HA dashboard nodes elected a leader but
//! never shared data: every node wrote straight into its own SQLite file, so
//! a site created on the old leader was missing on the new leader after a
//! failover and the nodes drifted into different site lists (QA finding
//! 2026-10-16).
//!
//! Every state-changing dashboard operation is now a [`ReplicatedOp`]. The
//! leader appends it to a persistent log (sled), ships it to followers with
//! the existing `/ha/heartbeat` RPC (Raft AppendEntries semantics: prev-log
//! consistency check, truncation of conflicting suffixes), marks it committed
//! once a majority stored it, and only then applies it and answers the
//! client. Followers apply committed entries in log order. A follower that
//! receives a write forwards the operation to the leader (`/ha/submit`).
//! Elections only grant votes to candidates whose log is at least as
//! up to date (Raft election restriction), so a newly elected leader always
//! holds every committed write.

use chrono::{DateTime, Utc};
use patronus_sdwan::{
    database::Database,
    netpolicy::{NetworkPolicy, PolicyEnforcer, PolicyId},
    policy::RoutingPolicy,
    types::{PathId, PathStatus, Site, SiteId},
};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;

use crate::auth::users::{UpdateUserRequest, UserRepository};
use crate::security::token_revocation::TokenRevocation;

/// A user record including its password hash (the public `User` type skips
/// the hash when serialising, so it can't be used on the wire here).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplicatedUser {
    pub id: String,
    pub email: String,
    pub name: String,
    pub role: String,
    pub password_hash: String,
    pub created_at: DateTime<Utc>,
    pub is_active: bool,
}

/// One state change, applied identically on every node.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", content = "data")]
pub enum ReplicatedOp {
    /// Written by a new leader at the start of its term so earlier entries
    /// can be committed (Raft §5.4.2).
    Noop,
    UpsertSite(Site),
    DeleteSite(String),
    UpsertRoutingPolicy(RoutingPolicy),
    DeleteRoutingPolicy(u64),
    AddNetworkPolicy(NetworkPolicy),
    RemoveNetworkPolicy(PolicyId),
    CreateUser(ReplicatedUser),
    UpdateUser {
        id: String,
        update: UpdateUserRequest,
    },
    SetPassword {
        id: String,
        password_hash: String,
    },
    RevokeToken {
        token_id: String,
        user_id: String,
        reason: String,
        expires_at: DateTime<Utc>,
    },
    RevokeAllUserTokens {
        user_id: String,
        reason: String,
    },
    UpdatePathStatus {
        path_id: u64,
        status: PathStatus,
    },
    /// An enrollment token for a new edge (only its digest is stored).
    EdgeToken {
        digest: String,
        label: String,
        created_at: i64,
    },
    /// An edge enrolled: its site, endpoints, overlay record; the token is used up.
    EdgeEnroll {
        site: Site,
        edge: patronus_sdwan::edge::EdgeRecord,
        used_token: String,
        at: i64,
    },
    /// An edge's heartbeat: seen now, with the site status the measurements imply.
    EdgeHeartbeat {
        site_id: String,
        at: i64,
        status: String,
    },
    /// An edge was revoked: its credential, record and site are removed.
    EdgeRevoke(String),
}

/// A log entry: an operation stamped with its position and leader term.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    pub index: u64,
    pub term: u64,
    pub op: ReplicatedOp,
}

/// Persistent, append-only (with conflict truncation) operation log.
pub struct ReplicationLog {
    _db: sled::Db,
    entries: sled::Tree,
    meta: sled::Tree,
}

const META_APPLIED: &[u8] = b"applied_index";
const META_TERM: &[u8] = b"current_term";

impl ReplicationLog {
    /// Open (or create) the log under `dir`.
    pub fn open(dir: impl AsRef<Path>) -> anyhow::Result<Self> {
        Self::from_db(sled::open(dir)?)
    }

    /// In-memory log (tests).
    pub fn temporary() -> anyhow::Result<Self> {
        Self::from_db(sled::Config::new().temporary(true).open()?)
    }

    fn from_db(db: sled::Db) -> anyhow::Result<Self> {
        Ok(Self {
            entries: db.open_tree("entries")?,
            meta: db.open_tree("meta")?,
            _db: db,
        })
    }

    fn read_u64(&self, key: &[u8]) -> u64 {
        self.meta
            .get(key)
            .ok()
            .flatten()
            .and_then(|v| v.as_ref().try_into().ok().map(u64::from_be_bytes))
            .unwrap_or(0)
    }

    fn write_u64(&self, key: &[u8], v: u64) -> anyhow::Result<()> {
        self.meta.insert(key, &v.to_be_bytes())?;
        self.meta.flush()?;
        Ok(())
    }

    /// Index and term of the last entry, `(0, 0)` when empty.
    pub fn last(&self) -> (u64, u64) {
        match self.entries.last().ok().flatten() {
            Some((_, v)) => serde_json::from_slice::<LogEntry>(&v)
                .map(|e| (e.index, e.term))
                .unwrap_or((0, 0)),
            None => (0, 0),
        }
    }

    pub fn get(&self, index: u64) -> Option<LogEntry> {
        self.entries
            .get(index.to_be_bytes())
            .ok()
            .flatten()
            .and_then(|v| serde_json::from_slice(&v).ok())
    }

    /// Term of the entry at `index`; index 0 is the empty prefix (term 0).
    pub fn term_at(&self, index: u64) -> Option<u64> {
        if index == 0 {
            return Some(0);
        }
        self.get(index).map(|e| e.term)
    }

    pub fn append(&self, entry: &LogEntry) -> anyhow::Result<()> {
        self.entries
            .insert(entry.index.to_be_bytes(), serde_json::to_vec(entry)?)?;
        self.entries.flush()?;
        Ok(())
    }

    /// Drop every entry at or after `index` (conflicting uncommitted suffix).
    pub fn truncate_from(&self, index: u64) -> anyhow::Result<()> {
        let keys: Vec<_> = self
            .entries
            .range(index.to_be_bytes()..)
            .keys()
            .filter_map(|k| k.ok())
            .collect();
        for k in keys {
            self.entries.remove(k)?;
        }
        self.entries.flush()?;
        Ok(())
    }

    /// Up to `max` entries starting at `from`.
    pub fn range(&self, from: u64, max: usize) -> Vec<LogEntry> {
        self.entries
            .range(from.to_be_bytes()..)
            .values()
            .filter_map(|v| v.ok())
            .filter_map(|v| serde_json::from_slice(&v).ok())
            .take(max)
            .collect()
    }

    pub fn applied_index(&self) -> u64 {
        self.read_u64(META_APPLIED)
    }

    pub fn set_applied_index(&self, v: u64) -> anyhow::Result<()> {
        self.write_u64(META_APPLIED, v)
    }

    pub fn saved_term(&self) -> u64 {
        self.read_u64(META_TERM)
    }

    pub fn save_term(&self, term: u64) -> anyhow::Result<()> {
        self.write_u64(META_TERM, term)
    }
}

/// Applies operations to this node's real stores.
pub struct StateMachine {
    pub db: Arc<Database>,
    pub policy_enforcer: Arc<PolicyEnforcer>,
    pub users: Arc<UserRepository>,
    pub revocation: Arc<TokenRevocation>,
}

impl StateMachine {
    pub async fn apply(&self, op: &ReplicatedOp) -> anyhow::Result<()> {
        match op {
            ReplicatedOp::Noop => {}
            ReplicatedOp::UpsertSite(site) => self.db.upsert_site(site).await?,
            ReplicatedOp::DeleteSite(id) => {
                let id = SiteId::from_str(id).map_err(|e| anyhow::anyhow!("{e}"))?;
                self.db.delete_site(&id).await?;
            }
            ReplicatedOp::UpsertRoutingPolicy(p) => self.db.upsert_policy(p).await?,
            ReplicatedOp::DeleteRoutingPolicy(id) => self.db.delete_policy(*id).await?,
            ReplicatedOp::AddNetworkPolicy(p) => self.policy_enforcer.add_policy(p.clone()).await?,
            ReplicatedOp::RemoveNetworkPolicy(id) => {
                self.policy_enforcer.remove_policy(*id).await?
            }
            ReplicatedOp::CreateUser(u) => self
                .users
                .insert_replicated(u)
                .await
                .map_err(|e| anyhow::anyhow!("{e}"))?,
            ReplicatedOp::UpdateUser { id, update } => {
                self.users
                    .update_user(id, update.clone())
                    .await
                    .map_err(|e| anyhow::anyhow!("{e}"))?;
            }
            ReplicatedOp::SetPassword { id, password_hash } => self
                .users
                .update_password(id, password_hash)
                .await
                .map_err(|e| anyhow::anyhow!("{e}"))?,
            ReplicatedOp::RevokeToken {
                token_id,
                user_id,
                reason,
                expires_at,
            } => {
                self.revocation
                    .revoke_token(
                        token_id.clone(),
                        user_id.clone(),
                        reason.clone(),
                        *expires_at,
                    )
                    .await?
            }
            ReplicatedOp::RevokeAllUserTokens { user_id, reason } => {
                self.revocation
                    .revoke_all_user_tokens(user_id, reason.clone())
                    .await?;
            }
            ReplicatedOp::UpdatePathStatus { path_id, status } => {
                self.db
                    .update_path_status(PathId::new(*path_id), *status)
                    .await?
            }
            ReplicatedOp::EdgeToken {
                digest,
                label,
                created_at,
            } => {
                patronus_sdwan::edge::put_token(self.db.pool(), digest, label, *created_at).await?
            }
            ReplicatedOp::EdgeEnroll {
                site,
                edge,
                used_token,
                at,
            } => {
                self.db.upsert_site(site).await?;
                self.db.store_endpoints(&site.id, &site.endpoints).await?;
                patronus_sdwan::edge::upsert_edge(self.db.pool(), edge).await?;
                patronus_sdwan::edge::consume_token(self.db.pool(), used_token, *at).await?;
            }
            ReplicatedOp::EdgeHeartbeat {
                site_id,
                at,
                status,
            } => {
                patronus_sdwan::edge::touch_edge(self.db.pool(), site_id, *at).await?;
                patronus_sdwan::edge::touch_site(self.db.pool(), site_id, *at, status).await?;
            }
            ReplicatedOp::EdgeRevoke(site_id) => {
                patronus_sdwan::edge::delete_edge(self.db.pool(), site_id).await?;
                if let Ok(id) = SiteId::from_str(site_id) {
                    self.db.delete_site(&id).await?;
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn log_append_truncate_and_meta_persist() {
        let dir = tempfile::tempdir().unwrap();
        {
            let log = ReplicationLog::open(dir.path()).unwrap();
            assert_eq!(log.last(), (0, 0));
            assert_eq!(log.term_at(0), Some(0));
            for i in 1..=5 {
                log.append(&LogEntry {
                    index: i,
                    term: if i < 4 { 1 } else { 2 },
                    op: ReplicatedOp::Noop,
                })
                .unwrap();
            }
            assert_eq!(log.last(), (5, 2));
            assert_eq!(
                log.range(2, 2).iter().map(|e| e.index).collect::<Vec<_>>(),
                vec![2, 3]
            );
            log.truncate_from(4).unwrap();
            assert_eq!(log.last(), (3, 1));
            assert!(log.get(4).is_none());
            log.set_applied_index(3).unwrap();
            log.save_term(7).unwrap();
        }
        // Survives a restart.
        let log = ReplicationLog::open(dir.path()).unwrap();
        assert_eq!(log.last(), (3, 1));
        assert_eq!(log.applied_index(), 3);
        assert_eq!(log.saved_term(), 7);
    }

    #[test]
    fn op_round_trips_through_json() {
        let op = ReplicatedOp::RevokeAllUserTokens {
            user_id: "u1".into(),
            reason: "r".into(),
        };
        let s = serde_json::to_string(&op).unwrap();
        let back: ReplicatedOp = serde_json::from_str(&s).unwrap();
        assert!(matches!(back, ReplicatedOp::RevokeAllUserTokens { .. }));
    }
}
