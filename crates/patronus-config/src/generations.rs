//! Configuration generations (NixOS-style history, diff and commit-confirmed).
//!
//! Every applied change set is a numbered **generation**: a full copy of the
//! configuration document ([`ConfigStore::export_json`]) with its time, actor,
//! commit message and content hash. Ids come from an AUTOINCREMENT column, so
//! one is never reused, not even after pruning. Retention keeps the newest
//! [`MAX_GENERATIONS`], plus the live one, the boot default, pinned ones and
//! the two a pending commit-confirm refers to.
//!
//! How a change becomes a generation. Managers call
//! [`ConfigStore::snapshot`] *before* they write (the same call the revision
//! history always had). That
//!  1. seals the change set that was open before (the configuration as it is
//!     now becomes a generation carrying that change set's message),
//!  2. makes sure the state as it is now is itself a generation (it is the
//!     one to roll back to; a baseline generation when something changed the
//!     store outside a recorded change set), and
//!  3. opens the new change set (actor, message).
//!
//! Reads ([`ConfigStore::generations`]) seal the open change set too, so the
//! newest generation is always the live configuration. A change that ended up
//! identical to the newest generation records nothing (a failed change the
//! manager undid leaves no generation).
//!
//! Commit-confirmed: [`ConfigStore::start_pending`] records "previous
//! generation, deadline" in the store. The deadline is enforced by
//! `patronus applyd` (root, its own timer, see `patronus_network::applyd`),
//! by `patronus apply` at boot ([`resolve_pending_at_boot`]) and by the
//! explicit commands, never by the web process that asked for it.

use crate::store::ConfigStore;
use patronus_core::{Error, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::Row;

/// Generations kept (older unpinned ones are pruned).
pub const MAX_GENERATIONS: i64 = 200;

/// Longest commit-confirm window the API accepts, in minutes.
pub const MAX_CONFIRM_MINUTES: i64 = 120;

/// An open change set older than this that changed nothing is forgotten.
const OPEN_TTL_SECS: i64 = 600;

fn db_err(what: &str) -> impl Fn(sqlx::Error) -> Error + '_ {
    move |e| Error::Config(format!("{what}: {e}"))
}

/// One generation (without its document).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Generation {
    pub id: i64,
    pub created_at: i64,
    /// Who made the change: a web user, `cli`, `gitops`, `system`.
    pub actor: String,
    /// The commit message.
    pub message: String,
    /// `change`, `baseline`, `migrated`, `rollback`, `import` or `revert`.
    pub kind: String,
    pub hash: String,
    pub pinned: bool,
    /// The newest generation: what is enforced now.
    pub live: bool,
    /// The generation the next boot loads (differs from `live` only while a
    /// commit-confirmed change is waiting for its confirmation).
    pub boot: bool,
}

/// A commit-confirmed change waiting for its confirmation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Pending {
    /// The generation to go back to.
    pub previous: i64,
    /// The generation that was applied.
    pub generation: i64,
    pub started: i64,
    /// Unix time at which `previous` is restored unless confirmed.
    pub deadline: i64,
    pub minutes: i64,
    pub actor: String,
}

impl Pending {
    pub fn seconds_left(&self, now: i64) -> i64 {
        (self.deadline - now).max(0)
    }
}

fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

/// Canonical hash of a configuration document: independent of row order.
pub fn content_hash(doc: &Value) -> String {
    let mut h = Sha256::new();
    if let Some(tables) = doc.get("tables").and_then(Value::as_object) {
        for (t, rows) in tables {
            let mut lines: Vec<String> = rows
                .as_array()
                .into_iter()
                .flatten()
                .map(|r| r.to_string())
                .collect();
            if lines.is_empty() {
                continue;
            }
            lines.sort();
            h.update(t.as_bytes());
            h.update(b"\n");
            for l in lines {
                h.update(l.as_bytes());
                h.update(b"\n");
            }
        }
    }
    format!("{:x}", h.finalize())
}

/// "before create firewall rule x" -> "create firewall rule x": the manager
/// names the change set before it happens, the generation holds the result.
fn clean_message(m: &str) -> String {
    let m = m.trim();
    m.strip_prefix("before ").unwrap_or(m).to_string()
}

#[derive(Serialize, Deserialize)]
struct OpenChange {
    actor: String,
    message: String,
    kind: String,
    at: i64,
}

impl ConfigStore {
    async fn gstate_get(&self, key: &str) -> Result<Option<String>> {
        let r = sqlx::query("SELECT value FROM config_generation_state WHERE key = ?")
            .bind(key)
            .fetch_optional(self.pool()?)
            .await
            .map_err(db_err("read generation state"))?;
        Ok(r.map(|r| r.get::<String, _>(0)))
    }

    async fn gstate_set(&self, key: &str, value: &str) -> Result<()> {
        sqlx::query(
            "INSERT INTO config_generation_state (key, value) VALUES (?, ?)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        )
        .bind(key)
        .bind(value)
        .execute(self.pool()?)
        .await
        .map_err(db_err("write generation state"))?;
        Ok(())
    }

    async fn gstate_del(&self, key: &str) -> Result<()> {
        sqlx::query("DELETE FROM config_generation_state WHERE key = ?")
            .bind(key)
            .execute(self.pool()?)
            .await
            .map_err(db_err("clear generation state"))?;
        Ok(())
    }

    /// Hashes of generations copied from the old revision table are computed
    /// on first use.
    async fn ensure_hashes(&self) -> Result<()> {
        let rows = sqlx::query("SELECT id, config_json FROM config_generations WHERE content_hash = ''")
            .fetch_all(self.pool()?)
            .await
            .map_err(db_err("read generations"))?;
        for r in rows {
            let id: i64 = r.get(0);
            let doc: Value = serde_json::from_str(&r.get::<String, _>(1)).unwrap_or(Value::Null);
            sqlx::query("UPDATE config_generations SET content_hash = ? WHERE id = ?")
                .bind(content_hash(&doc))
                .bind(id)
                .execute(self.pool()?)
                .await
                .map_err(db_err("hash generation"))?;
        }
        Ok(())
    }

    /// (id, hash) of the newest generation.
    async fn latest_generation(&self) -> Result<Option<(i64, String)>> {
        self.ensure_hashes().await?;
        let r = sqlx::query(
            "SELECT id, content_hash FROM config_generations ORDER BY id DESC LIMIT 1",
        )
        .fetch_optional(self.pool()?)
        .await
        .map_err(db_err("read newest generation"))?;
        Ok(r.map(|r| (r.get(0), r.get(1))))
    }

    /// Record `doc` as a new generation, unless the newest one has the same
    /// hash and `force` is off. Returns the new id.
    async fn insert_generation(
        &self,
        at: i64,
        actor: &str,
        message: &str,
        kind: &str,
        doc: &Value,
        force: bool,
    ) -> Result<Option<i64>> {
        let hash = content_hash(doc);
        // one statement: two processes sealing at once record it once
        let r = sqlx::query(
            "INSERT INTO config_generations (created_at, actor, message, kind, content_hash, config_json)
             SELECT ?1, ?2, ?3, ?4, ?5, ?6
             WHERE ?7 OR NOT EXISTS (
                 SELECT 1 FROM config_generations
                 WHERE id = (SELECT MAX(id) FROM config_generations) AND content_hash = ?5)",
        )
        .bind(at)
        .bind(actor)
        .bind(message)
        .bind(kind)
        .bind(&hash)
        .bind(doc.to_string())
        .bind(force)
        .execute(self.pool()?)
        .await
        .map_err(db_err("record generation"))?;
        if r.rows_affected() == 0 {
            return Ok(None);
        }
        let id = r.last_insert_rowid();
        if self.pending().await?.is_none() {
            self.gstate_set("boot", &id.to_string()).await?;
        }
        self.prune_generations().await?;
        Ok(Some(id))
    }

    async fn prune_generations(&self) -> Result<()> {
        let mut keep: Vec<i64> = Vec::new();
        if let Some(b) = self.gstate_get("boot").await?.and_then(|v| v.parse().ok()) {
            keep.push(b);
        }
        if let Some(p) = self.pending().await? {
            keep.push(p.previous);
            keep.push(p.generation);
        }
        let list = keep
            .iter()
            .map(|i| i.to_string())
            .chain(std::iter::once("-1".to_string()))
            .collect::<Vec<_>>()
            .join(",");
        sqlx::query(&format!(
            "DELETE FROM config_generations
             WHERE pinned = 0 AND id NOT IN ({list})
               AND id NOT IN (SELECT id FROM config_generations ORDER BY id DESC LIMIT ?)"
        ))
        .bind(MAX_GENERATIONS)
        .execute(self.pool()?)
        .await
        .map_err(db_err("prune generations"))?;
        Ok(())
    }

    /// Seal the open change set: when the configuration now differs from the
    /// newest generation, record it as a generation carrying the change
    /// set's actor and message. Returns the new id.
    pub async fn seal(&self) -> Result<Option<i64>> {
        let Some(open) = self.gstate_get("open").await? else {
            return Ok(None);
        };
        let open: OpenChange = serde_json::from_str(&open)
            .map_err(|e| Error::Config(format!("open change set: {e}")))?;
        self.ensure_hashes().await?;
        let doc = self.export_json().await?;
        match self
            .insert_generation(
                open.at,
                &open.actor,
                &clean_message(&open.message),
                &open.kind,
                &doc,
                false,
            )
            .await?
        {
            Some(id) => {
                self.gstate_del("open").await?;
                Ok(Some(id))
            }
            None => {
                // nothing changed (yet): the change may still be in flight,
                // so keep the change set open for a while
                if now() - open.at > OPEN_TTL_SECS {
                    self.gstate_del("open").await?;
                }
                Ok(None)
            }
        }
    }

    pub async fn snapshot_kind(&self, user: &str, summary: &str, kind: &str) -> Result<i64> {
        self.seal().await?;
        let doc = self.export_json().await?;
        let hash = content_hash(&doc);
        let id = match self.latest_generation().await? {
            Some((id, h)) if h == hash => id,
            Some(_) => self
                .insert_generation(
                    now(),
                    "system",
                    "changes made outside a recorded change set",
                    "baseline",
                    &doc,
                    true,
                )
                .await?
                .unwrap_or(0),
            None => self
                .insert_generation(now(), "system", "initial configuration", "baseline", &doc, true)
                .await?
                .unwrap_or(0),
        };
        let open = OpenChange {
            actor: user.to_string(),
            message: summary.to_string(),
            kind: kind.to_string(),
            at: now(),
        };
        self.gstate_set("open", &serde_json::to_string(&open)?).await?;
        Ok(id)
    }

    /// Record the configuration as it is now as a generation right away
    /// (used by rollback, import, revert and the CLI, which know their
    /// message). `None` when it equals the newest generation.
    pub async fn commit_generation(
        &self,
        actor: &str,
        message: &str,
        kind: &str,
    ) -> Result<Option<i64>> {
        self.seal().await?;
        let doc = self.export_json().await?;
        self.insert_generation(now(), actor, message, kind, &doc, false)
            .await
    }

    /// Every generation, newest first. Seals the open change set first.
    pub async fn generations(&self) -> Result<Vec<Generation>> {
        self.seal().await?;
        self.ensure_hashes().await?;
        let boot: Option<i64> = self.gstate_get("boot").await?.and_then(|v| v.parse().ok());
        let rows = sqlx::query(
            "SELECT id, created_at, actor, message, kind, content_hash, pinned
             FROM config_generations ORDER BY id DESC",
        )
        .fetch_all(self.pool()?)
        .await
        .map_err(db_err("list generations"))?;
        let newest = rows.first().map(|r| r.get::<i64, _>(0));
        let boot = boot.or(newest);
        Ok(rows
            .iter()
            .map(|r| {
                let id: i64 = r.get(0);
                Generation {
                    id,
                    created_at: r.get(1),
                    actor: r.get(2),
                    message: r.get(3),
                    kind: r.get(4),
                    hash: r.get(5),
                    pinned: r.get::<i64, _>(6) != 0,
                    live: Some(id) == newest,
                    boot: Some(id) == boot,
                }
            })
            .collect())
    }

    pub async fn generation(&self, id: i64) -> Result<Option<Generation>> {
        Ok(self.generations().await?.into_iter().find(|g| g.id == id))
    }

    /// The live generation, if any exists yet.
    pub async fn live_generation(&self) -> Result<Option<Generation>> {
        Ok(self.generations().await?.into_iter().find(|g| g.live))
    }

    /// The configuration document of generation `id`.
    pub async fn generation_json(&self, id: i64) -> Result<Option<Value>> {
        let row = sqlx::query("SELECT config_json FROM config_generations WHERE id = ?")
            .bind(id)
            .fetch_optional(self.pool()?)
            .await
            .map_err(db_err("load generation"))?;
        row.map(|r| serde_json::from_str(&r.get::<String, _>(0)).map_err(Into::into))
            .transpose()
    }

    /// Is the configuration enforced now different from the newest
    /// generation (something wrote the store outside a change set)?
    pub async fn has_unrecorded_changes(&self) -> Result<bool> {
        self.seal().await?;
        let h = content_hash(&self.export_json().await?);
        Ok(match self.latest_generation().await? {
            Some((_, lh)) => lh != h,
            None => true,
        })
    }

    /// Seal the open change set and close it: whatever happens in the store
    /// after this belongs to no change set until the next snapshot. Returns
    /// the generation the change set produced, if it changed anything.
    pub async fn finish_change_set(&self) -> Result<Option<i64>> {
        let id = self.seal().await?;
        self.gstate_del("open").await?;
        Ok(id)
    }

    /// Replace the commit message of generation `id` (the user typed one).
    pub async fn set_generation_message(&self, id: i64, message: &str) -> Result<()> {
        sqlx::query("UPDATE config_generations SET message = ? WHERE id = ?")
            .bind(message)
            .bind(id)
            .execute(self.pool()?)
            .await
            .map_err(db_err("set commit message"))?;
        Ok(())
    }

    pub async fn pin_generation(&self, id: i64, pinned: bool) -> Result<()> {
        let r = sqlx::query("UPDATE config_generations SET pinned = ? WHERE id = ?")
            .bind(pinned as i64)
            .bind(id)
            .execute(self.pool()?)
            .await
            .map_err(db_err("pin generation"))?;
        if r.rows_affected() == 0 {
            return Err(Error::Config(format!("Generation {id} not found")));
        }
        Ok(())
    }

    /// Replace the configuration with a document, keeping the anti-lockout
    /// rules whatever the document says.
    pub async fn import_checked(&self, doc: &Value) -> Result<()> {
        self.import_json(doc).await?;
        crate::defaults::ensure_system_rules(self).await
    }

    /// Put generation `id`'s configuration back into the store (the caller
    /// then applies it). It is recorded as a new generation, so a rollback
    /// can be rolled back; undoing a change set that was never sealed (a
    /// manager's failure path) records nothing. Returns the id of the new
    /// generation, or of the existing one when nothing changed.
    pub async fn restore_generation(&self, id: i64, actor: &str) -> Result<i64> {
        let doc = self
            .generation_json(id)
            .await?
            .ok_or_else(|| Error::Config(format!("Revision {id} not found")))?;
        let latest = self.latest_generation().await?.map(|l| l.0);
        if Some(id) == latest && self.gstate_get("open").await?.is_some() {
            // undo of a change that never became a generation
            self.import_checked(&doc).await?;
            self.gstate_del("open").await?;
            return Ok(id);
        }
        self.seal().await?;
        self.import_checked(&doc).await?;
        let now_doc = self.export_json().await?;
        let new = self
            .insert_generation(
                now(),
                actor,
                &format!("rollback to generation {id}"),
                "rollback",
                &now_doc,
                false,
            )
            .await?;
        self.gstate_del("open").await?;
        match new {
            Some(n) => Ok(n),
            None => Ok(self.latest_generation().await?.map(|l| l.0).unwrap_or(id)),
        }
    }

    // ---------------------------------------------------------------
    // commit-confirmed
    // ---------------------------------------------------------------

    pub async fn pending(&self) -> Result<Option<Pending>> {
        match self.gstate_get("pending").await? {
            None => Ok(None),
            Some(s) => Ok(Some(
                serde_json::from_str(&s)
                    .map_err(|e| Error::Config(format!("pending commit-confirm: {e}")))?,
            )),
        }
    }

    /// Arm the auto-revert: after `minutes` the configuration of generation
    /// `previous` is restored unless [`confirm_pending`](Self::confirm_pending)
    /// ran. Call it after the change was applied. `None` when the change left
    /// the configuration unchanged (nothing to confirm) or a commit-confirm
    /// is already pending (it keeps its original previous generation and
    /// deadline: further changes are covered by it).
    pub async fn start_pending(
        &self,
        previous: i64,
        minutes: i64,
        actor: &str,
    ) -> Result<Option<Pending>> {
        if !(1..=MAX_CONFIRM_MINUTES).contains(&minutes) {
            return Err(Error::Config(format!(
                "Invalid confirm timeout: {minutes} minutes (1 to {MAX_CONFIRM_MINUTES})"
            )));
        }
        if let Some(p) = self.pending().await? {
            return Ok(Some(p));
        }
        self.seal().await?;
        let Some((generation, _)) = self.latest_generation().await? else {
            return Ok(None);
        };
        if generation == previous {
            return Ok(None);
        }
        if self.generation_json(previous).await?.is_none() {
            return Err(Error::Config(format!("Generation {previous} not found")));
        }
        let t = now();
        let p = Pending {
            previous,
            generation,
            started: t,
            deadline: t + minutes * 60,
            minutes,
            actor: actor.to_string(),
        };
        self.gstate_set("boot", &previous.to_string()).await?;
        self.gstate_set("pending", &serde_json::to_string(&p)?).await?;
        let _ = self
            .audit(
                actor,
                "commit-confirm-start",
                "config",
                Some(&generation.to_string()),
                &json!({"previous": previous, "minutes": minutes}),
            )
            .await;
        Ok(Some(p))
    }

    /// Keep the pending change: it becomes the boot default.
    pub async fn confirm_pending(&self, actor: &str) -> Result<Option<Pending>> {
        let Some(p) = self.pending().await? else {
            return Ok(None);
        };
        self.gstate_del("pending").await?;
        // everything applied while it was on trial is confirmed with it: the
        // boot default is whatever is live now
        self.seal().await?;
        let boot = self
            .latest_generation()
            .await?
            .map(|l| l.0)
            .unwrap_or(p.generation);
        self.gstate_set("boot", &boot.to_string()).await?;
        let _ = self
            .audit(
                actor,
                "commit-confirm-confirm",
                "config",
                Some(&p.generation.to_string()),
                &Value::Null,
            )
            .await;
        Ok(Some(p))
    }

    /// Make the deadline now (the independent timer reverts at its next tick).
    pub async fn expire_pending_now(&self) -> Result<bool> {
        let Some(mut p) = self.pending().await? else {
            return Ok(false);
        };
        p.deadline = now();
        self.gstate_set("pending", &serde_json::to_string(&p)?).await?;
        Ok(true)
    }

    /// The store half of a revert: put the previous generation's
    /// configuration back, clear the pending state, record the revert as a
    /// generation. Safe to run without applying (the boot does).
    pub async fn revert_pending_store(&self, actor: &str, reason: &str) -> Result<Option<i64>> {
        let Some(p) = self.pending().await? else {
            return Ok(None);
        };
        let doc = self.generation_json(p.previous).await?.ok_or_else(|| {
            Error::Config(format!("previous generation {} is gone", p.previous))
        })?;
        self.seal().await?;
        self.import_checked(&doc).await?;
        // cleared before anything is applied: from here on the store, which
        // is what a boot loads, holds the previous configuration
        self.gstate_del("pending").await?;
        let now_doc = self.export_json().await?;
        let new = self
            .insert_generation(
                now(),
                actor,
                &format!("{reason} (back to generation {})", p.previous),
                "revert",
                &now_doc,
                true,
            )
            .await?;
        if let Some(n) = new {
            self.gstate_set("boot", &n.to_string()).await?;
        }
        let _ = self
            .audit(
                actor,
                "commit-confirm-revert",
                "config",
                Some(&p.generation.to_string()),
                &json!({"previous": p.previous, "reason": reason}),
            )
            .await;
        Ok(new)
    }

    pub async fn last_revert(&self) -> Result<Option<Value>> {
        Ok(self
            .gstate_get("last_revert")
            .await?
            .and_then(|s| serde_json::from_str(&s).ok()))
    }

    pub async fn set_last_revert(&self, v: &Value) -> Result<()> {
        self.gstate_set("last_revert", &v.to_string()).await
    }

    /// Primary-key columns of every configuration table (for diffs).
    pub async fn table_keys(&self) -> Result<crate::gendiff::KeyMap> {
        let mut out = crate::gendiff::KeyMap::new();
        for t in self.config_tables().await? {
            let rows = sqlx::query(&format!("PRAGMA table_info(\"{t}\")"))
                .fetch_all(self.pool()?)
                .await
                .map_err(db_err("table info"))?;
            let mut pk: Vec<(i64, String)> = rows
                .iter()
                .filter(|r| r.get::<i64, _>("pk") > 0)
                .map(|r| (r.get::<i64, _>("pk"), r.get::<String, _>("name")))
                .collect();
            pk.sort();
            out.insert(t, pk.into_iter().map(|(_, n)| n).collect());
        }
        Ok(out)
    }

    /// A document named by a generation id or `live`.
    pub async fn document(&self, spec: &str) -> Result<Value> {
        if spec == "live" {
            return self.export_json().await;
        }
        let id: i64 = spec
            .parse()
            .map_err(|_| Error::Config(format!("Invalid generation {spec:?} (an id or 'live')")))?;
        self.generation_json(id)
            .await?
            .ok_or_else(|| Error::Config(format!("Generation {id} not found")))
    }
}

/// One tick of the independent timer: if a commit-confirm is due, revert it
/// (store first, then `apply`). Returns the id of the revert generation.
/// `apply` runs every applier as the caller's user (applyd: root).
pub async fn revert_if_due<F, Fut>(
    store: &ConfigStore,
    actor: &str,
    apply: F,
) -> Result<Option<i64>>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = std::result::Result<(), String>>,
{
    let Some(p) = store.pending().await? else {
        return Ok(None);
    };
    if now() < p.deadline {
        return Ok(None);
    }
    revert_now(store, actor, "not confirmed in time", apply).await
}

/// Revert the pending change now (deadline reached or asked for).
pub async fn revert_now<F, Fut>(
    store: &ConfigStore,
    actor: &str,
    reason: &str,
    apply: F,
) -> Result<Option<i64>>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = std::result::Result<(), String>>,
{
    let new = store
        .revert_pending_store(
            actor,
            &format!("commit-confirm: change reverted, {reason}"),
        )
        .await?;
    let res = apply().await;
    let rec = match &res {
        Ok(()) => json!({"at": now(), "generation": new, "ok": true, "reason": reason}),
        Err(e) => json!({"at": now(), "generation": new, "ok": false, "reason": reason, "error": e}),
    };
    let _ = store.set_last_revert(&rec).await;
    if let Err(e) = res {
        tracing::error!("applying the reverted configuration failed: {e}");
    }
    Ok(new)
}

/// Boot: a commit-confirmed change whose deadline passed while the box was
/// down must not come back. Call before the appliers run. Returns the
/// pending state when it is still counting down (the timer resumes).
pub async fn resolve_pending_at_boot(store: &ConfigStore) -> Result<BootPending> {
    let Some(p) = store.pending().await? else {
        return Ok(BootPending::None);
    };
    if now() >= p.deadline {
        store
            .revert_pending_store("commit-confirm", "deadline passed while the box was down")
            .await?;
        let _ = store
            .set_last_revert(&json!({"at": now(), "ok": true, "reason": "deadline passed while the box was down"}))
            .await;
        Ok(BootPending::Reverted(p))
    } else {
        Ok(BootPending::Resumed(p))
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum BootPending {
    None,
    /// Deadline passed: the previous generation is in the store again.
    Reverted(Pending),
    /// Still counting down.
    Resumed(Pending),
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn marker(s: &ConfigStore) -> Option<String> {
        s.load_system_config("test.marker").await.unwrap()
    }

    async fn change(s: &ConfigStore, actor: &str, msg: &str, v: &str) {
        s.snapshot(actor, &format!("before {msg}")).await.unwrap();
        s.save_system_config("test.marker", v).await.unwrap();
    }

    #[tokio::test]
    async fn every_change_set_is_a_numbered_generation_with_actor_and_message() {
        let s = ConfigStore::open_in_memory().await.unwrap();
        change(&s, "alice", "set marker one", "one").await;
        change(&s, "cli", "set marker two", "two").await;
        let g = s.generations().await.unwrap();
        // baseline + "one" + "two"
        assert_eq!(g.len(), 3, "{g:?}");
        assert_eq!(g[0].message, "set marker two");
        assert_eq!(g[0].actor, "cli");
        assert_eq!(g[1].message, "set marker one");
        assert_eq!(g[1].actor, "alice");
        assert_eq!(g[2].kind, "baseline");
        assert!(g[0].live && !g[1].live);
        assert!(g[0].boot);
        assert_eq!(g[0].hash.len(), 64);
        assert!(g[0].id > g[1].id && g[1].id > g[2].id);
    }

    #[tokio::test]
    async fn a_change_that_changed_nothing_records_no_generation() {
        let s = ConfigStore::open_in_memory().await.unwrap();
        let first = s.snapshot("web", "before nothing").await.unwrap();
        let again = s.snapshot("web", "before still nothing").await.unwrap();
        assert_eq!(first, again);
        assert_eq!(s.generations().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn ids_are_monotonic_and_never_reused_after_pruning() {
        let s = ConfigStore::open_in_memory().await.unwrap();
        let mut last = 0;
        for i in 0..(MAX_GENERATIONS + 6) {
            change(&s, "t", "step", &format!("v{i}")).await;
        }
        let g = s.generations().await.unwrap();
        assert_eq!(g.len() as i64, MAX_GENERATIONS);
        for w in g.windows(2) {
            assert!(w[0].id > w[1].id);
        }
        let newest = g[0].id;
        assert!(newest > MAX_GENERATIONS, "pruned ids are gone for good");
        change(&s, "t", "after pruning", "x").await;
        let g2 = s.generations().await.unwrap();
        assert!(g2[0].id > newest);
        assert!(!g2.iter().any(|x| x.id == 1), "id 1 was pruned, not reused");
        last += g2[0].id;
        assert!(last > 0);
    }

    #[tokio::test]
    async fn retention_keeps_pinned_and_boot_default() {
        let s = ConfigStore::open_in_memory().await.unwrap();
        change(&s, "t", "first", "first").await;
        let first = s.live_generation().await.unwrap().unwrap().id;
        s.pin_generation(first, true).await.unwrap();
        for i in 0..(MAX_GENERATIONS + 3) {
            change(&s, "t", "step", &format!("v{i}")).await;
        }
        let g = s.generations().await.unwrap();
        assert!(g.iter().any(|x| x.id == first && x.pinned));
        assert_eq!(g.len() as i64, MAX_GENERATIONS + 1);
        assert!(g.iter().any(|x| x.boot && x.live));
        assert!(s.pin_generation(999_999, true).await.is_err());
    }

    #[tokio::test]
    async fn rollback_is_a_new_generation_and_can_be_rolled_back() {
        let s = ConfigStore::open_in_memory().await.unwrap();
        change(&s, "a", "one", "one").await;
        change(&s, "a", "two", "two").await;
        let g = s.generations().await.unwrap();
        let one = g.iter().find(|x| x.message == "one").unwrap().id;
        let two = g[0].id;
        let new = s.restore_generation(one, "cli").await.unwrap();
        assert!(new > two);
        assert_eq!(marker(&s).await.as_deref(), Some("one"));
        let g = s.generations().await.unwrap();
        assert_eq!(g[0].id, new);
        assert_eq!(g[0].kind, "rollback");
        assert_eq!(g[0].message, format!("rollback to generation {one}"));
        assert_eq!(g[0].actor, "cli");
        // and back
        s.restore_generation(two, "cli").await.unwrap();
        assert_eq!(marker(&s).await.as_deref(), Some("two"));
        assert!(s.restore_generation(424_242, "cli").await.is_err());
    }

    #[tokio::test]
    async fn undoing_an_unsealed_change_leaves_no_generation() {
        let s = ConfigStore::open_in_memory().await.unwrap();
        change(&s, "a", "one", "one").await;
        let before = s.generations().await.unwrap().len();
        let rev = s.snapshot("web", "before doomed").await.unwrap();
        s.save_system_config("test.marker", "doomed").await.unwrap();
        s.restore_revision(rev, "web").await.unwrap();
        assert_eq!(marker(&s).await.as_deref(), Some("one"));
        assert_eq!(s.generations().await.unwrap().len(), before);
    }

    #[tokio::test]
    async fn old_revisions_migrate_with_their_ids() {
        // a store from before generations: rows in config_revisions
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("old.db");
        {
            let s = ConfigStore::open(&path).await.unwrap();
            sqlx::query("DELETE FROM config_generations")
                .execute(s.pool().unwrap())
                .await
                .unwrap();
            sqlx::query("DELETE FROM schema_migrations WHERE version = 30")
                .execute(s.pool().unwrap())
                .await
                .unwrap();
            sqlx::query("DROP TABLE config_generations")
                .execute(s.pool().unwrap())
                .await
                .unwrap();
            sqlx::query("DROP TABLE config_generation_state")
                .execute(s.pool().unwrap())
                .await
                .unwrap();
            let doc = s.export_json().await.unwrap().to_string();
            for (id, msg) in [(7, "before a"), (9, "before b")] {
                sqlx::query(
                    "INSERT INTO config_revisions (id, created_at, user, summary, config_json)
                     VALUES (?, 1000, 'web', ?, ?)",
                )
                .bind(id)
                .bind(msg)
                .bind(&doc)
                .execute(s.pool().unwrap())
                .await
                .unwrap();
            }
            s.close().await;
        }
        let s = ConfigStore::open(&path).await.unwrap();
        let g = s.generations().await.unwrap();
        let ids: Vec<i64> = g.iter().map(|x| x.id).collect();
        assert_eq!(ids, vec![9, 7]);
        assert_eq!(g[0].kind, "migrated");
        assert_eq!(g[0].message, "before b");
        // new ones continue after the migrated ids
        let n = s.snapshot("web", "before c").await.unwrap();
        s.save_system_config("test.marker", "c").await.unwrap();
        let g = s.generations().await.unwrap();
        assert!(g[0].id > 9, "{g:?} {n}");
    }

    #[tokio::test]
    async fn commit_confirm_arms_confirms_and_survives_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cc.db");
        let s = ConfigStore::open(&path).await.unwrap();
        let prev = s.snapshot("web", "before risky").await.unwrap();
        s.save_system_config("test.marker", "risky").await.unwrap();
        let p = s.start_pending(prev, 5, "alice").await.unwrap().unwrap();
        assert_eq!(p.previous, prev);
        assert!(p.generation > prev);
        assert_eq!(p.deadline - p.started, 300);
        // boot default stays the previous generation while pending
        let g = s.generations().await.unwrap();
        assert!(g.iter().find(|x| x.id == prev).unwrap().boot);
        assert!(g.iter().find(|x| x.id == p.generation).unwrap().live);
        s.close().await;
        // a restart of whatever process asked for it: state is still there
        let s = ConfigStore::open(&path).await.unwrap();
        assert_eq!(s.pending().await.unwrap().unwrap(), p);
        assert!(s.confirm_pending("alice").await.unwrap().is_some());
        assert!(s.pending().await.unwrap().is_none());
        let g = s.generations().await.unwrap();
        assert!(g.iter().find(|x| x.id == p.generation).unwrap().boot);
        assert!(s.confirm_pending("alice").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn pending_is_refused_for_a_change_that_changed_nothing_and_bad_minutes() {
        let s = ConfigStore::open_in_memory().await.unwrap();
        let prev = s.snapshot("web", "before nothing").await.unwrap();
        assert!(s.start_pending(prev, 5, "a").await.unwrap().is_none());
        assert!(s.start_pending(prev, 0, "a").await.is_err());
        assert!(s.start_pending(prev, 9999, "a").await.is_err());
    }

    #[tokio::test]
    async fn a_second_change_while_pending_keeps_the_first_deadline() {
        let s = ConfigStore::open_in_memory().await.unwrap();
        let prev = s.snapshot("web", "before one").await.unwrap();
        s.save_system_config("test.marker", "1").await.unwrap();
        let p1 = s.start_pending(prev, 5, "a").await.unwrap().unwrap();
        let prev2 = s.snapshot("web", "before two").await.unwrap();
        s.save_system_config("test.marker", "2").await.unwrap();
        let p2 = s.start_pending(prev2, 10, "a").await.unwrap().unwrap();
        assert_eq!(p1.previous, p2.previous);
        assert_eq!(p1.deadline, p2.deadline);
    }

    #[tokio::test]
    async fn revert_when_due_restores_previous_and_records_a_generation() {
        let s = ConfigStore::open_in_memory().await.unwrap();
        s.save_system_config("test.marker", "good").await.unwrap();
        let prev = s.snapshot("web", "before bad").await.unwrap();
        s.save_system_config("test.marker", "bad").await.unwrap();
        let p = s.start_pending(prev, 5, "web").await.unwrap().unwrap();
        // not due yet: nothing happens
        let applied = std::sync::atomic::AtomicUsize::new(0);
        let r = revert_if_due(&s, "applyd", || async {
            applied.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        })
        .await
        .unwrap();
        assert!(r.is_none());
        assert_eq!(marker(&s).await.as_deref(), Some("bad"));
        // deadline reached
        assert!(s.expire_pending_now().await.unwrap());
        let r = revert_if_due(&s, "applyd", || async {
            applied.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        })
        .await
        .unwrap();
        assert!(r.is_some());
        assert_eq!(applied.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert_eq!(marker(&s).await.as_deref(), Some("good"));
        assert!(s.pending().await.unwrap().is_none());
        let g = s.generations().await.unwrap();
        assert_eq!(g[0].kind, "revert");
        assert!(g[0].message.contains(&format!("back to generation {}", p.previous)));
        assert!(g[0].boot && g[0].live);
        assert_eq!(s.last_revert().await.unwrap().unwrap()["ok"], true);
        // a revert with an apply error still leaves the store reverted
        let prev = s.snapshot("web", "before bad2").await.unwrap();
        s.save_system_config("test.marker", "bad2").await.unwrap();
        s.start_pending(prev, 5, "web").await.unwrap().unwrap();
        s.expire_pending_now().await.unwrap();
        revert_if_due(&s, "applyd", || async { Err("nft said no".to_string()) })
            .await
            .unwrap();
        assert_eq!(marker(&s).await.as_deref(), Some("good"));
        assert_eq!(s.last_revert().await.unwrap().unwrap()["ok"], false);
    }

    #[tokio::test]
    async fn boot_reverts_an_expired_pending_and_resumes_a_running_one() {
        let s = ConfigStore::open_in_memory().await.unwrap();
        s.save_system_config("test.marker", "good").await.unwrap();
        let prev = s.snapshot("web", "before bad").await.unwrap();
        s.save_system_config("test.marker", "bad").await.unwrap();
        let p = s.start_pending(prev, 5, "web").await.unwrap().unwrap();
        match resolve_pending_at_boot(&s).await.unwrap() {
            BootPending::Resumed(r) => assert_eq!(r, p),
            o => panic!("{o:?}"),
        }
        assert_eq!(marker(&s).await.as_deref(), Some("bad"));
        s.expire_pending_now().await.unwrap();
        assert!(matches!(
            resolve_pending_at_boot(&s).await.unwrap(),
            BootPending::Reverted(_)
        ));
        assert_eq!(marker(&s).await.as_deref(), Some("good"));
        assert_eq!(resolve_pending_at_boot(&s).await.unwrap(), BootPending::None);
    }

    #[tokio::test]
    async fn reverting_keeps_the_anti_lockout_rules() {
        let s = ConfigStore::open_in_memory().await.unwrap();
        s.save_system_config(crate::defaults::DEFAULTS_SEEDED_KEY, "test").await.unwrap();
        crate::defaults::ensure_system_rules(&s).await.unwrap();
        let mut doc = s.export_json().await.unwrap();
        doc["tables"]["firewall_rules"] = json!([]);
        s.import_checked(&doc).await.unwrap();
        let rules = s.load_firewall_rules_with_origin().await.unwrap();
        assert!(rules
            .iter()
            .any(|(r, o)| r.name == "Anti-lockout" && *o == crate::store::RuleOrigin::System));
    }

    #[test]
    fn hash_ignores_row_order_and_empty_tables() {
        let a = json!({"tables": {"t": [{"id": 1}, {"id": 2}], "e": []}});
        let b = json!({"tables": {"t": [{"id": 2}, {"id": 1}]}});
        assert_eq!(content_hash(&a), content_hash(&b));
        let c = json!({"tables": {"t": [{"id": 2}, {"id": 3}]}});
        assert_ne!(content_hash(&a), content_hash(&c));
    }

    #[tokio::test]
    async fn unrecorded_changes_are_visible_and_become_a_baseline() {
        let s = ConfigStore::open_in_memory().await.unwrap();
        change(&s, "a", "one", "one").await;
        s.generations().await.unwrap();
        assert!(!s.has_unrecorded_changes().await.unwrap());
        // something writes the store without a change set
        s.save_system_config("test.marker", "sneaky").await.unwrap();
        assert!(s.has_unrecorded_changes().await.unwrap());
        s.snapshot("web", "before next").await.unwrap();
        let g = s.generations().await.unwrap();
        assert_eq!(g[0].kind, "baseline");
        assert_eq!(g[0].message, "changes made outside a recorded change set");
    }
}
