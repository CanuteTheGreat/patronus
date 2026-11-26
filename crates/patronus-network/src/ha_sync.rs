//! HA configuration sync (lane G, phase 2): settings and history.
//!
//! The primary pushes selected sections of its configuration (see
//! `patronus_config::hasync`) over HTTPS to the backup with a dedicated API key; the backup merges
//! them into its own configuration, applies them through its normal appliers (rolling back on a
//! refusal) and answers with the result, which the primary shows. Settings are `ha.cfgsync.*`
//! keys of `lan_settings` (declarative config: export, plan, apply, API, HA page); each push /
//! receive leaves a row in `ha_sync_history` (measured, not configuration, pruned to
//! `history_keep`).

use crate::lan::{self, db_err, invalid, now};
use patronus_config::hasync::SECTIONS;
use patronus_config::store::ConfigStore;
use patronus_core::Result;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::Row;
use std::collections::BTreeMap;

pub const DEFAULT_CHECK_SECS: u32 = 20;
pub const DEFAULT_RETRY_SECS: u32 = 60;
pub const DEFAULT_TIMEOUT_SECS: u32 = 30;
pub const DEFAULT_HISTORY_KEEP: u32 = 200;

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct SyncSettings {
    /// this node is the source: it pushes its configuration to the peer
    pub push: bool,
    /// this node is a target: it accepts pushes made with an operator API key
    pub accept: bool,
    /// `https://host[:port]` of the peer's web UI; empty = `https://<ha.peer>`
    pub peer_url: Option<String>,
    /// `sha256//<base64>` pin of the peer's TLS public key (shown on the peer's HA page)
    pub peer_pin: Option<String>,
    /// operator API key created on the peer for this purpose (never returned by the API)
    #[serde(skip)]
    pub api_key: String,
    /// seconds between looks for a changed configuration
    pub check_secs: u32,
    /// seconds before a failed push is tried again
    pub retry_secs: u32,
    /// seconds a push may take
    pub timeout_secs: u32,
    /// history rows kept
    pub history_keep: u32,
    /// switched-on sections
    pub sections: Vec<String>,
}

impl Default for SyncSettings {
    fn default() -> Self {
        Self {
            push: false,
            accept: false,
            peer_url: None,
            peer_pin: None,
            api_key: String::new(),
            check_secs: DEFAULT_CHECK_SECS,
            retry_secs: DEFAULT_RETRY_SECS,
            timeout_secs: DEFAULT_TIMEOUT_SECS,
            history_keep: DEFAULT_HISTORY_KEEP,
            sections: SECTIONS.iter().map(|s| s.name.to_string()).collect(),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SyncInput {
    #[serde(default)]
    pub push: Option<bool>,
    #[serde(default)]
    pub accept: Option<bool>,
    #[serde(default)]
    pub peer_url: Option<String>,
    #[serde(default)]
    pub peer_pin: Option<String>,
    #[serde(default)]
    pub api_key: Option<String>,
    #[serde(default)]
    pub check_secs: Option<u32>,
    #[serde(default)]
    pub retry_secs: Option<u32>,
    #[serde(default)]
    pub timeout_secs: Option<u32>,
    #[serde(default)]
    pub history_keep: Option<u32>,
    /// section name -> on/off
    #[serde(default)]
    pub sections: Option<BTreeMap<String, bool>>,
}

fn opt(s: Option<String>) -> Option<String> {
    s.map(|v| v.trim().to_string()).filter(|v| !v.is_empty())
}

fn ranged(v: Option<String>, lo: u32, hi: u32, d: u32) -> u32 {
    v.and_then(|v| v.parse().ok())
        .filter(|v| (lo..=hi).contains(v))
        .unwrap_or(d)
}

pub async fn sync_settings(store: &ConfigStore) -> Result<SyncSettings> {
    let m = lan::settings_with_prefix(store, "ha.cfgsync.").await?;
    let g = |k: &str| m.get(&format!("ha.cfgsync.{k}")).cloned();
    let d = SyncSettings::default();
    Ok(SyncSettings {
        push: g("push").is_some_and(|v| lan::flag(&v)),
        accept: g("accept").is_some_and(|v| lan::flag(&v)),
        peer_url: opt(g("peer_url")),
        peer_pin: opt(g("peer_pin")),
        api_key: g("api_key").unwrap_or_default(),
        check_secs: ranged(g("check_secs"), 5, 3600, d.check_secs),
        retry_secs: ranged(g("retry_secs"), 10, 3600, d.retry_secs),
        timeout_secs: ranged(g("timeout_secs"), 5, 600, d.timeout_secs),
        history_keep: ranged(g("history_keep"), 10, 10000, d.history_keep),
        sections: SECTIONS
            .iter()
            .filter(|s| {
                g(&format!("section.{}", s.name))
                    .map(|v| lan::flag(&v))
                    .unwrap_or(true)
            })
            .map(|s| s.name.to_string())
            .collect(),
    })
}

/// `https://host[:port]` only (no path, query or credentials).
pub fn check_peer_url(s: &str) -> Result<String> {
    let s = s.trim().trim_end_matches('/');
    let rest = s
        .strip_prefix("https://")
        .ok_or_else(|| invalid(format!("peer URL {s:?}: must start with https://")))?;
    let ok = !rest.is_empty()
        && rest.len() <= 253
        && !rest.contains(['/', '?', '#', '@', ' ', '"', '\\'])
        && rest
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':' | '[' | ']'));
    if !ok {
        return Err(invalid(format!(
            "peer URL {s:?}: https://host or https://host:port"
        )));
    }
    Ok(format!("https://{rest}"))
}

/// `sha256//` + 44 base64 characters.
pub fn check_pin(s: &str) -> Result<String> {
    let s = s.trim();
    let b = s
        .strip_prefix("sha256//")
        .ok_or_else(|| invalid(format!("peer pin {s:?}: sha256//<base64>")))?;
    if b.len() != 44
        || !b
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '='))
    {
        return Err(invalid(format!(
            "peer pin {s:?}: sha256//<44 base64 characters>"
        )));
    }
    Ok(s.to_string())
}

fn check_key(s: &str) -> Result<String> {
    let s = s.trim();
    if s.len() < 8 || s.len() > 200 || !s.chars().all(|c| c.is_ascii_graphic()) {
        return Err(invalid("API key: the token shown when the key was created"));
    }
    Ok(s.to_string())
}

pub async fn save_sync_settings(store: &ConfigStore, i: &SyncInput) -> Result<SyncSettings> {
    let mut s = sync_settings(store).await?;
    if let Some(v) = i.push {
        s.push = v;
    }
    if let Some(v) = i.accept {
        s.accept = v;
    }
    if let Some(v) = &i.peer_url {
        s.peer_url = if v.trim().is_empty() {
            None
        } else {
            Some(check_peer_url(v)?)
        };
    }
    if let Some(v) = &i.peer_pin {
        s.peer_pin = if v.trim().is_empty() {
            None
        } else {
            Some(check_pin(v)?)
        };
    }
    if let Some(v) = &i.api_key {
        s.api_key = if v.trim().is_empty() {
            String::new()
        } else {
            check_key(v)?
        };
    }
    for (what, v, lo, hi, dst) in [
        ("check interval", i.check_secs, 5, 3600, &mut s.check_secs),
        ("retry delay", i.retry_secs, 10, 3600, &mut s.retry_secs),
        ("timeout", i.timeout_secs, 5, 600, &mut s.timeout_secs),
        (
            "history length",
            i.history_keep,
            10,
            10000,
            &mut s.history_keep,
        ),
    ] {
        if let Some(v) = v {
            if !(lo..=hi).contains(&v) {
                return Err(invalid(format!("{what}: {lo}-{hi}")));
            }
            *dst = v;
        }
    }
    if let Some(m) = &i.sections {
        for (name, on) in m {
            if !SECTIONS.iter().any(|s| s.name == name) {
                return Err(invalid(format!(
                    "sync section {name:?}: one of {}",
                    SECTIONS
                        .iter()
                        .map(|s| s.name)
                        .collect::<Vec<_>>()
                        .join(", ")
                )));
            }
            s.sections.retain(|n| n != name);
            if *on {
                s.sections.push(name.clone());
            }
        }
    }
    if s.push && s.accept {
        return Err(invalid(
            "a node either pushes its configuration or accepts it, not both (the two would overwrite each other)",
        ));
    }
    if s.push && s.api_key.is_empty() {
        return Err(invalid(
            "pushing needs the peer's API key (create an operator key on the peer)",
        ));
    }
    if s.push && s.peer_pin.is_none() {
        return Err(invalid(
            "pushing needs the peer's TLS pin (shown on the peer's HA page): the API key is never sent to an unverified server",
        ));
    }
    let on = |b: bool| (b as u8).to_string();
    let mut kv = vec![
        ("ha.cfgsync.push".to_string(), on(s.push)),
        ("ha.cfgsync.accept".into(), on(s.accept)),
        (
            "ha.cfgsync.peer_url".into(),
            s.peer_url.clone().unwrap_or_default(),
        ),
        (
            "ha.cfgsync.peer_pin".into(),
            s.peer_pin.clone().unwrap_or_default(),
        ),
        ("ha.cfgsync.api_key".into(), s.api_key.clone()),
        ("ha.cfgsync.check_secs".into(), s.check_secs.to_string()),
        ("ha.cfgsync.retry_secs".into(), s.retry_secs.to_string()),
        ("ha.cfgsync.timeout_secs".into(), s.timeout_secs.to_string()),
        ("ha.cfgsync.history_keep".into(), s.history_keep.to_string()),
    ];
    for sec in SECTIONS {
        kv.push((
            format!("ha.cfgsync.section.{}", sec.name),
            on(s.sections.iter().any(|n| n == sec.name)),
        ));
    }
    for (k, v) in kv {
        lan::set_setting(store, &k, &v).await?;
    }
    Ok(s)
}

/// The peer's base URL: the setting, else `https://<ha.peer>`.
pub fn peer_base(s: &SyncSettings, ha_peer: Option<&str>) -> Option<String> {
    if let Some(u) = &s.peer_url {
        return Some(u.clone());
    }
    ha_peer.map(|p| {
        if p.contains(':') {
            format!("https://[{p}]")
        } else {
            format!("https://{p}")
        }
    })
}

// ---------------------------------------------------------------------------
// history
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct HistoryRow {
    pub id: i64,
    pub ts: i64,
    pub direction: String,
    pub peer: String,
    pub sections: String,
    pub ok: bool,
    pub message: String,
    pub duration_ms: i64,
    pub config_hash: String,
}

#[allow(clippy::too_many_arguments)]
pub async fn record(
    store: &ConfigStore,
    direction: &str,
    peer: &str,
    sections: &[String],
    ok: bool,
    message: &str,
    duration_ms: i64,
    config_hash: &str,
) -> Result<()> {
    let keep = sync_settings(store).await?.history_keep;
    let pool = store.pool()?;
    sqlx::query(
        "INSERT INTO ha_sync_history (ts, direction, peer, sections, ok, message, duration_ms, config_hash)
         VALUES (?,?,?,?,?,?,?,?)",
    )
    .bind(now())
    .bind(direction)
    .bind(peer)
    .bind(sections.join(","))
    .bind(ok as i64)
    .bind(message.chars().take(2000).collect::<String>())
    .bind(duration_ms)
    .bind(config_hash)
    .execute(pool)
    .await
    .map_err(db_err("record sync"))?;
    sqlx::query(
        "DELETE FROM ha_sync_history WHERE id NOT IN (SELECT id FROM ha_sync_history ORDER BY id DESC LIMIT ?)",
    )
    .bind(i64::from(keep))
    .execute(pool)
    .await
    .map_err(db_err("prune sync history"))?;
    Ok(())
}

pub async fn history(store: &ConfigStore, limit: i64) -> Result<Vec<HistoryRow>> {
    let rows = sqlx::query(
        "SELECT id, ts, direction, peer, sections, ok, message, duration_ms, config_hash
         FROM ha_sync_history ORDER BY id DESC LIMIT ?",
    )
    .bind(limit)
    .fetch_all(store.pool()?)
    .await
    .map_err(db_err("read sync history"))?;
    Ok(rows
        .iter()
        .map(|r| HistoryRow {
            id: r.get(0),
            ts: r.get(1),
            direction: r.get(2),
            peer: r.get(3),
            sections: r.get(4),
            ok: r.get::<i64, _>(5) != 0,
            message: r.get(6),
            duration_ms: r.get(7),
            config_hash: r.get(8),
        })
        .collect())
}

/// What the HA page shows: last push, last receive, and whether the last push failed.
pub async fn status(store: &ConfigStore) -> Result<Value> {
    let h = history(store, 50).await?;
    let last = |dir: &str| h.iter().find(|r| r.direction == dir).cloned();
    let last_ok = |dir: &str| h.iter().find(|r| r.direction == dir && r.ok).cloned();
    Ok(json!({
        "last_push": last("push"),
        "last_push_ok": last_ok("push"),
        "last_receive": last("receive"),
        "recent": h.into_iter().take(10).collect::<Vec<_>>(),
    }))
}

/// Hash of the last successful push (what the peer is known to have), if any.
pub async fn last_pushed_hash(store: &ConfigStore) -> Result<Option<String>> {
    let r = sqlx::query(
        "SELECT config_hash FROM ha_sync_history WHERE direction='push' AND ok=1 ORDER BY id DESC LIMIT 1",
    )
    .fetch_optional(store.pool()?)
    .await
    .map_err(db_err("read sync history"))?;
    Ok(r.map(|r| r.get(0)))
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn store() -> (tempfile::TempDir, ConfigStore) {
        let d = tempfile::tempdir().unwrap();
        let s = ConfigStore::open(d.path().join("c.db")).await.unwrap();
        (d, s)
    }

    const PIN: &str = "sha256//AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

    #[tokio::test]
    async fn defaults_round_trip_and_validation() {
        let (_d, s) = store().await;
        let d = sync_settings(&s).await.unwrap();
        assert!(!d.push && !d.accept && d.sections.len() == SECTIONS.len());
        let e = save_sync_settings(
            &s,
            &SyncInput {
                push: Some(true),
                ..Default::default()
            },
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(e.contains("API key"), "{e}");
        let e = save_sync_settings(
            &s,
            &SyncInput {
                push: Some(true),
                api_key: Some("pat_abcdefgh".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(e.contains("pin"), "{e}");
        let ok = save_sync_settings(
            &s,
            &SyncInput {
                push: Some(true),
                api_key: Some("pat_abcdefgh".into()),
                peer_pin: Some(PIN.into()),
                peer_url: Some("https://192.168.50.3/".into()),
                sections: Some(BTreeMap::from([("nat".to_string(), false)])),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert!(ok.push && !ok.sections.contains(&"nat".to_string()));
        assert_eq!(ok.peer_url.as_deref(), Some("https://192.168.50.3"));
        let back = sync_settings(&s).await.unwrap();
        assert_eq!(back, ok);
        // both roles on one node are refused
        let e = save_sync_settings(
            &s,
            &SyncInput {
                accept: Some(true),
                ..Default::default()
            },
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(e.contains("not both"), "{e}");
        assert!(save_sync_settings(
            &s,
            &SyncInput {
                check_secs: Some(1),
                ..Default::default()
            }
        )
        .await
        .is_err());
        assert!(save_sync_settings(
            &s,
            &SyncInput {
                sections: Some(BTreeMap::from([("interfaces".to_string(), true)])),
                ..Default::default()
            }
        )
        .await
        .is_err());
    }

    #[test]
    fn url_and_pin_checks() {
        assert!(check_peer_url("http://x").is_err());
        assert!(check_peer_url("https://a/b").is_err());
        assert!(check_peer_url("https://u@a").is_err());
        assert_eq!(
            check_peer_url("https://fw2.lan:8443/").unwrap(),
            "https://fw2.lan:8443"
        );
        assert!(check_pin("sha256//short").is_err());
        assert!(check_pin(PIN).is_ok());
        let sset = SyncSettings::default();
        assert_eq!(
            peer_base(&sset, Some("10.0.0.3")).as_deref(),
            Some("https://10.0.0.3")
        );
        assert_eq!(
            peer_base(&sset, Some("fd00::3")).as_deref(),
            Some("https://[fd00::3]")
        );
        assert_eq!(peer_base(&sset, None), None);
    }

    #[tokio::test]
    async fn history_is_pruned_and_reports_the_last_good_push() {
        let (_d, s) = store().await;
        save_sync_settings(
            &s,
            &SyncInput {
                history_keep: Some(10),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        for i in 0..15 {
            record(
                &s,
                "push",
                "p",
                &["nat".into()],
                i % 2 == 0,
                "m",
                5,
                &format!("h{i}"),
            )
            .await
            .unwrap();
        }
        assert_eq!(history(&s, 100).await.unwrap().len(), 10);
        assert_eq!(last_pushed_hash(&s).await.unwrap().as_deref(), Some("h14"));
        record(&s, "push", "p", &[], false, "the peer refused", 5, "")
            .await
            .unwrap();
        assert_eq!(last_pushed_hash(&s).await.unwrap().as_deref(), Some("h14"));
        let st = status(&s).await.unwrap();
        assert_eq!(st["last_push"]["ok"], false);
        assert_eq!(st["last_push_ok"]["config_hash"], "h14");
    }
}
