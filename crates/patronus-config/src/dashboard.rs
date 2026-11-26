//! Dashboard and diagnostics settings, and the per-user dashboard layouts.
//!
//! Settings are typed `system_config` keys with built-in defaults, so they are
//! carried by export / plan / apply, backups, GitOps and rollbacks like every
//! other configuration value:
//!
//! | key | default | meaning |
//! |-----|---------|---------|
//! | `dashboard.refresh_seconds` | 30 | the dashboard re-reads its widgets this often (0 = never) |
//! | `dashboard.activity_sample_secs` | 3 | pause between two `/proc` samples of the system activity sampler |
//! | `dashboard.activity_top` | 25 | processes the activity API/page list when no limit is asked for |
//! | `diag.tcp_timeout_secs` | 3 | connect timeout of the Diagnostics "test port" tool |
//! | `diag.tcp_tests_per_minute` | 30 | port tests allowed per minute |
//!
//! Layouts are rows of `dashboard_layouts` (migration 1520): one JSON document
//! per web user; the widget registry that gives the ids meaning lives in
//! `patronus-web`.

use crate::store::ConfigStore;
use patronus_core::{Error, Result};
use serde::{Deserialize, Serialize};
use sqlx::Row;

pub const K_REFRESH: &str = "dashboard.refresh_seconds";
pub const K_SAMPLE: &str = "dashboard.activity_sample_secs";
pub const K_TOP: &str = "dashboard.activity_top";
pub const K_TCP_TIMEOUT: &str = "diag.tcp_timeout_secs";
pub const K_TCP_RATE: &str = "diag.tcp_tests_per_minute";

pub const KEYS: &[&str] = &[K_REFRESH, K_SAMPLE, K_TOP, K_TCP_TIMEOUT, K_TCP_RATE];

/// Largest layout document accepted (bytes).
pub const MAX_LAYOUT_BYTES: usize = 16 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Settings {
    pub refresh_seconds: u32,
    pub activity_sample_secs: u32,
    pub activity_top: u32,
    pub tcp_timeout_secs: u32,
    pub tcp_tests_per_minute: u32,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            refresh_seconds: 30,
            activity_sample_secs: 3,
            activity_top: 25,
            tcp_timeout_secs: 3,
            tcp_tests_per_minute: 30,
        }
    }
}

/// Valid range of each key (inclusive); `refresh_seconds` also allows 0.
fn range(key: &str) -> (u32, u32) {
    match key {
        K_REFRESH => (5, 3600),
        K_SAMPLE => (1, 60),
        K_TOP => (5, 500),
        K_TCP_TIMEOUT => (1, 30),
        _ => (1, 600),
    }
}

fn valid(key: &str, v: u32) -> bool {
    let (lo, hi) = range(key);
    (v >= lo && v <= hi) || (key == K_REFRESH && v == 0)
}

impl Settings {
    fn slot(&mut self, key: &str) -> Option<&mut u32> {
        Some(match key {
            K_REFRESH => &mut self.refresh_seconds,
            K_SAMPLE => &mut self.activity_sample_secs,
            K_TOP => &mut self.activity_top,
            K_TCP_TIMEOUT => &mut self.tcp_timeout_secs,
            K_TCP_RATE => &mut self.tcp_tests_per_minute,
            _ => return None,
        })
    }
}

/// Effective settings: stored values that parse and are in range, else the default.
pub async fn load(store: &ConfigStore) -> Settings {
    let mut s = Settings::default();
    for k in KEYS {
        if let Ok(Some(raw)) = store.load_system_config(k).await {
            if let Ok(v) = raw.trim().parse::<u32>() {
                if valid(k, v) {
                    if let Some(slot) = s.slot(k) {
                        *slot = v;
                    }
                }
            }
        }
    }
    s
}

/// Store the keys named in `patch` (JSON object keyed by the short names:
/// `refresh_seconds`, `activity_sample_secs`, `activity_top`,
/// `tcp_timeout_secs`, `tcp_tests_per_minute`). Unknown names and
/// out-of-range values are errors; nothing is saved then.
pub async fn save(store: &ConfigStore, patch: &serde_json::Value) -> Result<Settings> {
    let obj = patch
        .as_object()
        .ok_or_else(|| Error::Config("Invalid dashboard settings: expected a JSON object".into()))?;
    let mut todo = Vec::new();
    for (name, v) in obj {
        let key = match name.as_str() {
            "refresh_seconds" => K_REFRESH,
            "activity_sample_secs" => K_SAMPLE,
            "activity_top" => K_TOP,
            "tcp_timeout_secs" => K_TCP_TIMEOUT,
            "tcp_tests_per_minute" => K_TCP_RATE,
            other => {
                return Err(Error::Config(format!(
                    "Invalid dashboard settings: unknown setting {other:?}"
                )))
            }
        };
        let n = v
            .as_u64()
            .and_then(|n| u32::try_from(n).ok())
            .filter(|n| valid(key, *n))
            .ok_or_else(|| {
                let (lo, hi) = range(key);
                Error::Config(format!(
                    "Invalid dashboard settings: {name} must be a whole number from {lo} to {hi}{}",
                    if key == K_REFRESH { " (or 0 = never)" } else { "" }
                ))
            })?;
        todo.push((key, n));
    }
    for (k, n) in todo {
        store.save_system_config(k, &n.to_string()).await?;
    }
    Ok(load(store).await)
}

fn db_err(what: &str) -> impl Fn(sqlx::Error) -> Error + '_ {
    move |e| Error::Config(format!("{what}: {e}"))
}

/// The stored layout document of `user`.
pub async fn get_layout(store: &ConfigStore, user: &str) -> Result<Option<String>> {
    let row = sqlx::query("SELECT layout_json FROM dashboard_layouts WHERE user = ?")
        .bind(user)
        .fetch_optional(store.pool()?)
        .await
        .map_err(db_err("read dashboard layout"))?;
    Ok(row.map(|r| r.get(0)))
}

/// Store the layout document of `user` (replaces the old one).
pub async fn put_layout(store: &ConfigStore, user: &str, json: &str) -> Result<()> {
    if json.len() > MAX_LAYOUT_BYTES {
        return Err(Error::Config(
            "Invalid dashboard layout: document too large".into(),
        ));
    }
    sqlx::query(
        "INSERT INTO dashboard_layouts (user, layout_json, updated_at) VALUES (?, ?, ?)
         ON CONFLICT(user) DO UPDATE SET layout_json = excluded.layout_json, updated_at = excluded.updated_at",
    )
    .bind(user)
    .bind(json)
    .bind(chrono::Utc::now().timestamp())
    .execute(store.pool()?)
    .await
    .map_err(db_err("save dashboard layout"))?;
    Ok(())
}

/// Forget the layout of `user` (back to the default). True when one existed.
pub async fn delete_layout(store: &ConfigStore, user: &str) -> Result<bool> {
    let r = sqlx::query("DELETE FROM dashboard_layouts WHERE user = ?")
        .bind(user)
        .execute(store.pool()?)
        .await
        .map_err(db_err("delete dashboard layout"))?;
    Ok(r.rows_affected() > 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    async fn store() -> (tempfile::TempDir, ConfigStore) {
        let d = tempfile::tempdir().unwrap();
        let s = ConfigStore::open(d.path().join("c.db")).await.unwrap();
        (d, s)
    }

    #[tokio::test]
    async fn defaults_save_validate_and_ignore_garbage() {
        let (_d, s) = store().await;
        assert_eq!(load(&s).await, Settings::default());
        let n = save(&s, &json!({"refresh_seconds": 0, "activity_top": 50})).await.unwrap();
        assert_eq!((n.refresh_seconds, n.activity_top, n.tcp_timeout_secs), (0, 50, 3));
        for bad in [
            json!({"refresh_seconds": 2}),
            json!({"activity_sample_secs": 0}),
            json!({"tcp_timeout_secs": 31}),
            json!({"tcp_tests_per_minute": "many"}),
            json!({"nope": 1}),
            json!([1]),
        ] {
            assert!(save(&s, &bad).await.is_err(), "{bad}");
        }
        // one bad key saves nothing from the same request
        assert!(save(&s, &json!({"activity_top": 7, "tcp_timeout_secs": 99})).await.is_err());
        assert_eq!(load(&s).await.activity_top, 50);
        // a hand-edited bad stored value falls back to the default
        s.save_system_config(K_TOP, "99999").await.unwrap();
        assert_eq!(load(&s).await.activity_top, 25);
    }

    #[tokio::test]
    async fn layouts_are_per_user_and_travel_with_the_export() {
        let (_d, s) = store().await;
        assert_eq!(get_layout(&s, "alice").await.unwrap(), None);
        put_layout(&s, "alice", r#"{"v":1,"widgets":[]}"#).await.unwrap();
        put_layout(&s, "alice", r#"{"v":1,"widgets":[{"id":"x","on":true}]}"#).await.unwrap();
        put_layout(&s, "bob", "{}").await.unwrap();
        assert!(get_layout(&s, "alice").await.unwrap().unwrap().contains("\"x\""));
        assert_eq!(get_layout(&s, "bob").await.unwrap().as_deref(), Some("{}"));
        let export = s.export_json().await.unwrap();
        assert_eq!(export["tables"]["dashboard_layouts"].as_array().map(Vec::len), Some(2), "{export}");
        assert!(delete_layout(&s, "alice").await.unwrap());
        assert!(!delete_layout(&s, "alice").await.unwrap());
        assert!(get_layout(&s, "bob").await.unwrap().is_some());
        assert!(put_layout(&s, "bob", &"x".repeat(MAX_LAYOUT_BYTES + 1)).await.is_err());
    }
}
