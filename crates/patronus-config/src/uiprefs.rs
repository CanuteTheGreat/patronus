//! Web UI display settings (typed `system_config` keys, so they are part of the
//! declarative config: export, plan, apply, revisions; API `GET/PUT /api/system/ui`,
//! System page card):
//!
//! - `ui.health_warn_pct` (default 80) / `ui.health_crit_pct` (default 90): where a
//!   usage value (CPU, memory, disk) turns amber / red on the dashboard and the
//!   System page. 1-100, warn below crit.
//! - `refresh_secs` = the key `dashboard.refresh_seconds` (owned by [`crate::dashboard`],
//!   default 30): how often the dashboard re-reads its widgets; 0 = never (the page says it
//!   is a snapshot), otherwise 5-3600. Shown here too so the Display card sets it; ONE key.
//!
//! An absent or empty key = the default.

use crate::store::ConfigStore;
use patronus_core::{Error, Result};
use serde::{Deserialize, Serialize};

pub const K_WARN: &str = "ui.health_warn_pct";
pub const K_CRIT: &str = "ui.health_crit_pct";
/// The dashboard's own key (one setting, two views: `/api/system/ui` and the dashboard settings).
pub const K_REFRESH: &str = crate::dashboard::K_REFRESH;
pub const KEYS: &[&str] = &[K_WARN, K_CRIT, K_REFRESH];

pub const DEFAULT_WARN: u8 = 80;
pub const DEFAULT_CRIT: u8 = 90;
pub const DEFAULT_REFRESH: u32 = 30;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct UiPrefs {
    pub health_warn_pct: u8,
    pub health_crit_pct: u8,
    pub refresh_secs: u32,
}

impl Default for UiPrefs {
    fn default() -> Self {
        UiPrefs {
            health_warn_pct: DEFAULT_WARN,
            health_crit_pct: DEFAULT_CRIT,
            refresh_secs: DEFAULT_REFRESH,
        }
    }
}

/// Severity of a usage percentage against the thresholds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    Ok,
    Warn,
    Crit,
}

impl Level {
    /// The ui-kit tone class (`ui-usage warn`, `ui-badge crit`); empty for ok.
    pub fn class(self) -> &'static str {
        match self {
            Level::Ok => "",
            Level::Warn => "warn",
            Level::Crit => "crit",
        }
    }
}

impl UiPrefs {
    pub fn level(&self, pct: f64) -> Level {
        if pct >= self.health_crit_pct as f64 {
            Level::Crit
        } else if pct >= self.health_warn_pct as f64 {
            Level::Warn
        } else {
            Level::Ok
        }
    }

    pub fn validate(&self) -> Result<()> {
        let bad = |m: &str| Err(Error::Config(format!("Invalid UI settings: {m}")));
        if !(1..=100).contains(&self.health_warn_pct) || !(1..=100).contains(&self.health_crit_pct)
        {
            return bad("thresholds are percentages (1-100)");
        }
        if self.health_warn_pct >= self.health_crit_pct {
            return bad("the warning threshold must be below the critical one");
        }
        if self.refresh_secs != 0 && !(5..=3600).contains(&self.refresh_secs) {
            return bad("refresh is 0 (off) or 5-3600 seconds");
        }
        Ok(())
    }
}

async fn get(store: &ConfigStore, k: &str) -> Option<String> {
    store
        .load_system_config(k)
        .await
        .ok()
        .flatten()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

/// The effective settings (stored values over the defaults; an unparsable or
/// inconsistent stored set falls back to the defaults as a whole).
pub async fn resolve(store: &ConfigStore) -> UiPrefs {
    let d = UiPrefs::default();
    let p = UiPrefs {
        health_warn_pct: get(store, K_WARN)
            .await
            .and_then(|v| v.parse().ok())
            .unwrap_or(d.health_warn_pct),
        health_crit_pct: get(store, K_CRIT)
            .await
            .and_then(|v| v.parse().ok())
            .unwrap_or(d.health_crit_pct),
        refresh_secs: get(store, K_REFRESH)
            .await
            .and_then(|v| v.parse().ok())
            .unwrap_or(d.refresh_secs),
    };
    if p.validate().is_ok() {
        p
    } else {
        d
    }
}

/// Fields of `PUT /api/system/ui`: absent = unchanged; `reset` = all defaults.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UiInput {
    #[serde(default)]
    pub health_warn_pct: Option<u8>,
    #[serde(default)]
    pub health_crit_pct: Option<u8>,
    #[serde(default)]
    pub refresh_secs: Option<u32>,
    #[serde(default)]
    pub reset: bool,
}

/// Validate and store; returns the new effective settings.
pub async fn save(store: &ConfigStore, i: &UiInput) -> Result<UiPrefs> {
    let mut p = if i.reset {
        UiPrefs::default()
    } else {
        resolve(store).await
    };
    if let Some(v) = i.health_warn_pct {
        p.health_warn_pct = v;
    }
    if let Some(v) = i.health_crit_pct {
        p.health_crit_pct = v;
    }
    if let Some(v) = i.refresh_secs {
        p.refresh_secs = v;
    }
    p.validate()?;
    if i.reset {
        for k in KEYS {
            store.save_system_config(k, "").await?;
        }
    }
    let d = UiPrefs::default();
    for (k, v, dv) in [
        (K_WARN, p.health_warn_pct as u32, d.health_warn_pct as u32),
        (K_CRIT, p.health_crit_pct as u32, d.health_crit_pct as u32),
        (K_REFRESH, p.refresh_secs, d.refresh_secs),
    ] {
        // a value equal to the default is stored empty, so a later default change reaches it
        store
            .save_system_config(
                k,
                &if v == dv {
                    String::new()
                } else {
                    v.to_string()
                },
            )
            .await?;
    }
    Ok(p)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn defaults_store_and_validation() {
        let s = ConfigStore::open_in_memory().await.unwrap();
        assert_eq!(resolve(&s).await, UiPrefs::default());
        let p = save(
            &s,
            &UiInput {
                health_warn_pct: Some(70),
                refresh_secs: Some(0),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(
            (p.health_warn_pct, p.health_crit_pct, p.refresh_secs),
            (70, 90, 0)
        );
        assert_eq!(resolve(&s).await, p);
        // one key: the dashboard's own settings see the same refresh
        assert_eq!(crate::dashboard::load(&s).await.refresh_seconds, 0);
        assert_eq!(p.level(69.9), Level::Ok);
        assert_eq!(p.level(70.0), Level::Warn);
        assert_eq!(p.level(95.0), Level::Crit);
        for bad in [
            UiInput {
                health_warn_pct: Some(95),
                ..Default::default()
            },
            UiInput {
                health_crit_pct: Some(101),
                ..Default::default()
            },
            UiInput {
                refresh_secs: Some(1),
                ..Default::default()
            },
        ] {
            assert!(save(&s, &bad).await.is_err(), "{bad:?}");
        }
        assert_eq!(
            resolve(&s).await,
            p,
            "a refused change keeps the stored settings"
        );
        let r = save(
            &s,
            &UiInput {
                reset: true,
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(r, UiPrefs::default());
        // an inconsistent hand-edited store falls back to the defaults
        s.save_system_config(K_WARN, "99").await.unwrap();
        assert_eq!(resolve(&s).await, UiPrefs::default());
    }
}
