//! `cve.*` settings: typed keys with documented defaults (nothing is hard-coded in the
//! engine), stored in `system_config`, so they are exported, planned, applied and rolled back
//! with the rest of the configuration.

use patronus_config::ConfigStore;
use patronus_core::{Error, Result};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use std::collections::BTreeMap;

pub const POLICIES: &[&str] = &["off", "notify", "apply"];

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Settings {
    /// Scan on a schedule (the page always shows the last result).
    pub enabled: bool,
    /// Download the crate advisory archive on a schedule (the only network use).
    pub fetch: bool,
    pub osv_url: String,
    pub osv_max_bytes: u64,
    pub osv_refresh_hours: u32,
    /// Advisory data older than this is shown as stale, never as clean.
    pub osv_stale_days: u32,
    pub glsa_dir: String,
    pub glsa_stale_days: u32,
    pub pkg_db: String,
    /// Empty = every `patronus*` executable in /usr/bin, /usr/sbin, /usr/local/bin.
    pub binaries: Vec<String>,
    pub manifest_path: String,
    pub scan_interval_secs: u64,
    pub tick_secs: u64,
    pub data_dir: String,
    pub portageq: String,
    pub emerge: String,
    /// `off`, `notify` (show only) or `apply` (install GLSA fixes in the window).
    pub security_updates: String,
    /// Local time, `HH:MM-HH:MM`; may cross midnight.
    pub window: String,
    pub apply_min_interval_secs: u64,
    pub apply_max_packages: u32,
    pub apply_timeout_secs: u64,
    pub history_days: u32,
    pub history_max_rows: u32,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            enabled: true,
            fetch: true,
            osv_url: "https://osv-vulnerabilities.storage.googleapis.com/crates.io/all.zip".into(),
            osv_max_bytes: 64 << 20,
            osv_refresh_hours: 24,
            osv_stale_days: 7,
            glsa_dir: "/var/db/repos/gentoo/metadata/glsa".into(),
            glsa_stale_days: 14,
            pkg_db: "/var/db/pkg".into(),
            binaries: Vec::new(),
            manifest_path: "/usr/share/patronus/package-manifest.json".into(),
            scan_interval_secs: 6 * 3600,
            tick_secs: 60,
            data_dir: "/var/lib/patronus/cve".into(),
            portageq: "portageq".into(),
            emerge: "emerge".into(),
            security_updates: "notify".into(),
            window: "02:00-05:00".into(),
            apply_min_interval_secs: 6 * 3600,
            apply_max_packages: 20,
            apply_timeout_secs: 3600,
            history_days: 90,
            history_max_rows: 2000,
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SettingsIn {
    pub enabled: Option<bool>,
    pub fetch: Option<bool>,
    pub osv_url: Option<String>,
    pub osv_max_bytes: Option<u64>,
    pub osv_refresh_hours: Option<u32>,
    pub osv_stale_days: Option<u32>,
    pub glsa_dir: Option<String>,
    pub glsa_stale_days: Option<u32>,
    pub pkg_db: Option<String>,
    pub binaries: Option<Vec<String>>,
    pub manifest_path: Option<String>,
    pub scan_interval_secs: Option<u64>,
    pub tick_secs: Option<u64>,
    pub data_dir: Option<String>,
    pub portageq: Option<String>,
    pub emerge: Option<String>,
    pub security_updates: Option<String>,
    pub window: Option<String>,
    pub apply_min_interval_secs: Option<u64>,
    pub apply_max_packages: Option<u32>,
    pub apply_timeout_secs: Option<u64>,
    pub history_days: Option<u32>,
    pub history_max_rows: Option<u32>,
}

fn bad(m: impl std::fmt::Display) -> Error {
    Error::Config(format!("Invalid {m}"))
}

fn flag(v: &str) -> bool {
    matches!(v.trim(), "1" | "true" | "yes" | "on")
}

fn list(v: &str) -> Vec<String> {
    v.split([',', '\n'])
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect()
}

fn abs_path(what: &str, p: &str) -> Result<String> {
    let p = p.trim();
    if !p.starts_with('/')
        || p.len() > 255
        || p.contains("..")
        || p.bytes().any(|b| b < 0x21 && b != b' ')
        || p.contains(',')
    {
        return Err(bad(format!("{what} {p:?}: want an absolute path")));
    }
    Ok(p.to_string())
}

/// A program: a bare name found in PATH or an absolute path.
fn program(what: &str, p: &str) -> Result<String> {
    let p = p.trim();
    let ok = !p.is_empty()
        && p.len() < 256
        && !p.contains("..")
        && p.bytes().all(|b| b.is_ascii_graphic() && b != b',');
    if !ok {
        return Err(bad(format!("{what} {p:?}")));
    }
    Ok(p.to_string())
}

/// `HH:MM-HH:MM` -> (start, end) in minutes since midnight.
pub fn parse_window(w: &str) -> Option<(u32, u32)> {
    let (a, b) = w.trim().split_once('-')?;
    let m = |t: &str| -> Option<u32> {
        let (h, mi) = t.trim().split_once(':')?;
        let (h, mi): (u32, u32) = (h.parse().ok()?, mi.parse().ok()?);
        (h < 24 && mi < 60).then_some(h * 60 + mi)
    };
    let (s, e) = (m(a)?, m(b)?);
    (s != e).then_some((s, e))
}

pub fn in_window(w: &str, minute_of_day: u32) -> bool {
    match parse_window(w) {
        Some((s, e)) if s < e => minute_of_day >= s && minute_of_day < e,
        Some((s, e)) => minute_of_day >= s || minute_of_day < e,
        None => false,
    }
}

impl Settings {
    pub fn merged(&self, i: &SettingsIn) -> Result<Settings> {
        let mut s = self.clone();
        macro_rules! set {
            ($f:ident) => {
                if let Some(v) = i.$f.clone() {
                    s.$f = v;
                }
            };
        }
        set!(enabled);
        set!(fetch);
        set!(osv_max_bytes);
        set!(osv_refresh_hours);
        set!(osv_stale_days);
        set!(glsa_stale_days);
        set!(scan_interval_secs);
        set!(tick_secs);
        set!(apply_min_interval_secs);
        set!(apply_max_packages);
        set!(apply_timeout_secs);
        set!(history_days);
        set!(history_max_rows);
        if let Some(v) = &i.osv_url {
            let u = v.trim();
            if !(u.starts_with("https://") || u.starts_with("http://"))
                || u.len() > 500
                || u.bytes().any(|b| b <= b' ')
            {
                return Err(bad(format!("osv_url {u:?}: want an http(s) URL")));
            }
            s.osv_url = u.to_string();
        }
        if let Some(v) = &i.glsa_dir {
            s.glsa_dir = abs_path("glsa_dir", v)?;
        }
        if let Some(v) = &i.pkg_db {
            s.pkg_db = abs_path("pkg_db", v)?;
        }
        if let Some(v) = &i.manifest_path {
            s.manifest_path = abs_path("manifest_path", v)?;
        }
        if let Some(v) = &i.data_dir {
            s.data_dir = abs_path("data_dir", v)?;
        }
        if let Some(v) = &i.binaries {
            s.binaries = v
                .iter()
                .map(|b| abs_path("binaries entry", b))
                .collect::<Result<_>>()?;
        }
        if let Some(v) = &i.portageq {
            s.portageq = program("portageq", v)?;
        }
        if let Some(v) = &i.emerge {
            s.emerge = program("emerge", v)?;
        }
        if let Some(v) = &i.security_updates {
            let v = v.trim().to_lowercase();
            if !POLICIES.contains(&v.as_str()) {
                return Err(bad(format!(
                    "security_updates {v:?}: one of {}",
                    POLICIES.join(", ")
                )));
            }
            s.security_updates = v;
        }
        if let Some(v) = &i.window {
            if parse_window(v).is_none() {
                return Err(bad(format!(
                    "window {v:?}: want HH:MM-HH:MM with two different times"
                )));
            }
            s.window = v.trim().to_string();
        }
        let range = |what: &str, v: u64, lo: u64, hi: u64| -> Result<()> {
            if v < lo || v > hi {
                Err(bad(format!("{what} {v}: between {lo} and {hi}")))
            } else {
                Ok(())
            }
        };
        range("osv_max_bytes", s.osv_max_bytes, 1 << 20, 1 << 30)?;
        range("osv_refresh_hours", s.osv_refresh_hours as u64, 1, 24 * 90)?;
        range("osv_stale_days", s.osv_stale_days as u64, 1, 365)?;
        range("glsa_stale_days", s.glsa_stale_days as u64, 1, 365)?;
        range("scan_interval_secs", s.scan_interval_secs, 60, 7 * 86400)?;
        range("tick_secs", s.tick_secs, 1, 3600)?;
        range(
            "apply_min_interval_secs",
            s.apply_min_interval_secs,
            60,
            30 * 86400,
        )?;
        range("apply_max_packages", s.apply_max_packages as u64, 1, 500)?;
        range("apply_timeout_secs", s.apply_timeout_secs, 60, 6 * 3600)?;
        range("history_days", s.history_days as u64, 1, 3650)?;
        range("history_max_rows", s.history_max_rows as u64, 10, 1_000_000)?;
        Ok(s)
    }

    pub fn pairs(&self) -> Vec<(&'static str, String)> {
        let b = |v: bool| if v { "1" } else { "0" }.to_string();
        vec![
            ("cve.enabled", b(self.enabled)),
            ("cve.fetch", b(self.fetch)),
            ("cve.osv_url", self.osv_url.clone()),
            ("cve.osv_max_bytes", self.osv_max_bytes.to_string()),
            ("cve.osv_refresh_hours", self.osv_refresh_hours.to_string()),
            ("cve.osv_stale_days", self.osv_stale_days.to_string()),
            ("cve.glsa_dir", self.glsa_dir.clone()),
            ("cve.glsa_stale_days", self.glsa_stale_days.to_string()),
            ("cve.pkg_db", self.pkg_db.clone()),
            ("cve.binaries", self.binaries.join(",")),
            ("cve.manifest_path", self.manifest_path.clone()),
            (
                "cve.scan_interval_secs",
                self.scan_interval_secs.to_string(),
            ),
            ("cve.tick_secs", self.tick_secs.to_string()),
            ("cve.data_dir", self.data_dir.clone()),
            ("cve.portageq", self.portageq.clone()),
            ("cve.emerge", self.emerge.clone()),
            ("cve.security_updates", self.security_updates.clone()),
            ("cve.window", self.window.clone()),
            (
                "cve.apply_min_interval_secs",
                self.apply_min_interval_secs.to_string(),
            ),
            (
                "cve.apply_max_packages",
                self.apply_max_packages.to_string(),
            ),
            (
                "cve.apply_timeout_secs",
                self.apply_timeout_secs.to_string(),
            ),
            ("cve.history_days", self.history_days.to_string()),
            ("cve.history_max_rows", self.history_max_rows.to_string()),
        ]
    }
}

pub async fn load(store: &ConfigStore) -> Result<Settings> {
    let rows = sqlx::query("SELECT key, value FROM system_config WHERE key LIKE 'cve.%'")
        .fetch_all(store.pool()?)
        .await
        .map_err(|e| Error::Config(format!("cve settings: {e}")))?;
    let mut raw: BTreeMap<String, String> = BTreeMap::new();
    for r in rows {
        raw.insert(r.get(0), r.get(1));
    }
    let g = |k: &str| raw.get(k).map(|v| v.trim().to_string());
    let mut i = SettingsIn::default();
    macro_rules! parse {
        ($f:ident, $k:literal) => {
            if let Some(v) = g($k) {
                i.$f = v.parse().ok();
            }
        };
    }
    i.enabled = g("cve.enabled").map(|v| flag(&v));
    i.fetch = g("cve.fetch").map(|v| flag(&v));
    i.binaries = g("cve.binaries").map(|v| list(&v));
    i.osv_url = g("cve.osv_url");
    i.glsa_dir = g("cve.glsa_dir");
    i.pkg_db = g("cve.pkg_db");
    i.manifest_path = g("cve.manifest_path");
    i.data_dir = g("cve.data_dir");
    i.portageq = g("cve.portageq");
    i.emerge = g("cve.emerge");
    i.security_updates = g("cve.security_updates");
    i.window = g("cve.window");
    parse!(osv_max_bytes, "cve.osv_max_bytes");
    parse!(osv_refresh_hours, "cve.osv_refresh_hours");
    parse!(osv_stale_days, "cve.osv_stale_days");
    parse!(glsa_stale_days, "cve.glsa_stale_days");
    parse!(scan_interval_secs, "cve.scan_interval_secs");
    parse!(tick_secs, "cve.tick_secs");
    parse!(apply_min_interval_secs, "cve.apply_min_interval_secs");
    parse!(apply_max_packages, "cve.apply_max_packages");
    parse!(apply_timeout_secs, "cve.apply_timeout_secs");
    parse!(history_days, "cve.history_days");
    parse!(history_max_rows, "cve.history_max_rows");
    let d = Settings::default();
    match d.merged(&i) {
        Ok(s) => Ok(s),
        Err(e) => {
            tracing::warn!("CVE exposure settings: {e}; using the defaults");
            Ok(d)
        }
    }
}

pub async fn write(store: &ConfigStore, s: &Settings) -> Result<()> {
    for (k, v) in s.pairs() {
        store.save_system_config(k, &v).await?;
    }
    Ok(())
}

pub async fn save(store: &ConfigStore, i: &SettingsIn) -> Result<Settings> {
    let s = load(store).await?.merged(i)?;
    write(store, &s).await?;
    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows() {
        assert!(in_window("02:00-05:00", 120));
        assert!(!in_window("02:00-05:00", 300));
        assert!(in_window("23:00-02:00", 30));
        assert!(in_window("23:00-02:00", 23 * 60 + 30));
        assert!(!in_window("23:00-02:00", 12 * 60));
        assert!(parse_window("02:00-02:00").is_none());
        assert!(parse_window("25:00-02:00").is_none());
        assert!(parse_window("nonsense").is_none());
    }

    #[test]
    fn validation() {
        let d = Settings::default();
        let bad = |i: SettingsIn| d.merged(&i).unwrap_err().to_string();
        assert!(bad(SettingsIn {
            security_updates: Some("always".into()),
            ..Default::default()
        })
        .contains("Invalid"));
        assert!(bad(SettingsIn {
            window: Some("later".into()),
            ..Default::default()
        })
        .contains("Invalid"));
        assert!(bad(SettingsIn {
            osv_url: Some("ftp://x".into()),
            ..Default::default()
        })
        .contains("Invalid"));
        assert!(bad(SettingsIn {
            glsa_dir: Some("relative/dir".into()),
            ..Default::default()
        })
        .contains("Invalid"));
        assert!(bad(SettingsIn {
            scan_interval_secs: Some(5),
            ..Default::default()
        })
        .contains("Invalid"));
        let ok = d
            .merged(&SettingsIn {
                security_updates: Some("APPLY".into()),
                window: Some("01:30-03:00".into()),
                binaries: Some(vec!["/usr/bin/patronus-web".into()]),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(ok.security_updates, "apply");
        assert_eq!(ok.binaries.len(), 1);
    }
}
