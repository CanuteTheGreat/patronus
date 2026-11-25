//! System log viewer settings (`/logs`, `/api/logs/system`).
//!
//! One typed group of `system_config` keys `logview.*`, so it travels with
//! export / plan / apply, backups and GitOps. Layers, lowest first: built-in
//! defaults, the environment (`PATRONUS_SYSLOG` = the log file path, the name
//! earlier releases used), the store. An absent or empty key = not set.
//!
//! The viewer reads journald or syslog files; which one is chosen at run time
//! (`backend`). Nothing here is a build-time switch.

use crate::store::ConfigStore;
use patronus_core::{Error, Result};
use serde::{Deserialize, Serialize};

pub const K_BACKEND: &str = "logview.backend";
pub const K_FILE_PATH: &str = "logview.file_path";
pub const K_MANAGED_FILE: &str = "logview.managed_file";
pub const K_MANAGE_LOGGER: &str = "logview.manage_logger";
pub const K_ROTATED: &str = "logview.rotated_files";
pub const K_DEFAULT_LIMIT: &str = "logview.default_limit";
pub const K_MAX_LIMIT: &str = "logview.max_limit";
pub const K_MAX_SCAN: &str = "logview.max_scan_bytes";
pub const K_POLL_MS: &str = "logview.live_poll_ms";
pub const K_JOURNALCTL: &str = "logview.journalctl";
pub const K_BOOT_MARKERS: &str = "logview.boot_markers";
pub const K_UNIT_MAP: &str = "logview.unit_map";
pub const K_PREVIEW: &str = "logview.preview_lines";
pub const K_STREAM_SECS: &str = "logview.stream_max_secs";
pub const K_DOWNLOAD_MAX: &str = "logview.download_max_lines";

pub const KEYS: &[&str] = &[
    K_BACKEND,
    K_FILE_PATH,
    K_MANAGED_FILE,
    K_MANAGE_LOGGER,
    K_ROTATED,
    K_DEFAULT_LIMIT,
    K_MAX_LIMIT,
    K_MAX_SCAN,
    K_POLL_MS,
    K_JOURNALCTL,
    K_BOOT_MARKERS,
    K_UNIT_MAP,
    K_PREVIEW,
    K_STREAM_SECS,
    K_DOWNLOAD_MAX,
];

/// Hard ceiling of lines per page (the router tier's memory budget).
pub const HARD_MAX_LIMIT: u32 = 2000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogViewSettings {
    /// `auto` (journald when it is running, else files), `journald` or `files`.
    pub backend: String,
    /// Syslog file the files back end reads (rotated `.0`/`.1`... are read too).
    pub file_path: String,
    /// File the standard tier's logger is configured to write WITH the
    /// priority in every line; preferred over `file_path` when it has data.
    pub managed_file: String,
    /// Let the syslog applier configure rsyslog / syslog-ng / sysklogd to write
    /// `managed_file` with facility.priority in every line.
    pub manage_logger: bool,
    /// How many rotated files (`<file>.0` .. `.N-1`, `.1` .. `.N`) to read.
    pub rotated_files: u32,
    pub default_limit: u32,
    pub max_limit: u32,
    /// Bytes one request may read from files (bounds memory and time).
    pub max_scan_bytes: u64,
    /// Live mode: how often the files back end looks for new lines.
    pub live_poll_ms: u64,
    pub journalctl: String,
    /// `|`-separated substrings that mark a boot in a file ("Linux version ...").
    pub boot_markers: String,
    /// Files back end: `identifier=service` pairs (comma separated) so the
    /// unit filter finds a service whose log identifier has another name.
    pub unit_map: String,
    /// Lines of the Monitoring page preview.
    pub preview_lines: u32,
    /// A live stream ends after this long; the browser resumes from its cursor.
    pub stream_max_secs: u64,
    pub download_max_lines: u32,
}

impl Default for LogViewSettings {
    fn default() -> Self {
        Self {
            backend: "auto".into(),
            file_path: "/var/log/messages".into(),
            managed_file: "/var/log/patronus/system.log".into(),
            manage_logger: true,
            rotated_files: 3,
            default_limit: 500,
            max_limit: HARD_MAX_LIMIT,
            max_scan_bytes: 8 * 1024 * 1024,
            live_poll_ms: 500,
            journalctl: "journalctl".into(),
            boot_markers: "Linux version |patronus-boot:".into(),
            unit_map: String::new(),
            preview_lines: 20,
            stream_max_secs: 3600,
            download_max_lines: 10000,
        }
    }
}

impl LogViewSettings {
    /// `self` with every non-empty pair applied (unknown keys ignored, an
    /// unparsable value keeps the old one: `validate` reports it on save).
    pub fn overlay(mut self, pairs: &[(String, String)]) -> Self {
        for (k, v) in pairs {
            let v = v.trim();
            if v.is_empty() {
                continue;
            }
            match k.as_str() {
                K_BACKEND => self.backend = v.to_ascii_lowercase(),
                K_FILE_PATH => self.file_path = v.into(),
                K_MANAGED_FILE => self.managed_file = v.into(),
                K_MANAGE_LOGGER => {
                    self.manage_logger =
                        matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on")
                }
                K_ROTATED => self.rotated_files = v.parse().unwrap_or(self.rotated_files),
                K_DEFAULT_LIMIT => self.default_limit = v.parse().unwrap_or(self.default_limit),
                K_MAX_LIMIT => self.max_limit = v.parse().unwrap_or(self.max_limit),
                K_MAX_SCAN => self.max_scan_bytes = v.parse().unwrap_or(self.max_scan_bytes),
                K_POLL_MS => self.live_poll_ms = v.parse().unwrap_or(self.live_poll_ms),
                K_JOURNALCTL => self.journalctl = v.into(),
                K_BOOT_MARKERS => self.boot_markers = v.into(),
                K_UNIT_MAP => self.unit_map = v.into(),
                K_PREVIEW => self.preview_lines = v.parse().unwrap_or(self.preview_lines),
                K_STREAM_SECS => self.stream_max_secs = v.parse().unwrap_or(self.stream_max_secs),
                K_DOWNLOAD_MAX => {
                    self.download_max_lines = v.parse().unwrap_or(self.download_max_lines)
                }
                _ => {}
            }
        }
        self
    }

    /// Environment layer (`get` = a variable lookup, for tests).
    pub fn from_env_with(get: impl Fn(&str) -> Option<String>) -> Vec<(String, String)> {
        let mut v = Vec::new();
        if let Some(p) = get("PATRONUS_SYSLOG") {
            v.push((K_FILE_PATH.to_string(), p));
        }
        for k in KEYS {
            let name = format!("PATRONUS_{}", k.replace('.', "_").to_ascii_uppercase());
            if let Some(x) = get(&name) {
                v.push((k.to_string(), x));
            }
        }
        v
    }

    pub fn validate(&self) -> Result<()> {
        let bad = |m: String| Err(Error::Config(format!("Invalid system log settings: {m}")));
        if !["auto", "journald", "files"].contains(&self.backend.as_str()) {
            return bad("backend is auto, journald or files".into());
        }
        for (what, p) in [
            ("file path", &self.file_path),
            ("managed file", &self.managed_file),
        ] {
            if !p.starts_with('/') {
                return bad(format!("the {what} must be an absolute path"));
            }
        }
        if self.rotated_files > 20 {
            return bad("rotated files: 0-20".into());
        }
        if self.max_limit == 0 || self.max_limit > HARD_MAX_LIMIT {
            return bad(format!("maximum lines per page: 1-{HARD_MAX_LIMIT}"));
        }
        if self.default_limit == 0 || self.default_limit > self.max_limit {
            return bad("default lines per page: 1 up to the maximum".into());
        }
        if !(65_536..=268_435_456).contains(&self.max_scan_bytes) {
            return bad("scan budget: 65536 bytes - 256 MiB".into());
        }
        if !(100..=10_000).contains(&self.live_poll_ms) {
            return bad("live poll interval: 100-10000 ms".into());
        }
        if self.journalctl.trim().is_empty() {
            return bad("journalctl command is empty".into());
        }
        if self.boot_markers.split('|').all(|m| m.is_empty()) {
            return bad("at least one boot marker".into());
        }
        for pair in self
            .unit_map
            .split(',')
            .map(str::trim)
            .filter(|p| !p.is_empty())
        {
            if !pair.contains('=') {
                return bad(format!("unit map entry '{pair}' is not identifier=service"));
            }
        }
        if self.preview_lines > 200 {
            return bad("preview lines: 0-200".into());
        }
        if !(10..=86_400).contains(&self.stream_max_secs) {
            return bad("live stream lifetime: 10-86400 s".into());
        }
        if self.download_max_lines == 0 || self.download_max_lines > 200_000 {
            return bad("download lines: 1-200000".into());
        }
        Ok(())
    }

    /// `identifier -> service` pairs of `unit_map`.
    pub fn unit_pairs(&self) -> Vec<(String, String)> {
        self.unit_map
            .split(',')
            .filter_map(|p| p.split_once('='))
            .map(|(a, b)| (a.trim().to_string(), b.trim().to_string()))
            .filter(|(a, b)| !a.is_empty() && !b.is_empty())
            .collect()
    }

    pub fn markers(&self) -> Vec<String> {
        self.boot_markers
            .split('|')
            .filter(|m| !m.is_empty())
            .map(String::from)
            .collect()
    }
}

/// Raw `logview.*` values of the store (empty = unset), for the settings form.
pub async fn stored(store: &ConfigStore) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for k in KEYS {
        out.push((
            k.to_string(),
            store
                .load_system_config(k)
                .await
                .ok()
                .flatten()
                .unwrap_or_default(),
        ));
    }
    out
}

/// The effective settings: defaults < environment < store.
pub async fn resolve(store: Option<&ConfigStore>) -> LogViewSettings {
    let mut s = LogViewSettings::default()
        .overlay(&LogViewSettings::from_env_with(|k| std::env::var(k).ok()));
    if let Some(st) = store {
        s = s.overlay(&stored(st).await);
    }
    s
}

/// Store `changes` (key -> value, empty = back to the lower layers) after
/// validating the result. `reset` forgets every stored key first.
pub async fn save(store: &ConfigStore, changes: &[(String, String)], reset: bool) -> Result<()> {
    let mut want = if reset {
        KEYS.iter()
            .map(|k| (k.to_string(), String::new()))
            .collect()
    } else {
        stored(store).await
    };
    for (k, v) in changes {
        if !KEYS.contains(&k.as_str()) {
            return Err(Error::Config(format!(
                "Invalid system log settings: unknown key {k}"
            )));
        }
        if let Some(e) = want.iter_mut().find(|(n, _)| n == k) {
            e.1 = v.trim().to_string();
        }
    }
    let eff = LogViewSettings::default()
        .overlay(&LogViewSettings::from_env_with(|k| std::env::var(k).ok()))
        .overlay(&want);
    eff.validate()?;
    for (k, v) in &want {
        let cur = store
            .load_system_config(k)
            .await
            .ok()
            .flatten()
            .unwrap_or_default();
        if &cur != v {
            store.save_system_config(k, v).await?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_valid_and_standard() {
        let d = LogViewSettings::default();
        d.validate().unwrap();
        assert_eq!(d.file_path, "/var/log/messages");
        assert_eq!(d.max_limit, 2000);
    }

    #[test]
    fn layers_override_key_by_key_and_empty_is_unset() {
        let env = LogViewSettings::from_env_with(|k| {
            (k == "PATRONUS_SYSLOG").then(|| "/tmp/x".to_string())
        });
        let s = LogViewSettings::default().overlay(&env).overlay(&[
            (K_DEFAULT_LIMIT.into(), "100".into()),
            (K_FILE_PATH.into(), "".into()),
        ]);
        assert_eq!(s.file_path, "/tmp/x");
        assert_eq!(s.default_limit, 100);
    }

    #[test]
    fn bad_values_are_refused() {
        let with = |f: fn(&mut LogViewSettings)| {
            let mut s = LogViewSettings::default();
            f(&mut s);
            s.validate().is_err()
        };
        assert!(with(|s| s.max_limit = 5000));
        assert!(with(|s| s.backend = "syslog".into()));
        assert!(with(|s| s.unit_map = "dhcpd".into()));
        assert!(with(|s| s.file_path = "messages".into()));
    }

    #[test]
    fn unit_map_and_markers_parse() {
        let s = LogViewSettings {
            unit_map: "dhcpd = dhcpd4, ntpd=chronyd".into(),
            ..Default::default()
        };
        assert_eq!(s.unit_pairs()[0], ("dhcpd".into(), "dhcpd4".into()));
        assert_eq!(s.unit_pairs().len(), 2);
        assert_eq!(s.markers(), vec!["Linux version ", "patronus-boot:"]);
    }
}
