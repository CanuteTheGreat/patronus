//! Where the standard tier gets Patronus updates from: the update channel and
//! the mirror (Portage overlay and an optional binary package host).
//!
//! One typed setting group, read by the update jobs (`crate::sysops` in
//! patronus-network renders it into Portage configuration before every check
//! and apply), the System page's Updates card and `/api/system/updates/channel`.
//!
//! Channels (pfSense/OPNsense call the same choice "branch"/"release type"):
//!
//! * `stable`: tagged releases only (`net-firewall/patronus-X.Y.Z`);
//!   pre-releases (`_rc`, `_beta`, `_alpha`, `_pre`) and the live ebuild are
//!   masked;
//! * `testing`: tagged releases and release candidates; the live ebuild stays
//!   masked;
//! * `development`: the live ebuild (`net-firewall/patronus-9999`), built from
//!   the main branch at every update.
//!
//! Layers, lowest to highest (a higher layer replaces a lower one key by key):
//! built-in defaults < `[update]` of `/etc/patronus/patronus.toml` (`channel`,
//! `overlay_uri`, `binhost_uri`, `repo_location`) < the config store
//! (`system_config` `update.*`, set through the UI/API and carried by
//! export/plan/apply, backups and GitOps). An empty stored value means
//! "not set" (the lower layer applies).

use crate::store::ConfigStore;
use patronus_core::{Error, Result};
use serde::{Deserialize, Serialize};

pub const K_CHANNEL: &str = "update.channel";
pub const K_OVERLAY_URI: &str = "update.overlay_uri";
pub const K_BINHOST_URI: &str = "update.binhost_uri";
pub const K_REPO_LOCATION: &str = "update.repo_location";
pub const KEYS: &[&str] = &[K_CHANNEL, K_OVERLAY_URI, K_BINHOST_URI, K_REPO_LOCATION];

/// The published Patronus overlay (the `gentoo/` directory of the source
/// repository, split out by CI on every change of main).
pub const DEFAULT_OVERLAY_URI: &str = "https://github.com/CanuteTheGreat/patronus-overlay.git";
/// Where Portage keeps the overlay on the device.
pub const DEFAULT_REPO_LOCATION: &str = "/var/db/repos/patronus";
/// Portage repository name of the overlay (its `profiles/repo_name`).
pub const REPO_NAME: &str = "patronus";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Channel {
    #[default]
    Stable,
    Testing,
    Development,
}

impl Channel {
    pub const ALL: [Channel; 3] = [Channel::Stable, Channel::Testing, Channel::Development];

    pub fn as_str(self) -> &'static str {
        match self {
            Channel::Stable => "stable",
            Channel::Testing => "testing",
            Channel::Development => "development",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "stable" | "release" => Some(Channel::Stable),
            "testing" | "rc" => Some(Channel::Testing),
            "development" | "devel" | "dev" | "live" => Some(Channel::Development),
            _ => None,
        }
    }

    /// One line for the UI / install summary.
    pub fn describe(self) -> &'static str {
        match self {
            Channel::Stable => "tagged releases only",
            Channel::Testing => "releases and release candidates",
            Channel::Development => "the main branch, built from source at every update",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdateSettings {
    pub channel: Channel,
    /// Git (`https://`, `ssh://`, `git://`, `file://`) or `rsync://` URI of
    /// the Patronus overlay.
    pub overlay_uri: String,
    /// Optional binary package host for Patronus packages (empty = build
    /// from source).
    pub binhost_uri: String,
    /// Absolute directory of the overlay on the device.
    pub repo_location: String,
}

impl Default for UpdateSettings {
    fn default() -> Self {
        Self {
            channel: Channel::default(),
            overlay_uri: DEFAULT_OVERLAY_URI.into(),
            binhost_uri: String::new(),
            repo_location: DEFAULT_REPO_LOCATION.into(),
        }
    }
}

/// One layer: only the keys it names.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Layer {
    pub channel: Option<Channel>,
    pub overlay_uri: Option<String>,
    pub binhost_uri: Option<String>,
    pub repo_location: Option<String>,
}

fn nonempty(s: &str) -> Option<String> {
    let t = s.trim();
    (!t.is_empty()).then(|| t.to_string())
}

impl Layer {
    /// `[update]` of patronus.toml text (unreadable = no layer).
    pub fn from_toml(text: &str) -> Self {
        #[derive(Deserialize, Default)]
        struct Sec {
            channel: Option<String>,
            overlay_uri: Option<String>,
            binhost_uri: Option<String>,
            repo_location: Option<String>,
        }
        #[derive(Deserialize, Default)]
        struct File {
            #[serde(default)]
            update: Option<Sec>,
        }
        let Ok(f) = toml::from_str::<File>(text) else {
            return Self::default();
        };
        let Some(s) = f.update else {
            return Self::default();
        };
        Self {
            channel: s.channel.as_deref().and_then(Channel::parse),
            overlay_uri: s.overlay_uri.as_deref().and_then(nonempty),
            // an explicit empty binhost in the file means "none": keep it
            binhost_uri: s.binhost_uri.map(|v| v.trim().to_string()),
            repo_location: s.repo_location.as_deref().and_then(nonempty),
        }
    }

    fn from_pairs(p: &[(&'static str, String)]) -> Self {
        let get = |k: &str| {
            p.iter()
                .find(|(n, _)| *n == k)
                .and_then(|(_, v)| nonempty(v))
        };
        Self {
            channel: get(K_CHANNEL).and_then(|v| Channel::parse(&v)),
            overlay_uri: get(K_OVERLAY_URI),
            // "none" stored = explicitly no binhost
            binhost_uri: get(K_BINHOST_URI).map(|v| {
                if v.eq_ignore_ascii_case("none") {
                    String::new()
                } else {
                    v
                }
            }),
            repo_location: get(K_REPO_LOCATION),
        }
    }
}

impl UpdateSettings {
    pub fn overlay(mut self, l: &Layer) -> Self {
        if let Some(v) = l.channel {
            self.channel = v;
        }
        if let Some(v) = &l.overlay_uri {
            self.overlay_uri = v.clone();
        }
        if let Some(v) = &l.binhost_uri {
            self.binhost_uri = v.clone();
        }
        if let Some(v) = &l.repo_location {
            self.repo_location = v.clone();
        }
        self
    }

    /// Portage `sync-type` for the overlay URI.
    pub fn sync_type(&self) -> &'static str {
        if self.overlay_uri.starts_with("rsync://") {
            "rsync"
        } else {
            "git"
        }
    }

    pub fn validate(&self) -> Result<()> {
        let bad = |m: String| Err(Error::Config(format!("Invalid update settings: {m}")));
        let safe = |s: &str| {
            !s.chars()
                .any(|c| c.is_whitespace() || c.is_control() || matches!(c, '"' | '\'' | '\\'))
        };
        let u = &self.overlay_uri;
        if ![
            "https://", "http://", "ssh://", "git://", "file:///", "rsync://",
        ]
        .iter()
        .any(|p| u.starts_with(p))
            || !safe(u)
            || u.len() < 10
        {
            return bad(format!(
                "the overlay mirror '{u}' must be an https://, http://, ssh://, git://, file:/// or rsync:// URL"
            ));
        }
        let b = &self.binhost_uri;
        if !b.is_empty()
            && (!["https://", "http://", "file:///"]
                .iter()
                .any(|p| b.starts_with(p))
                || !safe(b))
        {
            return bad(format!(
                "the binary package host '{b}' must be an https://, http:// or file:/// URL"
            ));
        }
        let r = &self.repo_location;
        if !r.starts_with('/') || r == "/" || !safe(r) || r.contains("..") {
            return bad(format!(
                "the overlay location '{r}' must be an absolute directory"
            ));
        }
        Ok(())
    }
}

fn bootstrap_toml() -> String {
    std::fs::read_to_string(crate::defaults::default_bootstrap_path()).unwrap_or_default()
}

/// The raw stored `update.*` values (empty = unset).
pub async fn stored(store: &ConfigStore) -> Vec<(&'static str, String)> {
    let mut out = Vec::new();
    for k in KEYS {
        out.push((
            *k,
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

/// The effective settings from every layer.
pub async fn resolve(store: Option<&ConfigStore>) -> UpdateSettings {
    let mut s = UpdateSettings::default().overlay(&Layer::from_toml(&bootstrap_toml()));
    if let Some(st) = store {
        s = s.overlay(&Layer::from_pairs(&stored(st).await));
    }
    s
}

/// Fields of `PUT /api/system/updates/channel`: absent = unchanged, empty
/// string = back to the lower layers' value (`binhost_uri: "none"` = no
/// binary host even when patronus.toml names one).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UpdateInput {
    #[serde(default)]
    pub channel: Option<String>,
    #[serde(default)]
    pub overlay_uri: Option<String>,
    #[serde(default)]
    pub binhost_uri: Option<String>,
    #[serde(default)]
    pub repo_location: Option<String>,
    #[serde(default)]
    pub reset: bool,
}

/// Validate `input` against the effective result, store it and return the
/// previous raw values (for an undo).
pub async fn save(store: &ConfigStore, input: &UpdateInput) -> Result<Vec<(&'static str, String)>> {
    let before = stored(store).await;
    let mut want = before.clone();
    if input.reset {
        for e in want.iter_mut() {
            e.1.clear();
        }
    }
    let mut set = |k: &str, v: String| {
        if let Some(e) = want.iter_mut().find(|(n, _)| *n == k) {
            e.1 = v;
        }
    };
    if let Some(c) = &input.channel {
        let t = c.trim();
        if t.is_empty() {
            set(K_CHANNEL, String::new());
        } else {
            match Channel::parse(t) {
                Some(ch) => set(K_CHANNEL, ch.as_str().into()),
                None => {
                    return Err(Error::Config(format!(
                        "Invalid update settings: unknown channel '{t}' (stable, testing or development)"
                    )))
                }
            }
        }
    }
    if let Some(v) = &input.overlay_uri {
        set(K_OVERLAY_URI, v.trim().to_string());
    }
    if let Some(v) = &input.binhost_uri {
        set(K_BINHOST_URI, v.trim().to_string());
    }
    if let Some(v) = &input.repo_location {
        set(K_REPO_LOCATION, v.trim().trim_end_matches('/').to_string());
    }
    UpdateSettings::default()
        .overlay(&Layer::from_toml(&bootstrap_toml()))
        .overlay(&Layer::from_pairs(&want))
        .validate()?;
    for (k, v) in &want {
        store.save_system_config(k, v).await?;
    }
    Ok(before)
}

/// Put back what [`save`] returned.
pub async fn restore(store: &ConfigStore, before: &[(&'static str, String)]) -> Result<()> {
    for (k, v) in before {
        store.save_system_config(k, v).await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_stable_and_the_published_overlay() {
        let s = UpdateSettings::default();
        assert_eq!(s.channel, Channel::Stable);
        assert_eq!(s.overlay_uri, DEFAULT_OVERLAY_URI);
        assert!(s.binhost_uri.is_empty());
        assert_eq!(s.sync_type(), "git");
        s.validate().unwrap();
    }

    #[test]
    fn toml_layer_and_aliases() {
        let l = Layer::from_toml(
            "[web]\nhttps_port = 443\n[update]\nchannel = \"devel\"\noverlay_uri = \"rsync://mirror.example/patronus\"\nbinhost_uri = \"\"\n",
        );
        assert_eq!(l.channel, Some(Channel::Development));
        let s = UpdateSettings::default().overlay(&l);
        assert_eq!(s.sync_type(), "rsync");
        assert_eq!(s.binhost_uri, "");
        assert_eq!(Layer::from_toml("not toml ["), Layer::default());
        assert_eq!(Layer::from_toml("[web]\n"), Layer::default());
    }

    #[test]
    fn validation_refuses_bad_values() {
        let mut s = UpdateSettings {
            overlay_uri: "ftp://x/y".into(),
            ..Default::default()
        };
        assert!(s.validate().is_err());
        s.overlay_uri = "https://example.org/a b".into();
        assert!(s.validate().is_err());
        s.overlay_uri = "file:///srv/patronus-overlay".into();
        s.validate().unwrap();
        s.binhost_uri = "rsync://x".into();
        assert!(s.validate().is_err());
        s.binhost_uri = "https://pkgs.example.org/patronus/amd64".into();
        s.validate().unwrap();
        s.repo_location = "relative".into();
        assert!(s.validate().is_err());
        s.repo_location = "/var/db/../etc".into();
        assert!(s.validate().is_err());
    }

    #[tokio::test]
    async fn store_layer_save_and_restore() {
        let store = ConfigStore::open_in_memory().await.unwrap();
        let before = save(
            &store,
            &UpdateInput {
                channel: Some("testing".into()),
                binhost_uri: Some("https://pkgs.example.org/p".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let s = resolve(Some(&store)).await;
        assert_eq!(s.channel, Channel::Testing);
        assert_eq!(s.binhost_uri, "https://pkgs.example.org/p");
        assert!(save(
            &store,
            &UpdateInput {
                channel: Some("nightly-ish".into()),
                ..Default::default()
            }
        )
        .await
        .is_err());
        assert!(save(
            &store,
            &UpdateInput {
                overlay_uri: Some("nope".into()),
                ..Default::default()
            }
        )
        .await
        .is_err());
        // a refused save changes nothing
        assert_eq!(resolve(Some(&store)).await.channel, Channel::Testing);
        restore(&store, &before).await.unwrap();
        assert_eq!(resolve(Some(&store)).await.channel, Channel::Stable);
    }
}
