//! Typed ports of the services that are not the web UI: the parental-time
//! "time's up" page and the HAProxy statistics page.
//!
//! Same layers as the web listeners ([`crate::webui`]), lowest to highest, a
//! higher layer replacing a lower one key by key:
//!
//! 1. built-in defaults: time's-up page [`DEFAULT_TIMEUP_PORT`] (8081, see
//!    below), HAProxy stats [`DEFAULT_HAPROXY_STATS_PORT`] (8404) bound to
//!    [`DEFAULT_HAPROXY_STATS_BIND`] (loopback);
//! 2. environment (`PATRONUS_TIMEUP_PORT`, `PATRONUS_HAPROXY_STATS_PORT`,
//!    `PATRONUS_HAPROXY_STATS_BIND`);
//! 3. `patronus.toml`: `[time] portal_port`, `[haproxy] stats_port`,
//!    `stats_bind`;
//! 4. the config store (`system_config` `time.portal_port`,
//!    `haproxy.stats_port`, `haproxy.stats_bind`; the old `lan_settings` key
//!    `seg.time_portal_port` is still read when the new key is unset).
//!
//! Why the time's-up page is not on port 80: it is a plain-HTTP landing page
//! its own listener serves, and the web UI already owns :80 (the HTTP -> HTTPS
//! redirect listener, `web.http_redirect_port`). Two listeners cannot share
//! the port, so the default stays 8081; it is a setting, and validation
//! refuses any port the web UI uses.
//!
//! The HAProxy stats page is admin-only (password required, it can disable
//! backends) and listens on loopback unless `haproxy.stats_bind` says
//! otherwise.

use crate::store::ConfigStore;
use crate::webui::WebSettings;
use patronus_core::{Error, Result};
use serde::{Deserialize, Serialize};

pub const K_TIMEUP_PORT: &str = "time.portal_port";
pub const K_HAPROXY_STATS_PORT: &str = "haproxy.stats_port";
pub const K_HAPROXY_STATS_BIND: &str = "haproxy.stats_bind";
pub const KEYS: &[&str] = &[K_TIMEUP_PORT, K_HAPROXY_STATS_PORT, K_HAPROXY_STATS_BIND];
/// The pre-`time.portal_port` location (`lan_settings`).
pub const LEGACY_TIMEUP_KEY: &str = "seg.time_portal_port";

pub const DEFAULT_TIMEUP_PORT: u16 = 8081;
pub const DEFAULT_HAPROXY_STATS_PORT: u16 = 8404;
pub const DEFAULT_HAPROXY_STATS_BIND: &str = "127.0.0.1";

/// Ports other services of the router own; the time's-up page never takes them.
const RESERVED: &[(u16, &str)] = &[
    (22, "SSH"),
    (53, "DNS"),
    (67, "DHCP"),
    (68, "DHCP"),
    (123, "NTP"),
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServicePorts {
    /// Plain-HTTP port of the "time's up" page.
    pub timeup_port: u16,
    pub haproxy_stats_port: u16,
    /// Literal IP the HAProxy stats page binds to.
    pub haproxy_stats_bind: String,
}

impl Default for ServicePorts {
    fn default() -> Self {
        Self {
            timeup_port: DEFAULT_TIMEUP_PORT,
            haproxy_stats_port: DEFAULT_HAPROXY_STATS_PORT,
            haproxy_stats_bind: DEFAULT_HAPROXY_STATS_BIND.to_string(),
        }
    }
}

/// One layer: only the keys it names.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Layer {
    pub timeup_port: Option<u16>,
    pub haproxy_stats_port: Option<u16>,
    pub haproxy_stats_bind: Option<String>,
}

fn port(s: &str) -> Option<u16> {
    s.trim().parse::<u16>().ok().filter(|p| *p != 0)
}

fn nonempty(s: &str) -> Option<String> {
    let t = s.trim();
    (!t.is_empty()).then(|| t.to_string())
}

impl Layer {
    pub fn from_env_with(get: impl Fn(&str) -> Option<String>) -> Self {
        Layer {
            timeup_port: get("PATRONUS_TIMEUP_PORT").and_then(|v| port(&v)),
            haproxy_stats_port: get("PATRONUS_HAPROXY_STATS_PORT").and_then(|v| port(&v)),
            haproxy_stats_bind: get("PATRONUS_HAPROXY_STATS_BIND").and_then(|v| nonempty(&v)),
        }
    }

    pub fn from_env() -> Self {
        Self::from_env_with(|k| std::env::var(k).ok())
    }

    pub fn from_toml(text: &str) -> Self {
        #[derive(Deserialize, Default)]
        struct Time {
            portal_port: Option<u16>,
        }
        #[derive(Deserialize, Default)]
        struct Haproxy {
            stats_port: Option<u16>,
            stats_bind: Option<String>,
        }
        #[derive(Deserialize, Default)]
        struct File {
            #[serde(default)]
            time: Time,
            #[serde(default)]
            haproxy: Haproxy,
        }
        let Ok(f) = toml::from_str::<File>(text) else {
            return Layer::default();
        };
        Layer {
            timeup_port: f.time.portal_port.filter(|p| *p != 0),
            haproxy_stats_port: f.haproxy.stats_port.filter(|p| *p != 0),
            haproxy_stats_bind: f.haproxy.stats_bind.and_then(|v| nonempty(&v)),
        }
    }

    fn from_pairs(p: &[(&'static str, String)]) -> Self {
        let get = |k: &str| {
            p.iter()
                .find(|(n, _)| *n == k)
                .map(|(_, v)| v.trim().to_string())
                .filter(|v| !v.is_empty())
        };
        Layer {
            timeup_port: get(K_TIMEUP_PORT).and_then(|v| port(&v)),
            haproxy_stats_port: get(K_HAPROXY_STATS_PORT).and_then(|v| port(&v)),
            haproxy_stats_bind: get(K_HAPROXY_STATS_BIND),
        }
    }

    pub async fn from_store(store: &ConfigStore) -> Self {
        let mut l = Self::from_pairs(&stored(store).await);
        if l.timeup_port.is_none() {
            l.timeup_port = legacy_timeup(store).await;
        }
        l
    }
}

async fn legacy_timeup(store: &ConfigStore) -> Option<u16> {
    let pool = store.pool().ok()?;
    let v: Option<String> = sqlx::query_scalar("SELECT value FROM lan_settings WHERE key = ?")
        .bind(LEGACY_TIMEUP_KEY)
        .fetch_optional(pool)
        .await
        .ok()
        .flatten();
    v.and_then(|v| port(&v))
}

impl ServicePorts {
    pub fn overlay(mut self, l: &Layer) -> Self {
        if let Some(v) = l.timeup_port {
            self.timeup_port = v;
        }
        if let Some(v) = l.haproxy_stats_port {
            self.haproxy_stats_port = v;
        }
        if let Some(v) = &l.haproxy_stats_bind {
            self.haproxy_stats_bind = v.clone();
        }
        self
    }

    /// Reject a combination that cannot work. `web` = the web UI's own ports.
    pub fn validate(&self, web: &WebSettings) -> Result<()> {
        let bad = |m: String| Err(Error::Config(format!("Invalid service port settings: {m}")));
        if self.timeup_port == 0 {
            return bad("the time's-up page port must be 1-65535".into());
        }
        if web.all_ports().contains(&self.timeup_port) {
            return bad(format!(
                "the time's-up page port {} is a web UI port (the web UI answers there)",
                self.timeup_port
            ));
        }
        if let Some((_, what)) = RESERVED.iter().find(|(p, _)| *p == self.timeup_port) {
            return bad(format!(
                "the time's-up page port {} belongs to {what}",
                self.timeup_port
            ));
        }
        if self.haproxy_stats_port == 0 {
            return bad("the HAProxy stats port must be 1-65535".into());
        }
        if web.all_ports().contains(&self.haproxy_stats_port) {
            return bad(format!(
                "the HAProxy stats port {} is a web UI port",
                self.haproxy_stats_port
            ));
        }
        if self.haproxy_stats_bind.parse::<std::net::IpAddr>().is_err() {
            return bad(format!(
                "HAProxy stats bind address '{}' is not an IP address",
                self.haproxy_stats_bind
            ));
        }
        Ok(())
    }
}

/// Effective settings from every layer. Validation is not applied here (a bad
/// value that slipped in through a file must not stop the router); callers
/// that bind or open ports use [`ServicePorts::validate`] or the `*_checked`
/// helpers.
pub async fn resolve(store: Option<&ConfigStore>) -> ServicePorts {
    let path = crate::defaults::default_bootstrap_path();
    let toml = std::fs::read_to_string(&path).unwrap_or_default();
    let mut s = ServicePorts::default()
        .overlay(&Layer::from_env())
        .overlay(&Layer::from_toml(&toml));
    if let Some(st) = store {
        s = s.overlay(&Layer::from_store(st).await);
    }
    s
}

/// The time's-up page port to use now: the effective value, or the default
/// when the effective one is invalid (it would collide with the web UI).
pub async fn timeup_port(store: &ConfigStore) -> u16 {
    let s = resolve(Some(store)).await;
    let web = crate::webui::resolve(Some(store)).await;
    let probe = ServicePorts {
        timeup_port: s.timeup_port,
        ..ServicePorts::default()
    };
    if probe.validate(&web).is_ok() {
        s.timeup_port
    } else {
        DEFAULT_TIMEUP_PORT
    }
}

/// The raw `time.portal_port` / `haproxy.*` values in the store (empty = unset).
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

/// Fields of `PUT /api/system/ports`: absent = unchanged, 0 / empty = back to
/// the lower layers.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PortsInput {
    #[serde(default)]
    pub timeup_port: Option<u16>,
    #[serde(default)]
    pub haproxy_stats_port: Option<u16>,
    #[serde(default)]
    pub haproxy_stats_bind: Option<String>,
    /// `true` = forget every stored value.
    #[serde(default)]
    pub reset: bool,
}

/// Validate `input` on top of the other layers and store it; returns the
/// previous raw values for an undo.
pub async fn save(store: &ConfigStore, input: &PortsInput) -> Result<Vec<(&'static str, String)>> {
    let before = stored(store).await;
    let mut want = before.clone();
    let set = |want: &mut Vec<(&'static str, String)>, k: &str, v: String| {
        if let Some(e) = want.iter_mut().find(|(n, _)| *n == k) {
            e.1 = v;
        }
    };
    if input.reset {
        for e in want.iter_mut() {
            e.1.clear();
        }
    }
    let p = |n: u16| if n == 0 { String::new() } else { n.to_string() };
    if let Some(n) = input.timeup_port {
        set(&mut want, K_TIMEUP_PORT, p(n));
    }
    if let Some(n) = input.haproxy_stats_port {
        set(&mut want, K_HAPROXY_STATS_PORT, p(n));
    }
    if let Some(v) = &input.haproxy_stats_bind {
        set(&mut want, K_HAPROXY_STATS_BIND, v.trim().to_string());
    }
    let path = crate::defaults::default_bootstrap_path();
    let toml = std::fs::read_to_string(&path).unwrap_or_default();
    // A stored value that does not parse would be silently ignored by the
    // layer: refuse it instead of storing it.
    for (k, v) in &want {
        let v = v.trim();
        if v.is_empty() {
            continue;
        }
        let ok = if *k == K_HAPROXY_STATS_BIND {
            v.parse::<std::net::IpAddr>().is_ok()
        } else {
            port(v).is_some()
        };
        if !ok {
            return Err(Error::Config(format!(
                "Invalid service port settings: '{v}' is not valid for {k}"
            )));
        }
    }
    let eff = ServicePorts::default()
        .overlay(&Layer::from_env())
        .overlay(&Layer::from_toml(&toml))
        .overlay(&Layer::from_pairs(&want));
    let web = crate::webui::resolve(Some(store)).await;
    eff.validate(&web)?;
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
#[allow(clippy::field_reassign_with_default)]
mod tests {
    use super::*;

    fn env(pairs: &'static [(&'static str, &'static str)]) -> Layer {
        Layer::from_env_with(|k| {
            pairs
                .iter()
                .find(|(n, _)| *n == k)
                .map(|(_, v)| v.to_string())
        })
    }

    #[test]
    fn defaults_are_documented_values_and_valid() {
        let d = ServicePorts::default();
        assert_eq!(d.timeup_port, 8081);
        assert_eq!(d.haproxy_stats_port, 8404);
        assert_eq!(d.haproxy_stats_bind, "127.0.0.1");
        d.validate(&WebSettings::default()).unwrap();
    }

    #[test]
    fn layers_override_key_by_key() {
        let s = ServicePorts::default()
            .overlay(&env(&[("PATRONUS_TIMEUP_PORT", "8090")]))
            .overlay(&Layer::from_toml(
                "[haproxy]\nstats_port = 9000\nstats_bind = \"10.0.0.2\"\n",
            ));
        assert_eq!(s.timeup_port, 8090);
        assert_eq!(s.haproxy_stats_port, 9000);
        assert_eq!(s.haproxy_stats_bind, "10.0.0.2");
        let s = s.overlay(&Layer::from_toml("[time]\nportal_port = 8095\n"));
        assert_eq!(s.timeup_port, 8095);
    }

    #[test]
    fn invalid_ports_are_rejected() {
        let web = WebSettings::default();
        let mut s = ServicePorts::default();
        s.timeup_port = 0;
        assert!(s.validate(&web).is_err());
        for p in [80, 443, 22, 53] {
            s.timeup_port = p;
            assert!(s.validate(&web).is_err(), "port {p}");
        }
        s.timeup_port = 8081;
        s.haproxy_stats_port = 0;
        assert!(s.validate(&web).is_err());
        s.haproxy_stats_port = 443;
        assert!(s.validate(&web).is_err());
        s.haproxy_stats_port = 8404;
        s.haproxy_stats_bind = "not-an-ip".into();
        assert!(s.validate(&web).is_err());
        // a web UI moved to 8081 takes the port away from the time page
        let mut web = WebSettings::default();
        web.extra_https_ports = vec![8081];
        assert!(ServicePorts::default().validate(&web).is_err());
    }

    #[tokio::test]
    async fn store_layer_wins_save_validates_and_restores() {
        let s = ConfigStore::open_in_memory().await.unwrap();
        assert_eq!(timeup_port(&s).await, 8081);
        let before = save(
            &s,
            &PortsInput {
                timeup_port: Some(8090),
                haproxy_stats_port: Some(9404),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let eff = resolve(Some(&s)).await;
        assert_eq!(eff.timeup_port, 8090);
        assert_eq!(eff.haproxy_stats_port, 9404);
        assert_eq!(timeup_port(&s).await, 8090);
        // refused values store nothing
        for bad in [80u16, 443, 22] {
            assert!(save(
                &s,
                &PortsInput {
                    timeup_port: Some(bad),
                    ..Default::default()
                }
            )
            .await
            .is_err());
        }
        assert!(save(
            &s,
            &PortsInput {
                haproxy_stats_bind: Some("nope".into()),
                ..Default::default()
            }
        )
        .await
        .is_err());
        assert_eq!(resolve(Some(&s)).await.timeup_port, 8090);
        restore(&s, &before).await.unwrap();
        assert_eq!(resolve(Some(&s)).await, ServicePorts::default());
        // reset forgets stored values
        save(
            &s,
            &PortsInput {
                timeup_port: Some(8091),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        save(
            &s,
            &PortsInput {
                reset: true,
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(timeup_port(&s).await, 8081);
    }
}
