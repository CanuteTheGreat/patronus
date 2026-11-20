//! Where the web UI listens: addresses, HTTPS port, the HTTP -> HTTPS
//! redirect port, extra HTTPS ports and the TLS certificate.
//!
//! One typed setting group, read by `patronus-web` (to bind), by the firewall
//! applier (the anti-lockout rule opens exactly these ports) and by the
//! System page / `/api/system/web`.
//!
//! Layers, lowest to highest (a higher layer replaces a lower one key by key):
//!
//! 1. built-in defaults: the standard ports on every tier, HTTPS on 443 and plain
//!    HTTP on 80 that only redirects to HTTPS. No other listener: 8443 (what
//!    earlier releases used) is an explicit opt-in through `extra_https_ports`;
//! 2. environment (`PATRONUS_HTTPS_PORT`, `PATRONUS_HTTP_REDIRECT_PORT`,
//!    `PATRONUS_WEB_EXTRA_HTTPS_PORTS`, `PATRONUS_WEB_LISTEN`,
//!    `PATRONUS_TLS_CERT`, `PATRONUS_TLS_KEY`): deployment defaults of an image
//!    or container (the embedded tier's `embedded.env`);
//! 3. `[web]` of `/etc/patronus/patronus.toml` (`listen_addr` or `listen`,
//!    `https_port`, `http_redirect_port`, `extra_https_ports`, `tls_cert`,
//!    `tls_key`). The old `listen_port` / `use_tls` keys were never honoured and
//!    still are not: the port is `https_port`, TLS is always on;
//! 4. the config store (`system_config` `web.*`, set through the UI/API and
//!    carried by export/plan/apply, backups and GitOps).
//!
//! Port values: `0` for the redirect port means "no plain-HTTP listener";
//! `none` for the extra ports means "no extra listener".

use crate::store::ConfigStore;
use patronus_core::{Error, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;

pub const K_LISTEN: &str = "web.listen";
pub const K_HTTPS_PORT: &str = "web.https_port";
pub const K_REDIRECT_PORT: &str = "web.http_redirect_port";
pub const K_EXTRA_PORTS: &str = "web.extra_https_ports";
pub const K_TLS_CERT: &str = "web.tls_cert";
pub const K_TLS_KEY: &str = "web.tls_key";
pub const KEYS: &[&str] = &[
    K_LISTEN,
    K_HTTPS_PORT,
    K_REDIRECT_PORT,
    K_EXTRA_PORTS,
    K_TLS_CERT,
    K_TLS_KEY,
];

/// Built-in defaults (layer 1).
pub const DEFAULT_HTTPS_PORT: u16 = 443;
pub const DEFAULT_REDIRECT_PORT: u16 = 80;
pub const DEFAULT_EXTRA_PORTS: &[u16] = &[];
/// Listen on every IPv4 address unless told otherwise.
pub const DEFAULT_LISTEN: &str = "0.0.0.0";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WebSettings {
    /// Literal IP addresses to bind (empty never happens in the effective
    /// view: it is `["0.0.0.0"]`).
    pub listen: Vec<String>,
    pub https_port: u16,
    /// 0 = no plain-HTTP listener.
    pub http_redirect_port: u16,
    pub extra_https_ports: Vec<u16>,
    /// PEM certificate chain / key paths; both empty = the generated
    /// self-signed certificate under the TLS directory.
    pub tls_cert: String,
    pub tls_key: String,
}

impl Default for WebSettings {
    fn default() -> Self {
        Self {
            listen: vec![DEFAULT_LISTEN.to_string()],
            https_port: DEFAULT_HTTPS_PORT,
            http_redirect_port: DEFAULT_REDIRECT_PORT,
            extra_https_ports: DEFAULT_EXTRA_PORTS.to_vec(),
            tls_cert: String::new(),
            tls_key: String::new(),
        }
    }
}

/// One layer: only the keys it names.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Layer {
    pub listen: Option<Vec<String>>,
    pub https_port: Option<u16>,
    pub http_redirect_port: Option<u16>,
    pub extra_https_ports: Option<Vec<u16>>,
    pub tls_cert: Option<String>,
    pub tls_key: Option<String>,
}

fn split(s: &str) -> Vec<String> {
    s.split([',', ' ', '\n'])
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .map(String::from)
        .collect()
}

fn port(s: &str) -> Option<u16> {
    s.trim().parse::<u16>().ok()
}

fn ports(s: &str) -> Option<Vec<u16>> {
    let t = s.trim();
    if t.eq_ignore_ascii_case("none") {
        return Some(Vec::new());
    }
    let v: Vec<u16> = split(t)
        .iter()
        .filter_map(|p| p.parse::<u16>().ok())
        .filter(|p| *p != 0)
        .collect();
    (!v.is_empty()).then_some(v)
}

fn nonempty(s: &str) -> Option<String> {
    let t = s.trim();
    (!t.is_empty()).then(|| t.to_string())
}

impl Layer {
    /// Layer 2: the environment (`get` = a variable lookup, for tests).
    pub fn from_env_with(get: impl Fn(&str) -> Option<String>) -> Self {
        Layer {
            listen: get("PATRONUS_WEB_LISTEN")
                .map(|v| split(&v))
                .filter(|v| !v.is_empty()),
            https_port: get("PATRONUS_HTTPS_PORT")
                .and_then(|v| port(&v))
                .filter(|p| *p != 0),
            http_redirect_port: get("PATRONUS_HTTP_REDIRECT_PORT").and_then(|v| port(&v)),
            extra_https_ports: get("PATRONUS_WEB_EXTRA_HTTPS_PORTS").and_then(|v| ports(&v)),
            tls_cert: get("PATRONUS_TLS_CERT").and_then(|v| nonempty(&v)),
            tls_key: get("PATRONUS_TLS_KEY").and_then(|v| nonempty(&v)),
        }
    }

    pub fn from_env() -> Self {
        Self::from_env_with(|k| std::env::var(k).ok())
    }

    /// Layer 3: `[web]` of patronus.toml text (an unreadable file = no layer).
    pub fn from_toml(text: &str) -> Self {
        #[derive(Deserialize, Default)]
        struct File {
            #[serde(default)]
            web: Web,
        }
        #[derive(Deserialize, Default)]
        struct Web {
            listen: Option<toml::Value>,
            listen_addr: Option<toml::Value>,
            https_port: Option<u16>,
            http_redirect_port: Option<u16>,
            extra_https_ports: Option<toml::Value>,
            tls_cert: Option<String>,
            tls_key: Option<String>,
        }
        fn list(v: &toml::Value) -> Vec<String> {
            match v {
                toml::Value::String(s) => split(s),
                toml::Value::Array(a) => a
                    .iter()
                    .filter_map(|x| x.as_str().map(|s| s.trim().to_string()))
                    .filter(|s| !s.is_empty())
                    .collect(),
                _ => Vec::new(),
            }
        }
        let Ok(f) = toml::from_str::<File>(text) else {
            return Layer::default();
        };
        let w = f.web;
        Layer {
            listen: w
                .listen
                .or(w.listen_addr)
                .map(|v| list(&v))
                .filter(|v| !v.is_empty()),
            https_port: w.https_port.filter(|p| *p != 0),
            http_redirect_port: w.http_redirect_port,
            extra_https_ports: w.extra_https_ports.and_then(|v| match &v {
                toml::Value::Array(a) if a.is_empty() => Some(Vec::new()),
                toml::Value::Array(a) => {
                    let p: Vec<u16> = a
                        .iter()
                        .filter_map(|x| x.as_integer())
                        .filter_map(|n| u16::try_from(n).ok())
                        .filter(|p| *p != 0)
                        .collect();
                    (!p.is_empty()).then_some(p)
                }
                toml::Value::String(s) => ports(s),
                _ => None,
            }),
            tls_cert: w.tls_cert.and_then(|v| nonempty(&v)),
            tls_key: w.tls_key.and_then(|v| nonempty(&v)),
        }
    }

    /// Layer 4: the `web.*` keys of the store (an absent or empty key = not set).
    pub async fn from_store(store: &ConfigStore) -> Self {
        async fn get(store: &ConfigStore, k: &str) -> Option<String> {
            store
                .load_system_config(k)
                .await
                .ok()
                .flatten()
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
        }
        let mut v = Vec::new();
        for k in KEYS {
            v.push((*k, get(store, k).await.unwrap_or_default()));
        }
        layer_from_pairs(&v)
    }
}

impl WebSettings {
    /// `self` with every key `l` names replaced.
    pub fn overlay(mut self, l: &Layer) -> Self {
        if let Some(v) = &l.listen {
            self.listen = v.clone();
        }
        if let Some(v) = l.https_port {
            self.https_port = v;
        }
        if let Some(v) = l.http_redirect_port {
            self.http_redirect_port = v;
        }
        if let Some(v) = &l.extra_https_ports {
            self.extra_https_ports = v.clone();
        }
        if let Some(v) = &l.tls_cert {
            self.tls_cert = v.clone();
        }
        if let Some(v) = &l.tls_key {
            self.tls_key = v.clone();
        }
        self
    }

    /// Every TCP port the UI listens on, primary first: what the anti-lockout
    /// rule must accept. The redirect port is included when it is on.
    pub fn all_ports(&self) -> Vec<u16> {
        let mut v = vec![self.https_port];
        if self.http_redirect_port != 0 {
            v.push(self.http_redirect_port);
        }
        v.extend(self.extra_https_ports.iter().copied());
        let mut seen = Vec::new();
        v.retain(|p| {
            if seen.contains(p) {
                false
            } else {
                seen.push(*p);
                true
            }
        });
        v
    }

    /// Reject a combination that cannot work (never stored).
    pub fn validate(&self) -> Result<()> {
        let bad = |m: String| Err(Error::Config(format!("Invalid web UI settings: {m}")));
        if self.https_port == 0 {
            return bad("the HTTPS port must be 1-65535".into());
        }
        if self.http_redirect_port == self.https_port {
            return bad("the HTTP redirect port must differ from the HTTPS port".into());
        }
        if self.extra_https_ports.contains(&0) {
            return bad("extra HTTPS ports must be 1-65535".into());
        }
        if self.extra_https_ports.contains(&self.https_port)
            || self.extra_https_ports.contains(&self.http_redirect_port)
        {
            return bad("extra HTTPS ports must differ from the main and redirect ports".into());
        }
        let mut e = self.extra_https_ports.clone();
        e.sort_unstable();
        e.dedup();
        if e.len() != self.extra_https_ports.len() {
            return bad("extra HTTPS ports repeat".into());
        }
        if self.listen.is_empty() {
            return bad("no listen address".into());
        }
        for a in &self.listen {
            if a.parse::<std::net::IpAddr>().is_err() {
                return bad(format!("listen address '{a}' is not an IP address"));
            }
        }
        if self.tls_cert.is_empty() != self.tls_key.is_empty() {
            return bad("set both the certificate and the key, or neither".into());
        }
        for (what, p) in [("certificate", &self.tls_cert), ("key", &self.tls_key)] {
            if !p.is_empty() && !Path::new(p).is_absolute() {
                return bad(format!("the TLS {what} path must be absolute"));
            }
        }
        Ok(())
    }
}

/// The effective settings from every layer; `toml_path` None = the bootstrap
/// file's default location.
pub async fn resolve(store: Option<&ConfigStore>) -> WebSettings {
    let path = crate::defaults::default_bootstrap_path();
    let toml = std::fs::read_to_string(&path).unwrap_or_default();
    let mut s = WebSettings::default()
        .overlay(&Layer::from_env())
        .overlay(&Layer::from_toml(&toml));
    if let Some(st) = store {
        s = s.overlay(&Layer::from_store(st).await);
    }
    s
}

/// Settings stored for the UI form: the raw `web.*` values (empty = unset).
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

/// Fields of `PUT /api/system/web`: absent = unchanged, empty string = back
/// to the lower layers' value.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WebInput {
    #[serde(default)]
    pub listen: Option<String>,
    #[serde(default)]
    pub https_port: Option<u16>,
    #[serde(default)]
    pub http_redirect_port: Option<u16>,
    #[serde(default)]
    pub extra_https_ports: Option<String>,
    #[serde(default)]
    pub tls_cert: Option<String>,
    #[serde(default)]
    pub tls_key: Option<String>,
    /// `true` = forget every stored `web.*` value.
    #[serde(default)]
    pub reset: bool,
}

/// Apply `input` to the store (validated against the effective result first)
/// and return the previous raw values, for an undo.
pub async fn save(store: &ConfigStore, input: &WebInput) -> Result<Vec<(&'static str, String)>> {
    let before = stored(store).await;
    let mut want: Vec<(&'static str, String)> = before.clone();
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
    if let Some(v) = &input.listen {
        set(&mut want, K_LISTEN, split(v).join(","));
    }
    if let Some(p) = input.https_port {
        set(
            &mut want,
            K_HTTPS_PORT,
            if p == 0 { String::new() } else { p.to_string() },
        );
    }
    if let Some(p) = input.http_redirect_port {
        set(&mut want, K_REDIRECT_PORT, p.to_string());
    }
    if let Some(v) = &input.extra_https_ports {
        let t = v.trim();
        let val = if t.is_empty() {
            String::new()
        } else if t.eq_ignore_ascii_case("none") {
            "none".into()
        } else {
            let mut out = Vec::new();
            for p in split(t) {
                match p.parse::<u16>() {
                    Ok(n) if n != 0 => out.push(n.to_string()),
                    _ => {
                        return Err(Error::Config(format!(
                            "Invalid web UI settings: '{p}' is not a port"
                        )))
                    }
                }
            }
            out.join(",")
        };
        set(&mut want, K_EXTRA_PORTS, val);
    }
    if let Some(v) = &input.tls_cert {
        set(&mut want, K_TLS_CERT, v.trim().to_string());
    }
    if let Some(v) = &input.tls_key {
        set(&mut want, K_TLS_KEY, v.trim().to_string());
    }
    // validate the result of the new stored layer on top of the others
    let path = crate::defaults::default_bootstrap_path();
    let toml = std::fs::read_to_string(&path).unwrap_or_default();
    let layer = layer_from_pairs(&want);
    let eff = WebSettings::default()
        .overlay(&Layer::from_env())
        .overlay(&Layer::from_toml(&toml))
        .overlay(&layer);
    eff.validate()?;
    for (k, v) in &want {
        store.save_system_config(k, v).await?;
    }
    Ok(before)
}

fn layer_from_pairs(p: &[(&'static str, String)]) -> Layer {
    let get = |k: &str| {
        p.iter()
            .find(|(n, _)| *n == k)
            .map(|(_, v)| v.trim().to_string())
            .filter(|v| !v.is_empty())
    };
    Layer {
        listen: get(K_LISTEN).map(|v| split(&v)).filter(|v| !v.is_empty()),
        https_port: get(K_HTTPS_PORT).and_then(|v| port(&v)).filter(|p| *p != 0),
        http_redirect_port: get(K_REDIRECT_PORT).and_then(|v| port(&v)),
        extra_https_ports: get(K_EXTRA_PORTS).and_then(|v| ports(&v)),
        tls_cert: get(K_TLS_CERT),
        tls_key: get(K_TLS_KEY),
    }
}

/// Put back what [`save`] returned.
pub async fn restore(store: &ConfigStore, before: &[(&'static str, String)]) -> Result<()> {
    for (k, v) in before {
        store.save_system_config(k, v).await?;
    }
    Ok(())
}

/// The stored anti-lockout rule opens the ports it was seeded with
/// (`22, 8443`, or the image's `22,80,443`): make a system "Anti-lockout"
/// rule open SSH (its first port) plus every port the web UI listens on.
pub fn follow_web_ports(
    rule: &mut patronus_core::types::FirewallRule,
    origin: crate::store::RuleOrigin,
    web: &WebSettings,
) {
    use patronus_core::types::PortSpec;
    if origin != crate::store::RuleOrigin::System || rule.name != "Anti-lockout" {
        return;
    }
    if let Some(PortSpec::Multiple(ports)) = &mut rule.dport {
        let Some(ssh) = ports.first().copied() else {
            return;
        };
        let mut v = vec![ssh];
        for p in web.all_ports() {
            if !v.contains(&p) {
                v.push(p);
            }
        }
        *ports = v;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::RuleOrigin;
    use patronus_core::types::{ChainType, FirewallAction, FirewallRule, PortSpec, Protocol};

    fn env(pairs: &'static [(&'static str, &'static str)]) -> Layer {
        Layer::from_env_with(|k| {
            pairs
                .iter()
                .find(|(n, _)| *n == k)
                .map(|(_, v)| v.to_string())
        })
    }

    #[test]
    fn built_in_default_is_443_with_80_redirect_and_no_other_listener() {
        let d = WebSettings::default();
        assert_eq!(d.https_port, 443);
        assert_eq!(d.http_redirect_port, 80);
        assert!(d.extra_https_ports.is_empty());
        assert_eq!(d.all_ports(), vec![443, 80]);
        d.validate().unwrap();
    }

    #[test]
    fn eight_four_four_three_is_an_explicit_opt_in() {
        let s = WebSettings::default().overlay(&env(&[("PATRONUS_WEB_EXTRA_HTTPS_PORTS", "8443")]));
        assert_eq!(s.all_ports(), vec![443, 80, 8443]);
        let s = WebSettings::default()
            .overlay(&Layer::from_toml("[web]\nextra_https_ports = [8443]\n"));
        assert_eq!(s.all_ports(), vec![443, 80, 8443]);
    }

    #[test]
    fn layers_override_key_by_key() {
        let toml = Layer::from_toml(
            "[web]\nlisten_addr = \"10.0.0.1\"\nhttps_port = 4443\nextra_https_ports = []\n",
        );
        assert_eq!(toml.https_port, Some(4443));
        assert_eq!(toml.extra_https_ports, Some(vec![]));
        let s = WebSettings::default()
            .overlay(&env(&[
                ("PATRONUS_HTTPS_PORT", "9443"),
                ("PATRONUS_HTTP_REDIRECT_PORT", "0"),
            ]))
            .overlay(&toml);
        assert_eq!(s.https_port, 4443, "toml beats env");
        assert_eq!(s.http_redirect_port, 0, "env redirect stays");
        assert_eq!(s.listen, vec!["10.0.0.1"]);
        assert!(s.extra_https_ports.is_empty());
        assert_eq!(s.all_ports(), vec![4443]);
    }

    #[test]
    fn the_old_toml_keys_are_not_honoured() {
        let l = Layer::from_toml(
            "[web]\nlisten_addr = \"0.0.0.0\"\nlisten_port = 8080\nuse_tls = false\n",
        );
        assert_eq!(l.https_port, None);
        assert_eq!(l.listen, Some(vec!["0.0.0.0".to_string()]));
        assert_eq!(Layer::from_toml("not toml ["), Layer::default());
    }

    #[test]
    fn embedded_env_sets_443_and_80_and_none() {
        let s = WebSettings::default().overlay(&env(&[
            ("PATRONUS_HTTPS_PORT", "443"),
            ("PATRONUS_HTTP_REDIRECT_PORT", "80"),
            ("PATRONUS_WEB_EXTRA_HTTPS_PORTS", "none"),
        ]));
        assert_eq!(s.all_ports(), vec![443, 80]);
    }

    #[test]
    fn validation_refuses_collisions_and_half_certs() {
        let d = WebSettings::default;
        let bad = |s: WebSettings| assert!(s.validate().is_err(), "{s:?}");
        bad(WebSettings {
            http_redirect_port: 443,
            ..d()
        });
        bad(WebSettings {
            extra_https_ports: vec![80],
            ..d()
        });
        bad(WebSettings {
            tls_cert: "/x/cert.pem".into(),
            ..d()
        });
        bad(WebSettings {
            tls_cert: "/x/cert.pem".into(),
            tls_key: "relative.pem".into(),
            ..d()
        });
        WebSettings {
            tls_cert: "/x/cert.pem".into(),
            tls_key: "/x/key.pem".into(),
            ..d()
        }
        .validate()
        .unwrap();
        bad(WebSettings {
            listen: vec!["@lan".into()],
            ..d()
        });
    }

    fn anti(ports: Vec<u16>) -> FirewallRule {
        let mut r = FirewallRule::new(
            "Anti-lockout".into(),
            ChainType::Input,
            FirewallAction::Accept,
        );
        r.protocol = Some(Protocol::Tcp);
        r.dport = Some(PortSpec::Multiple(ports));
        r
    }

    #[test]
    fn anti_lockout_follows_the_configured_ports() {
        let web = WebSettings::default();
        let mut r = anti(vec![22, 8443]);
        follow_web_ports(&mut r, RuleOrigin::System, &web);
        assert_eq!(r.dport, Some(PortSpec::Multiple(vec![22, 443, 80])));
        // a custom ssh port stays first, a web-less change drops stale ports
        let web = WebSettings {
            https_port: 4443,
            http_redirect_port: 0,
            extra_https_ports: vec![],
            ..WebSettings::default()
        };
        let mut r = anti(vec![2222, 80, 443]);
        follow_web_ports(&mut r, RuleOrigin::System, &web);
        assert_eq!(r.dport, Some(PortSpec::Multiple(vec![2222, 4443])));
        // user rules are never touched
        let mut r = anti(vec![22, 8443]);
        follow_web_ports(&mut r, RuleOrigin::User, &web);
        assert_eq!(r.dport, Some(PortSpec::Multiple(vec![22, 8443])));
    }

    #[tokio::test]
    async fn store_layer_wins_and_save_validates_and_restores() {
        let s = ConfigStore::open_in_memory().await.unwrap();
        let eff = resolve(Some(&s)).await;
        assert_eq!(eff.https_port, 443);
        let before = save(
            &s,
            &WebInput {
                https_port: Some(7443),
                http_redirect_port: Some(0),
                extra_https_ports: Some("none".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let eff = resolve(Some(&s)).await;
        assert_eq!(eff.all_ports(), vec![7443]);
        // a refused change stores nothing
        let err = save(
            &s,
            &WebInput {
                http_redirect_port: Some(7443),
                ..Default::default()
            },
        )
        .await;
        assert!(err.is_err());
        assert_eq!(resolve(Some(&s)).await.all_ports(), vec![7443]);
        restore(&s, &before).await.unwrap();
        assert_eq!(resolve(Some(&s)).await.all_ports(), vec![443, 80]);
        // reset clears
        save(
            &s,
            &WebInput {
                https_port: Some(7443),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        save(
            &s,
            &WebInput {
                reset: true,
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(resolve(Some(&s)).await.https_port, 443);
    }
}
