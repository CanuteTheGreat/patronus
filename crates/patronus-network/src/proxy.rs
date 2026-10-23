//! Web proxy with domain blocking (USE=web-proxy): Squid for the LAN.
//!
//! `squid` runs through the supervisor with a generated config: a forward
//! proxy on the LAN interface (default port 3128), optionally also intercepting
//! plain HTTP from the LAN (the firewall redirects TCP 80 from the LAN to the
//! intercept port), memory cache only, and a list of blocked domains (a domain
//! blocks its subdomains too). Only the LAN's own networks may use it. HTTPS is
//! never intercepted: clients using the proxy explicitly are filtered by domain
//! through CONNECT; transparent mode filters HTTP only.

use crate::lan::{self, invalid};
use crate::supervise::{which, Supervisor};
use crate::svc::{self, Coll, Field, Kind, Settings, Spec, Svc};
use async_trait::async_trait;
use patronus_config::applier::{Applier, ApplyReport, Phase};
use patronus_config::store::ConfigStore;
use patronus_core::{Error, Result};
use serde_json::{json, Value};

pub const INSTANCE: &str = "squid";
/// Port Squid listens on for redirected (intercepted) HTTP.
pub const INTERCEPT_PORT: u16 = 3129;

static FIELDS: [Field; 5] = [
    Field::new("enabled", "Web proxy", Kind::Bool).def("0"),
    Field::new("interface", "Serve clients on", Kind::Iface)
        .def("@lan")
        .help(
            "the proxy port is opened on this interface only; only its networks may use the proxy",
        ),
    Field::new("port", "Proxy port", Kind::Int(1025, 65535)).def("3128"),
    Field::new(
        "transparent",
        "Intercept plain HTTP from the LAN",
        Kind::Bool,
    )
    .def("0")
    .help("redirects TCP 80 from the LAN to the proxy; HTTPS is not intercepted"),
    Field::new("cache_mb", "Memory cache (MB)", Kind::Int(0, 4096)).def("64"),
];

static BLOCK_FIELDS: [Field; 2] = [
    Field::new("domain", "Blocked domain", Kind::Host).req(),
    Field::new("note", "Note", Kind::Text),
];

static SPEC: Spec = Spec {
    slug: "proxy",
    title: "Web proxy",
    blurb: "Squid proxy for the LAN with a domain block list (a blocked domain blocks its subdomains). \
            Clients set the proxy in their browser, or turn on interception for plain HTTP. HTTPS is \
            filtered by domain only for clients that use the proxy explicitly.",
    applier: "proxy",
    fields: &FIELDS,
    colls: &[Coll {
        key: "blocked",
        title: "Blocked domains",
        table: "proxy_blocked",
        fields: &BLOCK_FIELDS,
        unique: Some("domain"),
    }],
    actions: &[],
};

pub struct ProxySvc;

#[async_trait]
impl Svc for ProxySvc {
    fn spec(&self) -> &'static Spec {
        &SPEC
    }
}

pub fn safe_domain(d: &str) -> bool {
    !d.is_empty()
        && d.len() <= 253
        && !d.starts_with('.')
        && d.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
}

/// squid.conf. `nets` are the CIDRs of the served interfaces, `listen` the
/// addresses to bind.
pub fn render_conf(
    s: &Settings,
    nets: &[String],
    listen: &[String],
    blocked: &[String],
    dir: &str,
) -> String {
    let port = s.n("port");
    let mut c = lan::header("#", "squid");
    for l in listen {
        c.push_str(&format!("http_port {l}:{port}\n"));
        if s.b("transparent") {
            c.push_str(&format!("http_port {l}:{INTERCEPT_PORT} intercept\n"));
        }
    }
    for (i, n) in nets.iter().enumerate() {
        c.push_str(&format!("acl lan{i} src {n}\n"));
    }
    c.push_str("acl Safe_ports port 80 443 21 70 210 1025-65535\nacl SSL_ports port 443\nacl CONNECT method CONNECT\n");
    for (i, d) in blocked.iter().enumerate() {
        c.push_str(&format!("acl blocked{i} dstdomain .{d}\n"));
    }
    c.push_str("http_access deny !Safe_ports\nhttp_access deny CONNECT !SSL_ports\n");
    for i in 0..blocked.len() {
        c.push_str(&format!("http_access deny blocked{i}\n"));
    }
    for i in 0..nets.len() {
        c.push_str(&format!("http_access allow lan{i}\n"));
    }
    c.push_str("http_access deny all\n");
    c.push_str(&format!(
        "cache_mem {} MB\ncache deny all\npid_filename none\naccess_log none\ncache_log stderr\n\
         coredump_dir {dir}\nvisible_hostname patronus\nvia off\nforwarded_for delete\nshutdown_lifetime 2 seconds\n",
        s.n("cache_mb")
    ));
    c
}

#[derive(Clone)]
pub struct ProxyApplier {
    sup: Supervisor,
}

impl Default for ProxyApplier {
    fn default() -> Self {
        Self {
            sup: Supervisor::detect(),
        }
    }
}

impl ProxyApplier {
    pub fn with_supervisor(sup: Supervisor) -> Self {
        Self { sup }
    }
}

/// (networks, listen addresses) of the interfaces the proxy serves.
async fn served(store: &ConfigStore, spec: &str) -> Result<(Vec<String>, Vec<String>)> {
    let devs = lan::resolve_iface(store, spec).await?;
    let cfg = crate::netconf::NetConfig::load(store).await?;
    let (mut nets, mut listen) = (Vec::new(), Vec::new());
    for d in &devs {
        if let Some(i) = cfg.iface(d) {
            for n in i.ipv4.iter().filter(|n| n.is_ipv4()) {
                nets.push(format!("{}/{}", n.network(), n.prefix()));
                listen.push(n.ip().to_string());
            }
        }
    }
    Ok((nets, listen))
}

async fn blocked(store: &ConfigStore) -> Result<Vec<String>> {
    Ok(svc::raw_rows(store, &SPEC.colls[0])
        .await?
        .iter()
        .filter_map(|r| r["domain"].as_str().map(|d| d.trim().to_ascii_lowercase()))
        .filter(|d| safe_domain(d))
        .collect())
}

#[async_trait]
impl Applier for ProxyApplier {
    fn name(&self) -> &'static str {
        "proxy"
    }

    fn phase(&self) -> Phase {
        Phase::Services
    }

    async fn apply(&self, store: &ConfigStore) -> Result<ApplyReport> {
        let mut rep = ApplyReport::default();
        let s = Settings::load(store, &SPEC).await?;
        if !s.b("enabled") {
            let was = self.sup.stop(svc::DAEMON_SERVICE, INSTANCE).await?;
            rep.applied(if was {
                "web proxy stopped"
            } else {
                "web proxy is off"
            });
            return Ok(rep);
        }
        let bin = which("squid").ok_or_else(|| {
            Error::Service("the web proxy needs squid, which is not installed (emerge net-proxy/squid, USE=web-proxy)".into())
        })?;
        let (nets, listen) = served(store, &s.s("interface")).await?;
        if listen.is_empty() {
            return Err(invalid(
                "web proxy: the LAN interface has no static IPv4 address to listen on",
            ));
        }
        let b = blocked(store).await?;
        let conf = self.sup.paths.state_dir.join("squid.conf");
        let text = render_conf(
            &s,
            &nets,
            &listen,
            &b,
            &self.sup.paths.state_dir.to_string_lossy(),
        );
        let started = svc::ensure_daemon(
            &self.sup,
            INSTANCE,
            vec![
                bin.to_string_lossy().into(),
                "-N".into(),
                "-f".into(),
                conf.to_string_lossy().into(),
            ],
            vec![(conf, text, 0o644)],
        )
        .await?;
        rep.applied(format!(
            "squid {}: {} on port {}, {} blocked domain(s)",
            if started {
                "(re)started"
            } else {
                "running, unchanged"
            },
            listen.join(", "),
            s.n("port"),
            b.len()
        ));
        Ok(rep)
    }

    async fn render(&self, store: &ConfigStore) -> Result<String> {
        let s = Settings::load(store, &SPEC).await?;
        if !s.b("enabled") {
            return Ok("# web proxy off\n".into());
        }
        let (nets, listen) = served(store, &s.s("interface")).await.unwrap_or_default();
        Ok(render_conf(
            &s,
            &nets,
            &listen,
            &blocked(store).await.unwrap_or_default(),
            "/tmp",
        ))
    }

    async fn status(&self, store: &ConfigStore) -> Result<Value> {
        let s = Settings::load(store, &SPEC).await?;
        Ok(json!({
            "enabled": s.b("enabled"),
            "installed": which("squid").is_some(),
            "running": self.sup.is_running(svc::DAEMON_SERVICE, INSTANCE),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_blocks_domains_and_only_serves_the_lan() {
        let mut m = serde_json::Map::new();
        for (k, v) in [("port", "3128"), ("transparent", "1"), ("cache_mb", "32")] {
            m.insert(k.into(), json!(v));
        }
        let c = render_conf(
            &Settings(m),
            &["192.168.50.0/24".into()],
            &["192.168.50.1".into()],
            &["blocked.example.test".into()],
            "/x",
        );
        assert!(c.contains("http_port 192.168.50.1:3128\nhttp_port 192.168.50.1:3129 intercept\n"));
        let deny = c.find("http_access deny blocked0").unwrap();
        let allow = c.find("http_access allow lan0").unwrap();
        assert!(deny < allow, "blocks come before the allow");
        assert!(c.trim_end().contains("http_access deny all"));
        assert!(c.contains("cache_mem 32 MB"));
        assert!(!safe_domain("a b") && !safe_domain(".x") && safe_domain("a-b.example.org"));
    }
}
