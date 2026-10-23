//! UPnP IGD / NAT-PMP / PCP for LAN clients (USE=upnp, off by default).
//!
//! `miniupnpd` (nftables backend) runs through the supervisor with a
//! generated config. It lets LAN clients ask for port mappings on the WAN
//! address; in secure mode a client may only map its own address, and only
//! ports inside the range set here. miniupnpd keeps its mappings in its own
//! nftables table; the Patronus firewall opens the discovery/control ports on
//! the LAN side only and forwards mapped (DNAT'ed) traffic towards the LAN.

use crate::lan;
use crate::supervise::{which, Supervisor};
use crate::svc::{self, Field, Kind, Settings, Spec, Svc};
use async_trait::async_trait;
use patronus_config::applier::{Applier, ApplyReport, Phase};
use patronus_config::store::ConfigStore;
use patronus_core::{Error, Result};
use serde_json::{json, Value};

pub const INSTANCE: &str = "miniupnpd";

static FIELDS: [Field; 8] = [
    Field::new("enabled", "UPnP / NAT-PMP", Kind::Bool)
        .def("0")
        .help("Off by default: any program on the LAN can open WAN ports while this is on"),
    Field::new("interface", "Serve clients on", Kind::Iface)
        .def("@lan")
        .help("SSDP (UDP 1900), the control URL (TCP 5000) and NAT-PMP (UDP 5351) are opened on this interface only"),
    Field::new("ext_interface", "WAN interface", Kind::Iface).def("@wan"),
    Field::new("upnp", "UPnP IGD", Kind::Bool).def("1"),
    Field::new("natpmp", "NAT-PMP / PCP", Kind::Bool).def("1"),
    Field::new("secure_mode", "Clients map only their own address", Kind::Bool).def("1"),
    Field::new("port_min", "Lowest mappable external port", Kind::Int(1024, 65535)).def("1024"),
    Field::new("port_max", "Highest mappable external port", Kind::Int(1024, 65535)).def("65535"),
];

static SPEC: Spec = Spec {
    slug: "upnp",
    title: "UPnP / NAT-PMP",
    blurb:
        "Lets LAN programs (games, VoIP, torrent clients) open WAN port mappings by themselves. \
            Runs miniupnpd. Off by default: enable it only on trusted LANs.",
    applier: "upnp",
    fields: &FIELDS,
    colls: &[],
    actions: &[],
};

pub struct UpnpSvc;

#[async_trait]
impl Svc for UpnpSvc {
    fn spec(&self) -> &'static Spec {
        &SPEC
    }

    async fn put(&self, store: &ConfigStore, body: &Value) -> Result<()> {
        let cur = Settings::load(store, &SPEC).await?;
        let n = |k: &str| {
            body.get(k)
                .and_then(|v| {
                    v.as_str()
                        .map(|s| s.to_string())
                        .or_else(|| v.as_i64().map(|i| i.to_string()))
                })
                .and_then(|s| s.trim().parse::<i64>().ok())
                .unwrap_or_else(|| cur.n(k))
        };
        if n("port_min") > n("port_max") {
            return Err(lan::invalid(
                "UPnP: the lowest mappable port is above the highest",
            ));
        }
        svc::put_settings(store, &SPEC, body).await
    }
}

/// miniupnpd.conf. `lan_dev`/`wan_dev` are device names; `ext_private` is set
/// when the WAN address is private (double NAT), where miniupnpd refuses to
/// map unless told otherwise.
pub fn render_conf(
    s: &Settings,
    lan_devs: &[String],
    wan_dev: &str,
    ext_private: bool,
    lease: &str,
) -> String {
    let mut c = lan::header("#", "miniupnpd");
    c.push_str(&format!("ext_ifname={wan_dev}\n"));
    for d in lan_devs {
        c.push_str(&format!("listening_ip={d}\n"));
    }
    c.push_str("port=5000\nnat_pmp=");
    c.push_str(if s.b("natpmp") { "yes\n" } else { "no\n" });
    c.push_str("enable_upnp=");
    c.push_str(if s.b("upnp") { "yes\n" } else { "no\n" });
    c.push_str(&format!(
        "secure_mode={}\nsystem_uptime=yes\nlease_file={lease}\nclean_ruleset_interval=600\n",
        if s.b("secure_mode") { "yes" } else { "no" }
    ));
    if ext_private {
        c.push_str("ext_allow_private_ipv4=yes\n");
    }
    c.push_str("friendly_name=Patronus\n");
    // only the configured range, from any LAN address; everything else denied
    let (lo, hi) = (s.n("port_min").max(1024), s.n("port_max").min(65535));
    c.push_str(&format!(
        "allow {lo}-{hi} 0.0.0.0/0 {lo}-{hi}\ndeny 0-65535 0.0.0.0/0 0-65535\n"
    ));
    c
}

#[derive(Clone)]
pub struct UpnpApplier {
    sup: Supervisor,
}

impl Default for UpnpApplier {
    fn default() -> Self {
        Self {
            sup: Supervisor::detect(),
        }
    }
}

impl UpnpApplier {
    pub fn with_supervisor(sup: Supervisor) -> Self {
        Self { sup }
    }
}

async fn wan_is_private(store: &ConfigStore, dev: &str) -> bool {
    let Ok(cfg) = crate::netconf::NetConfig::load(store).await else {
        return false;
    };
    cfg.iface(dev).is_some_and(|i| {
        i.ipv4.iter().any(|n| match n.ip() {
            std::net::IpAddr::V4(a) => a.is_private() || a.is_link_local(),
            _ => false,
        })
    })
}

#[async_trait]
impl Applier for UpnpApplier {
    fn name(&self) -> &'static str {
        "upnp"
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
                "UPnP/NAT-PMP stopped"
            } else {
                "UPnP/NAT-PMP is off"
            });
            return Ok(rep);
        }
        let bin = which("miniupnpd").ok_or_else(|| {
            Error::Service(
                "UPnP needs miniupnpd, which is not installed (emerge net-misc/miniupnpd, USE=upnp)".into(),
            )
        })?;
        let lan_devs = lan::resolve_iface(store, &s.s("interface")).await?;
        let wan_devs = lan::resolve_iface(store, &s.s("ext_interface")).await?;
        let (Some(wan), false) = (wan_devs.first(), lan_devs.is_empty()) else {
            return Err(lan::invalid(
                "UPnP: the LAN and WAN interfaces need a role (Interfaces page)",
            ));
        };
        let conf = self.sup.paths.state_dir.join("miniupnpd.conf");
        let lease = self.sup.paths.state_dir.join("upnp.leases");
        let text = render_conf(
            &s,
            &lan_devs,
            wan,
            wan_is_private(store, wan).await,
            &lease.to_string_lossy(),
        );
        let started = svc::ensure_daemon(
            &self.sup,
            INSTANCE,
            vec![
                bin.to_string_lossy().into(),
                "-d".into(),
                "-f".into(),
                conf.to_string_lossy().into(),
            ],
            vec![(conf, text, 0o644)],
        )
        .await?;
        rep.applied(format!(
            "miniupnpd {} (WAN {wan}, clients on {})",
            if started {
                "(re)started"
            } else {
                "running, unchanged"
            },
            lan_devs.join(", ")
        ));
        Ok(rep)
    }

    async fn render(&self, store: &ConfigStore) -> Result<String> {
        let s = Settings::load(store, &SPEC).await?;
        if !s.b("enabled") {
            return Ok("# UPnP/NAT-PMP off\n".into());
        }
        let lan_devs = lan::resolve_iface(store, &s.s("interface"))
            .await
            .unwrap_or_default();
        let wan = lan::resolve_iface(store, &s.s("ext_interface"))
            .await
            .unwrap_or_default();
        Ok(render_conf(
            &s,
            &lan_devs,
            wan.first().map(String::as_str).unwrap_or("?"),
            false,
            "upnp.leases",
        ))
    }

    async fn status(&self, store: &ConfigStore) -> Result<Value> {
        let s = Settings::load(store, &SPEC).await?;
        Ok(json!({
            "enabled": s.b("enabled"),
            "installed": which("miniupnpd").is_some(),
            "running": self.sup.is_running(svc::DAEMON_SERVICE, INSTANCE),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings(pairs: &[(&str, &str)]) -> Settings {
        let mut m = serde_json::Map::new();
        for (k, v) in pairs {
            m.insert((*k).into(), json!(v));
        }
        Settings(m)
    }

    #[test]
    fn config_follows_the_settings() {
        let s = settings(&[
            ("natpmp", "1"),
            ("upnp", "0"),
            ("secure_mode", "1"),
            ("port_min", "2000"),
            ("port_max", "3000"),
        ]);
        let c = render_conf(&s, &["eth1".into()], "eth0", true, "/x/leases");
        assert!(c.contains("ext_ifname=eth0\nlistening_ip=eth1\n"));
        assert!(c.contains("nat_pmp=yes\n") && c.contains("enable_upnp=no\n"));
        assert!(c.contains("secure_mode=yes\n") && c.contains("ext_allow_private_ipv4=yes\n"));
        assert!(c.contains("allow 2000-3000 0.0.0.0/0 2000-3000\ndeny 0-65535"));
        assert!(!render_conf(&s, &["eth1".into()], "eth0", false, "l").contains("allow_private"));
    }
}
