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

static FIELDS: [Field; 9] = [
    Field::new("enabled", "UPnP / NAT-PMP", Kind::Bool)
        .def("0")
        .help("Off by default: any program on the LAN can open WAN ports while this is on"),
    Field::new("interface", "Serve clients on", Kind::Iface)
        .def("@lan")
        .help("SSDP (UDP 1900), the control URL (TCP 5000) and NAT-PMP (UDP 5351) are opened on this interface only"),
    Field::new("ext_interface", "WAN interface", Kind::Iface).def("@wan"),
    Field::new("upnp", "UPnP IGD", Kind::Bool).def("1"),
    Field::new("natpmp", "NAT-PMP / PCP", Kind::Bool).def("1"),
    Field::new("ext_ip", "Announce this public address", Kind::Ipv4)
        .help("optional: for 1:1 NAT or double NAT, where the WAN address is private; miniupnpd refuses private WAN addresses otherwise"),
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

/// miniupnpd.conf. `lan_dev`/`wan_dev` are device names; `ext_ip` declares the WAN address
/// when the WAN address is private (double NAT), where miniupnpd refuses to
/// map unless told otherwise.
pub fn render_conf(
    s: &Settings,
    lan_devs: &[String],
    wan_dev: &str,
    ext_ip: Option<&str>,
    lease: &str,
) -> String {
    let mut c = lan::header("#", "miniupnpd");
    c.push_str(&format!("ext_ifname={wan_dev}\n"));
    for d in lan_devs {
        c.push_str(&format!("listening_ip={d}\n"));
    }
    c.push_str("port=5000\nenable_natpmp=");
    c.push_str(if s.b("natpmp") { "yes\n" } else { "no\n" });
    c.push_str("enable_upnp=");
    c.push_str(if s.b("upnp") { "yes\n" } else { "no\n" });
    c.push_str(&format!(
        "secure_mode={}\nsystem_uptime=yes\nlease_file={lease}\nclean_ruleset_interval=600\n",
        if s.b("secure_mode") { "yes" } else { "no" }
    ));
    if let Some(ip) = ext_ip {
        // a private or reserved WAN address: declare it as the public one
        c.push_str(&format!("ext_ip={ip}\n"));
    }
    c.push_str("friendly_name=Patronus\n");
    // miniupnpd's nftables backend writes into chains that must already
    // exist; it never creates them. They live in a table of Patronus' own.
    c.push_str(&format!(
        "upnp_table_name={NFT_TABLE}\nupnp_nat_table_name={NFT_TABLE}\nupnp_forward_chain=forward_miniupnpd\nupnp_nat_chain=prerouting_miniupnpd\nupnp_nat_postrouting_chain=postrouting_miniupnpd\n"
    ));
    // only the configured range, from any LAN address; everything else denied
    let (lo, hi) = (s.n("port_min").max(1024), s.n("port_max").min(65535));
    c.push_str(&format!(
        "allow {lo}-{hi} 0.0.0.0/0 {lo}-{hi}\ndeny 0-65535 0.0.0.0/0 0-65535\n"
    ));
    c
}

/// The nft table holding miniupnpd's mapping chains (kernel state, not
/// persisted by the firewall applier: recreated here at every apply).
pub const NFT_TABLE: &str = "patronus_upnp";

const NFT_SKELETON: &str = "table inet patronus_upnp {
  chain forward { type filter hook forward priority -10; policy accept; jump forward_miniupnpd; }
  chain forward_miniupnpd { }
  chain prerouting { type nat hook prerouting priority dstnat; policy accept; jump prerouting_miniupnpd; }
  chain prerouting_miniupnpd { }
  chain postrouting { type nat hook postrouting priority srcnat; policy accept; jump postrouting_miniupnpd; }
  chain postrouting_miniupnpd { }
}
";

fn nft_table_exists() -> bool {
    std::process::Command::new("nft")
        .args(["list", "table", "inet", NFT_TABLE])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Create the mapping chains once (a later apply keeps live mappings).
fn ensure_nft_table() -> Result<()> {
    use std::io::Write;
    if nft_table_exists() {
        return Ok(());
    }
    let mut child = std::process::Command::new("nft")
        .args(["-f", "-"])
        .stdin(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| Error::Service(format!("nft: {e}")))?;
    child
        .stdin
        .take()
        .ok_or_else(|| Error::Service("nft: no stdin".into()))?
        .write_all(NFT_SKELETON.as_bytes())
        .map_err(|e| Error::Service(format!("nft: {e}")))?;
    let out = child
        .wait_with_output()
        .map_err(|e| Error::Service(format!("nft: {e}")))?;
    if !out.status.success() {
        return Err(Error::Service(format!(
            "UPnP: nft table: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    Ok(())
}

fn drop_nft_table() {
    if nft_table_exists() {
        let _ = std::process::Command::new("nft")
            .args(["delete", "table", "inet", NFT_TABLE])
            .output();
    }
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
            drop_nft_table();
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
            Some(s.s("ext_ip")).filter(|a| !a.is_empty()).as_deref(),
            &lease.to_string_lossy(),
        );
        ensure_nft_table()?;
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
            None,
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
        let c = render_conf(&s, &["eth1".into()], "eth0", Some("10.0.0.2"), "/x/leases");
        assert!(c.contains("ext_ifname=eth0\nlistening_ip=eth1\n"));
        assert!(c.contains("enable_natpmp=yes\n") && c.contains("enable_upnp=no\n"));
        assert!(c.contains("secure_mode=yes\n") && c.contains("ext_ip=10.0.0.2\n"));
        assert!(c.contains("allow 2000-3000 0.0.0.0/0 2000-3000\ndeny 0-65535"));
        assert!(c.contains("upnp_table_name=patronus_upnp\nupnp_nat_table_name=patronus_upnp\n"));
        assert!(c.contains("upnp_nat_chain=prerouting_miniupnpd\n"));
        for chain in ["forward_miniupnpd", "prerouting_miniupnpd", "postrouting_miniupnpd"] {
            assert!(NFT_SKELETON.contains(&format!("chain {chain} {{ }}")), "{chain}");
        }
        assert!(!render_conf(&s, &["eth1".into()], "eth0", None, "l").contains("ext_ip"));
    }
}
