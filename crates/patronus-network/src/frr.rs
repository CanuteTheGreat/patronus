//! Dynamic routing with FRR (USE=dynamic-routing): BGP and OSPF, replacing
//! the old in-tree BGP session code with the real thing.
//!
//! Patronus owns `/etc/frr/frr.conf` (integrated config; a hand-written one
//! is kept once as `frr.conf.pre-patronus`) and `/etc/frr/daemons` (which
//! FRR daemons start: zebra always, bgpd / ospfd as configured), restarts the
//! `frr` service when either changes, and reads session state back from
//! `vtysh` for the page. Learned routes are installed in the kernel by zebra.
//! The firewall accepts TCP/179 from the configured neighbours and OSPF
//! (protocol 89) on the OSPF interfaces (`patronus_firewall::svc_rules`).
//!
//! BGP: `no bgp ebgp-requires-policy` is set so the sessions you configure
//! here exchange the networks you list (and whatever the peer announces):
//! filter what you accept with prefix lists in a hand-written `frr.conf` if
//! the peer is not trusted.

use crate::lan::{self, invalid, LanEnv, ManagedFile};
use crate::svc::{self, Coll, Field, Kind, Settings, Spec, Svc};
use async_trait::async_trait;
use patronus_config::applier::{Applier, ApplyReport, Phase};
use patronus_config::store::ConfigStore;
use patronus_core::{Error, Result};
use serde_json::{json, Value};

pub const CONF: &str = "/etc/frr/frr.conf";
pub const DAEMONS: &str = "/etc/frr/daemons";
pub const SERVICE: &str = "frr";
pub const VTYSH: &str = "vtysh";

static FIELDS: [Field; 6] = [
    Field::new("bgp_enabled", "BGP", Kind::Bool).def("0"),
    Field::new("bgp_asn", "Local AS number", Kind::Int(1, 4_294_967_295)).def("65001"),
    Field::new("router_id", "Router ID", Kind::Ipv4)
        .help("an IPv4 address that identifies this router (BGP and OSPF)"),
    Field::new(
        "bgp_redistribute_connected",
        "BGP: announce connected networks",
        Kind::Bool,
    )
    .def("0"),
    Field::new("ospf_enabled", "OSPF", Kind::Bool).def("0"),
    Field::new(
        "ospf_redistribute_connected",
        "OSPF: announce connected networks",
        Kind::Bool,
    )
    .def("0"),
];

static NEIGHBOR_FIELDS: [Field; 5] = [
    Field::new("address", "Neighbour address", Kind::Ip).req(),
    Field::new("remote_as", "Remote AS", Kind::Int(1, 4_294_967_295)).req(),
    Field::new("password", "MD5 password", Kind::Secret),
    Field::new("description", "Description", Kind::Token),
    Field::new("enabled", "Enabled", Kind::Bool).def("1"),
];

static NETWORK_FIELDS: [Field; 1] = [Field::new("prefix", "Network to announce", Kind::Cidr).req()];

static OSPF_FIELDS: [Field; 4] = [
    Field::new("iface", "Interface", Kind::Iface).req(),
    Field::new("area", "Area", Kind::Token).def("0.0.0.0"),
    Field::new(
        "passive",
        "Passive (announce only, no neighbours)",
        Kind::Bool,
    )
    .def("0"),
    Field::new("enabled", "Enabled", Kind::Bool).def("1"),
];

static SPEC: Spec = Spec {
    slug: "frr",
    title: "Dynamic routing (BGP / OSPF)",
    blurb: "BGP and OSPF with FRRouting. Sessions and announced networks are written to \
            /etc/frr/frr.conf; learned routes are installed in the kernel by zebra. The table \
            below shows the live session state from FRR.",
    applier: "frr",
    fields: &FIELDS,
    colls: &[
        Coll {
            key: "bgp_neighbors",
            title: "BGP neighbours",
            table: "frr_bgp_neighbors",
            fields: &NEIGHBOR_FIELDS,
            unique: Some("address"),
        },
        Coll {
            key: "bgp_networks",
            title: "BGP networks to announce",
            table: "frr_bgp_networks",
            fields: &NETWORK_FIELDS,
            unique: Some("prefix"),
        },
        Coll {
            key: "ospf_interfaces",
            title: "OSPF interfaces",
            table: "frr_ospf_interfaces",
            fields: &OSPF_FIELDS,
            unique: Some("iface"),
        },
    ],
    actions: &[],
};

pub struct FrrSvc;

#[async_trait]
impl Svc for FrrSvc {
    fn spec(&self) -> &'static Spec {
        &SPEC
    }
}

#[derive(Debug, Clone, Default)]
pub struct Plan {
    pub bgp: bool,
    pub asn: i64,
    pub router_id: String,
    pub bgp_connected: bool,
    pub ospf: bool,
    pub ospf_connected: bool,
    /// (address, remote_as, password, description)
    pub neighbors: Vec<(String, i64, String, String)>,
    pub networks: Vec<String>,
    /// (device, area, passive)
    pub ospf_ifaces: Vec<(String, String, bool)>,
}

pub async fn plan(store: &ConfigStore) -> Result<Plan> {
    let s = Settings::load(store, &SPEC).await?;
    let mut p = Plan {
        bgp: s.b("bgp_enabled"),
        asn: s.n("bgp_asn"),
        router_id: s.s("router_id"),
        bgp_connected: s.b("bgp_redistribute_connected"),
        ospf: s.b("ospf_enabled"),
        ospf_connected: s.b("ospf_redistribute_connected"),
        ..Default::default()
    };
    for r in svc::raw_rows(store, &SPEC.colls[0]).await? {
        if lan::flag(r["enabled"].as_str().unwrap_or("")) {
            p.neighbors.push((
                r["address"].as_str().unwrap_or("").into(),
                r["remote_as"]
                    .as_str()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(0),
                r["password"].as_str().unwrap_or("").into(),
                r["description"].as_str().unwrap_or("").into(),
            ));
        }
    }
    for r in svc::raw_rows(store, &SPEC.colls[1]).await? {
        p.networks.push(r["prefix"].as_str().unwrap_or("").into());
    }
    for r in svc::raw_rows(store, &SPEC.colls[2]).await? {
        if !lan::flag(r["enabled"].as_str().unwrap_or("")) {
            continue;
        }
        for d in lan::resolve_iface(store, r["iface"].as_str().unwrap_or("")).await? {
            p.ospf_ifaces.push((
                d,
                r["area"]
                    .as_str()
                    .filter(|a| !a.is_empty())
                    .unwrap_or("0.0.0.0")
                    .into(),
                lan::flag(r["passive"].as_str().unwrap_or("")),
            ));
        }
    }
    Ok(p)
}

pub fn validate(p: &Plan) -> Result<()> {
    if (p.bgp || p.ospf) && p.router_id.parse::<std::net::Ipv4Addr>().is_err() {
        return Err(invalid(
            "FRR: set a router ID (an IPv4 address) before enabling BGP or OSPF",
        ));
    }
    if p.bgp && p.neighbors.is_empty() && p.networks.is_empty() {
        return Err(invalid("BGP: add a neighbour or a network to announce"));
    }
    for (_, area, _) in &p.ospf_ifaces {
        let ok_dotted = area.parse::<std::net::Ipv4Addr>().is_ok();
        if !ok_dotted && area.parse::<u32>().is_err() {
            return Err(invalid(format!("OSPF area {area:?} (a number or a.b.c.d)")));
        }
    }
    Ok(())
}

pub fn render_conf(p: &Plan) -> String {
    let mut c = lan::header("!", "FRR integrated config");
    c.push_str("frr defaults traditional\nhostname patronus\nlog syslog informational\nservice integrated-vtysh-config\n!\n");
    if p.bgp {
        c.push_str(&format!("router bgp {}\n bgp router-id {}\n no bgp ebgp-requires-policy\n no bgp default ipv4-unicast\n", p.asn, p.router_id));
        for (a, asn, pw, d) in &p.neighbors {
            c.push_str(&format!(" neighbor {a} remote-as {asn}\n"));
            if !d.is_empty() {
                c.push_str(&format!(" neighbor {a} description {d}\n"));
            }
            if !pw.is_empty() {
                c.push_str(&format!(" neighbor {a} password {pw}\n"));
            }
        }
        c.push_str(" !\n address-family ipv4 unicast\n");
        for n in p.networks.iter().filter(|n| !n.contains(':')) {
            c.push_str(&format!("  network {n}\n"));
        }
        if p.bgp_connected {
            c.push_str("  redistribute connected\n");
        }
        for (a, _, _, _) in p.neighbors.iter().filter(|n| !n.0.contains(':')) {
            c.push_str(&format!("  neighbor {a} activate\n"));
        }
        c.push_str(" exit-address-family\n !\n address-family ipv6 unicast\n");
        for n in p.networks.iter().filter(|n| n.contains(':')) {
            c.push_str(&format!("  network {n}\n"));
        }
        if p.bgp_connected {
            c.push_str("  redistribute connected\n");
        }
        for (a, _, _, _) in p.neighbors.iter().filter(|n| n.0.contains(':')) {
            c.push_str(&format!("  neighbor {a} activate\n"));
        }
        c.push_str(" exit-address-family\n!\n");
    }
    if p.ospf {
        for (d, area, passive) in &p.ospf_ifaces {
            c.push_str(&format!("interface {d}\n ip ospf area {area}\n"));
            if *passive {
                c.push_str(" ip ospf passive\n");
            }
            c.push_str("!\n");
        }
        c.push_str(&format!("router ospf\n ospf router-id {}\n", p.router_id));
        if p.ospf_connected {
            c.push_str(" redistribute connected\n");
        }
        c.push_str("!\n");
    }
    c.push_str("line vty\n!\n");
    c
}

pub fn render_daemons(p: &Plan) -> String {
    let yn = |b: bool| if b { "yes" } else { "no" };
    let mut c = lan::header("#", "FRR daemons");
    c.push_str(&format!(
        "zebra=yes\nbgpd={}\nospfd={}\nospf6d=no\nripd=no\nripngd=no\nisisd=no\npimd=no\npim6d=no\nldpd=no\nnhrpd=no\neigrpd=no\nbabeld=no\nsharpd=no\npbrd=no\nbfdd=no\nfabricd=no\nvrrpd=no\npathd=no\n\nvtysh_enable=yes\nzebra_options=\"  -A 127.0.0.1 -s 90000000\"\nbgpd_options=\"   -A 127.0.0.1\"\nospfd_options=\"  -A 127.0.0.1\"\n",
        yn(p.bgp),
        yn(p.ospf)
    ));
    c
}

/// Peers out of `show bgp summary json`.
pub fn parse_bgp_summary(j: &Value) -> Vec<Value> {
    let mut out = Vec::new();
    if let Some(fams) = j.as_object() {
        for (fam, v) in fams {
            if let Some(peers) = v["peers"].as_object() {
                for (addr, p) in peers {
                    out.push(json!({
                        "family": fam,
                        "peer": addr,
                        "remote_as": p["remoteAs"],
                        "state": p["state"],
                        "prefixes_received": p["pfxRcd"],
                        "uptime": p["peerUptime"],
                    }));
                }
            }
        }
    }
    out
}

#[derive(Clone, Default)]
pub struct FrrApplier {
    env: LanEnv,
}

impl FrrApplier {
    pub fn new(env: LanEnv) -> Self {
        Self { env }
    }

    fn vtysh(&self, cmd: &str) -> Option<String> {
        if self.env.root != std::path::Path::new("/") {
            return None;
        }
        let o = std::process::Command::new(VTYSH)
            .args(["-c", cmd])
            .output()
            .ok()?;
        o.status
            .success()
            .then(|| String::from_utf8_lossy(&o.stdout).into_owned())
    }
}

#[async_trait]
impl Applier for FrrApplier {
    fn name(&self) -> &'static str {
        "frr"
    }

    fn phase(&self) -> Phase {
        Phase::Services
    }

    async fn apply(&self, store: &ConfigStore) -> Result<ApplyReport> {
        let mut rep = ApplyReport::default();
        let p = plan(store).await?;
        let managed = lan::is_managed(&self.env, CONF);
        if !p.bgp && !p.ospf && !managed {
            rep.applied("dynamic routing is off (FRR config untouched)");
            return Ok(rep);
        }
        validate(&p)?;
        if !self.env.has_binary("/usr/lib/frr/zebra") && !self.env.has_binary("/usr/sbin/zebra") {
            return Err(Error::Service(
                "dynamic routing needs FRR, which is not installed (emerge net-misc/frr, USE=dynamic-routing)"
                    .into(),
            ));
        }
        // keep a hand-written config once
        let conf_path = self.env.path(CONF);
        let bak = self.env.path("/etc/frr/frr.conf.pre-patronus");
        if conf_path.exists() && !managed && !bak.exists() {
            let _ = std::fs::copy(&conf_path, &bak);
            rep.warn("kept the existing /etc/frr/frr.conf as frr.conf.pre-patronus");
        }
        let c1 = lan::install(
            &self.env,
            &ManagedFile {
                path: CONF,
                content: render_conf(&p),
                mode: 0o640,
                group: Some("frr"),
                check: None,
            },
        )?;
        let c2 = lan::install(
            &self.env,
            &ManagedFile {
                path: DAEMONS,
                content: render_daemons(&p),
                mode: 0o640,
                group: Some("frr"),
                check: None,
            },
        )?;
        if c1 || c2 {
            rep.applied(format!("wrote {CONF} and {DAEMONS}"));
        }
        let needed = p.bgp || p.ospf;
        if needed {
            lan::reconcile(&self.env, SERVICE, true, c1 || c2, CONF, &mut rep)?;
        } else if self.env.services.is_running(SERVICE) {
            self.env.services.restart(SERVICE)?;
            rep.applied("FRR restarted with no routing protocol enabled");
        }
        rep.applied(format!(
            "BGP {} ({} neighbour(s), {} network(s)), OSPF {} ({} interface(s))",
            if p.bgp { "on" } else { "off" },
            p.neighbors.len(),
            p.networks.len(),
            if p.ospf { "on" } else { "off" },
            p.ospf_ifaces.len()
        ));
        Ok(rep)
    }

    async fn render(&self, store: &ConfigStore) -> Result<String> {
        let p = plan(store).await?;
        if !p.bgp && !p.ospf {
            return Ok("# dynamic routing off\n".into());
        }
        Ok(format!(
            "## {CONF}\n{}\n## {DAEMONS}\n{}",
            render_conf(&p),
            render_daemons(&p)
        ))
    }

    async fn status(&self, store: &ConfigStore) -> Result<Value> {
        let p = plan(store).await?;
        let bgp = self
            .vtysh("show bgp summary json")
            .and_then(|t| serde_json::from_str::<Value>(&t).ok())
            .map(|j| parse_bgp_summary(&j))
            .unwrap_or_default();
        let ospf = self
            .vtysh("show ip ospf neighbor json")
            .and_then(|t| serde_json::from_str::<Value>(&t).ok())
            .unwrap_or(Value::Null);
        let bgp_routes = std::process::Command::new("ip")
            .args(["-4", "route", "show", "proto", "bgp"])
            .output()
            .map(|o| {
                String::from_utf8_lossy(&o.stdout)
                    .lines()
                    .map(String::from)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        Ok(json!({
            "bgp_enabled": p.bgp,
            "ospf_enabled": p.ospf,
            "installed": self.env.has_binary("/usr/lib/frr/zebra") || self.env.has_binary("/usr/sbin/zebra"),
            "running": self.env.services.is_running(SERVICE),
            "bgp_sessions": bgp,
            "ospf_neighbors": ospf,
            "kernel_bgp_routes": bgp_routes,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lan::testutil::{self, read};
    use crate::lan::ServiceControl;

    async fn add(s: &ConfigStore, coll: usize, body: Value) {
        svc::save_row(s, &SPEC.colls[coll], None, &body)
            .await
            .unwrap();
    }

    #[test]
    fn bgp_config_has_neighbours_networks_and_activation() {
        let p = Plan {
            bgp: true,
            asn: 65001,
            router_id: "10.0.0.1".into(),
            neighbors: vec![
                (
                    "203.0.113.1".into(),
                    65000,
                    "md5-secret".into(),
                    "isp".into(),
                ),
                ("2001:db8::1".into(), 65000, String::new(), String::new()),
            ],
            networks: vec!["192.168.50.0/24".into(), "2001:db8:50::/64".into()],
            ..Default::default()
        };
        let c = render_conf(&p);
        for want in [
            "router bgp 65001",
            "bgp router-id 10.0.0.1",
            "neighbor 203.0.113.1 remote-as 65000",
            "neighbor 203.0.113.1 description isp",
            "neighbor 203.0.113.1 password md5-secret",
            "address-family ipv4 unicast\n  network 192.168.50.0/24",
            "  neighbor 203.0.113.1 activate",
            "address-family ipv6 unicast\n  network 2001:db8:50::/64",
            "  neighbor 2001:db8::1 activate",
        ] {
            assert!(c.contains(want), "missing {want:?}\n{c}");
        }
        assert!(!c.contains("router ospf"));
        assert!(render_daemons(&p).contains("bgpd=yes\nospfd=no"));
    }

    #[test]
    fn ospf_is_configured_per_interface() {
        let p = Plan {
            ospf: true,
            router_id: "10.0.0.1".into(),
            ospf_ifaces: vec![
                ("rtr-lan".into(), "0.0.0.0".into(), true),
                ("rtr-wan".into(), "0.0.0.1".into(), false),
            ],
            ..Default::default()
        };
        let c = render_conf(&p);
        assert!(
            c.contains("interface rtr-lan\n ip ospf area 0.0.0.0\n ip ospf passive"),
            "{c}"
        );
        assert!(
            c.contains("interface rtr-wan\n ip ospf area 0.0.0.1\n!"),
            "{c}"
        );
        assert!(c.contains("router ospf\n ospf router-id 10.0.0.1"));
    }

    #[test]
    fn summary_json_is_flattened() {
        let j = json!({"ipv4Unicast": {"peers": {"203.0.113.1": {"remoteAs": 65000, "state": "Established", "pfxRcd": 2, "peerUptime": "00:00:10"}}}});
        let v = parse_bgp_summary(&j);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0]["state"], "Established");
        assert_eq!(v[0]["prefixes_received"], 2);
    }

    #[tokio::test]
    async fn written_to_frr_conf_and_service_restarted_only_on_change() {
        let t = testutil::env(&["/usr/lib/frr/zebra"]);
        let s = testutil::store().await;
        let a = FrrApplier::new(t.env.clone());
        a.apply(&s).await.unwrap();
        assert!(!t.env.has_binary(CONF));
        svc::put_settings(&s, &SPEC, &json!({"bgp_enabled": true}))
            .await
            .unwrap();
        assert!(a
            .apply(&s)
            .await
            .unwrap_err()
            .to_string()
            .contains("router ID"));
        svc::put_settings(&s, &SPEC, &json!({"router_id": "10.0.0.1"}))
            .await
            .unwrap();
        assert!(a
            .apply(&s)
            .await
            .unwrap_err()
            .to_string()
            .contains("neighbour"));
        for bad in [
            json!({"address": "x", "remote_as": 1}),
            json!({"address": "203.0.113.1", "remote_as": 0}),
            json!({"address": "203.0.113.1", "remote_as": 5, "description": "a b"}),
        ] {
            assert!(
                svc::save_row(&s, &SPEC.colls[0], None, &bad).await.is_err(),
                "{bad}"
            );
        }
        add(
            &s,
            0,
            json!({"address": "203.0.113.1", "remote_as": 65000, "password": "md5-secret-1"}),
        )
        .await;
        add(&s, 1, json!({"prefix": "192.168.50.0/24"})).await;
        a.apply(&s).await.unwrap();
        let c = read(&t, CONF);
        assert!(
            c.contains("neighbor 203.0.113.1 remote-as 65000")
                && c.contains("network 192.168.50.0/24"),
            "{c}"
        );
        assert!(read(&t, DAEMONS).contains("bgpd=yes"));
        assert!(t.services.is_running(SERVICE));
        let n = t.services.log.lock().unwrap().len();
        a.apply(&s).await.unwrap();
        assert_eq!(
            t.services.log.lock().unwrap().len(),
            n,
            "unchanged apply must not restart FRR"
        );
        // the password never leaves the store through the API representation
        let rows = svc::list_rows(&s, &SPEC.colls[0]).await.unwrap();
        assert_eq!(rows[0]["password"], json!(svc::SECRET_MASK));
    }
}
