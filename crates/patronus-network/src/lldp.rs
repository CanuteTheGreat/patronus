//! LLDP (USE=lldp): announce this router to its link neighbours and list the
//! neighbours it hears, like pfSense's `lldpd` package and the "Neighbors"
//! pages of OPNsense (os-lldpd), UniFi and OpenWrt (`lldpd`).
//!
//! The Link Layer Discovery Protocol (IEEE 802.1AB) is a layer-2 multicast
//! (ethertype 0x88cc, 01:80:c2:00:00:0e): each port announces the system name,
//! port name, capabilities and management address to the device on the other
//! end of the cable and learns the same from it. Switches and access points
//! show the router's name on the right port; the router page shows which
//! switch port every uplink or LAN cable ends on. Patronus runs `lldpd`
//! through the supervisor (`patronus-daemon@lldpd`, OpenRC and systemd) with a
//! generated command line and `lldpcli` config. Only the interfaces listed on
//! the page are given to the daemon (`-I`): the WAN side is never announced
//! unless it is listed. LLDP frames are not IP, so the packet filter never
//! sees them and no firewall rule is needed.
//!
//! The neighbour table is read live from the daemon's control socket
//! (`lldpcli show neighbors`, key/value format, which every lldpd build has)
//! as root through the apply broker; nothing about neighbours is stored.

use crate::lan::{self, invalid};
use crate::supervise::{which, Supervisor};
use crate::svc::{self, Coll, Field, Kind, Settings, Spec, Svc};
use async_trait::async_trait;
use patronus_config::applier::{Applier, ApplyReport, Phase};
use patronus_config::store::ConfigStore;
use patronus_core::{Error, Result};
use serde_json::{json, Map, Value};

pub const INSTANCE: &str = "lldpd";

const MODES: &[&str] = &["rx-and-tx", "rx-only", "tx-only", "disabled"];

static FIELDS: [Field; 11] = [
    Field::new("enabled", "LLDP", Kind::Bool).def("0"),
    Field::new("system_name", "System name", Kind::Host).help(
        "announced to neighbours; empty announces the router's host name",
    ),
    Field::new("tx_interval", "Announce every (seconds)", Kind::Int(1, 3600)).def("30"),
    Field::new("tx_hold", "Hold multiplier", Kind::Int(1, 100))
        .def("4")
        .help("neighbours forget this router after interval x multiplier seconds of silence"),
    Field::new("port_id", "Port ID is", Kind::Select(&["ifname", "macaddress"]))
        .def("ifname")
        .help("what the neighbour shows as this router's port: the interface name or its MAC address"),
    Field::new("hide_kernel", "Hide kernel version", Kind::Bool)
        .def("1")
        .help("do not announce the kernel release and machine type"),
    Field::new("med_inventory", "LLDP-MED inventory", Kind::Bool)
        .def("0")
        .help("announce hardware/software inventory TLVs (serial number, firmware); off keeps them private"),
    Field::new("cdp", "Cisco CDP", Kind::Bool)
        .def("0")
        .help("also speak and understand the Cisco Discovery Protocol"),
    Field::new("edp", "Extreme EDP", Kind::Bool)
        .def("0")
        .help("also speak and understand the Extreme Discovery Protocol"),
    Field::new("fdp", "Foundry FDP", Kind::Bool)
        .def("0")
        .help("also speak and understand the Foundry Discovery Protocol"),
    Field::new("sonmp", "Nortel SONMP", Kind::Bool)
        .def("0")
        .help("also speak and understand the Nortel Discovery Protocol"),
];

static IFACE_FIELDS: [Field; 4] = [
    Field::new("iface", "Interface", Kind::Iface)
        .req()
        .help("device or @wan / @lan / @optN: a port whose cable end should be announced and listened on"),
    Field::new("mode", "Mode", Kind::Select(MODES))
        .def("rx-and-tx")
        .help("announce and listen, listen only (stay silent), announce only, or off"),
    Field::new("enabled", "Enabled", Kind::Bool).def("1"),
    Field::new("description", "Description", Kind::Text),
];

static SPEC: Spec = Spec {
    slug: "lldp",
    title: "LLDP",
    blurb: "Announce this router to the switches, access points and servers on its cables (system \
            name, port, capabilities) and list the neighbours it hears back: which switch port \
            each interface is plugged into. Only the interfaces listed here take part (at least \
            one); the WAN side is never announced unless you list it. Runs lldpd; the neighbour \
            table below is read live from the daemon.",
    applier: "lldp",
    fields: &FIELDS,
    colls: &[Coll {
        key: "interfaces",
        title: "Interfaces",
        table: "lldp_interfaces",
        fields: &IFACE_FIELDS,
        unique: Some("iface"),
    }],
    actions: &[],
};

pub struct LldpSvc;

#[async_trait]
impl Svc for LldpSvc {
    fn spec(&self) -> &'static Spec {
        &SPEC
    }
}

/// Everything the generated files and the command line depend on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    /// Interface devices with their mode (deduplicated, in order).
    pub ports: Vec<(String, String)>,
    pub system_name: String,
    pub tx_interval: i64,
    pub tx_hold: i64,
    pub port_id: String,
    pub hide_kernel: bool,
    pub med_inventory: bool,
    pub cdp: bool,
    pub edp: bool,
    pub fdp: bool,
    pub sonmp: bool,
}

/// The enabled interfaces resolved to (device, mode).
pub async fn ports(store: &ConfigStore) -> Result<Vec<(String, String)>> {
    let mut out: Vec<(String, String)> = Vec::new();
    for r in svc::raw_rows(store, &SPEC.colls[0]).await? {
        if !lan::flag(r["enabled"].as_str().unwrap_or("")) {
            continue;
        }
        let mode = match r["mode"].as_str().unwrap_or("") {
            "" => "rx-and-tx",
            m => m,
        };
        for d in lan::resolve_iface(store, r["iface"].as_str().unwrap_or("")).await? {
            if !out.iter().any(|(x, _)| *x == d) {
                out.push((d, mode.to_string()));
            }
        }
    }
    Ok(out)
}

pub async fn plan(store: &ConfigStore) -> Result<Plan> {
    let s = Settings::load(store, &SPEC).await?;
    Ok(Plan {
        ports: ports(store).await?,
        system_name: s.s("system_name"),
        tx_interval: s.n("tx_interval"),
        tx_hold: s.n("tx_hold"),
        port_id: s.s("port_id"),
        hide_kernel: s.b("hide_kernel"),
        med_inventory: s.b("med_inventory"),
        cdp: s.b("cdp"),
        edp: s.b("edp"),
        fdp: s.b("fdp"),
        sonmp: s.b("sonmp"),
    })
}

/// The `lldpcli` commands lldpd runs at start (`-O`).
pub fn render_conf(p: &Plan) -> String {
    let mut c = lan::header("#", "lldpd (LLDP announce + neighbours)");
    c.push_str(&format!("configure lldp tx-interval {}\n", p.tx_interval));
    c.push_str(&format!("configure lldp tx-hold {}\n", p.tx_hold));
    c.push_str(&format!(
        "configure lldp portidsubtype {}\n",
        if p.port_id == "macaddress" {
            "macaddress"
        } else {
            "ifname"
        }
    ));
    if !p.system_name.is_empty() {
        c.push_str(&format!("configure system hostname {}\n", p.system_name));
    }
    for (dev, mode) in &p.ports {
        c.push_str(&format!("configure ports {dev} lldp status {mode}\n"));
    }
    c
}

/// lldpd command line (foreground, own control socket and pid file).
pub fn argv(bin: &str, p: &Plan, conf: &str, socket: &str, pidfile: &str) -> Vec<String> {
    let mut v: Vec<String> = vec![
        bin.into(),
        "-d".into(),
        "-u".into(),
        socket.into(),
        "-p".into(),
        pidfile.into(),
        "-O".into(),
        conf.into(),
        "-I".into(),
        p.ports
            .iter()
            .map(|(d, _)| d.as_str())
            .collect::<Vec<_>>()
            .join(","),
    ];
    if p.hide_kernel {
        v.push("-k".into());
    }
    if !p.med_inventory {
        v.push("-i".into());
    }
    for (on, flag) in [(p.cdp, "-c"), (p.edp, "-e"), (p.fdp, "-f"), (p.sonmp, "-s")] {
        if on {
            v.push(flag.into());
        }
    }
    v
}

/// Chassis / port ID sub-types as `lldpcli -f keyvalue` names them.
const ID_TYPES: &[&str] = &[
    "mac",
    "ip",
    "ifname",
    "ifalias",
    "local",
    "portcomp",
    "chassis-component",
    "agent",
    "unhandled",
];

/// Parse `lldpcli -f keyvalue show neighbors details` into one object per
/// neighbour: `interface, protocol, age, chassis_id, system_name,
/// system_description, management, capabilities, port_id, port_description,
/// ttl`. A neighbour starts at its `via` line.
pub fn parse_neighbors(text: &str) -> Vec<Value> {
    let mut out: Vec<Map<String, Value>> = Vec::new();
    let mut cur: Option<(String, Map<String, Value>)> = None;
    let flush = |cur: &mut Option<(String, Map<String, Value>)>, out: &mut Vec<Map<String, Value>>| {
        if let Some((_, m)) = cur.take() {
            out.push(m);
        }
    };
    for line in text.lines() {
        let Some(rest) = line.strip_prefix("lldp.") else {
            continue;
        };
        let Some((key, val)) = rest.split_once('=') else {
            continue;
        };
        // interface names may contain dots (VLANs): split at the first
        // `.via` / `.rid` / `.age` / `.chassis.` / `.port.`
        let (iface, field) = if let Some(i) = key.find(".chassis.") {
            (&key[..i], format!("chassis.{}", &key[i + 9..]))
        } else if let Some(i) = key.find(".port.") {
            (&key[..i], format!("port.{}", &key[i + 6..]))
        } else if let Some((i, f)) = ["via", "rid", "age"]
            .iter()
            .find_map(|f| key.strip_suffix(&format!(".{f}")).map(|i| (i, *f)))
        {
            (i, f.to_string())
        } else {
            continue;
        };
        // lldpcli prints `via` first for every neighbour
        if field == "via" || cur.as_ref().map(|(i, _)| i != iface).unwrap_or(true) {
            flush(&mut cur, &mut out);
            let mut m = Map::new();
            m.insert("interface".into(), json!(iface));
            cur = Some((iface.to_string(), m));
        }
        let Some((_, m)) = cur.as_mut() else { continue };
        let set = |m: &mut Map<String, Value>, k: &str, v: &str| {
            m.insert(k.into(), Value::String(v.to_string()));
        };
        match field.as_str() {
            "via" => set(m, "protocol", val),
            "age" => set(m, "age", val),
            "chassis.name" => set(m, "system_name", val),
            "chassis.descr" => set(m, "system_description", val),
            "chassis.mgmt-ip" => {
                let old = m
                    .get("management")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string();
                set(
                    m,
                    "management",
                    &if old.is_empty() {
                        val.to_string()
                    } else {
                        format!("{old}, {val}")
                    },
                );
            }
            "port.descr" => set(m, "port_description", val),
            "port.ttl" => set(m, "ttl", val),
            f if f.starts_with("chassis.") && f.ends_with(".enabled") => {
                if val == "on" {
                    let cap = &f[8..f.len() - 8];
                    let old = m
                        .get("capabilities")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string();
                    set(
                        m,
                        "capabilities",
                        &if old.is_empty() {
                            cap.to_string()
                        } else {
                            format!("{old}, {cap}")
                        },
                    );
                }
            }
            f if f.starts_with("chassis.") && ID_TYPES.contains(&&f[8..]) => {
                set(m, "chassis_id", val)
            }
            f if f.starts_with("port.") && ID_TYPES.contains(&&f[5..]) => set(m, "port_id", val),
            _ => {}
        }
    }
    flush(&mut cur, &mut out);
    out.into_iter().map(Value::Object).collect()
}

#[derive(Clone)]
pub struct LldpApplier {
    sup: Supervisor,
}

impl Default for LldpApplier {
    fn default() -> Self {
        Self {
            sup: Supervisor::detect(),
        }
    }
}

impl LldpApplier {
    pub fn with_supervisor(sup: Supervisor) -> Self {
        Self { sup }
    }

    fn conf_path(&self) -> std::path::PathBuf {
        self.sup.paths.state_dir.join("lldpd.conf")
    }

    fn socket(&self) -> std::path::PathBuf {
        self.sup.paths.run_dir.join("lldpd.socket")
    }

    fn pidfile(&self) -> std::path::PathBuf {
        self.sup.paths.run_dir.join("lldpd.pid")
    }

    /// Neighbour table from the running daemon (empty when it is not running).
    fn neighbors(&self) -> Vec<Value> {
        let Some(cli) = which("lldpcli") else {
            return Vec::new();
        };
        let o = std::process::Command::new(cli)
            .arg("-u")
            .arg(self.socket())
            .args(["-f", "keyvalue", "show", "neighbors", "details"])
            .output();
        match o {
            Ok(o) if o.status.success() => parse_neighbors(&String::from_utf8_lossy(&o.stdout)),
            _ => Vec::new(),
        }
    }
}

#[async_trait]
impl Applier for LldpApplier {
    fn name(&self) -> &'static str {
        "lldp"
    }

    fn phase(&self) -> Phase {
        Phase::Services
    }

    async fn apply(&self, store: &ConfigStore) -> Result<ApplyReport> {
        let mut rep = ApplyReport::default();
        let s = Settings::load(store, &SPEC).await?;
        if !s.b("enabled") {
            if self.sup.stop(svc::DAEMON_SERVICE, INSTANCE).await? {
                rep.applied("LLDP stopped");
            } else {
                rep.applied("LLDP is off");
            }
            return Ok(rep);
        }
        let p = plan(store).await?;
        if p.ports.is_empty() {
            return Err(invalid(
                "LLDP: list at least one interface (assigned to a device) to announce on",
            ));
        }
        let bin = which("lldpd").ok_or_else(|| {
            Error::Service(
                "LLDP needs lldpd, which is not installed (emerge net-misc/lldpd, USE=lldp)".into(),
            )
        })?;
        std::fs::create_dir_all(&self.sup.paths.run_dir)
            .map_err(|e| Error::Network(format!("{}: {e}", self.sup.paths.run_dir.display())))?;
        let conf = self.conf_path();
        let started = svc::ensure_daemon(
            &self.sup,
            INSTANCE,
            argv(
                &bin.to_string_lossy(),
                &p,
                &conf.to_string_lossy(),
                &self.socket().to_string_lossy(),
                &self.pidfile().to_string_lossy(),
            ),
            vec![(conf, render_conf(&p), 0o644)],
        )
        .await?;
        rep.applied(format!(
            "LLDP {} on {}",
            if started {
                "(re)started"
            } else {
                "running, unchanged,"
            },
            p.ports
                .iter()
                .map(|(d, _)| d.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ));
        Ok(rep)
    }

    async fn render(&self, store: &ConfigStore) -> Result<String> {
        let s = Settings::load(store, &SPEC).await?;
        if !s.b("enabled") {
            return Ok("# LLDP off\n".into());
        }
        let p = plan(store).await?;
        Ok(format!(
            "## lldpd command line\nlldpd {}\n\n## lldpd.conf\n{}",
            argv("", &p, "lldpd.conf", "lldpd.socket", "lldpd.pid")[1..].join(" "),
            render_conf(&p)
        ))
    }

    async fn status(&self, store: &ConfigStore) -> Result<Value> {
        let s = Settings::load(store, &SPEC).await?;
        let running = self.sup.is_running(svc::DAEMON_SERVICE, INSTANCE);
        let neighbors = if running { self.neighbors() } else { Vec::new() };
        Ok(json!({
            "enabled": s.b("enabled"),
            "installed": which("lldpd").is_some(),
            "running": running,
            "interfaces": ports(store).await.unwrap_or_default().into_iter().map(|(d, m)| format!("{d} ({m})")).collect::<Vec<_>>(),
            "neighbor_count": neighbors.len(),
            "neighbors": neighbors,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::supervise::{InitMode, NetPaths};

    fn plan_of(ports: &[(&str, &str)]) -> Plan {
        Plan {
            ports: ports
                .iter()
                .map(|(d, m)| (d.to_string(), m.to_string()))
                .collect(),
            system_name: String::new(),
            tx_interval: 30,
            tx_hold: 4,
            port_id: "ifname".into(),
            hide_kernel: true,
            med_inventory: false,
            cdp: false,
            edp: false,
            fdp: false,
            sonmp: false,
        }
    }

    #[test]
    fn config_and_command_line() {
        let mut p = plan_of(&[("rtr-lan", "rx-and-tx"), ("rtr-opt1", "rx-only")]);
        p.system_name = "edge1".into();
        p.tx_interval = 10;
        p.cdp = true;
        let c = render_conf(&p);
        assert!(c.contains("configure lldp tx-interval 10\n"));
        assert!(c.contains("configure lldp tx-hold 4\n"));
        assert!(c.contains("configure lldp portidsubtype ifname\n"));
        assert!(c.contains("configure system hostname edge1\n"));
        assert!(c.contains("configure ports rtr-lan lldp status rx-and-tx\n"));
        assert!(c.contains("configure ports rtr-opt1 lldp status rx-only\n"));
        assert!(c.lines().take(3).any(|l| l.contains(lan::MARKER)));
        let a = argv("/usr/sbin/lldpd", &p, "/c", "/s", "/p");
        assert_eq!(a[0], "/usr/sbin/lldpd");
        assert_eq!(a[1], "-d");
        let i = a.iter().position(|x| x == "-I").unwrap();
        assert_eq!(a[i + 1], "rtr-lan,rtr-opt1");
        assert!(a.contains(&"-k".to_string()), "kernel hidden");
        assert!(a.contains(&"-i".to_string()), "inventory off");
        assert!(a.contains(&"-c".to_string()) && !a.contains(&"-e".to_string()));
        // no host name set: the daemon's own is announced
        let q = plan_of(&[("a", "rx-and-tx")]);
        assert!(!render_conf(&q).contains("configure system hostname"));
        p.med_inventory = true;
        p.hide_kernel = false;
        let a = argv("lldpd", &p, "/c", "/s", "/p");
        assert!(!a.contains(&"-i".to_string()) && !a.contains(&"-k".to_string()));
    }

    const SAMPLE: &str = "\
lldp.eth0.via=LLDP
lldp.eth0.rid=1
lldp.eth0.age=0 day, 00:00:12
lldp.eth0.chassis.mac=02:00:00:00:00:02
lldp.eth0.chassis.name=core-switch
lldp.eth0.chassis.descr=Switch OS 1.2
lldp.eth0.chassis.mgmt-ip=192.0.2.2
lldp.eth0.chassis.mgmt-ip=2001:db8::2
lldp.eth0.chassis.Bridge.enabled=on
lldp.eth0.chassis.Router.enabled=off
lldp.eth0.port.ifname=Gi1/0/7
lldp.eth0.port.descr=uplink to router
lldp.eth0.port.ttl=120
lldp.eth0.10.via=CDPv2
lldp.eth0.10.rid=2
lldp.eth0.10.age=0 day, 00:01:00
lldp.eth0.10.chassis.local=sw2
lldp.eth0.10.chassis.name=sw2
lldp.eth0.10.port.local=42
lldp.eth0.10.port.ttl=180
";

    #[test]
    fn parses_lldpcli_keyvalue_neighbors() {
        let n = parse_neighbors(SAMPLE);
        assert_eq!(n.len(), 2, "{n:?}");
        assert_eq!(n[0]["interface"], "eth0");
        assert_eq!(n[0]["protocol"], "LLDP");
        assert_eq!(n[0]["chassis_id"], "02:00:00:00:00:02");
        assert_eq!(n[0]["system_name"], "core-switch");
        assert_eq!(n[0]["system_description"], "Switch OS 1.2");
        assert_eq!(n[0]["management"], "192.0.2.2, 2001:db8::2");
        assert_eq!(n[0]["capabilities"], "Bridge");
        assert_eq!(n[0]["port_id"], "Gi1/0/7");
        assert_eq!(n[0]["port_description"], "uplink to router");
        assert_eq!(n[0]["ttl"], "120");
        // a VLAN device name keeps its dot
        assert_eq!(n[1]["interface"], "eth0.10");
        assert_eq!(n[1]["protocol"], "CDPv2");
        assert_eq!(n[1]["chassis_id"], "sw2");
        assert_eq!(n[1]["port_id"], "42");
        assert!(parse_neighbors("").is_empty());
        assert!(parse_neighbors("garbage\nlldp.noequals\n").is_empty());
    }

    #[tokio::test]
    async fn needs_an_interface_and_the_daemon() {
        let s = crate::lan::testutil::store().await;
        let d = tempfile::tempdir().unwrap();
        let a = LldpApplier::with_supervisor(Supervisor::new(
            InitMode::Direct,
            NetPaths::under(d.path()),
        ));
        // off: nothing to do, and the page text says so
        assert!(a.apply(&s).await.is_ok());
        assert!(a.render(&s).await.unwrap().contains("LLDP off"));
        svc::put_settings(&s, &SPEC, &json!({"enabled": true}))
            .await
            .unwrap();
        let e = a.apply(&s).await.unwrap_err();
        assert!(e.to_string().contains("at least one interface"), "{e}");
        // values are validated before they can reach a config
        for bad in [
            json!({"iface": "lan;x"}),
            json!({"iface": "@lan", "mode": "both"}),
        ] {
            assert!(svc::save_row(&s, &SPEC.colls[0], None, &bad).await.is_err());
        }
        assert!(
            svc::put_settings(&s, &SPEC, &json!({"tx_interval": 0}))
                .await
                .is_err()
        );
        assert!(
            svc::put_settings(&s, &SPEC, &json!({"system_name": "a b\nc"}))
                .await
                .is_err()
        );
        svc::save_row(
            &s,
            &SPEC.colls[0],
            None,
            &json!({"iface": "eth9", "mode": "rx-only"}),
        )
        .await
        .unwrap();
        assert!(
            svc::save_row(&s, &SPEC.colls[0], None, &json!({"iface": "eth9"}))
                .await
                .is_err(),
            "the same interface twice is refused"
        );
        let r = a.render(&s).await.unwrap();
        assert!(r.contains("-I eth9"), "{r}");
        assert!(r.contains("configure ports eth9 lldp status rx-only"), "{r}");
        // a disabled row is not given to the daemon
        svc::save_row(
            &s,
            &SPEC.colls[0],
            None,
            &json!({"iface": "eth8", "enabled": false}),
        )
        .await
        .unwrap();
        let r = a.render(&s).await.unwrap();
        assert!(!r.contains("eth8"), "{r}");
        // status of a stopped daemon: no neighbours, not an error
        let st = a.status(&s).await.unwrap();
        assert_eq!(st["running"], false);
        assert_eq!(st["neighbor_count"], 0);
    }
}
