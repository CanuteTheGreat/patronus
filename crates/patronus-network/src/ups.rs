//! UPS support (USE=ups) through NUT, the Network UPS Tools: a driver
//! (`usbhid-ups`, `snmp-ups`, `apcsmart`, `dummy-ups`) talks to the UPS,
//! `upsd` serves its readings, `upsmon` watches them and runs the shutdown
//! command when the battery is about to run out.
//!
//! Patronus renders every NUT config file from typed settings (`ups.*`),
//! writes them to a state directory of its own (`NUT_CONFPATH`, readable by
//! the NUT user and nobody else) and runs the three daemons through the
//! supervisor (`patronus-daemon@nut-driver|nut-upsd|nut-upsmon`) on OpenRC
//! and systemd alike. Nothing is written to /etc/nut.
//!
//! Modes (`nut.conf` MODE): `standalone` (one box, upsd on loopback),
//! `netserver` (upsd also listens on the LAN interface's own addresses, never
//! on 0.0.0.0, so other hosts can monitor the UPS and the firewall opens the
//! port on the LAN only) and `netclient` (no local UPS: upsmon follows the
//! UPS of another NUT server).
//!
//! Low-battery policy: NUT's own flag (`LB`), a time on battery
//! (`upssched` timer that forces the shutdown), or a charge threshold
//! (driver `ignorelb` + `override.battery.charge.low`, usbhid-ups only).
//! `SHUTDOWNCMD` is the typed key `ups.shutdown_command` (default: the
//! Patronus power-off request); tests point it at a script that writes a
//! marker file, so a shutdown is asserted, never executed.
//!
//! The readings (`upsc` output) are parsed by pure functions below; the web
//! crate records them (`ups_samples`) and raises the power events.

use crate::lan::{self, invalid, AddrSource, IfAddr, LiveAddrs};
use crate::supervise::{which, Supervisor};
use crate::svc::{self, Field, Kind, Settings, Spec, Svc};
use async_trait::async_trait;
use patronus_config::applier::{Applier, ApplyReport, Phase};
use patronus_config::store::ConfigStore;
use patronus_core::{Error, Result};
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

pub const DRIVER_INSTANCE: &str = "nut-driver";
pub const UPSD_INSTANCE: &str = "nut-upsd";
pub const UPSMON_INSTANCE: &str = "nut-upsmon";
pub const INSTANCES: [&str; 3] = [DRIVER_INSTANCE, UPSD_INSTANCE, UPSMON_INSTANCE];

/// The Gentoo atom that provides the daemons (and the `ups` USE flag's RDEPEND).
pub const NUT_ATOM: &str = "sys-power/nut";

pub const DRIVERS: &[&str] = &["usbhid-ups", "snmp-ups", "apcsmart", "dummy-ups"];
pub const MODES: &[&str] = &["standalone", "netserver", "netclient"];
pub const POLICIES: &[&str] = &["on_low_battery", "after_on_battery", "charge_below"];

/// Where NUT's programs live (drivers are in a private directory that
/// differs between distributions).
const BIN_DIRS: &[&str] = &[
    "/usr/lib/nut",
    "/lib/nut",
    "/usr/libexec/nut",
    "/usr/lib64/nut",
    "/usr/sbin",
    "/sbin",
    "/usr/bin",
    "/bin",
    "/usr/local/sbin",
    "/usr/local/bin",
];

static FIELDS: [Field; 21] = [
    Field::new("enabled", "UPS monitoring", Kind::Bool).def("0"),
    Field::new("mode", "Mode", Kind::Select(MODES))
        .def("standalone")
        .help("standalone: this router's own UPS; netserver: also share it with LAN hosts; netclient: follow the UPS of another NUT server"),
    Field::new("driver", "UPS driver", Kind::Select(DRIVERS))
        .def("usbhid-ups")
        .help("usbhid-ups: USB; snmp-ups: network card; apcsmart: serial APC; dummy-ups: scripted test UPS"),
    Field::new("ups_name", "UPS name", Kind::Token)
        .def("ups")
        .help("the name clients use (ups@router)"),
    Field::new("port", "Port / device", Kind::Token)
        .def("auto")
        .help("usbhid-ups: auto; apcsmart: serial device such as /dev/ttyS0; dummy-ups: path of the .dev script; snmp-ups: the SNMP host below is used"),
    Field::new("snmp_host", "SNMP host", Kind::Host).help("snmp-ups only: the UPS network card"),
    Field::new("snmp_community", "SNMP community", Kind::Secret)
        .help("snmp-ups only: read community (8 or more characters); never shown again"),
    Field::new("snmp_version", "SNMP version", Kind::Select(&["v1", "v2c"])).def("v2c"),
    Field::new("server", "NUT server", Kind::Host)
        .help("netclient only: the host whose upsd serves the UPS"),
    Field::new("server_port", "NUT server port", Kind::Int(1, 65535)).def("3493"),
    Field::new("listen_iface", "Share on", Kind::Iface)
        .def("@lan")
        .help("netserver only: upsd listens on this interface's own addresses, never on all"),
    Field::new("listen_port", "NUT port", Kind::Int(1, 65535)).def("3493"),
    Field::new("monitor_user", "Monitor user", Kind::Token).def("patronus-mon"),
    Field::new("monitor_password", "Monitor password", Kind::Secret).help(
        "generated when empty; never shown again. netclient: the password the NUT server expects",
    ),
    Field::new("shutdown_policy", "Shut down", Kind::Select(POLICIES))
        .def("on_low_battery")
        .help("on_low_battery: when the UPS reports a low battery; after_on_battery: after the time below on battery; charge_below: when the charge falls under the percentage below (usbhid-ups)"),
    Field::new("shutdown_after_secs", "Seconds on battery", Kind::Int(10, 86400)).def("300"),
    Field::new("shutdown_charge_pct", "Charge threshold (%)", Kind::Int(1, 99)).def("20"),
    Field::new("shutdown_command", "Shutdown command", Kind::Text)
        .def(DEFAULT_SHUTDOWN)
        .help("absolute program and plain arguments (letters, digits, . _ / : = @ + - and spaces)"),
    Field::new("poll_secs", "Poll interval (s)", Kind::Int(1, 60)).def("5"),
    Field::new("retention_days", "Keep history (days)", Kind::Int(1, 365)).def("30"),
    Field::new("run_user", "NUT system user", Kind::Token)
        .def("nut")
        .help("the unprivileged account the NUT daemons run as"),
];

/// The Patronus command that powers the router off through the init system.
pub const DEFAULT_SHUTDOWN: &str = "/usr/bin/patronus poweroff-request";

static SPEC: Spec = Spec {
    slug: "ups",
    title: "UPS (NUT)",
    blurb:
        "Watch an uninterruptible power supply with NUT: charge, runtime and load, events when the \
            power fails and returns, and a clean shutdown before the battery runs out. The UPS can \
            be shared with other hosts on the LAN.",
    applier: "ups",
    fields: &FIELDS,
    colls: &[],
    actions: &[],
};

pub struct UpsSvc;

#[async_trait]
impl Svc for UpsSvc {
    fn spec(&self) -> &'static Spec {
        &SPEC
    }

    async fn put(&self, store: &ConfigStore, body: &Value) -> Result<()> {
        if let Some(c) = body.get("shutdown_command") {
            if let Some(s) = c.as_str() {
                if !s.trim().is_empty() {
                    check_shutdown_command(s)?;
                }
            }
        }
        svc::put_settings(store, &SPEC, body).await
    }
}

/// A command line that is safe inside a quoted NUT config value: an absolute
/// program, then plain words. No quotes, no shell metacharacters.
pub fn check_shutdown_command(s: &str) -> Result<String> {
    let t = s.trim();
    let ok_char = |c: char| c.is_ascii_alphanumeric() || " ._/:=@+-".contains(c);
    if t.is_empty() || t.len() > 160 || !t.chars().all(ok_char) || !t.starts_with('/') {
        return Err(invalid(
            "shutdown command (an absolute program path, then plain arguments: letters, digits and . _ / : = @ + - only)",
        ));
    }
    Ok(t.split_whitespace().collect::<Vec<_>>().join(" "))
}

// ---------------------------------------------------------------------------
// typed configuration
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cfg {
    pub enabled: bool,
    pub mode: String,
    pub driver: String,
    pub ups_name: String,
    pub port: String,
    pub snmp_host: String,
    pub snmp_community: String,
    pub snmp_version: String,
    pub server: String,
    pub server_port: u16,
    pub listen_iface: String,
    pub listen_port: u16,
    pub monitor_user: String,
    pub monitor_password: String,
    pub policy: String,
    pub after_secs: i64,
    pub charge_pct: i64,
    pub shutdown_command: String,
    pub poll_secs: i64,
    pub retention_days: i64,
    pub run_user: String,
}

impl Cfg {
    pub fn from_settings(s: &Settings) -> Self {
        let cmd = s.s("shutdown_command");
        Self {
            enabled: s.b("enabled"),
            mode: s.s("mode"),
            driver: s.s("driver"),
            ups_name: s.s("ups_name"),
            port: s.s("port"),
            snmp_host: s.s("snmp_host"),
            snmp_community: s.s("snmp_community"),
            snmp_version: s.s("snmp_version"),
            server: s.s("server"),
            server_port: s.n("server_port") as u16,
            listen_iface: s.s("listen_iface"),
            listen_port: s.n("listen_port") as u16,
            monitor_user: s.s("monitor_user"),
            monitor_password: s.s("monitor_password"),
            policy: s.s("shutdown_policy"),
            after_secs: s.n("shutdown_after_secs"),
            charge_pct: s.n("shutdown_charge_pct"),
            shutdown_command: if cmd.is_empty() {
                DEFAULT_SHUTDOWN.into()
            } else {
                cmd
            },
            poll_secs: s.n("poll_secs"),
            retention_days: s.n("retention_days"),
            run_user: s.s("run_user"),
        }
    }

    pub async fn load(store: &ConfigStore) -> Result<Self> {
        Ok(Self::from_settings(&Settings::load(store, &SPEC).await?))
    }

    /// Does this mode run a local UPS driver and upsd?
    pub fn local_ups(&self) -> bool {
        self.mode != "netclient"
    }

    /// The `upsc` target (host, port, UPS name): the local upsd, or the
    /// remote server in netclient mode.
    pub fn target(&self) -> (String, u16, String) {
        if self.mode == "netclient" {
            (self.server.clone(), self.server_port, self.ups_name.clone())
        } else {
            ("127.0.0.1".into(), self.listen_port, self.ups_name.clone())
        }
    }

    /// Everything that cannot be checked field by field.
    pub fn validate(&self) -> Result<()> {
        check_shutdown_command(&self.shutdown_command)?;
        if self.local_ups() {
            if !DRIVERS.contains(&self.driver.as_str()) {
                return Err(invalid(format!("UPS driver {:?}", self.driver)));
            }
            if self.driver == "snmp-ups" {
                if self.snmp_host.is_empty() {
                    return Err(invalid("UPS: snmp-ups needs the SNMP host of the UPS"));
                }
                if self.snmp_community.is_empty() {
                    return Err(invalid(
                        "UPS: snmp-ups needs the SNMP community (8 or more characters)",
                    ));
                }
            } else if self.port.is_empty() {
                return Err(invalid("UPS: the port / device is required"));
            }
            if self.policy == "charge_below" && self.driver != "usbhid-ups" {
                return Err(invalid(
                    "UPS: shutting down below a charge percentage needs the usbhid-ups driver (the others cannot apply it); use on_low_battery or after_on_battery",
                ));
            }
        } else {
            if self.server.is_empty() {
                return Err(invalid("UPS: netclient mode needs the NUT server host"));
            }
            if self.monitor_password.is_empty() {
                return Err(invalid(
                    "UPS: netclient mode needs the monitor user's password on the NUT server",
                ));
            }
            if self.policy == "charge_below" {
                return Err(invalid(
                    "UPS: a netclient cannot change the server's low-battery threshold; use on_low_battery or after_on_battery",
                ));
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// config rendering (pure)
// ---------------------------------------------------------------------------

/// Where the generated files go.
#[derive(Debug, Clone)]
pub struct Dirs {
    /// `NUT_CONFPATH`
    pub conf: PathBuf,
    /// `NUT_STATEPATH`: driver sockets, upssched pipe, power-down flag
    pub state: PathBuf,
}

impl Dirs {
    pub fn under(sup: &Supervisor) -> Self {
        Self {
            conf: sup.paths.state_dir.join("nut"),
            state: sup.paths.run_dir.join("nut"),
        }
    }
}

fn banner(what: &str) -> String {
    lan::header("#", what)
}

pub fn nut_conf(c: &Cfg) -> String {
    let mut s = banner("nut.conf");
    s.push_str(&format!("MODE={}\n", c.mode));
    s
}

pub fn ups_conf(c: &Cfg) -> String {
    let mut s = banner("ups.conf");
    s.push_str("maxretry = 3\n\n");
    s.push_str(&format!("[{}]\n", c.ups_name));
    s.push_str(&format!("\tdriver = {}\n", c.driver));
    if c.driver == "snmp-ups" {
        s.push_str(&format!("\tport = {}\n", c.snmp_host));
        s.push_str(&format!("\tcommunity = {}\n", c.snmp_community));
        s.push_str(&format!("\tsnmp_version = {}\n", c.snmp_version));
    } else {
        s.push_str(&format!("\tport = {}\n", c.port));
    }
    s.push_str(&format!("\tpollinterval = {}\n", c.poll_secs.max(1)));
    s.push_str("\tdesc = \"Patronus UPS\"\n");
    if c.policy == "charge_below" && c.driver == "usbhid-ups" {
        s.push_str("\tignorelb\n");
        s.push_str(&format!(
            "\toverride.battery.charge.low = {}\n",
            c.charge_pct
        ));
        s.push_str("\toverride.battery.runtime.low = 0\n");
    }
    s
}

/// `LISTEN` addresses of upsd: loopback always; in netserver mode also the
/// addresses configured on the LAN devices (global IPv6 and IPv4, never
/// link-local, never a wildcard).
pub fn listen_addrs(c: &Cfg, addrs: &[IfAddr], devices: &[String]) -> Vec<IpAddr> {
    let mut v: Vec<IpAddr> = vec!["127.0.0.1".parse().unwrap()];
    if c.mode == "netserver" {
        for a in addrs {
            if !devices.contains(&a.ifname) || a.addr.is_unspecified() || a.addr.is_loopback() {
                continue;
            }
            let ok = match a.addr {
                IpAddr::V4(_) => true,
                IpAddr::V6(_) => a.is_global_v6(),
            };
            if ok && !v.contains(&a.addr) {
                v.push(a.addr);
            }
        }
    }
    v
}

pub fn upsd_conf(c: &Cfg, listen: &[IpAddr]) -> String {
    let mut s = banner("upsd.conf");
    s.push_str("MAXAGE 15\n");
    for a in listen {
        s.push_str(&format!("LISTEN {a} {}\n", c.listen_port));
    }
    s
}

/// `upsd.users`: one account, the one upsmon logs in with. `mask` hides the
/// password (for the dry-run / render view).
pub fn upsd_users(c: &Cfg, mask: bool) -> String {
    let mut s = banner("upsd.users");
    s.push_str(&format!("[{}]\n", c.monitor_user));
    s.push_str(&format!(
        "\tpassword = {}\n",
        if mask {
            svc::SECRET_MASK
        } else {
            &c.monitor_password
        }
    ));
    s.push_str("\tupsmon primary\n");
    s
}

fn quote(s: &str) -> String {
    format!("\"{s}\"")
}

pub fn upsmon_conf(c: &Cfg, dirs: &Dirs, upssched: Option<&Path>, mask: bool) -> String {
    let mut s = banner("upsmon.conf");
    let (host, port, name) = c.target();
    let role = if c.mode == "netclient" {
        "secondary"
    } else {
        "primary"
    };
    let pw = if mask {
        svc::SECRET_MASK.to_string()
    } else {
        c.monitor_password.clone()
    };
    s.push_str(&format!(
        "MONITOR {name}@{host}:{port} 1 {} {pw} {role}\n",
        c.monitor_user
    ));
    s.push_str("MINSUPPLIES 1\n");
    s.push_str(&format!("SHUTDOWNCMD {}\n", quote(&c.shutdown_command)));
    s.push_str(&format!(
        "POLLFREQ {}\nPOLLFREQALERT {}\n",
        c.poll_secs, c.poll_secs
    ));
    s.push_str("HOSTSYNC 15\nDEADTIME 15\nFINALDELAY 5\n");
    s.push_str(&format!(
        "POWERDOWNFLAG {}\n",
        dirs.state.join("killpower").display()
    ));
    s.push_str(&format!("RUN_AS_USER {}\n", c.run_user));
    if let (Some(up), "after_on_battery") = (upssched, c.policy.as_str()) {
        s.push_str(&format!("NOTIFYCMD {}\n", up.display()));
        s.push_str("NOTIFYFLAG ONBATT SYSLOG+EXEC\nNOTIFYFLAG ONLINE SYSLOG+EXEC\n");
    }
    s
}

pub fn upssched_conf(c: &Cfg, dirs: &Dirs, cmd_script: &Path) -> String {
    let mut s = banner("upssched.conf");
    s.push_str(&format!("CMDSCRIPT {}\n", cmd_script.display()));
    s.push_str(&format!(
        "PIPEFN {}\nLOCKFN {}\n",
        dirs.state.join("upssched.pipe").display(),
        dirs.state.join("upssched.lock").display()
    ));
    s.push_str(&format!(
        "AT ONBATT * START-TIMER onbatt-fsd {}\n",
        c.after_secs
    ));
    s.push_str("AT ONLINE * CANCEL-TIMER onbatt-fsd\n");
    s
}

/// The script upssched runs when the on-battery timer fires: force the
/// shutdown sequence (`upsmon -c fsd` makes upsmon run SHUTDOWNCMD).
pub fn upssched_script(upsmon: &Path) -> String {
    format!(
        "#!/bin/sh\n# {} (upssched command script)\ncase \"$1\" in\n  onbatt-fsd) exec {} -c fsd ;;\nesac\nexit 0\n",
        lan::MARKER,
        upsmon.display()
    )
}

// ---------------------------------------------------------------------------
// reading UPS data (pure parsers over `upsc` output)
// ---------------------------------------------------------------------------

/// `variable: value` lines of `upsc ups@host`.
pub fn parse_upsc(text: &str) -> BTreeMap<String, String> {
    let mut m = BTreeMap::new();
    for l in text.lines() {
        if l.starts_with("Error:") || l.starts_with("Init SSL") {
            continue;
        }
        if let Some((k, v)) = l.split_once(": ") {
            let k = k.trim();
            if !k.is_empty() && !k.contains(' ') {
                m.insert(k.to_string(), v.trim().to_string());
            }
        } else if let Some(k) = l.strip_suffix(':') {
            if !k.contains(' ') && !k.is_empty() {
                m.insert(k.to_string(), String::new());
            }
        }
    }
    m
}

/// UPS names of `upsc -l host`.
pub fn parse_upsc_list(text: &str) -> Vec<String> {
    text.lines()
        .map(str::trim)
        .filter(|l| {
            !l.is_empty()
                && !l.starts_with("Error:")
                && !l.starts_with("Init SSL")
                && !l.contains(' ')
        })
        .map(String::from)
        .collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PowerState {
    Online,
    OnBattery,
    LowBattery,
    Unknown,
}

impl PowerState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Online => "online",
            Self::OnBattery => "on_battery",
            Self::LowBattery => "low_battery",
            Self::Unknown => "unknown",
        }
    }
}

/// What the status card shows.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Snapshot {
    pub model: Option<String>,
    pub manufacturer: Option<String>,
    pub serial: Option<String>,
    /// raw `ups.status` words: OL, OB, LB, RB, CHRG, DISCHRG, ...
    pub flags: Vec<String>,
    pub state: PowerState,
    pub replace_battery: bool,
    pub charge_pct: Option<f64>,
    pub runtime_secs: Option<i64>,
    pub load_pct: Option<f64>,
    pub input_voltage: Option<f64>,
    pub output_voltage: Option<f64>,
    pub battery_voltage: Option<f64>,
}

fn num(m: &BTreeMap<String, String>, k: &str) -> Option<f64> {
    m.get(k)
        .and_then(|v| v.parse::<f64>().ok())
        .filter(|v| v.is_finite())
}

pub fn snapshot(m: &BTreeMap<String, String>) -> Snapshot {
    let flags: Vec<String> = m
        .get("ups.status")
        .map(|s| s.split_whitespace().map(String::from).collect())
        .unwrap_or_default();
    let has = |f: &str| flags.iter().any(|x| x == f);
    let state = if has("OB") && has("LB") {
        PowerState::LowBattery
    } else if has("OB") {
        PowerState::OnBattery
    } else if has("OL") {
        PowerState::Online
    } else {
        PowerState::Unknown
    };
    let text = |k: &str| m.get(k).filter(|v| !v.is_empty()).cloned();
    Snapshot {
        model: text("device.model").or_else(|| text("ups.model")),
        manufacturer: text("device.mfr").or_else(|| text("ups.mfr")),
        serial: text("device.serial").or_else(|| text("ups.serial")),
        replace_battery: has("RB"),
        flags,
        state,
        charge_pct: num(m, "battery.charge"),
        runtime_secs: num(m, "battery.runtime").map(|v| v as i64),
        load_pct: num(m, "ups.load"),
        input_voltage: num(m, "input.voltage"),
        output_voltage: num(m, "output.voltage"),
        battery_voltage: num(m, "battery.voltage"),
    }
}

/// The outcome of asking upsd about one UPS.
#[derive(Debug, Clone, PartialEq)]
pub enum Outcome {
    Reading(Snapshot),
    /// upsd answers but does not know this UPS (or the driver has no data)
    NoUps(String),
    /// nobody answers on the port
    Unreachable(String),
}

/// Interpret the combined stdout + stderr of `upsc <ups>@<host>:<port>`.
pub fn interpret(text: &str) -> Outcome {
    if let Some(e) = text.lines().find_map(|l| l.strip_prefix("Error:")) {
        let e = e.trim();
        return if e.contains("Connection failure")
            || e.contains("Connection refused")
            || e.contains("Server disconnected")
            || e.contains("timed out")
            || e.contains("Network is unreachable")
            || e.contains("Name or service not known")
        {
            Outcome::Unreachable(e.to_string())
        } else {
            Outcome::NoUps(e.to_string())
        };
    }
    let m = parse_upsc(text);
    if m.is_empty() {
        return Outcome::NoUps("upsd returned no data".into());
    }
    if m.get("ups.status").is_none() {
        return Outcome::NoUps("the UPS reports no status (driver not connected)".into());
    }
    Outcome::Reading(snapshot(&m))
}

/// Ask upsd with `upsc` (5 s limit). Never fails: problems are outcomes.
pub async fn query(host: &str, port: u16, name: &str) -> Outcome {
    let Some(bin) = find_bin("upsc") else {
        return Outcome::NoUps(format!(
            "upsc is not installed (emerge {NUT_ATOM}, USE=ups)"
        ));
    };
    let target = format!("{name}@{host}:{port}");
    let run = tokio::process::Command::new(bin)
        .arg(&target)
        .stdin(std::process::Stdio::null())
        .kill_on_drop(true)
        .output();
    match tokio::time::timeout(std::time::Duration::from_secs(5), run).await {
        Ok(Ok(o)) => {
            let mut t = String::from_utf8_lossy(&o.stdout).into_owned();
            t.push('\n');
            t.push_str(&String::from_utf8_lossy(&o.stderr));
            interpret(&t)
        }
        Ok(Err(e)) => Outcome::NoUps(format!("upsc: {e}")),
        Err(_) => Outcome::Unreachable("upsc timed out".into()),
    }
}

// ---------------------------------------------------------------------------
// programs and users
// ---------------------------------------------------------------------------

pub fn find_bin_in(dirs: &[PathBuf], name: &str) -> Option<PathBuf> {
    use std::os::unix::fs::PermissionsExt;
    dirs.iter().map(|d| d.join(name)).find(|p| {
        std::fs::metadata(p)
            .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
            .unwrap_or(false)
    })
}

pub fn find_bin(name: &str) -> Option<PathBuf> {
    let dirs: Vec<PathBuf> = BIN_DIRS.iter().map(PathBuf::from).collect();
    find_bin_in(&dirs, name).or_else(|| which(name))
}

fn random_password() -> Result<String> {
    use std::io::Read;
    let mut b = [0u8; 16];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut b))
        .map_err(|e| Error::Service(format!("generate the monitor password: {e}")))?;
    Ok(b.iter().map(|x| format!("{x:02x}")).collect())
}

/// Make `conf` (root:<group> 2750, so files written into it carry the NUT
/// group) and `state` (<user>:<group> 0750) when running as root and the NUT
/// account exists. Returns whether the daemons can be started as that user.
fn prepare_dirs(d: &Dirs, user: &str) -> Result<bool> {
    use std::os::unix::fs::PermissionsExt;
    for p in [&d.conf, &d.state] {
        std::fs::create_dir_all(p)
            .map_err(|e| Error::Service(format!("create {}: {e}", p.display())))?;
    }
    if !nix::unistd::geteuid().is_root() {
        return Ok(false);
    }
    let Ok(Some(u)) = nix::unistd::User::from_name(user) else {
        return Ok(false);
    };
    let gid = u.gid;
    let _ = nix::unistd::chown(&d.conf, Some(nix::unistd::Uid::from_raw(0)), Some(gid));
    let _ = std::fs::set_permissions(&d.conf, std::fs::Permissions::from_mode(0o2750));
    let _ = nix::unistd::chown(&d.state, Some(u.uid), Some(gid));
    let _ = std::fs::set_permissions(&d.state, std::fs::Permissions::from_mode(0o750));
    Ok(true)
}

// ---------------------------------------------------------------------------
// applier
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct UpsApplier {
    sup: Supervisor,
    addrs: Arc<dyn AddrSource>,
    bin_dirs: Vec<PathBuf>,
}

impl Default for UpsApplier {
    fn default() -> Self {
        Self::with_supervisor(Supervisor::detect())
    }
}

impl UpsApplier {
    pub fn with_supervisor(sup: Supervisor) -> Self {
        Self {
            sup,
            addrs: Arc::new(LiveAddrs),
            bin_dirs: BIN_DIRS.iter().map(PathBuf::from).collect(),
        }
    }

    pub fn with_env(sup: Supervisor, addrs: Arc<dyn AddrSource>, bin_dirs: Vec<PathBuf>) -> Self {
        Self {
            sup,
            addrs,
            bin_dirs,
        }
    }

    fn bin(&self, name: &str) -> Result<PathBuf> {
        find_bin_in(&self.bin_dirs, name).ok_or_else(|| {
            Error::Service(format!(
                "UPS monitoring needs {name}, which is not installed (emerge {NUT_ATOM}, USE=ups)"
            ))
        })
    }

    async fn stop_all(&self, keep: &[&str]) -> Result<Vec<&'static str>> {
        let mut stopped = Vec::new();
        for i in INSTANCES {
            if !keep.contains(&i) && self.sup.stop(svc::DAEMON_SERVICE, i).await? {
                stopped.push(i);
            }
        }
        Ok(stopped)
    }

    async fn lan_devices(&self, store: &ConfigStore, c: &Cfg) -> Result<Vec<String>> {
        lan::resolve_iface(store, &c.listen_iface).await
    }

    /// Settings with the monitor password generated and stored when a
    /// local UPS needs one and none is set.
    async fn load_with_password(&self, store: &ConfigStore) -> Result<Cfg> {
        let mut c = Cfg::load(store).await?;
        if c.enabled && c.local_ups() && c.monitor_password.is_empty() {
            let pw = random_password()?;
            lan::set_setting(store, "ups.monitor_password", &pw).await?;
            c.monitor_password = pw;
        }
        Ok(c)
    }

    fn env_argv(&self, dirs: &Dirs, bin: &Path, args: &[&str]) -> Result<Vec<String>> {
        let env = which("env").ok_or_else(|| Error::Service("`env` is missing".into()))?;
        let mut v: Vec<String> = vec![
            env.to_string_lossy().into(),
            format!("NUT_CONFPATH={}", dirs.conf.display()),
            format!("NUT_STATEPATH={}", dirs.state.display()),
            bin.to_string_lossy().into(),
        ];
        v.extend(args.iter().map(|s| s.to_string()));
        Ok(v)
    }
}

#[async_trait]
impl Applier for UpsApplier {
    fn name(&self) -> &'static str {
        "ups"
    }

    fn phase(&self) -> Phase {
        Phase::Services
    }

    async fn apply(&self, store: &ConfigStore) -> Result<ApplyReport> {
        let mut rep = ApplyReport::default();
        let c = self.load_with_password(store).await?;
        if !c.enabled {
            let n = self.stop_all(&[]).await?.len();
            rep.applied(if n > 0 {
                "UPS monitoring stopped"
            } else {
                "UPS monitoring is off"
            });
            return Ok(rep);
        }
        c.validate()?;
        let upsmon = self.bin("upsmon")?;
        let dirs = Dirs::under(&self.sup);
        let drop_priv = prepare_dirs(&dirs, &c.run_user)?;
        let user_args: Vec<&str> = if drop_priv {
            vec!["-u", c.run_user.as_str()]
        } else {
            vec![]
        };

        let mut keep: Vec<&str> = vec![UPSMON_INSTANCE];
        let mut started = Vec::new();
        let mut files = vec![(dirs.conf.join("nut.conf"), nut_conf(&c), 0o640)];

        if c.local_ups() {
            keep.push(DRIVER_INSTANCE);
            keep.push(UPSD_INSTANCE);
            let driver = self.bin(&c.driver)?;
            let upsd = self.bin("upsd")?;
            let devs = self.lan_devices(store, &c).await?;
            let listen = listen_addrs(&c, &self.addrs.addrs()?, &devs);
            if c.mode == "netserver" && listen.len() < 2 {
                return Err(invalid(format!(
                    "UPS: no address on {} to share the UPS on",
                    c.listen_iface
                )));
            }
            let ups_conf_f = (dirs.conf.join("ups.conf"), ups_conf(&c), 0o640);
            // driver
            let mut dargs = vec!["-a", c.ups_name.as_str(), "-F"];
            dargs.extend(user_args.iter());
            let argv = self.env_argv(&dirs, &driver, &dargs)?;
            if svc::ensure_daemon(&self.sup, DRIVER_INSTANCE, argv, vec![ups_conf_f.clone()])
                .await?
            {
                started.push("driver");
            }
            // upsd
            let mut uargs = vec!["-F"];
            uargs.extend(user_args.iter());
            let argv = self.env_argv(&dirs, &upsd, &uargs)?;
            let ufiles = vec![
                ups_conf_f,
                (dirs.conf.join("upsd.conf"), upsd_conf(&c, &listen), 0o640),
                (dirs.conf.join("upsd.users"), upsd_users(&c, false), 0o640),
            ];
            if svc::ensure_daemon(&self.sup, UPSD_INSTANCE, argv, ufiles).await? {
                started.push("upsd");
            }
        }

        // upsmon (+ upssched for the time-on-battery policy)
        let mut mfiles = files.split_off(0);
        let mut sched: Option<PathBuf> = None;
        if c.policy == "after_on_battery" {
            let up = self.bin("upssched")?;
            let script = dirs.conf.join("upssched-cmd");
            mfiles.push((script.clone(), upssched_script(&upsmon), 0o750));
            mfiles.push((
                dirs.conf.join("upssched.conf"),
                upssched_conf(&c, &dirs, &script),
                0o640,
            ));
            sched = Some(up);
        }
        mfiles.push((
            dirs.conf.join("upsmon.conf"),
            upsmon_conf(&c, &dirs, sched.as_deref(), false),
            0o640,
        ));
        let argv = self.env_argv(&dirs, &upsmon, &["-F"])?;
        if svc::ensure_daemon(&self.sup, UPSMON_INSTANCE, argv, mfiles).await? {
            started.push("upsmon");
        }
        let stopped = self.stop_all(&keep).await?;
        rep.applied(format!(
            "UPS monitoring ({} mode, {}): {}{}",
            c.mode,
            if c.local_ups() {
                &c.driver
            } else {
                "remote UPS"
            },
            if started.is_empty() {
                "running, unchanged".to_string()
            } else {
                format!("(re)started {}", started.join(", "))
            },
            if stopped.is_empty() {
                String::new()
            } else {
                format!("; stopped {}", stopped.join(", "))
            }
        ));
        Ok(rep)
    }

    async fn render(&self, store: &ConfigStore) -> Result<String> {
        let c = Cfg::load(store).await?;
        if !c.enabled {
            return Ok("# UPS monitoring off\n".into());
        }
        c.validate()?;
        let dirs = Dirs::under(&self.sup);
        let mut out = format!("## nut.conf\n{}", nut_conf(&c));
        if c.local_ups() {
            let devs = self.lan_devices(store, &c).await?;
            let listen = listen_addrs(&c, &self.addrs.addrs()?, &devs);
            let mut masked = c.clone();
            masked.snmp_community = svc::SECRET_MASK.into();
            out.push_str(&format!("\n## ups.conf\n{}", ups_conf(&masked)));
            out.push_str(&format!("\n## upsd.conf\n{}", upsd_conf(&c, &listen)));
            out.push_str(&format!("\n## upsd.users\n{}", upsd_users(&c, true)));
        }
        let sched = (c.policy == "after_on_battery").then(|| PathBuf::from("upssched"));
        out.push_str(&format!(
            "\n## upsmon.conf\n{}",
            upsmon_conf(&c, &dirs, sched.as_deref(), true)
        ));
        if c.policy == "after_on_battery" {
            out.push_str(&format!(
                "\n## upssched.conf\n{}",
                upssched_conf(&c, &dirs, &dirs.conf.join("upssched-cmd"))
            ));
        }
        Ok(out)
    }

    async fn status(&self, store: &ConfigStore) -> Result<Value> {
        let c = Cfg::load(store).await?;
        let running: Vec<Value> = INSTANCES
            .iter()
            .map(|i| json!({"daemon": i, "running": self.sup.is_running(svc::DAEMON_SERVICE, i)}))
            .collect();
        Ok(json!({
            "enabled": c.enabled,
            "mode": c.mode,
            "installed": find_bin_in(&self.bin_dirs, "upsmon").is_some(),
            "daemons": running,
            "ups": status_document(store).await?,
        }))
    }
}

// ---------------------------------------------------------------------------
// the status document shared by the API and the card
// ---------------------------------------------------------------------------

/// `{enabled, installed, mode, state, reading, message}`; honest about every
/// way there can be nothing to show.
pub async fn status_document(store: &ConfigStore) -> Result<Value> {
    let c = Cfg::load(store).await?;
    let installed = find_bin("upsc").is_some();
    let mut doc = json!({
        "enabled": c.enabled,
        "installed": installed,
        "mode": c.mode,
        "ups_name": c.ups_name,
        "state": "unknown",
        "reading": Value::Null,
        "message": Value::Null,
    });
    if !c.enabled {
        doc["message"] = json!("UPS monitoring is off. Turn it on under Services > UPS.");
        return Ok(doc);
    }
    if !installed {
        doc["message"] = json!(format!(
            "NUT is not installed on this system (emerge {NUT_ATOM}, USE=ups)."
        ));
        return Ok(doc);
    }
    let (host, port, name) = c.target();
    match query(&host, port, &name).await {
        Outcome::Reading(s) => {
            doc["state"] = json!(s.state.as_str());
            doc["reading"] = serde_json::to_value(&s).unwrap_or(Value::Null);
        }
        Outcome::NoUps(why) => {
            doc["message"] = json!(format!("No UPS data: {why}."));
        }
        Outcome::Unreachable(why) => {
            doc["message"] = json!(format!("The NUT server does not answer: {why}."));
        }
    }
    Ok(doc)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lan::testutil;
    use crate::supervise::{InitMode, NetPaths};

    const ONLINE: &str = include_str!("../tests/fixtures/ups/online.txt");
    const ON_BATTERY: &str = include_str!("../tests/fixtures/ups/on_battery.txt");
    const LOW_BATTERY: &str = include_str!("../tests/fixtures/ups/low_battery.txt");
    const REPLACE: &str = include_str!("../tests/fixtures/ups/replace_battery.txt");
    const LIST: &str = include_str!("../tests/fixtures/ups/list.txt");
    const UNKNOWN: &str = include_str!("../tests/fixtures/ups/no_ups_unknown.txt");
    const REFUSED: &str = include_str!("../tests/fixtures/ups/no_ups_refused.txt");

    fn reading(t: &str) -> Snapshot {
        match interpret(t) {
            Outcome::Reading(s) => s,
            o => panic!("{o:?}"),
        }
    }

    fn cfg() -> Cfg {
        Cfg::from_settings(&Settings(
            SPEC.fields
                .iter()
                .map(|f| (f.key.to_string(), Value::String(f.default.to_string())))
                .collect(),
        ))
    }

    #[test]
    fn online_fixture() {
        let s = reading(ONLINE);
        assert_eq!(s.state, PowerState::Online);
        assert_eq!(s.flags, ["OL", "CHRG"]);
        assert_eq!(s.charge_pct, Some(100.0));
        assert_eq!(s.runtime_secs, Some(2610));
        assert_eq!(s.load_pct, Some(18.0));
        assert_eq!(s.input_voltage, Some(231.0));
        assert_eq!(s.output_voltage, Some(230.0));
        assert_eq!(s.battery_voltage, Some(13.6));
        assert_eq!(s.model.as_deref(), Some("Eaton 3S 700"));
        assert_eq!(s.manufacturer.as_deref(), Some("Eaton"));
        assert!(!s.replace_battery);
    }

    #[test]
    fn on_battery_and_low_battery_fixtures() {
        let s = reading(ON_BATTERY);
        assert_eq!(s.state, PowerState::OnBattery);
        assert_eq!(s.charge_pct, Some(71.0));
        assert_eq!(s.input_voltage, Some(0.0));
        let s = reading(LOW_BATTERY);
        assert_eq!(s.state, PowerState::LowBattery);
        assert_eq!(s.flags, ["OB", "DISCHRG", "LB"]);
        assert_eq!(s.charge_pct, Some(14.0));
        assert_eq!(s.runtime_secs, Some(150));
    }

    #[test]
    fn replace_battery_is_a_flag_not_a_state() {
        let s = reading(REPLACE);
        assert_eq!(s.state, PowerState::Online);
        assert!(s.replace_battery);
    }

    #[test]
    fn no_ups_cases_are_outcomes_not_errors() {
        assert!(matches!(interpret(UNKNOWN), Outcome::NoUps(e) if e.contains("Unknown UPS")));
        assert!(
            matches!(interpret(REFUSED), Outcome::Unreachable(e) if e.contains("Connection refused"))
        );
        assert!(matches!(interpret(""), Outcome::NoUps(_)));
        // a driver that is up but reports no status
        assert!(matches!(
            interpret("battery.charge: 50\n"),
            Outcome::NoUps(_)
        ));
    }

    #[test]
    fn list_fixture() {
        assert_eq!(parse_upsc_list(LIST), ["ups"]);
        assert!(parse_upsc_list(UNKNOWN).is_empty());
        assert!(parse_upsc_list(REFUSED).is_empty());
    }

    #[test]
    fn parser_ignores_junk_and_missing_numbers() {
        let m = parse_upsc("Init SSL without certificate database\nups.status: OB\nbattery.charge: n/a\nups.load: \n");
        let s = snapshot(&m);
        assert_eq!(s.state, PowerState::OnBattery);
        assert_eq!(s.charge_pct, None);
        assert_eq!(s.load_pct, None);
        assert_eq!(snapshot(&BTreeMap::new()).state, PowerState::Unknown);
    }

    #[test]
    fn shutdown_command_is_checked() {
        assert!(check_shutdown_command(DEFAULT_SHUTDOWN).is_ok());
        assert!(check_shutdown_command("/usr/local/bin/mark /tmp/x").is_ok());
        for bad in [
            "poweroff",
            "/sbin/poweroff; reboot",
            "/sbin/poweroff \"x\"",
            "/bin/x $(id)",
            "/bin/x\nSHUTDOWNCMD y",
            "",
            "/bin/x `id`",
        ] {
            assert!(check_shutdown_command(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn standalone_config_files() {
        let c = Cfg {
            monitor_password: "pw-secret-1".into(),
            ..cfg()
        };
        c.validate().unwrap();
        let dirs = Dirs {
            conf: "/c".into(),
            state: "/s".into(),
        };
        assert!(nut_conf(&c).contains("MODE=standalone"));
        let u = ups_conf(&c);
        assert!(u.contains("[ups]\n\tdriver = usbhid-ups\n\tport = auto\n"));
        assert!(!u.contains("ignorelb"));
        assert!(u.lines().take(3).any(|l| l.contains(lan::MARKER)));
        let listen = listen_addrs(&c, &[], &[]);
        assert_eq!(upsd_conf(&c, &listen).matches("LISTEN").count(), 1);
        assert!(upsd_conf(&c, &listen).contains("LISTEN 127.0.0.1 3493\n"));
        let users = upsd_users(&c, false);
        assert!(users.contains("[patronus-mon]") && users.contains("password = pw-secret-1"));
        assert!(users.contains("upsmon primary"));
        assert!(!upsd_users(&c, true).contains("pw-secret-1"));
        let m = upsmon_conf(&c, &dirs, None, false);
        assert!(m.contains("MONITOR ups@127.0.0.1:3493 1 patronus-mon pw-secret-1 primary\n"));
        assert!(m.contains(&format!("SHUTDOWNCMD \"{DEFAULT_SHUTDOWN}\"\n")));
        assert!(m.contains("POWERDOWNFLAG /s/killpower\n"));
        assert!(!m.contains("NOTIFYCMD"));
        assert!(!upsmon_conf(&c, &dirs, None, true).contains("pw-secret-1"));
    }

    #[test]
    fn netserver_listens_on_the_lan_addresses_only() {
        let c = Cfg {
            mode: "netserver".into(),
            monitor_password: "x-pass-word".into(),
            ..cfg()
        };
        let a = |i: &str, s: &str| IfAddr {
            ifname: i.into(),
            addr: s.parse().unwrap(),
            prefix: 24,
        };
        let addrs = [
            a("lo", "127.0.0.1"),
            a("rtr-lan", "192.168.50.1"),
            a("rtr-lan", "fd00:50::1"),
            a("rtr-lan", "fe80::1"),
            a("rtr-wan", "203.0.113.2"),
        ];
        let l = listen_addrs(&c, &addrs, &["rtr-lan".to_string()]);
        let txt = upsd_conf(&c, &l);
        assert!(txt.contains("LISTEN 127.0.0.1 3493"));
        assert!(txt.contains("LISTEN 192.168.50.1 3493"));
        assert!(txt.contains("LISTEN fd00:50::1 3493"));
        assert!(!txt.contains("203.0.113.2") && !txt.contains("fe80") && !txt.contains("0.0.0.0"));
        // standalone ignores the LAN
        let s = Cfg {
            mode: "standalone".into(),
            ..c
        };
        assert_eq!(listen_addrs(&s, &addrs, &["rtr-lan".into()]).len(), 1);
    }

    #[test]
    fn policies_render_what_nut_needs() {
        let dirs = Dirs {
            conf: "/c".into(),
            state: "/s".into(),
        };
        let mut c = Cfg {
            monitor_password: "pw-secret-1".into(),
            policy: "after_on_battery".into(),
            after_secs: 90,
            ..cfg()
        };
        c.validate().unwrap();
        let sc = upssched_conf(&c, &dirs, Path::new("/c/upssched-cmd"));
        assert!(sc.contains("CMDSCRIPT /c/upssched-cmd\n"));
        assert!(sc.contains("AT ONBATT * START-TIMER onbatt-fsd 90\n"));
        assert!(sc.contains("AT ONLINE * CANCEL-TIMER onbatt-fsd\n"));
        let m = upsmon_conf(&c, &dirs, Some(Path::new("/usr/sbin/upssched")), false);
        assert!(m.contains("NOTIFYCMD /usr/sbin/upssched\n"));
        assert!(m.contains("NOTIFYFLAG ONBATT SYSLOG+EXEC"));
        assert!(upssched_script(Path::new("/usr/sbin/upsmon")).contains("/usr/sbin/upsmon -c fsd"));
        // charge threshold
        c.policy = "charge_below".into();
        c.charge_pct = 35;
        c.validate().unwrap();
        let u = ups_conf(&c);
        assert!(u.contains("\tignorelb\n") && u.contains("override.battery.charge.low = 35\n"));
        c.driver = "apcsmart".into();
        c.port = "/dev/ttyS0".into();
        assert!(c.validate().unwrap_err().to_string().contains("usbhid-ups"));
    }

    #[test]
    fn validation_by_mode_and_driver() {
        let mut c = cfg();
        c.driver = "snmp-ups".into();
        assert!(c.validate().unwrap_err().to_string().contains("SNMP host"));
        c.snmp_host = "192.0.2.9".into();
        assert!(c.validate().unwrap_err().to_string().contains("community"));
        c.snmp_community = "communityx".into();
        c.validate().unwrap();
        let u = ups_conf(&c);
        assert!(u.contains("port = 192.0.2.9\n") && u.contains("community = communityx\n"));
        // netclient
        let mut n = Cfg {
            mode: "netclient".into(),
            ..cfg()
        };
        assert!(n.validate().unwrap_err().to_string().contains("server"));
        n.server = "nut.example".into();
        assert!(n.validate().unwrap_err().to_string().contains("password"));
        n.monitor_password = "remote-pass".into();
        n.validate().unwrap();
        assert_eq!(n.target(), ("nut.example".into(), 3493, "ups".into()));
        let m = upsmon_conf(
            &n,
            &Dirs {
                conf: "/c".into(),
                state: "/s".into(),
            },
            None,
            false,
        );
        assert!(m.contains("MONITOR ups@nut.example:3493 1 patronus-mon remote-pass secondary\n"));
    }

    #[tokio::test]
    async fn settings_are_validated_and_secrets_never_returned() {
        let s = testutil::store().await;
        let svc = UpsSvc;
        assert!(svc
            .put(&s, &json!({"shutdown_command": "/bin/x;reboot"}))
            .await
            .is_err());
        assert!(svc.put(&s, &json!({"driver": "evil-ups"})).await.is_err());
        assert!(svc
            .put(&s, &json!({"snmp_community": "short"}))
            .await
            .is_err());
        svc.put(
            &s,
            &json!({"enabled": true, "monitor_password": "a-long-secret", "snmp_community": "community-1"}),
        )
        .await
        .unwrap();
        let g = svc.get(&s).await.unwrap();
        assert_eq!(g["settings"]["monitor_password"], "********");
        assert_eq!(g["settings"]["snmp_community"], "********");
        assert!(!g.to_string().contains("a-long-secret"));
        assert_eq!(g["settings"]["listen_iface"], "@lan");
        assert_eq!(g["settings"]["listen_port"], 3493);
        // the defaults are the safe ones
        let d = Cfg::from_settings(&Settings(svc::raw_settings(&s, &SPEC).await.unwrap()));
        assert_eq!(d.mode, "standalone");
        assert_eq!(d.shutdown_command, DEFAULT_SHUTDOWN);
    }

    #[tokio::test]
    async fn apply_off_and_without_nut() {
        let s = testutil::store().await;
        let d = tempfile::tempdir().unwrap();
        let sup = Supervisor::new(InitMode::Direct, NetPaths::under(d.path()));
        let a = UpsApplier::with_env(
            sup,
            Arc::new(crate::lan::StaticAddrs(vec![])),
            vec![d.path().join("nobin")],
        );
        let r = a.apply(&s).await.unwrap();
        assert!(format!("{r:?}").contains("off"), "{r:?}");
        assert!(a.render(&s).await.unwrap().contains("off"));
        svc::put_settings(&s, &SPEC, &json!({"enabled": true}))
            .await
            .unwrap();
        let e = a.apply(&s).await.unwrap_err();
        assert!(e.to_string().contains(NUT_ATOM), "{e}");
        // the generated password was stored (and is masked in the dry run)
        let c = Cfg::load(&s).await.unwrap();
        assert_eq!(c.monitor_password.len(), 32);
        let shown = a.render(&s).await.unwrap();
        assert!(!shown.contains(&c.monitor_password), "{shown}");
        assert!(shown.contains("SHUTDOWNCMD"));
    }

    #[test]
    fn finds_programs_in_given_dirs() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("dummy-ups");
        std::fs::write(&p, "#!/bin/sh\n").unwrap();
        assert!(find_bin_in(&[d.path().into()], "dummy-ups").is_none());
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(find_bin_in(&[d.path().into()], "dummy-ups"), Some(p));
    }
}
