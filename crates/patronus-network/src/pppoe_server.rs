//! PPPoE access concentrator (USE=pppoe-server): subscribers (another
//! router's PPPoE WAN client, a lab, a building's CPEs) dial in over a LAN
//! port, authenticate and get an address from a pool, then reach the
//! internet through this box - the role of pfSense's "PPPoE server" and
//! OPNsense's `os-pppoe-server`-style plugins.
//!
//! It runs rp-pppoe's `pppoe-server` (discovery, kernel-mode sessions) which
//! starts one `pppd` per session with the options file generated here, all
//! supervised as `patronus-daemon@pppoe-server` (OpenRC and systemd).
//! Everything an operator may want to change is a typed setting in
//! `lan_settings` (`pppoe-server.*`): the interfaces, access concentrator and
//! service name, the server address and the client pool, DNS, MTU, LCP
//! keep-alive, authentication method, session caps, the interface numbering
//! used for the session devices, internet/NAT/LAN access, and RADIUS.
//!
//! Users are the `pppoe_server_users` table (name, password, optional fixed
//! address). Passwords are shared secrets (CHAP needs them in the clear): the
//! API never returns them and the generated files are root-owned, mode 0600
//! (`/etc/ppp/{chap,pap}-secrets` get a Patronus block, other lines are kept).
//! With RADIUS on, pppd's `radius.so` plugin asks the RADIUS server instead
//! (and sends accounting); the local list is then not consulted.
//!
//! Session devices are numbered from `unit_base` (`ppp<base>` ..
//! `ppp<base+max-1>`), a range of their own, so the firewall can match exactly
//! those devices and never the PPPoE *client* of a WAN link (`ppp0`).

use crate::lan::{self, invalid};
use crate::supervise::{which, write_atomic, Supervisor};
use crate::svc::{self, Coll, Field, Kind, Settings, Spec, Svc};
use async_trait::async_trait;
use patronus_config::applier::{Applier, ApplyReport, Phase};
use patronus_config::store::ConfigStore;
use patronus_core::{Error, Result};
use serde_json::{json, Value};
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

pub const INSTANCE: &str = "pppoe-server";
pub const CHAP_SECRETS: &str = "/etc/ppp/chap-secrets";
pub const PAP_SECRETS: &str = "/etc/ppp/pap-secrets";
const BEGIN: &str = "# BEGIN Managed by Patronus (PPPoE server users)";
const END: &str = "# END Managed by Patronus (PPPoE server users)";
/// Hard cap of simultaneous sessions (pool and device range).
pub const MAX_SESSIONS: i64 = 4000;

const AUTH: &[&str] = &["chap", "mschap-v2", "pap", "any"];
const MODES: &[&str] = &["auto", "kernel", "userspace"];

static FIELDS: [Field; 32] = [
    Field::new("enabled", "PPPoE server", Kind::Bool).def("0"),
    Field::new("interfaces", "Serve on", Kind::Ifaces)
        .help("one or more ports (device, @lan, @optN) that subscribers are attached to; never the WAN"),
    Field::new("ac_name", "Access concentrator name", Kind::Token)
        .help("shown to clients in discovery; empty = this host's name"),
    Field::new("service_name", "Service name", Kind::Token)
        .help("advertised service name; empty = answer every request"),
    Field::new("local_ip", "Server address", Kind::Ipv4)
        .def("10.70.0.1")
        .help("the router's end of every session"),
    Field::new("range_start", "Client pool: first address", Kind::Ipv4).def("10.70.0.10"),
    Field::new("range_end", "Client pool: last address", Kind::Ipv4).def("10.70.0.200"),
    Field::new("max_sessions", "Maximum sessions", Kind::Int(0, MAX_SESSIONS))
        .def("0")
        .help("0 = the size of the pool"),
    Field::new("per_mac_limit", "Sessions per client MAC", Kind::Int(0, 100))
        .def("0")
        .help("0 = unlimited"),
    Field::new("auth", "Authentication", Kind::Select(AUTH))
        .def("chap")
        .help("chap, mschap-v2 or pap only, or any (the client picks; PAP sends the password in the clear)"),
    Field::new("dns1", "DNS server 1 for clients", Kind::Ip),
    Field::new("dns2", "DNS server 2 for clients", Kind::Ip),
    Field::new("mtu", "Session MTU/MRU", Kind::Int(576, 1500))
        .def("1492")
        .help("1492 fits PPPoE over Ethernet"),
    Field::new("lcp_interval", "LCP keep-alive interval (s)", Kind::Int(0, 3600)).def("30"),
    Field::new("lcp_failures", "LCP failures before a session drops", Kind::Int(1, 100)).def("4"),
    Field::new("idle_timeout", "Idle timeout (s)", Kind::Int(0, 86_400))
        .def("0")
        .help("0 = never drop an idle session"),
    Field::new("mode", "Session mode", Kind::Select(MODES))
        .def("auto")
        .help("kernel = in-kernel PPPoE (fast); userspace = pppoe helper per session; auto = kernel when the pppd plugin is installed"),
    Field::new("unit_base", "First session device number", Kind::Int(100, 60_000))
        .def("1000")
        .help("sessions are ppp<N>, N from this number up; keeps them apart from a PPPoE WAN link (ppp0)"),
    Field::new("internet", "Clients reach the internet", Kind::Bool).def("1"),
    Field::new("internet_interface", "Internet interface", Kind::Iface).def("@wan"),
    Field::new("nat", "Masquerade clients out of the internet interface", Kind::Bool)
        .def("1")
        .help("off when the clients' addresses are routed upstream"),
    Field::new("lan_access", "Clients reach the LAN", Kind::Bool)
        .def("0")
        .help("allow clients to open connections to the LAN interfaces"),
    Field::new("router_ports", "Router services clients may use", Kind::Text)
        .def("udp/53,tcp/53")
        .help("comma-separated proto/port or proto/lo-hi (udp/53,tcp/22); ping is always allowed; empty = none"),
    Field::new("radius_enabled", "Authenticate against RADIUS", Kind::Bool)
        .def("0")
        .help("replaces the local user list below; needs a RADIUS server that knows this router as a client"),
    Field::new("radius_server", "RADIUS server", Kind::Host),
    Field::new("radius_auth_port", "RADIUS authentication port", Kind::Int(1, 65535)).def("1812"),
    Field::new("radius_acct_port", "RADIUS accounting port", Kind::Int(1, 65535)).def("1813"),
    Field::new("radius_secret", "RADIUS shared secret", Kind::Secret),
    Field::new("radius_accounting", "Send RADIUS accounting", Kind::Bool).def("1"),
    Field::new("radius_timeout", "RADIUS timeout (s)", Kind::Int(1, 60)).def("3"),
    Field::new("radius_retries", "RADIUS retries", Kind::Int(1, 10)).def("3"),
    Field::new("radius_source", "RADIUS source address", Kind::Ipv4)
        .help("optional: the address RADIUS requests come from (and NAS-IP-Address)"),
];

static USER_FIELDS: [Field; 5] = [
    Field::new("username", "User name", Kind::Token).req(),
    Field::new("password", "Password", Kind::Secret).req(),
    Field::new("address", "Fixed address", Kind::Ipv4)
        .help("optional: always give this user this address (outside the pool is fine)"),
    Field::new("enabled", "Enabled", Kind::Bool).def("1"),
    Field::new("description", "Description", Kind::Text),
];

static SPEC: Spec = Spec {
    slug: "pppoe-server",
    title: "PPPoE server",
    blurb: "PPPoE access concentrator: subscribers dial in on the chosen ports with a user name \
            and password, get an address from the pool and reach the internet through this \
            router. Runs rp-pppoe's pppoe-server + pppd (kernel sessions). Users share \
            /etc/ppp/chap-secrets with the L2TP server: an L2TP user can also dial in here. \
            With RADIUS the local users are not consulted.",
    applier: "pppoe-server",
    fields: &FIELDS,
    colls: &[Coll {
        key: "users",
        title: "Users",
        table: "pppoe_server_users",
        fields: &USER_FIELDS,
        unique: Some("username"),
    }],
    actions: &[],
};

pub struct PppoeServerSvc;

/// Pool: server address outside it, ordered, `max` sessions at most.
/// Returns the number of sessions the pool allows.
pub fn check_pool(local: &str, start: &str, end: &str, max: i64) -> Result<i64> {
    let (Ok(l), Ok(a), Ok(b)) = (
        local.parse::<Ipv4Addr>(),
        start.parse::<Ipv4Addr>(),
        end.parse::<Ipv4Addr>(),
    ) else {
        return Err(invalid(
            "PPPoE server: the server address and the client pool must be IPv4 addresses",
        ));
    };
    let (a, b, l) = (u32::from(a), u32::from(b), u32::from(l));
    if a > b {
        return Err(invalid(
            "PPPoE server: the client pool's first address is after its last",
        ));
    }
    if (a..=b).contains(&l) {
        return Err(invalid(
            "PPPoE server: the server address must be outside the client pool",
        ));
    }
    let size = (b - a) as i64 + 1;
    if size > MAX_SESSIONS {
        return Err(invalid(format!(
            "PPPoE server: the client pool has {size} addresses, at most {MAX_SESSIONS} are supported"
        )));
    }
    if max > size {
        return Err(invalid(format!(
            "PPPoE server: {max} sessions do not fit in a pool of {size} addresses"
        )));
    }
    Ok(if max == 0 { size } else { max })
}

/// proto/port list, `udp/53,tcp/22,tcp/8000-8010` -> normalised or an error.
pub fn check_router_ports(s: &str) -> std::result::Result<String, String> {
    let mut out = Vec::new();
    for part in s.split(',').map(str::trim).filter(|p| !p.is_empty()) {
        let (proto, ports) = part
            .split_once('/')
            .ok_or_else(|| format!("{part:?}: write proto/port, e.g. udp/53"))?;
        let proto = proto.to_ascii_lowercase();
        if proto != "tcp" && proto != "udp" {
            return Err(format!("{part:?}: the protocol is tcp or udp"));
        }
        let num = |t: &str| -> std::result::Result<u32, String> {
            match t.parse::<u32>() {
                Ok(n) if (1..=65535).contains(&n) => Ok(n),
                _ => Err(format!("{part:?}: {t:?} is not a port from 1 to 65535")),
            }
        };
        let norm = match ports.split_once('-') {
            Some((a, b)) => {
                let (a, b) = (num(a)?, num(b)?);
                if a > b {
                    return Err(format!("{part:?}: the range runs backwards"));
                }
                format!("{a}-{b}")
            }
            None => num(ports)?.to_string(),
        };
        out.push(format!("{proto}/{norm}"));
    }
    if out.len() > 32 {
        return Err("at most 32 entries".into());
    }
    Ok(out.join(","))
}

#[async_trait]
impl Svc for PppoeServerSvc {
    fn spec(&self) -> &'static Spec {
        &SPEC
    }

    async fn put(&self, store: &ConfigStore, body: &Value) -> Result<()> {
        // judge the settings as they will be after this change, before storing
        let cur = Settings::load(store, &SPEC).await?;
        let pick = |k: &str| {
            body.get(k)
                .map(|v| match v {
                    Value::String(s) => s.trim().to_string(),
                    other => other.to_string(),
                })
                .unwrap_or_else(|| cur.s(k))
        };
        check_pool(
            &pick("local_ip"),
            &pick("range_start"),
            &pick("range_end"),
            pick("max_sessions").parse().unwrap_or(0),
        )?;
        if let Some(rp) = body.get("router_ports").and_then(Value::as_str) {
            check_router_ports(rp).map_err(|e| invalid(format!("router services: {e}")))?;
        }
        svc::put_settings(store, &SPEC, body).await
    }

    async fn save_row(
        &self,
        store: &ConfigStore,
        coll: &str,
        id: Option<i64>,
        body: &Value,
    ) -> Result<i64> {
        if let Some(a) = body.get("address").and_then(Value::as_str) {
            let a = a.trim();
            if !a.is_empty() {
                let s = Settings::load(store, &SPEC).await?;
                if a == s.s("local_ip") {
                    return Err(invalid(
                        "PPPoE user: the fixed address is the server's own address",
                    ));
                }
                // another user may not hold the same fixed address
                for r in svc::raw_rows(store, &SPEC.colls[0]).await? {
                    if r["address"].as_str() == Some(a) && r["id"].as_i64() != id {
                        return Err(invalid(format!(
                            "PPPoE user: {a} is already the fixed address of {}",
                            r["username"].as_str().unwrap_or("another user")
                        )));
                    }
                }
            }
        }
        let c = svc::find_coll(&SPEC, coll)?;
        svc::save_row(store, c, id, body).await
    }
}

// ---------------------------------------------------------------------------
// generated files
// ---------------------------------------------------------------------------

/// The session device names `ppp<base>` .. `ppp<base+n-1>`. Exact names, not
/// prefix globs: `ppp100*` would also match `ppp1000` and `ppp100`.
pub fn unit_patterns(base: u32, n: u32) -> Vec<String> {
    (base..base.saturating_add(n))
        .map(|u| format!("ppp{u}"))
        .collect()
}

/// The session device patterns for stored settings (used by the firewall
/// rules through the same maths).
pub fn session_patterns(s: &Settings, pool_size: i64) -> Vec<String> {
    unit_patterns(s.n("unit_base") as u32, pool_size as u32)
}

/// pppd options for every session (`pppoe-server -O`).
pub fn render_options(s: &Settings, radius_conf: Option<&Path>) -> String {
    let mut c = lan::header("#", "pppd options for PPPoE server sessions");
    match s.s("auth").as_str() {
        "mschap-v2" => c.push_str("require-mschap-v2\nrefuse-pap\nrefuse-chap\nrefuse-mschap\n"),
        "pap" => c.push_str("require-pap\nrefuse-chap\nrefuse-mschap\nrefuse-mschap-v2\n"),
        "any" => c.push_str("auth\n"),
        _ => c.push_str("require-chap\nrefuse-pap\nrefuse-mschap\nrefuse-mschap-v2\n"),
    }
    c.push_str("noccp\nnodefaultroute\nnoipdefault\n");
    c.push_str(&format!("mtu {0}\nmru {0}\n", s.s("mtu")));
    if s.n("lcp_interval") > 0 {
        c.push_str(&format!(
            "lcp-echo-interval {}\nlcp-echo-failure {}\n",
            s.s("lcp_interval"),
            s.s("lcp_failures")
        ));
    }
    if s.n("idle_timeout") > 0 {
        c.push_str(&format!("idle {}\n", s.s("idle_timeout")));
    }
    for k in ["dns1", "dns2"] {
        let d = s.s(k);
        if d.parse::<Ipv4Addr>().is_ok() {
            c.push_str(&format!("ms-dns {d}\n"));
        }
    }
    if let Some(r) = radius_conf {
        c.push_str(&format!(
            "plugin radius.so\nradius-config-file {}\n",
            r.display()
        ));
    }
    c
}

/// radiusclient.conf for pppd's radius.so (the plugin reads it, the servers
/// file with the secret, and the dictionary).
pub fn render_radius_conf(s: &Settings, dir: &Path, run_dir: &Path) -> String {
    let mut c = lan::header("#", "radiusclient.conf for the PPPoE server");
    let server = s.s("radius_server");
    c.push_str(&format!(
        "auth_order radius\nlogin_tries 3\nlogin_timeout 60\nnologin /nonexistent\nissue /nonexistent\n\
         authserver {server}:{}\nacctserver {server}:{}\nservers {}\ndictionary {}\nseqfile {}\nmapfile {}\n\
         radius_timeout {}\nradius_retries {}\n",
        s.s("radius_auth_port"),
        s.s("radius_acct_port"),
        dir.join("radius-servers").display(),
        dir.join("radius-dictionary").display(),
        run_dir.join("pppoe-radius.seq").display(),
        dir.join("radius-portmap").display(),
        s.s("radius_timeout"),
        s.s("radius_retries"),
    ));
    let src = s.s("radius_source");
    if !src.is_empty() {
        c.push_str(&format!("bindaddr {src}\n"));
    }
    c
}

pub fn render_radius_servers(s: &Settings) -> String {
    let server = s.s("radius_server");
    format!("{server} {}\n", s.s("radius_secret"))
}

/// The RADIUS attributes pppd's plugin needs (RFC 2865/2866, MS-CHAP
/// RFC 2548), written here so it never depends on a distribution's file.
pub const RADIUS_DICTIONARY: &str = "\
ATTRIBUTE User-Name 1 string
ATTRIBUTE User-Password 2 string
ATTRIBUTE CHAP-Password 3 string
ATTRIBUTE NAS-IP-Address 4 ipaddr
ATTRIBUTE NAS-Port 5 integer
ATTRIBUTE Service-Type 6 integer
ATTRIBUTE Framed-Protocol 7 integer
ATTRIBUTE Framed-IP-Address 8 ipaddr
ATTRIBUTE Framed-IP-Netmask 9 ipaddr
ATTRIBUTE Framed-Routing 10 integer
ATTRIBUTE Filter-Id 11 string
ATTRIBUTE Framed-MTU 12 integer
ATTRIBUTE Framed-Compression 13 integer
ATTRIBUTE Reply-Message 18 string
ATTRIBUTE Callback-Number 19 string
ATTRIBUTE Framed-Route 22 string
ATTRIBUTE State 24 string
ATTRIBUTE Class 25 string
ATTRIBUTE Vendor-Specific 26 string
ATTRIBUTE Session-Timeout 27 integer
ATTRIBUTE Idle-Timeout 28 integer
ATTRIBUTE Termination-Action 29 integer
ATTRIBUTE Called-Station-Id 30 string
ATTRIBUTE Calling-Station-Id 31 string
ATTRIBUTE NAS-Identifier 32 string
ATTRIBUTE Acct-Status-Type 40 integer
ATTRIBUTE Acct-Delay-Time 41 integer
ATTRIBUTE Acct-Input-Octets 42 integer
ATTRIBUTE Acct-Output-Octets 43 integer
ATTRIBUTE Acct-Session-Id 44 string
ATTRIBUTE Acct-Authentic 45 integer
ATTRIBUTE Acct-Session-Time 46 integer
ATTRIBUTE Acct-Input-Packets 47 integer
ATTRIBUTE Acct-Output-Packets 48 integer
ATTRIBUTE Acct-Terminate-Cause 49 integer
ATTRIBUTE Acct-Input-Gigawords 52 integer
ATTRIBUTE Acct-Output-Gigawords 53 integer
ATTRIBUTE CHAP-Challenge 60 string
ATTRIBUTE NAS-Port-Type 61 integer
ATTRIBUTE Port-Limit 62 integer
ATTRIBUTE Connect-Info 77 string

VALUE Service-Type Login-User 1
VALUE Service-Type Framed-User 2
VALUE Service-Type Callback-Login-User 3
VALUE Service-Type Callback-Framed-User 4
VALUE Service-Type Outbound-User 5
VALUE Service-Type Administrative-User 6
VALUE Framed-Protocol PPP 1
VALUE Framed-Protocol SLIP 2
VALUE Framed-Compression None 0
VALUE Framed-Compression Van-Jacobson-TCP-IP 1
VALUE Acct-Status-Type Start 1
VALUE Acct-Status-Type Stop 2
VALUE Acct-Status-Type Alive 3
VALUE Acct-Status-Type Accounting-On 7
VALUE Acct-Status-Type Accounting-Off 8
VALUE Acct-Authentic RADIUS 1
VALUE Acct-Authentic Local 2
VALUE Acct-Authentic Remote 3
VALUE Acct-Terminate-Cause User-Request 1
VALUE Acct-Terminate-Cause Lost-Carrier 2
VALUE Acct-Terminate-Cause Lost-Service 3
VALUE Acct-Terminate-Cause Idle-Timeout 4
VALUE Acct-Terminate-Cause Session-Timeout 5
VALUE Acct-Terminate-Cause Admin-Reset 6
VALUE Acct-Terminate-Cause Admin-Reboot 7
VALUE Acct-Terminate-Cause Port-Error 8
VALUE Acct-Terminate-Cause NAS-Error 9
VALUE Acct-Terminate-Cause NAS-Request 10
VALUE Acct-Terminate-Cause NAS-Reboot 11
VALUE NAS-Port-Type Async 0
VALUE NAS-Port-Type Sync 1
VALUE NAS-Port-Type ISDN 2
VALUE NAS-Port-Type Virtual 5
VALUE NAS-Port-Type Ethernet 15

VENDOR Microsoft 311
ATTRIBUTE MS-CHAP-Response 1 string Microsoft
ATTRIBUTE MS-CHAP-Error 2 string Microsoft
ATTRIBUTE MS-CHAP-CPW-1 3 string Microsoft
ATTRIBUTE MS-CHAP-CPW-2 4 string Microsoft
ATTRIBUTE MS-CHAP-LM-Enc-PW 5 string Microsoft
ATTRIBUTE MS-CHAP-NT-Enc-PW 6 string Microsoft
ATTRIBUTE MS-MPPE-Encryption-Policy 7 string Microsoft
ATTRIBUTE MS-MPPE-Encryption-Type 8 string Microsoft
ATTRIBUTE MS-MPPE-Encryption-Types 8 string Microsoft
ATTRIBUTE MS-RAS-Vendor 9 integer Microsoft
ATTRIBUTE MS-CHAP-Domain 10 string Microsoft
ATTRIBUTE MS-CHAP-Challenge 11 string Microsoft
ATTRIBUTE MS-CHAP-MPPE-Keys 12 string Microsoft
ATTRIBUTE MS-BAP-Usage 13 integer Microsoft
ATTRIBUTE MS-Link-Utilization-Threshold 14 integer Microsoft
ATTRIBUTE MS-Link-Drop-Time-Limit 15 integer Microsoft
ATTRIBUTE MS-MPPE-Send-Key 16 string Microsoft
ATTRIBUTE MS-MPPE-Recv-Key 17 string Microsoft
ATTRIBUTE MS-RAS-Version 18 string Microsoft
ATTRIBUTE MS-Old-ARAP-Password 19 string Microsoft
ATTRIBUTE MS-New-ARAP-Password 20 string Microsoft
ATTRIBUTE MS-ARAP-PW-Change-Reason 21 integer Microsoft
ATTRIBUTE MS-Filter 22 string Microsoft
ATTRIBUTE MS-Acct-Auth-Type 23 integer Microsoft
ATTRIBUTE MS-Acct-EAP-Type 24 integer Microsoft
ATTRIBUTE MS-CHAP2-Response 25 string Microsoft
ATTRIBUTE MS-CHAP2-Success 26 string Microsoft
ATTRIBUTE MS-CHAP2-CPW 27 string Microsoft
ATTRIBUTE MS-Primary-DNS-Server 28 ipaddr Microsoft
ATTRIBUTE MS-Secondary-DNS-Server 29 ipaddr Microsoft
ATTRIBUTE MS-Primary-NBNS-Server 30 ipaddr Microsoft
ATTRIBUTE MS-Secondary-NBNS-Server 31 ipaddr Microsoft
";

/// A user line block for chap-/pap-secrets: `"user" * "password" address`.
pub fn secrets_block(users: &[User]) -> Vec<String> {
    users
        .iter()
        .map(|u| {
            format!(
                "\"{}\" * \"{}\" {}",
                u.name,
                u.password,
                if u.address.is_empty() {
                    "*"
                } else {
                    &u.address
                }
            )
        })
        .collect()
}

/// `existing` with the Patronus block replaced (or appended); foreign lines
/// are kept as they are.
pub fn merge_secrets(existing: &str, lines: &[String]) -> String {
    let mut out = String::new();
    let mut skipping = false;
    for l in existing.lines() {
        if l.trim() == BEGIN {
            skipping = true;
            continue;
        }
        if l.trim() == END {
            skipping = false;
            continue;
        }
        if !skipping {
            out.push_str(l);
            out.push('\n');
        }
    }
    if !lines.is_empty() {
        out.push_str(BEGIN);
        out.push('\n');
        for l in lines {
            out.push_str(l);
            out.push('\n');
        }
        out.push_str(END);
        out.push('\n');
    }
    out
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct User {
    pub name: String,
    pub password: String,
    pub address: String,
}

pub async fn users(store: &ConfigStore) -> Result<Vec<User>> {
    Ok(svc::raw_rows(store, &SPEC.colls[0])
        .await?
        .iter()
        .filter(|r| lan::flag(r["enabled"].as_str().unwrap_or("")))
        .map(|r| User {
            name: r["username"].as_str().unwrap_or("").to_string(),
            password: r["password"].as_str().unwrap_or("").to_string(),
            address: r["address"].as_str().unwrap_or("").to_string(),
        })
        .collect())
}

/// Does a pppd plugin directory hold `name`? (pppd's `/usr/lib*/pppd/<ver>/`.)
fn pppd_plugin_exists(name: &str) -> bool {
    for root in ["/usr/lib", "/usr/lib64", "/usr/lib/pppd", "/usr/lib64/pppd"] {
        let r = Path::new(root);
        if r.join("pppd").is_dir() {
            if let Ok(vs) = std::fs::read_dir(r.join("pppd")) {
                for v in vs.flatten() {
                    if v.path().join(name).exists() {
                        return true;
                    }
                }
            }
        }
        if let Ok(vs) = std::fs::read_dir(r) {
            for v in vs.flatten() {
                if v.path().join(name).exists() {
                    return true;
                }
                // /usr/lib/<triplet>/pppd/<ver>/
                if let Ok(vs2) = std::fs::read_dir(v.path().join("pppd")) {
                    for v2 in vs2.flatten() {
                        if v2.path().join(name).exists() {
                            return true;
                        }
                    }
                }
            }
        }
    }
    false
}

/// Can this kernel do PPPoE sessions itself? (module loaded, loadable, or built in)
fn kernel_pppoe_available() -> bool {
    if Path::new("/sys/module/pppoe").exists() || Path::new("/proc/net/pppoe").exists() {
        return true;
    }
    std::process::Command::new("modprobe")
        .args(["-q", "pppoe"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
        && Path::new("/sys/module/pppoe").exists()
}

/// The pppoe-server command line for stored settings.
pub fn server_argv(
    bin: &Path,
    s: &Settings,
    devices: &[String],
    options: &Path,
    pidfile: &Path,
    pool: i64,
    kernel: bool,
) -> Vec<String> {
    let mut a: Vec<String> = vec![bin.to_string_lossy().into(), "-F".into()];
    for d in devices {
        a.push("-I".into());
        a.push(d.clone());
    }
    let ac = s.s("ac_name");
    if !ac.is_empty() {
        a.push("-C".into());
        a.push(ac);
    }
    let sn = s.s("service_name");
    if !sn.is_empty() {
        a.push("-S".into());
        a.push(sn);
    }
    a.extend([
        "-L".into(),
        s.s("local_ip"),
        "-R".into(),
        s.s("range_start"),
        "-N".into(),
        pool.to_string(),
        "-O".into(),
        options.to_string_lossy().into(),
        "-X".into(),
        pidfile.to_string_lossy().into(),
        "-u".into(),
        "-o".into(),
        s.s("unit_base"),
    ]);
    if s.n("per_mac_limit") > 0 {
        a.push("-x".into());
        a.push(s.s("per_mac_limit"));
    }
    if kernel {
        a.push("-k".into());
    }
    a
}

/// Ports the clients may use on the router, normalised (settings validated).
pub fn router_ports(s: &Settings) -> String {
    check_router_ports(&s.s("router_ports")).unwrap_or_default()
}

// ---------------------------------------------------------------------------
// applier
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct PppoeServerApplier {
    sup: Supervisor,
    chap: PathBuf,
    pap: PathBuf,
}

impl Default for PppoeServerApplier {
    fn default() -> Self {
        Self {
            sup: Supervisor::detect(),
            chap: CHAP_SECRETS.into(),
            pap: PAP_SECRETS.into(),
        }
    }
}

impl PppoeServerApplier {
    pub fn with(sup: Supervisor, chap: PathBuf, pap: PathBuf) -> Self {
        Self { sup, chap, pap }
    }
    fn dir(&self) -> PathBuf {
        self.sup.paths.state_dir.join("pppoe-server")
    }
    fn options_path(&self) -> PathBuf {
        self.dir().join("options")
    }

    /// pppd children of this server (their command line names our options file).
    fn session_pids(&self) -> Vec<i32> {
        let opts = self.options_path().to_string_lossy().to_string();
        let mut v = Vec::new();
        if let Ok(rd) = std::fs::read_dir("/proc") {
            for e in rd.flatten() {
                let Some(pid) = e.file_name().to_str().and_then(|n| n.parse::<i32>().ok()) else {
                    continue;
                };
                let Ok(c) = std::fs::read(e.path().join("cmdline")) else {
                    continue;
                };
                let args: Vec<&[u8]> = c.split(|b| *b == 0).collect();
                let is_pppd = args.first().is_some_and(|a| a.ends_with(b"pppd"));
                let names_file = args
                    .windows(2)
                    .any(|w| w[0] == b"file" && w[1] == opts.as_bytes());
                if is_pppd && names_file {
                    v.push(pid);
                }
            }
        }
        v
    }

    async fn stop_all(&self) -> Result<bool> {
        let was = self.sup.stop(svc::DAEMON_SERVICE, INSTANCE).await?;
        // OpenRC's supervisor may leave the per-session pppd processes
        for p in self.session_pids() {
            let _ = std::process::Command::new("kill")
                .args(["-TERM", &p.to_string()])
                .status();
        }
        Ok(was)
    }

    /// Ports and devices of live sessions for the status page.
    fn sessions(&self, base: u32, n: u32) -> Vec<String> {
        let mut v = Vec::new();
        for i in 0..n.min(MAX_SESSIONS as u32) {
            let dev = format!("ppp{}", base + i);
            if !Path::new("/sys/class/net").join(&dev).exists() {
                continue;
            }
            let rd = |f: &str| {
                std::fs::read_to_string(format!("/sys/class/net/{dev}/statistics/{f}"))
                    .unwrap_or_default()
                    .trim()
                    .to_string()
            };
            let addr = std::process::Command::new("ip")
                .args(["-o", "-4", "addr", "show", "dev", &dev])
                .output()
                .ok()
                .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
                .unwrap_or_default();
            let (mut local, mut peer) = (String::new(), String::new());
            let mut it = addr.split_whitespace();
            while let Some(t) = it.next() {
                match t {
                    "inet" => local = it.next().unwrap_or("").to_string(),
                    "peer" => peer = it.next().unwrap_or("").to_string(),
                    _ => {}
                }
            }
            v.push(format!(
                "{dev}  {local} -> {peer}  rx {} B  tx {} B",
                rd("rx_bytes"),
                rd("tx_bytes")
            ));
        }
        v
    }
}

#[async_trait]
impl Applier for PppoeServerApplier {
    fn name(&self) -> &'static str {
        "pppoe-server"
    }

    fn phase(&self) -> Phase {
        Phase::Services
    }

    async fn apply(&self, store: &ConfigStore) -> Result<ApplyReport> {
        let mut rep = ApplyReport::default();
        let s = Settings::load(store, &SPEC).await?;
        let existing_chap = std::fs::read_to_string(&self.chap).unwrap_or_default();
        let existing_pap = std::fs::read_to_string(&self.pap).unwrap_or_default();
        if !s.b("enabled") {
            let was = self.stop_all().await?;
            for (p, e) in [(&self.chap, &existing_chap), (&self.pap, &existing_pap)] {
                if e.contains(BEGIN) {
                    write_atomic(p, &merge_secrets(e, &[]), 0o600)?;
                }
            }
            rep.applied(if was {
                "PPPoE server stopped"
            } else {
                "PPPoE server is off"
            });
            return Ok(rep);
        }
        let pool = check_pool(
            &s.s("local_ip"),
            &s.s("range_start"),
            &s.s("range_end"),
            s.n("max_sessions"),
        )?;
        if (s.n("unit_base") + pool) > 65_000 {
            return Err(invalid(
                "PPPoE server: the first session device number plus the session count must stay below 65000",
            ));
        }
        let mut devices: Vec<String> = Vec::new();
        for spec in s.s("interfaces").split(',') {
            let spec = spec.trim();
            if spec.is_empty() {
                continue;
            }
            for d in lan::resolve_iface(store, spec).await? {
                if !devices.contains(&d) {
                    devices.push(d);
                }
            }
        }
        if devices.is_empty() {
            return Err(invalid(
                "PPPoE server: choose at least one interface to serve on",
            ));
        }
        let wan = lan::resolve_iface(store, "@wan").await.unwrap_or_default();
        if let Some(d) = devices.iter().find(|d| wan.contains(d)) {
            return Err(invalid(format!(
                "PPPoE server: {d} is the WAN interface; serve subscribers on a LAN or optional port"
            )));
        }
        let radius = s.b("radius_enabled");
        let u = users(store).await?;
        if radius {
            if s.s("radius_server").is_empty() || s.s("radius_secret").is_empty() {
                return Err(invalid(
                    "PPPoE server: RADIUS needs a server and a shared secret",
                ));
            }
        } else {
            if u.is_empty() {
                return Err(invalid(
                    "PPPoE server: add at least one user (or use RADIUS) before enabling the server",
                ));
            }
            for x in &u {
                if x.address == s.s("local_ip") {
                    return Err(invalid(format!(
                        "PPPoE user {}: the fixed address is the server's own address",
                        x.name
                    )));
                }
            }
        }
        let server = which("pppoe-server").ok_or_else(|| {
            Error::Service(
                "the PPPoE server needs pppoe-server, which is not installed (emerge net-dialup/rp-pppoe, USE=pppoe-server)"
                    .into(),
            )
        })?;
        if which("pppd").is_none() {
            return Err(Error::Service(
                "the PPPoE server needs pppd (emerge net-dialup/ppp)".into(),
            ));
        }
        let kernel = match s.s("mode").as_str() {
            "kernel" => true,
            "userspace" => false,
            _ => pppd_plugin_exists("rp-pppoe.so") && kernel_pppoe_available(),
        };
        // user lists: pppd reads them from /etc/ppp only
        let lines = if radius {
            Vec::new()
        } else {
            secrets_block(&u)
        };
        for (p, e) in [(&self.chap, &existing_chap), (&self.pap, &existing_pap)] {
            if write_atomic(p, &merge_secrets(e, &lines), 0o600)? {
                rep.applied(format!(
                    "wrote {} PPPoE user(s) to {}",
                    lines.len(),
                    p.display()
                ));
            }
        }
        let dir = self.dir();
        let run = self.sup.paths.run_dir.clone();
        std::fs::create_dir_all(&dir)
            .map_err(|e| Error::Service(format!("{}: {e}", dir.display())))?;
        std::fs::create_dir_all(&run)
            .map_err(|e| Error::Service(format!("{}: {e}", run.display())))?;
        let opts = self.options_path();
        let mut files: Vec<(PathBuf, String, u32)> = Vec::new();
        let radius_conf = dir.join("radiusclient.conf");
        if radius {
            files.push((
                radius_conf.clone(),
                render_radius_conf(&s, &dir, &run),
                0o600,
            ));
            files.push((dir.join("radius-servers"), render_radius_servers(&s), 0o600));
            files.push((
                dir.join("radius-dictionary"),
                RADIUS_DICTIONARY.to_string(),
                0o644,
            ));
            files.push((
                dir.join("radius-portmap"),
                "# NAS-Port mapping unused\n".to_string(),
                0o644,
            ));
        } else {
            for f in [
                "radiusclient.conf",
                "radius-servers",
                "radius-dictionary",
                "radius-portmap",
            ] {
                let _ = std::fs::remove_file(dir.join(f));
            }
        }
        files.push((
            opts.clone(),
            render_options(&s, radius.then_some(radius_conf.as_path())),
            0o600,
        ));
        let argv = server_argv(
            &server,
            &s,
            &devices,
            &opts,
            &run.join("pppoe-server.pid"),
            pool,
            kernel,
        );
        let started = svc::ensure_daemon(&self.sup, INSTANCE, argv, files).await?;
        rep.applied(format!(
            "pppoe-server {} on {}: {} user(s){}, clients {}-{}, server {}, {} session(s) at most, {} sessions",
            if started { "(re)started" } else { "running, unchanged" },
            devices.join(", "),
            u.len(),
            if radius { " + RADIUS" } else { "" },
            s.s("range_start"),
            s.s("range_end"),
            s.s("local_ip"),
            pool,
            if kernel { "kernel" } else { "userspace" },
        ));
        Ok(rep)
    }

    async fn render(&self, store: &ConfigStore) -> Result<String> {
        let s = Settings::load(store, &SPEC).await?;
        if !s.b("enabled") {
            return Ok("# PPPoE server off\n".into());
        }
        let dir = self.dir();
        let radius = s.b("radius_enabled");
        let conf = dir.join("radiusclient.conf");
        let pool = check_pool(
            &s.s("local_ip"),
            &s.s("range_start"),
            &s.s("range_end"),
            s.n("max_sessions"),
        )?;
        let mut out = format!(
            "## options\n{}",
            render_options(&s, radius.then_some(conf.as_path()))
        );
        if radius {
            out.push_str(&format!(
                "## radiusclient.conf\n{}",
                render_radius_conf(&s, &dir, &self.sup.paths.run_dir)
            ));
            // the secret never appears in a plan
        } else {
            out.push_str(&format!(
                "## users\n{} enabled user(s)\n",
                users(store).await?.len()
            ));
        }
        out.push_str(&format!(
            "## pool\n{} - {} (server {}), {} session(s), devices {}\n",
            s.s("range_start"),
            s.s("range_end"),
            s.s("local_ip"),
            pool,
            {
                let d = session_patterns(&s, pool);
                match (d.first(), d.last()) {
                    (Some(f), Some(l)) => format!("{f}..{l}"),
                    _ => String::new(),
                }
            }
        ));
        Ok(out)
    }

    async fn status(&self, store: &ConfigStore) -> Result<Value> {
        let s = Settings::load(store, &SPEC).await?;
        let pool = check_pool(
            &s.s("local_ip"),
            &s.s("range_start"),
            &s.s("range_end"),
            s.n("max_sessions"),
        )
        .unwrap_or(0);
        let sessions = if s.b("enabled") {
            self.sessions(s.n("unit_base") as u32, pool as u32)
        } else {
            Vec::new()
        };
        Ok(json!({
            "enabled": s.b("enabled"),
            "installed": which("pppoe-server").is_some() && which("pppd").is_some(),
            "running": self.sup.is_running(svc::DAEMON_SERVICE, INSTANCE),
            "pool_size": pool,
            "session_count": sessions.len(),
            "sessions": sessions,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::supervise::{InitMode, NetPaths};

    #[test]
    fn unit_patterns_cover_exactly_the_range() {
        assert_eq!(
            unit_patterns(1000, 3),
            vec!["ppp1000", "ppp1001", "ppp1002"]
        );
        assert_eq!(unit_patterns(60000, 0), Vec::<String>::new());
        assert_eq!(unit_patterns(100, 4000).len(), 4000);
    }

    #[test]
    fn secrets_block_keeps_foreign_lines() {
        let base = "# mine\n\"x\" * \"y\" *\n";
        let users = vec![
            User {
                name: "alice".into(),
                password: "pw-123456".into(),
                address: String::new(),
            },
            User {
                name: "bob".into(),
                password: "pw-abcdefg".into(),
                address: "10.70.0.99".into(),
            },
        ];
        let one = merge_secrets(base, &secrets_block(&users));
        assert!(one.starts_with(base));
        assert!(one.contains("\"alice\" * \"pw-123456\" *\n"));
        assert!(one.contains("\"bob\" * \"pw-abcdefg\" 10.70.0.99\n"));
        let two = merge_secrets(&one, &secrets_block(&users[..1]));
        assert!(!two.contains("bob") && two.contains("alice"));
        assert_eq!(merge_secrets(&two, &[]), base);
    }

    #[test]
    fn pool_rules() {
        assert_eq!(
            check_pool("10.70.0.1", "10.70.0.10", "10.70.0.19", 0).unwrap(),
            10
        );
        assert_eq!(
            check_pool("10.70.0.1", "10.70.0.10", "10.70.0.19", 4).unwrap(),
            4
        );
        assert!(check_pool("10.70.0.15", "10.70.0.10", "10.70.0.19", 0).is_err());
        assert!(check_pool("10.70.0.1", "10.70.0.20", "10.70.0.19", 0).is_err());
        assert!(check_pool("10.70.0.1", "10.70.0.10", "10.70.0.19", 11).is_err());
        assert!(check_pool("10.70.0.1", "10.70.0.10", "10.70.40.19", 0).is_err());
        assert!(check_pool("fe80::1", "10.70.0.10", "10.70.0.19", 0).is_err());
    }

    #[test]
    fn router_ports_are_normalised() {
        assert_eq!(
            check_router_ports("UDP/53, tcp/22,tcp/8000-8010").unwrap(),
            "udp/53,tcp/22,tcp/8000-8010"
        );
        assert_eq!(check_router_ports("").unwrap(), "");
        for bad in ["53", "icmp/1", "tcp/0", "tcp/70000", "tcp/9-1", "tcp/a"] {
            assert!(check_router_ports(bad).is_err(), "{bad}");
        }
    }

    #[tokio::test]
    async fn settings_users_and_rendering() {
        let s = crate::lan::testutil::store().await;
        let d = tempfile::tempdir().unwrap();
        let chap = d.path().join("chap-secrets");
        let pap = d.path().join("pap-secrets");
        std::fs::write(&chap, "# keep\n").unwrap();
        let a = PppoeServerApplier::with(
            Supervisor::new(InitMode::Direct, NetPaths::under(d.path())),
            chap.clone(),
            pap.clone(),
        );
        // off: nothing happens
        a.apply(&s).await.unwrap();
        // validation of settings
        let svc = PppoeServerSvc;
        for bad in [
            json!({"range_start": "10.70.0.1"}),
            json!({"max_sessions": 5000}),
            json!({"mtu": 100}),
            json!({"auth": "plain"}),
            json!({"router_ports": "53"}),
            json!({"unit_base": 5}),
            json!({"nope": 1}),
        ] {
            assert!(svc.put(&s, &bad).await.is_err(), "{bad}");
        }
        svc.put(&s, &json!({"enabled": true, "interfaces": "eth9"}))
            .await
            .unwrap();
        assert!(a.apply(&s).await.unwrap_err().to_string().contains("user"));
        let c = &SPEC.colls[0];
        for bad in [
            json!({"username": "a b", "password": "<redacted:password>"}),
            json!({"username": "alice", "password": "short"}),
            json!({"username": "alice", "password": "pass\"word123"}),
            json!({"username": "alice"}),
            json!({"username": "alice", "password": "alice-secret-1", "address": "10.70.0.1"}),
            json!({"username": "alice", "password": "alice-secret-1", "address": "nope"}),
        ] {
            assert!(
                svc.save_row(&s, "users", None, &bad).await.is_err(),
                "{bad}"
            );
        }
        svc.save_row(
            &s,
            "users",
            None,
            &json!({"username": "alice", "password": "alice-secret-1", "address": "10.70.0.77"}),
        )
        .await
        .unwrap();
        // the same fixed address twice is refused
        assert!(svc
            .save_row(
                &s,
                "users",
                None,
                &json!({"username": "bob", "password": "bob-secret-123", "address": "10.70.0.77"})
            )
            .await
            .is_err());
        let rows = svc::list_rows(&s, c).await.unwrap();
        assert_eq!(rows[0]["password"], json!(svc::SECRET_MASK));
        assert_eq!(users(&s).await.unwrap()[0].password, "alice-secret-1");
        let st = Settings::load(&s, &SPEC).await.unwrap();
        let o = render_options(&st, None);
        assert!(
            o.contains("require-chap")
                && o.contains("mtu 1492")
                && o.contains("lcp-echo-interval 30")
        );
        assert!(!o.contains("radius"));
        svc.put(
            &s,
            &json!({"auth": "pap", "dns1": "192.0.2.53", "idle_timeout": 600}),
        )
        .await
        .unwrap();
        let st = Settings::load(&s, &SPEC).await.unwrap();
        let o = render_options(&st, Some(Path::new("/x/radiusclient.conf")));
        assert!(
            o.contains("require-pap") && o.contains("ms-dns 192.0.2.53") && o.contains("idle 600")
        );
        assert!(o.contains("plugin radius.so\nradius-config-file /x/radiusclient.conf"));
        // plan: text, no secrets
        let plan = a.render(&s).await.unwrap();
        assert!(plan.contains("ppp1000..ppp1190") && !plan.contains("alice-secret-1"));
        // radius: files carry the secret only where they must
        svc.put(&s, &json!({"radius_enabled": true, "radius_server": "192.0.2.10", "radius_secret": "radius-secret-1", "radius_source": "192.0.2.1"})).await.unwrap();
        let st = Settings::load(&s, &SPEC).await.unwrap();
        let rc = render_radius_conf(&st, Path::new("/d"), Path::new("/r"));
        assert!(
            rc.contains("authserver 192.0.2.10:1812")
                && rc.contains("bindaddr 192.0.2.1")
                && !rc.contains("radius-secret-1")
        );
        assert!(render_radius_servers(&st).contains("192.0.2.10 radius-secret-1"));
        assert!(!a.render(&s).await.unwrap().contains("radius-secret-1"));
        let argv = server_argv(
            Path::new("/usr/sbin/pppoe-server"),
            &st,
            &["eth1".into(), "eth2".into()],
            Path::new("/o"),
            Path::new("/p"),
            191,
            true,
        );
        let j = argv.join(" ");
        assert!(
            j.contains("-I eth1 -I eth2")
                && j.contains("-L 10.70.0.1 -R 10.70.0.10 -N 191")
                && j.contains("-u -o 1000")
                && j.ends_with("-k")
        );
    }
}
