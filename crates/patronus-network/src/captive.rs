//! Captive portal configuration and kernel side (USE=captive-portal, lane u).
//!
//! The way pfSense/OPNsense captive portals, UniFi hotspots and OpenWrt's
//! openNDS work: clients on a portal zone (an interface, VLAN or bridge,
//! wired or wireless) reach nothing beyond the router until they sign in on a
//! splash page; then their MAC + IPv4 address is let through until an idle or
//! hard timeout, a logout, or an administrator's disconnect.
//!
//! This module owns the configuration (the generic feature page `captive`:
//! global `captive.*` settings in `lan_settings` and the collections zones,
//! users, voucher rolls, passthrough) and the [`CaptiveApplier`], which loads
//! the own nft table `inet patronus_portal`:
//!
//! - per zone `z<id>`: sets `z<id>_auth` (ether_addr . ipv4_addr, element
//!   timeout = what is left of the hard timeout, so the kernel ends a session
//!   by itself even if no Patronus process runs), `z<id>_amac` (MACs of
//!   signed-in clients for their IPv6 traffic), `z<id>_seen` (dynamic, idle
//!   timeout: every forwarded packet of a signed-in client refreshes it, the
//!   portal ends sessions that fall out of it), `z<id>_mpass` / `z<id>_ipass`
//!   (passthrough client MACs / client networks) and `z<id>_dpass` (addresses
//!   of the allowed destination host names, resolved at apply time);
//! - chain `prerouting` (nat, priority -105, before the main table's dstnat):
//!   an unauthenticated client's TCP 80 to anywhere, and TCP 443 to the
//!   router itself, are redirected to the portal listeners
//!   (`captive.http_port` / `captive.https_port`), so the splash page is at
//!   `http(s)://<router address>/` on the standard ports;
//! - chain `forward` (filter, priority -16: before the guest network,
//!   segmentation and the main table): passthrough and signed-in clients fall
//!   through to the other tables, everything else from the zone is dropped
//!   (TCP gets a reset so browsers fail fast). The table only ever drops or
//!   falls through; the main table still decides what a signed-in client may
//!   reach (`patronus-firewall/src/svc_rules.rs` adds the DHCP, DNS and
//!   portal-port accepts on zone interfaces).
//!
//! Active sessions live in `cp_sessions` (runtime state, NON_CONFIG); every
//! apply re-adds their elements with the time they have left, so a firewall
//! reload or a reboot does not sign anyone out early. The sign-in pages,
//! RADIUS, vouchers, `tc` bandwidth classes and session bookkeeping are the
//! `patronus-captiveportal` crate, served by patronus-web.

use crate::lan::{self, invalid, IfAddr};
use crate::svc::{self, Coll, Field, Kind, Settings, Spec, Svc};
use async_trait::async_trait;
use patronus_config::applier::{Applier, ApplyReport, Phase};
use patronus_config::store::ConfigStore;
use patronus_core::{Error, Result};
use serde::Serialize;
use serde_json::{json, Map, Value};
use sqlx::Row;
use std::collections::{BTreeMap, HashMap};
use std::net::{IpAddr, Ipv4Addr};

pub const TABLE: &str = "patronus_portal";
/// Login backends of a zone.
pub const AUTHS: &[&str] = &["none", "local", "voucher", "radius"];
const PASS_KINDS: &[&str] = &["mac", "ip", "host"];
/// Ports a portal listener may never take (SSH, DNS, DHCP, the web UI's standard ports).
const RESERVED_PORTS: &[i64] = &[22, 53, 67, 68, 80, 443];

static FIELDS: [Field; 9] = [
    Field::new("http_port", "Portal HTTP port", Kind::Int(1024, 65535))
        .def("8002")
        .help("Where unauthenticated clients' web requests are redirected (internal; clients use port 80)"),
    Field::new("https_port", "Portal HTTPS port", Kind::Int(1024, 65535))
        .def("8003")
        .help("The HTTPS portal: login page, status/logout page and the RFC 8908 API"),
    Field::new("hostname", "Portal host name", Kind::Host)
        .help("Name in redirects and the DHCP captive-portal option (empty = the router's address on the zone); use one your certificate covers"),
    Field::new("tls_cert", "Portal certificate file", Kind::Token)
        .help("PEM certificate for the HTTPS portal (empty = the web UI's certificate)"),
    Field::new("tls_key", "Portal key file", Kind::Token).help("PEM private key of that certificate"),
    Field::new("session_retention_days", "Keep ended sessions (days)", Kind::Int(1, 3650))
        .def("30"),
    Field::new("acct_interim_secs", "RADIUS interim accounting (seconds)", Kind::Int(0, 86400))
        .def("300")
        .help("0 = only start and stop"),
    Field::new("voucher_code_length", "Voucher code length", Kind::Int(6, 20)).def("10"),
    Field::new("poll_secs", "Session check interval (seconds)", Kind::Int(1, 60))
        .def("2")
        .help("How often idle/hard timeouts and disconnects are checked"),
];

static ZONE_FIELDS: [Field; 31] = [
    Field::new("name", "Zone", Kind::Token).req(),
    Field::new("enabled", "Enabled", Kind::Bool).def("1"),
    Field::new("interface", "Interface", Kind::Iface)
        .req()
        .help("@lan, @optN, a VLAN (eth0.30) or a bridge (br-guest); wired or wireless"),
    Field::new("auth", "Login", Kind::Select(AUTHS))
        .def("none")
        .help("none = accept the terms and click; local = portal users; voucher = codes of a roll; radius = a RADIUS server"),
    Field::new("radius_server", "RADIUS server", Kind::Host),
    Field::new("radius_port", "RADIUS auth port", Kind::Int(1, 65535)).def("1812"),
    Field::new("radius_acct_port", "RADIUS accounting port", Kind::Int(1, 65535)).def("1813"),
    Field::new("radius_secret", "RADIUS shared secret", Kind::Secret),
    Field::new("radius_accounting", "RADIUS accounting", Kind::Bool).def("1"),
    Field::new("radius_nas_id", "NAS identifier", Kind::Token).def("patronus"),
    Field::new("radius_timeout_secs", "RADIUS timeout (seconds)", Kind::Int(1, 30)).def("3"),
    Field::new("idle_minutes", "Idle timeout (minutes)", Kind::Int(0, 10080))
        .def("30")
        .help("0 = off"),
    Field::new("hard_minutes", "Hard timeout (minutes)", Kind::Int(0, 525600))
        .def("480")
        .help("Session length; 0 = until idle or logout"),
    Field::new("download_kbit", "Download per client (kbit/s)", Kind::Int(0, 10_000_000))
        .def("0")
        .help("0 = no limit"),
    Field::new("upload_kbit", "Upload per client (kbit/s)", Kind::Int(0, 10_000_000))
        .def("0")
        .help("0 = no limit"),
    Field::new("terms_required", "Terms must be accepted", Kind::Bool).def("1"),
    Field::new("https_login", "Login page over HTTPS", Kind::Bool)
        .def("1")
        .help("Off = serve the login page over plain HTTP (no certificate warning on devices that do not trust it)"),
    Field::new("redirect_url", "After login go to", Kind::Text)
        .help("http(s) URL; empty = the page the client first asked for"),
    Field::new("page_title", "Page title", Kind::Text).def("Welcome"),
    Field::new("welcome_text", "Welcome text", Kind::Text).def("Sign in to use this network."),
    Field::new("terms_text", "Terms", Kind::Text)
        .def("I will use this network lawfully and fairly."),
    Field::new("button_text", "Login button", Kind::Text).def("Connect"),
    Field::new("success_text", "Signed-in text", Kind::Text).def("You are online."),
    Field::new("logout_text", "Logout button", Kind::Text).def("Disconnect"),
    Field::new("user_label", "User name label", Kind::Text).def("User name"),
    Field::new("password_label", "Password label", Kind::Text).def("Password"),
    Field::new("voucher_label", "Voucher label", Kind::Text).def("Voucher code"),
    Field::new("error_text", "Login refused text", Kind::Text)
        .def("That did not work. Check what you typed and try again."),
    Field::new("accent_color", "Accent colour", Kind::Token)
        .help("#rrggbb for the button; empty = the built-in theme"),
    Field::new("description", "Description", Kind::Text),
    Field::new("max_sessions", "Sessions per account", Kind::Int(0, 1000))
        .def("0")
        .help("Local/RADIUS users and vouchers: how many devices at once (0 = no limit)"),
];

static USER_FIELDS: [Field; 5] = [
    Field::new("username", "User name", Kind::Token).req(),
    Field::new("password", "Password", Kind::Secret).req(),
    Field::new("zone", "Zone", Kind::Token).help("Empty = every zone with local login"),
    Field::new("enabled", "Enabled", Kind::Bool).def("1"),
    Field::new("description", "Description", Kind::Text),
];

static ROLL_FIELDS: [Field; 5] = [
    Field::new("name", "Roll", Kind::Token).req(),
    Field::new("zone", "Zone", Kind::Token).req(),
    Field::new("count", "Vouchers", Kind::Int(1, 1000)).def("20"),
    Field::new("minutes", "Minutes each", Kind::Int(1, 525600))
        .def("60")
        .help("Counted from a voucher's first use"),
    Field::new("description", "Description", Kind::Text),
];

static PASS_FIELDS: [Field; 4] = [
    Field::new("zone", "Zone", Kind::Token).req(),
    Field::new("kind", "Type", Kind::Select(PASS_KINDS))
        .req()
        .help("mac / ip = a client that never sees the portal; host = a destination reachable before login"),
    Field::new("value", "MAC, address/network or host name", Kind::Token).req(),
    Field::new("description", "Description", Kind::Text),
];

pub static ZONES: Coll = Coll {
    key: "zones",
    title: "Zones",
    table: "cp_zones",
    fields: &ZONE_FIELDS,
    unique: Some("name"),
};
pub static USERS: Coll = Coll {
    key: "users",
    title: "Portal users",
    table: "cp_users",
    fields: &USER_FIELDS,
    unique: Some("username"),
};
pub static ROLLS: Coll = Coll {
    key: "rolls",
    title: "Voucher rolls",
    table: "cp_voucher_rolls",
    fields: &ROLL_FIELDS,
    unique: Some("name"),
};
pub static PASS: Coll = Coll {
    key: "passthrough",
    title: "Passthrough",
    table: "cp_passthrough",
    fields: &PASS_FIELDS,
    unique: None,
};

static COLLS: [Coll; 4] = [
    Coll {
        key: "zones",
        title: "Zones",
        table: "cp_zones",
        fields: &ZONE_FIELDS,
        unique: Some("name"),
    },
    Coll {
        key: "users",
        title: "Portal users",
        table: "cp_users",
        fields: &USER_FIELDS,
        unique: Some("username"),
    },
    Coll {
        key: "rolls",
        title: "Voucher rolls",
        table: "cp_voucher_rolls",
        fields: &ROLL_FIELDS,
        unique: Some("name"),
    },
    Coll {
        key: "passthrough",
        title: "Passthrough",
        table: "cp_passthrough",
        fields: &PASS_FIELDS,
        unique: None,
    },
];

pub static SPEC: Spec = Spec {
    slug: "captive",
    title: "Captive portal",
    blurb: "Sign-in page for clients of a zone (an interface, VLAN or guest network): click-through with terms, portal users, voucher rolls or RADIUS, with idle and hard timeouts, per-client bandwidth and passthrough lists. Signed-in clients, disconnects and voucher sheets: Captive portal sessions page.",
    applier: "captive",
    fields: &FIELDS,
    colls: &COLLS,
    actions: &[("disconnect", "Disconnect a session")],
};

/// Tables this feature's configuration edits change (lane undo snapshot).
pub const CONFIG_TABLES: &[&str] = &[
    "cp_zones",
    "cp_users",
    "cp_voucher_rolls",
    "cp_vouchers",
    "cp_passthrough",
];

// ---------------------------------------------------------------------------
// typed views
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
pub struct Globals {
    pub http_port: u16,
    pub https_port: u16,
    pub hostname: String,
    pub tls_cert: String,
    pub tls_key: String,
    pub retention_days: i64,
    pub interim_secs: i64,
    pub code_len: usize,
    pub poll_secs: u64,
}

impl Globals {
    pub fn from_settings(s: &Settings) -> Self {
        Self {
            http_port: u16::try_from(s.n("http_port")).unwrap_or(8002),
            https_port: u16::try_from(s.n("https_port")).unwrap_or(8003),
            hostname: s.s("hostname"),
            tls_cert: s.s("tls_cert"),
            tls_key: s.s("tls_key"),
            retention_days: s.n("session_retention_days").max(1),
            interim_secs: s.n("acct_interim_secs").max(0),
            code_len: usize::try_from(s.n("voucher_code_length"))
                .unwrap_or(10)
                .clamp(6, 20),
            poll_secs: u64::try_from(s.n("poll_secs")).unwrap_or(2).clamp(1, 60),
        }
    }

    pub async fn load(store: &ConfigStore) -> Result<Self> {
        Ok(Self::from_settings(&Settings::load(store, &SPEC).await?))
    }

    fn check(&self) -> Result<()> {
        for p in [self.http_port, self.https_port] {
            if RESERVED_PORTS.contains(&i64::from(p)) {
                return Err(invalid(format!(
                    "portal port {p} (reserved for SSH, DNS, DHCP or the web UI)"
                )));
            }
        }
        if self.http_port == self.https_port {
            return Err(invalid("portal ports (HTTP and HTTPS must differ)"));
        }
        if self.tls_cert.is_empty() != self.tls_key.is_empty() {
            return Err(invalid(
                "portal certificate (set both the certificate and the key file, or neither)",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Radius {
    pub server: String,
    pub port: u16,
    pub acct_port: u16,
    #[serde(skip)]
    pub secret: String,
    pub accounting: bool,
    pub nas_id: String,
    pub timeout_secs: u64,
}

/// Every text on the portal pages (from the zone's settings).
#[derive(Debug, Clone, Serialize)]
pub struct PageText {
    pub title: String,
    pub welcome: String,
    pub terms: String,
    pub button: String,
    pub success: String,
    pub logout: String,
    pub user_label: String,
    pub password_label: String,
    pub voucher_label: String,
    pub error: String,
    pub accent: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Zone {
    pub id: i64,
    pub name: String,
    pub enabled: bool,
    pub interface: String,
    pub auth: String,
    pub radius: Radius,
    pub idle_minutes: i64,
    pub hard_minutes: i64,
    pub download_kbit: i64,
    pub upload_kbit: i64,
    pub terms_required: bool,
    pub https_login: bool,
    pub redirect_url: String,
    pub max_sessions: i64,
    pub page: PageText,
}

impl Zone {
    pub fn set(&self, what: &str) -> String {
        format!("z{}_{what}", self.id)
    }
}

fn field_default(fields: &[Field], key: &str) -> &'static str {
    fields
        .iter()
        .find(|f| f.key == key)
        .map(|f| f.default)
        .unwrap_or("")
}

fn row_s(r: &Map<String, Value>, fields: &[Field], k: &str) -> String {
    match r.get(k).and_then(Value::as_str) {
        Some(v) if !v.is_empty() => v.to_string(),
        _ => field_default(fields, k).to_string(),
    }
}

fn row_n(r: &Map<String, Value>, fields: &[Field], k: &str) -> i64 {
    row_s(r, fields, k).parse().unwrap_or(0)
}

fn row_b(r: &Map<String, Value>, fields: &[Field], k: &str) -> bool {
    lan::flag(&row_s(r, fields, k))
}

pub fn zone_from_row(r: &Map<String, Value>) -> Zone {
    let f = &ZONE_FIELDS[..];
    Zone {
        id: r.get("id").and_then(Value::as_i64).unwrap_or(0),
        name: row_s(r, f, "name"),
        enabled: row_b(r, f, "enabled"),
        interface: row_s(r, f, "interface"),
        auth: row_s(r, f, "auth"),
        radius: Radius {
            server: row_s(r, f, "radius_server"),
            port: u16::try_from(row_n(r, f, "radius_port")).unwrap_or(1812),
            acct_port: u16::try_from(row_n(r, f, "radius_acct_port")).unwrap_or(1813),
            secret: row_s(r, f, "radius_secret"),
            accounting: row_b(r, f, "radius_accounting"),
            nas_id: row_s(r, f, "radius_nas_id"),
            timeout_secs: u64::try_from(row_n(r, f, "radius_timeout_secs"))
                .unwrap_or(3)
                .clamp(1, 30),
        },
        idle_minutes: row_n(r, f, "idle_minutes").max(0),
        hard_minutes: row_n(r, f, "hard_minutes").max(0),
        download_kbit: row_n(r, f, "download_kbit").max(0),
        upload_kbit: row_n(r, f, "upload_kbit").max(0),
        terms_required: row_b(r, f, "terms_required"),
        https_login: row_b(r, f, "https_login"),
        redirect_url: r
            .get("redirect_url")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
        max_sessions: row_n(r, f, "max_sessions").max(0),
        page: PageText {
            title: row_s(r, f, "page_title"),
            welcome: row_s(r, f, "welcome_text"),
            terms: row_s(r, f, "terms_text"),
            button: row_s(r, f, "button_text"),
            success: row_s(r, f, "success_text"),
            logout: row_s(r, f, "logout_text"),
            user_label: row_s(r, f, "user_label"),
            password_label: row_s(r, f, "password_label"),
            voucher_label: row_s(r, f, "voucher_label"),
            error: row_s(r, f, "error_text"),
            accent: r
                .get("accent_color")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
        },
    }
}

/// Every zone (enabled or not), ordered by id.
pub async fn zones(store: &ConfigStore) -> Result<Vec<Zone>> {
    Ok(svc::raw_rows(store, &ZONES)
        .await?
        .iter()
        .map(zone_from_row)
        .collect())
}

#[derive(Debug, Clone, Serialize)]
pub struct Pass {
    pub zone: String,
    pub kind: String,
    pub value: String,
}

pub async fn passthrough(store: &ConfigStore) -> Result<Vec<Pass>> {
    Ok(svc::raw_rows(store, &PASS)
        .await?
        .iter()
        .map(|r| Pass {
            zone: row_s(r, &PASS_FIELDS, "zone"),
            kind: row_s(r, &PASS_FIELDS, "kind"),
            value: row_s(r, &PASS_FIELDS, "value"),
        })
        .collect())
}

/// A signed-in client whose kernel elements an apply must keep.
#[derive(Debug, Clone, Serialize)]
pub struct ActiveSession {
    pub id: i64,
    pub zone: String,
    pub ip: Ipv4Addr,
    pub mac: String,
    /// Unix time of the hard timeout (0 = none).
    pub expires: i64,
}

pub async fn active_sessions(store: &ConfigStore, now: i64) -> Result<Vec<ActiveSession>> {
    let rows = sqlx::query(
        "SELECT id, zone, ip, mac, expires FROM cp_sessions \
         WHERE ended IS NULL AND (expires = 0 OR expires > ?) ORDER BY id",
    )
    .bind(now)
    .fetch_all(store.pool()?)
    .await
    .map_err(lan::db_err("read portal sessions"))?;
    Ok(rows
        .iter()
        .filter_map(|r| {
            Some(ActiveSession {
                id: r.get(0),
                zone: r.get(1),
                ip: r.get::<String, _>(2).parse().ok()?,
                mac: lan::check_mac(&r.get::<String, _>(3)).ok()?,
                expires: r.get(4),
            })
        })
        .collect())
}

// ---------------------------------------------------------------------------
// the nft table
// ---------------------------------------------------------------------------

/// A zone ready to render: its devices and its resolved passthrough.
#[derive(Debug, Clone, Default)]
pub struct ZonePlan {
    pub devs: Vec<String>,
    pub macs: Vec<String>,
    pub nets: Vec<String>,
    pub dsts: Vec<Ipv4Addr>,
}

fn qdevs(devs: &[String]) -> String {
    format!(
        "{{ {} }}",
        devs.iter()
            .map(|d| format!("\"{d}\""))
            .collect::<Vec<_>>()
            .join(", ")
    )
}

fn elements(v: &[String]) -> String {
    if v.is_empty() {
        String::new()
    } else {
        format!(" elements = {{ {} }};", v.join(", "))
    }
}

/// Seconds an element keeps for a session expiring at `expires` (None = no timeout).
pub fn remaining(expires: i64, now: i64) -> Option<i64> {
    (expires > 0).then(|| (expires - now).max(1))
}

/// The whole `inet patronus_portal` table (replaces the old one atomically).
pub fn render_nft(
    g: &Globals,
    zones: &[(Zone, ZonePlan)],
    sessions: &[ActiveSession],
    now: i64,
) -> String {
    let t = format!("inet {TABLE}");
    let mut o = format!("table {t}\ndelete table {t}\ntable {t} {{\n");
    for (z, p) in zones {
        let mine: Vec<&ActiveSession> = sessions.iter().filter(|s| s.zone == z.name).collect();
        let auth: Vec<String> = mine
            .iter()
            .map(|s| match remaining(s.expires, now) {
                Some(r) => format!("{} . {} timeout {r}s", s.mac, s.ip),
                None => format!("{} . {}", s.mac, s.ip),
            })
            .collect();
        let mut amac: Vec<String> = Vec::new();
        for s in &mine {
            let e = match remaining(s.expires, now) {
                Some(r) => format!("{} timeout {r}s", s.mac),
                None => s.mac.clone(),
            };
            if !amac.iter().any(|x| x.starts_with(&s.mac)) {
                amac.push(e);
            }
        }
        o.push_str(&format!(
            "  set {} {{ type ether_addr . ipv4_addr; flags timeout;{} }}\n",
            z.set("auth"),
            elements(&auth)
        ));
        o.push_str(&format!(
            "  set {} {{ type ether_addr; flags timeout;{} }}\n",
            z.set("amac"),
            elements(&amac)
        ));
        if z.idle_minutes > 0 {
            let seen: Vec<String> = mine
                .iter()
                .map(|s| format!("{} . {}", s.mac, s.ip))
                .collect();
            o.push_str(&format!(
                "  set {} {{ type ether_addr . ipv4_addr; flags dynamic, timeout; timeout {}s;{} }}\n",
                z.set("seen"),
                z.idle_minutes * 60,
                elements(&seen)
            ));
        }
        o.push_str(&format!(
            "  set {} {{ type ether_addr;{} }}\n",
            z.set("mpass"),
            elements(&p.macs)
        ));
        o.push_str(&format!(
            "  set {} {{ type ipv4_addr; flags interval;{} }}\n",
            z.set("ipass"),
            elements(&p.nets)
        ));
        let dsts: Vec<String> = p.dsts.iter().map(|a| a.to_string()).collect();
        o.push_str(&format!(
            "  set {} {{ type ipv4_addr;{} }}\n",
            z.set("dpass"),
            elements(&dsts)
        ));
    }
    // redirect of unauthenticated web traffic to the portal listeners
    o.push_str(
        "  chain prerouting {\n    type nat hook prerouting priority -105; policy accept;\n",
    );
    for (z, p) in zones {
        o.push_str(&format!(
            "    iifname {} meta nfproto ipv4 jump {}\n",
            qdevs(&p.devs),
            z.set("pre")
        ));
    }
    o.push_str("  }\n");
    for (z, _) in zones {
        o.push_str(&format!(
            "  chain {} {{\n    ether saddr @{} return\n    ip saddr @{} return\n    ether saddr . ip saddr @{} return\n    ip daddr @{} return\n    tcp dport 80 redirect to :{} comment \"portal {}\"\n    fib daddr type local tcp dport 443 redirect to :{} comment \"portal {}\"\n  }}\n",
            z.set("pre"),
            z.set("mpass"),
            z.set("ipass"),
            z.set("auth"),
            z.set("dpass"),
            g.http_port,
            z.name,
            g.https_port,
            z.name
        ));
    }
    // the gate
    o.push_str("  chain forward {\n    type filter hook forward priority -16; policy accept;\n");
    for (z, p) in zones {
        o.push_str(&format!(
            "    iifname {} jump {}\n",
            qdevs(&p.devs),
            z.set("fwd")
        ));
    }
    o.push_str("  }\n");
    for (z, _) in zones {
        let signed_in = if z.idle_minutes > 0 {
            format!(
                "    meta nfproto ipv4 ether saddr . ip saddr @{} update @{} {{ ether saddr . ip saddr }} return\n",
                z.set("auth"),
                z.set("seen")
            )
        } else {
            format!(
                "    meta nfproto ipv4 ether saddr . ip saddr @{} return\n",
                z.set("auth")
            )
        };
        o.push_str(&format!(
            "  chain {} {{\n    ether saddr @{} return\n    meta nfproto ipv4 ip saddr @{} return\n{signed_in}    meta nfproto ipv6 ether saddr @{} return\n    meta nfproto ipv4 ip daddr @{} return\n    meta l4proto tcp reject with tcp reset comment \"portal {}: not signed in\"\n    counter drop comment \"portal {}: not signed in\"\n  }}\n",
            z.set("fwd"),
            z.set("mpass"),
            z.set("ipass"),
            z.set("amac"),
            z.set("dpass"),
            z.name,
            z.name
        ));
    }
    o.push_str("}\n");
    o
}

/// Resolve a zone's passthrough rows. Host names are looked up now (their
/// addresses are what the kernel can match); a failed lookup is a warning.
pub fn plan_pass(zone: &Zone, pass: &[Pass], warn: &mut Vec<String>) -> ZonePlan {
    let mut p = ZonePlan::default();
    for e in pass.iter().filter(|e| e.zone == zone.name) {
        match e.kind.as_str() {
            "mac" => match lan::check_mac(&e.value) {
                Ok(m) if !p.macs.contains(&m) => p.macs.push(m),
                Ok(_) => {}
                Err(_) => warn.push(format!(
                    "portal {}: bad MAC {:?} skipped",
                    zone.name, e.value
                )),
            },
            "ip" => match check_net4(&e.value) {
                Ok(n) if !p.nets.contains(&n) => p.nets.push(n),
                Ok(_) => {}
                Err(_) => warn.push(format!(
                    "portal {}: bad address {:?} skipped",
                    zone.name, e.value
                )),
            },
            "host" => {
                if let Ok(ip) = e.value.parse::<Ipv4Addr>() {
                    if !p.dsts.contains(&ip) {
                        p.dsts.push(ip);
                    }
                    continue;
                }
                use std::net::ToSocketAddrs;
                match (e.value.as_str(), 0u16).to_socket_addrs() {
                    Ok(addrs) => {
                        let mut any = false;
                        for a in addrs {
                            if let IpAddr::V4(v4) = a.ip() {
                                any = true;
                                if !p.dsts.contains(&v4) {
                                    p.dsts.push(v4);
                                }
                            }
                        }
                        if !any {
                            warn.push(format!(
                                "portal {}: {} has no IPv4 address",
                                zone.name, e.value
                            ));
                        }
                    }
                    Err(err) => warn.push(format!(
                        "portal {}: cannot resolve {}: {err}",
                        zone.name, e.value
                    )),
                }
            }
            _ => {}
        }
    }
    p.dsts.sort();
    p
}

fn check_net4(s: &str) -> Result<String> {
    let n: ipnetwork::IpNetwork = s
        .parse()
        .map_err(|_| invalid(format!("address or network {s:?}")))?;
    match n {
        ipnetwork::IpNetwork::V4(n4) => {
            if n4.prefix() == 32 {
                Ok(n4.ip().to_string())
            } else {
                Ok(format!("{}/{}", n4.network(), n4.prefix()))
            }
        }
        _ => Err(invalid(format!("IPv4 address or network {s:?}"))),
    }
}

/// The portal's URL for a client on `router` (its address on the zone).
pub fn portal_base(g: &Globals, router: Ipv4Addr) -> String {
    let host = if g.hostname.is_empty() {
        router.to_string()
    } else {
        g.hostname.clone()
    };
    format!("https://{host}:{}", g.https_port)
}

/// RFC 8908 API URI per device (DHCP option 114 / RFC 8910), for the DHCP server.
pub async fn dhcp_api_urls(store: &ConfigStore, addrs: &[IfAddr]) -> HashMap<String, String> {
    let mut out = HashMap::new();
    let Ok(g) = Globals::load(store).await else {
        return out;
    };
    let Ok(zs) = zones(store).await else {
        return out;
    };
    for z in zs.iter().filter(|z| z.enabled) {
        for dev in lan::resolve_iface(store, &z.interface)
            .await
            .unwrap_or_default()
        {
            if let Some(IpAddr::V4(a)) = addrs
                .iter()
                .find(|a| a.ifname == dev && a.addr.is_ipv4())
                .map(|a| a.addr)
            {
                out.insert(dev.clone(), format!("{}/api/captive", portal_base(&g, a)));
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------
// the page
// ---------------------------------------------------------------------------

pub struct CaptiveSvc;

/// `n` random characters from an unambiguous 32-letter alphabet (/dev/urandom).
pub fn random_code(n: usize) -> Result<String> {
    use std::io::Read;
    const A: &[u8; 32] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    let mut buf = vec![0u8; n];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut buf))
        .map_err(|e| Error::Network(format!("random: {e}")))?;
    Ok(buf
        .iter()
        .map(|b| A[usize::from(*b) % 32] as char)
        .collect())
}

fn check_url(s: &str) -> Result<()> {
    if s.is_empty() {
        return Ok(());
    }
    let ok = (s.starts_with("http://") || s.starts_with("https://"))
        && s.len() <= 200
        && s.bytes()
            .all(|b| (0x21..0x7f).contains(&b) && b != b'"' && b != b'<' && b != b'>');
    if ok {
        Ok(())
    } else {
        Err(invalid("after-login URL (an http:// or https:// address)"))
    }
}

fn check_color(s: &str) -> Result<()> {
    if s.is_empty()
        || (s.len() == 7 && s.starts_with('#') && s[1..].bytes().all(|b| b.is_ascii_hexdigit()))
    {
        Ok(())
    } else {
        Err(invalid("accent colour (#rrggbb)"))
    }
}

async fn zone_names(store: &ConfigStore) -> Result<Vec<String>> {
    Ok(zones(store).await?.into_iter().map(|z| z.name).collect())
}

/// Row `id` of `c` merged with `body` (what the row would be after the save).
async fn merged_row(
    store: &ConfigStore,
    c: &Coll,
    id: Option<i64>,
    body: &Value,
) -> Result<Map<String, Value>> {
    let mut row = match id {
        Some(id) => svc::raw_rows(store, c)
            .await?
            .into_iter()
            .find(|r| r["id"].as_i64() == Some(id))
            .ok_or_else(|| Error::Config(format!("no {} {id}", c.key)))?,
        None => Map::new(),
    };
    if let Some(obj) = body.as_object() {
        for f in c.fields {
            if let Some(v) = obj.get(f.key) {
                let s = svc::check(f, v)?;
                if f.kind == Kind::Secret && (s == svc::SECRET_MASK || s.is_empty()) {
                    continue;
                }
                row.insert(f.key.into(), Value::String(s));
            }
        }
    }
    Ok(row)
}

async fn check_zone(store: &ConfigStore, id: Option<i64>, body: &Value) -> Result<()> {
    let row = merged_row(store, &ZONES, id, body).await?;
    let z = zone_from_row(&row);
    if z.auth == "radius" && (z.radius.server.is_empty() || z.radius.secret.is_empty()) {
        return Err(invalid(
            "RADIUS login (needs the RADIUS server and its shared secret)",
        ));
    }
    check_url(&z.redirect_url)?;
    check_color(&z.page.accent)?;
    if z.enabled {
        for other in zones(store).await? {
            if Some(other.id) != id && other.enabled && other.interface == z.interface {
                return Err(invalid(format!(
                    "interface {} (zone {} already runs a portal there)",
                    z.interface, other.name
                )));
            }
        }
    }
    Ok(())
}

async fn check_zone_ref(store: &ConfigStore, zone: &str, empty_ok: bool) -> Result<()> {
    if zone.is_empty() && empty_ok {
        return Ok(());
    }
    if zone_names(store).await?.iter().any(|z| z == zone) {
        Ok(())
    } else {
        Err(invalid(format!("zone {zone:?} (no such zone)")))
    }
}

async fn generate_codes(store: &ConfigStore, roll_id: i64, count: i64, len: usize) -> Result<()> {
    let pool = store.pool()?;
    let mut made = 0;
    let mut tries = 0;
    while made < count {
        tries += 1;
        if tries > count * 20 + 100 {
            return Err(Error::Config("voucher codes: too many collisions".into()));
        }
        let code = random_code(len)?;
        let r = sqlx::query(
            "INSERT OR IGNORE INTO cp_vouchers (roll_id, code, updated_at) VALUES (?, ?, ?)",
        )
        .bind(roll_id)
        .bind(&code)
        .bind(lan::now())
        .execute(pool)
        .await
        .map_err(lan::db_err("save voucher"))?;
        made += r.rows_affected() as i64;
    }
    Ok(())
}

/// The codes of a roll.
pub async fn roll_codes(store: &ConfigStore, roll_id: i64) -> Result<Vec<String>> {
    let rows = sqlx::query("SELECT code FROM cp_vouchers WHERE roll_id = ? ORDER BY id")
        .bind(roll_id)
        .fetch_all(store.pool()?)
        .await
        .map_err(lan::db_err("read vouchers"))?;
    Ok(rows.iter().map(|r| r.get(0)).collect())
}

#[async_trait]
impl Svc for CaptiveSvc {
    fn spec(&self) -> &'static Spec {
        &SPEC
    }

    async fn put(&self, store: &ConfigStore, body: &Value) -> Result<()> {
        let mut cur = Settings::load(store, &SPEC).await?;
        if let Some(obj) = body.as_object() {
            for f in SPEC.fields {
                if let Some(v) = obj.get(f.key) {
                    cur.0.insert(f.key.into(), Value::String(svc::check(f, v)?));
                }
            }
        }
        Globals::from_settings(&cur).check()?;
        svc::put_settings(store, &SPEC, body).await?;
        let keys: Vec<&String> = body
            .as_object()
            .map(|o| o.keys().collect())
            .unwrap_or_default();
        let _ = store
            .audit(
                "web",
                "captive_settings",
                "captive",
                None,
                &json!({"changed": keys}),
            )
            .await;
        Ok(())
    }

    async fn save_row(
        &self,
        store: &ConfigStore,
        coll: &str,
        id: Option<i64>,
        body: &Value,
    ) -> Result<i64> {
        let c = svc::find_coll(&SPEC, coll)?;
        let mut body = body.clone();
        match coll {
            "zones" => check_zone(store, id, &body).await?,
            "users" => {
                let row = merged_row(store, c, id, &body).await?;
                check_zone_ref(store, &row_s(&row, &USER_FIELDS, "zone"), true).await?;
                // the password is stored as an argon2 hash, never as typed
                if let Some(pw) = body.get("password").and_then(Value::as_str) {
                    if !pw.is_empty() && pw != svc::SECRET_MASK {
                        svc::check(&USER_FIELDS[1], &Value::String(pw.into()))?;
                        let h = hash_password(pw)?;
                        body["password"] = Value::String(h);
                    }
                }
            }
            "rolls" => {
                let row = merged_row(store, c, id, &body).await?;
                check_zone_ref(store, &row_s(&row, &ROLL_FIELDS, "zone"), false).await?;
                if let Some(id) = id {
                    let before = svc::raw_rows(store, c)
                        .await?
                        .into_iter()
                        .find(|r| r["id"].as_i64() == Some(id))
                        .map(|r| row_n(&r, &ROLL_FIELDS, "count"))
                        .unwrap_or(0);
                    if row_n(&row, &ROLL_FIELDS, "count") != before {
                        return Err(invalid(
                            "voucher count (a roll's codes are printed already: add a new roll instead)",
                        ));
                    }
                }
            }
            "passthrough" => {
                let row = merged_row(store, c, id, &body).await?;
                check_zone_ref(store, &row_s(&row, &PASS_FIELDS, "zone"), false).await?;
                let v = row_s(&row, &PASS_FIELDS, "value");
                let norm = match row_s(&row, &PASS_FIELDS, "kind").as_str() {
                    "mac" => lan::check_mac(&v)?,
                    "ip" => check_net4(&v)?,
                    _ => {
                        if v.parse::<Ipv4Addr>().is_ok() || lan::valid_dns_name(&v, false) {
                            v.to_ascii_lowercase()
                        } else {
                            return Err(invalid(format!("host name {v:?}")));
                        }
                    }
                };
                if body.get("value").is_some() {
                    body["value"] = Value::String(norm);
                }
            }
            _ => {}
        }
        let rid = svc::save_row(store, c, id, &body).await?;
        if coll == "rolls" && id.is_none() {
            let row = svc::raw_rows(store, c)
                .await?
                .into_iter()
                .find(|r| r["id"].as_i64() == Some(rid))
                .unwrap_or_default();
            let g = Globals::load(store).await?;
            generate_codes(store, rid, row_n(&row, &ROLL_FIELDS, "count"), g.code_len).await?;
        }
        let _ = store
            .audit(
                "web",
                &format!("captive_{coll}_save"),
                "captive",
                Some(&rid.to_string()),
                &json!({}),
            )
            .await;
        Ok(rid)
    }

    async fn delete_row(&self, store: &ConfigStore, coll: &str, id: i64) -> Result<()> {
        let c = svc::find_coll(&SPEC, coll)?;
        svc::delete_row(store, c, id).await?;
        if coll == "rolls" {
            sqlx::query("DELETE FROM cp_vouchers WHERE roll_id = ?")
                .bind(id)
                .execute(store.pool()?)
                .await
                .map_err(lan::db_err("delete vouchers"))?;
        }
        let _ = store
            .audit(
                "web",
                &format!("captive_{coll}_delete"),
                "captive",
                Some(&id.to_string()),
                &json!({}),
            )
            .await;
        Ok(())
    }

    async fn action(&self, store: &ConfigStore, name: &str, body: &Value) -> Result<Value> {
        match name {
            "disconnect" => {
                let id = body
                    .get("id")
                    .and_then(|v| v.as_i64().or_else(|| v.as_str()?.parse().ok()))
                    .ok_or_else(|| invalid("session id"))?;
                let n = request_disconnect(store, id).await?;
                if n == 0 {
                    return Err(Error::Config(format!("no active session {id}")));
                }
                Ok(json!({"disconnecting": id}))
            }
            _ => Err(invalid(format!("request: no action {name:?}"))),
        }
    }
}

/// Mark an active session for the portal to end (it does within `poll_secs`).
pub async fn request_disconnect(store: &ConfigStore, id: i64) -> Result<u64> {
    let r = sqlx::query("UPDATE cp_sessions SET disconnect_req = 1 WHERE id = ? AND ended IS NULL")
        .bind(id)
        .execute(store.pool()?)
        .await
        .map_err(lan::db_err("disconnect session"))?;
    if r.rows_affected() > 0 {
        let _ = store
            .audit(
                "web",
                "captive_disconnect",
                "captive",
                Some(&id.to_string()),
                &json!({}),
            )
            .await;
    }
    Ok(r.rows_affected())
}

fn argon2_hasher() -> argon2::Argon2<'static> {
    // the same cost rules as the web accounts (`PATRONUS_ARGON2_MEM_KIB` on small routers)
    if let Some(m) = std::env::var("PATRONUS_ARGON2_MEM_KIB")
        .ok()
        .and_then(|v| v.parse::<u32>().ok())
        .map(|m| m.clamp(4096, 19456))
    {
        if let Ok(p) = argon2::Params::new(m, 4, 1, None) {
            return argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, p);
        }
    }
    argon2::Argon2::default()
}

/// argon2id hash (`$argon2id$...`) of a portal password.
pub fn hash_password(pw: &str) -> Result<String> {
    use argon2::password_hash::{PasswordHasher, SaltString};
    use std::io::Read;
    let mut raw = [0u8; 16];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut raw))
        .map_err(|e| Error::Config(format!("random: {e}")))?;
    let salt = SaltString::encode_b64(&raw).map_err(|e| Error::Config(format!("salt: {e}")))?;
    argon2_hasher()
        .hash_password(pw.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| Error::Config(format!("hash password: {e}")))
}

/// Does `pw` match a hash made by [`hash_password`]?
pub fn verify_password(pw: &str, hash: &str) -> bool {
    use argon2::password_hash::{PasswordHash, PasswordVerifier};
    PasswordHash::new(hash)
        .map(|h| {
            argon2::Argon2::default()
                .verify_password(pw.as_bytes(), &h)
                .is_ok()
        })
        .unwrap_or(false)
}

// ---------------------------------------------------------------------------
// the applier
// ---------------------------------------------------------------------------

/// Runs nft (a recorder in tests).
pub trait NftRun: Send + Sync {
    fn nft(&self, script: &str) -> Result<()>;
    fn table_exists(&self) -> bool;
}

pub struct SystemNft;

impl NftRun for SystemNft {
    fn nft(&self, script: &str) -> Result<()> {
        use std::io::Write;
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
            .write_all(script.as_bytes())
            .map_err(|e| Error::Service(format!("nft: {e}")))?;
        let out = child
            .wait_with_output()
            .map_err(|e| Error::Service(format!("nft: {e}")))?;
        if out.status.success() {
            Ok(())
        } else {
            Err(Error::Service(format!(
                "captive portal nft rules: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            )))
        }
    }

    fn table_exists(&self) -> bool {
        std::process::Command::new("nft")
            .args(["list", "table", "inet", TABLE])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }
}

#[derive(Default)]
pub struct CaptiveApplier;

/// Enabled zones with their devices and passthrough (warnings for skipped ones).
pub async fn plan(store: &ConfigStore, warn: &mut Vec<String>) -> Result<Vec<(Zone, ZonePlan)>> {
    let pass = passthrough(store).await?;
    let mut out = Vec::new();
    for z in zones(store).await?.into_iter().filter(|z| z.enabled) {
        let devs: Vec<String> = lan::resolve_iface(store, &z.interface)
            .await?
            .into_iter()
            .filter(|d| !d.starts_with('@') && lan::valid_iface_spec(d))
            .collect();
        if devs.is_empty() {
            warn.push(format!(
                "portal {}: interface {} has no device (Interfaces page), zone skipped",
                z.name, z.interface
            ));
            continue;
        }
        let zp = z.clone();
        let pass2 = pass.clone();
        let (mut p, w) = tokio::task::spawn_blocking(move || {
            let mut w = Vec::new();
            let p = plan_pass(&zp, &pass2, &mut w);
            (p, w)
        })
        .await
        .map_err(|e| Error::Config(format!("portal passthrough: {e}")))?;
        warn.extend(w);
        p.devs = devs;
        out.push((z, p));
    }
    Ok(out)
}

impl CaptiveApplier {
    pub async fn apply_with(&self, store: &ConfigStore, nft: &dyn NftRun) -> Result<ApplyReport> {
        let mut rep = ApplyReport::default();
        let g = Globals::load(store).await?;
        let mut warn = Vec::new();
        let zones = plan(store, &mut warn).await?;
        for w in warn {
            rep.warn(w);
        }
        if zones.is_empty() {
            if nft.table_exists() {
                nft.nft(&format!("delete table inet {TABLE}\n"))?;
                rep.applied(format!("captive portal off: table inet {TABLE} removed"));
            } else {
                rep.applied("captive portal off");
            }
            return Ok(rep);
        }
        let now = lan::now();
        let sessions = active_sessions(store, now).await?;
        nft.nft(&render_nft(&g, &zones, &sessions, now))?;
        rep.applied(format!(
            "captive portal table inet {TABLE} loaded: {} ({} signed-in client(s) kept)",
            zones
                .iter()
                .map(|(z, p)| format!("{} on {}", z.name, p.devs.join(",")))
                .collect::<Vec<_>>()
                .join("; "),
            sessions.len()
        ));
        Ok(rep)
    }
}

#[async_trait]
impl Applier for CaptiveApplier {
    fn name(&self) -> &'static str {
        "captive"
    }

    fn phase(&self) -> Phase {
        Phase::Services
    }

    async fn apply(&self, store: &ConfigStore) -> Result<ApplyReport> {
        self.apply_with(store, &SystemNft).await
    }

    async fn render(&self, store: &ConfigStore) -> Result<String> {
        let g = Globals::load(store).await?;
        let mut warn = Vec::new();
        let zones = plan(store, &mut warn).await?;
        if zones.is_empty() {
            return Ok("# captive portal off\n".into());
        }
        let now = lan::now();
        let sessions = active_sessions(store, now).await?;
        let mut o = render_nft(&g, &zones, &sessions, now);
        for w in warn {
            o.push_str(&format!("# warning: {w}\n"));
        }
        Ok(o)
    }

    async fn status(&self, store: &ConfigStore) -> Result<Value> {
        let g = Globals::load(store).await?;
        let now = lan::now();
        let sessions = active_sessions(store, now).await?;
        let mut per: BTreeMap<String, usize> = BTreeMap::new();
        for s in &sessions {
            *per.entry(s.zone.clone()).or_default() += 1;
        }
        let mut zs = Vec::new();
        for z in zones(store).await? {
            let devs = lan::resolve_iface(store, &z.interface)
                .await
                .unwrap_or_default();
            zs.push(json!({
                "name": z.name, "enabled": z.enabled, "interface": z.interface,
                "devices": devs, "login": z.auth,
                "signed_in": per.get(&z.name).copied().unwrap_or(0),
            }));
        }
        Ok(json!({
            "zones": zs,
            "signed_in": sessions.len(),
            "firewall_table": SystemNft.table_exists(),
            "portal_ports": {"http": g.http_port, "https": g.https_port},
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn zone(id: i64, name: &str, idle: i64) -> Zone {
        let mut r = Map::new();
        r.insert("id".into(), json!(id));
        r.insert("name".into(), json!(name));
        r.insert("interface".into(), json!("@lan"));
        r.insert("idle_minutes".into(), json!(idle.to_string()));
        zone_from_row(&r)
    }

    fn globals() -> Globals {
        Globals {
            http_port: 8002,
            https_port: 8003,
            hostname: String::new(),
            tls_cert: String::new(),
            tls_key: String::new(),
            retention_days: 30,
            interim_secs: 300,
            code_len: 10,
            poll_secs: 2,
        }
    }

    #[test]
    fn zone_defaults_fill_every_page_text() {
        let z = zone(1, "guests", 30);
        assert_eq!(z.auth, "none");
        assert_eq!(z.hard_minutes, 480);
        assert_eq!(z.page.button, "Connect");
        assert!(z.terms_required && z.https_login && z.enabled);
        assert_eq!(z.radius.port, 1812);
        assert_eq!(z.radius.acct_port, 1813);
    }

    #[test]
    fn table_gates_redirects_and_keeps_sessions() {
        let z = zone(3, "lobby", 15);
        let p = ZonePlan {
            devs: vec!["eth1".into(), "eth1.30".into()],
            macs: vec!["02:00:00:00:00:aa".into()],
            nets: vec!["10.9.0.0/24".into()],
            dsts: vec!["192.0.2.7".parse().unwrap()],
        };
        let s = vec![
            ActiveSession {
                id: 1,
                zone: "lobby".into(),
                ip: "10.1.0.5".parse().unwrap(),
                mac: "02:00:00:00:00:05".into(),
                expires: 1600,
            },
            ActiveSession {
                id: 2,
                zone: "other".into(),
                ip: "10.2.0.5".parse().unwrap(),
                mac: "02:00:00:00:00:06".into(),
                expires: 0,
            },
        ];
        let t = render_nft(&globals(), &[(z, p)], &s, 1000);
        assert!(t.starts_with("table inet patronus_portal\ndelete table inet patronus_portal\n"));
        assert!(
            t.contains("02:00:00:00:00:05 . 10.1.0.5 timeout 600s"),
            "{t}"
        );
        assert!(!t.contains("10.2.0.5"), "another zone's session stays out");
        assert!(t.contains(
            "set z3_seen { type ether_addr . ipv4_addr; flags dynamic, timeout; timeout 900s;"
        ));
        assert!(t.contains("iifname { \"eth1\", \"eth1.30\" } meta nfproto ipv4 jump z3_pre"));
        assert!(t.contains("tcp dport 80 redirect to :8002"));
        assert!(t.contains("fib daddr type local tcp dport 443 redirect to :8003"));
        assert!(t.contains("update @z3_seen { ether saddr . ip saddr } return"));
        assert!(t.contains("elements = { 02:00:00:00:00:aa }"));
        assert!(t.contains("elements = { 10.9.0.0/24 }"));
        assert!(t.contains("elements = { 192.0.2.7 }"));
        assert!(t.contains("priority -16"));
        assert!(t.contains("counter drop"));
        // drop comes after every way through
        let fwd = &t[t.find("chain z3_fwd").unwrap()..];
        assert!(fwd.find("@z3_auth").unwrap() < fwd.find("counter drop").unwrap());
    }

    #[test]
    fn no_idle_timeout_means_no_seen_set() {
        let t = render_nft(
            &globals(),
            &[(
                zone(1, "a", 0),
                ZonePlan {
                    devs: vec!["eth1".into()],
                    ..Default::default()
                },
            )],
            &[],
            0,
        );
        assert!(!t.contains("z1_seen"));
        assert!(t.contains("ether saddr . ip saddr @z1_auth return"));
    }

    #[test]
    fn passthrough_is_normalised_and_bad_rows_warn() {
        let z = zone(1, "a", 0);
        let pass = vec![
            Pass {
                zone: "a".into(),
                kind: "mac".into(),
                value: "02-00-00-00-00-AA".into(),
            },
            Pass {
                zone: "a".into(),
                kind: "ip".into(),
                value: "10.0.0.7/24".into(),
            },
            Pass {
                zone: "a".into(),
                kind: "ip".into(),
                value: "10.0.0.9".into(),
            },
            Pass {
                zone: "a".into(),
                kind: "mac".into(),
                value: "nope".into(),
            },
            Pass {
                zone: "a".into(),
                kind: "host".into(),
                value: "198.51.100.1".into(),
            },
            Pass {
                zone: "b".into(),
                kind: "mac".into(),
                value: "02:00:00:00:00:bb".into(),
            },
        ];
        let mut w = Vec::new();
        let p = plan_pass(&z, &pass, &mut w);
        assert_eq!(p.macs, vec!["02:00:00:00:00:aa"]);
        assert_eq!(p.nets, vec!["10.0.0.0/24", "10.0.0.9"]);
        assert_eq!(p.dsts, vec!["198.51.100.1".parse::<Ipv4Addr>().unwrap()]);
        assert_eq!(w.len(), 1);
    }

    #[test]
    fn ports_and_urls_are_checked() {
        let mut g = globals();
        assert!(g.check().is_ok());
        g.https_port = 443;
        assert!(g.check().is_err());
        g.https_port = 8002;
        assert!(g.check().is_err());
        assert!(check_url("https://example.org/x").is_ok());
        assert!(check_url("javascript:alert(1)").is_err());
        assert!(check_url("https://a\"b").is_err());
        assert!(check_color("#12abEF").is_ok());
        assert!(check_color("red").is_err());
        assert_eq!(
            portal_base(&globals(), "10.0.0.1".parse().unwrap()),
            "https://10.0.0.1:8003"
        );
        assert_eq!(remaining(0, 5), None);
        assert_eq!(remaining(4, 5), Some(1));
    }
}
