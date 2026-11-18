//! Guest network (USE=guest, main-router tier): an isolated network for
//! visitors, the way pfSense/OPNsense "guest" VLANs, OpenWrt guest networks
//! and UniFi/Firewalla guest networks work, with every value a setting.
//!
//! One bridge (`guest.bridge`, default `br-guest`) is the guest L3 interface.
//! Its members are the guest VLAN sub-interface (`<parent>.<vlan>`, when
//! `guest.vlan_id` > 0; the trunk to an AP or managed switch), any extra
//! devices in `guest.ports` (a spare LAN port, a test veth) and, with
//! `guest.wifi`, the guest SSID served by a dedicated hostapd.
//!
//! What the applier makes true (all of it from the settings, nothing baked in):
//! - the bridge/VLAN/ports exist, the bridge carries the router address
//!   (`guest.address`), IPv6 is off on it, bridge ports are `isolated` when
//!   `guest.isolate_clients` (and hostapd runs `ap_isolate=1`): a guest cannot
//!   reach another guest at layer 2;
//! - a dedicated dnsmasq serves DHCP (and DNS, unless `guest.dns_servers` hands
//!   out other resolvers) on the bridge address only;
//! - the own nft table `inet patronus_guest` (priority -15, so it runs before
//!   the main firewall and the segmentation table, and only ever drops or
//!   falls through): guests reach the router only for DHCP, DNS, ping and the
//!   ports in `guest.router_ports`; they forward only to the internet
//!   interface (never to the LAN, other VLANs, or the router's other
//!   addresses), optionally not into private ranges beyond the router
//!   (`guest.block_private`, the ISP modem's admin page) and optionally only on
//!   `guest.egress_ports`; nothing starts a new flow *into* the guest network;
//!   IPv6 from guests is dropped (not supported yet); the guest subnet is
//!   masqueraded out of the internet interface;
//! - bandwidth caps: per guest network (`tc` tbf on the bridge for download,
//!   an ingress policer for upload) and per client (nft dynamic-set meters on
//!   the client's address, both directions);
//! - time-limited access, enforced in the kernel (no daemon, it expires by
//!   itself): `schedule` (daily window and weekdays, nft `meta hour`/`meta
//!   day`, converted from local time when the rules are loaded: re-applied
//!   when the UTC offset changes) or `timed` (closed until the "open for N
//!   minutes" button is pressed, closes by itself at `open_until`);
//! - the Wi-Fi password: one shared passphrase plus optional vouchers (own
//!   passphrases that stop working after N minutes; a 60 s watcher in the web
//!   process re-applies the SSID when one expires). No captive portal needed.
//!
//! The main firewall only gets the accepts the guest network needs
//! (`patronus-firewall/src/svc_rules.rs`: DHCP/DNS/ping/router ports in,
//! guest -> internet out); everything else about a guest stays default-deny.

use crate::lan::{self, invalid};
use crate::supervise::{which, Supervisor};
use crate::svc::{self, Coll, Field, Kind, Settings, Spec, Svc};
use async_trait::async_trait;
use patronus_config::applier::{Applier, ApplyReport, Phase};
use patronus_config::store::ConfigStore;
use patronus_core::{Error, Result};
use serde_json::{json, Map, Value};
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

pub const TABLE: &str = "patronus_guest";
pub const DNSMASQ_INSTANCE: &str = "guest-dnsmasq";
pub const HOSTAPD_INSTANCE: &str = "guest-hostapd";

const ACCESS: &[&str] = &["always", "schedule", "timed"];
const SECURITIES: &[&str] = &["wpa2", "wpa2_wpa3"];
const BANDS: &[&str] = &["2g", "5g"];

static FIELDS: [Field; 36] = [
    Field::new("enabled", "Guest network", Kind::Bool)
        .def("0")
        .help("Off by default. Guests get DHCP, DNS and the internet, nothing else"),
    Field::new("bridge", "Guest bridge", Kind::Token)
        .def("br-guest")
        .help("the guest network's interface on this router"),
    Field::new("parent", "VLAN trunk interface", Kind::Iface)
        .def("@lan")
        .help("device that carries the guest VLAN to your access point or switch (@lan or a device name)"),
    Field::new("vlan_id", "Guest VLAN id", Kind::Int(0, 4094))
        .def("30")
        .help("0 = no VLAN: use only the ports below and the Wi-Fi network"),
    Field::new("ports", "Extra guest ports", Kind::Text)
        .help("comma-separated devices put into the guest network (a spare LAN port); they must not have a role"),
    Field::new("address", "Router address and subnet", Kind::Cidr4)
        .def("192.168.30.1/24")
        .help("the router's address on the guest network; must not overlap any other network"),
    Field::new("dhcp_start", "DHCP range start", Kind::Ipv4)
        .help("empty: derived from the subnet"),
    Field::new("dhcp_end", "DHCP range end", Kind::Ipv4)
        .help("empty: derived from the subnet"),
    Field::new("lease_minutes", "DHCP lease time (minutes)", Kind::Int(2, 43200))
        .def("120"),
    Field::new("dns_servers", "DNS servers handed to guests", Kind::Text)
        .help("comma-separated IPv4 addresses; empty: the router answers DNS itself"),
    Field::new("dns_upstreams", "Router DNS forwards to", Kind::Text)
        .help("comma-separated IP addresses; empty: the router's own resolvers"),
    Field::new("internet_interface", "Internet interface", Kind::Iface)
        .def("@wan")
        .help("guests are only forwarded out of this interface"),
    Field::new("block_private", "Block private ranges beyond the router", Kind::Bool)
        .def("1")
        .help("guests cannot reach 10/8, 172.16/12, 192.168/16, 100.64/10 or 169.254/16 behind the WAN, such as the ISP modem's admin page"),
    Field::new("isolate_clients", "Isolate guests from each other", Kind::Bool)
        .def("1")
        .help("bridge ports are isolated and the SSID runs with client isolation. A guest VLAN that continues on an unmanaged switch cannot be isolated by this router"),
    Field::new("allow_ping", "Guests may ping the router", Kind::Bool).def("1"),
    Field::new("router_ports", "Other router services guests may use", Kind::Text)
        .help("comma-separated proto/port or proto/lo-hi (tcp/853,udp/123); empty: only DHCP and DNS"),
    Field::new("egress_ports", "Limit guests to these internet ports", Kind::Text)
        .help("comma-separated proto/port or proto/lo-hi; empty: everything is allowed out"),
    Field::new("down_kbit", "Network download cap (kbit/s)", Kind::Int(0, 100_000_000))
        .def("0")
        .help("0 = no cap; shared by all guests"),
    Field::new("up_kbit", "Network upload cap (kbit/s)", Kind::Int(0, 100_000_000))
        .def("0"),
    Field::new("client_down_kbit", "Per-guest download cap (kbit/s)", Kind::Int(0, 100_000_000))
        .def("0")
        .help("0 = no cap; policed per guest address"),
    Field::new("client_up_kbit", "Per-guest upload cap (kbit/s)", Kind::Int(0, 100_000_000))
        .def("0"),
    Field::new("access", "Access", Kind::Select(ACCESS))
        .def("always")
        .help("always open; a daily schedule; or timed (closed until you open it for a while)"),
    Field::new("schedule_from", "Schedule: open from (HH:MM)", Kind::Token)
        .def("07:00"),
    Field::new("schedule_to", "Schedule: until (HH:MM)", Kind::Token)
        .def("23:00")
        .help("earlier than the start = overnight"),
    Field::new("schedule_days", "Schedule: weekdays", Kind::Text)
        .def("0,1,2,3,4,5,6")
        .help("0 = Sunday ... 6 = Saturday, or mon,tue,..."),
    Field::new("open_until", "Open until (epoch seconds)", Kind::Int(0, 4_102_444_800))
        .def("0")
        .help("set by the \"Open for\" button (timed access)"),
    Field::new("wifi", "Guest Wi-Fi network", Kind::Bool)
        .def("0")
        .help("needs an access-point capable radio in this router"),
    Field::new("ssid", "Wi-Fi name", Kind::Text).def("Guest"),
    Field::new("wifi_psk", "Wi-Fi password", Kind::Secret)
        .help("8-63 characters, shared by all guests; use \"New Wi-Fi password\" to generate one"),
    Field::new("wifi_security", "Wi-Fi security", Kind::Select(SECURITIES))
        .def("wpa2_wpa3"),
    Field::new("wifi_iface", "Wi-Fi radio interface", Kind::Token)
        .help("empty: the first access-point capable radio"),
    Field::new("wifi_band", "Wi-Fi band", Kind::Select(BANDS)).def("2g"),
    Field::new("wifi_channel", "Wi-Fi channel", Kind::Int(1, 177)).def("6"),
    Field::new("wifi_country", "Wi-Fi country code", Kind::Token).def("US"),
    Field::new("description", "Note", Kind::Text),
    Field::new("lan_overlap_check", "Refuse overlapping subnets", Kind::Bool)
        .def("1")
        .help("keep on: an address range that overlaps another network breaks both"),
];

static VOUCHER_FIELDS: [Field; 3] = [
    Field::new("name", "Voucher", Kind::Token).req(),
    Field::new("code", "Wi-Fi password", Kind::Secret)
        .req()
        .help("8-63 characters; works until the time below has passed"),
    Field::new("minutes", "Valid for (minutes)", Kind::Int(0, 525_600))
        .def("1440")
        .help("0 = never expires; counted from when the voucher was saved"),
];

static SPEC: Spec = Spec {
    slug: "guest",
    title: "Guest network",
    blurb: "An isolated network for visitors: its own VLAN and/or Wi-Fi name, DHCP and DNS, internet only. \
            Guests cannot reach your LAN, this router's web page or SSH, or each other. Optional speed caps, \
            opening hours, and a shared Wi-Fi password or time-limited vouchers (no login page needed).",
    applier: "guest",
    fields: &FIELDS,
    colls: &[Coll {
        key: "vouchers",
        title: "Wi-Fi vouchers",
        table: "guest_vouchers",
        fields: &VOUCHER_FIELDS,
        unique: Some("name"),
    }],
    actions: &[
        ("new_password", "New Wi-Fi password"),
        ("voucher", "New voucher"),
        ("open", "Open for a while"),
        ("close", "Close now"),
    ],
};

// ---------------------------------------------------------------------------
// parsed configuration
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortSpec {
    pub proto: &'static str,
    pub lo: u16,
    pub hi: u16,
}

impl PortSpec {
    fn nft(&self) -> String {
        if self.lo == self.hi {
            self.lo.to_string()
        } else {
            format!("{}-{}", self.lo, self.hi)
        }
    }
}

/// `tcp/443,udp/53,tcp/8000-8100`
pub fn parse_ports(s: &str, what: &str) -> Result<Vec<PortSpec>> {
    let mut out = Vec::new();
    for part in s.split(',').map(str::trim).filter(|p| !p.is_empty()) {
        let bad = || invalid(format!("{what} {part:?} (use tcp/443 or udp/5000-5010)"));
        let (proto, ports) = part.split_once('/').ok_or_else(bad)?;
        let proto = match proto.to_ascii_lowercase().as_str() {
            "tcp" => "tcp",
            "udp" => "udp",
            _ => return Err(bad()),
        };
        let (lo, hi) = match ports.split_once('-') {
            Some((a, b)) => (a.parse::<u16>().map_err(|_| bad())?, b.parse::<u16>().map_err(|_| bad())?),
            None => {
                let p = ports.parse::<u16>().map_err(|_| bad())?;
                (p, p)
            }
        };
        if lo == 0 || hi < lo {
            return Err(bad());
        }
        out.push(PortSpec { proto, lo, hi });
    }
    Ok(out)
}

fn ports_for<'a>(v: &'a [PortSpec], proto: &str) -> Vec<&'a PortSpec> {
    v.iter().filter(|p| p.proto == proto).collect()
}

fn nft_ports(v: &[&PortSpec]) -> String {
    format!(
        "{{ {} }}",
        v.iter().map(|p| p.nft()).collect::<Vec<_>>().join(", ")
    )
}

fn parse_ip_list(s: &str, what: &str, v4_only: bool) -> Result<Vec<std::net::IpAddr>> {
    let mut out = Vec::new();
    for p in s.split(',').map(str::trim).filter(|p| !p.is_empty()) {
        let a: std::net::IpAddr = p
            .parse()
            .map_err(|_| invalid(format!("{what} {p:?} (an IP address)")))?;
        if v4_only && !a.is_ipv4() {
            return Err(invalid(format!("{what} {p:?} (an IPv4 address)")));
        }
        out.push(a);
    }
    Ok(out)
}

fn hhmm(s: &str, what: &str) -> Result<u32> {
    let bad = || invalid(format!("{what} {s:?} (HH:MM, 24 hours)"));
    let (h, m) = s.split_once(':').ok_or_else(bad)?;
    let (h, m): (u32, u32) = (h.parse().map_err(|_| bad())?, m.parse().map_err(|_| bad())?);
    if h > 23 || m > 59 || s.len() != 5 {
        return Err(bad());
    }
    Ok(h * 60 + m)
}

fn clock(min: u32) -> String {
    format!("{:02}:{:02}", (min / 60) % 24, min % 60)
}

/// `0,1,5` / `mon,tue` -> sorted unique 0..=6 (0 = Sunday).
pub fn parse_days(s: &str) -> Result<Vec<u8>> {
    let mut v = Vec::new();
    for p in s.split(',').map(str::trim).filter(|p| !p.is_empty()) {
        let d = match p.to_ascii_lowercase().as_str() {
            "sun" | "0" | "7" => 0,
            "mon" | "1" => 1,
            "tue" | "2" => 2,
            "wed" | "3" => 3,
            "thu" | "4" => 4,
            "fri" | "5" => 5,
            "sat" | "6" => 6,
            _ => return Err(invalid(format!("weekday {p:?} (0-6 or mon,tue,...)"))),
        };
        if !v.contains(&d) {
            v.push(d);
        }
    }
    if v.is_empty() {
        return Err(invalid("weekdays (at least one day)"));
    }
    v.sort_unstable();
    Ok(v)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Gate {
    Always,
    Schedule { from: u32, to: u32, days: Vec<u8> },
    Timed { open_until: i64 },
}

#[derive(Debug, Clone, PartialEq)]
pub struct Limits {
    pub down: u64,
    pub up: u64,
    pub client_down: u64,
    pub client_up: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct WifiCfg {
    pub enabled: bool,
    pub ssid: String,
    pub psk: String,
    pub security: String,
    pub iface: String,
    pub band: String,
    pub channel: u32,
    pub country: String,
    pub isolate: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Cfg {
    pub enabled: bool,
    pub bridge: String,
    pub parent: String,
    pub vlan_id: u32,
    pub ports: Vec<String>,
    pub router: Ipv4Addr,
    pub prefix: u8,
    pub dhcp_start: Ipv4Addr,
    pub dhcp_end: Ipv4Addr,
    pub lease_minutes: u32,
    pub dns_servers: Vec<Ipv4Addr>,
    pub dns_upstreams: Vec<std::net::IpAddr>,
    pub internet: String,
    pub block_private: bool,
    pub isolate: bool,
    pub allow_ping: bool,
    pub router_ports: Vec<PortSpec>,
    pub egress_ports: Vec<PortSpec>,
    pub limits: Limits,
    pub gate: Gate,
    pub wifi: WifiCfg,
    pub overlap_check: bool,
}

fn ifname_ok(n: &str) -> bool {
    !n.is_empty()
        && n.len() <= 15
        && n.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

fn net_base(a: Ipv4Addr, prefix: u8) -> u32 {
    let mask = if prefix == 0 { 0 } else { u32::MAX << (32 - u32::from(prefix)) };
    u32::from(a) & mask
}

impl Cfg {
    /// Parse and cross-check the stored (or about to be stored) settings.
    pub fn parse(s: &Settings, now: i64) -> Result<Self> {
        let bridge = s.s("bridge");
        if !ifname_ok(&bridge) {
            return Err(invalid(
                "guest bridge (1-15 letters, digits, - _ .)",
            ));
        }
        let vlan_id = s.n("vlan_id") as u32;
        let ports: Vec<String> = s
            .s("ports")
            .split(',')
            .map(str::trim)
            .filter(|p| !p.is_empty())
            .map(String::from)
            .collect();
        for p in &ports {
            if !ifname_ok(p) || *p == bridge {
                return Err(invalid(format!("guest port {p:?} (a device name)")));
            }
        }
        let parent = s.s("parent");
        if vlan_id > 0 && parent.is_empty() {
            return Err(invalid("VLAN trunk interface (needed with a guest VLAN)"));
        }
        let net: ipnetwork::Ipv4Network = s
            .s("address")
            .parse()
            .map_err(|_| invalid("router address (a.b.c.d/nn)"))?;
        let (router, prefix) = (net.ip(), net.prefix());
        if !(16..=29).contains(&prefix) {
            return Err(invalid("guest subnet (a prefix from /16 to /29)"));
        }
        let base = net_base(router, prefix);
        let size = 1u64 << (32 - u32::from(prefix));
        let bcast = (u64::from(base) + size - 1) as u32;
        if u32::from(router) == base || u32::from(router) == bcast {
            return Err(invalid("router address (the network or broadcast address)"));
        }
        let ip4 = |k: &str, what: &str| -> Result<Option<Ipv4Addr>> {
            let v = s.s(k);
            if v.is_empty() {
                return Ok(None);
            }
            let a: Ipv4Addr = v.parse().map_err(|_| invalid(format!("{what} (an IPv4 address)")))?;
            let u = u32::from(a);
            if u <= base || u >= bcast {
                return Err(invalid(format!("{what} (outside the guest subnet)")));
            }
            Ok(Some(a))
        };
        let hosts = size - 2;
        let dhcp_start = ip4("dhcp_start", "DHCP range start")?
            .unwrap_or_else(|| Ipv4Addr::from(base + (100.min(hosts / 2) as u32).max(2)));
        let dhcp_end = ip4("dhcp_end", "DHCP range end")?.unwrap_or_else(|| Ipv4Addr::from(bcast - 1));
        if u32::from(dhcp_start) > u32::from(dhcp_end) {
            return Err(invalid("DHCP range (start is after the end)"));
        }
        if (u32::from(dhcp_start)..=u32::from(dhcp_end)).contains(&u32::from(router)) {
            return Err(invalid("DHCP range (it contains the router address)"));
        }
        let dns_servers: Vec<Ipv4Addr> = parse_ip_list(&s.s("dns_servers"), "DNS server", true)?
            .into_iter()
            .filter_map(|a| match a {
                std::net::IpAddr::V4(v) => Some(v),
                _ => None,
            })
            .collect();
        let dns_upstreams = parse_ip_list(&s.s("dns_upstreams"), "DNS forwarder", false)?;
        let router_ports = parse_ports(&s.s("router_ports"), "router service")?;
        let egress_ports = parse_ports(&s.s("egress_ports"), "internet port")?;
        let (down, up, cd, cu) = (
            s.n("down_kbit") as u64,
            s.n("up_kbit") as u64,
            s.n("client_down_kbit") as u64,
            s.n("client_up_kbit") as u64,
        );
        let gate = match s.s("access").as_str() {
            "schedule" => {
                let from = hhmm(&s.s("schedule_from"), "schedule start")?;
                let to = hhmm(&s.s("schedule_to"), "schedule end")?;
                if from == to {
                    return Err(invalid("schedule (start and end are the same time)"));
                }
                Gate::Schedule {
                    from,
                    to,
                    days: parse_days(&s.s("schedule_days"))?,
                }
            }
            "timed" => Gate::Timed {
                open_until: s.s("open_until").parse().unwrap_or(0).max(0),
            },
            _ => Gate::Always,
        };
        let _ = now;
        let wifi_on = s.b("wifi");
        let ssid = s.s("ssid");
        let psk = s.s("wifi_psk");
        let security = s.s("wifi_security");
        let band = s.s("wifi_band");
        let channel = s.n("wifi_channel") as u32;
        let country = s.s("wifi_country").to_ascii_uppercase();
        let iface = s.s("wifi_iface");
        if wifi_on {
            if ssid.is_empty()
                || ssid.len() > 32
                || !ssid.bytes().all(|b| b.is_ascii_graphic() || b == b' ')
            {
                return Err(invalid("Wi-Fi name (1-32 printable ASCII characters)"));
            }
            if !(8..=63).contains(&psk.len()) && psk != svc::SECRET_MASK {
                return Err(invalid(
                    "Wi-Fi password (8-63 characters; use \"New Wi-Fi password\")",
                ));
            }
            if psk.bytes().any(|b| matches!(b, b'|' | b',' | b' ')) {
                return Err(invalid("Wi-Fi password (no | , or spaces)"));
            }
            if country.len() != 2 || !country.bytes().all(|b| b.is_ascii_uppercase()) {
                return Err(invalid("Wi-Fi country code (two letters)"));
            }
            if (band == "2g" && channel > 14) || (band == "5g" && channel < 32) {
                return Err(invalid("Wi-Fi channel (does not belong to the band)"));
            }
            if !iface.is_empty() && !ifname_ok(&iface) {
                return Err(invalid("Wi-Fi radio interface (a device name)"));
            }
        }
        Ok(Cfg {
            enabled: s.b("enabled"),
            bridge,
            parent,
            vlan_id,
            ports,
            router,
            prefix,
            dhcp_start,
            dhcp_end,
            lease_minutes: s.n("lease_minutes").clamp(2, 43200) as u32,
            dns_servers,
            dns_upstreams,
            internet: s.s("internet_interface"),
            block_private: s.b("block_private"),
            isolate: s.b("isolate_clients"),
            allow_ping: s.b("allow_ping"),
            router_ports,
            egress_ports,
            limits: Limits {
                down,
                up,
                client_down: cd,
                client_up: cu,
            },
            gate,
            wifi: WifiCfg {
                enabled: wifi_on,
                ssid,
                psk,
                security,
                iface,
                band,
                channel,
                country,
                isolate: s.b("isolate_clients"),
            },
            overlap_check: s.b("lan_overlap_check"),
        })
    }

    pub fn network(&self) -> String {
        format!(
            "{}/{}",
            Ipv4Addr::from(net_base(self.router, self.prefix)),
            self.prefix
        )
    }

    pub fn netmask(&self) -> Ipv4Addr {
        let mask = if self.prefix == 0 { 0 } else { u32::MAX << (32 - u32::from(self.prefix)) };
        Ipv4Addr::from(mask)
    }

    /// The VLAN sub-interface name for `parent_dev`.
    pub fn vlan_dev(&self, parent_dev: &str) -> String {
        format!("{parent_dev}.{}", self.vlan_id)
    }
}

// ---------------------------------------------------------------------------
// renderers (pure)
// ---------------------------------------------------------------------------

const PRIVATE_RANGES: &str =
    "10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10, 169.254.0.0/16";

/// Expressions that, when true, close the network (each becomes its own drop
/// rule); `None` = never closed; `Some(vec![])` = closed unconditionally.
pub fn gate_closed(g: &Gate, now: i64) -> Option<Vec<String>> {
    match g {
        Gate::Always => None,
        Gate::Timed { open_until } => {
            if *open_until <= now {
                Some(Vec::new())
            } else {
                Some(vec![format!("meta time >= {open_until}")])
            }
        }
        Gate::Schedule { from, to, days } => {
            let mut v = Vec::new();
            if days.len() < 7 {
                v.push(format!(
                    "meta day != {{ {} }}",
                    days.iter().map(u8::to_string).collect::<Vec<_>>().join(", ")
                ));
            }
            if from < to {
                v.push(format!(
                    "meta hour != \"{}\"-\"{}\"",
                    clock(*from),
                    clock(to - 1)
                ));
            } else {
                v.push(format!(
                    "meta hour \"{}\"-\"{}\"",
                    clock(*to),
                    clock(from - 1)
                ));
            }
            Some(v)
        }
    }
}

fn kbytes(kbit: u64) -> u64 {
    (kbit / 8).max(1)
}

/// The nft script for the guest table (replaces the table atomically).
pub fn render_nft(c: &Cfg, wan_devs: &[String], now: i64) -> String {
    let br = &c.bridge;
    let r = c.router;
    let mut o = format!("add table inet {TABLE}\ndelete table inet {TABLE}\n");
    o.push_str(&format!("table inet {TABLE} {{\n"));
    for (name, kbit) in [("up_clients", c.limits.client_up), ("down_clients", c.limits.client_down)] {
        if kbit > 0 {
            o.push_str(&format!(
                "  set {name} {{ type ipv4_addr; flags dynamic; size 8192; timeout 5m; }}\n"
            ));
        }
    }
    let closed = gate_closed(&c.gate, now);
    let gate_lines = |chain: &mut String| {
        if let Some(exprs) = &closed {
            if exprs.is_empty() {
                chain.push_str("    drop comment \"guest network is closed\"\n");
            }
            for e in exprs {
                chain.push_str(&format!("    {e} drop comment \"guest network is closed\"\n"));
            }
        }
    };
    // --- input: what a guest may ask of the router itself
    o.push_str(&format!(
        "  chain input {{\n    type filter hook input priority -15; policy accept;\n    iifname \"{br}\" jump guest_in\n  }}\n"
    ));
    let mut gin = String::from("    meta nfproto ipv6 drop\n    ct state invalid drop\n");
    gin.push_str("    udp sport 68 udp dport 67 accept comment \"guest DHCP\"\n");
    gate_lines(&mut gin);
    if c.dns_servers.is_empty() {
        gin.push_str(&format!(
            "    ip daddr {r} udp dport 53 accept comment \"guest DNS\"\n    ip daddr {r} tcp dport 53 accept comment \"guest DNS\"\n"
        ));
    }
    if c.allow_ping {
        gin.push_str(&format!(
            "    ip daddr {r} icmp type echo-request accept comment \"guest ping\"\n"
        ));
    }
    for proto in ["tcp", "udp"] {
        let p = ports_for(&c.router_ports, proto);
        if !p.is_empty() {
            gin.push_str(&format!(
                "    ip daddr {r} {proto} dport {} accept comment \"guest router service\"\n",
                nft_ports(&p)
            ));
        }
    }
    gin.push_str("    drop comment \"guests reach nothing else on the router\"\n");
    o.push_str(&format!("  chain guest_in {{\n{gin}  }}\n"));
    // --- forward
    o.push_str(&format!(
        "  chain forward {{\n    type filter hook forward priority -15; policy accept;\n    iifname \"{br}\" jump guest_out\n    oifname \"{br}\" jump to_guest\n  }}\n"
    ));
    let wan = wan_devs
        .iter()
        .map(|d| format!("\"{d}\""))
        .collect::<Vec<_>>()
        .join(", ");
    let mut gout = String::from("    meta nfproto ipv6 drop\n    ct state invalid drop\n");
    gate_lines(&mut gout);
    gout.push_str(&format!(
        "    ip saddr != {} drop comment \"no spoofed guest addresses\"\n",
        c.network()
    ));
    if wan.is_empty() {
        gout.push_str("    drop comment \"no internet interface\"\n");
    } else {
        gout.push_str(&format!(
            "    oifname != {{ {wan} }} drop comment \"guests only go to the internet\"\n"
        ));
    }
    if c.block_private {
        gout.push_str(&format!(
            "    ip daddr {{ {PRIVATE_RANGES} }} drop comment \"no private ranges beyond the router\"\n"
        ));
    }
    if c.limits.client_up > 0 {
        let k = kbytes(c.limits.client_up);
        gout.push_str(&format!(
            "    add @up_clients {{ ip saddr limit rate over {k} kbytes/second burst {} kbytes }} counter drop comment \"per-guest upload cap\"\n",
            (k / 4).max(64)
        ));
    }
    if !c.egress_ports.is_empty() {
        for proto in ["tcp", "udp"] {
            let p = ports_for(&c.egress_ports, proto);
            if !p.is_empty() {
                gout.push_str(&format!(
                    "    {proto} dport {} accept comment \"allowed guest ports\"\n",
                    nft_ports(&p)
                ));
            }
        }
        gout.push_str("    ip protocol icmp accept comment \"guest ICMP\"\n");
        gout.push_str("    drop comment \"port not allowed for guests\"\n");
    }
    o.push_str(&format!("  chain guest_out {{\n{gout}  }}\n"));
    let mut tg = String::from(
        "    ct state != established,related drop comment \"nothing starts a connection into the guest network\"\n",
    );
    gate_lines(&mut tg);
    if c.limits.client_down > 0 {
        let k = kbytes(c.limits.client_down);
        tg.push_str(&format!(
            "    add @down_clients {{ ip daddr limit rate over {k} kbytes/second burst {} kbytes }} counter drop comment \"per-guest download cap\"\n",
            (k / 4).max(64)
        ));
    }
    o.push_str(&format!("  chain to_guest {{\n{tg}  }}\n"));
    if !wan.is_empty() {
        o.push_str(&format!(
            "  chain postrouting {{\n    type nat hook postrouting priority srcnat; policy accept;\n    ip saddr {} oifname {{ {wan} }} masquerade\n  }}\n",
            c.network()
        ));
    }
    o.push_str("}\n");
    o
}

/// `tc` argument vectors for the network caps: (download root qdisc,
/// upload ingress policer). `None` = no cap, remove what was there.
pub fn tc_download(c: &Cfg) -> Option<Vec<String>> {
    (c.limits.down > 0).then(|| {
        let rate = c.limits.down;
        let burst = (rate * 125 / 50).max(6000);
        vec![
            "qdisc".into(),
            "replace".into(),
            "dev".into(),
            c.bridge.clone(),
            "root".into(),
            "tbf".into(),
            "rate".into(),
            format!("{rate}kbit"),
            "burst".into(),
            format!("{burst}b"),
            "latency".into(),
            "200ms".into(),
        ]
    })
}

pub fn tc_upload(c: &Cfg) -> Option<Vec<String>> {
    (c.limits.up > 0).then(|| {
        let rate = c.limits.up;
        let burst = (rate * 125 / 25).max(12000);
        vec![
            "filter".into(),
            "replace".into(),
            "dev".into(),
            c.bridge.clone(),
            "parent".into(),
            "ffff:".into(),
            "protocol".into(),
            "all".into(),
            "prio".into(),
            "1".into(),
            "matchall".into(),
            "action".into(),
            "police".into(),
            "rate".into(),
            format!("{rate}kbit"),
            "burst".into(),
            format!("{burst}b"),
            "conform-exceed".into(),
            "drop".into(),
        ]
    })
}

pub fn render_dnsmasq(c: &Cfg, lease_file: &str, pid_file: &str) -> String {
    let mut o = lan::header("#", "guest network dnsmasq");
    o.push_str(&format!(
        "interface={}\nbind-interfaces\nlisten-address={}\nexcept-interface=lo\npid-file={pid_file}\ndhcp-leasefile={lease_file}\ndhcp-authoritative\ndomain-needed\nbogus-priv\nno-hosts\n",
        c.bridge, c.router
    ));
    if c.dns_servers.is_empty() {
        o.push_str("cache-size=1000\n");
        if c.dns_upstreams.is_empty() {
            // the router's own resolv.conf
        } else {
            o.push_str("no-resolv\n");
            for u in &c.dns_upstreams {
                o.push_str(&format!("server={u}\n"));
            }
        }
    } else {
        o.push_str("port=0\n");
    }
    o.push_str(&format!(
        "dhcp-range={},{},{},{}m\ndhcp-option=option:router,{}\n",
        c.dhcp_start,
        c.dhcp_end,
        c.netmask(),
        c.lease_minutes,
        c.router
    ));
    let dns: Vec<String> = if c.dns_servers.is_empty() {
        vec![c.router.to_string()]
    } else {
        c.dns_servers.iter().map(|d| d.to_string()).collect()
    };
    o.push_str(&format!("dhcp-option=option:dns-server,{}\n", dns.join(",")));
    o
}

/// One guest PSK entry: shared passphrase plus the active vouchers.
pub fn render_psk_file(shared: &str, vouchers: &[(i64, String)]) -> String {
    let mut o = String::from("# generated by Patronus - guest network\n");
    o.push_str(&format!("keyid=guest 00:00:00:00:00:00 {shared}\n"));
    for (id, code) in vouchers {
        o.push_str(&format!("keyid=voucher-{id} 00:00:00:00:00:00 {code}\n"));
    }
    o
}

pub fn render_hostapd(c: &Cfg, iface: &str, psk_path: &Path, ctrl_dir: &Path, vouchers: &[(i64, String)]) -> Result<String> {
    let w = &c.wifi;
    if !ifname_ok(iface) {
        return Err(invalid("Wi-Fi radio interface"));
    }
    let hw_mode = if w.band == "5g" { "a" } else { "g" };
    let sae = w.security == "wpa2_wpa3";
    let mut o = String::from("# generated by Patronus - guest Wi-Fi, do not edit\n");
    o.push_str(&format!(
        "interface={iface}\ndriver=nl80211\nbridge={}\nssid={}\nctrl_interface={}\nctrl_interface_group=0\n",
        c.bridge,
        w.ssid,
        ctrl_dir.display()
    ));
    o.push_str(&format!(
        "country_code={}\nieee80211d=1\nhw_mode={hw_mode}\nchannel={}\nieee80211n=1\n",
        w.country, w.channel
    ));
    o.push_str(&format!(
        "wpa=2\nwpa_key_mgmt=WPA-PSK{}\nrsn_pairwise=CCMP\nauth_algs=1\nieee80211w={}\n",
        if sae { " SAE" } else { "" },
        if sae { 1 } else { 0 }
    ));
    if sae {
        o.push_str("sae_pwe=2\n");
    }
    o.push_str(&format!("wpa_psk_file={}\n", psk_path.display()));
    if sae {
        o.push_str(&format!("sae_password={}\n", w.psk));
        for (_, code) in vouchers {
            o.push_str(&format!("sae_password={code}\n"));
        }
    }
    o.push_str(&format!(
        "ap_isolate={}\nmulticast_to_unicast=1\ntdls_prohibit=1\nwpa_disable_eapol_key_retries=1\n",
        if w.isolate { 1 } else { 0 }
    ));
    Ok(o)
}

// ---------------------------------------------------------------------------
// vouchers
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub struct Voucher {
    pub id: i64,
    pub name: String,
    pub code: String,
    pub minutes: i64,
    pub saved_at: i64,
}

impl Voucher {
    pub fn expires_at(&self) -> Option<i64> {
        (self.minutes > 0).then(|| self.saved_at + self.minutes * 60)
    }
    pub fn active(&self, now: i64) -> bool {
        self.expires_at().is_none_or(|e| e > now)
    }
}

pub async fn vouchers(store: &ConfigStore) -> Result<Vec<Voucher>> {
    use sqlx::Row;
    let rows = sqlx::query("SELECT id, name, code, COALESCE(minutes, 0), updated_at FROM guest_vouchers ORDER BY id")
        .fetch_all(store.pool()?)
        .await
        .map_err(|e| Error::Config(format!("read vouchers: {e}")))?;
    Ok(rows
        .iter()
        .map(|r| Voucher {
            id: r.get(0),
            name: r.get(1),
            code: r.get::<Option<String>, _>(2).unwrap_or_default(),
            minutes: r.get(3),
            saved_at: r.get(4),
        })
        .collect())
}

/// `n` random characters from an unambiguous 32-letter alphabet (/dev/urandom).
pub fn random_code(n: usize) -> Result<String> {
    use std::io::Read;
    const A: &[u8; 32] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    let mut buf = vec![0u8; n];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut buf))
        .map_err(|e| Error::Network(format!("random: {e}")))?;
    Ok(buf.iter().map(|b| A[usize::from(*b) % 32] as char).collect())
}

// ---------------------------------------------------------------------------
// the page
// ---------------------------------------------------------------------------

pub struct GuestSvc;

fn now() -> i64 {
    lan::now()
}

/// Merge `body` over the stored settings (secrets keep their stored value on
/// the mask) and parse the result, so a bad combination is refused before
/// anything is written.
async fn merged(store: &ConfigStore, body: &Value) -> Result<Settings> {
    let mut cur = Settings::load(store, &SPEC).await?;
    if let Some(obj) = body.as_object() {
        for f in SPEC.fields {
            let Some(v) = obj.get(f.key) else { continue };
            let s = svc::check(f, v)?;
            if f.kind == Kind::Secret && (s == svc::SECRET_MASK || s.is_empty()) {
                continue;
            }
            cur.0.insert(f.key.into(), Value::String(s));
        }
    }
    Ok(cur)
}

#[async_trait]
impl Svc for GuestSvc {
    fn spec(&self) -> &'static Spec {
        &SPEC
    }

    async fn put(&self, store: &ConfigStore, body: &Value) -> Result<()> {
        let m = merged(store, body).await?;
        let cfg = Cfg::parse(&m, now())?;
        if cfg.enabled {
            conflict_check(store, &cfg).await?;
        }
        svc::put_settings(store, &SPEC, body).await?;
        let keys: Vec<&String> = body.as_object().map(|o| o.keys().collect()).unwrap_or_default();
        let _ = store
            .audit(
                "web",
                "guest_settings",
                "guest",
                None,
                &json!({"changed": keys, "enabled": cfg.enabled, "network": cfg.network()}),
            )
            .await;
        Ok(())
    }

    async fn save_row(&self, store: &ConfigStore, coll: &str, id: Option<i64>, body: &Value) -> Result<i64> {
        let c = svc::find_coll(&SPEC, coll)?;
        if let Some(code) = body.get("code").and_then(Value::as_str) {
            check_wifi_secret(code)?;
        }
        let rid = svc::save_row(store, c, id, body).await?;
        let _ = store
            .audit("web", "guest_voucher_save", "guest", Some(&rid.to_string()), &json!({}))
            .await;
        Ok(rid)
    }

    async fn delete_row(&self, store: &ConfigStore, coll: &str, id: i64) -> Result<()> {
        let c = svc::find_coll(&SPEC, coll)?;
        svc::delete_row(store, c, id).await?;
        let _ = store
            .audit("web", "guest_voucher_delete", "guest", Some(&id.to_string()), &json!({}))
            .await;
        Ok(())
    }

    fn action_applies(&self, _name: &str) -> bool {
        true
    }

    async fn action(&self, store: &ConfigStore, name: &str, body: &Value) -> Result<Value> {
        match name {
            "new_password" => {
                let code = random_code(16)?;
                svc::put_settings(store, &SPEC, &json!({ "wifi_psk": code })).await?;
                let _ = store
                    .audit("web", "guest_new_password", "guest", None, &json!({}))
                    .await;
                Ok(json!({"wifi_password": code, "note": "shown once; the Wi-Fi page never shows it again"}))
            }
            "voucher" => {
                let mins = body
                    .get("minutes")
                    .and_then(|v| v.as_i64().or_else(|| v.as_str().and_then(|s| s.parse().ok())))
                    .unwrap_or(1440);
                if !(0..=525_600).contains(&mins) {
                    return Err(invalid("voucher minutes (0 to 525600)"));
                }
                let code = random_code(12)?;
                let existing = vouchers(store).await?;
                let name = match body.get("name").and_then(Value::as_str).filter(|n| !n.is_empty()) {
                    Some(n) => n.to_string(),
                    None => format!("voucher-{}", existing.iter().map(|v| v.id).max().unwrap_or(0) + 1),
                };
                let id = self
                    .save_row(store, "vouchers", None, &json!({"name": name, "code": code, "minutes": mins}))
                    .await?;
                Ok(json!({"id": id, "name": name, "wifi_password": code, "valid_minutes": mins,
                          "note": "shown once"}))
            }
            "open" => {
                let mins = body
                    .get("minutes")
                    .and_then(|v| v.as_i64().or_else(|| v.as_str().and_then(|s| s.parse().ok())))
                    .unwrap_or(240);
                if !(1..=10_080).contains(&mins) {
                    return Err(invalid("open for (1 to 10080 minutes)"));
                }
                let until = now() + mins * 60;
                svc::put_settings(
                    store,
                    &SPEC,
                    &json!({"access": "timed", "open_until": until.to_string()}),
                )
                .await?;
                let _ = store
                    .audit("web", "guest_open", "guest", None, &json!({"minutes": mins, "until": until}))
                    .await;
                Ok(json!({"open_until": until, "minutes": mins}))
            }
            "close" => {
                svc::put_settings(store, &SPEC, &json!({"access": "timed", "open_until": "0"})).await?;
                let _ = store.audit("web", "guest_close", "guest", None, &json!({})).await;
                Ok(json!({"open_until": 0}))
            }
            other => Err(Error::Config(format!("Invalid request: no action {other:?}"))),
        }
    }
}

fn check_wifi_secret(s: &str) -> Result<()> {
    if s == svc::SECRET_MASK || s.is_empty() {
        return Ok(());
    }
    if !(8..=63).contains(&s.len()) || s.bytes().any(|b| matches!(b, b'|' | b',' | b' ')) {
        return Err(invalid("Wi-Fi password (8-63 characters, no | , or spaces)"));
    }
    Ok(())
}

/// The guest subnet must not overlap any other IPv4 network on the box
/// (except the guest bridge itself).
async fn conflict_check(store: &ConfigStore, c: &Cfg) -> Result<()> {
    if !c.overlap_check {
        return Ok(());
    }
    let mine: ipnetwork::Ipv4Network = format!("{}/{}", Ipv4Addr::from(net_base(c.router, c.prefix)), c.prefix)
        .parse()
        .map_err(|_| invalid("guest subnet"))?;
    let mut others: Vec<(String, ipnetwork::Ipv4Network)> = Vec::new();
    {
        use crate::lan::AddrSource;
        if let Ok(addrs) = lan::LiveAddrs.addrs() {
            for a in addrs {
                if a.ifname == c.bridge {
                    continue;
                }
                if let std::net::IpAddr::V4(v4) = a.addr {
                    if v4.is_loopback() || v4.is_link_local() {
                        continue;
                    }
                    if let Ok(n) = ipnetwork::Ipv4Network::new(Ipv4Addr::from(net_base(v4, a.prefix)), a.prefix) {
                        others.push((a.ifname.clone(), n));
                    }
                }
            }
        }
    }
    // configured (not yet live) addresses of other interfaces
    if let Ok(cfg) = crate::netconf::NetConfig::load(store).await {
        for i in &cfg.interfaces {
            if i.name == c.bridge {
                continue;
            }
            for a in &i.ipv4 {
                if let ipnetwork::IpNetwork::V4(n) = a {
                    if let Ok(nn) =
                        ipnetwork::Ipv4Network::new(Ipv4Addr::from(net_base(n.ip(), n.prefix())), n.prefix())
                    {
                        others.push((i.name.clone(), nn));
                    }
                }
            }
        }
    }
    for (dev, n) in others {
        if n.contains(mine.network()) || mine.contains(n.network()) {
            return Err(invalid(format!(
                "guest subnet {mine} (overlaps {n} on {dev}; pick another address)"
            )));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// the applier
// ---------------------------------------------------------------------------

/// Runs the system commands the applier needs (a recorder in tests).
pub trait Host: Send + Sync {
    /// Run a program; Err carries stderr on a non-zero exit.
    fn run(&self, argv: &[String]) -> Result<String>;
    /// Run, ignoring failure.
    fn try_run(&self, argv: &[String]) -> Option<String> {
        self.run(argv).ok()
    }
    fn nft(&self, script: &str) -> Result<()>;
    fn write_sysctl(&self, key: &str, value: &str) -> Result<()>;
    fn dev_exists(&self, dev: &str) -> bool;
}

pub struct SystemHost;

impl Host for SystemHost {
    fn run(&self, argv: &[String]) -> Result<String> {
        let Some((prog, args)) = argv.split_first() else {
            return Err(Error::Network("empty command".into()));
        };
        let out = std::process::Command::new(prog)
            .args(args)
            .output()
            .map_err(|e| Error::Network(format!("{prog}: {e}")))?;
        if out.status.success() {
            Ok(String::from_utf8_lossy(&out.stdout).to_string())
        } else {
            Err(Error::Network(format!(
                "{} failed: {}",
                argv.join(" "),
                String::from_utf8_lossy(&out.stderr).trim()
            )))
        }
    }

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
                "guest network nft rules: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            )))
        }
    }

    fn write_sysctl(&self, key: &str, value: &str) -> Result<()> {
        // the key is a /proc/sys path (device names may contain dots)
        let p = PathBuf::from("/proc/sys").join(key);
        match std::fs::write(&p, value) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(Error::Network(format!("{}: {e}", p.display()))),
        }
    }

    fn dev_exists(&self, dev: &str) -> bool {
        Path::new("/sys/class/net").join(dev).exists()
    }
}

fn a(args: &[&str]) -> Vec<String> {
    args.iter().map(|s| s.to_string()).collect()
}

/// Devices currently enslaved to `bridge`: (name, kind, e.g. "vlan").
fn bridge_members(host: &dyn Host, bridge: &str) -> Vec<(String, String)> {
    let Some(out) = host.try_run(&a(&["ip", "-j", "-d", "link", "show", "master", bridge])) else {
        return Vec::new();
    };
    let v: Value = serde_json::from_str(&out).unwrap_or(Value::Null);
    v.as_array()
        .map(|l| {
            l.iter()
                .filter_map(|e| {
                    let n = e.get("ifname")?.as_str()?.to_string();
                    let k = e
                        .get("linkinfo")
                        .and_then(|l| l.get("info_kind"))
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string();
                    Some((n, k))
                })
                .collect()
        })
        .unwrap_or_default()
}

fn bridge_addrs(host: &dyn Host, bridge: &str) -> Vec<String> {
    let Some(out) = host.try_run(&a(&["ip", "-j", "-4", "addr", "show", "dev", bridge])) else {
        return Vec::new();
    };
    let v: Value = serde_json::from_str(&out).unwrap_or(Value::Null);
    v.as_array()
        .into_iter()
        .flatten()
        .flat_map(|e| e.get("addr_info").and_then(Value::as_array).cloned().unwrap_or_default())
        .filter_map(|ai| {
            Some(format!(
                "{}/{}",
                ai.get("local")?.as_str()?,
                ai.get("prefixlen")?.as_u64()?
            ))
        })
        .collect()
}

/// Make the kernel side (bridge, VLAN, ports, address, isolation, caps) match `c`.
/// Returns the human-readable lines of what it did.
pub fn apply_kernel(host: &dyn Host, c: &Cfg, parent_dev: Option<&str>, wifi_iface: Option<&str>) -> Result<Vec<String>> {
    let br = c.bridge.as_str();
    let mut said = Vec::new();
    if !host.dev_exists(br) {
        host.run(&a(&["ip", "link", "add", "name", br, "type", "bridge"]))?;
        said.push(format!("bridge {br} created"));
    }
    host.try_run(&a(&["ip", "link", "set", br, "type", "bridge", "stp_state", "0"]));
    // addresses: exactly the configured one
    let want = format!("{}/{}", c.router, c.prefix);
    let have = bridge_addrs(host, br);
    if have != vec![want.clone()] {
        host.try_run(&a(&["ip", "-4", "addr", "flush", "dev", br]));
        host.run(&a(&["ip", "addr", "add", &want, "dev", br]))?;
        said.push(format!("{br} address {want}"));
    }
    host.run(&a(&["ip", "link", "set", br, "up"]))?;
    // no IPv6 on guest networks yet
    host.write_sysctl(&format!("net/ipv6/conf/{br}/disable_ipv6"), "1")?;
    host.write_sysctl(&format!("net/ipv4/conf/{br}/forwarding"), "1")?;
    host.write_sysctl(&format!("net/ipv4/conf/{br}/send_redirects"), "0")?;

    // members
    let mut want_members: Vec<(String, bool)> = Vec::new(); // (dev, isolate-able)
    if c.vlan_id > 0 {
        let parent = parent_dev.ok_or_else(|| invalid("VLAN trunk interface (no device behind it)"))?;
        let vd = c.vlan_dev(parent);
        if vd.len() > 15 {
            return Err(invalid(format!(
                "VLAN device name {vd:?} is longer than 15 characters (use a shorter trunk device name)"
            )));
        }
        if !host.dev_exists(&vd) {
            host.run(&a(&["ip", "link", "set", parent, "up"]))?;
            host.run(&a(&[
                "ip", "link", "add", "link", parent, "name", &vd, "type", "vlan", "id", &c.vlan_id.to_string(),
            ]))?;
            said.push(format!("VLAN {vd} created"));
        }
        // a VLAN trunk is one bridge port for many remote guests: no L2 isolation here
        want_members.push((vd, false));
    }
    for p in &c.ports {
        if !host.dev_exists(p) {
            return Err(invalid(format!("guest port {p:?} (no such device)")));
        }
        want_members.push((p.clone(), true));
    }
    let have_members = bridge_members(host, br);
    for (name, kind) in &have_members {
        if Some(name.as_str()) == wifi_iface {
            continue;
        }
        if !want_members.iter().any(|(w, _)| w == name) {
            if kind == "vlan" {
                host.try_run(&a(&["ip", "link", "del", name]));
                said.push(format!("stale VLAN {name} removed"));
            } else {
                host.try_run(&a(&["ip", "link", "set", name, "nomaster"]));
                said.push(format!("{name} left the guest network"));
            }
        }
    }
    for (name, isolable) in &want_members {
        if !have_members.iter().any(|(n, _)| n == name) {
            host.run(&a(&["ip", "link", "set", name, "master", br]))?;
            said.push(format!("{name} joined {br}"));
        }
        host.run(&a(&["ip", "link", "set", name, "up"]))?;
        let iso = if c.isolate && *isolable { "on" } else { "off" };
        host.try_run(&a(&["bridge", "link", "set", "dev", name, "isolated", iso]));
    }
    // network caps
    match tc_download(c) {
        Some(args) => {
            let mut v = vec!["tc".to_string()];
            v.extend(args);
            host.run(&v)?;
        }
        None => {
            host.try_run(&a(&["tc", "qdisc", "del", "dev", br, "root"]));
        }
    }
    match tc_upload(c) {
        Some(args) => {
            host.try_run(&a(&["tc", "qdisc", "replace", "dev", br, "handle", "ffff:", "ingress"]));
            let mut v = vec!["tc".to_string()];
            v.extend(args);
            host.run(&v)?;
        }
        None => {
            host.try_run(&a(&["tc", "qdisc", "del", "dev", br, "ingress"]));
        }
    }
    Ok(said)
}

/// Remove everything the applier created (network switched off).
pub fn teardown_kernel(host: &dyn Host, bridge: &str) -> Vec<String> {
    let mut said = Vec::new();
    host.try_run(&a(&["nft", "delete", "table", "inet", TABLE]));
    if host.dev_exists(bridge) {
        for (name, kind) in bridge_members(host, bridge) {
            if kind == "vlan" {
                host.try_run(&a(&["ip", "link", "del", &name]));
            } else {
                host.try_run(&a(&["ip", "link", "set", &name, "nomaster"]));
            }
        }
        host.try_run(&a(&["ip", "link", "del", bridge]));
        said.push(format!("bridge {bridge} removed"));
    }
    said
}

#[derive(Clone)]
pub struct GuestApplier {
    sup: Supervisor,
}

impl Default for GuestApplier {
    fn default() -> Self {
        Self {
            sup: Supervisor::detect(),
        }
    }
}

impl GuestApplier {
    pub fn with_supervisor(sup: Supervisor) -> Self {
        Self { sup }
    }

    fn dir(&self) -> PathBuf {
        self.sup.paths.state_dir.join("guest")
    }

    async fn stop_daemons(&self) -> Result<()> {
        self.sup.stop(svc::DAEMON_SERVICE, DNSMASQ_INSTANCE).await?;
        self.sup.stop(svc::DAEMON_SERVICE, HOSTAPD_INSTANCE).await?;
        Ok(())
    }

    async fn load(&self, store: &ConfigStore) -> Result<(Settings, Cfg)> {
        let s = Settings::load(store, &SPEC).await?;
        let c = Cfg::parse(&s, now())?;
        Ok((s, c))
    }

    /// Wi-Fi radio interface for this config, and why not if there is none.
    fn pick_radio(c: &Cfg) -> std::result::Result<String, String> {
        if !c.wifi.iface.is_empty() {
            return if Path::new("/sys/class/net").join(&c.wifi.iface).exists() {
                Ok(c.wifi.iface.clone())
            } else {
                Err(format!("Wi-Fi interface {} does not exist", c.wifi.iface))
            };
        }
        let radios = crate::radio::radios();
        if radios.is_empty() {
            return Err("this router has no Wi-Fi radio".into());
        }
        for r in &radios {
            if r.ap && !r.ifaces.is_empty() && r.bands.contains(&c.wifi.band) {
                return Ok(r.ifaces[0].clone());
            }
        }
        Err(format!(
            "no radio can run an access point on the {} band",
            c.wifi.band
        ))
    }

    async fn apply_with(&self, store: &ConfigStore, host: &dyn Host) -> Result<ApplyReport> {
        let mut rep = ApplyReport::default();
        let (_s, c) = self.load(store).await?;
        let dir = self.dir();
        if !c.enabled {
            self.stop_daemons().await?;
            for l in teardown_kernel(host, &c.bridge) {
                rep.applied(l);
            }
            // a bridge name that was changed while off leaves nothing: the table is gone too
            rep.applied("guest network is off");
            return Ok(rep);
        }
        conflict_check(store, &c).await?;
        let parent_dev = if c.vlan_id > 0 {
            lan::resolve_iface(store, &c.parent).await?.into_iter().next()
        } else {
            None
        };
        if c.vlan_id > 0 && parent_dev.is_none() {
            return Err(invalid(format!(
                "guest network: interface {} has no device (Interfaces page)",
                c.parent
            )));
        }
        let wan_devs: Vec<String> = lan::resolve_iface(store, &c.internet).await?;
        if wan_devs.is_empty() {
            return Err(invalid(format!(
                "guest network: internet interface {} has no device (Interfaces page)",
                c.internet
            )));
        }
        let dnsmasq = which("dnsmasq").ok_or_else(|| {
            Error::Service("the guest network needs dnsmasq, which is not installed (emerge net-dns/dnsmasq)".into())
        })?;
        std::fs::create_dir_all(&dir).map_err(|e| Error::Network(format!("{}: {e}", dir.display())))?;

        // Wi-Fi (optional): resolve the radio before touching the kernel
        let mut wifi_note = None;
        let wifi_iface = if c.wifi.enabled {
            match Self::pick_radio(&c) {
                Ok(i) => Some(i),
                Err(why) => {
                    wifi_note = Some(why);
                    None
                }
            }
        } else {
            None
        };
        for l in apply_kernel(host, &c, parent_dev.as_deref(), wifi_iface.as_deref())? {
            rep.applied(l);
        }
        // the firewall rules, atomically
        let script = render_nft(&c, &wan_devs, now());
        host.nft(&script)?;
        rep.applied(format!("firewall table inet {TABLE} loaded"));

        // DHCP + DNS
        let conf = dir.join("dnsmasq.conf");
        let text = render_dnsmasq(
            &c,
            &dir.join("dnsmasq.leases").to_string_lossy(),
            &dir.join("dnsmasq.pid").to_string_lossy(),
        );
        let started = svc::ensure_daemon(
            &self.sup,
            DNSMASQ_INSTANCE,
            vec![
                dnsmasq.to_string_lossy().into(),
                "-k".into(),
                "-C".into(),
                conf.to_string_lossy().into(),
            ],
            vec![(conf, text, 0o644)],
        )
        .await?;
        rep.applied(format!(
            "guest DHCP/DNS {} on {} ({} - {})",
            if started { "(re)started" } else { "running, unchanged" },
            c.bridge,
            c.dhcp_start,
            c.dhcp_end
        ));

        // Wi-Fi
        match (&wifi_iface, c.wifi.enabled) {
            (Some(iface), true) => {
                let hostapd = which("hostapd").ok_or_else(|| {
                    Error::Service("the guest Wi-Fi needs hostapd, which is not installed (emerge net-wireless/hostapd)".into())
                })?;
                let psk_path = dir.join("hostapd.psk");
                let ctrl = self.sup.paths.run_dir.join("guest-hostapd");
                std::fs::create_dir_all(&ctrl).map_err(|e| Error::Network(format!("{}: {e}", ctrl.display())))?;
                let now_ts = now();
                let active: Vec<(i64, String)> = vouchers(store)
                    .await?
                    .into_iter()
                    .filter(|v| v.active(now_ts) && check_wifi_secret(&v.code).is_ok() && !v.code.is_empty())
                    .map(|v| (v.id, v.code))
                    .collect();
                let psk_text = render_psk_file(&c.wifi.psk, &active);
                let before = std::fs::read_to_string(&psk_path).unwrap_or_default();
                let changed_psk = crate::supervise::write_atomic(&psk_path, &psk_text, 0o600)?;
                let conf_path = dir.join("hostapd.conf");
                let conf = render_hostapd(&c, iface, &psk_path, &ctrl, &active)?;
                let restarted = svc::ensure_daemon(
                    &self.sup,
                    HOSTAPD_INSTANCE,
                    vec![hostapd.to_string_lossy().into(), conf_path.to_string_lossy().into()],
                    vec![(conf_path, conf, 0o600)],
                )
                .await?;
                if changed_psk && !restarted {
                    // live: new passphrases work at once; stations that used a
                    // removed one are dropped (the others reconnect by themselves)
                    let removed = before
                        .lines()
                        .filter_map(|l| l.strip_prefix("keyid="))
                        .any(|l| !psk_text.contains(l));
                    let cli = which("hostapd_cli");
                    if let Some(cli) = cli {
                        let cli = cli.to_string_lossy().to_string();
                        let ctrl_s = ctrl.to_string_lossy().to_string();
                        host.try_run(&[cli.clone(), "-p".into(), ctrl_s.clone(), "-i".into(), iface.clone(), "reload_wpa_psk".into()]);
                        if removed {
                            if let Some(sta) = host.try_run(&[cli.clone(), "-p".into(), ctrl_s.clone(), "-i".into(), iface.clone(), "all_sta".into()]) {
                                for mac in sta.lines().map(str::trim).filter(|l| l.len() == 17 && l.matches(':').count() == 5) {
                                    host.try_run(&[cli.clone(), "-p".into(), ctrl_s.clone(), "-i".into(), iface.clone(), "deauthenticate".into(), mac.into()]);
                                }
                            }
                        }
                    }
                }
                rep.applied(format!(
                    "guest Wi-Fi {:?} on {iface} {}",
                    c.wifi.ssid,
                    if restarted { "(re)started" } else { "running" }
                ));
            }
            (None, true) => {
                self.sup.stop(svc::DAEMON_SERVICE, HOSTAPD_INSTANCE).await?;
                rep.warn(format!(
                    "guest Wi-Fi not broadcast: {}",
                    wifi_note.unwrap_or_else(|| "no radio".into())
                ));
            }
            _ => {
                self.sup.stop(svc::DAEMON_SERVICE, HOSTAPD_INSTANCE).await?;
            }
        }
        Ok(rep)
    }
}

#[async_trait]
impl Applier for GuestApplier {
    fn name(&self) -> &'static str {
        "guest"
    }

    fn phase(&self) -> Phase {
        Phase::Services
    }

    async fn apply(&self, store: &ConfigStore) -> Result<ApplyReport> {
        self.apply_with(store, &SystemHost).await
    }

    async fn render(&self, store: &ConfigStore) -> Result<String> {
        let (_s, c) = self.load(store).await?;
        if !c.enabled {
            return Ok("# guest network off\n".into());
        }
        let wan = lan::resolve_iface(store, &c.internet).await.unwrap_or_default();
        let mut o = render_nft(&c, &wan, now());
        o.push_str("\n# dnsmasq\n");
        o.push_str(&render_dnsmasq(&c, "dnsmasq.leases", "dnsmasq.pid"));
        for t in [tc_download(&c), tc_upload(&c)].into_iter().flatten() {
            o.push_str(&format!("\n# tc {}\n", t.join(" ")));
        }
        Ok(o)
    }

    async fn status(&self, store: &ConfigStore) -> Result<Value> {
        let (_s, c) = self.load(store).await?;
        let host = SystemHost;
        let now_ts = now();
        let mut m = Map::new();
        m.insert("enabled".into(), json!(c.enabled));
        m.insert("network".into(), json!(c.network()));
        m.insert("bridge_up".into(), json!(host.dev_exists(&c.bridge)));
        m.insert("dhcp_dns_running".into(), json!(self.sup.is_running(svc::DAEMON_SERVICE, DNSMASQ_INSTANCE)));
        m.insert(
            "firewall_table".into(),
            json!(host
                .try_run(&a(&["nft", "list", "table", "inet", TABLE]))
                .is_some()),
        );
        let (open, why) = match gate_closed(&c.gate, now_ts) {
            None => (true, "always open".to_string()),
            Some(v) if v.is_empty() => (false, "closed (timed access is not open)".to_string()),
            Some(_) => match &c.gate {
                Gate::Timed { open_until } => (true, format!("open until {open_until} (epoch)")),
                Gate::Schedule { from, to, .. } => (true, format!("schedule {}-{}", clock(*from), clock(*to))),
                Gate::Always => (true, String::new()),
            },
        };
        m.insert("access_now".into(), json!(if open { "open" } else { "closed" }));
        m.insert("access_detail".into(), json!(why));
        let leases = std::fs::read_to_string(self.dir().join("dnsmasq.leases")).unwrap_or_default();
        let clients: Vec<String> = leases
            .lines()
            .filter_map(|l| {
                let f: Vec<&str> = l.split_whitespace().collect();
                (f.len() >= 4).then(|| format!("{} {} {}", f[2], f[1], f[3]))
            })
            .collect();
        m.insert("clients".into(), json!(clients));
        if c.wifi.enabled {
            let w = match Self::pick_radio(&c) {
                Ok(i) => json!({"available": true, "interface": i,
                    "running": self.sup.is_running(svc::DAEMON_SERVICE, HOSTAPD_INSTANCE)}),
                Err(why) => json!({"available": false, "reason": why}),
            };
            m.insert("wifi".into(), w);
        }
        let vs = vouchers(store).await.unwrap_or_default();
        let active = vs.iter().filter(|v| v.active(now_ts)).count();
        m.insert("vouchers".into(), json!({"active": active, "expired": vs.len() - active}));
        Ok(Value::Object(m))
    }
}

/// Is the guest network switched on?
pub async fn is_enabled(store: &ConfigStore) -> bool {
    Settings::load(store, &SPEC)
        .await
        .map(|s| s.b("enabled"))
        .unwrap_or(false)
}

/// Ids of the vouchers that work now (for the web watcher: a change of this
/// set means the SSID needs re-applying).
pub async fn active_voucher_ids(store: &ConfigStore, now_ts: i64) -> Result<Vec<i64>> {
    Ok(vouchers(store)
        .await?
        .into_iter()
        .filter(|v| v.active(now_ts))
        .map(|v| v.id)
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    fn settings(pairs: &[(&str, &str)]) -> Settings {
        let mut m = Map::new();
        for f in SPEC.fields {
            m.insert(f.key.into(), json!(f.default));
        }
        for (k, v) in pairs {
            m.insert((*k).into(), json!(v));
        }
        Settings(m)
    }

    fn cfg(pairs: &[(&str, &str)]) -> Cfg {
        Cfg::parse(&settings(pairs), 1_000_000).unwrap()
    }

    #[test]
    fn defaults_give_a_complete_isolated_network() {
        let c = cfg(&[("enabled", "1")]);
        assert_eq!(c.bridge, "br-guest");
        assert_eq!(c.network(), "192.168.30.0/24");
        assert_eq!(c.dhcp_start.to_string(), "192.168.30.100");
        assert_eq!(c.dhcp_end.to_string(), "192.168.30.254");
        assert!(c.isolate && c.block_private && c.allow_ping);
    }

    #[test]
    fn every_default_is_valid_for_its_kind() {
        for f in SPEC.fields.iter().chain(VOUCHER_FIELDS.iter()) {
            if f.default.is_empty() {
                continue;
            }
            svc::check(f, &Value::String(f.default.into()))
                .unwrap_or_else(|e| panic!("default of {} is invalid: {e}", f.key));
        }
    }

    #[test]
    fn bad_values_are_refused() {
        let bad = |pairs: &[(&str, &str)]| Cfg::parse(&settings(pairs), 0).is_err();
        assert!(bad(&[("address", "192.168.30.0/24")]), "network address as router");
        assert!(bad(&[("address", "192.168.30.1/31")]), "prefix too long");
        assert!(bad(&[("dhcp_start", "192.168.31.5")]), "range outside subnet");
        assert!(bad(&[("dhcp_start", "192.168.30.50"), ("dhcp_end", "192.168.30.40")]));
        assert!(bad(&[("dhcp_start", "192.168.30.1"), ("dhcp_end", "192.168.30.9")]), "router in range");
        assert!(bad(&[("bridge", "br guest")]));
        assert!(bad(&[("ports", "eth1,a;b")]));
        assert!(bad(&[("router_ports", "tcp/99999")]));
        assert!(bad(&[("router_ports", "icmp/1")]));
        assert!(bad(&[("access", "schedule"), ("schedule_from", "08:00"), ("schedule_to", "08:00")]));
        assert!(bad(&[("access", "schedule"), ("schedule_from", "25:00")]));
        assert!(bad(&[("wifi", "1"), ("wifi_psk", "short")]));
        assert!(bad(&[("wifi", "1"), ("wifi_psk", "longenough1"), ("wifi_band", "5g"), ("wifi_channel", "6")]));
        assert!(bad(&[("dns_servers", "2001:db8::1")]));
        assert!(!bad(&[("wifi", "1"), ("wifi_psk", "longenough1")]));
    }

    #[test]
    fn small_subnets_get_a_sensible_range() {
        let c = cfg(&[("address", "10.9.9.1/29")]);
        assert_eq!(c.dhcp_start.to_string(), "10.9.9.3");
        assert_eq!(c.dhcp_end.to_string(), "10.9.9.6");
    }

    #[test]
    fn nft_isolates_guests_and_opens_only_dhcp_dns_ping() {
        let c = cfg(&[("enabled", "1")]);
        let t = render_nft(&c, &["eth0".into()], 1_000_000);
        assert!(t.starts_with("add table inet patronus_guest\ndelete table inet patronus_guest\n"));
        assert!(t.contains("iifname \"br-guest\" jump guest_in"));
        assert!(t.contains("udp sport 68 udp dport 67 accept"));
        assert!(t.contains("ip daddr 192.168.30.1 udp dport 53 accept"));
        assert!(t.contains("ip daddr 192.168.30.1 icmp type echo-request accept"));
        assert!(t.contains("drop comment \"guests reach nothing else on the router\""));
        assert!(t.contains("oifname != { \"eth0\" } drop"));
        assert!(t.contains("ip daddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16"));
        assert!(t.contains("ct state != established,related drop"));
        assert!(t.contains("ip saddr 192.168.30.0/24 oifname { \"eth0\" } masquerade"));
        assert!(!t.contains("set up_clients"), "no per-client cap by default");
        assert!(!t.contains("closed"), "always open by default");
        // IPv6 never passes
        assert_eq!(t.matches("meta nfproto ipv6 drop").count(), 2);
    }

    #[test]
    fn dns_handed_out_elsewhere_closes_port_53_on_the_router() {
        let c = cfg(&[("enabled", "1"), ("dns_servers", "9.9.9.9, 1.1.1.1"), ("allow_ping", "0")]);
        let t = render_nft(&c, &["eth0".into()], 0);
        assert!(!t.contains("dport 53"));
        assert!(!t.contains("echo-request"));
        let d = render_dnsmasq(&c, "/l", "/p");
        assert!(d.contains("port=0\n") && d.contains("dhcp-option=option:dns-server,9.9.9.9,1.1.1.1\n"));
    }

    #[test]
    fn limits_and_ports_are_rendered() {
        let c = cfg(&[
            ("enabled", "1"),
            ("client_up_kbit", "2000"),
            ("client_down_kbit", "8000"),
            ("router_ports", "tcp/853, udp/123, tcp/8000-8010"),
            ("egress_ports", "tcp/80,tcp/443,udp/53"),
        ]);
        let t = render_nft(&c, &["eth0".into()], 0);
        assert!(t.contains("set up_clients") && t.contains("set down_clients"));
        assert!(t.contains("add @up_clients { ip saddr limit rate over 250 kbytes/second"));
        assert!(t.contains("add @down_clients { ip daddr limit rate over 1000 kbytes/second"));
        assert!(t.contains("tcp dport { 853, 8000-8010 } accept comment \"guest router service\""));
        assert!(t.contains("udp dport { 123 } accept"));
        // the cap is evaluated before the allow-list accepts, or an accept would skip it
        assert!(t.find("add @up_clients").unwrap() < t.find("tcp dport { 80, 443 } accept").unwrap());
        assert!(t.contains("drop comment \"port not allowed for guests\""));
    }

    #[test]
    fn network_caps_become_tc_commands() {
        let c = cfg(&[("down_kbit", "10000"), ("up_kbit", "2000")]);
        let d = tc_download(&c).unwrap().join(" ");
        assert!(d.starts_with("qdisc replace dev br-guest root tbf rate 10000kbit burst"), "{d}");
        let u = tc_upload(&c).unwrap().join(" ");
        assert!(u.contains("parent ffff: protocol all prio 1 matchall action police rate 2000kbit"), "{u}");
        assert!(tc_download(&cfg(&[])).is_none() && tc_upload(&cfg(&[])).is_none());
    }

    #[test]
    fn schedule_and_timed_access_close_the_network_by_themselves() {
        let day = cfg(&[("enabled", "1"), ("access", "schedule"), ("schedule_from", "07:00"), ("schedule_to", "23:00"),
                        ("schedule_days", "mon,tue,wed,thu,fri")]);
        let g = gate_closed(&day.gate, 0).unwrap();
        assert_eq!(g, vec!["meta day != { 1, 2, 3, 4, 5 }", "meta hour != \"07:00\"-\"22:59\""]);
        let night = cfg(&[("access", "schedule"), ("schedule_from", "22:00"), ("schedule_to", "06:00")]);
        assert_eq!(gate_closed(&night.gate, 0).unwrap(), vec!["meta hour \"06:00\"-\"21:59\""]);
        let t = render_nft(&day, &["eth0".into()], 0);
        assert!(t.contains("meta hour != \"07:00\"-\"22:59\" drop comment \"guest network is closed\""));
        // the DHCP accept stays above the closing rules: a closed network still answers DHCP
        assert!(t.find("guest DHCP").unwrap() < t.find("guest network is closed").unwrap());
        let timed = cfg(&[("access", "timed"), ("open_until", "5000")]);
        assert_eq!(gate_closed(&timed.gate, 1000).unwrap(), vec!["meta time >= 5000"]);
        assert_eq!(gate_closed(&timed.gate, 6000).unwrap(), Vec::<String>::new());
        let t = render_nft(&timed, &["eth0".into()], 6000);
        assert!(t.contains("    drop comment \"guest network is closed\""));
        assert!(gate_closed(&Gate::Always, 0).is_none());
    }

    #[test]
    fn dnsmasq_serves_only_the_guest_address() {
        let c = cfg(&[("enabled", "1"), ("dns_upstreams", "198.51.100.53"), ("lease_minutes", "30")]);
        let d = render_dnsmasq(&c, "/var/l", "/var/p");
        for l in [
            "interface=br-guest",
            "bind-interfaces",
            "listen-address=192.168.30.1",
            "dhcp-range=192.168.30.100,192.168.30.254,255.255.255.0,30m",
            "dhcp-option=option:router,192.168.30.1",
            "dhcp-option=option:dns-server,192.168.30.1",
            "no-resolv",
            "server=198.51.100.53",
            "dhcp-leasefile=/var/l",
        ] {
            assert!(d.contains(&format!("{l}\n")), "missing {l}\n{d}");
        }
    }

    #[test]
    fn hostapd_isolates_clients_and_carries_the_vouchers() {
        let c = cfg(&[("wifi", "1"), ("wifi_psk", "sharedpass1"), ("ssid", "Guest Wi-Fi")]);
        let h = render_hostapd(&c, "wlan0", Path::new("/s/psk"), Path::new("/r"), &[(3, "VOUCHERCODE".into())]).unwrap();
        assert!(h.contains("bridge=br-guest\nssid=Guest Wi-Fi\n"));
        assert!(h.contains("ap_isolate=1"));
        assert!(h.contains("wpa_key_mgmt=WPA-PSK SAE") && h.contains("sae_password=sharedpass1") && h.contains("sae_password=VOUCHERCODE"));
        let p = render_psk_file("sharedpass1", &[(3, "VOUCHERCODE".into())]);
        assert!(p.contains("keyid=guest 00:00:00:00:00:00 sharedpass1\n") && p.contains("keyid=voucher-3 00:00:00:00:00:00 VOUCHERCODE\n"));
        assert!(render_hostapd(&c, "wlan0;x", Path::new("/p"), Path::new("/r"), &[]).is_err());
        let open = cfg(&[("wifi", "1"), ("wifi_psk", "sharedpass1"), ("isolate_clients", "0"), ("wifi_security", "wpa2")]);
        let h = render_hostapd(&open, "wlan0", Path::new("/s/psk"), Path::new("/r"), &[]).unwrap();
        assert!(h.contains("ap_isolate=0") && !h.contains("SAE") && h.contains("ieee80211w=0"));
    }

    #[test]
    fn voucher_expiry_counts_from_when_it_was_saved() {
        let v = Voucher { id: 1, name: "a".into(), code: "x".into(), minutes: 60, saved_at: 1000 };
        assert!(v.active(1000 + 3599) && !v.active(1000 + 3600));
        let forever = Voucher { minutes: 0, ..v };
        assert!(forever.active(i64::MAX / 2));
    }

    #[test]
    fn ports_and_days_parse() {
        assert_eq!(parse_ports("tcp/443, udp/5000-5010", "p").unwrap().len(), 2);
        assert!(parse_ports("tcp/0", "p").is_err() && parse_ports("tcp/9-3", "p").is_err());
        assert_eq!(parse_days("sat,sun,mon,0").unwrap(), vec![0, 1, 6]);
        assert!(parse_days("").is_err() && parse_days("funday").is_err());
        assert_eq!(random_code(12).unwrap().len(), 12);
        assert_ne!(random_code(16).unwrap(), random_code(16).unwrap());
    }

    // ---- kernel-side sequence against a recording host

    #[derive(Default)]
    struct Rec {
        cmds: Mutex<Vec<String>>,
        devs: Mutex<Vec<String>>,
        members: Mutex<String>,
        addrs: Mutex<String>,
        nft: Mutex<Vec<String>>,
        sysctls: Mutex<Vec<String>>,
    }

    impl Host for Rec {
        fn run(&self, argv: &[String]) -> Result<String> {
            let line = argv.join(" ");
            self.cmds.lock().unwrap().push(line.clone());
            if line.starts_with("ip -j -d link show master") {
                return Ok(self.members.lock().unwrap().clone());
            }
            if line.starts_with("ip -j -4 addr show") {
                return Ok(self.addrs.lock().unwrap().clone());
            }
            Ok(String::new())
        }
        fn nft(&self, s: &str) -> Result<()> {
            self.nft.lock().unwrap().push(s.into());
            Ok(())
        }
        fn write_sysctl(&self, k: &str, v: &str) -> Result<()> {
            self.sysctls.lock().unwrap().push(format!("{k}={v}"));
            Ok(())
        }
        fn dev_exists(&self, d: &str) -> bool {
            self.devs.lock().unwrap().iter().any(|x| x == d)
        }
    }

    #[test]
    fn kernel_setup_builds_bridge_vlan_and_isolated_ports() {
        let c = cfg(&[("enabled", "1"), ("ports", "gst-a,gst-b"), ("down_kbit", "5000"), ("up_kbit", "1000")]);
        let h = Rec::default();
        h.devs.lock().unwrap().extend(["gst-a".to_string(), "gst-b".to_string()]);
        let said = apply_kernel(&h, &c, Some("eth1"), None).unwrap();
        let cmds = h.cmds.lock().unwrap().join("\n");
        for want in [
            "ip link add name br-guest type bridge",
            "ip addr add 192.168.30.1/24 dev br-guest",
            "ip link add link eth1 name eth1.30 type vlan id 30",
            "ip link set eth1.30 master br-guest",
            "ip link set gst-a master br-guest",
            "bridge link set dev gst-a isolated on",
            "bridge link set dev gst-b isolated on",
            "bridge link set dev eth1.30 isolated off",
            "tc qdisc replace dev br-guest root tbf rate 5000kbit",
            "tc qdisc replace dev br-guest handle ffff: ingress",
        ] {
            assert!(cmds.contains(want), "missing {want}\n{cmds}");
        }
        assert!(h.sysctls.lock().unwrap().contains(&"net/ipv6/conf/br-guest/disable_ipv6=1".to_string()));
        assert!(said.iter().any(|l| l.contains("VLAN eth1.30 created")));
    }

    #[test]
    fn kernel_setup_is_idempotent_and_removes_stale_members() {
        let c = cfg(&[("enabled", "1"), ("vlan_id", "0"), ("ports", "gst-a"), ("isolate_clients", "0")]);
        let h = Rec::default();
        h.devs.lock().unwrap().extend(["br-guest", "gst-a"].map(String::from));
        *h.addrs.lock().unwrap() = r#"[{"addr_info":[{"local":"192.168.30.1","prefixlen":24}]}]"#.into();
        *h.members.lock().unwrap() = r#"[{"ifname":"gst-a","linkinfo":{}},{"ifname":"old.30","linkinfo":{"info_kind":"vlan"}},{"ifname":"gst-old","linkinfo":{}}]"#.into();
        apply_kernel(&h, &c, None, None).unwrap();
        let cmds = h.cmds.lock().unwrap().join("\n");
        assert!(!cmds.contains("addr add"), "address already right\n{cmds}");
        assert!(!cmds.contains("add name br-guest"), "bridge already there");
        assert!(cmds.contains("ip link del old.30"), "{cmds}");
        assert!(cmds.contains("ip link set gst-old nomaster"));
        assert!(!cmds.contains("gst-a master"), "already a member");
        assert!(cmds.contains("bridge link set dev gst-a isolated off"));
        assert!(cmds.contains("tc qdisc del dev br-guest root"), "no cap: any old cap removed");
    }

    #[test]
    fn a_missing_port_is_an_error_not_a_silent_skip() {
        let c = cfg(&[("enabled", "1"), ("vlan_id", "0"), ("ports", "nope0")]);
        assert!(apply_kernel(&Rec::default(), &c, None, None).is_err());
        let c = cfg(&[("enabled", "1")]);
        assert!(apply_kernel(&Rec::default(), &c, Some("a-very-long-trunk0"), None).is_err(), "VLAN name over 15 chars");
    }

    #[test]
    fn teardown_removes_table_vlan_and_bridge() {
        let h = Rec::default();
        h.devs.lock().unwrap().push("br-guest".into());
        *h.members.lock().unwrap() = r#"[{"ifname":"eth1.30","linkinfo":{"info_kind":"vlan"}},{"ifname":"gst-a","linkinfo":{}}]"#.into();
        let said = teardown_kernel(&h, "br-guest");
        let cmds = h.cmds.lock().unwrap().join("\n");
        assert!(cmds.contains("nft delete table inet patronus_guest"));
        assert!(cmds.contains("ip link del eth1.30") && cmds.contains("ip link set gst-a nomaster") && cmds.contains("ip link del br-guest"));
        assert!(said[0].contains("removed"));
    }

    // ---- the page + store

    #[tokio::test]
    async fn settings_are_validated_as_a_whole_and_audited() {
        let store = ConfigStore::open_in_memory().await.unwrap();
        GuestSvc.put(&store, &json!({"enabled": false, "vlan_id": 40, "address": "10.40.0.1/24"})).await.unwrap();
        let v = GuestSvc.get(&store).await.unwrap();
        assert_eq!(v["settings"]["vlan_id"], json!(40));
        assert_eq!(v["settings"]["bridge"], json!("br-guest"), "default shown");
        // a range that no longer fits the new subnet is refused as a whole, nothing half-saved
        let err = GuestSvc.put(&store, &json!({"address": "10.41.0.1/24", "dhcp_start": "10.40.0.50"})).await.unwrap_err();
        assert!(err.to_string().contains("Invalid"), "{err}");
        let v = GuestSvc.get(&store).await.unwrap();
        assert_eq!(v["settings"]["address"], json!("10.40.0.1/24"));
        // the password is stored but never returned
        GuestSvc.put(&store, &json!({"wifi": true, "wifi_psk": "sharedpass1"})).await.unwrap();
        let v = GuestSvc.get(&store).await.unwrap();
        assert_eq!(v["settings"]["wifi_psk"], json!("********"));
        GuestSvc.put(&store, &json!({"ssid": "Visitors", "wifi_psk": "********"})).await.unwrap();
        let raw = svc::raw_settings(&store, &SPEC).await.unwrap();
        assert_eq!(raw["wifi_psk"], json!("sharedpass1"), "mask keeps the stored secret");
        let n: i64 = sqlx::query_scalar("SELECT count(*) FROM audit_log WHERE action = 'guest_settings'")
            .fetch_one(store.pool().unwrap())
            .await
            .unwrap();
        assert!(n >= 3, "every change is in the audit log");
    }

    #[tokio::test]
    async fn actions_open_close_vouchers_and_password() {
        let store = ConfigStore::open_in_memory().await.unwrap();
        let r = GuestSvc.action(&store, "open", &json!({"minutes": 90})).await.unwrap();
        let until = r["open_until"].as_i64().unwrap();
        assert!(until > now() + 89 * 60 && until <= now() + 90 * 60 + 2);
        let raw = svc::raw_settings(&store, &SPEC).await.unwrap();
        assert_eq!(raw["access"], json!("timed"));
        assert_eq!(raw["open_until"], json!(until.to_string()));
        assert!(GuestSvc.action(&store, "open", &json!({"minutes": 0})).await.is_err());
        GuestSvc.action(&store, "close", &Value::Null).await.unwrap();
        assert_eq!(svc::raw_settings(&store, &SPEC).await.unwrap()["open_until"], json!("0"));
        let r = GuestSvc.action(&store, "voucher", &json!({"name": "friday", "minutes": 30})).await.unwrap();
        let code = r["wifi_password"].as_str().unwrap().to_string();
        assert_eq!(code.len(), 12);
        let vs = vouchers(&store).await.unwrap();
        assert_eq!((vs[0].name.as_str(), vs[0].minutes, vs[0].code.as_str()), ("friday", 30, code.as_str()));
        assert!(vs[0].active(now()));
        // the list never shows the code
        let g = GuestSvc.get(&store).await.unwrap();
        assert_eq!(g["collections"]["vouchers"][0]["code"], json!("********"));
        let p = GuestSvc.action(&store, "new_password", &Value::Null).await.unwrap();
        assert_eq!(p["wifi_password"].as_str().unwrap().len(), 16);
        assert!(GuestSvc.action(&store, "nope", &Value::Null).await.is_err());
        let ids = active_voucher_ids(&store, now()).await.unwrap();
        assert_eq!(ids, vec![vs[0].id]);
        assert!(active_voucher_ids(&store, now() + 31 * 60).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn off_means_no_kernel_state_and_on_loads_the_table() {
        let store = ConfigStore::open_in_memory().await.unwrap();
        store.set_interface_role("eth0", Some("wan")).await.unwrap();
        store.set_interface_role("eth1", Some("lan")).await.unwrap();
        let dir = tempfile::tempdir().unwrap();
        let ap = GuestApplier::with_supervisor(Supervisor {
            mode: crate::supervise::InitMode::Direct,
            paths: crate::supervise::NetPaths::under(dir.path()),
        });
        let h = Rec::default();
        let rep = ap.apply_with(&store, &h).await.unwrap();
        assert!(rep.applied.iter().any(|l| l.contains("guest network is off")));
        assert!(h.nft.lock().unwrap().is_empty());
    }
}
