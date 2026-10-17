//! Lane C store model: interface roles + addressing, VLANs (802.1Q and
//! QinQ), bonds, bridges and PPPoE links, read from / written to the
//! config store (`interfaces`, `interface_addresses`, `vlans`, `l2_*`,
//! `pppoe_links`; migration `0200_c_interfaces.sql`).
//!
//! [`NetConfig::load`] gives the whole desired state; [`NetConfig::validate`]
//! rejects inconsistent configurations ("Invalid ..." -> HTTP 400) before
//! anything is written or applied. The interfaces applier
//! ([`crate::interfaces::InterfacesApplier`]) turns it into kernel state.

use ipnetwork::IpNetwork;
use patronus_config::store::{is_valid_role, ConfigStore};
use patronus_core::{Error, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::Row;
use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

fn db<E: std::fmt::Display>(what: &'static str) -> impl FnOnce(E) -> Error {
    move |e| Error::Config(format!("{what}: {e}"))
}

fn invalid(msg: impl std::fmt::Display) -> Error {
    Error::Config(format!("Invalid {msg}"))
}

/// IPv4 configuration of an interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum V4Mode {
    /// Patronus does not touch IPv4 on this interface (role-only rows).
    #[default]
    Unmanaged,
    /// No IPv4 address (bond/bridge member, L2-only).
    None,
    Static,
    /// DHCP client (dhcpcd or busybox udhcpc).
    Dhcp,
}

impl V4Mode {
    pub fn as_str(&self) -> &'static str {
        match self {
            V4Mode::Unmanaged => "unmanaged",
            V4Mode::None => "none",
            V4Mode::Static => "static",
            V4Mode::Dhcp => "dhcp",
        }
    }
    pub fn parse(s: &str) -> Result<Self> {
        Ok(match s.trim().to_ascii_lowercase().as_str() {
            "" | "unmanaged" => V4Mode::Unmanaged,
            "none" => V4Mode::None,
            "static" => V4Mode::Static,
            "dhcp" => V4Mode::Dhcp,
            o => return Err(invalid(format!("IPv4 mode {o:?} (none, static, dhcp)"))),
        })
    }
}

/// IPv6 configuration of an interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum V6Mode {
    #[default]
    Unmanaged,
    /// IPv6 off: no global addresses, router advertisements ignored.
    None,
    Static,
    /// Addresses + default route from router advertisements.
    Slaac,
    /// DHCPv6 (dhcpcd).
    Dhcp6,
}

impl V6Mode {
    pub fn as_str(&self) -> &'static str {
        match self {
            V6Mode::Unmanaged => "unmanaged",
            V6Mode::None => "none",
            V6Mode::Static => "static",
            V6Mode::Slaac => "slaac",
            V6Mode::Dhcp6 => "dhcp6",
        }
    }
    pub fn parse(s: &str) -> Result<Self> {
        Ok(match s.trim().to_ascii_lowercase().as_str() {
            "" | "unmanaged" => V6Mode::Unmanaged,
            "none" => V6Mode::None,
            "static" => V6Mode::Static,
            "slaac" => V6Mode::Slaac,
            "dhcp6" | "dhcpv6" => V6Mode::Dhcp6,
            o => {
                return Err(invalid(format!(
                    "IPv6 mode {o:?} (none, static, slaac, dhcp6)"
                )))
            }
        })
    }
}

/// One interface's configuration (a row of `interfaces` + its addresses).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct IfaceConfig {
    pub name: String,
    /// `wan`, `lan`, `optN` (lane A column; resolved by the firewall).
    pub role: Option<String>,
    pub enabled: bool,
    pub ipv4_mode: V4Mode,
    pub ipv4: Vec<IpNetwork>,
    pub gateway4: Option<IpAddr>,
    pub ipv6_mode: V6Mode,
    pub ipv6: Vec<IpNetwork>,
    pub gateway6: Option<IpAddr>,
    pub mtu: Option<u32>,
    pub mac: Option<String>,
    pub description: Option<String>,
}

impl IfaceConfig {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            enabled: true,
            ..Default::default()
        }
    }

    /// True if Patronus manages anything on this interface beyond its role.
    pub fn is_managed(&self) -> bool {
        !self.enabled
            || self.ipv4_mode != V4Mode::Unmanaged
            || self.ipv6_mode != V6Mode::Unmanaged
            || self.mtu.is_some()
            || self.mac.is_some()
    }
}

/// 802.1Q VLAN, or an 802.1ad (QinQ outer) service VLAN.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VlanConfig {
    pub name: String,
    pub parent: String,
    pub vlan_id: u16,
    /// `802.1q` or `802.1ad`.
    pub protocol: String,
    pub enabled: bool,
    pub description: Option<String>,
}

/// Linux bond (LAGG).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BondConfig {
    pub name: String,
    pub mode: String,
    pub miimon: u32,
    pub lacp_rate: Option<String>,
    pub xmit_hash_policy: Option<String>,
    pub primary: Option<String>,
    pub members: Vec<String>,
    pub enabled: bool,
    pub description: Option<String>,
}

/// Linux bridge.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BridgeConfig {
    pub name: String,
    pub stp: bool,
    pub members: Vec<String>,
    pub enabled: bool,
    pub description: Option<String>,
}

/// PPPoE client link (pppd + the kernel PPPoE plugin).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PppoeConfig {
    pub name: String,
    pub parent: String,
    pub username: String,
    /// Never serialized back to API clients (see `redacted`).
    pub password: String,
    pub service_name: Option<String>,
    pub mtu: u32,
    pub default_route: bool,
    pub use_peer_dns: bool,
    pub ipv6: bool,
    pub enabled: bool,
    pub description: Option<String>,
}

impl PppoeConfig {
    /// Copy without the password (for API responses / logs).
    pub fn redacted(&self) -> Self {
        Self {
            password: String::new(),
            ..self.clone()
        }
    }
}

pub const BOND_MODES: &[&str] = &[
    "active-backup",
    "802.3ad",
    "balance-rr",
    "balance-xor",
    "broadcast",
    "balance-tlb",
    "balance-alb",
];
pub const XMIT_HASH_POLICIES: &[&str] = &[
    "layer2",
    "layer2+3",
    "layer3+4",
    "encap2+3",
    "encap3+4",
    "vlan+srcmac",
];

/// Kernel interface name rules (IFNAMSIZ 16 incl. NUL; no '/', ':' or
/// whitespace; not "." / "..").
pub fn is_valid_ifname(n: &str) -> bool {
    !n.is_empty()
        && n.len() <= 15
        && n != "."
        && n != ".."
        && n.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.' | b'@'))
        && !n.starts_with('-')
}

/// Unicast, non-zero `aa:bb:cc:dd:ee:ff`.
pub fn normalize_mac(m: &str) -> Result<String> {
    let m = m.trim().to_ascii_lowercase().replace('-', ":");
    let parts: Vec<&str> = m.split(':').collect();
    let ok = parts.len() == 6
        && parts
            .iter()
            .all(|p| p.len() == 2 && p.bytes().all(|b| b.is_ascii_hexdigit()));
    if !ok {
        return Err(invalid(format!("MAC address {m:?}")));
    }
    let first = u8::from_str_radix(parts[0], 16).unwrap_or(1);
    if first & 1 == 1 || m == "00:00:00:00:00:00" {
        return Err(invalid(format!(
            "MAC address {m:?} (must be a unicast, non-zero address)"
        )));
    }
    Ok(m)
}

/// The whole lane C desired state.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct NetConfig {
    pub interfaces: Vec<IfaceConfig>,
    pub vlans: Vec<VlanConfig>,
    pub bonds: Vec<BondConfig>,
    pub bridges: Vec<BridgeConfig>,
    pub pppoe: Vec<PppoeConfig>,
}

/// Tables lane C owns (plus `interfaces.role`, restored with its row).
pub const TABLES: &[&str] = &[
    "interfaces",
    "interface_addresses",
    "vlans",
    "l2_bonds",
    "l2_bond_members",
    "l2_bridges",
    "l2_bridge_members",
    "pppoe_links",
];

impl NetConfig {
    pub fn iface(&self, name: &str) -> Option<&IfaceConfig> {
        self.interfaces.iter().find(|i| i.name == name)
    }

    pub fn iface_mut(&mut self, name: &str) -> &mut IfaceConfig {
        if let Some(i) = self.interfaces.iter().position(|i| i.name == name) {
            return &mut self.interfaces[i];
        }
        self.interfaces.push(IfaceConfig::new(name));
        self.interfaces.last_mut().unwrap()
    }

    /// Names of the virtual devices Patronus creates.
    pub fn virtual_names(&self) -> BTreeSet<String> {
        let mut s = BTreeSet::new();
        s.extend(self.vlans.iter().map(|v| v.name.clone()));
        s.extend(self.bonds.iter().map(|b| b.name.clone()));
        s.extend(self.bridges.iter().map(|b| b.name.clone()));
        s.extend(self.pppoe.iter().map(|p| p.name.clone()));
        s
    }

    /// Which bond/bridge a device is enslaved to, if any.
    pub fn master_of(&self, dev: &str) -> Option<&str> {
        self.bonds
            .iter()
            .filter(|b| b.enabled)
            .find(|b| b.members.iter().any(|m| m == dev))
            .map(|b| b.name.as_str())
            .or_else(|| {
                self.bridges
                    .iter()
                    .filter(|b| b.enabled)
                    .find(|b| b.members.iter().any(|m| m == dev))
                    .map(|b| b.name.as_str())
            })
    }

    /// Everything that depends on `dev` (VLANs on it, bond/bridge it is a
    /// member of, PPPoE over it), for refusing deletes.
    pub fn users_of(&self, dev: &str) -> Vec<String> {
        let mut v = Vec::new();
        for x in &self.vlans {
            if x.parent == dev {
                v.push(format!("VLAN {}", x.name));
            }
        }
        for b in &self.bonds {
            if b.members.iter().any(|m| m == dev) {
                v.push(format!("bond {}", b.name));
            }
        }
        for b in &self.bridges {
            if b.members.iter().any(|m| m == dev) {
                v.push(format!("bridge {}", b.name));
            }
        }
        for p in &self.pppoe {
            if p.parent == dev {
                v.push(format!("PPPoE {}", p.name));
            }
        }
        v
    }

    /// Check the whole configuration. `existing` = devices present in the
    /// kernel now (physical NICs); virtual devices may refer to each other.
    pub fn validate(&self, existing: &[String]) -> Result<()> {
        let virt = self.virtual_names();
        let mut seen = BTreeSet::new();
        let mut names: Vec<&str> = Vec::new();
        names.extend(self.vlans.iter().map(|v| v.name.as_str()));
        names.extend(self.bonds.iter().map(|v| v.name.as_str()));
        names.extend(self.bridges.iter().map(|v| v.name.as_str()));
        names.extend(self.pppoe.iter().map(|v| v.name.as_str()));
        for n in names {
            if !is_valid_ifname(n) {
                return Err(invalid(format!("interface name {n:?}")));
            }
            if !seen.insert(n) {
                return Err(invalid(format!(
                    "configuration: two virtual interfaces are named {n:?}"
                )));
            }
            // A same-named kernel device is fine when a previous apply
            // created it; the applier refuses to take over foreign devices.
        }
        let known = |d: &str| virt.contains(d) || existing.iter().any(|e| e == d);

        let mut vids = BTreeSet::new();
        for v in &self.vlans {
            if !(1..=4094).contains(&v.vlan_id) {
                return Err(invalid(format!(
                    "VLAN id {} on {} (1-4094)",
                    v.vlan_id, v.name
                )));
            }
            if v.protocol != "802.1q" && v.protocol != "802.1ad" {
                return Err(invalid(format!(
                    "VLAN protocol {:?} (802.1q or 802.1ad)",
                    v.protocol
                )));
            }
            if !is_valid_ifname(&v.parent) || !known(&v.parent) {
                return Err(invalid(format!(
                    "VLAN {}: parent interface {:?} does not exist",
                    v.name, v.parent
                )));
            }
            if v.parent == v.name {
                return Err(invalid(format!("VLAN {}: parent is itself", v.name)));
            }
            if !vids.insert((v.parent.clone(), v.vlan_id, v.protocol.clone())) {
                return Err(invalid(format!(
                    "VLAN {}: {} id {} already exists on {}",
                    v.name, v.protocol, v.vlan_id, v.parent
                )));
            }
        }
        // parent chains must terminate (no VLAN loops)
        for v in &self.vlans {
            let mut cur = v.parent.clone();
            for _ in 0..8 {
                match self.vlans.iter().find(|x| x.name == cur) {
                    Some(p) => cur = p.parent.clone(),
                    None => break,
                }
                if cur == v.name {
                    return Err(invalid(format!("VLAN {}: parent loop", v.name)));
                }
            }
        }

        let mut member_of: BTreeMap<String, String> = BTreeMap::new();
        for b in &self.bonds {
            if !BOND_MODES.contains(&b.mode.as_str()) {
                return Err(invalid(format!(
                    "bond mode {:?} ({})",
                    b.mode,
                    BOND_MODES.join(", ")
                )));
            }
            if b.miimon > 10_000 {
                return Err(invalid(format!("bond miimon {} (0-10000 ms)", b.miimon)));
            }
            if let Some(r) = &b.lacp_rate {
                if r != "slow" && r != "fast" {
                    return Err(invalid(format!("LACP rate {r:?} (slow or fast)")));
                }
            }
            if let Some(h) = &b.xmit_hash_policy {
                if !XMIT_HASH_POLICIES.contains(&h.as_str()) {
                    return Err(invalid(format!("transmit hash policy {h:?}")));
                }
            }
            if let Some(p) = &b.primary {
                if !b.members.contains(p) {
                    return Err(invalid(format!(
                        "bond {}: primary {p:?} is not a member",
                        b.name
                    )));
                }
            }
            for m in &b.members {
                if !is_valid_ifname(m) || !existing.iter().any(|e| e == m) {
                    return Err(invalid(format!(
                        "bond {}: member {m:?} is not an existing network port",
                        b.name
                    )));
                }
                if virt.contains(m) {
                    return Err(invalid(format!(
                        "bond {}: member {m:?} is a virtual interface",
                        b.name
                    )));
                }
                if let Some(o) = member_of.insert(m.clone(), b.name.clone()) {
                    return Err(invalid(format!("{m} is already a member of {o}")));
                }
            }
        }
        for b in &self.bridges {
            for m in &b.members {
                if !is_valid_ifname(m) || !known(m) {
                    return Err(invalid(format!(
                        "bridge {}: member {m:?} does not exist",
                        b.name
                    )));
                }
                if m == &b.name || self.bridges.iter().any(|x| &x.name == m) {
                    return Err(invalid(format!(
                        "bridge {}: member {m:?} is a bridge",
                        b.name
                    )));
                }
                if self.pppoe.iter().any(|p| &p.name == m) {
                    return Err(invalid(format!(
                        "bridge {}: member {m:?} is a PPPoE link",
                        b.name
                    )));
                }
                if let Some(o) = member_of.insert(m.clone(), b.name.clone()) {
                    return Err(invalid(format!("{m} is already a member of {o}")));
                }
            }
        }
        for v in &self.vlans {
            if let Some(m) = member_of.get(&v.parent) {
                if self.bonds.iter().any(|b| &b.name == m) {
                    return Err(invalid(format!(
                        "VLAN {}: parent {} is a bond member; put the VLAN on {m}",
                        v.name, v.parent
                    )));
                }
            }
        }
        for p in &self.pppoe {
            if !is_valid_ifname(&p.parent) || !known(&p.parent) {
                return Err(invalid(format!(
                    "PPPoE {}: parent interface {:?} does not exist",
                    p.name, p.parent
                )));
            }
            if member_of.contains_key(&p.parent) {
                return Err(invalid(format!(
                    "PPPoE {}: parent {} is a bond/bridge member",
                    p.name, p.parent
                )));
            }
            if p.username.trim().is_empty() {
                return Err(invalid(format!("PPPoE {}: username is required", p.name)));
            }
            for (what, s) in [("username", &p.username), ("password", &p.password)] {
                if s.contains('\n') || s.contains('\r') || s.contains('\0') {
                    return Err(invalid(format!(
                        "PPPoE {}: {what} contains a newline",
                        p.name
                    )));
                }
            }
            if let Some(s) = &p.service_name {
                if s.contains(['\n', '\r', '"', '\\', '\0']) {
                    return Err(invalid(format!("PPPoE {}: service name", p.name)));
                }
            }
            if !(576..=1500).contains(&p.mtu) {
                return Err(invalid(format!(
                    "PPPoE {}: MTU {} (576-1500)",
                    p.name, p.mtu
                )));
            }
        }

        for i in &self.interfaces {
            if !is_valid_ifname(&i.name) {
                return Err(invalid(format!("interface name {:?}", i.name)));
            }
            if let Some(r) = &i.role {
                if !is_valid_role(r) {
                    return Err(invalid(format!(
                        "interface role {r:?} (wan, lan or opt<N>)"
                    )));
                }
                // Several interfaces may share a role (patronus.toml's
                // `wan_interfaces = [...]`); the firewall renders one rule
                // per device.
                let _ = r;
            }
            if let Some(m) = member_of.get(&i.name) {
                let addressed = matches!(i.ipv4_mode, V4Mode::Static | V4Mode::Dhcp)
                    || matches!(i.ipv6_mode, V6Mode::Static | V6Mode::Slaac | V6Mode::Dhcp6);
                if addressed || i.role.is_some() {
                    return Err(invalid(format!(
                        "{} is a member of {m}: configure addresses and roles on {m} instead",
                        i.name
                    )));
                }
            }
            let is_ppp = self.pppoe.iter().any(|p| p.name == i.name);
            if is_ppp && !matches!(i.ipv4_mode, V4Mode::Unmanaged | V4Mode::None) {
                return Err(invalid(format!(
                    "{}: a PPPoE link gets its IPv4 address from the provider",
                    i.name
                )));
            }
            match i.ipv4_mode {
                V4Mode::Static if i.ipv4.is_empty() => {
                    return Err(invalid(format!(
                        "{}: static IPv4 needs at least one address",
                        i.name
                    )))
                }
                _ => {}
            }
            for a in &i.ipv4 {
                if !a.is_ipv4() || a.prefix() == 0 || a.ip().is_unspecified() {
                    return Err(invalid(format!("IPv4 address {a} on {}", i.name)));
                }
            }
            if i.ipv4_mode != V4Mode::Static && !i.ipv4.is_empty() {
                return Err(invalid(format!(
                    "{}: IPv4 addresses are only used in static mode",
                    i.name
                )));
            }
            if let Some(g) = i.gateway4 {
                if !g.is_ipv4() || i.ipv4_mode != V4Mode::Static {
                    return Err(invalid(format!(
                        "IPv4 gateway {g} on {} (static IPv4 only)",
                        i.name
                    )));
                }
                if !i.ipv4.iter().any(|n| n.contains(g)) {
                    return Err(invalid(format!(
                        "IPv4 gateway {g} is not inside any address on {}",
                        i.name
                    )));
                }
            }
            if i.ipv6_mode == V6Mode::Static && i.ipv6.is_empty() {
                return Err(invalid(format!(
                    "{}: static IPv6 needs at least one address",
                    i.name
                )));
            }
            for a in &i.ipv6 {
                let link_local =
                    matches!(a.ip(), IpAddr::V6(v) if (v.segments()[0] & 0xffc0) == 0xfe80);
                if !a.is_ipv6() || a.prefix() == 0 || a.ip().is_unspecified() || link_local {
                    return Err(invalid(format!(
                        "IPv6 address {a} on {} (global or ULA)",
                        i.name
                    )));
                }
            }
            if i.ipv6_mode != V6Mode::Static && !i.ipv6.is_empty() {
                return Err(invalid(format!(
                    "{}: IPv6 addresses are only used in static mode",
                    i.name
                )));
            }
            if let Some(g) = i.gateway6 {
                if !g.is_ipv6() || i.ipv6_mode != V6Mode::Static {
                    return Err(invalid(format!(
                        "IPv6 gateway {g} on {} (static IPv6 only)",
                        i.name
                    )));
                }
            }
            if let Some(m) = i.mtu {
                if !(68..=65535).contains(&m) {
                    return Err(invalid(format!("MTU {m} on {} (68-65535)", i.name)));
                }
            }
            if let Some(m) = &i.mac {
                normalize_mac(m)?;
            }
        }
        Ok(())
    }

    // ------------------------------------------------------------------
    // store I/O
    // ------------------------------------------------------------------

    /// Read the whole lane C configuration from the store.
    pub async fn load(store: &ConfigStore) -> Result<Self> {
        let pool = store.pool()?;
        let mut cfg = NetConfig::default();
        let rows = sqlx::query(
            "SELECT name, role, enabled, ipv4_mode, ipv6_mode, gateway4, gateway6, mtu, mac,
                    description, dhcp
             FROM interfaces ORDER BY name",
        )
        .fetch_all(pool)
        .await
        .map_err(db("load interfaces"))?;
        for r in rows {
            let name: String = r.get(0);
            let mut i = IfaceConfig::new(&name);
            i.role = r.get(1);
            i.enabled = r.get::<i64, _>(2) != 0;
            i.ipv4_mode = V4Mode::parse(&r.get::<String, _>(3))?;
            // legacy `dhcp` flag (pre-lane-C rows / GitOps)
            if i.ipv4_mode == V4Mode::Unmanaged && r.get::<i64, _>(10) != 0 {
                i.ipv4_mode = V4Mode::Dhcp;
            }
            i.ipv6_mode = V6Mode::parse(&r.get::<String, _>(4))?;
            i.gateway4 = parse_opt_ip(r.get(5))?;
            i.gateway6 = parse_opt_ip(r.get(6))?;
            i.mtu = r.get::<Option<i64>, _>(7).map(|m| m as u32);
            i.mac = r.get(8);
            i.description = r.get(9);
            cfg.interfaces.push(i);
        }
        let addrs = sqlx::query(
            "SELECT interface_name, address, prefix_len, family FROM interface_addresses
             ORDER BY id",
        )
        .fetch_all(pool)
        .await
        .map_err(db("load interface addresses"))?;
        for r in addrs {
            let name: String = r.get(0);
            let a: String = r.get(1);
            let p: i64 = r.get(2);
            let net: IpNetwork = format!("{a}/{p}")
                .parse()
                .map_err(|_| Error::Config(format!("bad stored address {a}/{p} on {name}")))?;
            let i = cfg.iface_mut(&name);
            if net.is_ipv4() {
                i.ipv4.push(net)
            } else {
                i.ipv6.push(net)
            }
        }
        for r in sqlx::query(
            "SELECT name, parent_interface, vlan_id, protocol, enabled, description
             FROM vlans ORDER BY name",
        )
        .fetch_all(pool)
        .await
        .map_err(db("load vlans"))?
        {
            cfg.vlans.push(VlanConfig {
                name: r.get(0),
                parent: r.get(1),
                vlan_id: r.get::<i64, _>(2) as u16,
                protocol: r.get(3),
                enabled: r.get::<i64, _>(4) != 0,
                description: r.get(5),
            });
        }
        let members = |table: &'static str, col: &'static str| {
            let pool = pool.clone();
            async move {
                let q = format!("SELECT member, {col} FROM {table} ORDER BY rowid");
                sqlx::query(&q)
                    .fetch_all(&pool)
                    .await
                    .map(|rows| {
                        rows.iter()
                            .map(|r| (r.get::<String, _>(0), r.get::<String, _>(1)))
                            .collect::<Vec<_>>()
                    })
                    .map_err(db("load members"))
            }
        };
        let bm = members("l2_bond_members", "bond").await?;
        for r in sqlx::query(
            "SELECT name, mode, miimon, lacp_rate, xmit_hash_policy, primary_member, enabled,
                    description FROM l2_bonds ORDER BY name",
        )
        .fetch_all(pool)
        .await
        .map_err(db("load bonds"))?
        {
            let name: String = r.get(0);
            cfg.bonds.push(BondConfig {
                members: bm
                    .iter()
                    .filter(|(_, b)| *b == name)
                    .map(|(m, _)| m.clone())
                    .collect(),
                name,
                mode: r.get(1),
                miimon: r.get::<i64, _>(2) as u32,
                lacp_rate: r.get(3),
                xmit_hash_policy: r.get(4),
                primary: r.get(5),
                enabled: r.get::<i64, _>(6) != 0,
                description: r.get(7),
            });
        }
        let brm = members("l2_bridge_members", "bridge").await?;
        for r in sqlx::query("SELECT name, stp, enabled, description FROM l2_bridges ORDER BY name")
            .fetch_all(pool)
            .await
            .map_err(db("load bridges"))?
        {
            let name: String = r.get(0);
            cfg.bridges.push(BridgeConfig {
                members: brm
                    .iter()
                    .filter(|(_, b)| *b == name)
                    .map(|(m, _)| m.clone())
                    .collect(),
                name,
                stp: r.get::<i64, _>(1) != 0,
                enabled: r.get::<i64, _>(2) != 0,
                description: r.get(3),
            });
        }
        for r in sqlx::query(
            "SELECT name, parent_interface, username, password, service_name, mtu,
                    default_route, use_peer_dns, ipv6, enabled, description
             FROM pppoe_links ORDER BY name",
        )
        .fetch_all(pool)
        .await
        .map_err(db("load pppoe links"))?
        {
            cfg.pppoe.push(PppoeConfig {
                name: r.get(0),
                parent: r.get(1),
                username: r.get(2),
                password: r.get(3),
                service_name: r.get(4),
                mtu: r.get::<i64, _>(5) as u32,
                default_route: r.get::<i64, _>(6) != 0,
                use_peer_dns: r.get::<i64, _>(7) != 0,
                ipv6: r.get::<i64, _>(8) != 0,
                enabled: r.get::<i64, _>(9) != 0,
                description: r.get(10),
            });
        }
        Ok(cfg)
    }

    /// Replace every lane C table with this configuration, atomically.
    /// Interface rows keep columns other lanes may add later.
    pub async fn save(&self, store: &ConfigStore) -> Result<()> {
        let now = chrono::Utc::now().timestamp();
        let mut tx = store.pool()?.begin().await.map_err(db("begin"))?;
        for t in [
            "interface_addresses",
            "l2_bond_members",
            "l2_bonds",
            "l2_bridge_members",
            "l2_bridges",
            "vlans",
            "pppoe_links",
        ] {
            sqlx::query(&format!("DELETE FROM {t}"))
                .execute(&mut *tx)
                .await
                .map_err(db("clear table"))?;
        }
        let keep: Vec<&str> = self.interfaces.iter().map(|i| i.name.as_str()).collect();
        let existing: Vec<String> = sqlx::query("SELECT name FROM interfaces")
            .fetch_all(&mut *tx)
            .await
            .map_err(db("list interfaces"))?
            .iter()
            .map(|r| r.get(0))
            .collect();
        for e in existing {
            if !keep.contains(&e.as_str()) {
                sqlx::query("DELETE FROM interfaces WHERE name = ?")
                    .bind(&e)
                    .execute(&mut *tx)
                    .await
                    .map_err(db("delete interface"))?;
            }
        }
        for i in &self.interfaces {
            sqlx::query(
                "INSERT INTO interfaces (name, role, enabled, dhcp, ipv4_mode, ipv6_mode,
                     gateway4, gateway6, mtu, mac, description, updated_at)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                 ON CONFLICT(name) DO UPDATE SET role = excluded.role,
                     enabled = excluded.enabled, dhcp = excluded.dhcp,
                     ipv4_mode = excluded.ipv4_mode, ipv6_mode = excluded.ipv6_mode,
                     gateway4 = excluded.gateway4, gateway6 = excluded.gateway6,
                     mtu = excluded.mtu, mac = excluded.mac,
                     description = excluded.description, updated_at = excluded.updated_at",
            )
            .bind(&i.name)
            .bind(&i.role)
            .bind(i.enabled as i64)
            .bind((i.ipv4_mode == V4Mode::Dhcp) as i64)
            .bind(i.ipv4_mode.as_str())
            .bind(i.ipv6_mode.as_str())
            .bind(i.gateway4.map(|g| g.to_string()))
            .bind(i.gateway6.map(|g| g.to_string()))
            .bind(i.mtu.map(|m| m as i64))
            .bind(&i.mac)
            .bind(&i.description)
            .bind(now)
            .execute(&mut *tx)
            .await
            .map_err(db("save interface"))?;
            for a in i.ipv4.iter().chain(i.ipv6.iter()) {
                sqlx::query(
                    "INSERT INTO interface_addresses (interface_name, address, prefix_len, family)
                     VALUES (?, ?, ?, ?)",
                )
                .bind(&i.name)
                .bind(a.ip().to_string())
                .bind(a.prefix() as i64)
                .bind(if a.is_ipv4() { "ipv4" } else { "ipv6" })
                .execute(&mut *tx)
                .await
                .map_err(db("save address"))?;
            }
        }
        for v in &self.vlans {
            sqlx::query(
                "INSERT INTO vlans (name, parent_interface, vlan_id, protocol, enabled,
                     description, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            )
            .bind(&v.name)
            .bind(&v.parent)
            .bind(v.vlan_id as i64)
            .bind(&v.protocol)
            .bind(v.enabled as i64)
            .bind(&v.description)
            .bind(now)
            .bind(now)
            .execute(&mut *tx)
            .await
            .map_err(db("save vlan"))?;
        }
        for b in &self.bonds {
            sqlx::query(
                "INSERT INTO l2_bonds (name, mode, miimon, lacp_rate, xmit_hash_policy,
                     primary_member, enabled, description, updated_at)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            )
            .bind(&b.name)
            .bind(&b.mode)
            .bind(b.miimon as i64)
            .bind(&b.lacp_rate)
            .bind(&b.xmit_hash_policy)
            .bind(&b.primary)
            .bind(b.enabled as i64)
            .bind(&b.description)
            .bind(now)
            .execute(&mut *tx)
            .await
            .map_err(db("save bond"))?;
            for m in &b.members {
                sqlx::query("INSERT INTO l2_bond_members (member, bond) VALUES (?, ?)")
                    .bind(m)
                    .bind(&b.name)
                    .execute(&mut *tx)
                    .await
                    .map_err(db("save bond member"))?;
            }
        }
        for b in &self.bridges {
            sqlx::query(
                "INSERT INTO l2_bridges (name, stp, enabled, description, updated_at)
                 VALUES (?, ?, ?, ?, ?)",
            )
            .bind(&b.name)
            .bind(b.stp as i64)
            .bind(b.enabled as i64)
            .bind(&b.description)
            .bind(now)
            .execute(&mut *tx)
            .await
            .map_err(db("save bridge"))?;
            for m in &b.members {
                sqlx::query("INSERT INTO l2_bridge_members (member, bridge) VALUES (?, ?)")
                    .bind(m)
                    .bind(&b.name)
                    .execute(&mut *tx)
                    .await
                    .map_err(db("save bridge member"))?;
            }
        }
        for p in &self.pppoe {
            sqlx::query(
                "INSERT INTO pppoe_links (name, parent_interface, username, password,
                     service_name, mtu, default_route, use_peer_dns, ipv6, enabled,
                     description, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            )
            .bind(&p.name)
            .bind(&p.parent)
            .bind(&p.username)
            .bind(&p.password)
            .bind(&p.service_name)
            .bind(p.mtu as i64)
            .bind(p.default_route as i64)
            .bind(p.use_peer_dns as i64)
            .bind(p.ipv6 as i64)
            .bind(p.enabled as i64)
            .bind(&p.description)
            .bind(now)
            .execute(&mut *tx)
            .await
            .map_err(db("save pppoe link"))?;
        }
        tx.commit().await.map_err(db("commit"))?;
        Ok(())
    }
}

fn parse_opt_ip(s: Option<String>) -> Result<Option<IpAddr>> {
    match s {
        None => Ok(None),
        Some(s) if s.trim().is_empty() => Ok(None),
        Some(s) => s
            .parse()
            .map(Some)
            .map_err(|_| Error::Config(format!("bad stored gateway {s:?}"))),
    }
}

/// Raw copy of lane C's tables, for undoing a failed change without
/// touching other lanes' tables (unlike `ConfigStore::import_json`).
pub async fn snapshot_tables(store: &ConfigStore) -> Result<Value> {
    let full = store.export_json().await?;
    let mut out = serde_json::Map::new();
    if let Some(t) = full.get("tables").and_then(|t| t.as_object()) {
        for name in TABLES {
            if let Some(rows) = t.get(*name) {
                out.insert(name.to_string(), rows.clone());
            }
        }
    }
    Ok(Value::Object(out))
}

/// Restore what [`snapshot_tables`] captured.
pub async fn restore_tables(store: &ConfigStore, snap: &Value) -> Result<()> {
    let tables = snap
        .as_object()
        .ok_or_else(|| Error::Config("bad lane C snapshot".into()))?;
    let mut tx = store.pool()?.begin().await.map_err(db("begin restore"))?;
    sqlx::query("PRAGMA defer_foreign_keys = ON")
        .execute(&mut *tx)
        .await
        .map_err(db("defer fks"))?;
    for t in TABLES.iter().rev() {
        sqlx::query(&format!("DELETE FROM \"{t}\""))
            .execute(&mut *tx)
            .await
            .map_err(db("clear table"))?;
    }
    for t in TABLES {
        let Some(rows) = tables.get(*t).and_then(|r| r.as_array()) else {
            continue;
        };
        for row in rows {
            let Some(obj) = row.as_object() else { continue };
            if obj.is_empty() {
                continue;
            }
            let cols: Vec<&String> = obj.keys().collect();
            if !cols
                .iter()
                .all(|c| c.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_'))
            {
                return Err(Error::Config("bad column in snapshot".into()));
            }
            let sql = format!(
                "INSERT INTO \"{t}\" ({}) VALUES ({})",
                cols.iter()
                    .map(|c| format!("\"{c}\""))
                    .collect::<Vec<_>>()
                    .join(", "),
                vec!["?"; cols.len()].join(", ")
            );
            let mut q = sqlx::query(&sql);
            for c in &cols {
                q = match &obj[*c] {
                    Value::Null => q.bind(None::<String>),
                    Value::Bool(b) => q.bind(*b as i64),
                    Value::Number(n) if n.is_i64() => q.bind(n.as_i64()),
                    Value::Number(n) => q.bind(n.as_f64()),
                    Value::String(s) => q.bind(s.clone()),
                    other => q.bind(other.to_string()),
                };
            }
            q.execute(&mut *tx).await.map_err(db("restore row"))?;
        }
    }
    tx.commit().await.map_err(db("commit restore"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn existing() -> Vec<String> {
        ["lo", "eth0", "eth1", "eth2", "eth3"]
            .iter()
            .map(|s| s.to_string())
            .collect()
    }

    fn sample() -> NetConfig {
        let mut c = NetConfig::default();
        let w = c.iface_mut("eth0");
        w.role = Some("wan".into());
        w.ipv4_mode = V4Mode::Dhcp;
        w.ipv6_mode = V6Mode::Slaac;
        let l = c.iface_mut("bond0");
        l.role = Some("lan".into());
        l.ipv4_mode = V4Mode::Static;
        l.ipv4 = vec!["192.168.1.1/24".parse().unwrap()];
        l.ipv6_mode = V6Mode::Static;
        l.ipv6 = vec!["fd00:1::1/64".parse().unwrap()];
        l.mtu = Some(9000);
        c.bonds.push(BondConfig {
            name: "bond0".into(),
            mode: "active-backup".into(),
            miimon: 100,
            lacp_rate: None,
            xmit_hash_policy: None,
            primary: Some("eth1".into()),
            members: vec!["eth1".into(), "eth2".into()],
            enabled: true,
            description: None,
        });
        c.vlans.push(VlanConfig {
            name: "bond0.10".into(),
            parent: "bond0".into(),
            vlan_id: 10,
            protocol: "802.1q".into(),
            enabled: true,
            description: Some("guests".into()),
        });
        c.bridges.push(BridgeConfig {
            name: "br0".into(),
            stp: true,
            members: vec!["eth3".into(), "bond0.10".into()],
            enabled: true,
            description: None,
        });
        c.pppoe.push(PppoeConfig {
            name: "pppoe0".into(),
            parent: "eth0".into(),
            username: "user@isp".into(),
            password: "s3cr\"et".into(),
            service_name: None,
            mtu: 1492,
            default_route: true,
            use_peer_dns: true,
            ipv6: false,
            enabled: true,
            description: None,
        });
        c
    }

    #[tokio::test]
    async fn round_trips_through_the_store_and_keeps_roles() {
        let s = ConfigStore::open_in_memory().await.unwrap();
        // lane A first-boot seeding writes role-only rows
        s.set_interface_role("eth9", Some("opt1")).await.unwrap();
        let mut c = NetConfig::load(&s).await.unwrap();
        assert_eq!(c.interfaces.len(), 1);
        assert!(
            !c.interfaces[0].is_managed(),
            "role-only rows are unmanaged"
        );
        let mut want = sample();
        want.interfaces.push(c.interfaces.remove(0));
        want.save(&s).await.unwrap();
        let mut back = NetConfig::load(&s).await.unwrap();
        back.interfaces.sort_by(|a, b| a.name.cmp(&b.name));
        want.interfaces.sort_by(|a, b| a.name.cmp(&b.name));
        assert_eq!(back, want);
        assert_eq!(s.interfaces_with_role("lan").await.unwrap(), vec!["bond0"]);
    }

    #[test]
    fn validation_rejects_inconsistent_configs() {
        sample().validate(&existing()).unwrap();
        let bad = |f: &dyn Fn(&mut NetConfig), needle: &str| {
            let mut c = sample();
            f(&mut c);
            let e = c.validate(&existing()).unwrap_err().to_string();
            assert!(e.contains("Invalid"), "{e}");
            assert!(e.contains(needle), "{needle:?} not in {e}");
        };
        bad(&|c| c.vlans[0].vlan_id = 4095, "VLAN id");
        bad(&|c| c.vlans[0].parent = "nope0".into(), "does not exist");
        bad(
            &|c| c.bonds[0].members.push("eth3".into()),
            "already a member",
        );
        bad(&|c| c.bonds[0].mode = "lacp".into(), "bond mode");
        bad(
            &|c| c.bonds[0].primary = Some("eth3".into()),
            "not a member",
        );
        bad(
            &|c| {
                let i = c.iface_mut("eth1");
                i.ipv4_mode = V4Mode::Static;
                i.ipv4 = vec!["10.0.0.1/24".parse().unwrap()];
            },
            "member of bond0",
        );
        bad(
            &|c| c.iface_mut("eth3").role = Some("dmz".into()),
            "interface role",
        );
        bad(
            &|c| c.iface_mut("bond0").ipv4.clear(),
            "at least one address",
        );
        bad(
            &|c| c.iface_mut("bond0").gateway4 = Some("10.9.9.9".parse().unwrap()),
            "not inside",
        );
        bad(
            &|c| c.iface_mut("bond0").mac = Some("01:00:5e:00:00:01".into()),
            "unicast",
        );
        bad(&|c| c.iface_mut("bond0").mtu = Some(10), "MTU");
        bad(&|c| c.pppoe[0].password = "a\nb".into(), "newline");
        bad(
            &|c| c.iface_mut("pppoe0").ipv4_mode = V4Mode::Static,
            "from the provider",
        );
        bad(
            &|c| {
                c.vlans.push(VlanConfig {
                    name: "x".into(),
                    parent: "eth1".into(),
                    vlan_id: 5,
                    protocol: "802.1q".into(),
                    enabled: true,
                    description: None,
                })
            },
            "bond member",
        );
        bad(
            &|c| c.vlans[0].name = "this-name-is-too-long".into(),
            "interface name",
        );
        assert_eq!(
            normalize_mac("02-AA-bb-cc-dd-ee").unwrap(),
            "02:aa:bb:cc:dd:ee"
        );
    }

    #[tokio::test]
    async fn snapshot_restore_only_touches_lane_c_tables() {
        let s = ConfigStore::open_in_memory().await.unwrap();
        let mut c = sample();
        c.pppoe.clear();
        c.save(&s).await.unwrap();
        let snap = snapshot_tables(&s).await.unwrap();
        NetConfig::default().save(&s).await.unwrap();
        s.set_sysctl(
            "net.ipv4.ip_forward",
            "1",
            patronus_config::store::RuleOrigin::User,
        )
        .await
        .unwrap();
        restore_tables(&s, &snap).await.unwrap();
        let mut back = NetConfig::load(&s).await.unwrap();
        back.interfaces.sort_by(|a, b| a.name.cmp(&b.name));
        c.interfaces.sort_by(|a, b| a.name.cmp(&b.name));
        assert_eq!(back, c);
        assert_eq!(
            s.load_sysctls().await.unwrap().len(),
            1,
            "other lanes untouched"
        );
    }
}
