//! Lane E: gateways, gateway monitoring, gateway groups (multi-WAN
//! failover and load balancing) and static routes -- the "routes" boot
//! phase.
//!
//! Model (tables from `patronus-config/migrations/0400_e_routing.sql`):
//! - a **gateway** is an upstream router reached through one interface
//!   (`@wan`, `@opt1` or a device). Its address is either configured or
//!   *dynamic*: learned from the default route the interfaces phase already
//!   installed on that interface (DHCP lease, PPPoE peer, static interface
//!   gateway, IPv6 router advertisement).
//! - the **monitor** ([`Monitor`], run by `patronus applyd`) pings each
//!   gateway (or its monitor IP) once a second through its own interface and
//!   publishes online / loss / latency / down per gateway.
//! - a **gateway group** (USE=multiwan) lists gateways by tier: the lowest
//!   tier that still has a usable member carries the traffic, several usable
//!   members in that tier share it by weight (ECMP), and when a whole tier
//!   fails the next one takes over.
//! - the **default gateway** setting (`routing.default_gateway4|6` in
//!   `system_config`) names a gateway or group; Patronus then installs its own
//!   default route (metric [`DEFAULT_METRIC`]) ahead of the per-interface
//!   defaults. Unset = automatic: the per-interface defaults alone decide.
//! - **static routes** (`routes` table) go via an IP address or a gateway
//!   name (a dynamic gateway keeps its routes when its address changes).
//!
//! Every kernel route Patronus installs here carries one of its own route
//! protocol numbers ([`STATIC_PROTO`], [`MONITOR_PROTO`], [`DEFAULT_PROTO`]),
//! and `apply` only ever replaces or deletes routes carrying them, so routes
//! added by hand, by DHCP clients or by the interfaces phase (proto 250) are
//! left alone.

use crate::lan::{check_description, check_iface_spec, db_err, invalid, now, resolve_iface};
use crate::linkstate::{argv, Cmd, KernelState, SystemCmd};
use async_trait::async_trait;
use ipnetwork::IpNetwork;
use patronus_config::applier::{Applier, ApplyReport, Phase};
use patronus_config::declarative::{DeclarativeConfig, ResourceKind, ResourceSpec};
use patronus_config::store::ConfigStore;
use patronus_core::{Error, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::Row;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

/// Route protocol of static routes.
pub const STATIC_PROTO: &str = "251";
/// Route protocol of the host routes that pin a gateway's monitor IP to it.
pub const MONITOR_PROTO: &str = "252";
/// Route protocol of the default route via the default gateway / group.
pub const DEFAULT_PROTO: &str = "253";
/// Metric of that default route (inside [`DEFAULT_TABLE`]).
pub const DEFAULT_METRIC: u32 = 1;
/// The routing table holding Patronus' default route. Two policy rules put
/// it ahead of the main table's default routes whatever their metric (a
/// distro or installer default with metric 0 included), while every more
/// specific main-table route (LAN subnets, static routes) still wins -- the
/// `suppress_prefixlength 0` pattern wg-quick uses:
///   pref [`RULE_PREF_MAIN`]   lookup main suppress_prefixlength 0
///   pref [`RULE_PREF_TABLE`]  lookup [`DEFAULT_TABLE`]
/// Without a default gateway set, that rule and the table are removed and
/// the main table's per-interface defaults route as before.
///
/// Policy routing: every gateway and gateway group also gets its own table
/// (numbered like its firewall mark, `patronus_config::policy`) with a
/// default route through it, reached by `fwmark <mark> lookup <mark>` rules
/// from [`RULE_PREF_POLICY`] on; firewall rules with a gateway set the mark.
pub const DEFAULT_TABLE: u32 = 4250;
pub const RULE_PREF_MAIN: u32 = 31000;
pub const RULE_PREF_POLICY: u32 = 31100;
pub const RULE_PREF_TABLE: u32 = 31900;
/// Priorities Patronus owns (rules outside are never touched).
const RULE_PREFS: std::ops::RangeInclusive<u32> = 31000..=31999;
const MAIN_TABLE: u32 = 254;
const OUR_PROTOS: [&str; 3] = [STATIC_PROTO, MONITOR_PROTO, DEFAULT_PROTO];

/// `system_config` keys of the default gateway (gateway or group name).
pub const DEFAULT_GW4_KEY: &str = "routing.default_gateway4";
pub const DEFAULT_GW6_KEY: &str = "routing.default_gateway6";

/// Every table lane E owns (web undo, docs).
pub const ROUTING_TABLES: &[&str] = &[
    "routes",
    "route_gateways",
    "route_gateway_groups",
    "route_gateway_group_members",
];

/// Whether gateway groups (multi-WAN) are compiled in (USE=multiwan).
pub const MULTIWAN: bool = cfg!(feature = "multiwan");

// ===========================================================================
// model
// ===========================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum Family {
    Inet,
    Inet6,
}

impl Family {
    pub fn as_str(&self) -> &'static str {
        match self {
            Family::Inet => "inet",
            Family::Inet6 => "inet6",
        }
    }
    pub fn parse(s: &str) -> Result<Self> {
        match s.trim() {
            "" | "inet" | "ipv4" | "4" => Ok(Family::Inet),
            "inet6" | "ipv6" | "6" => Ok(Family::Inet6),
            o => Err(invalid(format!("address family {o:?} (inet or inet6)"))),
        }
    }
    pub fn of(ip: &IpAddr) -> Self {
        if ip.is_ipv6() {
            Family::Inet6
        } else {
            Family::Inet
        }
    }
    pub fn v6(&self) -> bool {
        *self == Family::Inet6
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Gateway {
    pub name: String,
    pub interface: String,
    pub family: Family,
    /// None = dynamic (learned from the interface's default route).
    pub address: Option<IpAddr>,
    pub monitor_ip: Option<IpAddr>,
    pub monitor_enabled: bool,
    pub loss_threshold: u32,
    pub latency_threshold: u32,
    pub description: Option<String>,
}

/// When a group member stops carrying traffic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Trigger {
    Down,
    Loss,
    Latency,
    LossLatency,
}

impl Trigger {
    pub fn as_str(&self) -> &'static str {
        match self {
            Trigger::Down => "down",
            Trigger::Loss => "loss",
            Trigger::Latency => "latency",
            Trigger::LossLatency => "loss_latency",
        }
    }
    pub fn parse(s: &str) -> Result<Self> {
        match s.trim() {
            "" | "down" => Ok(Trigger::Down),
            "loss" => Ok(Trigger::Loss),
            "latency" => Ok(Trigger::Latency),
            "loss_latency" => Ok(Trigger::LossLatency),
            o => Err(invalid(format!(
                "trigger {o:?} (down, loss, latency or loss_latency)"
            ))),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Member {
    pub gateway: String,
    pub tier: u32,
    pub weight: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GatewayGroup {
    pub name: String,
    pub trigger: Trigger,
    pub members: Vec<Member>,
    pub description: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StaticRoute {
    pub id: i64,
    pub destination: IpNetwork,
    /// An IP address or a gateway name.
    pub gateway: Option<String>,
    /// A device or @role.
    pub interface: Option<String>,
    pub metric: Option<u32>,
    pub description: Option<String>,
    pub enabled: bool,
}

/// Everything lane E stores.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct RoutingConfig {
    pub gateways: Vec<Gateway>,
    pub groups: Vec<GatewayGroup>,
    pub routes: Vec<StaticRoute>,
    pub default4: Option<String>,
    pub default6: Option<String>,
    /// Firewall mark (= routing table) per gateway / group name.
    pub marks: BTreeMap<String, u32>,
}

impl RoutingConfig {
    pub fn gateway(&self, name: &str) -> Option<&Gateway> {
        self.gateways.iter().find(|g| g.name == name)
    }
    pub fn group(&self, name: &str) -> Option<&GatewayGroup> {
        self.groups.iter().find(|g| g.name == name)
    }
    fn default_for(&self, f: Family) -> Option<&str> {
        match f {
            Family::Inet => self.default4.as_deref(),
            Family::Inet6 => self.default6.as_deref(),
        }
    }
}

// ===========================================================================
// store
// ===========================================================================

fn parse_opt_ip(what: &str, v: Option<String>) -> Result<Option<IpAddr>> {
    match v.as_deref().map(str::trim) {
        None | Some("") => Ok(None),
        Some(s) => s
            .parse()
            .map(Some)
            .map_err(|_| Error::Config(format!("stored {what} {s:?} is not an IP address"))),
    }
}

/// Load every lane-E row.
pub async fn load(store: &ConfigStore) -> Result<RoutingConfig> {
    let pool = store.pool()?;
    let mut c = RoutingConfig::default();
    for r in sqlx::query(
        "SELECT name, interface, family, address, monitor_ip, monitor_enabled,
                loss_threshold, latency_threshold, description
         FROM route_gateways ORDER BY name",
    )
    .fetch_all(pool)
    .await
    .map_err(db_err("read gateways"))?
    {
        let name: String = r.get(0);
        c.gateways.push(Gateway {
            family: Family::parse(&r.get::<String, _>(2))
                .map_err(|e| Error::Config(format!("gateway {name}: {e}")))?,
            address: parse_opt_ip("gateway address", r.get(3))?,
            monitor_ip: parse_opt_ip("monitor IP", r.get(4))?,
            interface: r.get(1),
            monitor_enabled: r.get::<i64, _>(5) != 0,
            loss_threshold: r.get::<i64, _>(6).clamp(1, 100) as u32,
            latency_threshold: r.get::<i64, _>(7).max(1) as u32,
            description: r.get(8),
            name,
        });
    }
    for r in
        sqlx::query("SELECT name, trigger, description FROM route_gateway_groups ORDER BY name")
            .fetch_all(pool)
            .await
            .map_err(db_err("read gateway groups"))?
    {
        let name: String = r.get(0);
        let members = sqlx::query(
            "SELECT gateway, tier, weight FROM route_gateway_group_members
             WHERE group_name = ? ORDER BY tier, gateway",
        )
        .bind(&name)
        .fetch_all(pool)
        .await
        .map_err(db_err("read gateway group members"))?
        .iter()
        .map(|m| Member {
            gateway: m.get(0),
            tier: m.get::<i64, _>(1).max(1) as u32,
            weight: m.get::<i64, _>(2).max(1) as u32,
        })
        .collect();
        c.groups.push(GatewayGroup {
            trigger: Trigger::parse(&r.get::<String, _>(1))
                .map_err(|e| Error::Config(format!("gateway group {name}: {e}")))?,
            description: r.get(2),
            members,
            name,
        });
    }
    for r in sqlx::query(
        "SELECT id, destination, prefix_len, gateway, interface, metric, description, enabled
         FROM routes ORDER BY id",
    )
    .fetch_all(pool)
    .await
    .map_err(db_err("read static routes"))?
    {
        let id: i64 = r.get(0);
        let dst: Option<String> = r.get(1);
        let plen: Option<i64> = r.get(2);
        let destination = match dst {
            Some(d) => {
                let s = match plen {
                    Some(p) if !d.contains('/') => format!("{d}/{p}"),
                    _ => d.clone(),
                };
                s.parse::<IpNetwork>().map_err(|_| {
                    Error::Config(format!("static route {id}: bad destination {s:?}"))
                })?
            }
            None => {
                return Err(Error::Config(format!(
                    "static route {id}: no destination (use the default gateway setting)"
                )))
            }
        };
        c.routes.push(StaticRoute {
            id,
            destination,
            gateway: r
                .get::<Option<String>, _>(3)
                .filter(|s| !s.trim().is_empty()),
            interface: r
                .get::<Option<String>, _>(4)
                .filter(|s| !s.trim().is_empty()),
            metric: r.get::<Option<i64>, _>(5).map(|m| m.max(0) as u32),
            description: r.get(6),
            enabled: r.get::<i64, _>(7) != 0,
        });
    }
    c.marks = patronus_config::policy::policy_marks(store).await?;
    let setting = |v: Option<String>| v.filter(|s| !s.trim().is_empty());
    c.default4 = setting(store.load_system_config(DEFAULT_GW4_KEY).await?);
    c.default6 = setting(store.load_system_config(DEFAULT_GW6_KEY).await?);
    Ok(c)
}

/// Gateway / group names: what the default-gateway setting, static routes
/// and firewall rules (policy routing) refer to.
pub fn check_name(what: &str, s: &str) -> Result<String> {
    let s = s.trim();
    let ok = !s.is_empty()
        && s.len() <= 32
        && s.chars().next().is_some_and(|c| c.is_ascii_alphabetic())
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-');
    if ok {
        Ok(s.to_string())
    } else {
        Err(invalid(format!(
            "{what} name {s:?} (letters, digits, '_' or '-', starting with a letter, at most 32)"
        )))
    }
}

fn opt_ip(what: &str, s: Option<&str>) -> Result<Option<IpAddr>> {
    match s.map(str::trim).filter(|s| !s.is_empty()) {
        None => Ok(None),
        Some(v) => v
            .parse()
            .map(Some)
            .map_err(|_| invalid(format!("{what} {v:?} (an IP address)"))),
    }
}

/// A gateway as entered in the UI / API.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct GatewayInput {
    pub name: String,
    pub interface: String,
    #[serde(default)]
    pub family: Option<String>,
    /// Empty = dynamic.
    #[serde(default)]
    pub address: Option<String>,
    #[serde(default)]
    pub monitor_ip: Option<String>,
    #[serde(default)]
    pub monitor_enabled: Option<bool>,
    #[serde(default)]
    pub loss_threshold: Option<u32>,
    #[serde(default)]
    pub latency_threshold: Option<u32>,
    #[serde(default)]
    pub description: Option<String>,
}

impl GatewayInput {
    pub fn validated(&self) -> Result<Gateway> {
        let address = opt_ip("gateway address", self.address.as_deref())?;
        let monitor_ip = opt_ip("monitor IP", self.monitor_ip.as_deref())?;
        let family = match (&self.family, address) {
            (Some(f), _) if !f.trim().is_empty() => Family::parse(f)?,
            (_, Some(a)) => Family::of(&a),
            _ => Family::Inet,
        };
        for (what, ip) in [("gateway address", address), ("monitor IP", monitor_ip)] {
            if let Some(ip) = ip {
                if Family::of(&ip) != family {
                    return Err(invalid(format!(
                        "{what} {ip}: not an {} address",
                        if family.v6() { "IPv6" } else { "IPv4" }
                    )));
                }
                if ip.is_unspecified() || ip.is_multicast() || ip.is_loopback() {
                    return Err(invalid(format!("{what} {ip}")));
                }
            }
        }
        let loss_threshold = self.loss_threshold.unwrap_or(20);
        if !(1..=100).contains(&loss_threshold) {
            return Err(invalid("loss threshold (1-100 %)"));
        }
        let latency_threshold = self.latency_threshold.unwrap_or(500);
        if !(1..=60_000).contains(&latency_threshold) {
            return Err(invalid("latency threshold (1-60000 ms)"));
        }
        Ok(Gateway {
            name: check_name("gateway", &self.name)?,
            interface: check_iface_spec(&self.interface)?,
            family,
            address,
            monitor_ip,
            monitor_enabled: self.monitor_enabled.unwrap_or(true),
            loss_threshold,
            latency_threshold,
            description: check_description(self.description.as_deref())?,
        })
    }
}

async fn name_taken(store: &ConfigStore, table: &str, name: &str) -> Result<bool> {
    let n: i64 = sqlx::query(&format!("SELECT COUNT(*) FROM {table} WHERE name = ?"))
        .bind(name)
        .fetch_one(store.pool()?)
        .await
        .map_err(db_err("check name"))?
        .get(0);
    Ok(n > 0)
}

/// Create (`existing = None`) or replace the gateway `existing`. Names are
/// fixed once created (static routes, groups and rules refer to them).
pub async fn save_gateway(store: &ConfigStore, existing: Option<&str>, g: &Gateway) -> Result<()> {
    let pool = store.pool()?;
    match existing {
        None => {
            if name_taken(store, "route_gateways", &g.name).await?
                || name_taken(store, "route_gateway_groups", &g.name).await?
            {
                return Err(invalid(format!(
                    "request: a gateway or group named {} already exists",
                    g.name
                )));
            }
        }
        Some(old) => {
            if old != g.name {
                return Err(invalid(
                    "request: a gateway cannot be renamed (delete it and add a new one)",
                ));
            }
            if !name_taken(store, "route_gateways", old).await? {
                return Err(Error::Config(format!("gateway {old} not found")));
            }
            let cfg = load(store).await?;
            if cfg.gateway(old).is_some_and(|cur| cur.family != g.family) {
                for (slot, f) in [
                    (&cfg.default4, Family::Inet),
                    (&cfg.default6, Family::Inet6),
                ] {
                    if slot.as_deref() == Some(old) {
                        return Err(invalid(format!(
                            "request: {old} is the default {} gateway; its family cannot change",
                            if f.v6() { "IPv6" } else { "IPv4" }
                        )));
                    }
                }
                if let Some(grp) = cfg
                    .groups
                    .iter()
                    .find(|grp| grp.members.iter().any(|m| m.gateway == old))
                {
                    return Err(invalid(format!(
                        "request: {old} is a member of gateway group {}; its family cannot change",
                        grp.name
                    )));
                }
            }
        }
    }
    sqlx::query(
        "INSERT INTO route_gateways (name, interface, family, address, monitor_ip,
            monitor_enabled, loss_threshold, latency_threshold, description, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(name) DO UPDATE SET interface = excluded.interface,
            family = excluded.family, address = excluded.address,
            monitor_ip = excluded.monitor_ip, monitor_enabled = excluded.monitor_enabled,
            loss_threshold = excluded.loss_threshold,
            latency_threshold = excluded.latency_threshold,
            description = excluded.description, updated_at = excluded.updated_at",
    )
    .bind(&g.name)
    .bind(&g.interface)
    .bind(g.family.as_str())
    .bind(g.address.map(|a| a.to_string()))
    .bind(g.monitor_ip.map(|a| a.to_string()))
    .bind(g.monitor_enabled as i64)
    .bind(g.loss_threshold as i64)
    .bind(g.latency_threshold as i64)
    .bind(&g.description)
    .bind(now())
    .execute(pool)
    .await
    .map_err(db_err("write gateway"))?;
    Ok(())
}

/// What still refers to a gateway or group name.
async fn users_of(store: &ConfigStore, name: &str) -> Result<Vec<String>> {
    let cfg = load(store).await?;
    let mut v = Vec::new();
    if cfg.default4.as_deref() == Some(name) {
        v.push("the default IPv4 gateway setting".to_string());
    }
    if cfg.default6.as_deref() == Some(name) {
        v.push("the default IPv6 gateway setting".to_string());
    }
    for r in &cfg.routes {
        if r.gateway.as_deref() == Some(name) {
            v.push(format!("static route {}", r.destination));
        }
    }
    for g in &cfg.groups {
        if g.members.iter().any(|m| m.gateway == name) {
            v.push(format!("gateway group {}", g.name));
        }
    }
    let rules: Vec<String> = sqlx::query("SELECT name FROM firewall_rules WHERE gateway = ?")
        .bind(name)
        .fetch_all(store.pool()?)
        .await
        .map_err(db_err("read firewall rules"))?
        .iter()
        .map(|r| format!("firewall rule {}", r.get::<String, _>(0)))
        .collect();
    v.extend(rules);
    Ok(v)
}

pub async fn delete_gateway(store: &ConfigStore, name: &str) -> Result<()> {
    if !name_taken(store, "route_gateways", name).await? {
        return Err(Error::Config(format!("gateway {name} not found")));
    }
    let users = users_of(store, name).await?;
    if !users.is_empty() {
        return Err(invalid(format!(
            "request: gateway {name} is still used by {}",
            users.join(", ")
        )));
    }
    sqlx::query("DELETE FROM route_gateways WHERE name = ?")
        .bind(name)
        .execute(store.pool()?)
        .await
        .map_err(db_err("delete gateway"))?;
    Ok(())
}

/// Members as entered: a list, or `"GW1:1, GW2:2:3"` (gateway:tier[:weight]).
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum MembersInput {
    List(Vec<Member>),
    Spec(String),
}

#[derive(Debug, Clone, Deserialize)]
pub struct GroupInput {
    pub name: String,
    #[serde(default)]
    pub trigger: Option<String>,
    pub members: MembersInput,
    #[serde(default)]
    pub description: Option<String>,
}

impl GroupInput {
    pub fn validated(&self) -> Result<GatewayGroup> {
        let raw = match &self.members {
            MembersInput::List(v) => v.clone(),
            MembersInput::Spec(s) => {
                let mut v = Vec::new();
                for part in s
                    .split([',', '\n'])
                    .map(str::trim)
                    .filter(|p| !p.is_empty())
                {
                    let f: Vec<&str> = part.split(':').map(str::trim).collect();
                    let num = |i: usize, d: u32| -> Result<u32> {
                        match f.get(i) {
                            None | Some(&"") => Ok(d),
                            Some(x) => x.parse().map_err(|_| {
                                invalid(format!("member {part:?} (gateway:tier[:weight])"))
                            }),
                        }
                    };
                    if f.len() > 3 {
                        return Err(invalid(format!("member {part:?} (gateway:tier[:weight])")));
                    }
                    v.push(Member {
                        gateway: f[0].to_string(),
                        tier: num(1, 1)?,
                        weight: num(2, 1)?,
                    });
                }
                v
            }
        };
        if raw.is_empty() {
            return Err(invalid("gateway group: it needs at least one member"));
        }
        let mut seen = BTreeSet::new();
        let mut members = Vec::new();
        for m in raw {
            let gateway = check_name("member gateway", &m.gateway)?;
            if !seen.insert(gateway.clone()) {
                return Err(invalid(format!("gateway group: {gateway} is listed twice")));
            }
            if !(1..=5).contains(&m.tier) {
                return Err(invalid(format!("tier of {gateway} (1-5)")));
            }
            if !(1..=100).contains(&m.weight) {
                return Err(invalid(format!("weight of {gateway} (1-100)")));
            }
            members.push(Member {
                gateway,
                tier: m.tier,
                weight: m.weight,
            });
        }
        Ok(GatewayGroup {
            name: check_name("gateway group", &self.name)?,
            trigger: Trigger::parse(self.trigger.as_deref().unwrap_or(""))?,
            members,
            description: check_description(self.description.as_deref())?,
        })
    }
}

pub async fn save_group(
    store: &ConfigStore,
    existing: Option<&str>,
    g: &GatewayGroup,
) -> Result<()> {
    if !MULTIWAN {
        return Err(invalid(
            "request: gateway groups (multi-WAN) are not built into this Patronus (USE=multiwan)",
        ));
    }
    match existing {
        None => {
            if name_taken(store, "route_gateways", &g.name).await?
                || name_taken(store, "route_gateway_groups", &g.name).await?
            {
                return Err(invalid(format!(
                    "request: a gateway or group named {} already exists",
                    g.name
                )));
            }
        }
        Some(old) => {
            if old != g.name {
                return Err(invalid("request: a gateway group cannot be renamed"));
            }
            if !name_taken(store, "route_gateway_groups", old).await? {
                return Err(Error::Config(format!("gateway group {old} not found")));
            }
        }
    }
    // check before writing anything: members exist, one family, and a group
    // that is the default gateway keeps that family
    let cfg = load(store).await?;
    let mut fam = None;
    for m in &g.members {
        let gw = cfg.gateway(&m.gateway).ok_or_else(|| {
            invalid(format!(
                "gateway group {}: there is no gateway {}",
                g.name, m.gateway
            ))
        })?;
        if *fam.get_or_insert(gw.family) != gw.family {
            return Err(invalid(format!(
                "gateway group {}: members mix IPv4 and IPv6 gateways",
                g.name
            )));
        }
    }
    for (slot, f) in [
        (&cfg.default4, Family::Inet),
        (&cfg.default6, Family::Inet6),
    ] {
        if slot.as_deref() == Some(g.name.as_str()) && fam != Some(f) {
            return Err(invalid(format!(
                "request: {} is the default {} gateway; its members must stay {}",
                g.name,
                if f.v6() { "IPv6" } else { "IPv4" },
                if f.v6() { "IPv6" } else { "IPv4" }
            )));
        }
    }
    let mut tx = store.pool()?.begin().await.map_err(db_err("begin"))?;
    sqlx::query(
        "INSERT INTO route_gateway_groups (name, trigger, description, updated_at)
         VALUES (?, ?, ?, ?)
         ON CONFLICT(name) DO UPDATE SET trigger = excluded.trigger,
            description = excluded.description, updated_at = excluded.updated_at",
    )
    .bind(&g.name)
    .bind(g.trigger.as_str())
    .bind(&g.description)
    .bind(now())
    .execute(&mut *tx)
    .await
    .map_err(db_err("write gateway group"))?;
    sqlx::query("DELETE FROM route_gateway_group_members WHERE group_name = ?")
        .bind(&g.name)
        .execute(&mut *tx)
        .await
        .map_err(db_err("write gateway group"))?;
    for m in &g.members {
        sqlx::query(
            "INSERT INTO route_gateway_group_members (group_name, gateway, tier, weight)
             VALUES (?, ?, ?, ?)",
        )
        .bind(&g.name)
        .bind(&m.gateway)
        .bind(m.tier as i64)
        .bind(m.weight as i64)
        .execute(&mut *tx)
        .await
        .map_err(|e| {
            if e.to_string().contains("FOREIGN KEY") {
                invalid(format!(
                    "gateway group {}: there is no gateway {}",
                    g.name, m.gateway
                ))
            } else {
                Error::Config(format!("write gateway group member: {e}"))
            }
        })?;
    }
    tx.commit()
        .await
        .map_err(|e| Error::Config(format!("write gateway group: {e}")))?;
    Ok(())
}

fn group_family(cfg: &RoutingConfig, g: &GatewayGroup) -> Option<Family> {
    g.members
        .first()
        .and_then(|m| cfg.gateway(&m.gateway))
        .map(|gw| gw.family)
}

pub async fn delete_group(store: &ConfigStore, name: &str) -> Result<()> {
    if !name_taken(store, "route_gateway_groups", name).await? {
        return Err(Error::Config(format!("gateway group {name} not found")));
    }
    let users: Vec<String> = users_of(store, name)
        .await?
        .into_iter()
        .filter(|u| !u.starts_with("gateway group"))
        .collect();
    if !users.is_empty() {
        return Err(invalid(format!(
            "request: gateway group {name} is still used by {}",
            users.join(", ")
        )));
    }
    sqlx::query("DELETE FROM route_gateway_groups WHERE name = ?")
        .bind(name)
        .execute(store.pool()?)
        .await
        .map_err(db_err("delete gateway group"))?;
    Ok(())
}

/// Set (`Some`) or clear the default gateway / group of one family.
pub async fn set_default(store: &ConfigStore, family: Family, name: Option<&str>) -> Result<()> {
    let key = if family.v6() {
        DEFAULT_GW6_KEY
    } else {
        DEFAULT_GW4_KEY
    };
    let name = name.map(str::trim).filter(|s| !s.is_empty());
    if let Some(n) = name {
        let cfg = load(store).await?;
        let fam = if let Some(g) = cfg.gateway(n) {
            Some(g.family)
        } else if let Some(g) = cfg.group(n) {
            if !MULTIWAN {
                return Err(invalid(
                    "request: gateway groups need USE=multiwan in this Patronus build",
                ));
            }
            group_family(&cfg, g)
        } else {
            return Err(invalid(format!(
                "request: there is no gateway or group {n}"
            )));
        };
        if fam != Some(family) {
            return Err(invalid(format!(
                "request: {n} is not an {} gateway",
                if family.v6() { "IPv6" } else { "IPv4" }
            )));
        }
    }
    store.save_system_config(key, name.unwrap_or("")).await
}

/// A static route as entered.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct RouteInput {
    pub destination: String,
    #[serde(default)]
    pub gateway: Option<String>,
    #[serde(default)]
    pub interface: Option<String>,
    #[serde(default)]
    pub metric: Option<u32>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub enabled: Option<bool>,
}

impl RouteInput {
    /// Checked against the gateways that exist (`cfg`).
    pub fn validated(&self, cfg: &RoutingConfig, id: i64) -> Result<StaticRoute> {
        let d = self.destination.trim();
        let net: IpNetwork = d.parse().map_err(|_| {
            invalid(format!(
                "destination {d:?} (a network such as 10.20.0.0/16)"
            ))
        })?;
        // store the network address (10.20.0.0/16, not 10.20.3.4/16)
        let destination = IpNetwork::new(net.network(), net.prefix())
            .map_err(|_| invalid(format!("destination {d:?}")))?;
        if destination.prefix() == 0 {
            return Err(invalid(
                "destination: the default route is set with Default gateway, not as a static route",
            ));
        }
        let fam = Family::of(&destination.ip());
        let gateway = self
            .gateway
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty());
        let gateway = match gateway {
            None => None,
            Some(g) => match g.parse::<IpAddr>() {
                Ok(ip) => {
                    if Family::of(&ip) != fam {
                        return Err(invalid(format!(
                            "gateway {ip}: the destination is {}",
                            if fam.v6() { "IPv6" } else { "IPv4" }
                        )));
                    }
                    if ip.is_unspecified() || ip.is_multicast() || ip.is_loopback() {
                        return Err(invalid(format!("gateway {ip}")));
                    }
                    Some(ip.to_string())
                }
                Err(_) => {
                    let gw = cfg.gateway(g).ok_or_else(|| {
                        invalid(format!("gateway {g:?} (an IP address or a gateway name)"))
                    })?;
                    if gw.family != fam {
                        return Err(invalid(format!(
                            "gateway {g}: it is an {} gateway, the destination is not",
                            if gw.family.v6() { "IPv6" } else { "IPv4" }
                        )));
                    }
                    Some(gw.name.clone())
                }
            },
        };
        let interface = match self
            .interface
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            None => None,
            Some(i) => Some(check_iface_spec(i)?),
        };
        if gateway.is_none() && interface.is_none() {
            return Err(invalid("route: give a gateway, an interface, or both"));
        }
        if let Some(m) = self.metric {
            if m > 1_000_000 {
                return Err(invalid("metric (0-1000000)"));
            }
        }
        Ok(StaticRoute {
            id,
            destination,
            gateway,
            interface,
            metric: self.metric,
            description: check_description(self.description.as_deref())?,
            enabled: self.enabled.unwrap_or(true),
        })
    }
}

/// Insert (`id = None`) or update a static route; returns its id.
pub async fn save_route(store: &ConfigStore, id: Option<i64>, r: &StaticRoute) -> Result<i64> {
    let pool = store.pool()?;
    let cfg = load(store).await?;
    if cfg
        .routes
        .iter()
        .any(|o| Some(o.id) != id && o.destination == r.destination && o.metric == r.metric)
    {
        return Err(invalid(format!(
            "request: a route to {} with that metric already exists",
            r.destination
        )));
    }
    let t = now();
    let dst = r.destination.network().to_string();
    let plen = r.destination.prefix() as i64;
    match id {
        None => {
            let res = sqlx::query(
                "INSERT INTO routes (destination, prefix_len, gateway, interface, metric,
                    description, enabled, created_at, updated_at)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            )
            .bind(&dst)
            .bind(plen)
            .bind(&r.gateway)
            .bind(&r.interface)
            .bind(r.metric.map(|m| m as i64))
            .bind(&r.description)
            .bind(r.enabled as i64)
            .bind(t)
            .bind(t)
            .execute(pool)
            .await
            .map_err(db_err("write static route"))?;
            Ok(res.last_insert_rowid())
        }
        Some(id) => {
            let res = sqlx::query(
                "UPDATE routes SET destination = ?, prefix_len = ?, gateway = ?, interface = ?,
                    metric = ?, description = ?, enabled = ?, updated_at = ? WHERE id = ?",
            )
            .bind(&dst)
            .bind(plen)
            .bind(&r.gateway)
            .bind(&r.interface)
            .bind(r.metric.map(|m| m as i64))
            .bind(&r.description)
            .bind(r.enabled as i64)
            .bind(t)
            .bind(id)
            .execute(pool)
            .await
            .map_err(db_err("write static route"))?;
            if res.rows_affected() == 0 {
                return Err(Error::Config(format!("static route {id} not found")));
            }
            Ok(id)
        }
    }
}

pub async fn delete_route(store: &ConfigStore, id: i64) -> Result<()> {
    let res = sqlx::query("DELETE FROM routes WHERE id = ?")
        .bind(id)
        .execute(store.pool()?)
        .await
        .map_err(db_err("delete static route"))?;
    if res.rows_affected() == 0 {
        return Err(Error::Config(format!("static route {id} not found")));
    }
    Ok(())
}

/// Copy of lane E's rows + settings (web undo).
pub async fn snapshot_tables(store: &ConfigStore) -> Result<Value> {
    let doc = store.export_json().await?;
    let mut out = serde_json::Map::new();
    if let Some(t) = doc.get("tables").and_then(Value::as_object) {
        for name in ROUTING_TABLES {
            if let Some(rows) = t.get(*name) {
                out.insert((*name).to_string(), rows.clone());
            }
        }
    }
    let cfg = load(store).await?;
    out.insert(
        "_defaults".into(),
        json!([
            cfg.default4.unwrap_or_default(),
            cfg.default6.unwrap_or_default()
        ]),
    );
    Ok(Value::Object(out))
}

/// Put lane E's tables back to a [`snapshot_tables`] state.
pub async fn restore_tables(store: &ConfigStore, snap: &Value) -> Result<()> {
    let Some(tables) = snap.as_object() else {
        return Ok(());
    };
    let mut tx = store
        .pool()?
        .begin()
        .await
        .map_err(db_err("begin restore"))?;
    sqlx::query("PRAGMA defer_foreign_keys = ON")
        .execute(&mut *tx)
        .await
        .map_err(db_err("defer fks"))?;
    // children first, so ON DELETE CASCADE has nothing left to do
    for name in ROUTING_TABLES.iter().rev() {
        sqlx::query(&format!("DELETE FROM \"{name}\""))
            .execute(&mut *tx)
            .await
            .map_err(db_err("restore"))?;
    }
    for name in ROUTING_TABLES {
        for row in tables
            .get(*name)
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let Some(obj) = row.as_object() else { continue };
            let cols: Vec<&String> = obj.keys().collect();
            let sql = format!(
                "INSERT INTO \"{name}\" ({}) VALUES ({})",
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
                    Value::Number(n) if n.is_i64() => q.bind(n.as_i64()),
                    Value::Number(n) => q.bind(n.as_f64()),
                    Value::String(s) => q.bind(s.clone()),
                    other => q.bind(other.to_string()),
                };
            }
            q.execute(&mut *tx).await.map_err(db_err("restore row"))?;
        }
    }
    tx.commit().await.map_err(db_err("commit restore"))?;
    if let Some(d) = tables.get("_defaults").and_then(Value::as_array) {
        let s = |i: usize| d.get(i).and_then(Value::as_str).unwrap_or("").to_string();
        store.save_system_config(DEFAULT_GW4_KEY, &s(0)).await?;
        store.save_system_config(DEFAULT_GW6_KEY, &s(1)).await?;
    }
    Ok(())
}

// ===========================================================================
// gateway state (resolution + monitor results)
// ===========================================================================

/// A gateway resolved against the live kernel.
#[derive(Debug, Clone, PartialEq, Serialize, Default)]
pub struct Resolved {
    pub dev: Option<String>,
    /// Next hop; None with `ptp` = a point-to-point link (PPPoE) routed by
    /// device alone.
    pub address: Option<IpAddr>,
    pub ptp: bool,
    pub link_up: bool,
    /// Why the gateway cannot be used at all (no device, no address...).
    pub problem: Option<String>,
}

impl Resolved {
    pub fn routable(&self) -> bool {
        self.problem.is_none() && self.dev.is_some() && (self.address.is_some() || self.ptp)
    }
}

/// Resolve every gateway: interface role -> device, dynamic address ->
/// the device's own default route (never one of ours).
pub async fn resolve_all(
    store: &ConfigStore,
    cfg: &RoutingConfig,
    k: &KernelState,
) -> Result<BTreeMap<String, Resolved>> {
    let mut out = BTreeMap::new();
    for g in &cfg.gateways {
        let devs = resolve_iface(store, &g.interface).await?;
        out.insert(
            g.name.clone(),
            resolve_one(g, devs.first().map(String::as_str), k),
        );
    }
    Ok(out)
}

pub fn resolve_one(g: &Gateway, dev: Option<&str>, k: &KernelState) -> Resolved {
    let mut r = Resolved::default();
    let Some(dev) = dev else {
        r.problem = Some(format!("interface {} is not assigned", g.interface));
        return r;
    };
    r.dev = Some(dev.to_string());
    let Some(link) = k.get(dev) else {
        r.problem = Some(format!("device {dev} does not exist"));
        return r;
    };
    r.link_up = link.up
        && !matches!(
            link.operstate.as_str(),
            "DOWN" | "LOWERLAYERDOWN" | "NOTPRESENT"
        );
    match g.address {
        Some(a) => r.address = Some(a),
        None => {
            let learned = k
                .default_routes
                .iter()
                .filter(|d| {
                    d.dev == dev
                        && d.v6 == g.family.v6()
                        && !OUR_PROTOS.contains(&d.protocol.as_str())
                })
                .min_by_key(|d| d.metric);
            match learned {
                Some(d) => match d.gateway.as_deref().and_then(|s| s.parse().ok()) {
                    Some(ip) => r.address = Some(ip),
                    None => r.ptp = true,
                },
                None => {
                    r.problem = Some(format!(
                        "no {} default route on {dev} yet (DHCP/PPPoE/RA not up?)",
                        if g.family.v6() { "IPv6" } else { "IPv4" }
                    ))
                }
            }
        }
    }
    r
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GwState {
    /// Fewer than three probes so far.
    Pending,
    Online,
    /// Packet loss at or above the gateway's threshold.
    Loss,
    /// Average round trip above the gateway's threshold.
    Latency,
    /// No replies to the last probes, link down, or not resolvable.
    Down,
    /// Monitoring off (or nothing to probe): treated as up.
    Unmonitored,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GwStatus {
    pub state: GwState,
    pub loss_pct: u32,
    pub rtt_ms: Option<f64>,
    pub samples: u32,
    pub detail: Option<String>,
    /// Unix time the state last changed.
    pub since: i64,
}

/// Whether a member in `state` carries traffic for a group with `trigger`.
pub fn usable(state: GwState, trigger: Trigger) -> bool {
    match state {
        GwState::Pending | GwState::Online | GwState::Unmonitored => true,
        GwState::Down => false,
        GwState::Loss => !matches!(trigger, Trigger::Loss | Trigger::LossLatency),
        GwState::Latency => !matches!(trigger, Trigger::Latency | Trigger::LossLatency),
    }
}

/// Probe window per gateway (one sample a second).
pub const WINDOW: usize = 10;
/// Consecutive lost probes that make a gateway down.
pub const DOWN_AFTER: usize = 5;

/// State of a gateway from its recent probe results (`None` = lost).
pub fn evaluate(samples: &VecDeque<Option<f64>>, g: &Gateway) -> (GwState, u32, Option<f64>) {
    let n = samples.len();
    let lost = samples.iter().filter(|s| s.is_none()).count();
    let loss = (lost * 100).checked_div(n).unwrap_or(0) as u32;
    let ok: Vec<f64> = samples.iter().flatten().copied().collect();
    let rtt = (!ok.is_empty()).then(|| ok.iter().sum::<f64>() / ok.len() as f64);
    let tail = n.min(DOWN_AFTER);
    let state = if n >= 3 && samples.iter().rev().take(tail).all(|s| s.is_none()) {
        GwState::Down
    } else if n < 3 {
        GwState::Pending
    } else if loss >= g.loss_threshold {
        GwState::Loss
    } else if rtt.is_some_and(|r| r > g.latency_threshold as f64) {
        GwState::Latency
    } else {
        GwState::Online
    };
    (state, loss, rtt)
}

static PUBLISHED: StdMutex<Option<BTreeMap<String, GwStatus>>> = StdMutex::new(None);

/// Where the monitor also writes its results (for `patronus apply` run as
/// another process, and for debugging).
pub fn status_file() -> PathBuf {
    std::env::var_os("PATRONUS_GATEWAY_STATUS")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/run/patronus/gateway-status.json"))
}

fn publish(st: &BTreeMap<String, GwStatus>) {
    *PUBLISHED.lock().unwrap_or_else(|e| e.into_inner()) = Some(st.clone());
    let path = status_file();
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let tmp = path.with_extension("json.tmp");
    if let Ok(s) = serde_json::to_string(st) {
        if std::fs::write(&tmp, s).is_ok() {
            let _ = std::fs::rename(&tmp, &path);
        }
    }
}

/// Latest monitor results: this process's monitor, else a fresh status
/// file (< 30 s old), else nothing (every gateway counts as up).
pub fn current_status() -> Option<BTreeMap<String, GwStatus>> {
    if let Some(s) = PUBLISHED.lock().unwrap_or_else(|e| e.into_inner()).clone() {
        return Some(s);
    }
    let path = status_file();
    let fresh = std::fs::metadata(&path)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.elapsed().ok())
        .is_some_and(|age| age < Duration::from_secs(30));
    if !fresh {
        return None;
    }
    std::fs::read_to_string(&path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
}

/// Effective state: unresolvable or link down beats the probe results.
fn effective(name: &str, res: &Resolved, status: &BTreeMap<String, GwStatus>) -> GwState {
    if !res.routable() || !res.link_up {
        return GwState::Down;
    }
    status
        .get(name)
        .map(|s| s.state)
        .unwrap_or(GwState::Pending)
}

// ===========================================================================
// planning
// ===========================================================================

/// One next hop of a kernel route.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct Hop {
    pub via: Option<String>,
    pub dev: Option<String>,
    pub weight: u32,
}

/// A kernel route of ours (tagged with one of [`OUR_PROTOS`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct KRoute {
    pub v6: bool,
    /// `default` or a network in CIDR form.
    pub dst: String,
    pub metric: u32,
    pub proto: String,
    /// 254 = main.
    pub table: u32,
    pub hops: Vec<Hop>,
}

impl KRoute {
    fn key(&self) -> (bool, String, u32, u32) {
        (self.v6, self.dst.clone(), self.metric, self.table)
    }

    fn table_args(&self, a: &mut Vec<String>) {
        if self.table != MAIN_TABLE {
            a.extend(["table".into(), self.table.to_string()]);
        }
    }

    /// `ip` arguments that install this route.
    pub fn replace_args(&self) -> Vec<String> {
        let mut a = vec![
            if self.v6 { "-6" } else { "-4" }.to_string(),
            "route".into(),
            "replace".into(),
            self.dst.clone(),
        ];
        self.table_args(&mut a);
        a.extend([
            "metric".into(),
            self.metric.to_string(),
            "proto".into(),
            self.proto.clone(),
        ]);
        if self.hops.len() == 1 {
            let h = &self.hops[0];
            if let Some(v) = &h.via {
                a.extend(["via".into(), v.clone()]);
            }
            if let Some(d) = &h.dev {
                a.extend(["dev".into(), d.clone()]);
            }
        } else {
            for h in &self.hops {
                a.push("nexthop".into());
                if let Some(v) = &h.via {
                    a.extend(["via".into(), v.clone()]);
                }
                if let Some(d) = &h.dev {
                    a.extend(["dev".into(), d.clone()]);
                }
                a.extend(["weight".into(), h.weight.to_string()]);
            }
        }
        a
    }

    pub fn delete_args(&self) -> Vec<String> {
        let mut a = vec![
            if self.v6 { "-6" } else { "-4" }.to_string(),
            "route".into(),
            "del".into(),
            self.dst.clone(),
        ];
        self.table_args(&mut a);
        a.extend([
            "metric".into(),
            self.metric.to_string(),
            "proto".into(),
            self.proto.clone(),
        ]);
        a
    }

    /// Does the kernel route `have` already do what `self` asks for? A
    /// wanted hop without a device matches whatever device the kernel
    /// picked; a single path ignores weights.
    pub fn satisfied_by(&self, have: &KRoute) -> bool {
        if self.key() != have.key()
            || self.proto != have.proto
            || self.hops.len() != have.hops.len()
        {
            return false;
        }
        let single = self.hops.len() == 1;
        let mut want = self.hops.clone();
        let mut got = have.hops.clone();
        want.sort();
        got.sort();
        want.iter().zip(got.iter()).all(|(w, g)| {
            w.via == g.via
                && (w.dev.is_none() || w.dev == g.dev)
                && (single || w.weight == g.weight)
        })
    }
}

fn host_net(ip: &IpAddr) -> String {
    match ip {
        IpAddr::V4(_) => format!("{ip}/32"),
        IpAddr::V6(_) => format!("{ip}/128"),
    }
}

fn norm_dst(d: &str, v6: bool) -> String {
    if d == "default" || d.contains('/') {
        d.to_string()
    } else if v6 {
        format!("{d}/128")
    } else {
        format!("{d}/32")
    }
}

/// Parse `ip -j route show table T proto N` (any of ours) output.
pub fn parse_owned(json: &str, v6: bool, proto: &str, table: u32) -> Result<Vec<KRoute>> {
    if json.trim().is_empty() {
        return Ok(Vec::new());
    }
    let v: Vec<Value> = serde_json::from_str(json)
        .map_err(|e| Error::Network(format!("parse `ip -j route`: {e}")))?;
    let s = |r: &Value, k: &str| r.get(k).and_then(Value::as_str).map(str::to_string);
    let mut out: Vec<KRoute> = Vec::new();
    for r in &v {
        let Some(dst) = s(r, "dst") else { continue };
        let metric = r.get("metric").and_then(Value::as_u64).unwrap_or(0) as u32;
        let hops: Vec<Hop> = match r.get("nexthops").and_then(Value::as_array) {
            Some(nh) => nh
                .iter()
                .map(|h| Hop {
                    via: s(h, "gateway"),
                    dev: s(h, "dev"),
                    weight: h.get("weight").and_then(Value::as_u64).unwrap_or(1) as u32,
                })
                .collect(),
            None => vec![Hop {
                via: s(r, "gateway"),
                dev: s(r, "dev"),
                weight: 1,
            }],
        };
        // `table all` listings name the table of every non-main route
        let table = match r.get("table") {
            Some(Value::Number(n)) => n.as_u64().map(|n| n as u32).unwrap_or(table),
            Some(Value::String(t)) if t == "main" => MAIN_TABLE,
            Some(Value::String(t)) => t.parse().unwrap_or(table),
            _ => table,
        };
        let k = KRoute {
            v6,
            dst: norm_dst(&dst, v6),
            metric,
            proto: proto.to_string(),
            table,
            hops,
        };
        // older iproute2 prints an IPv6 multipath route as one entry per hop
        match out.iter_mut().find(|o| o.key() == k.key()) {
            Some(o) => o.hops.extend(k.hops),
            None => out.push(k),
        }
    }
    Ok(out)
}

/// What the routes phase wants in the kernel.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Desired {
    pub routes: Vec<KRoute>,
    pub warnings: Vec<String>,
    /// Per family: what the default route is via (for status / UI).
    pub default_hops: BTreeMap<String, Vec<String>>,
}

fn hop_for(name: &str, res: &Resolved, weight: u32) -> Option<Hop> {
    if !res.routable() {
        return None;
    }
    let _ = name;
    Some(Hop {
        via: res.address.map(|a| a.to_string()),
        dev: res.dev.clone(),
        weight,
    })
}

/// Members of `g` that carry traffic now: the lowest tier with a usable
/// member (empty when every member is down).
pub fn select_members<'a>(
    g: &'a GatewayGroup,
    resolved: &BTreeMap<String, Resolved>,
    status: &BTreeMap<String, GwStatus>,
) -> Vec<&'a Member> {
    let tiers: BTreeSet<u32> = g.members.iter().map(|m| m.tier).collect();
    for t in tiers {
        let up: Vec<&Member> = g
            .members
            .iter()
            .filter(|m| m.tier == t)
            .filter(|m| {
                resolved
                    .get(&m.gateway)
                    .is_some_and(|r| usable(effective(&m.gateway, r, status), g.trigger))
            })
            .collect();
        if !up.is_empty() {
            return up;
        }
    }
    Vec::new()
}

/// Compute the desired routes from the config, resolved gateways, monitor
/// results and the devices static-route interface specs resolve to.
pub fn desired(
    cfg: &RoutingConfig,
    resolved: &BTreeMap<String, Resolved>,
    status: &BTreeMap<String, GwStatus>,
    iface_devs: &BTreeMap<String, Option<String>>,
) -> Desired {
    let mut d = Desired::default();
    // default route per family
    for fam in [Family::Inet, Family::Inet6] {
        let Some(name) = cfg.default_for(fam) else {
            continue;
        };
        let fam_name = if fam.v6() { "IPv6" } else { "IPv4" };
        let hops: Vec<(String, Hop)> = if let Some(g) = cfg.gateway(name) {
            match resolved.get(name).and_then(|r| hop_for(name, r, 1)) {
                Some(h) if g.family == fam => vec![(name.to_string(), h)],
                Some(_) => {
                    d.warnings.push(format!(
                        "default {fam_name} gateway {name} is not an {fam_name} gateway"
                    ));
                    vec![]
                }
                None => {
                    d.warnings.push(format!(
                        "default {fam_name} gateway {name} cannot be used: {}",
                        resolved
                            .get(name)
                            .and_then(|r| r.problem.clone())
                            .unwrap_or_else(|| "not resolved".into())
                    ));
                    vec![]
                }
            }
        } else if let Some(g) = cfg.group(name) {
            if !MULTIWAN {
                d.warnings.push(format!(
                    "default {fam_name} gateway {name} is a gateway group; this Patronus is built without multi-WAN (USE=multiwan)"
                ));
                vec![]
            } else {
                let sel = select_members(g, resolved, status);
                if sel.is_empty() {
                    d.warnings.push(format!(
                        "every member of gateway group {name} is down; the interfaces' own default routes apply"
                    ));
                }
                sel.into_iter()
                    .filter_map(|m| {
                        resolved
                            .get(&m.gateway)
                            .and_then(|r| hop_for(&m.gateway, r, m.weight))
                            .map(|h| (m.gateway.clone(), h))
                    })
                    .collect()
            }
        } else {
            d.warnings
                .push(format!("default {fam_name} gateway {name} does not exist"));
            vec![]
        };
        if !hops.is_empty() {
            d.default_hops.insert(
                fam.as_str().into(),
                hops.iter().map(|(n, _)| n.clone()).collect(),
            );
            d.routes.push(KRoute {
                v6: fam.v6(),
                dst: "default".into(),
                metric: DEFAULT_METRIC,
                proto: DEFAULT_PROTO.into(),
                table: DEFAULT_TABLE,
                hops: hops.into_iter().map(|(_, h)| h).collect(),
            });
        }
    }
    // policy routing: one table per gateway / group, numbered like its mark
    for g in &cfg.gateways {
        let (Some(&mark), Some(h)) = (
            cfg.marks.get(&g.name),
            resolved.get(&g.name).and_then(|r| hop_for(&g.name, r, 1)),
        ) else {
            continue;
        };
        d.routes.push(KRoute {
            v6: g.family.v6(),
            dst: "default".into(),
            metric: DEFAULT_METRIC,
            proto: DEFAULT_PROTO.into(),
            table: mark,
            hops: vec![h],
        });
    }
    if MULTIWAN {
        for g in &cfg.groups {
            let (Some(&mark), Some(fam)) = (cfg.marks.get(&g.name), group_family(cfg, g)) else {
                continue;
            };
            let hops: Vec<Hop> = select_members(g, resolved, status)
                .into_iter()
                .filter_map(|m| {
                    resolved
                        .get(&m.gateway)
                        .and_then(|r| hop_for(&m.gateway, r, m.weight))
                })
                .collect();
            if hops.is_empty() {
                continue;
            }
            d.routes.push(KRoute {
                v6: fam.v6(),
                dst: "default".into(),
                metric: DEFAULT_METRIC,
                proto: DEFAULT_PROTO.into(),
                table: mark,
                hops,
            });
        }
    }
    // monitor host routes: probes for a monitor IP leave via that gateway
    for g in &cfg.gateways {
        let (Some(mon), Some(r)) = (g.monitor_ip, resolved.get(&g.name)) else {
            continue;
        };
        if !g.monitor_enabled || !r.routable() || Some(mon) == r.address {
            continue;
        }
        d.routes.push(KRoute {
            v6: g.family.v6(),
            dst: host_net(&mon),
            metric: 0,
            proto: MONITOR_PROTO.into(),
            table: MAIN_TABLE,
            hops: vec![Hop {
                via: r.address.map(|a| a.to_string()),
                dev: r.dev.clone(),
                weight: 1,
            }],
        });
    }
    // static routes
    for r in cfg.routes.iter().filter(|r| r.enabled) {
        let v6 = r.destination.is_ipv6();
        let mut hop = Hop {
            via: None,
            dev: None,
            weight: 1,
        };
        if let Some(spec) = &r.interface {
            match iface_devs.get(spec).cloned().flatten() {
                Some(dev) => hop.dev = Some(dev),
                None => {
                    d.warnings.push(format!(
                        "static route {}: interface {spec} is not assigned; skipped",
                        r.destination
                    ));
                    continue;
                }
            }
        }
        match &r.gateway {
            None => {}
            Some(g) if g.parse::<IpAddr>().is_ok() => hop.via = Some(g.clone()),
            Some(name) => match resolved.get(name) {
                Some(res) if res.routable() => {
                    hop.via = res.address.map(|a| a.to_string());
                    if hop.dev.is_none() {
                        hop.dev = res.dev.clone();
                    }
                }
                _ => {
                    d.warnings.push(format!(
                        "static route {}: gateway {name} cannot be used now ({}); skipped",
                        r.destination,
                        resolved
                            .get(name)
                            .and_then(|x| x.problem.clone())
                            .unwrap_or_else(|| "it does not exist".into())
                    ));
                    continue;
                }
            },
        }
        let route = KRoute {
            v6,
            dst: r.destination.to_string(),
            metric: r.metric.unwrap_or(0),
            proto: STATIC_PROTO.into(),
            table: MAIN_TABLE,
            hops: vec![hop],
        };
        if d.routes.iter().any(|o| o.key() == route.key()) {
            d.warnings.push(format!(
                "static route {}: duplicate destination and metric; skipped",
                r.destination
            ));
            continue;
        }
        d.routes.push(route);
    }
    d
}

/// The `ip` calls that turn `have` (our routes in the kernel) into `want`:
/// replacements first (no gap while a default route moves), then removals.
pub fn diff(want: &[KRoute], have: &[KRoute]) -> Vec<Vec<String>> {
    let mut ops = Vec::new();
    for w in want {
        if !have.iter().any(|h| w.satisfied_by(h)) {
            ops.push(w.replace_args());
        }
    }
    for h in have {
        // a wanted route with the same key replaces it in place
        if !want.iter().any(|w| w.key() == h.key()) {
            ops.push(h.delete_args());
        }
    }
    ops
}

/// A routing policy rule in Patronus' priority range, as the kernel lists
/// it or as wanted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KRule {
    pub v6: bool,
    pub pref: u32,
    /// Table name or number (`main`, `4250`, `65537`).
    pub table: String,
    pub suppress: Option<u64>,
    pub fwmark: Option<u32>,
}

impl KRule {
    fn add_args(&self) -> Vec<String> {
        let mut a = argv(&[
            if self.v6 { "-6" } else { "-4" },
            "rule",
            "add",
            "pref",
            &self.pref.to_string(),
        ]);
        if let Some(m) = self.fwmark {
            a.extend(argv(&["fwmark", &format!("{m:#x}")]));
        }
        a.extend(argv(&["lookup", &self.table]));
        if let Some(sp) = self.suppress {
            a.extend(argv(&["suppress_prefixlength", &sp.to_string()]));
        }
        a
    }
}

/// Parse `ip -j rule show`, keeping only the priorities Patronus owns.
pub fn parse_rules(json: &str, v6: bool) -> Result<Vec<KRule>> {
    if json.trim().is_empty() {
        return Ok(Vec::new());
    }
    let v: Vec<Value> = serde_json::from_str(json)
        .map_err(|e| Error::Network(format!("parse `ip -j rule`: {e}")))?;
    Ok(v.iter()
        .filter_map(|r| {
            let pref = r.get("priority").and_then(Value::as_u64)? as u32;
            if !RULE_PREFS.contains(&pref) {
                return None;
            }
            Some(KRule {
                v6,
                pref,
                table: match r.get("table") {
                    Some(Value::String(t)) => t.clone(),
                    Some(Value::Number(n)) => n.to_string(),
                    _ => String::new(),
                },
                suppress: r
                    .get("suppress_prefixlen")
                    .or_else(|| r.get("suppress_prefixlength"))
                    .and_then(Value::as_u64),
                fwmark: match r.get("fwmark") {
                    Some(Value::String(m)) => m
                        .strip_prefix("0x")
                        .and_then(|h| u32::from_str_radix(h, 16).ok())
                        .or_else(|| m.parse().ok()),
                    Some(Value::Number(n)) => n.as_u64().map(|n| n as u32),
                    _ => None,
                },
            })
        })
        .collect())
}

/// The policy rules the desired routes need, per family: the main-table
/// rule ahead of everything else, one fwmark rule per policy table, then
/// the default-gateway table.
pub fn wanted_rules(d: &Desired) -> Vec<KRule> {
    let mut out = Vec::new();
    for v6 in [false, true] {
        let mut tables: Vec<u32> = d
            .routes
            .iter()
            .filter(|r| r.v6 == v6 && r.table != MAIN_TABLE && r.table != DEFAULT_TABLE)
            .map(|r| r.table)
            .collect();
        tables.sort();
        tables.dedup();
        let default = d
            .routes
            .iter()
            .any(|r| r.v6 == v6 && r.table == DEFAULT_TABLE);
        if tables.is_empty() && !default {
            continue;
        }
        out.push(KRule {
            v6,
            pref: RULE_PREF_MAIN,
            table: "main".into(),
            suppress: Some(0),
            fwmark: None,
        });
        for (i, t) in tables.into_iter().enumerate() {
            let pref = RULE_PREF_POLICY + i as u32;
            if pref >= RULE_PREF_TABLE {
                break;
            }
            out.push(KRule {
                v6,
                pref,
                table: t.to_string(),
                suppress: None,
                fwmark: Some(t),
            });
        }
        if default {
            out.push(KRule {
                v6,
                pref: RULE_PREF_TABLE,
                table: DEFAULT_TABLE.to_string(),
                suppress: None,
                fwmark: None,
            });
        }
    }
    out
}

/// The `ip rule` calls that turn `have` (rules in Patronus' priority range)
/// into `want`.
pub fn rule_ops(want: &[KRule], have: &[KRule]) -> Vec<Vec<String>> {
    let mut ops = Vec::new();
    for v6 in [false, true] {
        let fam = if v6 { "-6" } else { "-4" };
        let prefs: BTreeSet<u32> = want
            .iter()
            .chain(have.iter())
            .filter(|r| r.v6 == v6)
            .map(|r| r.pref)
            .collect();
        for pref in prefs {
            let w = want.iter().find(|r| r.v6 == v6 && r.pref == pref);
            let mine: Vec<&KRule> = have
                .iter()
                .filter(|r| r.v6 == v6 && r.pref == pref)
                .collect();
            if let Some(w) = w {
                if mine.len() == 1 && mine[0] == w {
                    continue;
                }
            }
            for _ in &mine {
                ops.push(argv(&[fam, "rule", "del", "pref", &pref.to_string()]));
            }
            if let Some(w) = w {
                ops.push(w.add_args());
            }
        }
    }
    ops
}

// ===========================================================================
// applier
// ===========================================================================

/// The routes phase.
pub struct RoutesApplier {
    cmd: Arc<dyn Cmd>,
    proc_sys: PathBuf,
    status_override: Option<BTreeMap<String, GwStatus>>,
    lock: tokio::sync::Mutex<()>,
}

impl Default for RoutesApplier {
    fn default() -> Self {
        Self::new(Arc::new(SystemCmd), PathBuf::from("/proc/sys"))
    }
}

impl RoutesApplier {
    pub fn new(cmd: Arc<dyn Cmd>, proc_sys: PathBuf) -> Self {
        Self {
            cmd,
            proc_sys,
            status_override: None,
            lock: tokio::sync::Mutex::new(()),
        }
    }

    /// Fixed monitor results (tests).
    pub fn with_status(mut self, st: BTreeMap<String, GwStatus>) -> Self {
        self.status_override = Some(st);
        self
    }

    fn status_now(&self) -> BTreeMap<String, GwStatus> {
        self.status_override
            .clone()
            .or_else(current_status)
            .unwrap_or_default()
    }

    async fn kernel(&self) -> Result<KernelState> {
        KernelState::read(self.cmd.as_ref()).await
    }

    async fn owned_routes(&self) -> Result<Vec<KRoute>> {
        let mut v = Vec::new();
        for (v6, fam) in [(false, "-4"), (true, "-6")] {
            // default routes live in the default-gateway and policy tables
            for (p, table) in [
                (STATIC_PROTO, "main"),
                (MONITOR_PROTO, "main"),
                (DEFAULT_PROTO, "all"),
            ] {
                let out = self
                    .cmd
                    .run(
                        "ip",
                        &argv(&["-j", fam, "route", "show", "table", table, "proto", p]),
                    )
                    .await;
                match out {
                    Ok(o) => v.extend(parse_owned(&o, v6, p, MAIN_TABLE)?),
                    // our table is only created with the first default route
                    Err(e) if e.to_string().contains("table does not exist") => {}
                    // IPv6 disabled on this box: nothing of ours there
                    Err(e) if v6 => tracing::debug!("ip -6 route: {e}"),
                    Err(e) => return Err(e),
                }
            }
        }
        Ok(v)
    }

    async fn owned_rules(&self) -> Result<Vec<KRule>> {
        let mut v = Vec::new();
        for (v6, fam) in [(false, "-4"), (true, "-6")] {
            match self
                .cmd
                .run("ip", &argv(&["-j", fam, "rule", "show"]))
                .await
            {
                Ok(o) => v.extend(parse_rules(&o, v6)?),
                Err(e) if v6 => tracing::debug!("ip -6 rule: {e}"),
                Err(e) => return Err(e),
            }
        }
        Ok(v)
    }

    async fn plan(
        &self,
        store: &ConfigStore,
    ) -> Result<(RoutingConfig, Desired, BTreeMap<String, Resolved>)> {
        let cfg = load(store).await?;
        // nothing configured: no need to read the kernel (or have `ip`)
        let k = if cfg.gateways.is_empty() && cfg.routes.is_empty() {
            KernelState::default()
        } else {
            self.kernel().await?
        };
        let resolved = resolve_all(store, &cfg, &k).await?;
        let mut iface_devs = BTreeMap::new();
        for r in &cfg.routes {
            if let Some(spec) = &r.interface {
                let devs = resolve_iface(store, spec).await?;
                iface_devs.insert(spec.clone(), devs.into_iter().next());
            }
        }
        let st = self.status_now();
        let d = desired(&cfg, &resolved, &st, &iface_devs);
        Ok((cfg, d, resolved))
    }

    /// Load balancing spreads flows by ports too, not only by address pair
    /// (one client talking to one server would otherwise never spread).
    fn multipath_hashing(&self, d: &Desired, rep: &mut ApplyReport) {
        // With two or more uplinks (load balancing or policy routing) a
        // flow's replies come back on the uplink it left by, which is not
        // always the one the main default route names: strict
        // reverse-path filtering would drop them.
        let devs: BTreeSet<&str> = d
            .routes
            .iter()
            .filter(|r| r.table != MAIN_TABLE && !r.v6)
            .flat_map(|r| r.hops.iter().filter_map(|h| h.dev.as_deref()))
            .collect();
        if devs.len() >= 2 {
            for dev in devs {
                let p = self.proc_sys.join(format!("net/ipv4/conf/{dev}/rp_filter"));
                if std::fs::read_to_string(&p)
                    .map(|s| s.trim() == "1")
                    .unwrap_or(false)
                {
                    match std::fs::write(&p, "2") {
                        Ok(()) => {
                            rep.applied(format!("{dev}: loose reverse-path filter (rp_filter=2)"))
                        }
                        Err(e) => rep.warn(format!("{}: {e}", p.display())),
                    }
                }
            }
        }
        for (fam, p) in self.multipath_hash_paths(d) {
            if std::fs::read_to_string(&p)
                .map(|s| s.trim() == "1")
                .unwrap_or(false)
            {
                continue;
            }
            match std::fs::write(&p, "1") {
                Ok(()) => rep.applied(format!(
                    "{fam} multipath hashing by ports (fib_multipath_hash_policy=1)"
                )),
                Err(e) => rep.warn(hash_policy_warning(
                    fam,
                    &format!("writing {} failed: {e}", p.display()),
                )),
            }
        }
    }

    /// `fib_multipath_hash_policy` of every family that has a load-balanced
    /// (multi-nexthop) route in `d`, where the kernel has the setting.
    fn multipath_hash_paths(&self, d: &Desired) -> Vec<(&'static str, std::path::PathBuf)> {
        let mut v = Vec::new();
        for (fam, v6) in [("ipv4", false), ("ipv6", true)] {
            if !d.routes.iter().any(|r| r.v6 == v6 && r.hops.len() > 1) {
                continue;
            }
            let p = self
                .proc_sys
                .join(format!("net/{fam}/fib_multipath_hash_policy"));
            if p.exists() {
                v.push((fam, p));
            }
        }
        v
    }

    /// Load balancing whose port hashing is not in effect -- e.g. a
    /// container without the sysctl, where /proc/sys is read-only and the
    /// apply could not set it. Read on every status so the Routing page and
    /// GET /api/routing say so instead of only the apply report.
    pub(crate) fn multipath_hash_warnings(&self, d: &Desired) -> Vec<String> {
        self.multipath_hash_paths(d)
            .into_iter()
            .filter_map(|(fam, p)| match std::fs::read_to_string(&p) {
                Ok(v) if v.trim() == "1" => None,
                Ok(v) => Some(hash_policy_warning(fam, &format!("it is {}", v.trim()))),
                Err(e) => Some(hash_policy_warning(
                    fam,
                    &format!("reading {} failed: {e}", p.display()),
                )),
            })
            .collect()
    }
}

/// The warning for load balancing without port hashing (`why`: what went
/// wrong), naming how to fix it where Patronus cannot (containers).
pub fn hash_policy_warning(fam: &str, why: &str) -> String {
    format!(
        "load balancing spreads flows by address pair only (one client talking to one \
         server always uses the same uplink): net.{fam}.fib_multipath_hash_policy should \
         be 1 but {why}; in a container set it with `--sysctl \
         net.{fam}.fib_multipath_hash_policy=1` (docker-compose.yml `sysctls:`)"
    )
}

#[async_trait]
impl Applier for RoutesApplier {
    fn name(&self) -> &'static str {
        "routes"
    }

    fn phase(&self) -> Phase {
        Phase::Routes
    }

    async fn apply(&self, store: &ConfigStore) -> Result<ApplyReport> {
        let _g = self.lock.lock().await;
        let (_cfg, d, _) = self.plan(store).await?;
        let have = self.owned_routes().await?;
        let mut rep = ApplyReport::default();
        for w in &d.warnings {
            rep.warn(w.clone());
        }
        let rules = self.owned_rules().await?;
        let mut failed = Vec::new();
        let ops = diff(&d.routes, &have)
            .into_iter()
            .chain(rule_ops(&wanted_rules(&d), &rules));
        for op in ops {
            match self.cmd.run("ip", &op).await {
                Ok(_) => rep.applied(format!("ip {}", op.join(" "))),
                Err(e) => {
                    // "No such process" / "No such file": already gone
                    let msg = e.to_string();
                    if op.get(2).map(String::as_str) == Some("del")
                        && (msg.contains("No such process") || msg.contains("No such file"))
                    {
                        continue;
                    }
                    failed.push(msg);
                }
            }
        }
        self.multipath_hashing(&d, &mut rep);
        if rep.applied.is_empty() && failed.is_empty() {
            rep.applied(format!("routes up to date ({} managed)", d.routes.len()));
        }
        if !failed.is_empty() {
            return Err(Error::Network(format!("routes: {}", failed.join("; "))));
        }
        Ok(rep)
    }

    async fn render(&self, store: &ConfigStore) -> Result<String> {
        let cfg = load(store).await?;
        let mut out = String::new();
        // dry run: resolve against the live kernel when it can be read
        let k = self.kernel().await.unwrap_or_default();
        let resolved = resolve_all(store, &cfg, &k).await?;
        let mut iface_devs = BTreeMap::new();
        for r in &cfg.routes {
            if let Some(spec) = &r.interface {
                let devs = resolve_iface(store, spec).await?;
                iface_devs.insert(spec.clone(), devs.into_iter().next());
            }
        }
        let d = desired(&cfg, &resolved, &self.status_now(), &iface_devs);
        for r in &d.routes {
            out.push_str(&format!("ip {}\n", r.replace_args().join(" ")));
        }
        for op in rule_ops(&wanted_rules(&d), &[]) {
            out.push_str(&format!("ip {}\n", op.join(" ")));
        }
        for w in &d.warnings {
            out.push_str(&format!("# warning: {w}\n"));
        }
        if d.routes.is_empty() && d.warnings.is_empty() {
            out.push_str("# no static routes, no default gateway set (automatic)\n");
        }
        Ok(out)
    }

    async fn status(&self, store: &ConfigStore) -> Result<Value> {
        let (cfg, d, resolved) = self.plan(store).await?;
        let st = self.status_now();
        let gateways: Vec<Value> = cfg
            .gateways
            .iter()
            .map(|g| {
                let r = resolved.get(&g.name).cloned().unwrap_or_default();
                let s = st.get(&g.name);
                let state = if !g.monitor_enabled && r.routable() && r.link_up {
                    GwState::Unmonitored
                } else {
                    effective(&g.name, &r, &st)
                };
                json!({
                    "name": g.name,
                    "interface": g.interface,
                    "family": g.family.as_str(),
                    "address": g.address.map(|a| a.to_string()),
                    "dynamic": g.address.is_none(),
                    "monitor_ip": g.monitor_ip.map(|a| a.to_string()),
                    "monitor_enabled": g.monitor_enabled,
                    "loss_threshold": g.loss_threshold,
                    "latency_threshold": g.latency_threshold,
                    "description": g.description,
                    "dev": r.dev,
                    "resolved_address": r.address.map(|a| a.to_string()),
                    "ptp": r.ptp,
                    "link_up": r.link_up,
                    "problem": r.problem,
                    "state": state,
                    "loss_pct": s.map(|s| s.loss_pct),
                    "rtt_ms": s.and_then(|s| s.rtt_ms),
                    "since": s.map(|s| s.since),
                    "detail": s.and_then(|s| s.detail.clone()),
                })
            })
            .collect();
        let groups: Vec<Value> = cfg
            .groups
            .iter()
            .map(|g| {
                let active: BTreeSet<String> = select_members(g, &resolved, &st)
                    .into_iter()
                    .map(|m| m.gateway.clone())
                    .collect();
                json!({
                    "name": g.name,
                    "trigger": g.trigger.as_str(),
                    "description": g.description,
                    "members": g.members.iter().map(|m| {
                        let state = resolved.get(&m.gateway).map(|r| effective(&m.gateway, r, &st));
                        json!({
                            "gateway": m.gateway, "tier": m.tier, "weight": m.weight,
                            "state": state,
                            "usable": state.is_some_and(|s| usable(s, g.trigger)),
                            "active": active.contains(&m.gateway),
                        })
                    }).collect::<Vec<_>>(),
                })
            })
            .collect();
        Ok(json!({
            "multiwan": MULTIWAN,
            // results from a monitor in this process or a fresh status file
            "monitor_running": self.status_override.is_some() || current_status().is_some(),
            "gateways": gateways,
            "groups": groups,
            "default4": cfg.default4,
            "default6": cfg.default6,
            "default_via": d.default_hops,
            "warnings": d
                .warnings
                .iter()
                .cloned()
                .chain(self.multipath_hash_warnings(&d))
                .collect::<Vec<_>>(),
            "routes": cfg.routes,
        }))
    }

    async fn teardown(&self) -> Result<()> {
        for op in rule_ops(&[], &self.owned_rules().await?) {
            self.cmd.run("ip", &op).await?;
        }
        for h in self.owned_routes().await? {
            self.cmd.run("ip", &h.delete_args()).await?;
        }
        Ok(())
    }

    fn resource_kinds(&self) -> &'static [ResourceKind] {
        &[ResourceKind::GatewayGroup]
    }

    async fn upsert_resource(&self, store: &ConfigStore, config: &DeclarativeConfig) -> Result<()> {
        let ResourceSpec::GatewayGroup(spec) = &config.spec else {
            return Err(Error::Config(format!(
                "routes: unexpected resource {:?}",
                config.kind
            )));
        };
        let g = GroupInput {
            name: config.metadata.name.clone(),
            trigger: None,
            members: MembersInput::List(
                spec.members
                    .iter()
                    .map(|m| Member {
                        gateway: m.gateway_name.clone(),
                        tier: m.tier as u32,
                        weight: m.weight,
                    })
                    .collect(),
            ),
            description: config.metadata.description.clone(),
        }
        .validated()?;
        let exists = name_taken(store, "route_gateway_groups", &g.name).await?;
        save_group(store, exists.then_some(g.name.as_str()), &g).await
    }

    async fn delete_resource(
        &self,
        store: &ConfigStore,
        kind: &ResourceKind,
        name: &str,
    ) -> Result<()> {
        match kind {
            ResourceKind::GatewayGroup => delete_group(store, name).await,
            k => Err(Error::Config(format!("routes: unexpected resource {k:?}"))),
        }
    }
}

// ===========================================================================
// monitor
// ===========================================================================

/// Sends one probe; `Some(rtt_ms)` on a reply.
#[async_trait]
pub trait Prober: Send + Sync {
    async fn probe(&self, dev: &str, target: IpAddr) -> Option<f64>;
}

/// `ping -c1 -W1 -I <dev>` (iputils or busybox).
pub struct PingProber;

/// The round trip of a ping reply line (`time=0.123 ms`).
pub fn parse_ping_rtt(out: &str) -> Option<f64> {
    let i = out.find("time=")?;
    let rest = &out[i + 5..];
    let end = rest
        .find(|c: char| !(c.is_ascii_digit() || c == '.'))
        .unwrap_or(rest.len());
    rest[..end].parse().ok()
}

#[async_trait]
impl Prober for PingProber {
    async fn probe(&self, dev: &str, target: IpAddr) -> Option<f64> {
        let fam = if target.is_ipv6() { "-6" } else { "-4" };
        let out = tokio::time::timeout(
            Duration::from_secs(3),
            tokio::process::Command::new("ping")
                .args([
                    fam,
                    "-n",
                    "-c",
                    "1",
                    "-W",
                    "1",
                    "-I",
                    dev,
                    &target.to_string(),
                ])
                .output(),
        )
        .await
        .ok()?
        .ok()?;
        if !out.status.success() {
            return None;
        }
        parse_ping_rtt(&String::from_utf8_lossy(&out.stdout)).or(Some(0.0))
    }
}

/// Per gateway: the (device, address) the samples belong to, and the
/// samples (`None` = lost).
type ProbeWindow = (
    Option<(Option<String>, Option<IpAddr>)>,
    VecDeque<Option<f64>>,
);

/// Gateway monitor: probes every gateway once a tick, publishes the states
/// and re-applies the routes phase when a state or address changes.
pub struct Monitor {
    applier: Arc<dyn Applier>,
    cmd: Arc<dyn Cmd>,
    prober: Arc<dyn Prober>,
    windows: BTreeMap<String, ProbeWindow>,
    states: BTreeMap<String, GwStatus>,
    last_sig: Option<String>,
    ticks: u64,
}

impl Monitor {
    pub fn new(applier: Arc<dyn Applier>, cmd: Arc<dyn Cmd>, prober: Arc<dyn Prober>) -> Self {
        Self {
            applier,
            cmd,
            prober,
            windows: BTreeMap::new(),
            states: BTreeMap::new(),
            last_sig: None,
            ticks: 0,
        }
    }

    /// The real monitor (ping + ip).
    pub fn system(applier: Arc<dyn Applier>) -> Self {
        Self::new(applier, Arc::new(SystemCmd), Arc::new(PingProber))
    }

    pub fn states(&self) -> &BTreeMap<String, GwStatus> {
        &self.states
    }

    /// One round: probe, evaluate, publish, re-apply on change. Returns
    /// whether the routes phase was applied.
    pub async fn tick(&mut self, store: &ConfigStore) -> Result<bool> {
        self.ticks += 1;
        let cfg = load(store).await?;
        if cfg.gateways.is_empty() {
            if !self.states.is_empty() || self.ticks == 1 {
                self.states.clear();
                self.windows.clear();
                publish(&self.states);
            }
            return Ok(false);
        }
        let k = KernelState::read(self.cmd.as_ref()).await?;
        let resolved = resolve_all(store, &cfg, &k).await?;
        let probes = cfg.gateways.iter().map(|g| {
            let r = resolved.get(&g.name).cloned().unwrap_or_default();
            let target = g.monitor_ip.or(r.address);
            let prober = self.prober.clone();
            let go = g.monitor_enabled && r.routable() && r.link_up && target.is_some();
            async move {
                if !go {
                    return (g.name.clone(), None);
                }
                let dev = r.dev.clone().unwrap_or_default();
                (
                    g.name.clone(),
                    Some(prober.probe(&dev, target.unwrap()).await),
                )
            }
        });
        let results: BTreeMap<String, Option<Option<f64>>> = futures::future::join_all(probes)
            .await
            .into_iter()
            .collect();
        let t = now();
        let mut next = BTreeMap::new();
        for g in &cfg.gateways {
            let r = resolved.get(&g.name).cloned().unwrap_or_default();
            let ident = Some((r.dev.clone(), r.address));
            let entry = self
                .windows
                .entry(g.name.clone())
                .or_insert_with(|| (ident.clone(), VecDeque::new()));
            if entry.0 != ident {
                // new device or address: old samples say nothing about it
                *entry = (ident.clone(), VecDeque::new());
            }
            let (state, loss, rtt, detail) = match results.get(&g.name).cloned().flatten() {
                Some(sample) => {
                    entry.1.push_back(sample);
                    while entry.1.len() > WINDOW {
                        entry.1.pop_front();
                    }
                    let (s, l, rt) = evaluate(&entry.1, g);
                    (s, l, rt, None)
                }
                None => {
                    entry.1.clear();
                    if !r.routable() {
                        (GwState::Down, 100, None, r.problem.clone())
                    } else if !r.link_up {
                        (
                            GwState::Down,
                            100,
                            None,
                            Some(format!(
                                "link {} is down",
                                r.dev.clone().unwrap_or_default()
                            )),
                        )
                    } else if !g.monitor_enabled {
                        (GwState::Unmonitored, 0, None, None)
                    } else {
                        (
                            GwState::Unmonitored,
                            0,
                            None,
                            Some("nothing to probe: set a monitor IP".into()),
                        )
                    }
                }
            };
            let since = match self.states.get(&g.name) {
                Some(prev) if prev.state == state => prev.since,
                _ => t,
            };
            if self.states.get(&g.name).map(|p| p.state) != Some(state) {
                tracing::info!(
                    "gateway {}: {:?} (loss {loss}%, rtt {:?} ms)",
                    g.name,
                    state,
                    rtt
                );
            }
            next.insert(
                g.name.clone(),
                GwStatus {
                    state,
                    loss_pct: loss,
                    rtt_ms: rtt.map(|r| (r * 1000.0).round() / 1000.0),
                    samples: entry.1.len() as u32,
                    detail,
                    since,
                },
            );
        }
        self.windows.retain(|n, _| next.contains_key(n));
        self.states = next;
        publish(&self.states);
        let sig = format!(
            "{:?}",
            cfg.gateways
                .iter()
                .map(|g| {
                    let r = resolved.get(&g.name);
                    (
                        &g.name,
                        r.map(|r| (r.dev.clone(), r.address, r.routable())),
                        self.states.get(&g.name).map(|s| s.state),
                    )
                })
                .collect::<Vec<_>>()
        );
        // re-apply on any change, and every 30 ticks to heal drift
        if self.last_sig.as_deref() != Some(&sig) || self.ticks.is_multiple_of(30) {
            self.last_sig = Some(sig);
            match self.applier.apply(store).await {
                Ok(r) => {
                    for l in r.applied.iter().filter(|l| l.starts_with("ip ")) {
                        tracing::info!("gateway monitor: {l}");
                    }
                }
                Err(e) => tracing::warn!("gateway monitor: applying routes: {e}"),
            }
            return Ok(true);
        }
        Ok(false)
    }

    /// Run forever, one tick a second.
    pub fn spawn(mut self, store: Arc<ConfigStore>) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut t = tokio::time::interval(Duration::from_secs(1));
            t.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                t.tick().await;
                if let Err(e) = self.tick(&store).await {
                    tracing::warn!("gateway monitor: {e}");
                }
            }
        })
    }
}

#[cfg(test)]
mod tests;
