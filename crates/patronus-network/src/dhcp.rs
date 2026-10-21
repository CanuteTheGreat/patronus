//! DHCP server (lane D): DHCPv4 pools with static mappings, DHCP relay,
//! DHCPv6 ([`crate::dhcp6`]) and router advertisements ([`crate::ra`]),
//! applied by one [`DhcpApplier`] because the daemons share state:
//!
//! | `dhcp.backend` | DHCPv4                                 | DHCPv6                                 | RA (`dhcp.ra_backend`) |
//! |----------------|----------------------------------------|----------------------------------------|------------------------|
//! | `kea`          | `kea-dhcp4`, `/etc/kea/kea-dhcp4.conf` | `kea-dhcp6`, `/etc/kea/kea-dhcp6.conf` | `radvd`, `/etc/radvd.conf` |
//! | `dnsmasq`      | `dnsmasq`, `/etc/dnsmasq.conf`         | same                                   | same (or radvd)        |
//!
//! `auto` picks Kea when `kea-dhcp4` is installed (USE=kea), else dnsmasq.
//! Relays always use dnsmasq's `dhcp-relay` (Kea has no relay agent).
//! Those are the files the Gentoo packages' OpenRC scripts and systemd
//! units read; the old code wrote `/etc/patronus/dhcp.conf`, which no
//! daemon ever read, and only knew `systemctl`.
//!
//! Leases are read from the daemon's own lease database
//! (`/var/lib/kea/kea-leases{4,6}.csv`, `/var/lib/misc/dnsmasq.leases`).

use crate::dhcp6::{self, Resolved6};
use crate::lan::{self, db_err, invalid, now, DnsmasqPart, IfAddr, LanEnv, ManagedFile};
use crate::ra::{self, ResolvedRa};
use async_trait::async_trait;
use patronus_config::applier::{Applier, ApplyReport, Phase};
use patronus_config::store::ConfigStore;
use patronus_core::{Error, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::Row;
use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr};

pub const KEA4_CONF: &str = "/etc/kea/kea-dhcp4.conf";
pub const KEA4_BIN: &str = "/usr/sbin/kea-dhcp4";
pub const KEA4_LEASES: &str = "/var/lib/kea/kea-leases4.csv";

// ---------------------------------------------------------------------------
// model
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct StaticMapping {
    pub id: i64,
    pub pool_id: i64,
    pub mac: String,
    pub ip: Ipv4Addr,
    pub hostname: Option<String>,
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DhcpPool {
    pub id: i64,
    pub interface: String,
    pub enabled: bool,
    pub range_start: Ipv4Addr,
    pub range_end: Ipv4Addr,
    pub lease_time: u32,
    pub gateway: Option<Ipv4Addr>,
    pub dns_servers: Vec<IpAddr>,
    pub domain: Option<String>,
    pub ntp_servers: Vec<IpAddr>,
    pub description: Option<String>,
    pub static_mappings: Vec<StaticMapping>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PoolInput {
    pub interface: String,
    #[serde(default = "yes")]
    pub enabled: bool,
    pub range_start: String,
    pub range_end: String,
    #[serde(default)]
    pub lease_time: Option<u32>,
    #[serde(default)]
    pub gateway: Option<String>,
    #[serde(default)]
    pub dns_servers: Option<String>,
    #[serde(default)]
    pub domain: Option<String>,
    #[serde(default)]
    pub ntp_servers: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
}

fn yes() -> bool {
    true
}

fn v4(what: &str, s: &str) -> Result<Ipv4Addr> {
    s.trim()
        .parse()
        .map_err(|_| invalid(format!("{what} {s:?} (an IPv4 address)")))
}

fn opt(s: &Option<String>) -> Option<&str> {
    s.as_deref().map(str::trim).filter(|s| !s.is_empty())
}

impl PoolInput {
    pub fn validate(&self) -> Result<DhcpPool> {
        let interface = lan::check_iface_spec(&self.interface)?;
        let range_start = v4("range start", &self.range_start)?;
        let range_end = v4("range end", &self.range_end)?;
        if u32::from(range_start) > u32::from(range_end) {
            return Err(invalid("range: start is after end"));
        }
        let lease_time = self.lease_time.unwrap_or(86400);
        if !(120..=31_536_000).contains(&lease_time) {
            return Err(invalid("lease time (120 s to 1 year)"));
        }
        Ok(DhcpPool {
            id: 0,
            interface,
            enabled: self.enabled,
            range_start,
            range_end,
            lease_time,
            gateway: opt(&self.gateway).map(|g| v4("gateway", g)).transpose()?,
            dns_servers: lan::parse_ip_list("DNS server", opt(&self.dns_servers).unwrap_or(""))?,
            domain: opt(&self.domain)
                .map(|d| lan::check_dns_name("domain", d))
                .transpose()?,
            ntp_servers: lan::parse_ip_list("NTP server", opt(&self.ntp_servers).unwrap_or(""))?,
            description: lan::check_description(self.description.as_deref())?,
            static_mappings: vec![],
        })
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StaticInput {
    pub mac: String,
    pub ip: String,
    #[serde(default)]
    pub hostname: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
}

impl StaticInput {
    pub fn validate(&self, pool: &DhcpPool) -> Result<StaticMapping> {
        let ip = v4("static mapping address", &self.ip)?;
        if (u32::from(pool.range_start)..=u32::from(pool.range_end)).contains(&u32::from(ip)) {
            // Kea and dnsmasq accept it, but it is the classic way to hand
            // one address out twice
            return Err(invalid(format!(
                "static mapping address {ip}: it is inside the dynamic range {}-{}",
                pool.range_start, pool.range_end
            )));
        }
        Ok(StaticMapping {
            id: 0,
            pool_id: pool.id,
            mac: lan::check_mac(&self.mac)?,
            ip,
            hostname: opt(&self.hostname)
                .map(|h| lan::check_label("hostname", h))
                .transpose()?,
            description: lan::check_description(self.description.as_deref())?,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DhcpRelay {
    pub id: i64,
    pub interface: String,
    pub enabled: bool,
    pub servers: Vec<IpAddr>,
    pub description: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RelayInput {
    pub interface: String,
    #[serde(default = "yes")]
    pub enabled: bool,
    pub servers: String,
    #[serde(default)]
    pub description: Option<String>,
}

impl RelayInput {
    pub fn validate(&self) -> Result<DhcpRelay> {
        let servers = lan::parse_ip_list("relay server", &self.servers)?;
        if servers.is_empty() {
            return Err(invalid("relay: at least one DHCP server address"));
        }
        if let Some(m) = servers
            .iter()
            .find(|a| a.is_multicast() || a.is_unspecified())
        {
            return Err(invalid(format!(
                "relay server {m}: give the DHCP server's unicast address"
            )));
        }
        Ok(DhcpRelay {
            id: 0,
            interface: lan::check_iface_spec(&self.interface)?,
            enabled: self.enabled,
            servers,
            description: lan::check_description(self.description.as_deref())?,
        })
    }
}

// ---------------------------------------------------------------------------
// store accessors
// ---------------------------------------------------------------------------

fn row_to_pool(r: &sqlx::sqlite::SqliteRow) -> Option<DhcpPool> {
    let list = |c: &str| {
        lan::parse_ip_list("", &r.get::<Option<String>, _>(c).unwrap_or_default())
            .unwrap_or_default()
    };
    Some(DhcpPool {
        id: r.get("id"),
        interface: r.get("interface"),
        enabled: r.get::<i64, _>("enabled") != 0,
        range_start: r.get::<String, _>("range_start").parse().ok()?,
        range_end: r.get::<String, _>("range_end").parse().ok()?,
        lease_time: r.get::<i64, _>("lease_time") as u32,
        gateway: r
            .get::<Option<String>, _>("gateway")
            .and_then(|g| g.parse().ok()),
        dns_servers: list("dns_servers"),
        domain: r.get("domain"),
        ntp_servers: list("ntp_servers"),
        description: r.get("description"),
        static_mappings: vec![],
    })
}

pub async fn list_pools(store: &ConfigStore) -> Result<Vec<DhcpPool>> {
    let rows = sqlx::query("SELECT * FROM dhcp_pools ORDER BY id")
        .fetch_all(store.pool()?)
        .await
        .map_err(db_err("load DHCP pools"))?;
    let mut pools: Vec<DhcpPool> = rows.iter().filter_map(row_to_pool).collect();
    let maps = sqlx::query("SELECT * FROM dhcp_static_mappings ORDER BY id")
        .fetch_all(store.pool()?)
        .await
        .map_err(db_err("load static mappings"))?;
    for m in &maps {
        let Ok(ip) = m.get::<String, _>("ip").parse() else {
            continue;
        };
        let sm = StaticMapping {
            id: m.get("id"),
            pool_id: m.get("pool_id"),
            mac: m.get("mac"),
            ip,
            hostname: m.get("hostname"),
            description: m.get("description"),
        };
        if let Some(p) = pools.iter_mut().find(|p| p.id == sm.pool_id) {
            p.static_mappings.push(sm);
        }
    }
    Ok(pools)
}

pub async fn get_pool(store: &ConfigStore, id: i64) -> Result<Option<DhcpPool>> {
    Ok(list_pools(store).await?.into_iter().find(|p| p.id == id))
}

pub async fn upsert_pool(store: &ConfigStore, id: Option<i64>, p: &DhcpPool) -> Result<i64> {
    let mut q = match id {
        None => sqlx::query(
            "INSERT INTO dhcp_pools (interface, enabled, range_start, range_end, lease_time,
             gateway, dns_servers, domain, ntp_servers, description, updated_at)
             VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        ),
        Some(_) => sqlx::query(
            "UPDATE dhcp_pools SET interface=?, enabled=?, range_start=?, range_end=?,
             lease_time=?, gateway=?, dns_servers=?, domain=?, ntp_servers=?, description=?,
             updated_at=? WHERE id=?",
        ),
    }
    .bind(&p.interface)
    .bind(p.enabled as i64)
    .bind(p.range_start.to_string())
    .bind(p.range_end.to_string())
    .bind(p.lease_time as i64)
    .bind(p.gateway.map(|g| g.to_string()))
    .bind(lan::join_ips(&p.dns_servers))
    .bind(&p.domain)
    .bind(lan::join_ips(&p.ntp_servers))
    .bind(&p.description)
    .bind(now());
    if let Some(i) = id {
        q = q.bind(i);
    }
    let what = format!("a DHCP pool on {}", p.interface);
    let res = q
        .execute(store.pool()?)
        .await
        .map_err(|e| lan::unique_err(e, &what))?;
    match id {
        Some(i) if res.rows_affected() == 0 => {
            Err(Error::Config(format!("DHCP pool {i} not found")))
        }
        Some(i) => Ok(i),
        None => Ok(res.last_insert_rowid()),
    }
}

pub async fn delete_pool(store: &ConfigStore, id: i64) -> Result<()> {
    let r = sqlx::query("DELETE FROM dhcp_pools WHERE id = ?")
        .bind(id)
        .execute(store.pool()?)
        .await
        .map_err(db_err("delete DHCP pool"))?;
    if r.rows_affected() == 0 {
        return Err(Error::Config(format!("DHCP pool {id} not found")));
    }
    Ok(())
}

pub async fn add_static(store: &ConfigStore, m: &StaticMapping) -> Result<i64> {
    let what = format!("a mapping for {} or {}", m.mac, m.ip);
    let res = sqlx::query(
        "INSERT INTO dhcp_static_mappings (pool_id, mac, ip, hostname, description, updated_at)
         VALUES (?,?,?,?,?,?)",
    )
    .bind(m.pool_id)
    .bind(&m.mac)
    .bind(m.ip.to_string())
    .bind(&m.hostname)
    .bind(&m.description)
    .bind(now())
    .execute(store.pool()?)
    .await
    .map_err(|e| lan::unique_err(e, &what))?;
    Ok(res.last_insert_rowid())
}

pub async fn delete_static(store: &ConfigStore, id: i64) -> Result<()> {
    let r = sqlx::query("DELETE FROM dhcp_static_mappings WHERE id = ?")
        .bind(id)
        .execute(store.pool()?)
        .await
        .map_err(db_err("delete static mapping"))?;
    if r.rows_affected() == 0 {
        return Err(Error::Config(format!("static mapping {id} not found")));
    }
    Ok(())
}

pub async fn list_relays(store: &ConfigStore) -> Result<Vec<DhcpRelay>> {
    let rows = sqlx::query("SELECT * FROM dhcp_relays ORDER BY id")
        .fetch_all(store.pool()?)
        .await
        .map_err(db_err("load DHCP relays"))?;
    Ok(rows
        .iter()
        .map(|r| DhcpRelay {
            id: r.get("id"),
            interface: r.get("interface"),
            enabled: r.get::<i64, _>("enabled") != 0,
            servers: lan::parse_ip_list("", &r.get::<String, _>("servers")).unwrap_or_default(),
            description: r.get("description"),
        })
        .collect())
}

pub async fn upsert_relay(store: &ConfigStore, id: Option<i64>, r: &DhcpRelay) -> Result<i64> {
    let mut q = match id {
        None => sqlx::query(
            "INSERT INTO dhcp_relays (interface, enabled, servers, description, updated_at)
             VALUES (?,?,?,?,?)",
        ),
        Some(_) => sqlx::query(
            "UPDATE dhcp_relays SET interface=?, enabled=?, servers=?, description=?, updated_at=?
             WHERE id=?",
        ),
    }
    .bind(&r.interface)
    .bind(r.enabled as i64)
    .bind(lan::join_ips(&r.servers))
    .bind(&r.description)
    .bind(now());
    if let Some(i) = id {
        q = q.bind(i);
    }
    let what = format!("a relay on {}", r.interface);
    let res = q
        .execute(store.pool()?)
        .await
        .map_err(|e| lan::unique_err(e, &what))?;
    match id {
        Some(i) if res.rows_affected() == 0 => Err(Error::Config(format!("relay {i} not found"))),
        Some(i) => Ok(i),
        None => Ok(res.last_insert_rowid()),
    }
}

pub async fn delete_relay(store: &ConfigStore, id: i64) -> Result<()> {
    let r = sqlx::query("DELETE FROM dhcp_relays WHERE id = ?")
        .bind(id)
        .execute(store.pool()?)
        .await
        .map_err(db_err("delete relay"))?;
    if r.rows_affected() == 0 {
        return Err(Error::Config(format!("relay {id} not found")));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// backends
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Backend {
    Kea,
    Dnsmasq,
}

impl Backend {
    pub fn as_str(&self) -> &'static str {
        match self {
            Backend::Kea => "kea",
            Backend::Dnsmasq => "dnsmasq",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum RaBackend {
    Radvd,
    Dnsmasq,
}

/// Daemons installed on this box (what USE flags pulled in).
pub fn available(env: &LanEnv) -> BTreeMap<&'static str, bool> {
    BTreeMap::from([
        ("kea", env.has_binary(KEA4_BIN)),
        ("dnsmasq", env.has_binary(lan::DNSMASQ_BIN)),
        ("radvd", env.has_binary(ra::RADVD_BIN)),
    ])
}

pub async fn backend(store: &ConfigStore, env: &LanEnv) -> Result<Backend> {
    let want = lan::setting_or(store, "dhcp.backend", "auto").await?;
    Ok(match want.as_str() {
        "kea" => Backend::Kea,
        "dnsmasq" => Backend::Dnsmasq,
        _ if env.has_binary(KEA4_BIN) => Backend::Kea,
        _ => Backend::Dnsmasq,
    })
}

pub async fn ra_backend(store: &ConfigStore, env: &LanEnv, b: Backend) -> Result<RaBackend> {
    let want = lan::setting_or(store, "dhcp.ra_backend", "auto").await?;
    Ok(match want.as_str() {
        "radvd" => RaBackend::Radvd,
        "dnsmasq" => RaBackend::Dnsmasq,
        _ if b == Backend::Dnsmasq && env.has_binary(lan::DNSMASQ_BIN) => RaBackend::Dnsmasq,
        _ if env.has_binary(ra::RADVD_BIN) => RaBackend::Radvd,
        _ => RaBackend::Dnsmasq,
    })
}

pub fn check_backend_setting(v: &str, allowed: &[&str]) -> Result<String> {
    let v = v.trim().to_ascii_lowercase();
    if allowed.contains(&v.as_str()) {
        Ok(v)
    } else {
        Err(invalid(format!("backend {v:?} ({})", allowed.join(", "))))
    }
}

// ---------------------------------------------------------------------------
// resolution: pools -> devices + router addresses
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct Resolved4 {
    pub pool: DhcpPool,
    pub dev: String,
    pub router: Ipv4Addr,
    pub prefix: u8,
    pub subnet: String,
}

impl Resolved4 {
    fn netmask(&self) -> Ipv4Addr {
        Ipv4Addr::from(u32::MAX.checked_shl(32 - self.prefix as u32).unwrap_or(0))
    }
}

pub async fn resolve_pools(
    store: &ConfigStore,
    addrs: &[IfAddr],
    rep: &mut ApplyReport,
) -> Result<Vec<Resolved4>> {
    let mut out = Vec::new();
    for p in list_pools(store).await?.into_iter().filter(|p| p.enabled) {
        let devs = lan::resolve_iface(store, &p.interface).await?;
        if devs.is_empty() {
            rep.warn(format!(
                "DHCP pool on {}: interface role is not assigned, skipped",
                p.interface
            ));
            continue;
        }
        let hit = addrs.iter().find(|a| {
            devs.contains(&a.ifname)
                && a.addr.is_ipv4()
                && a.network().is_some_and(|n| {
                    n.contains(IpAddr::V4(p.range_start)) && n.contains(IpAddr::V4(p.range_end))
                })
        });
        match hit {
            Some(a) => {
                let IpAddr::V4(router) = a.addr else { continue };
                if (u32::from(p.range_start)..=u32::from(p.range_end)).contains(&u32::from(router))
                {
                    rep.warn(format!(
                        "DHCP pool on {}: the range contains the router's own address {router}",
                        a.ifname
                    ));
                }
                out.push(Resolved4 {
                    subnet: a.network().map(|n| n.to_string()).unwrap_or_default(),
                    dev: a.ifname.clone(),
                    router,
                    prefix: a.prefix,
                    pool: p,
                });
            }
            None => rep.warn(format!(
                "DHCP pool {}-{} on {}: no IPv4 address on {} covers that range, skipped",
                p.range_start,
                p.range_end,
                p.interface,
                devs.join(",")
            )),
        }
    }
    Ok(out)
}

/// Options a pool hands out (explicit, or the router itself when that
/// service runs).
struct Options4 {
    gateway: Ipv4Addr,
    dns: Vec<Ipv4Addr>,
    ntp: Vec<Ipv4Addr>,
}

fn v4s(v: &[IpAddr]) -> Vec<Ipv4Addr> {
    v.iter()
        .filter_map(|a| match a {
            IpAddr::V4(x) => Some(*x),
            _ => None,
        })
        .collect()
}

fn options4(r: &Resolved4, dns_on: bool, ntp_on: bool) -> Options4 {
    let dns = v4s(&r.pool.dns_servers);
    let ntp = v4s(&r.pool.ntp_servers);
    Options4 {
        gateway: r.pool.gateway.unwrap_or(r.router),
        dns: if dns.is_empty() && dns_on {
            vec![r.router]
        } else {
            dns
        },
        ntp: if ntp.is_empty() && ntp_on {
            vec![r.router]
        } else {
            ntp
        },
    }
}

async fn service_flags(store: &ConfigStore, env: &LanEnv) -> Result<(bool, bool)> {
    #[cfg(feature = "dns")]
    let dns_on = crate::dns::dns_enabled(store, env).await?;
    #[cfg(not(feature = "dns"))]
    let dns_on = {
        let _ = env;
        false
    };
    let ntp_on =
        cfg!(feature = "ntp") && lan::flag(&lan::setting_or(store, "ntp.enabled", "0").await?);
    Ok((dns_on, ntp_on))
}

// ---------------------------------------------------------------------------
// rendering
// ---------------------------------------------------------------------------

fn ip_join(v: &[Ipv4Addr], sep: &str) -> String {
    v.iter()
        .map(|a| a.to_string())
        .collect::<Vec<_>>()
        .join(sep)
}

/// `/etc/kea/kea-dhcp4.conf`.
pub fn render_kea4(pools: &[Resolved4], dns_on: bool, ntp_on: bool) -> String {
    let mut ifaces: Vec<&str> = pools.iter().map(|r| r.dev.as_str()).collect();
    ifaces.sort();
    ifaces.dedup();
    let subnets: Vec<Value> = pools
        .iter()
        .map(|r| {
            let o = options4(r, dns_on, ntp_on);
            let mut opts = vec![json!({"name": "routers", "data": o.gateway.to_string()})];
            if !o.dns.is_empty() {
                opts.push(json!({"name": "domain-name-servers", "data": ip_join(&o.dns, ", ")}));
            }
            if !o.ntp.is_empty() {
                opts.push(json!({"name": "ntp-servers", "data": ip_join(&o.ntp, ", ")}));
            }
            if let Some(d) = &r.pool.domain {
                opts.push(json!({"name": "domain-name", "data": d}));
            }
            let reservations: Vec<Value> = r
                .pool
                .static_mappings
                .iter()
                .map(|m| {
                    let mut v = json!({"hw-address": m.mac, "ip-address": m.ip.to_string()});
                    if let Some(h) = &m.hostname {
                        v["hostname"] = json!(h);
                    }
                    v
                })
                .collect();
            json!({
                "id": r.pool.id,
                "subnet": r.subnet,
                "interface": r.dev,
                "pools": [{"pool": format!("{} - {}", r.pool.range_start, r.pool.range_end)}],
                "valid-lifetime": r.pool.lease_time,
                "option-data": opts,
                "reservations": reservations,
            })
        })
        .collect();
    let doc = json!({
        "Dhcp4": {
            "interfaces-config": {"interfaces": ifaces},
            "lease-database": {"type": "memfile", "persist": true, "name": KEA4_LEASES, "lfc-interval": 3600},
            "subnet4": subnets,
            "loggers": [{"name": "kea-dhcp4", "output-options": [{"output": "stdout"}], "severity": "INFO"}],
        }
    });
    format!(
        "{}{}\n",
        lan::header("//", "Kea DHCPv4 server"),
        serde_json::to_string_pretty(&doc).unwrap_or_default()
    )
}

fn dnsmasq_v4_lines(r: &Resolved4, dns_on: bool, ntp_on: bool) -> Vec<String> {
    let tag = format!("p{}", r.pool.id);
    let o = options4(r, dns_on, ntp_on);
    let mut v = vec![
        format!(
            "dhcp-range=set:{tag},{},{},{},{}",
            r.pool.range_start,
            r.pool.range_end,
            r.netmask(),
            r.pool.lease_time
        ),
        format!("dhcp-option=tag:{tag},option:router,{}", o.gateway),
    ];
    if !o.dns.is_empty() {
        v.push(format!(
            "dhcp-option=tag:{tag},option:dns-server,{}",
            ip_join(&o.dns, ",")
        ));
    }
    if !o.ntp.is_empty() {
        v.push(format!(
            "dhcp-option=tag:{tag},option:ntp-server,{}",
            ip_join(&o.ntp, ",")
        ));
    }
    if let Some(d) = &r.pool.domain {
        v.push(format!("dhcp-option=tag:{tag},option:domain-name,{d}"));
    }
    for m in &r.pool.static_mappings {
        match &m.hostname {
            Some(h) => v.push(format!("dhcp-host={},{},{h}", m.mac, m.ip)),
            None => v.push(format!("dhcp-host={},{}", m.mac, m.ip)),
        }
    }
    v
}

/// Everything the DHCP side needs from the store + live addresses.
struct Plan {
    backend: Backend,
    ra_backend: RaBackend,
    v4: Vec<Resolved4>,
    v6: Vec<Resolved6>,
    ras: Vec<ResolvedRa>,
    /// (device, local address, servers)
    relays: Vec<(String, IpAddr, Vec<IpAddr>)>,
    dns_on: bool,
    ntp_on: bool,
}

async fn plan(store: &ConfigStore, env: &LanEnv, rep: &mut ApplyReport) -> Result<Plan> {
    let addrs = env.addrs()?;
    let backend = backend(store, env).await?;
    let ra_backend = ra_backend(store, env, backend).await?;
    let v4 = resolve_pools(store, &addrs, rep).await?;
    let v6 = dhcp6::resolve(store, &addrs, rep).await?;
    let ras = ra::resolve(store, &addrs, rep).await?;
    if ra_backend == RaBackend::Dnsmasq {
        // dnsmasq only sets the M flag (and clears A) for a DHCPv6 range it
        // serves itself; without one it can only send `ra-only`, i.e. plain
        // SLAAC. Say so instead of silently downgrading managed/assisted.
        for r in &ras {
            let pool_here = backend == Backend::Dnsmasq && v6.iter().any(|p| p.dev == r.dev);
            if !pool_here && ra::needs_managed_flag(&r.ra.mode) {
                rep.warn(format!(
                    "router advertisements on {}: mode {} needs the M flag, which dnsmasq only \
                     sets for a DHCPv6 pool it serves on that interface; advertising SLAAC only. \
                     Add a DHCPv6 pool there, or use radvd as the RA backend when DHCPv6 comes \
                     from Kea or a relay",
                    r.dev, r.ra.mode
                ));
            }
        }
    }
    let (dns_on, ntp_on) = service_flags(store, env).await?;
    let mut relays = Vec::new();
    for r in list_relays(store).await?.into_iter().filter(|r| r.enabled) {
        let devs = lan::resolve_iface(store, &r.interface).await?;
        if devs.is_empty() {
            rep.warn(format!(
                "DHCP relay on {}: interface role is not assigned, skipped",
                r.interface
            ));
            continue;
        }
        for dev in devs {
            if v4.iter().any(|p| p.dev == dev) || v6.iter().any(|p| p.dev == dev) {
                rep.warn(format!(
                    "DHCP relay on {dev}: a DHCP server pool is configured there too; relay skipped"
                ));
                continue;
            }
            for fam_v4 in [true, false] {
                let servers: Vec<IpAddr> = r
                    .servers
                    .iter()
                    .copied()
                    .filter(|s| s.is_ipv4() == fam_v4)
                    .collect();
                if servers.is_empty() {
                    continue;
                }
                let local = addrs.iter().find(|a| {
                    a.ifname == dev && a.addr.is_ipv4() == fam_v4 && (fam_v4 || a.is_global_v6())
                });
                match local {
                    Some(a) => relays.push((dev.clone(), a.addr, servers)),
                    None => rep.warn(format!(
                        "DHCP relay on {dev}: no {} address on the interface, skipped",
                        if fam_v4 { "IPv4" } else { "global IPv6" }
                    )),
                }
            }
        }
    }
    Ok(Plan {
        backend,
        ra_backend,
        v4,
        v6,
        ras,
        relays,
        dns_on,
        ntp_on,
    })
}

/// DHCP/RA/relay lines of `/etc/dnsmasq.conf` (see [`lan::sync_dnsmasq`]).
pub async fn dnsmasq_part(
    store: &ConfigStore,
    env: &LanEnv,
    _rep: &mut ApplyReport,
) -> Result<DnsmasqPart> {
    // warnings are reported by DhcpApplier's own plan; don't repeat them
    let mut quiet = ApplyReport::default();
    let p = plan(store, env, &mut quiet).await?;
    let mut part = DnsmasqPart::default();
    let mut lines = Vec::new();
    let dnsmasq_serves = p.backend == Backend::Dnsmasq && (!p.v4.is_empty() || !p.v6.is_empty());
    if dnsmasq_serves {
        lines.push("dhcp-authoritative".to_string());
        lines.push(format!("dhcp-leasefile={}", lan::DNSMASQ_LEASES));
        for r in &p.v4 {
            part.interfaces.push(r.dev.clone());
            lines.extend(dnsmasq_v4_lines(r, p.dns_on, p.ntp_on));
        }
        for r in &p.v6 {
            part.interfaces.push(r.dev.clone());
            let slaac = p
                .ras
                .iter()
                .find(|ra| ra.dev == r.dev)
                .is_some_and(|ra| ra.ra.mode != "managed");
            lines.extend(dhcp6::dnsmasq_lines(r, slaac, p.dns_on));
        }
    }
    if p.ra_backend == RaBackend::Dnsmasq && !p.ras.is_empty() {
        lines.push("enable-ra".into());
        for ra in &p.ras {
            part.interfaces.push(ra.dev.clone());
            lines.push(ra::dnsmasq_ra_param(ra));
            let pool_here = dnsmasq_serves && p.v6.iter().any(|r| r.dev == ra.dev);
            if !pool_here {
                lines.extend(ra::dnsmasq_ra_only_lines(ra, p.dns_on));
            }
        }
    }
    for (dev, local, servers) in &p.relays {
        part.interfaces.push(dev.clone());
        for s in servers {
            // No third (interface) field: in dnsmasq that names the
            // interface towards a *multicast* DHCPv6 server, and with it set
            // to the client side dnsmasq drops the server's replies (proven
            // in the netlab relay test). The local address alone selects
            // the client interface.
            lines.push(format!("dhcp-relay={local},{s}"));
        }
    }
    part.lines = lines;
    Ok(part)
}

// ---------------------------------------------------------------------------
// leases
// ---------------------------------------------------------------------------

/// One lease from the daemon's lease database.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Lease {
    pub ip: String,
    /// MAC (v4) or DUID (v6).
    pub mac: String,
    pub hostname: Option<String>,
    /// Unix time the lease ends (0 = never).
    pub expires: i64,
    pub family: &'static str,
    pub source: &'static str,
    /// active | expired | declined | released
    pub state: &'static str,
    pub is_static: bool,
}

fn csv_split(line: &str) -> Vec<String> {
    // Kea escapes commas inside values as &#x2c
    line.split(',').map(|f| f.replace("&#x2c", ",")).collect()
}

/// Parse a Kea memfile lease CSV (v4 or v6). Later rows replace earlier
/// rows for the same address (memfile appends updates).
pub fn parse_kea_leases(s: &str, v6: bool, now_ts: i64) -> Vec<Lease> {
    let mut lines = s.lines();
    let Some(head) = lines.next() else {
        return vec![];
    };
    let cols: Vec<String> = csv_split(head);
    let idx = |n: &str| cols.iter().position(|c| c == n);
    let (Some(ia), Some(ie), Some(iv)) = (idx("address"), idx("expire"), idx("valid_lifetime"))
    else {
        return vec![];
    };
    let ih = idx("hostname");
    let ist = idx("state");
    let imac = if v6 { idx("duid") } else { idx("hwaddr") };
    let mut by_ip: BTreeMap<String, Lease> = BTreeMap::new();
    for l in lines {
        let f = csv_split(l);
        let get = |i: Option<usize>| i.and_then(|i| f.get(i)).cloned().unwrap_or_default();
        let ip = get(Some(ia));
        if ip.is_empty() {
            continue;
        }
        let expires: i64 = get(Some(ie)).parse().unwrap_or(0);
        let valid: i64 = get(Some(iv)).parse().unwrap_or(0);
        let state = match get(ist).as_str() {
            "1" => "declined",
            "2" => "expired",
            _ if valid == 0 => "released",
            _ if expires != 0 && expires < now_ts => "expired",
            _ => "active",
        };
        let host = get(ih);
        by_ip.insert(
            ip.clone(),
            Lease {
                ip,
                mac: get(imac),
                hostname: (!host.is_empty()).then(|| host.trim_end_matches('.').to_string()),
                expires,
                family: if v6 { "ipv6" } else { "ipv4" },
                source: "kea",
                state,
                is_static: false,
            },
        );
    }
    by_ip.into_values().collect()
}

/// Parse dnsmasq's lease file (`<expiry> <mac> <ip> <host> <client-id>`;
/// after the `duid` line: `<expiry> <iaid> <ip> <host> <duid>`).
pub fn parse_dnsmasq_leases(s: &str, now_ts: i64) -> Vec<Lease> {
    let mut v6 = false;
    let mut out = Vec::new();
    for l in s.lines() {
        let f: Vec<&str> = l.split_whitespace().collect();
        if f.first() == Some(&"duid") {
            v6 = true;
            continue;
        }
        if f.len() < 4 {
            continue;
        }
        let expires: i64 = f[0].parse().unwrap_or(0);
        out.push(Lease {
            ip: f[2].to_string(),
            mac: if v6 {
                f.get(4).unwrap_or(&"").to_string()
            } else {
                f[1].to_string()
            },
            hostname: (f[3] != "*").then(|| f[3].to_string()),
            expires,
            family: if v6 { "ipv6" } else { "ipv4" },
            source: "dnsmasq",
            state: if expires != 0 && expires < now_ts {
                "expired"
            } else {
                "active"
            },
            is_static: false,
        });
    }
    out
}

/// Every lease the DHCP daemons know, static mappings marked.
pub async fn leases(store: &ConfigStore, env: &LanEnv) -> Result<Vec<Lease>> {
    let t = now();
    let mut v = Vec::new();
    if let Ok(s) = std::fs::read_to_string(env.path(KEA4_LEASES)) {
        v.extend(parse_kea_leases(&s, false, t));
    }
    if let Ok(s) = std::fs::read_to_string(env.path(dhcp6::KEA6_LEASES)) {
        v.extend(parse_kea_leases(&s, true, t));
    }
    if let Ok(s) = std::fs::read_to_string(env.path(lan::DNSMASQ_LEASES)) {
        v.extend(parse_dnsmasq_leases(&s, t));
    }
    let statics: Vec<(String, String)> = list_pools(store)
        .await?
        .into_iter()
        .flat_map(|p| p.static_mappings)
        .map(|m| (m.mac, m.ip.to_string()))
        .collect();
    for l in &mut v {
        l.is_static = statics
            .iter()
            .any(|(mac, ip)| mac.eq_ignore_ascii_case(&l.mac) && *ip == l.ip);
    }
    v.sort_by(|a, b| (a.family, &a.ip).cmp(&(b.family, &b.ip)));
    Ok(v)
}

// ---------------------------------------------------------------------------
// applier
// ---------------------------------------------------------------------------

/// DHCPv4 + DHCPv6 + RA + relay applier (boot phase `services`).
#[derive(Clone, Default)]
pub struct DhcpApplier {
    env: LanEnv,
}

impl DhcpApplier {
    pub fn new(env: LanEnv) -> Self {
        Self { env }
    }

    /// (service, binary, file, needed)
    fn files(&self, p: &Plan) -> Vec<(&'static str, &'static str, ManagedFile, bool)> {
        let kea = p.backend == Backend::Kea;
        let radvd = p.ra_backend == RaBackend::Radvd;
        vec![
            (
                "kea-dhcp4",
                KEA4_BIN,
                ManagedFile {
                    path: KEA4_CONF,
                    content: render_kea4(&p.v4, p.dns_on, p.ntp_on),
                    mode: 0o640,
                    group: Some("dhcp"),
                    check: Some(vec![KEA4_BIN, "-t", "{}"]),
                },
                kea && !p.v4.is_empty(),
            ),
            (
                "kea-dhcp6",
                dhcp6::KEA6_BIN,
                ManagedFile {
                    path: dhcp6::KEA6_CONF,
                    content: dhcp6::render_kea(&p.v6, p.dns_on),
                    mode: 0o640,
                    group: Some("dhcp"),
                    check: Some(vec![dhcp6::KEA6_BIN, "-t", "{}"]),
                },
                kea && !p.v6.is_empty(),
            ),
            (
                "radvd",
                ra::RADVD_BIN,
                ManagedFile {
                    path: ra::RADVD_CONF,
                    content: ra::render_radvd(&p.ras, p.dns_on),
                    mode: 0o644,
                    group: None,
                    check: Some(vec![ra::RADVD_BIN, "-c", "-C", "{}"]),
                },
                radvd && !p.ras.is_empty(),
            ),
        ]
    }

    /// A daemon's file rendered from an empty configuration (no subnets, no
    /// pools, no reservations, no RA interfaces): what is left on disk when
    /// the daemon is no longer needed.
    fn idle_content(svc: &str, p: &Plan) -> String {
        match svc {
            "kea-dhcp4" => render_kea4(&[], p.dns_on, p.ntp_on),
            "kea-dhcp6" => dhcp6::render_kea(&[], p.dns_on),
            _ => ra::render_radvd(&[], p.dns_on),
        }
    }

    /// Status for the UI: backend, daemons, leases.
    pub async fn status_value(&self, store: &ConfigStore) -> Result<Value> {
        let b = backend(store, &self.env).await?;
        let rb = ra_backend(store, &self.env, b).await?;
        let svcs: BTreeMap<&str, bool> = ["kea-dhcp4", "kea-dhcp6", "radvd", "dnsmasq"]
            .into_iter()
            .map(|s| (s, self.env.services.is_running(s)))
            .collect();
        Ok(json!({
            "backend": b,
            "ra_backend": rb,
            "available": available(&self.env),
            "services": svcs,
            "leases": leases(store, &self.env).await?,
        }))
    }
}

#[async_trait]
impl Applier for DhcpApplier {
    fn name(&self) -> &'static str {
        "dhcp"
    }

    fn phase(&self) -> Phase {
        Phase::Services
    }

    async fn apply(&self, store: &ConfigStore) -> Result<ApplyReport> {
        let mut rep = ApplyReport::default();
        let p = plan(store, &self.env, &mut rep).await?;
        let env = &self.env;
        for (svc, bin, f, needed) in self.files(&p) {
            if !needed {
                // the last pool was deleted / the backend switched: the
                // daemon's file must not keep serving the old pools
                let idle = Self::idle_content(svc, &p);
                lan::retire(env, svc, ManagedFile { content: idle, ..f }, &mut rep)?;
                continue;
            }
            if !env.has_binary(bin) {
                return Err(Error::Service(format!(
                    "{svc} is needed but {bin} is not installed ({})",
                    if svc == "radvd" {
                        "emerge net-misc/radvd, or set the RA backend to dnsmasq"
                    } else {
                        "emerge net-misc/kea (USE=kea), or set the DHCP backend to dnsmasq"
                    }
                )));
            }
            if svc == "radvd" {
                lan::install(
                    env,
                    &ManagedFile {
                        path: ra::RADVD_CONFD,
                        content: lan::header("#", "radvd OpenRC options")
                            + "# IPv6 forwarding is owned by Patronus (sysctl phase): never let\n\
                               # the init script turn it off when radvd stops.\n\
                               FORWARD=\"no\"\n",
                        mode: 0o644,
                        group: None,
                        check: None,
                    },
                )?;
            }
            if svc.starts_with("kea-") {
                // Kea writes its pid file to /run/kea; on OpenRC that dir
                // only exists if tmpfiles ran for the package since boot
                lan::ensure_dir(env, "/run/kea", 0o750, Some(("dhcp", "dhcp")));
            }
            let changed = lan::install(env, &f)?;
            if changed {
                rep.applied(format!("wrote {}", f.path));
            }
            lan::reconcile(env, svc, true, changed, f.path, &mut rep)?;
        }
        lan::sync_dnsmasq(store, env, &mut rep).await?;
        rep.applied(format!(
            "DHCP: backend {}, {} IPv4 pool(s), {} IPv6 pool(s), {} RA interface(s), {} relay(s)",
            p.backend.as_str(),
            p.v4.len(),
            p.v6.len(),
            p.ras.len(),
            p.relays.len()
        ));
        Ok(rep)
    }

    async fn render(&self, store: &ConfigStore) -> Result<String> {
        let mut rep = ApplyReport::default();
        let p = plan(store, &self.env, &mut rep).await?;
        let mut s = format!(
            "# DHCP backend: {}, router advertisements: {:?}\n",
            p.backend.as_str(),
            p.ra_backend
        );
        for w in &rep.warnings {
            s.push_str(&format!("# warning: {w}\n"));
        }
        for (svc, _, f, needed) in self.files(&p) {
            if needed {
                s.push_str(&format!("## {} ({svc})\n{}", f.path, f.content));
            }
        }
        if let Some(d) = lan::render_dnsmasq(store, &self.env, &mut rep).await? {
            s.push_str(&format!("## {} (dnsmasq)\n{d}", lan::DNSMASQ_CONF));
        }
        Ok(s)
    }

    async fn status(&self, store: &ConfigStore) -> Result<Value> {
        self.status_value(store).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lan::testutil::{self, read};
    use crate::lan::ServiceControl;

    async fn seed(s: &ConfigStore) -> i64 {
        let pool = PoolInput {
            interface: "@lan".into(),
            enabled: true,
            range_start: "192.168.50.100".into(),
            range_end: "192.168.50.199".into(),
            lease_time: Some(3600),
            domain: Some("lan.example".into()),
            ..Default::default()
        }
        .validate()
        .unwrap();
        let id = upsert_pool(s, None, &pool).await.unwrap();
        let pool = get_pool(s, id).await.unwrap().unwrap();
        let m = StaticInput {
            mac: "AA:BB:CC:00:00:02".into(),
            ip: "192.168.50.20".into(),
            hostname: Some("printer".into()),
            description: None,
        }
        .validate(&pool)
        .unwrap();
        add_static(s, &m).await.unwrap();
        id
    }

    #[tokio::test]
    async fn kea_backend_writes_the_path_kea_reads_and_starts_it() {
        let t = testutil::env(&[
            KEA4_BIN,
            dhcp6::KEA6_BIN,
            ra::RADVD_BIN,
            lan::DNSMASQ_BIN,
            "/usr/sbin/unbound",
        ]);
        let s = testutil::store().await;
        seed(&s).await;
        let a = DhcpApplier::new(t.env.clone());
        let rep = a.apply(&s).await.unwrap();
        let conf = read(&t, KEA4_CONF);
        assert!(conf.starts_with("// Managed by Patronus"), "{conf}");
        let body: String = conf
            .lines()
            .filter(|l| !l.starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");
        let j: Value = serde_json::from_str(&body).unwrap();
        let sub = &j["Dhcp4"]["subnet4"][0];
        assert_eq!(sub["subnet"], "192.168.50.0/24");
        assert_eq!(sub["interface"], "rtr-lan");
        assert_eq!(sub["pools"][0]["pool"], "192.168.50.100 - 192.168.50.199");
        assert_eq!(sub["reservations"][0]["hw-address"], "aa:bb:cc:00:00:02");
        assert_eq!(sub["reservations"][0]["ip-address"], "192.168.50.20");
        // the DNS resolver is on by default -> the router is the DNS server
        assert_eq!(
            conf.contains("\"domain-name-servers\""),
            cfg!(feature = "dns"),
            "{conf}"
        );
        assert_eq!(
            *t.services.log.lock().unwrap(),
            vec!["restart kea-dhcp4".to_string()],
            "{rep:?}"
        );
        // idempotent: nothing restarts the second time
        a.apply(&s).await.unwrap();
        assert_eq!(t.services.log.lock().unwrap().len(), 1);
        // kea serves DHCP; nothing needs dnsmasq
        assert!(read(&t, lan::DNSMASQ_CONF).is_empty());
    }

    #[tokio::test]
    async fn deleting_the_last_pool_empties_the_kea_config_before_stopping_kea() {
        let t = testutil::env(&[KEA4_BIN, lan::DNSMASQ_BIN, "/usr/sbin/unbound"]);
        let s = testutil::store().await;
        let id = seed(&s).await;
        let a = DhcpApplier::new(t.env.clone());
        a.apply(&s).await.unwrap();
        assert!(t.services.is_running("kea-dhcp4"));
        assert!(read(&t, KEA4_CONF).contains("192.168.50.100 - 192.168.50.199"));

        delete_pool(&s, id).await.unwrap();
        let rep = a.apply(&s).await.unwrap();
        assert!(!t.services.is_running("kea-dhcp4"), "{rep:?}");
        let conf = read(&t, KEA4_CONF);
        assert!(conf.starts_with("// Managed by Patronus"), "{conf}");
        for gone in ["192.168.50", "aa:bb:cc:00:00:02", "rtr-lan"] {
            assert!(!conf.contains(gone), "deleted pool left {gone}: {conf}");
        }
        let body: String = conf
            .lines()
            .filter(|l| !l.starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");
        let j: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(j["Dhcp4"]["subnet4"], json!([]));
        assert_eq!(j["Dhcp4"]["interfaces-config"]["interfaces"], json!([]));
        assert!(
            rep.applied.iter().any(|l| l.contains("nothing configured")),
            "{rep:?}"
        );
        // a second apply changes nothing
        let n = t.services.log.lock().unwrap().len();
        a.apply(&s).await.unwrap();
        assert_eq!(t.services.log.lock().unwrap().len(), n);

        // a hand-maintained Kea file is never touched
        std::fs::write(t.env.path(KEA4_CONF), "{\"mine\": true}\n").unwrap();
        a.apply(&s).await.unwrap();
        assert_eq!(read(&t, KEA4_CONF), "{\"mine\": true}\n");
    }

    #[tokio::test]
    async fn dnsmasq_backend_serves_v4_v6_ra_and_relays() {
        let t = testutil::env(&[lan::DNSMASQ_BIN, "/usr/sbin/unbound"]);
        let s = testutil::store().await;
        seed(&s).await;
        s.set_interface_role("rtr-opt1", Some("opt1"))
            .await
            .unwrap();
        let p6 = dhcp6::Dhcp6Input {
            interface: "@lan".into(),
            enabled: true,
            range_start: "fd00:50::100".into(),
            range_end: "fd00:50::1ff".into(),
            ..Default::default()
        }
        .validate()
        .unwrap();
        dhcp6::upsert(&s, None, &p6).await.unwrap();
        let ra = ra::RaInput {
            interface: "@lan".into(),
            enabled: true,
            mode: Some("managed".into()),
            min_interval: Some(3),
            max_interval: Some(10),
            ..Default::default()
        }
        .validate()
        .unwrap();
        ra::upsert(&s, None, &ra).await.unwrap();
        let relay = RelayInput {
            interface: "@opt1".into(),
            enabled: true,
            servers: "10.9.9.9".into(),
            description: None,
        }
        .validate()
        .unwrap();
        upsert_relay(&s, None, &relay).await.unwrap();

        let a = DhcpApplier::new(t.env.clone());
        let rep = a.apply(&s).await.unwrap();
        // managed RA with dnsmasq's own pool on the interface: M flag works
        assert!(
            !rep.warnings.iter().any(|w| w.contains("M flag")),
            "{rep:?}"
        );
        let c = read(&t, lan::DNSMASQ_CONF);
        for want in [
            "interface=rtr-lan",
            "interface=rtr-opt1",
            "port=0",
            "dhcp-range=set:p1,192.168.50.100,192.168.50.199,255.255.255.0,3600",
            "dhcp-option=tag:p1,option:router,192.168.50.1",
            "dhcp-option=tag:p1,option:domain-name,lan.example",
            "dhcp-host=aa:bb:cc:00:00:02,192.168.50.20,printer",
            "dhcp-range=set:v6p1,fd00:50::100,fd00:50::1ff,64,86400",
            "enable-ra",
            "ra-param=rtr-lan,10,30",
            "dhcp-relay=192.168.60.1,10.9.9.9",
        ] {
            assert!(c.contains(want), "missing {want:?} in\n{c}");
        }
        assert_eq!(
            c.contains("dhcp-option=tag:p1,option:dns-server,192.168.50.1"),
            cfg!(feature = "dns")
        );
        assert_eq!(
            *t.services.log.lock().unwrap(),
            vec!["restart dnsmasq".to_string()]
        );
        // deleting everything stops the daemon Patronus started
        for p in list_pools(&s).await.unwrap() {
            delete_pool(&s, p.id).await.unwrap();
        }
        for p in dhcp6::list(&s).await.unwrap() {
            dhcp6::delete(&s, p.id).await.unwrap();
        }
        for r in ra::list(&s).await.unwrap() {
            ra::delete(&s, r.id).await.unwrap();
        }
        for r in list_relays(&s).await.unwrap() {
            delete_relay(&s, r.id).await.unwrap();
        }
        a.apply(&s).await.unwrap();
        assert!(!t.services.is_running("dnsmasq"));
    }

    #[tokio::test]
    async fn managed_ra_without_a_dnsmasq_pool_warns_instead_of_silently_going_slaac() {
        // Kea serves DHCPv6, radvd is not installed -> auto RA backend is
        // dnsmasq, which cannot advertise the M flag for Kea's pool.
        let t = testutil::env(&[KEA4_BIN, dhcp6::KEA6_BIN, lan::DNSMASQ_BIN]);
        let s = testutil::store().await;
        let p6 = dhcp6::Dhcp6Input {
            interface: "@lan".into(),
            enabled: true,
            range_start: "fd00:50::100".into(),
            range_end: "fd00:50::1ff".into(),
            ..Default::default()
        }
        .validate()
        .unwrap();
        dhcp6::upsert(&s, None, &p6).await.unwrap();
        for mode in ["managed", "assisted", "stateless", "slaac"] {
            for r in ra::list(&s).await.unwrap() {
                ra::delete(&s, r.id).await.unwrap();
            }
            let ra = ra::RaInput {
                interface: "@lan".into(),
                enabled: true,
                mode: Some(mode.into()),
                ..Default::default()
            }
            .validate()
            .unwrap();
            ra::upsert(&s, None, &ra).await.unwrap();
            let rep = DhcpApplier::new(t.env.clone()).apply(&s).await.unwrap();
            let warned = rep
                .warnings
                .iter()
                .any(|w| w.contains("rtr-lan") && w.contains("M flag"));
            assert_eq!(warned, ra::needs_managed_flag(mode), "{mode}: {rep:?}");
            assert!(read(&t, lan::DNSMASQ_CONF).contains("enable-ra"), "{mode}");
        }
    }

    #[tokio::test]
    async fn unassigned_role_and_foreign_subnet_are_skipped_with_warnings() {
        let t = testutil::env(&[lan::DNSMASQ_BIN]);
        let s = testutil::store().await;
        for (iface, a, b) in [
            ("@opt2", "10.1.1.10", "10.1.1.20"),
            ("@lan", "10.2.2.10", "10.2.2.20"),
        ] {
            let p = PoolInput {
                interface: iface.into(),
                range_start: a.into(),
                range_end: b.into(),
                enabled: true,
                ..Default::default()
            }
            .validate()
            .unwrap();
            upsert_pool(&s, None, &p).await.unwrap();
        }
        let rep = DhcpApplier::new(t.env.clone()).apply(&s).await.unwrap();
        assert_eq!(rep.warnings.len(), 2, "{rep:?}");
        assert!(t.services.log.lock().unwrap().is_empty());
    }

    #[test]
    fn static_mapping_validation() {
        let pool = PoolInput {
            interface: "@lan".into(),
            range_start: "192.168.50.100".into(),
            range_end: "192.168.50.199".into(),
            ..Default::default()
        }
        .validate()
        .unwrap();
        let mk = |ip: &str, host: &str| StaticInput {
            mac: "aa:bb:cc:dd:ee:ff".into(),
            ip: ip.into(),
            hostname: Some(host.into()),
            description: None,
        };
        assert!(mk("192.168.50.20", "nas").validate(&pool).is_ok());
        assert!(mk("192.168.50.150", "nas").validate(&pool).is_err());
        assert!(mk("192.168.50.20", "nas\ndhcp-range=x")
            .validate(&pool)
            .is_err());
    }

    #[test]
    fn parses_lease_databases() {
        let kea = "address,hwaddr,client_id,valid_lifetime,expire,subnet_id,fqdn_fwd,fqdn_rev,hostname,state,user_context,pool_id\n\
                   192.168.50.100,aa:bb:cc:00:00:01,,3600,2000000000,1,0,0,c1,0,,0\n\
                   192.168.50.101,aa:bb:cc:00:00:03,,3600,100,1,0,0,,0,,0\n\
                   192.168.50.100,aa:bb:cc:00:00:01,,3600,2000000100,1,0,0,c1,0,,0\n";
        let l = parse_kea_leases(kea, false, 1_000_000_000);
        assert_eq!(l.len(), 2);
        assert_eq!(l[0].expires, 2000000100);
        assert_eq!(l[0].state, "active");
        assert_eq!(l[1].state, "expired");
        let dm = "2000000000 aa:bb:cc:00:00:02 192.168.50.20 printer 01:aa:bb:cc:00:00:02\n\
                  duid 00:01:00:01:aa\n\
                  2000000000 1234 fd00:50::150 * 00:01:00:01:bb\n";
        let l = parse_dnsmasq_leases(dm, 1_000_000_000);
        assert_eq!(l.len(), 2);
        assert_eq!(l[0].hostname.as_deref(), Some("printer"));
        assert_eq!(l[1].family, "ipv6");
        assert_eq!(l[1].mac, "00:01:00:01:bb");
    }
}
