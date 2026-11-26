//! DNS (lane D): Unbound resolver or dnsmasq forwarder, with host
//! overrides, domain overrides and a DNS block list (DNSBL).
//!
//! `dns.mode`:
//! - `resolver` (default): Unbound, config at `/etc/unbound/unbound.conf`
//!   (what Gentoo's `unbound` OpenRC script and systemd unit read; the old
//!   code wrote `/etc/patronus/unbound/unbound.conf`, which nothing read).
//!   Recurses, or forwards everything to `dns.upstreams` when set.
//! - `forwarder`: dnsmasq answers on port 53 (same `/etc/dnsmasq.conf` the
//!   DHCP side uses, see [`crate::lan::sync_dnsmasq`]), forwarding to
//!   `dns.upstreams` (or the box's own resolv.conf).
//! - `disabled`: no DNS service from Patronus.
//! - `auto` (nothing stored): `resolver` when Unbound is installed
//!   (USE=unbound), else `disabled`.
//!
//! Block lists: domains from `dns_blocklist` plus every list in
//! `dns.blocklist_urls` (hosts-file or one-domain-per-line format, fetched
//! with curl at apply time and cached under /var/lib/patronus/dnsbl so a
//! failed download keeps the last good copy). Blocked names answer NXDOMAIN
//! (`dns.block_mode=nxdomain`) or 0.0.0.0/:: (`null`).

use crate::lan::{self, db_err, invalid, now, DnsmasqPart, LanEnv, ManagedFile};
use async_trait::async_trait;
use patronus_config::applier::{Applier, ApplyReport, Phase};
use patronus_config::store::ConfigStore;
use patronus_core::{Error, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::Row;
use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::process::Command;

pub const UNBOUND_CONF: &str = "/etc/unbound/unbound.conf";
pub const UNBOUND_BIN: &str = "/usr/sbin/unbound";
pub const UNBOUND_CHECKCONF: &str = "/usr/sbin/unbound-checkconf";
pub const UNBOUND_ANCHOR: &str = "/var/lib/unbound/root.key";
pub const DNSBL_CACHE: &str = "/var/lib/patronus/dnsbl";

pub const MODES: &[&str] = &["auto", "resolver", "forwarder", "disabled"];

// ---------------------------------------------------------------------------
// model
// ---------------------------------------------------------------------------

/// Global DNS settings (`lan_settings` keys `dns.*`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DnsSettings {
    pub mode: String,
    pub upstreams: Vec<IpAddr>,
    pub dnssec: bool,
    /// Interface specs served (default `@lan`).
    pub interfaces: Vec<String>,
    pub blocklist_urls: Vec<String>,
    pub block_mode: String,
    /// NAT64 prefix to synthesize AAAA records for (USE=nat64 with DNS64 on).
    #[serde(default)]
    pub dns64_prefix: Option<String>,
    /// DNS rebinding protection: answers from the Internet that contain a
    /// private address are stripped (unbound `private-address`, dnsmasq
    /// `stop-dns-rebind`). Off on stores that predate the setting (a split-
    /// horizon setup that resolves a public name to a private address would
    /// break silently), on for new installs.
    #[serde(default)]
    pub rebind_protection: bool,
    /// Domains that may resolve to private addresses (unbound `private-domain`,
    /// dnsmasq `rebind-domain-ok`).
    #[serde(default)]
    pub rebind_exceptions: Vec<String>,
    /// DNS over TLS to the upstreams (Unbound `forward-tls-upstream`, port
    /// 853), certificate checked against `upstream_tls_name`.
    #[serde(default)]
    pub upstream_tls: bool,
    /// The name in the upstreams' TLS certificate (`dns.quad9.net`,
    /// `cloudflare-dns.com`, `dns.google`, ...).
    #[serde(default)]
    pub upstream_tls_name: String,
    /// Local domain (`dns.local_domain`, empty = off): lease and static
    /// hostnames resolve as `<host>.<domain>`, queries for it never leave
    /// the router, and it is the default DHCP domain option.
    #[serde(default)]
    pub local_domain: String,
    /// dnsmasq cache entries (`dns.cache_size`).
    #[serde(default = "default_cache_size")]
    pub cache_size: u32,
    /// Log every query (dnsmasq `log-queries`; `dns.log_queries`).
    #[serde(default)]
    pub log_queries: bool,
}

pub const DEFAULT_CACHE_SIZE: u32 = 10000;
const MAX_CACHE_SIZE: u32 = 10_000_000;

fn default_cache_size() -> u32 {
    DEFAULT_CACHE_SIZE
}

/// CA bundle Unbound checks DoT upstream certificates against
/// (app-misc/ca-certificates; same path on Debian).
pub const UNBOUND_CA_BUNDLE: &str = "/etc/ssl/certs/ca-certificates.crt";

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DnsSettingsInput {
    #[serde(default)]
    pub local_domain: Option<String>,
    #[serde(default)]
    pub cache_size: Option<u32>,
    #[serde(default)]
    pub log_queries: Option<bool>,
    #[serde(default)]
    pub mode: Option<String>,
    #[serde(default)]
    pub upstreams: Option<String>,
    #[serde(default)]
    pub dnssec: Option<bool>,
    #[serde(default)]
    pub interfaces: Option<String>,
    #[serde(default)]
    pub blocklist_urls: Option<String>,
    #[serde(default)]
    pub block_mode: Option<String>,
    #[serde(default)]
    pub rebind_protection: Option<bool>,
    #[serde(default)]
    pub rebind_exceptions: Option<String>,
    #[serde(default)]
    pub upstream_tls: Option<bool>,
    #[serde(default)]
    pub upstream_tls_name: Option<String>,
}

/// Private and local ranges unbound strips from public answers.
pub const REBIND_PRIVATE_RANGES: &[&str] = &[
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "169.254.0.0/16",
    "127.0.0.0/8",
    "fd00::/8",
    "fe80::/10",
    "::1/128",
];

fn split_list(s: &str) -> Vec<String> {
    s.split([',', ' ', '\n'])
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .map(String::from)
        .collect()
}

pub fn check_url(u: &str) -> Result<String> {
    let ok_scheme =
        u.starts_with("https://") || u.starts_with("http://") || u.starts_with("file:///");
    if ok_scheme
        && u.len() <= 500
        && u.bytes()
            .all(|b| b.is_ascii_graphic() && !matches!(b, b'"' | b'\'' | b'\\' | b'`'))
    {
        Ok(u.to_string())
    } else {
        Err(invalid(format!(
            "block list URL {u:?} (http://, https:// or file:///)"
        )))
    }
}

impl DnsSettings {
    /// The mode in effect (`auto` resolved against what is installed).
    pub fn effective_mode(&self, env: &LanEnv) -> &str {
        match self.mode.as_str() {
            "auto" if env.has_binary(UNBOUND_BIN) => "resolver",
            "auto" => "disabled",
            m => m,
        }
    }
}

/// Is a DNS service running on the router (for DHCP/RA defaults)?
pub async fn dns_enabled(store: &ConfigStore, env: &LanEnv) -> Result<bool> {
    Ok(settings(store).await?.effective_mode(env) != "disabled")
}

pub async fn settings(store: &ConfigStore) -> Result<DnsSettings> {
    let m = lan::settings_with_prefix(store, "dns.").await?;
    let g = |k: &str, d: &str| {
        m.get(k)
            .filter(|v| !v.trim().is_empty())
            .cloned()
            .unwrap_or_else(|| d.to_string())
    };
    Ok(DnsSettings {
        mode: g("dns.mode", "auto"),
        upstreams: lan::parse_ip_list("", &g("dns.upstreams", "")).unwrap_or_default(),
        dnssec: lan::flag(&g("dns.dnssec", "1")),
        interfaces: split_list(&g("dns.interfaces", "@lan")),
        blocklist_urls: split_list(&g("dns.blocklist_urls", "")),
        block_mode: g("dns.block_mode", "nxdomain"),
        rebind_protection: lan::flag(&g("dns.rebind_protection", "0")),
        rebind_exceptions: split_list(&g("dns.rebind_exceptions", "")),
        upstream_tls: lan::flag(&g("dns.upstream_tls", "0")),
        upstream_tls_name: g("dns.upstream_tls_name", ""),
        local_domain: g("dns.local_domain", "").trim().to_string(),
        cache_size: g("dns.cache_size", "")
            .parse()
            .unwrap_or(DEFAULT_CACHE_SIZE),
        log_queries: lan::flag(&g("dns.log_queries", "0")),
        dns64_prefix: {
            let n = lan::settings_with_prefix(store, "nat64.").await?;
            let on = n.get("nat64.enabled").is_some_and(|v| lan::flag(v))
                && n.get("nat64.dns64").is_none_or(|v| lan::flag(v));
            on.then(|| {
                n.get("nat64.prefix")
                    .filter(|v| !v.trim().is_empty())
                    .cloned()
                    .unwrap_or_else(|| "64:ff9b::/96".to_string())
            })
        },
    })
}

/// Validate and store the settings given (unset fields keep their value).
pub async fn save_settings(store: &ConfigStore, i: &DnsSettingsInput) -> Result<()> {
    let mut kv: Vec<(&str, String)> = Vec::new();
    if let Some(m) = &i.mode {
        let m = m.trim().to_ascii_lowercase();
        if !MODES.contains(&m.as_str()) {
            return Err(invalid(format!(
                "DNS mode {m:?} (auto, resolver, forwarder or disabled)"
            )));
        }
        kv.push(("dns.mode", m));
    }
    if let Some(u) = &i.upstreams {
        let v = lan::parse_ip_list("upstream DNS server", u)?;
        kv.push(("dns.upstreams", lan::join_ips(&v).unwrap_or_default()));
    }
    if let Some(d) = i.dnssec {
        kv.push(("dns.dnssec", if d { "1" } else { "0" }.into()));
    }
    if let Some(s) = &i.interfaces {
        let v = split_list(s)
            .iter()
            .map(|x| lan::check_iface_spec(x))
            .collect::<Result<Vec<_>>>()?;
        kv.push(("dns.interfaces", v.join(",")));
    }
    if let Some(s) = &i.blocklist_urls {
        let v = split_list(s)
            .iter()
            .map(|x| check_url(x))
            .collect::<Result<Vec<_>>>()?;
        kv.push(("dns.blocklist_urls", v.join(",")));
    }
    if let Some(b) = &i.block_mode {
        let b = b.trim().to_ascii_lowercase();
        if b != "nxdomain" && b != "null" {
            return Err(invalid("block mode (nxdomain or null)"));
        }
        kv.push(("dns.block_mode", b));
    }
    if let Some(r) = i.rebind_protection {
        kv.push(("dns.rebind_protection", if r { "1" } else { "0" }.into()));
    }
    if let Some(s) = &i.rebind_exceptions {
        let v = split_list(s)
            .iter()
            .map(|x| lan::check_dns_name("rebind exception domain", x))
            .collect::<Result<Vec<_>>>()?;
        kv.push(("dns.rebind_exceptions", v.join(",")));
    }
    if let Some(t) = i.upstream_tls {
        kv.push(("dns.upstream_tls", if t { "1" } else { "0" }.into()));
    }
    if let Some(n) = &i.upstream_tls_name {
        let n = if n.trim().is_empty() {
            String::new()
        } else {
            lan::check_dns_name("DNS over TLS server name", n)?
        };
        kv.push(("dns.upstream_tls_name", n));
    }
    if let Some(d) = &i.local_domain {
        let d = d.trim().trim_matches('.');
        let d = if d.is_empty() {
            String::new()
        } else {
            lan::check_dns_name("local domain", d)?
        };
        kv.push(("dns.local_domain", d));
    }
    if let Some(n) = i.cache_size {
        if n > MAX_CACHE_SIZE {
            return Err(invalid(format!(
                "cache size {n} (0 disables caching, at most {MAX_CACHE_SIZE})"
            )));
        }
        kv.push(("dns.cache_size", n.to_string()));
    }
    if let Some(l) = i.log_queries {
        kv.push(("dns.log_queries", if l { "1" } else { "0" }.into()));
    }
    let after = {
        let mut s = settings(store).await?;
        for (k, v) in &kv {
            match *k {
                "dns.mode" => s.mode = v.clone(),
                "dns.upstreams" => s.upstreams = lan::parse_ip_list("", v)?,
                "dns.upstream_tls" => s.upstream_tls = lan::flag(v),
                "dns.upstream_tls_name" => s.upstream_tls_name = v.clone(),
                _ => {}
            }
        }
        s
    };
    if after.upstream_tls {
        if after.upstreams.is_empty() {
            return Err(invalid(
                "DNS over TLS: set the upstream servers it should use (e.g. 9.9.9.9, 149.112.112.112)",
            ));
        }
        if after.upstream_tls_name.is_empty() {
            return Err(invalid(
                "DNS over TLS: the server name in the upstreams' certificate (e.g. dns.quad9.net)",
            ));
        }
        if after.mode == "forwarder" {
            return Err(invalid(
                "DNS over TLS needs the resolver mode (Unbound); the dnsmasq forwarder cannot speak TLS",
            ));
        }
    }
    if after.mode == "forwarder" && after.upstreams.is_empty() {
        // allowed: dnsmasq then uses the router's own /etc/resolv.conf
        tracing::info!("DNS forwarder without upstreams: using /etc/resolv.conf");
    }
    for (k, v) in kv {
        lan::set_setting(store, k, &v).await?;
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HostOverride {
    pub id: i64,
    pub hostname: String,
    pub domain: String,
    pub address: IpAddr,
    pub description: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HostInput {
    pub hostname: String,
    pub domain: String,
    pub address: String,
    #[serde(default)]
    pub description: Option<String>,
}

impl HostInput {
    pub fn validate(&self) -> Result<HostOverride> {
        Ok(HostOverride {
            id: 0,
            hostname: lan::check_label("hostname", &self.hostname)?,
            domain: lan::check_dns_name("domain", &self.domain)?,
            address: self
                .address
                .trim()
                .parse()
                .map_err(|_| invalid(format!("address {:?}", self.address)))?,
            description: lan::check_description(self.description.as_deref())?,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DomainOverride {
    pub id: i64,
    pub domain: String,
    pub server: IpAddr,
    pub port: u16,
    pub description: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DomainInput {
    pub domain: String,
    /// `10.0.0.53`, `10.0.0.53@5353` or `[fd00::53]@5353`
    pub server: String,
    #[serde(default)]
    pub description: Option<String>,
}

fn parse_server(s: &str) -> Option<(IpAddr, u16)> {
    let s = s.trim();
    let (host, port) = match s.rsplit_once('@') {
        Some((h, p)) => (h, p.parse().ok()?),
        None => (s, 53),
    };
    let host = host.trim_start_matches('[').trim_end_matches(']');
    Some((host.parse().ok()?, port))
}

impl DomainInput {
    pub fn validate(&self) -> Result<DomainOverride> {
        let (server, port) = parse_server(&self.server).ok_or_else(|| {
            invalid(format!(
                "DNS server {:?} (address or address@port)",
                self.server
            ))
        })?;
        Ok(DomainOverride {
            id: 0,
            domain: lan::check_dns_name("domain", &self.domain)?,
            server,
            port,
            description: lan::check_description(self.description.as_deref())?,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BlockedDomain {
    pub id: i64,
    pub domain: String,
    pub description: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BlockInput {
    pub domain: String,
    #[serde(default)]
    pub description: Option<String>,
}

// ---------------------------------------------------------------------------
// store accessors
// ---------------------------------------------------------------------------

pub async fn list_hosts(store: &ConfigStore) -> Result<Vec<HostOverride>> {
    let rows = sqlx::query("SELECT * FROM dns_host_overrides ORDER BY domain, hostname")
        .fetch_all(store.pool()?)
        .await
        .map_err(db_err("load host overrides"))?;
    Ok(rows
        .iter()
        .filter_map(|r| {
            Some(HostOverride {
                id: r.get("id"),
                hostname: r.get("hostname"),
                domain: r.get("domain"),
                address: r.get::<String, _>("address").parse().ok()?,
                description: r.get("description"),
            })
        })
        .collect())
}

pub async fn add_host(store: &ConfigStore, h: &HostOverride) -> Result<i64> {
    let what = format!("{}.{} -> {}", h.hostname, h.domain, h.address);
    let r = sqlx::query(
        "INSERT INTO dns_host_overrides (hostname, domain, address, description, updated_at)
         VALUES (?,?,?,?,?)",
    )
    .bind(&h.hostname)
    .bind(&h.domain)
    .bind(h.address.to_string())
    .bind(&h.description)
    .bind(now())
    .execute(store.pool()?)
    .await
    .map_err(|e| lan::unique_err(e, &what))?;
    Ok(r.last_insert_rowid())
}

pub async fn list_domains(store: &ConfigStore) -> Result<Vec<DomainOverride>> {
    let rows = sqlx::query("SELECT * FROM dns_domain_overrides ORDER BY domain")
        .fetch_all(store.pool()?)
        .await
        .map_err(db_err("load domain overrides"))?;
    Ok(rows
        .iter()
        .filter_map(|r| {
            let (server, port) = parse_server(&r.get::<String, _>("server"))?;
            Some(DomainOverride {
                id: r.get("id"),
                domain: r.get("domain"),
                server,
                port,
                description: r.get("description"),
            })
        })
        .collect())
}

pub async fn add_domain(store: &ConfigStore, d: &DomainOverride) -> Result<i64> {
    let server = match d.server {
        IpAddr::V6(a) => format!("[{a}]@{}", d.port),
        IpAddr::V4(a) => format!("{a}@{}", d.port),
    };
    let what = format!("{} -> {server}", d.domain);
    let r = sqlx::query(
        "INSERT INTO dns_domain_overrides (domain, server, description, updated_at)
         VALUES (?,?,?,?)",
    )
    .bind(&d.domain)
    .bind(&server)
    .bind(&d.description)
    .bind(now())
    .execute(store.pool()?)
    .await
    .map_err(|e| lan::unique_err(e, &what))?;
    Ok(r.last_insert_rowid())
}

pub async fn list_blocked(store: &ConfigStore) -> Result<Vec<BlockedDomain>> {
    let rows = sqlx::query("SELECT * FROM dns_blocklist ORDER BY domain")
        .fetch_all(store.pool()?)
        .await
        .map_err(db_err("load block list"))?;
    Ok(rows
        .iter()
        .map(|r| BlockedDomain {
            id: r.get("id"),
            domain: r.get("domain"),
            description: r.get("description"),
        })
        .collect())
}

pub async fn add_blocked(store: &ConfigStore, i: &BlockInput) -> Result<i64> {
    let d = lan::check_dns_name("domain", &i.domain)?;
    let desc = lan::check_description(i.description.as_deref())?;
    let r =
        sqlx::query("INSERT INTO dns_blocklist (domain, description, updated_at) VALUES (?,?,?)")
            .bind(&d)
            .bind(&desc)
            .bind(now())
            .execute(store.pool()?)
            .await
            .map_err(|e| lan::unique_err(e, &d))?;
    Ok(r.last_insert_rowid())
}

/// Delete a row from one of the DNS tables by id.
pub async fn delete_row(store: &ConfigStore, table: &str, id: i64) -> Result<()> {
    let table = match table {
        "hosts" => "dns_host_overrides",
        "domains" => "dns_domain_overrides",
        "blocklist" => "dns_blocklist",
        other => return Err(invalid(format!("DNS table {other:?}"))),
    };
    let r = sqlx::query(&format!("DELETE FROM {table} WHERE id = ?"))
        .bind(id)
        .execute(store.pool()?)
        .await
        .map_err(db_err("delete DNS entry"))?;
    if r.rows_affected() == 0 {
        return Err(Error::Config(format!("DNS entry {id} not found")));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// block lists
// ---------------------------------------------------------------------------

/// Domains from a hosts file / domain list.
pub fn parse_blocklist(s: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for line in s.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let f: Vec<&str> = line.split_whitespace().collect();
        let names: &[&str] = match f.first() {
            Some(&"0.0.0.0") | Some(&"127.0.0.1") | Some(&"::") | Some(&"::1") => &f[1..],
            _ => &f[..1],
        };
        for n in names {
            let n = n.trim_end_matches('.').to_ascii_lowercase();
            if n != "localhost" && n.contains('.') && lan::valid_dns_name(&n, true) {
                out.insert(n);
            }
        }
    }
    out
}

fn cache_name(url: &str) -> String {
    // stable, filesystem-safe name per URL
    let mut h: u64 = 0xcbf29ce484222325;
    for b in url.bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    format!("{h:016x}.txt")
}

/// One block list: download (when `fetch`; the last good copy is kept on
/// failure) and parse it. `None` when there is no copy yet.
pub(crate) async fn load_list(
    env: &LanEnv,
    url: &str,
    fetch: bool,
    max_age_secs: u64,
    rep: &mut ApplyReport,
) -> Option<BTreeSet<String>> {
    let dir = env.path(DNSBL_CACHE);
    let cache = dir.join(cache_name(url));
    // a copy younger than `max_age_secs` is not downloaded again
    let fresh = max_age_secs > 0
        && std::fs::metadata(&cache)
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| t.elapsed().ok())
            .is_some_and(|age| age.as_secs() < max_age_secs);
    if fetch && !fresh {
        let _ = std::fs::create_dir_all(&dir);
        let tmp = cache.with_extension("new");
        let res = tokio::process::Command::new("curl")
            .args([
                "-fsSL",
                "--max-time",
                "60",
                "--max-filesize",
                "67108864",
                "-o",
            ])
            .arg(&tmp)
            .arg(url)
            .output()
            .await;
        match res {
            Ok(o) if o.status.success() => {
                let _ = std::fs::rename(&tmp, &cache);
            }
            Ok(o) => rep.warn(format!(
                "block list {url}: download failed ({}), using the cached copy",
                String::from_utf8_lossy(&o.stderr).trim()
            )),
            Err(e) => rep.warn(format!("block list {url}: cannot run curl: {e}")),
        }
    }
    match std::fs::read_to_string(&cache) {
        Ok(body) => {
            let d = parse_blocklist(&body);
            rep.applied(format!("block list {url}: {} domains", d.len()));
            Some(d)
        }
        Err(_) => {
            rep.warn(format!("block list {url}: no copy available yet"));
            None
        }
    }
}

/// Fetch every configured list (keeping the last good copy on failure) and
/// return the full set of blocked domains.
pub async fn blocked_domains(
    store: &ConfigStore,
    env: &LanEnv,
    s: &DnsSettings,
    fetch: bool,
    rep: &mut ApplyReport,
) -> Result<BTreeSet<String>> {
    let mut all: BTreeSet<String> = list_blocked(store)
        .await?
        .into_iter()
        .map(|b| b.domain)
        .collect();
    for url in &s.blocklist_urls {
        if let Some(d) = load_list(env, url, fetch, 0, rep).await {
            all.extend(d);
        }
    }
    Ok(all)
}

// ---------------------------------------------------------------------------
// rendering
// ---------------------------------------------------------------------------

struct Served {
    devs: Vec<String>,
    addrs: Vec<IpAddr>,
    nets: Vec<String>,
}

async fn served(
    store: &ConfigStore,
    env: &LanEnv,
    s: &DnsSettings,
    rep: &mut ApplyReport,
) -> Result<Served> {
    let all = env.addrs()?;
    let mut devs = Vec::new();
    for spec in &s.interfaces {
        let d = lan::resolve_iface(store, spec).await?;
        if d.is_empty() {
            rep.warn(format!(
                "DNS on {spec}: interface role is not assigned, skipped"
            ));
        }
        devs.extend(d);
    }
    devs.sort();
    devs.dedup();
    let mine: Vec<&lan::IfAddr> = all
        .iter()
        .filter(|a| devs.contains(&a.ifname))
        .filter(|a| a.addr.is_ipv4() || a.is_global_v6())
        .collect();
    let mut nets: Vec<String> = mine
        .iter()
        .filter_map(|a| a.network().map(|n| n.to_string()))
        .collect();
    nets.sort();
    nets.dedup();
    // HA: the resolver answers on the virtual IP too (unbound binds it with
    // ip-freebind before it exists), and the list is the same on MASTER and
    // BACKUP: live VIPs are dropped from the scan and re-added from the config
    let vips: Vec<(String, std::net::IpAddr)> = crate::ha_carp_vips(store)
        .await?
        .into_iter()
        .filter(|(d, _)| devs.contains(d))
        .map(|(d, n)| (d, n.ip()))
        .collect();
    let mut addrs: Vec<IpAddr> = mine
        .iter()
        .filter(|a| !vips.iter().any(|(d, ip)| *d == a.ifname && *ip == a.addr))
        .map(|a| a.addr)
        .collect();
    for (_, ip) in &vips {
        if !addrs.contains(ip) {
            addrs.push(*ip);
        }
    }
    Ok(Served { addrs, devs, nets })
}

fn rr(addr: &IpAddr) -> &'static str {
    if addr.is_ipv4() {
        "A"
    } else {
        "AAAA"
    }
}

/// `/etc/unbound/unbound.conf`.
#[allow(clippy::too_many_arguments)]
pub fn render_unbound(
    s: &DnsSettings,
    sv_addrs: &[IpAddr],
    sv_nets: &[String],
    hosts: &[HostOverride],
    domains: &[DomainOverride],
    blocked: &BTreeSet<String>,
    dnssec: bool,
) -> String {
    let mut c = lan::header("#", "Unbound DNS resolver");
    c.push_str("server:\n    verbosity: 1\n    use-syslog: yes\n");
    c.push_str("    chroot: \"\"\n    username: \"unbound\"\n    directory: \"/etc/unbound\"\n");
    c.push_str(
        "    pidfile: \"/run/unbound.pid\"\n    port: 53\n    do-ip4: yes\n    do-ip6: yes\n",
    );
    c.push_str("    do-udp: yes\n    do-tcp: yes\n    ip-freebind: yes\n");
    c.push_str("    interface: 127.0.0.1\n    interface: ::1\n");
    for a in sv_addrs {
        c.push_str(&format!("    interface: {a}\n"));
    }
    c.push_str("    access-control: 0.0.0.0/0 refuse\n    access-control: ::/0 refuse\n");
    c.push_str("    access-control: 127.0.0.0/8 allow\n    access-control: ::1/128 allow\n");
    for n in sv_nets {
        c.push_str(&format!("    access-control: {n} allow\n"));
    }
    c.push_str("    hide-identity: yes\n    hide-version: yes\n    prefetch: yes\n");
    if dot(s) {
        c.push_str(&format!("    tls-cert-bundle: \"{UNBOUND_CA_BUNDLE}\"\n"));
    }
    // unbound refuses to forward to 127.0.0.0/8 / ::1 unless told otherwise
    // (a local DNS server on another port is a common domain override)
    if domains.iter().any(|d| d.server.is_loopback()) || s.upstreams.iter().any(|u| u.is_loopback())
    {
        c.push_str("    do-not-query-localhost: no\n");
    }
    c.push_str("    qname-minimisation: yes\n    harden-glue: yes\n");
    // DNS rebinding protection: a public name must not resolve into the LAN.
    // private-domain lifts it for the names that legitimately do (domain
    // overrides below, host-override domains, the operator's exceptions).
    if s.rebind_protection {
        for r in REBIND_PRIVATE_RANGES {
            c.push_str(&format!("    private-address: {r}\n"));
        }
        let mut ok: BTreeSet<&str> = BTreeSet::new();
        ok.extend(s.rebind_exceptions.iter().map(String::as_str));
        ok.extend(hosts.iter().map(|h| h.domain.as_str()));
        for d in domains {
            ok.remove(d.domain.as_str()); // emitted with the override below
        }
        for d in ok {
            c.push_str(&format!("    private-domain: \"{d}.\"\n"));
        }
    }
    if dnssec {
        c.push_str(&format!(
            "    auto-trust-anchor-file: \"{UNBOUND_ANCHOR}\"\n"
        ));
        if s.dns64_prefix.is_some() {
            c.push_str("    module-config: \"dns64 validator iterator\"\n");
        }
    } else if s.dns64_prefix.is_some() {
        c.push_str("    module-config: \"dns64 iterator\"\n");
    } else {
        c.push_str("    module-config: \"iterator\"\n");
    }
    // DNS64 (USE=nat64): synthesize AAAA records for IPv4-only names so
    // IPv6-only clients reach them through the NAT64 gateway.
    if let Some(p) = &s.dns64_prefix {
        c.push_str(&format!("    dns64-prefix: {p}\n"));
    }
    // One local-zone per name (unbound rejects duplicates). Host overrides:
    // transparent zones answer the override and resolve every other name in
    // the domain normally. Domain overrides: transparent too, which lifts
    // unbound's built-in static zones (test., invalid., onion., home.arpa.,
    // the RFC 1918 reverse zones, ...) so `corp.test` or
    // `168.192.in-addr.arpa` really reach the configured server instead of
    // getting NXDOMAIN locally. Blocked domains win over both.
    let kind = if s.block_mode == "null" {
        "always_null"
    } else {
        "always_nxdomain"
    };
    let mut zones: BTreeMap<&str, &str> = BTreeMap::new();
    if !s.local_domain.is_empty() {
        zones.insert(s.local_domain.as_str(), "transparent");
    }
    for z in hosts.iter().map(|h| h.domain.as_str()) {
        zones.insert(z, "transparent");
    }
    for d in domains {
        zones.insert(d.domain.as_str(), "transparent");
    }
    for b in blocked {
        zones.insert(b.as_str(), kind);
    }
    for (z, k) in &zones {
        c.push_str(&format!("    local-zone: \"{z}.\" {k}\n"));
    }
    for h in hosts {
        c.push_str(&format!(
            "    local-data: \"{}.{}. 3600 IN {} {}\"\n    local-data-ptr: \"{} {}.{}\"\n",
            h.hostname,
            h.domain,
            rr(&h.address),
            h.address,
            h.address,
            h.hostname,
            h.domain
        ));
    }
    for d in domains {
        // private/internal domains are not DNSSEC-signed
        c.push_str(&format!(
            "    domain-insecure: \"{0}.\"\n    private-domain: \"{0}.\"\n",
            d.domain
        ));
    }
    c.push_str(
        "\nremote-control:\n    control-enable: yes\n    control-interface: /run/unbound.ctl\n",
    );
    let mut by_domain: BTreeMap<&str, Vec<String>> = BTreeMap::new();
    for d in domains {
        by_domain
            .entry(d.domain.as_str())
            .or_default()
            .push(format!("{}@{}", d.server, d.port));
    }
    for (dom, servers) in by_domain {
        c.push_str(&format!("\nforward-zone:\n    name: \"{dom}.\"\n"));
        for sv in servers {
            c.push_str(&format!("    forward-addr: {sv}\n"));
        }
    }
    if !s.upstreams.is_empty() {
        c.push_str("\nforward-zone:\n    name: \".\"\n");
        if dot(s) {
            // DNS over TLS: port 853, certificate must carry the name;
            // never falls back to plain DNS
            c.push_str("    forward-tls-upstream: yes\n");
            for u in &s.upstreams {
                c.push_str(&format!(
                    "    forward-addr: {u}@853#{}\n",
                    s.upstream_tls_name
                ));
            }
        } else {
            for u in &s.upstreams {
                c.push_str(&format!("    forward-addr: {u}\n"));
            }
        }
    }
    c
}

/// Is DNS over TLS to the upstreams in effect?
fn dot(s: &DnsSettings) -> bool {
    s.upstream_tls && !s.upstreams.is_empty() && !s.upstream_tls_name.is_empty()
}

/// `(<host>.<domain>, ip)` of static DHCP mappings with a hostname.
/// `only_dns_record`: just the ones flagged `dns_record`.
pub async fn static_records(
    store: &ConfigStore,
    domain: &str,
    only_dns_record: bool,
) -> Result<Vec<(String, std::net::Ipv4Addr)>> {
    #[cfg(feature = "dhcp")]
    {
        let mut out = Vec::new();
        for p in crate::dhcp::list_pools(store).await? {
            for m in p.static_mappings {
                if let Some(h) = m.hostname.filter(|_| m.dns_record || !only_dns_record) {
                    out.push((format!("{h}.{domain}"), m.ip));
                }
            }
        }
        out.sort();
        out.dedup();
        Ok(out)
    }
    #[cfg(not(feature = "dhcp"))]
    {
        let _ = (store, domain, only_dns_record);
        Ok(Vec::new())
    }
}

/// DNS lines of `/etc/dnsmasq.conf` (forwarder mode only).
pub async fn dnsmasq_part(
    store: &ConfigStore,
    env: &LanEnv,
    _rep: &mut ApplyReport,
) -> Result<DnsmasqPart> {
    let s = settings(store).await?;
    if s.effective_mode(env) != "forwarder" {
        return Ok(DnsmasqPart::default());
    }
    let mut quiet = ApplyReport::default();
    let sv = served(store, env, &s, &mut quiet).await?;
    let mut lines = vec![
        "domain-needed".to_string(),
        "bogus-priv".to_string(),
        format!("cache-size={}", s.cache_size),
        // the router's own /etc/hosts maps its name to 127.0.1.1 for local
        // tools; served to the LAN that sends clients to their own loopback
        "no-hosts".to_string(),
    ];
    // the router's own name answers with its address on each served network
    let g = crate::general::settings(store).await?;
    // no name in the store (an install that never set one): the kernel's
    #[cfg(not(test))]
    let kernel = std::fs::read_to_string("/proc/sys/kernel/hostname")
        .ok()
        .map(|h| h.trim().to_string())
        .filter(|h| !h.is_empty() && h != "localhost" && h != "(none)");
    #[cfg(test)]
    let kernel: Option<String> = None;
    if let Some(h) = g.hostname.clone().or(kernel).as_deref() {
        let short = h.split('.').next().unwrap_or(h).to_string();
        let mut names = vec![short.clone()];
        if h.contains('.') {
            names.push(h.to_string());
        } else if let Some(d) = g.domain.as_deref().or(Some(s.local_domain.as_str())) {
            if !d.is_empty() {
                names.push(format!("{short}.{d}"));
            }
        }
        for n in names {
            for dev in &sv.devs {
                lines.push(format!("interface-name={n},{dev}"));
            }
        }
    }
    if s.log_queries {
        lines.push("log-queries".into());
    }
    let local = s.local_domain.as_str();
    if !local.is_empty() {
        // names of DHCP leases and static mappings are <host>.<domain>;
        // the domain is answered here only, never forwarded upstream
        lines.push(format!("domain={local}"));
        lines.push(format!("local=/{local}/"));
        lines.push("expand-hosts".into());
        // dns_record: published whether or not the device is online
        for (name, ip) in static_records(store, local, true).await? {
            lines.push(format!("host-record={name},{ip}"));
        }
    }
    if s.rebind_protection {
        lines.push("stop-dns-rebind".into());
        lines.push("rebind-localhost-ok".into());
        let mut ok: BTreeSet<String> = s.rebind_exceptions.iter().cloned().collect();
        ok.extend(list_hosts(store).await?.into_iter().map(|h| h.domain));
        ok.extend(list_domains(store).await?.into_iter().map(|d| d.domain));
        for d in ok {
            lines.push(format!("rebind-domain-ok=/{d}/"));
        }
    }
    if !s.upstreams.is_empty() {
        lines.push("no-resolv".into());
        for u in &s.upstreams {
            lines.push(format!("server={u}"));
        }
    }
    let mut hosts: BTreeMap<String, Vec<IpAddr>> = BTreeMap::new();
    for h in list_hosts(store).await? {
        hosts
            .entry(format!("{}.{}", h.hostname, h.domain))
            .or_default()
            .push(h.address);
    }
    for (name, addrs) in hosts {
        lines.push(format!(
            "host-record={name},{}",
            addrs
                .iter()
                .map(|a| a.to_string())
                .collect::<Vec<_>>()
                .join(",")
        ));
    }
    for d in list_domains(store).await? {
        lines.push(format!("server=/{}/{}#{}", d.domain, d.server, d.port));
    }
    // the DNS applier reports the block lists itself; the DHCP applier
    // rewrites the same file and must not repeat (or claim) those lines
    let blocked = blocked_domains(store, env, &s, false, &mut ApplyReport::default()).await?;
    for b in blocked {
        if s.block_mode == "null" {
            lines.push(format!("address=/{b}/#"));
        } else {
            lines.push(format!("address=/{b}/"));
        }
    }
    let mut interfaces = sv.devs;
    interfaces.push("lo".into());
    Ok(DnsmasqPart {
        interfaces,
        lines,
        dns: true,
    })
}

// ---------------------------------------------------------------------------
// applier
// ---------------------------------------------------------------------------

/// DNS applier (boot phase `services`).
#[derive(Clone, Default)]
pub struct DnsApplier {
    env: LanEnv,
}

impl DnsApplier {
    pub fn new(env: LanEnv) -> Self {
        Self { env }
    }

    /// DNSSEC needs a root trust anchor unbound can write to; create it
    /// with unbound-anchor (built-in anchor when offline). Without one,
    /// DNSSEC is turned off rather than leaving unbound unable to start.
    fn ensure_anchor(&self, rep: &mut ApplyReport) -> bool {
        let p = self.env.path(UNBOUND_ANCHOR);
        if !p.exists() && self.env.check_configs {
            let _ = Command::new("unbound-anchor").arg("-a").arg(&p).output();
            if let (Ok(Some(u)), true) = (nix::unistd::User::from_name("unbound"), p.exists()) {
                let _ = nix::unistd::chown(&p, Some(u.uid), Some(u.gid));
            }
        }
        if p.exists() {
            true
        } else {
            rep.warn(format!(
                "DNSSEC: no trust anchor at {UNBOUND_ANCHOR} (unbound-anchor failed); validating disabled"
            ));
            false
        }
    }

    async fn unbound_conf(
        &self,
        store: &ConfigStore,
        fetch: bool,
        rep: &mut ApplyReport,
    ) -> Result<String> {
        let s = settings(store).await?;
        let sv = served(store, &self.env, &s, rep).await?;
        let blocked = blocked_domains(store, &self.env, &s, fetch, rep).await?;
        let dnssec = s.dnssec && (!fetch || self.ensure_anchor(rep));
        let mut hosts = list_hosts(store).await?;
        let domains = list_domains(store).await?;
        // local domain: static-mapping hostnames are local-data (lease
        // names need dnsmasq, see docs); the zone itself is transparent
        if !s.local_domain.is_empty() {
            for (name, ip) in static_records(store, &s.local_domain, false).await? {
                if let Some(h) = name.strip_suffix(&format!(".{}", s.local_domain)) {
                    hosts.push(HostOverride {
                        id: 0,
                        hostname: h.to_string(),
                        domain: s.local_domain.clone(),
                        address: IpAddr::V4(ip),
                        description: None,
                    });
                }
            }
        }
        let conf = render_unbound(&s, &sv.addrs, &sv.nets, &hosts, &domains, &blocked, dnssec);
        // per-device / per-group DNS policy views (device segmentation)
        #[cfg(feature = "segmentation")]
        {
            let globals = crate::seg_dns::Globals {
                kind: s.block_mode.clone(),
                hosts,
                domains,
                blocked,
            };
            crate::seg_dns::augment(store, &self.env, conf, globals, fetch, rep).await
        }
        #[cfg(not(feature = "segmentation"))]
        {
            Ok(conf)
        }
    }

    /// Query-log directory + rotation and the "use my resolver" nft table
    /// for devices that have a DNS policy.
    #[cfg(feature = "segmentation")]
    async fn segmentation_side_effects(
        &self,
        store: &ConfigStore,
        rep: &mut ApplyReport,
    ) -> Result<()> {
        let cl = crate::seg_dns::clients(store).await.unwrap_or_default();
        if self.env.check_configs {
            let log = std::path::Path::new(crate::seg_dns::UNBOUND_LOG);
            if let Some(dir) = log.parent() {
                let _ = std::fs::create_dir_all(dir);
                if let Ok(Some(u)) = nix::unistd::User::from_name("unbound") {
                    let _ = nix::unistd::chown(dir, Some(u.uid), Some(u.gid));
                }
            }
            let logging = crate::seg_dns::any_logging(store).await;
            crate::seg_dns::systemd_querylog_dropin(logging, rep);
            if std::path::Path::new("/etc/logrotate.d").is_dir() {
                let _ = std::fs::write(
                    "/etc/logrotate.d/patronus-unbound",
                    crate::seg_dns::LOGROTATE_CONF,
                );
            }
            // an empty set removes the redirect of devices that lost their policy
            let ips: Vec<std::net::Ipv4Addr> = cl.iter().map(|c| c.ip).collect();
            if !ips.is_empty() || crate::seg_dns::enforce_table_exists() {
                crate::seg_dns::apply_enforce(&ips, rep);
            }
        }
        Ok(())
    }

    pub async fn status_value(&self, store: &ConfigStore) -> Result<Value> {
        let s = settings(store).await?;
        Ok(json!({
            "mode": s.mode,
            "effective_mode": s.effective_mode(&self.env),
            "available": {
                "unbound": self.env.has_binary(UNBOUND_BIN),
                "dnsmasq": self.env.has_binary(lan::DNSMASQ_BIN),
            },
            "services": {
                "unbound": self.env.services.is_running("unbound"),
                "dnsmasq": self.env.services.is_running("dnsmasq"),
            },
        }))
    }
}

#[async_trait]
impl Applier for DnsApplier {
    fn name(&self) -> &'static str {
        "dns"
    }

    fn phase(&self) -> Phase {
        Phase::Services
    }

    async fn apply(&self, store: &ConfigStore) -> Result<ApplyReport> {
        let mut rep = ApplyReport::default();
        let s = settings(store).await?;
        let env = &self.env;
        let mode = s.effective_mode(env).to_string();
        if mode == "resolver" {
            if !env.has_binary(UNBOUND_BIN) {
                return Err(Error::Service(
                    "DNS resolver mode needs Unbound but /usr/sbin/unbound is not installed \
                     (emerge net-dns/unbound, USE=unbound) - or switch DNS to forwarder mode"
                        .into(),
                ));
            }
            let conf = self.unbound_conf(store, true, &mut rep).await?;
            let changed = lan::install(
                env,
                &ManagedFile {
                    path: UNBOUND_CONF,
                    content: conf,
                    mode: 0o644,
                    group: None,
                    check: Some(vec![UNBOUND_CHECKCONF, "{}"]),
                },
            )?;
            if changed {
                rep.applied(format!("wrote {UNBOUND_CONF}"));
            }
            #[cfg(feature = "segmentation")]
            self.segmentation_side_effects(store, &mut rep).await?;
            // dnsmasq (DHCP) must give up port 53 before unbound binds it
            lan::sync_dnsmasq(store, env, &mut rep).await?;
            lan::reconcile(env, "unbound", true, changed, UNBOUND_CONF, &mut rep)?;
        } else {
            lan::reconcile(env, "unbound", false, false, UNBOUND_CONF, &mut rep)?;
            #[cfg(feature = "segmentation")]
            if !crate::seg_dns::clients(store)
                .await
                .unwrap_or_default()
                .is_empty()
            {
                rep.warn(
                    "per-device DNS policies need DNS mode \"resolver\" (Unbound): the dnsmasq \
                     forwarder has no per-client views, so they are NOT enforced"
                        .to_string(),
                );
            }
            if mode == "forwarder" && s.upstream_tls {
                rep.warn(
                    "DNS over TLS is on but DNS runs as the dnsmasq forwarder, which cannot use \
                     TLS: upstream queries go out as plain DNS (switch DNS to resolver mode)"
                        .to_string(),
                );
            }
            if mode == "forwarder" {
                // refresh the block list cache before dnsmasq reads it
                blocked_domains(store, env, &s, true, &mut rep).await?;
            }
            lan::sync_dnsmasq(store, env, &mut rep).await?;
        }
        rep.applied(format!("DNS mode: {mode}"));
        Ok(rep)
    }

    async fn render(&self, store: &ConfigStore) -> Result<String> {
        let mut rep = ApplyReport::default();
        let s = settings(store).await?;
        let mode = s.effective_mode(&self.env);
        let mut out = format!("# DNS mode: {mode}\n");
        if mode == "resolver" {
            let c = self.unbound_conf(store, false, &mut rep).await?;
            out.push_str(&format!("## {UNBOUND_CONF} (unbound)\n{c}"));
        } else if let Some(d) = lan::render_dnsmasq(store, &self.env, &mut rep).await? {
            out.push_str(&format!("## {} (dnsmasq)\n{d}", lan::DNSMASQ_CONF));
        }
        for w in &rep.warnings {
            out.push_str(&format!("# warning: {w}\n"));
        }
        Ok(out)
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

    async fn seed(s: &ConfigStore) {
        let h = HostInput {
            hostname: "nas".into(),
            domain: "home.example".into(),
            address: "192.168.50.5".into(),
            description: None,
        }
        .validate()
        .unwrap();
        add_host(s, &h).await.unwrap();
        let d = DomainInput {
            domain: "corp.example".into(),
            server: "10.0.0.53@5353".into(),
            description: None,
        }
        .validate()
        .unwrap();
        add_domain(s, &d).await.unwrap();
        add_blocked(
            s,
            &BlockInput {
                domain: "ads.example".into(),
                description: None,
            },
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn resolver_mode_writes_unbound_conf_with_overrides_and_dnsbl() {
        let t = testutil::env(&[UNBOUND_BIN, lan::DNSMASQ_BIN]);
        std::fs::create_dir_all(t.env.path("/var/lib/unbound")).unwrap();
        std::fs::write(t.env.path(UNBOUND_ANCHOR), "x").unwrap();
        let s = testutil::store().await;
        seed(&s).await;
        let list = t.env.path("/srv/list.txt");
        std::fs::create_dir_all(list.parent().unwrap()).unwrap();
        std::fs::write(&list, "# hosts\n0.0.0.0 tracker.example\nmalware.example\n").unwrap();
        save_settings(
            &s,
            &DnsSettingsInput {
                blocklist_urls: Some(format!("file://{}", list.display())),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let a = DnsApplier::new(t.env.clone());
        a.apply(&s).await.unwrap();
        let c = read(&t, UNBOUND_CONF);
        for want in [
            "interface: 192.168.50.1",
            "interface: fd00:50::1",
            "access-control: 192.168.50.0/24 allow",
            "local-zone: \"home.example.\" transparent",
            "local-data: \"nas.home.example. 3600 IN A 192.168.50.5\"",
            "local-data-ptr: \"192.168.50.5 nas.home.example\"",
            "local-zone: \"ads.example.\" always_nxdomain",
            "local-zone: \"tracker.example.\" always_nxdomain",
            "local-zone: \"malware.example.\" always_nxdomain",
            "name: \"corp.example.\"",
            "forward-addr: 10.0.0.53@5353",
            // lifts unbound's built-in static zones (test., home.arpa., ...)
            "local-zone: \"corp.example.\" transparent",
            "auto-trust-anchor-file",
        ] {
            assert!(c.contains(want), "missing {want:?} in\n{c}");
        }
        let mut zones: Vec<&str> = c.lines().filter(|l| l.contains("local-zone:")).collect();
        let n = zones.len();
        zones.sort();
        zones.dedup();
        assert_eq!(
            n,
            zones.len(),
            "unbound rejects duplicate local-zone lines:\n{c}"
        );
        assert!(!c.contains("interface: 203.0.113.2"), "never serve the WAN");
        assert_eq!(
            *t.services.log.lock().unwrap(),
            vec!["restart unbound".to_string()]
        );
    }

    #[tokio::test]
    async fn forwarder_mode_moves_dns_to_dnsmasq_and_stops_unbound() {
        let t = testutil::env(&[UNBOUND_BIN, lan::DNSMASQ_BIN]);
        let s = testutil::store().await;
        seed(&s).await;
        save_settings(
            &s,
            &DnsSettingsInput {
                dnssec: Some(false),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let a = DnsApplier::new(t.env.clone());
        a.apply(&s).await.unwrap();
        assert!(t.services.is_running("unbound"));
        save_settings(
            &s,
            &DnsSettingsInput {
                mode: Some("forwarder".into()),
                upstreams: Some("9.9.9.9".into()),
                block_mode: Some("null".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        a.apply(&s).await.unwrap();
        assert!(!t.services.is_running("unbound"));
        assert!(t.services.is_running("dnsmasq"));
        let c = read(&t, lan::DNSMASQ_CONF);
        for want in [
            "interface=rtr-lan",
            "interface=lo",
            "no-resolv",
            "server=9.9.9.9",
            "host-record=nas.home.example,192.168.50.5",
            "server=/corp.example/10.0.0.53#5353",
            "address=/ads.example/#",
        ] {
            assert!(c.contains(want), "missing {want:?} in\n{c}");
        }
        assert!(!c.contains("port=0"));
    }

    #[tokio::test]
    async fn rebinding_protection_is_off_for_an_upgraded_store_and_renders_when_on() {
        let t = testutil::env(&[UNBOUND_BIN, lan::DNSMASQ_BIN]);
        std::fs::create_dir_all(t.env.path("/var/lib/unbound")).unwrap();
        std::fs::write(t.env.path(UNBOUND_ANCHOR), "x").unwrap();
        let s = testutil::store().await;
        seed(&s).await;
        // a store that predates the setting: off, nothing rendered
        assert!(!settings(&s).await.unwrap().rebind_protection);
        let a = DnsApplier::new(t.env.clone());
        a.apply(&s).await.unwrap();
        let c = read(&t, UNBOUND_CONF);
        assert!(
            !c.contains("private-address"),
            "split-horizon setups must keep working:\n{c}"
        );
        // switch on, with an exception
        save_settings(
            &s,
            &DnsSettingsInput {
                rebind_protection: Some(true),
                rebind_exceptions: Some("plex.direct, media.example".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        a.apply(&s).await.unwrap();
        let c = read(&t, UNBOUND_CONF);
        for want in [
            "private-address: 10.0.0.0/8",
            "private-address: 172.16.0.0/12",
            "private-address: 192.168.0.0/16",
            "private-address: 169.254.0.0/16",
            "private-address: 127.0.0.0/8",
            "private-address: fd00::/8",
            "private-address: fe80::/10",
            "private-address: ::1/128",
            "private-domain: \"plex.direct.\"",
            "private-domain: \"media.example.\"",
            // host override domain and domain override: the LAN's own names still resolve
            "private-domain: \"home.example.\"",
            "private-domain: \"corp.example.\"",
        ] {
            assert!(c.contains(want), "missing {want:?} in\n{c}");
        }
        let mut pd: Vec<&str> = c
            .lines()
            .filter(|l| l.contains("private-domain:"))
            .collect();
        let n = pd.len();
        pd.sort();
        pd.dedup();
        assert_eq!(n, pd.len(), "no duplicate private-domain lines:\n{c}");
        // and off again
        save_settings(
            &s,
            &DnsSettingsInput {
                rebind_protection: Some(false),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        a.apply(&s).await.unwrap();
        assert!(!read(&t, UNBOUND_CONF).contains("private-address"));
    }

    #[tokio::test]
    async fn rebinding_protection_reaches_the_dnsmasq_forwarder_too() {
        let t = testutil::env(&[UNBOUND_BIN, lan::DNSMASQ_BIN]);
        let s = testutil::store().await;
        seed(&s).await;
        save_settings(
            &s,
            &DnsSettingsInput {
                mode: Some("forwarder".into()),
                upstreams: Some("9.9.9.9".into()),
                rebind_protection: Some(true),
                rebind_exceptions: Some("plex.direct".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        DnsApplier::new(t.env.clone()).apply(&s).await.unwrap();
        let c = read(&t, lan::DNSMASQ_CONF);
        for want in [
            "stop-dns-rebind",
            "rebind-localhost-ok",
            "rebind-domain-ok=/plex.direct/",
            "rebind-domain-ok=/home.example/",
            "rebind-domain-ok=/corp.example/",
        ] {
            assert!(c.contains(want), "missing {want:?} in\n{c}");
        }
    }

    #[tokio::test]
    async fn dns_over_tls_upstreams_render_and_validate() {
        let t = testutil::env(&[UNBOUND_BIN, lan::DNSMASQ_BIN]);
        std::fs::create_dir_all(t.env.path("/var/lib/unbound")).unwrap();
        std::fs::write(t.env.path(UNBOUND_ANCHOR), "x").unwrap();
        let s = testutil::store().await;
        seed(&s).await;
        // needs upstreams and a certificate name, never with the forwarder
        let e = save_settings(
            &s,
            &DnsSettingsInput {
                upstream_tls: Some(true),
                upstream_tls_name: Some("dns.quad9.net".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap_err();
        assert!(e.to_string().contains("upstream servers"), "{e}");
        let e = save_settings(
            &s,
            &DnsSettingsInput {
                upstream_tls: Some(true),
                upstreams: Some("9.9.9.9".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap_err();
        assert!(e.to_string().contains("server name"), "{e}");
        let e = save_settings(
            &s,
            &DnsSettingsInput {
                upstream_tls: Some(true),
                upstreams: Some("9.9.9.9".into()),
                upstream_tls_name: Some("dns.quad9.net\nforward-addr: 6.6.6.6".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap_err();
        assert!(e.to_string().contains("Invalid"), "{e}");
        let e = save_settings(
            &s,
            &DnsSettingsInput {
                mode: Some("forwarder".into()),
                upstream_tls: Some(true),
                upstreams: Some("9.9.9.9".into()),
                upstream_tls_name: Some("dns.quad9.net".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap_err();
        assert!(e.to_string().contains("resolver"), "{e}");
        save_settings(
            &s,
            &DnsSettingsInput {
                mode: Some("resolver".into()),
                upstream_tls: Some(true),
                upstreams: Some("9.9.9.9, 2620:fe::fe".into()),
                upstream_tls_name: Some("DNS.Quad9.net.".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let a = DnsApplier::new(t.env.clone());
        a.apply(&s).await.unwrap();
        let c = read(&t, UNBOUND_CONF);
        for want in [
            "tls-cert-bundle: \"/etc/ssl/certs/ca-certificates.crt\"",
            "forward-tls-upstream: yes",
            "forward-addr: 9.9.9.9@853#dns.quad9.net",
            "forward-addr: 2620:fe::fe@853#dns.quad9.net",
        ] {
            assert!(c.contains(want), "missing {want:?} in\n{c}");
        }
        assert!(
            !c.contains("forward-addr: 9.9.9.9\n"),
            "no plain fallback:\n{c}"
        );
        // off again: plain forwarding
        save_settings(
            &s,
            &DnsSettingsInput {
                upstream_tls: Some(false),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        a.apply(&s).await.unwrap();
        let c = read(&t, UNBOUND_CONF);
        assert!(c.contains("forward-addr: 9.9.9.9\n") && !c.contains("forward-tls-upstream"));
        assert!(!c.contains("tls-cert-bundle"));
    }

    #[tokio::test]
    async fn rebind_exceptions_are_validated() {
        let s = testutil::store().await;
        for bad in [
            "evil\"; private-address: 0.0.0.0/0",
            "x.example;y",
            "x.example\nserver:",
            "x$(id).example",
            "x.example\"",
        ] {
            let r = save_settings(
                &s,
                &DnsSettingsInput {
                    rebind_exceptions: Some(bad.into()),
                    ..Default::default()
                },
            )
            .await;
            assert!(r.is_err(), "{bad:?} must be refused");
        }
        assert!(settings(&s).await.unwrap().rebind_exceptions.is_empty());
    }

    #[test]
    fn rejects_bad_input() {
        assert!(HostInput {
            hostname: "a b".into(),
            domain: "x.example".into(),
            address: "1.2.3.4".into(),
            description: None
        }
        .validate()
        .is_err());
        assert!(DomainInput {
            domain: "corp.example".into(),
            server: "10.0.0.53\nforward-addr: 1.1.1.1".into(),
            description: None
        }
        .validate()
        .is_err());
        assert!(check_url("ftp://x").is_err());
        assert!(check_url("https://x.example/list\"").is_err());
        let d = parse_blocklist("127.0.0.1 localhost\n0.0.0.0 a.example b.example # c\nbad name\n");
        assert_eq!(d.len(), 2);
    }

    #[tokio::test]
    async fn local_domain_cache_log_and_static_names_in_dnsmasq() {
        let t = testutil::env(&[UNBOUND_BIN, lan::DNSMASQ_BIN]);
        let s = testutil::store().await;
        seed(&s).await;
        // a static mapping with dns_record (published offline) and one without
        let pool = crate::dhcp::PoolInput {
            interface: "@lan".into(),
            enabled: true,
            range_start: "192.168.50.100".into(),
            range_end: "192.168.50.199".into(),
            ..Default::default()
        }
        .validate()
        .unwrap();
        let pid = crate::dhcp::upsert_pool(&s, None, &pool).await.unwrap();
        let pool = crate::dhcp::get_pool(&s, pid).await.unwrap().unwrap();
        for (mac, ip, h, rec) in [
            ("aa:bb:cc:00:00:01", "192.168.50.20", "printer", true),
            ("aa:bb:cc:00:00:02", "192.168.50.21", "camera", false),
        ] {
            let m = crate::dhcp::StaticInput {
                mac: mac.into(),
                ip: ip.into(),
                hostname: Some(h.into()),
                dns_record: rec,
                ..Default::default()
            }
            .validate(&pool)
            .unwrap();
            crate::dhcp::add_static(&s, &m).await.unwrap();
        }
        save_settings(
            &s,
            &DnsSettingsInput {
                mode: Some("forwarder".into()),
                upstreams: Some("9.9.9.9".into()),
                dnssec: Some(false),
                local_domain: Some(" .Lan.Example. ".into()),
                cache_size: Some(2500),
                log_queries: Some(true),
                // DNS to a WireGuard device as well as the LAN
                interfaces: Some("@lan,wg0".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let set = settings(&s).await.unwrap();
        assert_eq!(set.local_domain, "lan.example");
        assert_eq!((set.cache_size, set.log_queries), (2500, true));
        crate::general::save_settings(
            &s,
            &crate::general::GeneralInput {
                hostname: Some("gw".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        DnsApplier::new(t.env.clone()).apply(&s).await.unwrap();
        let c = read(&t, lan::DNSMASQ_CONF);
        for want in [
            "cache-size=2500",
            "log-queries",
            "domain=lan.example",
            "local=/lan.example/",
            "expand-hosts",
            "host-record=printer.lan.example,192.168.50.20",
            "interface=wg0",
            "server=/corp.example/10.0.0.53#5353",
            // the router's own name: its interface addresses, never /etc/hosts' 127.0.1.1
            "no-hosts",
            "interface-name=gw,wg0",
            "interface-name=gw.lan.example,wg0",
        ] {
            assert!(c.contains(want), "missing {want:?} in\n{c}");
        }
        assert!(
            !c.contains("camera.lan.example"),
            "no dns_record, no offline name:\n{c}"
        );
        // off again
        save_settings(
            &s,
            &DnsSettingsInput {
                local_domain: Some("".into()),
                log_queries: Some(false),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        DnsApplier::new(t.env.clone()).apply(&s).await.unwrap();
        let c = read(&t, lan::DNSMASQ_CONF);
        for no in [
            "expand-hosts",
            "local=/",
            "log-queries",
            "host-record=printer",
        ] {
            assert!(!c.contains(no), "{no} still present:\n{c}");
        }
    }

    #[tokio::test]
    async fn local_domain_and_cache_validation_and_defaults() {
        let s = testutil::store().await;
        let d = settings(&s).await.unwrap();
        assert_eq!(
            (d.local_domain.as_str(), d.cache_size, d.log_queries),
            ("", 10000, false)
        );
        for bad in ["bad domain", "a..b", "x;y"] {
            let r = save_settings(
                &s,
                &DnsSettingsInput {
                    local_domain: Some(bad.into()),
                    ..Default::default()
                },
            )
            .await;
            assert!(r.is_err(), "{bad}");
        }
        let r = save_settings(
            &s,
            &DnsSettingsInput {
                cache_size: Some(MAX_CACHE_SIZE + 1),
                ..Default::default()
            },
        )
        .await;
        assert!(r.is_err());
    }

    #[tokio::test]
    async fn resolver_mode_keeps_local_domain_local_and_adds_static_names() {
        let t = testutil::env(&[UNBOUND_BIN, lan::DNSMASQ_BIN]);
        std::fs::create_dir_all(t.env.path("/var/lib/unbound")).unwrap();
        std::fs::write(t.env.path(UNBOUND_ANCHOR), "x").unwrap();
        let s = testutil::store().await;
        let pool = crate::dhcp::PoolInput {
            interface: "@lan".into(),
            enabled: true,
            range_start: "192.168.50.100".into(),
            range_end: "192.168.50.199".into(),
            ..Default::default()
        }
        .validate()
        .unwrap();
        let pid = crate::dhcp::upsert_pool(&s, None, &pool).await.unwrap();
        let pool = crate::dhcp::get_pool(&s, pid).await.unwrap().unwrap();
        let m = crate::dhcp::StaticInput {
            mac: "aa:bb:cc:00:00:01".into(),
            ip: "192.168.50.20".into(),
            hostname: Some("printer".into()),
            ..Default::default()
        }
        .validate(&pool)
        .unwrap();
        crate::dhcp::add_static(&s, &m).await.unwrap();
        save_settings(
            &s,
            &DnsSettingsInput {
                dnssec: Some(false),
                local_domain: Some("lan.example".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        DnsApplier::new(t.env.clone()).apply(&s).await.unwrap();
        let c = read(&t, UNBOUND_CONF);
        assert!(
            c.contains("local-zone: \"lan.example.\" transparent"),
            "{c}"
        );
        assert!(c.contains("printer.lan.example."), "{c}");
        assert!(c.contains("192.168.50.20"), "{c}");
    }
}
