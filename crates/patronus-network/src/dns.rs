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
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DnsSettingsInput {
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
}

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
    let after = {
        let mut s = settings(store).await?;
        for (k, v) in &kv {
            match *k {
                "dns.mode" => s.mode = v.clone(),
                "dns.upstreams" => s.upstreams = lan::parse_ip_list("", v)?,
                _ => {}
            }
        }
        s
    };
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
    let dir = env.path(DNSBL_CACHE);
    for url in &s.blocklist_urls {
        let cache = dir.join(cache_name(url));
        if fetch {
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
                all.extend(d);
            }
            Err(_) => rep.warn(format!("block list {url}: no copy available yet")),
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
    Ok(Served {
        addrs: mine.iter().map(|a| a.addr).collect(),
        devs,
        nets,
    })
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
    // unbound refuses to forward to 127.0.0.0/8 / ::1 unless told otherwise
    // (a local DNS server on another port is a common domain override)
    if domains.iter().any(|d| d.server.is_loopback()) || s.upstreams.iter().any(|u| u.is_loopback())
    {
        c.push_str("    do-not-query-localhost: no\n");
    }
    c.push_str("    qname-minimisation: yes\n    harden-glue: yes\n");
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
        for u in &s.upstreams {
            c.push_str(&format!("    forward-addr: {u}\n"));
        }
    }
    c
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
        "cache-size=10000".to_string(),
    ];
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
        Ok(render_unbound(
            &s,
            &sv.addrs,
            &sv.nets,
            &list_hosts(store).await?,
            &list_domains(store).await?,
            &blocked,
            dnssec,
        ))
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
            // dnsmasq (DHCP) must give up port 53 before unbound binds it
            lan::sync_dnsmasq(store, env, &mut rep).await?;
            lan::reconcile(env, "unbound", true, changed, UNBOUND_CONF, &mut rep)?;
        } else {
            lan::reconcile(env, "unbound", false, false, UNBOUND_CONF, &mut rep)?;
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
}
