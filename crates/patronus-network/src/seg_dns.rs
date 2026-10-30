//! Per-device / per-group DNS policy and query logs (design section 6, "c2").
//!
//! A *DNS policy* (`seg_dns_policies`) is attached to a group or to one
//! device (`dns_policy_id`, the device wins). The unbound applier renders
//! one `view:` per policy in use and maps every device's reserved IPv4 to it
//! with `access-control-view` (the same address the nft isolation layer
//! uses as the device identity):
//!
//! - block / allow / override rules and extra block-list URLs per policy;
//! - the *family* preset: adult + malware lists, safe-search CNAMEs (Google,
//!   YouTube, Bing, DuckDuckGo, Brave) and the "turn DoH off" canary names
//!   (Firefox, iCloud Private Relay);
//! - `inherit_global` = unbound `view-first: yes` (the global block lists and
//!   overrides still apply). A policy with *allow* rules cannot be a
//!   view-first view (unbound falls back to the global zone and the global
//!   block would win), so its view carries a copy of the global zones minus
//!   the allowed names and has `view-first: no`.
//! - per-device query logs: unbound `log-replies` + `log-local-actions` to a
//!   file, tailed by patronus-web ([`ingest`]), stored in `seg_dns_log` for
//!   the policies with `log_queries = 1` only, pruned by retention days.
//! - enforcement of "use my resolver": [`render_enforce`] (table
//!   `inet patronus_dnspol`) redirects udp/tcp 53 of policed devices to the
//!   router's resolver and refuses DNS-over-TLS (853). DoH cannot be blocked
//!   reliably (stated in the UI).
//!
//! Needs the unbound resolver mode; dnsmasq forwarder mode has no views and
//! the applier says so instead of pretending.

use crate::dns;
use crate::lan::{self, LanEnv};
use patronus_config::applier::ApplyReport;
use patronus_config::store::ConfigStore;
use patronus_core::{Error, Result};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};

/// unbound log file (read by patronus-web).
pub const UNBOUND_LOG: &str = "/var/log/unbound/unbound.log";
pub const ENFORCE_TABLE: &str = "patronus_dnspol";
/// lists refreshed at most this often by policy applies
pub const LIST_MAX_AGE: u64 = 6 * 3600;

/// Family preset lists (`dns.family_lists` in `lan_settings` overrides them).
pub const FAMILY_LISTS: &[&str] = &[
    "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/porn-only/hosts",
    "https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-hosts.txt",
];

/// Safe-search enforcement: `(name, CNAME target)`, from the providers' docs
/// (Google forcesafesearch, YouTube strict mode, Bing strict, DuckDuckGo
/// safe, Brave forcesafe).
pub const SAFE_SEARCH: &[(&str, &str)] = &[
    ("www.google.com", "forcesafesearch.google.com"),
    ("www.youtube.com", "restrict.youtube.com"),
    ("m.youtube.com", "restrict.youtube.com"),
    ("youtubei.googleapis.com", "restrict.youtube.com"),
    ("youtube.googleapis.com", "restrict.youtube.com"),
    ("www.youtube-nocookie.com", "restrict.youtube.com"),
    ("www.bing.com", "strict.bing.com"),
    ("duckduckgo.com", "safe.duckduckgo.com"),
    ("www.duckduckgo.com", "safe.duckduckgo.com"),
    ("search.brave.com", "forcesafe.search.brave.com"),
];

/// Names whose NXDOMAIN tells the client to switch its encrypted-DNS bypass
/// off (Firefox DoH canary, Apple iCloud Private Relay).
pub const DOH_CANARIES: &[&str] = &[
    "use-application-dns.net",
    "mask.icloud.com",
    "mask-h2.icloud.com",
];

// ---------------------------------------------------------------------------
// model
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Policy {
    pub id: i64,
    pub name: String,
    pub description: Option<String>,
    pub block_mode: String,
    pub blocklist_urls: Vec<String>,
    pub family: bool,
    pub log_queries: bool,
    pub log_retention_days: i64,
    pub inherit_global: bool,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct PolicyInput {
    pub name: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub block_mode: Option<String>,
    /// URLs separated by space, comma or newline
    #[serde(default)]
    pub blocklist_urls: Option<String>,
    #[serde(default)]
    pub family: Option<bool>,
    #[serde(default)]
    pub log_queries: Option<bool>,
    #[serde(default)]
    pub log_retention_days: Option<i64>,
    #[serde(default)]
    pub inherit_global: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Rule {
    pub id: i64,
    pub policy_id: i64,
    pub action: String,
    pub domain: String,
    pub address: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct RuleInput {
    pub action: String,
    pub domain: String,
    #[serde(default)]
    pub address: Option<String>,
}

/// A device (or the clients of a group) the policy applies to.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Client {
    pub device_id: i64,
    pub name: String,
    pub ip: Ipv4Addr,
    pub policy_id: i64,
}

fn split_urls(s: &str) -> Vec<String> {
    s.split([',', ' ', '\n', '\t'])
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .map(String::from)
        .collect()
}

pub fn valid_policy_name(n: &str) -> bool {
    (1..=32).contains(&n.len())
        && n.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
}

fn row_policy(r: &sqlx::sqlite::SqliteRow) -> Policy {
    Policy {
        id: r.get("id"),
        name: r.get("name"),
        description: r.get("description"),
        block_mode: r.get("block_mode"),
        blocklist_urls: split_urls(&r.get::<String, _>("blocklist_urls")),
        family: r.get::<i64, _>("family") != 0,
        log_queries: r.get::<i64, _>("log_queries") != 0,
        log_retention_days: r.get("log_retention_days"),
        inherit_global: r.get::<i64, _>("inherit_global") != 0,
    }
}

const POLICY_COLS: &str =
    "id, name, description, block_mode, blocklist_urls, family, log_queries, log_retention_days, inherit_global";

pub async fn list_policies(store: &ConfigStore) -> Result<Vec<Policy>> {
    let rows = sqlx::query(&format!(
        "SELECT {POLICY_COLS} FROM seg_dns_policies ORDER BY name"
    ))
    .fetch_all(store.pool()?)
    .await
    .map_err(lan::db_err("list DNS policies"))?;
    Ok(rows.iter().map(row_policy).collect())
}

pub async fn get_policy(store: &ConfigStore, id: i64) -> Result<Option<Policy>> {
    let r = sqlx::query(&format!(
        "SELECT {POLICY_COLS} FROM seg_dns_policies WHERE id = ?"
    ))
    .bind(id)
    .fetch_optional(store.pool()?)
    .await
    .map_err(lan::db_err("get DNS policy"))?;
    Ok(r.as_ref().map(row_policy))
}

fn check_input(i: &PolicyInput, creating: bool) -> Result<()> {
    if creating && i.name.is_none() {
        return Err(lan::invalid("policy name is required"));
    }
    if let Some(n) = &i.name {
        if !valid_policy_name(n) {
            return Err(lan::invalid(format!(
                "policy name {n:?} (a-z, 0-9, - and _, at most 32)"
            )));
        }
    }
    if let Some(m) = &i.block_mode {
        if !matches!(m.as_str(), "nxdomain" | "null") {
            return Err(lan::invalid(format!("block mode {m:?} (nxdomain or null)")));
        }
    }
    if let Some(u) = &i.blocklist_urls {
        for url in split_urls(u) {
            dns::check_url(&url)?;
        }
    }
    if let Some(d) = i.log_retention_days {
        if !(1..=365).contains(&d) {
            return Err(lan::invalid("log retention must be 1..365 days"));
        }
    }
    lan::check_description(i.description.as_deref())?;
    Ok(())
}

pub async fn create_policy(store: &ConfigStore, i: &PolicyInput) -> Result<i64> {
    check_input(i, true)?;
    let name = i.name.clone().unwrap_or_default();
    let urls = split_urls(i.blocklist_urls.as_deref().unwrap_or("")).join("\n");
    let r = sqlx::query(
        "INSERT INTO seg_dns_policies (name, description, block_mode, blocklist_urls, family,
            log_queries, log_retention_days, inherit_global, updated_at)
         VALUES (?,?,?,?,?,?,?,?,?)",
    )
    .bind(&name)
    .bind(&i.description)
    .bind(i.block_mode.as_deref().unwrap_or("nxdomain"))
    .bind(urls)
    .bind(i64::from(i.family.unwrap_or(false)))
    .bind(i64::from(i.log_queries.unwrap_or(false)))
    .bind(i.log_retention_days.unwrap_or(7))
    .bind(i64::from(i.inherit_global.unwrap_or(true)))
    .bind(lan::now())
    .execute(store.pool()?)
    .await
    .map_err(|e| lan::unique_err(e, &name))?;
    Ok(r.last_insert_rowid())
}

pub async fn update_policy(store: &ConfigStore, id: i64, i: &PolicyInput) -> Result<()> {
    check_input(i, false)?;
    let cur = get_policy(store, id)
        .await?
        .ok_or_else(|| Error::Config(format!("DNS policy {id} not found")))?;
    let name = i.name.clone().unwrap_or(cur.name);
    let urls = match &i.blocklist_urls {
        Some(u) => split_urls(u).join("\n"),
        None => cur.blocklist_urls.join("\n"),
    };
    sqlx::query(
        "UPDATE seg_dns_policies SET name=?, description=?, block_mode=?, blocklist_urls=?, family=?,
            log_queries=?, log_retention_days=?, inherit_global=?, updated_at=? WHERE id=?",
    )
    .bind(&name)
    .bind(i.description.clone().or(cur.description))
    .bind(i.block_mode.clone().unwrap_or(cur.block_mode))
    .bind(urls)
    .bind(i64::from(i.family.unwrap_or(cur.family)))
    .bind(i64::from(i.log_queries.unwrap_or(cur.log_queries)))
    .bind(i.log_retention_days.unwrap_or(cur.log_retention_days))
    .bind(i64::from(i.inherit_global.unwrap_or(cur.inherit_global)))
    .bind(lan::now())
    .bind(id)
    .execute(store.pool()?)
    .await
    .map_err(|e| lan::unique_err(e, &name))?;
    Ok(())
}

/// Deleting a policy detaches it from every group and device.
pub async fn delete_policy(store: &ConfigStore, id: i64) -> Result<()> {
    let pool = store.pool()?;
    for sql in [
        "UPDATE seg_groups SET dns_policy_id = NULL WHERE dns_policy_id = ?",
        "UPDATE seg_devices SET dns_policy_id = NULL WHERE dns_policy_id = ?",
        "DELETE FROM seg_dns_rules WHERE policy_id = ?",
    ] {
        sqlx::query(sql)
            .bind(id)
            .execute(pool)
            .await
            .map_err(lan::db_err("detach DNS policy"))?;
    }
    let r = sqlx::query("DELETE FROM seg_dns_policies WHERE id = ?")
        .bind(id)
        .execute(pool)
        .await
        .map_err(lan::db_err("delete DNS policy"))?;
    if r.rows_affected() == 0 {
        return Err(Error::Config(format!("DNS policy {id} not found")));
    }
    Ok(())
}

pub async fn list_rules(store: &ConfigStore, policy_id: i64) -> Result<Vec<Rule>> {
    let rows = sqlx::query(
        "SELECT id, policy_id, action, domain, address FROM seg_dns_rules WHERE policy_id = ? ORDER BY id",
    )
    .bind(policy_id)
    .fetch_all(store.pool()?)
    .await
    .map_err(lan::db_err("list DNS rules"))?;
    Ok(rows
        .iter()
        .map(|r| Rule {
            id: r.get(0),
            policy_id: r.get(1),
            action: r.get(2),
            domain: r.get(3),
            address: r.get(4),
        })
        .collect())
}

pub async fn add_rule(store: &ConfigStore, policy_id: i64, i: &RuleInput) -> Result<i64> {
    if get_policy(store, policy_id).await?.is_none() {
        return Err(Error::Config(format!("DNS policy {policy_id} not found")));
    }
    let domain = lan::check_dns_name("domain", &i.domain)?;
    let address = match (i.action.as_str(), i.address.as_deref().map(str::trim)) {
        ("block" | "allow", _) => None,
        ("override", Some(a)) => Some(
            a.parse::<IpAddr>()
                .map_err(|_| lan::invalid(format!("override address {a:?}")))?
                .to_string(),
        ),
        ("override", None) => return Err(lan::invalid("an override needs an address")),
        (a, _) => {
            return Err(lan::invalid(format!(
                "rule action {a:?} (block, allow or override)"
            )))
        }
    };
    let r = sqlx::query(
        "INSERT INTO seg_dns_rules (policy_id, action, domain, address) VALUES (?,?,?,?)",
    )
    .bind(policy_id)
    .bind(&i.action)
    .bind(&domain)
    .bind(address)
    .execute(store.pool()?)
    .await
    .map_err(|e| lan::unique_err(e, &domain))?;
    Ok(r.last_insert_rowid())
}

pub async fn delete_rule(store: &ConfigStore, policy_id: i64, rule_id: i64) -> Result<()> {
    let r = sqlx::query("DELETE FROM seg_dns_rules WHERE id = ? AND policy_id = ?")
        .bind(rule_id)
        .bind(policy_id)
        .execute(store.pool()?)
        .await
        .map_err(lan::db_err("delete DNS rule"))?;
    if r.rows_affected() == 0 {
        return Err(Error::Config(format!("DNS rule {rule_id} not found")));
    }
    Ok(())
}

/// Attach a policy to a group or device (`None` detaches).
pub async fn assign(
    store: &ConfigStore,
    kind: &str,
    id: i64,
    policy_id: Option<i64>,
) -> Result<()> {
    let table = match kind {
        "group" => "seg_groups",
        "device" => "seg_devices",
        k => {
            return Err(lan::invalid(format!(
                "assign target {k:?} (group or device)"
            )))
        }
    };
    if let Some(p) = policy_id {
        if get_policy(store, p).await?.is_none() {
            return Err(Error::Config(format!("DNS policy {p} not found")));
        }
    }
    let r = sqlx::query(&format!(
        "UPDATE {table} SET dns_policy_id = ? WHERE id = ?"
    ))
    .bind(policy_id)
    .bind(id)
    .execute(store.pool()?)
    .await
    .map_err(lan::db_err("assign DNS policy"))?;
    if r.rows_affected() == 0 {
        return Err(Error::Config(format!("{kind} {id} not found")));
    }
    Ok(())
}

/// The policy currently attached to a group or device (to undo an assignment).
pub async fn assignment(store: &ConfigStore, kind: &str, id: i64) -> Result<Option<i64>> {
    let table = match kind {
        "group" => "seg_groups",
        "device" => "seg_devices",
        k => {
            return Err(lan::invalid(format!(
                "assign target {k:?} (group or device)"
            )))
        }
    };
    sqlx::query_scalar(&format!("SELECT dns_policy_id FROM {table} WHERE id = ?"))
        .bind(id)
        .fetch_optional(store.pool()?)
        .await
        .map_err(lan::db_err("read DNS assignment"))
        .map(Option::flatten)
}

/// Active devices with an effective DNS policy (their own, else their group's).
pub async fn clients(store: &ConfigStore) -> Result<Vec<Client>> {
    let rows = sqlx::query(
        "SELECT d.id, d.name, d.ip4, COALESCE(d.dns_policy_id, g.dns_policy_id)
         FROM seg_devices d JOIN seg_groups g ON g.id = d.group_id
         WHERE d.state = 'active' AND d.ip4 IS NOT NULL
           AND COALESCE(d.dns_policy_id, g.dns_policy_id) IS NOT NULL
         ORDER BY d.id",
    )
    .fetch_all(store.pool()?)
    .await
    .map_err(lan::db_err("list DNS clients"))?;
    Ok(rows
        .iter()
        .filter_map(|r| {
            Some(Client {
                device_id: r.get(0),
                name: r.get(1),
                ip: r.get::<String, _>(2).trim().parse().ok()?,
                policy_id: r.get(3),
            })
        })
        .collect())
}

// ---------------------------------------------------------------------------
// rendering
// ---------------------------------------------------------------------------

/// A policy with everything resolved (lists downloaded, clients known).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Resolved {
    pub name: String,
    pub block_mode: String,
    pub inherit_global: bool,
    pub log: bool,
    pub blocks: BTreeSet<String>,
    pub allows: BTreeSet<String>,
    pub overrides: BTreeMap<String, Vec<IpAddr>>,
    /// safe-search: name -> CNAME target
    pub cnames: BTreeMap<String, String>,
    pub clients: Vec<Ipv4Addr>,
}

/// What a view that does not fall back to the global zones must repeat.
#[derive(Debug, Clone, Default)]
pub struct Globals {
    pub kind: String,
    pub hosts: Vec<dns::HostOverride>,
    pub domains: Vec<dns::DomainOverride>,
    pub blocked: BTreeSet<String>,
}

pub fn view_name(policy: &str) -> String {
    format!("seg_{policy}")
}

fn rr(a: &IpAddr) -> &'static str {
    if a.is_ipv4() {
        "A"
    } else {
        "AAAA"
    }
}

fn kind_of(mode: &str) -> &'static str {
    if mode == "null" {
        "always_null"
    } else {
        "always_nxdomain"
    }
}

/// The text added to unbound.conf for the views.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Extra {
    /// lines of the `server:` clause (`access-control-view`, logging)
    pub server: String,
    /// `view:` clauses, appended at the end of the file
    pub views: String,
}

/// Render the views. `logfile` turns query logging on for the whole server
/// (the tailer keeps only the policies with `log`).
pub fn render_extra(rs: &[Resolved], g: &Globals, logfile: Option<&str>) -> Extra {
    let mut x = Extra::default();
    if let Some(f) = logfile {
        x.server.push_str(&format!(
            "    use-syslog: no\n    logfile: \"{f}\"\n    log-replies: yes\n    log-tag-queryreply: yes\n    log-local-actions: yes\n"
        ));
    }
    for r in rs {
        let v = view_name(&r.name);
        for c in &r.clients {
            x.server
                .push_str(&format!("    access-control-view: {c}/32 \"{v}\"\n"));
        }
        x.views.push_str(&format!("\nview:\n    name: \"{v}\"\n"));
        // zones of this view, one entry per name (unbound rejects duplicates):
        // lists < rules(block) < overrides/safe-search < allow
        let mut zones: BTreeMap<String, &str> = BTreeMap::new();
        let mut data: Vec<String> = Vec::new();
        let copy_global = !r.inherit_global || !r.allows.is_empty();
        if copy_global {
            // `view-first: no`: the view replaces the global zones, so repeat them
            for h in &g.hosts {
                zones.insert(h.domain.clone(), "transparent");
                data.push(format!(
                    "local-data: \"{}.{}. 3600 IN {} {}\"",
                    h.hostname,
                    h.domain,
                    rr(&h.address),
                    h.address
                ));
            }
            for d in &g.domains {
                zones.insert(d.domain.clone(), "transparent");
            }
            if r.inherit_global {
                for b in &g.blocked {
                    zones.insert(b.clone(), kind_of(&g.kind));
                }
            }
        } else {
            x.views.push_str("    view-first: yes\n");
        }
        let kind = kind_of(&r.block_mode);
        for b in &r.blocks {
            zones.insert(b.clone(), kind);
        }
        for (name, addrs) in &r.overrides {
            zones.insert(name.clone(), "typetransparent");
            for a in addrs {
                data.push(format!("local-data: \"{name}. 300 IN {} {a}\"", rr(a)));
            }
        }
        for (name, target) in &r.cnames {
            // `redirect` (not typetransparent): unbound then follows the CNAME
            // and answers with the target's addresses
            zones.insert(name.clone(), "redirect");
            data.push(format!("local-data: \"{name}. 300 IN CNAME {target}.\""));
        }
        for a in &r.allows {
            zones.insert(a.clone(), "transparent");
        }
        for (z, k) in &zones {
            x.views.push_str(&format!("    local-zone: \"{z}.\" {k}\n"));
        }
        for d in &data {
            x.views.push_str(&format!("    {d}\n"));
        }
    }
    x
}

/// Splice the views into a rendered unbound.conf: server lines go to the end
/// of the `server:` clause (before `remote-control:`), views to the end.
pub fn splice(conf: &str, x: &Extra) -> String {
    if x.server.is_empty() && x.views.is_empty() {
        return conf.to_string();
    }
    let mut conf = conf.to_string();
    if x.server.contains("use-syslog: no") {
        conf = conf.replace("    use-syslog: yes\n", "");
    }
    let marker = "\nremote-control:";
    let mut out = match conf.find(marker) {
        Some(i) => {
            let (a, b) = conf.split_at(i);
            format!("{a}\n{}{b}", x.server.trim_end_matches('\n'))
        }
        None => format!("{conf}\n{}", x.server),
    };
    if !out.ends_with('\n') {
        out.push('\n');
    }
    out.push_str(&x.views);
    out
}

/// Per-device DNS enforcement: devices with a policy cannot bypass the
/// resolver with a hard-coded server (redirected) or DNS-over-TLS (refused).
pub fn render_enforce(clients: &[Ipv4Addr]) -> String {
    let t = format!("inet {ENFORCE_TABLE}");
    let mut s = format!("add table {t}\n");
    s.push_str(&format!("add set {t} policed_v4 {{ type ipv4_addr; }}\n"));
    s.push_str(&format!(
        "add chain {t} prerouting {{ type nat hook prerouting priority -102; policy accept; }}\n"
    ));
    s.push_str(&format!(
        "add chain {t} forward {{ type filter hook forward priority -12; policy accept; }}\n"
    ));
    s.push_str(&format!(
        "flush chain {t} prerouting\nflush chain {t} forward\nflush set {t} policed_v4\n"
    ));
    if !clients.is_empty() {
        let ips: Vec<String> = clients.iter().map(|c| c.to_string()).collect();
        s.push_str(&format!(
            "add element {t} policed_v4 {{ {} }}\n",
            ips.join(", ")
        ));
        for proto in ["udp", "tcp"] {
            s.push_str(&format!(
                "add rule {t} prerouting ip saddr @policed_v4 fib daddr type != local {proto} dport 53 counter redirect to :53 comment \"DNS policy\"\n"
            ));
        }
        s.push_str(&format!(
            "add rule {t} forward ip saddr @policed_v4 tcp dport 853 counter reject with tcp reset comment \"DNS policy: no DoT\"\n"
        ));
        s.push_str(&format!(
            "add rule {t} forward ip saddr @policed_v4 udp dport 853 counter drop comment \"DNS policy: no DoT\"\n"
        ));
    }
    s
}

// ---------------------------------------------------------------------------
// resolving policies for the applier
// ---------------------------------------------------------------------------

async fn family_lists(store: &ConfigStore) -> Vec<String> {
    let m = lan::settings_with_prefix(store, "dns.")
        .await
        .unwrap_or_default();
    match m.get("dns.family_lists").filter(|v| !v.trim().is_empty()) {
        Some(v) => split_urls(v),
        None => FAMILY_LISTS.iter().map(|s| s.to_string()).collect(),
    }
}

/// Everything the unbound applier needs: the policies in use (with lists
/// loaded), and a warning for what cannot be honoured.
pub async fn resolve(
    store: &ConfigStore,
    env: &LanEnv,
    fetch: bool,
    rep: &mut ApplyReport,
) -> Result<Vec<Resolved>> {
    let cl = clients(store).await?;
    if cl.is_empty() {
        return Ok(Vec::new());
    }
    let policies: HashMap<i64, Policy> = list_policies(store)
        .await?
        .into_iter()
        .map(|p| (p.id, p))
        .collect();
    let fam = family_lists(store).await;
    let mut out = Vec::new();
    let mut ids: Vec<i64> = cl.iter().map(|c| c.policy_id).collect();
    ids.sort();
    ids.dedup();
    for id in ids {
        let Some(p) = policies.get(&id) else { continue };
        let mut r = Resolved {
            name: p.name.clone(),
            block_mode: p.block_mode.clone(),
            inherit_global: p.inherit_global,
            log: p.log_queries,
            ..Resolved::default()
        };
        let mut urls = p.blocklist_urls.clone();
        if p.family {
            urls.extend(fam.iter().cloned());
        }
        urls.dedup();
        for u in &urls {
            if let Some(d) = dns::load_list(env, u, fetch, LIST_MAX_AGE, rep).await {
                r.blocks.extend(d);
            }
        }
        if p.family {
            for (n, t) in SAFE_SEARCH {
                r.cnames.insert((*n).to_string(), (*t).to_string());
            }
            for n in DOH_CANARIES {
                r.blocks.insert((*n).to_string());
            }
        }
        for rule in list_rules(store, id).await? {
            match rule.action.as_str() {
                "block" => {
                    r.blocks.insert(rule.domain);
                }
                "allow" => {
                    r.allows.insert(rule.domain);
                }
                "override" => {
                    if let Some(a) = rule.address.and_then(|a| a.parse().ok()) {
                        r.overrides.entry(rule.domain).or_default().push(a);
                    }
                }
                _ => {}
            }
        }
        // a rule that blocks AND allows the same name: allow wins (rendered last);
        // an allowed name must not stay in the block set
        r.blocks.retain(|b| !r.allows.contains(b));
        r.clients = cl
            .iter()
            .filter(|c| c.policy_id == id)
            .map(|c| c.ip)
            .collect();
        out.push(r);
    }
    Ok(out)
}

/// The finished unbound.conf: the global rendering plus the views.
pub async fn augment(
    store: &ConfigStore,
    env: &LanEnv,
    conf: String,
    g: Globals,
    fetch: bool,
    rep: &mut ApplyReport,
) -> Result<String> {
    let rs = resolve(store, env, fetch, rep).await?;
    if rs.is_empty() {
        return Ok(conf);
    }
    let logfile = rs.iter().any(|r| r.log).then_some(UNBOUND_LOG);
    Ok(splice(&conf, &render_extra(&rs, &g, logfile)))
}

/// Install the enforcement table (best effort: the resolver config is the
/// source of truth; a missing `nft` is reported, not fatal).
pub fn apply_enforce(clients: &[Ipv4Addr], rep: &mut ApplyReport) {
    let script = render_enforce(clients);
    match run_nft(&script) {
        Ok(()) => rep.applied(format!(
            "DNS policy enforcement: {} device(s) redirected to the resolver",
            clients.len()
        )),
        Err(e) => rep.warn(format!("DNS policy enforcement table: {e}")),
    }
}

/// Is the enforcement table loaded?
pub fn enforce_table_exists() -> bool {
    std::process::Command::new("nft")
        .args(["list", "table", "inet", ENFORCE_TABLE])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn run_nft(script: &str) -> Result<()> {
    use std::io::Write;
    let mut child = std::process::Command::new("nft")
        .args(["-f", "-"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| Error::Network(format!("cannot run nft: {e}")))?;
    if let Some(i) = child.stdin.as_mut() {
        let _ = i.write_all(script.as_bytes());
    }
    let o = child
        .wait_with_output()
        .map_err(|e| Error::Network(format!("nft: {e}")))?;
    if o.status.success() {
        Ok(())
    } else {
        Err(Error::Network(
            String::from_utf8_lossy(&o.stderr).trim().to_string(),
        ))
    }
}

// ---------------------------------------------------------------------------
// query log
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LogEvent {
    /// `reply: <client> <qname> <type> IN <RCODE> <time> <cached> <size>`
    Reply {
        ts: i64,
        client: String,
        qname: String,
        qtype: String,
        rcode: String,
    },
    /// `info: <action> <client> <qname> <type> IN` (log-local-actions)
    Local {
        client: String,
        qname: String,
        qtype: String,
    },
}

/// Parse one unbound log line (epoch timestamps, `log-time-ascii: no`).
pub fn parse_line(line: &str) -> Option<LogEvent> {
    let rest = line.strip_prefix('[')?;
    let (ts, rest) = rest.split_once(']')?;
    let ts: i64 = ts.trim().parse().ok()?;
    let w: Vec<&str> = rest.split_whitespace().collect();
    // w[0] = "unbound[pid:tid]", w[1] = "reply:" | "info:" ...
    let tag = *w.get(1)?;
    match tag {
        "reply:" => {
            // client qname type IN rcode
            let (client, qname, qtype, class, rcode) =
                (*w.get(2)?, *w.get(3)?, *w.get(4)?, *w.get(5)?, *w.get(6)?);
            if class != "IN" {
                return None;
            }
            Some(LogEvent::Reply {
                ts,
                client: client.trim_start_matches("::ffff:").to_string(),
                qname: qname.trim_end_matches('.').to_ascii_lowercase(),
                qtype: qtype.to_string(),
                rcode: rcode.to_string(),
            })
        }
        "info:" => {
            // unbound 1.26: `info: <zone> <action> <client>@<port> <qname> <type> IN`
            // (older: `info: <action> <client> <qname> <type> IN`): find the action
            let i = w.iter().skip(2).position(|t| {
                matches!(
                    *t,
                    "always_nxdomain" | "always_null" | "always_refuse" | "refuse" | "deny"
                )
            })? + 2;
            let client = w.get(i + 1)?.split('@').next()?;
            let (qname, qtype) = (*w.get(i + 2)?, *w.get(i + 3)?);
            Some(LogEvent::Local {
                client: client.trim_start_matches("::ffff:").to_string(),
                qname: qname.trim_end_matches('.').to_ascii_lowercase(),
                qtype: qtype.to_string(),
            })
        }
        _ => None,
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize)]
pub struct IngestStats {
    pub lines: usize,
    pub stored: usize,
    pub skipped: usize,
}

/// Devices whose queries are logged: ip -> (device_id)
async fn logged_devices(store: &ConfigStore) -> Result<HashMap<String, i64>> {
    let rows = sqlx::query(
        "SELECT d.ip4, d.id FROM seg_devices d JOIN seg_groups g ON g.id = d.group_id
         JOIN seg_dns_policies p ON p.id = COALESCE(d.dns_policy_id, g.dns_policy_id)
         WHERE d.ip4 IS NOT NULL AND p.log_queries = 1",
    )
    .fetch_all(store.pool()?)
    .await
    .map_err(lan::db_err("logged devices"))?;
    Ok(rows
        .iter()
        .map(|r| (r.get::<String, _>(0).trim().to_string(), r.get::<i64, _>(1)))
        .collect())
}

const MAX_READ: u64 = 8 * 1024 * 1024;

fn inode_of(m: &std::fs::Metadata) -> i64 {
    use std::os::unix::fs::MetadataExt;
    m.ino() as i64
}

/// Read what unbound appended to `path` since the last call, store the
/// replies of logging devices. Safe across restarts (offset kept in
/// `seg_dns_log_pos`) and rotation (new inode or a shorter file = start over).
pub async fn ingest(store: &ConfigStore, path: &Path) -> Result<IngestStats> {
    use std::io::{Read, Seek, SeekFrom};
    let mut stats = IngestStats::default();
    let Ok(meta) = std::fs::metadata(path) else {
        return Ok(stats);
    };
    let pool = store.pool()?;
    let key = path.to_string_lossy().to_string();
    let pos = sqlx::query("SELECT inode, offset FROM seg_dns_log_pos WHERE path = ?")
        .bind(&key)
        .fetch_optional(pool)
        .await
        .map_err(lan::db_err("log position"))?;
    let (ino, size) = (inode_of(&meta), meta.len());
    let mut offset = match pos {
        // first sight of the file: only what is logged from now on matters
        // when it is huge, else read it all
        None => 0u64,
        Some(r) if r.get::<i64, _>(0) == ino && (r.get::<i64, _>(1) as u64) <= size => {
            r.get::<i64, _>(1) as u64
        }
        Some(_) => 0, // rotated or truncated
    };
    if offset >= size {
        save_pos(store, &key, ino, size).await?;
        return Ok(stats);
    }
    let mut f = std::fs::File::open(path).map_err(|e| Error::Network(format!("{key}: {e}")))?;
    f.seek(SeekFrom::Start(offset))
        .map_err(|e| Error::Network(format!("{key}: {e}")))?;
    let mut buf = Vec::new();
    f.take(MAX_READ)
        .read_to_end(&mut buf)
        .map_err(|e| Error::Network(format!("{key}: {e}")))?;
    // only whole lines; the partial tail is read next time
    let Some(last_nl) = buf.iter().rposition(|b| *b == b'\n') else {
        if (buf.len() as u64) < MAX_READ {
            return Ok(stats);
        }
        // a single 8 MiB "line": skip it
        save_pos(store, &key, ino, offset + buf.len() as u64).await?;
        return Ok(stats);
    };
    buf.truncate(last_nl + 1);
    offset += buf.len() as u64;
    let devices = logged_devices(store).await?;
    let text = String::from_utf8_lossy(&buf);
    let mut blocked: BTreeSet<(String, String, String)> = BTreeSet::new();
    let mut tx = pool.begin().await.map_err(lan::db_err("begin log batch"))?;
    for line in text.lines() {
        stats.lines += 1;
        match parse_line(line) {
            Some(LogEvent::Local {
                client,
                qname,
                qtype,
            }) => {
                if blocked.len() > 4096 {
                    blocked.clear();
                }
                blocked.insert((client, qname, qtype));
            }
            Some(LogEvent::Reply {
                ts,
                client,
                qname,
                qtype,
                rcode,
            }) => {
                let was_blocked = blocked.remove(&(client.clone(), qname.clone(), qtype.clone()));
                let Some(dev) = devices.get(&client) else {
                    stats.skipped += 1;
                    continue;
                };
                sqlx::query(
                    "INSERT INTO seg_dns_log (ts, client, device_id, qname, qtype, rcode, blocked)
                     VALUES (?,?,?,?,?,?,?)",
                )
                .bind(ts)
                .bind(&client)
                .bind(dev)
                .bind(&qname)
                .bind(&qtype)
                .bind(&rcode)
                .bind(i64::from(was_blocked))
                .execute(&mut *tx)
                .await
                .map_err(lan::db_err("store DNS log"))?;
                stats.stored += 1;
            }
            None => stats.skipped += 1,
        }
    }
    sqlx::query(
        "INSERT INTO seg_dns_log_pos (path, inode, offset) VALUES (?,?,?)
         ON CONFLICT(path) DO UPDATE SET inode = excluded.inode, offset = excluded.offset",
    )
    .bind(&key)
    .bind(ino)
    .bind(offset as i64)
    .execute(&mut *tx)
    .await
    .map_err(lan::db_err("save log position"))?;
    tx.commit().await.map_err(lan::db_err("commit log batch"))?;
    Ok(stats)
}

async fn save_pos(store: &ConfigStore, key: &str, ino: i64, offset: u64) -> Result<()> {
    sqlx::query(
        "INSERT INTO seg_dns_log_pos (path, inode, offset) VALUES (?,?,?)
         ON CONFLICT(path) DO UPDATE SET inode = excluded.inode, offset = excluded.offset",
    )
    .bind(key)
    .bind(ino)
    .bind(offset as i64)
    .execute(store.pool()?)
    .await
    .map_err(lan::db_err("save log position"))?;
    Ok(())
}

/// Delete log rows past their policy's retention (devices without a logging
/// policy: 7 days) and keep at most `max_rows` rows.
pub async fn prune(store: &ConfigStore, now_ts: i64, max_rows: i64) -> Result<u64> {
    let pool = store.pool()?;
    let r = sqlx::query(
        "DELETE FROM seg_dns_log WHERE ts < ? - 86400 * COALESCE(
            (SELECT p.log_retention_days FROM seg_devices d JOIN seg_groups g ON g.id = d.group_id
             JOIN seg_dns_policies p ON p.id = COALESCE(d.dns_policy_id, g.dns_policy_id)
             WHERE d.id = seg_dns_log.device_id), 7)",
    )
    .bind(now_ts)
    .execute(pool)
    .await
    .map_err(lan::db_err("prune DNS log"))?;
    let mut n = r.rows_affected();
    let r =
        sqlx::query("DELETE FROM seg_dns_log WHERE id <= (SELECT MAX(id) FROM seg_dns_log) - ?")
            .bind(max_rows.max(1000))
            .execute(pool)
            .await
            .map_err(lan::db_err("cap DNS log"))?;
    n += r.rows_affected();
    Ok(n)
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct LogQuery {
    pub device: Option<i64>,
    /// substring of the queried name
    pub q: Option<String>,
    #[serde(default)]
    pub blocked: bool,
    pub since: Option<i64>,
    pub until: Option<i64>,
    pub limit: Option<i64>,
    /// pagination: only rows with an id below this
    pub before: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct LogRow {
    pub id: i64,
    pub ts: i64,
    pub client: String,
    pub device_id: Option<i64>,
    pub device: Option<String>,
    pub qname: String,
    pub qtype: Option<String>,
    pub rcode: Option<String>,
    pub blocked: bool,
}

fn like_escape(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_")
}

pub async fn search_log(store: &ConfigStore, q: &LogQuery) -> Result<Vec<LogRow>> {
    let mut sql = String::from(
        "SELECT l.id, l.ts, l.client, l.device_id, d.name, l.qname, l.qtype, l.rcode, l.blocked
         FROM seg_dns_log l LEFT JOIN seg_devices d ON d.id = l.device_id WHERE 1=1",
    );
    if q.device.is_some() {
        sql.push_str(" AND l.device_id = ?");
    }
    if q.q.as_deref().is_some_and(|s| !s.is_empty()) {
        sql.push_str(" AND l.qname LIKE ? ESCAPE '\\'");
    }
    if q.blocked {
        sql.push_str(" AND l.blocked = 1");
    }
    if q.since.is_some() {
        sql.push_str(" AND l.ts >= ?");
    }
    if q.until.is_some() {
        sql.push_str(" AND l.ts <= ?");
    }
    if q.before.is_some() {
        sql.push_str(" AND l.id < ?");
    }
    sql.push_str(" ORDER BY l.id DESC LIMIT ?");
    let mut query = sqlx::query(&sql);
    if let Some(d) = q.device {
        query = query.bind(d);
    }
    if let Some(s) = q.q.as_deref().filter(|s| !s.is_empty()) {
        query = query.bind(format!("%{}%", like_escape(&s.to_ascii_lowercase())));
    }
    if let Some(s) = q.since {
        query = query.bind(s);
    }
    if let Some(s) = q.until {
        query = query.bind(s);
    }
    if let Some(b) = q.before {
        query = query.bind(b);
    }
    query = query.bind(q.limit.unwrap_or(200).clamp(1, 5000));
    let rows = query
        .fetch_all(store.pool()?)
        .await
        .map_err(lan::db_err("search DNS log"))?;
    Ok(rows
        .iter()
        .map(|r| LogRow {
            id: r.get(0),
            ts: r.get(1),
            client: r.get(2),
            device_id: r.get(3),
            device: r.get(4),
            qname: r.get(5),
            qtype: r.get(6),
            rcode: r.get(7),
            blocked: r.get::<i64, _>(8) != 0,
        })
        .collect())
}

pub async fn clear_log(store: &ConfigStore, device: Option<i64>) -> Result<u64> {
    let r = match device {
        Some(d) => {
            sqlx::query("DELETE FROM seg_dns_log WHERE device_id = ?")
                .bind(d)
                .execute(store.pool()?)
                .await
        }
        None => {
            sqlx::query("DELETE FROM seg_dns_log")
                .execute(store.pool()?)
                .await
        }
    }
    .map_err(lan::db_err("clear DNS log"))?;
    Ok(r.rows_affected())
}

/// CSV with the spreadsheet-formula guard (a name starting with = + - @ is
/// prefixed with a quote).
pub fn to_csv(rows: &[LogRow]) -> String {
    fn cell(s: &str) -> String {
        let s = if s.starts_with(['=', '+', '-', '@']) {
            format!("'{s}")
        } else {
            s.to_string()
        };
        format!("\"{}\"", s.replace('"', "\"\""))
    }
    let mut out = String::from("time,device,client,name,type,rcode,blocked\n");
    for r in rows {
        let t = chrono::DateTime::from_timestamp(r.ts, 0)
            .map(|d| d.to_rfc3339())
            .unwrap_or_default();
        out.push_str(&format!(
            "{},{},{},{},{},{},{}\n",
            t,
            cell(r.device.as_deref().unwrap_or("")),
            cell(&r.client),
            cell(&r.qname),
            cell(r.qtype.as_deref().unwrap_or("")),
            cell(r.rcode.as_deref().unwrap_or("")),
            r.blocked
        ));
    }
    out
}

pub fn log_path() -> PathBuf {
    std::env::var_os("PATRONUS_UNBOUND_LOG")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(UNBOUND_LOG))
}

/// systemd runs unbound with `-d` (foreground), which sends the log to
/// stderr and ignores `logfile:`. This drop-in appends stdout/stderr to the
/// same file the tailer reads (OpenRC's daemonized unbound honours `logfile:`).
pub const SYSTEMD_DROPIN: &str = "/etc/systemd/system/unbound.service.d/patronus-querylog.conf";
pub const SYSTEMD_DROPIN_BODY: &str = "[Service]\nStandardOutput=append:/var/log/unbound/unbound.log\nStandardError=append:/var/log/unbound/unbound.log\n";

/// Is any device's DNS policy logging queries?
pub async fn any_logging(store: &ConfigStore) -> bool {
    logged_devices(store)
        .await
        .map(|m| !m.is_empty())
        .unwrap_or(false)
}

/// Install (`on`) or remove the systemd drop-in; `daemon-reload` when it changed.
pub fn systemd_querylog_dropin(on: bool, rep: &mut ApplyReport) {
    if !Path::new("/run/systemd/system").is_dir() {
        return;
    }
    let p = Path::new(SYSTEMD_DROPIN);
    let current = std::fs::read_to_string(p).ok();
    let changed = if on {
        if current.as_deref() == Some(SYSTEMD_DROPIN_BODY) {
            false
        } else {
            if let Some(d) = p.parent() {
                let _ = std::fs::create_dir_all(d);
            }
            std::fs::write(p, SYSTEMD_DROPIN_BODY).is_ok()
        }
    } else if current.is_some() {
        std::fs::remove_file(p).is_ok()
    } else {
        false
    };
    if changed {
        let _ = std::process::Command::new("systemctl")
            .arg("daemon-reload")
            .output();
        rep.applied(format!(
            "unbound query log via systemd: drop-in {}",
            if on { "installed" } else { "removed" }
        ));
    }
}

/// logrotate snippet (copytruncate: the tailer notices the shorter file).
pub const LOGROTATE_CONF: &str = "/var/log/unbound/unbound.log {\n    size 50M\n    rotate 2\n    copytruncate\n    missingok\n    notifempty\n    compress\n}\n";

#[cfg(test)]
mod tests {
    use super::*;

    fn res(name: &str) -> Resolved {
        Resolved {
            name: name.into(),
            block_mode: "nxdomain".into(),
            inherit_global: true,
            ..Resolved::default()
        }
    }

    #[test]
    fn parse_unbound_log_lines() {
        let r = parse_line("[1761700000] unbound[691:0] reply: 172.31.77.12 Games.Example. A IN NXDOMAIN 0.000000 0 42").unwrap();
        assert_eq!(
            r,
            LogEvent::Reply {
                ts: 1761700000,
                client: "172.31.77.12".into(),
                qname: "games.example".into(),
                qtype: "A".into(),
                rcode: "NXDOMAIN".into()
            }
        );
        let l = parse_line(
            "[1761700000] unbound[691:0] info: always_nxdomain 172.31.77.12 games.example. A IN",
        )
        .unwrap();
        assert_eq!(
            l,
            LogEvent::Local {
                client: "172.31.77.12".into(),
                qname: "games.example".into(),
                qtype: "A".into()
            }
        );
        // the older layout still parses
        assert_eq!(
            parse_line("[1] unbound[1:0] info: always_null 10.0.0.5 a.example. AAAA IN"),
            Some(LogEvent::Local {
                client: "10.0.0.5".into(),
                qname: "a.example".into(),
                qtype: "AAAA".into()
            })
        );
        // transparent/static hits are not "blocked"; noise is ignored
        assert!(
            parse_line("[1761700000] unbound[691:0] info: transparent 1.2.3.4 x. A IN").is_none()
        );
        assert!(parse_line("[1761700000] unbound[691:0] query: 172.31.77.12 x. A IN").is_none());
        assert!(parse_line("garbage").is_none());
        assert!(parse_line("[x] unbound[1:0] reply: a b c IN NOERROR").is_none());
        // v4-mapped client
        let m = parse_line("[1] unbound[1:0] reply: ::ffff:10.0.0.5 a.b. AAAA IN NOERROR 0.0 1 40")
            .unwrap();
        assert!(matches!(m, LogEvent::Reply { client, .. } if client == "10.0.0.5"));
    }

    #[test]
    fn view_first_policy_renders_block_override_and_safe_search() {
        let mut p = res("kids");
        p.blocks.insert("games.example".into());
        p.overrides
            .insert("printer.lan".into(), vec!["10.0.0.9".parse().unwrap()]);
        p.cnames
            .insert("www.google.com".into(), "forcesafesearch.google.com".into());
        p.clients = vec!["10.0.0.12".parse().unwrap(), "10.0.0.13".parse().unwrap()];
        let x = render_extra(&[p], &Globals::default(), None);
        assert!(x
            .server
            .contains("access-control-view: 10.0.0.12/32 \"seg_kids\""));
        assert!(x
            .server
            .contains("access-control-view: 10.0.0.13/32 \"seg_kids\""));
        assert!(!x.server.contains("logfile"));
        assert!(x
            .views
            .contains("view:\n    name: \"seg_kids\"\n    view-first: yes\n"));
        assert!(x
            .views
            .contains("local-zone: \"games.example.\" always_nxdomain"));
        assert!(x
            .views
            .contains("local-zone: \"printer.lan.\" typetransparent"));
        assert!(x
            .views
            .contains("local-data: \"printer.lan. 300 IN A 10.0.0.9\""));
        assert!(x
            .views
            .contains("local-data: \"www.google.com. 300 IN CNAME forcesafesearch.google.com.\""));
    }

    #[test]
    fn allow_rule_makes_a_self_contained_view_without_the_blocked_name() {
        let mut p = res("teens");
        p.allows.insert("ads.example".into());
        p.clients = vec!["10.0.0.20".parse().unwrap()];
        let g = Globals {
            kind: "always_nxdomain".into(),
            blocked: ["ads.example".to_string(), "bad.example".to_string()].into(),
            hosts: vec![dns::HostOverride {
                id: 1,
                hostname: "nas".into(),
                domain: "home.lan".into(),
                address: "10.0.0.2".parse().unwrap(),
                description: None,
            }],
            domains: vec![],
        };
        let x = render_extra(&[p], &g, None);
        assert!(!x.views.contains("view-first: yes"));
        assert!(x
            .views
            .contains("local-zone: \"bad.example.\" always_nxdomain"));
        // the allowed name is transparent (the global block does not apply)
        assert!(x.views.contains("local-zone: \"ads.example.\" transparent"));
        assert!(!x
            .views
            .contains("local-zone: \"ads.example.\" always_nxdomain"));
        assert!(x
            .views
            .contains("local-data: \"nas.home.lan. 3600 IN A 10.0.0.2\""));
        // one entry per zone name: unbound rejects duplicates
        assert_eq!(x.views.matches("local-zone: \"ads.example.\"").count(), 1);
    }

    #[test]
    fn logging_switches_unbound_from_syslog_to_a_file() {
        let mut p = res("kids");
        p.log = true;
        p.clients = vec!["10.0.0.12".parse().unwrap()];
        let x = render_extra(&[p], &Globals::default(), Some(UNBOUND_LOG));
        let conf = "server:\n    verbosity: 1\n    use-syslog: yes\n    port: 53\n\nremote-control:\n    control-enable: yes\n";
        let out = splice(conf, &x);
        assert!(!out.contains("use-syslog: yes"));
        assert!(out.contains("use-syslog: no\n    logfile: \"/var/log/unbound/unbound.log\""));
        assert!(out.contains("log-replies: yes"));
        assert!(out.contains("log-local-actions: yes"));
        // server lines land inside the server clause, views after everything
        let srv = out.find("access-control-view").unwrap();
        assert!(srv < out.find("remote-control:").unwrap());
        assert!(out.find("view:\n").unwrap() > out.find("control-enable").unwrap());
        // nothing to add: the config is returned unchanged
        assert_eq!(splice(conf, &Extra::default()), conf);
    }

    #[test]
    fn enforcement_redirects_policed_devices_and_refuses_dot() {
        let s = render_enforce(&["10.0.0.12".parse().unwrap()]);
        assert!(s.contains("add element inet patronus_dnspol policed_v4 { 10.0.0.12 }"));
        assert!(s.contains("fib daddr type != local udp dport 53 counter redirect to :53"));
        assert!(s.contains("fib daddr type != local tcp dport 53 counter redirect to :53"));
        assert!(s.contains("tcp dport 853 counter reject with tcp reset"));
        assert!(s.contains("udp dport 853 counter drop"));
        assert!(!render_enforce(&[]).contains("add element"));
    }

    #[test]
    fn csv_export_guards_formulas_and_quotes() {
        let rows = vec![LogRow {
            id: 1,
            ts: 1761700000,
            client: "10.0.0.5".into(),
            device_id: Some(1),
            device: Some("=cmd|' /C calc'!A0".into()),
            qname: "a\"b.example".into(),
            qtype: Some("A".into()),
            rcode: Some("NOERROR".into()),
            blocked: false,
        }];
        let c = to_csv(&rows);
        assert!(c.contains("\"'=cmd|' /C calc'!A0\""));
        assert!(c.contains("\"a\"\"b.example\""));
    }

    #[test]
    fn policy_names_are_restricted() {
        assert!(valid_policy_name("kids-2_a"));
        assert!(!valid_policy_name("Kids"));
        assert!(!valid_policy_name("a b"));
        assert!(!valid_policy_name(""));
        assert!(!valid_policy_name(&"a".repeat(33)));
    }

    async fn store() -> ConfigStore {
        let s = ConfigStore::open_in_memory().await.unwrap();
        for sql in [
            "INSERT INTO seg_groups (id, name) VALUES (11, 'kids'), (12, 'family')",
            "INSERT INTO seg_devices (id, name, group_id, kind, segment, ip4, state, created_at)
             VALUES (1, 'tablet', 11, 'wifi', '@lan', '10.0.0.11', 'active', 0),
                    (2, 'laptop', 12, 'wired', '@lan', '10.0.0.12', 'active', 0),
                    (3, 'gone', 11, 'wifi', '@lan', '10.0.0.13', 'revoked', 0)",
        ] {
            sqlx::query(sql).execute(s.pool().unwrap()).await.unwrap();
        }
        s
    }

    #[tokio::test]
    async fn policy_crud_assignment_and_effective_clients() {
        let s = store().await;
        let kids = create_policy(
            &s,
            &PolicyInput {
                name: Some("kids".into()),
                family: Some(true),
                log_queries: Some(true),
                blocklist_urls: Some("https://a.example/l.txt, file:///x/y".into()),
                ..PolicyInput::default()
            },
        )
        .await
        .unwrap();
        let lax = create_policy(
            &s,
            &PolicyInput {
                name: Some("lax".into()),
                ..PolicyInput::default()
            },
        )
        .await
        .unwrap();
        assert!(create_policy(
            &s,
            &PolicyInput {
                name: Some("kids".into()),
                ..Default::default()
            }
        )
        .await
        .is_err());
        assert!(create_policy(
            &s,
            &PolicyInput {
                name: Some("Bad Name".into()),
                ..Default::default()
            }
        )
        .await
        .is_err());
        assert!(create_policy(
            &s,
            &PolicyInput {
                name: Some("x".into()),
                blocklist_urls: Some("javascript:alert(1)".into()),
                ..Default::default()
            }
        )
        .await
        .is_err());
        assert_eq!(
            get_policy(&s, kids)
                .await
                .unwrap()
                .unwrap()
                .blocklist_urls
                .len(),
            2
        );
        // group policy applies to the active kid device only (revoked is the seg table's job)
        assign(&s, "group", 11, Some(kids)).await.unwrap();
        let c = clients(&s).await.unwrap();
        assert_eq!(
            c.iter().map(|c| c.name.as_str()).collect::<Vec<_>>(),
            vec!["tablet"]
        );
        // a device policy wins over the group's
        assign(&s, "device", 1, Some(lax)).await.unwrap();
        assert_eq!(clients(&s).await.unwrap()[0].policy_id, lax);
        assert!(assign(&s, "device", 1, Some(999)).await.is_err());
        assert!(assign(&s, "rack", 1, None).await.is_err());
        // rules: validated
        add_rule(
            &s,
            kids,
            &RuleInput {
                action: "block".into(),
                domain: "Games.Example".into(),
                address: None,
            },
        )
        .await
        .unwrap();
        add_rule(
            &s,
            kids,
            &RuleInput {
                action: "override".into(),
                domain: "nas.lan".into(),
                address: Some("10.0.0.2".into()),
            },
        )
        .await
        .unwrap();
        assert!(add_rule(
            &s,
            kids,
            &RuleInput {
                action: "override".into(),
                domain: "x.lan".into(),
                address: None
            }
        )
        .await
        .is_err());
        assert!(add_rule(
            &s,
            kids,
            &RuleInput {
                action: "override".into(),
                domain: "x.lan".into(),
                address: Some("nope".into())
            }
        )
        .await
        .is_err());
        assert!(add_rule(
            &s,
            kids,
            &RuleInput {
                action: "block".into(),
                domain: "a\"b".into(),
                address: None
            }
        )
        .await
        .is_err());
        assert!(
            add_rule(
                &s,
                kids,
                &RuleInput {
                    action: "block".into(),
                    domain: "games.example".into(),
                    address: None
                }
            )
            .await
            .is_err(),
            "duplicate"
        );
        let rules = list_rules(&s, kids).await.unwrap();
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].domain, "games.example");
        // deleting a policy detaches it
        delete_policy(&s, lax).await.unwrap();
        assert_eq!(clients(&s).await.unwrap()[0].policy_id, kids);
        update_policy(
            &s,
            kids,
            &PolicyInput {
                log_retention_days: Some(0),
                ..Default::default()
            },
        )
        .await
        .unwrap_err();
        update_policy(
            &s,
            kids,
            &PolicyInput {
                log_retention_days: Some(30),
                family: Some(false),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let p = get_policy(&s, kids).await.unwrap().unwrap();
        assert_eq!(
            (p.log_retention_days, p.family, p.log_queries),
            (30, false, true)
        );
    }

    #[tokio::test]
    async fn log_ingest_filters_by_policy_flags_blocked_and_survives_rotation() {
        let s = store().await;
        let kids = create_policy(
            &s,
            &PolicyInput {
                name: Some("kids".into()),
                log_queries: Some(true),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        // laptop's group has no policy: not logged
        assign(&s, "group", 11, Some(kids)).await.unwrap();
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("unbound.log");
        std::fs::write(
            &f,
            "[100] unbound[1:0] info: games.example. always_nxdomain 10.0.0.11@5353 games.example. A IN\n\
             [100] unbound[1:0] reply: 10.0.0.11 games.example. A IN NXDOMAIN 0.0 0 40\n\
             [101] unbound[1:0] reply: 10.0.0.11 ok.example. A IN NOERROR 0.0 0 60\n\
             [102] unbound[1:0] reply: 10.0.0.12 laptop-query.example. A IN NOERROR 0.0 0 60\n\
             [103] unbound[1:0] reply: 127.0.0.1 router.example. A IN NOERROR 0.0 0 60\n\
             [104] unbound[1:0] reply: 10.0.0.11 partial.exam",
        )
        .unwrap();
        let st = ingest(&s, &f).await.unwrap();
        assert_eq!(st.stored, 2, "{st:?}");
        let rows = search_log(&s, &LogQuery::default()).await.unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[1].qname, "games.example");
        assert!(rows[1].blocked && rows[1].rcode.as_deref() == Some("NXDOMAIN"));
        assert!(!rows[0].blocked);
        assert_eq!(rows[0].device.as_deref(), Some("tablet"));
        // the partial last line is picked up once it is complete; nothing is stored twice
        use std::io::Write;
        let mut fh = std::fs::OpenOptions::new().append(true).open(&f).unwrap();
        fh.write_all(b"ple. A IN NOERROR 0.0 0 60\n").unwrap();
        let st = ingest(&s, &f).await.unwrap();
        assert_eq!(st.stored, 1);
        assert_eq!(ingest(&s, &f).await.unwrap().stored, 0);
        assert_eq!(search_log(&s, &LogQuery::default()).await.unwrap().len(), 3);
        // rotation (new file, shorter): start over
        std::fs::remove_file(&f).unwrap();
        std::fs::write(
            &f,
            "[200] unbound[1:0] reply: 10.0.0.11 after.rotation. A IN NOERROR 0.0 0 60\n",
        )
        .unwrap();
        assert_eq!(ingest(&s, &f).await.unwrap().stored, 1);
        // search filters
        let q = |q: &str| LogQuery {
            q: Some(q.into()),
            ..Default::default()
        };
        assert_eq!(search_log(&s, &q("rotation")).await.unwrap().len(), 1);
        assert_eq!(
            search_log(&s, &q("%")).await.unwrap().len(),
            0,
            "LIKE wildcards are escaped"
        );
        assert_eq!(
            search_log(
                &s,
                &LogQuery {
                    blocked: true,
                    ..Default::default()
                }
            )
            .await
            .unwrap()
            .len(),
            1
        );
        assert_eq!(
            search_log(
                &s,
                &LogQuery {
                    device: Some(2),
                    ..Default::default()
                }
            )
            .await
            .unwrap()
            .len(),
            0
        );
        assert_eq!(
            search_log(
                &s,
                &LogQuery {
                    since: Some(150),
                    ..Default::default()
                }
            )
            .await
            .unwrap()
            .len(),
            1
        );
        assert_eq!(
            search_log(
                &s,
                &LogQuery {
                    limit: Some(2),
                    ..Default::default()
                }
            )
            .await
            .unwrap()
            .len(),
            2
        );
        // retention: kids policy keeps 7 days; rows from "now" survive, old ones go
        let now = 200 + 6 * 86400;
        assert_eq!(prune(&s, now, 200_000).await.unwrap(), 0);
        let now = 200 + 8 * 86400;
        assert_eq!(prune(&s, now, 200_000).await.unwrap(), 4);
        assert_eq!(clear_log(&s, None).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn prune_caps_the_row_count() {
        let s = store().await;
        for i in 0..1500 {
            sqlx::query("INSERT INTO seg_dns_log (ts, client, device_id, qname) VALUES (?, '10.0.0.11', 1, 'x.example')")
                .bind(1_000_000 + i)
                .execute(s.pool().unwrap())
                .await
                .unwrap();
        }
        // (max_rows is floored at 1000)
        let n = prune(&s, 1_000_000, 10).await.unwrap();
        assert_eq!(n, 500);
        let left: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM seg_dns_log")
            .fetch_one(s.pool().unwrap())
            .await
            .unwrap();
        assert_eq!(left, 1000);
    }
}
