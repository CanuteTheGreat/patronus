//! DNS filtering catalog (lane D, docs/DNS-FILTERING.md): a curated list of free
//! block lists, scheduled refresh with per-list status, Unbound RPZ zones with
//! per-list blocked-answer counts, an allow list (name, wildcard, regex) and the
//! DNS query log with "block this domain" / "allow this domain" actions.
//!
//! Resolver mode (Unbound): every enabled list becomes ONE `rpz:` zone, so Unbound
//! loads it natively (a million names do not bloat unbound.conf), applies it
//! before the cache, and names the list in its log line
//! (`rpz: applied [<list>] ...`), which the tailer ([`ingest`]) turns into per-list
//! counters. Lists in hosts/domain format are converted into RPZ zone files
//! (`<name> CNAME .`, plus `*.<name> CNAME .` when the list blocks subdomains);
//! lists already in RPZ format (threat-intel zones) are loaded as they are. A
//! generated `allow` zone comes FIRST: its `rpz-passthru` records win over every
//! later zone, which is how the allow list also overrides lists in RPZ format.
//!
//! Forwarder mode (dnsmasq, the router tier): the same lists become `address=/name/`
//! lines, capped by the board's memory ([`board_cap`]); a list that does not fit is
//! skipped as a whole and its status says why.
//!
//! Lists are fetched with curl (the last good copy is kept on any failure, an
//! implausible download, e.g. an HTML error page or a list that shrank to under
//! half, is refused) into `/var/lib/patronus/dnsbl/lists`. Free lists only; the
//! licence of each catalog entry is recorded in [`CATALOG`].

use crate::lan::{self, db_err, invalid, now, LanEnv};
use patronus_config::applier::ApplyReport;
use patronus_config::store::ConfigStore;
use patronus_core::{Error, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::Row;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::Path;

pub const LISTS_DIR: &str = "/var/lib/patronus/dnsbl/lists";
pub const UNBOUND_LOG: &str = "/var/log/unbound/unbound.log";
pub const DNSMASQ_LOG: &str = "/var/log/patronus-dnsmasq.log";
pub const ALLOW_ZONE_NAME: &str = "patronus-allow.rpz.";
pub const DEFAULT_REFRESH_HOURS: i64 = 24;
pub const MIN_REFRESH_HOURS: i64 = 1;
pub const MAX_REFRESH_HOURS: i64 = 168;
/// Largest list file accepted (bytes).
pub const MAX_LIST_BYTES: u64 = 96 * 1024 * 1024;
/// Allow list rows.
pub const MAX_ALLOW: i64 = 1000;
/// Query log retention (days) and row cap.
pub const LOG_RETENTION_DAYS: i64 = 7;
pub const LOG_MAX_ROWS: i64 = 200_000;
pub const RECENT_MAX_ROWS: i64 = 2000;
pub const HITS_RETENTION_DAYS: i64 = 90;

pub const FORMATS: &[&str] = &["hosts", "domains", "rpz"];
pub const RPZ_ACTIONS: &[&str] = &["", "nxdomain", "nodata", "drop", "passthru", "disabled"];

// ---------------------------------------------------------------------------
// the catalog
// ---------------------------------------------------------------------------

/// One free list the user can subscribe to with a click.
#[derive(Debug, Clone, Serialize)]
pub struct CatalogEntry {
    pub id: &'static str,
    pub name: &'static str,
    /// ads | malware | phishing | threat-intel
    pub group: &'static str,
    pub description: &'static str,
    /// `{key}` is replaced by the list's access key (entries with `needs_key`).
    pub url: &'static str,
    /// hosts | domains | rpz
    pub format: &'static str,
    /// A listed name also blocks its subdomains (domain lists, RPZ with `*.` records).
    pub subdomains: bool,
    pub license: &'static str,
    pub license_url: &'static str,
    pub homepage: &'static str,
    /// Entries at the time of writing (a hint for the size estimate, not a promise).
    pub approx_entries: u32,
    pub needs_key: bool,
    pub key_url: &'static str,
    /// Remarks on the licence or the source (shown in the UI).
    pub note: &'static str,
}

const HAGEZI_LIC: &str = "https://github.com/hagezi/dns-blocklists/blob/main/LICENSE";
const HAGEZI_HOME: &str = "https://github.com/hagezi/dns-blocklists";

pub const CATALOG: &[CatalogEntry] = &[
    CatalogEntry {
        id: "stevenblack",
        name: "StevenBlack unified hosts",
        group: "ads",
        description: "Ads, trackers and malware hosts merged from reputable sources.",
        url: "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
        format: "hosts",
        subdomains: false,
        license: "MIT",
        license_url: "https://github.com/StevenBlack/hosts/blob/master/license.txt",
        homepage: "https://github.com/StevenBlack/hosts",
        approx_entries: 82_000,
        needs_key: false,
        key_url: "",
        note: "",
    },
    CatalogEntry {
        id: "oisd-small",
        name: "OISD small",
        group: "ads",
        description: "Block ads, trackers and malware with very few false positives.",
        url: "https://small.oisd.nl/domainswild2",
        format: "domains",
        subdomains: true,
        license: "GPL-3.0",
        license_url: "https://github.com/sjhgvr/oisd/blob/main/LICENSE",
        homepage: "https://oisd.nl",
        approx_entries: 63_000,
        needs_key: false,
        key_url: "",
        note: "",
    },
    CatalogEntry {
        id: "oisd-big",
        name: "OISD big",
        group: "ads",
        description: "Larger OISD set: more ads, trackers, malware and scam domains.",
        url: "https://big.oisd.nl/domainswild2",
        format: "domains",
        subdomains: true,
        license: "GPL-3.0",
        license_url: "https://github.com/sjhgvr/oisd/blob/main/LICENSE",
        homepage: "https://oisd.nl",
        approx_entries: 222_000,
        needs_key: false,
        key_url: "",
        note: "",
    },
    CatalogEntry {
        id: "hagezi-light",
        name: "Hagezi Light",
        group: "ads",
        description: "Hagezi's lightest tier: basic ad, tracker and malware blocking, almost no breakage.",
        url: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/light-onlydomains.txt",
        format: "domains",
        subdomains: true,
        license: "GPL-3.0",
        license_url: HAGEZI_LIC,
        homepage: HAGEZI_HOME,
        approx_entries: 70_000,
        needs_key: false,
        key_url: "",
        note: "",
    },
    CatalogEntry {
        id: "hagezi-multi",
        name: "Hagezi Multi Normal",
        group: "ads",
        description: "Hagezi's balanced tier: ads, tracking, malware, scams.",
        url: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/multi-onlydomains.txt",
        format: "domains",
        subdomains: true,
        license: "GPL-3.0",
        license_url: HAGEZI_LIC,
        homepage: HAGEZI_HOME,
        approx_entries: 130_000,
        needs_key: false,
        key_url: "",
        note: "",
    },
    CatalogEntry {
        id: "hagezi-pro",
        name: "Hagezi Pro",
        group: "ads",
        description: "Hagezi's recommended tier: extended protection, rare breakage.",
        url: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/pro-onlydomains.txt",
        format: "domains",
        subdomains: true,
        license: "GPL-3.0",
        license_url: HAGEZI_LIC,
        homepage: HAGEZI_HOME,
        approx_entries: 241_000,
        needs_key: false,
        key_url: "",
        note: "",
    },
    CatalogEntry {
        id: "hagezi-pro-plus",
        name: "Hagezi Pro++",
        group: "ads",
        description: "Hagezi's stricter tier: more trackers and telemetry, some breakage possible.",
        url: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/pro.plus-onlydomains.txt",
        format: "domains",
        subdomains: true,
        license: "GPL-3.0",
        license_url: HAGEZI_LIC,
        homepage: HAGEZI_HOME,
        approx_entries: 290_000,
        needs_key: false,
        key_url: "",
        note: "",
    },
    CatalogEntry {
        id: "hagezi-ultimate",
        name: "Hagezi Ultimate",
        group: "ads",
        description: "Hagezi's most aggressive tier: expect to allow-list some sites.",
        url: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/ultimate-onlydomains.txt",
        format: "domains",
        subdomains: true,
        license: "GPL-3.0",
        license_url: HAGEZI_LIC,
        homepage: HAGEZI_HOME,
        approx_entries: 340_000,
        needs_key: false,
        key_url: "",
        note: "",
    },
    CatalogEntry {
        id: "hagezi-tif-mini",
        name: "Hagezi Threat Intelligence Feeds (mini), RPZ",
        group: "threat-intel",
        description: "Malware, phishing, scam and cryptojacking domains from threat-intelligence feeds, as an RPZ zone.",
        url: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/rpz/tif.mini.txt",
        format: "rpz",
        subdomains: true,
        license: "GPL-3.0",
        license_url: HAGEZI_LIC,
        homepage: HAGEZI_HOME,
        approx_entries: 329_000,
        needs_key: false,
        key_url: "",
        note: "Native RPZ zone; needs the Unbound resolver (a dnsmasq forwarder loads the plain names).",
    },
    CatalogEntry {
        id: "phishing-army",
        name: "Phishing Army",
        group: "phishing",
        description: "Community phishing domain list aggregated from PhishTank, OpenPhish, CERT.PL and others.",
        url: "https://phishing.army/download/phishing-army-domains.txt",
        format: "domains",
        subdomains: false,
        license: "free to use, non-commercial community project",
        license_url: "https://phishing.army/license/",
        homepage: "https://phishing.army",
        approx_entries: 146_000,
        needs_key: false,
        key_url: "",
        note: "The feed itself is free; businesses must check the terms of its upstream sources (see the licence page).",
    },
    CatalogEntry {
        id: "urlhaus",
        name: "URLhaus malware domains (RPZ)",
        group: "threat-intel",
        description: "Hosts that currently serve malware, from abuse.ch URLhaus, as an RPZ zone.",
        url: "https://urlhaus-api.abuse.ch/v2/files/exports/{key}/rpz.txt",
        format: "rpz",
        subdomains: false,
        license: "CC0-1.0",
        license_url: "https://urlhaus.abuse.ch/api/",
        homepage: "https://urlhaus.abuse.ch",
        approx_entries: 2_000,
        needs_key: true,
        key_url: "https://auth.abuse.ch/",
        note: "Since 2026-10-21 abuse.ch exports need a free Auth-Key. The export file name is documented only behind that login: if abuse.ch names it differently, edit the URL of this list.",
    },
];

pub fn catalog_entry(id: &str) -> Option<&'static CatalogEntry> {
    CATALOG.iter().find(|c| c.id == id)
}

// ---------------------------------------------------------------------------
// parsing
// ---------------------------------------------------------------------------

fn is_ip_literal(s: &str) -> bool {
    s.parse::<std::net::IpAddr>().is_ok()
}

fn clean_name(n: &str) -> Option<String> {
    let n = n.trim().trim_end_matches('.').to_ascii_lowercase();
    let n = n.strip_prefix("*.").unwrap_or(&n).to_string();
    if n == "localhost" || !n.contains('.') || is_ip_literal(&n) {
        return None;
    }
    lan::valid_dns_name(&n, true).then_some(n)
}

/// Names of a hosts file, a domain list, an OISD "wildcard" list (`*.name`) or any
/// mix of them; comments (`#`, `!`) and blank lines are skipped.
pub fn parse_names(body: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for line in body.lines() {
        let line = line.split(['#', '!']).next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let f: Vec<&str> = line.split_whitespace().collect();
        let names: &[&str] = if is_ip_literal(f[0]) {
            &f[1..]
        } else {
            &f[..1]
        };
        for n in names {
            if let Some(n) = clean_name(n) {
                out.insert(n);
            }
        }
    }
    out
}

/// The blocked names of a zone in RPZ format: owners of `CNAME` records (the
/// `*.name` twin only tells that subdomains are blocked too; `rpz-ip` / `rpz-nsdname`
/// triggers and the SOA/NS lines are not names). Returns (names, wildcard seen).
pub fn parse_rpz(body: &str) -> (BTreeSet<String>, bool) {
    let mut out = BTreeSet::new();
    let mut wild = false;
    for line in body.lines() {
        if line.starts_with([' ', '\t', ';', '$']) || line.trim().is_empty() {
            continue;
        }
        let line = line.split(';').next().unwrap_or("");
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 3 {
            continue;
        }
        // owner [ttl] [IN] CNAME target
        let Some(ci) = f.iter().position(|t| t.eq_ignore_ascii_case("CNAME")) else {
            continue;
        };
        let owner = f[0].to_ascii_lowercase();
        if owner.ends_with('.') || owner.contains(".rpz-") || owner.starts_with("rpz-") {
            continue;
        }
        if let Some(rest) = owner.strip_prefix("*.") {
            if clean_name(rest).is_some() {
                wild = true;
            }
            continue;
        }
        if f.get(ci + 1).is_some_and(|t| t.starts_with("rpz-")) {
            continue; // an existing passthru/drop override, not a block
        }
        if let Some(n) = clean_name(&owner) {
            out.insert(n);
        }
    }
    (out, wild)
}

fn parse_for(format: &str, body: &str) -> (BTreeSet<String>, bool) {
    if format == "rpz" {
        parse_rpz(body)
    } else {
        (parse_names(body), false)
    }
}

/// The zone file Unbound loads for a list in hosts/domain format.
pub fn zone_file(
    zone: &str,
    names: &BTreeSet<String>,
    subdomains: bool,
    null_mode: bool,
) -> String {
    let mut s = String::with_capacity(names.len() * 48 + 200);
    s.push_str(&format!(
        "$ORIGIN {zone}\n$TTL 300\n@ IN SOA localhost. root.localhost. 1 3600 600 86400 300\n@ IN NS localhost.\n"
    ));
    for n in names {
        if null_mode {
            s.push_str(&format!("{n} A 0.0.0.0\n{n} AAAA ::\n"));
            if subdomains {
                s.push_str(&format!("*.{n} A 0.0.0.0\n*.{n} AAAA ::\n"));
            }
        } else {
            s.push_str(&format!("{n} CNAME .\n"));
            if subdomains {
                s.push_str(&format!("*.{n} CNAME .\n"));
            }
        }
    }
    s
}

// ---------------------------------------------------------------------------
// allow list
// ---------------------------------------------------------------------------

pub const ALLOW_KINDS: &[&str] = &["domain", "wildcard", "regex"];

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AllowEntry {
    pub id: i64,
    pub kind: String,
    pub pattern: String,
    pub description: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct AllowInput {
    pub kind: String,
    pub pattern: String,
    #[serde(default)]
    pub description: Option<String>,
}

fn regex_for(p: &str) -> std::result::Result<regex_lite::Regex, String> {
    regex_lite::RegexBuilder::new(p)
        .size_limit(200_000)
        .build()
        .map_err(|e| e.to_string())
}

impl AllowInput {
    pub fn validate(&self) -> Result<(String, String, String)> {
        let kind = self.kind.trim().to_ascii_lowercase();
        if !ALLOW_KINDS.contains(&kind.as_str()) {
            return Err(invalid("allow list kind (domain, wildcard or regex)"));
        }
        let pat = self.pattern.trim().to_string();
        let pattern = match kind.as_str() {
            "domain" => {
                let p = pat.trim_end_matches('.').to_ascii_lowercase();
                if p.contains('*') || !lan::valid_dns_name(&p, true) {
                    return Err(invalid(format!(
                        "allow list domain {pat:?} (a plain name such as example.com; it also allows its subdomains)"
                    )));
                }
                p
            }
            "wildcard" => {
                let p = pat.to_ascii_lowercase();
                let ok = !p.is_empty()
                    && p.len() <= 253
                    && p.contains('*')
                    && p.bytes().all(|b| {
                        b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_' | b'*')
                    });
                if !ok {
                    return Err(invalid(format!(
                        "allow list wildcard {pat:?} (letters, digits, - _ . and * , e.g. *.cdn.example.com)"
                    )));
                }
                p
            }
            _ => {
                if pat.is_empty() || pat.len() > 200 {
                    return Err(invalid("allow list regular expression (1-200 characters)"));
                }
                if let Err(e) = regex_for(&pat) {
                    return Err(invalid(format!(
                        "allow list regular expression {pat:?}: {}",
                        e.lines().next().unwrap_or("")
                    )));
                }
                pat
            }
        };
        let d = self.description.clone().unwrap_or_default();
        if d.len() > 200 || d.contains('\n') {
            return Err(invalid("allow list description"));
        }
        Ok((kind, pattern, d))
    }
}

/// Glob with `*` (any run of characters, dots included) over the whole name.
pub fn glob_match(pat: &str, name: &str) -> bool {
    let parts: Vec<&str> = pat.split('*').collect();
    if parts.len() == 1 {
        return pat == name;
    }
    let mut rest = name;
    for (i, p) in parts.iter().enumerate() {
        if i == 0 {
            match rest.strip_prefix(p) {
                Some(r) => rest = r,
                None => return false,
            }
        } else if i == parts.len() - 1 {
            return rest.ends_with(p);
        } else {
            match rest.find(p) {
                Some(j) => rest = &rest[j + p.len()..],
                None => return false,
            }
        }
    }
    true
}

/// The allow list, compiled.
#[derive(Default)]
pub struct Allow {
    pub domains: Vec<String>,
    globs: Vec<String>,
    regs: Vec<regex_lite::Regex>,
}

impl Allow {
    pub fn compile(entries: &[AllowEntry]) -> Self {
        let mut a = Allow::default();
        for e in entries {
            match e.kind.as_str() {
                "domain" => a.domains.push(e.pattern.clone()),
                "wildcard" => a.globs.push(e.pattern.clone()),
                _ => {
                    if let Ok(r) = regex_for(&e.pattern) {
                        a.regs.push(r)
                    }
                }
            }
        }
        a
    }

    pub fn is_empty(&self) -> bool {
        self.domains.is_empty() && self.globs.is_empty() && self.regs.is_empty()
    }

    /// Is `name` allowed (so it must not be blocked)?
    pub fn matches(&self, name: &str) -> bool {
        self.domains.iter().any(|d| {
            name == d
                || name
                    .strip_suffix(d.as_str())
                    .is_some_and(|p| p.ends_with('.'))
        }) || self.globs.iter().any(|g| glob_match(g, name))
            || self.regs.iter().any(|r| r.is_match(name))
    }
}

// ---------------------------------------------------------------------------
// settings and board caps
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FilterSettings {
    pub refresh_hours: i64,
    /// 0 = automatic (the board's cap)
    pub max_domains: i64,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct FilterSettingsInput {
    pub refresh_hours: Option<i64>,
    pub max_domains: Option<i64>,
}

pub async fn filter_settings(store: &ConfigStore) -> Result<FilterSettings> {
    let g = |k: &'static str, d: i64| async move {
        Ok::<i64, Error>(
            lan::get_setting(store, k)
                .await?
                .and_then(|v| v.trim().parse().ok())
                .unwrap_or(d),
        )
    };
    Ok(FilterSettings {
        refresh_hours: g("dns.filter_refresh_hours", DEFAULT_REFRESH_HOURS)
            .await?
            .clamp(MIN_REFRESH_HOURS, MAX_REFRESH_HOURS),
        max_domains: g("dns.filter_max_domains", 0).await?.max(0),
    })
}

pub async fn save_filter_settings(store: &ConfigStore, i: &FilterSettingsInput) -> Result<()> {
    if let Some(h) = i.refresh_hours {
        if !(MIN_REFRESH_HOURS..=MAX_REFRESH_HOURS).contains(&h) {
            return Err(invalid(format!(
                "refresh interval ({MIN_REFRESH_HOURS}..{MAX_REFRESH_HOURS} hours)"
            )));
        }
        lan::set_setting(store, "dns.filter_refresh_hours", &h.to_string()).await?;
    }
    if let Some(m) = i.max_domains {
        if !(0..=50_000_000).contains(&m) {
            return Err(invalid("maximum names (0 = automatic, up to 50,000,000)"));
        }
        lan::set_setting(store, "dns.filter_max_domains", &m.to_string()).await?;
    }
    Ok(())
}

/// Memory of the box in kB (`PATRONUS_DNS_FILTER_MEM_KB` overrides it for tests).
pub fn mem_total_kb() -> u64 {
    if let Some(v) = std::env::var("PATRONUS_DNS_FILTER_MEM_KB")
        .ok()
        .and_then(|v| v.parse().ok())
    {
        return v;
    }
    std::fs::read_to_string("/proc/meminfo")
        .ok()
        .and_then(|t| {
            t.lines()
                .find(|l| l.starts_with("MemTotal:"))
                .and_then(|l| l.split_whitespace().nth(1)?.parse().ok())
        })
        .unwrap_or(0)
}

/// The most names the board can carry for `mode` (`resolver` = Unbound RPZ,
/// `forwarder` = dnsmasq address lines), from its RAM. Measured in the netlab lane
/// (lane-s-dns-filter.sh, 150,000 names with their `*.` twins = 300,000 RPZ records): Unbound
/// grew from 10 MB to 193 MB, about 1.2 kB per listed name; dnsmasq (address= lines) 2.1 MB to
/// 15.1 MB for 150,000 names, about 90 B per name. The table keeps the filter near 15% of the
/// RAM (Unbound) or 6% (dnsmasq) so the rest of the router has room (docs/DNS-FILTERING.md).
pub fn board_cap(mem_kb: u64, mode: &str) -> u64 {
    let mb = mem_kb / 1024;
    if mode == "forwarder" {
        match mb {
            0..=200 => 90_000,
            201..=400 => 200_000,
            401..=1000 => 400_000,
            _ => 800_000,
        }
    } else {
        match mb {
            0..=511 => 40_000,
            512..=1023 => 60_000,
            1024..=2047 => 120_000,
            2048..=4095 => 250_000,
            4096..=8191 => 500_000,
            _ => 1_000_000,
        }
    }
}

pub fn effective_cap(s: &FilterSettings, mode: &str) -> u64 {
    let board = board_cap(mem_total_kb(), mode);
    if s.max_domains > 0 {
        board.min(s.max_domains as u64)
    } else {
        board
    }
}

// ---------------------------------------------------------------------------
// store: lists, allow list, status
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct List {
    pub id: i64,
    pub name: String,
    pub catalog: Option<String>,
    pub url: String,
    pub format: String,
    pub subdomains: bool,
    pub enabled: bool,
    pub action: String,
    /// never serialized to the API/UI as the key itself
    #[serde(skip_serializing)]
    pub auth_key: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct ListInput {
    /// Subscribe to a catalog entry (all other fields are then optional)
    #[serde(default)]
    pub catalog: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub format: Option<String>,
    #[serde(default)]
    pub subdomains: Option<bool>,
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub action: Option<String>,
    #[serde(default)]
    pub auth_key: Option<String>,
}

fn valid_list_name(n: &str) -> bool {
    !n.is_empty()
        && n.len() <= 48
        && n.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

fn row_list(r: &sqlx::sqlite::SqliteRow) -> List {
    List {
        id: r.get("id"),
        name: r.get("name"),
        catalog: r.get("catalog"),
        url: r.get("url"),
        format: r.get("format"),
        subdomains: r.get::<i64, _>("subdomains") != 0,
        enabled: r.get::<i64, _>("enabled") != 0,
        action: r.get("action"),
        auth_key: r.get("auth_key"),
    }
}

pub async fn list_lists(store: &ConfigStore) -> Result<Vec<List>> {
    let rows = sqlx::query("SELECT * FROM dnsf_lists ORDER BY id")
        .fetch_all(store.pool()?)
        .await
        .map_err(db_err("read DNS filter lists"))?;
    Ok(rows.iter().map(row_list).collect())
}

fn check_action(a: &str) -> Result<()> {
    if RPZ_ACTIONS.contains(&a) {
        Ok(())
    } else {
        Err(invalid(format!(
            "RPZ action {a:?} (one of nxdomain, nodata, drop, passthru, disabled; empty = the list's own)"
        )))
    }
}

pub async fn add_list(store: &ConfigStore, i: &ListInput) -> Result<i64> {
    let (cat, name, url, format, subs) = match i.catalog.as_deref().filter(|c| !c.is_empty()) {
        Some(c) => {
            let e = catalog_entry(c).ok_or_else(|| invalid(format!("catalog entry {c:?}")))?;
            (
                Some(e.id.to_string()),
                i.name.clone().unwrap_or_else(|| e.id.to_string()),
                i.url.clone().unwrap_or_else(|| e.url.to_string()),
                i.format.clone().unwrap_or_else(|| e.format.to_string()),
                i.subdomains.unwrap_or(e.subdomains),
            )
        }
        None => (
            None,
            i.name.clone().unwrap_or_default(),
            i.url.clone().unwrap_or_default(),
            i.format.clone().unwrap_or_else(|| "domains".into()),
            i.subdomains.unwrap_or(false),
        ),
    };
    let name = name.trim().to_ascii_lowercase();
    if !valid_list_name(&name) {
        return Err(invalid("list name (letters, digits, - _ . up to 48)"));
    }
    if !FORMATS.contains(&format.as_str()) {
        return Err(invalid("list format (hosts, domains or rpz)"));
    }
    let key = i.auth_key.clone().unwrap_or_default().trim().to_string();
    if key.len() > 200 || key.contains(char::is_whitespace) || key.contains('"') {
        return Err(invalid("access key"));
    }
    let probe = url.replace("{key}", "x");
    crate::dns::check_url(&probe)?;
    if url.contains("{key}") && key.is_empty() && cat.is_none() {
        return Err(invalid("URL with {key}: give the access key"));
    }
    let action = i.action.clone().unwrap_or_default();
    check_action(&action)?;
    if action == "passthru" && format != "rpz" {
        return Err(invalid("action passthru is for lists in RPZ format"));
    }
    let r = sqlx::query(
        "INSERT INTO dnsf_lists (name, catalog, url, format, subdomains, enabled, action, auth_key, updated_at)
         VALUES (?,?,?,?,?,?,?,?,?)",
    )
    .bind(&name)
    .bind(&cat)
    .bind(&url)
    .bind(&format)
    .bind(i64::from(subs))
    .bind(i64::from(i.enabled.unwrap_or(true)))
    .bind(&action)
    .bind(&key)
    .bind(now())
    .execute(store.pool()?)
    .await
    .map_err(|e| lan::unique_err(e, &format!("list {name}")))?;
    Ok(r.last_insert_rowid())
}

pub async fn update_list(store: &ConfigStore, id: i64, i: &ListInput) -> Result<()> {
    let cur = list_lists(store)
        .await?
        .into_iter()
        .find(|l| l.id == id)
        .ok_or_else(|| invalid(format!("list {id}: not found")))?;
    let action = i.action.clone().unwrap_or(cur.action.clone());
    check_action(&action)?;
    if action == "passthru" && cur.format != "rpz" {
        return Err(invalid("action passthru is for lists in RPZ format"));
    }
    let url = i.url.clone().unwrap_or(cur.url.clone());
    crate::dns::check_url(&url.replace("{key}", "x"))?;
    let key = match &i.auth_key {
        Some(k) if !k.trim().is_empty() => k.trim().to_string(),
        _ => cur.auth_key.clone(),
    };
    sqlx::query(
        "UPDATE dnsf_lists SET url=?, enabled=?, action=?, auth_key=?, subdomains=?, updated_at=? WHERE id=?",
    )
    .bind(&url)
    .bind(i64::from(i.enabled.unwrap_or(cur.enabled)))
    .bind(&action)
    .bind(&key)
    .bind(i64::from(i.subdomains.unwrap_or(cur.subdomains)))
    .bind(now())
    .bind(id)
    .execute(store.pool()?)
    .await
    .map_err(db_err("update DNS filter list"))?;
    Ok(())
}

pub async fn delete_list(store: &ConfigStore, id: i64) -> Result<()> {
    let n = sqlx::query("DELETE FROM dnsf_lists WHERE id = ?")
        .bind(id)
        .execute(store.pool()?)
        .await
        .map_err(db_err("delete DNS filter list"))?
        .rows_affected();
    if n == 0 {
        return Err(invalid(format!("list {id}: not found")));
    }
    let _ = sqlx::query("DELETE FROM dnsf_status WHERE list_id = ?")
        .bind(id)
        .execute(store.pool()?)
        .await;
    Ok(())
}

pub async fn list_allow(store: &ConfigStore) -> Result<Vec<AllowEntry>> {
    let rows = sqlx::query("SELECT id, kind, pattern, description FROM dnsf_allow ORDER BY id")
        .fetch_all(store.pool()?)
        .await
        .map_err(db_err("read DNS allow list"))?;
    Ok(rows
        .iter()
        .map(|r| AllowEntry {
            id: r.get(0),
            kind: r.get(1),
            pattern: r.get(2),
            description: r.get(3),
        })
        .collect())
}

pub async fn add_allow(store: &ConfigStore, i: &AllowInput) -> Result<i64> {
    let (kind, pattern, desc) = i.validate()?;
    let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM dnsf_allow")
        .fetch_one(store.pool()?)
        .await
        .map_err(db_err("count DNS allow list"))?;
    if n >= MAX_ALLOW {
        return Err(invalid(format!("allow list: at most {MAX_ALLOW} entries")));
    }
    let r = sqlx::query(
        "INSERT INTO dnsf_allow (kind, pattern, description, updated_at) VALUES (?,?,?,?)",
    )
    .bind(&kind)
    .bind(&pattern)
    .bind(&desc)
    .bind(now())
    .execute(store.pool()?)
    .await
    .map_err(|e| lan::unique_err(e, &format!("allow entry {pattern}")))?;
    Ok(r.last_insert_rowid())
}

pub async fn delete_allow(store: &ConfigStore, id: i64) -> Result<()> {
    let n = sqlx::query("DELETE FROM dnsf_allow WHERE id = ?")
        .bind(id)
        .execute(store.pool()?)
        .await
        .map_err(db_err("delete DNS allow entry"))?
        .rows_affected();
    if n == 0 {
        return Err(invalid(format!("allow entry {id}: not found")));
    }
    Ok(())
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Status {
    pub list_id: i64,
    pub last_attempt: i64,
    pub last_ok: i64,
    pub entries: i64,
    pub used: i64,
    pub bytes: i64,
    pub last_error: String,
    pub force: bool,
}

pub async fn statuses(store: &ConfigStore) -> Result<HashMap<i64, Status>> {
    let rows = sqlx::query(
        "SELECT list_id, last_attempt, last_ok, entries, used, bytes, last_error, force FROM dnsf_status",
    )
    .fetch_all(store.pool()?)
    .await
    .map_err(db_err("read DNS filter status"))?;
    Ok(rows
        .iter()
        .map(|r| {
            (
                r.get::<i64, _>(0),
                Status {
                    list_id: r.get(0),
                    last_attempt: r.get(1),
                    last_ok: r.get(2),
                    entries: r.get(3),
                    used: r.get(4),
                    bytes: r.get(5),
                    last_error: r.get(6),
                    force: r.get::<i64, _>(7) != 0,
                },
            )
        })
        .collect())
}

async fn save_status(store: &ConfigStore, s: &Status) -> Result<()> {
    sqlx::query(
        "INSERT INTO dnsf_status (list_id, last_attempt, last_ok, entries, used, bytes, last_error, force)
         VALUES (?,?,?,?,?,?,?,?)
         ON CONFLICT(list_id) DO UPDATE SET last_attempt=excluded.last_attempt, last_ok=excluded.last_ok,
           entries=excluded.entries, used=excluded.used, bytes=excluded.bytes,
           last_error=excluded.last_error, force=excluded.force",
    )
    .bind(s.list_id)
    .bind(s.last_attempt)
    .bind(s.last_ok)
    .bind(s.entries)
    .bind(s.used)
    .bind(s.bytes)
    .bind(&s.last_error)
    .bind(i64::from(s.force))
    .execute(store.pool()?)
    .await
    .map_err(db_err("save DNS filter status"))?;
    Ok(())
}

/// Ask for a download at the next apply (`None` = every list).
pub async fn request_refresh(store: &ConfigStore, id: Option<i64>) -> Result<()> {
    let lists = list_lists(store).await?;
    let st = statuses(store).await?;
    for l in lists.iter().filter(|l| id.is_none_or(|i| i == l.id)) {
        let mut s = st.get(&l.id).cloned().unwrap_or(Status {
            list_id: l.id,
            ..Default::default()
        });
        s.force = true;
        save_status(store, &s).await?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// fetching
// ---------------------------------------------------------------------------

fn list_path(env: &LanEnv, id: i64, ext: &str) -> std::path::PathBuf {
    env.path(LISTS_DIR).join(format!("{id}.{ext}"))
}

fn zone_name(id: i64) -> String {
    format!("patronus-list-{id}.rpz.")
}

/// Is a download of this list due?
pub fn due(st: Option<&Status>, refresh_hours: i64, now: i64, have_copy: bool) -> bool {
    match st {
        None => true,
        Some(s) if s.force || !have_copy => true,
        Some(s) => {
            // a failed attempt is retried after an hour at the earliest
            let base = if s.last_ok >= s.last_attempt {
                s.last_ok
            } else {
                s.last_attempt
            };
            let wait = if s.last_ok >= s.last_attempt {
                refresh_hours * 3600
            } else {
                3600.min(refresh_hours * 3600)
            };
            now - base >= wait
        }
    }
}

/// Download `l` into the cache (the old copy stays on any failure).
async fn fetch(env: &LanEnv, l: &List) -> std::result::Result<u64, String> {
    let dir = env.path(LISTS_DIR);
    std::fs::create_dir_all(&dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
    let raw = list_path(env, l.id, "raw");
    let tmp = list_path(env, l.id, "new");
    let url = l.url.replace("{key}", &l.auth_key);
    // url and output go through stdin so an access key never shows in `ps`
    let cfg = format!(
        "url = \"{}\"\noutput = \"{}\"\nuser-agent = \"patronus-dnsfilter/1\"\n",
        url.replace('"', "%22"),
        tmp.display()
    );
    let mut child = tokio::process::Command::new("curl")
        .args([
            "-fsSL",
            "--max-time",
            "300",
            "--connect-timeout",
            "20",
            "--max-filesize",
            &MAX_LIST_BYTES.to_string(),
            "-K",
            "-",
        ])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| format!("cannot run curl: {e}"))?;
    {
        use tokio::io::AsyncWriteExt;
        if let Some(mut si) = child.stdin.take() {
            let _ = si.write_all(cfg.as_bytes()).await;
        }
    }
    let out = child
        .wait_with_output()
        .await
        .map_err(|e| format!("curl: {e}"))?;
    if !out.status.success() {
        let _ = std::fs::remove_file(&tmp);
        let msg = String::from_utf8_lossy(&out.stderr)
            .replace(&l.auth_key, "<key>")
            .trim()
            .to_string();
        return Err(format!(
            "download failed: {}",
            msg.lines().last().unwrap_or("curl error")
        ));
    }
    let bytes = std::fs::metadata(&tmp).map(|m| m.len()).unwrap_or(0);
    std::fs::rename(&tmp, &raw).map_err(|e| format!("cannot store the download: {e}"))?;
    Ok(bytes)
}

/// Result of loading one list.
pub struct Loaded {
    pub names: BTreeSet<String>,
    /// RPZ lists: the zone has `*.` twins
    pub rpz_wild: bool,
}

fn load_cached(env: &LanEnv, l: &List) -> Option<Loaded> {
    let body = std::fs::read(list_path(env, l.id, "raw")).ok()?;
    let body = String::from_utf8_lossy(&body);
    let (names, wild) = parse_for(&l.format, &body);
    Some(Loaded {
        names,
        rpz_wild: wild,
    })
}

// ---------------------------------------------------------------------------
// prepare: refresh what is due, write zone files, decide what the resolver loads
// ---------------------------------------------------------------------------

/// One RPZ zone for Unbound.
#[derive(Debug, Clone, PartialEq)]
pub struct Zone {
    pub name: String,
    pub file: String,
    pub log_name: String,
    pub action: String,
}

#[derive(Default)]
pub struct Prepared {
    /// Unbound: allow zone first, then one zone per usable list
    pub zones: Vec<Zone>,
    /// dnsmasq: names per list, within the cap, allowed names removed
    pub names: BTreeMap<String, BTreeSet<String>>,
    /// dnsmasq: allowed domains that must still resolve under a blocked parent
    pub allow_domains: Vec<String>,
    /// a zone file changed on disk: the resolver must reload
    pub zones_changed: bool,
    pub log_queries: bool,
    /// the resolver log is read (lists enabled, query log on, or a manual block list)
    pub tail: bool,
}

impl Prepared {
    pub fn any(&self) -> bool {
        self.zones.len() > 1 || !self.names.is_empty()
    }
}

fn write_if_changed(path: &Path, content: &str) -> std::io::Result<bool> {
    use std::os::unix::fs::PermissionsExt;
    if std::fs::read_to_string(path).ok().as_deref() == Some(content) {
        return Ok(false);
    }
    if let Some(d) = path.parent() {
        std::fs::create_dir_all(d)?;
    }
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, content)?;
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o644))?;
    std::fs::rename(&tmp, path)?;
    Ok(true)
}

/// Refresh what is due (`fetch`), keep status, write the zone files for the
/// resolver `mode` ("resolver" | "forwarder"). Never fails because of one list:
/// a broken list is reported in its status and the last good copy stays.
pub async fn prepare(
    store: &ConfigStore,
    env: &LanEnv,
    mode: &str,
    null_mode: bool,
    fetch_now: bool,
    write: bool,
    rep: &mut ApplyReport,
) -> Result<Prepared> {
    let settings = filter_settings(store).await?;
    let lists: Vec<List> = list_lists(store)
        .await?
        .into_iter()
        .filter(|l| l.enabled)
        .collect();
    let allow_rows = list_allow(store).await?;
    let allow = Allow::compile(&allow_rows);
    let st = statuses(store).await?;
    let cap = effective_cap(&settings, mode);
    let mut budget = cap as i64;
    let mut p = Prepared {
        log_queries: lan::flag(&lan::setting_or(store, "dns.log_queries", "0").await?),
        tail: wants_tail(store).await,
        ..Default::default()
    };
    if lists.is_empty() && allow_rows.is_empty() {
        return Ok(p);
    }
    let t = now();
    let mut all_names: Vec<(String, BTreeSet<String>)> = Vec::new();
    let mut zone_changed = false;
    for l in &lists {
        let mut s = st.get(&l.id).cloned().unwrap_or(Status {
            list_id: l.id,
            ..Default::default()
        });
        let have = list_path(env, l.id, "raw").exists();
        if fetch_now && due(st.get(&l.id), settings.refresh_hours, t, have) {
            s.last_attempt = t;
            s.force = false;
            match fetch(env, l).await {
                Ok(bytes) => {
                    // judge the new copy before it replaces the old statistics
                    let raw = list_path(env, l.id, "raw");
                    let body = std::fs::read(&raw).unwrap_or_default();
                    let text = String::from_utf8_lossy(&body);
                    let (names, _) = parse_for(&l.format, &text);
                    let prev = s.entries;
                    if names.is_empty() {
                        s.last_error =
                            "the download holds no domain names (not a list in the chosen format?)"
                                .into();
                        restore_previous(env, l.id);
                        rep.warn(format!("DNS filter list {}: {}", l.name, s.last_error));
                    } else if prev > 1000 && (names.len() as i64) * 2 < prev {
                        s.last_error = format!(
                            "the new copy has {} names, was {prev}: kept the old copy",
                            names.len()
                        );
                        restore_previous(env, l.id);
                        rep.warn(format!("DNS filter list {}: {}", l.name, s.last_error));
                    } else {
                        s.last_ok = t;
                        s.entries = names.len() as i64;
                        s.bytes = bytes as i64;
                        s.last_error.clear();
                        let _ = std::fs::copy(&raw, list_path(env, l.id, "good"));
                    }
                }
                Err(e) => {
                    s.last_error = e;
                    rep.warn(format!("DNS filter list {}: {}", l.name, s.last_error));
                }
            }
        }
        // load the cached copy
        let Some(loaded) = load_cached(env, l) else {
            if s.last_error.is_empty() {
                s.last_error = "no copy downloaded yet".into();
            }
            s.used = 0;
            if write {
                save_status(store, &s).await?;
            }
            continue;
        };
        if s.entries == 0 {
            s.entries = loaded.names.len() as i64;
        }
        let n = loaded.names.len() as i64;
        if n > budget {
            s.used = 0;
            s.last_error = format!(
                "not loaded: {n} names do not fit the {} name limit of this {} ({} left); raise the limit or unsubscribe from a bigger list",
                cap,
                if mode == "forwarder" { "router" } else { "box" },
                budget.max(0)
            );
            rep.warn(format!("DNS filter list {}: {}", l.name, s.last_error));
            if write {
                save_status(store, &s).await?;
            }
            continue;
        }
        budget -= n;
        s.used = n;
        if s.last_error.starts_with("not loaded") || s.last_error == "no copy downloaded yet" {
            s.last_error.clear();
        }
        if write {
            save_status(store, &s).await?;
        }
        if mode == "resolver" {
            let zone = zone_name(l.id);
            let file = list_path(env, l.id, "zone");
            let content = if l.format == "rpz" {
                // a list in RPZ format is loaded as it is
                std::fs::read_to_string(list_path(env, l.id, "raw")).unwrap_or_default()
            } else {
                zone_file(&zone, &loaded.names, l.subdomains, null_mode)
            };
            if write {
                match write_if_changed(&file, &content) {
                    Ok(c) => zone_changed |= c,
                    Err(e) => {
                        rep.warn(format!(
                            "DNS filter list {}: cannot write its zone: {e}",
                            l.name
                        ));
                        continue;
                    }
                }
            }
            p.zones.push(Zone {
                name: zone,
                file: file.to_string_lossy().into_owned(),
                log_name: l.name.clone(),
                action: l.action.clone(),
            });
        }
        all_names.push((l.name.clone(), loaded.names));
        rep.applied(format!("DNS filter list {}: {} names", l.name, n));
    }
    if mode == "resolver" {
        // the allow zone is first so its passthru records beat every list
        let zone = ALLOW_ZONE_NAME.to_string();
        let mut z = format!(
            "$ORIGIN {zone}\n$TTL 300\n@ IN SOA localhost. root.localhost. 1 3600 600 86400 300\n@ IN NS localhost.\n"
        );
        let mut seen = BTreeSet::new();
        for d in &allow.domains {
            if seen.insert(d.clone()) {
                z.push_str(&format!(
                    "{d} CNAME rpz-passthru.\n*.{d} CNAME rpz-passthru.\n"
                ));
            }
        }
        // wildcards and regular expressions: every name of the lists they match
        // (a name that is not in any list is not blocked, so nothing to allow)
        if !allow.is_empty() {
            for (_, names) in &all_names {
                for n in names {
                    if !allow.domains.is_empty() && allow.matches(n) && seen.contains(n) {
                        continue;
                    }
                    if allow.matches(n) && seen.insert(n.clone()) {
                        z.push_str(&format!(
                            "{n} CNAME rpz-passthru.\n*.{n} CNAME rpz-passthru.\n"
                        ));
                    }
                }
            }
        }
        let file = env.path(LISTS_DIR).join("allow.zone");
        if write {
            match write_if_changed(&file, &z) {
                Ok(c) => zone_changed |= c,
                Err(e) => rep.warn(format!("DNS allow list: cannot write its zone: {e}")),
            }
        }
        if !allow.is_empty() || !p.zones.is_empty() {
            p.zones.insert(
                0,
                Zone {
                    name: zone,
                    file: file.to_string_lossy().into_owned(),
                    log_name: "allow".into(),
                    action: String::new(),
                },
            );
        }
        // an allow list alone (no lists) needs no RPZ at all
        if p.zones.len() == 1 {
            p.zones.clear();
        }
    } else {
        for (name, names) in all_names {
            let kept: BTreeSet<String> = names.into_iter().filter(|n| !allow.matches(n)).collect();
            p.names.insert(name, kept);
        }
        p.allow_domains = allow.domains.clone();
    }
    p.zones_changed = zone_changed;
    Ok(p)
}

/// A rejected download: put the last good copy back.
fn restore_previous(env: &LanEnv, id: i64) {
    let good = list_path(env, id, "good");
    let raw = list_path(env, id, "raw");
    if good.exists() {
        let _ = std::fs::copy(&good, &raw);
    } else {
        let _ = std::fs::remove_file(&raw);
    }
}

// ---------------------------------------------------------------------------
// rendering into the resolver configs
// ---------------------------------------------------------------------------

/// Add the RPZ zones, the respip module and the log settings to a rendered
/// unbound.conf (the render itself stays pure).
pub fn splice_unbound(conf: &str, p: &Prepared) -> String {
    let log_on = !p.zones.is_empty() || p.log_queries || p.tail;
    if !log_on {
        return conf.to_string();
    }
    let mut conf = conf.to_string();
    if !p.zones.is_empty() {
        // module-config: respip ahead of validator/iterator
        let modules = conf
            .lines()
            .find_map(|l| l.trim().strip_prefix("module-config:"))
            .map(|v| v.trim().trim_matches('"').to_string());
        let (old, mut mods): (Option<String>, Vec<String>) = match modules {
            Some(m) => (
                Some(m.clone()),
                m.split_whitespace().map(String::from).collect(),
            ),
            None => {
                let dnssec = conf.contains("auto-trust-anchor-file");
                (
                    None,
                    if dnssec {
                        vec!["validator".into(), "iterator".into()]
                    } else {
                        vec!["iterator".into()]
                    },
                )
            }
        };
        if !mods.iter().any(|m| m == "respip") {
            let at = mods
                .iter()
                .position(|m| m == "validator" || m == "iterator")
                .unwrap_or(0);
            mods.insert(at, "respip".into());
        }
        let line = format!("    module-config: \"{}\"\n", mods.join(" "));
        match old {
            Some(o) => {
                let from = format!("    module-config: \"{o}\"\n");
                conf = conf.replace(&from, &line);
            }
            None => {
                conf = conf.replacen(
                    "    qname-minimisation: yes\n",
                    &format!("    qname-minimisation: yes\n{line}"),
                    1,
                );
            }
        }
    }
    // logging: the tailer needs a file; the rpz-applied lines (and local actions) are
    // `info` messages, so replies are only logged when the query log is on
    if !conf.contains("\n    logfile:") {
        let mut s = format!(
            "    use-syslog: no\n    logfile: \"{UNBOUND_LOG}\"\n    log-local-actions: yes\n"
        );
        if p.log_queries {
            s.push_str("    log-replies: yes\n");
        }
        conf = conf.replace("    use-syslog: yes\n", "");
        conf = conf.replacen(
            "\n    verbosity: 1\n",
            &format!("\n    verbosity: 1\n{s}"),
            1,
        );
    } else if p.log_queries && !conf.contains("log-replies: yes") {
        conf = conf.replacen("    logfile:", "    log-replies: yes\n    logfile:", 1);
    }
    if !p.zones.is_empty() {
        let mut z = String::new();
        for zn in &p.zones {
            z.push_str(&format!(
                "\nrpz:\n    name: \"{}\"\n    zonefile: \"{}\"\n",
                zn.name, zn.file
            ));
            if zn.log_name != "allow" {
                z.push_str(&format!(
                    "    rpz-log: yes\n    rpz-log-name: \"{}\"\n",
                    zn.log_name
                ));
            }
            if !zn.action.is_empty() {
                z.push_str(&format!("    rpz-action-override: {}\n", zn.action));
            }
        }
        let marker = "\nremote-control:";
        conf = match conf.find(marker) {
            Some(i) => {
                let (a, b) = conf.split_at(i);
                format!("{a}{z}{b}")
            }
            None => format!("{conf}{z}"),
        };
    }
    conf
}

/// dnsmasq lines: blocked names (`address=`), allowed domains under a blocked parent,
/// and the log file the tailer reads.
pub fn dnsmasq_lines(p: &Prepared, null_mode: bool) -> Vec<String> {
    let mut lines = Vec::new();
    let mut seen = BTreeSet::new();
    for names in p.names.values() {
        for n in names {
            if seen.insert(n) {
                lines.push(if null_mode {
                    format!("address=/{n}/#")
                } else {
                    format!("address=/{n}/")
                });
            }
        }
    }
    if !p.names.is_empty() {
        for d in &p.allow_domains {
            lines.push(format!("server=/{d}/#"));
        }
        lines.push(format!("log-facility={DNSMASQ_LOG}"));
        lines.push("log-queries".into());
    } else if p.log_queries {
        lines.push(format!("log-facility={DNSMASQ_LOG}"));
    }
    lines
}

// ---------------------------------------------------------------------------
// query log tailer: per-list counters, recent blocked names, the query log
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LogEvent {
    /// `rpz: applied [list] trigger action client@port qname type IN`
    Rpz {
        list: String,
        client: String,
        qname: String,
        qtype: String,
    },
    /// a local-zone action of the manual block list
    Local {
        client: String,
        qname: String,
        qtype: String,
    },
    /// `client qname type IN rcode ...` (log-replies)
    Reply {
        ts: i64,
        client: String,
        qname: String,
        qtype: String,
        rcode: String,
    },
    /// dnsmasq: `query[A] name from client`
    DnsmasqQuery {
        client: String,
        qname: String,
        qtype: String,
    },
    /// dnsmasq: `config name is NXDOMAIN|0.0.0.0|::`
    DnsmasqBlocked { qname: String },
}

pub const MANUAL_LIST: &str = "manual";

pub fn parse_line(line: &str) -> Option<LogEvent> {
    if let Some(rest) = line.strip_prefix('[') {
        // unbound: [epoch] unbound[pid:tid] info: ...
        let (ts, rest) = rest.split_once(']')?;
        let ts: i64 = ts.trim().parse().ok()?;
        let w: Vec<&str> = rest.split_whitespace().collect();
        if w.get(1) != Some(&"info:") {
            return None;
        }
        if w.get(2) == Some(&"rpz:") && w.get(3) == Some(&"applied") {
            // [list] trigger action client@port qname type IN
            let list = w
                .get(4)?
                .trim_start_matches('[')
                .trim_end_matches(']')
                .to_string();
            let client = w
                .get(7)?
                .split('@')
                .next()?
                .trim_start_matches("::ffff:")
                .to_string();
            return Some(LogEvent::Rpz {
                list,
                client,
                qname: w.get(8)?.trim_end_matches('.').to_ascii_lowercase(),
                qtype: w.get(9)?.to_string(),
            });
        }
        // local action: <zone> <action> <client>@<port> <qname> <type> IN
        if let Some(i) = w.iter().skip(2).position(|t| {
            matches!(
                *t,
                "always_nxdomain" | "always_null" | "always_refuse" | "refuse" | "deny"
            )
        }) {
            let i = i + 2;
            let client = w
                .get(i + 1)?
                .split('@')
                .next()?
                .trim_start_matches("::ffff:")
                .to_string();
            return Some(LogEvent::Local {
                client,
                qname: w.get(i + 2)?.trim_end_matches('.').to_ascii_lowercase(),
                qtype: w.get(i + 3)?.to_string(),
            });
        }
        // reply: <client> <qname> <type> IN <rcode> <time> <cached> <size>
        if w.get(5) == Some(&"IN") && w.get(2)?.parse::<std::net::IpAddr>().is_ok() {
            return Some(LogEvent::Reply {
                ts,
                client: w.get(2)?.trim_start_matches("::ffff:").to_string(),
                qname: w.get(3)?.trim_end_matches('.').to_ascii_lowercase(),
                qtype: w.get(4)?.to_string(),
                rcode: w.get(6)?.to_string(),
            });
        }
        None
    } else {
        // dnsmasq (syslog style): `Nov 26 05:00:00 dnsmasq[12]: query[A] x.com from 10.0.0.2`
        let i = line.find("dnsmasq[")?;
        let msg = line[i..].split_once("]: ")?.1;
        let w: Vec<&str> = msg.split_whitespace().collect();
        if let Some(t) = w.first().and_then(|t| t.strip_prefix("query[")) {
            if w.get(2) == Some(&"from") {
                return Some(LogEvent::DnsmasqQuery {
                    client: w.get(3)?.to_string(),
                    qname: w.get(1)?.trim_end_matches('.').to_ascii_lowercase(),
                    qtype: t.trim_end_matches(']').to_string(),
                });
            }
        }
        if w.first() == Some(&"config") && w.get(2) == Some(&"is") {
            return Some(LogEvent::DnsmasqBlocked {
                qname: w.get(1)?.trim_end_matches('.').to_ascii_lowercase(),
            });
        }
        None
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize)]
pub struct IngestStats {
    pub lines: usize,
    pub blocked: usize,
    pub queries: usize,
}

/// Which list owns a blocked name (dnsmasq has no per-list log): the longest suffix
/// of `qname` found in a list.
#[derive(Default)]
pub struct Attributor {
    sets: Vec<(String, BTreeSet<String>)>,
    sig: String,
}

impl Attributor {
    pub async fn refresh(&mut self, store: &ConfigStore, env: &LanEnv) -> Result<()> {
        let lists: Vec<List> = list_lists(store)
            .await?
            .into_iter()
            .filter(|l| l.enabled)
            .collect();
        let st = statuses(store).await?;
        let sig = lists
            .iter()
            .map(|l| format!("{}:{}", l.id, st.get(&l.id).map(|s| s.last_ok).unwrap_or(0)))
            .collect::<Vec<_>>()
            .join(",");
        if sig == self.sig {
            return Ok(());
        }
        self.sets = lists
            .iter()
            .filter_map(|l| load_cached(env, l).map(|x| (l.name.clone(), x.names)))
            .collect();
        self.sig = sig;
        Ok(())
    }

    pub fn owner(&self, qname: &str) -> Option<&str> {
        let mut cur = qname;
        loop {
            for (n, s) in &self.sets {
                if s.contains(cur) {
                    return Some(n);
                }
            }
            match cur.split_once('.') {
                Some((_, rest)) if rest.contains('.') => cur = rest,
                _ => return None,
            }
        }
    }
}

const MAX_READ: u64 = 8 * 1024 * 1024;

fn inode_of(m: &std::fs::Metadata) -> i64 {
    use std::os::unix::fs::MetadataExt;
    m.ino() as i64
}

/// Read what the resolver appended to `path` since the last call: per-list
/// counters and recent blocked names always, the query log when `dns.log_queries`
/// is on. Safe across restarts (offset in `dnsf_log_pos`) and log rotation.
pub async fn ingest(store: &ConfigStore, path: &Path, attr: &Attributor) -> Result<IngestStats> {
    use std::io::{Read, Seek, SeekFrom};
    let mut stats = IngestStats::default();
    let Ok(meta) = std::fs::metadata(path) else {
        return Ok(stats);
    };
    let pool = store.pool()?;
    let key = path.to_string_lossy().to_string();
    let pos = sqlx::query("SELECT inode, offset FROM dnsf_log_pos WHERE path = ?")
        .bind(&key)
        .fetch_optional(pool)
        .await
        .map_err(db_err("log position"))?;
    let (ino, size) = (inode_of(&meta), meta.len());
    let mut offset = match pos {
        Some(r) if r.get::<i64, _>(0) == ino && (r.get::<i64, _>(1) as u64) <= size => {
            r.get::<i64, _>(1) as u64
        }
        _ => 0,
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
    let Some(last_nl) = buf.iter().rposition(|b| *b == b'\n') else {
        if (buf.len() as u64) < MAX_READ {
            return Ok(stats);
        }
        save_pos(store, &key, ino, offset + buf.len() as u64).await?;
        return Ok(stats);
    };
    buf.truncate(last_nl + 1);
    offset += buf.len() as u64;
    let log_queries = lan::flag(&lan::setting_or(store, "dns.log_queries", "0").await?);
    let text = String::from_utf8_lossy(&buf);
    let t = now();
    // (client, qname, type) -> list that blocked it, for the reply row that follows
    let mut pending: HashMap<(String, String, String), String> = HashMap::new();
    let mut last_dm: Option<(String, String, String)> = None; // dnsmasq: last query
    let mut hits: BTreeMap<(String, i64), i64> = BTreeMap::new();
    let mut recent: BTreeMap<(String, String), (i64, i64)> = BTreeMap::new();
    let mut tx = pool.begin().await.map_err(db_err("begin log batch"))?;
    let mut count_block = |list: &str, qname: &str, ts: i64| {
        *hits.entry((list.to_string(), ts / 86400)).or_default() += 1;
        let e = recent
            .entry((qname.to_string(), list.to_string()))
            .or_insert((ts, 0));
        e.0 = e.0.max(ts);
        e.1 += 1;
    };
    for line in text.lines() {
        stats.lines += 1;
        let ev = match parse_line(line) {
            Some(e) => e,
            None => continue,
        };
        match ev {
            LogEvent::Rpz {
                list,
                client,
                qname,
                qtype,
            } => {
                count_block(&list, &qname, t);
                stats.blocked += 1;
                if pending.len() > 4096 {
                    pending.clear();
                }
                pending.insert((client, qname, qtype), list);
            }
            LogEvent::Local {
                client,
                qname,
                qtype,
            } => {
                count_block(MANUAL_LIST, &qname, t);
                stats.blocked += 1;
                if pending.len() > 4096 {
                    pending.clear();
                }
                pending.insert((client, qname, qtype), MANUAL_LIST.to_string());
            }
            LogEvent::Reply {
                ts,
                client,
                qname,
                qtype,
                rcode,
            } => {
                let by = pending
                    .remove(&(client.clone(), qname.clone(), qtype.clone()))
                    .unwrap_or_default();
                if log_queries {
                    sqlx::query(
                        "INSERT INTO dnsf_querylog (ts, client, qname, qtype, rcode, blocked_by) VALUES (?,?,?,?,?,?)",
                    )
                    .bind(ts)
                    .bind(&client)
                    .bind(&qname)
                    .bind(&qtype)
                    .bind(&rcode)
                    .bind(&by)
                    .execute(&mut *tx)
                    .await
                    .map_err(db_err("store DNS log"))?;
                    stats.queries += 1;
                }
            }
            LogEvent::DnsmasqQuery {
                client,
                qname,
                qtype,
            } => {
                last_dm = Some((client, qname, qtype));
            }
            LogEvent::DnsmasqBlocked { qname } => {
                let list = attr.owner(&qname).unwrap_or(MANUAL_LIST).to_string();
                count_block(&list, &qname, t);
                stats.blocked += 1;
                if log_queries {
                    if let Some((client, q, qtype)) = last_dm.take().filter(|(_, q, _)| *q == qname)
                    {
                        sqlx::query(
                            "INSERT INTO dnsf_querylog (ts, client, qname, qtype, rcode, blocked_by) VALUES (?,?,?,?,?,?)",
                        )
                        .bind(t)
                        .bind(&client)
                        .bind(&q)
                        .bind(&qtype)
                        .bind("NXDOMAIN")
                        .bind(&list)
                        .execute(&mut *tx)
                        .await
                        .map_err(db_err("store DNS log"))?;
                        stats.queries += 1;
                    }
                }
            }
        }
    }
    for ((list, day), n) in hits {
        sqlx::query(
            "INSERT INTO dnsf_hits (list, day, blocked) VALUES (?,?,?)
             ON CONFLICT(list, day) DO UPDATE SET blocked = blocked + excluded.blocked",
        )
        .bind(&list)
        .bind(day)
        .bind(n)
        .execute(&mut *tx)
        .await
        .map_err(db_err("count blocked answers"))?;
    }
    for ((domain, list), (ts, n)) in recent {
        sqlx::query(
            "INSERT INTO dnsf_recent (domain, list, last_seen, hits) VALUES (?,?,?,?)
             ON CONFLICT(domain, list) DO UPDATE SET last_seen = MAX(last_seen, excluded.last_seen),
               hits = hits + excluded.hits",
        )
        .bind(&domain)
        .bind(&list)
        .bind(ts)
        .bind(n)
        .execute(&mut *tx)
        .await
        .map_err(db_err("remember blocked names"))?;
    }
    sqlx::query(
        "INSERT INTO dnsf_log_pos (path, inode, offset) VALUES (?,?,?)
         ON CONFLICT(path) DO UPDATE SET inode = excluded.inode, offset = excluded.offset",
    )
    .bind(&key)
    .bind(ino)
    .bind(offset as i64)
    .execute(&mut *tx)
    .await
    .map_err(db_err("save log position"))?;
    tx.commit().await.map_err(db_err("commit log batch"))?;
    Ok(stats)
}

async fn save_pos(store: &ConfigStore, key: &str, ino: i64, offset: u64) -> Result<()> {
    sqlx::query(
        "INSERT INTO dnsf_log_pos (path, inode, offset) VALUES (?,?,?)
         ON CONFLICT(path) DO UPDATE SET inode = excluded.inode, offset = excluded.offset",
    )
    .bind(key)
    .bind(ino)
    .bind(offset as i64)
    .execute(store.pool()?)
    .await
    .map_err(db_err("save log position"))?;
    Ok(())
}

/// Retention: old log rows, old counters, the recent list cap.
pub async fn prune(store: &ConfigStore) -> Result<()> {
    let pool = store.pool()?;
    let t = now();
    let q = |s: &'static str| async move {
        sqlx::query(s)
            .bind(t)
            .execute(pool)
            .await
            .map_err(db_err("prune DNS filter data"))
    };
    sqlx::query("DELETE FROM dnsf_querylog WHERE ts < ? - 86400 * ?")
        .bind(t)
        .bind(LOG_RETENTION_DAYS)
        .execute(pool)
        .await
        .map_err(db_err("prune DNS log"))?;
    sqlx::query("DELETE FROM dnsf_querylog WHERE id <= (SELECT MAX(id) FROM dnsf_querylog) - ?")
        .bind(LOG_MAX_ROWS)
        .execute(pool)
        .await
        .map_err(db_err("cap DNS log"))?;
    sqlx::query("DELETE FROM dnsf_hits WHERE day < ? / 86400 - ?")
        .bind(t)
        .bind(HITS_RETENTION_DAYS)
        .execute(pool)
        .await
        .map_err(db_err("prune counters"))?;
    sqlx::query(
        "DELETE FROM dnsf_recent WHERE rowid NOT IN
         (SELECT rowid FROM dnsf_recent ORDER BY last_seen DESC LIMIT ?)",
    )
    .bind(RECENT_MAX_ROWS)
    .execute(pool)
    .await
    .map_err(db_err("cap recent blocked names"))?;
    let _ = q; // (kept for symmetry with the other prune helpers)
    Ok(())
}

pub async fn clear_log(store: &ConfigStore) -> Result<u64> {
    let r = sqlx::query("DELETE FROM dnsf_querylog")
        .execute(store.pool()?)
        .await
        .map_err(db_err("clear DNS log"))?;
    let _ = sqlx::query("DELETE FROM dnsf_recent")
        .execute(store.pool()?)
        .await;
    Ok(r.rows_affected())
}

#[derive(Debug, Default, Clone, Deserialize)]
pub struct LogQuery {
    #[serde(default)]
    pub q: Option<String>,
    #[serde(default)]
    pub blocked: Option<bool>,
    #[serde(default)]
    pub client: Option<String>,
    #[serde(default)]
    pub limit: Option<i64>,
}

pub async fn search_log(store: &ConfigStore, q: &LogQuery) -> Result<Vec<Value>> {
    let mut sql = String::from(
        "SELECT id, ts, client, qname, qtype, rcode, blocked_by FROM dnsf_querylog WHERE 1=1",
    );
    if q.q.as_deref().is_some_and(|s| !s.is_empty()) {
        sql.push_str(" AND qname LIKE ?");
    }
    if q.client.as_deref().is_some_and(|s| !s.is_empty()) {
        sql.push_str(" AND client = ?");
    }
    match q.blocked {
        Some(true) => sql.push_str(" AND blocked_by <> ''"),
        Some(false) => sql.push_str(" AND blocked_by = ''"),
        None => {}
    }
    sql.push_str(" ORDER BY id DESC LIMIT ?");
    let mut query = sqlx::query(&sql);
    if let Some(s) = q.q.as_deref().filter(|s| !s.is_empty()) {
        let esc = s.replace(['%', '_'], "");
        query = query.bind(format!("%{}%", esc.to_ascii_lowercase()));
    }
    if let Some(c) = q.client.as_deref().filter(|s| !s.is_empty()) {
        query = query.bind(c.to_string());
    }
    let rows = query
        .bind(q.limit.unwrap_or(200).clamp(1, 1000))
        .fetch_all(store.pool()?)
        .await
        .map_err(db_err("search DNS log"))?;
    Ok(rows
        .iter()
        .map(|r| {
            json!({
                "id": r.get::<i64, _>(0), "ts": r.get::<i64, _>(1), "client": r.get::<String, _>(2),
                "qname": r.get::<String, _>(3), "qtype": r.get::<String, _>(4),
                "rcode": r.get::<String, _>(5), "blocked_by": r.get::<String, _>(6),
            })
        })
        .collect())
}

// ---------------------------------------------------------------------------
// overview for the API / page
// ---------------------------------------------------------------------------

pub async fn overview(store: &ConfigStore, env: &LanEnv, mode: &str) -> Result<Value> {
    let settings = filter_settings(store).await?;
    let lists = list_lists(store).await?;
    let st = statuses(store).await?;
    let t = now();
    let day = t / 86400;
    let hits_rows = sqlx::query(
        "SELECT list, SUM(CASE WHEN day = ? THEN blocked ELSE 0 END), SUM(CASE WHEN day >= ? THEN blocked ELSE 0 END), SUM(blocked)
         FROM dnsf_hits GROUP BY list",
    )
    .bind(day)
    .bind(day - 6)
    .fetch_all(store.pool()?)
    .await
    .map_err(db_err("read counters"))?;
    let hits: HashMap<String, (i64, i64, i64)> = hits_rows
        .iter()
        .map(|r| (r.get::<String, _>(0), (r.get(1), r.get(2), r.get(3))))
        .collect();
    let cap = effective_cap(&settings, mode);
    let used: i64 = lists
        .iter()
        .filter(|l| l.enabled)
        .map(|l| st.get(&l.id).map(|s| s.used).unwrap_or(0))
        .sum();
    let lists_v: Vec<Value> = lists
        .iter()
        .map(|l| {
            let s = st.get(&l.id);
            let h = hits.get(&l.name).copied().unwrap_or((0, 0, 0));
            let e = l.catalog.as_deref().and_then(catalog_entry);
            json!({
                "id": l.id, "name": l.name, "catalog": l.catalog, "url": l.url.replace("{key}", "<key>"),
                "format": l.format, "subdomains": l.subdomains, "enabled": l.enabled, "action": l.action,
                "key_set": !l.auth_key.is_empty(),
                "license": e.map(|e| e.license), "license_url": e.map(|e| e.license_url),
                "status": s.map(|s| json!({
                    "last_attempt": s.last_attempt, "last_ok": s.last_ok, "entries": s.entries,
                    "used": s.used, "bytes": s.bytes, "last_error": s.last_error, "force": s.force,
                })),
                "blocked_today": h.0, "blocked_7d": h.1, "blocked_total": h.2,
            })
        })
        .collect();
    let manual = hits.get(MANUAL_LIST).copied().unwrap_or((0, 0, 0));
    let recent_rows = sqlx::query(
        "SELECT domain, list, last_seen, hits FROM dnsf_recent ORDER BY last_seen DESC LIMIT 50",
    )
    .fetch_all(store.pool()?)
    .await
    .map_err(db_err("read recent blocked names"))?;
    let recent: Vec<Value> = recent_rows
        .iter()
        .map(|r| json!({"domain": r.get::<String, _>(0), "list": r.get::<String, _>(1), "last_seen": r.get::<i64, _>(2), "hits": r.get::<i64, _>(3)}))
        .collect();
    let subscribed: BTreeSet<&str> = lists.iter().filter_map(|l| l.catalog.as_deref()).collect();
    let catalog: Vec<Value> = CATALOG
        .iter()
        .map(|c| {
            let mut v = serde_json::to_value(c).unwrap_or(Value::Null);
            v["subscribed"] = json!(subscribed.contains(c.id));
            // does it fit the board? (the size is a hint, the real count is in the status)
            v["fits"] = json!(u64::from(c.approx_entries) <= cap);
            v
        })
        .collect();
    Ok(json!({
        "mode": mode,
        "settings": settings,
        "cap": cap,
        "board_cap": board_cap(mem_total_kb(), mode),
        "used": used,
        "mem_mb": mem_total_kb() / 1024,
        "catalog": catalog,
        "lists": lists_v,
        "allow": list_allow(store).await?,
        "manual_blocked": manual.2,
        "manual_blocked_today": manual.0,
        "recent": recent,
        "rpz_available": mode == "resolver" && env.has_binary(crate::dns::UNBOUND_BIN),
        "log_path": if mode == "forwarder" { DNSMASQ_LOG } else { UNBOUND_LOG },
    }))
}

/// systemd runs unbound in the foreground (`-d`: log to stderr, `logfile:` ignored): this
/// drop-in appends its output to the file the tailer reads. Same file and body as the
/// segmentation query log, so both can own it without fighting.
pub const SYSTEMD_DROPIN: &str = "/etc/systemd/system/unbound.service.d/patronus-querylog.conf";
pub const SYSTEMD_DROPIN_BODY: &str = "[Service]\nStandardOutput=append:/var/log/unbound/unbound.log\nStandardError=append:/var/log/unbound/unbound.log\n";
pub const LOGROTATE_CONF: &str = "/var/log/unbound/unbound.log {\n    size 50M\n    rotate 2\n    copytruncate\n    missingok\n    notifempty\n    compress\n}\n";

pub fn systemd_log_dropin(on: bool) {
    if !on || !Path::new("/run/systemd/system").is_dir() {
        return;
    }
    let p = Path::new(SYSTEMD_DROPIN);
    if std::fs::read_to_string(p).ok().as_deref() != Some(SYSTEMD_DROPIN_BODY) {
        if let Some(d) = p.parent() {
            let _ = std::fs::create_dir_all(d);
        }
        if std::fs::write(p, SYSTEMD_DROPIN_BODY).is_ok() {
            let _ = patronus_core::ServiceManager::new().reload_definitions();
        }
    }
}

/// A log file that grew past `limit` bytes and was read to its end is emptied
/// (copytruncate): a router has no logrotate, and the file lives in RAM.
pub fn truncate_if_big(path: &Path, limit: u64) {
    if let Ok(m) = std::fs::metadata(path) {
        if m.len() > limit {
            let _ = std::fs::OpenOptions::new()
                .write(true)
                .open(path)
                .and_then(|f| f.set_len(0));
        }
    }
}

/// Does the filter need the log file tailed (any list or the query log)?
pub async fn wants_tail(store: &ConfigStore) -> bool {
    let lists = list_lists(store).await.unwrap_or_default();
    lists.iter().any(|l| l.enabled)
        || lan::flag(
            &lan::setting_or(store, "dns.log_queries", "0")
                .await
                .unwrap_or_default(),
        )
        || crate::dns::list_blocked(store)
            .await
            .map(|b| !b.is_empty())
            .unwrap_or(false)
}

/// Refresh due lists and re-apply DNS when something is due (called by applyd).
pub async fn refresh_due(store: &ConfigStore) -> Result<bool> {
    let settings = filter_settings(store).await?;
    let lists = list_lists(store).await?;
    let st = statuses(store).await?;
    let t = now();
    let env = LanEnv::system();
    Ok(lists.iter().filter(|l| l.enabled).any(|l| {
        due(
            st.get(&l.id),
            settings.refresh_hours,
            t,
            list_path(&env, l.id, "raw").exists(),
        )
    }))
}

// ---------------------------------------------------------------------------
// tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_hosts_domains_and_wildcard_lists() {
        let n = parse_names(
            "# comment\n127.0.0.1 localhost\n0.0.0.0 ads.example.com tracker.example.net # c\n\
             *.wild.example.org\nplain.example.io\n! adblock comment\n::1 localhost\nbad name here\n1.2.3.4\n",
        );
        let v: Vec<&str> = n.iter().map(String::as_str).collect();
        assert_eq!(
            v,
            [
                "ads.example.com",
                "plain.example.io",
                "tracker.example.net",
                "wild.example.org"
            ]
        );
    }

    #[test]
    fn rpz_names_come_from_cname_owners_only() {
        let (n, wild) = parse_rpz(
            "$TTL 3600\n@ SOA localhost. root.localhost. 1 2 3 4 5\n  NS localhost.\n; c\n\
             bad.example.com CNAME .\n*.bad.example.com CNAME .\nok.example.com CNAME rpz-passthru.\n\
             32.1.2.0.192.rpz-ip CNAME .\nevil.example.org 300 IN CNAME .\n",
        );
        let v: Vec<&str> = n.iter().map(String::as_str).collect();
        assert_eq!(v, ["bad.example.com", "evil.example.org"]);
        assert!(wild);
    }

    #[test]
    fn zone_files_carry_the_subdomain_twin_and_null_answers() {
        let n: BTreeSet<String> = ["a.example.com".to_string()].into();
        let z = zone_file("x.rpz.", &n, true, false);
        assert!(z.contains("a.example.com CNAME .\n*.a.example.com CNAME .\n"));
        assert!(z.starts_with("$ORIGIN x.rpz.\n"));
        let z = zone_file("x.rpz.", &n, false, true);
        assert!(z.contains("a.example.com A 0.0.0.0\na.example.com AAAA ::\n"));
        assert!(!z.contains("*."));
    }

    #[test]
    fn allow_kinds_match_and_validate() {
        let e = |k: &str, p: &str| AllowEntry {
            id: 0,
            kind: k.into(),
            pattern: p.into(),
            description: String::new(),
        };
        let a = Allow::compile(&[
            e("domain", "example.com"),
            e("wildcard", "ads*.cdn.example.net"),
            e("regex", r"^track\d+\.example\.org$"),
        ]);
        assert!(a.matches("example.com") && a.matches("www.example.com"));
        assert!(!a.matches("badexample.com"));
        assert!(a.matches("ads7.cdn.example.net") && !a.matches("x.cdn.example.net"));
        assert!(a.matches("track12.example.org") && !a.matches("track.example.org"));
        let bad = |k: &str, p: &str| {
            AllowInput {
                kind: k.into(),
                pattern: p.into(),
                description: None,
            }
            .validate()
            .is_err()
        };
        assert!(bad("domain", "*.example.com") && bad("domain", "not a name"));
        assert!(bad("wildcard", "example.com") && bad("regex", "(unclosed"));
        assert!(bad("regex", "") && bad("glob", "x"));
        assert!(!bad("regex", "^a.*b$"));
    }

    #[test]
    fn glob_matches_runs_of_characters() {
        assert!(glob_match("*.example.com", "a.b.example.com"));
        assert!(glob_match("a*c", "abbbc") && !glob_match("a*c", "abbbd"));
        assert!(glob_match("*", "anything"));
        assert!(!glob_match("*.example.com", "example.com"));
    }

    #[test]
    fn board_caps_follow_the_ram() {
        assert_eq!(board_cap(128 * 1024, "forwarder"), 90_000);
        assert_eq!(board_cap(512 * 1024, "forwarder"), 400_000);
        assert_eq!(board_cap(512 * 1024, "resolver"), 60_000);
        assert_eq!(board_cap(8 * 1024 * 1024, "resolver"), 1_000_000);
        assert!(board_cap(128 * 1024, "resolver") <= 40_000);
    }

    #[test]
    fn refresh_schedule_retries_failures_after_an_hour() {
        let s = |ok, att, force| Status {
            list_id: 1,
            last_ok: ok,
            last_attempt: att,
            force,
            ..Default::default()
        };
        assert!(due(None, 24, 1000, false));
        assert!(!due(Some(&s(1000, 1000, false)), 24, 1000 + 3600, true));
        assert!(due(Some(&s(1000, 1000, false)), 24, 1000 + 86400, true));
        assert!(due(Some(&s(1000, 1000, true)), 24, 1001, true));
        // failed attempt: retry in an hour, not at the next apply
        assert!(!due(Some(&s(500, 1000, false)), 24, 1000 + 600, true));
        assert!(due(Some(&s(500, 1000, false)), 24, 1000 + 3600, true));
        assert!(due(Some(&s(1000, 1000, false)), 24, 1001, false));
    }

    #[test]
    fn parses_real_unbound_log_lines() {
        let rpz = "[1795669763] unbound[544:0] info: rpz: applied [stevenblack] *.ads.example.net. rpz-nxdomain 127.0.0.1@47264 x.ads.example.net. A IN";
        assert_eq!(
            parse_line(rpz),
            Some(LogEvent::Rpz {
                list: "stevenblack".into(),
                client: "127.0.0.1".into(),
                qname: "x.ads.example.net".into(),
                qtype: "A".into()
            })
        );
        let local = "[1795669763] unbound[544:0] info: man.example.net. always_nxdomain 127.0.0.1@59897 man.example.net. A IN";
        assert!(matches!(parse_line(local), Some(LogEvent::Local { .. })));
        let reply = "[1795669763] unbound[544:0] info: 127.0.0.1 x.ads.example.net. A IN NXDOMAIN 0.000000 1 46";
        assert_eq!(
            parse_line(reply),
            Some(LogEvent::Reply {
                ts: 1795669763,
                client: "127.0.0.1".into(),
                qname: "x.ads.example.net".into(),
                qtype: "A".into(),
                rcode: "NXDOMAIN".into()
            })
        );
        // a transparent (allowed) local zone is not a block
        let tr = "[1795669763] unbound[544:0] info: ok.ads.example.net. transparent 127.0.0.1@42971 ok.ads.example.net. A IN";
        assert_eq!(parse_line(tr), None);
        assert_eq!(
            parse_line("Nov 26 05:00:00 dnsmasq[12]: config ads.example.com is NXDOMAIN"),
            Some(LogEvent::DnsmasqBlocked {
                qname: "ads.example.com".into()
            })
        );
        assert!(matches!(
            parse_line("Nov 26 05:00:00 dnsmasq[12]: query[A] ads.example.com from 10.0.0.2"),
            Some(LogEvent::DnsmasqQuery { .. })
        ));
    }

    #[test]
    fn splice_adds_respip_rpz_and_logging() {
        let conf = "server:\n    verbosity: 1\n    use-syslog: yes\n    qname-minimisation: yes\n    module-config: \"validator iterator\"\n\nremote-control:\n    control-enable: yes\n";
        let p = Prepared {
            zones: vec![
                Zone {
                    name: ALLOW_ZONE_NAME.into(),
                    file: "/a".into(),
                    log_name: "allow".into(),
                    action: String::new(),
                },
                Zone {
                    name: "patronus-list-1.rpz.".into(),
                    file: "/b".into(),
                    log_name: "stevenblack".into(),
                    action: "disabled".into(),
                },
            ],
            ..Default::default()
        };
        let c = splice_unbound(conf, &p);
        assert!(c.contains("module-config: \"respip validator iterator\""));
        assert!(c.contains("logfile: \"/var/log/unbound/unbound.log\""));
        assert!(!c.contains("use-syslog: yes"));
        assert!(
            c.contains("rpz:\n    name: \"patronus-allow.rpz.\"\n    zonefile: \"/a\"\n\n")
                || c.contains("zonefile: \"/a\"\n\nrpz:")
        );
        assert!(c.contains("rpz-log-name: \"stevenblack\"\n    rpz-action-override: disabled"));
        assert!(c.find("rpz:").unwrap() < c.find("remote-control:").unwrap());
        // no module-config line at all (plain recursor): iterator becomes respip + iterator
        let c = splice_unbound(
            "server:\n    verbosity: 1\n    use-syslog: yes\n    qname-minimisation: yes\n",
            &p,
        );
        assert!(c.contains("module-config: \"respip iterator\""));
        // nothing to do without zones or the query log
        assert_eq!(splice_unbound(conf, &Prepared::default()), conf);
    }

    #[test]
    fn dnsmasq_lines_respect_allow_domains_and_null_mode() {
        let mut p = Prepared::default();
        p.names
            .insert("a".into(), ["ads.example.com".to_string()].into());
        p.allow_domains = vec!["ok.ads.example.com".into()];
        let l = dnsmasq_lines(&p, false);
        assert!(l.contains(&"address=/ads.example.com/".to_string()));
        assert!(l.contains(&"server=/ok.ads.example.com/#".to_string()));
        assert!(dnsmasq_lines(&p, true).contains(&"address=/ads.example.com/#".to_string()));
    }

    #[test]
    fn catalog_is_complete_and_free() {
        let ids: BTreeSet<&str> = CATALOG.iter().map(|c| c.id).collect();
        assert_eq!(ids.len(), CATALOG.len(), "unique ids");
        for want in [
            "stevenblack",
            "oisd-small",
            "hagezi-pro",
            "hagezi-tif-mini",
            "urlhaus",
            "phishing-army",
        ] {
            assert!(ids.contains(want), "{want}");
        }
        for c in CATALOG {
            assert!(
                !c.license.is_empty() && c.license_url.starts_with("https://"),
                "{}",
                c.id
            );
            assert!(FORMATS.contains(&c.format), "{}", c.id);
            assert!(c.url.starts_with("https://"), "{}", c.id);
            assert_eq!(c.needs_key, c.url.contains("{key}"), "{}", c.id);
            assert!(valid_list_name(c.id));
        }
    }

    #[tokio::test]
    async fn measured_data_is_not_configuration_and_lists_are_exported() {
        let s = crate::lan::testutil::store().await;
        add_list(
            &s,
            &ListInput {
                catalog: Some("oisd-small".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        add_allow(
            &s,
            &AllowInput {
                kind: "domain".into(),
                pattern: "example.com".into(),
                description: None,
            },
        )
        .await
        .unwrap();
        let doc = s.export_json().await.unwrap();
        let t = doc["tables"].as_object().unwrap();
        assert!(t.contains_key("dnsf_lists") && t.contains_key("dnsf_allow"));
        for m in [
            "dnsf_status",
            "dnsf_hits",
            "dnsf_recent",
            "dnsf_querylog",
            "dnsf_log_pos",
        ] {
            assert!(
                !t.contains_key(m),
                "{m} is measured data, not configuration"
            );
        }
        // the catalog fills in format, subdomains and the licence-bearing entry
        let l = list_lists(&s).await.unwrap();
        assert_eq!(l[0].format, "domains");
        assert!(l[0].subdomains);
        assert_eq!(l[0].name, "oisd-small");
        // a second subscription to the same name is a client error
        let e = add_list(
            &s,
            &ListInput {
                catalog: Some("oisd-small".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap_err();
        assert!(e.to_string().contains("already configured"), "{e}");
        // the key never leaves through the serialized list
        let mut l0 = l[0].clone();
        l0.auth_key = "secret-key".into();
        assert!(!serde_json::to_string(&l0).unwrap().contains("secret-key"));
        // limits
        for i in 0..5 {
            add_allow(
                &s,
                &AllowInput {
                    kind: "domain".into(),
                    pattern: format!("a{i}.example.com"),
                    description: None,
                },
            )
            .await
            .unwrap();
        }
        assert_eq!(list_allow(&s).await.unwrap().len(), 6);
        save_filter_settings(
            &s,
            &FilterSettingsInput {
                refresh_hours: Some(12),
                max_domains: Some(1000),
            },
        )
        .await
        .unwrap();
        let fs = filter_settings(&s).await.unwrap();
        assert_eq!((fs.refresh_hours, fs.max_domains), (12, 1000));
        assert!(save_filter_settings(
            &s,
            &FilterSettingsInput {
                refresh_hours: Some(999),
                max_domains: None
            }
        )
        .await
        .is_err());
    }

    #[tokio::test]
    async fn the_tailer_counts_per_list_keeps_recent_names_and_the_log() {
        let s = crate::lan::testutil::store().await;
        crate::lan::set_setting(&s, "dns.log_queries", "1")
            .await
            .unwrap();
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("unbound.log");
        let mut body = String::new();
        let l = |s: &str| format!("[1795669763] unbound[5:0] info: {s}\n");
        body.push_str(&l("rpz: applied [stevenblack] ads.example.net. rpz-nxdomain 10.0.0.2@5000 ads.example.net. A IN"));
        body.push_str(&l("10.0.0.2 ads.example.net. A IN NXDOMAIN 0.000000 1 44"));
        body.push_str(&l("rpz: applied [stevenblack] *.ads.example.net. rpz-nxdomain 10.0.0.3@5001 x.ads.example.net. A IN"));
        body.push_str(&l(
            "10.0.0.3 x.ads.example.net. A IN NXDOMAIN 0.000000 1 44",
        ));
        body.push_str(&l(
            "rpz: applied [thr] bad.example.org. rpz-nxdomain 10.0.0.2@5002 bad.example.org. A IN",
        ));
        body.push_str(&l("10.0.0.2 www.example.com. A IN NOERROR 0.001 0 60"));
        body.push_str(&l(
            "man.example.com. always_nxdomain 10.0.0.2@5003 man.example.com. A IN",
        ));
        body.push_str("garbage line\n");
        body.push_str("[1795669764] unbound[5:0] info: 10.0.0.2 partial.example.com. A IN NOER"); // no newline yet
        std::fs::write(&log, &body).unwrap();
        let attr = Attributor::default();
        let st = ingest(&s, &log, &attr).await.unwrap();
        assert_eq!((st.blocked, st.queries), (4, 3), "{st:?}");
        let rows =
            sqlx::query("SELECT list, SUM(blocked) FROM dnsf_hits GROUP BY list ORDER BY list")
                .fetch_all(s.pool().unwrap())
                .await
                .unwrap();
        let got: Vec<(String, i64)> = rows.iter().map(|r| (r.get(0), r.get(1))).collect();
        assert_eq!(
            got,
            vec![
                ("manual".into(), 1),
                ("stevenblack".into(), 2),
                ("thr".into(), 1)
            ]
        );
        let q = search_log(
            &s,
            &LogQuery {
                blocked: Some(true),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(q.len(), 2);
        assert!(q
            .iter()
            .any(|r| r["qname"] == "ads.example.net" && r["blocked_by"] == "stevenblack"));
        let ok = search_log(
            &s,
            &LogQuery {
                q: Some("www".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(ok.len(), 1);
        assert_eq!(ok[0]["rcode"], "NOERROR");
        assert_eq!(ok[0]["blocked_by"], "");
        // the partial last line is read once it is complete; nothing is counted twice
        let mut f = std::fs::OpenOptions::new().append(true).open(&log).unwrap();
        std::io::Write::write_all(&mut f, b"ERROR 0.001 0 60\n").unwrap();
        let st = ingest(&s, &log, &attr).await.unwrap();
        assert_eq!((st.blocked, st.queries), (0, 1));
        assert_eq!(
            ingest(&s, &log, &attr).await.unwrap(),
            IngestStats::default()
        );
        // rotation (a shorter file) starts over
        std::fs::write(&log, l("rpz: applied [thr] bad2.example.org. rpz-nxdomain 10.0.0.2@5002 bad2.example.org. A IN")).unwrap();
        assert_eq!(ingest(&s, &log, &attr).await.unwrap().blocked, 1);
        let ov = overview(&s, &crate::lan::testutil::env(&[]).env, "resolver")
            .await
            .unwrap();
        assert_eq!(ov["manual_blocked"], 1);
        assert!(ov["recent"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["domain"] == "bad2.example.org"));
        // retention
        sqlx::query("UPDATE dnsf_querylog SET ts = 1")
            .execute(s.pool().unwrap())
            .await
            .unwrap();
        prune(&s).await.unwrap();
        assert!(search_log(&s, &LogQuery::default())
            .await
            .unwrap()
            .is_empty());
        assert_eq!(clear_log(&s).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn dnsmasq_log_lines_are_attributed_to_the_owning_list() {
        let s = crate::lan::testutil::store().await;
        let t = crate::lan::testutil::env(&[]);
        let dir = t.env.path(LISTS_DIR);
        std::fs::create_dir_all(&dir).unwrap();
        let id = add_list(
            &s,
            &ListInput {
                name: Some("ads".into()),
                url: Some("file:///x".into()),
                format: Some("domains".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        std::fs::write(dir.join(format!("{id}.raw")), "ads.example.net\n").unwrap();
        let mut attr = Attributor::default();
        attr.refresh(&s, &t.env).await.unwrap();
        assert_eq!(attr.owner("a.b.ads.example.net"), Some("ads"));
        assert_eq!(attr.owner("example.net"), None);
        crate::lan::set_setting(&s, "dns.log_queries", "1")
            .await
            .unwrap();
        let d = tempfile::tempdir().unwrap();
        let log = d.path().join("dnsmasq.log");
        std::fs::write(&log, "Nov 26 05:00:00 dnsmasq[7]: query[A] x.ads.example.net from 10.0.0.9\nNov 26 05:00:00 dnsmasq[7]: config x.ads.example.net is NXDOMAIN\n").unwrap();
        let st = ingest(&s, &log, &attr).await.unwrap();
        assert_eq!((st.blocked, st.queries), (1, 1));
        let r = search_log(&s, &LogQuery::default()).await.unwrap();
        assert_eq!(r[0]["client"], "10.0.0.9");
        assert_eq!(r[0]["blocked_by"], "ads");
    }
}
