//! Aliases that fill themselves (lane B): URL tables, GeoIP country sets
//! and threat-intelligence feeds.
//!
//! All three are ordinary firewall aliases (`$name` in a rule, nft sets
//! `alias_<name>_v4|_v6|_ports`); a row in `firewall_alias_sources` says
//! where their entries come from:
//!
//! | kind | entries come from |
//! |---|---|
//! | `url` | a text list fetched from a URL (pfSense "URL Table" / "URL Table (Ports)") |
//! | `geoip` | the DB-IP "country lite" database, filtered to the alias's countries |
//! | `threat` | a blocklist URL (Spamhaus DROP/EDROP, FireHOL level 1, abuse.ch, ...); the firewall also drops the feed's addresses in the chosen direction ahead of the user's rules |
//!
//! Refreshing is size-capped (`max_entries` per alias, `firewall.threatintel.max_total`
//! across threat feeds), keeps the old entries when a fetch fails, retries a
//! failed refresh after at most 15 minutes and never lets a feed cover
//! private/reserved space (a list containing `10.0.0.0/8` must not cut the
//! LAN off). Boot never needs the network: the entries are stored.

use crate::aliases::{self, Alias, AliasSource};
use crate::nftables::{alias_port_set_name, alias_set_name, AliasKind, TABLE};
use patronus_config::ConfigStore;
use patronus_core::types::IpVersion;
use patronus_core::{Error, Result};
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;

pub const KIND_URL: &str = "url";
pub const KIND_GEOIP: &str = "geoip";
pub const KIND_THREAT: &str = "threat";
/// Alias name prefix of threat feeds.
pub const THREAT_PREFIX: &str = "ti_";
/// Host alias whose members are never dropped by a threat feed.
pub const THREAT_ALLOW: &str = "ti_allow";
/// Upper bound for any feed (nft set memory).
pub const HARD_MAX_ENTRIES: u64 = 500_000;
/// Default cap over all threat feeds together.
pub const DEFAULT_THREAT_TOTAL: u64 = 400_000;
/// NFLOG group of the logging rules (read by the patronus-web collector).
pub const NFLOG_GROUP: u16 = 7;
/// Largest download accepted for a list / the GeoIP database.
const MAX_LIST_BYTES: u64 = 64 * 1024 * 1024;
const MAX_DB_BYTES: u64 = 256 * 1024 * 1024;

fn invalid(m: impl Into<String>) -> Error {
    Error::Config(format!("Invalid request: {}", m.into()))
}

// ---------------------------------------------------------------------
// catalog
// ---------------------------------------------------------------------

/// A well-known free blocklist.
pub struct CatalogFeed {
    pub id: &'static str,
    pub name: &'static str,
    pub url: &'static str,
    pub description: &'static str,
}

pub const CATALOG: &[CatalogFeed] = &[
    CatalogFeed {
        id: "spamhaus_drop",
        name: "Spamhaus DROP",
        url: "https://www.spamhaus.org/drop/drop.txt",
        description: "Netblocks hijacked or leased by spammers and cyber-criminals (IPv4)",
    },
    CatalogFeed {
        id: "spamhaus_edrop",
        name: "Spamhaus EDROP",
        url: "https://www.spamhaus.org/drop/edrop.txt",
        description: "DROP extension: netblocks controlled by known cyber-criminals (IPv4)",
    },
    CatalogFeed {
        id: "spamhaus_dropv6",
        name: "Spamhaus DROPv6",
        url: "https://www.spamhaus.org/drop/dropv6.txt",
        description: "DROP for IPv6",
    },
    CatalogFeed {
        id: "firehol_level1",
        name: "FireHOL level 1",
        url: "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
        description: "Maximum protection, minimum false positives (private ranges are never blocked)",
    },
    CatalogFeed {
        id: "abusech_feodo",
        name: "abuse.ch Feodo Tracker",
        url: "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
        description: "Botnet C&C servers (Feodo/Dridex/Emotet/TrickBot)",
    },
    CatalogFeed {
        id: "abusech_sslbl",
        name: "abuse.ch SSLBL botnet C&C",
        url: "https://sslbl.abuse.ch/blacklist/sslipblacklist.txt",
        description: "IPs of botnet C&C servers using malicious SSL certificates",
    },
];

/// Alias name of a threat feed id (`ti_<id>`).
pub fn threat_alias_name(id: &str) -> String {
    format!("{THREAT_PREFIX}{id}")
}

/// `id` of a catalog feed, if it is one.
pub fn catalog_feed(id: &str) -> Option<&'static CatalogFeed> {
    CATALOG.iter().find(|c| c.id == id)
}

// ---------------------------------------------------------------------
// validation of a source
// ---------------------------------------------------------------------

/// Is this an http(s) URL with a plain host part and nothing that could
/// reach curl as an option or a second URL?
pub fn check_url(u: &str) -> Result<String> {
    let u = u.trim();
    let rest = u
        .strip_prefix("http://")
        .or_else(|| u.strip_prefix("https://"))
        .ok_or_else(|| invalid("the URL must start with http:// or https://"))?;
    if rest.is_empty()
        || u.len() > 2048
        || !u
            .bytes()
            .all(|b| b.is_ascii_graphic() && !matches!(b, b'"' | b'\\' | b'{' | b'}' | b'`'))
    {
        return Err(invalid("the URL has characters that are not allowed"));
    }
    Ok(u.to_string())
}

/// ISO 3166-1 alpha-2 codes: two upper-case letters, normalised.
pub fn check_countries(c: &[String]) -> Result<Vec<String>> {
    let mut out: Vec<String> = Vec::new();
    for x in c.iter().flat_map(|s| s.split([',', ' ', '\n', ';'])) {
        let x = x.trim().to_ascii_uppercase();
        if x.is_empty() {
            continue;
        }
        if x.len() != 2 || !x.bytes().all(|b| b.is_ascii_uppercase()) {
            return Err(invalid(format!(
                "country {x:?}: use two-letter ISO codes such as DE or US"
            )));
        }
        if !out.contains(&x) {
            out.push(x);
        }
    }
    out.sort();
    Ok(out)
}

/// Validate (and normalise) a source for `alias`.
pub fn check_source(alias: &Alias, s: &AliasSource) -> Result<AliasSource> {
    let mut s = s.clone();
    s.kind = s.kind.trim().to_ascii_lowercase();
    match s.kind.as_str() {
        KIND_URL | KIND_THREAT => {
            s.url = Some(check_url(s.url.as_deref().unwrap_or(""))?);
            s.countries.clear();
        }
        KIND_GEOIP => {
            s.url = None;
            s.countries = check_countries(&s.countries)?;
            if s.countries.is_empty() {
                return Err(invalid("a GeoIP alias needs at least one country"));
            }
            if alias.kind != AliasKind::Host {
                return Err(invalid("a GeoIP alias is a host alias"));
            }
        }
        o => {
            return Err(invalid(format!(
                "alias source {o:?} (url, geoip or threat)"
            )))
        }
    }
    if s.kind == KIND_THREAT {
        if alias.kind != AliasKind::Host {
            return Err(invalid("a threat feed is a host alias"));
        }
        if !alias.name.starts_with(THREAT_PREFIX) {
            return Err(invalid(format!(
                "a threat feed alias is named {THREAT_PREFIX}<id>"
            )));
        }
    }
    if !matches!(s.direction.as_str(), "in" | "out" | "both") {
        return Err(invalid("direction: in, out or both"));
    }
    if !(300..=31_536_000).contains(&s.refresh_secs) {
        return Err(invalid(
            "refresh interval: between 5 minutes and one year (in seconds)",
        ));
    }
    if s.max_entries == 0 || s.max_entries > HARD_MAX_ENTRIES {
        return Err(invalid(format!(
            "max entries: 1..={HARD_MAX_ENTRIES} (nft set memory)"
        )));
    }
    Ok(s)
}

/// Build a validated alias from the user-facing description shared by the
/// web API and GitOps: `alias_type` is `host`, `port`, `geoip`,
/// `urltable` or `urltable_ports`; for the self-filling types `entries`
/// are the countries (geoip) or the URL (urltable) unless `source` says
/// more. The entries of a self-filling alias come from refreshing it.
pub fn build_alias(
    name: &str,
    alias_type: &str,
    entries: Vec<String>,
    description: Option<String>,
    source: Option<AliasSource>,
) -> Result<Alias> {
    let t = alias_type.trim().to_ascii_lowercase();
    let (kind, source) = match t.as_str() {
        "geoip" => {
            let mut s = source.unwrap_or_else(|| AliasSource::new(KIND_GEOIP));
            if s.countries.is_empty() {
                s.countries = entries.clone();
            }
            s.kind = KIND_GEOIP.into();
            (AliasKind::Host, Some(s))
        }
        "urltable" | "url_table" | "url" | "urltable_ports" | "url_table_ports" | "url_ports" => {
            let mut s = source.unwrap_or_else(|| AliasSource::new(KIND_URL));
            if s.url.as_deref().unwrap_or("").is_empty() {
                s.url = entries.first().cloned();
            }
            if s.kind != KIND_THREAT {
                s.kind = KIND_URL.into();
            }
            let k = if t.ends_with("ports") {
                AliasKind::Port
            } else {
                AliasKind::Host
            };
            (k, Some(s))
        }
        _ => (aliases::parse_kind(alias_type)?, source),
    };
    let mut a = Alias {
        name: name.to_string(),
        kind,
        entries: if source.is_some() {
            Vec::new()
        } else {
            entries
        },
        description: description.filter(|d| !d.trim().is_empty()),
        source,
    }
    .validated()?;
    if let Some(s) = a.source.clone() {
        a.source = Some(check_source(&a, &s)?);
    }
    Ok(a)
}

// ---------------------------------------------------------------------
// ranges: parse, merge, subtract, render
// ---------------------------------------------------------------------

type R4 = (u32, u32);
type R6 = (u128, u128);

/// Entries of one list, merged and sorted.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Ranges {
    pub v4: Vec<R4>,
    pub v6: Vec<R6>,
}

impl Ranges {
    pub fn len(&self) -> usize {
        self.v4.len() + self.v6.len()
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Merge overlapping/adjacent v4 ranges.
pub fn merge4(v: &mut Vec<R4>) {
    v.sort();
    let mut out: Vec<R4> = Vec::with_capacity(v.len());
    for &(a, b) in v.iter() {
        if let Some(last) = out.last_mut() {
            if a <= last.1 || (last.1 != u32::MAX && a == last.1 + 1) {
                last.1 = last.1.max(b);
                continue;
            }
        }
        out.push((a, b));
    }
    *v = out;
}

/// Merge overlapping/adjacent v6 ranges.
pub fn merge6(v: &mut Vec<R6>) {
    v.sort();
    let mut out: Vec<R6> = Vec::with_capacity(v.len());
    for &(a, b) in v.iter() {
        if let Some(last) = out.last_mut() {
            if a <= last.1 || (last.1 != u128::MAX && a == last.1 + 1) {
                last.1 = last.1.max(b);
                continue;
            }
        }
        out.push((a, b));
    }
    *v = out;
}

fn subtract4(v: &mut Vec<R4>, holes: &[R4]) {
    let mut out = Vec::with_capacity(v.len());
    for &(a, b) in v.iter() {
        let mut cur = Some((a, b));
        for &(ha, hb) in holes {
            let Some((ca, cb)) = cur else { break };
            if hb < ca || ha > cb {
                continue;
            }
            if ha > ca {
                out.push((ca, ha - 1));
            }
            cur = if hb < cb { Some((hb + 1, cb)) } else { None };
        }
        if let Some(c) = cur {
            out.push(c);
        }
    }
    *v = out;
}

fn subtract6(v: &mut Vec<R6>, holes: &[R6]) {
    let mut out = Vec::with_capacity(v.len());
    for &(a, b) in v.iter() {
        let mut cur = Some((a, b));
        for &(ha, hb) in holes {
            let Some((ca, cb)) = cur else { break };
            if hb < ca || ha > cb {
                continue;
            }
            if ha > ca {
                out.push((ca, ha - 1));
            }
            cur = if hb < cb { Some((hb + 1, cb)) } else { None };
        }
        if let Some(c) = cur {
            out.push(c);
        }
    }
    *v = out;
}

fn cidr4(s: &str) -> R4 {
    let (a, p) = s.split_once('/').expect("cidr");
    let a: Ipv4Addr = a.parse().expect("v4");
    let p: u32 = p.parse().expect("len");
    let mask = if p == 0 { 0 } else { u32::MAX << (32 - p) };
    let start = u32::from(a) & mask;
    (start, start | !mask)
}

fn cidr6(s: &str) -> R6 {
    let (a, p) = s.split_once('/').expect("cidr");
    let a: Ipv6Addr = a.parse().expect("v6");
    let p: u32 = p.parse().expect("len");
    let mask = if p == 0 { 0 } else { u128::MAX << (128 - p) };
    let start = u128::from(a) & mask;
    (start, start | !mask)
}

/// Space a threat feed must never cover.
pub fn reserved_ranges() -> (Vec<R4>, Vec<R6>) {
    let mut v4: Vec<R4> = [
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.0.0.0/24",
        "192.168.0.0/16",
        "224.0.0.0/3",
    ]
    .iter()
    .map(|s| cidr4(s))
    .collect();
    merge4(&mut v4);
    let mut v6: Vec<R6> = ["::/128", "::1/128", "fc00::/7", "fe80::/10", "ff00::/8"]
        .iter()
        .map(|s| cidr6(s))
        .collect();
    merge6(&mut v6);
    (v4, v6)
}

/// One list token (address, CIDR or `a-b`) as a range.
enum Tok {
    V4(R4),
    V6(R6),
}

fn token(t: &str) -> Option<Tok> {
    if let Some((a, p)) = t.split_once('/') {
        let addr: IpAddr = a.parse().ok()?;
        if p.is_empty() || p.len() > 3 || !p.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        let plen: u32 = p.parse().ok()?;
        return match addr {
            // a /0../7 in a feed is a mistake or an attack, never a netblock
            IpAddr::V4(_) if (8..=32).contains(&plen) => Some(Tok::V4(cidr4(&format!("{a}/{p}")))),
            IpAddr::V6(_) if (16..=128).contains(&plen) => {
                Some(Tok::V6(cidr6(&format!("{a}/{p}"))))
            }
            _ => None,
        };
    }
    if let Some((a, b)) = t.split_once('-') {
        return match (a.parse::<IpAddr>().ok()?, b.parse::<IpAddr>().ok()?) {
            (IpAddr::V4(a), IpAddr::V4(b)) if a <= b => Some(Tok::V4((a.into(), b.into()))),
            (IpAddr::V6(a), IpAddr::V6(b)) if a <= b => Some(Tok::V6((a.into(), b.into()))),
            _ => None,
        };
    }
    match t.parse::<IpAddr>().ok()? {
        IpAddr::V4(a) => Some(Tok::V4((a.into(), a.into()))),
        IpAddr::V6(a) => Some(Tok::V6((a.into(), a.into()))),
    }
}

/// The address token of one list line: comments (`#`, `;`, `//`) and
/// anything after the first blank/comma are dropped; NDJSON lines
/// (`{"cidr":"1.2.3.0/24",...}`, Spamhaus' new format) give their
/// `cidr` / `ip` field.
fn line_token(line: &str) -> Option<String> {
    let l = line.trim();
    if l.is_empty() || l.starts_with(['#', ';']) || l.starts_with("//") {
        return None;
    }
    if l.starts_with('{') {
        let v: serde_json::Value = serde_json::from_str(l).ok()?;
        return v
            .get("cidr")
            .or_else(|| v.get("ip"))
            .and_then(|x| x.as_str())
            .map(str::to_string);
    }
    let l = l.split(['#', ';']).next().unwrap_or("");
    let t = l
        .split(|c: char| c.is_whitespace() || c == ',')
        .next()
        .unwrap_or("");
    let t = t.trim_matches('"');
    (!t.is_empty()).then(|| t.to_string())
}

/// Result of parsing a downloaded list.
#[derive(Debug, Default)]
pub struct Parsed {
    pub ranges: Ranges,
    pub ports: Vec<String>,
    /// Lines that held something other than an entry.
    pub skipped: usize,
}

/// Parse a host list (one entry per line).
pub fn parse_host_list(text: &str) -> Parsed {
    let mut p = Parsed::default();
    for line in text.lines() {
        let Some(t) = line_token(line) else {
            // blank and comment lines are not "skipped entries"
            let l = line.trim();
            if !(l.is_empty() || l.starts_with(['#', ';']) || l.starts_with("//")) {
                p.skipped += 1;
            }
            continue;
        };
        match token(&t) {
            Some(Tok::V4(r)) => p.ranges.v4.push(r),
            Some(Tok::V6(r)) => p.ranges.v6.push(r),
            None => p.skipped += 1,
        }
    }
    merge4(&mut p.ranges.v4);
    merge6(&mut p.ranges.v6);
    p
}

/// Parse a port list (ports and `a-b` ranges, one per line).
pub fn parse_port_list(text: &str) -> Parsed {
    let mut p = Parsed::default();
    let mut set: Vec<(u16, u16)> = Vec::new();
    for line in text.lines() {
        let Some(t) = line_token(line) else { continue };
        let one = |s: &str| s.parse::<u16>().ok().filter(|n| *n != 0);
        let r = match t.split_once('-') {
            Some((a, b)) => one(a).zip(one(b)).filter(|(a, b)| a <= b),
            None => one(&t).map(|n| (n, n)),
        };
        match r {
            Some(r) => set.push(r),
            None => p.skipped += 1,
        }
    }
    set.sort();
    set.dedup();
    p.ports = set
        .into_iter()
        .map(|(a, b)| {
            if a == b {
                a.to_string()
            } else {
                format!("{a}-{b}")
            }
        })
        .collect();
    p
}

fn fmt4(a: u32, b: u32) -> String {
    if a == b {
        return Ipv4Addr::from(a).to_string();
    }
    let len = b - a;
    // an aligned power-of-two block is shown as a CIDR
    if len != u32::MAX && (len + 1).is_power_of_two() && a & len == 0 {
        return format!("{}/{}", Ipv4Addr::from(a), 32 - (len + 1).trailing_zeros());
    }
    if a == 0 && b == u32::MAX {
        return "0.0.0.0/0".into();
    }
    format!("{}-{}", Ipv4Addr::from(a), Ipv4Addr::from(b))
}

fn fmt6(a: u128, b: u128) -> String {
    if a == b {
        return Ipv6Addr::from(a).to_string();
    }
    let len = b - a;
    if len != u128::MAX && (len + 1).is_power_of_two() && a & len == 0 {
        return format!("{}/{}", Ipv6Addr::from(a), 128 - (len + 1).trailing_zeros());
    }
    format!("{}-{}", Ipv6Addr::from(a), Ipv6Addr::from(b))
}

impl Ranges {
    /// Entry texts (IPv4 first), as an alias stores them.
    pub fn render(&self) -> Vec<String> {
        let mut v: Vec<String> = Vec::with_capacity(self.len());
        v.extend(self.v4.iter().map(|&(a, b)| fmt4(a, b)));
        v.extend(self.v6.iter().map(|&(a, b)| fmt6(a, b)));
        v
    }

    /// Keep at most `cap` ranges (the lowest addresses; the bool says
    /// whether anything was dropped).
    pub fn capped(mut self, cap: usize) -> (Self, bool) {
        if self.len() <= cap {
            return (self, false);
        }
        if self.v4.len() > cap {
            self.v4.truncate(cap);
            self.v6.clear();
        } else {
            self.v6.truncate(cap - self.v4.len());
        }
        (self, true)
    }

    /// Remove private / reserved space.
    pub fn without_reserved(mut self) -> Self {
        let (h4, h6) = reserved_ranges();
        subtract4(&mut self.v4, &h4);
        subtract6(&mut self.v6, &h6);
        self
    }
}

// ---------------------------------------------------------------------
// GeoIP database (DB-IP "IP to Country Lite", CC-BY 4.0)
// ---------------------------------------------------------------------

/// Parsed DB-IP country database.
#[derive(Debug, Default)]
pub struct GeoDb {
    v4: Vec<(u32, u32, [u8; 2])>,
    v6: Vec<(u128, u128, [u8; 2])>,
}

impl GeoDb {
    /// Parse `start,end,CC` lines (quotes optional).
    pub fn parse(text: &str) -> GeoDb {
        let mut db = GeoDb::default();
        for line in text.lines() {
            let mut f = line.split(',').map(|x| x.trim().trim_matches('"'));
            let (Some(a), Some(b), Some(cc)) = (f.next(), f.next(), f.next()) else {
                continue;
            };
            let cc = cc.to_ascii_uppercase();
            if cc.len() != 2 || cc == "ZZ" {
                continue;
            }
            let cc = [cc.as_bytes()[0], cc.as_bytes()[1]];
            match (a.parse::<IpAddr>(), b.parse::<IpAddr>()) {
                (Ok(IpAddr::V4(a)), Ok(IpAddr::V4(b))) if a <= b => {
                    db.v4.push((a.into(), b.into(), cc))
                }
                (Ok(IpAddr::V6(a)), Ok(IpAddr::V6(b))) if a <= b => {
                    db.v6.push((a.into(), b.into(), cc))
                }
                _ => {}
            }
        }
        // sorted so `lookup` can binary-search (DB-IP ranges do not overlap)
        db.v4.sort_unstable_by_key(|r| r.0);
        db.v6.sort_unstable_by_key(|r| r.0);
        db
    }

    pub fn len(&self) -> usize {
        self.v4.len() + self.v6.len()
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Ranges of the given countries, merged.
    pub fn ranges_for(&self, countries: &[String]) -> Ranges {
        let want: HashSet<[u8; 2]> = countries
            .iter()
            .filter(|c| c.len() == 2)
            .map(|c| {
                [
                    c.as_bytes()[0].to_ascii_uppercase(),
                    c.as_bytes()[1].to_ascii_uppercase(),
                ]
            })
            .collect();
        let mut r = Ranges {
            v4: self
                .v4
                .iter()
                .filter(|(_, _, c)| want.contains(c))
                .map(|&(a, b, _)| (a, b))
                .collect(),
            v6: self
                .v6
                .iter()
                .filter(|(_, _, c)| want.contains(c))
                .map(|&(a, b, _)| (a, b))
                .collect(),
        };
        merge4(&mut r.v4);
        merge6(&mut r.v6);
        r
    }

    /// Country of one address (binary search over the sorted ranges).
    pub fn lookup(&self, ip: IpAddr) -> Option<String> {
        let cc = match ip {
            IpAddr::V4(a) => {
                let x = u32::from(a);
                let i = self.v4.partition_point(|r| r.0 <= x);
                self.v4.get(i.checked_sub(1)?).filter(|r| x <= r.1)?.2
            }
            IpAddr::V6(a) => {
                let x = u128::from(a);
                let i = self.v6.partition_point(|r| r.0 <= x);
                self.v6.get(i.checked_sub(1)?).filter(|r| x <= r.1)?.2
            }
        };
        Some(String::from_utf8_lossy(&cc).into_owned())
    }

    /// Country codes in the database with their range counts.
    pub fn countries(&self) -> Vec<(String, usize)> {
        let mut m: HashMap<[u8; 2], usize> = HashMap::new();
        for (_, _, c) in &self.v4 {
            *m.entry(*c).or_default() += 1;
        }
        for (_, _, c) in &self.v6 {
            *m.entry(*c).or_default() += 1;
        }
        let mut v: Vec<(String, usize)> = m
            .into_iter()
            .map(|(c, n)| (String::from_utf8_lossy(&c).into_owned(), n))
            .collect();
        v.sort();
        v
    }
}

/// Directory of downloaded data (`$PATRONUS_FEEDS_DIR`, default
/// `/var/lib/patronus/feeds`).
pub fn feeds_dir() -> PathBuf {
    std::env::var_os("PATRONUS_FEEDS_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/var/lib/patronus/feeds"))
}

/// The decompressed GeoIP database file.
pub fn geoip_db_path() -> PathBuf {
    feeds_dir().join("dbip-country-lite.csv")
}

pub const CFG_GEO_URL: &str = "firewall.geoip.db_url";
pub const CFG_GEO_DAYS: &str = "firewall.geoip.refresh_days";
pub const CFG_GEO_UPDATED: &str = "firewall.geoip.db_updated";
pub const CFG_GEO_ATTEMPT: &str = "firewall.geoip.db_attempt";
pub const CFG_GEO_STATUS: &str = "firewall.geoip.db_status";
pub const CFG_THREAT_TOTAL: &str = "firewall.threatintel.max_total";
/// `1` = log what the default policy drops (NFLOG, rate limited).
pub const CFG_LOG_DEFAULT_DENY: &str = "firewall.log_default_deny";

/// DB-IP publishes `dbip-country-lite-YYYY-MM.csv.gz` once a month.
pub fn default_geoip_urls(now: i64) -> Vec<String> {
    let d = chrono::DateTime::<chrono::Utc>::from_timestamp(now, 0).unwrap_or_default();
    let (y, m) = (
        d.format("%Y").to_string().parse::<i32>().unwrap_or(2026),
        d.format("%m").to_string().parse::<u32>().unwrap_or(1),
    );
    let (py, pm) = if m == 1 { (y - 1, 12) } else { (y, m - 1) };
    vec![
        format!("https://download.db-ip.com/free/dbip-country-lite-{y}-{m:02}.csv.gz"),
        format!("https://download.db-ip.com/free/dbip-country-lite-{py}-{pm:02}.csv.gz"),
    ]
}

/// GeoIP database settings and state.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct GeoDbStatus {
    /// Empty = the DB-IP monthly download.
    pub db_url: String,
    pub refresh_days: u64,
    pub updated: Option<i64>,
    pub attempt: Option<i64>,
    pub status: String,
    pub present: bool,
    pub size_bytes: u64,
}

async fn cfg(store: &ConfigStore, k: &str) -> Result<Option<String>> {
    store.load_system_config(k).await
}

pub async fn geoip_status(store: &ConfigStore) -> Result<GeoDbStatus> {
    let p = geoip_db_path();
    let meta = std::fs::metadata(&p).ok();
    Ok(GeoDbStatus {
        db_url: cfg(store, CFG_GEO_URL).await?.unwrap_or_default(),
        refresh_days: cfg(store, CFG_GEO_DAYS)
            .await?
            .and_then(|v| v.parse().ok())
            .unwrap_or(30),
        updated: cfg(store, CFG_GEO_UPDATED)
            .await?
            .and_then(|v| v.parse().ok()),
        attempt: cfg(store, CFG_GEO_ATTEMPT)
            .await?
            .and_then(|v| v.parse().ok()),
        status: cfg(store, CFG_GEO_STATUS)
            .await?
            .unwrap_or_else(|| "not downloaded yet".into()),
        present: meta.is_some(),
        size_bytes: meta.map(|m| m.len()).unwrap_or(0),
    })
}

/// Save the database URL (empty = DB-IP) and refresh interval.
pub async fn set_geoip_config(store: &ConfigStore, db_url: &str, refresh_days: u64) -> Result<()> {
    let u = db_url.trim();
    if !u.is_empty() {
        check_url(u)?;
    }
    if !(1..=365).contains(&refresh_days) {
        return Err(invalid("refresh: 1 to 365 days"));
    }
    store.save_system_config(CFG_GEO_URL, u).await?;
    store
        .save_system_config(CFG_GEO_DAYS, &refresh_days.to_string())
        .await
}

// ---------------------------------------------------------------------
// fetching
// ---------------------------------------------------------------------

/// Where list bytes come from (curl in production, a map in tests).
#[async_trait::async_trait]
pub trait Fetcher: Send + Sync {
    /// The body of `url` (gunzipped when it is gzip data), at most
    /// `max_bytes`.
    async fn fetch(&self, url: &str, max_bytes: u64) -> Result<Vec<u8>>;
}

/// `curl` + `gzip -dc`.
pub struct CurlFetcher;

#[async_trait::async_trait]
impl Fetcher for CurlFetcher {
    async fn fetch(&self, url: &str, max_bytes: u64) -> Result<Vec<u8>> {
        let url = check_url(url)?;
        let dir = feeds_dir();
        std::fs::create_dir_all(&dir)
            .map_err(|e| Error::Config(format!("create {}: {e}", dir.display())))?;
        let tmp = dir.join(format!(".dl-{}-{}", std::process::id(), rand_suffix()));
        let out = tokio::process::Command::new("curl")
            .args([
                "-fsSL",
                "--proto",
                "=http,https",
                "--proto-redir",
                "=http,https",
                "--max-time",
                "300",
                "--connect-timeout",
                "20",
                "--max-filesize",
                &max_bytes.to_string(),
                "-A",
                "Patronus-feeds/1.0",
                "-o",
            ])
            .arg(&tmp)
            .arg("--")
            .arg(&url)
            .output()
            .await
            .map_err(|e| Error::Config(format!("cannot run curl: {e}")))?;
        if !out.status.success() {
            let _ = std::fs::remove_file(&tmp);
            return Err(Error::Config(format!(
                "download failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            )));
        }
        let raw = std::fs::read(&tmp).map_err(|e| Error::Config(format!("read download: {e}")));
        let gz = raw
            .as_ref()
            .map(|r| r.starts_with(&[0x1f, 0x8b]))
            .unwrap_or(false);
        let res = if gz {
            let o = tokio::process::Command::new("gzip")
                .arg("-dc")
                .arg(&tmp)
                .output()
                .await
                .map_err(|e| Error::Config(format!("cannot run gzip: {e}")))?;
            if o.status.success() {
                Ok(o.stdout)
            } else {
                Err(Error::Config("the download is not valid gzip data".into()))
            }
        } else {
            raw
        };
        let _ = std::fs::remove_file(&tmp);
        res
    }
}

fn rand_suffix() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

// ---------------------------------------------------------------------
// refreshing
// ---------------------------------------------------------------------

/// What one refresh did.
#[derive(Debug, Clone, PartialEq)]
pub struct Outcome {
    pub alias: String,
    pub ok: bool,
    pub status: String,
    pub count: usize,
    /// The alias after a successful refresh whose entries changed (the
    /// caller swaps the live nft set for it).
    pub changed: Option<Alias>,
}

async fn record(
    store: &ConfigStore,
    name: &str,
    now: i64,
    ok: bool,
    status: &str,
    count: Option<usize>,
) -> Result<()> {
    sqlx::query(
        "UPDATE firewall_alias_sources SET last_attempt = ?,
            last_refresh = CASE WHEN ? THEN ? ELSE last_refresh END,
            last_status = ?,
            last_count = COALESCE(?, last_count) WHERE alias = ?",
    )
    .bind(now)
    .bind(ok)
    .bind(now)
    .bind(status)
    .bind(count.map(|c| c as i64))
    .bind(name)
    .execute(store.pool()?)
    .await
    .map_err(|e| Error::Config(format!("record refresh: {e}")))?;
    Ok(())
}

async fn write_entries(
    store: &ConfigStore,
    name: &str,
    entries: &[String],
    now: i64,
) -> Result<()> {
    sqlx::query("UPDATE firewall_aliases SET entries = ?, updated_at = ? WHERE name = ?")
        .bind(serde_json::to_string(entries).expect("strings serialize"))
        .bind(now)
        .bind(name)
        .execute(store.pool()?)
        .await
        .map_err(|e| Error::Config(format!("write alias entries: {e}")))?;
    Ok(())
}

/// Seconds after which a failed refresh is tried again.
pub fn retry_secs(refresh_secs: u64) -> u64 {
    refresh_secs.min(900)
}

/// Is this source due at `now`?
pub fn is_due(src: &AliasSource, now: i64) -> bool {
    if !src.enabled {
        return false;
    }
    let Some(att) = src.last_attempt else {
        return true;
    };
    let failed = src.last_refresh.map(|r| r < att).unwrap_or(true);
    let wait = if failed {
        retry_secs(src.refresh_secs)
    } else {
        src.refresh_secs
    };
    now >= att + wait as i64
}

/// Download (if due or `force`d) the GeoIP database into
/// [`geoip_db_path`]. Returns whether a new file was written.
pub async fn refresh_geoip_db(
    store: &ConfigStore,
    fetcher: &dyn Fetcher,
    force: bool,
    now: i64,
) -> Result<bool> {
    let st = geoip_status(store).await?;
    let fresh = st.present
        && st
            .updated
            .map(|u| now - u < (st.refresh_days * 86_400) as i64)
            .unwrap_or(false);
    // a failed download is retried after 15 minutes, not every tick
    let recently_failed = st
        .attempt
        .map(|a| now - a < 900 && st.updated.map(|u| u < a).unwrap_or(true))
        .unwrap_or(false);
    if !force && (fresh || recently_failed) {
        return Ok(false);
    }
    let urls = if st.db_url.is_empty() {
        default_geoip_urls(now)
    } else {
        vec![st.db_url.clone()]
    };
    store
        .save_system_config(CFG_GEO_ATTEMPT, &now.to_string())
        .await?;
    let mut last_err = String::new();
    for u in urls {
        match fetcher.fetch(&u, MAX_DB_BYTES).await {
            Ok(bytes) => {
                let text = String::from_utf8_lossy(&bytes);
                let db = GeoDb::parse(&text);
                if db.len() < 10 {
                    last_err = format!(
                        "{u}: not a DB-IP country database ({} usable rows)",
                        db.len()
                    );
                    continue;
                }
                let p = geoip_db_path();
                let dir = p.parent().map(|d| d.to_path_buf()).unwrap_or_default();
                std::fs::create_dir_all(&dir)
                    .map_err(|e| Error::Config(format!("create {}: {e}", dir.display())))?;
                let tmp = dir.join(".dbip.tmp");
                std::fs::write(&tmp, &bytes)
                    .and_then(|_| std::fs::rename(&tmp, &p))
                    .map_err(|e| Error::Config(format!("write {}: {e}", p.display())))?;
                store
                    .save_system_config(CFG_GEO_UPDATED, &now.to_string())
                    .await?;
                store
                    .save_system_config(
                        CFG_GEO_STATUS,
                        &format!("ok: {} ranges from {u}", db.len()),
                    )
                    .await?;
                return Ok(true);
            }
            Err(e) => last_err = format!("{u}: {e}"),
        }
    }
    store
        .save_system_config(CFG_GEO_STATUS, &format!("error: {last_err}"))
        .await?;
    Err(Error::Config(format!("GeoIP database: {last_err}")))
}

/// Load the downloaded GeoIP database, if there is one.
pub fn load_geoip_db() -> Option<GeoDb> {
    let text = std::fs::read(geoip_db_path()).ok()?;
    Some(GeoDb::parse(&String::from_utf8_lossy(&text)))
}

async fn threat_total_cap(store: &ConfigStore) -> Result<u64> {
    Ok(cfg(store, CFG_THREAT_TOTAL)
        .await?
        .and_then(|v| v.parse().ok())
        .filter(|v| *v > 0)
        .unwrap_or(DEFAULT_THREAT_TOTAL)
        .min(2 * HARD_MAX_ENTRIES))
}

/// Refresh one alias now. A failed fetch keeps the old entries and is
/// recorded in the alias's status (the error is also in the outcome).
pub async fn refresh_alias(
    store: &ConfigStore,
    fetcher: &dyn Fetcher,
    name: &str,
    now: i64,
) -> Result<Outcome> {
    let all = aliases::load_aliases(store).await?;
    let Some(alias) = all.iter().find(|a| a.name == name).cloned() else {
        return Err(invalid(format!("alias {name} not found")));
    };
    let Some(src) = alias.source.clone() else {
        return Err(invalid(format!(
            "alias {name} is not a URL table, GeoIP or threat alias"
        )));
    };
    let fail = |status: String| Outcome {
        alias: name.to_string(),
        ok: false,
        status,
        count: alias.entries.len(),
        changed: None,
    };
    let built: std::result::Result<(Vec<String>, String), String> = async {
        match src.kind.as_str() {
            KIND_GEOIP => {
                match refresh_geoip_db(store, fetcher, false, now).await {
                    Ok(_) => {}
                    // a stale database still answers; only "none at all" is fatal
                    Err(e) if geoip_db_path().exists() => {
                        tracing::warn!("GeoIP database refresh failed, using the old file: {e}")
                    }
                    Err(e) => return Err(e.to_string()),
                }
                let db = load_geoip_db()
                    .ok_or_else(|| "the GeoIP database has not been downloaded".to_string())?;
                let r = db.ranges_for(&src.countries);
                let (r, trunc) = r.capped(src.max_entries as usize);
                let n = r.len();
                let msg = format!(
                    "ok: {n} ranges for {}{}",
                    src.countries.join(","),
                    if trunc {
                        " (truncated at the entry cap)"
                    } else {
                        ""
                    }
                );
                Ok((r.render(), msg))
            }
            KIND_URL | KIND_THREAT => {
                let url = src.url.clone().unwrap_or_default();
                let bytes = fetcher
                    .fetch(&url, MAX_LIST_BYTES)
                    .await
                    .map_err(|e| e.to_string())?;
                let text = String::from_utf8_lossy(&bytes);
                let mut cap = src.max_entries as usize;
                if src.kind == KIND_THREAT {
                    // the shared budget over all threat feeds
                    let total = threat_total_cap(store).await.map_err(|e| e.to_string())? as usize;
                    let others: usize = all
                        .iter()
                        .filter(|a| a.name != name)
                        .filter_map(|a| a.source.as_ref())
                        .filter(|s| s.kind == KIND_THREAT && s.enabled)
                        .map(|s| s.last_count.unwrap_or(0).max(0) as usize)
                        .sum();
                    cap = cap.min(total.saturating_sub(others));
                    if cap == 0 {
                        return Err(format!(
                            "the threat-feed budget of {total} entries is used up by other feeds"
                        ));
                    }
                }
                if alias.kind == AliasKind::Port {
                    let p = parse_port_list(&text);
                    if p.ports.is_empty() {
                        return Err(format!(
                            "no ports found in the list ({} bad lines)",
                            p.skipped
                        ));
                    }
                    let trunc = p.ports.len() > cap;
                    let mut ports = p.ports;
                    ports.truncate(cap);
                    let msg = format!(
                        "ok: {} ports{}",
                        ports.len(),
                        if trunc {
                            " (truncated at the entry cap)"
                        } else {
                            ""
                        }
                    );
                    Ok((ports, msg))
                } else {
                    let p = parse_host_list(&text);
                    if p.ranges.is_empty() {
                        return Err(format!(
                            "no addresses found in the list ({} unusable lines)",
                            p.skipped
                        ));
                    }
                    let r = if src.kind == KIND_THREAT {
                        p.ranges.without_reserved()
                    } else {
                        p.ranges
                    };
                    let (r, trunc) = r.capped(cap);
                    let msg = format!(
                        "ok: {} entries{}{}",
                        r.len(),
                        if trunc {
                            " (truncated at the entry cap)"
                        } else {
                            ""
                        },
                        if p.skipped > 0 {
                            format!(", {} unusable lines skipped", p.skipped)
                        } else {
                            String::new()
                        }
                    );
                    Ok((r.render(), msg))
                }
            }
            o => Err(format!("unknown source kind {o:?}")),
        }
    }
    .await;
    match built {
        Err(e) => {
            let status = format!("error: {e}");
            record(store, name, now, false, &status, None).await?;
            Ok(fail(status))
        }
        Ok((entries, status)) => {
            // refuse anything that would not load before touching the alias
            let mut candidate = alias.clone();
            candidate.entries = entries.clone();
            if let Err(e) = candidate.elements() {
                let status = format!("error: refreshed list is invalid: {e}");
                record(store, name, now, false, &status, None).await?;
                return Ok(fail(status));
            }
            let changed = entries != alias.entries;
            if changed {
                write_entries(store, name, &entries, now).await?;
            }
            record(store, name, now, true, &status, Some(entries.len())).await?;
            Ok(Outcome {
                alias: name.to_string(),
                ok: true,
                status,
                count: entries.len(),
                changed: changed.then_some(candidate),
            })
        }
    }
}

/// Refresh every alias that is due (`only` = exactly those names, due or
/// not). GeoIP aliases use the downloaded database (fetched first when
/// there is none; refreshed by `refresh_geoip_db` on its own schedule).
pub async fn refresh_due(
    store: &ConfigStore,
    fetcher: &dyn Fetcher,
    only: Option<&[String]>,
    now: i64,
) -> Result<Vec<Outcome>> {
    let all = aliases::load_aliases(store).await?;
    let mut names: Vec<String> = all
        .iter()
        .filter_map(|a| a.source.as_ref().map(|s| (a, s)))
        .filter(|(a, s)| match only {
            Some(o) => o.contains(&a.name),
            None => is_due(s, now),
        })
        .map(|(a, _)| a.name.clone())
        .collect();
    names.sort();
    // the monthly database refresh also re-evaluates every GeoIP alias
    let has_geo = all
        .iter()
        .any(|a| a.source.as_ref().map(|s| s.kind.as_str()) == Some(KIND_GEOIP));
    if only.is_none() && has_geo {
        if let Ok(true) = refresh_geoip_db(store, fetcher, false, now)
            .await
            .map_err(|e| tracing::warn!("{e}"))
            .map(|r| r && load_geoip_db().is_some())
        {
            for a in &all {
                if a.source.as_ref().map(|s| s.kind.as_str()) == Some(KIND_GEOIP)
                    && !names.contains(&a.name)
                {
                    names.push(a.name.clone());
                }
            }
        }
    }
    let mut out = Vec::new();
    for n in names {
        out.push(refresh_alias(store, fetcher, &n, now).await?);
    }
    Ok(out)
}

// ---------------------------------------------------------------------
// threat-feed rules
// ---------------------------------------------------------------------

/// Chain every threat-feed rule lives in (jumped to from input, forward and
/// output right after the anti-lockout rule).
pub const THREAT_CHAIN: &str = "ti_check";

/// nft rules for every enabled threat feed (the sets come from
/// [`aliases::sets_script`]). Input, forward and output jump to
/// [`THREAT_CHAIN`], which first `return`s for members of the `ti_allow`
/// host alias (they continue through the user's rules as usual), then drops
/// each feed's addresses as the source (`in`) and/or destination (`out`)
/// of a packet, counting hits and logging them (rate limited) with the prefix
/// `patronus[ti:<feed>] drop: `.
pub fn threat_rules(all: &[Alias]) -> Vec<String> {
    let feeds: Vec<(&Alias, &AliasSource)> = all
        .iter()
        .filter_map(|a| a.source.as_ref().map(|s| (a, s)))
        .filter(|(a, s)| {
            s.kind == KIND_THREAT && s.enabled && a.kind == AliasKind::Host && !a.entries.is_empty()
        })
        .collect();
    if feeds.is_empty() {
        return Vec::new();
    }
    let c = THREAT_CHAIN;
    let mut out = vec![format!("add chain {TABLE} {c}")];
    for chain in ["input", "forward", "output"] {
        out.push(format!("add rule {TABLE} {chain} jump {c}"));
    }
    if let Some(a) = all
        .iter()
        .find(|a| a.name == THREAT_ALLOW && a.kind == AliasKind::Host)
    {
        for (fam, ver) in [("ip", IpVersion::V4), ("ip6", IpVersion::V6)] {
            let set = alias_set_name(&a.name, ver);
            for side in ["saddr", "daddr"] {
                out.push(format!(
                    "add rule {TABLE} {c} {fam} {side} @{set} return comment \"threat-intel exemption\""
                ));
            }
        }
    }
    for (a, s) in feeds {
        let id = a.name.trim_start_matches(THREAT_PREFIX);
        let mut sides: Vec<&str> = Vec::new();
        if matches!(s.direction.as_str(), "in" | "both") {
            sides.push("saddr");
        }
        if matches!(s.direction.as_str(), "out" | "both") {
            sides.push("daddr");
        }
        for (fam, ver) in [("ip", IpVersion::V4), ("ip6", IpVersion::V6)] {
            let set = alias_set_name(&a.name, ver);
            for side in &sides {
                out.push(format!(
                    "add rule {TABLE} {c} {fam} {side} @{set} limit rate 5/second burst 10 packets \
                     log prefix \"patronus[ti:{id}] drop: \" group {NFLOG_GROUP}"
                ));
                out.push(format!(
                    "add rule {TABLE} {c} {fam} {side} @{set} counter drop comment \"threat-intel {id}\""
                ));
            }
        }
    }
    out
}

/// ISO 3166-1 alpha-2 codes with English names (for the UI's pickers).
pub const COUNTRIES: &[(&str, &str)] = &[
    ("AD", "Andorra"),
    ("AE", "United Arab Emirates"),
    ("AF", "Afghanistan"),
    ("AG", "Antigua and Barbuda"),
    ("AI", "Anguilla"),
    ("AL", "Albania"),
    ("AM", "Armenia"),
    ("AO", "Angola"),
    ("AQ", "Antarctica"),
    ("AR", "Argentina"),
    ("AS", "American Samoa"),
    ("AT", "Austria"),
    ("AU", "Australia"),
    ("AW", "Aruba"),
    ("AX", "Aland Islands"),
    ("AZ", "Azerbaijan"),
    ("BA", "Bosnia and Herzegovina"),
    ("BB", "Barbados"),
    ("BD", "Bangladesh"),
    ("BE", "Belgium"),
    ("BF", "Burkina Faso"),
    ("BG", "Bulgaria"),
    ("BH", "Bahrain"),
    ("BI", "Burundi"),
    ("BJ", "Benin"),
    ("BL", "Saint Barthelemy"),
    ("BM", "Bermuda"),
    ("BN", "Brunei"),
    ("BO", "Bolivia"),
    ("BQ", "Caribbean Netherlands"),
    ("BR", "Brazil"),
    ("BS", "Bahamas"),
    ("BT", "Bhutan"),
    ("BW", "Botswana"),
    ("BY", "Belarus"),
    ("BZ", "Belize"),
    ("CA", "Canada"),
    ("CC", "Cocos Islands"),
    ("CD", "DR Congo"),
    ("CF", "Central African Republic"),
    ("CG", "Republic of the Congo"),
    ("CH", "Switzerland"),
    ("CI", "Cote d'Ivoire"),
    ("CK", "Cook Islands"),
    ("CL", "Chile"),
    ("CM", "Cameroon"),
    ("CN", "China"),
    ("CO", "Colombia"),
    ("CR", "Costa Rica"),
    ("CU", "Cuba"),
    ("CV", "Cabo Verde"),
    ("CW", "Curacao"),
    ("CX", "Christmas Island"),
    ("CY", "Cyprus"),
    ("CZ", "Czechia"),
    ("DE", "Germany"),
    ("DJ", "Djibouti"),
    ("DK", "Denmark"),
    ("DM", "Dominica"),
    ("DO", "Dominican Republic"),
    ("DZ", "Algeria"),
    ("EC", "Ecuador"),
    ("EE", "Estonia"),
    ("EG", "Egypt"),
    ("EH", "Western Sahara"),
    ("ER", "Eritrea"),
    ("ES", "Spain"),
    ("ET", "Ethiopia"),
    ("FI", "Finland"),
    ("FJ", "Fiji"),
    ("FK", "Falkland Islands"),
    ("FM", "Micronesia"),
    ("FO", "Faroe Islands"),
    ("FR", "France"),
    ("GA", "Gabon"),
    ("GB", "United Kingdom"),
    ("GD", "Grenada"),
    ("GE", "Georgia"),
    ("GF", "French Guiana"),
    ("GG", "Guernsey"),
    ("GH", "Ghana"),
    ("GI", "Gibraltar"),
    ("GL", "Greenland"),
    ("GM", "Gambia"),
    ("GN", "Guinea"),
    ("GP", "Guadeloupe"),
    ("GQ", "Equatorial Guinea"),
    ("GR", "Greece"),
    ("GT", "Guatemala"),
    ("GU", "Guam"),
    ("GW", "Guinea-Bissau"),
    ("GY", "Guyana"),
    ("HK", "Hong Kong"),
    ("HN", "Honduras"),
    ("HR", "Croatia"),
    ("HT", "Haiti"),
    ("HU", "Hungary"),
    ("ID", "Indonesia"),
    ("IE", "Ireland"),
    ("IL", "Israel"),
    ("IM", "Isle of Man"),
    ("IN", "India"),
    ("IO", "British Indian Ocean Territory"),
    ("IQ", "Iraq"),
    ("IR", "Iran"),
    ("IS", "Iceland"),
    ("IT", "Italy"),
    ("JE", "Jersey"),
    ("JM", "Jamaica"),
    ("JO", "Jordan"),
    ("JP", "Japan"),
    ("KE", "Kenya"),
    ("KG", "Kyrgyzstan"),
    ("KH", "Cambodia"),
    ("KI", "Kiribati"),
    ("KM", "Comoros"),
    ("KN", "Saint Kitts and Nevis"),
    ("KP", "North Korea"),
    ("KR", "South Korea"),
    ("KW", "Kuwait"),
    ("KY", "Cayman Islands"),
    ("KZ", "Kazakhstan"),
    ("LA", "Laos"),
    ("LB", "Lebanon"),
    ("LC", "Saint Lucia"),
    ("LI", "Liechtenstein"),
    ("LK", "Sri Lanka"),
    ("LR", "Liberia"),
    ("LS", "Lesotho"),
    ("LT", "Lithuania"),
    ("LU", "Luxembourg"),
    ("LV", "Latvia"),
    ("LY", "Libya"),
    ("MA", "Morocco"),
    ("MC", "Monaco"),
    ("MD", "Moldova"),
    ("ME", "Montenegro"),
    ("MF", "Saint Martin"),
    ("MG", "Madagascar"),
    ("MH", "Marshall Islands"),
    ("MK", "North Macedonia"),
    ("ML", "Mali"),
    ("MM", "Myanmar"),
    ("MN", "Mongolia"),
    ("MO", "Macao"),
    ("MP", "Northern Mariana Islands"),
    ("MQ", "Martinique"),
    ("MR", "Mauritania"),
    ("MS", "Montserrat"),
    ("MT", "Malta"),
    ("MU", "Mauritius"),
    ("MV", "Maldives"),
    ("MW", "Malawi"),
    ("MX", "Mexico"),
    ("MY", "Malaysia"),
    ("MZ", "Mozambique"),
    ("NA", "Namibia"),
    ("NC", "New Caledonia"),
    ("NE", "Niger"),
    ("NF", "Norfolk Island"),
    ("NG", "Nigeria"),
    ("NI", "Nicaragua"),
    ("NL", "Netherlands"),
    ("NO", "Norway"),
    ("NP", "Nepal"),
    ("NR", "Nauru"),
    ("NU", "Niue"),
    ("NZ", "New Zealand"),
    ("OM", "Oman"),
    ("PA", "Panama"),
    ("PE", "Peru"),
    ("PF", "French Polynesia"),
    ("PG", "Papua New Guinea"),
    ("PH", "Philippines"),
    ("PK", "Pakistan"),
    ("PL", "Poland"),
    ("PM", "Saint Pierre and Miquelon"),
    ("PR", "Puerto Rico"),
    ("PS", "Palestine"),
    ("PT", "Portugal"),
    ("PW", "Palau"),
    ("PY", "Paraguay"),
    ("QA", "Qatar"),
    ("RE", "Reunion"),
    ("RO", "Romania"),
    ("RS", "Serbia"),
    ("RU", "Russia"),
    ("RW", "Rwanda"),
    ("SA", "Saudi Arabia"),
    ("SB", "Solomon Islands"),
    ("SC", "Seychelles"),
    ("SD", "Sudan"),
    ("SE", "Sweden"),
    ("SG", "Singapore"),
    ("SH", "Saint Helena"),
    ("SI", "Slovenia"),
    ("SJ", "Svalbard and Jan Mayen"),
    ("SK", "Slovakia"),
    ("SL", "Sierra Leone"),
    ("SM", "San Marino"),
    ("SN", "Senegal"),
    ("SO", "Somalia"),
    ("SR", "Suriname"),
    ("SS", "South Sudan"),
    ("ST", "Sao Tome and Principe"),
    ("SV", "El Salvador"),
    ("SX", "Sint Maarten"),
    ("SY", "Syria"),
    ("SZ", "Eswatini"),
    ("TC", "Turks and Caicos Islands"),
    ("TD", "Chad"),
    ("TG", "Togo"),
    ("TH", "Thailand"),
    ("TJ", "Tajikistan"),
    ("TK", "Tokelau"),
    ("TL", "Timor-Leste"),
    ("TM", "Turkmenistan"),
    ("TN", "Tunisia"),
    ("TO", "Tonga"),
    ("TR", "Turkey"),
    ("TT", "Trinidad and Tobago"),
    ("TV", "Tuvalu"),
    ("TW", "Taiwan"),
    ("TZ", "Tanzania"),
    ("UA", "Ukraine"),
    ("UG", "Uganda"),
    ("US", "United States"),
    ("UY", "Uruguay"),
    ("UZ", "Uzbekistan"),
    ("VA", "Vatican City"),
    ("VC", "Saint Vincent and the Grenadines"),
    ("VE", "Venezuela"),
    ("VG", "British Virgin Islands"),
    ("VI", "U.S. Virgin Islands"),
    ("VN", "Vietnam"),
    ("VU", "Vanuatu"),
    ("WF", "Wallis and Futuna"),
    ("WS", "Samoa"),
    ("XK", "Kosovo"),
    ("YE", "Yemen"),
    ("YT", "Mayotte"),
    ("ZA", "South Africa"),
    ("ZM", "Zambia"),
    ("ZW", "Zimbabwe"),
];

/// Name of the nft port set of an alias (re-export for the UI layer).
pub fn port_set(alias: &str) -> String {
    alias_port_set_name(alias)
}

#[cfg(test)]
mod tests {
    use super::*;

    const DROP: &str = "; Spamhaus DROP List 2026/10/26\n\
        1.10.16.0/20 ; SBL256894\n\
        1.19.0.0/16 ; SBL434604\n\
        2.56.8.0/22 ; SBL1\n\
        garbage line here\n\
        10.0.0.0/8 ; evil private\n\
        0.0.0.0/0 ; everything\n\
        2a02:4500::/32 ; SBL2\n";

    #[test]
    fn parses_spamhaus_style_lists_and_rejects_dangerous_prefixes() {
        let p = parse_host_list(DROP);
        // /0 is refused, 10/8 parses (private space is removed for threat feeds only)
        assert_eq!(p.skipped, 2, "garbage + /0");
        assert_eq!(p.ranges.v6.len(), 1);
        let r = p.ranges.clone().without_reserved().render();
        assert_eq!(
            r,
            vec![
                "1.10.16.0/20",
                "1.19.0.0/16",
                "2.56.8.0/22",
                "2a02:4500::/32"
            ]
        );
        // a URL table keeps what it is given
        assert!(p.ranges.render().contains(&"10.0.0.0/8".to_string()));
    }

    #[test]
    fn firehol_ndjson_ranges_and_merging() {
        let t = "# firehol\n1.2.3.0/25\n1.2.3.128/25\n1.2.4.5\n1.2.4.6\n9.9.9.9-9.9.9.12\n{\"cidr\":\"5.6.0.0/16\",\"sblid\":\"SBL1\"}\n\"7.7.7.7\",x\n";
        let p = parse_host_list(t);
        assert_eq!(
            p.ranges.render(),
            vec![
                "1.2.3.0/24",
                "1.2.4.5-1.2.4.6",
                "5.6.0.0/16",
                "7.7.7.7",
                "9.9.9.9-9.9.9.12"
            ]
        );
        assert_eq!(p.skipped, 0);
    }

    #[test]
    fn reserved_space_is_cut_out_of_a_wide_range() {
        let p = parse_host_list("8.0.0.0-12.255.255.255\n172.0.0.0/8\n");
        assert_eq!(
            p.ranges.without_reserved().render(),
            vec![
                "8.0.0.0/7",
                "11.0.0.0-12.255.255.255",
                "172.0.0.0/12",
                "172.32.0.0-172.255.255.255"
            ]
        );
    }

    #[test]
    fn ports_list() {
        let p = parse_port_list("# x\n80\n443\n8000-8010\n80\n0\nnope\n");
        assert_eq!(p.ports, vec!["80", "443", "8000-8010"]);
        assert_eq!(p.skipped, 2);
    }

    #[test]
    fn geoip_db_filters_countries_and_merges() {
        let csv = "\"1.0.0.0\",\"1.0.0.255\",\"AU\"\n1.0.1.0,1.0.3.255,CN\n1.0.4.0,1.0.7.255,CN\n2.0.0.0,2.0.0.255,DE\n\
                   2001:db8::,2001:db8::ffff,CN\n3.0.0.0,3.0.0.9,ZZ\nbad,line\n";
        let db = GeoDb::parse(csv);
        assert_eq!(db.len(), 5);
        let r = db.ranges_for(&["CN".to_string()]);
        assert_eq!(r.render(), vec!["1.0.1.0-1.0.7.255", "2001:db8::/112"]);
        assert_eq!(db.lookup("2.0.0.7".parse().unwrap()).as_deref(), Some("DE"));
        assert_eq!(db.lookup("9.9.9.9".parse().unwrap()), None);
    }

    #[test]
    fn caps_keep_the_lowest_ranges() {
        let p = parse_host_list("1.0.0.0/24\n2.0.0.0/24\n3.0.0.0/24\n2001:db8::/32\n");
        let (r, t) = p.ranges.clone().capped(2);
        assert!(t);
        assert_eq!(r.render(), vec!["1.0.0.0/24", "2.0.0.0/24"]);
        let (r, t) = p.ranges.capped(10);
        assert!(!t);
        assert_eq!(r.len(), 4);
    }

    #[test]
    fn source_validation() {
        let host = |n: &str| Alias {
            name: n.into(),
            kind: AliasKind::Host,
            entries: vec![],
            description: None,
            source: None,
        };
        let src = |k: &str| AliasSource {
            kind: k.into(),
            url: Some("https://example.invalid/list.txt".into()),
            countries: vec![],
            refresh_secs: 3600,
            max_entries: 1000,
            direction: "both".into(),
            enabled: true,
            last_attempt: None,
            last_refresh: None,
            last_status: None,
            last_count: None,
        };
        assert!(check_source(&host("lst"), &src("url")).is_ok());
        assert!(
            check_source(&host("x"), &src("threat")).is_err(),
            "needs ti_ prefix"
        );
        assert!(check_source(&host("ti_x"), &src("threat")).is_ok());
        assert!(
            check_source(&host("g"), &src("geoip")).is_err(),
            "no countries"
        );
        let mut g = src("geoip");
        g.countries = vec!["de, cn".into(), "RU".into()];
        assert_eq!(
            check_source(&host("g"), &g).unwrap().countries,
            vec!["CN", "DE", "RU"]
        );
        g.countries = vec!["Germany".into()];
        assert!(check_source(&host("g"), &g).is_err());
        let mut bad = src("url");
        for u in [
            "ftp://x/y",
            "file:///etc/passwd",
            "https://x/y z",
            "https://",
            "-o/etc/x",
        ] {
            bad.url = Some(u.into());
            assert!(check_source(&host("a"), &bad).is_err(), "{u}");
        }
        let mut bad = src("url");
        bad.refresh_secs = 10;
        assert!(check_source(&host("a"), &bad).is_err());
        bad.refresh_secs = 3600;
        bad.max_entries = HARD_MAX_ENTRIES + 1;
        assert!(check_source(&host("a"), &bad).is_err());
    }

    struct MapFetch(std::sync::Mutex<HashMap<String, std::result::Result<Vec<u8>, String>>>);
    #[async_trait::async_trait]
    impl Fetcher for MapFetch {
        async fn fetch(&self, url: &str, _max: u64) -> Result<Vec<u8>> {
            match self.0.lock().unwrap().get(url) {
                Some(Ok(b)) => Ok(b.clone()),
                Some(Err(e)) => Err(Error::Config(e.clone())),
                None => Err(Error::Config(format!("404 {url}"))),
            }
        }
    }

    fn fetcher(items: &[(&str, std::result::Result<&str, &str>)]) -> MapFetch {
        MapFetch(std::sync::Mutex::new(
            items
                .iter()
                .map(|(u, r)| {
                    (
                        u.to_string(),
                        r.map(|s| s.as_bytes().to_vec()).map_err(|e| e.to_string()),
                    )
                })
                .collect(),
        ))
    }

    fn url_alias(name: &str, kind: &str, url: &str, cap: u64) -> Alias {
        Alias {
            name: name.into(),
            kind: AliasKind::Host,
            entries: vec![],
            description: None,
            source: Some(AliasSource {
                kind: kind.into(),
                url: Some(url.into()),
                countries: vec![],
                refresh_secs: 3600,
                max_entries: cap,
                direction: "both".into(),
                enabled: true,
                last_attempt: None,
                last_refresh: None,
                last_status: None,
                last_count: None,
            }),
        }
    }

    #[tokio::test]
    async fn refresh_fills_keeps_old_entries_on_failure_and_retries_early() {
        let s = ConfigStore::open_in_memory().await.unwrap();
        let u = "http://feeds.invalid/list.txt";
        aliases::save_alias(&s, &url_alias("blk", KIND_URL, u, 1000))
            .await
            .unwrap();
        let f = fetcher(&[(u, Ok("192.0.2.0/24\n198.51.100.7\n"))]);
        let o = refresh_alias(&s, &f, "blk", 1000).await.unwrap();
        assert!(o.ok && o.changed.is_some() && o.count == 2, "{o:?}");
        let a = aliases::get_alias(&s, "blk").await.unwrap().unwrap();
        assert_eq!(a.entries, vec!["192.0.2.0/24", "198.51.100.7"]);
        let src = a.source.unwrap();
        assert_eq!(src.last_count, Some(2));
        assert!(!is_due(&src, 1000 + 3599));
        assert!(is_due(&src, 1000 + 3600));
        // unchanged list: ok, nothing to swap
        let o = refresh_alias(&s, &f, "blk", 5000).await.unwrap();
        assert!(o.ok && o.changed.is_none());
        // the feed goes away: old entries stay, status says why, retry within 15 min
        let f2 = fetcher(&[(u, Err("HTTP 503"))]);
        let o = refresh_alias(&s, &f2, "blk", 9000).await.unwrap();
        assert!(!o.ok && o.status.contains("503"), "{o:?}");
        let a = aliases::get_alias(&s, "blk").await.unwrap().unwrap();
        assert_eq!(a.entries.len(), 2);
        let src = a.source.unwrap();
        assert_eq!(src.last_refresh, Some(5000));
        assert!(!is_due(&src, 9000 + 899) && is_due(&src, 9000 + 900));
        // garbage is not accepted as a list
        let f3 = fetcher(&[(u, Ok("<html>blocked</html>\n"))]);
        let o = refresh_alias(&s, &f3, "blk", 12_000).await.unwrap();
        assert!(!o.ok && o.status.contains("no addresses"), "{o:?}");
        assert_eq!(
            aliases::get_alias(&s, "blk")
                .await
                .unwrap()
                .unwrap()
                .entries
                .len(),
            2
        );
    }

    #[tokio::test]
    async fn threat_feeds_share_a_budget_and_never_cover_private_space() {
        let s = ConfigStore::open_in_memory().await.unwrap();
        let (u1, u2) = ("http://f.invalid/a", "http://f.invalid/b");
        aliases::save_alias(&s, &url_alias("ti_a", KIND_THREAT, u1, 100))
            .await
            .unwrap();
        aliases::save_alias(&s, &url_alias("ti_b", KIND_THREAT, u2, 100))
            .await
            .unwrap();
        s.save_system_config(CFG_THREAT_TOTAL, "3").await.unwrap();
        let f = fetcher(&[
            (u1, Ok("10.0.0.0/8\n203.0.113.0/24\n198.51.100.0/24\n")),
            (u2, Ok("192.0.2.1\n192.0.2.3\n192.0.2.5\n")),
        ]);
        let o = refresh_alias(&s, &f, "ti_a", 1).await.unwrap();
        assert_eq!(o.count, 2, "10/8 removed: {o:?}");
        let o = refresh_alias(&s, &f, "ti_b", 1).await.unwrap();
        assert!(
            o.ok && o.count == 1 && o.status.contains("truncated"),
            "{o:?}"
        );
        let rules = threat_rules(&aliases::load_aliases(&s).await.unwrap());
        let text = rules.join("\n");
        assert!(text.contains("add rule inet patronus ti_check ip saddr @alias_ti_a_v4 counter drop comment \"threat-intel a\""), "{text}");
        assert!(
            text.contains("ti_check ip daddr @alias_ti_b_v4 counter drop"),
            "{text}"
        );
        assert!(
            text.contains("add rule inet patronus forward jump ti_check"),
            "{text}"
        );
        assert!(text.contains("log prefix \"patronus[ti:a] drop: \" group 7"));
    }

    #[test]
    fn default_geoip_urls_use_this_and_last_month() {
        // 2026-01-15
        let u = default_geoip_urls(1_768_435_200);
        assert_eq!(
            u[0],
            "https://download.db-ip.com/free/dbip-country-lite-2026-01.csv.gz"
        );
        assert_eq!(
            u[1],
            "https://download.db-ip.com/free/dbip-country-lite-2025-12.csv.gz"
        );
    }
}
