//! Traffic insight history (device segmentation, part d).
//!
//! `/insights` used to show the flows tracked *right now* and kept no history.
//! This module adds the history: a collector polls the kernel's conntrack
//! table (per-flow byte counters, `nf_conntrack_acct` is switched on by the
//! sysctl applier), keeps the last counters of every flow and adds the
//! *delta* per `(hour bucket, internal address, direction, country, ASN)` to
//! `ins_usage`. Country and ASN come from the DB-IP lite databases
//! ([`patronus_firewall::asn::Enricher`]). Retention (default 30 days) and a
//! top-N per bucket (default 200, the rest folds into country `--`, ASN 0)
//! bound the table; addresses, devices and groups can be excluded from
//! collection (privacy).
//!
//! Rows are keyed by the internal IP, so the history works with or without the
//! device model. When the segmentation tables exist (`seg_devices`), the
//! per-device views map a device to its address(es) at query time.

use patronus_config::ConfigStore;
use patronus_firewall::asn::Enricher;
use serde::Serialize;
use serde_json::{json, Value};
use sqlx::{Row, SqlitePool};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::IpAddr;

pub const BUCKET_SECS: i64 = 3600;
pub const CFG_ENABLED: &str = "insight.enabled";
pub const CFG_RETENTION: &str = "insight.retention_days";
pub const CFG_TOP_N: &str = "insight.top_n";
pub const DEFAULT_RETENTION_DAYS: i64 = 30;
pub const DEFAULT_TOP_N: i64 = 200;
/// Seconds between conntrack polls.
pub const POLL_SECS: u64 = 15;

pub fn bucket_of(ts: i64) -> i64 {
    ts - ts.rem_euclid(BUCKET_SECS)
}

// ---------------------------------------------------------------------------
// conntrack parsing
// ---------------------------------------------------------------------------

/// One tracked flow with the counters of both directions kept apart.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirFlow {
    pub proto: String,
    pub osrc: IpAddr,
    pub odst: IpAddr,
    pub sport: u16,
    pub dport: u16,
    /// Source of the reply tuple (the real responder after DNAT).
    pub rsrc: IpAddr,
    pub obytes: u64,
    pub opackets: u64,
    pub rbytes: u64,
    pub rpackets: u64,
    pub accounted: bool,
}

pub type FlowKey = (String, IpAddr, IpAddr, u16, u16);

impl DirFlow {
    pub fn key(&self) -> FlowKey {
        (
            self.proto.clone(),
            self.osrc,
            self.odst,
            self.sport,
            self.dport,
        )
    }
}

/// Flows of `/proc/net/nf_conntrack` (or `conntrack -L -o extended`) text,
/// original and reply direction separately.
pub fn parse_dir_flows(text: &str) -> Vec<DirFlow> {
    const PROTOS: &[&str] = &[
        "tcp", "udp", "icmp", "icmpv6", "sctp", "dccp", "gre", "udplite",
    ];
    let mut out = Vec::new();
    for line in text.lines() {
        let words: Vec<&str> = line.split_whitespace().collect();
        let Some(proto) = words.iter().find(|w| PROTOS.contains(w)) else {
            continue;
        };
        let vals = |k: &str| -> Vec<&str> {
            words
                .iter()
                .filter_map(|w| w.strip_prefix(k).and_then(|v| v.strip_prefix('=')))
                .collect()
        };
        let ip = |k: &str, n: usize| vals(k).get(n).and_then(|v| v.parse::<IpAddr>().ok());
        let num = |k: &str, n: usize| {
            vals(k)
                .get(n)
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(0)
        };
        let (Some(osrc), Some(odst), Some(rsrc)) = (ip("src", 0), ip("dst", 0), ip("src", 1))
        else {
            continue;
        };
        out.push(DirFlow {
            proto: proto.to_string(),
            osrc,
            odst,
            sport: num("sport", 0) as u16,
            dport: num("dport", 0) as u16,
            rsrc,
            obytes: num("bytes", 0),
            opackets: num("packets", 0),
            rbytes: num("bytes", 1),
            rpackets: num("packets", 1),
            accounted: !vals("bytes").is_empty(),
        });
    }
    out
}

/// Addresses that belong to the inside (never a "remote" for the insight):
/// RFC 1918, loopback, link-local, IPv6 ULA / link-local.
pub fn is_internal(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => a.is_private() || a.is_loopback() || a.is_link_local(),
        IpAddr::V6(a) => {
            let s = a.segments()[0];
            a.is_loopback() || (s & 0xfe00) == 0xfc00 || (s & 0xffc0) == 0xfe80
        }
    }
}

fn not_unicast(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => a.is_multicast() || a.is_broadcast() || a.is_unspecified(),
        IpAddr::V6(a) => a.is_multicast() || a.is_unspecified(),
    }
}

/// Which side is "ours" and how many bytes went up / down.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attribution {
    pub local: IpAddr,
    pub remote: IpAddr,
    pub up_bytes: u64,
    pub up_packets: u64,
    pub down_bytes: u64,
    pub down_packets: u64,
}

/// Attribute a flow's (delta) counters to an internal address. `None` for
/// traffic between two internal addresses (the router's own UI, LAN to
/// LAN) and for multicast / broadcast.
pub fn attribute(f: &DirFlow, ob: u64, op: u64, rb: u64, rp: u64) -> Option<Attribution> {
    if is_internal(f.osrc) && is_internal(f.odst) {
        return None;
    }
    if not_unicast(f.osrc) || not_unicast(f.odst) {
        return None;
    }
    let (local, remote, up, down) = if is_internal(f.osrc) {
        // a device opened it: original direction = up
        (f.osrc, f.odst, (ob, op), (rb, rp))
    } else if is_internal(f.rsrc) {
        // inbound to an internal server (port forward / the router itself):
        // the reply tuple names the inside host, replies go "up"
        (f.rsrc, f.osrc, (rb, rp), (ob, op))
    } else {
        // public on both sides: the router's own traffic
        (f.osrc, f.odst, (ob, op), (rb, rp))
    };
    Some(Attribution {
        local,
        remote,
        up_bytes: up.0,
        up_packets: up.1,
        down_bytes: down.0,
        down_packets: down.1,
    })
}

// ---------------------------------------------------------------------------
// the collector
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Agg {
    pub bytes: u64,
    pub packets: u64,
    pub flows: u64,
}

/// `(bucket, ip, dir, country, asn)`.
pub type RowKey = (i64, String, &'static str, String, u32);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsageRow {
    pub key: RowKey,
    pub org: String,
    pub agg: Agg,
}

/// Addresses whose traffic is not recorded.
#[derive(Debug, Clone, Default)]
pub struct Exclusions {
    pub ips: HashSet<IpAddr>,
    pub nets: Vec<(IpAddr, u8)>,
}

impl Exclusions {
    pub fn matches(&self, ip: IpAddr) -> bool {
        self.ips.contains(&ip) || self.nets.iter().any(|(n, bits)| in_net(ip, *n, *bits))
    }
}

pub fn in_net(ip: IpAddr, net: IpAddr, bits: u8) -> bool {
    match (ip, net) {
        (IpAddr::V4(a), IpAddr::V4(n)) if bits <= 32 => {
            let mask = if bits == 0 {
                0
            } else {
                u32::MAX << (32 - bits)
            };
            u32::from(a) & mask == u32::from(n) & mask
        }
        (IpAddr::V6(a), IpAddr::V6(n)) if bits <= 128 => {
            let mask = if bits == 0 {
                0
            } else {
                u128::MAX << (128 - bits)
            };
            u128::from(a) & mask == u128::from(n) & mask
        }
        _ => false,
    }
}

/// `1.2.3.4`, `10.0.0.0/8`, `fd00::/8`.
pub fn parse_ip_or_net(s: &str) -> Option<(IpAddr, u8)> {
    let s = s.trim();
    match s.split_once('/') {
        Some((a, b)) => {
            let ip: IpAddr = a.parse().ok()?;
            let bits: u8 = b.parse().ok()?;
            let max = if ip.is_ipv4() { 32 } else { 128 };
            (bits <= max).then_some((ip, bits))
        }
        None => {
            let ip: IpAddr = s.parse().ok()?;
            Some((ip, if ip.is_ipv4() { 32 } else { 128 }))
        }
    }
}

pub struct Collector {
    prev: HashMap<FlowKey, (u64, u64, u64, u64)>,
    primed: bool,
    pub enrich: Enricher,
    pub exclude: Exclusions,
    /// Addresses of the router itself: its own traffic is not a device's.
    pub router_ips: HashSet<IpAddr>,
    acc: BTreeMap<RowKey, (String, Agg)>,
}

impl Collector {
    pub fn new(enrich: Enricher) -> Self {
        Self {
            prev: HashMap::new(),
            primed: false,
            enrich,
            exclude: Exclusions::default(),
            router_ips: HashSet::new(),
            acc: BTreeMap::new(),
        }
    }

    /// One look at the conntrack table at time `now`. The first look only
    /// records the baseline (the flows' earlier history is not ours to
    /// count); afterwards a flow's new bytes are its counter minus the last
    /// look, a counter that went backwards is a new flow with the same
    /// tuple (count it whole), a flow seen for the first time counts whole
    /// and adds one to the bucket's flow count.
    pub fn ingest(&mut self, flows: &[DirFlow], now: i64) {
        let bucket = bucket_of(now);
        let mut cur: HashMap<FlowKey, (u64, u64, u64, u64)> = HashMap::with_capacity(flows.len());
        for f in flows.iter().filter(|f| f.accounted) {
            let key = f.key();
            let c = (f.obytes, f.opackets, f.rbytes, f.rpackets);
            let (d, is_new) = match self.prev.get(&key) {
                Some(p) => {
                    if c.0 < p.0 || c.2 < p.2 {
                        (c, true) // counters restarted: another flow, same tuple
                    } else {
                        (
                            (
                                c.0 - p.0,
                                c.1.saturating_sub(p.1),
                                c.2 - p.2,
                                c.3.saturating_sub(p.3),
                            ),
                            false,
                        )
                    }
                }
                None => (if self.primed { c } else { (0, 0, 0, 0) }, self.primed),
            };
            cur.insert(key, c);
            if !self.primed {
                continue;
            }
            if d == (0, 0, 0, 0) && !is_new {
                continue;
            }
            // the router's own traffic (it opened the flow, or it ends at the router
            // itself) is not a device's: a port forward (orig destination = the router,
            // reply source = the LAN server) is
            if self.router_ips.contains(&f.osrc)
                || (f.rsrc == f.odst && self.router_ips.contains(&f.odst))
            {
                continue;
            }
            let Some(a) = attribute(f, d.0, d.1, d.2, d.3) else {
                continue;
            };
            if self.exclude.matches(a.local) || self.router_ips.contains(&a.local) {
                continue;
            }
            let (cc, asn, org) = self.enrich.lookup(a.remote);
            for (dir, bytes, packets) in [
                ("up", a.up_bytes, a.up_packets),
                ("down", a.down_bytes, a.down_packets),
            ] {
                let e = self
                    .acc
                    .entry((bucket, a.local.to_string(), dir, cc.clone(), asn))
                    .or_insert_with(|| (org.clone(), Agg::default()));
                e.1.bytes += bytes;
                e.1.packets += packets;
                // a flow is counted once, under "up" (one flow = one row pair)
                if is_new && dir == "up" {
                    e.1.flows += 1;
                }
            }
        }
        self.prev = cur;
        self.primed = true;
    }

    /// Everything accumulated since the last call.
    pub fn take(&mut self) -> Vec<UsageRow> {
        std::mem::take(&mut self.acc)
            .into_iter()
            .map(|(key, (org, agg))| UsageRow { key, org, agg })
            .collect()
    }

    pub fn pending(&self) -> usize {
        self.acc.len()
    }
}

// ---------------------------------------------------------------------------
// settings
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Settings {
    pub enabled: bool,
    pub retention_days: i64,
    pub top_n: i64,
}

pub async fn load_settings(store: &ConfigStore) -> Settings {
    let get = |k: &'static str| async move { store.load_system_config(k).await.ok().flatten() };
    Settings {
        enabled: get(CFG_ENABLED).await.map(|v| v != "0").unwrap_or(true),
        retention_days: get(CFG_RETENTION)
            .await
            .and_then(|v| v.parse().ok())
            .filter(|d| (1..=3650).contains(d))
            .unwrap_or(DEFAULT_RETENTION_DAYS),
        top_n: get(CFG_TOP_N)
            .await
            .and_then(|v| v.parse().ok())
            .filter(|n| (10..=100_000).contains(n))
            .unwrap_or(DEFAULT_TOP_N),
    }
}

pub async fn save_settings(
    store: &ConfigStore,
    enabled: Option<bool>,
    retention_days: Option<i64>,
    top_n: Option<i64>,
) -> anyhow::Result<()> {
    if let Some(d) = retention_days {
        if !(1..=3650).contains(&d) {
            anyhow::bail!("Invalid request: retention is 1 to 3650 days");
        }
    }
    if let Some(n) = top_n {
        if !(10..=100_000).contains(&n) {
            anyhow::bail!("Invalid request: top-N is 10 to 100000 rows per hour");
        }
    }
    let e = |x: patronus_core::Error| anyhow::anyhow!("{x}");
    if let Some(v) = enabled {
        store
            .save_system_config(CFG_ENABLED, if v { "1" } else { "0" })
            .await
            .map_err(e)?;
    }
    if let Some(v) = retention_days {
        store
            .save_system_config(CFG_RETENTION, &v.to_string())
            .await
            .map_err(e)?;
    }
    if let Some(v) = top_n {
        store
            .save_system_config(CFG_TOP_N, &v.to_string())
            .await
            .map_err(e)?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// store
// ---------------------------------------------------------------------------

fn pool(store: &ConfigStore) -> anyhow::Result<&SqlitePool> {
    store.pool().map_err(|e| anyhow::anyhow!("{e}"))
}

/// Add `rows` to the hourly buckets.
pub async fn flush(store: &ConfigStore, rows: &[UsageRow]) -> anyhow::Result<()> {
    if rows.is_empty() {
        return Ok(());
    }
    let mut tx = pool(store)?.begin().await?;
    for r in rows {
        sqlx::query(
            "INSERT INTO ins_usage (bucket, ip, dir, country, asn, asn_org, bytes, packets, flows) \
             VALUES (?,?,?,?,?,?,?,?,?) \
             ON CONFLICT(bucket, ip, dir, country, asn) DO UPDATE SET \
               bytes = bytes + excluded.bytes, packets = packets + excluded.packets, \
               flows = flows + excluded.flows, \
               asn_org = CASE WHEN excluded.asn_org <> '' THEN excluded.asn_org ELSE asn_org END",
        )
        .bind(r.key.0)
        .bind(&r.key.1)
        .bind(r.key.2)
        .bind(&r.key.3)
        .bind(r.key.4 as i64)
        .bind(&r.org)
        .bind(r.agg.bytes as i64)
        .bind(r.agg.packets as i64)
        .bind(r.agg.flows as i64)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(())
}

/// Keep the `top_n` biggest rows of a bucket; fold the others into
/// `(country '--', asn 0)` of the same address and direction, so device
/// totals stay right.
pub async fn fold_bucket(store: &ConfigStore, bucket: i64, top_n: i64) -> anyhow::Result<u64> {
    let p = pool(store)?;
    let n: i64 = sqlx::query("SELECT COUNT(*) FROM ins_usage WHERE bucket = ?")
        .bind(bucket)
        .fetch_one(p)
        .await?
        .get(0);
    if n <= top_n {
        return Ok(0);
    }
    let rows = sqlx::query(
        "SELECT ip, dir, country, asn, bytes, packets, flows FROM ins_usage WHERE bucket = ? \
         ORDER BY bytes DESC, ip, dir, country, asn LIMIT -1 OFFSET ?",
    )
    .bind(bucket)
    .bind(top_n)
    .fetch_all(p)
    .await?;
    let mut tx = p.begin().await?;
    let mut folded = 0;
    for r in rows {
        let (ip, dir, cc, asn): (String, String, String, i64) =
            (r.get(0), r.get(1), r.get(2), r.get(3));
        if cc == "--" && asn == 0 {
            continue; // already the fold row
        }
        let (b, pk, fl): (i64, i64, i64) = (r.get(4), r.get(5), r.get(6));
        sqlx::query(
            "DELETE FROM ins_usage WHERE bucket=? AND ip=? AND dir=? AND country=? AND asn=?",
        )
        .bind(bucket)
        .bind(&ip)
        .bind(&dir)
        .bind(&cc)
        .bind(asn)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "INSERT INTO ins_usage (bucket, ip, dir, country, asn, asn_org, bytes, packets, flows) \
             VALUES (?,?,?,'--',0,'',?,?,?) \
             ON CONFLICT(bucket, ip, dir, country, asn) DO UPDATE SET \
               bytes = bytes + excluded.bytes, packets = packets + excluded.packets, flows = flows + excluded.flows",
        )
        .bind(bucket).bind(&ip).bind(&dir).bind(b).bind(pk).bind(fl)
        .execute(&mut *tx).await?;
        folded += 1;
    }
    tx.commit().await?;
    Ok(folded)
}

/// Delete buckets older than the retention. Returns the rows removed.
pub async fn prune(store: &ConfigStore, now: i64, retention_days: i64) -> anyhow::Result<u64> {
    let cutoff = bucket_of(now) - retention_days * 86_400;
    Ok(sqlx::query("DELETE FROM ins_usage WHERE bucket < ?")
        .bind(cutoff)
        .execute(pool(store)?)
        .await?
        .rows_affected())
}

/// Remove the rows of addresses that were just excluded from collection.
pub async fn forget_ip(store: &ConfigStore, ip: &str) -> anyhow::Result<u64> {
    Ok(sqlx::query("DELETE FROM ins_usage WHERE ip = ?")
        .bind(ip)
        .execute(pool(store)?)
        .await?
        .rows_affected())
}

// ---------------------------------------------------------------------------
// device directory (needs the segmentation tables; empty without them)
// ---------------------------------------------------------------------------

async fn table_columns(p: &SqlitePool, table: &str) -> Vec<String> {
    sqlx::query(&format!("PRAGMA table_info({table})"))
        .fetch_all(p)
        .await
        .map(|r| r.into_iter().map(|x| x.get::<String, _>(1)).collect())
        .unwrap_or_default()
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct DeviceRef {
    pub id: i64,
    pub name: String,
    pub ips: Vec<String>,
    pub group: Option<String>,
}

/// Devices of the segmentation model with their addresses. Empty when the
/// model is absent (segmentation not built / not migrated).
pub async fn devices(store: &ConfigStore) -> Vec<DeviceRef> {
    let Ok(p) = pool(store) else { return vec![] };
    let cols = table_columns(p, "seg_devices").await;
    if !cols.iter().any(|c| c == "name") || !cols.iter().any(|c| c == "id") {
        return vec![];
    }
    let has = |c: &str| cols.iter().any(|x| x == c);
    let sel = format!(
        "SELECT d.id, d.name, {}, {}, {} FROM seg_devices d {} ORDER BY d.id",
        if has("ip4") { "d.ip4" } else { "NULL" },
        if has("last_ip") { "d.last_ip" } else { "NULL" },
        if has("group_id") {
            "(SELECT g.name FROM seg_groups g WHERE g.id = d.group_id)"
        } else {
            "NULL"
        },
        if has("state") {
            "WHERE d.state <> 'revoked'"
        } else {
            ""
        },
    );
    let rows = sqlx::query(&sel).fetch_all(p).await.unwrap_or_default();
    rows.into_iter()
        .map(|r| {
            let mut ips: Vec<String> =
                [r.get::<Option<String>, _>(2), r.get::<Option<String>, _>(3)]
                    .into_iter()
                    .flatten()
                    .filter(|s| !s.is_empty())
                    .collect();
            ips.sort();
            ips.dedup();
            DeviceRef {
                id: r.get(0),
                name: r.get(1),
                ips,
                group: r.get(4),
            }
        })
        .collect()
}

/// Exclusions from the store: addresses/CIDRs plus the addresses of named
/// devices and of every device in a named group.
pub async fn load_exclusions(store: &ConfigStore) -> Exclusions {
    let mut ex = Exclusions::default();
    let Ok(p) = pool(store) else { return ex };
    let rows = sqlx::query("SELECT kind, ref FROM ins_exclude")
        .fetch_all(p)
        .await
        .unwrap_or_default();
    let devs = if rows.iter().any(|r| r.get::<String, _>(0) != "ip") {
        devices(store).await
    } else {
        vec![]
    };
    let add = |s: &str, ex: &mut Exclusions| {
        if let Some((ip, bits)) = parse_ip_or_net(s) {
            if (ip.is_ipv4() && bits == 32) || (ip.is_ipv6() && bits == 128) {
                ex.ips.insert(ip);
            } else {
                ex.nets.push((ip, bits));
            }
        }
    };
    for r in rows {
        let (kind, rf): (String, String) = (r.get(0), r.get(1));
        match kind.as_str() {
            "ip" => add(&rf, &mut ex),
            "device" => {
                for d in devs.iter().filter(|d| d.name == rf) {
                    d.ips.iter().for_each(|i| add(i, &mut ex));
                }
            }
            "group" => {
                for d in devs
                    .iter()
                    .filter(|d| d.group.as_deref() == Some(rf.as_str()))
                {
                    d.ips.iter().for_each(|i| add(i, &mut ex));
                }
            }
            _ => {}
        }
    }
    ex
}

pub async fn list_exclusions(store: &ConfigStore) -> anyhow::Result<Vec<(String, String)>> {
    Ok(
        sqlx::query("SELECT kind, ref FROM ins_exclude ORDER BY kind, ref")
            .fetch_all(pool(store)?)
            .await?
            .into_iter()
            .map(|r| (r.get(0), r.get(1)))
            .collect(),
    )
}

/// Add an exclusion (`kind` = ip | group | device) and delete what was
/// already recorded for it. Returns the rows removed.
pub async fn add_exclusion(store: &ConfigStore, kind: &str, rf: &str) -> anyhow::Result<u64> {
    let rf = rf.trim();
    match kind {
        "ip" => {
            if parse_ip_or_net(rf).is_none() {
                anyhow::bail!("Invalid request: {rf:?} is not an IP address or CIDR");
            }
        }
        "device" | "group" => {
            if rf.is_empty() || rf.len() > 64 {
                anyhow::bail!("Invalid request: give the {kind} name");
            }
            let known = devices(store).await;
            let ok = if kind == "device" {
                known.iter().any(|d| d.name == rf)
            } else {
                known.iter().any(|d| d.group.as_deref() == Some(rf))
            };
            if !ok {
                anyhow::bail!("Invalid request: no such {kind} {rf:?} (device segmentation must define it first)");
            }
        }
        _ => anyhow::bail!("Invalid request: kind is ip, device or group"),
    }
    sqlx::query("INSERT OR IGNORE INTO ins_exclude (kind, ref) VALUES (?,?)")
        .bind(kind)
        .bind(rf)
        .execute(pool(store)?)
        .await?;
    // forget what was recorded
    let ex = load_exclusions(store).await;
    let p = pool(store)?;
    let ips: Vec<String> = sqlx::query("SELECT DISTINCT ip FROM ins_usage")
        .fetch_all(p)
        .await?
        .into_iter()
        .map(|r| r.get(0))
        .collect();
    let mut removed = 0;
    for s in ips {
        if s.parse::<IpAddr>().map(|i| ex.matches(i)).unwrap_or(false) {
            removed += forget_ip(store, &s).await?;
        }
    }
    Ok(removed)
}

pub async fn remove_exclusion(store: &ConfigStore, kind: &str, rf: &str) -> anyhow::Result<bool> {
    Ok(
        sqlx::query("DELETE FROM ins_exclude WHERE kind=? AND ref=?")
            .bind(kind)
            .bind(rf)
            .execute(pool(store)?)
            .await?
            .rows_affected()
            > 0,
    )
}

// ---------------------------------------------------------------------------
// queries
// ---------------------------------------------------------------------------

/// `1h`, `6h`, `24h`, `7d`, `30d` ... in seconds (1 hour to 3650 days).
pub fn parse_window(s: &str) -> Option<i64> {
    let s = s.trim();
    let (n, unit) = s.split_at(s.len().checked_sub(1)?);
    let n: i64 = n.parse().ok()?;
    let secs = match unit {
        "h" => n.checked_mul(3600)?,
        "d" => n.checked_mul(86_400)?,
        _ => return None,
    };
    (3600..=3650 * 86_400).contains(&secs).then_some(secs)
}

/// The addresses a `device` selector stands for: an IP address (as is), or a
/// segmentation device id / name. `Err` when it names nothing.
pub async fn resolve_device(
    store: &ConfigStore,
    sel: &str,
) -> anyhow::Result<(Vec<String>, Option<DeviceRef>)> {
    let sel = sel.trim();
    if let Ok(ip) = sel.parse::<IpAddr>() {
        return Ok((vec![ip.to_string()], None));
    }
    let id = sel.parse::<i64>().ok();
    let d = devices(store)
        .await
        .into_iter()
        .find(|d| Some(d.id) == id || d.name == sel);
    match d {
        Some(d) => Ok((d.ips.clone(), Some(d))),
        None => anyhow::bail!("not found: no device {sel:?} (give an IP address, or a device id or name of device segmentation)"),
    }
}

fn in_clause(n: usize) -> String {
    format!("({})", vec!["?"; n].join(","))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum By {
    Country,
    Asn,
}

/// Top countries or ASNs over `window_secs` ending at `now`, optionally for
/// the given addresses only.
pub async fn top(
    store: &ConfigStore,
    by: By,
    now: i64,
    window_secs: i64,
    ips: Option<&[String]>,
    limit: i64,
) -> anyhow::Result<Vec<Value>> {
    if matches!(ips, Some(i) if i.is_empty()) {
        return Ok(vec![]);
    }
    let (sel, grp) = match by {
        By::Country => ("country, 0, ''", "country"),
        By::Asn => ("country, asn, MAX(asn_org)", "asn"),
    };
    let mut sql = format!(
        "SELECT {sel}, SUM(CASE WHEN dir='up' THEN bytes ELSE 0 END), \
                SUM(CASE WHEN dir='down' THEN bytes ELSE 0 END), SUM(packets), SUM(flows) \
         FROM ins_usage WHERE bucket >= ? AND bucket <= ?"
    );
    if let Some(i) = ips {
        sql += &format!(" AND ip IN {}", in_clause(i.len()));
    }
    sql += &format!(" GROUP BY {grp} ORDER BY SUM(bytes) DESC, {grp} LIMIT ?");
    let mut q = sqlx::query(&sql)
        .bind(bucket_of(now - window_secs))
        .bind(bucket_of(now));
    for i in ips.unwrap_or(&[]) {
        q = q.bind(i);
    }
    let rows = q.bind(limit).fetch_all(pool(store)?).await?;
    Ok(rows
        .into_iter()
        .map(|r| {
            let (up, down): (i64, i64) = (r.get(3), r.get(4));
            let base = match by {
                By::Country => json!({"country": r.get::<String, _>(0)}),
                By::Asn => json!({"asn": r.get::<i64, _>(1), "org": r.get::<String, _>(2), "country": r.get::<String, _>(0)}),
            };
            let mut v = base;
            v["up_bytes"] = json!(up);
            v["down_bytes"] = json!(down);
            v["bytes"] = json!(up + down);
            v["packets"] = json!(r.get::<i64, _>(5));
            v["flows"] = json!(r.get::<i64, _>(6));
            v
        })
        .collect())
}

/// Hourly bytes up/down over the window (zero-filled), optionally for
/// the given addresses only.
pub async fn timeline(
    store: &ConfigStore,
    now: i64,
    window_secs: i64,
    ips: Option<&[String]>,
) -> anyhow::Result<Vec<Value>> {
    let (from, to) = (bucket_of(now - window_secs), bucket_of(now));
    let mut by_bucket: BTreeMap<i64, (i64, i64)> = BTreeMap::new();
    if !matches!(ips, Some(i) if i.is_empty()) {
        let mut sql = "SELECT bucket, SUM(CASE WHEN dir='up' THEN bytes ELSE 0 END), \
                       SUM(CASE WHEN dir='down' THEN bytes ELSE 0 END) FROM ins_usage \
                       WHERE bucket >= ? AND bucket <= ?"
            .to_string();
        if let Some(i) = ips {
            sql += &format!(" AND ip IN {}", in_clause(i.len()));
        }
        sql += " GROUP BY bucket";
        let mut q = sqlx::query(&sql).bind(from).bind(to);
        for i in ips.unwrap_or(&[]) {
            q = q.bind(i);
        }
        for r in q.fetch_all(pool(store)?).await? {
            by_bucket.insert(r.get(0), (r.get(1), r.get(2)));
        }
    }
    let mut out = vec![];
    let mut b = from;
    while b <= to {
        let (up, down) = by_bucket.get(&b).copied().unwrap_or((0, 0));
        out.push(json!({"bucket": b, "up_bytes": up, "down_bytes": down}));
        b += BUCKET_SECS;
    }
    Ok(out)
}

/// Per internal address (joined with its device when the model exists):
/// bytes up/down, flows and the top country.
pub async fn device_totals(
    store: &ConfigStore,
    now: i64,
    window_secs: i64,
    limit: i64,
) -> anyhow::Result<Vec<Value>> {
    let rows = sqlx::query(
        "SELECT ip, SUM(CASE WHEN dir='up' THEN bytes ELSE 0 END), \
                SUM(CASE WHEN dir='down' THEN bytes ELSE 0 END), SUM(flows) \
         FROM ins_usage WHERE bucket >= ? AND bucket <= ? GROUP BY ip \
         ORDER BY SUM(bytes) DESC, ip LIMIT ?",
    )
    .bind(bucket_of(now - window_secs))
    .bind(bucket_of(now))
    .bind(limit)
    .fetch_all(pool(store)?)
    .await?;
    let devs = devices(store).await;
    let mut out = vec![];
    for r in rows {
        let ip: String = r.get(0);
        let (up, down): (i64, i64) = (r.get(1), r.get(2));
        let d = devs.iter().find(|d| d.ips.contains(&ip));
        let top_cc = top(
            store,
            By::Country,
            now,
            window_secs,
            Some(std::slice::from_ref(&ip)),
            1,
        )
        .await?;
        out.push(json!({
            "ip": ip,
            "device_id": d.map(|d| d.id),
            "device": d.map(|d| d.name.clone()),
            "group": d.and_then(|d| d.group.clone()),
            "up_bytes": up, "down_bytes": down, "bytes": up + down,
            "flows": r.get::<i64, _>(3),
            "top_country": top_cc.first().map(|c| c["country"].clone()),
        }));
    }
    Ok(out)
}

pub async fn row_count(store: &ConfigStore) -> i64 {
    match pool(store) {
        Ok(p) => sqlx::query("SELECT COUNT(*) FROM ins_usage")
            .fetch_one(p)
            .await
            .map(|r| r.get(0))
            .unwrap_or(0),
        Err(_) => 0,
    }
}

// ---------------------------------------------------------------------------
// the background task
// ---------------------------------------------------------------------------

fn read_conntrack_text() -> Option<String> {
    if let Ok(t) = std::fs::read_to_string("/proc/net/nf_conntrack") {
        return Some(t);
    }
    let o = std::process::Command::new("conntrack")
        .args(["-L", "-o", "extended"])
        .output()
        .ok()?;
    o.status
        .success()
        .then(|| String::from_utf8_lossy(&o.stdout).into_owned())
}

/// The addresses configured on this host's interfaces (`ip -o addr`).
pub fn local_addresses() -> HashSet<IpAddr> {
    let Ok(o) = std::process::Command::new("ip")
        .args(["-o", "addr", "show"])
        .output()
    else {
        return HashSet::new();
    };
    parse_ip_o_addr(&String::from_utf8_lossy(&o.stdout))
}

/// Addresses of `ip -o addr show` text (`2: eth0    inet 10.0.0.1/24 brd ...`).
pub fn parse_ip_o_addr(text: &str) -> HashSet<IpAddr> {
    text.lines()
        .filter_map(|l| {
            let mut w = l.split_whitespace();
            w.find(|x| *x == "inet" || *x == "inet6")?;
            w.next()?.split('/').next()?.parse().ok()
        })
        .collect()
}

/// One collector round (also used by tests): read conntrack, ingest, and every
/// `flush_every`-th round write the buckets, fold and prune.
pub async fn tick(
    c: &mut Collector,
    store: &ConfigStore,
    now: i64,
    text: Option<&str>,
    flush_now: bool,
) -> anyhow::Result<()> {
    let settings = load_settings(store).await;
    if !settings.enabled {
        c.take();
        c.prev.clear();
        c.primed = false;
        return Ok(());
    }
    c.enrich.reload_if_changed();
    c.exclude = load_exclusions(store).await;
    if flush_now || c.router_ips.is_empty() {
        c.router_ips = tokio::task::spawn_blocking(local_addresses)
            .await
            .unwrap_or_default();
    }
    if let Some(t) = text {
        c.ingest(&parse_dir_flows(t), now);
    }
    if flush_now {
        let rows = c.take();
        flush(store, &rows).await?;
        fold_bucket(store, bucket_of(now), settings.top_n).await?;
        prune(store, now, settings.retention_days).await?;
    }
    Ok(())
}

/// Start the collector: a conntrack look every [`POLL_SECS`], a database
/// write every minute. `PATRONUS_INSIGHT_TICK_SECS` / `PATRONUS_INSIGHT_FLUSH_SECS`
/// override the intervals (tests).
pub fn spawn_collector(store: std::sync::Arc<ConfigStore>) {
    let secs = std::env::var("PATRONUS_INSIGHT_TICK_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .filter(|s| *s > 0)
        .unwrap_or(POLL_SECS);
    let flush_secs = std::env::var("PATRONUS_INSIGHT_FLUSH_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .filter(|s| *s > 0)
        .unwrap_or(60);
    let per_flush = (flush_secs / secs).max(1);
    tokio::spawn(async move {
        let enrich = tokio::task::spawn_blocking(Enricher::load)
            .await
            .unwrap_or_default();
        let mut c = Collector::new(enrich);
        let mut t = tokio::time::interval(std::time::Duration::from_secs(secs));
        t.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut n: u64 = 0;
        loop {
            t.tick().await;
            n += 1;
            let text = tokio::task::spawn_blocking(read_conntrack_text)
                .await
                .ok()
                .flatten();
            let now = chrono::Utc::now().timestamp();
            if let Err(e) = tick(
                &mut c,
                &store,
                now,
                text.as_deref(),
                n.is_multiple_of(per_flush),
            )
            .await
            {
                tracing::warn!("insight collector: {e}");
            }
        }
    });
}

/// Keep the DB-IP country and ASN files fresh: look every hour, download
/// when older than `refresh_days` (30; DB-IP publishes monthly). The monthly
/// `patronus ipdb update` job does the same for installs where the web
/// service is not running. `PATRONUS_IPDB_REFRESH=0` turns this off (tests
/// that must not reach the internet).
pub fn spawn_db_refresh(store: std::sync::Arc<ConfigStore>) {
    if std::env::var("PATRONUS_IPDB_REFRESH").is_ok_and(|v| v == "0") {
        return;
    }
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_secs(90)).await;
        let mut t = tokio::time::interval(std::time::Duration::from_secs(3600));
        t.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            t.tick().await;
            if !load_settings(&store).await.enabled {
                continue;
            }
            let now = chrono::Utc::now().timestamp();
            for (name, r) in patronus_firewall::asn::refresh_ip_databases(
                &store,
                &patronus_firewall::feeds::CurlFetcher,
                false,
                now,
            )
            .await
            {
                match r {
                    Ok(true) => tracing::info!("IP database {name}: updated"),
                    Ok(false) => {}
                    Err(e) => tracing::warn!("IP database {name}: {e}"),
                }
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use patronus_firewall::feeds::GeoDb;

    fn line(proto: &str, src: &str, dst: &str, dport: u16, ob: u64, rb: u64) -> String {
        format!(
            "ipv4     2 {proto}      6 100 ESTABLISHED src={src} dst={dst} sport=40000 dport={dport} packets=10 bytes={ob} src={dst} dst=203.0.113.2 sport={dport} dport=40000 packets=8 bytes={rb} [ASSURED] mark=0 use=1"
        )
    }

    fn enricher() -> Enricher {
        Enricher::new(
            Some(GeoDb::parse("198.51.100.0,198.51.100.255,AU\n192.0.2.0,192.0.2.255,DE\n")),
            Some(patronus_firewall::asn::AsnDb::parse(
                "198.51.100.0,198.51.100.255,64500,\"Example AU\"\n192.0.2.0,192.0.2.255,64501,\"Example DE\"\n",
            )),
        )
    }

    #[test]
    fn parse_keeps_both_directions_apart() {
        let f = parse_dir_flows(&line(
            "tcp",
            "192.168.50.10",
            "198.51.100.10",
            80,
            5000,
            95000,
        ));
        assert_eq!(f.len(), 1);
        assert_eq!(
            (f[0].obytes, f[0].rbytes, f[0].opackets, f[0].rpackets),
            (5000, 95000, 10, 8)
        );
        assert_eq!(f[0].dport, 80);
        assert_eq!(f[0].rsrc.to_string(), "198.51.100.10");
        assert!(f[0].accounted);
        let unacc = parse_dir_flows("ipv4 2 tcp 6 100 ESTABLISHED src=10.0.0.1 dst=8.8.8.8 sport=1 dport=22 src=8.8.8.8 dst=10.0.0.1 sport=22 dport=1 mark=0 use=1");
        assert!(!unacc[0].accounted);
        let v6 = parse_dir_flows("ipv6 10 tcp 6 100 ESTABLISHED src=fd00::10 dst=2001:db8::1 sport=1 dport=443 packets=3 bytes=300 src=2001:db8::1 dst=fd00::10 sport=443 dport=1 packets=2 bytes=900 use=1");
        assert_eq!(v6.len(), 1);
        assert_eq!(v6[0].rbytes, 900);
        assert!(parse_dir_flows("garbage\n\nnothing here").is_empty());
    }

    #[test]
    fn internal_addresses_and_attribution() {
        for s in [
            "10.1.2.3",
            "172.16.0.1",
            "192.168.1.1",
            "127.0.0.1",
            "169.254.1.1",
            "fd00::1",
            "fe80::1",
            "::1",
        ] {
            assert!(is_internal(s.parse().unwrap()), "{s}");
        }
        for s in [
            "8.8.8.8",
            "172.32.0.1",
            "100.64.0.1",
            "2001:db8::1",
            "fe00::1",
        ] {
            assert!(!is_internal(s.parse().unwrap()), "{s}");
        }
        let out = &parse_dir_flows(&line(
            "tcp",
            "192.168.50.10",
            "198.51.100.10",
            80,
            5000,
            95000,
        ))[0];
        let a = attribute(out, 5000, 10, 95000, 8).unwrap();
        assert_eq!(
            (a.local.to_string(), a.remote.to_string()),
            ("192.168.50.10".into(), "198.51.100.10".into())
        );
        assert_eq!(
            (a.up_bytes, a.down_bytes, a.up_packets, a.down_packets),
            (5000, 95000, 10, 8)
        );
        // inbound port forward: orig src public, dst the router's WAN address, reply src the LAN server
        let inb = parse_dir_flows("ipv4 2 tcp 6 100 ESTABLISHED src=198.51.100.7 dst=203.0.113.2 sport=5555 dport=443 packets=4 bytes=400 src=192.168.50.20 dst=198.51.100.7 sport=443 dport=5555 packets=3 bytes=3000 use=1");
        let a = attribute(&inb[0], 400, 4, 3000, 3).unwrap();
        assert_eq!(
            (a.local.to_string(), a.remote.to_string()),
            ("192.168.50.20".into(), "198.51.100.7".into())
        );
        assert_eq!(
            (a.up_bytes, a.down_bytes),
            (3000, 400),
            "the server's replies are its upload"
        );
        // LAN to LAN and multicast are not internet traffic
        let lan = parse_dir_flows(&line("tcp", "192.168.50.10", "192.168.50.1", 8443, 10, 10));
        assert!(attribute(&lan[0], 10, 1, 10, 1).is_none());
        let mc = parse_dir_flows("ipv4 2 udp 17 20 src=192.168.50.10 dst=239.255.255.250 sport=1900 dport=1900 packets=2 bytes=400 [UNREPLIED] src=239.255.255.250 dst=192.168.50.10 sport=1900 dport=1900 packets=0 bytes=0 use=1");
        assert!(attribute(&mc[0], 400, 2, 0, 0).is_none());
        // router's own traffic (public on both sides) is attributed to the initiator
        let own = parse_dir_flows(&line("udp", "203.0.113.2", "198.51.100.53", 53, 70, 120));
        let a = attribute(&own[0], 70, 1, 120, 1).unwrap();
        assert_eq!(a.local.to_string(), "203.0.113.2");
    }

    #[test]
    fn collector_counts_deltas_not_totals() {
        let mut c = Collector::new(enricher());
        let t0 = 1_800_000_000;
        // first look: a long-lived flow with history; baseline only
        c.ingest(
            &parse_dir_flows(&line(
                "tcp",
                "192.168.50.10",
                "198.51.100.10",
                443,
                1_000_000,
                9_000_000,
            )),
            t0,
        );
        assert!(
            c.take().is_empty(),
            "history before we looked is not counted"
        );
        // second look: +500 up, +4000 down
        c.ingest(
            &parse_dir_flows(&line(
                "tcp",
                "192.168.50.10",
                "198.51.100.10",
                443,
                1_000_500,
                9_004_000,
            )),
            t0 + 15,
        );
        let rows = c.take();
        let up = rows.iter().find(|r| r.key.2 == "up").unwrap();
        let down = rows.iter().find(|r| r.key.2 == "down").unwrap();
        assert_eq!((up.agg.bytes, down.agg.bytes), (500, 4000));
        assert_eq!(
            (up.key.3.as_str(), up.key.4, up.org.as_str()),
            ("AU", 64500, "Example AU")
        );
        assert_eq!(up.agg.flows, 0, "not a new flow");
        // nothing moved: no rows
        c.ingest(
            &parse_dir_flows(&line(
                "tcp",
                "192.168.50.10",
                "198.51.100.10",
                443,
                1_000_500,
                9_004_000,
            )),
            t0 + 30,
        );
        assert!(c.take().is_empty());
        // counter reset (same tuple, new flow): counted whole, one new flow
        c.ingest(
            &parse_dir_flows(&line(
                "tcp",
                "192.168.50.10",
                "198.51.100.10",
                443,
                100,
                200,
            )),
            t0 + 45,
        );
        let rows = c.take();
        assert_eq!(rows.iter().map(|r| r.agg.bytes).sum::<u64>(), 300);
        assert_eq!(rows.iter().map(|r| r.agg.flows).sum::<u64>(), 1);
    }

    #[test]
    fn new_flows_flow_expiry_and_several_remotes() {
        let mut c = Collector::new(enricher());
        let t0 = 1_800_000_000;
        c.ingest(&[], t0); // primed, nothing there
        let text = format!(
            "{}\n{}\n",
            line("tcp", "192.168.50.10", "198.51.100.10", 443, 1000, 2000),
            line("tcp", "192.168.50.20", "192.0.2.9", 80, 10, 30)
        );
        c.ingest(&parse_dir_flows(&text), t0 + 15);
        let rows = c.take();
        assert_eq!(rows.len(), 4, "2 devices x up/down");
        let find = |ip: &str, dir: &str| {
            rows.iter()
                .find(|r| r.key.1 == ip && r.key.2 == dir)
                .unwrap()
        };
        assert_eq!(find("192.168.50.10", "down").agg.bytes, 2000);
        assert_eq!(find("192.168.50.10", "up").agg.flows, 1);
        assert_eq!(find("192.168.50.20", "up").key.3, "DE");
        // the flow expires, a new one on the same tuple later starts from zero
        c.ingest(&[], t0 + 30);
        c.ingest(
            &parse_dir_flows(&line("tcp", "192.168.50.10", "198.51.100.10", 443, 50, 60)),
            t0 + 45,
        );
        let rows = c.take();
        assert_eq!(
            rows.iter().map(|r| r.agg.bytes).sum::<u64>(),
            110,
            "an expired flow's tuple does not subtract"
        );
        // unknown remote -> country --, asn 0
        c.ingest(
            &parse_dir_flows(&line("udp", "192.168.50.10", "9.9.9.9", 53, 70, 120)),
            t0 + 60,
        );
        let r = c.take();
        assert!(r.iter().all(|r| r.key.3 == "--" && r.key.4 == 0));
    }

    #[test]
    fn exclusions_by_ip_and_cidr_and_flows_without_counters() {
        let mut c = Collector::new(enricher());
        c.exclude.ips.insert("192.168.50.10".parse().unwrap());
        c.exclude.nets.push(("192.168.60.0".parse().unwrap(), 24));
        let t0 = 1_800_000_000;
        c.ingest(&[], t0);
        let text = format!(
            "{}\n{}\n{}\n",
            line("tcp", "192.168.50.10", "198.51.100.10", 443, 1000, 2000),
            line("tcp", "192.168.60.77", "198.51.100.10", 443, 1000, 2000),
            line("tcp", "192.168.50.11", "198.51.100.10", 443, 1000, 2000)
        );
        c.ingest(&parse_dir_flows(&text), t0 + 15);
        let rows = c.take();
        assert!(rows.iter().all(|r| r.key.1 == "192.168.50.11"), "{rows:?}");
        let mut c2 = Collector::new(enricher());
        c2.ingest(&[], t0);
        c2.ingest(&parse_dir_flows("ipv4 2 tcp 6 100 ESTABLISHED src=192.168.50.10 dst=8.8.8.8 sport=1 dport=22 src=8.8.8.8 dst=192.168.50.10 sport=22 dport=1 mark=0 use=1"), t0 + 15);
        assert!(c2.take().is_empty(), "no byte counters = nothing to count");
    }

    #[test]
    fn the_routers_own_traffic_is_not_a_devices() {
        let mut c = Collector::new(enricher());
        c.router_ips = parse_ip_o_addr(
            "1: lo    inet 127.0.0.1/8 scope host lo\n2: wan    inet 203.0.113.2/24 brd 203.0.113.255 scope global wan\n3: lan    inet 192.168.50.1/24 scope global lan\n3: lan    inet6 fd00::1/64 scope global\n",
        );
        assert_eq!(c.router_ips.len(), 4);
        let t0 = 1_800_000_000;
        c.ingest(&[], t0);
        let text = format!(
            "{}\n{}\n",
            line("udp", "203.0.113.2", "198.51.100.53", 53, 70, 120),
            line("tcp", "192.168.50.10", "198.51.100.10", 443, 1000, 2000)
        );
        c.ingest(&parse_dir_flows(&text), t0 + 15);
        let rows = c.take();
        assert!(rows.iter().all(|r| r.key.1 == "192.168.50.10"), "{rows:?}");
        assert_eq!(rows.len(), 2);
        assert!(parse_ip_o_addr("garbage\n\n").is_empty());
        // the router asking a resolver on a private address is not that resolver's traffic
        let mut c = Collector::new(enricher());
        c.router_ips = parse_ip_o_addr("2: wan    inet 203.0.113.2/24 scope global wan\n");
        c.ingest(&[], t0);
        let resolver = line("udp", "203.0.113.2", "10.1.10.97", 53, 70, 120);
        let to_router = "ipv4 2 tcp 6 100 ESTABLISHED src=198.51.100.7 dst=203.0.113.2 sport=5555 dport=22 packets=4 bytes=400 src=203.0.113.2 dst=198.51.100.7 sport=22 dport=5555 packets=3 bytes=300 use=1";
        // a port forward: orig destination is the router's WAN address, the reply comes from the LAN server
        let forward = "ipv4 2 tcp 6 100 ESTABLISHED src=198.51.100.7 dst=203.0.113.2 sport=5556 dport=443 packets=4 bytes=400 src=192.168.50.20 dst=198.51.100.7 sport=443 dport=5556 packets=3 bytes=3000 use=1";
        c.ingest(
            &parse_dir_flows(&format!("{resolver}\n{to_router}\n{forward}\n")),
            t0 + 15,
        );
        let rows = c.take();
        assert!(
            rows.iter().all(|r| r.key.1 == "192.168.50.20"),
            "only the port-forwarded server is a device here: {rows:?}"
        );
        assert_eq!(
            rows.iter().find(|r| r.key.2 == "up").unwrap().agg.bytes,
            3000,
            "the server's replies are its upload"
        );
    }

    #[test]
    fn net_matching_and_parsing() {
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        assert!(in_net(ip("10.1.2.3"), ip("10.0.0.0"), 8));
        assert!(!in_net(ip("11.1.2.3"), ip("10.0.0.0"), 8));
        assert!(in_net(ip("1.2.3.4"), ip("0.0.0.0"), 0));
        assert!(in_net(ip("fd00::5"), ip("fd00::"), 8));
        assert!(!in_net(ip("fe80::5"), ip("fd00::"), 8));
        assert!(
            !in_net(ip("10.1.2.3"), ip("fd00::"), 8),
            "families do not mix"
        );
        assert_eq!(parse_ip_or_net("10.0.0.0/8"), Some((ip("10.0.0.0"), 8)));
        assert_eq!(parse_ip_or_net(" 1.2.3.4 "), Some((ip("1.2.3.4"), 32)));
        assert_eq!(parse_ip_or_net("fd00::1"), Some((ip("fd00::1"), 128)));
        assert_eq!(parse_ip_or_net("10.0.0.0/33"), None);
        assert_eq!(parse_ip_or_net("nope"), None);
    }

    #[test]
    fn windows_and_buckets() {
        assert_eq!(parse_window("24h"), Some(86_400));
        assert_eq!(parse_window("7d"), Some(604_800));
        assert_eq!(parse_window("1h"), Some(3600));
        for bad in ["", "h", "0h", "30m", "-1h", "abc", "99999d", "1.5h"] {
            assert_eq!(parse_window(bad), None, "{bad:?}");
        }
        assert_eq!(bucket_of(7200), 7200);
        assert_eq!(bucket_of(7199), 3600);
        assert_eq!(bucket_of(10_801), 10_800);
    }

    async fn store() -> ConfigStore {
        ConfigStore::open_in_memory().await.unwrap()
    }

    fn row(bucket: i64, ip: &str, dir: &'static str, cc: &str, asn: u32, bytes: u64) -> UsageRow {
        UsageRow {
            key: (bucket, ip.into(), dir, cc.into(), asn),
            org: format!("AS{asn}"),
            agg: Agg {
                bytes,
                packets: bytes / 100,
                flows: 1,
            },
        }
    }

    #[tokio::test]
    async fn flush_adds_up_and_queries_rank_and_filter() {
        let s = store().await;
        let now = 1_800_003_600;
        let b = bucket_of(now);
        flush(
            &s,
            &[
                row(b, "192.168.50.10", "up", "AU", 64500, 100),
                row(b, "192.168.50.10", "down", "AU", 64500, 900),
            ],
        )
        .await
        .unwrap();
        flush(
            &s,
            &[
                row(b, "192.168.50.10", "down", "AU", 64500, 100),
                row(b, "192.168.50.20", "down", "DE", 64501, 5000),
                row(b - 7200, "192.168.50.10", "down", "US", 15169, 50),
            ],
        )
        .await
        .unwrap();
        assert_eq!(
            row_count(&s).await,
            4,
            "the second flush added to the first one's down row"
        );
        let c = top(&s, By::Country, now, 3600, None, 10).await.unwrap();
        assert_eq!(
            c.iter()
                .map(|x| x["country"].as_str().unwrap())
                .collect::<Vec<_>>(),
            ["DE", "AU"],
            "ranked by bytes"
        );
        assert_eq!(c[1]["down_bytes"], 1000, "two flushes added up");
        assert_eq!(c[1]["up_bytes"], 100);
        assert_eq!(c[1]["bytes"], 1100);
        let wide = top(&s, By::Country, now, 3 * 3600, None, 10).await.unwrap();
        assert!(
            wide.iter().any(|x| x["country"] == "US"),
            "a wider window sees the older bucket"
        );
        let ips = vec!["192.168.50.10".to_string()];
        let a = top(&s, By::Asn, now, 3 * 3600, Some(&ips), 10)
            .await
            .unwrap();
        assert_eq!(
            a.iter()
                .map(|x| x["asn"].as_i64().unwrap())
                .collect::<Vec<_>>(),
            [64500, 15169]
        );
        assert_eq!(a[0]["org"], "AS64500");
        assert!(
            top(&s, By::Asn, now, 3600, Some(&[]), 10)
                .await
                .unwrap()
                .is_empty(),
            "a device without addresses has no traffic"
        );
        assert_eq!(
            top(&s, By::Country, now, 3 * 3600, None, 1)
                .await
                .unwrap()
                .len(),
            1,
            "limit"
        );
        let tl = timeline(&s, now, 3 * 3600, Some(&ips)).await.unwrap();
        assert_eq!(tl.len(), 4, "zero-filled hours");
        assert_eq!(tl[3]["down_bytes"], 1000);
        assert_eq!(tl[2]["down_bytes"], 0);
        assert_eq!(tl[1]["down_bytes"], 50);
        let dt = device_totals(&s, now, 3600, 10).await.unwrap();
        assert_eq!(dt[0]["ip"], "192.168.50.20");
        assert_eq!(dt[0]["top_country"], "DE");
        assert!(
            dt[0]["device"].is_null(),
            "no device model here: keyed by IP"
        );
    }

    #[tokio::test]
    async fn top_n_folds_the_tail_and_keeps_device_totals() {
        let s = store().await;
        let b = bucket_of(1_800_000_000);
        let mut rows = vec![];
        for i in 0..30u32 {
            rows.push(row(
                b,
                "192.168.50.10",
                "down",
                "AU",
                64000 + i,
                1000 + i as u64,
            ));
        }
        rows.push(row(b, "192.168.50.10", "up", "AU", 64000, 77));
        flush(&s, &rows).await.unwrap();
        let before: i64 = sqlx::query("SELECT SUM(bytes) FROM ins_usage")
            .fetch_one(s.pool().unwrap())
            .await
            .unwrap()
            .get(0);
        let folded = fold_bucket(&s, b, 10).await.unwrap();
        assert_eq!(folded, 21, "31 rows: 10 kept, the 21 others fold");
        let after: i64 = sqlx::query("SELECT SUM(bytes) FROM ins_usage")
            .fetch_one(s.pool().unwrap())
            .await
            .unwrap()
            .get(0);
        assert_eq!(before, after, "folding loses no bytes");
        let n = row_count(&s).await;
        assert_eq!(n, 12, "10 kept + the down and up fold rows");
        let r =
            sqlx::query("SELECT bytes FROM ins_usage WHERE country='--' AND asn=0 AND dir='down'")
                .fetch_one(s.pool().unwrap())
                .await
                .unwrap();
        assert!(r.get::<i64, _>(0) > 0);
        // the fold rows count towards the top N, so a second pass may fold one more
        // row into them, and then nothing is left to fold: the totals never change
        while fold_bucket(&s, b, 10).await.unwrap() > 0 {}
        let again: i64 = sqlx::query("SELECT SUM(bytes) FROM ins_usage")
            .fetch_one(s.pool().unwrap())
            .await
            .unwrap()
            .get(0);
        assert_eq!(before, again);
        assert!(row_count(&s).await <= 11);
        assert_eq!(
            fold_bucket(&s, b, 10).await.unwrap(),
            0,
            "the fold rows themselves are never folded again"
        );
    }

    #[tokio::test]
    async fn retention_prunes_old_buckets_only() {
        let s = store().await;
        let now = 1_800_000_000;
        let old = bucket_of(now) - 31 * 86_400;
        let edge = bucket_of(now) - 30 * 86_400;
        flush(
            &s,
            &[
                row(old, "10.0.0.1", "up", "AU", 1, 1),
                row(edge, "10.0.0.1", "up", "AU", 1, 1),
                row(bucket_of(now), "10.0.0.1", "up", "AU", 1, 1),
            ],
        )
        .await
        .unwrap();
        assert_eq!(prune(&s, now, 30).await.unwrap(), 1);
        assert_eq!(row_count(&s).await, 2);
        assert_eq!(
            prune(&s, now, 1).await.unwrap(),
            1,
            "retention is configurable"
        );
    }

    #[tokio::test]
    async fn settings_defaults_validation_and_roundtrip() {
        let s = store().await;
        assert_eq!(
            load_settings(&s).await,
            Settings {
                enabled: true,
                retention_days: 30,
                top_n: 200
            }
        );
        assert!(save_settings(&s, None, Some(0), None).await.is_err());
        assert!(save_settings(&s, None, Some(3651), None).await.is_err());
        assert!(save_settings(&s, None, None, Some(9)).await.is_err());
        save_settings(&s, Some(false), Some(7), Some(50))
            .await
            .unwrap();
        assert_eq!(
            load_settings(&s).await,
            Settings {
                enabled: false,
                retention_days: 7,
                top_n: 50
            }
        );
        s.save_system_config(CFG_RETENTION, "garbage")
            .await
            .unwrap();
        assert_eq!(
            load_settings(&s).await.retention_days,
            30,
            "unreadable values fall back to the default"
        );
    }

    #[tokio::test]
    async fn disabled_collection_records_nothing_and_forgets_the_baseline() {
        let s = store().await;
        let mut c = Collector::new(enricher());
        let now = 1_800_000_000;
        let t = line("tcp", "192.168.50.10", "198.51.100.10", 443, 1000, 2000);
        tick(&mut c, &s, now, Some(&t), true).await.unwrap(); // baseline
        let t2 = line("tcp", "192.168.50.10", "198.51.100.10", 443, 1500, 2500);
        tick(&mut c, &s, now + 60, Some(&t2), true).await.unwrap();
        assert_eq!(row_count(&s).await, 2);
        save_settings(&s, Some(false), None, None).await.unwrap();
        let t3 = line("tcp", "192.168.50.10", "198.51.100.10", 443, 9500, 9500);
        tick(&mut c, &s, now + 120, Some(&t3), true).await.unwrap();
        assert_eq!(row_count(&s).await, 2, "disabled");
        save_settings(&s, Some(true), None, None).await.unwrap();
        tick(&mut c, &s, now + 180, Some(&t3), true).await.unwrap();
        assert_eq!(
            row_count(&s).await,
            2,
            "re-enabled: the first look is a baseline again, the gap is not counted"
        );
    }

    /// Devices in the real segmentation tables (migration 1300): home is a
    /// built-in group, iot is added here.
    async fn with_device_model(s: &ConfigStore) {
        sqlx::raw_sql(
            "INSERT INTO seg_groups (name) VALUES ('iot');
             INSERT INTO seg_devices (name, group_id, segment, ip4, last_ip, state, created_at, kind)
               VALUES ('laptop', (SELECT id FROM seg_groups WHERE name='home'), '@lan', '192.168.50.10', NULL, 'active', 0, 'wired'),
                      ('cam', (SELECT id FROM seg_groups WHERE name='iot'), '@lan', '192.168.50.20', '192.168.50.99', 'active', 0, 'wired'),
                      ('old-tv', (SELECT id FROM seg_groups WHERE name='iot'), '@lan', '192.168.50.30', NULL, 'revoked', 0, 'wired'),
                      ('new-phone', (SELECT id FROM seg_groups WHERE name='iot'), '@lan', NULL, NULL, 'pending', 0, 'wifi');",
        )
        .execute(s.pool().unwrap())
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn device_views_join_the_model_when_it_exists() {
        let s = store().await;
        assert!(
            devices(&s).await.is_empty(),
            "no model: no devices, no error"
        );
        assert!(resolve_device(&s, "laptop").await.is_err());
        assert_eq!(
            resolve_device(&s, "10.1.1.1").await.unwrap().0,
            ["10.1.1.1"],
            "an IP always works"
        );
        with_device_model(&s).await;
        let d = devices(&s).await;
        assert_eq!(
            d.len(),
            3,
            "revoked devices are not listed, a pending one has no address yet"
        );
        assert!(d.iter().any(|x| x.name == "new-phone" && x.ips.is_empty()));
        let d: Vec<DeviceRef> = d.into_iter().filter(|x| !x.ips.is_empty()).collect();
        assert_eq!(d[1].ips, ["192.168.50.20", "192.168.50.99"]);
        assert_eq!(d[1].group.as_deref(), Some("iot"));
        let (ips, dev) = resolve_device(&s, "cam").await.unwrap();
        assert_eq!((ips.len(), dev.unwrap().id), (2, 2));
        assert_eq!(
            resolve_device(&s, "1").await.unwrap().0,
            ["192.168.50.10"],
            "by id"
        );
        let now = 1_800_000_000;
        flush(
            &s,
            &[
                row(bucket_of(now), "192.168.50.10", "down", "AU", 1, 900),
                row(bucket_of(now), "192.168.50.99", "down", "DE", 2, 100),
                row(bucket_of(now), "192.168.50.20", "up", "DE", 2, 50),
            ],
        )
        .await
        .unwrap();
        let t = device_totals(&s, now, 3600, 10).await.unwrap();
        assert_eq!(t[0]["device"], "laptop");
        assert_eq!(t[0]["group"], "home");
        let cam = t.iter().find(|x| x["ip"] == "192.168.50.20").unwrap();
        assert_eq!(
            (cam["bytes"].as_i64(), cam["device"].as_str()),
            (Some(50), Some("cam"))
        );
        let t99 = t.iter().find(|x| x["ip"] == "192.168.50.99").unwrap();
        assert_eq!(t99["device"], "cam", "last_ip maps to the device too");
        let cam_ips = resolve_device(&s, "cam").await.unwrap().0;
        let cc = top(&s, By::Country, now, 3600, Some(&cam_ips), 10)
            .await
            .unwrap();
        assert_eq!(cc[0]["country"], "DE");
        assert_eq!(cc[0]["bytes"], 150, "all of the device's addresses");
    }

    #[tokio::test]
    async fn exclusions_resolve_devices_groups_and_forget_history() {
        let s = store().await;
        assert!(add_exclusion(&s, "ip", "nonsense").await.is_err());
        assert!(
            add_exclusion(&s, "group", "iot").await.is_err(),
            "unknown group"
        );
        assert!(add_exclusion(&s, "volume", "x").await.is_err());
        with_device_model(&s).await;
        let now = 1_800_000_000;
        flush(
            &s,
            &[
                row(bucket_of(now), "192.168.50.10", "down", "AU", 1, 900),
                row(bucket_of(now), "192.168.50.20", "down", "AU", 1, 100),
                row(bucket_of(now), "192.168.51.5", "down", "AU", 1, 10),
            ],
        )
        .await
        .unwrap();
        assert_eq!(
            add_exclusion(&s, "group", "iot").await.unwrap(),
            1,
            "the cam's history is deleted"
        );
        assert_eq!(add_exclusion(&s, "ip", "192.168.51.0/24").await.unwrap(), 1);
        assert_eq!(row_count(&s).await, 1);
        let ex = load_exclusions(&s).await;
        assert!(
            ex.matches("192.168.50.20".parse().unwrap())
                && ex.matches("192.168.50.99".parse().unwrap())
        );
        assert!(ex.matches("192.168.51.77".parse().unwrap()));
        assert!(!ex.matches("192.168.50.10".parse().unwrap()));
        add_exclusion(&s, "device", "laptop").await.unwrap();
        assert_eq!(row_count(&s).await, 0);
        assert_eq!(list_exclusions(&s).await.unwrap().len(), 3);
        assert!(remove_exclusion(&s, "device", "laptop").await.unwrap());
        assert!(!remove_exclusion(&s, "device", "laptop").await.unwrap());
        assert!(!load_exclusions(&s)
            .await
            .matches("192.168.50.10".parse().unwrap()));
    }
}
