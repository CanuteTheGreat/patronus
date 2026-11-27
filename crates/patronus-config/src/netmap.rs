//! Network map & discovery model (lane `w`, docs/design/network-map.md): hosts the router has seen
//! (`map_devices`, measured), the operator's labels and class rules, read-only share keys, typed
//! settings (`map.*` in `system_config`), device classification and the segmentation advisor.
//!
//! Pure store accessors and pure logic only: collection (leases, neighbour table, probes, LLDP)
//! and applying an advisor plan through the device-segmentation engine live in
//! `patronus-web/src/state/netmap.rs`.

use crate::seg::{db, invalid, now, unique};
use crate::store::ConfigStore;
use patronus_core::Result;
use serde::{Deserialize, Serialize};
use sqlx::Row;
use std::collections::{BTreeMap, BTreeSet};

/// Device classes, in the order the UI lists them.
pub const CLASSES: &[&str] = &[
    "computer", "phone", "printer", "camera", "iot", "media", "infra", "unknown",
];

// ---------------------------------------------------------------------------
// settings
// ---------------------------------------------------------------------------

/// Every setting: (key under `map.`, default, help). Typed, documented, exported with the config.
pub const SETTINGS: &[(&str, &str, &str)] = &[
    ("discovery_interval_secs", "60", "how often the router merges leases, neighbours and probes (10-3600)"),
    ("down_after_secs", "300", "a device not seen answering for this long is shown down (30-86400)"),
    ("retention_days", "30", "forget devices not seen for this many days (1-3650)"),
    ("probe", "ping", "off | ping (one ICMP echo to each address already known; never a sweep) | nmap (opt-in nmap -sn sweep of LAN-side subnets)"),
    ("probe_max", "256", "most addresses probed per round (1-4096)"),
    ("lldp", "auto", "auto (use lldpctl when installed) | off"),
    ("refresh_secs", "30", "how often an open map reloads (0 = never, 5-3600)"),
    ("untrusted", "iot,camera,printer,media", "classes that should not share a segment with trusted ones"),
    ("trusted", "computer,phone,infra", "classes the advisor protects"),
    ("group_iot", "iot", "segmentation group the advisor puts IoT devices in"),
    ("group_camera", "cameras", "segmentation group for cameras"),
    ("group_printer", "printers", "segmentation group for printers"),
    ("group_media", "media", "segmentation group for TVs and media players"),
    ("internet_iot", "allow", "allow | deny: internet for the IoT group"),
    ("internet_camera", "allow", "allow | deny: internet for cameras (cloud cameras need it)"),
    ("internet_printer", "deny", "allow | deny: internet for printers"),
    ("internet_media", "allow", "allow | deny: internet for media players"),
    ("printer_ports", "631,9100", "TCP ports trusted devices may open on printers (IPP, raw)"),
    ("camera_ports", "80,443,554", "TCP ports trusted devices may open on cameras (web, RTSP)"),
    ("vlan_base", "20", "first VLAN id of the advisor's VLAN plan (2-4000; one per class, step 10)"),
    ("share_detail", "basic", "basic (shared maps hide MACs and details) | full: default for new keys"),
];

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Settings {
    pub values: BTreeMap<String, String>,
}

impl Settings {
    pub fn defaults() -> Self {
        Self {
            values: SETTINGS
                .iter()
                .map(|(k, d, _)| (k.to_string(), d.to_string()))
                .collect(),
        }
    }
    pub fn get(&self, k: &str) -> &str {
        self.values.get(k).map(String::as_str).unwrap_or("")
    }
    pub fn num(&self, k: &str) -> i64 {
        self.get(k).parse().unwrap_or(0)
    }
    pub fn list(&self, k: &str) -> Vec<String> {
        self.get(k)
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect()
    }
    pub fn group_for(&self, class: &str) -> Option<String> {
        self.values.get(&format!("group_{class}")).cloned()
    }
}

/// Check one setting; returns the normalised value.
pub fn check_setting(key: &str, value: &str) -> Result<String> {
    let v = value.trim();
    let num = |lo: i64, hi: i64| -> Result<String> {
        match v.parse::<i64>() {
            Ok(n) if (lo..=hi).contains(&n) => Ok(n.to_string()),
            _ => Err(invalid(format!("map.{key}: a number {lo}-{hi}"))),
        }
    };
    let classes = |v: &str| -> Result<String> {
        let mut out = Vec::new();
        for c in v.split(',').map(str::trim).filter(|c| !c.is_empty()) {
            if !CLASSES.contains(&c) {
                return Err(invalid(format!("map.{key}: unknown class {c:?}")));
            }
            out.push(c.to_string());
        }
        Ok(out.join(","))
    };
    match key {
        "discovery_interval_secs" => num(10, 3600),
        "down_after_secs" => num(30, 86400),
        "retention_days" => num(1, 3650),
        "probe_max" => num(1, 4096),
        "vlan_base" => num(2, 4000),
        "refresh_secs" => {
            let s = num(0, 3600)?;
            if s != "0" && s.parse::<i64>().unwrap_or(0) < 5 {
                return Err(invalid("map.refresh_secs: 0 or 5-3600"));
            }
            Ok(s)
        }
        "probe" if matches!(v, "off" | "ping" | "nmap") => Ok(v.into()),
        "lldp" if matches!(v, "auto" | "off") => Ok(v.into()),
        "share_detail" if matches!(v, "basic" | "full") => Ok(v.into()),
        "untrusted" | "trusted" => classes(v),
        k if k.starts_with("internet_") && matches!(v, "allow" | "deny") => Ok(v.into()),
        k if k.starts_with("group_") && crate::seg::is_name(v) => Ok(v.into()),
        k if k.ends_with("_ports") => crate::seg::check_ports(v),
        k if SETTINGS.iter().any(|(n, _, _)| *n == k) => {
            Err(invalid(format!("map.{key}: {v:?} is not allowed")))
        }
        _ => Err(invalid(format!("setting map.{key}: no such setting"))),
    }
}

pub async fn load_settings(store: &ConfigStore) -> Result<Settings> {
    let mut s = Settings::defaults();
    for (k, _, _) in SETTINGS {
        if let Some(v) = store.load_system_config(&format!("map.{k}")).await? {
            if let Ok(v) = check_setting(k, &v) {
                s.values.insert(k.to_string(), v);
            }
        }
    }
    Ok(s)
}

pub async fn save_settings(store: &ConfigStore, changes: &BTreeMap<String, String>) -> Result<()> {
    let mut checked = Vec::new();
    for (k, v) in changes {
        checked.push((k.clone(), check_setting(k, v)?));
    }
    for (k, v) in checked {
        store.save_system_config(&format!("map.{k}"), &v).await?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// classification
// ---------------------------------------------------------------------------

/// Built-in hostname patterns (defaults; a user rule or a label always wins).
pub const BUILTIN_RULES: &[(&str, &str)] = &[
    ("*printer*", "printer"),
    ("*epson*", "printer"),
    ("*brother*", "printer"),
    ("*canon*", "printer"),
    ("hp[0-9a-f]*", "printer"),
    ("*laserjet*", "printer"),
    ("*officejet*", "printer"),
    ("*cam*", "camera"),
    ("*ipc*", "camera"),
    ("*reolink*", "camera"),
    ("*hikvision*", "camera"),
    ("*doorbell*", "camera"),
    ("*wyze*", "camera"),
    ("*nvr*", "camera"),
    ("*tuya*", "iot"),
    ("*shelly*", "iot"),
    ("*sonoff*", "iot"),
    ("esp-*", "iot"),
    ("esp32*", "iot"),
    ("*tasmota*", "iot"),
    ("*plug*", "iot"),
    ("*bulb*", "iot"),
    ("*thermostat*", "iot"),
    ("*nest*", "iot"),
    ("*ecobee*", "iot"),
    ("*hue*", "iot"),
    ("*sensor*", "iot"),
    ("*vacuum*", "iot"),
    ("*roku*", "media"),
    ("*chromecast*", "media"),
    ("*appletv*", "media"),
    ("*apple-tv*", "media"),
    ("*firetv*", "media"),
    ("*fire-tv*", "media"),
    ("*sonos*", "media"),
    ("*-tv", "media"),
    ("tv-*", "media"),
    ("*smarttv*", "media"),
    ("*bravia*", "media"),
    ("*shield*", "media"),
    ("*nas*", "infra"),
    ("*synology*", "infra"),
    ("*truenas*", "infra"),
    ("*proxmox*", "infra"),
    ("*horcrux*", "infra"),
    ("*pve*", "infra"),
    ("*esxi*", "infra"),
    ("*idrac*", "infra"),
    ("ilo-*", "infra"),
    ("*-ilo", "infra"),
    ("*ipmi*", "infra"),
    ("*bmc*", "infra"),
    ("*switch*", "infra"),
    ("*unifi*", "infra"),
    ("*server*", "infra"),
    ("*iphone*", "phone"),
    ("*android*", "phone"),
    ("*galaxy*", "phone"),
    ("*pixel*", "phone"),
    ("*phone*", "phone"),
    ("*laptop*", "computer"),
    ("*desktop*", "computer"),
    ("*macbook*", "computer"),
    ("*imac*", "computer"),
    ("*-pc", "computer"),
    ("pc-*", "computer"),
    ("*workstation*", "computer"),
    ("*thinkpad*", "computer"),
];

/// Case-insensitive glob with `*`, `?` and `[...]` ranges/sets.
pub fn glob(pattern: &str, text: &str) -> bool {
    fn m(p: &[char], t: &[char]) -> bool {
        match p.first() {
            None => t.is_empty(),
            Some('*') => (0..=t.len()).any(|i| m(&p[1..], &t[i..])),
            Some('?') => !t.is_empty() && m(&p[1..], &t[1..]),
            Some('[') => {
                let Some(end) = p.iter().position(|c| *c == ']') else {
                    return !t.is_empty() && t[0] == '[' && m(&p[1..], &t[1..]);
                };
                let Some(c) = t.first() else { return false };
                let set = &p[1..end];
                let mut hit = false;
                let mut i = 0;
                while i < set.len() {
                    if i + 2 < set.len() && set[i + 1] == '-' {
                        hit |= set[i] <= *c && *c <= set[i + 2];
                        i += 3;
                    } else {
                        hit |= set[i] == *c;
                        i += 1;
                    }
                }
                hit && m(&p[end + 1..], &t[1..])
            }
            Some(c) => t.first() == Some(c) && m(&p[1..], &t[1..]),
        }
    }
    let p: Vec<char> = pattern.to_ascii_lowercase().chars().collect();
    let t: Vec<char> = text.to_ascii_lowercase().chars().collect();
    m(&p, &t)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ClassRule {
    pub id: i64,
    pub field: String,
    pub pattern: String,
    pub class: String,
    pub priority: i64,
}

/// (class, where it came from: label | rule | builtin | none).
pub fn classify(
    hostname: Option<&str>,
    mac: &str,
    label: Option<&str>,
    rules: &[ClassRule],
) -> (String, &'static str) {
    if let Some(c) = label.filter(|c| CLASSES.contains(c)) {
        return (c.to_string(), "label");
    }
    let host = hostname.unwrap_or("");
    for r in rules {
        let text = if r.field == "mac" { mac } else { host };
        if !text.is_empty() && glob(&r.pattern, text) {
            return (r.class.clone(), "rule");
        }
    }
    if !host.is_empty() {
        for (p, c) in BUILTIN_RULES {
            if glob(p, host) {
                return (c.to_string(), "builtin");
            }
        }
    }
    ("unknown".into(), "none")
}

/// A locally administered (randomised / private) MAC: bit 1 of the first octet.
pub fn private_mac(mac: &str) -> bool {
    u8::from_str_radix(mac.get(0..2).unwrap_or("00"), 16)
        .map(|b| b & 2 == 2)
        .unwrap_or(false)
}

pub async fn list_rules(store: &ConfigStore) -> Result<Vec<ClassRule>> {
    let rows = sqlx::query(
        "SELECT id, field, pattern, class, priority FROM map_class_rules ORDER BY priority, id",
    )
    .fetch_all(store.pool()?)
    .await
    .map_err(db("list class rules"))?;
    Ok(rows
        .iter()
        .map(|r| ClassRule {
            id: r.get(0),
            field: r.get(1),
            pattern: r.get(2),
            class: r.get(3),
            priority: r.get(4),
        })
        .collect())
}

pub async fn add_rule(
    store: &ConfigStore,
    field: &str,
    pattern: &str,
    class: &str,
    priority: i64,
) -> Result<i64> {
    if !matches!(field, "hostname" | "mac") {
        return Err(invalid("rule field: hostname or mac"));
    }
    let pattern = pattern.trim();
    if pattern.is_empty()
        || pattern.len() > 64
        || pattern.chars().any(|c| c.is_whitespace() || c.is_control())
    {
        return Err(invalid(
            "rule pattern: 1-64 characters, no spaces (* ? [a-z] allowed)",
        ));
    }
    if !CLASSES.contains(&class) {
        return Err(invalid(format!("rule class {class:?}")));
    }
    let r = sqlx::query(
        "INSERT INTO map_class_rules (field, pattern, class, priority) VALUES (?,?,?,?)",
    )
    .bind(field)
    .bind(pattern)
    .bind(class)
    .bind(priority)
    .execute(store.pool()?)
    .await
    .map_err(|e| unique(e, &format!("rule {field} {pattern}")))?;
    Ok(r.last_insert_rowid())
}

pub async fn delete_rule(store: &ConfigStore, id: i64) -> Result<()> {
    let r = sqlx::query("DELETE FROM map_class_rules WHERE id = ?")
        .bind(id)
        .execute(store.pool()?)
        .await
        .map_err(db("delete class rule"))?;
    if r.rows_affected() == 0 {
        return Err(patronus_core::Error::Config(format!("no class rule {id}")));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// seen devices + labels
// ---------------------------------------------------------------------------

/// One sighting from one source in one collection round.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Observation {
    pub mac: String,
    pub ip: Option<String>,
    pub hostname: Option<String>,
    pub iface: Option<String>,
    pub segment: Option<String>,
    pub source: &'static str,
    pub up: bool,
    pub neigh_state: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct MapDevice {
    pub mac: String,
    pub ip: Option<String>,
    pub hostname: Option<String>,
    pub iface: Option<String>,
    pub segment: Option<String>,
    pub sources: String,
    pub neigh_state: Option<String>,
    pub first_seen: i64,
    pub last_seen: i64,
    pub last_up: Option<i64>,
    /// label name, else hostname, else the MAC
    pub name: String,
    pub label: Option<String>,
    pub class: String,
    pub class_source: String,
    pub note: Option<String>,
    pub private_mac: bool,
    /// up | down
    pub status: String,
}

pub async fn observe(store: &ConfigStore, obs: &[Observation], at: i64) -> Result<usize> {
    let pool = store.pool()?;
    for o in obs {
        let mac = o.mac.to_ascii_lowercase();
        let row = sqlx::query("SELECT sources FROM map_devices WHERE mac = ?")
            .bind(&mac)
            .fetch_optional(pool)
            .await
            .map_err(db("read map device"))?;
        let mut src: BTreeSet<String> = row
            .map(|r| r.get::<String, _>(0))
            .unwrap_or_default()
            .split(',')
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect();
        src.insert(o.source.to_string());
        let src = src.into_iter().collect::<Vec<_>>().join(",");
        sqlx::query(
            "INSERT INTO map_devices (mac, ip, hostname, iface, segment, sources, neigh_state, first_seen, last_seen, last_up)
             VALUES (?,?,?,?,?,?,?,?,?,?)
             ON CONFLICT(mac) DO UPDATE SET
               ip = COALESCE(excluded.ip, ip), hostname = COALESCE(excluded.hostname, hostname),
               iface = COALESCE(excluded.iface, iface), segment = COALESCE(excluded.segment, segment),
               sources = excluded.sources, neigh_state = COALESCE(excluded.neigh_state, neigh_state),
               last_seen = excluded.last_seen, last_up = COALESCE(excluded.last_up, last_up)",
        )
        .bind(&mac)
        .bind(&o.ip)
        .bind(&o.hostname)
        .bind(&o.iface)
        .bind(&o.segment)
        .bind(&src)
        .bind(&o.neigh_state)
        .bind(at)
        .bind(at)
        .bind(if o.up { Some(at) } else { None })
        .execute(pool)
        .await
        .map_err(db("record map device"))?;
    }
    Ok(obs.len())
}

pub async fn prune(store: &ConfigStore, retention_days: i64, at: i64) -> Result<u64> {
    let r = sqlx::query("DELETE FROM map_devices WHERE last_seen < ?")
        .bind(at - retention_days.max(1) * 86400)
        .execute(store.pool()?)
        .await
        .map_err(db("prune map devices"))?;
    Ok(r.rows_affected())
}

/// (name, class, note) of a label.
type Label = (Option<String>, Option<String>, Option<String>);

pub async fn list_devices(store: &ConfigStore, s: &Settings, at: i64) -> Result<Vec<MapDevice>> {
    let rules = list_rules(store).await?;
    let labels: BTreeMap<String, Label> =
        sqlx::query("SELECT mac, name, class, note FROM map_device_labels")
            .fetch_all(store.pool()?)
            .await
            .map_err(db("list labels"))?
            .iter()
            .map(|r| (r.get(0), (r.get(1), r.get(2), r.get(3))))
            .collect();
    let rows = sqlx::query(
        "SELECT mac, ip, hostname, iface, segment, sources, neigh_state, first_seen, last_seen, last_up
         FROM map_devices ORDER BY segment, ip, mac",
    )
    .fetch_all(store.pool()?)
    .await
    .map_err(db("list map devices"))?;
    let down_after = s.num("down_after_secs").max(1);
    Ok(rows
        .iter()
        .map(|r| {
            let mac: String = r.get(0);
            let hostname: Option<String> = r.get(2);
            let last_up: Option<i64> = r.get(9);
            let (lname, lclass, note) = labels.get(&mac).cloned().unwrap_or((None, None, None));
            let (class, src) = classify(hostname.as_deref(), &mac, lclass.as_deref(), &rules);
            MapDevice {
                name: lname
                    .clone()
                    .or_else(|| hostname.clone())
                    .unwrap_or_else(|| mac.clone()),
                label: lname,
                private_mac: private_mac(&mac),
                status: if last_up.map(|t| at - t <= down_after).unwrap_or(false) {
                    "up"
                } else {
                    "down"
                }
                .into(),
                ip: r.get(1),
                hostname,
                iface: r.get(3),
                segment: r.get(4),
                sources: r.get(5),
                neigh_state: r.get(6),
                first_seen: r.get(7),
                last_seen: r.get(8),
                last_up,
                class,
                class_source: src.into(),
                note,
                mac,
            }
        })
        .collect())
}

pub async fn set_label(
    store: &ConfigStore,
    mac: &str,
    name: Option<&str>,
    class: Option<&str>,
    note: Option<&str>,
) -> Result<()> {
    let mac = crate::seg::norm_mac(mac)?;
    let name = name.map(str::trim).filter(|s| !s.is_empty());
    if let Some(n) = name {
        if n.len() > 64 || n.chars().any(char::is_control) {
            return Err(invalid("label name: at most 64 characters"));
        }
    }
    let class = class.map(str::trim).filter(|s| !s.is_empty());
    if let Some(c) = class {
        if !CLASSES.contains(&c) {
            return Err(invalid(format!("class {c:?}")));
        }
    }
    let note = note.map(str::trim).filter(|s| !s.is_empty());
    if name.is_none() && class.is_none() && note.is_none() {
        sqlx::query("DELETE FROM map_device_labels WHERE mac = ?")
            .bind(&mac)
            .execute(store.pool()?)
            .await
            .map_err(db("clear label"))?;
        return Ok(());
    }
    sqlx::query(
        "INSERT INTO map_device_labels (mac, name, class, note, updated_at) VALUES (?,?,?,?,?)
         ON CONFLICT(mac) DO UPDATE SET name = excluded.name, class = excluded.class, note = excluded.note,
         updated_at = excluded.updated_at",
    )
    .bind(&mac)
    .bind(name)
    .bind(class)
    .bind(note)
    .bind(now())
    .execute(store.pool()?)
    .await
    .map_err(db("save label"))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// share keys (hash only; the web layer generates and hashes the key)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct ShareKey {
    pub id: i64,
    pub name: String,
    pub scope: String,
    pub detail: String,
    pub created_at: i64,
    pub expires_at: Option<i64>,
    pub last_used: Option<i64>,
}

fn key_row(r: &sqlx::sqlite::SqliteRow) -> ShareKey {
    ShareKey {
        id: r.get(0),
        name: r.get(1),
        scope: r.get(2),
        detail: r.get(3),
        created_at: r.get(4),
        expires_at: r.get(5),
        last_used: r.get(6),
    }
}

pub async fn list_keys(store: &ConfigStore) -> Result<Vec<ShareKey>> {
    Ok(sqlx::query("SELECT id, name, scope, detail, created_at, expires_at, last_used FROM map_share_keys ORDER BY name")
        .fetch_all(store.pool()?)
        .await
        .map_err(db("list share keys"))?
        .iter()
        .map(key_row)
        .collect())
}

pub async fn create_key(
    store: &ConfigStore,
    name: &str,
    key_hash: &str,
    scope: &str,
    detail: &str,
    expires_at: Option<i64>,
) -> Result<i64> {
    if !crate::seg::is_name(name) {
        return Err(invalid("key name: [a-z0-9_-], 1-32 characters"));
    }
    if !matches!(scope, "view" | "stats") || !matches!(detail, "basic" | "full") {
        return Err(invalid("key scope (view|stats) or detail (basic|full)"));
    }
    if key_hash.len() != 64 || !key_hash.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(invalid("key hash"));
    }
    let r = sqlx::query(
        "INSERT INTO map_share_keys (name, key_hash, scope, detail, created_at, expires_at) VALUES (?,?,?,?,?,?)",
    )
    .bind(name)
    .bind(key_hash)
    .bind(scope)
    .bind(detail)
    .bind(now())
    .bind(expires_at)
    .execute(store.pool()?)
    .await
    .map_err(|e| unique(e, &format!("share key {name}")))?;
    Ok(r.last_insert_rowid())
}

pub async fn delete_key(store: &ConfigStore, id: i64) -> Result<()> {
    let r = sqlx::query("DELETE FROM map_share_keys WHERE id = ?")
        .bind(id)
        .execute(store.pool()?)
        .await
        .map_err(db("delete share key"))?;
    if r.rows_affected() == 0 {
        return Err(patronus_core::Error::Config(format!("no share key {id}")));
    }
    Ok(())
}

/// The key with this hash, if it exists and has not expired; records the use.
pub async fn key_by_hash(store: &ConfigStore, key_hash: &str, at: i64) -> Result<Option<ShareKey>> {
    let row = sqlx::query(
        "SELECT id, name, scope, detail, created_at, expires_at, last_used FROM map_share_keys WHERE key_hash = ?",
    )
    .bind(key_hash)
    .fetch_optional(store.pool()?)
    .await
    .map_err(db("read share key"))?;
    let Some(k) = row.as_ref().map(key_row) else {
        return Ok(None);
    };
    if k.expires_at.map(|e| e <= at).unwrap_or(false) {
        return Ok(None);
    }
    // at most one write a minute per key
    if k.last_used.map(|t| at - t >= 60).unwrap_or(true) {
        let _ = sqlx::query("UPDATE map_share_keys SET last_used = ? WHERE id = ?")
            .bind(at)
            .bind(k.id)
            .execute(store.pool()?)
            .await;
    }
    Ok(Some(k))
}

// ---------------------------------------------------------------------------
// segmentation advisor (pure)
// ---------------------------------------------------------------------------

/// What the advisor knows about one LAN-side segment.
#[derive(Debug, Clone, PartialEq)]
pub struct SegView {
    pub segment: String,
    pub label: String,
    /// device segmentation is switched on for it
    pub isolated: bool,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Finding {
    pub id: String,
    pub severity: String,
    pub segment: String,
    pub title: String,
    pub detail: String,
    pub untrusted: Vec<String>,
    pub trusted: Vec<String>,
}

/// Flat-network check: untrusted classes sharing a segment, and a segmentation group, with trusted ones.
/// `group_of` maps a MAC to its device-segmentation group (devices not enrolled are absent).
pub fn advise(
    segs: &[SegView],
    devices: &[MapDevice],
    s: &Settings,
    group_of: &BTreeMap<String, String>,
) -> Vec<Finding> {
    let untrusted = s.list("untrusted");
    let trusted = s.list("trusted");
    let mut out = Vec::new();
    for sg in segs {
        let on: Vec<&MapDevice> = devices
            .iter()
            .filter(|d| d.segment.as_deref() == Some(sg.segment.as_str()))
            .collect();
        // a device is still exposed when it shares a group with a trusted device (or nothing isolates it)
        let grp = |d: &MapDevice| -> String {
            if sg.isolated {
                // an unenrolled MAC on an isolated segment forwards nothing: a group of its own
                group_of
                    .get(&d.mac)
                    .cloned()
                    .unwrap_or_else(|| format!("?{}", d.mac))
            } else {
                "*".into()
            }
        };
        let t: Vec<&&MapDevice> = on.iter().filter(|d| trusted.contains(&d.class)).collect();
        let tgroups: BTreeSet<String> = t.iter().map(|d| grp(d)).collect();
        let u: Vec<&&MapDevice> = on
            .iter()
            .filter(|d| untrusted.contains(&d.class) && tgroups.contains(&grp(d)))
            .collect();
        if u.is_empty() || t.is_empty() {
            continue;
        }
        let infra = t.iter().any(|d| d.class == "infra");
        let risky = u
            .iter()
            .any(|d| matches!(d.class.as_str(), "camera" | "iot"));
        let mut kinds: BTreeMap<&str, usize> = BTreeMap::new();
        for d in &u {
            *kinds.entry(d.class.as_str()).or_default() += 1;
        }
        let kinds = kinds
            .iter()
            .map(|(k, n)| format!("{n} {k}"))
            .collect::<Vec<_>>()
            .join(", ");
        out.push(Finding {
            id: "flat-network".into(),
            severity: if infra && risky { "high" } else { "medium" }.into(),
            segment: sg.segment.clone(),
            title: format!("{} is a flat network", sg.label),
            detail: format!(
                "{kinds} share this segment with {} trusted device(s){}. A compromised device here can reach them directly.",
                t.len(),
                if infra { " including management consoles" } else { "" }
            ),
            untrusted: u.iter().map(|d| d.mac.clone()).collect(),
            trusted: t.iter().map(|d| d.mac.clone()).collect(),
        });
    }
    out
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct GroupPlan {
    pub name: String,
    pub class: String,
    pub internet: String,
    pub intra: bool,
    pub exists: bool,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct MovePlan {
    pub mac: String,
    pub name: String,
    pub class: String,
    pub group: String,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct ServicePlan {
    pub name: String,
    pub src: String,
    pub dst: String,
    pub proto: String,
    pub ports: String,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Plan {
    pub segment: String,
    pub enable_isolation: bool,
    pub groups: Vec<GroupPlan>,
    pub moves: Vec<MovePlan>,
    pub services: Vec<ServicePlan>,
    pub links: Vec<(String, String)>,
    /// (class, VLAN id, group): for networks whose switches/APs can tag VLANs; not applied yet
    pub vlan_plan: Vec<(String, u16, String)>,
    pub notes: Vec<String>,
}

/// The isolation plan for one segment, reusing device segmentation: everything stays in `home`
/// except untrusted classes, which get their own groups (no traffic inside a group, internet per
/// class), plus one-way services so trusted devices still print and watch cameras, and a
/// home <-> media link so casting keeps working.
pub fn plan(
    segment: &str,
    isolated: bool,
    devices: &[MapDevice],
    s: &Settings,
    existing_groups: &BTreeSet<String>,
) -> Plan {
    let untrusted = s.list("untrusted");
    let mut groups: Vec<GroupPlan> = Vec::new();
    let mut moves = Vec::new();
    for d in devices
        .iter()
        .filter(|d| d.segment.as_deref() == Some(segment))
    {
        if !untrusted.contains(&d.class) {
            continue;
        }
        let Some(g) = s.group_for(&d.class) else {
            continue;
        };
        if !groups.iter().any(|x| x.name == g) {
            groups.push(GroupPlan {
                exists: existing_groups.contains(&g),
                name: g.clone(),
                class: d.class.clone(),
                internet: s.get(&format!("internet_{}", d.class)).to_string(),
                intra: false,
            });
        }
        moves.push(MovePlan {
            mac: d.mac.clone(),
            name: d.name.clone(),
            class: d.class.clone(),
            group: g,
        });
    }
    let mut services = Vec::new();
    let mut links = Vec::new();
    for g in &groups {
        match g.class.as_str() {
            "printer" => services.push(ServicePlan {
                name: format!("advisor-{}", g.name),
                src: crate::seg::GROUP_HOME.into(),
                dst: g.name.clone(),
                proto: "tcp".into(),
                ports: s.get("printer_ports").into(),
            }),
            "camera" => services.push(ServicePlan {
                name: format!("advisor-{}", g.name),
                src: crate::seg::GROUP_HOME.into(),
                dst: g.name.clone(),
                proto: "tcp".into(),
                ports: s.get("camera_ports").into(),
            }),
            "media" => links.push((crate::seg::GROUP_HOME.to_string(), g.name.clone())),
            _ => {}
        }
    }
    let base = s.num("vlan_base").clamp(2, 4000) as u16;
    let vlan_plan = groups
        .iter()
        .enumerate()
        .map(|(i, g)| {
            (
                g.class.clone(),
                base.saturating_add(10 * i as u16),
                g.name.clone(),
            )
        })
        .collect();
    let mut notes = vec![
        "Devices that are not moved stay in the group 'home' and keep talking to each other and the internet.".to_string(),
        "Undo: System > History, roll back to the revision before 'segmentation advisor'.".to_string(),
    ];
    notes.push("Wired devices behind an unmanaged switch reach each other without the router: put those on a router port, a managed switch with port isolation, or a VLAN (see the VLAN plan).".into());
    Plan {
        segment: segment.into(),
        enable_isolation: !isolated,
        groups,
        moves,
        services,
        links,
        vlan_plan,
        notes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dev(mac: &str, host: &str, class: &str, seg: &str) -> MapDevice {
        MapDevice {
            mac: mac.into(),
            ip: None,
            hostname: Some(host.into()),
            iface: None,
            segment: Some(seg.into()),
            sources: "lease".into(),
            neigh_state: None,
            first_seen: 0,
            last_seen: 0,
            last_up: None,
            name: host.into(),
            label: None,
            class: class.into(),
            class_source: "builtin".into(),
            note: None,
            private_mac: false,
            status: "up".into(),
        }
    }

    #[test]
    fn globs_and_builtin_classes() {
        assert!(glob("*cam*", "Front-Camera"));
        assert!(glob("hp[0-9a-f]*", "HP3C2AF1"));
        assert!(!glob("hp[0-9a-f]*", "hpz-laptop"));
        assert!(glob("esp-??", "esp-1a"));
        assert!(!glob("esp-??", "esp-1ab"));
        let c = |h| classify(Some(h), "aa:bb:cc:00:00:01", None, &[]).0;
        assert_eq!(c("office-printer"), "printer");
        assert_eq!(c("driveway-cam"), "camera");
        assert_eq!(c("tuya-plug-3"), "iot");
        assert_eq!(c("livingroom-tv"), "media");
        assert_eq!(c("nas"), "infra");
        assert_eq!(c("work-laptop"), "computer");
        assert_eq!(c("xyzzy"), "unknown");
    }

    #[test]
    fn label_beats_rule_beats_builtin() {
        let rules = vec![ClassRule {
            id: 1,
            field: "mac".into(),
            pattern: "aa:bb:cc:*".into(),
            class: "iot".into(),
            priority: 1,
        }];
        assert_eq!(
            classify(Some("nas"), "aa:bb:cc:00:00:01", None, &rules),
            ("iot".into(), "rule")
        );
        assert_eq!(
            classify(Some("nas"), "aa:bb:cc:00:00:01", Some("camera"), &rules),
            ("camera".into(), "label")
        );
        assert_eq!(
            classify(Some("nas"), "11:bb:cc:00:00:01", None, &rules),
            ("infra".into(), "builtin")
        );
        assert!(
            private_mac("02:00:00:00:00:01")
                && private_mac("da:a1:19:00:00:01")
                && !private_mac("00:11:22:33:44:55")
        );
    }

    #[test]
    fn settings_are_validated() {
        assert_eq!(check_setting("probe", "nmap").unwrap(), "nmap");
        assert!(check_setting("probe", "masscan").is_err());
        assert!(check_setting("down_after_secs", "5").is_err());
        assert!(check_setting("refresh_secs", "3").is_err());
        assert_eq!(check_setting("refresh_secs", "0").unwrap(), "0");
        assert!(check_setting("untrusted", "iot,toaster").is_err());
        assert!(check_setting("group_iot", "IoT Group").is_err());
        assert!(check_setting("nope", "1").is_err());
        assert!(check_setting("printer_ports", "631,9100").is_ok());
        for (k, d, _) in SETTINGS {
            assert_eq!(
                &check_setting(k, d).unwrap(),
                d,
                "default of {k} passes its own check"
            );
        }
    }

    #[test]
    fn flat_segment_is_flagged_and_isolated_one_is_not() {
        let s = Settings::defaults();
        let devs = vec![
            dev("aa:00:00:00:00:01", "nas", "infra", "@lan"),
            dev("aa:00:00:00:00:02", "work-laptop", "computer", "@lan"),
            dev("aa:00:00:00:00:03", "driveway-cam", "camera", "@lan"),
            dev("aa:00:00:00:00:04", "office-printer", "printer", "@lan"),
            dev("aa:00:00:00:00:05", "plug", "iot", "@opt1"),
        ];
        let segs = vec![
            SegView {
                segment: "@lan".into(),
                label: "LAN".into(),
                isolated: false,
            },
            SegView {
                segment: "@opt1".into(),
                label: "IoT".into(),
                isolated: false,
            },
        ];
        let f = advise(&segs, &devs, &s, &BTreeMap::new());
        assert_eq!(f.len(), 1, "{f:?}");
        assert_eq!(f[0].segment, "@lan");
        assert_eq!(f[0].severity, "high");
        assert_eq!(f[0].untrusted.len(), 2);
        // isolation on but everyone still in 'home': still flat
        let segs_on = vec![SegView {
            segment: "@lan".into(),
            label: "LAN".into(),
            isolated: true,
        }];
        let home: BTreeMap<String, String> = devs
            .iter()
            .map(|d| (d.mac.clone(), "home".to_string()))
            .collect();
        assert_eq!(advise(&segs_on, &devs, &s, &home).len(), 1);
        // after the plan: untrusted in their own groups -> no finding
        let mut grp = home.clone();
        grp.insert("aa:00:00:00:00:03".into(), "cameras".into());
        grp.insert("aa:00:00:00:00:04".into(), "printers".into());
        assert!(advise(&segs_on, &devs, &s, &grp).is_empty());
    }

    #[test]
    fn plan_uses_configured_groups_services_and_vlans() {
        let mut s = Settings::defaults();
        s.values.insert("group_camera".into(), "cams".into());
        s.values.insert("internet_camera".into(), "deny".into());
        let devs = vec![
            dev("aa:00:00:00:00:02", "work-laptop", "computer", "@lan"),
            dev("aa:00:00:00:00:03", "driveway-cam", "camera", "@lan"),
            dev("aa:00:00:00:00:04", "office-printer", "printer", "@lan"),
            dev("aa:00:00:00:00:06", "living-tv", "media", "@lan"),
        ];
        let p = plan(
            "@lan",
            false,
            &devs,
            &s,
            &BTreeSet::from(["printers".to_string()]),
        );
        assert!(p.enable_isolation);
        assert_eq!(p.moves.len(), 3);
        let cams = p.groups.iter().find(|g| g.class == "camera").unwrap();
        assert_eq!(
            (
                cams.name.as_str(),
                cams.internet.as_str(),
                cams.intra,
                cams.exists
            ),
            ("cams", "deny", false, false)
        );
        assert!(
            p.groups
                .iter()
                .find(|g| g.name == "printers")
                .unwrap()
                .exists
        );
        assert!(p
            .services
            .iter()
            .any(|x| x.dst == "printers" && x.ports == "631,9100" && x.src == "home"));
        assert!(p
            .services
            .iter()
            .any(|x| x.dst == "cams" && x.ports == "80,443,554"));
        assert_eq!(p.links, vec![("home".to_string(), "media".to_string())]);
        assert_eq!(p.vlan_plan[0].1, 20);
        assert_eq!(p.vlan_plan[1].1, 30);
        for sv in &p.services {
            assert!(crate::seg::is_name(&sv.name), "{}", sv.name);
        }
    }
}
