//! Declarative service pages (settings + row collections) shared by the
//! daemon-backed features that need a form and a table, nothing exotic:
//! syslog forwarding, NetFlow export, IGMP proxy, NAT64, L2TP, IDS, ...
//!
//! A feature describes itself with a [`Spec`] (typed fields, row
//! collections, which applier makes it real). This module validates every
//! value by its [`Kind`] (what ends up in a daemon config only ever passes
//! through a kind that cannot carry a newline or a quote), stores settings in
//! `lan_settings` (`<slug>.<key>`) and rows in the feature's own table, and
//! the web crate renders one generic page + `/api/svc/<slug>` from it. The
//! feature's applier turns the stored values into files, daemons and kernel
//! state; undo-on-failure is the LAN manager's (tables are in `LAN_TABLES`).

use crate::lan::{self, check_description, db_err, invalid, now};
use async_trait::async_trait;
use patronus_config::store::ConfigStore;
use patronus_core::{Error, Result};
use serde_json::{json, Map, Value};
use sqlx::Row;
use std::net::IpAddr;
use std::sync::Arc;

/// What a field holds (and how it is validated before it can reach a config).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Bool,
    /// Free one-line text, <= 200 chars, no control characters. Never put
    /// this into a daemon config; descriptions and notes only.
    Text,
    /// `[A-Za-z0-9._:/@+-]`, 1..=64 chars (user names, realms, paths-free ids).
    Token,
    Int(i64, i64),
    Select(&'static [&'static str]),
    /// `@wan`, `@lan`, `@optN` or a device name.
    Iface,
    /// IP address or DNS name.
    Host,
    Ip,
    Ipv4,
    Ipv6,
    /// IPv4/IPv6 address with prefix length.
    Cidr,
    Cidr4,
    Cidr6,
    Mac,
    /// Stored, never returned (`"********"` when set); `"********"` or empty on
    /// write keeps the stored value. 8..=128 printable ASCII without quotes.
    Secret,
}

pub const SECRET_MASK: &str = "********";

#[derive(Debug, Clone, Copy)]
pub struct Field {
    pub key: &'static str,
    pub label: &'static str,
    pub kind: Kind,
    pub required: bool,
    pub default: &'static str,
    pub help: &'static str,
}

impl Field {
    pub const fn new(key: &'static str, label: &'static str, kind: Kind) -> Self {
        Self {
            key,
            label,
            kind,
            required: false,
            default: "",
            help: "",
        }
    }
    pub const fn req(mut self) -> Self {
        self.required = true;
        self
    }
    pub const fn def(mut self, d: &'static str) -> Self {
        self.default = d;
        self
    }
    pub const fn help(mut self, h: &'static str) -> Self {
        self.help = h;
        self
    }
}

/// A table of rows (one per `Field` plus `id`, `updated_at`).
#[derive(Debug, Clone, Copy)]
pub struct Coll {
    pub key: &'static str,
    pub title: &'static str,
    pub table: &'static str,
    pub fields: &'static [Field],
    /// Field whose value must be unique across rows.
    pub unique: Option<&'static str>,
}

#[derive(Debug, Clone, Copy)]
pub struct Spec {
    pub slug: &'static str,
    pub title: &'static str,
    pub blurb: &'static str,
    /// Applier that makes the stored values real.
    pub applier: &'static str,
    pub fields: &'static [Field],
    pub colls: &'static [Coll],
    /// Named buttons: (name, label, confirm text).
    pub actions: &'static [(&'static str, &'static str)],
}

/// One feature page. Defaults implement everything from the [`Spec`].
#[async_trait]
pub trait Svc: Send + Sync {
    fn spec(&self) -> &'static Spec;

    /// `{settings:{..}, collections:{key:[rows]}}`
    async fn get(&self, store: &ConfigStore) -> Result<Value> {
        let spec = self.spec();
        let mut cols = Map::new();
        for c in spec.colls {
            cols.insert(c.key.into(), Value::Array(list_rows(store, c).await?));
        }
        Ok(json!({"settings": get_settings(store, spec).await?, "collections": cols}))
    }

    async fn put(&self, store: &ConfigStore, body: &Value) -> Result<()> {
        put_settings(store, self.spec(), body).await
    }

    async fn save_row(
        &self,
        store: &ConfigStore,
        coll: &str,
        id: Option<i64>,
        body: &Value,
    ) -> Result<i64> {
        let c = find_coll(self.spec(), coll)?;
        save_row(store, c, id, body).await
    }

    async fn delete_row(&self, store: &ConfigStore, coll: &str, id: i64) -> Result<()> {
        let c = find_coll(self.spec(), coll)?;
        delete_row(store, c, id).await
    }

    /// A button (`spec().actions`). `Ok` is the JSON answer.
    async fn action(&self, _store: &ConfigStore, name: &str, _body: &Value) -> Result<Value> {
        Err(Error::Config(format!(
            "Invalid request: no action {name:?}"
        )))
    }

    /// Actions that must run as root (through applyd) use the applier; the
    /// default runs in the caller's process.
    fn action_applier(&self) -> bool {
        false
    }
}

/// Every feature page compiled into this build.
#[allow(clippy::vec_init_then_push)]
pub fn all() -> Vec<Arc<dyn Svc>> {
    #[allow(unused_mut)]
    let mut v: Vec<Arc<dyn Svc>> = Vec::new();
    #[cfg(feature = "syslog")]
    v.push(Arc::new(crate::syslog::SyslogSvc));
    #[cfg(feature = "netflow")]
    v.push(Arc::new(crate::netflow::NetflowSvc));
    #[cfg(feature = "igmp")]
    v.push(Arc::new(crate::igmp::IgmpSvc));
    #[cfg(feature = "nat64")]
    v.push(Arc::new(crate::nat64::Nat64Svc));
    #[cfg(feature = "l2tp")]
    v.push(Arc::new(crate::l2tp::L2tpSvc));
    #[cfg(feature = "intrusion-detection")]
    v.push(Arc::new(crate::ids::IdsSvc));
    #[cfg(feature = "dynamic-routing")]
    v.push(Arc::new(crate::frr::FrrSvc));
    v.push(Arc::new(crate::wol::WolSvc));
    #[cfg(feature = "sdwan-edge")]
    v.push(Arc::new(crate::edge::EdgeSvc));
    v
}

pub fn find(slug: &str) -> Option<Arc<dyn Svc>> {
    all().into_iter().find(|s| s.spec().slug == slug)
}

/// Tables owned by the feature pages (for the lane undo snapshot).
pub const SVC_TABLES: &[&str] = &[
    "syslog_targets",
    "igmp_interfaces",
    "l2tp_users",
    "ids_rules",
    "frr_bgp_neighbors",
    "frr_bgp_networks",
    "frr_ospf_interfaces",
    "wol_hosts",
    "edge_endpoints",
    "edge_subnets",
];

pub fn find_coll(spec: &Spec, key: &str) -> Result<&'static Coll> {
    spec.colls
        .iter()
        .find(|c| c.key == key)
        .ok_or_else(|| invalid(format!("request: no collection {key:?}")))
}

// ---------------------------------------------------------------------------
// validation
// ---------------------------------------------------------------------------

fn as_text(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.trim().to_string()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

fn valid_host(s: &str) -> bool {
    s.parse::<IpAddr>().is_ok() || lan::valid_dns_name(s, false)
}

/// Validate one value for `f`; the normalised string form is what is stored.
pub fn check(f: &Field, v: &Value) -> Result<String> {
    let bad = |why: &str| invalid(format!("{} ({why})", f.label.to_lowercase()));
    let Some(t) = as_text(v) else {
        return Err(bad("expected a value"));
    };
    if t.is_empty() {
        return if f.required {
            Err(bad("required"))
        } else {
            Ok(String::new())
        };
    }
    match f.kind {
        Kind::Bool => match t.as_str() {
            "1" | "true" | "yes" | "on" => Ok("1".into()),
            "0" | "false" | "no" | "off" => Ok("0".into()),
            _ => Err(bad("yes or no")),
        },
        Kind::Text => {
            check_description(Some(&t))?;
            Ok(t)
        }
        Kind::Token => {
            if t.len() <= 64
                && t.bytes().all(|b| {
                    b.is_ascii_alphanumeric()
                        || matches!(b, b'.' | b'_' | b':' | b'/' | b'@' | b'+' | b'-')
                })
            {
                Ok(t)
            } else {
                Err(bad("letters, digits and . _ : / @ + - only, at most 64"))
            }
        }
        Kind::Int(lo, hi) => match t.parse::<i64>() {
            Ok(n) if (lo..=hi).contains(&n) => Ok(n.to_string()),
            _ => Err(bad(&format!("a number from {lo} to {hi}"))),
        },
        Kind::Select(opts) => {
            if opts.contains(&t.as_str()) {
                Ok(t)
            } else {
                Err(bad(&format!("one of {}", opts.join(", "))))
            }
        }
        Kind::Iface => lan::check_iface_spec(&t),
        Kind::Host => {
            if valid_host(&t) {
                Ok(t.to_ascii_lowercase())
            } else {
                Err(bad("an IP address or host name"))
            }
        }
        Kind::Ip => t
            .parse::<IpAddr>()
            .map(|a| a.to_string())
            .map_err(|_| bad("an IP address")),
        Kind::Ipv4 => t
            .parse::<std::net::Ipv4Addr>()
            .map(|a| a.to_string())
            .map_err(|_| bad("an IPv4 address")),
        Kind::Ipv6 => t
            .parse::<std::net::Ipv6Addr>()
            .map(|a| a.to_string())
            .map_err(|_| bad("an IPv6 address")),
        Kind::Cidr | Kind::Cidr4 | Kind::Cidr6 => {
            let n: ipnetwork::IpNetwork = t.parse().map_err(|_| bad("an address/prefix"))?;
            match (f.kind, n) {
                (Kind::Cidr4, ipnetwork::IpNetwork::V6(_)) => Err(bad("an IPv4 address/prefix")),
                (Kind::Cidr6, ipnetwork::IpNetwork::V4(_)) => Err(bad("an IPv6 address/prefix")),
                _ => Ok(format!("{}/{}", n.ip(), n.prefix())),
            }
        }
        Kind::Mac => lan::check_mac(&t),
        Kind::Secret => {
            if t == SECRET_MASK {
                return Ok(t);
            }
            if (8..=128).contains(&t.len())
                && t.bytes().all(|b| {
                    (0x21..0x7f).contains(&b) && !matches!(b, b'"' | b'\\' | b'\'' | b'#' | b';')
                })
            {
                Ok(t)
            } else {
                Err(bad(
                    "8-128 printable characters, no quotes, # ; or backslash",
                ))
            }
        }
    }
}

fn render_value(f: &Field, stored: &str) -> Value {
    match f.kind {
        Kind::Bool => Value::Bool(lan::flag(stored)),
        Kind::Int(..) => stored
            .parse::<i64>()
            .map(Value::from)
            .unwrap_or(Value::Null),
        Kind::Secret => {
            if stored.is_empty() {
                Value::String(String::new())
            } else {
                Value::String(SECRET_MASK.into())
            }
        }
        _ => Value::String(stored.to_string()),
    }
}

// ---------------------------------------------------------------------------
// settings
// ---------------------------------------------------------------------------

fn skey(spec: &Spec, f: &Field) -> String {
    format!("{}.{}", spec.slug, f.key)
}

/// Raw stored strings (secrets included): what the applier reads.
pub async fn raw_settings(store: &ConfigStore, spec: &Spec) -> Result<Map<String, Value>> {
    let mut m = Map::new();
    for f in spec.fields {
        let v = lan::setting_or(store, &skey(spec, f), f.default).await?;
        m.insert(f.key.into(), Value::String(v));
    }
    Ok(m)
}

/// Typed accessors over [`raw_settings`] for appliers.
pub struct Settings(pub Map<String, Value>);

impl Settings {
    pub async fn load(store: &ConfigStore, spec: &Spec) -> Result<Self> {
        Ok(Self(raw_settings(store, spec).await?))
    }
    pub fn s(&self, k: &str) -> String {
        self.0
            .get(k)
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string()
    }
    pub fn b(&self, k: &str) -> bool {
        lan::flag(&self.s(k))
    }
    pub fn n(&self, k: &str) -> i64 {
        self.s(k).parse().unwrap_or(0)
    }
}

pub async fn get_settings(store: &ConfigStore, spec: &Spec) -> Result<Value> {
    let raw = raw_settings(store, spec).await?;
    let mut m = Map::new();
    for f in spec.fields {
        let s = raw.get(f.key).and_then(Value::as_str).unwrap_or("");
        m.insert(f.key.into(), render_value(f, s));
    }
    Ok(Value::Object(m))
}

pub async fn put_settings(store: &ConfigStore, spec: &Spec, body: &Value) -> Result<()> {
    let obj = body
        .as_object()
        .ok_or_else(|| invalid("request: a JSON object"))?;
    for k in obj.keys() {
        if !spec.fields.iter().any(|f| f.key == k) {
            return Err(invalid(format!("request: unknown setting {k:?}")));
        }
    }
    let mut writes = Vec::new();
    for f in spec.fields {
        let Some(v) = obj.get(f.key) else { continue };
        let s = check(f, v)?;
        if f.kind == Kind::Secret && (s == SECRET_MASK || s.is_empty()) {
            if s.is_empty() && obj.get(f.key).is_some_and(|v| v.as_str() == Some("")) && f.required
            {
                return Err(invalid(format!("{} (required)", f.label.to_lowercase())));
            }
            continue; // keep the stored secret
        }
        writes.push((skey(spec, f), s));
    }
    for (k, v) in writes {
        lan::set_setting(store, &k, &v).await?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// collections
// ---------------------------------------------------------------------------

fn col_sql(f: &Field) -> &'static str {
    match f.kind {
        Kind::Bool | Kind::Int(..) => "INTEGER",
        _ => "TEXT",
    }
}

/// Raw rows (secrets included) for appliers: `id` + every field as a string.
pub async fn raw_rows(store: &ConfigStore, c: &Coll) -> Result<Vec<Map<String, Value>>> {
    let cols: Vec<&str> = c.fields.iter().map(|f| f.key).collect();
    let sql = format!(
        "SELECT id, {} FROM {} ORDER BY id",
        cols.iter()
            .map(|c| format!("CAST({c} AS TEXT)"))
            .collect::<Vec<_>>()
            .join(", "),
        c.table
    );
    let rows = sqlx::query(&sql)
        .fetch_all(store.pool()?)
        .await
        .map_err(db_err("read rows"))?;
    Ok(rows
        .iter()
        .map(|r| {
            let mut m = Map::new();
            m.insert("id".into(), Value::from(r.get::<i64, _>(0)));
            for (i, f) in c.fields.iter().enumerate() {
                let v: Option<String> = r.get(i + 1);
                m.insert(f.key.into(), Value::String(v.unwrap_or_default()));
            }
            m
        })
        .collect())
}

pub async fn list_rows(store: &ConfigStore, c: &Coll) -> Result<Vec<Value>> {
    Ok(raw_rows(store, c)
        .await?
        .into_iter()
        .map(|r| {
            let mut m = Map::new();
            m.insert("id".into(), r["id"].clone());
            for f in c.fields {
                let s = r.get(f.key).and_then(Value::as_str).unwrap_or("");
                m.insert(f.key.into(), render_value(f, s));
            }
            Value::Object(m)
        })
        .collect())
}

pub async fn save_row(store: &ConfigStore, c: &Coll, id: Option<i64>, body: &Value) -> Result<i64> {
    let obj = body
        .as_object()
        .ok_or_else(|| invalid("request: a JSON object"))?;
    for k in obj.keys() {
        if !c.fields.iter().any(|f| f.key == k) {
            return Err(invalid(format!("request: unknown field {k:?}")));
        }
    }
    let all = raw_rows(store, c).await?;
    let cur = match id {
        Some(id) => Some(
            all.iter()
                .find(|r| r["id"].as_i64() == Some(id))
                .cloned()
                .ok_or_else(|| Error::Config(format!("no {} {id}", c.key)))?,
        ),
        None => None,
    };
    let mut vals: Vec<(&Field, String)> = Vec::new();
    for f in c.fields {
        let s = match (obj.get(f.key), &cur) {
            (Some(v), _) => {
                let s = check(f, v)?;
                if f.kind == Kind::Secret && (s == SECRET_MASK || s.is_empty()) {
                    match &cur {
                        Some(r) => r[f.key].as_str().unwrap_or("").to_string(),
                        None if f.required => {
                            return Err(invalid(format!("{} (required)", f.label.to_lowercase())))
                        }
                        None => String::new(),
                    }
                } else {
                    s
                }
            }
            (None, Some(r)) => r[f.key].as_str().unwrap_or("").to_string(),
            (None, None) => {
                if f.required && f.default.is_empty() {
                    return Err(invalid(format!("{} (required)", f.label.to_lowercase())));
                }
                if f.default.is_empty() {
                    String::new()
                } else {
                    check(f, &Value::String(f.default.into()))?
                }
            }
        };
        vals.push((f, s));
    }
    if let Some(u) = c.unique {
        let mine = vals
            .iter()
            .find(|(f, _)| f.key == u)
            .map(|(_, s)| s.clone());
        if all.iter().any(|r| {
            r["id"].as_i64() != id && Some(r[u].as_str().unwrap_or("").to_string()) == mine
        }) {
            return Err(invalid(format!(
                "request: {} {:?} already exists",
                u,
                mine.unwrap_or_default()
            )));
        }
    }
    let cols: Vec<&str> = vals.iter().map(|(f, _)| f.key).collect();
    let sql = if id.is_some() {
        format!(
            "UPDATE {} SET {}, updated_at = ? WHERE id = ?",
            c.table,
            cols.iter()
                .map(|c| format!("{c} = ?"))
                .collect::<Vec<_>>()
                .join(", ")
        )
    } else {
        format!(
            "INSERT INTO {} ({}, updated_at) VALUES ({}, ?)",
            c.table,
            cols.join(", "),
            vec!["?"; cols.len()].join(", ")
        )
    };
    let mut q = sqlx::query(&sql);
    for (f, s) in &vals {
        q = match col_sql(f) {
            "INTEGER" => q.bind(if s.is_empty() {
                None
            } else {
                s.parse::<i64>().ok()
            }),
            _ => q.bind(if s.is_empty() { None } else { Some(s.clone()) }),
        };
    }
    q = q.bind(now());
    if let Some(id) = id {
        q = q.bind(id);
    }
    let r = q
        .execute(store.pool()?)
        .await
        .map_err(|e| Error::Config(format!("save {}: {e}", c.key)))?;
    Ok(id.unwrap_or_else(|| r.last_insert_rowid()))
}

pub async fn delete_row(store: &ConfigStore, c: &Coll, id: i64) -> Result<()> {
    let r = sqlx::query(&format!("DELETE FROM {} WHERE id = ?", c.table))
        .bind(id)
        .execute(store.pool()?)
        .await
        .map_err(db_err("delete row"))?;
    if r.rows_affected() == 0 {
        return Err(Error::Config(format!("no {} {id}", c.key)));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// daemons run by the supervisor (patronus-daemon@<instance>)
// ---------------------------------------------------------------------------

/// Service name of the generic supervised daemon units
/// (`patronus-daemon@<instance>.service`, OpenRC `patronus-daemon.<instance>`).
pub const DAEMON_SERVICE: &str = "patronus-daemon";

/// Make sure `instance` runs `argv` with exactly these generated files.
/// Returns true when it was (re)started.
pub async fn ensure_daemon(
    sup: &crate::supervise::Supervisor,
    instance: &str,
    argv: Vec<String>,
    files: Vec<(std::path::PathBuf, String, u32)>,
) -> Result<bool> {
    sup.ensure(&crate::supervise::DaemonSpec {
        service: DAEMON_SERVICE,
        instance: instance.to_string(),
        argv,
        files,
    })
    .await
}

/// Stop every `patronus-daemon` instance whose name starts with `prefix`
/// and is not in `keep`. Returns the stopped instance names.
pub async fn stop_daemons(
    sup: &crate::supervise::Supervisor,
    prefix: &str,
    keep: &[String],
) -> Result<Vec<String>> {
    let mut stopped = Vec::new();
    for inst in sup.instances(DAEMON_SERVICE) {
        if inst.starts_with(prefix)
            && !keep.contains(&inst)
            && sup.stop(DAEMON_SERVICE, &inst).await?
        {
            stopped.push(inst);
        }
    }
    Ok(stopped)
}

/// Instances (name, running) of daemons starting with `prefix`.
pub fn daemon_states(sup: &crate::supervise::Supervisor, prefix: &str) -> Vec<(String, bool)> {
    sup.instances(DAEMON_SERVICE)
        .into_iter()
        .filter(|i| i.starts_with(prefix))
        .map(|i| {
            let r = sup.is_running(DAEMON_SERVICE, &i);
            (i, r)
        })
        .collect()
}

/// Last `n` lines of a text file (reads at most the last 256 KiB).
pub fn tail_lines(path: &std::path::Path, n: usize) -> Vec<String> {
    use std::io::{Read, Seek, SeekFrom};
    let Ok(mut f) = std::fs::File::open(path) else {
        return Vec::new();
    };
    let len = f.metadata().map(|m| m.len()).unwrap_or(0);
    let start = len.saturating_sub(256 * 1024);
    let _ = f.seek(SeekFrom::Start(start));
    let mut buf = String::new();
    let _ = f.read_to_string(&mut buf);
    let lines: Vec<&str> = buf.lines().collect();
    let skip = if start > 0 { 1 } else { 0 };
    let lines = &lines[skip.min(lines.len())..];
    lines[lines.len().saturating_sub(n)..]
        .iter()
        .map(|s| s.to_string())
        .collect()
}

// ---------------------------------------------------------------------------
// schema for the generic page
// ---------------------------------------------------------------------------

fn field_json(f: &Field) -> Value {
    let (t, extra) = match f.kind {
        Kind::Bool => ("bool", Value::Null),
        Kind::Int(lo, hi) => ("number", json!({"min": lo, "max": hi})),
        Kind::Select(o) => ("select", json!(o)),
        Kind::Secret => ("secret", Value::Null),
        _ => ("text", Value::Null),
    };
    json!({"key": f.key, "label": f.label, "type": t, "extra": extra,
           "required": f.required, "default": f.default, "help": f.help})
}

pub fn schema(spec: &Spec) -> Value {
    json!({
        "slug": spec.slug,
        "title": spec.title,
        "blurb": spec.blurb,
        "fields": spec.fields.iter().map(field_json).collect::<Vec<_>>(),
        "actions": spec.actions.iter().map(|(n, l)| json!({"name": n, "label": l})).collect::<Vec<_>>(),
        "collections": spec.colls.iter().map(|c| json!({
            "key": c.key, "title": c.title,
            "fields": c.fields.iter().map(field_json).collect::<Vec<_>>(),
        })).collect::<Vec<_>>(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const F_PORT: Field = Field::new("port", "Port", Kind::Int(1, 65535)).req();
    const F_HOST: Field = Field::new("host", "Host", Kind::Host).req();
    const F_PROTO: Field =
        Field::new("proto", "Protocol", Kind::Select(&["udp", "tcp"])).def("udp");
    const F_ON: Field = Field::new("enabled", "Enabled", Kind::Bool).def("1");
    const F_PSK: Field = Field::new("psk", "Secret", Kind::Secret);
    static COLL_FIELDS: [Field; 5] = [F_HOST, F_PORT, F_PROTO, F_ON, F_PSK];
    static COLL: Coll = Coll {
        key: "targets",
        title: "Targets",
        table: "syslog_targets",
        fields: &[],
        unique: None,
    };

    #[test]
    fn values_are_validated_by_kind() {
        assert_eq!(check(&F_PORT, &json!(514)).unwrap(), "514");
        assert!(check(&F_PORT, &json!(0)).is_err());
        assert!(check(&F_PORT, &json!("514; rm")).is_err());
        assert_eq!(
            check(&F_HOST, &json!("Log.Example.com")).unwrap(),
            "log.example.com"
        );
        assert!(check(&F_HOST, &json!("a b")).is_err());
        assert!(check(&F_HOST, &json!("x\ny")).is_err());
        assert!(check(&F_PROTO, &json!("icmp")).is_err());
        assert_eq!(check(&F_ON, &json!(true)).unwrap(), "1");
        assert!(check(&F_PSK, &json!("short")).is_err());
        assert!(check(&F_PSK, &json!("has\"quote-1234")).is_err());
        assert_eq!(
            check(&F_PSK, &json!("good-secret-1")).unwrap(),
            "good-secret-1"
        );
        let cidr = Field::new("n", "Net", Kind::Cidr4);
        assert_eq!(check(&cidr, &json!("10.1.2.3/24")).unwrap(), "10.1.2.3/24");
        assert!(check(&cidr, &json!("fd00::/64")).is_err());
        let _ = (&COLL, &COLL_FIELDS);
    }

    #[test]
    fn secrets_are_masked_on_the_way_out() {
        assert_eq!(render_value(&F_PSK, "good-secret-1"), json!(SECRET_MASK));
        assert_eq!(render_value(&F_PSK, ""), json!(""));
    }
}
