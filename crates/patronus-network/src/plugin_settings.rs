//! Schema-driven settings of signed plugins (USE=plugins).
//!
//! A plugin's signed manifest may carry `settings`: a typed schema (string,
//! int, bool, enum, address, port, list) with limits, a hint, a default and a
//! `secret` flag. Patronus then
//!
//! - validates every saved value against that schema on the server (the form
//!   on the Packages page is only a rendering of the same schema),
//! - keeps the values in the config store (`plugin_settings`, so they ride
//!   along in export/import, revisions and GitOps `kind: PluginSettings`),
//! - never sends a secret value back to a browser (the API says only whether
//!   one is set),
//! - writes the effective values for the plugin's service into 0600 files
//!   next to the plugin directory: `<plugins>/<name>.settings.json` (JSON
//!   object) and `<plugins>/<name>.settings.env` (`PLUGIN_<KEY>='value'`
//!   lines for shell services). The service finds them through the `{settings}`
//!   and `{settings_env}` placeholders in its `exec` arguments.
//!
//! The limits below are format limits of the schema itself (they keep a signed
//! manifest from being used to exhaust the box), not operational values.

use crate::lan;
use patronus_config::store::ConfigStore;
use patronus_core::{Error, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use sqlx::Row;
use std::collections::BTreeMap;
use std::net::IpAddr;

pub const MAX_SETTINGS: usize = 64;
const MAX_TEXT: usize = 4096;
const MAX_LIST_ITEMS: i64 = 256;
const MAX_PATTERN: usize = 200;

fn invalid(m: impl Into<String>) -> Error {
    lan::invalid(m.into())
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    String,
    Int,
    Bool,
    Enum,
    Address,
    Port,
    List,
}

/// One setting of a plugin, as the signed manifest declares it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Setting {
    pub key: String,
    #[serde(rename = "type")]
    pub kind: Kind,
    #[serde(default)]
    pub label: String,
    /// Shown on hover AND keyboard focus of the field.
    #[serde(default)]
    pub hint: String,
    #[serde(default)]
    pub default: Option<Value>,
    /// int/port: value bounds; string: length; list: item count.
    #[serde(default)]
    pub min: Option<i64>,
    #[serde(default)]
    pub max: Option<i64>,
    /// string (and list of string): the whole value must match.
    #[serde(default)]
    pub pattern: Option<String>,
    /// enum: the allowed values.
    #[serde(default)]
    pub values: Vec<String>,
    /// list: item type (`string` when absent).
    #[serde(default)]
    pub item: Option<Kind>,
    /// list of int/port: item bounds.
    #[serde(default)]
    pub item_min: Option<i64>,
    #[serde(default)]
    pub item_max: Option<i64>,
    #[serde(default)]
    pub secret: bool,
    #[serde(default)]
    pub required: bool,
}

fn valid_key(k: &str) -> bool {
    let b = k.as_bytes();
    !b.is_empty()
        && b.len() <= 40
        && b[0].is_ascii_lowercase()
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'_')
}

fn printable(s: &str) -> bool {
    !s.chars().any(|c| c.is_control())
}

fn compile(p: &str) -> Result<regex::Regex> {
    if p.len() > MAX_PATTERN {
        return Err(invalid(format!("pattern longer than {MAX_PATTERN} characters")));
    }
    regex::RegexBuilder::new(&format!("^(?:{p})$"))
        .size_limit(1 << 20)
        .build()
        .map_err(|_| invalid("pattern is not a valid regular expression"))
}

/// Check a schema on its own (called from `check_manifest`).
pub fn check_schema(list: &[Setting]) -> Result<()> {
    if list.len() > MAX_SETTINGS {
        return Err(invalid(format!("settings: at most {MAX_SETTINGS}")));
    }
    let mut seen = std::collections::BTreeSet::new();
    for s in list {
        let ctx = |m: &str| invalid(format!("setting {:?}: {m}", s.key));
        if !valid_key(&s.key) {
            return Err(ctx("key is lowercase letters, digits and '_', starting with a letter, at most 40"));
        }
        if !seen.insert(s.key.clone()) {
            return Err(ctx("listed twice"));
        }
        if s.label.len() > 80 || !printable(&s.label) || s.hint.len() > 400 || !printable(&s.hint)
        {
            return Err(ctx("label (80) or hint (400) too long or not printable"));
        }
        let numeric = matches!(s.kind, Kind::Int | Kind::Port);
        if (s.min.is_some() || s.max.is_some())
            && !matches!(s.kind, Kind::Int | Kind::Port | Kind::String | Kind::List)
        {
            return Err(ctx("min/max apply to int, port, string and list only"));
        }
        if let (Some(a), Some(b)) = (s.min, s.max) {
            if a > b {
                return Err(ctx("min is larger than max"));
            }
        }
        if s.kind == Kind::Port && (s.min.is_some_and(|m| m < 1) || s.max.is_some_and(|m| m > 65535))
        {
            return Err(ctx("port limits stay within 1-65535"));
        }
        if matches!(s.kind, Kind::String | Kind::List) && s.min.is_some_and(|m| m < 0) {
            return Err(ctx("length/count limits are not negative"));
        }
        if s.kind == Kind::List && s.max.is_some_and(|m| m > MAX_LIST_ITEMS) {
            return Err(ctx("a list holds at most 256 items"));
        }
        if s.kind == Kind::String && s.max.is_some_and(|m| m > MAX_TEXT as i64) {
            return Err(ctx("a string holds at most 4096 characters"));
        }
        if let Some(p) = &s.pattern {
            if !(s.kind == Kind::String || (s.kind == Kind::List && item_kind(s) == Kind::String)) {
                return Err(ctx("pattern applies to strings and lists of strings"));
            }
            compile(p).map_err(|e| ctx(&e.to_string()))?;
        }
        if s.kind == Kind::Enum {
            if s.values.is_empty()
                || s.values.len() > 64
                || s.values
                    .iter()
                    .any(|v| v.is_empty() || v.len() > 80 || !printable(v))
                || s.values.iter().collect::<std::collections::BTreeSet<_>>().len() != s.values.len()
            {
                return Err(ctx("an enum needs 1-64 distinct values of 1-80 printable characters"));
            }
        } else if !s.values.is_empty() {
            return Err(ctx("values apply to enum only"));
        }
        if s.kind == Kind::List {
            if matches!(item_kind(s), Kind::List | Kind::Bool | Kind::Enum) {
                return Err(ctx("list items are string, int, address or port"));
            }
            let item_num = matches!(item_kind(s), Kind::Int | Kind::Port);
            if (s.item_min.is_some() || s.item_max.is_some()) && !item_num {
                return Err(ctx("item_min/item_max apply to lists of int or port"));
            }
        } else if s.item.is_some() || s.item_min.is_some() || s.item_max.is_some() {
            return Err(ctx("item, item_min and item_max apply to lists only"));
        }
        let _ = numeric;
        if s.secret {
            if s.kind != Kind::String {
                return Err(ctx("only a string can be secret"));
            }
            if s.default.is_some() {
                return Err(ctx("a secret has no default (the signed bundle is not secret)"));
            }
        }
        if let Some(d) = &s.default {
            validate_value(s, d).map_err(|e| ctx(&format!("default: {e}")))?;
        }
    }
    Ok(())
}

fn item_kind(s: &Setting) -> Kind {
    s.item.unwrap_or(Kind::String)
}

fn as_int(v: &Value) -> Option<i64> {
    match v {
        Value::Number(n) => n.as_i64(),
        Value::String(t) => {
            let t = t.trim();
            if t.is_empty() || t.len() > 18 {
                None
            } else {
                t.parse().ok()
            }
        }
        _ => None,
    }
}

fn scalar(
    kind: Kind,
    s: &Setting,
    v: &Value,
    min: Option<i64>,
    max: Option<i64>,
    what: &str,
) -> Result<Value> {
    let bad = |m: String| invalid(format!("{what}: {m}"));
    match kind {
        Kind::String => {
            let Value::String(t) = v else {
                return Err(bad("must be text".into()));
            };
            if t.chars().any(|c| c.is_control() && c != '\n' && c != '\t') || t.contains('\0') {
                return Err(bad("contains control characters".into()));
            }
            let n = t.chars().count() as i64;
            if n > MAX_TEXT as i64 {
                return Err(bad("longer than 4096 characters".into()));
            }
            if min.is_some_and(|m| n < m) {
                return Err(bad(format!("shorter than {} characters", min.unwrap())));
            }
            if max.is_some_and(|m| n > m) {
                return Err(bad(format!("longer than {} characters", max.unwrap())));
            }
            if let Some(p) = &s.pattern {
                if !compile(p)?.is_match(t) {
                    return Err(bad("does not match the required format".into()));
                }
            }
            Ok(json!(t))
        }
        Kind::Int | Kind::Port => {
            let Some(n) = as_int(v) else {
                return Err(bad("must be a whole number".into()));
            };
            let (lo, hi) = if kind == Kind::Port {
                (min.unwrap_or(1).max(1), max.unwrap_or(65535).min(65535))
            } else {
                (min.unwrap_or(i64::MIN), max.unwrap_or(i64::MAX))
            };
            if n < lo || n > hi {
                return Err(bad(if kind == Kind::Port && min.is_none() && max.is_none() {
                    "must be a port, 1-65535".to_string()
                } else if lo == i64::MIN {
                    format!("must be at most {hi}")
                } else if hi == i64::MAX {
                    format!("must be at least {lo}")
                } else {
                    format!("must be between {lo} and {hi}")
                }));
            }
            Ok(json!(n))
        }
        Kind::Bool => match v {
            Value::Bool(b) => Ok(json!(b)),
            Value::String(t) if t == "true" => Ok(json!(true)),
            Value::String(t) if t == "false" => Ok(json!(false)),
            _ => Err(bad("must be true or false".into())),
        },
        Kind::Enum => match v {
            Value::String(t) if s.values.contains(t) => Ok(json!(t)),
            _ => Err(bad(format!("must be one of {}", s.values.join(", ")))),
        },
        Kind::Address => match v {
            Value::String(t) => t
                .trim()
                .parse::<IpAddr>()
                .map(|a| json!(a.to_string()))
                .map_err(|_| bad("must be an IPv4 or IPv6 address".into())),
            _ => Err(bad("must be an IP address".into())),
        },
        Kind::List => Err(bad("lists nest nowhere".into())),
    }
}

/// Validate and normalise one value against its schema entry.
pub fn validate_value(s: &Setting, v: &Value) -> Result<Value> {
    let what = if s.label.is_empty() { &s.key } else { &s.label };
    if s.kind == Kind::List {
        let Value::Array(items) = v else {
            return Err(invalid(format!("{what}: must be a list")));
        };
        let n = items.len() as i64;
        if s.min.is_some_and(|m| n < m) {
            return Err(invalid(format!("{what}: at least {} entries", s.min.unwrap())));
        }
        if n > s.max.unwrap_or(MAX_LIST_ITEMS).min(MAX_LIST_ITEMS) {
            return Err(invalid(format!(
                "{what}: at most {} entries",
                s.max.unwrap_or(MAX_LIST_ITEMS).min(MAX_LIST_ITEMS)
            )));
        }
        let ik = item_kind(s);
        let mut out = Vec::new();
        for (i, it) in items.iter().enumerate() {
            let w = format!("{what} entry {}", i + 1);
            let (lo, hi) = if ik == Kind::String {
                (None, None)
            } else {
                (s.item_min, s.item_max)
            };
            out.push(scalar(ik, s, it, lo, hi, &w)?);
        }
        return Ok(Value::Array(out));
    }
    scalar(s.kind, s, v, s.min, s.max, what)
}

// ------------------------------------------------------------------ store

fn db(what: &'static str) -> impl Fn(sqlx::Error) -> Error {
    move |e| Error::Config(format!("{what}: {e}"))
}

/// Raw stored values of one plugin.
pub async fn stored(store: &ConfigStore, plugin: &str) -> Result<BTreeMap<String, Value>> {
    let rows = sqlx::query("SELECT setting, value FROM plugin_settings WHERE plugin = ?")
        .bind(plugin)
        .fetch_all(store.pool()?)
        .await
        .map_err(db("read plugin_settings"))?;
    Ok(rows
        .iter()
        .filter_map(|r| {
            let v: String = r.get(1);
            Some((r.get::<String, _>(0), serde_json::from_str(&v).ok()?))
        })
        .collect())
}

/// Stored value, else the schema default.
fn effective_value(s: &Setting, st: &BTreeMap<String, Value>) -> Option<Value> {
    st.get(&s.key).cloned().or_else(|| s.default.clone())
}

/// The values the plugin's service gets. A required setting with neither a
/// value nor a default is an error: the service is not started without it.
pub async fn effective(
    store: &ConfigStore,
    plugin: &str,
    schema: &[Setting],
) -> Result<Map<String, Value>> {
    let st = stored(store, plugin).await?;
    let mut out = Map::new();
    for s in schema {
        match effective_value(s, &st) {
            Some(v) => {
                out.insert(s.key.clone(), v);
            }
            None if s.required => {
                return Err(invalid(format!(
                    "setting {} is required and has no value yet",
                    if s.label.is_empty() { &s.key } else { &s.label }
                )))
            }
            None => {}
        }
    }
    Ok(out)
}

/// What the Packages page renders: the schema plus current values. A secret's
/// value is never included, only whether one is set.
pub async fn view(store: &ConfigStore, plugin: &str, schema: &[Setting]) -> Result<Vec<Value>> {
    let st = stored(store, plugin).await?;
    Ok(schema
        .iter()
        .map(|s| {
            let mut o = serde_json::to_value(s).unwrap_or(json!({}));
            let obj = o.as_object_mut().unwrap();
            if obj.get("label").and_then(|l| l.as_str()) == Some("") {
                obj.insert("label".into(), json!(s.key));
            }
            // the schema's own default never carries a secret (check_schema)
            let cur = st.get(&s.key);
            if s.secret {
                obj.insert("value".into(), Value::Null);
                obj.insert("is_set".into(), json!(cur.is_some()));
            } else {
                obj.insert("value".into(), effective_value(s, &st).unwrap_or(Value::Null));
                obj.insert("is_set".into(), json!(cur.is_some()));
            }
            o
        })
        .collect())
}

/// Save values from the form/API. `values` holds the keys to change; a secret
/// sent as an empty string keeps its current value; `clear` removes stored
/// values (back to the default). Unknown keys are refused. All or nothing.
pub async fn save(
    store: &ConfigStore,
    plugin: &str,
    schema: &[Setting],
    values: &Map<String, Value>,
    clear: &[String],
) -> Result<()> {
    let by: BTreeMap<&str, &Setting> = schema.iter().map(|s| (s.key.as_str(), s)).collect();
    let mut set: Vec<(&Setting, Value)> = Vec::new();
    for (k, v) in values {
        let Some(s) = by.get(k.as_str()) else {
            return Err(invalid(format!("setting {k:?}: the plugin has no such setting")));
        };
        if s.secret && v.as_str() == Some("") {
            continue;
        }
        set.push((s, validate_value(s, v)?));
    }
    for k in clear {
        if !by.contains_key(k.as_str()) {
            return Err(invalid(format!("setting {k:?}: the plugin has no such setting")));
        }
    }
    let mut tx = store.pool()?.begin().await.map_err(db("begin"))?;
    for k in clear {
        sqlx::query("DELETE FROM plugin_settings WHERE plugin = ? AND setting = ?")
            .bind(plugin)
            .bind(k)
            .execute(&mut *tx)
            .await
            .map_err(db("clear plugin setting"))?;
    }
    for (s, v) in &set {
        sqlx::query(
            "INSERT INTO plugin_settings (plugin, setting, value, secret) VALUES (?, ?, ?, ?)
             ON CONFLICT(plugin, setting) DO UPDATE SET value = excluded.value, secret = excluded.secret",
        )
        .bind(plugin)
        .bind(&s.key)
        .bind(v.to_string())
        .bind(s.secret as i64)
        .execute(&mut *tx)
        .await
        .map_err(db("save plugin setting"))?;
    }
    tx.commit().await.map_err(db("commit"))?;
    Ok(())
}

/// After an install/update: drop stored values the new schema no longer has or
/// no longer accepts (they fall back to the default).
pub async fn reconcile(store: &ConfigStore, plugin: &str, schema: &[Setting]) -> Result<Vec<String>> {
    let st = stored(store, plugin).await?;
    let mut dropped = Vec::new();
    for (k, v) in st {
        let ok = schema
            .iter()
            .find(|s| s.key == k)
            .is_some_and(|s| validate_value(s, &v).is_ok());
        if !ok {
            sqlx::query("DELETE FROM plugin_settings WHERE plugin = ? AND setting = ?")
                .bind(plugin)
                .bind(&k)
                .execute(store.pool()?)
                .await
                .map_err(db("drop plugin setting"))?;
            dropped.push(k);
        }
    }
    Ok(dropped)
}

pub async fn delete_all(store: &ConfigStore, plugin: &str) -> Result<()> {
    sqlx::query("DELETE FROM plugin_settings WHERE plugin = ?")
        .bind(plugin)
        .execute(store.pool()?)
        .await
        .map_err(db("delete plugin settings"))?;
    Ok(())
}

/// GitOps `kind: PluginSettings`: `spec` is `{key: value}`. The declared keys
/// replace the stored ones (a key left out goes back to its default), except
/// that a secret left out is kept, so a repository need not carry it.
pub async fn gitops_replace(
    store: &ConfigStore,
    plugin: &str,
    schema: &[Setting],
    spec: &Value,
) -> Result<()> {
    let Some(obj) = spec.as_object() else {
        return Err(invalid("PluginSettings spec must be an object"));
    };
    let clear: Vec<String> = schema
        .iter()
        .filter(|s| !s.secret && !obj.contains_key(&s.key))
        .map(|s| s.key.clone())
        .collect();
    save(store, plugin, schema, obj, &clear).await
}

// ----------------------------------------------------------- service files

/// JSON object file content for the service.
pub fn render_json(values: &Map<String, Value>) -> String {
    serde_json::to_string_pretty(&Value::Object(values.clone())).unwrap_or_else(|_| "{}".into()) + "\n"
}

fn sh_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// `PLUGIN_<KEY>='value'` lines (lists as compact JSON), for shell services.
pub fn render_env(values: &Map<String, Value>) -> String {
    let mut out = String::from("# Generated by Patronus from the plugin's settings; do not edit.\n");
    for (k, v) in values {
        let text = match v {
            Value::String(s) => s.clone(),
            other => other.to_string(),
        };
        out.push_str(&format!("PLUGIN_{}={}\n", k.to_ascii_uppercase(), sh_quote(&text)));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn st(kind: Kind, key: &str) -> Setting {
        Setting {
            key: key.into(),
            kind,
            label: String::new(),
            hint: String::new(),
            default: None,
            min: None,
            max: None,
            pattern: None,
            values: vec![],
            item: None,
            item_min: None,
            item_max: None,
            secret: false,
            required: false,
        }
    }

    fn schema() -> Vec<Setting> {
        let mut interval = st(Kind::Int, "interval");
        interval.min = Some(5);
        interval.max = Some(3600);
        interval.default = Some(json!(60));
        let mut name = st(Kind::String, "name");
        name.pattern = Some("[a-z][a-z0-9-]*".into());
        name.max = Some(20);
        let mut mode = st(Kind::Enum, "mode");
        mode.values = vec!["fast".into(), "safe".into()];
        mode.default = Some(json!("safe"));
        let mut token = st(Kind::String, "token");
        token.secret = true;
        token.required = true;
        let mut port = st(Kind::Port, "listen");
        port.min = Some(1024);
        let mut hosts = st(Kind::List, "hosts");
        hosts.item = Some(Kind::Address);
        hosts.max = Some(3);
        vec![interval, name, mode, token, st(Kind::Bool, "debug"), port, hosts, st(Kind::Address, "gw")]
    }

    #[test]
    fn the_schema_itself_is_checked() {
        assert!(check_schema(&schema()).is_ok());
        let bad = |f: &dyn Fn(&mut Setting)| {
            let mut s = st(Kind::Int, "x");
            f(&mut s);
            check_schema(&[s]).is_err()
        };
        assert!(bad(&|s| s.key = "Bad-Key".into()));
        assert!(bad(&|s| {
            s.min = Some(9);
            s.max = Some(1)
        }));
        assert!(bad(&|s| s.default = Some(json!("text"))));
        assert!(bad(&|s| s.values = vec!["a".into()]), "values on an int");
        assert!(bad(&|s| s.pattern = Some("a".into())), "pattern on an int");
        assert!(bad(&|s| {
            s.kind = Kind::String;
            s.pattern = Some("(".into())
        }));
        assert!(bad(&|s| {
            s.kind = Kind::String;
            s.secret = true;
            s.default = Some(json!("leaked"))
        }));
        assert!(bad(&|s| {
            s.kind = Kind::Bool;
            s.secret = true
        }));
        assert!(bad(&|s| {
            s.kind = Kind::Enum;
        }), "enum without values");
        assert!(bad(&|s| {
            s.kind = Kind::Port;
            s.max = Some(70000)
        }));
        assert!(check_schema(&[st(Kind::Int, "a"), st(Kind::Int, "a")]).is_err());
        let many: Vec<Setting> = (0..65).map(|i| st(Kind::Bool, &format!("k{i}"))).collect();
        assert!(check_schema(&many).is_err());
    }

    #[test]
    fn values_are_validated_and_out_of_range_is_refused() {
        let s = schema();
        let by = |k: &str| s.iter().find(|x| x.key == k).unwrap();
        assert_eq!(validate_value(by("interval"), &json!(30)).unwrap(), json!(30));
        assert_eq!(validate_value(by("interval"), &json!("30")).unwrap(), json!(30));
        assert!(validate_value(by("interval"), &json!(4)).is_err());
        assert!(validate_value(by("interval"), &json!(3601)).is_err());
        assert!(validate_value(by("interval"), &json!("x")).is_err());
        assert!(validate_value(by("interval"), &json!(1.5)).is_err());
        assert!(validate_value(by("name"), &json!("ok-name")).is_ok());
        assert!(validate_value(by("name"), &json!("Bad Name")).is_err());
        assert!(validate_value(by("name"), &json!("a-very-long-name-over-twenty")).is_err());
        assert!(validate_value(by("mode"), &json!("fast")).is_ok());
        assert!(validate_value(by("mode"), &json!("turbo")).is_err());
        assert!(validate_value(by("listen"), &json!(8080)).is_ok());
        assert!(validate_value(by("listen"), &json!(80)).is_err());
        assert!(validate_value(by("listen"), &json!(65536)).is_err());
        assert!(validate_value(&st(Kind::Port, "p"), &json!(0)).is_err());
        assert_eq!(validate_value(by("debug"), &json!("true")).unwrap(), json!(true));
        assert!(validate_value(by("debug"), &json!("yes")).is_err());
        assert_eq!(validate_value(by("gw"), &json!(" 10.0.0.1 ")).unwrap(), json!("10.0.0.1"));
        assert!(validate_value(by("gw"), &json!("10.0.0.999")).is_err());
        assert!(validate_value(by("gw"), &json!("example.com")).is_err());
        assert!(validate_value(by("hosts"), &json!(["10.0.0.1", "::1"])).is_ok());
        assert!(validate_value(by("hosts"), &json!(["10.0.0.1", "nope"])).is_err());
        assert!(validate_value(by("hosts"), &json!(["1.1.1.1", "1.1.1.2", "1.1.1.3", "1.1.1.4"])).is_err());
        assert!(validate_value(by("hosts"), &json!("1.1.1.1")).is_err());
        // an error never repeats the offending value (it may be a secret)
        let e = validate_value(by("name"), &json!("Sup3r Secret!")).unwrap_err().to_string();
        assert!(!e.contains("Sup3r"), "{e}");
    }

    #[tokio::test]
    async fn save_masks_secrets_and_round_trips_through_export() {
        let store = ConfigStore::open_in_memory().await.unwrap();
        let s = schema();
        let vals = |v: Value| v.as_object().unwrap().clone();
        // out of range: nothing is stored, even the valid sibling
        let r = save(&store, "p", &s, &vals(json!({"name": "ok", "interval": 1})), &[]).await;
        assert!(r.is_err());
        assert!(stored(&store, "p").await.unwrap().is_empty());
        assert!(save(&store, "p", &s, &vals(json!({"nope": 1})), &[]).await.is_err());
        // required secret has no value yet
        assert!(effective(&store, "p", &s).await.is_err());
        save(
            &store,
            "p",
            &s,
            &vals(json!({"token": "s3cr3t-token", "interval": 90, "hosts": ["10.1.1.1"]})),
            &[],
        )
        .await
        .unwrap();
        // the browser view: schema and values, but never the secret
        let v = view(&store, "p", &s).await.unwrap();
        let text = serde_json::to_string(&v).unwrap();
        assert!(!text.contains("s3cr3t-token"), "{text}");
        let tok = v.iter().find(|x| x["key"] == "token").unwrap();
        assert_eq!((tok["is_set"].clone(), tok["value"].clone()), (json!(true), Value::Null));
        let iv = v.iter().find(|x| x["key"] == "interval").unwrap();
        assert_eq!(iv["value"], json!(90));
        let mode = v.iter().find(|x| x["key"] == "mode").unwrap();
        assert_eq!((mode["value"].clone(), mode["is_set"].clone()), (json!("safe"), json!(false)));
        // an empty secret keeps the stored one; clear returns to the default
        save(&store, "p", &s, &vals(json!({"token": "", "interval": 120})), &["hosts".into()])
            .await
            .unwrap();
        let eff = effective(&store, "p", &s).await.unwrap();
        assert_eq!(eff["token"], json!("s3cr3t-token"));
        assert_eq!(eff["interval"], json!(120));
        assert_eq!(eff["mode"], json!("safe"));
        assert!(!eff.contains_key("hosts"));
        // the service files carry the secret; env lines are quoted
        let env = render_env(&vals(json!({"token": "it's", "hosts": ["a"]})));
        assert!(env.contains("PLUGIN_TOKEN='it'\\''s'"), "{env}");
        assert!(env.contains("PLUGIN_HOSTS='[\"a\"]'"), "{env}");
        assert!(render_json(&eff).contains("s3cr3t-token"));
        // export -> import round trip keeps the values (and flags the secret)
        let doc = store.export_json().await.unwrap();
        let rows = doc["tables"]["plugin_settings"].as_array().unwrap();
        assert_eq!(rows.len(), 2);
        let secret_row = rows.iter().find(|r| r["setting"] == "token").unwrap();
        assert_eq!(secret_row["secret"], json!(1));
        delete_all(&store, "p").await.unwrap();
        assert!(stored(&store, "p").await.unwrap().is_empty());
        store.import_json(&doc).await.unwrap();
        assert_eq!(effective(&store, "p", &s).await.unwrap(), eff);
    }

    #[tokio::test]
    async fn update_drops_values_the_new_schema_refuses_and_gitops_replaces() {
        let store = ConfigStore::open_in_memory().await.unwrap();
        let s = schema();
        let vals = |v: Value| v.as_object().unwrap().clone();
        save(&store, "p", &s, &vals(json!({"token": "t", "interval": 100, "name": "abc"})), &[])
            .await
            .unwrap();
        // v2 narrows interval to 5..50, drops `name`
        let mut s2: Vec<Setting> = s.iter().filter(|x| x.key != "name").cloned().collect();
        s2.iter_mut().find(|x| x.key == "interval").unwrap().max = Some(50);
        s2.iter_mut().find(|x| x.key == "interval").unwrap().default = Some(json!(10));
        let mut dropped = reconcile(&store, "p", &s2).await.unwrap();
        dropped.sort();
        assert_eq!(dropped, vec!["interval", "name"]);
        let eff = effective(&store, "p", &s2).await.unwrap();
        assert_eq!((eff["interval"].clone(), eff["token"].clone()), (json!(10), json!("t")));
        // GitOps: declared keys replace, absent plain keys reset, absent secret kept
        save(&store, "p", &s2, &vals(json!({"interval": 20, "mode": "fast"})), &[]).await.unwrap();
        gitops_replace(&store, "p", &s2, &json!({"interval": 30})).await.unwrap();
        let eff = effective(&store, "p", &s2).await.unwrap();
        assert_eq!(eff["interval"], json!(30));
        assert_eq!(eff["mode"], json!("safe"), "left out -> default again");
        assert_eq!(eff["token"], json!("t"), "a secret left out is kept");
        assert!(gitops_replace(&store, "p", &s2, &json!({"interval": 999})).await.is_err());
        assert!(gitops_replace(&store, "p", &s2, &json!([1])).await.is_err());
    }
}
