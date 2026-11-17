//! The declarative configuration file: the whole configuration as ONE
//! human-readable YAML document with a version header.
//!
//! - stable: tables sorted by name, rows by primary key, the key columns first
//!   and the others alphabetically, empty tables left out, no timestamps, so
//!   `export -> import -> export` is byte-identical and `git diff` shows
//!   exactly what changed;
//! - secrets (VPN private keys, PSKs, password hashes, TOTP secrets, API
//!   tokens, secret-named settings) are **not** in the file unless asked for
//!   (`--include-secrets`, written 0600): an import keeps the stored secret
//!   of every row it matches by key;
//! - measured history is never configuration: the file covers exactly the
//!   tables [`ConfigStore::export_json`] covers.
//!
//! It is the same data as the JSON backup (`config export`), so the JSON
//! backups keep importing too: [`parse_document`] accepts both.

use crate::gendiff::{self, KeyMap};
use crate::store::ConfigStore;
use patronus_core::{Error, Result};
use serde_json::{Map, Value};
use serde_yaml::Mapping;

/// Format version in the file header.
pub const FORMAT_VERSION: i64 = 1;

const HEADER: &str = "\
# Patronus declarative configuration. Edit it, then `patronus config import FILE`
# (or upload it on the Config generations page): the change is validated, shown as a
# diff against the live configuration and applied as a new generation.
# Secrets are not in this file unless it says `secrets: included`; an import keeps the
# stored secret of every row it matches by key.
";

fn sort_value(v: &Value) -> (u8, f64, String) {
    match v {
        Value::Number(n) => (0, n.as_f64().unwrap_or(0.0), String::new()),
        Value::String(s) => (1, 0.0, s.clone()),
        Value::Null => (2, 0.0, String::new()),
        other => (3, 0.0, other.to_string()),
    }
}

fn key_columns<'a>(table: &str, row: &'a Map<String, Value>, keys: &'a KeyMap) -> Vec<&'a str> {
    match keys.get(table) {
        Some(k) if !k.is_empty() => k.iter().map(String::as_str).collect(),
        _ if row.contains_key("id") => vec!["id"],
        _ => Vec::new(),
    }
}

/// The document as the declarative YAML text.
pub fn to_yaml(doc: &Value, keys: &KeyMap, include_secrets: bool) -> Result<String> {
    let tables = doc
        .get("tables")
        .and_then(Value::as_object)
        .ok_or_else(|| Error::Config("Invalid config document: no 'tables'".into()))?;
    let mut out_tables = Mapping::new();
    for (t, rows) in tables {
        let mut rows: Vec<&Map<String, Value>> = rows
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_object)
            .filter(|r| !r.is_empty())
            .collect();
        if rows.is_empty() {
            continue;
        }
        rows.sort_by(|a, b| {
            let ka = sort_key(t, a, keys);
            let kb = sort_key(t, b, keys);
            ka.partial_cmp(&kb).unwrap_or(std::cmp::Ordering::Equal)
        });
        let mut seq = Vec::new();
        for row in rows {
            let secret = if include_secrets {
                Vec::new()
            } else {
                gendiff::secret_columns(row)
            };
            let kc = key_columns(t, row, keys);
            let mut m = Mapping::new();
            let mut put = |c: &str| -> Result<()> {
                if let Some(v) = row.get(c) {
                    m.insert(
                        serde_yaml::Value::String(c.to_string()),
                        serde_yaml::to_value(v).map_err(|e| Error::Config(e.to_string()))?,
                    );
                }
                Ok(())
            };
            for c in &kc {
                if !secret.iter().any(|s| s == c) {
                    put(c)?;
                }
            }
            for c in row.keys() {
                if !kc.contains(&c.as_str()) && !secret.iter().any(|s| s == c) {
                    put(c)?;
                }
            }
            seq.push(serde_yaml::Value::Mapping(m));
        }
        out_tables.insert(
            serde_yaml::Value::String(t.clone()),
            serde_yaml::Value::Sequence(seq),
        );
    }
    let mut top = Mapping::new();
    top.insert(
        "patronus_config_version".into(),
        serde_yaml::Value::Number(FORMAT_VERSION.into()),
    );
    top.insert(
        "secrets".into(),
        if include_secrets {
            "included"
        } else {
            "excluded"
        }
        .into(),
    );
    top.insert("tables".into(), serde_yaml::Value::Mapping(out_tables));
    let body = serde_yaml::to_string(&serde_yaml::Value::Mapping(top))
        .map_err(|e| Error::Config(format!("write declarative file: {e}")))?;
    Ok(format!("{HEADER}{body}"))
}

fn sort_key(table: &str, row: &Map<String, Value>, keys: &KeyMap) -> Vec<(u8, f64, String)> {
    let kc = key_columns(table, row, keys);
    if kc.is_empty() {
        return vec![(3, 0.0, Value::Object(row.clone()).to_string())];
    }
    kc.iter()
        .map(|c| sort_value(row.get(*c).unwrap_or(&Value::Null)))
        .collect()
}

/// Parse a declarative YAML file into an export document. Returns it with
/// whether the file carries secrets.
pub fn from_yaml(text: &str) -> Result<(Value, bool)> {
    let v: Value = serde_yaml::from_str(text)
        .map_err(|e| Error::Config(format!("Invalid declarative file: {e}")))?;
    let obj = v
        .as_object()
        .ok_or_else(|| Error::Config("Invalid declarative file: not a mapping".into()))?;
    match obj.get("patronus_config_version").and_then(Value::as_i64) {
        Some(FORMAT_VERSION) => {}
        Some(other) => {
            return Err(Error::Config(format!(
                "Invalid declarative file: version {other} (this Patronus reads version {FORMAT_VERSION})"
            )))
        }
        None => {
            return Err(Error::Config(
                "Invalid declarative file: no patronus_config_version header".into(),
            ))
        }
    }
    let secrets = obj.get("secrets").and_then(Value::as_str) == Some("included");
    let tables = match obj.get("tables") {
        None | Some(Value::Null) => Map::new(),
        Some(Value::Object(t)) => t.clone(),
        Some(_) => {
            return Err(Error::Config(
                "Invalid declarative file: 'tables' is not a mapping".into(),
            ))
        }
    };
    let mut out = Map::new();
    for (t, rows) in tables {
        let rows = match rows {
            Value::Null => Vec::new(),
            Value::Array(a) => a,
            _ => {
                return Err(Error::Config(format!(
                    "Invalid declarative file: table {t:?} is not a list of rows"
                )))
            }
        };
        if rows.iter().any(|r| !r.is_object()) {
            return Err(Error::Config(format!(
                "Invalid declarative file: table {t:?} has a row that is not a mapping"
            )));
        }
        out.insert(t, Value::Array(rows));
    }
    Ok((serde_json::json!({"version": 2, "tables": out}), secrets))
}

/// Read an uploaded/imported file: the declarative YAML or the JSON backup.
pub fn parse_document(text: &str) -> Result<(Value, bool)> {
    if text.trim_start().starts_with('{') {
        let doc: Value = serde_json::from_str(text)
            .map_err(|e| Error::Config(format!("Invalid config file: not JSON ({e})")))?;
        if !doc.get("tables").is_some_and(Value::is_object) {
            return Err(Error::Config(
                "Invalid config file: not a Patronus configuration export (no \"tables\")".into(),
            ));
        }
        return Ok((doc, true));
    }
    from_yaml(text)
}

/// For every row of `new` that matches a live row by key, copy the live row's
/// secret columns the file does not carry (files exported without secrets).
pub fn merge_missing_secrets(new: &mut Value, live: &Value, keys: &KeyMap) {
    let Some(tables) = new.get_mut("tables").and_then(Value::as_object_mut) else {
        return;
    };
    for (t, rows) in tables.iter_mut() {
        let live_rows: Vec<&Map<String, Value>> = live
            .get("tables")
            .and_then(|x| x.get(t))
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_object)
            .collect();
        if live_rows.is_empty() {
            continue;
        }
        for row in rows.as_array_mut().into_iter().flatten() {
            let Some(row) = row.as_object_mut() else {
                continue;
            };
            let k = row_identity(t, row, keys);
            let Some(lr) = live_rows.iter().find(|l| row_identity(t, l, keys) == k) else {
                continue;
            };
            for c in gendiff::secret_columns(lr) {
                if !row.contains_key(&c) {
                    if let Some(v) = lr.get(&c) {
                        row.insert(c, v.clone());
                    }
                }
            }
        }
    }
}

fn row_identity(t: &str, row: &Map<String, Value>, keys: &KeyMap) -> String {
    let kc = key_columns(t, row, keys);
    if kc.is_empty() {
        // no key: the non-secret content identifies the row
        let sec = gendiff::secret_columns(row);
        let mut m = row.clone();
        for c in sec {
            m.remove(&c);
        }
        return Value::Object(m).to_string();
    }
    kc.iter()
        .map(|c| row.get(*c).cloned().unwrap_or(Value::Null).to_string())
        .collect::<Vec<_>>()
        .join("|")
}

/// Import `doc` into a scratch store and return what it then holds (the
/// anti-lockout rules re-added if the document dropped them). A separate
/// function with owned arguments: it keeps the future `Send`.
async fn scratch_import(doc: Value) -> Result<Value> {
    // `ConfigStore::open_in_memory` (migrations) is not `Send` for the
    // compiler, so it runs on its own thread with its own small runtime: the
    // caller (a web handler) stays `Send`.
    tokio::task::spawn_blocking(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| Error::Config(format!("scratch runtime: {e}")))?;
        rt.block_on(async move {
            let scratch = ConfigStore::open_in_memory().await?;
            let r = match scratch.import_checked(&doc).await {
                Ok(()) => scratch.export_json().await,
                Err(e) => Err(e),
            };
            scratch.close().await;
            r
        })
    })
    .await
    .map_err(|e| Error::Config(format!("scratch import: {e}")))?
}

/// What an import would do.
#[derive(Debug, Clone)]
pub struct ImportPreview {
    /// The document to import (secrets merged in from the live rows).
    pub doc: Value,
    /// Structured diff live -> document.
    pub diff: Value,
    /// Unified text diff of the declarative files, live -> document.
    pub text_diff: String,
    pub identical: bool,
}

/// Validate `text` (declarative YAML or JSON backup) and compute the diff
/// against the live configuration. Nothing is written: the document is
/// loaded into a scratch store to prove it would import.
pub async fn prepare_import(store: &ConfigStore, text: &str) -> Result<ImportPreview> {
    let (mut doc, _) = parse_document(text)?;
    let live = store.export_json().await?;
    let keys = store.table_keys().await?;
    merge_missing_secrets(&mut doc, &live, &keys);
    let resulting = scratch_import(doc.clone())
        .await
        .map_err(|e| Error::Config(format!("Invalid configuration, nothing was imported: {e}")))?;
    let diff = gendiff::diff_docs(&live, &resulting, &keys);
    let text_diff = gendiff::unified_diff(
        &to_yaml(&live, &keys, false)?,
        &to_yaml(&resulting, &keys, false)?,
        "live",
        "imported file",
    );
    let identical = diff["identical"].as_bool().unwrap_or(false);
    Ok(ImportPreview {
        doc,
        diff,
        text_diff,
        identical,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    async fn store_with_stuff() -> ConfigStore {
        let s = ConfigStore::open_in_memory().await.unwrap();
        s.save_system_config(crate::defaults::DEFAULTS_SEEDED_KEY, "test")
            .await
            .unwrap();
        crate::defaults::ensure_system_rules(&s).await.unwrap();
        s.save_system_config("hostname", "fw1").await.unwrap();
        s.save_system_config("smtp.password", "hunter2")
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO wg_interfaces (name, private_key, listen_port, addresses, updated_at) VALUES ('wg0', 'PRIVATE-KEY-VALUE', 51820, '10.9.0.1/24', 1)",
        )
        .execute(s.pool().unwrap())
        .await
        .unwrap();
        s
    }

    #[tokio::test]
    async fn export_import_export_is_a_fixed_point() {
        let s = store_with_stuff().await;
        let keys = s.table_keys().await.unwrap();
        let doc = s.export_json().await.unwrap();
        let y1 = to_yaml(&doc, &keys, false).unwrap();
        let (mut parsed, secrets) = from_yaml(&y1).unwrap();
        assert!(!secrets);
        merge_missing_secrets(&mut parsed, &doc, &keys);
        s.import_checked(&parsed).await.unwrap();
        let y2 = to_yaml(&s.export_json().await.unwrap(), &keys, false).unwrap();
        assert_eq!(y1, y2);
        // with secrets too
        let i1 = to_yaml(&s.export_json().await.unwrap(), &keys, true).unwrap();
        let (parsed, secrets) = from_yaml(&i1).unwrap();
        assert!(secrets);
        s.import_checked(&parsed).await.unwrap();
        let i2 = to_yaml(&s.export_json().await.unwrap(), &keys, true).unwrap();
        assert_eq!(i1, i2);
        // a fresh export of the same state is byte-identical (no timestamps)
        let y3 = to_yaml(&s.export_json().await.unwrap(), &keys, false).unwrap();
        assert_eq!(y1, y3);
    }

    #[tokio::test]
    async fn secrets_are_excluded_by_default_and_included_on_request() {
        let s = store_with_stuff().await;
        let keys = s.table_keys().await.unwrap();
        let doc = s.export_json().await.unwrap();
        let plain = to_yaml(&doc, &keys, false).unwrap();
        assert!(!plain.contains("PRIVATE-KEY-VALUE"), "{plain}");
        assert!(!plain.contains("hunter2"), "{plain}");
        assert!(plain.contains("secrets: excluded"));
        assert!(plain.contains("patronus_config_version: 1"));
        assert!(plain.contains("fw1") && plain.contains("wg0"));
        let full = to_yaml(&doc, &keys, true).unwrap();
        assert!(full.contains("PRIVATE-KEY-VALUE") && full.contains("hunter2"));
        assert!(full.contains("secrets: included"));
    }

    #[tokio::test]
    async fn an_import_without_secrets_keeps_the_stored_ones() {
        let s = store_with_stuff().await;
        let keys = s.table_keys().await.unwrap();
        let live = s.export_json().await.unwrap();
        let edited = to_yaml(&live, &keys, false)
            .unwrap()
            .replace("listen_port: 51820", "listen_port: 51999");
        let pv = prepare_import(&s, &edited).await.unwrap();
        assert!(!pv.identical);
        assert_eq!(pv.diff["summary"]["changed"], 1);
        assert!(pv.text_diff.contains("-  listen_port: 51820") || pv.text_diff.contains("51820"));
        assert!(!pv.diff.to_string().contains("PRIVATE-KEY-VALUE"));
        assert!(!pv.text_diff.contains("PRIVATE-KEY-VALUE"));
        s.import_checked(&pv.doc).await.unwrap();
        let k: String =
            sqlx::query_scalar("SELECT private_key FROM wg_interfaces WHERE name='wg0'")
                .fetch_one(s.pool().unwrap())
                .await
                .unwrap();
        assert_eq!(k, "PRIVATE-KEY-VALUE");
        let pw = s.load_system_config("smtp.password").await.unwrap();
        assert_eq!(pw.as_deref(), Some("hunter2"));
    }

    #[tokio::test]
    async fn an_unchanged_file_previews_as_identical() {
        let s = store_with_stuff().await;
        let keys = s.table_keys().await.unwrap();
        let y = to_yaml(&s.export_json().await.unwrap(), &keys, false).unwrap();
        let pv = prepare_import(&s, &y).await.unwrap();
        assert!(pv.identical, "{}", pv.text_diff);
        assert_eq!(pv.text_diff, "");
    }

    #[tokio::test]
    async fn bad_files_are_refused_with_a_reason() {
        let s = store_with_stuff().await;
        for (text, want) in [
            ("tables: {}\n", "no patronus_config_version"),
            ("patronus_config_version: 9\ntables: {}\n", "version 9"),
            (
                "patronus_config_version: 1\ntables:\n  no_such_table:\n    - id: 1\n",
                "unknown table",
            ),
            (
                "patronus_config_version: 1\ntables:\n  firewall_rules:\n    - bogus_column: 1\n",
                "nothing was imported",
            ),
            ("- just\n- a list\n", "not a mapping"),
            ("{\"tables\": 5}", "no \"tables\""),
            (
                "patronus_config_version: 1\ntables:\n  firewall_rules: 5\n",
                "not a list of rows",
            ),
        ] {
            let e = prepare_import(&s, text).await.unwrap_err().to_string();
            assert!(e.contains(want), "{text:?}: {e}");
        }
    }

    #[tokio::test]
    async fn a_file_that_drops_the_anti_lockout_rule_gets_it_back() {
        let s = store_with_stuff().await;
        let keys = s.table_keys().await.unwrap();
        let mut doc = s.export_json().await.unwrap();
        doc["tables"]["firewall_rules"] = json!([]);
        let y = to_yaml(&doc, &keys, false).unwrap();
        let pv = prepare_import(&s, &y).await.unwrap();
        // the anti-lockout rule is part of what would be stored: no removal
        assert!(
            pv.identical || !pv.diff.to_string().contains("Anti-lockout"),
            "{}",
            pv.text_diff
        );
        s.import_checked(&pv.doc).await.unwrap();
        assert!(s
            .load_firewall_rules_with_origin()
            .await
            .unwrap()
            .iter()
            .any(|(r, _)| r.name == "Anti-lockout"));
    }

    #[tokio::test]
    async fn the_json_backup_still_imports() {
        let s = store_with_stuff().await;
        let json_text = serde_json::to_string(&s.export_json().await.unwrap()).unwrap();
        let pv = prepare_import(&s, &json_text).await.unwrap();
        assert!(pv.identical);
    }

    #[tokio::test]
    async fn measured_history_is_never_in_the_file() {
        let s = store_with_stuff().await;
        let keys = s.table_keys().await.unwrap();
        let y = to_yaml(&s.export_json().await.unwrap(), &keys, true).unwrap();
        for t in [
            "ins_usage",
            "ins_uplink_samples",
            "audit_log",
            "config_generations",
            "config_revisions",
        ] {
            assert!(!y.contains(t), "{t} in the declarative file");
        }
    }

    #[test]
    fn rows_are_sorted_by_key_and_columns_are_stable() {
        let doc = json!({"tables": {"t": [
            {"id": 10, "b": 1, "a": 2}, {"id": 2, "b": 3, "a": 4}]}});
        let y = to_yaml(&doc, &KeyMap::new(), false).unwrap();
        let i2 = y.find("id: 2").unwrap();
        let i10 = y.find("id: 10").unwrap();
        assert!(i2 < i10, "numeric order, not text order:\n{y}");
        assert!(y.contains("  - id: 2\n    a: 4\n    b: 3"), "{y}");
    }

    #[test]
    fn tricky_scalars_survive_the_round_trip() {
        let doc = json!({"tables": {"t": [{"id": 1,
            "s1": "true", "s2": "123", "s3": "null", "s4": "", "s5": "multi\nline\n",
            "s6": "yes", "s7": "2026-01-02", "s8": "a: b # c", "n": null, "f": 1.5, "i": -7}]}});
        let y = to_yaml(&doc, &KeyMap::new(), true).unwrap();
        let (back, _) = from_yaml(&y).unwrap();
        assert_eq!(back["tables"], doc["tables"], "{y}");
    }
}
