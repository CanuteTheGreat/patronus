//! Configuration history: a readable per-section diff between two exported
//! configuration documents (a stored revision and the running configuration),
//! and the typed setting of the confirm-or-revert timer.
//!
//! The diff is what a restore of the revision would do to the running
//! configuration: rows it brings back (`added`), rows it removes (`removed`)
//! and fields it changes. Secrets (password hashes, keys, tokens) are never
//! put in the diff: their values read `(hidden)`.

use crate::store::ConfigStore;
use crate::Result;
use serde::Serialize;
use serde_json::{Map, Value};

/// Typed setting (`system_config`, so it is part of export/plan/apply and of
/// every revision): seconds a risky change stays unconfirmed before it is
/// reverted by the box itself. 0 = off (the default).
pub const CONFIRM_SECONDS_KEY: &str = "history.confirm_seconds";
pub const CONFIRM_SECONDS_MIN: u32 = 10;
pub const CONFIRM_SECONDS_MAX: u32 = 3600;

/// Shown instead of a secret's value.
pub const HIDDEN: &str = "(hidden)";

/// Rows listed per section and kind; the rest is only counted (`more`).
const MAX_ROWS: usize = 100;

/// Fields that change on every write and say nothing about the configuration.
const NOISE_FIELDS: &[&str] = &["updated_at", "created_at", "modified_at", "last_seen"];

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct FieldChange {
    pub field: String,
    pub from: Value,
    pub to: Value,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct RowChange {
    pub label: String,
    pub fields: Vec<FieldChange>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct RowView {
    pub label: String,
    /// Every non-secret column of the row.
    pub values: Map<String, Value>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Default)]
pub struct SectionDiff {
    pub table: String,
    pub title: String,
    /// Rows the revision has and the running configuration lacks.
    pub added: Vec<RowView>,
    /// Rows the running configuration has and the revision lacks.
    pub removed: Vec<RowView>,
    pub changed: Vec<RowChange>,
    /// Rows left out of the lists above (each list is capped).
    pub more: usize,
}

fn secret_name(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    [
        "password",
        "passwd",
        "hash",
        "secret",
        "private",
        "psk",
        "token",
        "totp",
        "recovery",
        "apikey",
        "api_key",
        "credential",
        "preshared",
    ]
    .iter()
    .any(|w| n.contains(w))
}

/// A readable name of a section: `firewall_rules` -> "Firewall rules".
pub fn section_title(table: &str) -> String {
    match table {
        "system_config" => return "System settings".into(),
        "nat_rules" => return "NAT rules".into(),
        "dhcp_pools" => return "DHCP pools".into(),
        "wg_interfaces" => return "WireGuard interfaces".into(),
        "wg_peers" => return "WireGuard peers".into(),
        "web_users" => return "Web accounts".into(),
        "sysctls" => return "Kernel settings".into(),
        _ => {}
    }
    let mut t = table.replace('_', " ");
    if let Some(c) = t.get_mut(0..1) {
        c.make_ascii_uppercase();
    }
    t
}

/// The first of id / key / name that is set and unique in every row of every side.
fn key_column(sides: &[&[Value]]) -> Option<&'static str> {
    if sides.iter().all(|s| s.is_empty()) {
        return None;
    }
    ["id", "key", "name"].into_iter().find(|k| {
        sides.iter().all(|rows| {
            let mut seen = std::collections::HashSet::new();
            rows.iter()
                .all(|r| r.get(*k).is_some_and(|v| !v.is_null() && seen.insert(v.to_string())))
        })
    })
}

fn label(row: &Value, table: &str) -> String {
    let get = |k: &str| {
        row.get(k)
            .and_then(|v| v.as_str().map(str::to_string).or_else(|| v.as_i64().map(|n| n.to_string())))
            .filter(|s| !s.is_empty())
    };
    if table == "system_config" {
        if let Some(k) = get("key") {
            return k;
        }
    }
    let name = ["name", "username", "description", "address", "interface", "device"]
        .into_iter()
        .find_map(get);
    match (name, get("id")) {
        (Some(n), Some(id)) => format!("{n} (#{id})"),
        (Some(n), None) => n,
        (None, Some(id)) => format!("#{id}"),
        (None, None) => "row".into(),
    }
}

/// The non-secret, non-noise columns of a row. In `system_config` the value of
/// a secret-named key is hidden.
fn view(row: &Value, table: &str) -> Map<String, Value> {
    let mut out = Map::new();
    let hide_value = table == "system_config"
        && row
            .get("key")
            .and_then(Value::as_str)
            .is_some_and(secret_name);
    if let Some(o) = row.as_object() {
        for (k, v) in o {
            if NOISE_FIELDS.contains(&k.as_str()) {
                continue;
            }
            let secret = secret_name(k) || (hide_value && k == "value");
            let shown = if secret && !v.is_null() && v != "" {
                Value::from(HIDDEN)
            } else {
                v.clone()
            };
            out.insert(k.clone(), shown);
        }
    }
    out
}

fn rows_of<'a>(doc: &'a Value, table: &str) -> &'a [Value] {
    doc.get("tables")
        .and_then(|t| t.get(table))
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or(&[])
}

fn diff_table(table: &str, cur: &[Value], rev: &[Value]) -> Option<SectionDiff> {
    let mut d = SectionDiff {
        table: table.into(),
        title: section_title(table),
        ..Default::default()
    };
    let mut more = 0usize;
    let mut push_view = |list: &mut Vec<RowView>, r: &Value| {
        if list.len() < MAX_ROWS {
            list.push(RowView {
                label: label(r, table),
                values: view(r, table),
            });
        } else {
            more += 1;
        }
    };
    match key_column(&[cur, rev]) {
        Some(k) => {
            for r in rev {
                match cur.iter().find(|c| c.get(k) == r.get(k)) {
                    None => push_view(&mut d.added, r),
                    Some(c) => {
                        let (a, b) = (view(c, table), view(r, table));
                        let (full_a, full_b) = (c.as_object(), r.as_object());
                        let mut fields = Vec::new();
                        let mut names: Vec<&String> = a.keys().chain(b.keys()).collect();
                        names.sort();
                        names.dedup();
                        for n in names {
                            let (x, y) = (a.get(n), b.get(n));
                            if x == y {
                                // hidden on both sides: compare the real values
                                let real = |o: Option<&Map<String, Value>>| o.and_then(|o| o.get(n));
                                if x == Some(&Value::from(HIDDEN)) && real(full_a) != real(full_b) {
                                    fields.push(FieldChange {
                                        field: n.clone(),
                                        from: Value::from(HIDDEN),
                                        to: Value::from(HIDDEN),
                                    });
                                }
                                continue;
                            }
                            fields.push(FieldChange {
                                field: n.clone(),
                                from: x.cloned().unwrap_or(Value::Null),
                                to: y.cloned().unwrap_or(Value::Null),
                            });
                        }
                        if !fields.is_empty() {
                            d.changed.push(RowChange {
                                label: label(c, table),
                                fields,
                            });
                        }
                    }
                }
            }
            for c in cur {
                if !rev.iter().any(|r| r.get(k) == c.get(k)) {
                    push_view(&mut d.removed, c);
                }
            }
        }
        None => {
            // no usable key: whole-row comparison (an edited row is a remove + an add)
            let same = |a: &Value, b: &Value| view(a, table) == view(b, table);
            for r in rev {
                if !cur.iter().any(|c| same(c, r)) {
                    push_view(&mut d.added, r);
                }
            }
            for c in cur {
                if !rev.iter().any(|r| same(r, c)) {
                    push_view(&mut d.removed, c);
                }
            }
        }
    }
    d.more = more;
    (!d.added.is_empty() || !d.removed.is_empty() || !d.changed.is_empty()).then_some(d)
}

/// What restoring `revision` would change in `current`, per section (sections
/// without a difference are left out, so "identical" is an empty list).
pub fn diff_docs(current: &Value, revision: &Value) -> Vec<SectionDiff> {
    let mut names: Vec<String> = [current, revision]
        .iter()
        .filter_map(|d| d.get("tables").and_then(Value::as_object))
        .flat_map(|t| t.keys().cloned())
        .collect();
    names.sort();
    names.dedup();
    names
        .iter()
        .filter_map(|t| diff_table(t, rows_of(current, t), rows_of(revision, t)))
        .collect()
}

/// Seconds a risky change waits for confirmation before the box reverts it
/// (0 = the timer is off, the default).
pub async fn confirm_seconds(store: &ConfigStore) -> u32 {
    store
        .load_system_config(CONFIRM_SECONDS_KEY)
        .await
        .ok()
        .flatten()
        .and_then(|v| v.trim().parse::<u32>().ok())
        .map(|n| if n == 0 { 0 } else { n.clamp(CONFIRM_SECONDS_MIN, CONFIRM_SECONDS_MAX) })
        .unwrap_or(0)
}

/// Validate and store the timer (0, or 10..=3600 seconds).
pub async fn set_confirm_seconds(store: &ConfigStore, seconds: u32) -> Result<()> {
    if seconds != 0 && !(CONFIRM_SECONDS_MIN..=CONFIRM_SECONDS_MAX).contains(&seconds) {
        return Err(crate::Error::Config(format!(
            "Invalid confirm timer: use 0 (off) or {CONFIRM_SECONDS_MIN} to {CONFIRM_SECONDS_MAX} seconds"
        )));
    }
    store
        .save_system_config(CONFIRM_SECONDS_KEY, &seconds.to_string())
        .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn doc(tables: Value) -> Value {
        json!({"version": 2, "tables": tables})
    }

    #[test]
    fn identical_documents_have_no_sections() {
        let d = doc(json!({"firewall_rules": [{"id": 1, "name": "a", "port": "22"}]}));
        assert!(diff_docs(&d, &d).is_empty());
    }

    #[test]
    fn added_removed_and_changed_rows_are_told_apart() {
        let cur = doc(json!({"firewall_rules": [
            {"id": 1, "name": "ssh", "port": "22", "updated_at": 5},
            {"id": 2, "name": "extra", "port": "99"}]}));
        let rev = doc(json!({"firewall_rules": [
            {"id": 1, "name": "ssh", "port": "2222", "updated_at": 9},
            {"id": 3, "name": "old", "port": "1"}]}));
        let d = diff_docs(&cur, &rev);
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].title, "Firewall rules");
        assert_eq!(d[0].added.len(), 1);
        assert_eq!(d[0].added[0].label, "old (#3)");
        assert_eq!(d[0].removed[0].label, "extra (#2)");
        assert_eq!(d[0].changed.len(), 1);
        assert_eq!(d[0].changed[0].fields.len(), 1, "updated_at is noise");
        assert_eq!(d[0].changed[0].fields[0].field, "port");
        assert_eq!(d[0].changed[0].fields[0].from, json!("22"));
        assert_eq!(d[0].changed[0].fields[0].to, json!("2222"));
    }

    #[test]
    fn secrets_never_appear() {
        let cur = doc(json!({
            "web_users": [{"id": 1, "username": "admin", "password_hash": "AAA", "role": "admin"}],
            "system_config": [{"key": "vpn.api_token", "value": "tok-1", "updated_at": 1}]}));
        let rev = doc(json!({
            "web_users": [{"id": 1, "username": "admin", "password_hash": "BBB", "role": "admin"}],
            "system_config": [{"key": "vpn.api_token", "value": "tok-2", "updated_at": 2}]}));
        let d = diff_docs(&cur, &rev);
        let text = serde_json::to_string(&d).unwrap();
        for s in ["AAA", "BBB", "tok-1", "tok-2"] {
            assert!(!text.contains(s), "{s} leaked: {text}");
        }
        assert_eq!(d.len(), 2, "a changed secret is still reported as changed");
        assert!(text.contains(HIDDEN));
    }

    #[test]
    fn rows_without_a_key_compare_whole_rows() {
        let cur = doc(json!({"x_log": [{"a": 1}, {"a": 2}]}));
        let rev = doc(json!({"x_log": [{"a": 2}, {"a": 3}]}));
        let d = diff_docs(&cur, &rev);
        assert_eq!((d[0].added.len(), d[0].removed.len()), (1, 1));
    }

    #[test]
    fn a_table_only_one_side_has_is_all_added_or_removed() {
        let cur = doc(json!({}));
        let rev = doc(json!({"routes": [{"id": 1, "name": "r"}]}));
        let d = diff_docs(&cur, &rev);
        assert_eq!(d[0].added.len(), 1);
        assert_eq!(diff_docs(&rev, &cur)[0].removed.len(), 1);
    }

    #[tokio::test]
    async fn confirm_timer_setting_defaults_off_and_validates() {
        let s = ConfigStore::open_in_memory().await.unwrap();
        assert_eq!(confirm_seconds(&s).await, 0);
        assert!(set_confirm_seconds(&s, 5).await.is_err());
        assert!(set_confirm_seconds(&s, 99999).await.is_err());
        set_confirm_seconds(&s, 60).await.unwrap();
        assert_eq!(confirm_seconds(&s).await, 60);
        set_confirm_seconds(&s, 0).await.unwrap();
        assert_eq!(confirm_seconds(&s).await, 0);
    }
}
