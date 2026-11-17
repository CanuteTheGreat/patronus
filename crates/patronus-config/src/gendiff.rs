//! Diffs between configuration documents (generation vs generation, or vs
//! live): a structured per-table / row / field diff and a unified text diff.
//!
//! Secrets (VPN private keys, PSKs, password hashes, TOTP secrets, API
//! tokens) never appear in either: a changed secret shows `(changed)`, an
//! added or removed row shows `(secret)` in place of the value.

use serde_json::{json, Map, Value};
use std::collections::BTreeMap;

/// Primary-key columns per table (empty = fall back to `id`, else the row).
pub type KeyMap = BTreeMap<String, Vec<String>>;

const SECRET_WORDS: &[&str] = &[
    "password",
    "passwd",
    "passphrase",
    "secret",
    "psk",
    "private_key",
    "preshared",
    "token",
    "recovery",
    "api_key",
    "apikey",
    "auth_key",
    "account_key",
    "community",
    "credential",
];

pub fn looks_secret(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    SECRET_WORDS.iter().any(|w| l.contains(w))
}

/// Columns of `row` that hold a secret: by column name, and the `value` of a
/// key/value row whose `key` names a secret (`system_config` and friends).
pub fn secret_columns(row: &Map<String, Value>) -> Vec<String> {
    let mut out: Vec<String> = row.keys().filter(|c| looks_secret(c)).cloned().collect();
    if let (Some(Value::String(k)), true) = (row.get("key"), row.contains_key("value")) {
        if looks_secret(k) && !out.iter().any(|c| c == "value") {
            out.push("value".to_string());
        }
    }
    out
}

fn is_empty_secret(v: &Value) -> bool {
    match v {
        Value::Null => true,
        Value::String(s) => s.is_empty(),
        _ => false,
    }
}

/// The row with every secret value replaced by `(secret)` (kept empty when
/// it is empty, so "no key set" stays visible).
pub fn redact_row(row: &Map<String, Value>) -> Map<String, Value> {
    let sec = secret_columns(row);
    let mut out = row.clone();
    for c in sec {
        if let Some(v) = out.get_mut(&c) {
            if !is_empty_secret(v) {
                *v = Value::String("(secret)".into());
            }
        }
    }
    out
}

fn row_key(table: &str, row: &Map<String, Value>, keys: &KeyMap) -> String {
    let cols: Vec<&str> = match keys.get(table) {
        Some(k) if !k.is_empty() => k.iter().map(String::as_str).collect(),
        _ if row.contains_key("id") => vec!["id"],
        _ => Vec::new(),
    };
    if cols.is_empty() {
        return Value::Object(row.clone()).to_string();
    }
    cols.iter()
        .map(|c| {
            let v = row.get(*c).cloned().unwrap_or(Value::Null);
            match v {
                Value::String(s) => format!("{c}={s}"),
                other => format!("{c}={other}"),
            }
        })
        .collect::<Vec<_>>()
        .join(",")
}

fn row_label(row: &Map<String, Value>) -> Option<String> {
    for c in ["name", "username", "interface", "alias", "key", "hostname", "description"] {
        if let Some(Value::String(s)) = row.get(c) {
            if !s.is_empty() && !looks_secret(c) {
                return Some(s.clone());
            }
        }
    }
    None
}

fn rows_of<'a>(
    doc: &'a Value,
    table: &str,
    keys: &KeyMap,
) -> BTreeMap<String, &'a Map<String, Value>> {
    let mut out = BTreeMap::new();
    for r in doc
        .get("tables")
        .and_then(|t| t.get(table))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        if let Some(o) = r.as_object() {
            let base = row_key(table, o, keys);
            let mut k = base.clone();
            let mut n = 1;
            while out.contains_key(&k) {
                n += 1;
                k = format!("{base}#{n}");
            }
            out.insert(k, o);
        }
    }
    out
}

/// Structured diff of two configuration documents.
pub fn diff_docs(a: &Value, b: &Value, keys: &KeyMap) -> Value {
    let mut names: Vec<String> = Vec::new();
    for d in [a, b] {
        if let Some(t) = d.get("tables").and_then(Value::as_object) {
            names.extend(t.keys().cloned());
        }
    }
    names.sort();
    names.dedup();
    let (mut n_add, mut n_rem, mut n_chg) = (0usize, 0usize, 0usize);
    let mut tables = Vec::new();
    for t in names {
        let ra = rows_of(a, &t, keys);
        let rb = rows_of(b, &t, keys);
        let (mut added, mut removed, mut changed) = (Vec::new(), Vec::new(), Vec::new());
        for (k, rowb) in &rb {
            match ra.get(k) {
                None => added.push(json!({
                    "key": k,
                    "label": row_label(rowb),
                    "row": redact_row(rowb),
                })),
                Some(rowa) => {
                    let mut fields = Vec::new();
                    let sec: Vec<String> = secret_columns(rowa)
                        .into_iter()
                        .chain(secret_columns(rowb))
                        .collect();
                    let mut cols: Vec<&String> = rowa.keys().chain(rowb.keys()).collect();
                    cols.sort();
                    cols.dedup();
                    for c in cols {
                        let (va, vb) = (rowa.get(c), rowb.get(c));
                        if va == vb {
                            continue;
                        }
                        if sec.iter().any(|s| s == c) {
                            fields.push(json!({"field": c, "secret": true, "change": "(changed)"}));
                        } else {
                            fields.push(json!({
                                "field": c,
                                "from": va.cloned().unwrap_or(Value::Null),
                                "to": vb.cloned().unwrap_or(Value::Null),
                            }));
                        }
                    }
                    if !fields.is_empty() {
                        changed.push(json!({
                            "key": k,
                            "label": row_label(rowb).or_else(|| row_label(rowa)),
                            "fields": fields,
                        }));
                    }
                }
            }
        }
        for (k, rowa) in &ra {
            if !rb.contains_key(k) {
                removed.push(json!({
                    "key": k,
                    "label": row_label(rowa),
                    "row": redact_row(rowa),
                }));
            }
        }
        if added.is_empty() && removed.is_empty() && changed.is_empty() {
            continue;
        }
        n_add += added.len();
        n_rem += removed.len();
        n_chg += changed.len();
        tables.push(json!({
            "table": t,
            "added": added,
            "removed": removed,
            "changed": changed,
        }));
    }
    json!({
        "identical": tables.is_empty(),
        "summary": {"added": n_add, "removed": n_rem, "changed": n_chg, "tables": tables.len()},
        "tables": tables,
    })
}

enum Op {
    Eq,
    Del,
    Add,
}

/// Line diff operations, common prefix/suffix trimmed, LCS in the middle
/// (a middle too big for that is shown as a full replacement).
fn line_ops<'a>(a: &[&'a str], b: &[&'a str]) -> Vec<(Op, &'a str)> {
    let mut pre = 0;
    while pre < a.len() && pre < b.len() && a[pre] == b[pre] {
        pre += 1;
    }
    let mut suf = 0;
    while suf < a.len() - pre && suf < b.len() - pre && a[a.len() - 1 - suf] == b[b.len() - 1 - suf]
    {
        suf += 1;
    }
    let (ma, mb) = (&a[pre..a.len() - suf], &b[pre..b.len() - suf]);
    let mut ops: Vec<(Op, &str)> = a[..pre].iter().map(|l| (Op::Eq, *l)).collect();
    if ma.len().saturating_mul(mb.len()) > 16_000_000 {
        ops.extend(ma.iter().map(|l| (Op::Del, *l)));
        ops.extend(mb.iter().map(|l| (Op::Add, *l)));
    } else {
        let (n, m) = (ma.len(), mb.len());
        let mut t = vec![0u32; (n + 1) * (m + 1)];
        let w = m + 1;
        for i in (0..n).rev() {
            for j in (0..m).rev() {
                t[i * w + j] = if ma[i] == mb[j] {
                    t[(i + 1) * w + j + 1] + 1
                } else {
                    t[(i + 1) * w + j].max(t[i * w + j + 1])
                };
            }
        }
        let (mut i, mut j) = (0, 0);
        while i < n && j < m {
            if ma[i] == mb[j] {
                ops.push((Op::Eq, ma[i]));
                i += 1;
                j += 1;
            } else if t[(i + 1) * w + j] >= t[i * w + j + 1] {
                ops.push((Op::Del, ma[i]));
                i += 1;
            } else {
                ops.push((Op::Add, mb[j]));
                j += 1;
            }
        }
        ops.extend(ma[i..].iter().map(|l| (Op::Del, *l)));
        ops.extend(mb[j..].iter().map(|l| (Op::Add, *l)));
    }
    ops.extend(a[a.len() - suf..].iter().map(|l| (Op::Eq, *l)));
    ops
}

/// A unified diff (3 lines of context); empty when the texts are equal.
pub fn unified_diff(a: &str, b: &str, label_a: &str, label_b: &str) -> String {
    let al: Vec<&str> = a.lines().collect();
    let bl: Vec<&str> = b.lines().collect();
    let ops = line_ops(&al, &bl);
    if ops.iter().all(|(o, _)| matches!(o, Op::Eq)) {
        return String::new();
    }
    // line numbers (0-based) before each op
    let mut pos = Vec::with_capacity(ops.len());
    let (mut ai, mut bi) = (0usize, 0usize);
    for (o, _) in &ops {
        pos.push((ai, bi));
        match o {
            Op::Eq => {
                ai += 1;
                bi += 1;
            }
            Op::Del => ai += 1,
            Op::Add => bi += 1,
        }
    }
    const CTX: usize = 3;
    let changes: Vec<usize> = ops
        .iter()
        .enumerate()
        .filter(|(_, (o, _))| !matches!(o, Op::Eq))
        .map(|(i, _)| i)
        .collect();
    let mut out = format!("--- {label_a}\n+++ {label_b}\n");
    let mut k = 0;
    while k < changes.len() {
        let mut end = k;
        while end + 1 < changes.len() && changes[end + 1] - changes[end] <= 2 * CTX + 1 {
            end += 1;
        }
        let lo = changes[k].saturating_sub(CTX);
        let hi = (changes[end] + CTX + 1).min(ops.len());
        let (sa, sb) = pos[lo];
        let la = ops[lo..hi]
            .iter()
            .filter(|(o, _)| !matches!(o, Op::Add))
            .count();
        let lb = ops[lo..hi]
            .iter()
            .filter(|(o, _)| !matches!(o, Op::Del))
            .count();
        out.push_str(&format!(
            "@@ -{},{} +{},{} @@\n",
            if la == 0 { sa } else { sa + 1 },
            la,
            if lb == 0 { sb } else { sb + 1 },
            lb
        ));
        for (o, l) in &ops[lo..hi] {
            out.push(match o {
                Op::Eq => ' ',
                Op::Del => '-',
                Op::Add => '+',
            });
            out.push_str(l);
            out.push('\n');
        }
        k = end + 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys() -> KeyMap {
        let mut k = KeyMap::new();
        k.insert("wg_interfaces".into(), vec!["id".into()]);
        k.insert("system_config".into(), vec!["key".into()]);
        k
    }

    #[test]
    fn per_table_row_and_field_diff() {
        let a = json!({"tables": {
            "firewall_rules": [{"id": 1, "name": "ssh", "enabled": 1}, {"id": 2, "name": "old", "enabled": 1}],
            "sysctls": [{"id": 1, "key": "a", "value": "1"}]}});
        let b = json!({"tables": {
            "firewall_rules": [{"id": 1, "name": "ssh", "enabled": 0}, {"id": 3, "name": "new", "enabled": 1}],
            "sysctls": [{"id": 1, "key": "a", "value": "1"}]}});
        let d = diff_docs(&a, &b, &KeyMap::new());
        assert_eq!(d["identical"], false);
        assert_eq!(d["summary"]["added"], 1);
        assert_eq!(d["summary"]["removed"], 1);
        assert_eq!(d["summary"]["changed"], 1);
        assert_eq!(d["tables"].as_array().unwrap().len(), 1, "unchanged tables are left out");
        let t = &d["tables"][0];
        assert_eq!(t["table"], "firewall_rules");
        assert_eq!(t["changed"][0]["label"], "ssh");
        assert_eq!(t["changed"][0]["fields"][0]["field"], "enabled");
        assert_eq!(t["changed"][0]["fields"][0]["from"], 1);
        assert_eq!(t["changed"][0]["fields"][0]["to"], 0);
        assert_eq!(t["added"][0]["label"], "new");
        assert_eq!(t["removed"][0]["label"], "old");
        assert!(diff_docs(&a, &a, &KeyMap::new())["identical"].as_bool().unwrap());
    }

    #[test]
    fn secrets_never_appear_in_a_diff() {
        let a = json!({"tables": {"wg_interfaces": [
            {"id": 1, "name": "wg0", "private_key": "AAAA-OLD-SECRET", "listen_port": 51820}]}});
        let b = json!({"tables": {"wg_interfaces": [
            {"id": 1, "name": "wg0", "private_key": "BBBB-NEW-SECRET", "listen_port": 51821},
            {"id": 2, "name": "wg1", "private_key": "CCCC-THIRD-SECRET", "listen_port": 1}]}});
        let d = diff_docs(&a, &b, &keys());
        let text = d.to_string();
        for leak in ["AAAA-OLD-SECRET", "BBBB-NEW-SECRET", "CCCC-THIRD-SECRET"] {
            assert!(!text.contains(leak), "{leak} leaked: {text}");
        }
        let fields = d["tables"][0]["changed"][0]["fields"].as_array().unwrap();
        let pk = fields.iter().find(|f| f["field"] == "private_key").unwrap();
        assert_eq!(pk["change"], "(changed)");
        assert_eq!(d["tables"][0]["added"][0]["row"]["private_key"], "(secret)");
        // the non-secret change next to it is shown with values
        let lp = fields.iter().find(|f| f["field"] == "listen_port").unwrap();
        assert_eq!(lp["to"], 51821);
    }

    #[test]
    fn key_value_rows_with_a_secret_name_are_redacted() {
        let a = json!({"tables": {"system_config": [{"key": "smtp.password", "value": "hunter2"},
                                                     {"key": "hostname", "value": "fw1"}]}});
        let b = json!({"tables": {"system_config": [{"key": "smtp.password", "value": "hunter3"},
                                                     {"key": "hostname", "value": "fw2"}]}});
        let d = diff_docs(&a, &b, &keys());
        let text = d.to_string();
        assert!(!text.contains("hunter"));
        assert!(text.contains("fw1") && text.contains("fw2"));
        assert!(text.contains("(changed)"));
    }

    #[test]
    fn secret_detection_covers_the_real_schema_names() {
        for c in [
            "password",
            "password_hash",
            "totp_secret",
            "recovery_codes",
            "private_key",
            "preshared_key",
            "psk",
            "token_hash",
            "secret",
            "enrol_secret",
            "passphrase",
        ] {
            assert!(looks_secret(c), "{c}");
        }
        for c in ["name", "public_key", "enabled", "address", "segment"] {
            assert!(!looks_secret(c), "{c}");
        }
    }

    #[test]
    fn unified_diff_shows_hunks_and_is_empty_for_equal_text() {
        assert_eq!(unified_diff("a\nb\n", "a\nb\n", "x", "y"), "");
        let a: String = (1..=20).map(|i| format!("line{i}\n")).collect();
        let b = a.replace("line10\n", "line10 changed\n").replace("line19\n", "");
        let d = unified_diff(&a, &b, "gen 1", "live");
        assert!(d.starts_with("--- gen 1\n+++ live\n"), "{d}");
        assert!(d.contains("-line10\n+line10 changed\n"), "{d}");
        assert!(d.contains("-line19\n"), "{d}");
        assert_eq!(d.matches("@@ -").count(), 2, "two hunks: {d}");
        // applying the hunks' counts is consistent: first hunk header
        assert!(d.contains("@@ -7,7 +7,7 @@"), "{d}");
    }

    #[test]
    fn unified_diff_handles_pure_add_and_pure_delete() {
        let d = unified_diff("", "a\nb\n", "x", "y");
        assert!(d.contains("@@ -0,0 +1,2 @@"), "{d}");
        let d = unified_diff("a\nb\n", "", "x", "y");
        assert!(d.contains("@@ -1,2 +0,0 @@"), "{d}");
    }
}
