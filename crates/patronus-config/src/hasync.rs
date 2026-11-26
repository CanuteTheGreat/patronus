//! HA configuration sync (lane G): which parts of the configuration a primary pushes to its
//! backup, and how a pushed part is merged into the backup's own configuration.
//!
//! A *section* is a set of configuration tables plus the `lan_settings` keys with given
//! prefixes. Everything node-specific (interfaces and their addresses, the `ha.*` keys, accounts,
//! TLS, API keys, measured history) belongs to no section and is never sent. Interface references
//! in the rows travel as roles (`@wan`, `@lan`, `@opt1`) so the backup resolves them on its own
//! devices, whatever they are called there.

use crate::store::ConfigStore;
use patronus_core::{Error, Result};
use serde_json::{json, Map, Value};

pub struct Section {
    pub name: &'static str,
    pub label: &'static str,
    pub tables: &'static [&'static str],
    /// `lan_settings` keys that start with one of these belong to the section
    pub prefixes: &'static [&'static str],
}

pub const SECTIONS: &[Section] = &[
    Section {
        name: "firewall",
        label: "Firewall rules and settings",
        tables: &["firewall_rules"],
        prefixes: &["firewall."],
    },
    Section {
        name: "aliases",
        label: "Aliases",
        tables: &["firewall_aliases", "firewall_alias_sources"],
        prefixes: &[],
    },
    Section {
        name: "schedules",
        label: "Schedules",
        tables: &["firewall_schedules"],
        prefixes: &[],
    },
    Section {
        name: "nat",
        label: "NAT",
        tables: &["nat_rules"],
        prefixes: &["nat64."],
    },
    Section {
        name: "dhcp",
        label: "DHCP server",
        tables: &[
            "dhcp_pools",
            "dhcp6_pools",
            "dhcp_static_mappings",
            "dhcp_relays",
        ],
        prefixes: &["dhcp."],
    },
    Section {
        name: "dns",
        label: "DNS forwarder / resolver",
        tables: &[
            "dns_blocklist",
            "dns_domain_overrides",
            "dns_host_overrides",
        ],
        prefixes: &["dns."],
    },
    Section {
        name: "vpn",
        label: "VPN (WireGuard, IPsec, OpenVPN, L2TP)",
        tables: &[
            "wg_interfaces",
            "wg_peers",
            "ipsec_tunnels",
            "ipsec_rw_profiles",
            "ipsec_rw_users",
            "ipsec_pki",
            "openvpn_clients",
            "openvpn_pki",
            "l2tp_users",
        ],
        prefixes: &["vpn.", "openvpn.", "l2tp."],
    },
];

pub fn section(name: &str) -> Option<&'static Section> {
    SECTIONS.iter().find(|s| s.name == name)
}

/// Columns that name an interface (a device or a role).
const INTERFACE_COLUMNS: &[&str] = &["interface", "interface_in", "interface_out"];

fn setting_in(sec: &Section, key: &str) -> bool {
    sec.prefixes.iter().any(|p| key.starts_with(p))
}

fn check_names(names: &[String]) -> Result<Vec<&'static Section>> {
    let mut out = Vec::new();
    for n in names {
        let s = section(n).ok_or_else(|| {
            Error::Config(format!(
                "Invalid sync section {n:?}: one of {}",
                SECTIONS
                    .iter()
                    .map(|s| s.name)
                    .collect::<Vec<_>>()
                    .join(", ")
            ))
        })?;
        if !out.iter().any(|x: &&Section| x.name == s.name) {
            out.push(s);
        }
    }
    Ok(out)
}

/// Device name -> role of this node's interfaces (`@lan`, `@wan`, ...).
fn device_roles(interfaces: &Value) -> Vec<(String, String)> {
    interfaces
        .pointer("/tables/interfaces")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|r| {
            let name = r.get("name")?.as_str()?;
            let role = r.get("role")?.as_str()?;
            (!role.is_empty()).then(|| {
                (
                    name.to_string(),
                    format!("@{}", role.trim_start_matches('@')),
                )
            })
        })
        .collect()
}

/// A document of the sections `names` ready to be pushed:
/// `{"version":1,"sections":[..],"tables":{..},"settings":{key:value}}`.
/// Interface device names are replaced by their role.
pub async fn export_sections(store: &ConfigStore, names: &[String]) -> Result<Value> {
    let secs = check_names(names)?;
    let mut want: Vec<&str> = secs.iter().flat_map(|s| s.tables.iter().copied()).collect();
    want.push("interfaces");
    want.push("lan_settings");
    let doc = store.export_tables_json(&want).await?;
    let roles = device_roles(&doc);
    let mut tables = Map::new();
    for s in &secs {
        for t in s.tables {
            let Some(rows) = doc
                .pointer(&format!("/tables/{t}"))
                .and_then(Value::as_array)
            else {
                continue;
            };
            let mut out = Vec::new();
            for r in rows {
                let mut r = r.clone();
                if let Some(o) = r.as_object_mut() {
                    for c in INTERFACE_COLUMNS {
                        if let Some(Value::String(v)) = o.get(*c) {
                            if let Some((_, role)) = roles.iter().find(|(d, _)| d == v) {
                                o.insert((*c).to_string(), Value::String(role.clone()));
                            }
                        }
                    }
                }
                out.push(r);
            }
            tables.insert((*t).to_string(), Value::Array(out));
        }
    }
    let mut settings = Map::new();
    for r in doc
        .pointer("/tables/lan_settings")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let (Some(k), Some(v)) = (
            r.get("key").and_then(Value::as_str),
            r.get("value").and_then(Value::as_str),
        ) else {
            continue;
        };
        if secs.iter().any(|s| setting_in(s, k)) {
            settings.insert(k.to_string(), Value::String(v.to_string()));
        }
    }
    Ok(json!({
        "version": 1,
        "sections": secs.iter().map(|s| s.name).collect::<Vec<_>>(),
        "tables": tables,
        "settings": settings,
    }))
}

/// Canonical text of a document (object keys sorted), the input of its hash.
pub fn canonical(v: &Value) -> String {
    fn go(v: &Value, o: &mut String) {
        match v {
            Value::Object(m) => {
                let mut k: Vec<&String> = m.keys().collect();
                k.sort();
                o.push('{');
                for (i, k) in k.into_iter().enumerate() {
                    if i > 0 {
                        o.push(',');
                    }
                    o.push_str(&Value::String(k.clone()).to_string());
                    o.push(':');
                    go(&m[k], o);
                }
                o.push('}');
            }
            Value::Array(a) => {
                o.push('[');
                for (i, x) in a.iter().enumerate() {
                    if i > 0 {
                        o.push(',');
                    }
                    go(x, o);
                }
                o.push(']');
            }
            other => o.push_str(&other.to_string()),
        }
    }
    let mut o = String::new();
    go(v, &mut o);
    o
}

/// The target's own export with the pushed sections replaced: `local` is its
/// `ConfigStore::export_json`, `incoming` a document from [`export_sections`]. Only the sections
/// the incoming document names are touched; every other table, and the `lan_settings` keys outside
/// those sections, stay as they are. Unknown sections and tables are errors.
pub fn merge(local: &Value, incoming: &Value) -> Result<Value> {
    let names: Vec<String> = incoming
        .get("sections")
        .and_then(Value::as_array)
        .ok_or_else(|| Error::Config("Invalid sync document: no 'sections'".into()))?
        .iter()
        .filter_map(|v| v.as_str().map(str::to_string))
        .collect();
    if incoming.get("version").and_then(Value::as_i64) != Some(1) {
        return Err(Error::Config(
            "Invalid sync document: unknown version".into(),
        ));
    }
    let secs = check_names(&names)?;
    let in_tables = incoming
        .get("tables")
        .and_then(Value::as_object)
        .ok_or_else(|| Error::Config("Invalid sync document: no 'tables'".into()))?;
    for t in in_tables.keys() {
        if !secs.iter().any(|s| s.tables.contains(&t.as_str())) {
            return Err(Error::Config(format!(
                "Invalid sync document: table {t:?} is not in the pushed sections"
            )));
        }
    }
    let in_settings = incoming
        .get("settings")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    for k in in_settings.keys() {
        if !secs.iter().any(|s| setting_in(s, k)) {
            return Err(Error::Config(format!(
                "Invalid sync document: setting {k:?} is not in the pushed sections"
            )));
        }
    }
    let mut doc = local.clone();
    let tables = doc
        .get_mut("tables")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| Error::Config("Invalid configuration document: no 'tables'".into()))?;
    for (t, rows) in in_tables {
        // a table this build does not have (a feature it lacks) is skipped, not an error
        if tables.contains_key(t) {
            tables.insert(t.clone(), rows.clone());
        }
    }
    let now = chrono::Utc::now().timestamp();
    let mut rows: Vec<Value> = tables
        .get("lan_settings")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter(|r| {
            r.get("key")
                .and_then(Value::as_str)
                .is_none_or(|k| !secs.iter().any(|s| setting_in(s, k)))
        })
        .collect();
    for (k, v) in &in_settings {
        rows.push(json!({"key": k, "value": v, "updated_at": now}));
    }
    tables.insert("lan_settings".into(), Value::Array(rows));
    Ok(doc)
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn store() -> (tempfile::TempDir, ConfigStore) {
        let d = tempfile::tempdir().unwrap();
        let s = ConfigStore::open(d.path().join("c.db")).await.unwrap();
        (d, s)
    }

    fn put(s: &ConfigStore, sql: &str) -> impl std::future::Future<Output = ()> + '_ {
        let sql = sql.to_string();
        async move {
            sqlx::query(&sql).execute(s.pool().unwrap()).await.unwrap();
        }
    }

    #[tokio::test]
    async fn exports_only_the_chosen_sections_with_interface_roles() {
        let (_d, s) = store().await;
        put(
            &s,
            "INSERT INTO interfaces (name, role) VALUES ('enp3s0', 'lan')",
        )
        .await;
        put(
            &s,
            "INSERT INTO firewall_aliases (name, alias_type, entries, updated_at) VALUES ('web', 'host', '[\"10.0.0.5\"]', 1)",
        )
        .await;
        put(
            &s,
            "INSERT INTO lan_settings (key, value, updated_at) VALUES ('dns.mode','forward',1), ('ha.priority','150',1), ('firewall.mss_clamp','1',1)",
        )
        .await;
        let d = export_sections(&s, &["firewall".into(), "aliases".into()])
            .await
            .unwrap();
        assert_eq!(d["sections"], json!(["firewall", "aliases"]));
        assert_eq!(d["tables"]["firewall_aliases"][0]["name"], "web");
        assert!(d["tables"].get("nat_rules").is_none());
        assert_eq!(d["settings"]["firewall.mss_clamp"], "1");
        assert!(
            d["settings"].get("dns.mode").is_none(),
            "dns is another section"
        );
        assert!(
            d["settings"].get("ha.priority").is_none(),
            "ha.* is never synced"
        );
        assert!(export_sections(&s, &["nope".into()]).await.is_err());
    }

    #[tokio::test]
    async fn device_names_become_roles() {
        let (_d, s) = store().await;
        put(
            &s,
            "INSERT INTO interfaces (name, role) VALUES ('enp3s0', 'lan'), ('enp4s0', 'wan')",
        )
        .await;
        let ins = "INSERT INTO nat_rules (name, nat_type, protocol, interface_in, interface_out, enabled, created_at, updated_at) VALUES ";
        sqlx::query(&format!(
            "{ins}('a','dnat','tcp','enp4s0',NULL,1,1,1), ('b','masquerade','tcp',NULL,'@wan',1,1,1)"
        ))
        .execute(s.pool().unwrap())
        .await
        .unwrap();
        let d = export_sections(&s, &["nat".into()]).await.unwrap();
        let rows = d["tables"]["nat_rules"].as_array().unwrap();
        assert!(rows.iter().any(|r| r["interface_in"] == "@wan"), "{rows:?}");
        assert!(rows.iter().any(|r| r["interface_out"] == "@wan"));
    }

    #[test]
    fn merge_replaces_only_the_pushed_sections() {
        let local = json!({"version":2,"tables":{
            "firewall_rules":[{"id":1,"name":"old"}],
            "nat_rules":[{"id":9,"name":"mine"}],
            "lan_settings":[
                {"key":"firewall.mss_clamp","value":"0","updated_at":1},
                {"key":"dns.mode","value":"local","updated_at":1},
                {"key":"ha.priority","value":"100","updated_at":1}]}});
        let incoming = json!({"version":1,"sections":["firewall"],
            "tables":{"firewall_rules":[{"id":5,"name":"new"}]},
            "settings":{"firewall.mss_clamp":"1"}});
        let m = merge(&local, &incoming).unwrap();
        assert_eq!(
            m["tables"]["firewall_rules"],
            json!([{"id":5,"name":"new"}])
        );
        assert_eq!(
            m["tables"]["nat_rules"], local["tables"]["nat_rules"],
            "a switched-off section is untouched"
        );
        let keys: Vec<(&str, &str)> = m["tables"]["lan_settings"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| (r["key"].as_str().unwrap(), r["value"].as_str().unwrap()))
            .collect();
        assert!(keys.contains(&("firewall.mss_clamp", "1")));
        assert!(keys.contains(&("dns.mode", "local")));
        assert!(keys.contains(&("ha.priority", "100")));
        assert_eq!(
            keys.iter()
                .filter(|(k, _)| *k == "firewall.mss_clamp")
                .count(),
            1
        );
    }

    #[test]
    fn merge_refuses_foreign_content() {
        let local = json!({"version":2,"tables":{"firewall_rules":[],"lan_settings":[]}});
        let bad_table =
            json!({"version":1,"sections":["firewall"],"tables":{"web_users":[]},"settings":{}});
        assert!(merge(&local, &bad_table)
            .unwrap_err()
            .to_string()
            .contains("web_users"));
        let bad_key =
            json!({"version":1,"sections":["firewall"],"tables":{},"settings":{"ha.password":"x"}});
        assert!(merge(&local, &bad_key)
            .unwrap_err()
            .to_string()
            .contains("ha.password"));
        let bad_sec = json!({"version":1,"sections":["interfaces"],"tables":{},"settings":{}});
        assert!(merge(&local, &bad_sec).is_err());
        let bad_ver = json!({"version":7,"sections":[],"tables":{},"settings":{}});
        assert!(merge(&local, &bad_ver).is_err());
    }

    #[test]
    fn canonical_text_ignores_key_order() {
        let a = json!({"b":1,"a":[{"y":2,"x":1}]});
        let b: Value = serde_json::from_str(r#"{"a":[{"x":1,"y":2}],"b":1}"#).unwrap();
        assert_eq!(canonical(&a), canonical(&b));
    }

    #[test]
    fn no_table_is_in_two_sections_and_none_is_node_specific() {
        let mut seen = std::collections::BTreeSet::new();
        for s in SECTIONS {
            for t in s.tables {
                assert!(seen.insert(*t), "{t} is in two sections");
                assert!(
                    ![
                        "interfaces",
                        "interface_addresses",
                        "web_users",
                        "api_keys",
                        "ha_vips"
                    ]
                    .contains(t),
                    "{t} is node-specific"
                );
            }
            for p in s.prefixes {
                assert!(
                    !"ha.".starts_with(p) && !p.starts_with("ha."),
                    "{p} would sync HA's own keys"
                );
            }
        }
    }
}
