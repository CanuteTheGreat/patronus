//! Shared pieces of the lane F (VPN) appliers: input validation and the
//! table snapshot the web UI uses to undo a store write when an apply fails.

use crate::lan::{db_err, invalid};
use ipnetwork::IpNetwork;
use patronus_config::store::ConfigStore;
use patronus_core::Result;
use serde_json::Value;

/// Every lane F table, parents first.
pub const VPN_TABLES: &[&str] = &[
    "wg_interfaces",
    "wg_peers",
    "ipsec_tunnels",
    "ipsec_rw_profiles",
    "ipsec_rw_users",
    "ipsec_pki",
];

/// Split a comma/space/newline separated list.
pub fn split_list(s: &str) -> Vec<String> {
    s.split([',', ' ', '\n', '\r', '\t'])
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .map(String::from)
        .collect()
}

/// A list of networks (`10.0.0.0/24`, `fd00::/64`; a bare address is a
/// host route). Host bits are kept as given (`10.99.0.1/24` is valid for
/// an interface address). Returns them normalised and comma-joined.
pub fn check_networks(what: &str, s: &str, allow_empty: bool) -> Result<String> {
    let mut out = Vec::new();
    for t in split_list(s) {
        let n: IpNetwork = t
            .parse()
            .map_err(|_| invalid(format!("{what}: {t:?} is not an address or network")))?;
        if !out.contains(&n.to_string()) {
            out.push(n.to_string());
        }
    }
    if out.is_empty() && !allow_empty {
        return Err(invalid(format!("{what}: at least one network is required")));
    }
    Ok(out.join(", "))
}

/// The networks of a stored list.
pub fn networks(s: &str) -> Vec<IpNetwork> {
    split_list(s)
        .iter()
        .filter_map(|t| t.parse().ok())
        .collect()
}

/// A host name or address (no port).
pub fn check_host(what: &str, s: &str) -> Result<String> {
    let s = s.trim();
    if s.parse::<std::net::IpAddr>().is_ok() || crate::lan::valid_dns_name(s, false) {
        Ok(s.to_string())
    } else {
        Err(invalid(format!(
            "{what}: {s:?} is not an address or host name"
        )))
    }
}

/// `host:port`, `[v6]:port` or `v4:port`.
pub fn check_endpoint(what: &str, s: &str) -> Result<String> {
    let s = s.trim();
    let (host, port) = if let Some(rest) = s.strip_prefix('[') {
        let (h, p) = rest
            .split_once("]:")
            .ok_or_else(|| invalid(format!("{what}: {s:?} is not [address]:port")))?;
        (h, p)
    } else {
        s.rsplit_once(':')
            .ok_or_else(|| invalid(format!("{what}: {s:?} needs a :port")))?
    };
    let port: u16 = port
        .parse()
        .ok()
        .filter(|p| *p > 0)
        .ok_or_else(|| invalid(format!("{what}: bad port in {s:?}")))?;
    if host.contains(':') && !s.starts_with('[') {
        return Err(invalid(format!(
            "{what}: write IPv6 endpoints as [addr]:port"
        )));
    }
    check_host(what, host)?;
    Ok(if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    })
}

/// A free-text name used in config files and UI (letters, digits, `-_. `).
pub fn check_name(what: &str, s: &str, max: usize) -> Result<String> {
    let s = s.trim();
    if s.is_empty()
        || s.len() > max
        || !s
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | ' '))
    {
        return Err(invalid(format!(
            "{what} {s:?}: 1-{max} letters, digits, '-', '_', '.' or spaces"
        )));
    }
    Ok(s.to_string())
}

/// Rows of every lane F table.
pub async fn snapshot_tables(store: &ConfigStore) -> Result<Value> {
    let doc = store.export_json().await?;
    let mut out = serde_json::Map::new();
    if let Some(t) = doc.get("tables").and_then(Value::as_object) {
        for name in VPN_TABLES {
            if let Some(rows) = t.get(*name) {
                out.insert((*name).to_string(), rows.clone());
            }
        }
    }
    Ok(Value::Object(out))
}

/// Put lane F's tables back to a [`snapshot_tables`] state.
pub async fn restore_tables(store: &ConfigStore, snap: &Value) -> Result<()> {
    let Some(tables) = snap.as_object() else {
        return Ok(());
    };
    let mut tx = store
        .pool()?
        .begin()
        .await
        .map_err(db_err("begin restore"))?;
    sqlx::query("PRAGMA defer_foreign_keys = ON")
        .execute(&mut *tx)
        .await
        .map_err(db_err("defer fks"))?;
    for name in VPN_TABLES.iter().rev() {
        sqlx::query(&format!("DELETE FROM \"{name}\""))
            .execute(&mut *tx)
            .await
            .map_err(db_err("restore"))?;
    }
    for name in VPN_TABLES {
        for row in tables
            .get(*name)
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let Some(obj) = row.as_object() else { continue };
            let cols: Vec<&String> = obj.keys().collect();
            if cols.is_empty()
                || !cols
                    .iter()
                    .all(|c| c.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_'))
            {
                continue;
            }
            let sql = format!(
                "INSERT INTO \"{name}\" ({}) VALUES ({})",
                cols.iter()
                    .map(|c| format!("\"{c}\""))
                    .collect::<Vec<_>>()
                    .join(", "),
                vec!["?"; cols.len()].join(", ")
            );
            let mut q = sqlx::query(&sql);
            for c in &cols {
                q = match &obj[*c] {
                    Value::Null => q.bind(None::<String>),
                    Value::Bool(b) => q.bind(*b as i64),
                    Value::Number(n) if n.is_i64() => q.bind(n.as_i64()),
                    Value::Number(n) => q.bind(n.as_f64()),
                    Value::String(s) => q.bind(s.clone()),
                    other => q.bind(other.to_string()),
                };
            }
            q.execute(&mut *tx).await.map_err(db_err("restore row"))?;
        }
    }
    tx.commit().await.map_err(db_err("commit restore"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validators_accept_real_values_and_refuse_junk() {
        assert_eq!(
            check_networks("x", "10.0.0.0/24 fd00::/64,10.0.0.0/24", false).unwrap(),
            "10.0.0.0/24, fd00::/64"
        );
        assert_eq!(
            check_networks("x", "10.9.0.2", false).unwrap(),
            "10.9.0.2/32"
        );
        assert!(check_networks("x", "", false).is_err());
        assert_eq!(check_networks("x", "", true).unwrap(), "");
        assert!(check_networks("x", "10.0.0.0/33", false).is_err());
        assert!(check_networks("x", "evil;rm", false).is_err());
        assert_eq!(
            check_endpoint("e", "vpn.example.net:51820").unwrap(),
            "vpn.example.net:51820"
        );
        assert_eq!(
            check_endpoint("e", "[2001:db8::1]:500").unwrap(),
            "[2001:db8::1]:500"
        );
        assert_eq!(
            check_endpoint("e", "198.51.100.7:1").unwrap(),
            "198.51.100.7:1"
        );
        for bad in [
            "host",
            "host:0",
            "host:70000",
            "2001:db8::1:51820",
            "bad host:1",
            "a\"b:1",
        ] {
            assert!(check_endpoint("e", bad).is_err(), "{bad}");
        }
        assert!(check_name("n", "Site B", 32).is_ok());
        assert!(check_name("n", "a\"b", 32).is_err());
        assert!(check_name("n", "", 32).is_err());
        assert!(check_name("n", &"x".repeat(33), 32).is_err());
    }
}
