//! Network state: the kernel's routing table, read live with
//! `ip -json route`. Configured static routes / gateways / multi-WAN are
//! lane E (store + applier); until that lands this page only shows what the
//! kernel really routes, never canned rows. Interfaces live in
//! `state/interfaces.rs` (lane C); DHCP/DNS/NTP/DDNS in `state/lan.rs`
//! (lane D).
//!
//! This file used to return two fixture routes (default via 192.168.1.254
//! on eth0 and 10.1.0.0/24 via wg0) on every box.

use serde_json::Value;

/// Reads the routing table.
#[derive(Default)]
pub struct NetworkManager;

impl NetworkManager {
    pub fn new() -> Self {
        Self
    }

    /// IPv4 + IPv6 routes of the main table, as the kernel has them.
    pub async fn list_routes(&self) -> anyhow::Result<Vec<crate::templates::Route>> {
        tokio::task::spawn_blocking(|| {
            let mut routes = Vec::new();
            for (family, flag) in [(4u8, "-4"), (6u8, "-6")] {
                let out = std::process::Command::new("ip")
                    .args(["-json", flag, "route", "show", "table", "main"])
                    .output()
                    .map_err(|e| anyhow::anyhow!("cannot run `ip` (iproute2): {e}"))?;
                if !out.status.success() {
                    let err = String::from_utf8_lossy(&out.stderr).trim().to_string();
                    if family == 6 {
                        // IPv6 disabled on this box: the IPv4 table stands.
                        tracing::debug!("`ip -6 route`: {err}");
                        continue;
                    }
                    anyhow::bail!("`ip {flag} route` failed: {err}");
                }
                routes.extend(parse_ip_routes(
                    &String::from_utf8_lossy(&out.stdout),
                    family,
                )?);
            }
            Ok(routes)
        })
        .await?
    }
}

/// Parse `ip -json route show` output. `family` (4/6) names the default
/// route's prefix.
pub fn parse_ip_routes(json: &str, family: u8) -> anyhow::Result<Vec<crate::templates::Route>> {
    let json = json.trim();
    if json.is_empty() {
        return Ok(Vec::new());
    }
    let v: Value = serde_json::from_str(json)
        .map_err(|e| anyhow::anyhow!("unexpected `ip -json route` output: {e}"))?;
    let Some(list) = v.as_array() else {
        anyhow::bail!("unexpected `ip -json route` output: not a list");
    };
    let s = |r: &Value, k: &str| r.get(k).and_then(Value::as_str).map(str::to_string);
    Ok(list
        .iter()
        .map(|r| {
            let dst = s(r, "dst").unwrap_or_default();
            let destination = match (dst.as_str(), family) {
                ("default", 4) => "0.0.0.0/0 (default)".to_string(),
                ("default", _) => "::/0 (default)".to_string(),
                _ => dst,
            };
            let mut gateway = s(r, "gateway");
            let mut interface = s(r, "dev");
            if let Some(hops) = r.get("nexthops").and_then(Value::as_array) {
                let g: Vec<String> = hops.iter().filter_map(|h| s(h, "gateway")).collect();
                let d: Vec<String> = hops.iter().filter_map(|h| s(h, "dev")).collect();
                gateway = (!g.is_empty()).then(|| g.join(", "));
                interface = (!d.is_empty()).then(|| d.join(", "));
            }
            let flags: Vec<&str> = r
                .get("flags")
                .and_then(Value::as_array)
                .map(|f| f.iter().filter_map(Value::as_str).collect())
                .unwrap_or_default();
            crate::templates::Route {
                destination,
                gateway: gateway.unwrap_or_else(|| "directly connected".to_string()),
                interface: interface.unwrap_or_default(),
                metric: r.get("metric").and_then(Value::as_u64).unwrap_or(0) as u32,
                // iproute2 omits "protocol" for `boot` (routes added by hand
                // or by a script without `proto`).
                origin: s(r, "protocol").unwrap_or_else(|| "boot".to_string()),
                is_active: !flags.iter().any(|f| *f == "linkdown" || *f == "dead"),
            }
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kernel_routes_are_parsed_not_invented() {
        let v4 = r#"[{"dst":"default","gateway":"203.0.113.1","dev":"rtr-wan","protocol":"dhcp","metric":1024,"flags":[]},
            {"dst":"192.168.50.0/24","dev":"rtr-lan","protocol":"kernel","scope":"link","prefsrc":"192.168.50.1","flags":["linkdown"]},
            {"dst":"10.77.0.0/24","gateway":"192.168.50.10","dev":"rtr-lan","flags":[]},
            {"dst":"10.88.0.0/16","protocol":"static","flags":[],"nexthops":[{"gateway":"192.0.2.1","dev":"a","weight":1,"flags":[]},{"gateway":"192.0.2.2","dev":"b","weight":1,"flags":[]}]}]"#;
        let r = parse_ip_routes(v4, 4).unwrap();
        assert_eq!(r.len(), 4);
        assert_eq!(r[0].destination, "0.0.0.0/0 (default)");
        assert_eq!(r[0].gateway, "203.0.113.1");
        assert_eq!(r[0].interface, "rtr-wan");
        assert_eq!(r[0].metric, 1024);
        assert_eq!(r[0].origin, "dhcp");
        assert!(r[0].is_active);
        assert_eq!(r[1].gateway, "directly connected");
        assert_eq!(r[1].origin, "kernel");
        assert!(!r[1].is_active, "linkdown");
        assert_eq!(r[2].origin, "boot");
        assert_eq!(r[3].gateway, "192.0.2.1, 192.0.2.2");
        assert_eq!(r[3].interface, "a, b");
        let v6 = r#"[{"dst":"default","gateway":"fe80::1","dev":"wan","protocol":"ra","metric":1024,"flags":[],"pref":"medium"}]"#;
        assert_eq!(
            parse_ip_routes(v6, 6).unwrap()[0].destination,
            "::/0 (default)"
        );
    }

    #[test]
    fn an_empty_table_is_an_empty_list() {
        assert!(parse_ip_routes("", 4).unwrap().is_empty());
        assert!(parse_ip_routes("[]\n", 6).unwrap().is_empty());
        assert!(parse_ip_routes("garbage", 4).is_err());
    }
}
