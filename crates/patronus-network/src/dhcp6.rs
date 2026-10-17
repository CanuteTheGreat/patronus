//! DHCPv6 server pools (stateful addresses): store model + config fragments
//! for Kea (`/etc/kea/kea-dhcp6.conf`) and dnsmasq. Applied by
//! [`crate::dhcp::DhcpApplier`] together with DHCPv4 and router
//! advertisements ([`crate::ra`]), because dnsmasq serves all three from one
//! config and DHCPv6 clients only ask once an RA tells them to (M flag).

use crate::lan::{self, db_err, invalid, now, IfAddr};
use patronus_config::store::ConfigStore;
use patronus_config::ApplyReport;
use patronus_core::Result;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::Row;
use std::net::{IpAddr, Ipv6Addr};

pub const KEA6_CONF: &str = "/etc/kea/kea-dhcp6.conf";
pub const KEA6_BIN: &str = "/usr/sbin/kea-dhcp6";
pub const KEA6_LEASES: &str = "/var/lib/kea/kea-leases6.csv";

/// A DHCPv6 pool as stored.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Dhcp6Pool {
    pub id: i64,
    pub interface: String,
    pub enabled: bool,
    pub range_start: Ipv6Addr,
    pub range_end: Ipv6Addr,
    pub prefix_len: u8,
    pub lease_time: u32,
    pub dns_servers: Vec<IpAddr>,
    pub description: Option<String>,
}

/// API/UI input (strings, validated by [`Dhcp6Input::validate`]).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Dhcp6Input {
    pub interface: String,
    #[serde(default = "yes")]
    pub enabled: bool,
    pub range_start: String,
    pub range_end: String,
    #[serde(default)]
    pub prefix_len: Option<u8>,
    #[serde(default)]
    pub lease_time: Option<u32>,
    #[serde(default)]
    pub dns_servers: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
}

fn yes() -> bool {
    true
}

impl Dhcp6Input {
    pub fn validate(&self) -> Result<Dhcp6Pool> {
        let interface = lan::check_iface_spec(&self.interface)?;
        let p = |what: &str, s: &str| -> Result<Ipv6Addr> {
            s.trim()
                .parse()
                .map_err(|_| invalid(format!("{what} {s:?} (an IPv6 address)")))
        };
        let range_start = p("range start", &self.range_start)?;
        let range_end = p("range end", &self.range_end)?;
        if u128::from(range_start) > u128::from(range_end) {
            return Err(invalid("range: start is after end"));
        }
        let prefix_len = self.prefix_len.unwrap_or(64);
        if !(48..=128).contains(&prefix_len) {
            return Err(invalid("prefix length (48-128)"));
        }
        let mask = u128::MAX << (128 - prefix_len as u32);
        if u128::from(range_start) & mask != u128::from(range_end) & mask {
            return Err(invalid("range: start and end are not in the same prefix"));
        }
        let lease_time = self.lease_time.unwrap_or(86400);
        if !(120..=31_536_000).contains(&lease_time) {
            return Err(invalid("lease time (120 s to 1 year)"));
        }
        Ok(Dhcp6Pool {
            id: 0,
            interface,
            enabled: self.enabled,
            range_start,
            range_end,
            prefix_len,
            lease_time,
            dns_servers: lan::parse_ip_list(
                "DNS server",
                self.dns_servers.as_deref().unwrap_or(""),
            )?,
            description: lan::check_description(self.description.as_deref())?,
        })
    }
}

fn row_to_pool(r: &sqlx::sqlite::SqliteRow) -> Option<Dhcp6Pool> {
    Some(Dhcp6Pool {
        id: r.get("id"),
        interface: r.get("interface"),
        enabled: r.get::<i64, _>("enabled") != 0,
        range_start: r.get::<String, _>("range_start").parse().ok()?,
        range_end: r.get::<String, _>("range_end").parse().ok()?,
        prefix_len: r.get::<i64, _>("prefix_len") as u8,
        lease_time: r.get::<i64, _>("lease_time") as u32,
        dns_servers: lan::parse_ip_list(
            "",
            &r.get::<Option<String>, _>("dns_servers")
                .unwrap_or_default(),
        )
        .unwrap_or_default(),
        description: r.get("description"),
    })
}

pub async fn list(store: &ConfigStore) -> Result<Vec<Dhcp6Pool>> {
    let rows = sqlx::query("SELECT * FROM dhcp6_pools ORDER BY id")
        .fetch_all(store.pool()?)
        .await
        .map_err(db_err("load DHCPv6 pools"))?;
    Ok(rows.iter().filter_map(row_to_pool).collect())
}

pub async fn upsert(store: &ConfigStore, id: Option<i64>, p: &Dhcp6Pool) -> Result<i64> {
    let dns = lan::join_ips(&p.dns_servers);
    let mut q = match id {
        None => sqlx::query(
            "INSERT INTO dhcp6_pools (interface, enabled, range_start, range_end, prefix_len,
             lease_time, dns_servers, description, updated_at) VALUES (?,?,?,?,?,?,?,?,?)",
        ),
        Some(_) => sqlx::query(
            "UPDATE dhcp6_pools SET interface=?, enabled=?, range_start=?, range_end=?,
             prefix_len=?, lease_time=?, dns_servers=?, description=?, updated_at=? WHERE id=?",
        ),
    }
    .bind(&p.interface)
    .bind(p.enabled as i64)
    .bind(p.range_start.to_string())
    .bind(p.range_end.to_string())
    .bind(p.prefix_len as i64)
    .bind(p.lease_time as i64)
    .bind(dns)
    .bind(&p.description)
    .bind(now());
    if let Some(i) = id {
        q = q.bind(i);
    }
    let res = q
        .execute(store.pool()?)
        .await
        .map_err(|e| lan::unique_err(e, &p.interface))?;
    match id {
        Some(i) if res.rows_affected() == 0 => Err(patronus_core::Error::Config(format!(
            "DHCPv6 pool {i} not found"
        ))),
        Some(i) => Ok(i),
        None => Ok(res.last_insert_rowid()),
    }
}

pub async fn delete(store: &ConfigStore, id: i64) -> Result<()> {
    let r = sqlx::query("DELETE FROM dhcp6_pools WHERE id = ?")
        .bind(id)
        .execute(store.pool()?)
        .await
        .map_err(db_err("delete DHCPv6 pool"))?;
    if r.rows_affected() == 0 {
        return Err(patronus_core::Error::Config(format!(
            "DHCPv6 pool {id} not found"
        )));
    }
    Ok(())
}

/// A pool bound to a device and the router's address in its prefix.
#[derive(Debug, Clone)]
pub struct Resolved6 {
    pub pool: Dhcp6Pool,
    pub dev: String,
    pub router: Ipv6Addr,
    pub subnet: String,
}

/// Bind enabled pools to devices (the device whose global address prefix
/// holds the range); warn and skip the rest.
pub async fn resolve(
    store: &ConfigStore,
    addrs: &[IfAddr],
    rep: &mut ApplyReport,
) -> Result<Vec<Resolved6>> {
    let mut out = Vec::new();
    for p in list(store).await?.into_iter().filter(|p| p.enabled) {
        let devs = lan::resolve_iface(store, &p.interface).await?;
        if devs.is_empty() {
            rep.warn(format!(
                "DHCPv6 pool on {}: interface role is not assigned, skipped",
                p.interface
            ));
            continue;
        }
        let hit = addrs.iter().find(|a| {
            devs.contains(&a.ifname)
                && a.is_global_v6()
                && a.prefix == p.prefix_len
                && a.network()
                    .is_some_and(|n| n.contains(IpAddr::V6(p.range_start)))
        });
        match hit {
            Some(a) => {
                let IpAddr::V6(router) = a.addr else { continue };
                out.push(Resolved6 {
                    subnet: a.network().map(|n| n.to_string()).unwrap_or_default(),
                    dev: a.ifname.clone(),
                    router,
                    pool: p,
                });
            }
            None => rep.warn(format!(
                "DHCPv6 pool {}-{} on {}: no address in that /{} on {}, skipped",
                p.range_start,
                p.range_end,
                p.interface,
                p.prefix_len,
                devs.join(",")
            )),
        }
    }
    Ok(out)
}

fn dns_for(r: &Resolved6, dns_on: bool) -> Vec<String> {
    if !r.pool.dns_servers.is_empty() {
        r.pool
            .dns_servers
            .iter()
            .filter(|a| a.is_ipv6())
            .map(|a| a.to_string())
            .collect()
    } else if dns_on {
        vec![r.router.to_string()]
    } else {
        vec![]
    }
}

/// `/etc/kea/kea-dhcp6.conf` for the resolved pools.
pub fn render_kea(pools: &[Resolved6], dns_on: bool) -> String {
    let mut ifaces: Vec<&str> = pools.iter().map(|r| r.dev.as_str()).collect();
    ifaces.sort();
    ifaces.dedup();
    let subnets: Vec<Value> = pools
        .iter()
        .map(|r| {
            let dns = dns_for(r, dns_on);
            let mut s = json!({
                "id": r.pool.id,
                "subnet": r.subnet,
                "interface": r.dev,
                "pools": [{"pool": format!("{} - {}", r.pool.range_start, r.pool.range_end)}],
                "valid-lifetime": r.pool.lease_time,
                "preferred-lifetime": r.pool.lease_time / 2 + r.pool.lease_time / 4,
            });
            if !dns.is_empty() {
                s["option-data"] = json!([{"name": "dns-servers", "data": dns.join(", ")}]);
            }
            s
        })
        .collect();
    let doc = json!({
        "Dhcp6": {
            "interfaces-config": {"interfaces": ifaces},
            "lease-database": {"type": "memfile", "persist": true, "name": KEA6_LEASES, "lfc-interval": 3600},
            "subnet6": subnets,
            "loggers": [{"name": "kea-dhcp6", "output-options": [{"output": "stdout"}], "severity": "INFO"}],
        }
    });
    format!(
        "{}{}\n",
        lan::header("//", "Kea DHCPv6 server"),
        serde_json::to_string_pretty(&doc).unwrap_or_default()
    )
}

/// dnsmasq lines for one pool (the RA mode decides `slaac`).
pub fn dnsmasq_lines(r: &Resolved6, with_slaac: bool, dns_on: bool) -> Vec<String> {
    let tag = format!("v6p{}", r.pool.id);
    let mut v = vec![format!(
        "dhcp-range=set:{tag},{},{},{}{},{}",
        r.pool.range_start,
        r.pool.range_end,
        if with_slaac { "slaac," } else { "" },
        r.pool.prefix_len,
        r.pool.lease_time
    )];
    let dns = dns_for(r, dns_on);
    if !dns.is_empty() {
        v.push(format!(
            "dhcp-option=tag:{tag},option6:dns-server,{}",
            dns.iter()
                .map(|a| format!("[{a}]"))
                .collect::<Vec<_>>()
                .join(",")
        ));
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_ranges() {
        let mut i = Dhcp6Input {
            interface: "@lan".into(),
            enabled: true,
            range_start: "fd00:50::100".into(),
            range_end: "fd00:50::1ff".into(),
            ..Default::default()
        };
        assert!(i.validate().is_ok());
        i.range_end = "fd00:51::1".into();
        assert!(i.validate().unwrap_err().to_string().contains("Invalid"));
        i.range_end = "nope".into();
        assert!(i.validate().is_err());
    }
}
