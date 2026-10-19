//! IPv6 router advertisements (SLAAC / DHCPv6 signalling) per interface:
//! store model + `/etc/radvd.conf` rendering. The dnsmasq rendering lives
//! with the DHCP orchestration in [`crate::dhcp`] because dnsmasq ties RA
//! to its DHCPv6 ranges. Applied by [`crate::dhcp::DhcpApplier`].
//!
//! Modes (pfSense naming):
//! - `slaac`: prefix with the A flag, no DHCPv6.
//! - `stateless`: SLAAC addresses, O flag (DNS etc. via DHCPv6).
//! - `managed`: M+O flags, prefix not autonomous: addresses from DHCPv6 only.
//! - `assisted`: M+O flags and an autonomous prefix: DHCPv6 and SLAAC.

use crate::lan::{self, db_err, invalid, now, IfAddr};
use patronus_config::store::ConfigStore;
use patronus_config::ApplyReport;
use patronus_core::Result;
use serde::{Deserialize, Serialize};
use sqlx::Row;
use std::net::{IpAddr, Ipv6Addr};

pub const RADVD_CONF: &str = "/etc/radvd.conf";
pub const RADVD_BIN: &str = "/usr/sbin/radvd";
/// OpenRC's radvd script turns IPv6 forwarding OFF when it stops unless
/// FORWARD="no" here; Patronus owns forwarding (sysctl phase).
pub const RADVD_CONFD: &str = "/etc/conf.d/radvd";

pub const MODES: &[&str] = &["slaac", "stateless", "managed", "assisted"];

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RaConfig {
    pub id: i64,
    pub interface: String,
    pub enabled: bool,
    pub mode: String,
    pub prefix: Option<String>,
    pub dns_servers: Vec<IpAddr>,
    pub min_interval: u32,
    pub max_interval: u32,
    pub description: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RaInput {
    pub interface: String,
    #[serde(default = "yes")]
    pub enabled: bool,
    #[serde(default)]
    pub mode: Option<String>,
    #[serde(default)]
    pub prefix: Option<String>,
    #[serde(default)]
    pub dns_servers: Option<String>,
    #[serde(default)]
    pub min_interval: Option<u32>,
    #[serde(default)]
    pub max_interval: Option<u32>,
    #[serde(default)]
    pub description: Option<String>,
}

fn yes() -> bool {
    true
}

impl RaInput {
    pub fn validate(&self) -> Result<RaConfig> {
        let interface = lan::check_iface_spec(&self.interface)?;
        let mode = self
            .mode
            .as_deref()
            .map(str::trim)
            .filter(|m| !m.is_empty())
            .unwrap_or("slaac")
            .to_ascii_lowercase();
        if !MODES.contains(&mode.as_str()) {
            return Err(invalid(format!(
                "RA mode {mode:?} (slaac, stateless, managed or assisted)"
            )));
        }
        let prefix = match self
            .prefix
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            None => None,
            Some(p) => {
                let n: ipnetwork::Ipv6Network = p
                    .parse()
                    .map_err(|_| invalid(format!("prefix {p:?} (e.g. fd00:50::/64)")))?;
                if n.prefix() != 64 {
                    return Err(invalid("prefix: SLAAC needs a /64"));
                }
                Some(format!("{}/64", n.network()))
            }
        };
        let dns_servers = lan::parse_ip_list("RDNSS", self.dns_servers.as_deref().unwrap_or(""))?;
        if dns_servers.iter().any(|a| a.is_ipv4()) {
            return Err(invalid(
                "RDNSS: router advertisements carry IPv6 DNS servers only",
            ));
        }
        let min_interval = self.min_interval.unwrap_or(200);
        let max_interval = self.max_interval.unwrap_or(600);
        // RFC 4861 6.2.1; widened so a huge `min_interval` from the API
        // cannot wrap `* 4` (u32) past the 0.75 x max bound.
        if !(4..=1800).contains(&max_interval)
            || min_interval < 3
            || u64::from(min_interval) * 4 > u64::from(max_interval) * 3
        {
            return Err(invalid(
                "RA intervals (max 4-1800 s, min >= 3 s and <= 0.75 x max)",
            ));
        }
        Ok(RaConfig {
            id: 0,
            interface,
            enabled: self.enabled,
            mode,
            prefix,
            dns_servers,
            min_interval,
            max_interval,
            description: lan::check_description(self.description.as_deref())?,
        })
    }
}

fn row_to_ra(r: &sqlx::sqlite::SqliteRow) -> RaConfig {
    RaConfig {
        id: r.get("id"),
        interface: r.get("interface"),
        enabled: r.get::<i64, _>("enabled") != 0,
        mode: r.get("mode"),
        prefix: r.get("prefix"),
        dns_servers: lan::parse_ip_list(
            "",
            &r.get::<Option<String>, _>("dns_servers")
                .unwrap_or_default(),
        )
        .unwrap_or_default(),
        min_interval: r.get::<i64, _>("min_interval") as u32,
        max_interval: r.get::<i64, _>("max_interval") as u32,
        description: r.get("description"),
    }
}

pub async fn list(store: &ConfigStore) -> Result<Vec<RaConfig>> {
    let rows = sqlx::query("SELECT * FROM ra_interfaces ORDER BY id")
        .fetch_all(store.pool()?)
        .await
        .map_err(db_err("load RA config"))?;
    Ok(rows.iter().map(row_to_ra).collect())
}

pub async fn upsert(store: &ConfigStore, id: Option<i64>, c: &RaConfig) -> Result<i64> {
    let mut q = match id {
        None => sqlx::query(
            "INSERT INTO ra_interfaces (interface, enabled, mode, prefix, dns_servers,
             min_interval, max_interval, description, updated_at) VALUES (?,?,?,?,?,?,?,?,?)",
        ),
        Some(_) => sqlx::query(
            "UPDATE ra_interfaces SET interface=?, enabled=?, mode=?, prefix=?, dns_servers=?,
             min_interval=?, max_interval=?, description=?, updated_at=? WHERE id=?",
        ),
    }
    .bind(&c.interface)
    .bind(c.enabled as i64)
    .bind(&c.mode)
    .bind(&c.prefix)
    .bind(lan::join_ips(&c.dns_servers))
    .bind(c.min_interval as i64)
    .bind(c.max_interval as i64)
    .bind(&c.description)
    .bind(now());
    if let Some(i) = id {
        q = q.bind(i);
    }
    let res = q
        .execute(store.pool()?)
        .await
        .map_err(|e| lan::unique_err(e, &c.interface))?;
    match id {
        Some(i) if res.rows_affected() == 0 => Err(patronus_core::Error::Config(format!(
            "RA config {i} not found"
        ))),
        Some(i) => Ok(i),
        None => Ok(res.last_insert_rowid()),
    }
}

pub async fn delete(store: &ConfigStore, id: i64) -> Result<()> {
    let r = sqlx::query("DELETE FROM ra_interfaces WHERE id = ?")
        .bind(id)
        .execute(store.pool()?)
        .await
        .map_err(db_err("delete RA config"))?;
    if r.rows_affected() == 0 {
        return Err(patronus_core::Error::Config(format!(
            "RA config {id} not found"
        )));
    }
    Ok(())
}

/// RA config bound to a device, with the router's global v6 address there.
#[derive(Debug, Clone)]
pub struct ResolvedRa {
    pub ra: RaConfig,
    pub dev: String,
    pub router: Option<Ipv6Addr>,
}

pub async fn resolve(
    store: &ConfigStore,
    addrs: &[IfAddr],
    rep: &mut ApplyReport,
) -> Result<Vec<ResolvedRa>> {
    let mut out = Vec::new();
    for ra in list(store).await?.into_iter().filter(|r| r.enabled) {
        let devs = lan::resolve_iface(store, &ra.interface).await?;
        if devs.is_empty() {
            rep.warn(format!(
                "router advertisements on {}: interface role is not assigned, skipped",
                ra.interface
            ));
            continue;
        }
        for dev in devs {
            let router = addrs.iter().find_map(|a| match a.addr {
                IpAddr::V6(v6) if a.ifname == dev && a.is_global_v6() => Some(v6),
                _ => None,
            });
            if router.is_none() && ra.prefix.is_none() {
                rep.warn(format!(
                    "router advertisements on {dev}: no global IPv6 address to advertise a prefix from"
                ));
            }
            out.push(ResolvedRa {
                ra: ra.clone(),
                dev,
                router,
            });
        }
    }
    Ok(out)
}

pub fn flags(mode: &str) -> (bool, bool, bool) {
    // (managed M, other O, autonomous A)
    match mode {
        "managed" => (true, true, false),
        "assisted" => (true, true, true),
        "stateless" => (false, true, true),
        _ => (false, false, true),
    }
}

/// Modes whose RA must carry the M flag (addresses via DHCPv6).
pub fn needs_managed_flag(mode: &str) -> bool {
    flags(mode).0
}

fn rdnss(r: &ResolvedRa, dns_on: bool) -> Vec<String> {
    if !r.ra.dns_servers.is_empty() {
        r.ra.dns_servers.iter().map(|a| a.to_string()).collect()
    } else if dns_on {
        r.router.map(|a| vec![a.to_string()]).unwrap_or_default()
    } else {
        vec![]
    }
}

/// `/etc/radvd.conf`.
pub fn render_radvd(ras: &[ResolvedRa], dns_on: bool) -> String {
    let mut s = lan::header("#", "radvd: IPv6 router advertisements");
    for r in ras {
        let (m, o, a) = flags(&r.ra.mode);
        let on = |b: bool| if b { "on" } else { "off" };
        s.push_str(&format!(
            "\ninterface {} {{\n    AdvSendAdvert on;\n    IgnoreIfMissing on;\n    \
             MinRtrAdvInterval {};\n    MaxRtrAdvInterval {};\n    \
             AdvManagedFlag {};\n    AdvOtherConfigFlag {};\n",
            r.dev,
            r.ra.min_interval,
            r.ra.max_interval,
            on(m),
            on(o)
        ));
        // `::/64` = every /64 configured on the interface
        let prefix = r.ra.prefix.clone().unwrap_or_else(|| "::/64".into());
        s.push_str(&format!(
            "    prefix {prefix} {{\n        AdvOnLink on;\n        AdvAutonomous {};\n    }};\n",
            on(a)
        ));
        let dns = rdnss(r, dns_on);
        if !dns.is_empty() {
            s.push_str(&format!("    RDNSS {} {{\n    }};\n", dns.join(" ")));
        }
        s.push_str("};\n");
    }
    s
}

/// dnsmasq lines for an interface with RA but no DHCPv6 pool.
///
/// dnsmasq cannot set the M flag here, so `managed`/`assisted` come out as
/// `ra-only` (SLAAC); [`crate::dhcp`]'s plan warns about that.
pub fn dnsmasq_ra_only_lines(r: &ResolvedRa, dns_on: bool) -> Vec<String> {
    let kind = match r.ra.mode.as_str() {
        "stateless" => "ra-stateless",
        _ => "ra-only",
    };
    let mut v = vec![match &r.ra.prefix {
        Some(p) => {
            let base = p.split('/').next().unwrap_or(p);
            format!("dhcp-range=set:ra-{},{base},{kind},64", r.dev)
        }
        None => format!(
            "dhcp-range=set:ra-{},::,constructor:{},{kind},64",
            r.dev, r.dev
        ),
    }];
    let dns = rdnss(r, dns_on);
    if !dns.is_empty() {
        v.push(format!(
            "dhcp-option=tag:ra-{},option6:dns-server,{}",
            r.dev,
            dns.iter()
                .map(|a| format!("[{a}]"))
                .collect::<Vec<_>>()
                .join(",")
        ));
    }
    v
}

pub fn dnsmasq_ra_param(r: &ResolvedRa) -> String {
    format!(
        "ra-param={},{},{}",
        r.dev,
        r.ra.max_interval,
        r.ra.max_interval * 3
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn radvd_flags_per_mode() {
        let ra = |mode: &str| ResolvedRa {
            ra: RaInput {
                interface: "@lan".into(),
                enabled: true,
                mode: Some(mode.into()),
                ..Default::default()
            }
            .validate()
            .unwrap(),
            dev: "rtr-lan".into(),
            router: Some("fd00:50::1".parse().unwrap()),
        };
        let s = render_radvd(&[ra("managed")], true);
        assert!(s.contains("interface rtr-lan {"));
        assert!(s.contains("AdvManagedFlag on;") && s.contains("AdvAutonomous off;"));
        assert!(s.contains("RDNSS fd00:50::1"));
        let s = render_radvd(&[ra("slaac")], false);
        assert!(s.contains("AdvManagedFlag off;") && s.contains("AdvAutonomous on;"));
        assert!(!s.contains("RDNSS"));
        assert!(RaInput {
            interface: "@lan".into(),
            mode: Some("bogus".into()),
            ..Default::default()
        }
        .validate()
        .is_err());
    }

    #[test]
    fn intervals_follow_rfc4861_without_overflow() {
        let v = |min: u32, max: u32| {
            RaInput {
                interface: "@lan".into(),
                min_interval: Some(min),
                max_interval: Some(max),
                ..Default::default()
            }
            .validate()
        };
        assert!(v(3, 4).is_ok());
        assert!(v(450, 600).is_ok());
        assert!(v(451, 600).is_err(), "min > 0.75 x max");
        assert!(v(2, 600).is_err(), "min < 3");
        assert!(v(3, 1801).is_err(), "max > 1800");
        // 2^30 * 4 wraps to 0 in u32: must still be rejected, not panic
        assert!(v(1 << 30, 600).is_err());
        assert!(v(u32::MAX, 1800).is_err());
    }
}
