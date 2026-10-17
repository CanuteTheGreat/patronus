//! Kernel link/address state as reported by iproute2 (`ip -j -d link`,
//! `ip -j addr`), and the command runner the interfaces applier uses.
//!
//! The applier diffs the store against this snapshot and only issues the
//! commands needed (full-state + idempotent: a second apply is a no-op).

use ipnetwork::IpNetwork;
use patronus_core::{Error, Result};
use serde_json::Value;
use std::collections::BTreeMap;

/// `ifalias` Patronus sets on every virtual device it creates, so it can
/// delete stale ones without ever touching devices it does not own.
pub const MANAGED_ALIAS: &str = "patronus";

/// One kernel address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KAddr {
    pub net: IpNetwork,
    /// Has a finite lifetime (DHCP / SLAAC / DHCPv6), i.e. not ours.
    pub dynamic: bool,
    /// `global`, `link`, `host`.
    pub scope: String,
}

/// One kernel link.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KLink {
    pub name: String,
    pub ifindex: u32,
    /// `vlan`, `bond`, `bridge`, `veth`, `ppp`, ... (None = physical NIC).
    pub kind: Option<String>,
    pub master: Option<String>,
    /// Lower device (VLAN parent).
    pub link: Option<String>,
    pub vlan_id: Option<u16>,
    pub vlan_protocol: Option<String>,
    pub bond_mode: Option<String>,
    pub bond_miimon: Option<u32>,
    pub bond_lacp_rate: Option<String>,
    pub bond_xmit_hash_policy: Option<String>,
    pub bond_primary: Option<String>,
    pub bridge_stp: Option<bool>,
    pub mtu: u32,
    pub mac: Option<String>,
    /// Administratively up (IFF_UP).
    pub up: bool,
    /// Carrier / operational state (`UP`, `DOWN`, `LOWERLAYERDOWN`, ...).
    pub operstate: String,
    pub alias: Option<String>,
    pub addrs: Vec<KAddr>,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}

impl KLink {
    pub fn managed(&self) -> bool {
        self.alias.as_deref() == Some(MANAGED_ALIAS)
    }
    pub fn v4(&self) -> impl Iterator<Item = &KAddr> {
        self.addrs.iter().filter(|a| a.net.is_ipv4())
    }
    pub fn v6_global(&self) -> impl Iterator<Item = &KAddr> {
        self.addrs
            .iter()
            .filter(|a| a.net.is_ipv6() && a.scope == "global")
    }
}

/// A default route (`ip -j [-6] route show default`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KRoute {
    pub v6: bool,
    pub dev: String,
    pub gateway: Option<String>,
    pub metric: u32,
    /// `static`, `dhcp`, `kernel`, `ra`, or a number.
    pub protocol: String,
}

/// All links by name, plus the default routes.
#[derive(Debug, Clone, Default)]
pub struct KernelState {
    pub links: BTreeMap<String, KLink>,
    pub default_routes: Vec<KRoute>,
}

fn s(v: &Value, k: &str) -> Option<String> {
    v.get(k).and_then(|x| x.as_str()).map(str::to_string)
}

impl KernelState {
    /// Parse `ip -j -d -s link show` and `ip -j addr show` output.
    pub fn parse(link_json: &str, addr_json: &str) -> Result<Self> {
        let links: Vec<Value> = serde_json::from_str(link_json)
            .map_err(|e| Error::Network(format!("parse `ip -j link`: {e}")))?;
        let addrs: Vec<Value> = if addr_json.trim().is_empty() {
            Vec::new()
        } else {
            serde_json::from_str(addr_json)
                .map_err(|e| Error::Network(format!("parse `ip -j addr`: {e}")))?
        };
        let mut st = KernelState::default();
        for l in &links {
            let Some(name) = s(l, "ifname") else { continue };
            let info = l.get("linkinfo");
            let data = info.and_then(|i| i.get("info_data"));
            let flags: Vec<String> = l
                .get("flags")
                .and_then(|f| f.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|x| x.as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default();
            let kind = info.and_then(|i| s(i, "info_kind"));
            let stats = l.get("stats64").or_else(|| l.get("stats"));
            let bytes = |dir: &str| {
                stats
                    .and_then(|s| s.get(dir))
                    .and_then(|d| d.get("bytes"))
                    .and_then(|b| b.as_u64())
                    .unwrap_or(0)
            };
            let mut k = KLink {
                name: name.clone(),
                ifindex: l.get("ifindex").and_then(|x| x.as_u64()).unwrap_or(0) as u32,
                master: s(l, "master"),
                link: s(l, "link"),
                mtu: l.get("mtu").and_then(|x| x.as_u64()).unwrap_or(0) as u32,
                mac: s(l, "address").filter(|_| s(l, "link_type").as_deref() == Some("ether")),
                up: flags.iter().any(|f| f == "UP"),
                operstate: s(l, "operstate").unwrap_or_default(),
                alias: s(l, "ifalias"),
                rx_bytes: bytes("rx"),
                tx_bytes: bytes("tx"),
                ..Default::default()
            };
            match kind.as_deref() {
                Some("vlan") => {
                    k.vlan_id = data
                        .and_then(|d| d.get("id"))
                        .and_then(|x| x.as_u64())
                        .map(|x| x as u16);
                    k.vlan_protocol = data
                        .and_then(|d| s(d, "protocol"))
                        .map(|p| p.to_lowercase());
                }
                Some("bond") => {
                    k.bond_mode = data.and_then(|d| s(d, "mode"));
                    k.bond_miimon = data
                        .and_then(|d| d.get("miimon"))
                        .and_then(|x| x.as_u64())
                        .map(|x| x as u32);
                    k.bond_lacp_rate = data.and_then(|d| s(d, "ad_lacp_rate"));
                    k.bond_xmit_hash_policy = data.and_then(|d| s(d, "xmit_hash_policy"));
                    k.bond_primary = data.and_then(|d| s(d, "primary"));
                }
                Some("bridge") => {
                    k.bridge_stp = data
                        .and_then(|d| d.get("stp_state"))
                        .and_then(|x| x.as_u64())
                        .map(|x| x != 0);
                }
                _ => {}
            }
            k.kind = kind;
            st.links.insert(name, k);
        }
        for a in &addrs {
            let Some(name) = s(a, "ifname") else { continue };
            let Some(link) = st.links.get_mut(&name) else {
                continue;
            };
            for ai in a
                .get("addr_info")
                .and_then(|x| x.as_array())
                .into_iter()
                .flatten()
            {
                let (Some(local), Some(p)) =
                    (s(ai, "local"), ai.get("prefixlen").and_then(|x| x.as_u64()))
                else {
                    continue;
                };
                let Ok(net) = format!("{local}/{p}").parse::<IpNetwork>() else {
                    continue;
                };
                let forever = ai
                    .get("valid_life_time")
                    .and_then(|x| x.as_u64())
                    .map(|v| v == u32::MAX as u64)
                    .unwrap_or(true);
                let dynamic =
                    ai.get("dynamic").and_then(|d| d.as_bool()).unwrap_or(false) || !forever;
                link.addrs.push(KAddr {
                    net,
                    dynamic,
                    scope: s(ai, "scope").unwrap_or_else(|| "global".into()),
                });
            }
        }
        Ok(st)
    }

    /// Read the live kernel state with `ip`.
    pub async fn read(cmd: &dyn Cmd) -> Result<Self> {
        let links = cmd
            .run("ip", &argv(&["-j", "-d", "-s", "link", "show"]))
            .await?;
        let addrs = cmd.run("ip", &argv(&["-j", "addr", "show"])).await?;
        let mut st = Self::parse(&links, &addrs)?;
        for (v6, fam) in [(false, "-4"), (true, "-6")] {
            let out = cmd
                .run("ip", &argv(&["-j", fam, "route", "show", "default"]))
                .await?;
            st.default_routes.extend(parse_routes(&out, v6)?);
        }
        Ok(st)
    }

    pub fn get(&self, n: &str) -> Option<&KLink> {
        self.links.get(n)
    }

    pub fn names(&self) -> Vec<String> {
        self.links.keys().cloned().collect()
    }

    /// The device the kernel would send traffic to `ip` out of, plus the
    /// source address it would use (`ip -j route get`). This is how the web
    /// UI learns which interface the admin is connected through.
    pub async fn route_get(
        cmd: &dyn Cmd,
        ip: std::net::IpAddr,
    ) -> Result<(String, Option<String>)> {
        let out = cmd
            .run("ip", &argv(&["-j", "route", "get", &ip.to_string()]))
            .await?;
        let v: Vec<Value> = serde_json::from_str(&out)
            .map_err(|e| Error::Network(format!("parse `ip route get`: {e}")))?;
        let r = v
            .first()
            .ok_or_else(|| Error::Network(format!("no route to {ip}")))?;
        let dev = s(r, "dev").ok_or_else(|| Error::Network(format!("no route to {ip}")))?;
        Ok((dev, s(r, "prefsrc")))
    }
}

/// Parse `ip -j route show default`.
pub fn parse_routes(json: &str, v6: bool) -> Result<Vec<KRoute>> {
    if json.trim().is_empty() {
        return Ok(Vec::new());
    }
    let v: Vec<Value> = serde_json::from_str(json)
        .map_err(|e| Error::Network(format!("parse `ip -j route`: {e}")))?;
    Ok(v.iter()
        .filter_map(|r| {
            Some(KRoute {
                v6,
                dev: s(r, "dev")?,
                gateway: s(r, "gateway"),
                metric: r.get("metric").and_then(|m| m.as_u64()).unwrap_or(0) as u32,
                protocol: match r.get("protocol") {
                    Some(Value::String(p)) => p.clone(),
                    Some(Value::Number(n)) => n.to_string(),
                    _ => "boot".into(),
                },
            })
        })
        .collect())
}

pub fn argv(a: &[&str]) -> Vec<String> {
    a.iter().map(|s| s.to_string()).collect()
}

/// Runs external commands (`ip`, `sysctl` writes go through files).
#[async_trait::async_trait]
pub trait Cmd: Send + Sync {
    /// Run `prog args...`; stdout on success, stderr in the error.
    async fn run(&self, prog: &str, args: &[String]) -> Result<String>;
}

/// The real thing.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemCmd;

#[async_trait::async_trait]
impl Cmd for SystemCmd {
    async fn run(&self, prog: &str, args: &[String]) -> Result<String> {
        let out = tokio::process::Command::new(prog)
            .args(args)
            .output()
            .await
            .map_err(|e| Error::Network(format!("{prog}: {e}")))?;
        if !out.status.success() {
            return Err(Error::Network(format!(
                "`{prog} {}` failed: {}",
                args.join(" "),
                String::from_utf8_lossy(&out.stderr).trim()
            )));
        }
        Ok(String::from_utf8_lossy(&out.stdout).to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    pub const LINKS: &str = r#"[
 {"ifindex":1,"ifname":"lo","flags":["LOOPBACK","UP","LOWER_UP"],"mtu":65536,"operstate":"UNKNOWN","link_type":"loopback","address":"00:00:00:00:00:00"},
 {"ifindex":2,"ifname":"eth0","flags":["BROADCAST","MULTICAST","UP","LOWER_UP"],"mtu":1500,"operstate":"UP","link_type":"ether","address":"52:54:00:12:34:56","stats64":{"rx":{"bytes":1000},"tx":{"bytes":2000}}},
 {"ifindex":3,"ifname":"eth1","flags":["BROADCAST","MULTICAST","SLAVE","UP"],"mtu":1500,"master":"bond0","operstate":"UP","link_type":"ether","address":"52:54:00:00:00:01","linkinfo":{"info_slave_kind":"bond"}},
 {"ifindex":5,"ifname":"bond0","flags":["BROADCAST","MULTICAST","MASTER","UP"],"mtu":1500,"operstate":"UP","link_type":"ether","address":"52:54:00:00:00:01","ifalias":"patronus","linkinfo":{"info_kind":"bond","info_data":{"mode":"active-backup","miimon":100}}},
 {"ifindex":6,"ifname":"bond0.10","link":"bond0","flags":["UP"],"mtu":1500,"operstate":"UP","link_type":"ether","address":"52:54:00:00:00:01","ifalias":"patronus","linkinfo":{"info_kind":"vlan","info_data":{"protocol":"802.1Q","id":10,"flags":["REORDER_HDR"]}}},
 {"ifindex":7,"ifname":"br0","flags":["UP"],"mtu":1500,"operstate":"UP","link_type":"ether","address":"aa:aa:aa:aa:aa:aa","linkinfo":{"info_kind":"bridge","info_data":{"stp_state":1}}}
]"#;
    pub const ADDRS: &str = r#"[
 {"ifindex":2,"ifname":"eth0","addr_info":[
   {"family":"inet","local":"203.0.113.5","prefixlen":24,"scope":"global","dynamic":true,"valid_life_time":3500},
   {"family":"inet6","local":"fe80::1","prefixlen":64,"scope":"link","valid_life_time":4294967295}]},
 {"ifindex":5,"ifname":"bond0","addr_info":[
   {"family":"inet","local":"192.168.1.1","prefixlen":24,"scope":"global","valid_life_time":4294967295}]}
]"#;

    #[test]
    fn parses_iproute2_json() {
        let k = KernelState::parse(LINKS, ADDRS).unwrap();
        let bond = k.get("bond0").unwrap();
        assert!(bond.managed());
        assert_eq!(bond.bond_mode.as_deref(), Some("active-backup"));
        assert_eq!(bond.addrs[0].net.to_string(), "192.168.1.1/24");
        assert!(!bond.addrs[0].dynamic);
        let v = k.get("bond0.10").unwrap();
        assert_eq!(
            (v.vlan_id, v.vlan_protocol.as_deref(), v.link.as_deref()),
            (Some(10), Some("802.1q"), Some("bond0"))
        );
        assert_eq!(k.get("eth1").unwrap().master.as_deref(), Some("bond0"));
        let e = k.get("eth0").unwrap();
        assert!(e.addrs[0].dynamic && e.kind.is_none() && e.up);
        assert_eq!((e.rx_bytes, e.tx_bytes), (1000, 2000));
        assert_eq!(e.v6_global().count(), 0);
        assert_eq!(k.get("br0").unwrap().bridge_stp, Some(true));
        assert!(!k.get("br0").unwrap().managed());
    }
}
