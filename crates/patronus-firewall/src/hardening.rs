//! fw4-style hardening knobs stored in `system_config` (lane B):
//!
//! | key | values | effect |
//! |---|---|---|
//! | `firewall.inbound_action` | `drop` (default) / `reject` | what unsolicited traffic from a WAN-role interface gets once nothing accepted it |
//! | `firewall.synflood_protect` | `0` (default) / `1` | rate-limit new TCP SYNs arriving on WAN-role interfaces, to the router and forwarded |
//! | `firewall.synflood_rate` / `_burst` | `25/second` / `50` | the limit |
//! | `firewall.mss_clamp` | comma list of `@role` / device, default `@wan` (empty = off) | clamp the TCP MSS to the route MTU for traffic in/out of those interfaces |
//! | `firewall.drop_ipv4_options` | `0` (default) / `1` | raw-prerouting drop of IPv4 TCP packets that carry IP options |

use crate::nftables::{is_valid_interface_name, TABLE};
use patronus_config::store::ConfigStore;
use patronus_core::{Error, Result};
use std::collections::BTreeMap;

pub const INBOUND_ACTION_KEY: &str = "firewall.inbound_action";
pub const SYNFLOOD_KEY: &str = "firewall.synflood_protect";
pub const SYNFLOOD_RATE_KEY: &str = "firewall.synflood_rate";
pub const SYNFLOOD_BURST_KEY: &str = "firewall.synflood_burst";
pub const MSS_CLAMP_KEY: &str = "firewall.mss_clamp";
pub const DROP_IPV4_OPTIONS_KEY: &str = "firewall.drop_ipv4_options";

pub const DEFAULT_SYNFLOOD_RATE: &str = "25/second";
pub const DEFAULT_SYNFLOOD_BURST: u32 = 50;
pub const DEFAULT_MSS_CLAMP: &str = "@wan";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hardening {
    pub reject: bool,
    pub synflood: bool,
    pub synflood_rate: String,
    pub synflood_burst: u32,
    pub mss_clamp: Vec<String>,
    pub drop_ipv4_options: bool,
}

impl Default for Hardening {
    fn default() -> Self {
        Self {
            reject: false,
            synflood: false,
            synflood_rate: DEFAULT_SYNFLOOD_RATE.into(),
            synflood_burst: DEFAULT_SYNFLOOD_BURST,
            mss_clamp: vec![DEFAULT_MSS_CLAMP.into()],
            drop_ipv4_options: false,
        }
    }
}

/// `25/second`, `100/minute`, or a bare number (per second).
pub fn normalize_rate(s: &str) -> Result<String> {
    let s = s.trim();
    let bad = || Error::Config(format!("SYN flood rate {s:?} (e.g. 25/second)"));
    let (n, unit) = match s.split_once('/') {
        Some((n, u)) => (n, u.trim()),
        None => (s, "second"),
    };
    let n: u32 = n.trim().parse().map_err(|_| bad())?;
    if n == 0 || !["second", "minute", "hour", "day"].contains(&unit) {
        return Err(bad());
    }
    Ok(format!("{n}/{unit}"))
}

/// Split and validate a `firewall.mss_clamp` list.
pub fn parse_mss_list(s: &str) -> Result<Vec<String>> {
    let mut v = Vec::new();
    for t in s.split(',').map(str::trim).filter(|t| !t.is_empty()) {
        let ok = match t.strip_prefix('@') {
            Some(r) => !r.is_empty() && r.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_'),
            None => is_valid_interface_name(t),
        };
        if !ok {
            return Err(Error::Config(format!(
                "MSS clamp interface {t:?} (@wan, @optN or a device name)"
            )));
        }
        if !v.iter().any(|x| x == t) {
            v.push(t.to_string());
        }
    }
    Ok(v)
}

fn flag(v: Option<String>) -> bool {
    v.is_some_and(|v| matches!(v.trim(), "1" | "true" | "yes" | "on"))
}

pub async fn load(store: &ConfigStore) -> Result<Hardening> {
    let d = Hardening::default();
    let g = |k: &'static str| async move { store.load_system_config(k).await };
    let mss = match g(MSS_CLAMP_KEY).await? {
        Some(v) => parse_mss_list(&v)?,
        None => d.mss_clamp.clone(),
    };
    Ok(Hardening {
        reject: g(INBOUND_ACTION_KEY)
            .await?
            .is_some_and(|v| v.trim().eq_ignore_ascii_case("reject")),
        synflood: flag(g(SYNFLOOD_KEY).await?),
        synflood_rate: match g(SYNFLOOD_RATE_KEY).await? {
            Some(v) => normalize_rate(&v)?,
            None => d.synflood_rate,
        },
        synflood_burst: g(SYNFLOOD_BURST_KEY)
            .await?
            .and_then(|v| v.trim().parse().ok())
            .filter(|b| *b > 0)
            .unwrap_or(d.synflood_burst),
        mss_clamp: mss,
        drop_ipv4_options: flag(g(DROP_IPV4_OPTIONS_KEY).await?),
    })
}

/// Rules placed before every other rule (`head`) and after all of them
/// (`tail`), plus the warnings for knobs that could not be applied.
#[derive(Debug, Default)]
pub struct Rendered {
    pub head: String,
    pub tail: String,
    pub warnings: Vec<String>,
    pub applied: Vec<String>,
}

fn set_of(devs: &[String]) -> String {
    let q: Vec<String> = devs.iter().map(|d| format!("\"{d}\"")).collect();
    if q.len() == 1 {
        q[0].clone()
    } else {
        format!("{{ {} }}", q.join(", "))
    }
}

pub fn render(h: &Hardening, roles: &BTreeMap<String, Vec<String>>) -> Rendered {
    let mut r = Rendered::default();
    let wan: Vec<String> = roles
        .get("wan")
        .map(|v| {
            v.iter()
                .filter(|d| is_valid_interface_name(d))
                .cloned()
                .collect()
        })
        .unwrap_or_default();

    if h.synflood {
        if wan.is_empty() {
            r.warnings
                .push("SYN flood protection: no WAN interface assigned, not applied".into());
        } else {
            let w = set_of(&wan);
            // new TCP connection attempts only (SYN without ACK/RST/FIN)
            for chain in ["input", "forward"] {
                r.head.push_str(&format!(
                    "add rule {TABLE} {chain} iifname {w} tcp flags & (fin | syn | rst | ack) == syn \
                     limit rate over {} burst {} packets counter drop comment \"SYN flood protection\"\n",
                    h.synflood_rate, h.synflood_burst
                ));
            }
            r.applied.push(format!(
                "SYN flood protection on {} ({} burst {})",
                wan.join(","),
                h.synflood_rate,
                h.synflood_burst
            ));
        }
    }

    if !h.mss_clamp.is_empty() {
        let mut devs: Vec<String> = Vec::new();
        for spec in &h.mss_clamp {
            match spec.strip_prefix('@') {
                Some(role) => match roles.get(&role.to_ascii_lowercase()) {
                    Some(v) if !v.is_empty() => devs.extend(v.iter().cloned()),
                    _ => r.warnings.push(format!(
                        "MSS clamping: role {spec} is not assigned to an interface"
                    )),
                },
                None => devs.push(spec.clone()),
            }
        }
        devs.retain(|d| is_valid_interface_name(d));
        devs.sort();
        devs.dedup();
        if !devs.is_empty() {
            let s = set_of(&devs);
            r.head.push_str(&format!(
                "add chain {TABLE} mss_clamp {{ type filter hook forward priority mangle; policy accept; }}\n\
                 add rule {TABLE} mss_clamp oifname {s} tcp flags syn tcp option maxseg size set rt mtu comment \"MSS clamp\"\n\
                 add rule {TABLE} mss_clamp iifname {s} tcp flags syn tcp option maxseg size set rt mtu comment \"MSS clamp\"\n"
            ));
            r.applied
                .push(format!("MSS clamping on {}", devs.join(",")));
        }
    }

    if h.drop_ipv4_options {
        r.head.push_str(&format!(
            "add chain {TABLE} raw_prerouting {{ type filter hook prerouting priority raw; policy accept; }}\n\
             add rule {TABLE} raw_prerouting ip hdrlength > 5 meta l4proto tcp counter drop comment \"drop IPv4 TCP with IP options\"\n"
        ));
        r.applied
            .push("dropping IPv4 TCP packets with IP options".into());
    }

    if h.reject {
        if wan.is_empty() {
            r.warnings
                .push("inbound action reject: no WAN interface assigned, policy drop stays".into());
        } else {
            let w = set_of(&wan);
            for chain in ["input", "forward"] {
                // what fw4 answers: RST for TCP, port-unreachable for UDP,
                // admin-prohibited for the rest
                r.tail.push_str(&format!(
                    "add rule {TABLE} {chain} iifname {w} meta l4proto tcp reject with tcp reset\n\
                     add rule {TABLE} {chain} iifname {w} meta l4proto udp reject with icmpx type port-unreachable\n\
                     add rule {TABLE} {chain} iifname {w} reject with icmpx type admin-prohibited\n"
                ));
            }
            r.applied.push(format!(
                "rejecting (not dropping) blocked traffic from {}",
                wan.join(",")
            ));
        }
    }
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rates_and_mss_lists_validate() {
        assert_eq!(normalize_rate("25").unwrap(), "25/second");
        assert_eq!(normalize_rate(" 10/minute ").unwrap(), "10/minute");
        for bad in ["", "0", "x/second", "5/fortnight", "5/second; drop", "-1"] {
            assert!(normalize_rate(bad).is_err(), "{bad}");
        }
        assert_eq!(
            parse_mss_list("@wan, @opt1,eth0.100,@wan").unwrap(),
            ["@wan", "@opt1", "eth0.100"]
        );
        assert!(parse_mss_list("").unwrap().is_empty());
        for bad in ["@", "a b", "eth0\"", "@w an", "waytoolonginterfacename0"] {
            assert!(parse_mss_list(bad).is_err(), "{bad}");
        }
    }

    #[tokio::test]
    async fn settings_load_with_fw4_defaults() {
        let s = ConfigStore::open_in_memory().await.unwrap();
        assert_eq!(load(&s).await.unwrap(), Hardening::default());
        s.save_system_config(INBOUND_ACTION_KEY, "REJECT")
            .await
            .unwrap();
        s.save_system_config(SYNFLOOD_KEY, "1").await.unwrap();
        s.save_system_config(SYNFLOOD_BURST_KEY, "0").await.unwrap();
        let h = load(&s).await.unwrap();
        assert!(h.reject && h.synflood);
        assert_eq!(h.synflood_burst, 50, "zero burst falls back to the default");
        s.save_system_config(INBOUND_ACTION_KEY, "bogus")
            .await
            .unwrap();
        assert!(
            !load(&s).await.unwrap().reject,
            "anything but reject is drop"
        );
    }

    #[test]
    fn render_without_roles_is_empty_but_warns() {
        let h = Hardening {
            reject: true,
            synflood: true,
            ..Default::default()
        };
        let r = render(&h, &BTreeMap::new());
        assert!(r.tail.is_empty());
        assert_eq!(r.warnings.len(), 3, "{:?}", r.warnings); // synflood, @wan clamp, reject
    }
}
