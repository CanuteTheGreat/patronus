//! Services that follow the virtual IP, and DHCP failover (lane G, part 2).
//!
//! # Services follow the VIP
//!
//! WireGuard, OpenVPN and IPsec listen for road warriors and site-to-site
//! peers on the address the peers dial: the WAN virtual IP. With HA on, only
//! the node that holds the VIP (VRRP `MASTER`) may run them; the other node
//! keeps the configuration but holds the service down, so two nodes never
//! answer for the same address and a peer's handshake always lands on the
//! node that owns the VIP.
//!
//! The state comes from the file keepalived's notify script writes
//! (`/run/patronus/ha-state`). The notify script then runs `patronus
//! ha-event STATE`, which re-applies exactly the follow appliers; each of
//! them asks [`follow_hold`] whether it may run. Unknown state (no notify
//! yet, e.g. right after boot) counts as BACKUP: the first MASTER
//! transition starts the service.
//!
//! # DHCP failover
//!
//! With `ha.dhcp_failover` on and the Kea backend, the DHCP applier loads
//! Kea's `libdhcp_ha.so` (and `libdhcp_lease_cmds.so`) and renders the pair
//! from [`kea_ha`]: hot-standby or load-balancing, the peer's address on the
//! sync network, heartbeat and takeover timers from typed settings. Kea runs
//! its own state machine (it is independent of VRRP, so a node can lose the
//! VIP and still serve leases it owns); leases are replicated as they are
//! granted, and the node that is left alone takes over the partner's leases
//! after `ha.dhcp_max_response_delay_ms`. The DHCP options that name the
//! router (default gateway, DNS) are the LAN virtual IP, so a client that
//! renews from the other node keeps a working gateway.

use crate::ha::{self, Settings};
use crate::lan::{self, IfAddr, LanEnv};
use patronus_config::applier::ApplyReport;
use patronus_config::store::ConfigStore;
use patronus_core::Result;
use serde_json::{json, Value};
use std::net::IpAddr;
use std::path::Path;

/// VRRP state as the notify script recorded it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HaState {
    Master,
    Backup,
    Fault,
    /// no notify yet (boot, keepalived not started)
    Unknown,
}

impl HaState {
    pub fn parse(s: &str) -> HaState {
        match s.trim() {
            "MASTER" => HaState::Master,
            "BACKUP" => HaState::Backup,
            "FAULT" | "STOP" => HaState::Fault,
            _ => HaState::Unknown,
        }
    }
    pub fn as_str(&self) -> &'static str {
        match self {
            HaState::Master => "MASTER",
            HaState::Backup => "BACKUP",
            HaState::Fault => "FAULT",
            HaState::Unknown => "unknown",
        }
    }
}

/// The recorded state in `file` (default [`ha::STATE_FILE`]).
pub fn read_state_file(file: Option<&Path>) -> HaState {
    let p = file.unwrap_or(Path::new(ha::STATE_FILE));
    std::fs::read_to_string(p)
        .ok()
        .and_then(|t| t.split_whitespace().next().map(HaState::parse))
        .unwrap_or(HaState::Unknown)
}

/// `Some(reason)` when `svc` (wireguard, openvpn, ipsec) must not run on
/// this node right now: HA is on with a carp virtual IP, the service is in
/// the follow list and this node is not MASTER. `None` = free to run.
pub async fn follow_hold(
    store: &ConfigStore,
    svc: &str,
    state_file: Option<&Path>,
) -> Result<Option<String>> {
    let s = ha::settings(store).await?;
    if !s.enabled || !s.follow_services.iter().any(|f| f == svc) {
        return Ok(None);
    }
    let carp = ha::list_vips(store)
        .await?
        .iter()
        .any(|v| v.enabled && v.mode == "carp");
    if !carp {
        return Ok(None);
    }
    Ok(match read_state_file(state_file) {
        HaState::Master => None,
        st => Some(format!(
            "HA state is {}: {svc} runs on the node that holds the virtual IP \
             (it starts when this node becomes MASTER)",
            st.as_str()
        )),
    })
}

/// Re-apply the appliers of the services that follow the virtual IP
/// (WireGuard, OpenVPN, IPsec: those built into this binary). Each one asks
/// [`follow_hold`] and starts or stops accordingly. Returns one line per
/// applier (`name: what happened` or `name: FAILED why`). Runs as root:
/// `patronus ha-event` (the notify script) and the HA applier.
pub async fn apply_followers(store: &ConfigStore) -> Vec<String> {
    use patronus_config::Applier;
    #[allow(unused_mut)]
    let mut list: Vec<std::sync::Arc<dyn Applier>> = crate::vpn_appliers();
    #[cfg(feature = "openvpn")]
    list.push(std::sync::Arc::new(
        crate::openvpn_server::OpenVpnApplier::default(),
    ));
    let mut out = Vec::new();
    for a in list {
        match a.apply(store).await {
            Ok(r) => out.push(format!("{}: {}", a.name(), r.applied.join(", "))),
            Err(e) => out.push(format!("{}: FAILED {e}", a.name())),
        }
    }
    out
}

// ---------------------------------------------------------------------------
// DHCP failover (Kea HA)
// ---------------------------------------------------------------------------

/// Everything Kea's HA hook needs for one daemon (DHCPv4 or DHCPv6).
#[derive(Debug, Clone, PartialEq)]
pub struct KeaHa {
    pub v6: bool,
    pub mode: String,
    pub role: String,
    pub this_name: String,
    pub this_url: String,
    pub peer_name: String,
    pub peer_url: String,
    pub heartbeat_ms: u32,
    pub max_response_delay_ms: u32,
    pub max_unacked: u32,
    pub send_lease_updates: bool,
}

fn url(ip: &str, port: u16) -> String {
    match ip.parse::<IpAddr>() {
        Ok(IpAddr::V6(_)) => format!("http://[{ip}]:{port}/"),
        _ => format!("http://{ip}:{port}/"),
    }
}

/// The node's own address on `dev`, never a virtual IP.
fn own_addr(
    addrs: &[IfAddr],
    dev: &str,
    want_v6: bool,
    vips: &[ha::ResolvedVip],
) -> Option<IpAddr> {
    addrs
        .iter()
        .filter(|a| a.ifname == dev && a.addr.is_ipv6() == want_v6)
        .filter(|a| {
            !a.addr.is_loopback()
                && !matches!(a.addr, IpAddr::V6(x) if (x.segments()[0] & 0xffc0) == 0xfe80)
        })
        .find(|a| !vips.iter().any(|v| v.dev == dev && v.net.ip() == a.addr))
        .map(|a| a.addr)
}

/// The Kea HA parameters of this node, or `None` (with a warning when the
/// operator asked for failover but it cannot be built).
pub async fn kea_ha(
    store: &ConfigStore,
    env: &LanEnv,
    v6: bool,
    rep: &mut ApplyReport,
) -> Result<Option<KeaHa>> {
    let s: Settings = ha::settings(store).await?;
    if !s.enabled || !s.dhcp_failover {
        return Ok(None);
    }
    let (carp, _alias, _) = ha::resolve_vips(store).await?;
    if carp.is_empty() {
        return Ok(None);
    }
    let Some(peer) = s
        .dhcp_peer
        .clone()
        .or_else(|| s.sync_peer.clone())
        .or_else(|| s.peer.clone())
    else {
        if !v6 {
            rep.warn(
                "DHCP failover is on but no peer address is known (set the sync peer, the VRRP \
                 peer or the DHCP failover peer): DHCP runs without failover",
            );
        }
        return Ok(None);
    };
    let addrs = env.addrs().unwrap_or_default();
    let peer_v6 = peer.parse::<IpAddr>().is_ok_and(|p| p.is_ipv6());
    let local = match &s.dhcp_local {
        Some(l) => Some(l.clone()),
        None => {
            let dev = match (
                &s.sync_interface,
                s.sync_peer.is_some() && s.dhcp_peer.is_none(),
            ) {
                (Some(spec), true) => lan::resolve_iface(store, spec).await?.into_iter().next(),
                _ => carp.first().map(|v| v.dev.clone()),
            };
            dev.and_then(|d| own_addr(&addrs, &d, peer_v6, &carp))
                .map(|a| a.to_string())
        }
    };
    let Some(local) = local else {
        if !v6 {
            rep.warn(
                "DHCP failover is on but this node's address towards the peer is unknown \
                 (no address on the sync/VIP interface, or set the DHCP failover local address): \
                 DHCP runs without failover",
            );
        }
        return Ok(None);
    };
    let port = if v6 { s.dhcp_port6 } else { s.dhcp_port4 };
    let (this_name, peer_name) = if s.dhcp_role == "primary" {
        ("patronus-primary", "patronus-secondary")
    } else {
        ("patronus-secondary", "patronus-primary")
    };
    Ok(Some(KeaHa {
        v6,
        mode: s.dhcp_mode.clone(),
        role: s.dhcp_role.clone(),
        this_name: this_name.into(),
        this_url: url(&local, port),
        peer_name: peer_name.into(),
        peer_url: url(&peer, port),
        heartbeat_ms: s.dhcp_heartbeat_ms,
        max_response_delay_ms: s.dhcp_max_response_delay_ms,
        max_unacked: s.dhcp_max_unacked,
        send_lease_updates: s.dhcp_send_lease_updates,
    }))
}

impl KeaHa {
    /// Kea's name for a role: hot-standby pairs a primary with a `standby`.
    fn role_name(&self, role: &str) -> &'static str {
        match (self.mode.as_str(), role) {
            (_, "primary") => "primary",
            ("hot-standby", _) => "standby",
            _ => "secondary",
        }
    }

    /// `hooks-libraries` and `multi-threading` for the daemon's top-level
    /// object (`Dhcp4` / `Dhcp6`). Hook libraries are named without a path:
    /// Kea resolves them in its own hooks directory on every distro.
    pub fn daemon_keys(&self) -> Value {
        let other = if self.role == "primary" {
            "secondary"
        } else {
            "primary"
        };
        let mut peers = vec![
            (
                self.this_name.clone(),
                self.this_url.clone(),
                self.role.clone(),
            ),
            (
                self.peer_name.clone(),
                self.peer_url.clone(),
                other.to_string(),
            ),
        ];
        peers.sort_by_key(|(_, _, r)| r != "primary");
        let peers: Vec<Value> = peers
            .into_iter()
            .map(|(name, url, role)| {
                json!({"name": name, "url": url, "role": self.role_name(&role), "auto-failover": true})
            })
            .collect();
        json!({
            "multi-threading": {"enable-multi-threading": true},
            "hooks-libraries": [
                {"library": "libdhcp_lease_cmds.so"},
                {"library": "libdhcp_ha.so", "parameters": {"high-availability": [{
                    "this-server-name": self.this_name,
                    "mode": self.mode,
                    "heartbeat-delay": self.heartbeat_ms,
                    "max-response-delay": self.max_response_delay_ms,
                    "max-ack-delay": self.max_response_delay_ms.min(10_000),
                    "max-unacked-clients": self.max_unacked,
                    "send-lease-updates": self.send_lease_updates,
                    "sync-leases": true,
                    "sync-timeout": 60_000,
                    "multi-threading": {
                        "enable-multi-threading": true,
                        "http-dedicated-listener": true,
                        "http-listener-threads": 2,
                        "http-client-threads": 2,
                    },
                    "peers": peers,
                }]}},
            ],
        })
    }
}

/// Kea's own view of the pair (`ha-heartbeat` to the local listener):
/// `hot-standby`, `load-balancing`, `partner-down`, `communication-interrupted`,
/// `waiting`, ... or `None` when the daemon does not answer.
pub fn kea_ha_state(ha: &KeaHa) -> Option<String> {
    use std::io::{Read, Write};
    let hostport = ha
        .this_url
        .trim_start_matches("http://")
        .trim_end_matches('/')
        .to_string();
    let svc = if ha.v6 { "dhcp6" } else { "dhcp4" };
    let body = format!(r#"{{"command":"ha-heartbeat","service":["{svc}"]}}"#);
    let addr = std::net::ToSocketAddrs::to_socket_addrs(&hostport)
        .ok()?
        .next()?;
    let mut c =
        std::net::TcpStream::connect_timeout(&addr, std::time::Duration::from_secs(2)).ok()?;
    c.set_read_timeout(Some(std::time::Duration::from_secs(3)))
        .ok()?;
    write!(
        c,
        "POST / HTTP/1.1\r\nHost: {hostport}\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .ok()?;
    let mut out = String::new();
    c.read_to_string(&mut out).ok()?;
    let j: Value = serde_json::from_str(out.split("\r\n\r\n").nth(1)?).ok()?;
    j.get(0)?
        .get("arguments")?
        .get("state")?
        .as_str()
        .map(str::to_string)
}

/// `{mode, role, peer, state}` per family for the HA page, or the reason
/// DHCP failover is not in effect.
pub async fn dhcp_status(store: &ConfigStore, env: &LanEnv, backend_is_kea: bool) -> Result<Value> {
    let s = ha::settings(store).await?;
    if !s.enabled || !s.dhcp_failover {
        return Ok(json!({"active": false, "reason": "DHCP failover is off"}));
    }
    if !backend_is_kea {
        return Ok(json!({
            "active": false,
            "reason": "the dnsmasq DHCP backend has no failover protocol: switch the DHCP backend \
                       to Kea (DHCP settings) to get DHCP failover between the two nodes",
        }));
    }
    let mut rep = ApplyReport::default();
    let mut out = json!({"active": false, "mode": s.dhcp_mode, "role": s.dhcp_role});
    let mut any = false;
    for v6 in [false, true] {
        if let Some(h) = kea_ha(store, env, v6, &mut rep).await? {
            any = true;
            let fam = if v6 { "dhcp6" } else { "dhcp4" };
            out["peer"] = json!(h.peer_url);
            let hc = h.clone();
            let st = tokio::task::spawn_blocking(move || kea_ha_state(&hc))
                .await
                .ok()
                .flatten();
            out[fam] = json!({"state": st});
        }
    }
    out["active"] = json!(any);
    if !any {
        out["reason"] = json!(rep.warnings.first().cloned().unwrap_or_default());
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lan::testutil;

    async fn on(s: &ConfigStore) {
        ha::save_vip(
            s,
            None,
            &ha::VipInput {
                name: Some("gw".into()),
                interface: Some("@lan".into()),
                address: Some("192.168.50.254/24".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        ha::save_settings(
            s,
            &ha::SettingsInput {
                enabled: Some(true),
                peer: Some("192.168.50.3".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn services_are_held_unless_this_node_is_master() {
        let s = testutil::store().await;
        let dir = std::env::temp_dir().join(format!("ha-follow-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("ha-state");
        // HA off: never held
        assert_eq!(follow_hold(&s, "wireguard", Some(&f)).await.unwrap(), None);
        on(&s).await;
        // no notify yet: held
        let why = follow_hold(&s, "wireguard", Some(&f))
            .await
            .unwrap()
            .unwrap();
        assert!(why.contains("unknown") && why.contains("MASTER"), "{why}");
        std::fs::write(&f, "BACKUP 1\n").unwrap();
        assert!(follow_hold(&s, "ipsec", Some(&f)).await.unwrap().is_some());
        std::fs::write(&f, "FAULT 2\n").unwrap();
        assert!(follow_hold(&s, "openvpn", Some(&f))
            .await
            .unwrap()
            .is_some());
        std::fs::write(&f, "MASTER 3\n").unwrap();
        assert_eq!(follow_hold(&s, "wireguard", Some(&f)).await.unwrap(), None);
        // a service outside the follow list always runs
        ha::save_settings(
            &s,
            &ha::SettingsInput {
                follow_services: Some(vec!["ipsec".into()]),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        std::fs::write(&f, "BACKUP 4\n").unwrap();
        assert_eq!(follow_hold(&s, "wireguard", Some(&f)).await.unwrap(), None);
        assert!(follow_hold(&s, "ipsec", Some(&f)).await.unwrap().is_some());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn kea_ha_hooks_name_both_peers_and_the_right_roles() {
        let mk = |mode: &str, role: &str| KeaHa {
            v6: false,
            mode: mode.into(),
            role: role.into(),
            this_name: format!("patronus-{role}"),
            this_url: "http://10.9.9.1:8000/".into(),
            peer_name: "patronus-other".into(),
            peer_url: "http://10.9.9.2:8000/".into(),
            heartbeat_ms: 1000,
            max_response_delay_ms: 4000,
            max_unacked: 0,
            send_lease_updates: true,
        };
        let j = mk("hot-standby", "secondary").daemon_keys();
        let ha = &j["hooks-libraries"][1]["parameters"]["high-availability"][0];
        assert_eq!(ha["this-server-name"], "patronus-secondary");
        assert_eq!(ha["mode"], "hot-standby");
        assert_eq!(ha["peers"][0]["role"], "primary");
        assert_eq!(ha["peers"][1]["role"], "standby");
        assert_eq!(ha["peers"][1]["name"], "patronus-secondary");
        assert_eq!(ha["heartbeat-delay"], 1000);
        assert_eq!(ha["max-unacked-clients"], 0);
        assert_eq!(j["hooks-libraries"][0]["library"], "libdhcp_lease_cmds.so");
        let j = mk("load-balancing", "primary").daemon_keys();
        let ha = &j["hooks-libraries"][1]["parameters"]["high-availability"][0];
        assert_eq!(ha["peers"][1]["role"], "secondary");
        assert_eq!(url("fd00::2", 8001), "http://[fd00::2]:8001/");
    }

    #[tokio::test]
    async fn kea_ha_needs_a_peer_and_a_local_address_and_says_so() {
        let t = testutil::env(&[]);
        let s = testutil::store().await;
        let mut rep = ApplyReport::default();
        // HA off
        assert!(kea_ha(&s, &t.env, false, &mut rep).await.unwrap().is_none());
        assert!(rep.warnings.is_empty());
        on(&s).await;
        let h = kea_ha(&s, &t.env, false, &mut rep).await.unwrap();
        // the test environment's addresses decide whether a local address exists
        if h.is_none() {
            assert!(rep.warnings[0].contains("failover"), "{:?}", rep.warnings);
        }
        ha::save_settings(
            &s,
            &ha::SettingsInput {
                dhcp_local: Some("192.168.50.2".into()),
                dhcp_peer: Some("192.168.50.3".into()),
                dhcp_role: Some("secondary".into()),
                dhcp_port4: Some(8100),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let h = kea_ha(&s, &t.env, false, &mut rep).await.unwrap().unwrap();
        assert_eq!(h.this_url, "http://192.168.50.2:8100/");
        assert_eq!(h.peer_url, "http://192.168.50.3:8100/");
        assert_eq!(h.this_name, "patronus-secondary");
        let h6 = kea_ha(&s, &t.env, true, &mut rep).await.unwrap().unwrap();
        assert_eq!(h6.this_url, "http://192.168.50.2:8001/");
        ha::save_settings(
            &s,
            &ha::SettingsInput {
                dhcp_failover: Some(false),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert!(kea_ha(&s, &t.env, false, &mut rep).await.unwrap().is_none());
    }
}
