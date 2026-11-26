//! Multi-WAN polish (lane E, docs/MULTIWAN.md): what gateway groups do beyond
//! tiers, weights and failover, the way pfSense and OPNsense gateway groups
//! behave.
//!
//! - **Sticky connections.** A load-balancing group with `sticky_secs > 0`
//!   gives every client address one member and keeps it for that long after
//!   the client's last packet. The assignment lives in an nftables map with
//!   element timeouts (own table `inet patronus_wan`, chain `sticky` in
//!   prerouting after the policy-routing marks): the first packet of an
//!   unassigned client picks a member by weight, later packets get the stored
//!   member's routing mark (the per-gateway tables of `patronus_config::policy`
//!   do the rest). Entries pointing at a member that left service are dropped
//!   at the next apply, so those clients are assigned again.
//! - **Kill states.** [`plan_kills`] says which gateways lose their tracked
//!   connections when the monitor sees a membership change; [`Killer`] deletes
//!   them (`conntrack -D` by the address of the gateway's interface: masqueraded
//!   flows reply to it, inbound ones arrived at it).
//! - **Warning levels** ([`warning_of`]) below the down thresholds.
//! - **DNS per gateway** ([`usable_dns_servers`]): the DNS servers of the
//!   gateways that carry traffic, used as resolver upstreams.

use crate::linkstate::{Cmd, KernelState};
use crate::routes::{
    usable, Family, Gateway, GwState, GwStatus, KillStates, RoutingConfig, Trigger,
};
use async_trait::async_trait;
use patronus_core::Result;
use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

/// The nftables table Patronus keeps the sticky assignments in.
pub const NFT_TABLE: &str = "patronus_wan";
/// Its only chain.
pub const NFT_CHAIN: &str = "sticky";
/// Hook priority: after the policy-routing marks (`mangle`, -150).
pub const NFT_PRIORITY: i32 = -140;

/// One sticky load-balancing group, ready to be rendered.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct StickyGroup {
    pub group: String,
    /// The group's own mark; a packet carrying it was policy-routed to the group.
    pub mark: u32,
    /// The group is (also) the default gateway: unmarked traffic belongs to it.
    pub is_default: bool,
    pub v6: bool,
    pub secs: u32,
    /// `(gateway mark, weight)` of the members that carry traffic now.
    pub members: Vec<(u32, u32)>,
    /// Devices of every gateway: traffic arriving there is never assigned.
    pub skip_ifaces: Vec<String>,
}

impl StickyGroup {
    pub fn map_name(&self) -> String {
        format!("st{}_{}", self.mark & 0xffff, if self.v6 { 6 } else { 4 })
    }
}

fn quote(s: &str) -> String {
    format!("\"{}\"", s.replace(['"', '\\'], ""))
}

/// The nft script that makes the sticky table match `groups`. `stale` are the
/// maps of the live table that no group wants any more.
pub fn render_nft(groups: &[StickyGroup], stale: &[String], flush: &BTreeSet<String>) -> String {
    let mut s = String::new();
    s.push_str(&format!("add table inet {NFT_TABLE}\n"));
    s.push_str(&format!(
        "add chain inet {NFT_TABLE} {NFT_CHAIN} {{ type filter hook prerouting priority {NFT_PRIORITY}; policy accept; }}\n"
    ));
    s.push_str(&format!("flush chain inet {NFT_TABLE} {NFT_CHAIN}\n"));
    for m in stale {
        s.push_str(&format!("delete map inet {NFT_TABLE} {m}\n"));
    }
    for g in groups {
        let map = g.map_name();
        let (ty, sa) = if g.v6 {
            ("ipv6_addr", "ip6 saddr")
        } else {
            ("ipv4_addr", "ip saddr")
        };
        s.push_str(&format!(
            "add map inet {NFT_TABLE} {map} {{ type {ty} : mark ; flags timeout ; }}\n"
        ));
        if flush.contains(&map) {
            s.push_str(&format!("flush map inet {NFT_TABLE} {map}\n"));
        }
        let skip = if g.skip_ifaces.is_empty() {
            String::new()
        } else {
            format!(
                "iifname != {{ {} }} ",
                g.skip_ifaces
                    .iter()
                    .map(|d| quote(d))
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        };
        let upd = format!("update @{map} {{ {sa} timeout {}s : meta mark }}", g.secs);
        let mut selectors = vec![format!("0x{:x}", g.mark)];
        if g.is_default {
            selectors.push("0x0".to_string());
        }
        // known client: its member's mark
        for sel in &selectors {
            s.push_str(&format!(
                "add rule inet {NFT_TABLE} {NFT_CHAIN} {skip}meta mark {sel} {sa} @{map} meta mark set {sa} map @{map} {upd}\n"
            ));
        }
        // new client: a member by weight
        let total: u32 = g.members.iter().map(|m| m.1.max(1)).sum();
        let pick = if g.members.len() == 1 {
            format!("meta mark set 0x{:x}", g.members[0].0)
        } else {
            let mut at = 0;
            let mut arms = Vec::new();
            for (mark, w) in &g.members {
                let w = (*w).max(1);
                arms.push(if w == 1 {
                    format!("{at} : 0x{mark:x}")
                } else {
                    format!("{at}-{} : 0x{mark:x}", at + w - 1)
                });
                at += w;
            }
            format!(
                "meta mark set numgen random mod {total} map {{ {} }}",
                arms.join(", ")
            )
        };
        for sel in &selectors {
            s.push_str(&format!(
                "add rule inet {NFT_TABLE} {NFT_CHAIN} {skip}meta mark {sel} {pick} {upd}\n"
            ));
        }
    }
    s
}

/// Map names and, per map, the marks stored in it, from `nft -j list table`.
pub fn parse_table(json: &str) -> BTreeMap<String, Vec<u32>> {
    let mut out = BTreeMap::new();
    let Ok(v) = serde_json::from_str::<serde_json::Value>(json) else {
        return out;
    };
    for item in v["nftables"].as_array().into_iter().flatten() {
        let Some(m) = item.get("map") else { continue };
        let Some(name) = m["name"].as_str() else {
            continue;
        };
        let mut marks = Vec::new();
        for e in m["elem"].as_array().into_iter().flatten() {
            if let Some(val) = e.as_array().and_then(|p| p.get(1)).and_then(|x| x.as_u64()) {
                marks.push(val as u32);
            }
        }
        out.insert(name.to_string(), marks);
    }
    out
}

/// Bring the live sticky table to `groups`. Returns what changed, for the
/// apply report. Assignments to members that no longer carry traffic are
/// dropped (that map is flushed); every other client keeps its member.
pub async fn apply_sticky(
    nft: &dyn Cmd,
    groups: &[StickyGroup],
    run_dir: &std::path::Path,
) -> Result<Vec<String>> {
    let live = nft
        .run(
            "nft",
            &[
                "-j".into(),
                "list".into(),
                "table".into(),
                "inet".into(),
                NFT_TABLE.into(),
            ],
        )
        .await
        .ok();
    let mut done = Vec::new();
    if groups.is_empty() {
        if live.is_some() {
            nft.run(
                "nft",
                &[
                    "delete".into(),
                    "table".into(),
                    "inet".into(),
                    NFT_TABLE.into(),
                ],
            )
            .await?;
            done.push("sticky connections: table removed".into());
        }
        return Ok(done);
    }
    let maps = live.as_deref().map(parse_table).unwrap_or_default();
    let want: BTreeSet<String> = groups.iter().map(|g| g.map_name()).collect();
    let stale: Vec<String> = maps.keys().filter(|m| !want.contains(*m)).cloned().collect();
    let mut flush = BTreeSet::new();
    for g in groups {
        let name = g.map_name();
        let usable_marks: BTreeSet<u32> = g.members.iter().map(|m| m.0).collect();
        if maps
            .get(&name)
            .is_some_and(|marks| marks.iter().any(|m| !usable_marks.contains(m)))
        {
            // the clients of a member that left are assigned again
            flush.insert(name);
            done.push(format!(
                "sticky {}: assignments to a lost member dropped",
                g.group
            ));
        }
    }
    let script = render_nft(groups, &stale, &flush);
    // nft reads the script from a file (the command runner has no stdin); the
    // run directory is root-owned, unlike a shared temp dir
    let _ = std::fs::create_dir_all(run_dir);
    let path = run_dir.join("wan-sticky.nft");
    let last = run_dir.join("wan-sticky.last");
    // an unchanged table is re-applied (it heals drift) but not reported
    let steady = render_nft(groups, &[], &BTreeSet::new());
    let changed = live.is_none()
        || !flush.is_empty()
        || !stale.is_empty()
        || std::fs::read_to_string(&last).ok().as_deref() != Some(steady.as_str());
    std::fs::write(&path, &script)
        .map_err(|e| patronus_core::Error::Network(format!("sticky: {}: {e}", path.display())))?;
    nft.run("nft", &["-f".into(), path.display().to_string()])
        .await?;
    let _ = std::fs::write(&last, &steady);
    if changed {
        done.push(format!(
            "sticky connections: {} group(s) in table {NFT_TABLE}",
            groups.len()
        ));
    }
    Ok(done)
}

/// `loss` or `latency` while a gateway that still carries traffic is above its
/// warning level (never for a gateway that is down or already degraded).
pub fn warning_of(g: &Gateway, state: GwState, loss: u32, rtt: Option<f64>) -> Option<String> {
    if !matches!(state, GwState::Online) {
        return None;
    }
    if g.loss_warn > 0 && loss >= g.loss_warn {
        return Some("loss".into());
    }
    if g.latency_warn > 0 && rtt.is_some_and(|r| r > f64::from(g.latency_warn)) {
        return Some("latency".into());
    }
    None
}

/// Why a gateway's connections are deleted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KillOrder {
    pub gateway: String,
    pub why: String,
}

/// Which gateways lose their tracked connections now. `prev` / `next` are the
/// monitor's state of the gateways before and after this round.
///
/// - a member that carried traffic for a group (usable) and no longer does
///   (down, or loss / latency the group's trigger reacts to) is killed when
///   the group's `kill_states` is `down` or `down_recovery`;
/// - with `down_recovery` a member that returns to service kills the flows of
///   the members of a worse tier (they moved to the fallback while it was
///   gone), unless its failback ramp is on: the ramp moves new flows gradually
///   and must not be undone by a cut-over of all of them.
pub fn plan_kills(
    cfg: &RoutingConfig,
    prev: &BTreeMap<String, GwStatus>,
    next: &BTreeMap<String, GwStatus>,
) -> Vec<KillOrder> {
    let mut out: BTreeMap<String, String> = BTreeMap::new();
    let st = |m: &BTreeMap<String, GwStatus>, g: &str| m.get(g).map(|s| s.state);
    for grp in &cfg.groups {
        if grp.kill_states == KillStates::None {
            continue;
        }
        for m in &grp.members {
            let (Some(was), Some(now)) = (st(prev, &m.gateway), st(next, &m.gateway)) else {
                continue;
            };
            let was_ok = usable(was, grp.trigger);
            let now_ok = usable(now, grp.trigger);
            if was_ok && !now_ok {
                out.entry(m.gateway.clone()).or_insert_with(|| {
                    format!("{} left gateway group {} ({:?})", m.gateway, grp.name, now)
                });
            }
            if !was_ok && now_ok && grp.kill_states == KillStates::DownRecovery {
                let ramp = next.get(&m.gateway).map_or(0, |s| s.ramp_secs);
                if ramp > 0 {
                    continue;
                }
                for other in grp.members.iter().filter(|o| o.tier > m.tier) {
                    if st(next, &other.gateway).is_some_and(|s| usable(s, grp.trigger)) {
                        out.entry(other.gateway.clone()).or_insert_with(|| {
                            format!(
                                "{} is back in gateway group {}: flows move to it",
                                m.gateway, grp.name
                            )
                        });
                    }
                }
            }
        }
    }
    out.into_iter()
        .map(|(gateway, why)| KillOrder { gateway, why })
        .collect()
}

/// The global addresses of `dev` in `family`.
pub fn dev_addrs(k: &KernelState, dev: &str, family: Family) -> Vec<IpAddr> {
    k.links
        .get(dev)
        .map(|l| {
            l.addrs
                .iter()
                .filter(|a| a.net.is_ipv6() == family.v6() && a.scope == "global")
                .map(|a| a.net.ip())
                .collect()
        })
        .unwrap_or_default()
}

/// Deletes tracked connections.
#[async_trait]
pub trait Killer: Send + Sync {
    /// Delete every tracked connection that uses the uplink address `addr`:
    /// outbound ones masqueraded to it (their reply comes back to `addr`) and
    /// inbound ones that arrived at it (port forwards, services on the router).
    /// How many went.
    async fn kill_flows(&self, addr: IpAddr) -> u32;
}

/// `conntrack -D --reply-dst ADDR` and `conntrack -D --orig-dst ADDR`
/// (conntrack-tools).
pub struct SystemKiller;

/// "conntrack v1.4.8 (conntrack-tools): 3 flow entries have been deleted."
pub fn parse_deleted(out: &str) -> u32 {
    out.split_whitespace()
        .collect::<Vec<_>>()
        .windows(4)
        .find(|w| w[1] == "flow" && w[2].starts_with("entr") && w[3] == "have")
        .and_then(|w| w[0].parse().ok())
        .unwrap_or(0)
}

#[async_trait]
impl Killer for SystemKiller {
    async fn kill_flows(&self, addr: IpAddr) -> u32 {
        let fam = if addr.is_ipv6() { "ipv6" } else { "ipv4" };
        let mut n = 0;
        for sel in ["--reply-dst", "--orig-dst"] {
            match tokio::process::Command::new("conntrack")
                .args(["-f", fam, "-D", sel, &addr.to_string()])
                .output()
                .await
            {
                Ok(o) => {
                    // the count is printed on stderr; no match exits 1 with "0 flow entries"
                    let text = format!(
                        "{} {}",
                        String::from_utf8_lossy(&o.stdout),
                        String::from_utf8_lossy(&o.stderr)
                    );
                    if !o.status.success() && !text.contains("flow entries") {
                        tracing::warn!("kill states: conntrack for {addr}: {}", text.trim());
                    }
                    n += parse_deleted(&text);
                }
                Err(e) => {
                    tracing::warn!("kill states: conntrack is not installed ({e})");
                    return n;
                }
            }
        }
        n
    }
}

/// DNS servers of the gateways that carry traffic now (down gateways' servers
/// are not queried: they sit behind a dead uplink), in gateway-name order.
pub fn usable_dns_servers(
    cfg: &RoutingConfig,
    status: &BTreeMap<String, GwStatus>,
) -> Vec<IpAddr> {
    let mut out: Vec<IpAddr> = Vec::new();
    for g in &cfg.gateways {
        let ok = match status.get(&g.name) {
            // no monitor result yet: usable
            None => true,
            Some(s) => usable(s.state, Trigger::LossLatency)
                || matches!(s.state, GwState::Loss | GwState::Latency),
        };
        if ok {
            for ip in &g.dns_servers {
                if !out.contains(ip) {
                    out.push(*ip);
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests;
