//! Store-backed management access from an upstream LAN (router tier).
//!
//! A unit that reaches the house network over a Wi-Fi/Ethernet *uplink* (WAN role) must stay
//! manageable from that network. That used to be a boot-time nft rule inserted from the
//! unit's `MGMT_NET`, which every later firewall apply rebuilt away. It now lives in the
//! config store as one **system** rule per uplink interface, `Upstream management via <if>`
//! (input, tcp, source = the management network, ports = SSH + every web UI listener), so
//! every apply renders it and the Firewall page lists it.
//!
//! The values are typed settings, never shell: `$PATRONUS_MGMT_NET` (CIDR list) and
//! `$PATRONUS_MGMT_IFACES` (interface list; default: the interfaces holding the WAN role),
//! which the router image's apply wrapper exports from the unit's `MGMT_NET` / `UPLINKS`
//! (unit.conf is parsed by the shell that owns it; this crate validates what it is given).
//!
//! [`ensure_management`] is idempotent and safe at every boot (CLI `patronus apply` and
//! `patronus-web` startup both call it): it inserts what is missing, refreshes a rule whose
//! network changed, and replaces a hand-added user rule that does the same job so the unit
//! does not end with duplicates. The ports always follow `ssh.port` and the web settings
//! ([`follow_upstream_ports`]), never literals.

use crate::store::{ConfigStore, RuleOrigin};
use crate::webui::WebSettings;
use patronus_core::types::{ChainType, FirewallAction, FirewallRule, PortSpec, Protocol};
use patronus_core::{Error, Result};

/// Name prefix of the seeded rules.
pub const UPSTREAM_RULE_PREFIX: &str = "Upstream management via ";
/// Environment variable: management networks (comma/space separated CIDRs).
pub const ENV_MGMT_NET: &str = "PATRONUS_MGMT_NET";
/// Environment variable: uplink interfaces (comma/space separated; default WAN-role interfaces).
pub const ENV_MGMT_IFACES: &str = "PATRONUS_MGMT_IFACES";

/// Which networks may manage the unit over which uplinks.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ManagementSpec {
    pub networks: Vec<String>,
    pub interfaces: Vec<String>,
    pub warnings: Vec<String>,
}

/// What [`ensure_management`] changed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MgmtReport {
    pub added: Vec<String>,
    pub updated: Vec<String>,
    /// Ids of hand-added user rules that the seeded rules replaced.
    pub replaced_user_rules: Vec<u64>,
    pub warnings: Vec<String>,
}

fn valid_cidr(s: &str) -> bool {
    let (addr, len) = match s.split_once('/') {
        Some((a, l)) => (a, l.parse::<u8>().ok()),
        None => return false,
    };
    match (addr.parse::<std::net::IpAddr>(), len) {
        (Ok(std::net::IpAddr::V4(_)), Some(l)) => l <= 32,
        (Ok(std::net::IpAddr::V6(_)), Some(l)) => l <= 128,
        _ => false,
    }
}

fn valid_iface(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 15
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

fn words(s: &str) -> impl Iterator<Item = &str> {
    s.split(|c: char| c == ',' || c.is_whitespace())
        .filter(|w| !w.is_empty())
}

impl ManagementSpec {
    /// Parse the two lists; anything that is not a CIDR / interface name is dropped with a
    /// warning (a typo must never widen the rule: `0.0.0.0/0` is refused too).
    pub fn parse(nets: Option<&str>, ifaces: Option<&str>) -> Self {
        let mut spec = Self::default();
        for n in words(nets.unwrap_or("")) {
            if !valid_cidr(n) || n.ends_with("/0") {
                spec.warnings.push(format!(
                    "management network {n:?} is not a usable CIDR; ignored"
                ));
            } else if !spec.networks.iter().any(|x| x == n) {
                spec.networks.push(n.to_string());
            }
        }
        for i in words(ifaces.unwrap_or("")) {
            if !valid_iface(i) {
                spec.warnings.push(format!(
                    "management interface {i:?} is not an interface name; ignored"
                ));
            } else if !spec.interfaces.iter().any(|x| x == i) {
                spec.interfaces.push(i.to_string());
            }
        }
        spec
    }

    /// From `$PATRONUS_MGMT_NET` / `$PATRONUS_MGMT_IFACES` (empty spec when unset).
    pub fn from_env() -> Self {
        Self::parse(
            std::env::var(ENV_MGMT_NET).ok().as_deref(),
            std::env::var(ENV_MGMT_IFACES).ok().as_deref(),
        )
    }
}

fn is_upstream(rule: &FirewallRule, origin: RuleOrigin) -> bool {
    origin == RuleOrigin::System && rule.name.starts_with(UPSTREAM_RULE_PREFIX)
}

/// The ports a management rule opens: SSH first, then the web listeners.
pub fn management_ports(ssh: u16, web: &WebSettings) -> Vec<u16> {
    let mut v = vec![ssh];
    for p in web.all_ports() {
        if !v.contains(&p) {
            v.push(p);
        }
    }
    v
}

/// A system `Upstream management via <if>` rule opens SSH and every web port as configured
/// now (the stored list may predate a port change). Other rules are left alone.
pub fn follow_upstream_ports(
    rule: &mut FirewallRule,
    origin: RuleOrigin,
    ssh: u16,
    web: &WebSettings,
) {
    if is_upstream(rule, origin) {
        rule.dport = Some(PortSpec::Multiple(management_ports(ssh, web)));
    }
}

fn rule_name(iface: &str, net: &str, many_nets: bool) -> String {
    if many_nets {
        format!("{UPSTREAM_RULE_PREFIX}{iface} from {net}")
    } else {
        format!("{UPSTREAM_RULE_PREFIX}{iface}")
    }
}

fn build_rule(name: String, iface: &str, net: &str, ports: &[u16]) -> FirewallRule {
    let mut r = FirewallRule::new(name, ChainType::Input, FirewallAction::Accept);
    r.interface_in = Some(iface.to_string());
    r.source = Some(net.to_string());
    r.protocol = Some(Protocol::Tcp);
    r.dport = Some(PortSpec::Multiple(ports.to_vec()));
    // starts with the rule name: nft shows it as the rule's comment, which the router image's
    // boot safety net looks for
    r.comment = Some(format!(
        "{UPSTREAM_RULE_PREFIX}{iface}: SSH and web UI from the upstream LAN {net} (system rule)"
    ));
    r
}

fn rule_ports(r: &FirewallRule) -> Option<Vec<u16>> {
    match r.dport.as_ref()? {
        PortSpec::Single(p) => Some(vec![*p]),
        PortSpec::Multiple(v) => Some(v.clone()),
        _ => None,
    }
}

/// Is `r` a hand-added user rule doing exactly what the seeded rule for (`iface`, `net`) does:
/// accept tcp to the management ports from that network on that interface, with no other
/// narrowing or side effects? Only then is it safe to replace it.
fn is_legacy_equivalent(
    r: &FirewallRule,
    o: RuleOrigin,
    iface: &str,
    net: &str,
    ok: &[u16],
) -> bool {
    o == RuleOrigin::User
        && r.enabled
        && r.chain == ChainType::Input
        && r.action == FirewallAction::Accept
        && r.protocol == Some(Protocol::Tcp)
        && r.interface_in.as_deref() == Some(iface)
        && r.source.as_deref() == Some(net)
        && r.destination.is_none()
        && r.interface_out.is_none()
        && r.sport.is_none()
        && r.schedule.is_none()
        && r.gateway.is_none()
        && r.ip_version.is_none()
        && !r.log
        && rule_ports(r).is_some_and(|p| !p.is_empty() && p.iter().all(|x| ok.contains(x)))
}

/// Seed / refresh the upstream management rules for `spec`. No-op without a network. Safe to
/// call at every boot and from several processes: rows are keyed by name, and the order
/// (insert the system rule, then delete the replaced user rule) means a crash in between
/// leaves a duplicate that the next call removes, never a gap in access.
pub async fn ensure_management(store: &ConfigStore, spec: &ManagementSpec) -> Result<MgmtReport> {
    let mut rep = MgmtReport {
        warnings: spec.warnings.clone(),
        ..Default::default()
    };
    if spec.networks.is_empty() {
        return Ok(rep);
    }
    let ifaces = if spec.interfaces.is_empty() {
        store.interfaces_with_role("wan").await?
    } else {
        spec.interfaces.clone()
    };
    if ifaces.is_empty() {
        let w = "management network configured but no uplink interface (no WAN role and no \
                 interface list): no upstream management rule seeded"
            .to_string();
        tracing::warn!("{w}");
        rep.warnings.push(w);
        return Ok(rep);
    }
    let ssh = crate::defaults::ssh_port(store).await;
    let web = crate::webui::resolve(Some(store)).await;
    let ports = management_ports(ssh, &web);
    // legacy rules may use the stock 22/80/443 as well as the configured ports
    let mut ok_ports = ports.clone();
    for p in [22u16, 80, 443] {
        if !ok_ports.contains(&p) {
            ok_ports.push(p);
        }
    }
    let many = spec.networks.len() > 1;
    for iface in &ifaces {
        for net in &spec.networks {
            let name = rule_name(iface, net, many);
            let rules = store.load_firewall_rules_with_origin().await?;
            let existing = rules
                .iter()
                .find(|(r, o)| *o == RuleOrigin::System && r.name == name);
            match existing {
                Some((r, _)) => {
                    let id =
                        r.id.ok_or_else(|| Error::Config("rule without id".into()))?;
                    let want = build_rule(name.clone(), iface, net, &ports);
                    if r.source != want.source
                        || r.interface_in != want.interface_in
                        || !r.enabled
                        || r.chain != want.chain
                        || r.action != want.action
                        || r.protocol != want.protocol
                        || r.destination.is_some()
                    {
                        // system rows are not editable through the API: refresh in place here
                        sqlx::query(
                            "UPDATE firewall_rules SET source = ?, interface_in = ?, enabled = 1,
                                 chain = ?, action = ?, protocol = ?, destination = NULL,
                                 updated_at = ? WHERE id = ?",
                        )
                        .bind(&want.source)
                        .bind(&want.interface_in)
                        .bind(want.chain.to_string())
                        .bind(want.action.to_string())
                        .bind(want.protocol.as_ref().map(|p| p.to_string()))
                        .bind(chrono::Utc::now().timestamp())
                        .bind(id as i64)
                        .execute(store.pool()?)
                        .await
                        .map_err(|e| Error::Config(format!("refresh {name}: {e}")))?;
                        rep.updated.push(name.clone());
                    }
                }
                None => {
                    store
                        .insert_firewall_rule(
                            &build_rule(name.clone(), iface, net, &ports),
                            RuleOrigin::System,
                        )
                        .await?;
                    rep.added.push(name.clone());
                }
            }
            // user rules that did the same job by hand are now redundant
            let rules = store.load_firewall_rules_with_origin().await?;
            for (r, o) in &rules {
                if is_legacy_equivalent(r, *o, iface, net, &ok_ports) {
                    if let Some(id) = r.id {
                        store.delete_firewall_rule(id).await?;
                        rep.replaced_user_rules.push(id);
                    }
                }
            }
        }
    }
    if !rep.added.is_empty() || !rep.updated.is_empty() || !rep.replaced_user_rules.is_empty() {
        store
            .audit(
                "system",
                "seed_upstream_management",
                "firewall_rule",
                None,
                &serde_json::json!({
                    "added": rep.added, "updated": rep.updated,
                    "replaced_user_rules": rep.replaced_user_rules,
                }),
            )
            .await?;
        tracing::info!(
            "upstream management rules: added {:?}, updated {:?}, replaced user rules {:?}",
            rep.added,
            rep.updated,
            rep.replaced_user_rules
        );
    }
    Ok(rep)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(net: &str, ifs: &str) -> ManagementSpec {
        ManagementSpec::parse(Some(net), Some(ifs))
    }

    fn legacy(iface: &str, ports: Vec<u16>) -> FirewallRule {
        let mut r = build_rule(
            format!("House LAN management via {iface}"),
            iface,
            "192.0.2.0/24",
            &ports,
        );
        r.comment = None;
        r
    }

    async fn rules(s: &ConfigStore) -> Vec<(FirewallRule, RuleOrigin)> {
        s.load_firewall_rules_with_origin().await.unwrap()
    }

    #[test]
    fn parsing_is_strict_and_never_widens() {
        let s = ManagementSpec::parse(
            Some("192.0.2.0/24, bogus 0.0.0.0/0 198.51.100.0/25 192.0.2.0/24"),
            Some("wl5-sta wl24-sta;rm x,eth1"),
        );
        assert_eq!(s.networks, vec!["192.0.2.0/24", "198.51.100.0/25"]);
        assert_eq!(s.interfaces, vec!["wl5-sta", "x", "eth1"]); // "wl24-sta;rm" is not an interface name
        assert_eq!(s.warnings.len(), 3, "{:?}", s.warnings);
        assert_eq!(ManagementSpec::parse(None, None), ManagementSpec::default());
        assert!(
            valid_cidr("2001:db8::/32") && !valid_cidr("10.0.0.0/33") && !valid_cidr("10.0.0.1")
        );
    }

    #[tokio::test]
    async fn seeds_one_system_rule_per_uplink_with_configured_ports_and_is_idempotent() {
        let s = ConfigStore::open_in_memory().await.unwrap();
        s.save_system_config(crate::defaults::SSH_PORT_KEY, "2222")
            .await
            .unwrap();
        let sp = spec("192.0.2.0/24", "wl5-sta wl24-sta");
        let r = ensure_management(&s, &sp).await.unwrap();
        assert_eq!(r.added.len(), 2);
        let again = ensure_management(&s, &sp).await.unwrap();
        assert_eq!(again, MgmtReport::default());
        let up: Vec<_> = rules(&s)
            .await
            .into_iter()
            .filter(|(r, _)| r.name.starts_with(UPSTREAM_RULE_PREFIX))
            .collect();
        assert_eq!(up.len(), 2);
        for (r, o) in &up {
            assert_eq!(*o, RuleOrigin::System);
            assert_eq!(r.source.as_deref(), Some("192.0.2.0/24"));
            assert_eq!(r.chain, ChainType::Input);
            assert_eq!(r.dport, Some(PortSpec::Multiple(vec![2222, 443, 80])));
        }
        // the store refuses to delete it (anti-lockout semantics)
        assert!(s.delete_firewall_rule(up[0].0.id.unwrap()).await.is_err());
    }

    #[tokio::test]
    async fn interfaces_default_to_wan_roles_and_no_uplink_means_no_rule() {
        let s = ConfigStore::open_in_memory().await.unwrap();
        let sp = spec("192.0.2.0/24", "");
        let r = ensure_management(&s, &sp).await.unwrap();
        assert!(r.added.is_empty() && r.warnings.len() == 1);
        s.set_interface_role("wl24-sta", Some("wan")).await.unwrap();
        let r = ensure_management(&s, &sp).await.unwrap();
        assert_eq!(r.added, vec!["Upstream management via wl24-sta"]);
        // no network configured: nothing, whatever the roles are
        let none = ensure_management(&s, &ManagementSpec::default())
            .await
            .unwrap();
        assert_eq!(none, MgmtReport::default());
    }

    #[tokio::test]
    async fn hand_added_slate_rules_are_replaced_without_duplicates_and_unrelated_ones_kept() {
        let s = ConfigStore::open_in_memory().await.unwrap();
        crate::defaults::ensure_defaults(&s, None, &[])
            .await
            .unwrap();
        let a = s
            .save_firewall_rule(&legacy("wl24-sta", vec![22, 80, 443]))
            .await
            .unwrap();
        let b = s
            .save_firewall_rule(&legacy("wl5-sta", vec![22, 80, 443]))
            .await
            .unwrap();
        // look-alikes that must survive: wider ports, other source, other interface, disabled, drop
        let mut wide = legacy("wl5-sta", vec![22, 8080]);
        wide.name = "wide".into();
        let mut other = legacy("wl5-sta", vec![22]);
        other.source = Some("198.51.100.0/24".into());
        other.name = "other src".into();
        let mut lan = legacy("br-lan", vec![22]);
        lan.name = "other if".into();
        let mut off = legacy("wl5-sta", vec![22]);
        off.enabled = false;
        off.name = "disabled".into();
        let mut drop = legacy("wl5-sta", vec![22]);
        drop.action = FirewallAction::Drop;
        drop.name = "drop".into();
        for r in [&wide, &other, &lan, &off, &drop] {
            s.save_firewall_rule(r).await.unwrap();
        }
        let sp = spec("192.0.2.0/24", "wl24-sta wl5-sta");
        let r = ensure_management(&s, &sp).await.unwrap();
        assert_eq!(r.replaced_user_rules, vec![a as u64, b as u64]);
        let names: Vec<String> = rules(&s).await.into_iter().map(|(r, _)| r.name).collect();
        for gone in [
            "House LAN management via wl24-sta",
            "House LAN management via wl5-sta",
        ] {
            assert!(!names.iter().any(|n| n == gone), "{names:?}");
        }
        for kept in ["wide", "other src", "other if", "disabled", "drop"] {
            assert!(names.iter().any(|n| n == kept), "{kept} lost: {names:?}");
        }
        assert_eq!(
            names
                .iter()
                .filter(|n| n.starts_with(UPSTREAM_RULE_PREFIX))
                .count(),
            2
        );
        // a second run changes nothing
        assert_eq!(
            ensure_management(&s, &sp).await.unwrap(),
            MgmtReport::default()
        );
    }

    #[tokio::test]
    async fn a_crash_between_insert_and_delete_heals_on_the_next_run() {
        let s = ConfigStore::open_in_memory().await.unwrap();
        s.insert_firewall_rule(
            &build_rule(
                format!("{UPSTREAM_RULE_PREFIX}wl5-sta"),
                "wl5-sta",
                "192.0.2.0/24",
                &[22, 443, 80],
            ),
            RuleOrigin::System,
        )
        .await
        .unwrap();
        s.save_firewall_rule(&legacy("wl5-sta", vec![22, 80, 443]))
            .await
            .unwrap();
        let r = ensure_management(&s, &spec("192.0.2.0/24", "wl5-sta"))
            .await
            .unwrap();
        assert!(r.added.is_empty() && r.replaced_user_rules.len() == 1);
    }

    #[tokio::test]
    async fn a_changed_management_network_refreshes_the_system_rule_in_place() {
        let s = ConfigStore::open_in_memory().await.unwrap();
        ensure_management(&s, &spec("192.0.2.0/24", "wl5-sta"))
            .await
            .unwrap();
        let r = ensure_management(&s, &spec("198.51.100.0/24", "wl5-sta"))
            .await
            .unwrap();
        assert_eq!(r.updated.len(), 1);
        let up: Vec<_> = rules(&s)
            .await
            .into_iter()
            .filter(|(r, _)| r.name.starts_with(UPSTREAM_RULE_PREFIX))
            .collect();
        assert_eq!(up.len(), 1);
        assert_eq!(up[0].0.source.as_deref(), Some("198.51.100.0/24"));
    }

    #[test]
    fn follow_upstream_ports_tracks_ssh_and_web_settings_for_system_rules_only() {
        let web = WebSettings::default();
        let mut r = build_rule(
            format!("{UPSTREAM_RULE_PREFIX}x"),
            "x",
            "192.0.2.0/24",
            &[22, 443],
        );
        follow_upstream_ports(&mut r, RuleOrigin::System, 2200, &web);
        assert_eq!(
            r.dport,
            Some(PortSpec::Multiple(management_ports(2200, &web)))
        );
        assert_eq!(rule_ports(&r).unwrap()[0], 2200);
        let mut u = build_rule(
            format!("{UPSTREAM_RULE_PREFIX}x"),
            "x",
            "192.0.2.0/24",
            &[22],
        );
        follow_upstream_ports(&mut u, RuleOrigin::User, 2200, &web);
        assert_eq!(u.dport, Some(PortSpec::Multiple(vec![22])));
        let mut o = build_rule("other".into(), "x", "192.0.2.0/24", &[22]);
        follow_upstream_ports(&mut o, RuleOrigin::System, 2200, &web);
        assert_eq!(o.dport, Some(PortSpec::Multiple(vec![22])));
    }
}
