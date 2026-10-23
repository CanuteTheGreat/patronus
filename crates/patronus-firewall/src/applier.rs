//! The firewall/NAT [`Applier`]: renders every filter and NAT row in the
//! config store into ONE nftables transaction and loads it atomically.
//!
//! This replaces the old in-memory `RuleManager` path, where every rule
//! lived only in a process's memory (lost on restart) and the boot unit
//! applied an empty ruleset.
//!
//! - Atomic: the script starts with `add table` + `delete table`, then
//!   recreates the base chains and all rules, all inside one `nft -f`
//!   run. nft either commits all of it or nothing, so a bad rule can never
//!   leave the box half-configured.
//! - Interface roles: `@wan`, `@lan`, `@optN` in `interface_in`/
//!   `interface_out` resolve to the interfaces carrying that role in the
//!   store (one nft rule per interface). An unassigned role skips the
//!   rule with a warning -- it is never widened to "any interface".
//!   `@mgmt` (anti-lockout) resolves to LAN, else WAN, else any interface.
//! - Fail closed: an accept rule that cannot be rendered is skipped (the
//!   chain policy is drop); a drop/reject rule that cannot be rendered, or
//!   an nft failure, aborts the apply. If the kernel had no Patronus table
//!   (boot), a lockdown ruleset (base chains + anti-lockout only) is
//!   loaded so the box is neither wide open nor unreachable.

use crate::aliases::{alias_map, load_aliases, sets_script};
use crate::nftables::{
    self, base_table_script, policy_chain_script, render_filter_rule, render_nat_rule,
    render_policy_rule, rule_to_nft_command, NatContext, TABLE,
};
use crate::schedule::{load_schedules, now as schedule_now};
use async_trait::async_trait;
use patronus_config::applier::{Applier, ApplyReport, Phase};
use patronus_config::declarative::{
    AddressSpec, DeclarativeConfig, Direction, ResourceKind, ResourceSpec, RuleAction,
};
use patronus_config::store::{ConfigStore, RuleOrigin};
use patronus_core::types::{
    ChainType, FirewallAction, FirewallRule, NatRule, NatType, PortSpec, Protocol,
};
use patronus_core::{Error, Result};
use std::collections::BTreeMap;

/// Firewall + NAT applier (boot phase [`Phase::Firewall`]).
#[derive(Debug, Default, Clone, Copy)]
pub struct FirewallApplier;

/// role -> interfaces
type Roles = BTreeMap<String, Vec<String>>;

async fn load_roles(store: &ConfigStore) -> Result<Roles> {
    let mut roles = Roles::new();
    for (name, role) in store.interface_roles().await? {
        roles.entry(role).or_default().push(name);
    }
    Ok(roles)
}

/// Devices behind the IPv4 gateways of lane E's `route_gateways` table
/// (device names, or roles resolved through `roles`; unassigned roles are
/// skipped).
async fn gateway_interfaces(store: &ConfigStore, roles: &Roles) -> Result<Vec<String>> {
    let rows = sqlx::query(
        "SELECT DISTINCT interface FROM route_gateways WHERE family = 'inet' ORDER BY interface",
    )
    .fetch_all(store.pool()?)
    .await
    .map_err(|e| Error::Config(format!("read gateways: {e}")))?;
    let mut out = Vec::new();
    for r in rows {
        let spec: String = sqlx::Row::get(&r, 0);
        match spec.strip_prefix('@') {
            Some(role) => out.extend(
                roles
                    .get(&role.to_ascii_lowercase())
                    .cloned()
                    .unwrap_or_default(),
            ),
            None => out.push(spec),
        }
    }
    Ok(out)
}

/// Devices the automatic outbound NAT covers: the WAN role plus every
/// interface an IPv4 gateway sits behind.
async fn nat_devices(store: &ConfigStore, roles: &Roles) -> Result<Vec<String>> {
    let mut v: Vec<String> = roles.get("wan").cloned().unwrap_or_default();
    for dev in gateway_interfaces(store, roles).await? {
        if !v.contains(&dev) {
            v.push(dev);
        }
    }
    Ok(v)
}

/// [`nat_devices`] for the UI ("automatic outbound NAT covers ...").
pub async fn auto_nat_devices(store: &ConfigStore) -> Result<Vec<String>> {
    nat_devices(store, &load_roles(store).await?).await
}

/// Resolve one interface field. `Ok(None)` = an unassigned role (skip the
/// rule); `Ok(Some(v))` = the concrete values (`None` inside = no match).
fn resolve_iface(value: &Option<String>, roles: &Roles) -> Option<Vec<Option<String>>> {
    let Some(v) = value else {
        return Some(vec![None]);
    };
    let Some(role) = v.strip_prefix('@') else {
        return Some(vec![Some(v.clone())]);
    };
    let role = role.to_ascii_lowercase();
    let named = |r: &str| roles.get(r).filter(|v| !v.is_empty()).cloned();
    if role == "mgmt" {
        return Some(match named("lan").or_else(|| named("wan")) {
            Some(names) => names.into_iter().map(Some).collect(),
            None => vec![None],
        });
    }
    named(&role).map(|names| names.into_iter().map(Some).collect())
}

/// `system_config` key holding the outbound NAT mode.
pub const OUTBOUND_NAT_MODE_KEY: &str = "firewall.outbound_nat_mode";

/// How outbound (source) NAT is generated -- the pfSense/OPNsense model.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OutboundNatMode {
    /// Only the automatic rules: IPv4 masquerade on every WAN interface.
    Automatic,
    /// Manual outbound rules first, then the automatic ones (default).
    Hybrid,
    /// Only the manual outbound rules.
    Manual,
    /// No outbound NAT at all.
    Disabled,
}

impl OutboundNatMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Automatic => "automatic",
            Self::Hybrid => "hybrid",
            Self::Manual => "manual",
            Self::Disabled => "disabled",
        }
    }
    pub fn parse(s: &str) -> Result<Self> {
        Ok(match s.trim().to_ascii_lowercase().as_str() {
            "automatic" | "auto" => Self::Automatic,
            "hybrid" => Self::Hybrid,
            "manual" => Self::Manual,
            "disabled" | "off" | "none" => Self::Disabled,
            o => {
                return Err(Error::Config(format!(
                    "Invalid outbound NAT mode {o:?} (automatic, hybrid, manual or disabled)"
                )))
            }
        })
    }
    fn auto_rules(&self) -> bool {
        matches!(self, Self::Automatic | Self::Hybrid)
    }
    fn manual_rules(&self) -> bool {
        matches!(self, Self::Hybrid | Self::Manual)
    }
}

/// The stored outbound NAT mode (default: hybrid).
pub async fn outbound_nat_mode(store: &ConfigStore) -> Result<OutboundNatMode> {
    match store.load_system_config(OUTBOUND_NAT_MODE_KEY).await? {
        Some(v) => OutboundNatMode::parse(&v),
        None => Ok(OutboundNatMode::Hybrid),
    }
}

/// Store the outbound NAT mode (the caller re-applies).
pub async fn set_outbound_nat_mode(store: &ConfigStore, mode: OutboundNatMode) -> Result<()> {
    store
        .save_system_config(OUTBOUND_NAT_MODE_KEY, mode.as_str())
        .await
}

/// fe80::/10: link-local addresses are not what a LAN client dials.
fn is_link_local_v6(ip: &std::net::Ipv6Addr) -> bool {
    (ip.segments()[0] & 0xffc0) == 0xfe80
}

/// Addresses configured on an interface (for NAT reflection).
fn interface_addresses(name: &str) -> Vec<std::net::IpAddr> {
    let Ok(addrs) = nix::ifaddrs::getifaddrs() else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for a in addrs.filter(|a| a.interface_name == name) {
        let Some(sa) = a.address else { continue };
        if let Some(v4) = sa.as_sockaddr_in() {
            out.push(std::net::IpAddr::V4(v4.ip()));
        } else if let Some(v6) = sa.as_sockaddr_in6() {
            let ip = v6.ip();
            if !is_link_local_v6(&ip) {
                out.push(std::net::IpAddr::V6(ip));
            }
        }
    }
    out
}

/// Is a NAT rule an outbound (source NAT) rule, governed by the mode?
fn is_outbound(t: &NatType) -> bool {
    matches!(t, NatType::Masquerade | NatType::Snat { .. })
}

/// Rendered ruleset plus what went into it.
pub struct Rendered {
    pub script: String,
    pub report: ApplyReport,
}

impl FirewallApplier {
    /// Render the full ruleset for the store. `lockdown` keeps only system
    /// (anti-lockout) rules and no NAT.
    pub async fn render_script(&self, store: &ConfigStore, lockdown: bool) -> Result<Rendered> {
        self.render_script_at(store, lockdown, schedule_now()).await
    }

    /// [`Self::render_script`] with schedules evaluated at `at`.
    pub async fn render_script_at(
        &self,
        store: &ConfigStore,
        lockdown: bool,
        at: chrono::NaiveDateTime,
    ) -> Result<Rendered> {
        let roles = load_roles(store).await?;
        let mut report = ApplyReport::default();
        let mut script = String::new();
        script.push_str(&format!("add table {TABLE}\ndelete table {TABLE}\n"));
        script.push_str(&base_table_script());

        let (aliases, schedules) = if lockdown {
            (Vec::new(), Vec::new())
        } else {
            (load_aliases(store).await?, load_schedules(store).await?)
        };
        script.push_str(&sets_script(&aliases)?);
        let amap = alias_map(&aliases);

        let (mut nfilter, mut nnat, mut nsched) = (0usize, 0usize, 0usize);
        // policy routing (lane E contract): gateway/group name -> mark
        let marks = if lockdown {
            Default::default()
        } else {
            patronus_config::policy::policy_marks(store).await?
        };
        let mut policy = String::new();
        for (rule, origin) in store.load_firewall_rules_with_origin().await? {
            if !rule.enabled || (lockdown && origin != RuleOrigin::System) {
                continue;
            }
            let label = format!("rule {} {:?}", rule.id.unwrap_or(0), rule.name);
            if let Some(sname) = &rule.schedule {
                match schedules.iter().find(|s| &s.name == sname) {
                    Some(s) if s.is_active_at(at) => {}
                    Some(_) => {
                        nsched += 1;
                        continue;
                    }
                    // A rule naming a missing schedule: an allow is not
                    // granted, a block keeps blocking (fail closed).
                    None if rule.action == FirewallAction::Accept => {
                        report.warn(format!(
                            "{label} skipped: its schedule {sname:?} does not exist"
                        ));
                        continue;
                    }
                    None => report.warn(format!(
                        "{label}: its schedule {sname:?} does not exist; enforcing it always"
                    )),
                }
            }
            let (Some(ins), Some(outs)) = (
                resolve_iface(&rule.interface_in, &roles),
                resolve_iface(&rule.interface_out, &roles),
            ) else {
                report.warn(format!(
                    "{label} skipped: its interface role is not assigned to any interface"
                ));
                continue;
            };
            for i in &ins {
                for o in &outs {
                    let mut r = rule.clone();
                    r.interface_in = i.clone();
                    r.interface_out = o.clone();
                    if r.comment.is_none() {
                        r.comment = Some(r.name.clone());
                    }
                    match render_filter_rule(&r, &amap) {
                        Ok(lines) => {
                            for l in lines {
                                script.push_str(&l);
                                script.push('\n');
                                nfilter += 1;
                            }
                            if let Some(g) = &rule.gateway {
                                match marks.get(g) {
                                    Some(m) => match render_policy_rule(&r, &amap, *m) {
                                        Ok(pl) => {
                                            for l in pl {
                                                policy.push_str(&l);
                                                policy.push('\n');
                                            }
                                        }
                                        Err(e) => {
                                            report.warn(format!("{label}: no policy routing ({e})"))
                                        }
                                    },
                                    None => report.warn(format!(
                                        "{label}: gateway {g:?} does not exist; its traffic \
                                         follows the default route"
                                    )),
                                }
                            }
                        }
                        Err(e) if rule.action == FirewallAction::Accept => {
                            report.warn(format!("{label} skipped (cannot render: {e})"));
                        }
                        Err(e) => {
                            return Err(Error::Firewall(format!(
                                "{label} is a {} rule that cannot be rendered, refusing to \
                                 load a ruleset without it: {e}",
                                rule.action
                            )))
                        }
                    }
                }
            }
        }

        if !policy.is_empty() {
            script.push_str(&policy_chain_script());
            script.push_str(&policy);
        }
        // lane F: VPN listen ports, IPsec SA traffic, IPsec NAT exemption
        let mut vpn = if lockdown {
            crate::vpn_rules::VpnRules::default()
        } else {
            crate::vpn_rules::vpn_rules(store).await?
        };
        // lane G: VRRP and connection-state sync between the HA nodes
        if !lockdown {
            vpn.filter.extend(crate::ha_rules::ha_rules(store).await?);
            // IGMP proxy, NAT64, L2TP, inline IDS
            let sr = crate::svc_rules::svc_rules(store).await?;
            vpn.filter.extend(sr.filter);
            vpn.nat_exempt.extend(sr.nat_exempt);
            vpn.nat_pre.extend(sr.nat_pre);
        }
        for l in &vpn.filter {
            script.push_str(l);
            script.push('\n');
            nfilter += 1;
        }
        if !lockdown {
            let mode = outbound_nat_mode(store).await?;
            let mut forward_tail = String::new();
            let mut pre = String::new();
            let mut post = String::new();
            // IPsec site-to-site traffic must not be masqueraded (lane F)
            for l in &vpn.nat_exempt {
                post.push_str(l);
                post.push('\n');
                nnat += 1;
            }
            for l in &vpn.nat_pre {
                pre.push_str(l);
                pre.push('\n');
                nnat += 1;
            }
            for (rule, _) in store.load_nat_rules_with_origin().await? {
                if !rule.enabled || (is_outbound(&rule.nat_type) && !mode.manual_rules()) {
                    continue;
                }
                let label = format!("NAT rule {} {:?}", rule.id.unwrap_or(0), rule.name);
                let (Some(ins), Some(outs)) = (
                    resolve_iface(&rule.interface_in, &roles),
                    resolve_iface(&rule.interface_out, &roles),
                ) else {
                    report.warn(format!(
                        "{label} skipped: its interface role is not assigned to any interface"
                    ));
                    continue;
                };
                for i in &ins {
                    for o in &outs {
                        let mut r = rule.clone();
                        r.interface_in = i.clone();
                        r.interface_out = o.clone();
                        if r.comment.is_none() {
                            r.comment = Some(r.name.clone());
                        }
                        let ctx = NatContext {
                            inbound_addresses: i
                                .as_deref()
                                .map(interface_addresses)
                                .unwrap_or_default(),
                        };
                        match render_nat_rule(&r, &amap, &ctx) {
                            Ok(l) => {
                                nnat += 1;
                                if r.reflection && ctx.inbound_addresses.is_empty() {
                                    report.warn(format!(
                                        "{label}: NAT reflection needs an address on {}",
                                        i.as_deref().unwrap_or("?")
                                    ));
                                }
                                for x in l.prerouting {
                                    pre.push_str(&x);
                                    pre.push('\n');
                                }
                                for x in l.postrouting {
                                    post.push_str(&x);
                                    post.push('\n');
                                }
                                for x in l.forward {
                                    forward_tail.push_str(&x);
                                    forward_tail.push('\n');
                                }
                            }
                            Err(e) => report.warn(format!("{label} skipped (cannot render: {e})")),
                        }
                    }
                }
            }
            if mode.auto_rules() {
                // every WAN, plus every interface an IPv4 gateway sits behind
                // (a second uplink on OPTn: multi-WAN, lane E) -- the
                // pfSense rule "interfaces with a gateway get outbound NAT"
                let nat_devs = nat_devices(store, &roles).await?;
                for wan in &nat_devs {
                    if !nftables::is_valid_interface_name(wan) {
                        report.warn(format!(
                            "WAN interface {wan:?}: invalid name, no outbound NAT"
                        ));
                        continue;
                    }
                    // Leading `meta nfproto ipv4`: IPv6 is routed, not NATed.
                    post.push_str(&format!(
                        "add rule {TABLE} postrouting meta nfproto ipv4 oifname \"{wan}\" \
                         masquerade comment \"Automatic outbound NAT\"\n"
                    ));
                    nnat += 1;
                }
            }
            // port-forward accepts go after the user's filter rules, so a
            // user block (e.g. an abusive source alias) still wins
            script.push_str(&forward_tail);
            script.push_str(&pre);
            script.push_str(&post);
            report.applied(format!("outbound NAT mode {}", mode.as_str()));
        }
        report.applied(format!(
            "{nfilter} filter rule(s), {nnat} NAT rule(s), {} alias(es)",
            aliases.len()
        ));
        if nsched > 0 {
            report.applied(format!(
                "{nsched} scheduled rule(s) inactive at {}",
                at.format("%a %H:%M")
            ));
        }
        Ok(Rendered { script, report })
    }
}

impl FirewallApplier {
    /// The lockdown ruleset: base chains (policy drop) plus anti-lockout
    /// only, no NAT. Built from the built-in anti-lockout definition and the
    /// interface roles -- never from the stored rules -- so it still loads
    /// when the stored rules are what failed (a damaged row, a rule from a
    /// newer version). If even the roles can't be read, anti-lockout is
    /// open on every interface: reachable beats locked out, and nothing is
    /// forwarded either way.
    pub async fn render_lockdown(&self, store: &ConfigStore) -> String {
        let roles = load_roles(store).await.unwrap_or_default();
        let mut script = format!("add table {TABLE}\ndelete table {TABLE}\n");
        script.push_str(&base_table_script());
        for (rule, origin) in patronus_config::defaults::default_filter_rules() {
            if origin != RuleOrigin::System {
                continue;
            }
            for i in resolve_iface(&rule.interface_in, &roles).unwrap_or_else(|| vec![None]) {
                let mut r = rule.clone();
                r.interface_in = i;
                r.comment = Some(r.name.clone());
                if let Ok(cmd) = rule_to_nft_command(&r) {
                    script.push_str(&cmd);
                    script.push('\n');
                }
            }
        }
        script
    }
}

impl FirewallApplier {
    /// Load the lockdown ruleset ([`render_lockdown`](Self::render_lockdown)).
    /// If even that cannot be loaded, switch forwarding off and return the
    /// error: a box without any ruleset must at least not route.
    pub async fn load_lockdown(&self, store: &ConfigStore) -> Result<()> {
        let lock = self.render_lockdown(store).await;
        nftables::execute_nft_script(&lock)
            .map(|_| ())
            .map_err(|e| {
                let off = disable_forwarding(std::path::Path::new("/proc/sys"));
                Error::Firewall(format!(
                    "the lockdown ruleset failed too: {e}; forwarding switched off ({})",
                    off.join(", ")
                ))
            })
    }
}

fn table_exists() -> bool {
    nftables::list_table().is_ok()
}

/// Last resort when no ruleset at all could be loaded: stop routing, so a
/// box without a firewall at least does not forward between WAN and LAN.
/// Returns what was switched off.
pub fn disable_forwarding(proc_sys: &std::path::Path) -> Vec<String> {
    let mut off = Vec::new();
    for key in ["net/ipv4/ip_forward", "net/ipv6/conf/all/forwarding"] {
        if std::fs::write(proc_sys.join(key), "0\n").is_ok() {
            off.push(key.replace('/', "."));
        }
    }
    off
}

/// br_netfilter keys that push *bridged* frames through the inet hooks.
const BRIDGE_NF_KEYS: [&str; 3] = [
    "net/bridge/bridge-nf-call-iptables",
    "net/bridge/bridge-nf-call-ip6tables",
    "net/bridge/bridge-nf-call-arptables",
];

/// A Patronus bridge is a layer-2 switch: frames between its member ports
/// are not routed and must not meet the routed `forward` policy (drop).
/// When the `br_netfilter` module is loaded (Docker and many distros load
/// it; a new network namespace then starts with `bridge-nf-call-*=1`), the
/// kernel would push every bridged frame through `inet patronus forward`,
/// where nothing matches `br0 -> br0` and the policy drops it: hosts on the
/// same bridge could no longer reach each other. Switch those hooks off at
/// every firewall apply (also catches a module loaded after boot); with the
/// module absent the keys don't exist and nothing is touched. Returns the
/// keys that were changed.
pub fn bridges_stay_layer2(proc_sys: &std::path::Path) -> Vec<String> {
    let mut changed = Vec::new();
    for key in BRIDGE_NF_KEYS {
        let path = proc_sys.join(key);
        let Ok(v) = std::fs::read_to_string(&path) else {
            continue; // module not loaded
        };
        if v.trim() == "0" {
            continue;
        }
        if let Err(e) = std::fs::write(&path, "0\n") {
            tracing::warn!("could not set {key} = 0: {e}");
        } else {
            changed.push(key.replace('/', "."));
        }
    }
    changed
}

#[async_trait]
impl Applier for FirewallApplier {
    fn name(&self) -> &'static str {
        "firewall"
    }

    fn phase(&self) -> Phase {
        Phase::Firewall
    }

    async fn apply(&self, store: &ConfigStore) -> Result<ApplyReport> {
        let had_table = table_exists();
        let full = self.render_script(store, false).await;
        let err = match full {
            Ok(r) => match nftables::execute_nft_script(&r.script) {
                Ok(_) => {
                    let mut report = r.report;
                    let l2 = bridges_stay_layer2(std::path::Path::new("/proc/sys"));
                    if !l2.is_empty() {
                        report.applied(format!(
                            "bridged traffic kept out of the routed filter ({} = 0)",
                            l2.join(", ")
                        ));
                    }
                    tracing::info!("firewall applied: {}", report.applied.join("; "));
                    return Ok(report);
                }
                Err(e) => e,
            },
            Err(e) => e,
        };
        if had_table {
            // nft rolled the transaction back: the previous ruleset is
            // still loaded and enforcing.
            return Err(Error::Firewall(format!(
                "{err} (previous ruleset left in place)"
            )));
        }
        // Nothing was loaded before (boot): don't leave the box open. The
        // lockdown ruleset does not read the stored rules, so it loads even
        // when they are what failed (this used to `?` out of the same
        // failing render and leave a booted box with no ruleset at all and
        // forwarding on).
        match self.load_lockdown(store).await {
            Ok(()) => Err(Error::Firewall(format!(
                "{err} (lockdown ruleset loaded: only anti-lockout access is allowed)"
            ))),
            Err(e2) => Err(Error::Firewall(format!("{err}; {e2}"))),
        }
    }

    async fn render(&self, store: &ConfigStore) -> Result<String> {
        let r = self.render_script(store, false).await?;
        let mut out = r.script;
        for w in r.report.warnings {
            out.push_str(&format!("# warning: {w}\n"));
        }
        Ok(out)
    }

    async fn teardown(&self) -> Result<()> {
        if table_exists() {
            nftables::delete_table()?;
        }
        Ok(())
    }

    fn resource_kinds(&self) -> &'static [ResourceKind] {
        &[ResourceKind::FirewallRule, ResourceKind::NatRule]
    }

    async fn upsert_resource(&self, store: &ConfigStore, config: &DeclarativeConfig) -> Result<()> {
        let name = &config.metadata.name;
        let (filters, nats, schedule) = declarative_to_rules(config)?;
        store.delete_rules_by_name(RuleOrigin::Gitops, name).await?;
        if let Some(s) = &schedule {
            crate::schedule::save_schedule(store, s).await?;
        }
        for r in filters {
            store.insert_firewall_rule(&r, RuleOrigin::Gitops).await?;
        }
        for r in nats {
            store.insert_nat_rule(&r, RuleOrigin::Gitops).await?;
        }
        Ok(())
    }

    async fn delete_resource(
        &self,
        store: &ConfigStore,
        _kind: &ResourceKind,
        name: &str,
    ) -> Result<()> {
        store.delete_rules_by_name(RuleOrigin::Gitops, name).await?;
        let sched = gitops_schedule_name(name);
        if crate::schedule::load_schedules(store)
            .await?
            .iter()
            .any(|s| s.name == sched)
        {
            crate::schedule::delete_schedule(store, &sched).await?;
        }
        Ok(())
    }
}

fn protocol_of(p: Option<&str>) -> Result<Option<Protocol>> {
    Ok(match p.map(|s| s.trim().to_ascii_lowercase()).as_deref() {
        None | Some("") | Some("any") | Some("all") => None,
        Some("tcp") => Some(Protocol::Tcp),
        Some("udp") => Some(Protocol::Udp),
        Some("icmp") => Some(Protocol::Icmp),
        Some(o) => return Err(Error::Config(format!("Invalid protocol {o:?}"))),
    })
}

/// Port alternatives of an AddressSpec (one nft rule per alternative).
fn port_specs(a: &AddressSpec) -> Vec<Option<PortSpec>> {
    let mut v: Vec<Option<PortSpec>> = Vec::new();
    match a.ports.as_deref() {
        Some([p]) => v.push(Some(PortSpec::Single(*p))),
        Some(ps) if !ps.is_empty() => v.push(Some(PortSpec::Multiple(ps.to_vec()))),
        _ => {}
    }
    for r in a.port_ranges.iter().flatten() {
        v.push(Some(PortSpec::Range(r.start, r.end)));
    }
    if v.is_empty() {
        v.push(None);
    }
    v
}

/// Name of the schedule a GitOps rule's inline `schedule:` becomes.
pub fn gitops_schedule_name(resource: &str) -> String {
    let mut n: String = format!("gitops_{resource}")
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect();
    n.truncate(31);
    n
}

/// Translate a declarative FirewallRule/NatRule into store rows (plus the
/// schedule an inline `schedule:` becomes).
pub fn declarative_to_rules(
    config: &DeclarativeConfig,
) -> Result<(
    Vec<FirewallRule>,
    Vec<NatRule>,
    Option<crate::schedule::Schedule>,
)> {
    let name = config.metadata.name.clone();
    match &config.spec {
        ResourceSpec::FirewallRule(s) => {
            let schedule = match &s.schedule {
                None => None,
                Some(sp) => Some(
                    crate::schedule::Schedule {
                        name: gitops_schedule_name(&name),
                        days: sp.days.clone().unwrap_or_else(|| {
                            ["mon", "tue", "wed", "thu", "fri", "sat", "sun"]
                                .iter()
                                .map(|d| d.to_string())
                                .collect()
                        }),
                        start: sp
                            .time_range
                            .as_ref()
                            .map(|t| t.start.clone())
                            .unwrap_or_else(|| "00:00".into()),
                        end: sp
                            .time_range
                            .as_ref()
                            .map(|t| t.end.clone())
                            .unwrap_or_else(|| "00:00".into()),
                        description: Some(format!("gitops:{name}")),
                    }
                    .validated()
                    .map_err(|e| Error::Config(format!("{name}: {e}")))?,
                ),
            };
            if s.gateway.is_some() && !matches!(s.action, RuleAction::Allow) {
                return Err(Error::Config(format!(
                    "{name}: a gateway (policy routing) needs action allow"
                )));
            }
            let action = match s.action {
                RuleAction::Allow => FirewallAction::Accept,
                RuleAction::Deny => FirewallAction::Drop,
                RuleAction::Reject => FirewallAction::Reject,
            };
            let protocol = protocol_of(s.protocol.as_deref())?;
            // Inbound on an interface = traffic entering it, whether for
            // the firewall itself (input) or passing through (forward).
            let placements: Vec<(ChainType, bool)> =
                match s.direction.clone().unwrap_or(Direction::Inbound) {
                    Direction::Inbound => {
                        vec![(ChainType::Input, true), (ChainType::Forward, true)]
                    }
                    Direction::Outbound => {
                        vec![(ChainType::Forward, false), (ChainType::Output, false)]
                    }
                    Direction::Both => vec![
                        (ChainType::Input, true),
                        (ChainType::Forward, true),
                        (ChainType::Forward, false),
                        (ChainType::Output, false),
                    ],
                };
            let mut out = Vec::new();
            for (chain, inbound) in placements {
                for sport in port_specs(&s.source) {
                    for dport in port_specs(&s.destination) {
                        let mut r = FirewallRule::new(name.clone(), chain.clone(), action.clone());
                        r.enabled = s.enabled;
                        r.source = s.source.address.clone();
                        r.destination = s.destination.address.clone();
                        r.protocol = protocol.clone();
                        r.sport = sport.clone();
                        r.dport = dport;
                        if inbound {
                            r.interface_in = s.interface.clone();
                        } else {
                            r.interface_out = s.interface.clone();
                        }
                        r.comment = Some(format!("gitops:{name}"));
                        r.log = s.log;
                        r.schedule = schedule.as_ref().map(|x| x.name.clone());
                        // policy routing steers traffic entering the router
                        if inbound && chain == ChainType::Forward {
                            r.gateway = s.gateway.clone();
                        }
                        out.push(r);
                    }
                }
            }
            Ok((out, Vec::new(), schedule))
        }
        ResourceSpec::NatRule(s) => {
            use patronus_config::declarative::NatType as D;
            let to_addr = || -> Result<std::net::IpAddr> {
                s.translation
                    .as_ref()
                    .and_then(|t| t.address.as_deref())
                    .ok_or_else(|| {
                        Error::Config(format!("{name}: translation.address is required"))
                    })?
                    .parse()
                    .map_err(|_| {
                        Error::Config(format!("{name}: translation.address must be an IP address"))
                    })
            };
            let mut base = NatRule::new(name.clone(), NatType::Masquerade);
            base.enabled = s.enabled;
            base.source = s.source.address.clone();
            base.destination = s.destination.address.clone();
            base.comment = Some(format!("gitops:{name}"));
            let mut out = Vec::new();
            match s.nat_type {
                D::Masquerade => {
                    base.interface_out = Some(s.interface.clone());
                    out.push(base);
                }
                D::Snat => {
                    base.nat_type = NatType::Snat {
                        to_address: to_addr()?,
                    };
                    base.interface_out = Some(s.interface.clone());
                    out.push(base);
                }
                D::Dnat => {
                    base.interface_in = Some(s.interface.clone());
                    let to_port = s
                        .translation
                        .as_ref()
                        .and_then(|t| t.ports.as_ref())
                        .and_then(|p| p.first().copied());
                    base.nat_type = NatType::Dnat {
                        to_address: to_addr()?,
                        to_port,
                    };
                    let ports: Vec<Option<PortSpec>> = port_specs(&s.destination);
                    for dport in ports {
                        if dport.is_some() {
                            // A port forward without a protocol field: TCP and UDP.
                            for p in [Protocol::Tcp, Protocol::Udp] {
                                let mut r = base.clone();
                                r.protocol = Some(p);
                                r.dport = dport.clone();
                                out.push(r);
                            }
                        } else {
                            out.push(base.clone());
                        }
                    }
                }
                D::Redirect => {
                    return Err(Error::Config(format!(
                        "{name}: redirect NAT is not supported by the firewall applier yet"
                    )))
                }
            }
            Ok((Vec::new(), out, None))
        }
        _ => Err(Error::Config(format!(
            "{name}: {:?} is not a firewall resource",
            config.kind
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use patronus_config::defaults::{ensure_defaults, Bootstrap};

    async fn seeded(wan: &[&str], lan: &[&str]) -> ConfigStore {
        let s = ConfigStore::open_in_memory().await.unwrap();
        let b = Bootstrap {
            wan: wan.iter().map(|s| s.to_string()).collect(),
            lan: lan.iter().map(|s| s.to_string()).collect(),
        };
        let existing: Vec<String> = wan.iter().chain(lan).map(|s| s.to_string()).collect();
        ensure_defaults(&s, Some(&b), &existing).await.unwrap();
        s
    }

    #[tokio::test]
    async fn default_ruleset_renders_safe_router_policy() {
        let s = seeded(&["eth0"], &["eth1"]).await;
        let r = FirewallApplier.render_script(&s, false).await.unwrap();
        let sc = &r.script;
        assert!(
            sc.starts_with("add table inet patronus\ndelete table inet patronus\n"),
            "{sc}"
        );
        assert!(sc.contains("policy drop"), "{sc}");
        // anti-lockout on LAN only, never on WAN
        assert!(
            sc.contains("add rule inet patronus input iifname \"eth1\" tcp dport {22,8443} accept"),
            "{sc}"
        );
        assert!(!sc.contains("iifname \"eth0\" tcp dport {22,8443}"), "{sc}");
        assert!(
            sc.contains("add rule inet patronus forward iifname \"eth1\" accept"),
            "{sc}"
        );
        assert!(
            sc.contains(
                "add rule inet patronus postrouting meta nfproto ipv4 oifname \"eth0\" masquerade"
            ),
            "{sc}"
        );
        // nothing accepts traffic arriving on the WAN
        assert!(!sc.contains("iifname \"eth0\""), "{sc}");
        assert!(r.report.warnings.is_empty(), "{:?}", r.report.warnings);
    }

    #[tokio::test]
    async fn single_nic_box_keeps_anti_lockout_on_wan_and_skips_lan_rules() {
        let s = seeded(&["eth0"], &[]).await;
        let r = FirewallApplier.render_script(&s, false).await.unwrap();
        assert!(
            r.script
                .contains("input iifname \"eth0\" tcp dport {22,8443} accept"),
            "{}",
            r.script
        );
        assert!(
            !r.script.contains("forward iifname"),
            "LAN rules must be skipped, not widened"
        );
        assert_eq!(r.report.warnings.len(), 2, "{:?}", r.report.warnings);
    }

    #[tokio::test]
    async fn unassigned_box_is_manageable_but_forwards_nothing() {
        let s = seeded(&[], &[]).await;
        let r = FirewallApplier.render_script(&s, false).await.unwrap();
        assert!(
            r.script
                .contains("add rule inet patronus input tcp dport {22,8443} accept"),
            "{}",
            r.script
        );
        assert!(!r.script.contains("masquerade"));
        assert!(!r.script.contains("forward iifname"));
    }

    #[tokio::test]
    async fn multiple_lan_interfaces_expand_and_lockdown_keeps_only_system_rules() {
        let s = seeded(&["eth0"], &["eth1", "eth2"]).await;
        let mut u = FirewallRule::new("user-drop".into(), ChainType::Forward, FirewallAction::Drop);
        u.interface_in = Some("@lan".into());
        u.destination = Some("10.9.9.9".into());
        s.save_firewall_rule(&u).await.unwrap();
        let r = FirewallApplier.render_script(&s, false).await.unwrap();
        assert!(r.script.contains("forward iifname \"eth1\" accept"));
        assert!(r.script.contains("forward iifname \"eth2\" accept"));
        assert!(r.script.contains("iifname \"eth2\" ip daddr 10.9.9.9 drop"));
        let l = FirewallApplier.render_script(&s, true).await.unwrap();
        assert!(l.script.contains("tcp dport {22,8443} accept"));
        assert!(!l.script.contains("masquerade") && !l.script.contains("10.9.9.9"));
    }

    #[tokio::test]
    async fn unrenderable_drop_rule_aborts_but_bad_accept_is_skipped() {
        let s = seeded(&["eth0"], &["eth1"]).await;
        let mut bad = FirewallRule::new(
            "bad-accept".into(),
            ChainType::Input,
            FirewallAction::Accept,
        );
        bad.source = Some("not an address".into());
        s.save_firewall_rule(&bad).await.unwrap();
        let r = FirewallApplier.render_script(&s, false).await.unwrap();
        assert!(r.report.warnings.iter().any(|w| w.contains("bad-accept")));
        let mut bad = FirewallRule::new("bad-drop".into(), ChainType::Input, FirewallAction::Drop);
        bad.source = Some("not an address".into());
        s.save_firewall_rule(&bad).await.unwrap();
        assert!(FirewallApplier.render_script(&s, false).await.is_err());
    }

    /// The lockdown ruleset must not depend on the stored rules: a damaged
    /// row used to fail the lockdown render too, leaving a booted box with
    /// no ruleset and forwarding on.
    #[tokio::test]
    async fn lockdown_renders_even_when_stored_rules_are_unreadable() {
        let s = seeded(&["eth0"], &["eth1"]).await;
        sqlx::query("UPDATE firewall_rules SET dport = 'garbage'")
            .execute(s.pool().unwrap())
            .await
            .unwrap();
        assert!(FirewallApplier.render_script(&s, false).await.is_err());
        assert!(FirewallApplier.render_script(&s, true).await.is_err());
        let l = FirewallApplier.render_lockdown(&s).await;
        assert!(
            l.starts_with("add table inet patronus\ndelete table inet patronus\n"),
            "{l}"
        );
        assert!(
            l.contains(
                "chain inet patronus forward { type filter hook forward priority 0; policy drop; }"
            ),
            "{l}"
        );
        assert!(
            l.contains("add rule inet patronus input iifname \"eth1\" tcp dport {22,8443} accept"),
            "{l}"
        );
        assert!(!l.contains("eth0\" tcp dport"), "never on WAN: {l}");
        assert!(
            !l.contains("masquerade") && !l.contains("forward iifname"),
            "{l}"
        );

        // roles unreadable too: anti-lockout on any interface, still nothing forwarded
        sqlx::query("DROP TABLE interfaces")
            .execute(s.pool().unwrap())
            .await
            .unwrap();
        let l = FirewallApplier.render_lockdown(&s).await;
        assert!(
            l.contains("add rule inet patronus input tcp dport {22,8443} accept"),
            "{l}"
        );
        assert!(
            !l.contains("forward iifname") && !l.contains("masquerade"),
            "{l}"
        );
    }

    #[test]
    fn disable_forwarding_writes_zero_to_both_families() {
        let d = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(d.path().join("net/ipv4")).unwrap();
        std::fs::create_dir_all(d.path().join("net/ipv6/conf/all")).unwrap();
        std::fs::write(d.path().join("net/ipv4/ip_forward"), "1\n").unwrap();
        std::fs::write(d.path().join("net/ipv6/conf/all/forwarding"), "1\n").unwrap();
        let off = disable_forwarding(d.path());
        assert_eq!(
            off,
            vec!["net.ipv4.ip_forward", "net.ipv6.conf.all.forwarding"]
        );
        for f in ["net/ipv4/ip_forward", "net/ipv6/conf/all/forwarding"] {
            assert_eq!(std::fs::read_to_string(d.path().join(f)).unwrap(), "0\n");
        }
        assert!(disable_forwarding(&d.path().join("missing")).is_empty());
    }

    #[test]
    fn bridges_stay_layer2_turns_br_netfilter_hooks_off_only_when_present() {
        let d = tempfile::tempdir().unwrap();
        // module absent: nothing to do, nothing created
        assert!(bridges_stay_layer2(d.path()).is_empty());
        assert!(!d.path().join("net/bridge").exists());
        std::fs::create_dir_all(d.path().join("net/bridge")).unwrap();
        for k in BRIDGE_NF_KEYS {
            std::fs::write(d.path().join(k), "1\n").unwrap();
        }
        // already-0 keys are left alone and not reported
        std::fs::write(d.path().join(BRIDGE_NF_KEYS[2]), "0\n").unwrap();
        assert_eq!(
            bridges_stay_layer2(d.path()),
            vec![
                "net.bridge.bridge-nf-call-iptables",
                "net.bridge.bridge-nf-call-ip6tables"
            ]
        );
        for k in BRIDGE_NF_KEYS {
            assert_eq!(
                std::fs::read_to_string(d.path().join(k)).unwrap().trim(),
                "0"
            );
        }
        assert!(bridges_stay_layer2(d.path()).is_empty());
    }

    #[tokio::test]
    async fn interfaces_behind_an_ipv4_gateway_get_outbound_nat_too() {
        // multi-WAN: a second uplink on OPT1 carrying a gateway (lane E)
        let s = seeded(&["eth0"], &["eth1"]).await;
        s.set_interface_role("eth5", Some("opt1")).await.unwrap();
        for (name, iface, fam) in [
            ("WAN2", "@opt1", "inet"),
            ("DIRECT", "eth6", "inet"),
            ("WAN1", "@wan", "inet"),
            ("V6ONLY", "eth7", "inet6"),
            ("NOPE", "@opt9", "inet"),
        ] {
            sqlx::query(
                "INSERT INTO route_gateways (name, interface, family, updated_at) VALUES (?, ?, ?, 0)",
            )
            .bind(name)
            .bind(iface)
            .bind(fam)
            .execute(s.pool().unwrap())
            .await
            .unwrap();
        }
        assert_eq!(
            auto_nat_devices(&s).await.unwrap(),
            vec!["eth0", "eth5", "eth6"],
            "WAN first, then gateway interfaces, no duplicates"
        );
        let out = FirewallApplier.render(&s).await.unwrap();
        for dev in ["eth0", "eth5", "eth6"] {
            assert_eq!(
                out.matches(&format!("oifname \"{dev}\" masquerade"))
                    .count(),
                1,
                "{dev}: {out}"
            );
        }
        assert!(
            !out.contains("oifname \"eth7\" masquerade"),
            "IPv6 is routed: {out}"
        );
        assert!(!out.contains("oifname \"eth1\" masquerade"), "{out}");
        // manual mode: none of the automatic ones
        set_outbound_nat_mode(&s, OutboundNatMode::Manual)
            .await
            .unwrap();
        let out = FirewallApplier.render(&s).await.unwrap();
        assert!(!out.contains("masquerade"), "{out}");
    }

    #[tokio::test]
    async fn rules_with_a_gateway_mark_their_traffic_for_policy_routing() {
        let s = seeded(&["eth0"], &["eth1"]).await;
        sqlx::query(
            "INSERT INTO route_gateways (name, interface, family, updated_at) VALUES ('WAN2', 'eth5', 'inet', 0)",
        )
        .execute(s.pool().unwrap())
        .await
        .unwrap();
        let mut r = FirewallRule::new("pbr".into(), ChainType::Forward, FirewallAction::Accept);
        r.interface_in = Some("@lan".into());
        r.protocol = Some(Protocol::Tcp);
        r.dport = Some(PortSpec::Single(8080));
        r.gateway = Some("WAN2".into());
        s.save_firewall_rule(&r).await.unwrap();
        let mut ghost = r.clone();
        ghost.name = "ghost".into();
        ghost.gateway = Some("NOPE".into());
        s.save_firewall_rule(&ghost).await.unwrap();
        let mut drop = r.clone();
        drop.name = "dropper".into();
        drop.action = FirewallAction::Drop;
        s.save_firewall_rule(&drop).await.unwrap();
        let out = FirewallApplier.render_script(&s, false).await.unwrap();
        let script = out.script;
        assert!(
            script.contains("add chain inet patronus pbr { type filter hook prerouting priority mangle; policy accept; }"),
            "{script}"
        );
        assert_eq!(
            script.matches("meta mark set").count(),
            1,
            "only the accept rule naming an existing gateway marks: {script}"
        );
        assert!(
            script.contains(
                "add rule inet patronus pbr iifname \"eth1\" tcp dport 8080 meta mark set 0x10001 comment \"policy route WAN2\""
            ),
            "{script}"
        );
        // the filter rule itself still passes the traffic
        assert!(
            script
                .contains("add rule inet patronus forward iifname \"eth1\" tcp dport 8080 accept"),
            "{script}"
        );
        let w = out.report.warnings.join("\n");
        assert!(w.contains("gateway \"NOPE\" does not exist"), "{w}");
        assert!(
            w.contains("dropper") && w.contains("no policy routing"),
            "{w}"
        );
        // no policy rules, no policy chain; lockdown never marks
        let lock = FirewallApplier
            .render_script(&s, true)
            .await
            .unwrap()
            .script;
        assert!(
            !lock.contains("chain inet patronus pbr") && !lock.contains("meta mark"),
            "{lock}"
        );
        let plain = seeded(&["eth0"], &["eth1"]).await;
        let p = FirewallApplier
            .render_script(&plain, false)
            .await
            .unwrap()
            .script;
        assert!(!p.contains("chain inet patronus pbr"), "{p}");
    }

    #[tokio::test]
    async fn report_counts_rendered_rules_and_render_shows_warnings() {
        let s = seeded(&["eth0"], &["eth1", "eth2"]).await;
        let r = FirewallApplier.render_script(&s, false).await.unwrap();
        // anti-lockout x2 LANs, LAN->fw x2, LAN->any x2; masquerade x1
        assert_eq!(
            r.report.applied,
            vec![
                "outbound NAT mode hybrid",
                "6 filter rule(s), 1 NAT rule(s), 0 alias(es)"
            ]
        );
        let s1 = seeded(&["eth0"], &[]).await;
        let out = FirewallApplier.render(&s1).await.unwrap();
        assert!(out.starts_with("add table inet patronus\n"), "{out}");
        assert!(out.contains("oifname \"eth0\" masquerade"), "{out}");
        assert_eq!(
            out.matches("# warning: ").count(),
            2,
            "unassigned LAN rules are listed as warnings: {out}"
        );
        assert_eq!(FirewallApplier.name(), "firewall");
        assert_eq!(FirewallApplier.phase(), Phase::Firewall);
        assert_eq!(
            FirewallApplier.resource_kinds(),
            &[ResourceKind::FirewallRule, ResourceKind::NatRule]
        );
    }

    #[test]
    fn declarative_gateway_steers_only_inbound_forwarded_traffic() {
        let parse = |y: &str| {
            patronus_config::ConfigParser::parse_yaml(y)
                .expect("yaml")
                .remove(0)
        };
        let doc = |action: &str, direction: &str| {
            format!(
                r#"
- apiVersion: patronus.firewall/v1
  kind: FirewallRule
  metadata: {{ name: pbr }}
  spec:
    action: {action}
    interface: "@lan"
    direction: {direction}
    source: {{}}
    destination: {{ ports: [8080] }}
    protocol: tcp
    gateway: WAN2
    enabled: true
"#
            )
        };
        let (rules, _, _) = declarative_to_rules(&parse(&doc("allow", "both"))).unwrap();
        let steered: Vec<_> = rules.iter().filter(|r| r.gateway.is_some()).collect();
        assert_eq!(steered.len(), 1, "{rules:?}");
        assert_eq!(steered[0].chain, ChainType::Forward);
        assert_eq!(steered[0].interface_in.as_deref(), Some("@lan"));
        assert_eq!(steered[0].gateway.as_deref(), Some("WAN2"));
        // the rest (input, outbound placements) carry no gateway
        assert_eq!(rules.len(), 4);
        let e = declarative_to_rules(&parse(&doc("deny", "inbound")))
            .unwrap_err()
            .to_string();
        assert!(e.contains("needs action allow"), "{e}");
    }

    #[test]
    fn declarative_ports_and_nat_translate_one_rule_per_alternative() {
        let parse = |y: &str| {
            patronus_config::ConfigParser::parse_yaml(y)
                .expect("yaml")
                .remove(0)
        };
        let fw = parse(
            r#"
- apiVersion: patronus.firewall/v1
  kind: FirewallRule
  metadata: { name: ports }
  spec:
    action: deny
    interface: "@lan"
    direction: inbound
    source: {}
    destination: { ports: [22], port_ranges: [ { start: 6000, end: 6010 } ] }
    protocol: tcp
    enabled: true
"#,
        );
        let (rules, nats, _) = declarative_to_rules(&fw).unwrap();
        assert!(nats.is_empty());
        // input + forward, each: single port 22 and the range
        assert_eq!(rules.len(), 4, "{rules:?}");
        assert!(rules
            .iter()
            .any(|r| r.dport == Some(PortSpec::Single(22)) && r.chain == ChainType::Input));
        assert!(
            rules
                .iter()
                .any(|r| r.dport == Some(PortSpec::Range(6000, 6010))
                    && r.chain == ChainType::Forward)
        );
        assert!(rules.iter().all(|r| r.action == FirewallAction::Drop));

        let any = parse(
            r#"
- apiVersion: patronus.firewall/v1
  kind: FirewallRule
  metadata: { name: any }
  spec:
    action: allow
    interface: "@lan"
    direction: outbound
    source: {}
    destination: { ports: [] }
    enabled: true
"#,
        );
        let (rules, _, _) = declarative_to_rules(&any).unwrap();
        assert_eq!(rules.len(), 2);
        assert!(rules
            .iter()
            .all(|r| r.dport.is_none() && r.interface_out.is_some()));

        let pf = parse(
            r#"
- apiVersion: patronus.firewall/v1
  kind: NatRule
  metadata: { name: pf }
  spec:
    nat_type: dnat
    interface: "@wan"
    source: {}
    destination: { ports: [8080] }
    translation: { address: "192.168.1.10", ports: [80] }
    enabled: true
"#,
        );
        let (rules, nats, _) = declarative_to_rules(&pf).unwrap();
        assert!(rules.is_empty());
        assert_eq!(nats.len(), 2, "tcp + udp: {nats:?}");
        assert!(nats.iter().all(|n| n.dport == Some(PortSpec::Single(8080))
            && n.nat_type
                == NatType::Dnat {
                    to_address: "192.168.1.10".parse().unwrap(),
                    to_port: Some(80)
                }));
    }

    #[tokio::test]
    async fn gitops_resources_become_store_rows_and_replace_by_name() {
        let yaml = r#"
- apiVersion: patronus.firewall/v1
  kind: FirewallRule
  metadata:
    name: allow-web
  spec:
    action: allow
    interface: "@wan"
    source: { address: "0.0.0.0/0" }
    destination: { address: "192.168.1.10", ports: [80, 443] }
    protocol: tcp
    enabled: true
"#;
        let cfg = patronus_config::ConfigParser::parse_yaml(yaml)
            .expect("yaml")
            .remove(0);
        let s = seeded(&["eth0"], &["eth1"]).await;
        FirewallApplier.upsert_resource(&s, &cfg).await.unwrap();
        FirewallApplier.upsert_resource(&s, &cfg).await.unwrap();
        let rows: Vec<_> = s
            .load_firewall_rules_with_origin()
            .await
            .unwrap()
            .into_iter()
            .filter(|(_, o)| *o == RuleOrigin::Gitops)
            .collect();
        assert_eq!(rows.len(), 2, "input + forward, replaced not duplicated");
        let r = FirewallApplier.render_script(&s, false).await.unwrap();
        assert!(r.script.contains("forward iifname \"eth0\" ip saddr 0.0.0.0/0 ip daddr 192.168.1.10 tcp dport {80,443} accept"), "{}", r.script);
        FirewallApplier
            .delete_resource(&s, &ResourceKind::FirewallRule, "allow-web")
            .await
            .unwrap();
        assert!(s
            .load_firewall_rules_with_origin()
            .await
            .unwrap()
            .iter()
            .all(|(_, o)| *o != RuleOrigin::Gitops));
    }

    fn at(s: &str) -> chrono::NaiveDateTime {
        chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M").unwrap()
    }

    #[tokio::test]
    async fn ipv6_addresses_use_ip6_and_mixed_families_are_refused() {
        let s = seeded(&["eth0"], &["eth1"]).await;
        let mut r = FirewallRule::new("v6".into(), ChainType::Forward, FirewallAction::Reject);
        r.interface_in = Some("@lan".into());
        r.destination = Some("2001:db8:113::1".into());
        r.protocol = Some(Protocol::Tcp);
        r.dport = Some(PortSpec::Single(8080));
        r.log = true;
        let id = s.save_firewall_rule(&r).await.unwrap();
        let sc = FirewallApplier
            .render_script(&s, false)
            .await
            .unwrap()
            .script;
        assert!(
            sc.contains(&format!(
                "forward iifname \"eth1\" ip6 daddr 2001:db8:113::1 tcp dport 8080 log prefix \"patronus[{id}] reject: \" reject with tcp reset"
            )),
            "{sc}"
        );
        let mut v6only = FirewallRule::new("v6only".into(), ChainType::Input, FirewallAction::Drop);
        v6only.ip_version = Some(patronus_core::types::IpVersion::V6);
        v6only.protocol = Some(Protocol::Icmp);
        s.save_firewall_rule(&v6only).await.unwrap();
        let sc = FirewallApplier
            .render_script(&s, false)
            .await
            .unwrap()
            .script;
        assert!(
            sc.contains("input meta nfproto ipv6 meta l4proto ipv6-icmp drop"),
            "{sc}"
        );
        let mut mixed = FirewallRule::new("mixed".into(), ChainType::Forward, FirewallAction::Drop);
        mixed.source = Some("10.0.0.0/8".into());
        mixed.destination = Some("2001:db8::/32".into());
        assert!(crate::nftables::render_filter_rule(&mixed, &Default::default()).is_err());
    }

    #[tokio::test]
    async fn aliases_render_as_sets_for_both_families_and_ports() {
        let s = seeded(&["eth0"], &["eth1"]).await;
        crate::aliases::save_alias(
            &s,
            &crate::aliases::Alias {
                name: "bad".into(),
                kind: crate::nftables::AliasKind::Host,
                entries: vec!["198.51.100.0/24".into(), "2001:db8:bad::/48".into()],
                description: None,
            },
        )
        .await
        .unwrap();
        crate::aliases::save_alias(
            &s,
            &crate::aliases::Alias {
                name: "web".into(),
                kind: crate::nftables::AliasKind::Port,
                entries: vec!["80".into(), "443".into()],
                description: None,
            },
        )
        .await
        .unwrap();
        let mut r = FirewallRule::new("blk".into(), ChainType::Forward, FirewallAction::Drop);
        r.source = Some("$bad".into());
        r.protocol = Some(Protocol::Tcp);
        r.dport = Some(PortSpec::Alias("web".into()));
        s.save_firewall_rule(&r).await.unwrap();
        let sc = FirewallApplier
            .render_script(&s, false)
            .await
            .unwrap()
            .script;
        for want in [
            "add set inet patronus alias_bad_v4 { type ipv4_addr; flags interval;",
            "add element inet patronus alias_bad_v6 { 2001:db8:bad::/48 }",
            "add element inet patronus alias_web_ports { 80, 443 }",
            "forward ip saddr @alias_bad_v4 tcp dport @alias_web_ports drop",
            "forward ip6 saddr @alias_bad_v6 tcp dport @alias_web_ports drop",
        ] {
            assert!(sc.contains(want), "missing {want:?}:\n{sc}");
        }
    }

    #[tokio::test]
    async fn scheduled_rules_follow_the_clock() {
        let s = seeded(&["eth0"], &["eth1"]).await;
        crate::schedule::save_schedule(
            &s,
            &crate::schedule::Schedule {
                name: "school".into(),
                days: vec!["mon".into(), "tue".into()],
                start: "08:00".into(),
                end: "15:00".into(),
                description: None,
            },
        )
        .await
        .unwrap();
        let mut r = FirewallRule::new("games".into(), ChainType::Forward, FirewallAction::Drop);
        r.destination = Some("192.0.2.66".into());
        r.schedule = Some("school".into());
        s.save_firewall_rule(&r).await.unwrap();
        let mut ghost =
            FirewallRule::new("ghost".into(), ChainType::Forward, FirewallAction::Accept);
        ghost.schedule = Some("nope".into());
        s.save_firewall_rule(&ghost).await.unwrap();
        // Monday 10:00 = inside, Monday 16:00 / Wednesday 10:00 = outside
        let inside = FirewallApplier
            .render_script_at(&s, false, at("2026-10-12 10:00"))
            .await
            .unwrap();
        assert!(inside.script.contains("ip daddr 192.0.2.66 drop"));
        assert!(
            !inside.script.contains("comment \"ghost\""),
            "missing schedule: allow not granted"
        );
        for t in ["2026-10-12 16:00", "2026-10-14 10:00"] {
            let out = FirewallApplier
                .render_script_at(&s, false, at(t))
                .await
                .unwrap();
            assert!(!out.script.contains("192.0.2.66"), "{t}");
            assert!(out.report.applied.iter().any(|a| a.contains("inactive")));
        }
        let st = crate::schedule::scheduled_rule_states(&s, at("2026-10-12 10:00"))
            .await
            .unwrap();
        assert!(st.iter().any(|(_, a)| *a));
    }

    #[tokio::test]
    async fn port_forward_matches_the_inbound_interface_and_port_with_a_paired_accept() {
        let s = seeded(&["eth0"], &["eth1"]).await;
        let mut pf = NatRule::new(
            "ssh-in".into(),
            NatType::Dnat {
                to_address: "192.168.50.10".parse().unwrap(),
                to_port: Some(9000),
            },
        );
        pf.interface_in = Some("@wan".into());
        pf.protocol = Some(Protocol::Tcp);
        pf.dport = Some(PortSpec::Single(8022));
        pf.reflection = true;
        s.save_nat_rule(&pf).await.unwrap();
        let mut one = NatRule::new(
            "srv".into(),
            NatType::OneToOne {
                external: "203.0.113.5".parse().unwrap(),
                internal: "192.168.50.20".parse().unwrap(),
            },
        );
        one.interface_in = Some("@wan".into());
        one.interface_out = Some("@wan".into());
        s.save_nat_rule(&one).await.unwrap();
        let mut snat = NatRule::new(
            "manual".into(),
            NatType::Snat {
                to_address: "203.0.113.9".parse().unwrap(),
            },
        );
        snat.interface_out = Some("@wan".into());
        snat.source = Some("192.168.60.0/24".into());
        s.save_nat_rule(&snat).await.unwrap();
        let sc = FirewallApplier
            .render_script(&s, false)
            .await
            .unwrap()
            .script;
        for want in [
            "prerouting iifname \"eth0\" tcp dport 8022 dnat ip to 192.168.50.10:9000",
            "forward ct status dnat ip daddr 192.168.50.10 tcp dport 9000 accept",
            "prerouting iifname \"eth0\" ip daddr 203.0.113.5 dnat ip to 192.168.50.20",
            "postrouting oifname \"eth0\" ip saddr 192.168.50.20 snat ip to 203.0.113.5",
            "postrouting oifname \"eth0\" ip saddr 192.168.60.0/24 snat ip to 203.0.113.9",
        ] {
            assert!(sc.contains(want), "missing {want:?}:\n{sc}");
        }
        assert!(!sc.contains("prerouting oifname"), "{sc}");
        // order: manual SNAT and 1:1 before the automatic masquerade
        let p = |x: &str| sc.find(x).unwrap();
        assert!(p("snat ip to 203.0.113.9") < p("Automatic outbound NAT"));
        assert!(p("snat ip to 203.0.113.5") < p("Automatic outbound NAT"));
        // port-forward accepts come after the user's forward rules
        assert!(p("forward iifname \"eth1\" accept") < p("ct status dnat"));

        set_outbound_nat_mode(&s, OutboundNatMode::Manual)
            .await
            .unwrap();
        let sc = FirewallApplier
            .render_script(&s, false)
            .await
            .unwrap()
            .script;
        assert!(!sc.contains("Automatic outbound NAT") && sc.contains("snat ip to 203.0.113.9"));
        set_outbound_nat_mode(&s, OutboundNatMode::Automatic)
            .await
            .unwrap();
        let sc = FirewallApplier
            .render_script(&s, false)
            .await
            .unwrap()
            .script;
        assert!(sc.contains("Automatic outbound NAT") && !sc.contains("snat ip to 203.0.113.9"));
        assert!(
            sc.contains("dnat ip to 192.168.50.10:9000"),
            "forwards are not outbound"
        );
        set_outbound_nat_mode(&s, OutboundNatMode::Disabled)
            .await
            .unwrap();
        let sc = FirewallApplier
            .render_script(&s, false)
            .await
            .unwrap()
            .script;
        assert!(!sc.contains("Automatic outbound NAT") && !sc.contains("203.0.113.9"));
    }

    #[test]
    fn reflection_renders_hairpin_dnat_and_masquerade() {
        let mut pf = NatRule::new(
            "pf".into(),
            NatType::Dnat {
                to_address: "192.168.50.10".parse().unwrap(),
                to_port: Some(9000),
            },
        );
        pf.interface_in = Some("wan0".into());
        pf.protocol = Some(Protocol::Tcp);
        pf.dport = Some(PortSpec::Single(8022));
        pf.reflection = true;
        let ctx = crate::nftables::NatContext {
            inbound_addresses: vec![
                "203.0.113.2".parse().unwrap(),
                "2001:db8::2".parse().unwrap(),
            ],
        };
        let l = crate::nftables::render_nat_rule(&pf, &Default::default(), &ctx).unwrap();
        assert!(l.prerouting.iter().any(|x| x.contains(
            "iifname != \"wan0\" ip daddr { 203.0.113.2 } tcp dport 8022 dnat ip to 192.168.50.10:9000"
        )), "{l:?}");
        assert!(
            l.postrouting.iter().any(|x| {
                x.contains(
            "iifname != \"wan0\" ct status dnat ip daddr 192.168.50.10 tcp dport 9000 masquerade"
        )
            }),
            "{l:?}"
        );
        assert!(
            l.forward[0].starts_with("add rule inet patronus forward ct status dnat"),
            "{l:?}"
        );
        pf.dport = Some(PortSpec::Range(8000, 8010));
        assert!(crate::nftables::render_nat_rule(&pf, &Default::default(), &ctx).is_err());
        let mut v6 = NatRule::new(
            "v6".into(),
            NatType::Dnat {
                to_address: "2001:db8::10".parse().unwrap(),
                to_port: Some(80),
            },
        );
        v6.protocol = Some(Protocol::Tcp);
        v6.dport = Some(PortSpec::Single(8080));
        let l = crate::nftables::render_nat_rule(&v6, &Default::default(), &Default::default())
            .unwrap();
        assert!(
            l.prerouting[0].contains("dnat ip6 to [2001:db8::10]:80"),
            "{l:?}"
        );
    }

    #[test]
    fn gitops_schedule_becomes_a_named_schedule() {
        let yaml = r#"
- apiVersion: patronus.firewall/v1
  kind: FirewallRule
  metadata:
    name: kids-night
  spec:
    action: deny
    interface: "@lan"
    source: { address: "192.168.1.50" }
    destination: {}
    log: true
    schedule: { days: [mon, tue], time_range: { start: "22:00", end: "06:00" } }
    enabled: true
"#;
        let cfg = patronus_config::ConfigParser::parse_yaml(yaml)
            .expect("yaml")
            .remove(0);
        let (rules, _, sched) = declarative_to_rules(&cfg).unwrap();
        let sched = sched.unwrap();
        assert_eq!(sched.name, "gitops_kids_night");
        assert_eq!(sched.start, "22:00");
        assert!(rules
            .iter()
            .all(|r| r.log && r.schedule.as_deref() == Some("gitops_kids_night")));
    }

    #[test]
    fn interface_addresses_lists_only_that_interfaces_addresses() {
        let lo = interface_addresses("lo");
        assert!(lo.contains(&"127.0.0.1".parse().unwrap()), "{lo:?}");
        assert!(lo.iter().all(|a| a.is_loopback()), "{lo:?}");
        let has_v6_lo = std::fs::read_to_string("/proc/net/if_inet6")
            .map(|t| {
                t.lines()
                    .any(|l| l.ends_with(" lo") && l.starts_with("0000"))
            })
            .unwrap_or(false);
        if has_v6_lo {
            assert!(lo.contains(&"::1".parse().unwrap()), "{lo:?}");
        }
        assert!(interface_addresses("no-such-if0").is_empty());
    }

    #[tokio::test]
    async fn rule_with_a_missing_schedule_blocks_always_but_never_allows() {
        let s = seeded(&["eth0"], &["eth1"]).await;
        let mut allow = FirewallRule::new(
            "ghost-allow".into(),
            ChainType::Forward,
            FirewallAction::Accept,
        );
        allow.destination = Some("198.51.100.7".into());
        allow.schedule = Some("nope".into());
        s.save_firewall_rule(&allow).await.unwrap();
        let mut block = FirewallRule::new(
            "ghost-block".into(),
            ChainType::Forward,
            FirewallAction::Drop,
        );
        block.destination = Some("198.51.100.8".into());
        block.schedule = Some("nope".into());
        s.save_firewall_rule(&block).await.unwrap();
        let r = FirewallApplier.render_script(&s, false).await.unwrap();
        assert!(!r.script.contains("198.51.100.7"), "{}", r.script);
        assert!(r.script.contains("ip daddr 198.51.100.8"), "{}", r.script);
        assert!(r
            .report
            .warnings
            .iter()
            .any(|w| w.contains("ghost-allow") && w.contains("skipped")));
        assert!(r
            .report
            .warnings
            .iter()
            .any(|w| w.contains("ghost-block") && w.contains("enforcing it always")));
    }

    #[tokio::test]
    async fn nat_rules_are_counted_and_reflection_without_an_address_warns() {
        // "wan9" does not exist: no address for reflection
        let s = seeded(&["wan9"], &["lan9"]).await;
        let base = FirewallApplier.render_script(&s, false).await.unwrap();
        let mut pf = NatRule::new(
            "plain-forward".into(),
            NatType::Dnat {
                to_address: "192.168.50.10".parse().unwrap(),
                to_port: None,
            },
        );
        pf.interface_in = Some("@wan".into());
        pf.protocol = Some(Protocol::Tcp);
        pf.dport = Some(PortSpec::Single(8022));
        s.save_nat_rule(&pf).await.unwrap();
        let r = FirewallApplier.render_script(&s, false).await.unwrap();
        let count = |rep: &ApplyReport| {
            rep.applied
                .iter()
                .find_map(|l| {
                    l.split(", ")
                        .find(|p| p.ends_with("NAT rule(s)"))
                        .map(|p| p.split(' ').next().unwrap().parse::<u32>().unwrap())
                })
                .unwrap()
        };
        assert_eq!(count(&r.report), count(&base.report) + 1, "{:?}", r.report);
        assert!(
            !r.report.warnings.iter().any(|w| w.contains("reflection")),
            "no reflection asked: {:?}",
            r.report.warnings
        );
        let mut hairpin = pf.clone();
        hairpin.name = "hairpin".into();
        hairpin.dport = Some(PortSpec::Single(8023));
        hairpin.reflection = true;
        s.save_nat_rule(&hairpin).await.unwrap();
        let r = FirewallApplier.render_script(&s, false).await.unwrap();
        assert_eq!(count(&r.report), count(&base.report) + 2, "{:?}", r.report);
        assert!(
            r.report
                .warnings
                .iter()
                .any(|w| w.contains("hairpin")
                    && w.contains("NAT reflection needs an address on wan9")),
            "{:?}",
            r.report.warnings
        );
    }

    #[test]
    fn only_fe80_slash_10_counts_as_link_local() {
        let ll = |s: &str| is_link_local_v6(&s.parse().unwrap());
        assert!(ll("fe80::1") && ll("febf::1"));
        assert!(!ll("fec0::1") && !ll("fe00::1") && !ll("2001:db8::1") && !ll("::1"));
    }

    #[tokio::test]
    async fn vpn_rules_are_counted_and_ipsec_exemption_precedes_masquerade() {
        let s = seeded(&["eth0"], &["eth1"]).await;
        let counts = |rep: &ApplyReport| {
            let line = rep
                .applied
                .iter()
                .find(|l| l.contains("filter rule(s)"))
                .unwrap_or_else(|| panic!("no count line: {rep:?}"));
            let n = |suffix: &str| {
                line.split(", ")
                    .find(|p| p.ends_with(suffix))
                    .map(|p| p.split(' ').next().unwrap().parse::<usize>().unwrap())
                    .unwrap()
            };
            (n("filter rule(s)"), n("NAT rule(s)"))
        };
        let base = FirewallApplier.render_script(&s, false).await.unwrap();
        let (f0, n0) = counts(&base.report);
        let pool = s.pool().unwrap();
        sqlx::query(
            "INSERT INTO wg_interfaces (name, private_key, listen_port, updated_at)
             VALUES ('wg0','k',51820,0)",
        )
        .execute(pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO ipsec_tunnels (name, remote_address, psk, local_ts, remote_ts, updated_at)
             VALUES ('siteb','198.51.100.2','x','192.168.50.0/24, fd00:50::/64','10.2.0.0/16,fd00:2::/64',0)",
        )
        .execute(pool)
        .await
        .unwrap();
        let r = FirewallApplier.render_script(&s, false).await.unwrap();
        // filter: WireGuard port, IKE, ESP, then input+forward per family
        // pair (v4, v6) = 3 + 4; NAT: one exemption per family pair = 2
        assert_eq!(counts(&r.report), (f0 + 7, n0 + 2), "{:?}", r.report);
        let sc = &r.script;
        let exempt = sc
            .find("postrouting ip saddr 192.168.50.0/24 ip daddr 10.2.0.0/16 accept")
            .unwrap_or_else(|| panic!("no IPsec NAT exemption: {sc}"));
        let masq = sc
            .find("oifname \"eth0\" masquerade")
            .unwrap_or_else(|| panic!("no masquerade: {sc}"));
        assert!(
            exempt < masq,
            "site-to-site traffic must skip NAT before the masquerade: {sc}"
        );
        // lockdown renders no VPN rules at all
        let l = FirewallApplier.render_script(&s, true).await.unwrap();
        assert!(!l.script.contains("51820"), "{}", l.script);
        assert!(!l.script.contains("IPsec"), "{}", l.script);
    }
}
