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
    self, base_table_script, render_filter_rule, render_nat_rule, rule_to_nft_command, NatContext,
    TABLE,
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
            // link-local addresses are not what a LAN client dials
            if (ip.segments()[0] & 0xffc0) != 0xfe80 {
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

        if !lockdown {
            let mode = outbound_nat_mode(store).await?;
            let mut forward_tail = String::new();
            let mut pre = String::new();
            let mut post = String::new();
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
                for wan in roles.get("wan").into_iter().flatten() {
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
                    tracing::info!("firewall applied: {}", r.report.applied.join("; "));
                    return Ok(r.report);
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
            if s.gateway.is_some() {
                return Err(Error::Config(format!(
                    "{name}: policy routing (gateway) is not supported by the firewall applier yet"
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
}
