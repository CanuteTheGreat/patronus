//! Firewall/NAT state: a thin adapter over the config store + the firewall
//! applier (lane B: rule editor with ordering, aliases, schedules, port
//! forwards, outbound / 1:1 NAT, reflection).
//!
//! Every mutation is: validate -> snapshot (config history) -> write the
//! store -> run the applier -> on applier failure undo the store write. The
//! store is the only copy of the rules, so rules survive restarts and
//! reboots and the boot unit (`patronus apply`) loads exactly what the UI
//! shows. Alias edits are the exception to "run the applier": they only
//! swap the elements of the alias's nftables sets (no ruleset reload).

use patronus_config::{Applier, ConfigStore, RuleOrigin};
use patronus_core::types::{
    ChainType, FirewallAction, FirewallRule as CoreFirewallRule, IpVersion, NatRule as CoreNatRule,
    NatType, PortSpec, Protocol,
};
use patronus_firewall::aliases::{self, Alias};
use patronus_firewall::applier::{outbound_nat_mode, set_outbound_nat_mode, OutboundNatMode};
use patronus_firewall::nftables::NatContext;
use patronus_firewall::schedule::{self, Schedule};
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::routes::api::firewall::{
    AliasBody, FirewallRule as ApiFirewallRule, NatRule as ApiNatRule, ScheduleBody,
};
use crate::templates;

fn parse_addr_port(s: &str) -> anyhow::Result<(std::net::IpAddr, Option<u16>)> {
    let bad = || anyhow::anyhow!("Invalid NAT target {s:?} (address or address:port)");
    if let Ok(a) = s.parse::<std::net::IpAddr>() {
        return Ok((a, None));
    }
    if let Some(rest) = s.strip_prefix('[') {
        let (a, p) = rest.split_once("]:").ok_or_else(bad)?;
        let port = p.parse::<u16>().ok().filter(|p| *p != 0).ok_or_else(bad)?;
        return Ok((a.parse().map_err(|_| bad())?, Some(port)));
    }
    let (a, p) = s.rsplit_once(':').ok_or_else(bad)?;
    let port = p.parse::<u16>().ok().filter(|p| *p != 0).ok_or_else(bad)?;
    Ok((
        a.parse::<std::net::Ipv4Addr>().map_err(|_| bad())?.into(),
        Some(port),
    ))
}

/// Interpret the `rule_type`/`target` fields of an incoming `NatRule` API
/// payload into a typed `NatType`. `target` holds the literal
/// "masquerade", an `address[:port]` (`[v6]:port`), or the internal
/// address of a 1:1 NAT. This never splices the raw string into an
/// nftables script itself (the injection-safety checks live in
/// `patronus_firewall::nftables`, which still runs on the typed rule).
pub(crate) fn parse_nat_type(
    rule_type: &str,
    target: &str,
    external: Option<&str>,
) -> anyhow::Result<NatType> {
    let t = target.trim();
    let kind = rule_type
        .trim()
        .to_ascii_uppercase()
        .replace(['-', ' '], "_");
    if t.eq_ignore_ascii_case("masquerade") || kind == "MASQUERADE" || kind == "NAT" {
        return Ok(NatType::Masquerade);
    }
    if matches!(kind.as_str(), "NPT" | "NPTV6" | "NPT_V6") {
        let ext = external
            .map(str::trim)
            .filter(|e| !e.is_empty())
            .ok_or_else(|| {
                anyhow::anyhow!("Invalid NPTv6 rule: the external prefix is required")
            })?;
        patronus_firewall::nftables::npt_prefix(ext).map_err(|e| anyhow::anyhow!("{e}"))?;
        patronus_firewall::nftables::npt_prefix(t).map_err(|e| anyhow::anyhow!("{e}"))?;
        return Ok(NatType::Npt {
            external: ext.to_string(),
            internal: t.to_string(),
        });
    }
    let (to_address, to_port) = parse_addr_port(t)?;
    match kind.as_str() {
        "DNAT" | "PORT_FORWARD" | "PORTFORWARD" | "RDR" => Ok(NatType::Dnat {
            to_address,
            to_port,
        }),
        "1:1" | "ONE_TO_ONE" | "ONETOONE" | "BINAT" => {
            if to_port.is_some() {
                anyhow::bail!("Invalid 1:1 NAT: the internal address takes no port");
            }
            let ext = external
                .map(str::trim)
                .filter(|e| !e.is_empty())
                .ok_or_else(|| anyhow::anyhow!("Invalid 1:1 NAT: external_address is required"))?;
            Ok(NatType::OneToOne {
                external: ext
                    .parse()
                    .map_err(|_| anyhow::anyhow!("Invalid 1:1 external address {ext:?}"))?,
                internal: to_address,
            })
        }
        "SNAT" => {
            if to_port.is_some() {
                anyhow::bail!("Invalid SNAT target {target:?}: no port");
            }
            Ok(NatType::Snat { to_address })
        }
        other => {
            anyhow::bail!("Invalid NAT type {other:?} (MASQUERADE, SNAT, DNAT/port forward or 1:1)")
        }
    }
}

fn any_or(s: &str) -> Option<String> {
    let t = s.trim();
    if t.is_empty() || t.eq_ignore_ascii_case("any") || t.eq_ignore_ascii_case("all") {
        None
    } else {
        Some(t.to_string())
    }
}

/// Validate an interface field: "any", a role token (`@wan`, `@lan`,
/// `@optN`, `@mgmt`) or a device name (checked again by the nft layer).
fn interface_field(s: &str) -> anyhow::Result<Option<String>> {
    let Some(v) = any_or(s) else { return Ok(None) };
    if let Some(role) = v.strip_prefix('@') {
        let role = role.to_ascii_lowercase();
        if role != "mgmt" && !patronus_config::store::is_valid_role(&role) {
            anyhow::bail!("Invalid interface role {v:?} (@wan, @lan, @optN)");
        }
        return Ok(Some(format!("@{role}")));
    }
    if !patronus_firewall::nftables::is_valid_interface_name(&v) {
        anyhow::bail!("Invalid interface name {v:?}");
    }
    Ok(Some(v))
}

fn display_iface(v: Option<&str>) -> String {
    match v {
        None => "any".into(),
        Some(r) if r.starts_with('@') => r[1..].to_uppercase(),
        Some(d) => d.to_string(),
    }
}

fn parse_protocol(s: &str) -> anyhow::Result<Option<Protocol>> {
    Ok(match s.trim().to_ascii_lowercase().as_str() {
        "tcp" => Some(Protocol::Tcp),
        "udp" => Some(Protocol::Udp),
        "icmp" | "icmpv6" | "ipv6-icmp" => Some(Protocol::Icmp),
        "any" | "all" | "" => None,
        other => anyhow::bail!("Invalid protocol {other:?} (tcp, udp, icmp or any)"),
    })
}

/// "80", "8000-8010", "22,443", "$alias", "any" -> PortSpec.
fn parse_ports(port: &str) -> anyhow::Result<Option<PortSpec>> {
    let port = port.trim();
    if port.is_empty() || port.eq_ignore_ascii_case("any") {
        return Ok(None);
    }
    if let Some(a) = port.strip_prefix('$') {
        if !patronus_firewall::nftables::is_valid_alias_name(a) {
            anyhow::bail!("Invalid port alias {port:?}");
        }
        return Ok(Some(PortSpec::Alias(a.to_string())));
    }
    let parse = |p: &str| {
        p.trim()
            .parse::<u16>()
            .ok()
            .filter(|n| *n != 0)
            .ok_or_else(|| anyhow::anyhow!("Invalid port {port:?}"))
    };
    Ok(Some(if let Some((lo, hi)) = port.split_once('-') {
        let (lo, hi) = (parse(lo)?, parse(hi)?);
        if lo > hi {
            anyhow::bail!("Invalid port range {port:?}");
        }
        PortSpec::Range(lo, hi)
    } else if port.contains(',') {
        PortSpec::Multiple(port.split(',').map(parse).collect::<anyhow::Result<_>>()?)
    } else {
        PortSpec::Single(parse(port)?)
    }))
}

fn port_display(p: Option<&PortSpec>) -> String {
    p.map(|p| {
        p.to_string()
            .trim_matches(|c| c == '{' || c == '}')
            .to_string()
    })
    .unwrap_or_else(|| "any".into())
}

fn parse_ip_version(s: Option<&str>) -> anyhow::Result<Option<IpVersion>> {
    Ok(match s.map(|s| s.trim().to_ascii_lowercase()).as_deref() {
        None | Some("") | Some("any") | Some("both") => None,
        Some("ipv4") | Some("inet4") | Some("4") | Some("v4") => Some(IpVersion::V4),
        Some("ipv6") | Some("inet6") | Some("6") | Some("v6") => Some(IpVersion::V6),
        Some(o) => anyhow::bail!("Invalid ip_version {o:?} (ipv4, ipv6 or any)"),
    })
}

/// Where to move a rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Move {
    Up,
    Down,
    Top,
    Bottom,
}

impl Move {
    pub fn parse(s: &str) -> anyhow::Result<Self> {
        Ok(match s.trim().to_ascii_lowercase().as_str() {
            "up" => Move::Up,
            "down" => Move::Down,
            "top" => Move::Top,
            "bottom" => Move::Bottom,
            o => anyhow::bail!("Invalid direction {o:?} (up, down, top, bottom)"),
        })
    }
}

/// Firewall management operations
pub struct FirewallManager {
    pub(crate) store: Arc<ConfigStore>,
    pub(crate) applier: Arc<dyn Applier>,
    /// Serializes edit+apply so two requests can't interleave.
    pub(crate) edit: Mutex<()>,
    /// Scheduled-rule states the kernel was last loaded with.
    sched_state: Mutex<Option<Vec<(u64, bool)>>>,
    /// Where URL tables / GeoIP / threat feeds download from (curl).
    pub(crate) fetcher: std::sync::RwLock<Arc<dyn patronus_firewall::feeds::Fetcher>>,
}

impl FirewallManager {
    pub fn new(store: Arc<ConfigStore>, applier: Arc<dyn Applier>) -> Self {
        Self {
            store,
            applier,
            edit: Mutex::new(()),
            sched_state: Mutex::new(None),
            fetcher: std::sync::RwLock::new(Arc::new(patronus_firewall::feeds::CurlFetcher)),
        }
    }

    pub(crate) fn e(e: patronus_core::Error) -> anyhow::Error {
        anyhow::anyhow!("{e}")
    }

    async fn alias_map(&self) -> anyhow::Result<patronus_firewall::nftables::AliasMap> {
        Ok(aliases::alias_map(
            &aliases::load_aliases(&self.store).await.map_err(Self::e)?,
        ))
    }

    /// Strictly translate an API rule into the typed rule nftables gets.
    /// Unknown values are rejected ("Invalid ..." -> 400) instead of being
    /// silently widened or flipped.
    pub(crate) fn rule_to_core(
        id: Option<u64>,
        rule: &ApiFirewallRule,
    ) -> anyhow::Result<CoreFirewallRule> {
        let protocol = parse_protocol(&rule.protocol)?;
        let dport = parse_ports(&rule.port)?;
        if dport.is_some() && !matches!(protocol, Some(Protocol::Tcp | Protocol::Udp)) {
            anyhow::bail!("Invalid rule: a port needs protocol tcp or udp");
        }
        let action = match rule.action.trim().to_ascii_lowercase().as_str() {
            "accept" | "allow" | "pass" => FirewallAction::Accept,
            "drop" | "deny" | "block" => FirewallAction::Drop,
            "reject" => FirewallAction::Reject,
            other => anyhow::bail!("Invalid action {other:?} (accept, drop or reject)"),
        };
        let chain = match rule
            .chain
            .as_deref()
            .unwrap_or("input")
            .trim()
            .to_ascii_lowercase()
            .as_str()
        {
            "input" | "" => ChainType::Input,
            "forward" => ChainType::Forward,
            "output" => ChainType::Output,
            other => anyhow::bail!("Invalid chain {other:?} (input, forward or output)"),
        };
        let iface = interface_field(&rule.interface)?;
        let (interface_in, mut interface_out) = match chain {
            ChainType::Output => (None, iface),
            _ => (iface, None),
        };
        if chain == ChainType::Forward {
            if let Some(o) = rule.interface_out.as_deref() {
                interface_out = interface_field(o)?;
            }
        }
        let name = rule
            .name
            .clone()
            .filter(|n| !n.trim().is_empty())
            .unwrap_or_else(|| rule.description.clone());
        if name.trim().is_empty() {
            anyhow::bail!("Invalid rule: a name or description is required");
        }
        let schedule = rule
            .schedule
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty() && !s.eq_ignore_ascii_case("always"))
            .map(str::to_string);
        Ok(CoreFirewallRule {
            id,
            name,
            enabled: rule.enabled,
            chain,
            action,
            source: any_or(&rule.source),
            destination: any_or(&rule.destination),
            protocol,
            sport: None,
            dport,
            interface_in,
            interface_out,
            comment: Some(rule.description.clone()).filter(|d| !d.is_empty()),
            log: rule.log,
            schedule,
            ip_version: parse_ip_version(rule.ip_version.as_deref())?,
            gateway: rule
                .gateway
                .as_deref()
                .map(str::trim)
                .filter(|g| !g.is_empty())
                .map(str::to_string),
        })
    }

    /// Run the applier's own validation (injection-safe address, interface,
    /// family, alias and l4 checks) so a bad rule is a 400 before it is
    /// stored, and check the schedule exists.
    async fn check_rule(&self, core: &CoreFirewallRule) -> anyhow::Result<()> {
        let mut probe = core.clone();
        for f in [&mut probe.interface_in, &mut probe.interface_out] {
            if f.as_deref().is_some_and(|v| v.starts_with('@')) {
                *f = Some("probe0".into());
            }
        }
        probe.enabled = true;
        patronus_firewall::nftables::render_filter_rule(&probe, &self.alias_map().await?)
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        if let Some(g) = &core.gateway {
            if !patronus_config::policy::policy_marks(&self.store)
                .await
                .map_err(Self::e)?
                .contains_key(g)
            {
                anyhow::bail!("Invalid rule: gateway {g:?} does not exist (Routing page)");
            }
            patronus_firewall::nftables::render_policy_rule(&probe, &self.alias_map().await?, 1)
                .map_err(|e| anyhow::anyhow!("{e}"))?;
        }
        if let Some(s) = &core.schedule {
            let all = schedule::load_schedules(&self.store)
                .await
                .map_err(Self::e)?;
            if !all.iter().any(|x| &x.name == s) {
                anyhow::bail!("Invalid rule: schedule {s:?} does not exist");
            }
        }
        Ok(())
    }

    fn core_to_template(r: &CoreFirewallRule, origin: RuleOrigin) -> templates::FirewallRule {
        let protocol = r
            .protocol
            .as_ref()
            .map(|p| p.to_string())
            .unwrap_or_else(|| "any".into());
        let port = port_display(r.dport.as_ref());
        let source = r.source.clone().unwrap_or_else(|| "any".into());
        let destination = r.destination.clone().unwrap_or_else(|| "any".into());
        let iface = r.interface_in.as_deref().or(r.interface_out.as_deref());
        let action = r.action.to_string();
        templates::FirewallRule {
            id: r.id.unwrap_or(0) as u32,
            name: r.name.clone(),
            action: format!("{}{}", action[..1].to_uppercase(), &action[1..]),
            interface: iface.unwrap_or("any").to_string(),
            interface_out: r
                .interface_out
                .clone()
                .filter(|_| r.chain == ChainType::Forward)
                .unwrap_or_else(|| "any".into()),
            protocol: protocol.clone(),
            source: source.clone(),
            destination: destination.clone(),
            port: port.clone(),
            description: r.comment.clone().unwrap_or_default(),
            enabled: r.enabled,
            chain: r.chain.to_string(),
            protocol_display: if protocol == "any" {
                "Any".into()
            } else {
                protocol.to_uppercase()
            },
            source_display: if source == "any" {
                "Any".into()
            } else {
                source
            },
            destination_display: format!(
                "{}:{}",
                if destination == "any" {
                    "Any"
                } else {
                    &destination
                },
                port
            ),
            port_display: port,
            interface_display: display_iface(iface),
            origin: origin.as_str().to_string(),
            log: r.log,
            schedule: r.schedule.clone().unwrap_or_default(),
            gateway: r.gateway.clone().unwrap_or_default(),
            ip_version: r
                .ip_version
                .map(|v| v.to_string())
                .unwrap_or_else(|| "any".into()),
        }
    }

    fn nat_to_template(r: &CoreNatRule, origin: RuleOrigin) -> templates::NatRule {
        let (rule_type, target, external) = match &r.nat_type {
            NatType::Masquerade => ("MASQUERADE", "masquerade".to_string(), String::new()),
            NatType::Snat { to_address } => ("SNAT", to_address.to_string(), String::new()),
            NatType::Dnat {
                to_address,
                to_port,
            } => (
                "DNAT",
                match (to_address, to_port) {
                    (std::net::IpAddr::V6(a), Some(p)) => format!("[{a}]:{p}"),
                    (a, Some(p)) => format!("{a}:{p}"),
                    (a, None) => a.to_string(),
                },
                String::new(),
            ),
            NatType::OneToOne { external, internal } => {
                ("1:1", internal.to_string(), external.to_string())
            }
            NatType::Npt { external, internal } => ("NPTv6", internal.clone(), external.clone()),
        };
        let iface = match &r.nat_type {
            NatType::Dnat { .. } | NatType::OneToOne { .. } | NatType::Npt { .. } => {
                r.interface_in.as_deref().or(r.interface_out.as_deref())
            }
            _ => r.interface_out.as_deref(),
        };
        templates::NatRule {
            id: r.id.unwrap_or(0) as u32,
            name: r.name.clone(),
            rule_type: rule_type.to_string(),
            interface: display_iface(iface),
            interface_raw: iface.unwrap_or("any").to_string(),
            source: r.source.clone().unwrap_or_else(|| "any".into()),
            destination: r.destination.clone().unwrap_or_else(|| "any".into()),
            target,
            external_address: external,
            protocol: r
                .protocol
                .as_ref()
                .map(|p| p.to_string())
                .unwrap_or_else(|| "any".into()),
            external_port: port_display(r.dport.as_ref()),
            reflection: r.reflection,
            description: r.comment.clone().unwrap_or_else(|| r.name.clone()),
            enabled: r.enabled,
            origin: origin.as_str().to_string(),
        }
    }

    /// Record the pre-change configuration (config history / rollback).
    pub(crate) async fn snapshot(&self, what: String) -> anyhow::Result<()> {
        self.store
            .snapshot("web", &format!("before {what}"))
            .await
            .map(|_| ())
            .map_err(Self::e)
    }

    pub(crate) async fn audit(
        &self,
        action: &str,
        entity: &str,
        id: &str,
        details: serde_json::Value,
    ) {
        let _ = self
            .store
            .audit("web", action, entity, Some(id), &details)
            .await;
    }

    pub(crate) async fn push(&self) -> anyhow::Result<()> {
        self.applier
            .apply(&self.store)
            .await
            .map(|_| ())
            .map_err(|e| anyhow::anyhow!("failed to apply firewall to nftables: {e}"))?;
        // the kernel now reflects the schedules as of this apply
        let states = schedule::scheduled_rule_states(&self.store, schedule::now())
            .await
            .map_err(Self::e)?;
        *self.sched_state.lock().await = Some(states);
        Ok(())
    }

    // ---------------------------------------------------------------
    // filter rules
    // ---------------------------------------------------------------

    pub async fn list_rules(&self) -> anyhow::Result<Vec<templates::FirewallRule>> {
        Ok(self
            .store
            .load_firewall_rules_with_origin()
            .await
            .map_err(Self::e)?
            .iter()
            .map(|(r, o)| Self::core_to_template(r, *o))
            .collect())
    }

    pub async fn get_rule(&self, id: u32) -> anyhow::Result<Option<templates::FirewallRule>> {
        Ok(self
            .store
            .get_firewall_rule(id as u64)
            .await
            .map_err(Self::e)?
            .map(|(r, o)| Self::core_to_template(&r, o)))
    }

    async fn order_ids(&self) -> anyhow::Result<Vec<u64>> {
        Ok(self
            .store
            .firewall_rule_order()
            .await
            .map_err(Self::e)?
            .into_iter()
            .filter(|(_, o)| *o != RuleOrigin::System)
            .map(|(i, _)| i)
            .collect())
    }

    pub async fn add_rule(&self, rule: ApiFirewallRule) -> anyhow::Result<u32> {
        let core = Self::rule_to_core(None, &rule)?;
        self.check_rule(&core).await?;
        let _g = self.edit.lock().await;
        self.snapshot(format!("create firewall rule {}", core.name))
            .await?;
        let id = self
            .store
            .save_firewall_rule(&core)
            .await
            .map_err(Self::e)? as u64;
        // optional explicit placement: before another rule
        if let Some(before) = rule.before {
            let mut ids = self.order_ids().await?;
            ids.retain(|i| *i != id);
            let at = ids.iter().position(|i| *i == before as u64).ok_or_else(|| {
                anyhow::anyhow!("Invalid placement: rule {before} is not a movable rule")
            });
            match at {
                Ok(at) => {
                    ids.insert(at, id);
                    self.store
                        .set_firewall_rule_order(&ids)
                        .await
                        .map_err(Self::e)?;
                }
                Err(e) => {
                    let _ = self.store.delete_firewall_rule(id).await;
                    return Err(e);
                }
            }
        }
        if let Err(e) = self.push().await {
            let _ = self.store.delete_firewall_rule(id).await;
            return Err(e);
        }
        self.audit(
            "create",
            "firewall_rule",
            &id.to_string(),
            serde_json::to_value(&core).unwrap_or_default(),
        )
        .await;
        Ok(id as u32)
    }

    /// Update a rule in the store and nftables together.
    pub async fn update_rule(&self, id: u32, rule: ApiFirewallRule) -> anyhow::Result<()> {
        let core = Self::rule_to_core(Some(id as u64), &rule)?;
        let _g = self.edit.lock().await;
        let Some((old, _)) = self
            .store
            .get_firewall_rule(id as u64)
            .await
            .map_err(Self::e)?
        else {
            anyhow::bail!("Rule {id} not found");
        };
        self.check_rule(&core).await?;
        self.snapshot(format!("update firewall rule {id} {}", old.name))
            .await?;
        self.store
            .update_firewall_rule(id as u64, &core)
            .await
            .map_err(Self::e)?;
        if let Err(e) = self.push().await {
            let _ = self.store.update_firewall_rule(id as u64, &old).await;
            return Err(e);
        }
        self.audit(
            "update",
            "firewall_rule",
            &id.to_string(),
            serde_json::to_value(&core).unwrap_or_default(),
        )
        .await;
        Ok(())
    }

    pub async fn delete_rule(&self, id: u32) -> anyhow::Result<()> {
        let _g = self.edit.lock().await;
        let Some((old, origin)) = self
            .store
            .get_firewall_rule(id as u64)
            .await
            .map_err(Self::e)?
        else {
            anyhow::bail!("Rule {id} not found");
        };
        if origin == RuleOrigin::System {
            anyhow::bail!(
                "Invalid request: rule {id} is a system rule (anti-lockout) and cannot be deleted"
            );
        }
        let order = self.order_ids().await?;
        self.snapshot(format!("delete firewall rule {id} {}", old.name))
            .await?;
        self.store
            .delete_firewall_rule(id as u64)
            .await
            .map_err(Self::e)?;
        if let Err(e) = self.push().await {
            let _ = self.store.insert_firewall_rule(&old, origin).await;
            let _ = self.store.set_firewall_rule_order(&order).await;
            return Err(e);
        }
        self.audit(
            "delete",
            "firewall_rule",
            &id.to_string(),
            serde_json::Value::Null,
        )
        .await;
        Ok(())
    }

    /// Move a rule one step / to the top / to the bottom. System rules
    /// (anti-lockout) are pinned first: they can't be moved and nothing
    /// can be moved above them.
    pub async fn move_rule(&self, id: u32, dir: Move) -> anyhow::Result<()> {
        let _g = self.edit.lock().await;
        let ids = self.order_ids().await?;
        let Some(pos) = ids.iter().position(|i| *i == id as u64) else {
            match self
                .store
                .get_firewall_rule(id as u64)
                .await
                .map_err(Self::e)?
            {
                Some((_, RuleOrigin::System)) => anyhow::bail!(
                    "Invalid request: rule {id} is a system rule (anti-lockout), pinned first"
                ),
                _ => anyhow::bail!("Rule {id} not found"),
            }
        };
        let mut new = ids.clone();
        let r = new.remove(pos);
        let to = match dir {
            Move::Up => pos.saturating_sub(1),
            Move::Down => (pos + 1).min(new.len()),
            Move::Top => 0,
            Move::Bottom => new.len(),
        };
        new.insert(to, r);
        if new == ids {
            return Ok(());
        }
        self.apply_order(&ids, &new, &format!("move firewall rule {id} {dir:?}"))
            .await
    }

    /// Set the full order of the movable (non-system) rules.
    pub async fn reorder(&self, new: Vec<u64>) -> anyhow::Result<()> {
        let _g = self.edit.lock().await;
        let ids = self.order_ids().await?;
        self.apply_order(&ids, &new, "reorder firewall rules").await
    }

    async fn apply_order(&self, old: &[u64], new: &[u64], what: &str) -> anyhow::Result<()> {
        self.snapshot(what.to_string()).await?;
        self.store
            .set_firewall_rule_order(new)
            .await
            .map_err(Self::e)?;
        if let Err(e) = self.push().await {
            let _ = self.store.set_firewall_rule_order(old).await;
            return Err(e);
        }
        self.audit("reorder", "firewall_rule", "*", serde_json::json!(new))
            .await;
        Ok(())
    }

    /// Re-apply everything from the store.
    pub async fn apply_rules(&self) -> anyhow::Result<()> {
        let _g = self.edit.lock().await;
        self.push().await
    }

    pub async fn count_active_rules(&self) -> anyhow::Result<usize> {
        Ok(self
            .store
            .load_firewall_rules()
            .await
            .map_err(Self::e)?
            .iter()
            .filter(|r| r.enabled)
            .count())
    }

    // ---------------------------------------------------------------
    // NAT
    // ---------------------------------------------------------------

    pub async fn list_nat_rules(&self) -> anyhow::Result<Vec<templates::NatRule>> {
        Ok(self
            .store
            .load_nat_rules_with_origin()
            .await
            .map_err(Self::e)?
            .iter()
            .map(|(r, o)| Self::nat_to_template(r, *o))
            .collect())
    }

    pub async fn get_nat_rule(&self, id: u32) -> anyhow::Result<Option<templates::NatRule>> {
        Ok(self
            .store
            .get_nat_rule(id as u64)
            .await
            .map_err(Self::e)?
            .map(|(r, o)| Self::nat_to_template(&r, o)))
    }

    async fn nat_to_core(&self, id: Option<u64>, rule: &ApiNatRule) -> anyhow::Result<CoreNatRule> {
        let nat_type = parse_nat_type(
            &rule.rule_type,
            &rule.target,
            rule.external_address.as_deref(),
        )
        .map_err(|e| {
            let m = e.to_string();
            if m.starts_with("Invalid") {
                e
            } else {
                anyhow::anyhow!("Invalid NAT rule: {m}")
            }
        })?;
        let iface = interface_field(&rule.interface)?;
        let protocol = parse_protocol(rule.protocol.as_deref().unwrap_or(""))?;
        let dport = parse_ports(rule.external_port.as_deref().unwrap_or(""))?;
        if dport.is_some() && !matches!(protocol, Some(Protocol::Tcp | Protocol::Udp)) {
            anyhow::bail!("Invalid NAT rule: a port needs protocol tcp or udp");
        }
        let (interface_in, interface_out) = match &nat_type {
            NatType::Dnat { .. } => (iface, None),
            NatType::OneToOne { .. } | NatType::Npt { .. } => (iface.clone(), iface),
            _ => (None, iface),
        };
        if rule.reflection && !matches!(nat_type, NatType::Dnat { .. }) {
            anyhow::bail!("Invalid NAT rule: reflection applies to port forwards only");
        }
        if let NatType::Dnat {
            to_port: Some(_), ..
        } = nat_type
        {
            if dport.is_none() {
                anyhow::bail!("Invalid port forward: a target port needs an external port");
            }
        }
        let name = rule
            .name
            .clone()
            .filter(|n| !n.trim().is_empty())
            .unwrap_or_else(|| rule.description.clone());
        let core = CoreNatRule {
            id,
            name: if name.trim().is_empty() {
                format!("{} rule", rule.rule_type)
            } else {
                name
            },
            enabled: rule.enabled,
            nat_type,
            source: any_or(&rule.source),
            destination: any_or(&rule.destination),
            protocol,
            dport,
            interface_out,
            interface_in,
            reflection: rule.reflection,
            comment: Some(rule.description.clone()).filter(|d| !d.is_empty()),
        };
        let mut probe = core.clone();
        for f in [&mut probe.interface_in, &mut probe.interface_out] {
            if f.as_deref().is_some_and(|v| v.starts_with('@')) {
                *f = Some("probe0".into());
            }
        }
        probe.enabled = true;
        patronus_firewall::nftables::render_nat_rule(
            &probe,
            &self.alias_map().await?,
            &NatContext::default(),
        )
        .map_err(|e| anyhow::anyhow!("{e}"))?;
        Ok(core)
    }

    pub async fn add_nat_rule(&self, rule: ApiNatRule) -> anyhow::Result<u32> {
        let core = self.nat_to_core(None, &rule).await?;
        let _g = self.edit.lock().await;
        self.snapshot(format!("create NAT rule {}", core.name))
            .await?;
        let id = self.store.save_nat_rule(&core).await.map_err(Self::e)? as u64;
        if let Err(e) = self.push().await {
            let _ = self.store.delete_nat_rule(id).await;
            return Err(e);
        }
        self.audit(
            "create",
            "nat_rule",
            &id.to_string(),
            serde_json::to_value(&core).unwrap_or_default(),
        )
        .await;
        Ok(id as u32)
    }

    pub async fn update_nat_rule(&self, id: u32, rule: ApiNatRule) -> anyhow::Result<()> {
        let core = self.nat_to_core(Some(id as u64), &rule).await?;
        let _g = self.edit.lock().await;
        let Some((old, _)) = self.store.get_nat_rule(id as u64).await.map_err(Self::e)? else {
            anyhow::bail!("NAT rule {id} not found");
        };
        self.snapshot(format!("update NAT rule {id} {}", old.name))
            .await?;
        self.store
            .update_nat_rule(id as u64, &core)
            .await
            .map_err(Self::e)?;
        if let Err(e) = self.push().await {
            let _ = self.store.update_nat_rule(id as u64, &old).await;
            return Err(e);
        }
        self.audit(
            "update",
            "nat_rule",
            &id.to_string(),
            serde_json::to_value(&core).unwrap_or_default(),
        )
        .await;
        Ok(())
    }

    pub async fn delete_nat_rule(&self, id: u32) -> anyhow::Result<()> {
        let _g = self.edit.lock().await;
        let Some((old, origin)) = self.store.get_nat_rule(id as u64).await.map_err(Self::e)? else {
            anyhow::bail!("NAT rule {id} not found");
        };
        if origin == RuleOrigin::System {
            anyhow::bail!("Invalid request: NAT rule {id} is a system rule and cannot be deleted");
        }
        // Every other edit records a revision; deleting a NAT rule did not,
        // so it could not be rolled back from the config history.
        self.snapshot(format!("delete NAT rule {id} {}", old.name))
            .await?;
        self.store
            .delete_nat_rule(id as u64)
            .await
            .map_err(Self::e)?;
        if let Err(e) = self.push().await {
            let _ = self.store.insert_nat_rule(&old, origin).await;
            return Err(e);
        }
        self.audit(
            "delete",
            "nat_rule",
            &id.to_string(),
            serde_json::Value::Null,
        )
        .await;
        Ok(())
    }

    pub async fn outbound_mode(&self) -> anyhow::Result<OutboundNatMode> {
        outbound_nat_mode(&self.store).await.map_err(Self::e)
    }

    pub async fn set_outbound_mode(&self, mode: &str) -> anyhow::Result<()> {
        let mode = OutboundNatMode::parse(mode).map_err(Self::e)?;
        let _g = self.edit.lock().await;
        let old = self.outbound_mode().await?;
        self.snapshot(format!("set outbound NAT mode {}", mode.as_str()))
            .await?;
        set_outbound_nat_mode(&self.store, mode)
            .await
            .map_err(Self::e)?;
        if let Err(e) = self.push().await {
            let _ = set_outbound_nat_mode(&self.store, old).await;
            return Err(e);
        }
        self.audit(
            "update",
            "outbound_nat_mode",
            mode.as_str(),
            serde_json::Value::Null,
        )
        .await;
        Ok(())
    }

    /// Interfaces the automatic outbound NAT covers: the WAN role plus
    /// every interface an IPv4 gateway sits behind (Routing page).
    pub async fn auto_nat_interfaces(&self) -> anyhow::Result<Vec<String>> {
        patronus_firewall::applier::auto_nat_devices(&self.store)
            .await
            .map_err(Self::e)
    }

    // ---------------------------------------------------------------
    // aliases
    // ---------------------------------------------------------------

    pub async fn list_alias_objects(&self) -> anyhow::Result<Vec<Alias>> {
        aliases::load_aliases(&self.store).await.map_err(Self::e)
    }

    /// Aliases for the page.
    pub async fn list_aliases(&self) -> anyhow::Result<Vec<templates::Alias>> {
        Ok(self
            .list_alias_objects()
            .await?
            .into_iter()
            .map(|a| templates::Alias {
                id: 0,
                alias_type: match a.source.as_ref().map(|s| s.kind.as_str()) {
                    Some("geoip") => "geoip".to_string(),
                    Some("threat") => "threat feed".to_string(),
                    Some(_) if a.kind == patronus_firewall::nftables::AliasKind::Port => {
                        "url table (ports)".to_string()
                    }
                    Some(_) => "url table".to_string(),
                    None => aliases::kind_str(a.kind).to_string(),
                },
                value: match &a.source {
                    Some(src) => match src.kind.as_str() {
                        "geoip" => {
                            format!("{} ({} ranges)", src.countries.join(", "), a.entries.len())
                        }
                        _ => format!(
                            "{} ({} entries; {})",
                            src.url.clone().unwrap_or_default(),
                            a.entries.len(),
                            src.last_status
                                .clone()
                                .unwrap_or_else(|| "not fetched yet".into())
                        ),
                    },
                    None => a.entries.join(", "),
                },
                description: a.description.unwrap_or_default(),
                name: a.name,
            })
            .collect())
    }

    fn body_to_alias(name: &str, b: &AliasBody) -> anyhow::Result<Alias> {
        let entries: Vec<String> = b
            .entries
            .iter()
            .flat_map(|e| e.split([',', '\n', ' ']))
            .map(str::trim)
            .filter(|e| !e.is_empty())
            .map(str::to_string)
            .collect();
        patronus_firewall::feeds::build_alias(
            name,
            &b.alias_type,
            entries,
            b.description.clone(),
            b.source.clone(),
        )
        .map_err(Self::e)
    }

    pub async fn create_alias(&self, b: AliasBody) -> anyhow::Result<()> {
        let name = b.name.clone().unwrap_or_default();
        let a = Self::body_to_alias(name.trim(), &b)?;
        let _g = self.edit.lock().await;
        if aliases::get_alias(&self.store, &a.name)
            .await
            .map_err(Self::e)?
            .is_some()
        {
            anyhow::bail!("Invalid request: alias {} already exists", a.name);
        }
        self.snapshot(format!("create alias {}", a.name)).await?;
        aliases::save_alias(&self.store, &a)
            .await
            .map_err(Self::e)?;
        // the new sets must exist before a rule can reference them
        if let Err(e) = self.push().await {
            let _ = aliases::delete_alias(&self.store, &a.name).await;
            return Err(e);
        }
        self.audit(
            "create",
            "alias",
            &a.name,
            serde_json::to_value(&a).unwrap_or_default(),
        )
        .await;
        Ok(())
    }

    /// Change an alias. Only the nft set elements are swapped (one
    /// transaction, no ruleset reload); a type change needs a full apply.
    /// Returns true if the update was applied live (sets only).
    pub async fn update_alias(&self, name: &str, b: AliasBody) -> anyhow::Result<bool> {
        let mut a = Self::body_to_alias(name, &b)?;
        let _g = self.edit.lock().await;
        let Some(old) = aliases::get_alias(&self.store, name)
            .await
            .map_err(Self::e)?
        else {
            anyhow::bail!("Alias {name} not found");
        };
        // a self-filling alias keeps what it fetched until the next refresh
        if a.source.is_some() {
            a.entries = old.entries.clone();
        }
        if old.kind != a.kind
            && !aliases::alias_users(&self.store, name)
                .await
                .map_err(Self::e)?
                .is_empty()
        {
            anyhow::bail!("Invalid request: alias {name} is in use; its type cannot change");
        }
        self.snapshot(format!("update alias {name}")).await?;
        aliases::save_alias(&self.store, &a)
            .await
            .map_err(Self::e)?;
        let live = if old.kind == a.kind {
            let script = aliases::update_sets_script(&a).map_err(Self::e)?;
            match patronus_firewall::nftables::execute_nft_script(&script) {
                Ok(_) => true,
                Err(e) => {
                    tracing::warn!("live alias update failed ({e}); re-applying the ruleset");
                    false
                }
            }
        } else {
            false
        };
        if !live {
            if let Err(e) = self.push().await {
                let _ = aliases::save_alias(&self.store, &old).await;
                return Err(e);
            }
        }
        self.audit(
            "update",
            "alias",
            name,
            serde_json::to_value(&a).unwrap_or_default(),
        )
        .await;
        Ok(live)
    }

    pub async fn delete_alias(&self, name: &str) -> anyhow::Result<()> {
        let _g = self.edit.lock().await;
        let Some(old) = aliases::get_alias(&self.store, name)
            .await
            .map_err(Self::e)?
        else {
            anyhow::bail!("Alias {name} not found");
        };
        self.snapshot(format!("delete alias {name}")).await?;
        aliases::delete_alias(&self.store, name)
            .await
            .map_err(Self::e)?;
        if let Err(e) = self.push().await {
            let _ = aliases::save_alias(&self.store, &old).await;
            return Err(e);
        }
        self.audit("delete", "alias", name, serde_json::Value::Null)
            .await;
        Ok(())
    }

    // ---------------------------------------------------------------
    // schedules
    // ---------------------------------------------------------------

    pub async fn list_schedules(&self) -> anyhow::Result<Vec<templates::FirewallSchedule>> {
        let now = schedule::now();
        Ok(schedule::load_schedules(&self.store)
            .await
            .map_err(Self::e)?
            .into_iter()
            .map(|s| templates::FirewallSchedule {
                active: s.is_active_at(now),
                days: s.days.join(","),
                description: s.description.clone().unwrap_or_default(),
                name: s.name,
                start: s.start,
                end: s.end,
            })
            .collect())
    }

    fn body_to_schedule(name: &str, b: &ScheduleBody) -> anyhow::Result<Schedule> {
        Schedule {
            name: name.to_string(),
            days: b
                .days
                .iter()
                .flat_map(|d| d.split([',', ' ']))
                .filter(|d| !d.is_empty())
                .map(str::to_string)
                .collect(),
            start: b.start.clone(),
            end: b.end.clone(),
            description: b.description.clone().filter(|d| !d.trim().is_empty()),
        }
        .validated()
        .map_err(Self::e)
    }

    /// Create (`create = true`) or replace a schedule, then re-apply (a
    /// changed window can switch rules on or off).
    pub async fn save_schedule(
        &self,
        name: &str,
        b: ScheduleBody,
        create: bool,
    ) -> anyhow::Result<()> {
        let s = Self::body_to_schedule(name.trim(), &b)?;
        let _g = self.edit.lock().await;
        let all = schedule::load_schedules(&self.store)
            .await
            .map_err(Self::e)?;
        let old = all.iter().find(|x| x.name == s.name).cloned();
        match (&old, create) {
            (Some(_), true) => anyhow::bail!("Invalid request: schedule {} already exists", s.name),
            (None, false) => anyhow::bail!("Schedule {} not found", s.name),
            _ => {}
        }
        self.snapshot(format!("save schedule {}", s.name)).await?;
        schedule::save_schedule(&self.store, &s)
            .await
            .map_err(Self::e)?;
        if let Err(e) = self.push().await {
            match &old {
                Some(o) => {
                    let _ = schedule::save_schedule(&self.store, o).await;
                }
                None => {
                    let _ = schedule::delete_schedule(&self.store, &s.name).await;
                }
            }
            return Err(e);
        }
        self.audit(
            "save",
            "schedule",
            &s.name,
            serde_json::to_value(&s).unwrap_or_default(),
        )
        .await;
        Ok(())
    }

    pub async fn delete_schedule(&self, name: &str) -> anyhow::Result<()> {
        let _g = self.edit.lock().await;
        if !schedule::load_schedules(&self.store)
            .await
            .map_err(Self::e)?
            .iter()
            .any(|s| s.name == name)
        {
            anyhow::bail!("Schedule {name} not found");
        }
        self.snapshot(format!("delete schedule {name}")).await?;
        schedule::delete_schedule(&self.store, name)
            .await
            .map_err(Self::e)?;
        self.audit("delete", "schedule", name, serde_json::Value::Null)
            .await;
        Ok(())
    }

    /// Re-apply the firewall if a scheduled rule became active/inactive
    /// since the last apply. Returns true if it re-applied. Called every
    /// few seconds by the schedule task patronus-web starts.
    pub async fn schedule_tick(&self) -> anyhow::Result<bool> {
        let states = schedule::scheduled_rule_states(&self.store, schedule::now())
            .await
            .map_err(Self::e)?;
        if self.sched_state.lock().await.as_ref() == Some(&states) {
            return Ok(false);
        }
        let _g = self.edit.lock().await;
        tracing::info!("firewall schedule changed state; re-applying the ruleset");
        self.push().await?;
        Ok(true)
    }

    // ---------------------------------------------------------------
    // page
    // ---------------------------------------------------------------

    /// Interface choices for the rule/NAT forms: roles first, then
    /// devices.
    pub async fn interface_options(&self) -> anyhow::Result<Vec<templates::InterfaceOption>> {
        let roles = self.store.interface_roles().await.map_err(Self::e)?;
        let mut out = vec![templates::InterfaceOption {
            value: "any".into(),
            label: "Any".into(),
        }];
        let mut role_names: Vec<String> = vec!["wan".into(), "lan".into()];
        for (_, r) in &roles {
            if !role_names.contains(r) {
                role_names.push(r.clone());
            }
        }
        for r in role_names {
            let devs: Vec<&str> = roles
                .iter()
                .filter(|(_, x)| *x == r)
                .map(|(n, _)| n.as_str())
                .collect();
            out.push(templates::InterfaceOption {
                value: format!("@{r}"),
                label: format!(
                    "{} ({})",
                    r.to_uppercase(),
                    if devs.is_empty() {
                        "unassigned".to_string()
                    } else {
                        devs.join(", ")
                    }
                ),
            });
        }
        for d in patronus_config::defaults::existing_interfaces() {
            if d != "lo" {
                out.push(templates::InterfaceOption {
                    label: d.clone(),
                    value: d,
                });
            }
        }
        Ok(out)
    }

    /// Everything the Firewall page shows.
    pub async fn page(&self) -> anyhow::Result<templates::FirewallTemplate> {
        let rules = self.list_rules().await?;
        let nat_rules = self.list_nat_rules().await?;
        let aliases = self.list_aliases().await?;
        Ok(templates::FirewallTemplate {
            enabled_filter_rules: rules.iter().filter(|r| r.enabled).count(),
            enabled_nat_rules: nat_rules.iter().filter(|r| r.enabled).count(),
            accept_rules_count: rules.iter().filter(|r| r.action == "Accept").count(),
            drop_rules_count: rules
                .iter()
                .filter(|r| r.action == "Drop" || r.action == "Reject")
                .count(),
            filter_rules: rules.clone(),
            rules,
            port_forwards: nat_rules
                .iter()
                .filter(|r| r.rule_type == "DNAT")
                .cloned()
                .collect(),
            one_to_one: nat_rules
                .iter()
                .filter(|r| r.rule_type == "1:1")
                .cloned()
                .collect(),
            npt: nat_rules
                .iter()
                .filter(|r| r.rule_type == "NPTv6")
                .cloned()
                .collect(),
            outbound_rules: nat_rules
                .iter()
                .filter(|r| r.rule_type == "MASQUERADE" || r.rule_type == "SNAT")
                .cloned()
                .collect(),
            nat_rules,
            port_aliases: aliases
                .iter()
                .filter(|a| a.alias_type == "port")
                .cloned()
                .collect(),
            host_aliases: aliases
                .iter()
                .filter(|a| a.alias_type == "host")
                .cloned()
                .collect(),
            aliases,
            schedules: self.list_schedules().await?,
            interfaces: self.interface_options().await?,
            outbound_mode: self.outbound_mode().await?.as_str().to_string(),
            auto_nat_interfaces: self.auto_nat_interfaces().await?.join(", "),
            gateways: patronus_config::policy::policy_marks(&self.store)
                .await
                .map_err(Self::e)?
                .into_keys()
                .collect(),
        })
    }
}

/// Background task: re-apply when a scheduled rule's window opens/closes.
pub fn spawn_schedule_task(fw: Arc<FirewallManager>) {
    let secs = std::env::var("PATRONUS_SCHEDULE_TICK_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .filter(|s| *s > 0)
        .unwrap_or(5);
    tokio::spawn(async move {
        let mut t = tokio::time::interval(std::time::Duration::from_secs(secs));
        loop {
            t.tick().await;
            if let Err(e) = fw.schedule_tick().await {
                tracing::error!("firewall schedule check failed: {e}");
            }
        }
    });
}

/// Applier that changes nothing (tests that only exercise HTTP/auth).
#[cfg(test)]
pub(crate) struct NoopApplier;

#[cfg(test)]
#[async_trait::async_trait]
impl Applier for NoopApplier {
    fn name(&self) -> &'static str {
        "firewall"
    }
    fn phase(&self) -> patronus_config::Phase {
        patronus_config::Phase::Firewall
    }
    async fn apply(&self, _s: &ConfigStore) -> patronus_core::Result<patronus_config::ApplyReport> {
        Ok(Default::default())
    }
    async fn render(&self, _s: &ConfigStore) -> patronus_core::Result<String> {
        Ok(String::new())
    }
}

#[cfg(test)]
mod tests {
    //! Unprivileged tests use a recording applier; the #[ignore]d ones push
    //! through the real FirewallApplier into real nftables (run by
    //! ci/privileged-tests.sh in a CAP_NET_ADMIN container).
    use super::*;
    use async_trait::async_trait;
    use patronus_config::applier::{ApplyReport, Phase};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    #[derive(Default)]
    struct FakeApplier {
        applies: AtomicUsize,
        fail: AtomicBool,
    }

    #[async_trait]
    impl Applier for FakeApplier {
        fn name(&self) -> &'static str {
            "firewall"
        }
        fn phase(&self) -> Phase {
            Phase::Firewall
        }
        async fn apply(&self, _s: &ConfigStore) -> patronus_core::Result<ApplyReport> {
            self.applies.fetch_add(1, Ordering::SeqCst);
            if self.fail.load(Ordering::SeqCst) {
                return Err(patronus_core::Error::Firewall("nft says no".into()));
            }
            Ok(ApplyReport::default())
        }
        async fn render(&self, _s: &ConfigStore) -> patronus_core::Result<String> {
            Ok(String::new())
        }
    }

    pub(crate) fn sample_rule(source: &str) -> ApiFirewallRule {
        ApiFirewallRule {
            id: None,
            name: None,
            chain: None,
            action: "Accept".to_string(),
            interface: "eth0".to_string(),
            interface_out: None,
            protocol: "tcp".to_string(),
            source: source.to_string(),
            destination: "any".to_string(),
            port: "80".to_string(),
            description: "test rule".to_string(),
            enabled: true,
            log: false,
            schedule: None,
            ip_version: None,
            gateway: None,
            before: None,
        }
    }

    fn sample_nat_rule(rule_type: &str, source: &str, target: &str) -> ApiNatRule {
        ApiNatRule {
            id: None,
            name: None,
            rule_type: rule_type.to_string(),
            interface: "eth0".to_string(),
            source: source.to_string(),
            destination: "any".to_string(),
            target: target.to_string(),
            description: "test nat rule".to_string(),
            enabled: true,
            protocol: None,
            external_port: None,
            external_address: None,
            reflection: false,
        }
    }

    async fn fake() -> (FirewallManager, Arc<FakeApplier>, Arc<ConfigStore>) {
        let store = Arc::new(ConfigStore::open_in_memory().await.unwrap());
        let a = Arc::new(FakeApplier::default());
        (FirewallManager::new(store.clone(), a.clone()), a, store)
    }

    #[tokio::test]
    async fn add_rule_rejects_injection_and_does_not_appear_in_list() {
        let (fw, a, _) = fake().await;
        let malicious = sample_rule("0.0.0.0/0; add rule inet patronus forward accept #");
        let e = fw.add_rule(malicious).await.unwrap_err().to_string();
        assert!(e.contains("Invalid"), "{e}");
        assert!(fw.list_rules().await.unwrap().is_empty());
        assert_eq!(a.applies.load(Ordering::SeqCst), 0, "rejected before apply");
    }

    #[tokio::test]
    async fn add_nat_rule_rejects_injection_and_unparseable_target() {
        let (fw, _, _) = fake().await;
        let malicious = sample_nat_rule(
            "MASQUERADE",
            "0.0.0.0/0; add rule inet patronus forward accept #",
            "masquerade",
        );
        assert!(fw.add_nat_rule(malicious).await.is_err());
        assert!(fw
            .add_nat_rule(sample_nat_rule("SNAT", "10.0.0.0/8", "not-an-ip-address"))
            .await
            .is_err());
        assert!(fw.list_nat_rules().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn rules_persist_in_the_store_and_each_change_is_applied() {
        let (fw, a, store) = fake().await;
        let id = fw.add_rule(sample_rule("10.0.0.0/8")).await.unwrap();
        assert_eq!(a.applies.load(Ordering::SeqCst), 1);
        let stored = store.load_firewall_rules().await.unwrap();
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].source.as_deref(), Some("10.0.0.0/8"));
        assert_eq!(stored[0].dport, Some(PortSpec::Single(80)));

        // A second manager over the same store (= a restarted patronus-web)
        // sees the rule.
        let fw2 = FirewallManager::new(store.clone(), a.clone());
        assert_eq!(fw2.get_rule(id).await.unwrap().unwrap().port, "80");

        let mut upd = sample_rule("10.0.0.0/8");
        upd.port = "8080".into();
        upd.log = true;
        fw.update_rule(id, upd).await.unwrap();
        let got = fw2.get_rule(id).await.unwrap().unwrap();
        assert_eq!(got.port, "8080");
        assert!(got.log);
        fw.delete_rule(id).await.unwrap();
        assert!(fw2.list_rules().await.unwrap().is_empty());
        assert_eq!(a.applies.load(Ordering::SeqCst), 3);
    }

    /// An apply failure must surface as an error and leave the store as it
    /// was (no phantom rule, no lost rule, order kept).
    #[tokio::test]
    async fn apply_failure_is_reported_and_the_store_is_rolled_back() {
        let (fw, a, _) = fake().await;
        let keep = fw.add_rule(sample_rule("192.0.2.0/24")).await.unwrap();
        let second = fw.add_rule(sample_rule("192.0.2.0/25")).await.unwrap();
        a.fail.store(true, Ordering::SeqCst);
        assert!(fw.add_rule(sample_rule("198.51.100.0/24")).await.is_err());
        assert_eq!(fw.list_rules().await.unwrap().len(), 2);
        let mut upd = sample_rule("192.0.2.0/24");
        upd.port = "9999".into();
        assert!(fw.update_rule(keep, upd).await.is_err());
        assert_eq!(fw.get_rule(keep).await.unwrap().unwrap().port, "80");
        assert!(fw.delete_rule(keep).await.is_err());
        assert!(fw.move_rule(second, Move::Up).await.is_err());
        let ids: Vec<u32> = fw
            .list_rules()
            .await
            .unwrap()
            .iter()
            .map(|r| r.id)
            .collect();
        assert_eq!(ids, vec![keep, second], "order restored after failures");
        assert!(fw
            .add_nat_rule(sample_nat_rule("MASQUERADE", "10.0.0.0/8", "masquerade"))
            .await
            .is_err());
        assert!(fw.list_nat_rules().await.unwrap().is_empty());
    }

    /// Every change made through the UI/API is undoable from the config
    /// history (NAT deletes recorded nothing), and a delete that fails to
    /// apply puts the rule back under the same id.
    #[tokio::test]
    async fn every_change_records_a_revision_and_failed_delete_keeps_the_id() {
        let (fw, a, store) = fake().await;
        let id = fw.add_rule(sample_rule("192.0.2.0/24")).await.unwrap();
        let mut upd = sample_rule("192.0.2.0/24");
        upd.port = "8080".into();
        fw.update_rule(id, upd).await.unwrap();
        let nat = fw
            .add_nat_rule(sample_nat_rule("MASQUERADE", "10.0.0.0/8", "masquerade"))
            .await
            .unwrap();
        fw.delete_nat_rule(nat).await.unwrap();
        let summaries: Vec<String> = store
            .list_revisions()
            .await
            .unwrap()
            .into_iter()
            .map(|(_, _, _, s)| s)
            .collect();
        for want in [
            "before create firewall rule",
            "before update firewall rule",
            "before create NAT rule",
            "before delete NAT rule",
        ] {
            assert!(
                summaries.iter().any(|s| s.starts_with(want)),
                "{want}: {summaries:?}"
            );
        }
        a.fail.store(true, Ordering::SeqCst);
        assert!(fw.delete_rule(id).await.is_err());
        let back = fw
            .get_rule(id)
            .await
            .unwrap()
            .expect("same id after a failed delete");
        assert_eq!(back.port, "8080");
    }

    #[tokio::test]
    async fn system_rules_are_listed_but_cannot_be_deleted_edited_or_moved() {
        let (fw, _, store) = fake().await;
        patronus_config::ensure_defaults(
            &store,
            Some(&patronus_config::Bootstrap {
                wan: vec!["eth0".into()],
                lan: vec!["eth1".into()],
            }),
            &["eth0".into(), "eth1".into()],
        )
        .await
        .unwrap();
        let rules = fw.list_rules().await.unwrap();
        let anti = rules.iter().find(|r| r.origin == "system").unwrap();
        assert_eq!(anti.interface_display, "MGMT");
        assert_eq!(anti.port, "22,8443");
        let e = fw.delete_rule(anti.id).await.unwrap_err().to_string();
        assert!(e.contains("Invalid"), "{e}");
        assert!(fw.update_rule(anti.id, sample_rule("any")).await.is_err());
        let e = fw
            .move_rule(anti.id, Move::Down)
            .await
            .unwrap_err()
            .to_string();
        assert!(e.contains("Invalid"), "{e}");
        // outbound NAT is automatic: no seeded row, mode hybrid
        assert!(fw.list_nat_rules().await.unwrap().is_empty());
        assert_eq!(fw.outbound_mode().await.unwrap(), OutboundNatMode::Hybrid);
        assert_eq!(fw.auto_nat_interfaces().await.unwrap(), vec!["eth0"]);
    }

    /// New user rules land after the existing user rules but ahead of the
    /// seeded "Allow LAN to any", never ahead of the anti-lockout rule; and
    /// rules move up/down/top/bottom, but never above a system rule.
    #[tokio::test]
    async fn rule_order_placement_and_moves() {
        let (fw, _, store) = fake().await;
        patronus_config::ensure_defaults(
            &store,
            Some(&patronus_config::Bootstrap {
                wan: vec!["eth0".into()],
                lan: vec!["eth1".into()],
            }),
            &["eth0".into(), "eth1".into()],
        )
        .await
        .unwrap();
        let mut r1 = sample_rule("any");
        r1.name = Some("first".into());
        let a = fw.add_rule(r1).await.unwrap();
        let mut r2 = sample_rule("any");
        r2.name = Some("second".into());
        let b = fw.add_rule(r2).await.unwrap();
        let names = |v: Vec<templates::FirewallRule>| -> Vec<String> {
            v.into_iter().map(|r| r.name).collect()
        };
        assert_eq!(
            names(fw.list_rules().await.unwrap()),
            vec![
                "Anti-lockout",
                "first",
                "second",
                "Allow LAN to firewall",
                "Allow LAN to any"
            ]
        );
        fw.move_rule(b, Move::Up).await.unwrap();
        fw.move_rule(b, Move::Top).await.unwrap(); // already at the top
        assert_eq!(names(fw.list_rules().await.unwrap())[1], "second");
        fw.move_rule(a, Move::Bottom).await.unwrap();
        let n = names(fw.list_rules().await.unwrap());
        assert_eq!(n[0], "Anti-lockout");
        assert_eq!(n.last().unwrap(), "first");
        // explicit placement on create
        let mut r3 = sample_rule("any");
        r3.name = Some("third".into());
        r3.before = Some(b);
        fw.add_rule(r3).await.unwrap();
        assert_eq!(names(fw.list_rules().await.unwrap())[1], "third");
        // a full reorder must list every movable rule exactly once
        let anti = store.firewall_rule_order().await.unwrap()[0].0;
        assert!(fw.reorder(vec![anti]).await.is_err());
    }

    #[tokio::test]
    async fn rule_translation_keeps_protocol_port_action_chain_roles_and_new_fields() {
        let t = |action: &str, proto: &str, port: &str| {
            let mut r = sample_rule("198.51.100.0/24");
            r.action = action.into();
            r.protocol = proto.into();
            r.port = port.into();
            FirewallManager::rule_to_core(Some(9), &r)
        };
        let c = t("accept", "tcp", "8080").unwrap();
        assert!(matches!(c.action, FirewallAction::Accept));
        assert!(matches!(c.protocol, Some(Protocol::Tcp)));
        assert!(matches!(c.dport, Some(PortSpec::Single(8080))));
        assert!(matches!(
            t("reject", "tcp", "22").unwrap().action,
            FirewallAction::Reject
        ));
        assert!(matches!(
            t("accept", "tcp", "8000-8010").unwrap().dport,
            Some(PortSpec::Range(8000, 8010))
        ));
        assert_eq!(
            t("accept", "tcp", "$web").unwrap().dport,
            Some(PortSpec::Alias("web".into()))
        );
        for (a, p, port) in [
            ("acept", "tcp", "80"),
            ("accept", "sctp", "80"),
            ("accept", "tcp", "http"),
            ("accept", "tcp", "70000"),
            ("accept", "any", "80"),
            ("accept", "tcp", "90-80"),
            ("accept", "tcp", "$bad name"),
        ] {
            let e = t(a, p, port).unwrap_err().to_string();
            assert!(e.contains("Invalid"), "{a}/{p}/{port}: {e}");
        }
        let mut r = sample_rule("any");
        r.interface = "@LAN".into();
        r.chain = Some("forward".into());
        r.interface_out = Some("@wan".into());
        r.ip_version = Some("ipv6".into());
        r.schedule = Some("work".into());
        let c = FirewallManager::rule_to_core(None, &r).unwrap();
        assert_eq!(c.chain, ChainType::Forward);
        assert_eq!(c.interface_in.as_deref(), Some("@lan"));
        assert_eq!(c.interface_out.as_deref(), Some("@wan"));
        assert_eq!(c.ip_version, Some(IpVersion::V6));
        assert_eq!(c.schedule.as_deref(), Some("work"));
        assert_eq!(c.source, None);
        r.interface = "@dmz".into();
        assert!(FirewallManager::rule_to_core(None, &r).is_err());
        r.interface = "eth0\" accept #".into();
        assert!(FirewallManager::rule_to_core(None, &r).is_err());
    }

    #[tokio::test]
    async fn ipv6_rules_unknown_aliases_and_schedules_are_validated() {
        let (fw, _, store) = fake().await;
        let mut r = sample_rule("2001:db8::/32");
        r.destination = "192.0.2.1".into();
        let e = fw.add_rule(r).await.unwrap_err().to_string();
        assert!(e.contains("Invalid"), "mixed families: {e}");
        let mut r = sample_rule("$nope");
        assert!(fw.add_rule(r.clone()).await.is_err(), "unknown alias");
        fw.create_alias(AliasBody {
            name: Some("nope".into()),
            alias_type: "host".into(),
            entries: vec!["192.0.2.1, 2001:db8::1".into()],
            description: None,
            source: None,
        })
        .await
        .unwrap();
        fw.add_rule(r.clone()).await.unwrap();
        r.schedule = Some("missing".into());
        let e = fw.add_rule(r).await.unwrap_err().to_string();
        assert!(e.contains("schedule"), "{e}");
        let e = fw.delete_alias("nope").await.unwrap_err().to_string();
        assert!(e.contains("Invalid"), "alias in use: {e}");
        let a = aliases::load_aliases(&store).await.unwrap();
        assert_eq!(a[0].entries, vec!["192.0.2.1", "2001:db8::1"]);
    }

    #[tokio::test]
    async fn port_forward_one_to_one_and_outbound_mode() {
        let (fw, _, store) = fake().await;
        let mut pf = sample_nat_rule("DNAT", "any", "192.168.50.10:9000");
        pf.interface = "@wan".into();
        pf.protocol = Some("tcp".into());
        pf.external_port = Some("8022".into());
        pf.reflection = true;
        let id = fw.add_nat_rule(pf.clone()).await.unwrap();
        let (r, _) = store.get_nat_rule(id as u64).await.unwrap().unwrap();
        assert_eq!(
            r.interface_in.as_deref(),
            Some("@wan"),
            "inbound, not oifname"
        );
        assert_eq!(r.interface_out, None);
        assert_eq!(r.dport, Some(PortSpec::Single(8022)));
        assert!(r.reflection);
        let t = fw.get_nat_rule(id).await.unwrap().unwrap();
        assert_eq!(t.target, "192.168.50.10:9000");
        assert_eq!(t.external_port, "8022");
        pf.external_port = Some("8023".into());
        fw.update_nat_rule(id, pf.clone()).await.unwrap();
        assert_eq!(
            fw.get_nat_rule(id).await.unwrap().unwrap().external_port,
            "8023"
        );
        pf.external_port = None;
        assert!(
            fw.add_nat_rule(pf.clone()).await.is_err(),
            "target port w/o external port"
        );
        pf.protocol = None;
        pf.external_port = Some("80".into());
        assert!(fw.add_nat_rule(pf).await.is_err(), "port without protocol");

        let mut one = sample_nat_rule("1:1", "any", "192.168.50.10");
        one.interface = "@wan".into();
        one.external_address = Some("203.0.113.5".into());
        let id = fw.add_nat_rule(one.clone()).await.unwrap();
        let (r, _) = store.get_nat_rule(id as u64).await.unwrap().unwrap();
        assert!(matches!(r.nat_type, NatType::OneToOne { .. }));
        assert_eq!(r.interface_in.as_deref(), Some("@wan"));
        one.external_address = Some("2001:db8::5".into());
        assert!(fw.add_nat_rule(one).await.is_err(), "mixed families");

        fw.set_outbound_mode("manual").await.unwrap();
        assert_eq!(fw.outbound_mode().await.unwrap(), OutboundNatMode::Manual);
        assert!(fw.set_outbound_mode("sometimes").await.is_err());
        assert_eq!(
            parse_nat_type("dnat", "[2001:db8::7]:80", None).unwrap(),
            NatType::Dnat {
                to_address: "2001:db8::7".parse().unwrap(),
                to_port: Some(80),
            }
        );
        assert!(matches!(
            parse_nat_type("dnat", "2001:db8::7", None).unwrap(),
            NatType::Dnat { to_port: None, .. }
        ));
    }

    #[tokio::test]
    async fn schedules_crud_and_tick_reapplies_only_on_change() {
        let (fw, a, _) = fake().await;
        fw.save_schedule(
            "work",
            ScheduleBody {
                days: vec!["mon,tue,wed,thu,fri,sat,sun".into()],
                start: "00:00".into(),
                end: "00:00".into(),
                description: None,
            },
            true,
        )
        .await
        .unwrap();
        let mut r = sample_rule("any");
        r.schedule = Some("work".into());
        fw.add_rule(r).await.unwrap();
        let before = a.applies.load(Ordering::SeqCst);
        assert!(
            !fw.schedule_tick().await.unwrap(),
            "no change since the last apply"
        );
        assert_eq!(a.applies.load(Ordering::SeqCst), before);
        assert!(fw.delete_schedule("work").await.is_err(), "in use");
        assert_eq!(fw.list_schedules().await.unwrap().len(), 1);
    }

    // ---- real nftables (CAP_NET_ADMIN), via the shipped FirewallApplier ----

    fn nft_table() -> String {
        let out = std::process::Command::new("nft")
            .args(["list", "table", "inet", "patronus"])
            .output()
            .expect("nft list table");
        String::from_utf8_lossy(&out.stdout).into_owned()
    }

    async fn real() -> (FirewallManager, Arc<ConfigStore>) {
        let _ = std::process::Command::new("nft")
            .args(["delete", "table", "inet", "patronus"])
            .status();
        let store = Arc::new(ConfigStore::open_in_memory().await.unwrap());
        patronus_config::ensure_defaults(
            &store,
            Some(&patronus_config::Bootstrap {
                wan: vec!["lo".into()],
                lan: vec![],
            }),
            &["lo".into()],
        )
        .await
        .unwrap();
        let fw = FirewallManager::new(store.clone(), Arc::new(patronus_firewall::FirewallApplier));
        fw.apply_rules()
            .await
            .expect("apply defaults (requires CAP_NET_ADMIN)");
        (fw, store)
    }

    #[tokio::test]
    #[ignore] // Requires real nftables (CAP_NET_ADMIN + nf_tables)
    async fn seeded_defaults_are_really_in_nftables() {
        let (fw, _) = real().await;
        let table = nft_table();
        for r in fw.list_rules().await.unwrap() {
            if r.enabled && r.origin == "system" {
                assert!(
                    table.contains(&r.description),
                    "{:?} missing:\n{table}",
                    r.description
                );
            }
        }
        assert!(table.contains("tcp dport { 22, 8443 } accept"), "{table}");
        assert!(table.contains("masquerade"), "{table}");
    }

    #[tokio::test]
    #[ignore] // Requires real nftables (CAP_NET_ADMIN + nf_tables)
    async fn added_updated_and_deleted_rules_reach_nftables_as_specified() {
        let (fw, _) = real().await;
        let marker = format!("port-rule-{}", std::process::id());
        let mut rule = sample_rule("198.51.100.0/24");
        rule.action = "accept".into();
        rule.port = "8080".into();
        rule.description = marker.clone();
        let id = fw.add_rule(rule).await.unwrap();
        let line = |t: &str| {
            t.lines()
                .find(|l| l.contains(&marker))
                .unwrap_or_else(|| panic!("rule missing:\n{t}"))
                .to_string()
        };
        let l = line(&nft_table());
        assert!(
            l.contains("tcp dport 8080") && l.contains("accept") && l.contains("198.51.100.0/24"),
            "{l}"
        );

        let mut upd = sample_rule("198.51.100.0/24");
        upd.action = "reject".into();
        upd.port = "9090".into();
        upd.log = true;
        upd.description = marker.clone();
        fw.update_rule(id, upd).await.unwrap();
        let table = nft_table();
        let l = line(&table);
        assert!(
            l.contains("tcp dport 9090")
                && l.contains("reject with tcp reset")
                && l.contains("log prefix"),
            "{l}"
        );
        assert_eq!(table.matches(&marker).count(), 1, "{table}");
        fw.delete_rule(id).await.unwrap();
        assert!(!nft_table().contains(&marker));
    }

    /// The seeded "Drop Invalid" default used to render as a bare `drop`
    /// in the input chain, shadowing every rule added after it.
    #[tokio::test]
    #[ignore] // Requires real nftables (CAP_NET_ADMIN + nf_tables)
    async fn user_rules_are_not_shadowed_by_an_unconditional_drop() {
        let (fw, _) = real().await;
        let marker = format!("reachable-{}", std::process::id());
        let mut rule = sample_rule("any");
        rule.description = marker.clone();
        let id = fw.add_rule(rule).await.expect("valid rule must apply");
        let table = nft_table();
        let input: Vec<&str> = table
            .split("chain input")
            .nth(1)
            // up to the next chain (a set like `{ 22, 8443 }` contains '}')
            .and_then(|c| c.split("\tchain ").next())
            .unwrap_or_else(|| panic!("no input chain:\n{table}"))
            .lines()
            .map(str::trim)
            .collect();
        let user_pos = input
            .iter()
            .position(|l| l.contains(&marker))
            .unwrap_or_else(|| panic!("user rule missing:\n{table}"));
        for l in &input[..user_pos] {
            let bare = l.split(" comment ").next().unwrap_or(l).trim();
            assert!(
                bare != "drop" && bare != "reject",
                "unconditional {bare:?} first:\n{table}"
            );
        }
        assert!(table.contains("ct state invalid drop"), "{table}");
        fw.delete_rule(id).await.unwrap();
    }

    /// "any" source/destination/interface used to be spliced verbatim.
    #[tokio::test]
    #[ignore] // Requires real nftables (CAP_NET_ADMIN + nf_tables)
    async fn any_source_destination_and_interface_apply_as_wildcards() {
        let (fw, _) = real().await;
        let marker = format!("any-wildcard-{}", std::process::id());
        let mut rule = sample_rule("any");
        rule.interface = "any".to_string();
        rule.description = marker.clone();
        let id = fw.add_rule(rule).await.expect("'any' must apply");
        let table = nft_table();
        let line = table
            .lines()
            .find(|l| l.contains(&marker))
            .unwrap_or_else(|| panic!("rule missing from nftables:\n{table}"));
        for bad in ["saddr any", "daddr any", "\"any\"", "saddr all"] {
            assert!(
                !line.contains(bad),
                "literal wildcard leaked into nft: {line}"
            );
        }
        assert!(
            !line.contains("saddr") && !line.contains("iifname"),
            "{line}"
        );
        fw.delete_rule(id).await.unwrap();
    }

    #[tokio::test]
    #[ignore] // Requires real nftables (CAP_NET_ADMIN + nf_tables)
    async fn nat_rules_reach_nftables_and_leave_on_delete() {
        let (fw, _) = real().await;
        let marker = format!("patronus-web-nat-test-{}", std::process::id());
        let mut nat = sample_nat_rule("MASQUERADE", "10.0.0.0/8", "masquerade");
        nat.description = marker.clone();
        let id = fw.add_nat_rule(nat).await.expect("valid NAT rule");
        assert!(nft_table().contains(&marker));
        fw.delete_nat_rule(id).await.unwrap();
        assert!(!nft_table().contains(&marker));
    }

    /// Alias edits only swap set elements: an object added to the table
    /// out of band survives (a ruleset reload would delete it).
    #[tokio::test]
    #[ignore] // Requires real nftables (CAP_NET_ADMIN + nf_tables)
    async fn alias_update_changes_set_elements_without_reloading() {
        let (fw, _) = real().await;
        fw.create_alias(AliasBody {
            name: Some("blk".into()),
            alias_type: "host".into(),
            entries: vec!["198.51.100.1".into()],
            description: None,
            source: None,
        })
        .await
        .unwrap();
        let mut r = sample_rule("$blk");
        r.action = "drop".into();
        let id = fw.add_rule(r).await.unwrap();
        let t = nft_table();
        assert!(
            t.contains("ip saddr @alias_blk_v4") && t.contains("ip6 saddr @alias_blk_v6"),
            "{t}"
        );
        assert!(std::process::Command::new("nft")
            .args([
                "add",
                "set",
                "inet",
                "patronus",
                "probe_marker",
                "{ type ipv4_addr; }"
            ])
            .status()
            .unwrap()
            .success());
        let live = fw
            .update_alias(
                "blk",
                AliasBody {
                    name: None,
                    alias_type: "host".into(),
                    entries: vec!["198.51.100.2".into(), "2001:db8::2".into()],
                    description: None,
                    source: None,
                },
            )
            .await
            .unwrap();
        assert!(live);
        let t = nft_table();
        assert!(t.contains("probe_marker"), "table was reloaded:\n{t}");
        assert!(
            t.contains("198.51.100.2") && !t.contains("198.51.100.1") && t.contains("2001:db8::2"),
            "{t}"
        );
        fw.delete_rule(id).await.unwrap();
        fw.delete_alias("blk").await.unwrap();
    }
}
