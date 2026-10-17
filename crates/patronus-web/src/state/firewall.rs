//! Firewall/NAT state: a thin adapter over the config store + the firewall
//! applier (lane A foundation; lane B extends the rule model and UI).
//!
//! Every mutation is: validate -> write the store -> run the applier ->
//! on applier failure undo the store write. The store is the only copy of
//! the rules (the old in-memory lists and their seeded "Allow SSH/HTTPS
//! from any" fixtures are gone), so rules survive restarts and reboots and
//! the boot unit (`patronus apply`) loads exactly what the UI shows.

use patronus_config::{Applier, ConfigStore, RuleOrigin};
use patronus_core::types::{
    ChainType, FirewallAction, FirewallRule as CoreFirewallRule, NatRule as CoreNatRule, NatType,
    PortSpec, Protocol,
};
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::routes::api::firewall::{FirewallRule as ApiFirewallRule, NatRule as ApiNatRule};
use crate::templates;

/// Interpret the free-text `rule_type`/`target` fields of an incoming
/// `NatRule` API payload into a typed `NatType`. `target` holds either the
/// literal "masquerade" or an `address[:port]` spec; this never splices the
/// raw string into an nftables script itself (that injection-safety check
/// lives in `patronus_firewall::nftables::nat_rule_to_nft_command`, which
/// still runs on the resulting typed rule), it only rejects inputs it can't
/// make sense of so a malformed rule fails fast with a clear error.
pub(crate) fn parse_nat_type(rule_type: &str, target: &str) -> anyhow::Result<NatType> {
    let trimmed_target = target.trim();
    if trimmed_target.eq_ignore_ascii_case("masquerade")
        || rule_type.eq_ignore_ascii_case("masquerade")
    {
        return Ok(NatType::Masquerade);
    }

    let (addr_part, port_part) = match trimmed_target.rsplit_once(':') {
        Some((addr, port)) if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) => {
            (addr, Some(port))
        }
        _ => (trimmed_target, None),
    };

    let to_address = addr_part
        .parse::<std::net::IpAddr>()
        .map_err(|_| anyhow::anyhow!("Invalid NAT target address: {:?}", target))?;

    match rule_type.to_uppercase().as_str() {
        "DNAT" => {
            let to_port = match port_part {
                Some(p) => Some(
                    p.parse::<u16>()
                        .map_err(|_| anyhow::anyhow!("Invalid NAT target port: {:?}", target))?,
                ),
                None => None,
            };
            Ok(NatType::Dnat {
                to_address,
                to_port,
            })
        }
        _ => Ok(NatType::Snat { to_address }),
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
    Ok(Some(v))
}

fn display_iface(v: Option<&str>) -> String {
    match v {
        None => "any".into(),
        Some(r) if r.starts_with('@') => r[1..].to_uppercase(),
        Some(d) => d.to_string(),
    }
}

/// Firewall management operations
pub struct FirewallManager {
    store: Arc<ConfigStore>,
    applier: Arc<dyn Applier>,
    /// Serializes edit+apply so two requests can't interleave.
    edit: Mutex<()>,
}

impl FirewallManager {
    pub fn new(store: Arc<ConfigStore>, applier: Arc<dyn Applier>) -> Self {
        Self {
            store,
            applier,
            edit: Mutex::new(()),
        }
    }

    /// Strictly translate an API rule into the typed rule nftables gets.
    /// Unknown values are rejected ("Invalid ..." -> 400) instead of being
    /// silently widened or flipped (protocol/port used to be dropped and any
    /// action other than "Accept" became Drop).
    pub(crate) fn rule_to_core(
        id: Option<u64>,
        rule: &ApiFirewallRule,
    ) -> anyhow::Result<CoreFirewallRule> {
        let protocol = match rule.protocol.trim().to_ascii_lowercase().as_str() {
            "tcp" => Some(Protocol::Tcp),
            "udp" => Some(Protocol::Udp),
            "icmp" => Some(Protocol::Icmp),
            "any" | "all" | "" => None,
            other => anyhow::bail!("Invalid protocol {other:?} (tcp, udp, icmp or any)"),
        };
        let port = rule.port.trim();
        let dport = if port.is_empty() || port.eq_ignore_ascii_case("any") {
            None
        } else {
            let parse = |p: &str| {
                p.trim()
                    .parse::<u16>()
                    .ok()
                    .filter(|n| *n != 0)
                    .ok_or_else(|| anyhow::anyhow!("Invalid port {:?}", rule.port))
            };
            let spec = if let Some((lo, hi)) = port.split_once('-') {
                let (lo, hi) = (parse(lo)?, parse(hi)?);
                if lo > hi {
                    anyhow::bail!("Invalid port range {:?}", rule.port);
                }
                PortSpec::Range(lo, hi)
            } else if port.contains(',') {
                PortSpec::Multiple(port.split(',').map(parse).collect::<anyhow::Result<_>>()?)
            } else {
                PortSpec::Single(parse(port)?)
            };
            if !matches!(protocol, Some(Protocol::Tcp | Protocol::Udp)) {
                anyhow::bail!("Invalid rule: a port needs protocol tcp or udp");
            }
            Some(spec)
        };
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
        let (interface_in, interface_out) = match chain {
            ChainType::Output => (None, iface),
            _ => (iface, None),
        };
        let name = rule
            .name
            .clone()
            .filter(|n| !n.trim().is_empty())
            .unwrap_or_else(|| rule.description.clone());

        let core = CoreFirewallRule {
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
        };
        // Same validation the applier will run (injection-safe address,
        // interface, l4 checks), so a bad rule is a 400 before it is stored.
        let mut probe = core.clone();
        for f in [&mut probe.interface_in, &mut probe.interface_out] {
            if f.as_deref().is_some_and(|v| v.starts_with('@')) {
                *f = Some("probe0".into());
            }
        }
        probe.enabled = true;
        patronus_firewall::nftables::rule_to_nft_command(&probe)
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        Ok(core)
    }

    fn core_to_template(r: &CoreFirewallRule, origin: RuleOrigin) -> templates::FirewallRule {
        let protocol = r
            .protocol
            .as_ref()
            .map(|p| p.to_string())
            .unwrap_or_else(|| "any".into());
        let port = r
            .dport
            .as_ref()
            .map(|p| {
                p.to_string()
                    .trim_matches(|c| c == '{' || c == '}')
                    .to_string()
            })
            .unwrap_or_else(|| "any".into());
        let source = r.source.clone().unwrap_or_else(|| "any".into());
        let destination = r.destination.clone().unwrap_or_else(|| "any".into());
        let iface = r.interface_in.as_deref().or(r.interface_out.as_deref());
        let action = r.action.to_string();
        templates::FirewallRule {
            id: r.id.unwrap_or(0) as u32,
            name: r.name.clone(),
            action: format!("{}{}", action[..1].to_uppercase(), &action[1..]),
            interface: iface.unwrap_or("any").to_string(),
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
        }
    }

    fn nat_to_template(r: &CoreNatRule, origin: RuleOrigin) -> templates::NatRule {
        let (rule_type, target) = match &r.nat_type {
            NatType::Masquerade => ("MASQUERADE".to_string(), "masquerade".to_string()),
            NatType::Snat { to_address } => ("SNAT".into(), to_address.to_string()),
            NatType::Dnat {
                to_address,
                to_port,
            } => (
                "DNAT".into(),
                match to_port {
                    Some(p) => format!("{to_address}:{p}"),
                    None => to_address.to_string(),
                },
            ),
        };
        templates::NatRule {
            id: r.id.unwrap_or(0) as u32,
            rule_type,
            interface: display_iface(r.interface_out.as_deref()),
            source: r.source.clone().unwrap_or_else(|| "any".into()),
            destination: r.destination.clone().unwrap_or_else(|| "any".into()),
            target,
            description: r.comment.clone().unwrap_or_else(|| r.name.clone()),
            enabled: r.enabled,
            origin: origin.as_str().to_string(),
        }
    }

    fn e(e: patronus_core::Error) -> anyhow::Error {
        anyhow::anyhow!("{e}")
    }

    async fn push(&self) -> anyhow::Result<()> {
        self.applier
            .apply(&self.store)
            .await
            .map(|_| ())
            .map_err(|e| anyhow::anyhow!("failed to apply firewall to nftables: {e}"))
    }

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

    pub async fn add_rule(&self, rule: ApiFirewallRule) -> anyhow::Result<u32> {
        let core = Self::rule_to_core(None, &rule)?;
        let _g = self.edit.lock().await;
        let id = self
            .store
            .save_firewall_rule(&core)
            .await
            .map_err(Self::e)? as u64;
        if let Err(e) = self.push().await {
            let _ = self.store.delete_firewall_rule(id).await;
            return Err(e);
        }
        let _ = self
            .store
            .audit(
                "web",
                "create",
                "firewall_rule",
                Some(&id.to_string()),
                &serde_json::to_value(&core).unwrap_or_default(),
            )
            .await;
        Ok(id as u32)
    }

    /// Update a rule in the store and nftables together (an update used to
    /// edit only the dashboard list while nftables kept the old rule).
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
        self.store
            .update_firewall_rule(id as u64, &core)
            .await
            .map_err(Self::e)?;
        if let Err(e) = self.push().await {
            let _ = self.store.update_firewall_rule(id as u64, &old).await;
            return Err(e);
        }
        let _ = self
            .store
            .audit(
                "web",
                "update",
                "firewall_rule",
                Some(&id.to_string()),
                &serde_json::to_value(&core).unwrap_or_default(),
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
        self.store
            .delete_firewall_rule(id as u64)
            .await
            .map_err(Self::e)?;
        if let Err(e) = self.push().await {
            let _ = self.store.insert_firewall_rule(&old, origin).await;
            return Err(e);
        }
        let _ = self
            .store
            .audit(
                "web",
                "delete",
                "firewall_rule",
                Some(&id.to_string()),
                &serde_json::Value::Null,
            )
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

    pub async fn add_nat_rule(&self, rule: ApiNatRule) -> anyhow::Result<u32> {
        let nat_type = parse_nat_type(&rule.rule_type, &rule.target)
            .map_err(|e| anyhow::anyhow!("Invalid NAT rule: {e}"))?;
        let core = CoreNatRule {
            id: None,
            name: rule.description.clone(),
            enabled: rule.enabled,
            nat_type,
            source: any_or(&rule.source),
            destination: any_or(&rule.destination),
            protocol: None,
            dport: None,
            interface_out: interface_field(&rule.interface)?,
            comment: Some(rule.description.clone()).filter(|d| !d.is_empty()),
        };
        let mut probe = core.clone();
        if probe
            .interface_out
            .as_deref()
            .is_some_and(|v| v.starts_with('@'))
        {
            probe.interface_out = Some("probe0".into());
        }
        probe.enabled = true;
        patronus_firewall::nftables::nat_rule_to_nft_command(&probe)
            .map_err(|e| anyhow::anyhow!("{e}"))?;

        let _g = self.edit.lock().await;
        let id = self.store.save_nat_rule(&core).await.map_err(Self::e)? as u64;
        if let Err(e) = self.push().await {
            let _ = self.store.delete_nat_rule(id).await;
            return Err(e);
        }
        let _ = self
            .store
            .audit(
                "web",
                "create",
                "nat_rule",
                Some(&id.to_string()),
                &serde_json::to_value(&core).unwrap_or_default(),
            )
            .await;
        Ok(id as u32)
    }

    pub async fn delete_nat_rule(&self, id: u32) -> anyhow::Result<()> {
        let _g = self.edit.lock().await;
        let Some((old, origin)) = self
            .store
            .load_nat_rules_with_origin()
            .await
            .map_err(Self::e)?
            .into_iter()
            .find(|(r, _)| r.id == Some(id as u64))
        else {
            anyhow::bail!("NAT rule {id} not found");
        };
        self.store
            .delete_nat_rule(id as u64)
            .await
            .map_err(Self::e)?;
        if let Err(e) = self.push().await {
            let _ = self.store.insert_nat_rule(&old, origin).await;
            return Err(e);
        }
        Ok(())
    }

    /// Aliases are not implemented yet (lane B): an honest empty list
    /// instead of the two hard-coded sample aliases this used to return.
    pub async fn list_aliases(&self) -> anyhow::Result<Vec<templates::Alias>> {
        Ok(Vec::new())
    }
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
            protocol: "tcp".to_string(),
            source: source.to_string(),
            destination: "any".to_string(),
            port: "80".to_string(),
            description: "test rule".to_string(),
            enabled: true,
        }
    }

    fn sample_nat_rule(rule_type: &str, source: &str, target: &str) -> ApiNatRule {
        ApiNatRule {
            id: None,
            rule_type: rule_type.to_string(),
            interface: "eth0".to_string(),
            source: source.to_string(),
            destination: "any".to_string(),
            target: target.to_string(),
            description: "test nat rule".to_string(),
            enabled: true,
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
        fw.update_rule(id, upd).await.unwrap();
        assert_eq!(fw2.get_rule(id).await.unwrap().unwrap().port, "8080");
        fw.delete_rule(id).await.unwrap();
        assert!(fw2.list_rules().await.unwrap().is_empty());
        assert_eq!(a.applies.load(Ordering::SeqCst), 3);
    }

    /// a4d7bf96: an apply failure must surface as an error and leave the
    /// store as it was (no phantom rule, no lost rule).
    #[tokio::test]
    async fn apply_failure_is_reported_and_the_store_is_rolled_back() {
        let (fw, a, _) = fake().await;
        let keep = fw.add_rule(sample_rule("192.0.2.0/24")).await.unwrap();
        a.fail.store(true, Ordering::SeqCst);
        assert!(fw.add_rule(sample_rule("198.51.100.0/24")).await.is_err());
        assert_eq!(fw.list_rules().await.unwrap().len(), 1);
        let mut upd = sample_rule("192.0.2.0/24");
        upd.port = "9999".into();
        assert!(fw.update_rule(keep, upd).await.is_err());
        assert_eq!(fw.get_rule(keep).await.unwrap().unwrap().port, "80");
        assert!(fw.delete_rule(keep).await.is_err());
        assert_eq!(fw.list_rules().await.unwrap().len(), 1);
        assert!(fw
            .add_nat_rule(sample_nat_rule("MASQUERADE", "10.0.0.0/8", "masquerade"))
            .await
            .is_err());
        assert!(fw.list_nat_rules().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn system_rules_are_listed_but_cannot_be_deleted_or_edited() {
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
        let nat = fw.list_nat_rules().await.unwrap();
        assert_eq!(nat[0].interface, "WAN");
        assert_eq!(nat[0].rule_type, "MASQUERADE");
    }

    /// User rules used to lose protocol/port and flip any action other than
    /// the exact string "Accept" to Drop.
    #[test]
    fn rule_translation_keeps_protocol_port_action_chain_and_roles() {
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
            t("Accept", "TCP", "8080").unwrap().action,
            FirewallAction::Accept
        ));
        assert!(matches!(
            t("drop", "udp", "any").unwrap().action,
            FirewallAction::Drop
        ));
        assert!(matches!(
            t("reject", "tcp", "22").unwrap().action,
            FirewallAction::Reject
        ));
        assert!(matches!(
            t("accept", "tcp", "8000-8010").unwrap().dport,
            Some(PortSpec::Range(8000, 8010))
        ));
        for (a, p, port) in [
            ("acept", "tcp", "80"),
            ("accept", "sctp", "80"),
            ("accept", "tcp", "http"),
            ("accept", "tcp", "70000"),
            ("accept", "any", "80"),
            ("accept", "tcp", "90-80"),
        ] {
            let e = t(a, p, port).unwrap_err().to_string();
            assert!(e.contains("Invalid"), "{a}/{p}/{port}: {e}");
        }
        let mut r = sample_rule("any");
        r.interface = "@LAN".into();
        r.chain = Some("forward".into());
        let c = FirewallManager::rule_to_core(None, &r).unwrap();
        assert_eq!(c.chain, ChainType::Forward);
        assert_eq!(c.interface_in.as_deref(), Some("@lan"));
        assert_eq!(c.source, None);
        r.interface = "@dmz".into();
        assert!(FirewallManager::rule_to_core(None, &r).is_err());
        r.interface = "eth0\" accept #".into();
        assert!(FirewallManager::rule_to_core(None, &r).is_err());
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
        upd.action = "drop".into();
        upd.port = "9090".into();
        upd.description = marker.clone();
        fw.update_rule(id, upd).await.unwrap();
        let table = nft_table();
        let l = line(&table);
        assert!(l.contains("tcp dport 9090") && l.contains("drop"), "{l}");
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
}
