//! The Applier contract: how a subsystem turns store rows into kernel /
//! daemon state.
//!
//! Every subsystem (sysctl, interfaces, VLANs, routes, firewall/NAT, DHCP,
//! DNS, VPN, HA, ...) implements [`Applier`] once, in the crate that owns
//! the subsystem (`patronus-firewall`, `patronus-network`, ...). The same
//! implementation is used by
//! - `patronus apply` at boot (all appliers, in [`Phase`] order),
//! - the web UI / API after every change (just that subsystem's applier),
//! - the declarative/GitOps engine ([`crate::apply::ApplyEngine`]), which
//!   dispatches resources to the applier that claims their kind.
//!
//! Rules for implementers (also in AGENTS.md):
//! 1. `apply` is **full-state and idempotent**: read everything the
//!    subsystem owns from the store and make the system match it. Never
//!    apply deltas; running it twice in a row must be a no-op.
//! 2. Be **atomic where the backend allows it** (one `nft -f` transaction,
//!    write config to a temp file and rename, then reload the daemon).
//! 3. **Fail closed**: on error, leave the previous working state (or a
//!    safe lockdown state), never a half-applied or wide-open one.
//! 4. Return what was done in an [`ApplyReport`]; return `Err` only when the
//!    subsystem could not be brought to the desired state.

use crate::declarative::{DeclarativeConfig, ResourceKind};
use crate::store::ConfigStore;
use async_trait::async_trait;
use patronus_core::{Error, Result};
use serde::Serialize;
use std::sync::Arc;

/// Boot/apply order. Lower phases are applied first; within a phase,
/// appliers run in registration order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Phase {
    /// Kernel sysctls (ip_forward v4/v6, rp_filter, ...). Lane A.
    Sysctl = 10,
    /// Interfaces, addresses, VLANs, bonds, bridges, PPPoE. Lane C.
    Interfaces = 20,
    /// Static routes, gateways, gateway groups, policy routing. Lane E.
    Routes = 30,
    /// nftables filter + NAT (and sets fed by aliases/threat intel). Lane B.
    Firewall = 40,
    /// Daemons: DHCP, DNS, VPN, HA, IDS, ... Lanes D, F, G, J.
    Services = 50,
}

impl Phase {
    pub const ALL: [Phase; 5] = [
        Phase::Sysctl,
        Phase::Interfaces,
        Phase::Routes,
        Phase::Firewall,
        Phase::Services,
    ];

    pub fn as_str(&self) -> &'static str {
        match self {
            Phase::Sysctl => "sysctl",
            Phase::Interfaces => "interfaces",
            Phase::Routes => "routes",
            Phase::Firewall => "firewall",
            Phase::Services => "services",
        }
    }

    pub fn parse(s: &str) -> Option<Phase> {
        Phase::ALL.into_iter().find(|p| p.as_str() == s)
    }
}

/// What one applier did.
#[derive(Debug, Clone, Default, Serialize, serde::Deserialize)]
pub struct ApplyReport {
    /// Human-readable lines describing what was applied.
    pub applied: Vec<String>,
    /// Non-fatal problems (a rule skipped because its interface role is
    /// unassigned, a per-interface sysctl for a device that doesn't exist).
    pub warnings: Vec<String>,
}

impl ApplyReport {
    pub fn applied(&mut self, s: impl Into<String>) {
        self.applied.push(s.into());
    }
    pub fn warn(&mut self, s: impl Into<String>) {
        let s = s.into();
        tracing::warn!("{s}");
        self.warnings.push(s);
    }
}

/// A subsystem that can bring the system in line with the store.
#[async_trait]
pub trait Applier: Send + Sync {
    /// Short stable name (`"sysctl"`, `"firewall"`, `"dhcp"`, ...).
    fn name(&self) -> &'static str;

    /// Which boot phase this applier belongs to.
    fn phase(&self) -> Phase;

    /// Make the system match the store for this subsystem (full state,
    /// idempotent, atomic where possible, fail closed).
    async fn apply(&self, store: &ConfigStore) -> Result<ApplyReport>;

    /// Show what `apply` would do without touching the system (the
    /// rendered nft script, the sysctl list, the daemon config file...).
    async fn render(&self, store: &ConfigStore) -> Result<String>;

    /// Live state for the UI (daemon running, DHCP leases, ...), read with
    /// the applier's privileges (via `patronus applyd` when the caller is
    /// the unprivileged web UI). Default: nothing to report.
    async fn status(&self, _store: &ConfigStore) -> Result<serde_json::Value> {
        Ok(serde_json::Value::Null)
    }

    /// Remove everything this applier manages (e.g. `patronus firewall
    /// flush`). Default: nothing to tear down.
    async fn teardown(&self) -> Result<()> {
        Ok(())
    }

    /// Declarative resource kinds this applier owns (GitOps dispatch).
    fn resource_kinds(&self) -> &'static [ResourceKind] {
        &[]
    }

    /// Store a declarative resource (create or replace by name). Only
    /// called for kinds listed in [`resource_kinds`](Self::resource_kinds);
    /// the engine calls [`apply`](Self::apply) once afterwards.
    async fn upsert_resource(
        &self,
        _store: &ConfigStore,
        config: &DeclarativeConfig,
    ) -> Result<()> {
        Err(Error::Config(format!(
            "{} does not handle declarative {:?} resources",
            self.name(),
            config.kind
        )))
    }

    /// Delete a declarative resource by name.
    async fn delete_resource(
        &self,
        _store: &ConfigStore,
        kind: &ResourceKind,
        _name: &str,
    ) -> Result<()> {
        Err(Error::Config(format!(
            "{} does not handle declarative {kind:?} resources",
            self.name()
        )))
    }
}

/// Outcome of one applier inside [`ApplierRegistry::apply_all`].
#[derive(Debug, Clone, Serialize)]
pub struct ApplierOutcome {
    pub applier: &'static str,
    pub phase: Phase,
    pub report: Option<ApplyReport>,
    pub error: Option<String>,
}

/// Outcome of a whole apply run.
#[derive(Debug, Clone, Default, Serialize)]
pub struct ApplyRunReport {
    pub outcomes: Vec<ApplierOutcome>,
}

impl ApplyRunReport {
    pub fn ok(&self) -> bool {
        self.outcomes.iter().all(|o| o.error.is_none())
    }
    pub fn failures(&self) -> Vec<&ApplierOutcome> {
        self.outcomes.iter().filter(|o| o.error.is_some()).collect()
    }
}

/// The set of appliers a binary knows about. Built once per binary (see
/// `patronus-cli/src/commands/apply.rs::registry`).
#[derive(Default, Clone)]
pub struct ApplierRegistry {
    appliers: Vec<Arc<dyn Applier>>,
}

impl ApplierRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an applier (builder style).
    pub fn with(mut self, a: impl Applier + 'static) -> Self {
        self.register(Arc::new(a));
        self
    }

    pub fn register(&mut self, a: Arc<dyn Applier>) {
        self.appliers.push(a);
    }

    /// Add several appliers (builder style), e.g. every LAN service a
    /// feature-gated crate compiled in.
    pub fn with_all(mut self, v: impl IntoIterator<Item = Arc<dyn Applier>>) -> Self {
        for a in v {
            self.register(a);
        }
        self
    }

    /// All appliers in apply order (phase, then registration order).
    pub fn ordered(&self) -> Vec<Arc<dyn Applier>> {
        let mut v: Vec<(usize, Arc<dyn Applier>)> =
            self.appliers.iter().cloned().enumerate().collect();
        v.sort_by_key(|(i, a)| (a.phase(), *i));
        v.into_iter().map(|(_, a)| a).collect()
    }

    pub fn by_name(&self, name: &str) -> Option<Arc<dyn Applier>> {
        self.appliers.iter().find(|a| a.name() == name).cloned()
    }

    /// The applier that owns declarative `kind`, if any.
    pub fn for_kind(&self, kind: &ResourceKind) -> Option<Arc<dyn Applier>> {
        self.appliers
            .iter()
            .find(|a| a.resource_kinds().contains(kind))
            .cloned()
    }

    /// Apply every applier whose phase is in `phases` (all if `None`), in
    /// order. A failing applier does not stop later ones: a broken DHCP
    /// config must not keep the firewall from loading at boot.
    pub async fn apply_all(&self, store: &ConfigStore, phases: Option<&[Phase]>) -> ApplyRunReport {
        let mut run = ApplyRunReport::default();
        for a in self.ordered() {
            if let Some(p) = phases {
                if !p.contains(&a.phase()) {
                    continue;
                }
            }
            tracing::info!("applying {} ({})", a.name(), a.phase().as_str());
            let outcome = match a.apply(store).await {
                Ok(report) => ApplierOutcome {
                    applier: a.name(),
                    phase: a.phase(),
                    report: Some(report),
                    error: None,
                },
                Err(e) => {
                    tracing::error!("{} failed: {e}", a.name());
                    ApplierOutcome {
                        applier: a.name(),
                        phase: a.phase(),
                        report: None,
                        error: Some(e.to_string()),
                    }
                }
            };
            run.outcomes.push(outcome);
        }
        run
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    struct Rec {
        name: &'static str,
        phase: Phase,
        log: Arc<Mutex<Vec<&'static str>>>,
        fail: bool,
    }

    #[async_trait]
    impl Applier for Rec {
        fn name(&self) -> &'static str {
            self.name
        }
        fn phase(&self) -> Phase {
            self.phase
        }
        async fn apply(&self, _s: &ConfigStore) -> Result<ApplyReport> {
            self.log.lock().unwrap().push(self.name);
            if self.fail {
                return Err(Error::Config("boom".into()));
            }
            Ok(ApplyReport::default())
        }
        async fn render(&self, _s: &ConfigStore) -> Result<String> {
            Ok(String::new())
        }
    }

    #[tokio::test]
    async fn applies_in_dependency_order_and_continues_past_failures() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let mk = |name, phase, fail| Rec {
            name,
            phase,
            log: log.clone(),
            fail,
        };
        // Registered out of order on purpose.
        let reg = ApplierRegistry::new()
            .with(mk("dhcp", Phase::Services, false))
            .with(mk("firewall", Phase::Firewall, false))
            .with(mk("routes", Phase::Routes, true))
            .with(mk("sysctl", Phase::Sysctl, false))
            .with(mk("interfaces", Phase::Interfaces, false));
        let store = ConfigStore::open_in_memory().await.unwrap();
        let run = reg.apply_all(&store, None).await;
        assert_eq!(
            *log.lock().unwrap(),
            vec!["sysctl", "interfaces", "routes", "firewall", "dhcp"]
        );
        assert!(!run.ok());
        assert_eq!(run.failures()[0].applier, "routes");

        log.lock().unwrap().clear();
        let run = reg.apply_all(&store, Some(&[Phase::Firewall])).await;
        assert!(run.ok());
        assert_eq!(*log.lock().unwrap(), vec!["firewall"]);
    }
}
