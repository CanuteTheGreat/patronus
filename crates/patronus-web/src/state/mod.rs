//! Application state, one adapter per subsystem.
//!
//! Convention (see AGENTS.md "Web UI"): every subsystem has its own
//! `state/<subsystem>.rs` holding a thin manager over the config store
//! ([`patronus_config::ConfigStore`]) plus that subsystem's
//! [`patronus_config::Applier`]: a mutation writes the store, runs the
//! applier, and undoes the store write if the applier fails, so the UI, the
//! store and the kernel never disagree. Lanes only touch their own file
//! here plus one field in [`AppState`].
//!
//! `firewall` is store-backed. `vpn`, `network`, `system` and `monitoring`
//! still hold in-memory fixtures that their lanes replace.

pub mod firewall;
pub mod monitoring;
pub mod network;
pub mod system;
pub mod vpn;

pub use firewall::FirewallManager;
pub use monitoring::MonitoringManager;
pub use network::NetworkManager;
pub use system::SystemManager;
pub use vpn::VpnManager;

use crate::auth::AuthState;
use patronus_config::{Applier, ConfigStore};
use patronus_secrets::SecretManager;
use std::sync::Arc;

/// Shared application state
#[derive(Clone)]
pub struct AppState {
    pub firewall: Arc<FirewallManager>,
    pub vpn: Arc<VpnManager>,
    pub network: Arc<NetworkManager>,
    pub system: Arc<SystemManager>,
    pub monitoring: Arc<MonitoringManager>,
    /// The persistent config store every subsystem adapter reads/writes.
    pub config_store: Arc<ConfigStore>,
    pub auth: AuthState,
    /// Secret storage + rotation. Backed by an in-memory store for now;
    /// swapping in `patronus_secrets::store::FileStore` plus a real
    /// master-key strategy is lane A/H follow-up work.
    pub secrets: Arc<SecretManager>,
}

impl AppState {
    /// Build the state over an opened store. `firewall_applier` is the
    /// applier firewall/NAT edits are pushed through
    /// (`patronus_firewall::FirewallApplier` in the shipped binary).
    pub async fn new(
        config_store: Arc<ConfigStore>,
        firewall_applier: Arc<dyn Applier>,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            firewall: Arc::new(FirewallManager::new(config_store.clone(), firewall_applier)),
            vpn: Arc::new(VpnManager::new()),
            network: Arc::new(NetworkManager::new()),
            system: Arc::new(SystemManager::new()),
            monitoring: Arc::new(MonitoringManager::new()),
            config_store,
            auth: AuthState::new(),
            secrets: Arc::new(SecretManager::new(Arc::new(
                patronus_secrets::store::MemoryStore::new(),
            ))),
        })
    }
}

/// What the shipped `patronus-web` (and `patronus web`) do at startup:
/// open the store, seed first-boot defaults if no boot unit ran yet (e.g.
/// in a container), push the stored firewall to the kernel, build state.
pub async fn startup(db: Option<std::path::PathBuf>) -> anyhow::Result<AppState> {
    let path = db.unwrap_or_else(patronus_config::store::default_db_path);
    let store = Arc::new(
        ConfigStore::open(&path)
            .await
            .map_err(|e| anyhow::anyhow!("config store {}: {e}", path.display()))?,
    );
    let bootstrap =
        patronus_config::Bootstrap::load(&patronus_config::defaults::default_bootstrap_path())
            .map_err(|e| anyhow::anyhow!("{e}"))?;
    let seeded = patronus_config::ensure_defaults(
        &store,
        bootstrap.as_ref(),
        &patronus_config::defaults::existing_interfaces(),
    )
    .await
    .map_err(|e| anyhow::anyhow!("seeding defaults: {e}"))?;
    for w in &seeded.warnings {
        tracing::warn!("{w}");
    }
    let applier: Arc<dyn Applier> = Arc::new(patronus_firewall::FirewallApplier);
    let report = applier
        .apply(&store)
        .await
        .map_err(|e| anyhow::anyhow!("failed to apply the stored firewall to nftables: {e}"))?;
    tracing::info!(
        "firewall applied from the store: {}",
        report.applied.join("; ")
    );
    AppState::new(store, applier).await
}
