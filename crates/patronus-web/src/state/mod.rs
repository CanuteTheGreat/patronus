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
//! `firewall`, `interfaces` and `lan` are store-backed. `vpn`, `network`,
//! `system` and `monitoring` read live system state (wg/swanctl, ip route,
//! systemd/OpenRC, /proc, backup files); their lanes add the store-backed
//! configuration. No subsystem may show fixture rows: an empty system shows
//! an empty list (see tests/no_fixtures.rs).

pub mod firewall;
pub mod host;
pub mod interfaces;
pub mod lan;
pub mod monitoring;
pub mod network;
pub mod system;
pub mod vpn;

pub use firewall::FirewallManager;
pub use interfaces::InterfacesManager;
pub use lan::LanManager;
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
    /// Interfaces & L2 (lane C): roles, addressing, VLAN/bond/bridge/PPPoE.
    pub interfaces: Arc<InterfacesManager>,
    /// DHCP / DNS / NTP / DDNS (lane D).
    pub lan: Arc<LanManager>,
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
            interfaces: Arc::new(InterfacesManager::system(
                config_store.clone(),
                firewall_applier.clone(),
            )),
            firewall: Arc::new(FirewallManager::new(config_store.clone(), firewall_applier)),
            lan: Arc::new(LanManager::new(config_store.clone())),
            vpn: Arc::new(VpnManager::new()),
            network: Arc::new(NetworkManager::new()),
            system: Arc::new(SystemManager::new(system::backup_dir_for(
                config_store.path(),
            ))),
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
    let state = AppState::new(store.clone(), applier.clone()).await?;
    // Interfaces before the firewall (boot phase order). A failure here is
    // logged, not fatal: the UI must come up to fix it.
    match state.interfaces.apply().await {
        Ok(r) => tracing::info!(
            "interfaces applied from the store: {}",
            r.applied.join("; ")
        ),
        Err(e) => tracing::error!("{e}"),
    }
    let report = applier
        .apply(&store)
        .await
        .map_err(|e| anyhow::anyhow!("failed to apply the stored firewall to nftables: {e}"))?;
    tracing::info!(
        "firewall applied from the store: {}",
        report.applied.join("; ")
    );
    // scheduled rules switch on/off on time (re-apply on a window edge)
    firewall::spawn_schedule_task(state.firewall.clone());
    Ok(state)
}
