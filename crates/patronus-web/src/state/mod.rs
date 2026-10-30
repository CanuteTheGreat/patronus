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
//! `firewall`, `interfaces`, `routing` and `lan` are store-backed. `vpn`, `network`,
//! `system` and `monitoring` read live system state (wg/swanctl, ip route,
//! systemd/OpenRC, /proc, backup files); their lanes add the store-backed
//! configuration. No subsystem may show fixture rows: an empty system shows
//! an empty list (see tests/no_fixtures.rs).

pub mod firewall;
pub mod fwfeeds;
pub mod fwlog;
pub mod host;
pub mod interfaces;
pub mod lan;
pub mod monitoring;
pub mod network;
pub mod routing;
#[cfg(feature = "segmentation")]
pub mod segmentation;
#[cfg(feature = "wifi-ap")]
pub mod segmentation_wifi;
pub mod system;
pub mod telemetry;
pub mod tunnels;
pub mod vpn;

pub use firewall::FirewallManager;
pub use interfaces::InterfacesManager;
pub use lan::LanManager;
pub use monitoring::MonitoringManager;
pub use network::NetworkManager;
pub use routing::RoutingManager;
pub use system::SystemManager;
pub use tunnels::TunnelsManager;
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
    /// Gateways, gateway groups, default gateway, static routes (lane E).
    pub routing: Arc<RoutingManager>,
    /// Live VPN state (wg show / swanctl --list-sas).
    pub vpn: Arc<VpnManager>,
    /// WireGuard tunnels/peers and IPsec tunnels (lane F).
    pub tunnels: Arc<TunnelsManager>,
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
    /// Remote / encrypted automatic backups.
    pub backup_targets: crate::backup_remote::BackupTargets,
}

impl AppState {
    /// Build the state over an opened store. `firewall_applier` is the
    /// applier firewall/NAT edits are pushed through
    /// (`patronus_firewall::FirewallApplier` in the shipped binary).
    pub async fn new(
        config_store: Arc<ConfigStore>,
        firewall_applier: Arc<dyn Applier>,
    ) -> anyhow::Result<Self> {
        let tunnels = Arc::new(TunnelsManager::new(
            config_store.clone(),
            firewall_applier.clone(),
        ));
        Ok(Self {
            interfaces: Arc::new(InterfacesManager::system(
                config_store.clone(),
                firewall_applier.clone(),
            )),
            firewall: Arc::new(FirewallManager::new(
                config_store.clone(),
                firewall_applier.clone(),
            )),
            lan: Arc::new(
                LanManager::new(config_store.clone()).with_firewall(firewall_applier.clone()),
            ),
            routing: Arc::new(RoutingManager::new(
                config_store.clone(),
                firewall_applier.clone(),
            )),
            vpn: Arc::new(VpnManager::with_ipsec(
                config_store.clone(),
                tunnels.ipsec_applier(),
            )),
            tunnels,
            network: Arc::new(NetworkManager::new()),
            system: Arc::new(
                SystemManager::new(system::backup_dir_for(config_store.path()))
                    .with_appliers(all_appliers(firewall_applier.clone())),
            ),
            monitoring: Arc::new(MonitoringManager::new()),
            auth: AuthState::new(config_store.clone()),
            backup_targets: crate::backup_remote::BackupTargets::new(config_store.clone()),
            config_store,
            secrets: Arc::new(SecretManager::new(Arc::new(
                patronus_secrets::store::MemoryStore::new(),
            ))),
        })
    }
}

/// Every subsystem applier patronus-web can drive (each through `patronus
/// applyd` when its socket exists), for applying a restored backup to the
/// whole system. `firewall` is the firewall applier the state uses.
pub fn all_appliers(firewall: Arc<dyn Applier>) -> Vec<Arc<dyn Applier>> {
    use patronus_network::applyd::RemoteApplier;
    let mut v: Vec<Arc<dyn Applier>> = vec![
        RemoteApplier::wrap(Arc::new(patronus_network::SysctlApplier::default())),
        RemoteApplier::wrap(Arc::new(patronus_network::InterfacesApplier::default())),
        RemoteApplier::wrap(Arc::new(patronus_network::RoutesApplier::default())),
        firewall,
    ];
    v.extend(
        patronus_network::lan::appliers()
            .into_iter()
            .chain(patronus_network::vpn_appliers())
            .map(RemoteApplier::wrap),
    );
    v
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
    // then static routes / the default gateway (lane E), likewise not fatal
    match state.routing.apply().await {
        Ok(r) => tracing::info!("routes applied from the store: {}", r.join("; ")),
        Err(e) => tracing::error!("routes: {e}"),
    }
    state.routing.spawn_local_monitor();
    // WireGuard tunnels (lane F, interfaces phase), likewise not fatal
    if state.tunnels.has(tunnels::Kind::WireGuard) {
        match state.tunnels.reapply(tunnels::Kind::WireGuard).await {
            Ok(r) => tracing::info!("WireGuard applied from the store: {}", r.join("; ")),
            Err(e) => tracing::error!("WireGuard: {e}"),
        }
    }
    let report = applier
        .apply(&store)
        .await
        .map_err(|e| anyhow::anyhow!("failed to apply the stored firewall to nftables: {e}"))?;
    tracing::info!(
        "firewall applied from the store: {}",
        report.applied.join("; ")
    );
    // IPsec (lane F, services phase): only when tunnels exist -- with none
    // configured the applier leaves strongSwan alone anyway
    if state.tunnels.has(tunnels::Kind::Ipsec) {
        if let Err(e) = state.tunnels.reapply(tunnels::Kind::Ipsec).await {
            tracing::error!("IPsec: {e}");
        }
    }
    // scheduled rules switch on/off on time (re-apply on a window edge)
    firewall::spawn_schedule_task(state.firewall.clone());
    // URL tables, GeoIP sets and threat feeds refresh themselves
    fwfeeds::spawn_feed_task(state.firewall.clone());
    // NFLOG collector behind the firewall log viewer
    fwlog::spawn_collector(state.firewall.clone());
    // gateway / tunnel / HA / configuration events for the event log and webhooks
    telemetry::spawn_watcher(state.clone());
    Ok(state)
}
