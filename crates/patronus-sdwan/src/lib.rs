//! Patronus SD-WAN
//!
//! Software-Defined Wide Area Networking for Patronus firewall.
//!
//! # Features
//!
//! - Automatic mesh VPN peering between sites
//! - Real-time path quality monitoring
//! - Intelligent routing based on application requirements
//! - Sub-second failover on path degradation
//! - Load balancing across multiple paths
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────┐    ┌──────────────┐    ┌─────────────┐
//! │   Mesh      │───▶│   Monitor    │───▶│   Routing   │
//! │   Manager   │    │   (Paths)    │    │   Engine    │
//! └─────────────┘    └──────────────┘    └─────────────┘
//!       │                    │                    │
//!       └────────────────────┴────────────────────┘
//!                            │
//!                     ┌──────▼──────┐
//!                     │  Database   │
//!                     └─────────────┘
//! ```

pub mod mesh;
pub mod monitor;
pub mod routing;
pub mod types;
pub mod policy;
pub mod database;
pub mod error;
pub mod peering;
pub mod netpolicy;
pub mod metrics;
pub mod traffic_stats;
pub mod health;
pub mod failover;
pub mod export;
pub mod compression;
pub mod dataplane;
pub mod dpi;
pub mod sla;
pub mod qos;

pub use error::{Error, Result};
pub use types::{SiteId, PathId, FlowKey};

use std::sync::Arc;

/// SD-WAN manager coordinating all components
pub struct SdwanManager {
    mesh: Arc<mesh::MeshManager>,
    monitor: Arc<monitor::PathMonitor>,
    routing: Arc<routing::RoutingEngine>,
    db: Arc<database::Database>,
}

impl SdwanManager {
    /// Create a new SD-WAN manager
    pub async fn new(config: SdwanConfig) -> Result<Self> {
        let db = Arc::new(database::Database::new(&config.database_path).await?);

        let mesh = Arc::new(mesh::MeshManager::new(
            config.site_id.clone(),
            config.site_name.clone(),
            db.clone(),
        ));

        let monitor = Arc::new(monitor::PathMonitor::new(db.clone()));
        let routing = Arc::new(routing::RoutingEngine::new(db.clone()));

        Ok(Self {
            mesh,
            monitor,
            routing,
            db,
        })
    }

    /// Start the SD-WAN manager
    pub async fn start(&self) -> Result<()> {
        tracing::info!("Starting SD-WAN manager");

        // Start mesh manager (site discovery and peering)
        self.mesh.start().await?;

        // Start path monitoring
        self.monitor.start().await?;

        // Start routing engine
        self.routing.start().await?;

        tracing::info!("SD-WAN manager started successfully");
        Ok(())
    }

    /// Stop the SD-WAN manager
    pub async fn stop(&self) -> Result<()> {
        tracing::info!("Stopping SD-WAN manager");

        self.routing.stop().await?;
        self.monitor.stop().await?;
        self.mesh.stop().await?;

        tracing::info!("SD-WAN manager stopped");
        Ok(())
    }

    /// Get mesh manager
    pub fn mesh(&self) -> &Arc<mesh::MeshManager> {
        &self.mesh
    }

    /// Get path monitor
    pub fn monitor(&self) -> &Arc<monitor::PathMonitor> {
        &self.monitor
    }

    /// Get routing engine
    pub fn routing(&self) -> &Arc<routing::RoutingEngine> {
        &self.routing
    }
}

/// SD-WAN configuration
#[derive(Clone, Debug)]
pub struct SdwanConfig {
    /// Unique site identifier
    pub site_id: SiteId,

    /// Human-readable site name
    pub site_name: String,

    /// Database file path
    pub database_path: String,

    /// Seed sites for bootstrapping
    pub seed_sites: Vec<String>,

    /// Control plane listen address
    pub control_plane_addr: std::net::SocketAddr,
}

impl Default for SdwanConfig {
    fn default() -> Self {
        Self {
            site_id: SiteId::generate(),
            site_name: "default-site".to_string(),
            database_path: "/var/lib/patronus/sdwan.db".to_string(),
            seed_sites: Vec::new(),
            control_plane_addr: "0.0.0.0:51821".parse().unwrap(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_sdwan_manager_creation() {
        let config = SdwanConfig {
            database_path: ":memory:".to_string(),
            ..Default::default()
        };

        let manager = SdwanManager::new(config).await;
        assert!(manager.is_ok());
    }
}
