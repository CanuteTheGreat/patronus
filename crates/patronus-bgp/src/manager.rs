//! BGP manager

use crate::{config::BgpConfig, error::Result, neighbor::BgpNeighbor, route::BgpRoute};
use std::collections::HashMap;
use std::net::IpAddr;

/// BGP manager
pub struct BgpManager {
    /// Configuration
    config: BgpConfig,

    /// Neighbors
    neighbors: HashMap<IpAddr, BgpNeighbor>,

    /// Routing table
    routes: Vec<BgpRoute>,
}

impl BgpManager {
    /// Create a new BGP manager
    pub fn new(config: BgpConfig) -> Self {
        let mut neighbors = HashMap::new();

        for neighbor_config in &config.neighbors {
            let neighbor = BgpNeighbor::new(neighbor_config.clone());
            neighbors.insert(neighbor_config.ip, neighbor);
        }

        Self {
            config,
            neighbors,
            routes: Vec::new(),
        }
    }

    /// Start BGP manager
    pub async fn start(&mut self) -> Result<()> {
        // Stub: would start all neighbor connections
        for neighbor in self.neighbors.values_mut() {
            neighbor.connect().await?;
        }
        Ok(())
    }

    /// Stop BGP manager
    pub async fn stop(&mut self) -> Result<()> {
        // Stub: would stop all neighbor connections
        for neighbor in self.neighbors.values_mut() {
            neighbor.disconnect().await?;
        }
        Ok(())
    }

    /// Get routes
    pub fn routes(&self) -> &[BgpRoute] {
        &self.routes
    }

    /// Get neighbors
    pub fn neighbors(&self) -> &HashMap<IpAddr, BgpNeighbor> {
        &self.neighbors
    }

    /// Get ASN
    pub fn asn(&self) -> u32 {
        self.config.asn
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{NeighborConfig, NetworkConfig, TimersConfig};
    use std::str::FromStr;

    #[test]
    fn test_manager_creation() {
        let config = BgpConfig {
            asn: 65001,
            router_id: IpAddr::from_str("10.0.0.1").unwrap(),
            neighbors: vec![NeighborConfig {
                ip: IpAddr::from_str("10.0.0.2").unwrap(),
                asn: 65002,
                description: None,
                password: None,
                timers: None,
                route_map_in: None,
                route_map_out: None,
                next_hop_self: false,
            }],
            networks: vec![],
            route_maps: vec![],
            timers: TimersConfig::default(),
        };

        let manager = BgpManager::new(config);

        assert_eq!(manager.asn(), 65001);
        assert_eq!(manager.neighbors().len(), 1);
        assert_eq!(manager.routes().len(), 0);
    }
}
