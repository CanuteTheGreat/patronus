//! BGP neighbor management

use crate::{config::NeighborConfig, error::Result};
use std::net::IpAddr;

/// BGP neighbor state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NeighborState {
    /// Idle state
    Idle,

    /// Connect state
    Connect,

    /// Active state
    Active,

    /// OpenSent state
    OpenSent,

    /// OpenConfirm state
    OpenConfirm,

    /// Established state
    Established,
}

/// BGP neighbor
#[derive(Debug)]
pub struct BgpNeighbor {
    /// Neighbor configuration
    config: NeighborConfig,

    /// Current state
    state: NeighborState,

    /// Peer IP address
    peer_ip: IpAddr,

    /// Remote AS number
    remote_asn: u32,
}

impl BgpNeighbor {
    /// Create a new BGP neighbor
    pub fn new(config: NeighborConfig) -> Self {
        let peer_ip = config.ip;
        let remote_asn = config.asn;

        Self {
            config,
            state: NeighborState::Idle,
            peer_ip,
            remote_asn,
        }
    }

    /// Get neighbor state
    pub fn state(&self) -> NeighborState {
        self.state
    }

    /// Get peer IP
    pub fn peer_ip(&self) -> IpAddr {
        self.peer_ip
    }

    /// Get remote ASN
    pub fn remote_asn(&self) -> u32 {
        self.remote_asn
    }

    /// Connect to neighbor (stub implementation)
    pub async fn connect(&mut self) -> Result<()> {
        // Stub: would establish TCP connection and send OPEN message
        self.state = NeighborState::Connect;
        Ok(())
    }

    /// Disconnect from neighbor (stub implementation)
    pub async fn disconnect(&mut self) -> Result<()> {
        // Stub: would send NOTIFICATION and close connection
        self.state = NeighborState::Idle;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_neighbor_creation() {
        let config = NeighborConfig {
            ip: IpAddr::from_str("10.0.0.1").unwrap(),
            asn: 65001,
            description: Some("Test neighbor".to_string()),
            password: None,
            timers: None,
            route_map_in: None,
            route_map_out: None,
            next_hop_self: false,
        };

        let neighbor = BgpNeighbor::new(config);

        assert_eq!(neighbor.state(), NeighborState::Idle);
        assert_eq!(neighbor.peer_ip(), IpAddr::from_str("10.0.0.1").unwrap());
        assert_eq!(neighbor.remote_asn(), 65001);
    }
}
