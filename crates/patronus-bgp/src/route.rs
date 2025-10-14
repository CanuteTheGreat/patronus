//! BGP route types

use ipnetwork::{IpNetwork, Ipv4Network};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr};

/// BGP route
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BgpRoute {
    /// Destination prefix
    pub prefix: Ipv4Network,

    /// Next hop
    pub next_hop: Ipv4Addr,

    /// AS path (u16 for ASN)
    pub as_path: Vec<u16>,

    /// Local preference (default 100)
    pub local_pref: u32,

    /// MED (metric) (default 0)
    pub med: u32,

    /// Communities
    pub communities: Vec<String>,

    /// Origin (0=IGP, 1=EGP, 2=Incomplete)
    pub origin: u8,
}

/// Route origin
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum RouteOrigin {
    /// IGP
    Igp,

    /// EGP
    Egp,

    /// Incomplete
    Incomplete,
}

/// Route action
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RouteAction {
    /// Accept route
    Accept,

    /// Reject route
    Reject,

    /// Modify route
    Modify {
        /// Local preference to set
        local_pref: Option<u32>,

        /// MED to set
        med: Option<u32>,

        /// Communities to add
        add_communities: Vec<String>,
    },
}

impl BgpRoute {
    /// Create a new BGP route
    pub fn new(prefix: Ipv4Network, next_hop: Ipv4Addr, as_path: Vec<u16>) -> Self {
        Self {
            prefix,
            next_hop,
            as_path,
            local_pref: 100,
            med: 0,
            communities: Vec::new(),
            origin: 2, // Incomplete
        }
    }

    /// Set local preference
    pub fn with_local_pref(mut self, pref: u32) -> Self {
        self.local_pref = pref;
        self
    }

    /// Set MED
    pub fn with_med(mut self, med: u32) -> Self {
        self.med = med;
        self
    }

    /// Add community
    pub fn with_community(mut self, community: String) -> Self {
        self.communities.push(community);
        self
    }

    /// Set origin (0=IGP, 1=EGP, 2=Incomplete)
    pub fn with_origin(mut self, origin: u8) -> Self {
        self.origin = origin;
        self
    }

    /// Convert to generic IpNetwork (for compatibility)
    pub fn to_ip_network(&self) -> IpNetwork {
        IpNetwork::V4(self.prefix)
    }

    /// Get next hop as generic IpAddr (for compatibility)
    pub fn next_hop_ip(&self) -> IpAddr {
        IpAddr::V4(self.next_hop)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_create_route() {
        let prefix = Ipv4Network::from_str("192.168.0.0/16").unwrap();
        let next_hop = Ipv4Addr::from_str("10.0.0.1").unwrap();
        let as_path = vec![65001, 65002];

        let route = BgpRoute::new(prefix, next_hop, as_path.clone());

        assert_eq!(route.prefix, prefix);
        assert_eq!(route.next_hop, next_hop);
        assert_eq!(route.as_path, as_path);
        assert_eq!(route.local_pref, 100);
        assert_eq!(route.med, 0);
    }

    #[test]
    fn test_route_builder() {
        let route = BgpRoute::new(
            Ipv4Network::from_str("192.168.0.0/16").unwrap(),
            Ipv4Addr::from_str("10.0.0.1").unwrap(),
            vec![65001],
        )
        .with_local_pref(150)
        .with_med(50)
        .with_community("65001:100".to_string())
        .with_origin(0); // IGP

        assert_eq!(route.local_pref, 150);
        assert_eq!(route.med, 50);
        assert_eq!(route.communities, vec!["65001:100"]);
        assert_eq!(route.origin, 0);
    }
}
