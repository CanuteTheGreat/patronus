//! BGP route types

use ipnetwork::IpNetwork;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// BGP route
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BgpRoute {
    /// Destination prefix
    pub prefix: IpNetwork,

    /// Next hop
    pub next_hop: IpAddr,

    /// AS path
    pub as_path: Vec<u32>,

    /// Local preference
    pub local_pref: Option<u32>,

    /// MED (metric)
    pub med: Option<u32>,

    /// Communities
    pub communities: Vec<String>,

    /// Origin
    pub origin: RouteOrigin,
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
    pub fn new(prefix: IpNetwork, next_hop: IpAddr, as_path: Vec<u32>) -> Self {
        Self {
            prefix,
            next_hop,
            as_path,
            local_pref: None,
            med: None,
            communities: Vec::new(),
            origin: RouteOrigin::Incomplete,
        }
    }

    /// Set local preference
    pub fn with_local_pref(mut self, pref: u32) -> Self {
        self.local_pref = Some(pref);
        self
    }

    /// Set MED
    pub fn with_med(mut self, med: u32) -> Self {
        self.med = Some(med);
        self
    }

    /// Add community
    pub fn with_community(mut self, community: String) -> Self {
        self.communities.push(community);
        self
    }

    /// Set origin
    pub fn with_origin(mut self, origin: RouteOrigin) -> Self {
        self.origin = origin;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_create_route() {
        let prefix = IpNetwork::from_str("192.168.0.0/16").unwrap();
        let next_hop = IpAddr::from_str("10.0.0.1").unwrap();
        let as_path = vec![65001, 65002];

        let route = BgpRoute::new(prefix, next_hop, as_path.clone());

        assert_eq!(route.prefix, prefix);
        assert_eq!(route.next_hop, next_hop);
        assert_eq!(route.as_path, as_path);
    }

    #[test]
    fn test_route_builder() {
        let route = BgpRoute::new(
            IpNetwork::from_str("192.168.0.0/16").unwrap(),
            IpAddr::from_str("10.0.0.1").unwrap(),
            vec![65001],
        )
        .with_local_pref(100)
        .with_med(50)
        .with_community("65001:100".to_string())
        .with_origin(RouteOrigin::Igp);

        assert_eq!(route.local_pref, Some(100));
        assert_eq!(route.med, Some(50));
        assert_eq!(route.communities, vec!["65001:100"]);
        assert_eq!(route.origin, RouteOrigin::Igp);
    }
}
