//! BGP Routing Information Base (RIB)
//!
//! Manages learned routes and performs best path selection.

use crate::route::BgpRoute;
use ipnetwork::Ipv4Network;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::{Arc, RwLock};
use tracing::{debug, info};

/// BGP Routing Information Base
pub struct Rib {
    /// Routes indexed by prefix
    routes: Arc<RwLock<HashMap<Ipv4Network, Vec<BgpRoute>>>>,

    /// Best routes (after path selection)
    best_routes: Arc<RwLock<HashMap<Ipv4Network, BgpRoute>>>,

    /// Local AS number
    local_asn: u16,
}

impl Rib {
    /// Create a new RIB
    pub fn new(local_asn: u16) -> Self {
        Self {
            routes: Arc::new(RwLock::new(HashMap::new())),
            best_routes: Arc::new(RwLock::new(HashMap::new())),
            local_asn,
        }
    }

    /// Add or update a route
    pub fn add_route(&self, route: BgpRoute) -> Result<(), String> {
        let prefix = route.prefix;

        debug!("Adding route to RIB: {} via {}", prefix, route.next_hop);

        let mut routes = self.routes.write().unwrap();
        let prefix_routes = routes.entry(prefix).or_insert_with(Vec::new);

        // Check if route already exists (update if so)
        if let Some(existing) = prefix_routes.iter_mut().find(|r| r.next_hop == route.next_hop) {
            *existing = route.clone();
        } else {
            prefix_routes.push(route.clone());
        }

        // Re-run best path selection for this prefix
        drop(routes);
        self.select_best_path(prefix);

        Ok(())
    }

    /// Remove a route
    pub fn remove_route(&self, prefix: Ipv4Network, next_hop: Ipv4Addr) -> Result<(), String> {
        debug!("Removing route from RIB: {} via {}", prefix, next_hop);

        let mut routes = self.routes.write().unwrap();

        if let Some(prefix_routes) = routes.get_mut(&prefix) {
            prefix_routes.retain(|r| r.next_hop != next_hop);

            if prefix_routes.is_empty() {
                routes.remove(&prefix);
                self.best_routes.write().unwrap().remove(&prefix);
                info!("Removed last route for prefix {}", prefix);
            } else {
                // Re-run best path selection
                drop(routes);
                self.select_best_path(prefix);
            }
        }

        Ok(())
    }

    /// Select best path for a prefix using BGP decision process
    fn select_best_path(&self, prefix: Ipv4Network) {
        let routes = self.routes.read().unwrap();

        if let Some(prefix_routes) = routes.get(&prefix) {
            if prefix_routes.is_empty() {
                return;
            }

            // BGP best path selection algorithm (simplified)
            // 1. Prefer route with highest local preference
            // 2. Prefer route with shortest AS path
            // 3. Prefer route with lowest origin type (IGP < EGP < Incomplete)
            // 4. Prefer route with lowest MED
            // 5. Prefer eBGP over iBGP
            // 6. Prefer route with lowest IGP cost to next hop
            // 7. Prefer route from router with lowest router ID

            let mut best = prefix_routes[0].clone();

            for route in prefix_routes.iter().skip(1) {
                // Step 1: Local preference (higher is better)
                if route.local_pref > best.local_pref {
                    best = route.clone();
                    continue;
                } else if route.local_pref < best.local_pref {
                    continue;
                }

                // Step 2: AS path length (shorter is better)
                if route.as_path.len() < best.as_path.len() {
                    best = route.clone();
                    continue;
                } else if route.as_path.len() > best.as_path.len() {
                    continue;
                }

                // Step 4: MED (lower is better)
                if route.med < best.med {
                    best = route.clone();
                    continue;
                }
            }

            info!("Selected best path for {}: via {} (AS path len: {})",
                  prefix, best.next_hop, best.as_path.len());

            self.best_routes.write().unwrap().insert(prefix, best);
        }
    }

    /// Get best route for a prefix
    pub fn get_best_route(&self, prefix: &Ipv4Network) -> Option<BgpRoute> {
        self.best_routes.read().unwrap().get(prefix).cloned()
    }

    /// Get all routes for a prefix
    pub fn get_routes(&self, prefix: &Ipv4Network) -> Vec<BgpRoute> {
        self.routes.read().unwrap()
            .get(prefix)
            .cloned()
            .unwrap_or_default()
    }

    /// Get all best routes
    pub fn get_all_best_routes(&self) -> Vec<BgpRoute> {
        self.best_routes.read().unwrap()
            .values()
            .cloned()
            .collect()
    }

    /// Longest prefix match lookup
    pub fn lookup(&self, ip: Ipv4Addr) -> Option<BgpRoute> {
        let best_routes = self.best_routes.read().unwrap();

        let mut best_match: Option<(Ipv4Network, BgpRoute)> = None;

        for (prefix, route) in best_routes.iter() {
            if prefix.contains(ip) {
                if let Some((best_prefix, _)) = &best_match {
                    // Keep the more specific prefix (longer prefix length)
                    if prefix.prefix() > best_prefix.prefix() {
                        best_match = Some((*prefix, route.clone()));
                    }
                } else {
                    best_match = Some((*prefix, route.clone()));
                }
            }
        }

        best_match.map(|(_, route)| route)
    }

    /// Get total number of routes
    pub fn route_count(&self) -> usize {
        self.routes.read().unwrap()
            .values()
            .map(|v| v.len())
            .sum()
    }

    /// Get number of unique prefixes
    pub fn prefix_count(&self) -> usize {
        self.routes.read().unwrap().len()
    }

    /// Clear all routes
    pub fn clear(&self) {
        self.routes.write().unwrap().clear();
        self.best_routes.write().unwrap().clear();
        info!("Cleared all routes from RIB");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn create_test_route(prefix: &str, next_hop: &str, as_path: Vec<u16>) -> BgpRoute {
        BgpRoute {
            prefix: Ipv4Network::from_str(prefix).unwrap(),
            next_hop: Ipv4Addr::from_str(next_hop).unwrap(),
            as_path,
            local_pref: 100,
            med: 0,
            origin: 0,
            communities: Vec::new(),
        }
    }

    #[test]
    fn test_rib_add_route() {
        let rib = Rib::new(65000);
        let route = create_test_route("10.0.0.0/24", "192.168.1.1", vec![65001]);

        assert!(rib.add_route(route).is_ok());
        assert_eq!(rib.route_count(), 1);
        assert_eq!(rib.prefix_count(), 1);
    }

    #[test]
    fn test_rib_best_path_selection() {
        let rib = Rib::new(65000);

        // Add two routes for the same prefix
        let route1 = create_test_route("10.0.0.0/24", "192.168.1.1", vec![65001, 65002, 65003]);
        let route2 = create_test_route("10.0.0.0/24", "192.168.1.2", vec![65001, 65002]); // Shorter AS path

        rib.add_route(route1).unwrap();
        rib.add_route(route2).unwrap();

        let prefix = Ipv4Network::from_str("10.0.0.0/24").unwrap();
        let best = rib.get_best_route(&prefix).unwrap();

        // Should select route2 (shorter AS path)
        assert_eq!(best.next_hop, Ipv4Addr::from_str("192.168.1.2").unwrap());
        assert_eq!(best.as_path.len(), 2);
    }

    #[test]
    fn test_rib_local_pref_selection() {
        let rib = Rib::new(65000);

        // Route with higher local preference should win
        let mut route1 = create_test_route("10.0.0.0/24", "192.168.1.1", vec![65001]);
        route1.local_pref = 150;

        let mut route2 = create_test_route("10.0.0.0/24", "192.168.1.2", vec![65001]);
        route2.local_pref = 100;

        rib.add_route(route1).unwrap();
        rib.add_route(route2).unwrap();

        let prefix = Ipv4Network::from_str("10.0.0.0/24").unwrap();
        let best = rib.get_best_route(&prefix).unwrap();

        assert_eq!(best.next_hop, Ipv4Addr::from_str("192.168.1.1").unwrap());
        assert_eq!(best.local_pref, 150);
    }

    #[test]
    fn test_rib_remove_route() {
        let rib = Rib::new(65000);
        let route = create_test_route("10.0.0.0/24", "192.168.1.1", vec![65001]);

        rib.add_route(route).unwrap();
        assert_eq!(rib.route_count(), 1);

        let prefix = Ipv4Network::from_str("10.0.0.0/24").unwrap();
        let next_hop = Ipv4Addr::from_str("192.168.1.1").unwrap();

        rib.remove_route(prefix, next_hop).unwrap();
        assert_eq!(rib.route_count(), 0);
        assert!(rib.get_best_route(&prefix).is_none());
    }

    #[test]
    fn test_rib_longest_prefix_match() {
        let rib = Rib::new(65000);

        // Add routes with different prefix lengths
        rib.add_route(create_test_route("10.0.0.0/8", "192.168.1.1", vec![65001])).unwrap();
        rib.add_route(create_test_route("10.0.0.0/16", "192.168.1.2", vec![65001])).unwrap();
        rib.add_route(create_test_route("10.0.0.0/24", "192.168.1.3", vec![65001])).unwrap();

        // Lookup should return most specific match
        let ip = Ipv4Addr::from_str("10.0.0.5").unwrap();
        let route = rib.lookup(ip).unwrap();

        assert_eq!(route.next_hop, Ipv4Addr::from_str("192.168.1.3").unwrap());
        assert_eq!(route.prefix.prefix(), 24);
    }

    #[test]
    fn test_rib_lookup_no_match() {
        let rib = Rib::new(65000);
        rib.add_route(create_test_route("10.0.0.0/24", "192.168.1.1", vec![65001])).unwrap();

        // IP outside the prefix should return None
        let ip = Ipv4Addr::from_str("192.168.1.5").unwrap();
        assert!(rib.lookup(ip).is_none());
    }

    #[test]
    fn test_rib_get_all_best_routes() {
        let rib = Rib::new(65000);

        rib.add_route(create_test_route("10.0.0.0/24", "192.168.1.1", vec![65001])).unwrap();
        rib.add_route(create_test_route("10.1.0.0/24", "192.168.1.2", vec![65001])).unwrap();
        rib.add_route(create_test_route("10.2.0.0/24", "192.168.1.3", vec![65001])).unwrap();

        let all_routes = rib.get_all_best_routes();
        assert_eq!(all_routes.len(), 3);
    }

    #[test]
    fn test_rib_clear() {
        let rib = Rib::new(65000);

        rib.add_route(create_test_route("10.0.0.0/24", "192.168.1.1", vec![65001])).unwrap();
        rib.add_route(create_test_route("10.1.0.0/24", "192.168.1.2", vec![65001])).unwrap();

        assert_eq!(rib.route_count(), 2);

        rib.clear();
        assert_eq!(rib.route_count(), 0);
        assert_eq!(rib.prefix_count(), 0);
    }
}
