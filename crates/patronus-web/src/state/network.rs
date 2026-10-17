//! Network state (routes). Lane E replaces the in-memory fixtures below with
//! a store-backed adapter + applier. Interfaces moved to the store-backed
//! `state/interfaces.rs` (lane C); DHCP/DNS/NTP/DDNS live in `state/lan.rs`
//! (lane D).

use std::sync::Arc;
use tokio::sync::RwLock;

/// Network management operations
pub struct NetworkManager {
    routes: Arc<RwLock<Vec<crate::templates::Route>>>,
}

impl Default for NetworkManager {
    fn default() -> Self {
        Self::new()
    }
}

impl NetworkManager {
    pub fn new() -> Self {
        let default_routes = vec![
            crate::templates::Route {
                destination: "0.0.0.0/0".to_string(),
                gateway: "192.168.1.254".to_string(),
                interface: "eth0".to_string(),
                metric: 100,
                is_static: true,
                is_active: true,
            },
            crate::templates::Route {
                destination: "10.1.0.0/24".to_string(),
                gateway: "10.99.0.2".to_string(),
                interface: "wg0".to_string(),
                metric: 50,
                is_static: true,
                is_active: true,
            },
        ];

        Self {
            routes: Arc::new(RwLock::new(default_routes)),
        }
    }

    pub async fn list_routes(&self) -> anyhow::Result<Vec<crate::templates::Route>> {
        let routes = self.routes.read().await;
        Ok(routes.clone())
    }
}
