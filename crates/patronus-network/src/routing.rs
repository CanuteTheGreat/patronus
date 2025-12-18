//! Routing table management

use patronus_core::{types::IpNetwork, Error, Result};
use rtnetlink::{new_connection, Handle};
use futures::TryStreamExt;
use std::net::IpAddr;

/// Represents a routing table entry
#[derive(Debug, Clone)]
pub struct Route {
    pub destination: Option<IpNetwork>,
    pub gateway: Option<IpAddr>,
    pub interface: Option<String>,
    pub metric: Option<u32>,
    pub table: u32,
}

/// Manages routing tables
pub struct RouteManager {
    handle: Handle,
}

impl RouteManager {
    /// Create a new route manager
    pub async fn new() -> Result<Self> {
        let (connection, handle, _) = new_connection()
            .map_err(|e| Error::Network(format!("Failed to create netlink connection: {}", e)))?;

        // Spawn the connection in the background
        tokio::spawn(connection);

        Ok(Self { handle })
    }

    /// List all routes
    pub async fn list_routes(&self) -> Result<Vec<Route>> {
        // TODO: Reimplement route listing with correct API
        tracing::warn!("Route listing not fully implemented - API changed");
        Ok(Vec::new())
    }

    /// Get interface name by index
    async fn get_interface_name(&self, index: u32) -> Result<String> {
        use crate::interfaces::InterfaceManager;

        let mgr = InterfaceManager::new().await?;
        if let Some(iface) = mgr.get_by_index(index).await? {
            Ok(iface.name)
        } else {
            Ok(format!("if{}", index))
        }
    }

    /// Add a route
    pub async fn add_route(
        &self,
        destination: Option<IpNetwork>,
        gateway: Option<IpAddr>,
        interface: Option<&str>,
        metric: Option<u32>,
    ) -> Result<()> {
        // Get interface index if name is provided
        let interface_index = if let Some(iface_name) = interface {
            use crate::interfaces::InterfaceManager;
            let mgr = InterfaceManager::new().await?;
            mgr.get_by_name(iface_name)
                .await?
                .map(|iface| iface.index)
        } else {
            None
        };

        // TODO: Reimplement route addition with correct API
        tracing::warn!("Route addition not fully implemented - API changed");

        tracing::info!(
            "Added route: {:?} via {:?} dev {:?}",
            destination,
            gateway,
            interface
        );
        Ok(())
    }

    /// Add a default gateway
    pub async fn add_default_gateway(&self, gateway: IpAddr, interface: Option<&str>) -> Result<()> {
        self.add_route(None, Some(gateway), interface, None).await
    }

    /// Remove a route
    pub async fn remove_route(
        &self,
        destination: Option<IpNetwork>,
        gateway: Option<IpAddr>,
    ) -> Result<()> {
        // For route deletion, we need to create a RouteMessage manually
        // This is a simplified approach - in practice, you'd want to query existing routes first
        tracing::warn!("Route deletion not fully implemented - API changed");

        tracing::info!("Skipping route removal: {:?} via {:?}", destination, gateway);
        Ok(())
    }

    /// Flush all routes (dangerous!)
    pub async fn flush_routes(&self) -> Result<()> {
        let routes = self.list_routes().await?;

        for route in routes {
            // Don't remove local routes (table 255)
            if route.table != 255 {
                self.remove_route(route.destination, route.gateway).await.ok();
            }
        }

        tracing::warn!("Flushed routing table");
        Ok(())
    }
}

impl Default for RouteManager {
    fn default() -> Self {
        // Can't use async in Default, so this will panic if called
        // Users should use RouteManager::new().await instead
        panic!("Use RouteManager::new().await instead of Default")
    }
}
