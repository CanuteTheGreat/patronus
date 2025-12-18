//! Routing table management

use patronus_core::{types::IpNetwork, Error, Result};
use rtnetlink::{new_connection, Handle};
use futures::TryStreamExt;
use std::net::{IpAddr, Ipv4Addr};
use netlink_packet_route::route::RouteAddress;

/// Represents a routing table entry
#[derive(Debug, Clone)]
pub struct Route {
    pub destination: Option<IpNetwork>,
    pub gateway: Option<IpAddr>,
    pub interface: Option<String>,
    pub metric: Option<u32>,
    pub table: u32,
}

/// Convert RouteAddress to IpAddr
fn route_address_to_ip(addr: &RouteAddress) -> IpAddr {
    match addr {
        RouteAddress::Inet(v4) => IpAddr::V4(*v4),
        RouteAddress::Inet6(v6) => IpAddr::V6(*v6),
        _ => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
    }
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
        let mut routes_stream = self.handle.route().get(rtnetlink::IpVersion::V4).execute();
        let mut routes = Vec::new();

        while let Some(msg) = routes_stream
            .try_next()
            .await
            .map_err(|e| Error::Network(format!("Failed to get routes: {}", e)))?
        {
            use netlink_packet_route::route::RouteAttribute;

            let mut destination: Option<IpNetwork> = None;
            let mut gateway: Option<IpAddr> = None;
            let mut oif_index: Option<u32> = None;
            let mut metric: Option<u32> = None;

            // Get prefix length from header
            let prefix_len = msg.header.destination_prefix_length;

            for attr in &msg.attributes {
                match attr {
                    RouteAttribute::Destination(addr) => {
                        destination = Some(IpNetwork {
                            addr: route_address_to_ip(addr),
                            prefix_len,
                        });
                    }
                    RouteAttribute::Gateway(addr) => {
                        gateway = Some(route_address_to_ip(addr));
                    }
                    RouteAttribute::Oif(idx) => {
                        oif_index = Some(*idx);
                    }
                    RouteAttribute::Priority(p) => {
                        metric = Some(*p);
                    }
                    _ => {}
                }
            }

            // Get interface name
            let interface_name = if let Some(idx) = oif_index {
                self.get_interface_name(idx).await.ok()
            } else {
                None
            };

            routes.push(Route {
                destination,
                gateway,
                interface: interface_name,
                metric,
                table: msg.header.table.into(),
            });
        }

        // Also get IPv6 routes
        let mut routes_v6 = self.handle.route().get(rtnetlink::IpVersion::V6).execute();

        while let Some(msg) = routes_v6
            .try_next()
            .await
            .map_err(|e| Error::Network(format!("Failed to get IPv6 routes: {}", e)))?
        {
            use netlink_packet_route::route::RouteAttribute;

            let mut destination: Option<IpNetwork> = None;
            let mut gateway: Option<IpAddr> = None;
            let mut oif_index: Option<u32> = None;
            let mut metric: Option<u32> = None;

            let prefix_len = msg.header.destination_prefix_length;

            for attr in &msg.attributes {
                match attr {
                    RouteAttribute::Destination(addr) => {
                        destination = Some(IpNetwork {
                            addr: route_address_to_ip(addr),
                            prefix_len,
                        });
                    }
                    RouteAttribute::Gateway(addr) => {
                        gateway = Some(route_address_to_ip(addr));
                    }
                    RouteAttribute::Oif(idx) => {
                        oif_index = Some(*idx);
                    }
                    RouteAttribute::Priority(p) => {
                        metric = Some(*p);
                    }
                    _ => {}
                }
            }

            let interface_name = if let Some(idx) = oif_index {
                self.get_interface_name(idx).await.ok()
            } else {
                None
            };

            routes.push(Route {
                destination,
                gateway,
                interface: interface_name,
                metric,
                table: msg.header.table.into(),
            });
        }

        Ok(routes)
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

    /// Get interface index by name
    async fn get_interface_index(&self, name: &str) -> Result<Option<u32>> {
        use crate::interfaces::InterfaceManager;

        let mgr = InterfaceManager::new().await?;
        if let Some(iface) = mgr.get_by_name(name).await? {
            Ok(Some(iface.index))
        } else {
            Ok(None)
        }
    }

    /// Add a route
    pub async fn add_route(
        &self,
        destination: Option<IpNetwork>,
        gateway: Option<IpAddr>,
        interface: Option<&str>,
        _metric: Option<u32>,
    ) -> Result<()> {
        // Get interface index if name is provided
        let interface_index = if let Some(iface_name) = interface {
            self.get_interface_index(iface_name).await?
        } else {
            None
        };

        // Clone for logging later
        let dest_display = destination.clone();
        let gw_display = gateway;

        match (destination, gateway) {
            (Some(dest), Some(gw)) => {
                // Route to specific destination via gateway
                let mut request = self.handle
                    .route()
                    .add()
                    .v4()
                    .destination_prefix(
                        match dest.addr {
                            IpAddr::V4(addr) => addr,
                            _ => return Err(Error::Network("Expected IPv4 address".to_string())),
                        },
                        dest.prefix_len,
                    )
                    .gateway(match gw {
                        IpAddr::V4(addr) => addr,
                        _ => return Err(Error::Network("Expected IPv4 gateway".to_string())),
                    });

                if let Some(idx) = interface_index {
                    request = request.output_interface(idx);
                }

                request
                    .execute()
                    .await
                    .map_err(|e| Error::Network(format!("Failed to add route: {}", e)))?;
            }
            (None, Some(gw)) => {
                // Default route
                let mut request = self.handle
                    .route()
                    .add()
                    .v4()
                    .gateway(match gw {
                        IpAddr::V4(addr) => addr,
                        _ => return Err(Error::Network("Expected IPv4 gateway".to_string())),
                    });

                if let Some(idx) = interface_index {
                    request = request.output_interface(idx);
                }

                request
                    .execute()
                    .await
                    .map_err(|e| Error::Network(format!("Failed to add default route: {}", e)))?;
            }
            (Some(dest), None) => {
                // Direct route to destination (no gateway)
                if let Some(idx) = interface_index {
                    self.handle
                        .route()
                        .add()
                        .v4()
                        .destination_prefix(
                            match dest.addr {
                                IpAddr::V4(addr) => addr,
                                _ => return Err(Error::Network("Expected IPv4 address".to_string())),
                            },
                            dest.prefix_len,
                        )
                        .output_interface(idx)
                        .execute()
                        .await
                        .map_err(|e| Error::Network(format!("Failed to add direct route: {}", e)))?;
                } else {
                    return Err(Error::Network("Interface required for direct routes".to_string()));
                }
            }
            (None, None) => {
                return Err(Error::Network("At least destination or gateway required".to_string()));
            }
        }

        tracing::info!(
            "Added route: {:?} via {:?} dev {:?}",
            dest_display,
            gw_display,
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
        // For deletion, we first find matching routes then delete them
        let routes = self.list_routes().await?;

        for route in routes {
            let dest_match = match (&destination, &route.destination) {
                (Some(d1), Some(d2)) => d1.addr == d2.addr && d1.prefix_len == d2.prefix_len,
                (None, None) => true,
                _ => false,
            };

            let gw_match = match (&gateway, &route.gateway) {
                (Some(g1), Some(g2)) => g1 == g2,
                (None, None) => true,
                (None, Some(_)) => true, // Don't require gateway match if not specified
                _ => false,
            };

            if dest_match && gw_match {
                // Found matching route - delete it
                if let Some(dest) = &route.destination {
                    match dest.addr {
                        IpAddr::V4(addr) => {
                            self.handle
                                .route()
                                .del(self.handle.route().add().v4().destination_prefix(addr, dest.prefix_len).message_mut().clone())
                                .execute()
                                .await
                                .map_err(|e| Error::Network(format!("Failed to delete route: {}", e)))?;
                        }
                        IpAddr::V6(addr) => {
                            self.handle
                                .route()
                                .del(self.handle.route().add().v6().destination_prefix(addr, dest.prefix_len).message_mut().clone())
                                .execute()
                                .await
                                .map_err(|e| Error::Network(format!("Failed to delete route: {}", e)))?;
                        }
                    }
                }
            }
        }

        tracing::info!("Removed route: {:?} via {:?}", destination, gateway);
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
