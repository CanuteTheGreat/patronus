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
        let mut routes = Vec::new();
        let mut route_stream = self.handle.route().get(rtnetlink::IpVersion::V4).execute();

        while let Some(msg) = route_stream
            .try_next()
            .await
            .map_err(|e| Error::Network(format!("Failed to get routes: {}", e)))?
        {
            use rtnetlink::packet::route::RouteAttribute;

            let mut destination = None;
            let mut gateway = None;
            let mut interface_index = None;
            let mut metric = None;

            for attr in &msg.attributes {
                match attr {
                    RouteAttribute::Destination(addr) => {
                        if addr.len() == 4 {
                            let ipv4 = std::net::Ipv4Addr::new(addr[0], addr[1], addr[2], addr[3]);
                            destination = Some(IpNetwork::new(
                                IpAddr::V4(ipv4),
                                msg.header.destination_prefix_length,
                            ));
                        }
                    }
                    RouteAttribute::Gateway(addr) => {
                        if addr.len() == 4 {
                            gateway = Some(IpAddr::V4(std::net::Ipv4Addr::new(
                                addr[0], addr[1], addr[2], addr[3],
                            )));
                        } else if addr.len() == 16 {
                            let mut octets = [0u8; 16];
                            octets.copy_from_slice(addr);
                            gateway = Some(IpAddr::V6(std::net::Ipv6Addr::from(octets)));
                        }
                    }
                    RouteAttribute::Oif(index) => {
                        interface_index = Some(*index);
                    }
                    RouteAttribute::Priority(pri) => {
                        metric = Some(*pri);
                    }
                    _ => {}
                }
            }

            // Get interface name if we have an index
            let interface = if let Some(index) = interface_index {
                self.get_interface_name(index).await.ok()
            } else {
                None
            };

            routes.push(Route {
                destination,
                gateway,
                interface,
                metric,
                table: msg.header.table as u32,
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

        let mut route_add = self.handle.route();

        // Determine IP version from destination or gateway
        let is_ipv6 = destination
            .as_ref()
            .map(|d| matches!(d.addr, IpAddr::V6(_)))
            .or_else(|| gateway.as_ref().map(|g| matches!(g, IpAddr::V6(_))))
            .unwrap_or(false);

        let mut add_request = if is_ipv6 {
            route_add.add_v6()
        } else {
            route_add.add()
        };

        // Set destination
        if let Some(dest) = destination {
            match dest.addr {
                IpAddr::V4(addr) => {
                    add_request = add_request.destination_prefix(addr, dest.prefix_len);
                }
                IpAddr::V6(addr) => {
                    add_request = add_request.destination_prefix(addr, dest.prefix_len);
                }
            }
        }

        // Set gateway
        if let Some(gw) = gateway {
            match gw {
                IpAddr::V4(addr) => {
                    add_request = add_request.gateway(addr);
                }
                IpAddr::V6(addr) => {
                    add_request = add_request.gateway(addr);
                }
            }
        }

        // Set interface
        if let Some(index) = interface_index {
            add_request = add_request.output_interface(index);
        }

        add_request
            .execute()
            .await
            .map_err(|e| Error::Network(format!("Failed to add route: {}", e)))?;

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
        let mut route_del = self.handle.route();

        // Determine IP version
        let is_ipv6 = destination
            .as_ref()
            .map(|d| matches!(d.addr, IpAddr::V6(_)))
            .or_else(|| gateway.as_ref().map(|g| matches!(g, IpAddr::V6(_))))
            .unwrap_or(false);

        let mut del_request = if is_ipv6 {
            route_del.del_v6()
        } else {
            route_del.del()
        };

        // Set destination
        if let Some(dest) = destination {
            match dest.addr {
                IpAddr::V4(addr) => {
                    del_request = del_request.destination_prefix(addr, dest.prefix_len);
                }
                IpAddr::V6(addr) => {
                    del_request = del_request.destination_prefix(addr, dest.prefix_len);
                }
            }
        }

        // Set gateway
        if let Some(gw) = gateway {
            match gw {
                IpAddr::V4(addr) => {
                    del_request = del_request.gateway(addr);
                }
                IpAddr::V6(addr) => {
                    del_request = del_request.gateway(addr);
                }
            }
        }

        del_request
            .execute()
            .await
            .map_err(|e| Error::Network(format!("Failed to remove route: {}", e)))?;

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
