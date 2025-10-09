//! Network interface management

use patronus_core::{types::{Interface, IpNetwork}, Error, Result};
use rtnetlink::{new_connection, Handle, IpVersion};
use futures::TryStreamExt;
use std::net::IpAddr;

/// Manages network interfaces
pub struct InterfaceManager {
    handle: Handle,
}

impl InterfaceManager {
    /// Create a new interface manager
    pub async fn new() -> Result<Self> {
        let (connection, handle, _) = new_connection()
            .map_err(|e| Error::Network(format!("Failed to create netlink connection: {}", e)))?;

        // Spawn the connection in the background
        tokio::spawn(connection);

        Ok(Self { handle })
    }

    /// List all network interfaces
    pub async fn list(&self) -> Result<Vec<Interface>> {
        let mut links = self.handle.link().get().execute();
        let mut interfaces = Vec::new();

        while let Some(msg) = links
            .try_next()
            .await
            .map_err(|e| Error::Network(format!("Failed to get interfaces: {}", e)))?
        {
            use rtnetlink::packet::link::LinkAttribute;

            let name = msg
                .attributes
                .iter()
                .find_map(|attr| {
                    if let LinkAttribute::IfName(name) = attr {
                        Some(name.clone())
                    } else {
                        None
                    }
                })
                .unwrap_or_else(|| format!("interface{}", msg.header.index));

            // Extract MAC address
            let mac_address = msg
                .attributes
                .iter()
                .find_map(|attr| {
                    if let LinkAttribute::Address(addr) = attr {
                        Some(addr.iter()
                            .map(|b| format!("{:02x}", b))
                            .collect::<Vec<_>>()
                            .join(":"))
                    } else {
                        None
                    }
                });

            // Get IP addresses for this interface
            let ip_addresses = self.get_interface_ips(msg.header.index).await?;

            let interface = Interface {
                name,
                mac_address,
                ip_addresses,
                mtu: msg.header.mtu,
                enabled: msg.header.flags & 0x1 != 0, // IFF_UP flag
                index: msg.header.index,
            };

            interfaces.push(interface);
        }

        Ok(interfaces)
    }

    /// Get IP addresses for a specific interface
    async fn get_interface_ips(&self, index: u32) -> Result<Vec<IpAddr>> {
        let mut addrs = Vec::new();

        // Get IPv4 addresses
        let mut ipv4_addrs = self.handle.address().get().set_link_index_filter(index).execute();
        while let Some(msg) = ipv4_addrs
            .try_next()
            .await
            .map_err(|e| Error::Network(format!("Failed to get IPv4 addresses: {}", e)))?
        {
            use rtnetlink::packet::address::AddressAttribute;

            if let Some(AddressAttribute::Address(addr)) = msg.attributes.iter().find(|attr| {
                matches!(attr, AddressAttribute::Address(_))
            }) {
                if msg.header.family == 2 { // AF_INET
                    if addr.len() == 4 {
                        addrs.push(IpAddr::V4(std::net::Ipv4Addr::new(
                            addr[0], addr[1], addr[2], addr[3]
                        )));
                    }
                } else if msg.header.family == 10 { // AF_INET6
                    if addr.len() == 16 {
                        let mut octets = [0u8; 16];
                        octets.copy_from_slice(addr);
                        addrs.push(IpAddr::V6(std::net::Ipv6Addr::from(octets)));
                    }
                }
            }
        }

        Ok(addrs)
    }

    /// Get a specific interface by name
    pub async fn get_by_name(&self, name: &str) -> Result<Option<Interface>> {
        let interfaces = self.list().await?;
        Ok(interfaces.into_iter().find(|iface| iface.name == name))
    }

    /// Get a specific interface by index
    pub async fn get_by_index(&self, index: u32) -> Result<Option<Interface>> {
        let interfaces = self.list().await?;
        Ok(interfaces.into_iter().find(|iface| iface.index == index))
    }

    /// Enable a network interface (bring it up)
    pub async fn enable(&self, name: &str) -> Result<()> {
        let interface = self.get_by_name(name).await?
            .ok_or_else(|| Error::Network(format!("Interface not found: {}", name)))?;

        self.handle
            .link()
            .set(interface.index)
            .up()
            .execute()
            .await
            .map_err(|e| Error::Network(format!("Failed to enable interface {}: {}", name, e)))?;

        tracing::info!("Enabled interface: {}", name);
        Ok(())
    }

    /// Disable a network interface (bring it down)
    pub async fn disable(&self, name: &str) -> Result<()> {
        let interface = self.get_by_name(name).await?
            .ok_or_else(|| Error::Network(format!("Interface not found: {}", name)))?;

        self.handle
            .link()
            .set(interface.index)
            .down()
            .execute()
            .await
            .map_err(|e| Error::Network(format!("Failed to disable interface {}: {}", name, e)))?;

        tracing::info!("Disabled interface: {}", name);
        Ok(())
    }

    /// Set MTU for an interface
    pub async fn set_mtu(&self, name: &str, mtu: u32) -> Result<()> {
        let interface = self.get_by_name(name).await?
            .ok_or_else(|| Error::Network(format!("Interface not found: {}", name)))?;

        self.handle
            .link()
            .set(interface.index)
            .mtu(mtu)
            .execute()
            .await
            .map_err(|e| Error::Network(format!("Failed to set MTU for {}: {}", name, e)))?;

        tracing::info!("Set MTU for {} to {}", name, mtu);
        Ok(())
    }

    /// Add an IP address to an interface
    pub async fn add_ip(&self, name: &str, ip: IpNetwork) -> Result<()> {
        let interface = self.get_by_name(name).await?
            .ok_or_else(|| Error::Network(format!("Interface not found: {}", name)))?;

        match ip.addr {
            IpAddr::V4(addr) => {
                self.handle
                    .address()
                    .add(interface.index, addr.into(), ip.prefix_len)
                    .execute()
                    .await
                    .map_err(|e| Error::Network(format!("Failed to add IPv4 address: {}", e)))?;
            }
            IpAddr::V6(addr) => {
                self.handle
                    .address()
                    .add(interface.index, addr.into(), ip.prefix_len)
                    .execute()
                    .await
                    .map_err(|e| Error::Network(format!("Failed to add IPv6 address: {}", e)))?;
            }
        }

        tracing::info!("Added IP {} to interface {}", ip.to_string(), name);
        Ok(())
    }

    /// Remove an IP address from an interface
    pub async fn remove_ip(&self, name: &str, ip: IpNetwork) -> Result<()> {
        let interface = self.get_by_name(name).await?
            .ok_or_else(|| Error::Network(format!("Interface not found: {}", name)))?;

        match ip.addr {
            IpAddr::V4(addr) => {
                self.handle
                    .address()
                    .del(interface.index, addr.into(), ip.prefix_len)
                    .execute()
                    .await
                    .map_err(|e| Error::Network(format!("Failed to remove IPv4 address: {}", e)))?;
            }
            IpAddr::V6(addr) => {
                self.handle
                    .address()
                    .del(interface.index, addr.into(), ip.prefix_len)
                    .execute()
                    .await
                    .map_err(|e| Error::Network(format!("Failed to remove IPv6 address: {}", e)))?;
            }
        }

        tracing::info!("Removed IP {} from interface {}", ip.to_string(), name);
        Ok(())
    }

    /// Flush all IP addresses from an interface
    pub async fn flush_ips(&self, name: &str) -> Result<()> {
        let interface = self.get_by_name(name).await?
            .ok_or_else(|| Error::Network(format!("Interface not found: {}", name)))?;

        let mut addrs = self.handle.address().get().set_link_index_filter(interface.index).execute();

        while let Some(msg) = addrs
            .try_next()
            .await
            .map_err(|e| Error::Network(format!("Failed to get addresses: {}", e)))?
        {
            use rtnetlink::packet::address::AddressAttribute;

            if let Some(AddressAttribute::Address(addr)) = msg.attributes.iter().find(|attr| {
                matches!(attr, AddressAttribute::Address(_))
            }) {
                if msg.header.family == 2 { // AF_INET
                    if addr.len() == 4 {
                        let ipv4 = std::net::Ipv4Addr::new(addr[0], addr[1], addr[2], addr[3]);
                        self.handle
                            .address()
                            .del(interface.index, ipv4.into(), msg.header.prefix_len)
                            .execute()
                            .await
                            .ok(); // Ignore errors
                    }
                } else if msg.header.family == 10 { // AF_INET6
                    if addr.len() == 16 {
                        let mut octets = [0u8; 16];
                        octets.copy_from_slice(addr);
                        let ipv6 = std::net::Ipv6Addr::from(octets);
                        self.handle
                            .address()
                            .del(interface.index, ipv6.into(), msg.header.prefix_len)
                            .execute()
                            .await
                            .ok(); // Ignore errors
                    }
                }
            }
        }

        tracing::info!("Flushed all IPs from interface: {}", name);
        Ok(())
    }
}
