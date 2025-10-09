//! VLAN management
//!
//! Provides VLAN (802.1Q) interface creation and management

use patronus_core::{Error, Result};
use rtnetlink::{new_connection, Handle};
use futures::TryStreamExt;

/// VLAN interface information
#[derive(Debug, Clone)]
pub struct VlanInterface {
    pub name: String,
    pub parent: String,
    pub vlan_id: u16,
    pub index: u32,
}

/// Manages VLAN interfaces
pub struct VlanManager {
    handle: Handle,
}

impl VlanManager {
    /// Create a new VLAN manager
    pub async fn new() -> Result<Self> {
        let (connection, handle, _) = new_connection()
            .map_err(|e| Error::Network(format!("Failed to create netlink connection: {}", e)))?;

        // Spawn the connection in the background
        tokio::spawn(connection);

        Ok(Self { handle })
    }

    /// Create a VLAN interface
    pub async fn create_vlan(&self, parent: &str, vlan_id: u16, name: Option<&str>) -> Result<String> {
        use crate::interfaces::InterfaceManager;

        // Get parent interface
        let iface_mgr = InterfaceManager::new().await?;
        let parent_iface = iface_mgr
            .get_by_name(parent)
            .await?
            .ok_or_else(|| Error::Network(format!("Parent interface not found: {}", parent)))?;

        // Generate VLAN interface name if not provided
        let vlan_name = name.unwrap_or(&format!("{}.{}", parent, vlan_id)).to_string();

        // Create VLAN interface using netlink
        self.handle
            .link()
            .add()
            .vlan(vlan_name.clone(), parent_iface.index, vlan_id)
            .execute()
            .await
            .map_err(|e| Error::Network(format!("Failed to create VLAN interface: {}", e)))?;

        tracing::info!("Created VLAN interface {} on {} (VLAN ID: {})", vlan_name, parent, vlan_id);
        Ok(vlan_name)
    }

    /// Delete a VLAN interface
    pub async fn delete_vlan(&self, name: &str) -> Result<()> {
        use crate::interfaces::InterfaceManager;

        let iface_mgr = InterfaceManager::new().await?;
        let iface = iface_mgr
            .get_by_name(name)
            .await?
            .ok_or_else(|| Error::Network(format!("VLAN interface not found: {}", name)))?;

        self.handle
            .link()
            .del(iface.index)
            .execute()
            .await
            .map_err(|e| Error::Network(format!("Failed to delete VLAN interface: {}", e)))?;

        tracing::info!("Deleted VLAN interface: {}", name);
        Ok(())
    }

    /// List all VLAN interfaces
    pub async fn list_vlans(&self) -> Result<Vec<VlanInterface>> {
        let mut vlans = Vec::new();
        let mut links = self.handle.link().get().execute();

        while let Some(msg) = links
            .try_next()
            .await
            .map_err(|e| Error::Network(format!("Failed to get interfaces: {}", e)))?
        {
            use rtnetlink::packet::link::{LinkAttribute, LinkInfo, InfoKind, InfoVlan};

            // Check if this is a VLAN interface
            let mut is_vlan = false;
            let mut vlan_id = None;
            let mut parent_index = None;

            for attr in &msg.attributes {
                if let LinkAttribute::LinkInfo(infos) = attr {
                    for info in infos {
                        match info {
                            LinkInfo::Kind(InfoKind::Vlan) => {
                                is_vlan = true;
                            }
                            LinkInfo::Data(InfoVlan::Id(id)) => {
                                vlan_id = Some(*id);
                            }
                            _ => {}
                        }
                    }
                }
                if let LinkAttribute::Link(idx) = attr {
                    parent_index = Some(*idx);
                }
            }

            if is_vlan {
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
                    .unwrap_or_else(|| format!("vlan{}", msg.header.index));

                // Get parent interface name
                let parent = if let Some(parent_idx) = parent_index {
                    self.get_interface_name(parent_idx).await.unwrap_or_else(|_| format!("if{}", parent_idx))
                } else {
                    "unknown".to_string()
                };

                vlans.push(VlanInterface {
                    name,
                    parent,
                    vlan_id: vlan_id.unwrap_or(0),
                    index: msg.header.index,
                });
            }
        }

        Ok(vlans)
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

    /// Get VLAN information by name
    pub async fn get_vlan(&self, name: &str) -> Result<Option<VlanInterface>> {
        let vlans = self.list_vlans().await?;
        Ok(vlans.into_iter().find(|v| v.name == name))
    }

    /// Set VLAN interface up
    pub async fn enable_vlan(&self, name: &str) -> Result<()> {
        use crate::interfaces::InterfaceManager;

        let iface_mgr = InterfaceManager::new().await?;
        iface_mgr.enable(name).await
    }

    /// Set VLAN interface down
    pub async fn disable_vlan(&self, name: &str) -> Result<()> {
        use crate::interfaces::InterfaceManager;

        let iface_mgr = InterfaceManager::new().await?;
        iface_mgr.disable(name).await
    }
}
