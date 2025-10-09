//! Patronus Network Management
//!
//! Provides abstractions for managing network interfaces, routing, and related networking tasks.

use patronus_core::{types::Interface, Result};

pub mod interfaces;
pub mod routing;
pub mod nat64;
pub mod gateway_groups;

#[cfg(feature = "vlan")]
pub mod vlan;

#[cfg(feature = "wireguard")]
pub mod wireguard;

#[cfg(feature = "dhcp")]
pub mod dhcp;

#[cfg(feature = "openvpn")]
pub mod openvpn;

#[cfg(feature = "ipsec")]
pub mod ipsec;

#[cfg(feature = "dns")]
pub mod dns;

#[cfg(feature = "multiwan")]
pub mod multiwan;

#[cfg(feature = "qos")]
pub mod qos;

#[cfg(feature = "ha")]
pub mod ha;

#[cfg(feature = "intrusion-detection")]
pub mod ids;

#[cfg(feature = "dynamic-routing")]
pub mod frr;

pub use interfaces::InterfaceManager;

#[cfg(feature = "vlan")]
pub use vlan::VlanManager;

#[cfg(feature = "wireguard")]
pub use wireguard::WireGuardManager;

#[cfg(feature = "dhcp")]
pub use dhcp::DhcpManager;

#[cfg(feature = "openvpn")]
pub use openvpn::OpenVpnManager;

#[cfg(feature = "ipsec")]
pub use ipsec::IpsecManager;

#[cfg(feature = "dns")]
pub use dns::UnboundManager;

#[cfg(feature = "multiwan")]
pub use multiwan::MultiWanManager;

#[cfg(feature = "qos")]
pub use qos::QosManager;

#[cfg(feature = "ha")]
pub use ha::{HaManager, HaBackend};

#[cfg(feature = "intrusion-detection")]
pub use ids::{IdsManager, IdsBackend};

#[cfg(feature = "dynamic-routing")]
pub use frr::FrrManager;

/// Get all network interfaces on the system
pub async fn list_interfaces() -> Result<Vec<Interface>> {
    let manager = InterfaceManager::new().await?;
    manager.list().await
}
