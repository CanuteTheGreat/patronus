//! Patronus Network Management
//!
//! Provides abstractions for managing network interfaces, routing, and related networking tasks.

use patronus_core::{types::Interface, Result};

pub use ipnetwork;

pub mod applyd;
pub mod bond;
pub mod bridge;
pub mod dhcp_client;
pub mod gateway_groups;
pub mod interfaces;
pub mod linkstate;
pub mod nat64;
pub mod netconf;
pub mod routing;
pub mod supervise;
pub mod sysctl;

#[cfg(feature = "vlan")]
pub mod vlan;

#[cfg(feature = "pppoe")]
pub mod pppoe;

/// Service name of the per-link pppd instances (also when PPPoE support is
/// compiled out, so stale instances can still be stopped).
pub const PPPOE_SERVICE: &str = "patronus-pppoe";

/// Which optional lane C features this build has (USE flags).
pub fn interface_features() -> serde_json::Value {
    serde_json::json!({
        "vlan": cfg!(feature = "vlan"),
        "pppoe": cfg!(feature = "pppoe"),
        "dhcp_client": dhcp_client::Client::preferred().as_str(),
    })
}

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

pub use interfaces::{InterfaceManager, InterfacesApplier};
pub use sysctl::SysctlApplier;

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
pub use ha::{HaBackend, HaManager};

#[cfg(feature = "intrusion-detection")]
pub use ids::{IdsBackend, IdsManager};

#[cfg(feature = "dynamic-routing")]
pub use frr::FrrManager;

/// Get all network interfaces on the system
pub async fn list_interfaces() -> Result<Vec<Interface>> {
    let manager = InterfaceManager::new().await?;
    manager.list().await
}
