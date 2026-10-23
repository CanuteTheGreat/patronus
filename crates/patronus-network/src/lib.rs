//! Patronus Network Management
//!
//! Provides abstractions for managing network interfaces, routing, and related networking tasks.

use patronus_core::{types::Interface, Result};

pub use ipnetwork;

pub mod applyd;
pub mod bond;
pub mod bridge;
pub mod dhcp_client;
pub mod interfaces;
pub mod lan;
pub mod linkstate;
pub mod netconf;
pub mod routes;
pub mod services;
pub mod supervise;
pub mod sysctl;
pub mod sysops;
pub mod vpn;

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

#[cfg(feature = "dhcp")]
pub mod dhcp6;

#[cfg(feature = "dhcp")]
pub mod ra;

#[cfg(feature = "openvpn")]
pub mod openvpn;
#[cfg(feature = "openvpn")]
pub mod openvpn_server;

#[cfg(feature = "ipsec")]
pub mod ipsec;

#[cfg(feature = "dns")]
pub mod dns;

#[cfg(feature = "dns")]
pub mod ddns;

#[cfg(feature = "ntp")]
pub mod ntp;

#[cfg(feature = "qos")]
pub mod shaping;

#[cfg(feature = "ha")]
pub mod ha;

pub mod svc;
pub mod wol;

#[cfg(feature = "sdwan-edge")]
pub mod edge;

#[cfg(feature = "syslog")]
pub mod syslog;

#[cfg(feature = "netflow")]
pub mod netflow;

#[cfg(feature = "igmp")]
pub mod igmp;

#[cfg(feature = "nat64")]
pub mod nat64;

#[cfg(feature = "l2tp")]
pub mod l2tp;
#[cfg(feature = "plugins")]
pub mod packages;
#[cfg(feature = "plugins")]
pub mod plugins;
#[cfg(feature = "web-proxy")]
pub mod proxy;
#[cfg(feature = "upnp")]
pub mod upnp;
#[cfg(feature = "vrf")]
pub mod vrf;

#[cfg(feature = "intrusion-detection")]
pub mod ids;

#[cfg(feature = "dynamic-routing")]
pub mod frr;

pub use interfaces::{InterfaceManager, InterfacesApplier};
pub use routes::RoutesApplier;
pub use sysctl::SysctlApplier;

#[cfg(feature = "wireguard")]
pub use wireguard::WireGuardApplier;

#[cfg(feature = "dhcp")]
pub use dhcp::DhcpApplier;

#[cfg(feature = "openvpn")]
pub use openvpn::OpenVpnManager;

#[cfg(feature = "ipsec")]
pub use ipsec::IpsecApplier;

/// Which VPNs this build has (USE=wireguard / USE=ipsec).
pub fn vpn_features() -> serde_json::Value {
    serde_json::json!({
        "wireguard": cfg!(feature = "wireguard"),
        "ipsec": cfg!(feature = "ipsec"),
    })
}

/// The lane F appliers compiled into this build (WireGuard in the
/// interfaces phase, IPsec in the services phase).
// cfg-gated pushes: vec![] cannot express them
#[allow(clippy::vec_init_then_push)]
pub fn vpn_appliers() -> Vec<std::sync::Arc<dyn patronus_config::Applier>> {
    #[allow(unused_mut)]
    let mut v: Vec<std::sync::Arc<dyn patronus_config::Applier>> = Vec::new();
    #[cfg(feature = "wireguard")]
    v.push(std::sync::Arc::new(wireguard::WireGuardApplier::default()));
    #[cfg(feature = "ipsec")]
    v.push(std::sync::Arc::new(ipsec::IpsecApplier::default()));
    v
}

#[cfg(feature = "dns")]
pub use ddns::DdnsApplier;
#[cfg(feature = "dns")]
pub use dns::DnsApplier;

#[cfg(feature = "ntp")]
pub use ntp::NtpApplier;

/// Get all network interfaces on the system
pub async fn list_interfaces() -> Result<Vec<Interface>> {
    let manager = InterfaceManager::new().await?;
    manager.list().await
}
