//! REST API endpoints
//!
//! All API endpoints return JSON responses.

pub mod apikeys;
pub mod authservers;
pub mod backup_targets;
pub mod bootenv;
pub mod device;
pub mod firewall;
pub mod groups;
pub mod ha;
pub mod import;
pub mod insight_history;
pub mod insights;
pub mod interfaces;
#[cfg(feature = "ipsec")]
pub mod ipsec_rw;
pub mod lan;
pub mod network;
pub mod packages;
pub mod qos;
pub mod routing;
#[cfg(all(feature = "dns", feature = "segmentation"))]
pub mod seg_dns;
#[cfg(feature = "segmentation")]
pub mod seg_time;
pub mod segmentation;
pub mod setup;
pub mod states;
pub mod status;
pub mod svc;
pub mod system;
pub mod telemetry;
pub mod vpn;
pub mod wifi;
pub mod wifi_uplink;
