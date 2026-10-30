//! Command handlers for the Patronus CLI

pub mod apply;
pub mod applyd;
pub mod bgp;
pub mod captiveportal;
pub mod daemon;
pub mod deploy;
pub mod edge;
pub mod firewall;
#[cfg(feature = "gitops")]
pub mod gitops;
pub mod init;
pub mod metrics;
#[cfg(feature = "plugins")]
pub mod plugin;
pub mod policy;
pub mod site;
pub mod status;
pub mod tunnel;
pub mod users;
pub mod validate;
pub mod web;
#[cfg(feature = "wifi-ap")]
pub mod wifi;
pub mod ztp;
