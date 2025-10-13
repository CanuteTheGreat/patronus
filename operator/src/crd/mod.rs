//! Custom Resource Definitions for Patronus SD-WAN

pub mod policy;
pub mod site;

pub use policy::{Policy, PolicySpec, PolicyStatus};
pub use site::{Site, SiteSpec, SiteStatus};
