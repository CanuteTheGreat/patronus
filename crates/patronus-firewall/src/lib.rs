//! Patronus Firewall Management
//!
//! Provides abstractions for managing firewall rules using nftables.

use patronus_core::{Error, Result};
use std::process::Command;

pub mod nftables;
pub mod rules;
pub mod aliases;

#[cfg(feature = "geoip")]
pub mod geoip;

pub use rules::RuleManager;
pub use aliases::AliasManager;

#[cfg(feature = "geoip")]
pub use geoip::{GeoIpManager, GeoIpBackend};

/// Check if nftables is available on the system
pub fn check_nftables_available() -> Result<bool> {
    let output = Command::new("nft")
        .arg("--version")
        .output()
        .map_err(|e| Error::Firewall(format!("Failed to check nftables: {}", e)))?;

    Ok(output.status.success())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_check_nftables() {
        // This test will only pass on systems with nftables installed
        let _ = check_nftables_available();
    }
}
