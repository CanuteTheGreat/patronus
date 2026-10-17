//! Linux bridges, created by the interfaces applier.

use crate::netconf::BridgeConfig;

/// `ip link add` arguments for a bridge.
pub fn create_args(b: &BridgeConfig) -> Vec<String> {
    [
        "link",
        "add",
        "name",
        &b.name,
        "type",
        "bridge",
        "stp_state",
        if b.stp { "1" } else { "0" },
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

/// Arguments to switch STP on/off on an existing bridge.
pub fn stp_args(b: &BridgeConfig) -> Vec<String> {
    [
        "link",
        "set",
        "dev",
        &b.name,
        "type",
        "bridge",
        "stp_state",
        if b.stp { "1" } else { "0" },
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}
