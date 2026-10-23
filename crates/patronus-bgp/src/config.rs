//! BGP configuration types

use ipnetwork::IpNetwork;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::time::Duration;

/// BGP configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BgpConfig {
    /// Local AS number
    pub asn: u32,

    /// Router ID
    pub router_id: IpAddr,

    /// BGP neighbors
    pub neighbors: Vec<NeighborConfig>,

    /// Networks to advertise
    pub networks: Vec<NetworkConfig>,

    /// Route maps
    #[serde(default)]
    pub route_maps: Vec<RouteMapConfig>,

    /// Timers
    #[serde(default)]
    pub timers: TimersConfig,
}

/// BGP neighbor configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NeighborConfig {
    /// Neighbor IP address
    pub ip: IpAddr,

    /// Remote AS number
    pub asn: u32,

    /// Description
    #[serde(default)]
    pub description: Option<String>,

    /// MD5 password for authentication
    #[serde(default)]
    pub password: Option<String>,

    /// Timers override for this neighbor
    #[serde(default)]
    pub timers: Option<TimersConfig>,

    /// Route map to apply to received routes
    #[serde(default)]
    pub route_map_in: Option<String>,

    /// Route map to apply to advertised routes
    #[serde(default)]
    pub route_map_out: Option<String>,

    /// Next hop self
    #[serde(default)]
    pub next_hop_self: bool,
}

/// Network configuration for advertisement
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// Network prefix to advertise
    pub prefix: IpNetwork,

    /// Route map to apply
    #[serde(default)]
    pub route_map: Option<String>,
}

/// Route map configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteMapConfig {
    /// Route map name
    pub name: String,

    /// Route map rules
    pub rules: Vec<RouteMapRule>,
}

/// Route map rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteMapRule {
    /// Sequence number
    pub sequence: u32,

    /// Action (permit or deny)
    pub action: RouteMapAction,

    /// Match conditions
    #[serde(default)]
    pub match_conditions: Vec<MatchCondition>,

    /// Set actions
    #[serde(default)]
    pub set_actions: Vec<SetAction>,
}

/// Route map action
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum RouteMapAction {
    /// Permit matching routes
    Permit,

    /// Deny matching routes
    Deny,
}

/// Match condition for route maps
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum MatchCondition {
    /// Match prefix list
    PrefixList { name: String },

    /// Match AS path
    AsPath { pattern: String },

    /// Match community
    Community { community: String },

    /// Match prefix
    Prefix { prefix: IpNetwork },
}

/// Set action for route maps
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SetAction {
    /// Set local preference
    LocalPreference { value: u32 },

    /// Set MED (metric)
    Med { value: u32 },

    /// Set community
    Community { community: String },

    /// Set AS path prepend
    AsPathPrepend { asn: u32, count: u8 },

    /// Set next hop
    NextHop { ip: IpAddr },
}

/// BGP timers configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimersConfig {
    /// Keepalive interval (seconds)
    #[serde(default = "default_keepalive")]
    pub keepalive_secs: u64,

    /// Hold time (seconds)
    #[serde(default = "default_holdtime")]
    pub holdtime_secs: u64,

    /// Connect retry interval (seconds)
    #[serde(default = "default_connect_retry")]
    pub connect_retry_secs: u64,
}

impl Default for TimersConfig {
    fn default() -> Self {
        Self {
            keepalive_secs: 30,
            holdtime_secs: 90,
            connect_retry_secs: 120,
        }
    }
}

fn default_keepalive() -> u64 {
    30
}

fn default_holdtime() -> u64 {
    90
}

fn default_connect_retry() -> u64 {
    120
}

impl TimersConfig {
    /// Get keepalive duration
    pub fn keepalive_duration(&self) -> Duration {
        Duration::from_secs(self.keepalive_secs)
    }

    /// Get hold time duration
    pub fn holdtime_duration(&self) -> Duration {
        Duration::from_secs(self.holdtime_secs)
    }

    /// Get connect retry duration
    pub fn connect_retry_duration(&self) -> Duration {
        Duration::from_secs(self.connect_retry_secs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_timers_default() {
        let timers = TimersConfig::default();
        assert_eq!(timers.keepalive_secs, 30);
        assert_eq!(timers.holdtime_secs, 90);
        assert_eq!(timers.connect_retry_secs, 120);
    }

    #[test]
    fn test_timers_duration() {
        let timers = TimersConfig::default();
        assert_eq!(timers.keepalive_duration(), Duration::from_secs(30));
        assert_eq!(timers.holdtime_duration(), Duration::from_secs(90));
        assert_eq!(timers.connect_retry_duration(), Duration::from_secs(120));
    }
}
