//! Gateway Groups - Advanced Multi-WAN Management
//!
//! Provides pfSense-style gateway groups with tiered failover:
//! - Tier 1 (preferred) → Tier 2 (backup) → Tier 3 (last resort)
//! - Load balancing within same tier
//! - Per-rule gateway selection in firewall
//! - Real-time gateway monitoring dashboard
//!
//! Example: Fiber (Tier 1) → Cable (Tier 2) → 4G (Tier 3)

use patronus_core::{Result, Error};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;

/// Gateway tier for failover priority
/// Lower tier number = higher priority
/// All gateways in same tier are used together (load balanced)
pub type GatewayTier = u8;

/// Gateway group member with tier
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayGroupMember {
    pub gateway_name: String,
    pub tier: GatewayTier,  // 1 = primary, 2 = backup, 3 = last resort, etc.
    pub weight: u32,         // For load balancing within tier
}

/// Advanced gateway group with tiered failover
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdvancedGatewayGroup {
    pub name: String,
    pub description: String,
    pub enabled: bool,
    pub members: Vec<GatewayGroupMember>,

    // Behavior settings
    pub trigger_level: u8,  // Minimum working gateways before failover
    pub sticky_connections: bool,  // Use source IP hashing for session persistence
}

impl AdvancedGatewayGroup {
    /// Get all gateway names in a specific tier
    pub fn get_tier_gateways(&self, tier: GatewayTier) -> Vec<String> {
        self.members.iter()
            .filter(|m| m.tier == tier)
            .map(|m| m.gateway_name.clone())
            .collect()
    }

    /// Get all tiers in use (sorted from lowest/best to highest/worst)
    pub fn get_tiers(&self) -> Vec<GatewayTier> {
        let mut tiers: Vec<GatewayTier> = self.members.iter()
            .map(|m| m.tier)
            .collect();
        tiers.sort_unstable();
        tiers.dedup();
        tiers
    }

    /// Get the currently active tier based on gateway status
    pub fn get_active_tier(&self, online_gateways: &[String]) -> Option<GatewayTier> {
        // Find lowest tier with at least one online gateway
        for tier in self.get_tiers() {
            let tier_gateways = self.get_tier_gateways(tier);
            let online_in_tier: Vec<_> = tier_gateways.iter()
                .filter(|gw| online_gateways.contains(gw))
                .collect();

            if !online_in_tier.is_empty() {
                return Some(tier);
            }
        }
        None
    }

    /// Get all members in active tier (for load balancing)
    pub fn get_active_members(&self, online_gateways: &[String]) -> Vec<GatewayGroupMember> {
        if let Some(active_tier) = self.get_active_tier(online_gateways) {
            self.members.iter()
                .filter(|m| m.tier == active_tier && online_gateways.contains(&m.gateway_name))
                .cloned()
                .collect()
        } else {
            vec![]
        }
    }

    /// Validate gateway group configuration
    pub fn validate(&self) -> Result<()> {
        if self.members.is_empty() {
            return Err(Error::Config("Gateway group has no members".to_string()));
        }

        // Check for duplicate gateways
        let mut seen = std::collections::HashSet::new();
        for member in &self.members {
            if !seen.insert(&member.gateway_name) {
                return Err(Error::Config(format!(
                    "Duplicate gateway in group: {}", member.gateway_name
                )));
            }
        }

        // Validate tiers are reasonable (1-10)
        for member in &self.members {
            if member.tier == 0 || member.tier > 10 {
                return Err(Error::Config(format!(
                    "Invalid tier {} (must be 1-10)", member.tier
                )));
            }
        }

        // Validate weights
        for member in &self.members {
            if member.weight == 0 || member.weight > 256 {
                return Err(Error::Config(format!(
                    "Invalid weight {} (must be 1-256)", member.weight
                )));
            }
        }

        Ok(())
    }
}

/// Gateway selection for firewall rules
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum GatewaySelection {
    Default,                      // Use default routing
    Gateway(String),              // Specific gateway
    GatewayGroup(String),         // Gateway group (with failover/load balancing)
}

/// Firewall rule with gateway selection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallRuleGateway {
    pub rule_id: String,
    pub gateway_selection: GatewaySelection,
}

/// Gateway group manager
pub struct GatewayGroupManager {
    groups: HashMap<String, AdvancedGatewayGroup>,
}

impl GatewayGroupManager {
    pub fn new() -> Self {
        Self {
            groups: HashMap::new(),
        }
    }

    /// Add or update a gateway group
    pub fn add_group(&mut self, group: AdvancedGatewayGroup) -> Result<()> {
        group.validate()?;
        self.groups.insert(group.name.clone(), group);
        Ok(())
    }

    /// Remove a gateway group
    pub fn remove_group(&mut self, name: &str) -> Result<()> {
        self.groups.remove(name)
            .ok_or_else(|| Error::Config(format!("Gateway group not found: {}", name)))?;
        Ok(())
    }

    /// Get a gateway group
    pub fn get_group(&self, name: &str) -> Option<&AdvancedGatewayGroup> {
        self.groups.get(name)
    }

    /// List all gateway groups
    pub fn list_groups(&self) -> Vec<&AdvancedGatewayGroup> {
        self.groups.values().collect()
    }

    /// Generate routing configuration for a gateway group
    pub fn generate_routing_config(
        &self,
        group_name: &str,
        online_gateways: &[String],
        gateway_ips: &HashMap<String, IpAddr>,
        gateway_interfaces: &HashMap<String, String>,
    ) -> Result<RoutingConfig> {
        let group = self.get_group(group_name)
            .ok_or_else(|| Error::Config(format!("Gateway group not found: {}", group_name)))?;

        if !group.enabled {
            return Err(Error::Config(format!("Gateway group {} is disabled", group_name)));
        }

        let active_members = group.get_active_members(online_gateways);

        if active_members.is_empty() {
            return Err(Error::Network(format!(
                "No online gateways in group {}", group_name
            )));
        }

        let active_tier = group.get_active_tier(online_gateways)
            .expect("Active tier should exist if we have active members");

        // Build nexthops for multipath routing
        let mut nexthops = Vec::new();

        for member in &active_members {
            let gateway_ip = gateway_ips.get(&member.gateway_name)
                .ok_or_else(|| Error::Config(format!(
                    "Gateway IP not found: {}", member.gateway_name
                )))?;

            let interface = gateway_interfaces.get(&member.gateway_name)
                .ok_or_else(|| Error::Config(format!(
                    "Gateway interface not found: {}", member.gateway_name
                )))?;

            nexthops.push(Nexthop {
                gateway: *gateway_ip,
                interface: interface.clone(),
                weight: member.weight,
            });
        }

        Ok(RoutingConfig {
            group_name: group_name.to_string(),
            active_tier,
            nexthops,
            sticky: group.sticky_connections,
        })
    }

    /// Get status summary for all groups
    pub fn get_status_summary(
        &self,
        online_gateways: &[String],
    ) -> HashMap<String, GroupStatus> {
        let mut summary = HashMap::new();

        for (name, group) in &self.groups {
            let active_tier = group.get_active_tier(online_gateways);
            let active_count = group.get_active_members(online_gateways).len();
            let total_count = group.members.len();

            summary.insert(name.clone(), GroupStatus {
                enabled: group.enabled,
                active_tier,
                active_gateways: active_count,
                total_gateways: total_count,
                is_healthy: active_tier == Some(1), // Tier 1 is optimal
                is_degraded: active_tier.is_some() && active_tier != Some(1),
                is_down: active_tier.is_none(),
            });
        }

        summary
    }
}

impl Default for GatewayGroupManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Routing configuration generated from gateway group
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoutingConfig {
    pub group_name: String,
    pub active_tier: GatewayTier,
    pub nexthops: Vec<Nexthop>,
    pub sticky: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Nexthop {
    pub gateway: IpAddr,
    pub interface: String,
    pub weight: u32,
}

/// Gateway group status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupStatus {
    pub enabled: bool,
    pub active_tier: Option<GatewayTier>,
    pub active_gateways: usize,
    pub total_gateways: usize,
    pub is_healthy: bool,    // All Tier 1 gateways online
    pub is_degraded: bool,   // Failover to Tier 2+
    pub is_down: bool,       // No gateways online
}

/// Example configurations
impl AdvancedGatewayGroup {
    /// Example: Fiber + Cable + 4G failover
    pub fn example_tiered_failover() -> Self {
        Self {
            name: "WAN_Failover".to_string(),
            description: "Fiber primary, cable backup, 4G emergency".to_string(),
            enabled: true,
            members: vec![
                GatewayGroupMember {
                    gateway_name: "fiber_wan".to_string(),
                    tier: 1,  // Primary
                    weight: 100,
                },
                GatewayGroupMember {
                    gateway_name: "cable_wan".to_string(),
                    tier: 2,  // Backup
                    weight: 100,
                },
                GatewayGroupMember {
                    gateway_name: "lte_wan".to_string(),
                    tier: 3,  // Emergency
                    weight: 100,
                },
            ],
            trigger_level: 1,
            sticky_connections: true,
        }
    }

    /// Example: Dual fiber load balancing with cable backup
    pub fn example_load_balance_with_backup() -> Self {
        Self {
            name: "WAN_LoadBalance".to_string(),
            description: "Load balance 2 fiber links, fail to cable".to_string(),
            enabled: true,
            members: vec![
                GatewayGroupMember {
                    gateway_name: "fiber1_wan".to_string(),
                    tier: 1,  // Primary tier
                    weight: 100,
                },
                GatewayGroupMember {
                    gateway_name: "fiber2_wan".to_string(),
                    tier: 1,  // Same tier = load balance
                    weight: 100,
                },
                GatewayGroupMember {
                    gateway_name: "cable_wan".to_string(),
                    tier: 2,  // Backup tier
                    weight: 100,
                },
            ],
            trigger_level: 1,
            sticky_connections: false,  // True round-robin
        }
    }

    /// Example: Weighted load balancing (1 Gbps + 500 Mbps)
    pub fn example_weighted_load_balance() -> Self {
        Self {
            name: "WAN_Weighted".to_string(),
            description: "Weighted 2:1 for different link speeds".to_string(),
            enabled: true,
            members: vec![
                GatewayGroupMember {
                    gateway_name: "wan_1gbps".to_string(),
                    tier: 1,
                    weight: 200,  // 2x weight
                },
                GatewayGroupMember {
                    gateway_name: "wan_500mbps".to_string(),
                    tier: 1,
                    weight: 100,  // 1x weight
                },
            ],
            trigger_level: 1,
            sticky_connections: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tiered_failover() {
        let group = AdvancedGatewayGroup::example_tiered_failover();

        // All online - should use Tier 1
        let online = vec!["fiber_wan".to_string(), "cable_wan".to_string(), "lte_wan".to_string()];
        assert_eq!(group.get_active_tier(&online), Some(1));

        // Tier 1 down - should fail to Tier 2
        let online = vec!["cable_wan".to_string(), "lte_wan".to_string()];
        assert_eq!(group.get_active_tier(&online), Some(2));

        // Only Tier 3 - should use it
        let online = vec!["lte_wan".to_string()];
        assert_eq!(group.get_active_tier(&online), Some(3));

        // All down - should return None
        let online = vec![];
        assert_eq!(group.get_active_tier(&online), None);
    }

    #[test]
    fn test_load_balance_within_tier() {
        let group = AdvancedGatewayGroup::example_load_balance_with_backup();

        let online = vec!["fiber1_wan".to_string(), "fiber2_wan".to_string(), "cable_wan".to_string()];

        // Should use Tier 1 (both fibers)
        assert_eq!(group.get_active_tier(&online), Some(1));

        let active = group.get_active_members(&online);
        assert_eq!(active.len(), 2);  // Both Tier 1 members
        assert!(active.iter().all(|m| m.tier == 1));
    }

    #[test]
    fn test_weighted_routing() {
        let group = AdvancedGatewayGroup::example_weighted_load_balance();

        let online = vec!["wan_1gbps".to_string(), "wan_500mbps".to_string()];
        let active = group.get_active_members(&online);

        assert_eq!(active.len(), 2);

        // Check weights
        let wan1 = active.iter().find(|m| m.gateway_name == "wan_1gbps").unwrap();
        let wan2 = active.iter().find(|m| m.gateway_name == "wan_500mbps").unwrap();

        assert_eq!(wan1.weight, 200);
        assert_eq!(wan2.weight, 100);
    }

    #[test]
    fn test_group_validation() {
        let mut group = AdvancedGatewayGroup::example_tiered_failover();
        assert!(group.validate().is_ok());

        // Empty group
        group.members.clear();
        assert!(group.validate().is_err());

        // Invalid tier
        group.members.push(GatewayGroupMember {
            gateway_name: "test".to_string(),
            tier: 0,  // Invalid
            weight: 100,
        });
        assert!(group.validate().is_err());
    }

    #[test]
    fn test_gateway_group_manager() {
        let mut manager = GatewayGroupManager::new();

        let group = AdvancedGatewayGroup::example_tiered_failover();
        manager.add_group(group.clone()).unwrap();

        assert_eq!(manager.list_groups().len(), 1);
        assert!(manager.get_group(&group.name).is_some());

        manager.remove_group(&group.name).unwrap();
        assert_eq!(manager.list_groups().len(), 0);
    }
}
