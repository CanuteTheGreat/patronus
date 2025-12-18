//! Firewall rule management

use patronus_core::{types::{FirewallRule, NatRule}, Result};
use std::sync::Arc;
use tokio::sync::RwLock;

#[cfg(feature = "nftables")]
use crate::nftables;

/// Manages firewall rules
pub struct RuleManager {
    filter_rules: Arc<RwLock<Vec<FirewallRule>>>,
    nat_rules: Arc<RwLock<Vec<NatRule>>>,
    next_filter_id: Arc<RwLock<u64>>,
    next_nat_id: Arc<RwLock<u64>>,
}

impl RuleManager {
    pub fn new() -> Self {
        Self {
            filter_rules: Arc::new(RwLock::new(Vec::new())),
            nat_rules: Arc::new(RwLock::new(Vec::new())),
            next_filter_id: Arc::new(RwLock::new(1)),
            next_nat_id: Arc::new(RwLock::new(1)),
        }
    }

    /// Initialize the firewall (create nftables table and chains)
    pub async fn initialize(&self) -> Result<()> {
        #[cfg(feature = "nftables")]
        {
            nftables::initialize_table()?;
            tracing::info!("Firewall initialized");
        }
        Ok(())
    }

    /// Apply all rules to the firewall
    pub async fn apply_all(&self) -> Result<()> {
        #[cfg(feature = "nftables")]
        {
            // Flush existing rules
            nftables::flush_table()?;

            // Reinitialize with base rules
            nftables::initialize_table()?;

            // Apply filter rules
            let filter_rules = self.filter_rules.read().await;
            for rule in filter_rules.iter() {
                if rule.enabled {
                    nftables::add_rule(rule)?;
                }
            }

            // Apply NAT rules
            let nat_rules = self.nat_rules.read().await;
            for rule in nat_rules.iter() {
                if rule.enabled {
                    nftables::add_nat_rule(rule)?;
                }
            }

            tracing::info!("Applied {} filter rules and {} NAT rules",
                filter_rules.len(), nat_rules.len());
        }
        Ok(())
    }

    /// Add a new firewall filter rule
    pub async fn add_filter_rule(&self, mut rule: FirewallRule) -> Result<()> {
        // Assign ID
        let mut next_id = self.next_filter_id.write().await;
        rule.id = Some(*next_id);
        *next_id += 1;
        drop(next_id);

        // Add to nftables if enabled
        #[cfg(feature = "nftables")]
        if rule.enabled {
            nftables::add_rule(&rule)?;
        }

        // Store rule
        let mut rules = self.filter_rules.write().await;
        rules.push(rule.clone());

        tracing::info!("Added filter rule: {}", rule.name);
        Ok(())
    }

    /// Add a new NAT rule
    pub async fn add_nat_rule(&mut self, mut rule: NatRule) -> Result<()> {
        // Assign ID
        let mut next_id = self.next_nat_id.write().await;
        rule.id = Some(*next_id);
        *next_id += 1;
        drop(next_id);

        // Add to nftables if enabled
        #[cfg(feature = "nftables")]
        if rule.enabled {
            nftables::add_nat_rule(&rule)?;
        }

        // Store rule
        let mut rules = self.nat_rules.write().await;
        rules.push(rule.clone());

        tracing::info!("Added NAT rule: {}", rule.name);
        Ok(())
    }

    /// List all firewall filter rules
    pub async fn list_filter_rules(&self) -> Result<Vec<FirewallRule>> {
        let rules = self.filter_rules.read().await;
        Ok(rules.clone())
    }

    /// List all NAT rules
    pub async fn list_nat_rules(&self) -> Result<Vec<NatRule>> {
        let rules = self.nat_rules.read().await;
        Ok(rules.clone())
    }

    /// Remove a firewall filter rule by ID
    pub async fn remove_filter_rule(&self, id: u64) -> Result<()> {
        let mut rules = self.filter_rules.write().await;
        rules.retain(|r| r.id != Some(id));

        // Reapply all rules to nftables
        drop(rules);
        self.apply_all().await?;

        tracing::info!("Removed filter rule ID: {}", id);
        Ok(())
    }

    /// Remove a NAT rule by ID
    pub async fn remove_nat_rule(&self, id: u64) -> Result<()> {
        let mut rules = self.nat_rules.write().await;
        rules.retain(|r| r.id != Some(id));

        // Reapply all rules to nftables
        drop(rules);
        self.apply_all().await?;

        tracing::info!("Removed NAT rule ID: {}", id);
        Ok(())
    }

    /// Flush all firewall rules
    pub async fn flush(&self) -> Result<()> {
        #[cfg(feature = "nftables")]
        {
            nftables::flush_table()?;
        }

        let mut filter_rules = self.filter_rules.write().await;
        filter_rules.clear();

        let mut nat_rules = self.nat_rules.write().await;
        nat_rules.clear();

        tracing::info!("Flushed all firewall rules");
        Ok(())
    }

    /// Enable IP forwarding
    pub async fn enable_forwarding(&self) -> Result<()> {
        #[cfg(feature = "nftables")]
        {
            nftables::enable_ip_forwarding()?;
        }
        Ok(())
    }

    /// Disable IP forwarding
    pub async fn disable_forwarding(&self) -> Result<()> {
        #[cfg(feature = "nftables")]
        {
            nftables::disable_ip_forwarding()?;
        }
        Ok(())
    }

    /// Get current nftables ruleset
    pub async fn get_nftables_ruleset(&self) -> Result<String> {
        #[cfg(feature = "nftables")]
        {
            nftables::list_table()
        }
        #[cfg(not(feature = "nftables"))]
        {
            Ok("nftables feature not enabled".to_string())
        }
    }
}

impl Default for RuleManager {
    fn default() -> Self {
        Self::new()
    }
}
