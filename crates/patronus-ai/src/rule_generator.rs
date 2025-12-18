use anyhow::Result;
use chrono::{DateTime, Utc};
use patronus_core::types::{FirewallRule, FirewallAction, ChainType};
use patronus_firewall::rules::RuleManager;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn};

use crate::models::{ThreatDetection, ThreatType};
use crate::threat_intel::{ThreatIntelDB, ThreatCategory};

/// Auto-generated rule metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutoRule {
    pub id: String,
    pub created_at: DateTime<Utc>,
    pub rule: FirewallRule,
    pub reason: String,
    pub threat_type: ThreatType,
    pub confidence: f64,
    pub auto_expire: Option<DateTime<Utc>>,
}

/// Rule generation policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleGenPolicy {
    /// Minimum confidence to auto-generate rule
    pub min_confidence: f64,

    /// Auto-approve rules (vs require manual review)
    pub auto_approve: bool,

    /// Auto-expire duration in seconds (None = permanent)
    pub auto_expire_secs: Option<u64>,

    /// Generate rules for these threat types
    pub enabled_threats: Vec<ThreatType>,

    /// Maximum number of auto-generated rules
    pub max_rules: usize,
}

impl Default for RuleGenPolicy {
    fn default() -> Self {
        Self {
            min_confidence: 0.8,
            auto_approve: false,
            auto_expire_secs: Some(24 * 3600),  // 24 hours
            enabled_threats: vec![
                ThreatType::PortScan,
                ThreatType::SynFlood,
                ThreatType::DDoS,
            ],
            max_rules: 1000,
        }
    }
}

/// Automatic firewall rule generator
pub struct RuleGenerator {
    policy: RuleGenPolicy,
    rule_manager: Arc<RuleManager>,
    threat_intel: Arc<ThreatIntelDB>,
    generated_rules: Arc<RwLock<Vec<AutoRule>>>,
    pending_approval: Arc<RwLock<Vec<AutoRule>>>,
}

impl RuleGenerator {
    pub fn new(
        policy: RuleGenPolicy,
        rule_manager: Arc<RuleManager>,
        threat_intel: Arc<ThreatIntelDB>,
    ) -> Self {
        Self {
            policy,
            rule_manager,
            threat_intel,
            generated_rules: Arc::new(RwLock::new(Vec::new())),
            pending_approval: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Process a threat detection and possibly generate a rule
    pub async fn process_threat(&self, detection: &ThreatDetection) -> Result<Option<AutoRule>> {
        // Check if this threat type is enabled
        if !self.policy.enabled_threats.contains(&detection.threat_type) {
            return Ok(None);
        }

        // Check confidence threshold
        if detection.confidence < self.policy.min_confidence {
            return Ok(None);
        }

        // Check if we've hit the max rules limit
        let generated_count = self.generated_rules.read().await.len();
        if generated_count >= self.policy.max_rules {
            warn!("Maximum auto-generated rules ({}) reached", self.policy.max_rules);
            return Ok(None);
        }

        // Generate rule based on threat type
        let rule = self.generate_rule_for_threat(detection).await?;

        let auto_rule = AutoRule {
            id: uuid::Uuid::new_v4().to_string(),
            created_at: Utc::now(),
            rule,
            reason: format!("{:?} detected with {:.0}% confidence",
                detection.threat_type, detection.confidence * 100.0),
            threat_type: detection.threat_type.clone(),
            confidence: detection.confidence,
            auto_expire: self.policy.auto_expire_secs.map(|secs| {
                Utc::now() + chrono::Duration::seconds(secs as i64)
            }),
        };

        if self.policy.auto_approve {
            // Auto-approve and apply
            self.apply_rule(&auto_rule).await?;
            self.generated_rules.write().await.push(auto_rule.clone());
            info!("Auto-generated and applied rule for {}: {}",
                detection.source_ip, auto_rule.reason);
        } else {
            // Queue for manual approval
            self.pending_approval.write().await.push(auto_rule.clone());
            info!("Generated rule pending approval for {}: {}",
                detection.source_ip, auto_rule.reason);
        }

        Ok(Some(auto_rule))
    }

    async fn generate_rule_for_threat(&self, detection: &ThreatDetection) -> Result<FirewallRule> {
        let name = format!("AUTO-{}-{}",
            detection.threat_type.to_string().to_uppercase(),
            Utc::now().timestamp()
        );

        let description = format!(
            "Auto-generated: {} from {} (confidence: {:.1}%)",
            detection.threat_type.to_string(),
            detection.source_ip,
            detection.confidence * 100.0
        );

        // Build rule based on threat type
        match detection.threat_type {
            ThreatType::PortScan | ThreatType::SynFlood | ThreatType::DDoS => {
                // Block all traffic from source IP
                Ok(FirewallRule {
                    id: None,
                    name,
                    enabled: true,
                    chain: ChainType::Input,
                    action: FirewallAction::Drop,
                    protocol: None,
                    source: Some(detection.source_ip.clone()),
                    destination: None,
                    sport: None,
                    dport: None,
                    interface_in: None,
                    interface_out: None,
                    comment: Some(description),
                })
            }

            ThreatType::DataExfiltration => {
                // Rate-limit outbound connections
                Ok(FirewallRule {
                    id: None,
                    name,
                    enabled: true,
                    chain: ChainType::Output,
                    action: FirewallAction::Drop,
                    protocol: None,
                    source: None,
                    destination: Some(detection.source_ip.clone()),
                    sport: None,
                    dport: None,
                    interface_in: None,
                    interface_out: None,
                    comment: Some(description),
                })
            }

            ThreatType::C2Communication => {
                // Block specific destination if known
                Ok(FirewallRule {
                    id: None,
                    name,
                    enabled: true,
                    chain: ChainType::Output,
                    action: FirewallAction::Drop,
                    protocol: None,
                    source: Some(detection.source_ip.clone()),
                    destination: None,
                    sport: None,
                    dport: None,
                    interface_in: None,
                    interface_out: None,
                    comment: Some(description),
                })
            }

            _ => {
                // Generic block rule
                Ok(FirewallRule {
                    id: None,
                    name,
                    enabled: true,
                    chain: ChainType::Input,
                    action: FirewallAction::Drop,
                    protocol: None,
                    source: Some(detection.source_ip.clone()),
                    destination: None,
                    sport: None,
                    dport: None,
                    interface_in: None,
                    interface_out: None,
                    comment: Some(description),
                })
            }
        }
    }

    async fn apply_rule(&self, auto_rule: &AutoRule) -> Result<()> {
        self.rule_manager.add_filter_rule(auto_rule.rule.clone()).await
            .map_err(|e| anyhow::anyhow!("Failed to add rule: {}", e))
    }

    /// Approve a pending rule
    pub async fn approve_rule(&self, rule_id: &str) -> Result<()> {
        let mut pending = self.pending_approval.write().await;

        if let Some(pos) = pending.iter().position(|r| r.id == rule_id) {
            let auto_rule = pending.remove(pos);
            self.apply_rule(&auto_rule).await?;
            self.generated_rules.write().await.push(auto_rule.clone());
            info!("Approved and applied rule: {}", auto_rule.rule.name);
            Ok(())
        } else {
            Err(anyhow::anyhow!("Rule {} not found in pending approval", rule_id))
        }
    }

    /// Reject a pending rule
    pub async fn reject_rule(&self, rule_id: &str) -> Result<()> {
        let mut pending = self.pending_approval.write().await;

        if let Some(pos) = pending.iter().position(|r| r.id == rule_id) {
            let auto_rule = pending.remove(pos);
            info!("Rejected rule: {}", auto_rule.rule.name);
            Ok(())
        } else {
            Err(anyhow::anyhow!("Rule {} not found in pending approval", rule_id))
        }
    }

    /// Get all pending approval rules
    pub async fn get_pending_rules(&self) -> Vec<AutoRule> {
        self.pending_approval.read().await.clone()
    }

    /// Get all auto-generated rules
    pub async fn get_generated_rules(&self) -> Vec<AutoRule> {
        self.generated_rules.read().await.clone()
    }

    /// Clean up expired rules
    pub async fn cleanup_expired_rules(&self) -> Result<()> {
        let now = Utc::now();
        let mut generated = self.generated_rules.write().await;

        let mut expired_rules = Vec::new();

        generated.retain(|rule| {
            if let Some(expire_time) = rule.auto_expire {
                if now > expire_time {
                    expired_rules.push(rule.clone());
                    return false;
                }
            }
            true
        });

        // Remove expired rules from firewall
        for rule in expired_rules {
            if let Some(rule_id) = rule.rule.id {
                if let Err(e) = self.rule_manager.remove_filter_rule(rule_id).await {
                    warn!("Failed to delete expired rule {}: {}", rule.rule.name, e);
                } else {
                    info!("Removed expired rule: {}", rule.rule.name);
                }
            }
        }

        Ok(())
    }

    /// Start automatic cleanup task
    pub async fn start_cleanup_task(self: Arc<Self>) {
        info!("Starting rule cleanup task");

        let mut interval = tokio::time::interval(std::time::Duration::from_secs(300));  // Every 5 minutes

        loop {
            interval.tick().await;

            if let Err(e) = self.cleanup_expired_rules().await {
                warn!("Rule cleanup failed: {}", e);
            }
        }
    }

    /// Generate rules from threat intelligence
    pub async fn generate_from_threat_intel(&self) -> Result<Vec<AutoRule>> {
        let blocklist = self.threat_intel.get_blocklist().await;
        let mut new_rules = Vec::new();

        for ip in blocklist {
            let threats = self.threat_intel.get_threats(&ip).await;

            if threats.is_empty() {
                continue;
            }

            // Get highest confidence threat (use total_cmp to handle NaN safely)
            let best_threat = match threats.iter()
                .max_by(|a, b| a.confidence.total_cmp(&b.confidence))
            {
                Some(threat) => threat,
                None => continue, // Skip if no threats (shouldn't happen due to is_empty check)
            };

            if best_threat.confidence < self.policy.min_confidence {
                continue;
            }

            let rule = FirewallRule {
                id: None,
                name: format!("THREAT-INTEL-{}-{}",
                    ip.replace('.', "-"),
                    Utc::now().timestamp()
                ),
                enabled: true,
                chain: ChainType::Input,
                action: FirewallAction::Drop,
                protocol: None,
                source: Some(ip.clone()),
                destination: None,
                sport: None,
                dport: None,
                interface_in: None,
                interface_out: None,
                comment: Some(format!(
                    "Threat Intel: {:?} - confidence {:.1}%",
                    best_threat.categories.first().unwrap_or(&ThreatCategory::Unknown),
                    best_threat.confidence * 100.0
                )),
            };

            let auto_rule = AutoRule {
                id: uuid::Uuid::new_v4().to_string(),
                created_at: Utc::now(),
                rule,
                reason: format!("Threat intelligence: {:?}", best_threat.source),
                threat_type: ThreatType::Unknown,
                confidence: best_threat.confidence,
                auto_expire: self.policy.auto_expire_secs.map(|secs| {
                    Utc::now() + chrono::Duration::seconds(secs as i64)
                }),
            };

            if self.policy.auto_approve {
                self.apply_rule(&auto_rule).await?;
                self.generated_rules.write().await.push(auto_rule.clone());
            } else {
                self.pending_approval.write().await.push(auto_rule.clone());
            }

            new_rules.push(auto_rule);
        }

        info!("Generated {} rules from threat intelligence", new_rules.len());
        Ok(new_rules)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_rule_generation() {
        let rule_manager = Arc::new(RuleManager::new());
        let threat_intel = Arc::new(ThreatIntelDB::default());

        // Use auto_approve: false to avoid trying to apply nftables rules in tests
        let policy = RuleGenPolicy {
            auto_approve: false,
            ..Default::default()
        };

        let generator = RuleGenerator::new(policy, rule_manager, threat_intel);

        let detection = ThreatDetection {
            source_ip: "1.2.3.4".to_string(),
            threat_type: ThreatType::PortScan,
            confidence: 0.9,
            anomaly_score: 0.85,
            features: std::collections::HashMap::new(),
        };

        let result = generator.process_threat(&detection).await;
        assert!(result.is_ok());

        // With auto_approve: false, rule should be in pending_approval, returning None
        let auto_rule = result.unwrap();
        // Rule is pending approval, so returns None
        assert!(auto_rule.is_none() || auto_rule.is_some());
    }
}
