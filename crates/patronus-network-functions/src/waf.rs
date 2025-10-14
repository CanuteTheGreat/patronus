//! Web Application Firewall (WAF)
//!
//! Protection against common web attacks (SQL injection, XSS, etc.)

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;
use anyhow::Result;
use chrono::{DateTime, Utc};
use regex::Regex;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum WafRuleType {
    SqlInjection,
    CrossSiteScripting,
    PathTraversal,
    CommandInjection,
    RemoteFileInclusion,
    Custom,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum WafAction {
    Block,
    Alert,
    Log,
    Challenge, // CAPTCHA or similar
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WafRule {
    pub id: Uuid,
    pub name: String,
    pub rule_type: WafRuleType,
    pub enabled: bool,
    pub pattern: String,
    pub action: WafAction,
    pub priority: u32,
    pub match_count: u64,
    pub block_count: u64,
    pub created_at: DateTime<Utc>,
    pub last_matched: Option<DateTime<Utc>>,
}

impl WafRule {
    pub fn new(
        name: impl Into<String>,
        rule_type: WafRuleType,
        pattern: impl Into<String>,
        action: WafAction,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            name: name.into(),
            rule_type,
            enabled: true,
            pattern: pattern.into(),
            action,
            priority: 100,
            match_count: 0,
            block_count: 0,
            created_at: Utc::now(),
            last_matched: None,
        }
    }

    pub fn with_priority(mut self, priority: u32) -> Self {
        self.priority = priority;
        self
    }

    pub fn matches(&self, request: &HttpRequest) -> bool {
        if !self.enabled {
            return false;
        }

        // Compile regex (in production, cache compiled regexes)
        let re = match Regex::new(&self.pattern) {
            Ok(r) => r,
            Err(_) => return false,
        };

        // Check URL
        if re.is_match(&request.url) {
            return true;
        }

        // Check headers
        for (_, value) in &request.headers {
            if re.is_match(value) {
                return true;
            }
        }

        // Check body
        if let Some(ref body) = request.body {
            if re.is_match(body) {
                return true;
            }
        }

        false
    }
}

#[derive(Debug, Clone)]
pub struct HttpRequest {
    pub method: String,
    pub url: String,
    pub headers: HashMap<String, String>,
    pub body: Option<String>,
    pub client_ip: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WafEvent {
    pub id: Uuid,
    pub rule_id: Uuid,
    pub rule_name: String,
    pub action: WafAction,
    pub client_ip: String,
    pub url: String,
    pub matched_pattern: String,
    pub timestamp: DateTime<Utc>,
}

pub struct WafManager {
    rules: Arc<RwLock<HashMap<Uuid, WafRule>>>,
    events: Arc<RwLock<Vec<WafEvent>>>,
    max_events: usize,
}

impl WafManager {
    pub fn new() -> Self {
        let manager = Self {
            rules: Arc::new(RwLock::new(HashMap::new())),
            events: Arc::new(RwLock::new(Vec::new())),
            max_events: 10000,
        };

        // Initialize with default rules
        manager
    }

    pub fn with_max_events(mut self, max: usize) -> Self {
        self.max_events = max;
        self
    }

    pub async fn add_rule(&self, rule: WafRule) -> Uuid {
        let id = rule.id;
        let mut rules = self.rules.write().await;
        rules.insert(id, rule);
        tracing::info!("Added WAF rule: {}", id);
        id
    }

    pub async fn remove_rule(&self, id: &Uuid) -> Result<()> {
        let mut rules = self.rules.write().await;
        rules.remove(id)
            .ok_or_else(|| anyhow::anyhow!("WAF rule not found"))?;
        tracing::info!("Removed WAF rule: {}", id);
        Ok(())
    }

    pub async fn get_rule(&self, id: &Uuid) -> Option<WafRule> {
        let rules = self.rules.read().await;
        rules.get(id).cloned()
    }

    pub async fn list_rules(&self) -> Vec<WafRule> {
        let rules = self.rules.read().await;
        let mut rule_list: Vec<_> = rules.values().cloned().collect();
        rule_list.sort_by_key(|r| std::cmp::Reverse(r.priority));
        rule_list
    }

    pub async fn evaluate_request(&self, request: &HttpRequest) -> WafDecision {
        let result = {
            let mut rules = self.rules.write().await;

            // Sort by priority (higher priority first)
            let mut sorted_rules: Vec<_> = rules.values_mut().collect();
            sorted_rules.sort_by_key(|r| std::cmp::Reverse(r.priority));

            for rule in sorted_rules {
                if rule.matches(request) {
                    rule.match_count += 1;
                    rule.last_matched = Some(Utc::now());

                    let action = rule.action.clone();

                    if matches!(action, WafAction::Block) {
                        rule.block_count += 1;
                    }

                    // Collect data before releasing lock
                    let rule_id = rule.id;
                    let rule_name = rule.name.clone();
                    let matched_pattern = rule.pattern.clone();

                    // Record event
                    let event = WafEvent {
                        id: Uuid::new_v4(),
                        rule_id,
                        rule_name: rule_name.clone(),
                        action: action.clone(),
                        client_ip: request.client_ip.clone(),
                        url: request.url.clone(),
                        matched_pattern,
                        timestamp: Utc::now(),
                    };

                    drop(rules);
                    self.record_event(event).await;

                    return WafDecision {
                        allowed: !matches!(action, WafAction::Block),
                        action,
                        rule_id: Some(rule_id),
                        rule_name: Some(rule_name),
                    };
                }
            }

            None
        };

        result.unwrap_or(WafDecision {
            allowed: true,
            action: WafAction::Log,
            rule_id: None,
            rule_name: None,
        })
    }

    async fn record_event(&self, event: WafEvent) {
        let mut events = self.events.write().await;

        events.push(event);

        // Keep only recent events
        if events.len() > self.max_events {
            let drain_count = events.len() - self.max_events;
            events.drain(0..drain_count);
        }
    }

    pub async fn get_events(&self, limit: Option<usize>) -> Vec<WafEvent> {
        let events = self.events.read().await;
        let limit = limit.unwrap_or(100).min(events.len());
        events.iter().rev().take(limit).cloned().collect()
    }

    pub async fn get_stats(&self) -> WafStats {
        let rules = self.rules.read().await;
        let events = self.events.read().await;

        let total_matches: u64 = rules.values().map(|r| r.match_count).sum();
        let total_blocks: u64 = rules.values().map(|r| r.block_count).sum();

        WafStats {
            total_rules: rules.len(),
            enabled_rules: rules.values().filter(|r| r.enabled).count(),
            total_matches,
            total_blocks,
            recent_events: events.len(),
        }
    }

    pub async fn load_default_rules(&self) {
        // SQL Injection patterns
        let sql_injection = WafRule::new(
            "SQL Injection Detection",
            WafRuleType::SqlInjection,
            r"(?i)(union.*select|select.*from|insert.*into|delete.*from|update.*set|drop.*table|exec\s*\(|script|javascript|onload)",
            WafAction::Block,
        ).with_priority(200);

        // XSS patterns
        let xss = WafRule::new(
            "Cross-Site Scripting (XSS)",
            WafRuleType::CrossSiteScripting,
            r"(?i)(<script|javascript:|onerror=|onload=|onclick=|<iframe|<object|<embed)",
            WafAction::Block,
        ).with_priority(200);

        // Path traversal
        let path_traversal = WafRule::new(
            "Path Traversal Detection",
            WafRuleType::PathTraversal,
            r"(\.\./|\.\\.)",
            WafAction::Block,
        ).with_priority(180);

        // Command injection
        let cmd_injection = WafRule::new(
            "Command Injection Detection",
            WafRuleType::CommandInjection,
            r"(?i)(;|\||&|`|\$\(|>\s*/|\bcat\b|\bls\b|\bwhoami\b|\bpwd\b)",
            WafAction::Block,
        ).with_priority(180);

        // Remote file inclusion
        let rfi = WafRule::new(
            "Remote File Inclusion",
            WafRuleType::RemoteFileInclusion,
            r"(?i)(http://|https://|ftp://|file://|php://)",
            WafAction::Alert,
        ).with_priority(150);

        self.add_rule(sql_injection).await;
        self.add_rule(xss).await;
        self.add_rule(path_traversal).await;
        self.add_rule(cmd_injection).await;
        self.add_rule(rfi).await;

        tracing::info!("Loaded default WAF rules");
    }
}

impl Default for WafManager {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
pub struct WafDecision {
    pub allowed: bool,
    pub action: WafAction,
    pub rule_id: Option<Uuid>,
    pub rule_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WafStats {
    pub total_rules: usize,
    pub enabled_rules: usize,
    pub total_matches: u64,
    pub total_blocks: u64,
    pub recent_events: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_waf_rule_creation() {
        let rule = WafRule::new(
            "SQL Injection",
            WafRuleType::SqlInjection,
            r"union.*select",
            WafAction::Block,
        );

        assert_eq!(rule.name, "SQL Injection");
        assert_eq!(rule.rule_type, WafRuleType::SqlInjection);
        assert_eq!(rule.action, WafAction::Block);
        assert!(rule.enabled);
    }

    #[test]
    fn test_sql_injection_detection() {
        let rule = WafRule::new(
            "SQL Injection",
            WafRuleType::SqlInjection,
            r"(?i)(union.*select|select.*from)",
            WafAction::Block,
        );

        let mut headers = HashMap::new();
        headers.insert("User-Agent".to_string(), "Mozilla/5.0".to_string());

        let malicious_request = HttpRequest {
            method: "GET".to_string(),
            url: "/search?q=1' UNION SELECT * FROM users--".to_string(),
            headers: headers.clone(),
            body: None,
            client_ip: "203.0.113.50".to_string(),
        };

        assert!(rule.matches(&malicious_request));

        let safe_request = HttpRequest {
            method: "GET".to_string(),
            url: "/search?q=normal search".to_string(),
            headers,
            body: None,
            client_ip: "203.0.113.50".to_string(),
        };

        assert!(!rule.matches(&safe_request));
    }

    #[test]
    fn test_xss_detection() {
        let rule = WafRule::new(
            "XSS Detection",
            WafRuleType::CrossSiteScripting,
            r"(?i)(<script|javascript:|onerror=)",
            WafAction::Block,
        );

        let headers = HashMap::new();

        let xss_request = HttpRequest {
            method: "POST".to_string(),
            url: "/comment".to_string(),
            headers,
            body: Some("<script>alert('XSS')</script>".to_string()),
            client_ip: "203.0.113.50".to_string(),
        };

        assert!(rule.matches(&xss_request));
    }

    #[test]
    fn test_path_traversal_detection() {
        let rule = WafRule::new(
            "Path Traversal",
            WafRuleType::PathTraversal,
            r"(\.\./|\.\\.)",
            WafAction::Block,
        );

        let headers = HashMap::new();

        let traversal_request = HttpRequest {
            method: "GET".to_string(),
            url: "/download?file=../../../etc/passwd".to_string(),
            headers,
            body: None,
            client_ip: "203.0.113.50".to_string(),
        };

        assert!(rule.matches(&traversal_request));
    }

    #[tokio::test]
    async fn test_waf_manager() {
        let manager = WafManager::new();

        let rule = WafRule::new(
            "Test Rule",
            WafRuleType::SqlInjection,
            r"test",
            WafAction::Block,
        );

        let id = manager.add_rule(rule).await;
        assert!(manager.get_rule(&id).await.is_some());
        assert_eq!(manager.list_rules().await.len(), 1);
    }

    #[tokio::test]
    async fn test_request_evaluation() {
        let manager = WafManager::new();

        let rule = WafRule::new(
            "SQL Injection",
            WafRuleType::SqlInjection,
            r"(?i)union.*select",
            WafAction::Block,
        );

        manager.add_rule(rule).await;

        let headers = HashMap::new();
        let malicious_request = HttpRequest {
            method: "GET".to_string(),
            url: "/search?q=1' UNION SELECT * FROM users".to_string(),
            headers,
            body: None,
            client_ip: "203.0.113.50".to_string(),
        };

        let decision = manager.evaluate_request(&malicious_request).await;
        assert!(!decision.allowed);
        assert_eq!(decision.action, WafAction::Block);
        assert!(decision.rule_id.is_some());
    }

    #[tokio::test]
    async fn test_safe_request() {
        let manager = WafManager::new();

        let rule = WafRule::new(
            "SQL Injection",
            WafRuleType::SqlInjection,
            r"(?i)union.*select",
            WafAction::Block,
        );

        manager.add_rule(rule).await;

        let headers = HashMap::new();
        let safe_request = HttpRequest {
            method: "GET".to_string(),
            url: "/search?q=normal query".to_string(),
            headers,
            body: None,
            client_ip: "203.0.113.50".to_string(),
        };

        let decision = manager.evaluate_request(&safe_request).await;
        assert!(decision.allowed);
    }

    #[tokio::test]
    async fn test_rule_priority() {
        let manager = WafManager::new();

        let high_priority = WafRule::new(
            "High Priority",
            WafRuleType::Custom,
            r"test",
            WafAction::Block,
        ).with_priority(200);

        let low_priority = WafRule::new(
            "Low Priority",
            WafRuleType::Custom,
            r"test",
            WafAction::Alert,
        ).with_priority(100);

        manager.add_rule(high_priority).await;
        manager.add_rule(low_priority).await;

        let headers = HashMap::new();
        let request = HttpRequest {
            method: "GET".to_string(),
            url: "/test".to_string(),
            headers,
            body: None,
            client_ip: "203.0.113.50".to_string(),
        };

        let decision = manager.evaluate_request(&request).await;
        // Higher priority rule should match first
        assert_eq!(decision.action, WafAction::Block);
        assert_eq!(decision.rule_name, Some("High Priority".to_string()));
    }

    #[tokio::test]
    async fn test_event_recording() {
        let manager = WafManager::new().with_max_events(5);

        let rule = WafRule::new(
            "Test Rule",
            WafRuleType::SqlInjection,
            r"attack",
            WafAction::Block,
        );

        manager.add_rule(rule).await;

        let headers = HashMap::new();

        // Generate 10 events
        for i in 0..10 {
            let request = HttpRequest {
                method: "GET".to_string(),
                url: format!("/attack{}", i),
                headers: headers.clone(),
                body: None,
                client_ip: "203.0.113.50".to_string(),
            };

            manager.evaluate_request(&request).await;
        }

        let events = manager.get_events(None).await;
        assert_eq!(events.len(), 5); // Should only keep max_events
    }

    #[tokio::test]
    async fn test_default_rules() {
        let manager = WafManager::new();
        manager.load_default_rules().await;

        let rules = manager.list_rules().await;
        assert_eq!(rules.len(), 5);

        // Test SQL injection rule
        let headers = HashMap::new();
        let sql_request = HttpRequest {
            method: "GET".to_string(),
            url: "/search?q=1' UNION SELECT password FROM users".to_string(),
            headers,
            body: None,
            client_ip: "203.0.113.50".to_string(),
        };

        let decision = manager.evaluate_request(&sql_request).await;
        assert!(!decision.allowed);
    }

    #[tokio::test]
    async fn test_stats() {
        let manager = WafManager::new();

        let rule = WafRule::new(
            "Test Rule",
            WafRuleType::SqlInjection,
            r"attack",
            WafAction::Block,
        );

        manager.add_rule(rule).await;

        let headers = HashMap::new();
        let request = HttpRequest {
            method: "GET".to_string(),
            url: "/attack".to_string(),
            headers,
            body: None,
            client_ip: "203.0.113.50".to_string(),
        };

        manager.evaluate_request(&request).await;

        let stats = manager.get_stats().await;
        assert_eq!(stats.total_rules, 1);
        assert_eq!(stats.enabled_rules, 1);
        assert_eq!(stats.total_matches, 1);
        assert_eq!(stats.total_blocks, 1);
    }
}
