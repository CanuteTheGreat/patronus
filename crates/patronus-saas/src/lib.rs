//! SD-WAN as a Service Platform
//!
//! Multi-tenant SaaS platform for managed SD-WAN services

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;
use chrono::{DateTime, Utc};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SubscriptionTier {
    Free,
    Starter,
    Professional,
    Enterprise,
}

impl SubscriptionTier {
    pub fn max_sites(&self) -> usize {
        match self {
            SubscriptionTier::Free => 2,
            SubscriptionTier::Starter => 10,
            SubscriptionTier::Professional => 100,
            SubscriptionTier::Enterprise => usize::MAX,
        }
    }

    pub fn max_bandwidth_gbps(&self) -> f64 {
        match self {
            SubscriptionTier::Free => 1.0,
            SubscriptionTier::Starter => 10.0,
            SubscriptionTier::Professional => 100.0,
            SubscriptionTier::Enterprise => f64::MAX,
        }
    }

    pub fn sla_uptime_percent(&self) -> f64 {
        match self {
            SubscriptionTier::Free => 95.0,
            SubscriptionTier::Starter => 99.0,
            SubscriptionTier::Professional => 99.9,
            SubscriptionTier::Enterprise => 99.99,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Subscription {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub tier: SubscriptionTier,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub active: bool,
}

impl Subscription {
    pub fn new(tenant_id: Uuid, tier: SubscriptionTier) -> Self {
        Self {
            id: Uuid::new_v4(),
            tenant_id,
            tier,
            created_at: Utc::now(),
            expires_at: None,
            active: true,
        }
    }

    pub fn is_expired(&self) -> bool {
        if let Some(expires_at) = self.expires_at {
            expires_at < Utc::now()
        } else {
            false
        }
    }

    pub fn is_active(&self) -> bool {
        self.active && !self.is_expired()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsageMetrics {
    pub tenant_id: Uuid,
    pub period_start: DateTime<Utc>,
    pub period_end: DateTime<Utc>,
    pub active_sites: usize,
    pub bandwidth_consumed_gb: f64,
    pub api_calls: u64,
    pub tunnel_hours: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tenant {
    pub id: Uuid,
    pub name: String,
    pub email: String,
    pub created_at: DateTime<Utc>,
    pub subscription_id: Option<Uuid>,
}

impl Tenant {
    pub fn new(name: String, email: String) -> Self {
        Self {
            id: Uuid::new_v4(),
            name,
            email,
            created_at: Utc::now(),
            subscription_id: None,
        }
    }
}

pub struct SaaSPlatform {
    tenants: Arc<RwLock<HashMap<Uuid, Tenant>>>,
    subscriptions: Arc<RwLock<HashMap<Uuid, Subscription>>>,
    usage_metrics: Arc<RwLock<HashMap<Uuid, Vec<UsageMetrics>>>>,
}

impl SaaSPlatform {
    pub fn new() -> Self {
        Self {
            tenants: Arc::new(RwLock::new(HashMap::new())),
            subscriptions: Arc::new(RwLock::new(HashMap::new())),
            usage_metrics: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn create_tenant(&self, name: String, email: String) -> Uuid {
        let tenant = Tenant::new(name, email);
        let id = tenant.id;

        let mut tenants = self.tenants.write().await;
        tenants.insert(id, tenant);

        id
    }

    pub async fn get_tenant(&self, id: &Uuid) -> Option<Tenant> {
        let tenants = self.tenants.read().await;
        tenants.get(id).cloned()
    }

    pub async fn create_subscription(&self, tenant_id: Uuid, tier: SubscriptionTier) -> Option<Uuid> {
        let subscription = Subscription::new(tenant_id, tier);
        let sub_id = subscription.id;

        // Update tenant with subscription
        let mut tenants = self.tenants.write().await;
        if let Some(tenant) = tenants.get_mut(&tenant_id) {
            tenant.subscription_id = Some(sub_id);

            let mut subscriptions = self.subscriptions.write().await;
            subscriptions.insert(sub_id, subscription);

            Some(sub_id)
        } else {
            None
        }
    }

    pub async fn get_subscription(&self, id: &Uuid) -> Option<Subscription> {
        let subscriptions = self.subscriptions.read().await;
        subscriptions.get(id).cloned()
    }

    pub async fn upgrade_subscription(&self, subscription_id: &Uuid, new_tier: SubscriptionTier) -> bool {
        let mut subscriptions = self.subscriptions.write().await;
        if let Some(subscription) = subscriptions.get_mut(subscription_id) {
            subscription.tier = new_tier;
            true
        } else {
            false
        }
    }

    pub async fn cancel_subscription(&self, subscription_id: &Uuid) -> bool {
        let mut subscriptions = self.subscriptions.write().await;
        if let Some(subscription) = subscriptions.get_mut(subscription_id) {
            subscription.active = false;
            true
        } else {
            false
        }
    }

    pub async fn record_usage(&self, tenant_id: Uuid, metrics: UsageMetrics) {
        let mut usage = self.usage_metrics.write().await;
        usage.entry(tenant_id).or_insert_with(Vec::new).push(metrics);
    }

    pub async fn get_usage_history(&self, tenant_id: &Uuid) -> Vec<UsageMetrics> {
        let usage = self.usage_metrics.read().await;
        usage.get(tenant_id).cloned().unwrap_or_default()
    }

    pub async fn check_quota(&self, tenant_id: &Uuid, sites: usize, bandwidth_gbps: f64) -> bool {
        let tenants = self.tenants.read().await;
        let tenant = match tenants.get(tenant_id) {
            Some(t) => t,
            None => return false,
        };

        let sub_id = match tenant.subscription_id {
            Some(id) => id,
            None => return false,
        };

        drop(tenants);

        let subscriptions = self.subscriptions.read().await;
        let subscription = match subscriptions.get(&sub_id) {
            Some(s) => s,
            None => return false,
        };

        if !subscription.is_active() {
            return false;
        }

        sites <= subscription.tier.max_sites() &&
        bandwidth_gbps <= subscription.tier.max_bandwidth_gbps()
    }

    pub async fn list_active_tenants(&self) -> Vec<Tenant> {
        let tenants = self.tenants.read().await;
        let subscriptions = self.subscriptions.read().await;

        tenants.values()
            .filter(|t| {
                if let Some(sub_id) = t.subscription_id {
                    subscriptions.get(&sub_id)
                        .map(|s| s.is_active())
                        .unwrap_or(false)
                } else {
                    false
                }
            })
            .cloned()
            .collect()
    }

    pub async fn get_platform_stats(&self) -> PlatformStats {
        let tenants = self.tenants.read().await;
        let subscriptions = self.subscriptions.read().await;

        let total_tenants = tenants.len();
        let active_subscriptions = subscriptions.values()
            .filter(|s| s.is_active())
            .count();

        let tier_counts = subscriptions.values()
            .filter(|s| s.is_active())
            .fold(HashMap::new(), |mut acc, s| {
                *acc.entry(format!("{:?}", s.tier)).or_insert(0) += 1;
                acc
            });

        PlatformStats {
            total_tenants,
            active_subscriptions,
            tier_distribution: tier_counts,
        }
    }
}

impl Default for SaaSPlatform {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlatformStats {
    pub total_tenants: usize,
    pub active_subscriptions: usize,
    pub tier_distribution: HashMap<String, usize>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_subscription_tier_limits() {
        assert_eq!(SubscriptionTier::Free.max_sites(), 2);
        assert_eq!(SubscriptionTier::Starter.max_sites(), 10);
        assert_eq!(SubscriptionTier::Professional.max_sites(), 100);

        assert_eq!(SubscriptionTier::Free.max_bandwidth_gbps(), 1.0);
        assert_eq!(SubscriptionTier::Enterprise.sla_uptime_percent(), 99.99);
    }

    #[test]
    fn test_subscription_creation() {
        let tenant_id = Uuid::new_v4();
        let sub = Subscription::new(tenant_id, SubscriptionTier::Professional);

        assert_eq!(sub.tenant_id, tenant_id);
        assert_eq!(sub.tier, SubscriptionTier::Professional);
        assert!(sub.is_active());
        assert!(!sub.is_expired());
    }

    #[test]
    fn test_tenant_creation() {
        let tenant = Tenant::new("Acme Corp".to_string(), "admin@acme.com".to_string());

        assert_eq!(tenant.name, "Acme Corp");
        assert_eq!(tenant.email, "admin@acme.com");
        assert!(tenant.subscription_id.is_none());
    }

    #[tokio::test]
    async fn test_platform_create_tenant() {
        let platform = SaaSPlatform::new();
        let tenant_id = platform.create_tenant(
            "Test Corp".to_string(),
            "test@example.com".to_string()
        ).await;

        let tenant = platform.get_tenant(&tenant_id).await;
        assert!(tenant.is_some());
        assert_eq!(tenant.unwrap().name, "Test Corp");
    }

    #[tokio::test]
    async fn test_create_subscription() {
        let platform = SaaSPlatform::new();
        let tenant_id = platform.create_tenant(
            "Test Corp".to_string(),
            "test@example.com".to_string()
        ).await;

        let sub_id = platform.create_subscription(tenant_id, SubscriptionTier::Starter).await;
        assert!(sub_id.is_some());

        let subscription = platform.get_subscription(&sub_id.unwrap()).await;
        assert!(subscription.is_some());
        assert_eq!(subscription.unwrap().tier, SubscriptionTier::Starter);
    }

    #[tokio::test]
    async fn test_upgrade_subscription() {
        let platform = SaaSPlatform::new();
        let tenant_id = platform.create_tenant("Test".to_string(), "test@test.com".to_string()).await;
        let sub_id = platform.create_subscription(tenant_id, SubscriptionTier::Free).await.unwrap();

        assert!(platform.upgrade_subscription(&sub_id, SubscriptionTier::Professional).await);

        let sub = platform.get_subscription(&sub_id).await.unwrap();
        assert_eq!(sub.tier, SubscriptionTier::Professional);
    }

    #[tokio::test]
    async fn test_cancel_subscription() {
        let platform = SaaSPlatform::new();
        let tenant_id = platform.create_tenant("Test".to_string(), "test@test.com".to_string()).await;
        let sub_id = platform.create_subscription(tenant_id, SubscriptionTier::Starter).await.unwrap();

        assert!(platform.cancel_subscription(&sub_id).await);

        let sub = platform.get_subscription(&sub_id).await.unwrap();
        assert!(!sub.is_active());
    }

    #[tokio::test]
    async fn test_usage_tracking() {
        let platform = SaaSPlatform::new();
        let tenant_id = platform.create_tenant("Test".to_string(), "test@test.com".to_string()).await;

        let metrics = UsageMetrics {
            tenant_id,
            period_start: Utc::now(),
            period_end: Utc::now(),
            active_sites: 5,
            bandwidth_consumed_gb: 100.0,
            api_calls: 1000,
            tunnel_hours: 720.0,
        };

        platform.record_usage(tenant_id, metrics).await;

        let history = platform.get_usage_history(&tenant_id).await;
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].active_sites, 5);
    }

    #[tokio::test]
    async fn test_check_quota_within_limits() {
        let platform = SaaSPlatform::new();
        let tenant_id = platform.create_tenant("Test".to_string(), "test@test.com".to_string()).await;
        platform.create_subscription(tenant_id, SubscriptionTier::Professional).await;

        assert!(platform.check_quota(&tenant_id, 50, 50.0).await);
    }

    #[tokio::test]
    async fn test_check_quota_exceeds_limits() {
        let platform = SaaSPlatform::new();
        let tenant_id = platform.create_tenant("Test".to_string(), "test@test.com".to_string()).await;
        platform.create_subscription(tenant_id, SubscriptionTier::Free).await;

        assert!(!platform.check_quota(&tenant_id, 10, 1.0).await); // Exceeds site limit
        assert!(!platform.check_quota(&tenant_id, 2, 5.0).await);  // Exceeds bandwidth limit
    }

    #[tokio::test]
    async fn test_list_active_tenants() {
        let platform = SaaSPlatform::new();

        let t1 = platform.create_tenant("Active1".to_string(), "a1@test.com".to_string()).await;
        let t2 = platform.create_tenant("Active2".to_string(), "a2@test.com".to_string()).await;
        let t3 = platform.create_tenant("Inactive".to_string(), "i@test.com".to_string()).await;

        platform.create_subscription(t1, SubscriptionTier::Starter).await;
        platform.create_subscription(t2, SubscriptionTier::Professional).await;
        let sub3 = platform.create_subscription(t3, SubscriptionTier::Free).await.unwrap();

        platform.cancel_subscription(&sub3).await;

        let active = platform.list_active_tenants().await;
        assert_eq!(active.len(), 2);
    }

    #[tokio::test]
    async fn test_platform_stats() {
        let platform = SaaSPlatform::new();

        let t1 = platform.create_tenant("T1".to_string(), "t1@test.com".to_string()).await;
        let t2 = platform.create_tenant("T2".to_string(), "t2@test.com".to_string()).await;

        platform.create_subscription(t1, SubscriptionTier::Starter).await;
        platform.create_subscription(t2, SubscriptionTier::Professional).await;

        let stats = platform.get_platform_stats().await;
        assert_eq!(stats.total_tenants, 2);
        assert_eq!(stats.active_subscriptions, 2);
    }
}
