//! Resource Isolation and Quotas

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;
use anyhow::Result;
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceUsage {
    pub sites: u32,
    pub tunnels: u32,
    pub bandwidth_mbps: u32,
    pub users: u32,
}

impl Default for ResourceUsage {
    fn default() -> Self {
        Self {
            sites: 0,
            tunnels: 0,
            bandwidth_mbps: 0,
            users: 0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceQuota {
    pub max_sites: Option<u32>,
    pub max_tunnels: Option<u32>,
    pub max_bandwidth_mbps: Option<u32>,
    pub max_users: Option<u32>,
}

impl ResourceQuota {
    pub fn unlimited() -> Self {
        Self {
            max_sites: None,
            max_tunnels: None,
            max_bandwidth_mbps: None,
            max_users: None,
        }
    }

    pub fn check_sites(&self, current: u32, additional: u32) -> bool {
        match self.max_sites {
            Some(max) => current + additional <= max,
            None => true,
        }
    }

    pub fn check_tunnels(&self, current: u32, additional: u32) -> bool {
        match self.max_tunnels {
            Some(max) => current + additional <= max,
            None => true,
        }
    }

    pub fn check_bandwidth(&self, current: u32, additional: u32) -> bool {
        match self.max_bandwidth_mbps {
            Some(max) => current + additional <= max,
            None => true,
        }
    }

    pub fn check_users(&self, current: u32, additional: u32) -> bool {
        match self.max_users {
            Some(max) => current + additional <= max,
            None => true,
        }
    }
}

pub struct IsolationManager {
    usage: Arc<RwLock<HashMap<Uuid, ResourceUsage>>>,
    quotas: Arc<RwLock<HashMap<Uuid, ResourceQuota>>>,
}

impl IsolationManager {
    pub fn new() -> Self {
        Self {
            usage: Arc::new(RwLock::new(HashMap::new())),
            quotas: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn set_quota(&self, org_id: Uuid, quota: ResourceQuota) {
        let mut quotas = self.quotas.write().await;
        quotas.insert(org_id, quota);
        tracing::info!("Set quota for organization: {}", org_id);
    }

    pub async fn get_usage(&self, org_id: &Uuid) -> ResourceUsage {
        let usage = self.usage.read().await;
        usage.get(org_id).cloned().unwrap_or_default()
    }

    pub async fn get_quota(&self, org_id: &Uuid) -> Option<ResourceQuota> {
        let quotas = self.quotas.read().await;
        quotas.get(org_id).cloned()
    }

    pub async fn check_site_quota(&self, org_id: &Uuid, additional: u32) -> Result<()> {
        let usage = self.usage.read().await;
        let quotas = self.quotas.read().await;

        let current = usage.get(org_id).map(|u| u.sites).unwrap_or(0);
        let quota = quotas.get(org_id).ok_or_else(|| anyhow::anyhow!("No quota set"))?;

        if quota.check_sites(current, additional) {
            Ok(())
        } else {
            anyhow::bail!("Site quota exceeded: {}/{:?}", current + additional, quota.max_sites)
        }
    }

    pub async fn check_tunnel_quota(&self, org_id: &Uuid, additional: u32) -> Result<()> {
        let usage = self.usage.read().await;
        let quotas = self.quotas.read().await;

        let current = usage.get(org_id).map(|u| u.tunnels).unwrap_or(0);
        let quota = quotas.get(org_id).ok_or_else(|| anyhow::anyhow!("No quota set"))?;

        if quota.check_tunnels(current, additional) {
            Ok(())
        } else {
            anyhow::bail!("Tunnel quota exceeded: {}/{:?}", current + additional, quota.max_tunnels)
        }
    }

    pub async fn check_bandwidth_quota(&self, org_id: &Uuid, additional: u32) -> Result<()> {
        let usage = self.usage.read().await;
        let quotas = self.quotas.read().await;

        let current = usage.get(org_id).map(|u| u.bandwidth_mbps).unwrap_or(0);
        let quota = quotas.get(org_id).ok_or_else(|| anyhow::anyhow!("No quota set"))?;

        if quota.check_bandwidth(current, additional) {
            Ok(())
        } else {
            anyhow::bail!("Bandwidth quota exceeded: {}/{:?}", current + additional, quota.max_bandwidth_mbps)
        }
    }

    pub async fn check_user_quota(&self, org_id: &Uuid, additional: u32) -> Result<()> {
        let usage = self.usage.read().await;
        let quotas = self.quotas.read().await;

        let current = usage.get(org_id).map(|u| u.users).unwrap_or(0);
        let quota = quotas.get(org_id).ok_or_else(|| anyhow::anyhow!("No quota set"))?;

        if quota.check_users(current, additional) {
            Ok(())
        } else {
            anyhow::bail!("User quota exceeded: {}/{:?}", current + additional, quota.max_users)
        }
    }

    pub async fn increment_sites(&self, org_id: Uuid, count: u32) -> Result<()> {
        self.check_site_quota(&org_id, count).await?;

        let mut usage = self.usage.write().await;
        let org_usage = usage.entry(org_id).or_insert_with(ResourceUsage::default);
        org_usage.sites += count;

        tracing::debug!("Incremented sites for org {}: +{}", org_id, count);
        Ok(())
    }

    pub async fn decrement_sites(&self, org_id: Uuid, count: u32) {
        let mut usage = self.usage.write().await;
        if let Some(org_usage) = usage.get_mut(&org_id) {
            org_usage.sites = org_usage.sites.saturating_sub(count);
            tracing::debug!("Decremented sites for org {}: -{}", org_id, count);
        }
    }

    pub async fn increment_tunnels(&self, org_id: Uuid, count: u32) -> Result<()> {
        self.check_tunnel_quota(&org_id, count).await?;

        let mut usage = self.usage.write().await;
        let org_usage = usage.entry(org_id).or_insert_with(ResourceUsage::default);
        org_usage.tunnels += count;

        tracing::debug!("Incremented tunnels for org {}: +{}", org_id, count);
        Ok(())
    }

    pub async fn decrement_tunnels(&self, org_id: Uuid, count: u32) {
        let mut usage = self.usage.write().await;
        if let Some(org_usage) = usage.get_mut(&org_id) {
            org_usage.tunnels = org_usage.tunnels.saturating_sub(count);
            tracing::debug!("Decremented tunnels for org {}: -{}", org_id, count);
        }
    }

    pub async fn set_bandwidth(&self, org_id: Uuid, bandwidth_mbps: u32) -> Result<()> {
        let quotas = self.quotas.read().await;
        let quota = quotas.get(&org_id).ok_or_else(|| anyhow::anyhow!("No quota set"))?;

        if let Some(max) = quota.max_bandwidth_mbps {
            if bandwidth_mbps > max {
                anyhow::bail!("Bandwidth exceeds quota: {} > {}", bandwidth_mbps, max);
            }
        }

        let mut usage = self.usage.write().await;
        let org_usage = usage.entry(org_id).or_insert_with(ResourceUsage::default);
        org_usage.bandwidth_mbps = bandwidth_mbps;

        Ok(())
    }

    pub async fn increment_users(&self, org_id: Uuid, count: u32) -> Result<()> {
        self.check_user_quota(&org_id, count).await?;

        let mut usage = self.usage.write().await;
        let org_usage = usage.entry(org_id).or_insert_with(ResourceUsage::default);
        org_usage.users += count;

        tracing::debug!("Incremented users for org {}: +{}", org_id, count);
        Ok(())
    }

    pub async fn decrement_users(&self, org_id: Uuid, count: u32) {
        let mut usage = self.usage.write().await;
        if let Some(org_usage) = usage.get_mut(&org_id) {
            org_usage.users = org_usage.users.saturating_sub(count);
            tracing::debug!("Decremented users for org {}: -{}", org_id, count);
        }
    }
}

impl Default for IsolationManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_quota_enforcement() {
        let manager = IsolationManager::new();
        let org_id = Uuid::new_v4();

        let quota = ResourceQuota {
            max_sites: Some(5),
            max_tunnels: Some(10),
            max_bandwidth_mbps: Some(100),
            max_users: Some(10),
        };

        manager.set_quota(org_id, quota).await;

        // Should succeed
        assert!(manager.increment_sites(org_id, 3).await.is_ok());

        // Should fail (3 + 3 > 5)
        assert!(manager.increment_sites(org_id, 3).await.is_err());

        // Should succeed (3 + 2 = 5)
        assert!(manager.increment_sites(org_id, 2).await.is_ok());
    }

    #[tokio::test]
    async fn test_unlimited_quota() {
        let manager = IsolationManager::new();
        let org_id = Uuid::new_v4();

        manager.set_quota(org_id, ResourceQuota::unlimited()).await;

        // All should succeed
        assert!(manager.increment_sites(org_id, 1000).await.is_ok());
        assert!(manager.increment_tunnels(org_id, 1000).await.is_ok());
        assert!(manager.increment_users(org_id, 1000).await.is_ok());
    }

    #[tokio::test]
    async fn test_usage_tracking() {
        let manager = IsolationManager::new();
        let org_id = Uuid::new_v4();

        let quota = ResourceQuota {
            max_sites: Some(100),
            max_tunnels: Some(100),
            max_bandwidth_mbps: Some(1000),
            max_users: Some(100),
        };

        manager.set_quota(org_id, quota).await;

        manager.increment_sites(org_id, 5).await.unwrap();
        manager.increment_tunnels(org_id, 10).await.unwrap();
        manager.increment_users(org_id, 3).await.unwrap();

        let usage = manager.get_usage(&org_id).await;
        assert_eq!(usage.sites, 5);
        assert_eq!(usage.tunnels, 10);
        assert_eq!(usage.users, 3);
    }

    #[tokio::test]
    async fn test_decrement() {
        let manager = IsolationManager::new();
        let org_id = Uuid::new_v4();

        let quota = ResourceQuota {
            max_sites: Some(10),
            max_tunnels: Some(10),
            max_bandwidth_mbps: Some(100),
            max_users: Some(10),
        };

        manager.set_quota(org_id, quota).await;

        manager.increment_sites(org_id, 5).await.unwrap();
        manager.decrement_sites(org_id, 2).await;

        let usage = manager.get_usage(&org_id).await;
        assert_eq!(usage.sites, 3);

        // Should now succeed (3 + 5 = 8 <= 10)
        assert!(manager.increment_sites(org_id, 5).await.is_ok());
    }
}
