//! Organization Management

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;
use chrono::{DateTime, Utc};
use anyhow::Result;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SubscriptionTier {
    Free,
    Starter,
    Professional,
    Enterprise,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceQuota {
    pub max_sites: Option<u32>,
    pub max_tunnels: Option<u32>,
    pub max_bandwidth_mbps: Option<u32>,
    pub max_users: Option<u32>,
}

impl Default for ResourceQuota {
    fn default() -> Self {
        Self {
            max_sites: Some(5),
            max_tunnels: Some(10),
            max_bandwidth_mbps: Some(100),
            max_users: Some(10),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Organization {
    pub id: Uuid,
    pub name: String,
    pub display_name: String,
    pub parent_id: Option<Uuid>,
    pub subscription_tier: SubscriptionTier,
    pub quota: ResourceQuota,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub metadata: HashMap<String, String>,
}

impl Organization {
    pub fn new(name: impl Into<String>, display_name: impl Into<String>) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            name: name.into(),
            display_name: display_name.into(),
            parent_id: None,
            subscription_tier: SubscriptionTier::Free,
            quota: ResourceQuota::default(),
            created_at: now,
            updated_at: now,
            metadata: HashMap::new(),
        }
    }

    pub fn with_tier(mut self, tier: SubscriptionTier) -> Self {
        self.subscription_tier = tier.clone();
        self.quota = match tier {
            SubscriptionTier::Free => ResourceQuota {
                max_sites: Some(5),
                max_tunnels: Some(10),
                max_bandwidth_mbps: Some(100),
                max_users: Some(10),
            },
            SubscriptionTier::Starter => ResourceQuota {
                max_sites: Some(20),
                max_tunnels: Some(50),
                max_bandwidth_mbps: Some(500),
                max_users: Some(50),
            },
            SubscriptionTier::Professional => ResourceQuota {
                max_sites: Some(100),
                max_tunnels: Some(500),
                max_bandwidth_mbps: Some(5000),
                max_users: Some(500),
            },
            SubscriptionTier::Enterprise => ResourceQuota {
                max_sites: None,
                max_tunnels: None,
                max_bandwidth_mbps: None,
                max_users: None,
            },
        };
        self
    }

    pub fn with_parent(mut self, parent_id: Uuid) -> Self {
        self.parent_id = Some(parent_id);
        self
    }

    pub fn is_child_of(&self, org_id: &Uuid) -> bool {
        self.parent_id.as_ref() == Some(org_id)
    }
}

pub struct OrganizationManager {
    organizations: HashMap<Uuid, Organization>,
    hierarchy: HashMap<Uuid, Vec<Uuid>>, // parent_id -> [child_ids]
}

impl OrganizationManager {
    pub fn new() -> Self {
        Self {
            organizations: HashMap::new(),
            hierarchy: HashMap::new(),
        }
    }

    pub fn create_organization(&mut self, org: Organization) -> Result<Uuid> {
        let org_id = org.id;

        // Update hierarchy if has parent
        if let Some(parent_id) = org.parent_id {
            self.hierarchy
                .entry(parent_id)
                .or_insert_with(Vec::new)
                .push(org_id);
        }

        self.organizations.insert(org_id, org);
        tracing::info!("Created organization: {}", org_id);

        Ok(org_id)
    }

    pub fn get_organization(&self, id: &Uuid) -> Option<&Organization> {
        self.organizations.get(id)
    }

    pub fn get_children(&self, parent_id: &Uuid) -> Vec<&Organization> {
        self.hierarchy
            .get(parent_id)
            .map(|child_ids| {
                child_ids
                    .iter()
                    .filter_map(|id| self.organizations.get(id))
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn get_hierarchy(&self, org_id: &Uuid) -> Vec<&Organization> {
        let mut result = vec![];
        let mut to_visit = vec![org_id];

        while let Some(current_id) = to_visit.pop() {
            if let Some(org) = self.organizations.get(current_id) {
                result.push(org);

                if let Some(children) = self.hierarchy.get(current_id) {
                    to_visit.extend(children);
                }
            }
        }

        result
    }

    pub fn update_tier(&mut self, org_id: &Uuid, tier: SubscriptionTier) -> Result<()> {
        if let Some(org) = self.organizations.get_mut(org_id) {
            org.subscription_tier = tier.clone();
            org.quota = match tier {
                SubscriptionTier::Free => ResourceQuota {
                    max_sites: Some(5),
                    max_tunnels: Some(10),
                    max_bandwidth_mbps: Some(100),
                    max_users: Some(10),
                },
                SubscriptionTier::Starter => ResourceQuota {
                    max_sites: Some(20),
                    max_tunnels: Some(50),
                    max_bandwidth_mbps: Some(500),
                    max_users: Some(50),
                },
                SubscriptionTier::Professional => ResourceQuota {
                    max_sites: Some(100),
                    max_tunnels: Some(500),
                    max_bandwidth_mbps: Some(5000),
                    max_users: Some(500),
                },
                SubscriptionTier::Enterprise => ResourceQuota {
                    max_sites: None,
                    max_tunnels: None,
                    max_bandwidth_mbps: None,
                    max_users: None,
                },
            };
            org.updated_at = Utc::now();
            Ok(())
        } else {
            anyhow::bail!("Organization not found")
        }
    }

    pub fn delete_organization(&mut self, org_id: &Uuid) -> Result<()> {
        // Check if has children
        if self.hierarchy.get(org_id).map_or(false, |c| !c.is_empty()) {
            anyhow::bail!("Cannot delete organization with children");
        }

        // Remove from parent's hierarchy
        if let Some(org) = self.organizations.get(org_id) {
            if let Some(parent_id) = org.parent_id {
                if let Some(children) = self.hierarchy.get_mut(&parent_id) {
                    children.retain(|id| id != org_id);
                }
            }
        }

        self.organizations.remove(org_id);
        tracing::info!("Deleted organization: {}", org_id);

        Ok(())
    }
}

impl Default for OrganizationManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_organization_creation() {
        let org = Organization::new("acme", "Acme Corporation")
            .with_tier(SubscriptionTier::Professional);

        assert_eq!(org.name, "acme");
        assert_eq!(org.display_name, "Acme Corporation");
        assert_eq!(org.subscription_tier, SubscriptionTier::Professional);
        assert_eq!(org.quota.max_sites, Some(100));
    }

    #[test]
    fn test_organization_hierarchy() {
        let mut manager = OrganizationManager::new();

        let parent = Organization::new("parent", "Parent Org")
            .with_tier(SubscriptionTier::Enterprise);
        let parent_id = parent.id;
        manager.create_organization(parent).unwrap();

        let child = Organization::new("child", "Child Org")
            .with_parent(parent_id);
        let child_id = child.id;
        manager.create_organization(child).unwrap();

        // Verify hierarchy
        let children = manager.get_children(&parent_id);
        assert_eq!(children.len(), 1);
        assert_eq!(children[0].id, child_id);

        // Verify get_hierarchy
        let hierarchy = manager.get_hierarchy(&parent_id);
        assert_eq!(hierarchy.len(), 2); // parent + child
    }

    #[test]
    fn test_tier_upgrade() {
        let mut manager = OrganizationManager::new();

        let org = Organization::new("test", "Test Org");
        let org_id = org.id;
        manager.create_organization(org).unwrap();

        manager.update_tier(&org_id, SubscriptionTier::Enterprise).unwrap();

        let updated = manager.get_organization(&org_id).unwrap();
        assert_eq!(updated.subscription_tier, SubscriptionTier::Enterprise);
        assert!(updated.quota.max_sites.is_none()); // Unlimited
    }

    #[test]
    fn test_cannot_delete_with_children() {
        let mut manager = OrganizationManager::new();

        let parent = Organization::new("parent", "Parent");
        let parent_id = parent.id;
        manager.create_organization(parent).unwrap();

        let child = Organization::new("child", "Child").with_parent(parent_id);
        manager.create_organization(child).unwrap();

        let result = manager.delete_organization(&parent_id);
        assert!(result.is_err());
    }
}
