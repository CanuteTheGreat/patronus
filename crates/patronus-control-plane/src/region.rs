//! Multi-Region Control Plane

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;
use chrono::{DateTime, Utc};
use anyhow::Result;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum RegionStatus {
    Active,
    Degraded,
    Offline,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Region {
    pub id: Uuid,
    pub name: String,
    pub location: String,
    pub endpoint: String,
    pub status: RegionStatus,
    pub capacity: RegionCapacity,
    pub created_at: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegionCapacity {
    pub max_sites: u32,
    pub current_sites: u32,
    pub max_tunnels: u32,
    pub current_tunnels: u32,
}

impl Region {
    pub fn new(name: impl Into<String>, location: impl Into<String>, endpoint: impl Into<String>) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            name: name.into(),
            location: location.into(),
            endpoint: endpoint.into(),
            status: RegionStatus::Active,
            capacity: RegionCapacity {
                max_sites: 1000,
                current_sites: 0,
                max_tunnels: 10000,
                current_tunnels: 0,
            },
            created_at: now,
            last_seen: now,
        }
    }

    pub fn is_available(&self) -> bool {
        self.status == RegionStatus::Active
    }

    pub fn has_capacity(&self) -> bool {
        self.capacity.current_sites < self.capacity.max_sites &&
        self.capacity.current_tunnels < self.capacity.max_tunnels
    }

    pub fn utilization_percent(&self) -> f64 {
        let site_util = self.capacity.current_sites as f64 / self.capacity.max_sites as f64;
        let tunnel_util = self.capacity.current_tunnels as f64 / self.capacity.max_tunnels as f64;
        site_util.max(tunnel_util) * 100.0
    }
}

pub struct RegionManager {
    regions: HashMap<Uuid, Region>,
    primary_region: Option<Uuid>,
}

impl RegionManager {
    pub fn new() -> Self {
        Self {
            regions: HashMap::new(),
            primary_region: None,
        }
    }

    pub fn register_region(&mut self, region: Region) -> Result<Uuid> {
        let region_id = region.id;

        // Set as primary if first region
        if self.primary_region.is_none() {
            self.primary_region = Some(region_id);
        }

        self.regions.insert(region_id, region);
        tracing::info!("Registered region: {}", region_id);

        Ok(region_id)
    }

    pub fn get_region(&self, region_id: &Uuid) -> Option<&Region> {
        self.regions.get(region_id)
    }

    pub fn get_primary_region(&self) -> Option<&Region> {
        self.primary_region.and_then(|id| self.regions.get(&id))
    }

    pub fn set_primary_region(&mut self, region_id: Uuid) -> Result<()> {
        if !self.regions.contains_key(&region_id) {
            anyhow::bail!("Region not found");
        }

        self.primary_region = Some(region_id);
        tracing::info!("Set primary region: {}", region_id);

        Ok(())
    }

    pub fn list_regions(&self) -> Vec<&Region> {
        self.regions.values().collect()
    }

    pub fn list_active_regions(&self) -> Vec<&Region> {
        self.regions
            .values()
            .filter(|r| r.is_available())
            .collect()
    }

    pub fn find_best_region(&self) -> Option<&Region> {
        self.regions
            .values()
            .filter(|r| r.is_available() && r.has_capacity())
            .min_by(|a, b| {
                a.utilization_percent()
                    .partial_cmp(&b.utilization_percent())
                    .unwrap()
            })
    }

    pub fn update_region_status(&mut self, region_id: &Uuid, status: RegionStatus) -> Result<()> {
        let region = self.regions.get_mut(region_id)
            .ok_or_else(|| anyhow::anyhow!("Region not found"))?;

        region.status = status;
        region.last_seen = Utc::now();

        tracing::info!("Updated region {} status to {:?}", region_id, region.status);

        Ok(())
    }

    pub fn heartbeat(&mut self, region_id: &Uuid) -> Result<()> {
        let region = self.regions.get_mut(region_id)
            .ok_or_else(|| anyhow::anyhow!("Region not found"))?;

        region.last_seen = Utc::now();

        Ok(())
    }

    pub fn remove_region(&mut self, region_id: &Uuid) -> Result<()> {
        if Some(*region_id) == self.primary_region {
            anyhow::bail!("Cannot remove primary region");
        }

        self.regions.remove(region_id);
        tracing::info!("Removed region: {}", region_id);

        Ok(())
    }
}

impl Default for RegionManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_region_creation() {
        let region = Region::new("us-east-1", "Virginia", "https://us-east-1.patronus.io");

        assert_eq!(region.name, "us-east-1");
        assert_eq!(region.location, "Virginia");
        assert!(region.is_available());
        assert!(region.has_capacity());
    }

    #[test]
    fn test_region_utilization() {
        let mut region = Region::new("us-west-2", "Oregon", "https://us-west-2.patronus.io");

        region.capacity.current_sites = 500;
        region.capacity.current_tunnels = 1000;

        let util = region.utilization_percent();
        assert_eq!(util, 50.0);
    }

    #[test]
    fn test_register_region() {
        let mut manager = RegionManager::new();
        let region = Region::new("eu-west-1", "Ireland", "https://eu-west-1.patronus.io");

        let region_id = manager.register_region(region).unwrap();

        assert!(manager.get_region(&region_id).is_some());
    }

    #[test]
    fn test_primary_region() {
        let mut manager = RegionManager::new();

        let region1 = Region::new("us-east-1", "Virginia", "https://us-east-1.patronus.io");
        let region1_id = region1.id;
        manager.register_region(region1).unwrap();

        let region2 = Region::new("us-west-2", "Oregon", "https://us-west-2.patronus.io");
        manager.register_region(region2).unwrap();

        // First region should be primary
        let primary = manager.get_primary_region().unwrap();
        assert_eq!(primary.id, region1_id);
    }

    #[test]
    fn test_set_primary_region() {
        let mut manager = RegionManager::new();

        let region1 = Region::new("us-east-1", "Virginia", "https://us-east-1.patronus.io");
        manager.register_region(region1).unwrap();

        let region2 = Region::new("us-west-2", "Oregon", "https://us-west-2.patronus.io");
        let region2_id = region2.id;
        manager.register_region(region2).unwrap();

        manager.set_primary_region(region2_id).unwrap();

        let primary = manager.get_primary_region().unwrap();
        assert_eq!(primary.id, region2_id);
    }

    #[test]
    fn test_list_active_regions() {
        let mut manager = RegionManager::new();

        let mut region1 = Region::new("us-east-1", "Virginia", "https://us-east-1.patronus.io");
        region1.status = RegionStatus::Active;
        manager.register_region(region1).unwrap();

        let mut region2 = Region::new("us-west-2", "Oregon", "https://us-west-2.patronus.io");
        region2.status = RegionStatus::Offline;
        manager.register_region(region2).unwrap();

        let active = manager.list_active_regions();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].name, "us-east-1");
    }

    #[test]
    fn test_find_best_region() {
        let mut manager = RegionManager::new();

        let mut region1 = Region::new("us-east-1", "Virginia", "https://us-east-1.patronus.io");
        region1.capacity.current_sites = 900; // 90% utilized
        manager.register_region(region1).unwrap();

        let mut region2 = Region::new("us-west-2", "Oregon", "https://us-west-2.patronus.io");
        region2.capacity.current_sites = 300; // 30% utilized
        manager.register_region(region2).unwrap();

        let best = manager.find_best_region().unwrap();
        assert_eq!(best.name, "us-west-2");
    }

    #[test]
    fn test_update_region_status() {
        let mut manager = RegionManager::new();

        let region = Region::new("eu-west-1", "Ireland", "https://eu-west-1.patronus.io");
        let region_id = region.id;
        manager.register_region(region).unwrap();

        manager.update_region_status(&region_id, RegionStatus::Degraded).unwrap();

        let updated = manager.get_region(&region_id).unwrap();
        assert_eq!(updated.status, RegionStatus::Degraded);
    }

    #[test]
    fn test_cannot_remove_primary_region() {
        let mut manager = RegionManager::new();

        let region = Region::new("us-east-1", "Virginia", "https://us-east-1.patronus.io");
        let region_id = region.id;
        manager.register_region(region).unwrap();

        let result = manager.remove_region(&region_id);
        assert!(result.is_err());
    }

    #[test]
    fn test_heartbeat() {
        let mut manager = RegionManager::new();

        let region = Region::new("ap-south-1", "Mumbai", "https://ap-south-1.patronus.io");
        let region_id = region.id;
        let initial_seen = region.last_seen;
        manager.register_region(region).unwrap();

        std::thread::sleep(std::time::Duration::from_millis(10));

        manager.heartbeat(&region_id).unwrap();

        let updated = manager.get_region(&region_id).unwrap();
        assert!(updated.last_seen > initial_seen);
    }
}
