//! 5G Network Slicing

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SliceType {
    EMBB,  // Enhanced Mobile Broadband
    URLLC, // Ultra-Reliable Low-Latency Communications
    MMTC,  // Massive Machine Type Communications
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkSlice {
    pub max_latency_ms: f64,
    pub min_bandwidth_mbps: f64,
    pub reliability_percent: f64,
}

impl NetworkSlice {
    pub fn embb() -> Self {
        Self {
            max_latency_ms: 50.0,
            min_bandwidth_mbps: 1000.0,
            reliability_percent: 99.0,
        }
    }

    pub fn urllc() -> Self {
        Self {
            max_latency_ms: 1.0,
            min_bandwidth_mbps: 100.0,
            reliability_percent: 99.999,
        }
    }

    pub fn mmtc() -> Self {
        Self {
            max_latency_ms: 1000.0,
            min_bandwidth_mbps: 1.0,
            reliability_percent: 99.0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FiveGSlice {
    pub id: Uuid,
    pub name: String,
    pub slice_type: SliceType,
    pub slice_config: NetworkSlice,
    pub allocated_bandwidth_mbps: f64,
    pub connected_devices: usize,
    pub active: bool,
}

impl FiveGSlice {
    pub fn new(name: String, slice_type: SliceType) -> Self {
        let slice_config = match slice_type {
            SliceType::EMBB => NetworkSlice::embb(),
            SliceType::URLLC => NetworkSlice::urllc(),
            SliceType::MMTC => NetworkSlice::mmtc(),
        };

        Self {
            id: Uuid::new_v4(),
            name,
            slice_type,
            slice_config,
            allocated_bandwidth_mbps: 0.0,
            connected_devices: 0,
            active: false,
        }
    }

    pub fn activate(&mut self) {
        self.active = true;
    }

    pub fn deactivate(&mut self) {
        self.active = false;
    }
}

pub struct SliceManager {
    slices: Arc<RwLock<HashMap<Uuid, FiveGSlice>>>,
}

impl SliceManager {
    pub fn new() -> Self {
        Self {
            slices: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn create_slice(&self, name: String, slice_type: SliceType) -> Uuid {
        let slice = FiveGSlice::new(name, slice_type);
        let id = slice.id;
        let mut slices = self.slices.write().await;
        slices.insert(id, slice);
        id
    }

    pub async fn get_slice(&self, id: &Uuid) -> Option<FiveGSlice> {
        let slices = self.slices.read().await;
        slices.get(id).cloned()
    }

    pub async fn activate_slice(&self, id: &Uuid) -> bool {
        let mut slices = self.slices.write().await;
        if let Some(slice) = slices.get_mut(id) {
            slice.activate();
            true
        } else {
            false
        }
    }

    pub async fn list_active_slices(&self) -> Vec<FiveGSlice> {
        let slices = self.slices.read().await;
        slices.values().filter(|s| s.active).cloned().collect()
    }
}

impl Default for SliceManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_slice_creation() {
        let slice = FiveGSlice::new("slice-1".to_string(), SliceType::EMBB);
        assert_eq!(slice.name, "slice-1");
        assert!(!slice.active);
    }

    #[test]
    fn test_slice_activation() {
        let mut slice = FiveGSlice::new("slice-1".to_string(), SliceType::URLLC);
        slice.activate();
        assert!(slice.active);
    }

    #[tokio::test]
    async fn test_slice_manager() {
        let manager = SliceManager::new();
        let id = manager.create_slice("test".to_string(), SliceType::MMTC).await;

        assert!(manager.activate_slice(&id).await);
        let slice = manager.get_slice(&id).await.unwrap();
        assert!(slice.active);
    }
}
