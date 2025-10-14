//! Edge Workload Scheduling

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SchedulingPolicy {
    LeastLoaded,
    Latency,
    ResourceAware,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EdgeWorkload {
    pub id: Uuid,
    pub name: String,
    pub cpu_requirement: f64,
    pub memory_requirement_gb: f64,
    pub latency_requirement_ms: Option<f64>,
}

impl EdgeWorkload {
    pub fn new(name: String, cpu: f64, memory: f64) -> Self {
        Self {
            id: Uuid::new_v4(),
            name,
            cpu_requirement: cpu,
            memory_requirement_gb: memory,
            latency_requirement_ms: None,
        }
    }

    pub fn with_latency_requirement(mut self, latency_ms: f64) -> Self {
        self.latency_requirement_ms = Some(latency_ms);
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkloadPlacement {
    pub workload_id: Uuid,
    pub node_id: Uuid,
    pub scheduled_successfully: bool,
}

pub struct WorkloadScheduler {
    placements: Arc<RwLock<HashMap<Uuid, WorkloadPlacement>>>,
    policy: SchedulingPolicy,
}

impl WorkloadScheduler {
    pub fn new(policy: SchedulingPolicy) -> Self {
        Self {
            placements: Arc::new(RwLock::new(HashMap::new())),
            policy,
        }
    }

    pub async fn schedule_workload(&self, workload: &EdgeWorkload, node_id: Uuid) -> bool {
        let placement = WorkloadPlacement {
            workload_id: workload.id,
            node_id,
            scheduled_successfully: true,
        };

        let mut placements = self.placements.write().await;
        placements.insert(workload.id, placement);
        true
    }

    pub async fn get_placement(&self, workload_id: &Uuid) -> Option<WorkloadPlacement> {
        let placements = self.placements.read().await;
        placements.get(workload_id).cloned()
    }

    pub async fn unschedule_workload(&self, workload_id: &Uuid) -> bool {
        let mut placements = self.placements.write().await;
        placements.remove(workload_id).is_some()
    }

    pub async fn list_placements(&self) -> Vec<WorkloadPlacement> {
        let placements = self.placements.read().await;
        placements.values().cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_workload_creation() {
        let workload = EdgeWorkload::new("app-1".to_string(), 2.0, 4.0);
        assert_eq!(workload.name, "app-1");
        assert_eq!(workload.cpu_requirement, 2.0);
    }

    #[test]
    fn test_workload_with_latency() {
        let workload = EdgeWorkload::new("app-1".to_string(), 2.0, 4.0)
            .with_latency_requirement(10.0);
        assert_eq!(workload.latency_requirement_ms, Some(10.0));
    }

    #[tokio::test]
    async fn test_schedule_workload() {
        let scheduler = WorkloadScheduler::new(SchedulingPolicy::LeastLoaded);
        let workload = EdgeWorkload::new("app-1".to_string(), 2.0, 4.0);
        let node_id = Uuid::new_v4();

        assert!(scheduler.schedule_workload(&workload, node_id).await);

        let placement = scheduler.get_placement(&workload.id).await;
        assert!(placement.is_some());
        assert_eq!(placement.unwrap().node_id, node_id);
    }

    #[tokio::test]
    async fn test_unschedule_workload() {
        let scheduler = WorkloadScheduler::new(SchedulingPolicy::LeastLoaded);
        let workload = EdgeWorkload::new("app-1".to_string(), 2.0, 4.0);
        let node_id = Uuid::new_v4();

        scheduler.schedule_workload(&workload, node_id).await;
        assert!(scheduler.unschedule_workload(&workload.id).await);
        assert!(scheduler.get_placement(&workload.id).await.is_none());
    }
}
