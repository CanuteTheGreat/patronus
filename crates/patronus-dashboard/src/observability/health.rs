//! Health check system for monitoring component status

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Overall health status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum HealthStatus {
    Healthy,
    Degraded,
    Unhealthy,
}

/// Individual component health
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentHealth {
    pub status: HealthStatus,
    pub message: Option<String>,
    pub last_check: chrono::DateTime<chrono::Utc>,
}

/// Health check manager
#[derive(Clone)]
pub struct HealthCheck {
    components: Arc<RwLock<HashMap<String, ComponentHealth>>>,
}

impl HealthCheck {
    /// Create new health check manager
    pub fn new() -> Self {
        Self {
            components: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Update component health
    pub async fn update_component(
        &self,
        name: impl Into<String>,
        status: HealthStatus,
        message: Option<String>,
    ) {
        let component = ComponentHealth {
            status,
            message,
            last_check: chrono::Utc::now(),
        };

        self.components.write().await.insert(name.into(), component);
    }

    /// Get overall health status
    pub async fn overall_status(&self) -> HealthStatus {
        let components = self.components.read().await;

        if components.is_empty() {
            return HealthStatus::Healthy;
        }

        let has_unhealthy = components
            .values()
            .any(|c| c.status == HealthStatus::Unhealthy);
        let has_degraded = components
            .values()
            .any(|c| c.status == HealthStatus::Degraded);

        if has_unhealthy {
            HealthStatus::Unhealthy
        } else if has_degraded {
            HealthStatus::Degraded
        } else {
            HealthStatus::Healthy
        }
    }

    /// Get all component health status
    pub async fn get_components(&self) -> HashMap<String, ComponentHealth> {
        self.components.read().await.clone()
    }

    /// Check database health
    pub async fn check_database(&self, pool: &sqlx::SqlitePool) -> bool {
        match sqlx::query("SELECT 1").fetch_one(pool).await {
            Ok(_) => {
                self.update_component("database", HealthStatus::Healthy, None)
                    .await;
                true
            }
            Err(e) => {
                self.update_component(
                    "database",
                    HealthStatus::Unhealthy,
                    Some(format!("Database error: {}", e)),
                )
                .await;
                false
            }
        }
    }

    /// Check SD-WAN engine health
    pub async fn check_sdwan(&self, db: &std::sync::Arc<patronus_sdwan::database::Database>) -> bool {
        match db.list_sites().await {
            Ok(_) => {
                self.update_component("sdwan", HealthStatus::Healthy, None)
                    .await;
                true
            }
            Err(e) => {
                self.update_component(
                    "sdwan",
                    HealthStatus::Unhealthy,
                    Some(format!("SD-WAN error: {}", e)),
                )
                .await;
                false
            }
        }
    }

    /// Perform liveness check (basic health)
    pub async fn liveness(&self) -> bool {
        // Liveness just checks if the service is running
        true
    }

    /// Perform readiness check (ready to serve traffic)
    pub async fn readiness(&self) -> bool {
        let status = self.overall_status().await;
        status != HealthStatus::Unhealthy
    }
}

impl Default for HealthCheck {
    fn default() -> Self {
        Self::new()
    }
}

/// Health check response
#[derive(Debug, Serialize)]
pub struct HealthResponse {
    pub status: HealthStatus,
    pub components: HashMap<String, ComponentHealth>,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_health_check_creation() {
        let health = HealthCheck::new();
        assert_eq!(health.overall_status().await, HealthStatus::Healthy);
    }

    #[tokio::test]
    async fn test_component_updates() {
        let health = HealthCheck::new();

        health
            .update_component("test", HealthStatus::Healthy, None)
            .await;
        assert_eq!(health.overall_status().await, HealthStatus::Healthy);

        health
            .update_component("test", HealthStatus::Degraded, Some("Warning".to_string()))
            .await;
        assert_eq!(health.overall_status().await, HealthStatus::Degraded);

        health
            .update_component("test", HealthStatus::Unhealthy, Some("Error".to_string()))
            .await;
        assert_eq!(health.overall_status().await, HealthStatus::Unhealthy);
    }

    #[tokio::test]
    async fn test_multiple_components() {
        let health = HealthCheck::new();

        health
            .update_component("db", HealthStatus::Healthy, None)
            .await;
        health
            .update_component("sdwan", HealthStatus::Healthy, None)
            .await;

        assert_eq!(health.overall_status().await, HealthStatus::Healthy);

        health
            .update_component("db", HealthStatus::Degraded, None)
            .await;
        assert_eq!(health.overall_status().await, HealthStatus::Degraded);
    }

    #[tokio::test]
    async fn test_liveness_and_readiness() {
        let health = HealthCheck::new();

        assert!(health.liveness().await);
        assert!(health.readiness().await);

        health
            .update_component("test", HealthStatus::Unhealthy, None)
            .await;

        assert!(health.liveness().await);
        assert!(!health.readiness().await);
    }
}
