//! Linkerd Integration

use serde::{Deserialize, Serialize};
use anyhow::Result;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceProfile {
    pub name: String,
    pub namespace: String,
    pub routes: Vec<RouteSpec>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteSpec {
    pub name: String,
    pub condition: RequestMatch,
    pub timeout: Option<String>,
    pub retry_budget: Option<RetryBudget>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestMatch {
    pub path_regex: Option<String>,
    pub method: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetryBudget {
    pub retry_ratio: f32,
    pub min_retries_per_second: u32,
    pub ttl: String,
}

pub struct LinkerdIntegration {
    namespace: String,
}

impl LinkerdIntegration {
    pub fn new(namespace: impl Into<String>) -> Self {
        Self { namespace: namespace.into() }
    }

    pub async fn create_service_profile(&self, profile: ServiceProfile) -> Result<()> {
        tracing::info!("Creating Linkerd ServiceProfile {}", profile.name);
        Ok(())
    }

    pub async fn enable_mtls(&self, service: &str) -> Result<()> {
        tracing::info!("Enabling mTLS for service {}", service);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_linkerd() {
        let linkerd = LinkerdIntegration::new("default");
        let profile = ServiceProfile {
            name: "test".to_string(),
            namespace: "default".to_string(),
            routes: vec![],
        };
        linkerd.create_service_profile(profile).await.unwrap();
    }
}
