//! Model Registry for versioning and tracking

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;
use chrono::{DateTime, Utc};
use anyhow::Result;
use sha2::{Sha256, Digest};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum ModelType {
    AnomalyDetection,
    PredictiveFailover,
    EncryptedDpi,
    TrafficForecasting,
    QosOptimization,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ModelStatus {
    Training,
    Validated,
    Deployed,
    Archived,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelMetadata {
    pub accuracy: Option<f64>,
    pub precision: Option<f64>,
    pub recall: Option<f64>,
    pub f1_score: Option<f64>,
    pub training_samples: u32,
    pub validation_samples: u32,
    pub training_duration_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelVersion {
    pub id: Uuid,
    pub model_name: String,
    pub version: String,
    pub model_type: ModelType,
    pub status: ModelStatus,
    pub checksum: String,
    pub size_bytes: u64,
    pub created_at: DateTime<Utc>,
    pub created_by: String,
    pub metadata: ModelMetadata,
    pub tags: HashMap<String, String>,
}

impl ModelVersion {
    pub fn new(
        model_name: impl Into<String>,
        version: impl Into<String>,
        model_type: ModelType,
        created_by: impl Into<String>,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            model_name: model_name.into(),
            version: version.into(),
            model_type,
            status: ModelStatus::Training,
            checksum: String::new(),
            size_bytes: 0,
            created_at: Utc::now(),
            created_by: created_by.into(),
            metadata: ModelMetadata {
                accuracy: None,
                precision: None,
                recall: None,
                f1_score: None,
                training_samples: 0,
                validation_samples: 0,
                training_duration_secs: 0,
            },
            tags: HashMap::new(),
        }
    }

    pub fn with_checksum(mut self, data: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(data);
        self.checksum = hex::encode(hasher.finalize());
        self.size_bytes = data.len() as u64;
        self
    }

    pub fn with_metadata(mut self, metadata: ModelMetadata) -> Self {
        self.metadata = metadata;
        self
    }

    pub fn with_tag(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.tags.insert(key.into(), value.into());
        self
    }

    pub fn set_status(&mut self, status: ModelStatus) {
        self.status = status;
    }
}

pub struct ModelRegistry {
    models: HashMap<Uuid, ModelVersion>,
    versions_by_name: HashMap<String, Vec<Uuid>>, // model_name -> [version_ids]
    deployed_models: HashMap<ModelType, Uuid>,    // model_type -> deployed_version_id
}

impl ModelRegistry {
    pub fn new() -> Self {
        Self {
            models: HashMap::new(),
            versions_by_name: HashMap::new(),
            deployed_models: HashMap::new(),
        }
    }

    pub fn register_model(&mut self, model: ModelVersion) -> Result<Uuid> {
        let model_id = model.id;
        let model_name = model.model_name.clone();

        // Add to versions_by_name
        self.versions_by_name
            .entry(model_name.clone())
            .or_insert_with(Vec::new)
            .push(model_id);

        self.models.insert(model_id, model);
        tracing::info!("Registered model: {} ({})", model_name, model_id);

        Ok(model_id)
    }

    pub fn get_model(&self, model_id: &Uuid) -> Option<&ModelVersion> {
        self.models.get(model_id)
    }

    pub fn get_versions(&self, model_name: &str) -> Vec<&ModelVersion> {
        self.versions_by_name
            .get(model_name)
            .map(|ids| {
                ids.iter()
                    .filter_map(|id| self.models.get(id))
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn get_latest_version(&self, model_name: &str) -> Option<&ModelVersion> {
        self.versions_by_name
            .get(model_name)
            .and_then(|ids| ids.last())
            .and_then(|id| self.models.get(id))
    }

    pub fn deploy_model(&mut self, model_id: &Uuid) -> Result<()> {
        let model = self.models.get_mut(model_id)
            .ok_or_else(|| anyhow::anyhow!("Model not found"))?;

        if model.status != ModelStatus::Validated {
            anyhow::bail!("Model must be validated before deployment");
        }

        model.status = ModelStatus::Deployed;
        self.deployed_models.insert(model.model_type.clone(), *model_id);

        tracing::info!("Deployed model: {} ({})", model.model_name, model_id);
        Ok(())
    }

    pub fn get_deployed_model(&self, model_type: &ModelType) -> Option<&ModelVersion> {
        self.deployed_models
            .get(model_type)
            .and_then(|id| self.models.get(id))
    }

    pub fn update_status(&mut self, model_id: &Uuid, status: ModelStatus) -> Result<()> {
        let model = self.models.get_mut(model_id)
            .ok_or_else(|| anyhow::anyhow!("Model not found"))?;

        model.status = status;
        tracing::info!("Updated model status: {} -> {:?}", model_id, model.status);

        Ok(())
    }

    pub fn archive_model(&mut self, model_id: &Uuid) -> Result<()> {
        let model = self.models.get_mut(model_id)
            .ok_or_else(|| anyhow::anyhow!("Model not found"))?;

        if model.status == ModelStatus::Deployed {
            // Remove from deployed models
            self.deployed_models.remove(&model.model_type);
        }

        model.status = ModelStatus::Archived;
        tracing::info!("Archived model: {}", model_id);

        Ok(())
    }

    pub fn list_models_by_status(&self, status: &ModelStatus) -> Vec<&ModelVersion> {
        self.models
            .values()
            .filter(|m| &m.status == status)
            .collect()
    }

    pub fn search_by_tag(&self, key: &str, value: &str) -> Vec<&ModelVersion> {
        self.models
            .values()
            .filter(|m| m.tags.get(key).map(|v| v == value).unwrap_or(false))
            .collect()
    }
}

impl Default for ModelRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_model_registration() {
        let mut registry = ModelRegistry::new();

        let model = ModelVersion::new(
            "anomaly-detector",
            "v1.0.0",
            ModelType::AnomalyDetection,
            "alice",
        );

        let model_id = model.id;
        registry.register_model(model).unwrap();

        let retrieved = registry.get_model(&model_id).unwrap();
        assert_eq!(retrieved.model_name, "anomaly-detector");
        assert_eq!(retrieved.version, "v1.0.0");
    }

    #[test]
    fn test_version_tracking() {
        let mut registry = ModelRegistry::new();

        let v1 = ModelVersion::new(
            "traffic-forecaster",
            "v1.0.0",
            ModelType::TrafficForecasting,
            "bob",
        );
        registry.register_model(v1).unwrap();

        let v2 = ModelVersion::new(
            "traffic-forecaster",
            "v1.1.0",
            ModelType::TrafficForecasting,
            "bob",
        );
        registry.register_model(v2).unwrap();

        let versions = registry.get_versions("traffic-forecaster");
        assert_eq!(versions.len(), 2);

        let latest = registry.get_latest_version("traffic-forecaster").unwrap();
        assert_eq!(latest.version, "v1.1.0");
    }

    #[test]
    fn test_deployment() {
        let mut registry = ModelRegistry::new();

        let mut model = ModelVersion::new(
            "anomaly-detector",
            "v1.0.0",
            ModelType::AnomalyDetection,
            "charlie",
        );
        model.status = ModelStatus::Validated;

        let model_id = model.id;
        registry.register_model(model).unwrap();

        registry.deploy_model(&model_id).unwrap();

        let deployed = registry.get_deployed_model(&ModelType::AnomalyDetection).unwrap();
        assert_eq!(deployed.id, model_id);
        assert_eq!(deployed.status, ModelStatus::Deployed);
    }

    #[test]
    fn test_cannot_deploy_unvalidated() {
        let mut registry = ModelRegistry::new();

        let model = ModelVersion::new(
            "anomaly-detector",
            "v1.0.0",
            ModelType::AnomalyDetection,
            "dave",
        );

        let model_id = model.id;
        registry.register_model(model).unwrap();

        let result = registry.deploy_model(&model_id);
        assert!(result.is_err());
    }

    #[test]
    fn test_checksum() {
        let data = b"model_weights_data";
        let model = ModelVersion::new(
            "test-model",
            "v1.0.0",
            ModelType::AnomalyDetection,
            "eve",
        ).with_checksum(data);

        assert!(!model.checksum.is_empty());
        assert_eq!(model.size_bytes, data.len() as u64);
    }

    #[test]
    fn test_tag_search() {
        let mut registry = ModelRegistry::new();

        let model1 = ModelVersion::new(
            "model-1",
            "v1.0.0",
            ModelType::AnomalyDetection,
            "frank",
        ).with_tag("environment", "production");

        let model2 = ModelVersion::new(
            "model-2",
            "v1.0.0",
            ModelType::PredictiveFailover,
            "frank",
        ).with_tag("environment", "staging");

        registry.register_model(model1).unwrap();
        registry.register_model(model2).unwrap();

        let prod_models = registry.search_by_tag("environment", "production");
        assert_eq!(prod_models.len(), 1);
        assert_eq!(prod_models[0].model_name, "model-1");
    }
}
