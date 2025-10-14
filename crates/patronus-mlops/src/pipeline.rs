//! ML Training Pipeline

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;
use chrono::{DateTime, Utc};
use anyhow::Result;
use async_trait::async_trait;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PipelineStage {
    DataCollection,
    DataPreprocessing,
    FeatureEngineering,
    Training,
    Validation,
    Testing,
    Deployment,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PipelineStatus {
    Pending,
    Running,
    Completed,
    Failed,
    Cancelled,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StageResult {
    pub stage: PipelineStage,
    pub status: PipelineStatus,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub error: Option<String>,
    pub metrics: HashMap<String, f64>,
}

impl StageResult {
    pub fn new(stage: PipelineStage) -> Self {
        Self {
            stage,
            status: PipelineStatus::Pending,
            started_at: None,
            completed_at: None,
            error: None,
            metrics: HashMap::new(),
        }
    }

    pub fn start(&mut self) {
        self.status = PipelineStatus::Running;
        self.started_at = Some(Utc::now());
    }

    pub fn complete(&mut self) {
        self.status = PipelineStatus::Completed;
        self.completed_at = Some(Utc::now());
    }

    pub fn fail(&mut self, error: String) {
        self.status = PipelineStatus::Failed;
        self.completed_at = Some(Utc::now());
        self.error = Some(error);
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrainingConfig {
    pub model_name: String,
    pub version: String,
    pub hyperparameters: HashMap<String, serde_json::Value>,
    pub training_data_path: String,
    pub validation_split: f64,
    pub epochs: u32,
    pub batch_size: u32,
}

impl TrainingConfig {
    pub fn new(model_name: impl Into<String>, version: impl Into<String>) -> Self {
        Self {
            model_name: model_name.into(),
            version: version.into(),
            hyperparameters: HashMap::new(),
            training_data_path: String::new(),
            validation_split: 0.2,
            epochs: 100,
            batch_size: 32,
        }
    }

    pub fn with_hyperparameter(
        mut self,
        key: impl Into<String>,
        value: serde_json::Value,
    ) -> Self {
        self.hyperparameters.insert(key.into(), value);
        self
    }

    pub fn with_data_path(mut self, path: impl Into<String>) -> Self {
        self.training_data_path = path.into();
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineRun {
    pub id: Uuid,
    pub config: TrainingConfig,
    pub status: PipelineStatus,
    pub stages: Vec<StageResult>,
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub created_by: String,
}

impl PipelineRun {
    pub fn new(config: TrainingConfig, created_by: impl Into<String>) -> Self {
        Self {
            id: Uuid::new_v4(),
            config,
            status: PipelineStatus::Pending,
            stages: vec![
                StageResult::new(PipelineStage::DataCollection),
                StageResult::new(PipelineStage::DataPreprocessing),
                StageResult::new(PipelineStage::FeatureEngineering),
                StageResult::new(PipelineStage::Training),
                StageResult::new(PipelineStage::Validation),
                StageResult::new(PipelineStage::Testing),
                StageResult::new(PipelineStage::Deployment),
            ],
            started_at: Utc::now(),
            completed_at: None,
            created_by: created_by.into(),
        }
    }

    pub fn get_stage_mut(&mut self, stage: &PipelineStage) -> Option<&mut StageResult> {
        self.stages.iter_mut().find(|s| &s.stage == stage)
    }

    pub fn get_current_stage(&self) -> Option<&StageResult> {
        self.stages.iter().find(|s| s.status == PipelineStatus::Running)
    }

    pub fn is_complete(&self) -> bool {
        self.status == PipelineStatus::Completed || self.status == PipelineStatus::Failed
    }
}

#[async_trait]
pub trait PipelineExecutor: Send + Sync {
    async fn execute_stage(&self, stage: &PipelineStage, config: &TrainingConfig) -> Result<HashMap<String, f64>>;
}

pub struct TrainingPipeline<E: PipelineExecutor> {
    runs: HashMap<Uuid, PipelineRun>,
    executor: E,
}

impl<E: PipelineExecutor> TrainingPipeline<E> {
    pub fn new(executor: E) -> Self {
        Self {
            runs: HashMap::new(),
            executor,
        }
    }

    pub fn create_run(&mut self, config: TrainingConfig, created_by: impl Into<String>) -> Uuid {
        let run = PipelineRun::new(config, created_by);
        let run_id = run.id;
        self.runs.insert(run_id, run);
        tracing::info!("Created pipeline run: {}", run_id);
        run_id
    }

    pub fn get_run(&self, run_id: &Uuid) -> Option<&PipelineRun> {
        self.runs.get(run_id)
    }

    pub async fn execute_run(&mut self, run_id: &Uuid) -> Result<()> {
        let run = self.runs.get_mut(run_id)
            .ok_or_else(|| anyhow::anyhow!("Run not found"))?;

        run.status = PipelineStatus::Running;

        // Execute each stage
        for i in 0..run.stages.len() {
            let stage = run.stages[i].stage.clone();

            // Start stage
            run.stages[i].start();
            tracing::info!("Starting stage: {:?}", stage);

            // Execute stage
            match self.executor.execute_stage(&stage, &run.config).await {
                Ok(metrics) => {
                    run.stages[i].metrics = metrics;
                    run.stages[i].complete();
                    tracing::info!("Completed stage: {:?}", stage);
                }
                Err(e) => {
                    run.stages[i].fail(e.to_string());
                    run.status = PipelineStatus::Failed;
                    run.completed_at = Some(Utc::now());
                    tracing::error!("Stage failed: {:?} - {}", stage, e);
                    return Err(e);
                }
            }
        }

        run.status = PipelineStatus::Completed;
        run.completed_at = Some(Utc::now());
        tracing::info!("Pipeline run completed: {}", run_id);

        Ok(())
    }

    pub fn cancel_run(&mut self, run_id: &Uuid) -> Result<()> {
        let run = self.runs.get_mut(run_id)
            .ok_or_else(|| anyhow::anyhow!("Run not found"))?;

        if run.is_complete() {
            anyhow::bail!("Cannot cancel completed run");
        }

        run.status = PipelineStatus::Cancelled;
        run.completed_at = Some(Utc::now());

        tracing::info!("Cancelled pipeline run: {}", run_id);
        Ok(())
    }

    pub fn list_runs(&self) -> Vec<&PipelineRun> {
        self.runs.values().collect()
    }

    pub fn list_runs_by_status(&self, status: &PipelineStatus) -> Vec<&PipelineRun> {
        self.runs.values().filter(|r| &r.status == status).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockExecutor;

    #[async_trait]
    impl PipelineExecutor for MockExecutor {
        async fn execute_stage(&self, _stage: &PipelineStage, _config: &TrainingConfig) -> Result<HashMap<String, f64>> {
            let mut metrics = HashMap::new();
            metrics.insert("accuracy".to_string(), 0.95);
            Ok(metrics)
        }
    }

    #[test]
    fn test_pipeline_run_creation() {
        let config = TrainingConfig::new("test-model", "v1.0.0")
            .with_data_path("/data/training");

        let run = PipelineRun::new(config, "alice");

        assert_eq!(run.status, PipelineStatus::Pending);
        assert_eq!(run.stages.len(), 7);
    }

    #[tokio::test]
    async fn test_pipeline_execution() {
        let executor = MockExecutor;
        let mut pipeline = TrainingPipeline::new(executor);

        let config = TrainingConfig::new("test-model", "v1.0.0");
        let run_id = pipeline.create_run(config, "bob");

        pipeline.execute_run(&run_id).await.unwrap();

        let run = pipeline.get_run(&run_id).unwrap();
        assert_eq!(run.status, PipelineStatus::Completed);
        assert!(run.completed_at.is_some());

        // Check all stages completed
        for stage in &run.stages {
            assert_eq!(stage.status, PipelineStatus::Completed);
        }
    }

    #[tokio::test]
    async fn test_pipeline_cancellation() {
        let executor = MockExecutor;
        let mut pipeline = TrainingPipeline::new(executor);

        let config = TrainingConfig::new("test-model", "v1.0.0");
        let run_id = pipeline.create_run(config, "charlie");

        pipeline.cancel_run(&run_id).unwrap();

        let run = pipeline.get_run(&run_id).unwrap();
        assert_eq!(run.status, PipelineStatus::Cancelled);
    }

    struct FailingExecutor;

    #[async_trait]
    impl PipelineExecutor for FailingExecutor {
        async fn execute_stage(&self, stage: &PipelineStage, _config: &TrainingConfig) -> Result<HashMap<String, f64>> {
            if stage == &PipelineStage::Training {
                anyhow::bail!("Training failed");
            }
            Ok(HashMap::new())
        }
    }

    #[tokio::test]
    async fn test_pipeline_failure() {
        let executor = FailingExecutor;
        let mut pipeline = TrainingPipeline::new(executor);

        let config = TrainingConfig::new("test-model", "v1.0.0");
        let run_id = pipeline.create_run(config, "dave");

        let result = pipeline.execute_run(&run_id).await;
        assert!(result.is_err());

        let run = pipeline.get_run(&run_id).unwrap();
        assert_eq!(run.status, PipelineStatus::Failed);
    }

    #[test]
    fn test_stage_result() {
        let mut stage = StageResult::new(PipelineStage::Training);

        assert_eq!(stage.status, PipelineStatus::Pending);
        assert!(stage.started_at.is_none());

        stage.start();
        assert_eq!(stage.status, PipelineStatus::Running);
        assert!(stage.started_at.is_some());

        stage.complete();
        assert_eq!(stage.status, PipelineStatus::Completed);
        assert!(stage.completed_at.is_some());
    }
}
