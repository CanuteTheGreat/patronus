//! Automated Retraining Triggers

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;
use chrono::{DateTime, Utc, Duration};
use anyhow::Result;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TriggerType {
    TimeBasedSchedule,
    PerformanceDegradation,
    DataDrift,
    ManualTrigger,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceThresholds {
    pub min_accuracy: f64,
    pub min_precision: f64,
    pub min_recall: f64,
    pub max_latency_ms: f64,
}

impl Default for PerformanceThresholds {
    fn default() -> Self {
        Self {
            min_accuracy: 0.85,
            min_precision: 0.80,
            min_recall: 0.80,
            max_latency_ms: 100.0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetrainingTrigger {
    pub id: Uuid,
    pub model_name: String,
    pub trigger_type: TriggerType,
    pub enabled: bool,
    pub schedule_interval_days: Option<u32>,
    pub performance_thresholds: Option<PerformanceThresholds>,
    pub data_drift_threshold: Option<f64>,
    pub last_triggered: Option<DateTime<Utc>>,
    pub trigger_count: u32,
}

impl RetrainingTrigger {
    pub fn time_based(model_name: impl Into<String>, interval_days: u32) -> Self {
        Self {
            id: Uuid::new_v4(),
            model_name: model_name.into(),
            trigger_type: TriggerType::TimeBasedSchedule,
            enabled: true,
            schedule_interval_days: Some(interval_days),
            performance_thresholds: None,
            data_drift_threshold: None,
            last_triggered: None,
            trigger_count: 0,
        }
    }

    pub fn performance_based(model_name: impl Into<String>, thresholds: PerformanceThresholds) -> Self {
        Self {
            id: Uuid::new_v4(),
            model_name: model_name.into(),
            trigger_type: TriggerType::PerformanceDegradation,
            enabled: true,
            schedule_interval_days: None,
            performance_thresholds: Some(thresholds),
            data_drift_threshold: None,
            last_triggered: None,
            trigger_count: 0,
        }
    }

    pub fn data_drift(model_name: impl Into<String>, threshold: f64) -> Self {
        Self {
            id: Uuid::new_v4(),
            model_name: model_name.into(),
            trigger_type: TriggerType::DataDrift,
            enabled: true,
            schedule_interval_days: None,
            performance_thresholds: None,
            data_drift_threshold: Some(threshold),
            last_triggered: None,
            trigger_count: 0,
        }
    }

    pub fn should_trigger_time_based(&self) -> bool {
        if !self.enabled || self.trigger_type != TriggerType::TimeBasedSchedule {
            return false;
        }

        let Some(interval_days) = self.schedule_interval_days else {
            return false;
        };

        match self.last_triggered {
            Some(last_trigger) => {
                let elapsed = Utc::now().signed_duration_since(last_trigger);
                elapsed >= Duration::days(interval_days as i64)
            }
            None => true, // Never triggered, should trigger
        }
    }

    pub fn should_trigger_performance(&self, metrics: &HashMap<String, f64>) -> bool {
        if !self.enabled || self.trigger_type != TriggerType::PerformanceDegradation {
            return false;
        }

        let Some(thresholds) = &self.performance_thresholds else {
            return false;
        };

        // Check if any metric falls below threshold
        if let Some(&accuracy) = metrics.get("accuracy") {
            if accuracy < thresholds.min_accuracy {
                return true;
            }
        }

        if let Some(&precision) = metrics.get("precision") {
            if precision < thresholds.min_precision {
                return true;
            }
        }

        if let Some(&recall) = metrics.get("recall") {
            if recall < thresholds.min_recall {
                return true;
            }
        }

        if let Some(&latency) = metrics.get("latency_ms") {
            if latency > thresholds.max_latency_ms {
                return true;
            }
        }

        false
    }

    pub fn should_trigger_data_drift(&self, drift_score: f64) -> bool {
        if !self.enabled || self.trigger_type != TriggerType::DataDrift {
            return false;
        }

        if let Some(threshold) = self.data_drift_threshold {
            drift_score > threshold
        } else {
            false
        }
    }

    pub fn trigger(&mut self) {
        self.last_triggered = Some(Utc::now());
        self.trigger_count += 1;
    }
}

pub struct RetrainingManager {
    triggers: HashMap<Uuid, RetrainingTrigger>,
    model_triggers: HashMap<String, Vec<Uuid>>, // model_name -> [trigger_ids]
}

impl RetrainingManager {
    pub fn new() -> Self {
        Self {
            triggers: HashMap::new(),
            model_triggers: HashMap::new(),
        }
    }

    pub fn add_trigger(&mut self, trigger: RetrainingTrigger) -> Uuid {
        let trigger_id = trigger.id;
        let model_name = trigger.model_name.clone();

        self.model_triggers
            .entry(model_name.clone())
            .or_insert_with(Vec::new)
            .push(trigger_id);

        self.triggers.insert(trigger_id, trigger);
        tracing::info!("Added retraining trigger for model: {}", model_name);

        trigger_id
    }

    pub fn remove_trigger(&mut self, trigger_id: &Uuid) -> Result<()> {
        let trigger = self.triggers.remove(trigger_id)
            .ok_or_else(|| anyhow::anyhow!("Trigger not found"))?;

        // Remove from model_triggers
        if let Some(triggers) = self.model_triggers.get_mut(&trigger.model_name) {
            triggers.retain(|id| id != trigger_id);
        }

        tracing::info!("Removed retraining trigger: {}", trigger_id);
        Ok(())
    }

    pub fn enable_trigger(&mut self, trigger_id: &Uuid) -> Result<()> {
        let trigger = self.triggers.get_mut(trigger_id)
            .ok_or_else(|| anyhow::anyhow!("Trigger not found"))?;

        trigger.enabled = true;
        tracing::info!("Enabled retraining trigger: {}", trigger_id);
        Ok(())
    }

    pub fn disable_trigger(&mut self, trigger_id: &Uuid) -> Result<()> {
        let trigger = self.triggers.get_mut(trigger_id)
            .ok_or_else(|| anyhow::anyhow!("Trigger not found"))?;

        trigger.enabled = false;
        tracing::info!("Disabled retraining trigger: {}", trigger_id);
        Ok(())
    }

    pub fn check_time_based_triggers(&mut self) -> Vec<String> {
        let mut models_to_retrain = vec![];

        for trigger in self.triggers.values_mut() {
            if trigger.should_trigger_time_based() {
                models_to_retrain.push(trigger.model_name.clone());
                trigger.trigger();
                tracing::info!("Time-based trigger fired for model: {}", trigger.model_name);
            }
        }

        models_to_retrain
    }

    pub fn check_performance_triggers(&mut self, model_name: &str, metrics: &HashMap<String, f64>) -> bool {
        if let Some(trigger_ids) = self.model_triggers.get(model_name) {
            for trigger_id in trigger_ids {
                if let Some(trigger) = self.triggers.get_mut(trigger_id) {
                    if trigger.should_trigger_performance(metrics) {
                        trigger.trigger();
                        tracing::warn!(
                            "Performance degradation detected for model: {} (accuracy: {:?})",
                            model_name,
                            metrics.get("accuracy")
                        );
                        return true;
                    }
                }
            }
        }
        false
    }

    pub fn check_data_drift_triggers(&mut self, model_name: &str, drift_score: f64) -> bool {
        if let Some(trigger_ids) = self.model_triggers.get(model_name) {
            for trigger_id in trigger_ids {
                if let Some(trigger) = self.triggers.get_mut(trigger_id) {
                    if trigger.should_trigger_data_drift(drift_score) {
                        trigger.trigger();
                        tracing::warn!(
                            "Data drift detected for model: {} (score: {})",
                            model_name,
                            drift_score
                        );
                        return true;
                    }
                }
            }
        }
        false
    }

    pub fn get_trigger(&self, trigger_id: &Uuid) -> Option<&RetrainingTrigger> {
        self.triggers.get(trigger_id)
    }

    pub fn list_triggers_for_model(&self, model_name: &str) -> Vec<&RetrainingTrigger> {
        self.model_triggers
            .get(model_name)
            .map(|ids| {
                ids.iter()
                    .filter_map(|id| self.triggers.get(id))
                    .collect()
            })
            .unwrap_or_default()
    }
}

impl Default for RetrainingManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_time_based_trigger() {
        let trigger = RetrainingTrigger::time_based("test-model", 7);

        assert_eq!(trigger.trigger_type, TriggerType::TimeBasedSchedule);
        assert!(trigger.should_trigger_time_based()); // Never triggered
    }

    #[test]
    fn test_performance_trigger() {
        let thresholds = PerformanceThresholds {
            min_accuracy: 0.90,
            ..Default::default()
        };

        let trigger = RetrainingTrigger::performance_based("test-model", thresholds);

        let mut good_metrics = HashMap::new();
        good_metrics.insert("accuracy".to_string(), 0.95);
        assert!(!trigger.should_trigger_performance(&good_metrics));

        let mut bad_metrics = HashMap::new();
        bad_metrics.insert("accuracy".to_string(), 0.85);
        assert!(trigger.should_trigger_performance(&bad_metrics));
    }

    #[test]
    fn test_data_drift_trigger() {
        let trigger = RetrainingTrigger::data_drift("test-model", 0.3);

        assert!(!trigger.should_trigger_data_drift(0.2)); // Below threshold
        assert!(trigger.should_trigger_data_drift(0.4)); // Above threshold
    }

    #[test]
    fn test_retraining_manager() {
        let mut manager = RetrainingManager::new();

        let trigger = RetrainingTrigger::time_based("anomaly-detector", 30);
        let trigger_id = manager.add_trigger(trigger);

        let triggers = manager.list_triggers_for_model("anomaly-detector");
        assert_eq!(triggers.len(), 1);

        manager.remove_trigger(&trigger_id).unwrap();

        let triggers = manager.list_triggers_for_model("anomaly-detector");
        assert_eq!(triggers.len(), 0);
    }

    #[test]
    fn test_trigger_count() {
        let mut trigger = RetrainingTrigger::time_based("test-model", 7);

        assert_eq!(trigger.trigger_count, 0);

        trigger.trigger();
        assert_eq!(trigger.trigger_count, 1);
        assert!(trigger.last_triggered.is_some());

        trigger.trigger();
        assert_eq!(trigger.trigger_count, 2);
    }

    #[test]
    fn test_enable_disable_trigger() {
        let mut manager = RetrainingManager::new();

        let trigger = RetrainingTrigger::time_based("test-model", 7);
        let trigger_id = manager.add_trigger(trigger);

        manager.disable_trigger(&trigger_id).unwrap();
        let trigger = manager.get_trigger(&trigger_id).unwrap();
        assert!(!trigger.enabled);

        manager.enable_trigger(&trigger_id).unwrap();
        let trigger = manager.get_trigger(&trigger_id).unwrap();
        assert!(trigger.enabled);
    }
}
