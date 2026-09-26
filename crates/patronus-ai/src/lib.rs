//! AI-Powered Threat Intelligence Engine for Patronus Firewall
//!
//! This module provides machine learning-based threat detection, threat intelligence
//! integration, and automatic firewall rule generation.

pub mod engine;
pub mod feature_collector;
pub mod models;
pub mod rule_generator;
pub mod threat_intel;

pub use engine::ThreatDetectionEngine;
pub use feature_collector::{FeatureCollector, FeatureVector, FlowFeatures, SourceFeatures};
pub use models::{ThreatClassifier, ThreatDetection, ThreatType};
pub use rule_generator::{AutoRule, RuleGenPolicy, RuleGenerator};
pub use threat_intel::{
    ThreatCategory, ThreatFeedAggregator, ThreatIntelDB, ThreatIntelEntry, ThreatSource,
};
