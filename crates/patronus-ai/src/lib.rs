//! AI-Powered Threat Intelligence Engine for Patronus Firewall
//!
//! This module provides machine learning-based threat detection, threat intelligence
//! integration, and automatic firewall rule generation.

pub mod feature_collector;
pub mod models;
pub mod threat_intel;
pub mod rule_generator;
pub mod engine;

pub use feature_collector::{FeatureCollector, FlowFeatures, SourceFeatures, FeatureVector};
pub use models::{ThreatClassifier, ThreatDetection, ThreatType};
pub use threat_intel::{ThreatIntelDB, ThreatFeedAggregator, ThreatIntelEntry, ThreatCategory, ThreatSource};
pub use rule_generator::{RuleGenerator, RuleGenPolicy, AutoRule};
pub use engine::ThreatDetectionEngine;
