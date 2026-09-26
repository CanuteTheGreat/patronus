//! Machine Learning Module for SD-WAN
//!
//! Provides three ML-powered features:
//! 1. Anomaly Detection - Detect unusual traffic patterns
//! 2. Predictive Failover - Predict link failures before they happen
//! 3. Encrypted Traffic DPI - Classify encrypted traffic using ML

pub mod anomaly;
pub mod dpi;
pub mod failover;

pub use anomaly::{AnomalyDetector, AnomalyScore};
pub use dpi::{EncryptedDpi, TrafficClass};
pub use failover::{FailoverPrediction, PredictiveFailover};
