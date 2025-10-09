use anyhow::Result;
use std::sync::Arc;
use std::time::Duration;
use tracing::{error, info};

use crate::feature_collector::{FeatureCollector, FlowFeatures};
use crate::models::ThreatClassifier;
use crate::threat_intel::{ThreatIntelDB, ThreatFeedAggregator};
use crate::rule_generator::{RuleGenerator, RuleGenPolicy};
use patronus_firewall::rules::RuleManager;

/// AI-powered threat detection engine
pub struct ThreatDetectionEngine {
    feature_collector: Arc<FeatureCollector>,
    threat_classifier: Arc<tokio::sync::RwLock<ThreatClassifier>>,
    threat_intel_db: Arc<ThreatIntelDB>,
    threat_feeds: Arc<ThreatFeedAggregator>,
    rule_generator: Arc<RuleGenerator>,
}

impl ThreatDetectionEngine {
    pub fn new(
        rule_manager: Arc<RuleManager>,
        rule_gen_policy: RuleGenPolicy,
    ) -> Self {
        // Create feature collector (5min window, collect every 1min)
        let feature_collector = Arc::new(FeatureCollector::new(
            Duration::from_secs(300),  // 5 minute aggregation window
            Duration::from_secs(60),   // Collect every minute
        ));

        // Create threat classifier
        let threat_classifier = Arc::new(tokio::sync::RwLock::new(
            ThreatClassifier::new()
        ));

        // Create threat intelligence database
        let threat_intel_db = Arc::new(ThreatIntelDB::new());

        // Create threat feed aggregator (update every 1 hour)
        let threat_feeds = Arc::new(ThreatFeedAggregator::new(
            Arc::clone(&threat_intel_db),
            Duration::from_secs(3600),
        ));

        // Create rule generator
        let rule_generator = Arc::new(RuleGenerator::new(
            rule_gen_policy,
            rule_manager,
            Arc::clone(&threat_intel_db),
        ));

        Self {
            feature_collector,
            threat_classifier,
            threat_intel_db,
            threat_feeds,
            rule_generator,
        }
    }

    /// Configure AbuseIPDB threat feed
    pub fn with_abuseipdb(mut self, api_key: String) -> Self {
        self.threat_feeds = Arc::new(
            Arc::try_unwrap(self.threat_feeds)
                .unwrap_or_else(|arc| (*arc).clone())
                .with_abuseipdb(api_key)
        );
        self
    }

    /// Start the threat detection engine
    pub async fn start(self: Arc<Self>) {
        info!("Starting AI Threat Detection Engine");

        // Start feature collector
        let collector = Arc::clone(&self.feature_collector);
        tokio::spawn(async move {
            collector.start().await;
        });

        // Start threat feed updates
        let feeds = Arc::clone(&self.threat_feeds);
        tokio::spawn(async move {
            feeds.start().await;
        });

        // Start rule cleanup task
        let rule_gen = Arc::clone(&self.rule_generator);
        tokio::spawn(async move {
            rule_gen.start_cleanup_task().await;
        });

        // Start threat detection loop
        let engine = Arc::clone(&self);
        tokio::spawn(async move {
            engine.detection_loop().await;
        });

        info!("AI Threat Detection Engine started");
    }

    async fn detection_loop(&self) {
        let mut interval = tokio::time::interval(Duration::from_secs(60));

        loop {
            interval.tick().await;

            // Get aggregated features
            let features = match self.feature_collector.get_features().await {
                Ok(f) => f,
                Err(e) => {
                    error!("Failed to get features: {}", e);
                    continue;
                }
            };

            // Detect threats
            for source_features in features {
                // Check threat intelligence first
                if self.threat_intel_db.is_threat(&source_features.ip).await {
                    info!("Known threat detected: {}", source_features.ip);

                    // Generate rules from threat intel periodically
                    if let Err(e) = self.rule_generator.generate_from_threat_intel().await {
                        error!("Failed to generate threat intel rules: {}", e);
                    }
                    continue;
                }

                // ML-based detection
                let classifier = self.threat_classifier.read().await;
                let detection = classifier.detect(&source_features);
                drop(classifier);

                // Process high-confidence threats
                if detection.confidence > 0.7 {
                    info!(
                        "Threat detected: {} from {} (confidence: {:.1}%)",
                        detection.threat_type.to_string(),
                        detection.source_ip,
                        detection.confidence * 100.0
                    );

                    // Generate firewall rule
                    if let Err(e) = self.rule_generator.process_threat(&detection).await {
                        error!("Failed to process threat: {}", e);
                    }
                }
            }
        }
    }

    /// Add a flow observation (called from eBPF collector)
    pub async fn observe_flow(&self, flow: FlowFeatures) {
        self.feature_collector.add_flow(flow).await;
    }

    /// Train the ML model on baseline normal traffic
    pub async fn train(&self) -> Result<()> {
        info!("Training threat detection model");

        // Get features from recent normal traffic
        let features = self.feature_collector.get_features().await?;

        // Filter out known threats
        let mut normal_features = Vec::new();
        for feature in features {
            if !self.threat_intel_db.is_threat(&feature.ip).await {
                // Only include low-anomaly traffic
                if feature.port_scan_score < 0.3
                    && feature.syn_flood_score < 0.3
                    && feature.ddos_score < 0.3
                {
                    normal_features.push(feature);
                }
            }
        }

        info!("Training on {} normal traffic samples", normal_features.len());

        // Train classifier
        let mut classifier = self.threat_classifier.write().await;
        classifier.train(&normal_features)?;

        info!("Model training complete");
        Ok(())
    }

    /// Get pending rules for manual approval
    pub async fn get_pending_rules(&self) -> Vec<crate::rule_generator::AutoRule> {
        self.rule_generator.get_pending_rules().await
    }

    /// Approve a pending rule
    pub async fn approve_rule(&self, rule_id: &str) -> Result<()> {
        self.rule_generator.approve_rule(rule_id).await
    }

    /// Reject a pending rule
    pub async fn reject_rule(&self, rule_id: &str) -> Result<()> {
        self.rule_generator.reject_rule(rule_id).await
    }
}

impl crate::models::ThreatType {
    pub fn to_string(&self) -> &str {
        match self {
            Self::Normal => "Normal",
            Self::PortScan => "Port Scan",
            Self::SynFlood => "SYN Flood",
            Self::DDoS => "DDoS",
            Self::DataExfiltration => "Data Exfiltration",
            Self::C2Communication => "C2 Communication",
            Self::Unknown => "Unknown Threat",
        }
    }
}
