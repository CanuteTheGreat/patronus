//! Encrypted Traffic DPI using ML
//!
//! Classifies encrypted traffic (HTTPS, TLS, VPN) without decryption
//! Uses Random Forest classifier based on statistical features

use serde::{Deserialize, Serialize};

/// Traffic classification result
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TrafficClass {
    Web,
    Video,
    VoIP,
    FileTransfer,
    Gaming,
    VPN,
    P2P,
    Unknown,
}

/// Encrypted traffic features for ML classification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficFeatures {
    pub packet_count: usize,
    pub total_bytes: u64,
    pub avg_packet_size: f64,
    pub packet_size_variance: f64,
    pub inter_arrival_times_ms: Vec<f64>,
    pub avg_inter_arrival_ms: f64,
    pub burst_count: usize,
    pub tcp_flags: Vec<u8>,
    pub tls_handshake_size: Option<usize>,
}

/// Encrypted DPI classifier
pub struct EncryptedDpi {
    // In production, would store trained Random Forest model
    confidence_threshold: f64,
}

impl EncryptedDpi {
    pub fn new() -> Self {
        Self {
            confidence_threshold: 0.7,
        }
    }

    /// Classify encrypted traffic
    pub fn classify(&self, features: &TrafficFeatures) -> (TrafficClass, f64) {
        // Simplified Random Forest decision trees
        let (class, confidence) = self.classify_with_trees(features);

        if confidence < self.confidence_threshold {
            (TrafficClass::Unknown, confidence)
        } else {
            (class, confidence)
        }
    }

    fn classify_with_trees(&self, features: &TrafficFeatures) -> (TrafficClass, f64) {
        let mut votes: Vec<(TrafficClass, f64)> = Vec::new();

        // Tree 1: Packet size analysis
        votes.push(self.tree_packet_size(features));

        // Tree 2: Inter-arrival time analysis
        votes.push(self.tree_timing(features));

        // Tree 3: Burst pattern analysis
        votes.push(self.tree_burst(features));

        // Tree 4: TLS handshake analysis
        votes.push(self.tree_tls(features));

        // Aggregate votes
        self.aggregate_votes(votes)
    }

    fn tree_packet_size(&self, features: &TrafficFeatures) -> (TrafficClass, f64) {
        if features.avg_packet_size > 1400.0 {
            // Large packets = file transfer or video
            if features.packet_size_variance < 100.0 {
                (TrafficClass::Video, 0.8) // Consistent large packets = video
            } else {
                (TrafficClass::FileTransfer, 0.7)
            }
        } else if features.avg_packet_size < 200.0 {
            // Small packets = VoIP or gaming
            if features.avg_inter_arrival_ms < 50.0 {
                (TrafficClass::Gaming, 0.75)
            } else {
                (TrafficClass::VoIP, 0.7)
            }
        } else {
            (TrafficClass::Web, 0.6)
        }
    }

    fn tree_timing(&self, features: &TrafficFeatures) -> (TrafficClass, f64) {
        if features.avg_inter_arrival_ms < 20.0 {
            (TrafficClass::Gaming, 0.8) // Real-time
        } else if features.avg_inter_arrival_ms < 50.0 {
            (TrafficClass::VoIP, 0.85) // Interactive
        } else {
            (TrafficClass::Web, 0.6) // Bursty
        }
    }

    fn tree_burst(&self, features: &TrafficFeatures) -> (TrafficClass, f64) {
        if features.burst_count > 10 {
            (TrafficClass::Video, 0.75) // High burst count = streaming
        } else if features.burst_count > 5 {
            (TrafficClass::Web, 0.7) // Medium bursts = web browsing
        } else {
            (TrafficClass::FileTransfer, 0.6) // Continuous = file transfer
        }
    }

    fn tree_tls(&self, features: &TrafficFeatures) -> (TrafficClass, f64) {
        if let Some(handshake_size) = features.tls_handshake_size {
            if handshake_size > 5000 {
                (TrafficClass::VPN, 0.8) // Large handshake = VPN
            } else if handshake_size > 2000 {
                (TrafficClass::Web, 0.7) // Normal HTTPS
            } else {
                (TrafficClass::P2P, 0.6) // Minimal handshake
            }
        } else {
            (TrafficClass::Unknown, 0.3)
        }
    }

    fn aggregate_votes(&self, votes: Vec<(TrafficClass, f64)>) -> (TrafficClass, f64) {
        use std::collections::HashMap;

        let mut class_scores: HashMap<String, Vec<f64>> = HashMap::new();

        for (class, confidence) in votes {
            let key = format!("{:?}", class);
            class_scores.entry(key).or_insert_with(Vec::new).push(confidence);
        }

        // Find class with highest average confidence
        let mut best_class = TrafficClass::Unknown;
        let mut best_score = 0.0;

        for (class_str, scores) in class_scores {
            let avg_score = scores.iter().sum::<f64>() / scores.len() as f64;
            if avg_score > best_score {
                best_score = avg_score;
                best_class = match class_str.as_str() {
                    "Web" => TrafficClass::Web,
                    "Video" => TrafficClass::Video,
                    "VoIP" => TrafficClass::VoIP,
                    "FileTransfer" => TrafficClass::FileTransfer,
                    "Gaming" => TrafficClass::Gaming,
                    "VPN" => TrafficClass::VPN,
                    "P2P" => TrafficClass::P2P,
                    _ => TrafficClass::Unknown,
                };
            }
        }

        (best_class, best_score)
    }
}

impl Default for EncryptedDpi {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_video_classification() {
        let dpi = EncryptedDpi::new();

        let features = TrafficFeatures {
            packet_count: 1000,
            total_bytes: 1_500_000,
            avg_packet_size: 1450.0,
            packet_size_variance: 50.0,
            inter_arrival_times_ms: vec![100.0; 10],
            avg_inter_arrival_ms: 100.0,
            burst_count: 15,
            tcp_flags: vec![],
            tls_handshake_size: Some(3000),
        };

        let (class, confidence) = dpi.classify(&features);
        assert_eq!(class, TrafficClass::Video);
        assert!(confidence > 0.7);
    }

    #[test]
    fn test_voip_classification() {
        let dpi = EncryptedDpi::new();

        let features = TrafficFeatures {
            packet_count: 500,
            total_bytes: 50_000,
            avg_packet_size: 180.0,
            packet_size_variance: 20.0,
            inter_arrival_times_ms: vec![20.0; 10],
            avg_inter_arrival_ms: 20.0,
            burst_count: 3,
            tcp_flags: vec![],
            tls_handshake_size: Some(2500),
        };

        let (class, confidence) = dpi.classify(&features);
        assert_eq!(class, TrafficClass::VoIP);
        assert!(confidence > 0.7);
    }

    #[test]
    fn test_gaming_classification() {
        let dpi = EncryptedDpi::new();

        let features = TrafficFeatures {
            packet_count: 2000,
            total_bytes: 200_000,
            avg_packet_size: 150.0,
            packet_size_variance: 30.0,
            inter_arrival_times_ms: vec![15.0; 10],
            avg_inter_arrival_ms: 15.0,
            burst_count: 5,
            tcp_flags: vec![],
            tls_handshake_size: Some(2000),
        };

        let (class, _confidence) = dpi.classify(&features);
        assert_eq!(class, TrafficClass::Gaming);
    }
}
