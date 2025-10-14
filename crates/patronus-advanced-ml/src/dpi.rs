//! Deep Learning for Deep Packet Inspection (DPI)

use ndarray::Array1;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use anyhow::Result;
use crate::neural_network::{NeuralNetwork, Layer, ActivationFunction};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum Protocol {
    HTTP,
    HTTPS,
    SSH,
    FTP,
    DNS,
    SMTP,
    QUIC,
    WebRTC,
    Torrent,
    Unknown,
}

impl Protocol {
    pub fn from_id(id: usize) -> Self {
        match id {
            0 => Protocol::HTTP,
            1 => Protocol::HTTPS,
            2 => Protocol::SSH,
            3 => Protocol::FTP,
            4 => Protocol::DNS,
            5 => Protocol::SMTP,
            6 => Protocol::QUIC,
            7 => Protocol::WebRTC,
            8 => Protocol::Torrent,
            _ => Protocol::Unknown,
        }
    }

    pub fn to_id(&self) -> usize {
        match self {
            Protocol::HTTP => 0,
            Protocol::HTTPS => 1,
            Protocol::SSH => 2,
            Protocol::FTP => 3,
            Protocol::DNS => 4,
            Protocol::SMTP => 5,
            Protocol::QUIC => 6,
            Protocol::WebRTC => 7,
            Protocol::Torrent => 8,
            Protocol::Unknown => 9,
        }
    }

    pub fn all() -> Vec<Protocol> {
        vec![
            Protocol::HTTP,
            Protocol::HTTPS,
            Protocol::SSH,
            Protocol::FTP,
            Protocol::DNS,
            Protocol::SMTP,
            Protocol::QUIC,
            Protocol::WebRTC,
            Protocol::Torrent,
        ]
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PacketFeatures {
    // Statistical features
    pub packet_size: f64,
    pub payload_size: f64,
    pub header_size: f64,

    // Timing features
    pub inter_arrival_time_ms: f64,

    // TCP/UDP features
    pub src_port: u16,
    pub dst_port: u16,
    pub flags: u8,

    // Payload features (first N bytes)
    pub payload_entropy: f64,
    pub payload_bytes: Vec<u8>, // First 32 bytes
}

impl PacketFeatures {
    pub fn new() -> Self {
        Self {
            packet_size: 0.0,
            payload_size: 0.0,
            header_size: 0.0,
            inter_arrival_time_ms: 0.0,
            src_port: 0,
            dst_port: 0,
            flags: 0,
            payload_entropy: 0.0,
            payload_bytes: vec![],
        }
    }

    pub fn to_vector(&self) -> Array1<f64> {
        let mut features = vec![
            self.packet_size / 1500.0, // Normalize by MTU
            self.payload_size / 1500.0,
            self.header_size / 100.0,
            self.inter_arrival_time_ms / 1000.0, // Normalize to seconds
            self.src_port as f64 / 65535.0,
            self.dst_port as f64 / 65535.0,
            self.flags as f64 / 255.0,
            self.payload_entropy,
        ];

        // Add normalized payload bytes (first 32)
        for byte in self.payload_bytes.iter().take(32) {
            features.push(*byte as f64 / 255.0);
        }

        // Pad if less than 32 bytes
        while features.len() < 40 {
            features.push(0.0);
        }

        Array1::from_vec(features)
    }

    pub fn calculate_entropy(data: &[u8]) -> f64 {
        if data.is_empty() {
            return 0.0;
        }

        let mut freq = [0u32; 256];
        for &byte in data {
            freq[byte as usize] += 1;
        }

        let len = data.len() as f64;
        let mut entropy = 0.0;

        for &count in &freq {
            if count > 0 {
                let p = count as f64 / len;
                entropy -= p * p.log2();
            }
        }

        entropy
    }
}

impl Default for PacketFeatures {
    fn default() -> Self {
        Self::new()
    }
}

pub struct DeepDpiClassifier {
    model: NeuralNetwork,
    protocol_map: HashMap<usize, Protocol>,
}

impl DeepDpiClassifier {
    pub fn new() -> Self {
        let mut model = NeuralNetwork::new();

        // Input: 40 features
        // Hidden layers with dropout-like regularization
        model.add_layer(Layer::new(40, 128, ActivationFunction::ReLU));
        model.add_layer(Layer::new(128, 64, ActivationFunction::ReLU));
        model.add_layer(Layer::new(64, 32, ActivationFunction::ReLU));

        // Output: 9 protocol classes
        model.add_layer(Layer::new(32, 9, ActivationFunction::Softmax));

        let mut protocol_map = HashMap::new();
        for (i, protocol) in Protocol::all().iter().enumerate() {
            protocol_map.insert(i, protocol.clone());
        }

        Self {
            model,
            protocol_map,
        }
    }

    pub fn classify(&self, features: &PacketFeatures) -> Result<Protocol> {
        let input = features.to_vector();
        let class_id = self.model.predict(&input)?;

        Ok(self.protocol_map
            .get(&class_id)
            .cloned()
            .unwrap_or(Protocol::Unknown))
    }

    pub fn classify_with_confidence(&self, features: &PacketFeatures) -> Result<(Protocol, f64)> {
        let input = features.to_vector();
        let proba = self.model.predict_proba(&input)?;

        let (class_id, &confidence) = proba
            .iter()
            .enumerate()
            .max_by(|(_, a), (_, b)| a.partial_cmp(b).unwrap())
            .ok_or_else(|| anyhow::anyhow!("Empty prediction"))?;

        let protocol = self.protocol_map
            .get(&class_id)
            .cloned()
            .unwrap_or(Protocol::Unknown);

        Ok((protocol, confidence))
    }

    pub fn batch_classify(&self, features: &[PacketFeatures]) -> Result<Vec<Protocol>> {
        features
            .iter()
            .map(|f| self.classify(f))
            .collect()
    }
}

impl Default for DeepDpiClassifier {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protocol_conversion() {
        let protocol = Protocol::HTTPS;
        let id = protocol.to_id();
        let back = Protocol::from_id(id);

        assert_eq!(protocol, back);
    }

    #[test]
    fn test_entropy_calculation() {
        // Uniform distribution
        let uniform = vec![0u8, 1, 2, 3, 4, 5, 6, 7];
        let entropy = PacketFeatures::calculate_entropy(&uniform);
        assert!(entropy > 2.8); // log2(8) = 3.0

        // All same
        let same = vec![0u8; 8];
        let entropy = PacketFeatures::calculate_entropy(&same);
        assert_eq!(entropy, 0.0);

        // Empty
        let empty: Vec<u8> = vec![];
        let entropy = PacketFeatures::calculate_entropy(&empty);
        assert_eq!(entropy, 0.0);
    }

    #[test]
    fn test_feature_vector() {
        let mut features = PacketFeatures::new();
        features.packet_size = 1500.0;
        features.src_port = 443;
        features.payload_bytes = vec![0x16, 0x03, 0x03]; // TLS handshake

        let vector = features.to_vector();
        assert_eq!(vector.len(), 40);

        // Check normalization
        assert!((vector[0] - 1.0).abs() < 1e-6); // packet_size / 1500
    }

    #[test]
    fn test_dpi_classifier_creation() {
        let classifier = DeepDpiClassifier::new();
        assert_eq!(classifier.protocol_map.len(), 9);
    }

    #[test]
    fn test_classify() {
        let classifier = DeepDpiClassifier::new();

        // HTTPS-like features
        let mut features = PacketFeatures::new();
        features.packet_size = 1200.0;
        features.src_port = 443;
        features.dst_port = 54321;
        features.payload_bytes = vec![0x16, 0x03, 0x03, 0x00, 0x50]; // TLS
        features.payload_entropy = 7.5;

        let result = classifier.classify(&features);
        assert!(result.is_ok());

        let protocol = result.unwrap();
        // Model is random, so just verify it returns a valid protocol
        assert!(matches!(
            protocol,
            Protocol::HTTP
                | Protocol::HTTPS
                | Protocol::SSH
                | Protocol::FTP
                | Protocol::DNS
                | Protocol::SMTP
                | Protocol::QUIC
                | Protocol::WebRTC
                | Protocol::Torrent
                | Protocol::Unknown
        ));
    }

    #[test]
    fn test_classify_with_confidence() {
        let classifier = DeepDpiClassifier::new();

        let features = PacketFeatures::new();
        let result = classifier.classify_with_confidence(&features);
        assert!(result.is_ok());

        let (_protocol, confidence) = result.unwrap();
        assert!(confidence >= 0.0 && confidence <= 1.0);
    }

    #[test]
    fn test_batch_classify() {
        let classifier = DeepDpiClassifier::new();

        let features = vec![
            PacketFeatures::new(),
            PacketFeatures::new(),
            PacketFeatures::new(),
        ];

        let results = classifier.batch_classify(&features);
        assert!(results.is_ok());

        let protocols = results.unwrap();
        assert_eq!(protocols.len(), 3);
    }

    #[test]
    fn test_protocol_all() {
        let protocols = Protocol::all();
        assert_eq!(protocols.len(), 9);
    }
}
