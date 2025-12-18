use anyhow::Result;
use ndarray::{Array1, Array2};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{debug, info};

use crate::feature_collector::{FeatureVector, SourceFeatures};

/// Threat classification
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ThreatType {
    Normal,
    PortScan,
    SynFlood,
    DDoS,
    DataExfiltration,
    C2Communication,
    Unknown,
}

/// Threat detection result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatDetection {
    pub source_ip: String,
    pub threat_type: ThreatType,
    pub confidence: f64,
    pub anomaly_score: f64,
    pub features: HashMap<String, f64>,
}

/// Isolation Forest for anomaly detection
pub struct IsolationForest {
    num_trees: usize,
    sample_size: usize,
    trees: Vec<IsolationTree>,
    avg_path_length: f64,
}

struct IsolationTree {
    root: Option<Box<TreeNode>>,
    height_limit: usize,
}

struct TreeNode {
    split_feature: usize,
    split_value: f64,
    left: Option<Box<TreeNode>>,
    right: Option<Box<TreeNode>>,
}

impl IsolationForest {
    pub fn new(num_trees: usize, sample_size: usize) -> Self {
        Self {
            num_trees,
            sample_size,
            trees: Vec::new(),
            avg_path_length: 0.0,
        }
    }

    /// Train the isolation forest on normal traffic
    pub fn train(&mut self, data: &Array2<f64>) -> Result<()> {
        info!("Training Isolation Forest with {} samples", data.nrows());

        let height_limit = (self.sample_size as f64).log2().ceil() as usize;

        self.trees.clear();
        for i in 0..self.num_trees {
            if i % 10 == 0 {
                debug!("Building tree {}/{}", i + 1, self.num_trees);
            }

            // Sample data
            let sample = self.sample_data(data);

            // Build tree
            let mut tree = IsolationTree {
                root: None,
                height_limit,
            };
            tree.root = self.build_tree(&sample, 0, height_limit);

            self.trees.push(tree);
        }

        // Compute average path length for normalization
        self.avg_path_length = self.compute_c(self.sample_size);

        info!("Isolation Forest training complete");
        Ok(())
    }

    /// Predict anomaly score (higher = more anomalous)
    pub fn predict(&self, features: &Array1<f64>) -> f64 {
        if self.trees.is_empty() {
            return 0.0;
        }

        let avg_path_length: f64 = self.trees.iter()
            .map(|tree| self.path_length(features, &tree.root, 0) as f64)
            .sum::<f64>() / self.trees.len() as f64;

        // Anomaly score: 2^(-avg_path / c)
        let score = 2_f64.powf(-avg_path_length / self.avg_path_length);

        score
    }

    fn sample_data(&self, data: &Array2<f64>) -> Array2<f64> {
        use rand::seq::SliceRandom;
        let mut rng = rand::thread_rng();

        let indices: Vec<usize> = (0..data.nrows()).collect();
        let sampled: Vec<usize> = indices.choose_multiple(&mut rng, self.sample_size.min(data.nrows()))
            .copied()
            .collect();

        let mut result = Array2::zeros((sampled.len(), data.ncols()));
        for (i, &idx) in sampled.iter().enumerate() {
            result.row_mut(i).assign(&data.row(idx));
        }

        result
    }

    fn build_tree(&self, data: &Array2<f64>, current_height: usize, height_limit: usize) -> Option<Box<TreeNode>> {
        if current_height >= height_limit || data.nrows() <= 1 {
            return None;
        }

        use rand::Rng;
        let mut rng = rand::thread_rng();

        // Randomly select feature and split value
        let split_feature = rng.gen_range(0..data.ncols());
        let col = data.column(split_feature);

        let min_val = col.iter().cloned().fold(f64::INFINITY, f64::min);
        let max_val = col.iter().cloned().fold(f64::NEG_INFINITY, f64::max);

        if (max_val - min_val).abs() < 1e-10 {
            return None;  // All values are the same
        }

        let split_value = rng.gen_range(min_val..max_val);

        // Split data
        let mut left_data = Vec::new();
        let mut right_data = Vec::new();

        for i in 0..data.nrows() {
            if data[[i, split_feature]] < split_value {
                left_data.push(data.row(i).to_owned());
            } else {
                right_data.push(data.row(i).to_owned());
            }
        }

        // Build subtrees
        let left = if !left_data.is_empty() {
            let left_array = self.vec_to_array2(&left_data);
            self.build_tree(&left_array, current_height + 1, height_limit)
        } else {
            None
        };

        let right = if !right_data.is_empty() {
            let right_array = self.vec_to_array2(&right_data);
            self.build_tree(&right_array, current_height + 1, height_limit)
        } else {
            None
        };

        Some(Box::new(TreeNode {
            split_feature,
            split_value,
            left,
            right,
        }))
    }

    fn vec_to_array2(&self, data: &[Array1<f64>]) -> Array2<f64> {
        if data.is_empty() {
            return Array2::zeros((0, 0));
        }

        let nrows = data.len();
        let ncols = data[0].len();
        let mut result = Array2::zeros((nrows, ncols));

        for (i, row) in data.iter().enumerate() {
            result.row_mut(i).assign(row);
        }

        result
    }

    fn path_length(&self, features: &Array1<f64>, node: &Option<Box<TreeNode>>, current_height: usize) -> usize {
        match node {
            None => current_height,
            Some(n) => {
                if features[n.split_feature] < n.split_value {
                    self.path_length(features, &n.left, current_height + 1)
                } else {
                    self.path_length(features, &n.right, current_height + 1)
                }
            }
        }
    }

    fn compute_c(&self, n: usize) -> f64 {
        if n <= 1 {
            return 0.0;
        }
        2.0 * ((n - 1) as f64).ln() + 0.5772156649 - 2.0 * (n - 1) as f64 / n as f64
    }
}

/// Rule-based threat classifier
pub struct ThreatClassifier {
    isolation_forest: Option<IsolationForest>,
}

impl ThreatClassifier {
    pub fn new() -> Self {
        Self {
            isolation_forest: Some(IsolationForest::new(100, 256)),
        }
    }

    /// Train on baseline normal traffic
    pub fn train(&mut self, normal_features: &[SourceFeatures]) -> Result<()> {
        if normal_features.is_empty() {
            return Ok(());
        }

        // Convert to feature matrix
        let vectors: Vec<FeatureVector> = normal_features.iter()
            .map(FeatureVector::from_source_features)
            .collect();

        let nrows = vectors.len();
        let ncols = vectors[0].values.len();
        let mut data = Array2::zeros((nrows, ncols));

        for (i, vec) in vectors.iter().enumerate() {
            for (j, &val) in vec.values.iter().enumerate() {
                data[[i, j]] = val;
            }
        }

        // Train isolation forest
        if let Some(ref mut forest) = self.isolation_forest {
            forest.train(&data)?;
        }

        Ok(())
    }

    /// Detect threats in observed traffic
    pub fn detect(&self, features: &SourceFeatures) -> ThreatDetection {
        let vector = FeatureVector::from_source_features(features);

        // Compute anomaly score using Isolation Forest
        let anomaly_score = if let Some(ref forest) = self.isolation_forest {
            let arr = Array1::from_vec(vector.values.clone());
            forest.predict(&arr)
        } else {
            0.0
        };

        // Rule-based classification
        let (threat_type, confidence) = self.classify_threat(features, anomaly_score);

        // Build feature map for transparency
        let mut feature_map = HashMap::new();
        for (label, value) in vector.labels.iter().zip(vector.values.iter()) {
            feature_map.insert(label.clone(), *value);
        }

        ThreatDetection {
            source_ip: features.ip.clone(),
            threat_type,
            confidence,
            anomaly_score,
            features: feature_map,
        }
    }

    fn classify_threat(&self, features: &SourceFeatures, anomaly_score: f64) -> (ThreatType, f64) {
        // Port scanning detection
        if features.port_scan_score > 0.7 {
            return (ThreatType::PortScan, features.port_scan_score);
        }

        // SYN flood detection
        if features.syn_flood_score > 0.7 {
            return (ThreatType::SynFlood, features.syn_flood_score);
        }

        // DDoS detection
        if features.ddos_score > 0.7 {
            return (ThreatType::DDoS, features.ddos_score);
        }

        // Data exfiltration (high outbound bytes, few connections)
        if features.total_bytes > 10_000_000  // >10MB
            && features.total_flows < 10
            && features.connection_rate < 1.0
        {
            let confidence = (features.total_bytes as f64 / 100_000_000.0).min(0.9);
            return (ThreatType::DataExfiltration, confidence);
        }

        // C2 communication (periodic beaconing)
        if features.avg_inter_arrival_time > 0.0
            && features.flow_duration_variance < 1000.0  // Low variance = periodic
            && features.total_flows > 10
        {
            let periodicity_score = 1.0 / (1.0 + features.flow_duration_variance / 1000.0);
            if periodicity_score > 0.7 {
                return (ThreatType::C2Communication, periodicity_score);
            }
        }

        // High anomaly score without specific pattern
        if anomaly_score > 0.6 {
            return (ThreatType::Unknown, anomaly_score);
        }

        (ThreatType::Normal, 1.0 - anomaly_score)
    }
}

impl Default for ThreatClassifier {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_isolation_forest() {
        let mut forest = IsolationForest::new(10, 8);

        // Create simple 2D dataset
        let mut data = Array2::zeros((20, 2));
        for i in 0..20 {
            data[[i, 0]] = (i as f64) / 10.0;
            data[[i, 1]] = (i as f64) / 10.0;
        }

        forest.train(&data).unwrap();

        // Normal point
        let normal = Array1::from_vec(vec![1.0, 1.0]);
        let score_normal = forest.predict(&normal);

        // Anomalous point
        let anomaly = Array1::from_vec(vec![10.0, 10.0]);
        let score_anomaly = forest.predict(&anomaly);

        assert!(score_anomaly > score_normal);
    }
}
