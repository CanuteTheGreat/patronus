use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

/// Network flow features extracted from eBPF
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowFeatures {
    pub timestamp: DateTime<Utc>,
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
    pub packets: u64,
    pub bytes: u64,
    pub duration_ms: u64,
    pub flags: u32,

    // Computed features for ML
    pub packets_per_second: f64,
    pub bytes_per_second: f64,
    pub avg_packet_size: f64,
    pub syn_count: u32,
    pub fin_count: u32,
    pub rst_count: u32,
    pub unique_dst_ports: u32,
    pub connection_rate: f64,
}

/// Aggregated features for a source IP
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceFeatures {
    pub ip: String,
    pub timestamp: DateTime<Utc>,

    // Connection patterns
    pub total_flows: u32,
    pub total_packets: u64,
    pub total_bytes: u64,
    pub avg_flow_duration: f64,
    pub connection_rate: f64,

    // Port scanning indicators
    pub unique_dst_ips: u32,
    pub unique_dst_ports: u32,
    pub port_diversity: f64,  // Entropy of port distribution
    pub failed_connections: u32,

    // Packet characteristics
    pub avg_packet_size: f64,
    pub packet_size_variance: f64,
    pub packets_per_flow: f64,

    // Protocol distribution
    pub tcp_ratio: f64,
    pub udp_ratio: f64,
    pub icmp_ratio: f64,

    // Timing features
    pub avg_inter_arrival_time: f64,
    pub flow_duration_variance: f64,

    // Anomaly indicators
    pub syn_flood_score: f64,
    pub port_scan_score: f64,
    pub ddos_score: f64,
}

/// Feature vector for ML models
#[derive(Debug, Clone)]
pub struct FeatureVector {
    pub values: Vec<f64>,
    pub labels: Vec<String>,
}

impl FeatureVector {
    pub fn from_source_features(features: &SourceFeatures) -> Self {
        let values = vec![
            features.total_flows as f64,
            features.total_packets as f64,
            features.total_bytes as f64,
            features.avg_flow_duration,
            features.connection_rate,
            features.unique_dst_ips as f64,
            features.unique_dst_ports as f64,
            features.port_diversity,
            features.failed_connections as f64,
            features.avg_packet_size,
            features.packet_size_variance,
            features.packets_per_flow,
            features.tcp_ratio,
            features.udp_ratio,
            features.icmp_ratio,
            features.avg_inter_arrival_time,
            features.flow_duration_variance,
            features.syn_flood_score,
            features.port_scan_score,
            features.ddos_score,
        ];

        let labels = vec![
            "total_flows".to_string(),
            "total_packets".to_string(),
            "total_bytes".to_string(),
            "avg_flow_duration".to_string(),
            "connection_rate".to_string(),
            "unique_dst_ips".to_string(),
            "unique_dst_ports".to_string(),
            "port_diversity".to_string(),
            "failed_connections".to_string(),
            "avg_packet_size".to_string(),
            "packet_size_variance".to_string(),
            "packets_per_flow".to_string(),
            "tcp_ratio".to_string(),
            "udp_ratio".to_string(),
            "icmp_ratio".to_string(),
            "avg_inter_arrival_time".to_string(),
            "flow_duration_variance".to_string(),
            "syn_flood_score".to_string(),
            "port_scan_score".to_string(),
            "ddos_score".to_string(),
        ];

        Self { values, labels }
    }
}

/// Flow aggregator - groups flows by source IP
pub struct FlowAggregator {
    flows: Arc<RwLock<HashMap<String, Vec<FlowFeatures>>>>,
    aggregation_window: Duration,
}

impl FlowAggregator {
    pub fn new(aggregation_window: Duration) -> Self {
        Self {
            flows: Arc::new(RwLock::new(HashMap::new())),
            aggregation_window,
        }
    }

    /// Add a flow to the aggregator
    pub async fn add_flow(&self, flow: FlowFeatures) {
        let mut flows = self.flows.write().await;
        flows.entry(flow.src_ip.clone())
            .or_insert_with(Vec::new)
            .push(flow);
    }

    /// Compute aggregated features for all sources
    pub async fn aggregate_features(&self) -> Result<Vec<SourceFeatures>> {
        let flows = self.flows.read().await;
        let mut source_features = Vec::new();

        for (src_ip, flow_list) in flows.iter() {
            if flow_list.is_empty() {
                continue;
            }

            let features = self.compute_source_features(src_ip, flow_list)?;
            source_features.push(features);
        }

        Ok(source_features)
    }

    /// Compute features for a single source IP
    fn compute_source_features(&self, src_ip: &str, flows: &[FlowFeatures]) -> Result<SourceFeatures> {
        let total_flows = flows.len() as u32;
        let total_packets: u64 = flows.iter().map(|f| f.packets).sum();
        let total_bytes: u64 = flows.iter().map(|f| f.bytes).sum();

        // Timing features
        let total_duration_ms: u64 = flows.iter().map(|f| f.duration_ms).sum();
        let avg_flow_duration = if total_flows > 0 {
            total_duration_ms as f64 / total_flows as f64
        } else {
            0.0
        };

        // Connection rate (flows per second)
        let time_span = flows.iter()
            .map(|f| f.timestamp)
            .max()
            .zip(flows.iter().map(|f| f.timestamp).min())
            .map(|(max, min)| (max - min).num_seconds().max(1))
            .unwrap_or(1);

        let connection_rate = total_flows as f64 / time_span as f64;

        // Port scanning indicators
        let unique_dst_ips: std::collections::HashSet<_> = flows.iter()
            .map(|f| f.dst_ip.clone())
            .collect();
        let unique_dst_ports: std::collections::HashSet<_> = flows.iter()
            .map(|f| f.dst_port)
            .collect();

        // Port diversity (entropy)
        let port_diversity = self.calculate_port_entropy(flows);

        // Failed connections (RST flags)
        let failed_connections = flows.iter()
            .filter(|f| f.rst_count > 0)
            .count() as u32;

        // Packet characteristics
        let avg_packet_size = if total_packets > 0 {
            total_bytes as f64 / total_packets as f64
        } else {
            0.0
        };

        let packet_sizes: Vec<f64> = flows.iter()
            .map(|f| if f.packets > 0 { f.bytes as f64 / f.packets as f64 } else { 0.0 })
            .collect();
        let packet_size_variance = self.calculate_variance(&packet_sizes);

        let packets_per_flow = if total_flows > 0 {
            total_packets as f64 / total_flows as f64
        } else {
            0.0
        };

        // Protocol distribution
        let tcp_count = flows.iter().filter(|f| f.protocol == 6).count() as f64;
        let udp_count = flows.iter().filter(|f| f.protocol == 17).count() as f64;
        let icmp_count = flows.iter().filter(|f| f.protocol == 1).count() as f64;

        let tcp_ratio = tcp_count / total_flows as f64;
        let udp_ratio = udp_count / total_flows as f64;
        let icmp_ratio = icmp_count / total_flows as f64;

        // Inter-arrival time
        let mut sorted_flows = flows.to_vec();
        sorted_flows.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));
        let inter_arrival_times: Vec<f64> = sorted_flows.windows(2)
            .map(|w| (w[1].timestamp - w[0].timestamp).num_milliseconds() as f64)
            .collect();
        let avg_inter_arrival_time = if !inter_arrival_times.is_empty() {
            inter_arrival_times.iter().sum::<f64>() / inter_arrival_times.len() as f64
        } else {
            0.0
        };

        let flow_durations: Vec<f64> = flows.iter().map(|f| f.duration_ms as f64).collect();
        let flow_duration_variance = self.calculate_variance(&flow_durations);

        // Anomaly scores
        let syn_flood_score = self.calculate_syn_flood_score(flows);
        let port_scan_score = self.calculate_port_scan_score(
            unique_dst_ports.len() as u32,
            total_flows,
            failed_connections,
        );
        let ddos_score = self.calculate_ddos_score(
            connection_rate,
            packets_per_flow,
            total_flows,
        );

        Ok(SourceFeatures {
            ip: src_ip.to_string(),
            timestamp: Utc::now(),
            total_flows,
            total_packets,
            total_bytes,
            avg_flow_duration,
            connection_rate,
            unique_dst_ips: unique_dst_ips.len() as u32,
            unique_dst_ports: unique_dst_ports.len() as u32,
            port_diversity,
            failed_connections,
            avg_packet_size,
            packet_size_variance,
            packets_per_flow,
            tcp_ratio,
            udp_ratio,
            icmp_ratio,
            avg_inter_arrival_time,
            flow_duration_variance,
            syn_flood_score,
            port_scan_score,
            ddos_score,
        })
    }

    /// Calculate port entropy (higher = more diverse)
    fn calculate_port_entropy(&self, flows: &[FlowFeatures]) -> f64 {
        let mut port_counts: HashMap<u16, u32> = HashMap::new();
        for flow in flows {
            *port_counts.entry(flow.dst_port).or_insert(0) += 1;
        }

        let total = flows.len() as f64;
        let mut entropy = 0.0;

        for count in port_counts.values() {
            let p = *count as f64 / total;
            if p > 0.0 {
                entropy -= p * p.log2();
            }
        }

        entropy
    }

    /// Calculate variance of a dataset
    fn calculate_variance(&self, values: &[f64]) -> f64 {
        if values.is_empty() {
            return 0.0;
        }

        let mean = values.iter().sum::<f64>() / values.len() as f64;
        let variance = values.iter()
            .map(|v| (v - mean).powi(2))
            .sum::<f64>() / values.len() as f64;

        variance
    }

    /// Calculate SYN flood score (0-1)
    fn calculate_syn_flood_score(&self, flows: &[FlowFeatures]) -> f64 {
        let syn_count: u32 = flows.iter().map(|f| f.syn_count).sum();
        let syn_ack_count: u32 = flows.iter()
            .filter(|f| f.syn_count > 0 && f.fin_count > 0)
            .count() as u32;

        if syn_count == 0 {
            return 0.0;
        }

        // High SYN without ACK indicates potential SYN flood
        let incomplete_ratio = 1.0 - (syn_ack_count as f64 / syn_count as f64);

        // Also consider connection rate
        let syn_rate = syn_count as f64 / flows.len().max(1) as f64;

        (incomplete_ratio * 0.7 + (syn_rate / 10.0).min(1.0) * 0.3).min(1.0)
    }

    /// Calculate port scan score (0-1)
    fn calculate_port_scan_score(&self, unique_ports: u32, total_flows: u32, failed: u32) -> f64 {
        if total_flows == 0 {
            return 0.0;
        }

        // Many unique ports with few packets each indicates scanning
        let port_diversity = unique_ports as f64 / total_flows as f64;
        let failure_rate = failed as f64 / total_flows as f64;

        // High port diversity + high failure rate = likely port scan
        (port_diversity * 0.6 + failure_rate * 0.4).min(1.0)
    }

    /// Calculate DDoS score (0-1)
    fn calculate_ddos_score(&self, conn_rate: f64, pkt_per_flow: f64, total_flows: u32) -> f64 {
        // High connection rate with many packets suggests DDoS
        let rate_score = (conn_rate / 100.0).min(1.0);  // Normalize to 100 conn/sec
        let volume_score = (total_flows as f64 / 1000.0).min(1.0);  // Normalize to 1000 flows
        let packet_score = (pkt_per_flow / 100.0).min(1.0);  // Normalize to 100 pkt/flow

        (rate_score * 0.4 + volume_score * 0.3 + packet_score * 0.3).min(1.0)
    }

    /// Clear old flows outside the aggregation window
    pub async fn cleanup_old_flows(&self) {
        let cutoff = Utc::now() - chrono::Duration::from_std(self.aggregation_window).unwrap();
        let mut flows = self.flows.write().await;

        for flow_list in flows.values_mut() {
            flow_list.retain(|f| f.timestamp > cutoff);
        }

        // Remove empty entries
        flows.retain(|_, v| !v.is_empty());
    }
}

/// Feature collector service
pub struct FeatureCollector {
    aggregator: FlowAggregator,
    collection_interval: Duration,
}

impl FeatureCollector {
    pub fn new(aggregation_window: Duration, collection_interval: Duration) -> Self {
        Self {
            aggregator: FlowAggregator::new(aggregation_window),
            collection_interval,
        }
    }

    /// Start the feature collection loop
    pub async fn start(self: Arc<Self>) {
        info!("Starting AI feature collector");

        let mut interval = tokio::time::interval(self.collection_interval);

        loop {
            interval.tick().await;

            // Cleanup old flows
            self.aggregator.cleanup_old_flows().await;

            // Aggregate features
            match self.aggregator.aggregate_features().await {
                Ok(features) => {
                    debug!("Aggregated features for {} sources", features.len());

                    // Log sources with high anomaly scores
                    for feature in features.iter() {
                        if feature.port_scan_score > 0.7 {
                            warn!(
                                "Potential port scan from {}: score = {:.2}",
                                feature.ip, feature.port_scan_score
                            );
                        }
                        if feature.syn_flood_score > 0.7 {
                            warn!(
                                "Potential SYN flood from {}: score = {:.2}",
                                feature.ip, feature.syn_flood_score
                            );
                        }
                        if feature.ddos_score > 0.7 {
                            warn!(
                                "Potential DDoS from {}: score = {:.2}",
                                feature.ip, feature.ddos_score
                            );
                        }
                    }
                }
                Err(e) => {
                    warn!("Failed to aggregate features: {}", e);
                }
            }
        }
    }

    /// Add a flow observation
    pub async fn add_flow(&self, flow: FlowFeatures) {
        self.aggregator.add_flow(flow).await;
    }

    /// Get current aggregated features
    pub async fn get_features(&self) -> Result<Vec<SourceFeatures>> {
        self.aggregator.aggregate_features().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_port_entropy() {
        let aggregator = FlowAggregator::new(Duration::from_secs(60));

        // All same port = low entropy
        let flows = vec![
            create_test_flow("1.1.1.1", "2.2.2.2", 80),
            create_test_flow("1.1.1.1", "2.2.2.2", 80),
            create_test_flow("1.1.1.1", "2.2.2.2", 80),
        ];
        let entropy = aggregator.calculate_port_entropy(&flows);
        assert!(entropy < 0.1);

        // Many different ports = high entropy
        let flows = vec![
            create_test_flow("1.1.1.1", "2.2.2.2", 80),
            create_test_flow("1.1.1.1", "2.2.2.2", 443),
            create_test_flow("1.1.1.1", "2.2.2.2", 22),
            create_test_flow("1.1.1.1", "2.2.2.2", 3389),
        ];
        let entropy = aggregator.calculate_port_entropy(&flows);
        assert!(entropy > 1.5);
    }

    fn create_test_flow(src: &str, dst: &str, dst_port: u16) -> FlowFeatures {
        FlowFeatures {
            timestamp: Utc::now(),
            src_ip: src.to_string(),
            dst_ip: dst.to_string(),
            src_port: 12345,
            dst_port,
            protocol: 6,
            packets: 10,
            bytes: 1000,
            duration_ms: 100,
            flags: 0,
            packets_per_second: 100.0,
            bytes_per_second: 10000.0,
            avg_packet_size: 100.0,
            syn_count: 1,
            fin_count: 1,
            rst_count: 0,
            unique_dst_ports: 1,
            connection_rate: 1.0,
        }
    }
}
