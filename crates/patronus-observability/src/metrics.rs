//! Prometheus Metrics Collection

use prometheus::{Counter, Gauge, Histogram, Registry, Opts, HistogramOpts};
use std::sync::Arc;
use anyhow::Result;

#[derive(Debug, Clone, Copy)]
pub enum MetricType {
    Counter,
    Gauge,
    Histogram,
}

pub struct MetricsCollector {
    registry: Arc<Registry>,

    // Network metrics
    pub packets_total: Counter,
    pub bytes_total: Counter,
    pub packet_loss: Gauge,
    pub latency: Histogram,

    // Tunnel metrics
    pub tunnels_active: Gauge,
    pub tunnel_failures: Counter,

    // BGP metrics
    pub bgp_peers_up: Gauge,
    pub bgp_routes: Gauge,
    pub bgp_updates: Counter,

    // ML metrics
    pub ml_predictions: Counter,
    pub ml_inference_time: Histogram,
    pub anomalies_detected: Counter,
}

impl MetricsCollector {
    pub fn new() -> Result<Self> {
        let registry = Registry::new();

        let packets_total = Counter::with_opts(
            Opts::new("patronus_packets_total", "Total packets processed")
        )?;

        let bytes_total = Counter::with_opts(
            Opts::new("patronus_bytes_total", "Total bytes processed")
        )?;

        let packet_loss = Gauge::with_opts(
            Opts::new("patronus_packet_loss", "Current packet loss percentage")
        )?;

        let latency = Histogram::with_opts(
            HistogramOpts::new("patronus_latency_ms", "Latency in milliseconds")
                .buckets(vec![1.0, 5.0, 10.0, 25.0, 50.0, 100.0, 250.0, 500.0])
        )?;

        let tunnels_active = Gauge::with_opts(
            Opts::new("patronus_tunnels_active", "Number of active tunnels")
        )?;

        let tunnel_failures = Counter::with_opts(
            Opts::new("patronus_tunnel_failures_total", "Total tunnel failures")
        )?;

        let bgp_peers_up = Gauge::with_opts(
            Opts::new("patronus_bgp_peers_up", "Number of BGP peers in up state")
        )?;

        let bgp_routes = Gauge::with_opts(
            Opts::new("patronus_bgp_routes", "Number of BGP routes")
        )?;

        let bgp_updates = Counter::with_opts(
            Opts::new("patronus_bgp_updates_total", "Total BGP updates received")
        )?;

        let ml_predictions = Counter::with_opts(
            Opts::new("patronus_ml_predictions_total", "Total ML predictions")
        )?;

        let ml_inference_time = Histogram::with_opts(
            HistogramOpts::new("patronus_ml_inference_ms", "ML inference time in milliseconds")
                .buckets(vec![0.1, 0.5, 1.0, 5.0, 10.0, 50.0])
        )?;

        let anomalies_detected = Counter::with_opts(
            Opts::new("patronus_anomalies_detected_total", "Total anomalies detected")
        )?;

        // Register all metrics
        registry.register(Box::new(packets_total.clone()))?;
        registry.register(Box::new(bytes_total.clone()))?;
        registry.register(Box::new(packet_loss.clone()))?;
        registry.register(Box::new(latency.clone()))?;
        registry.register(Box::new(tunnels_active.clone()))?;
        registry.register(Box::new(tunnel_failures.clone()))?;
        registry.register(Box::new(bgp_peers_up.clone()))?;
        registry.register(Box::new(bgp_routes.clone()))?;
        registry.register(Box::new(bgp_updates.clone()))?;
        registry.register(Box::new(ml_predictions.clone()))?;
        registry.register(Box::new(ml_inference_time.clone()))?;
        registry.register(Box::new(anomalies_detected.clone()))?;

        Ok(Self {
            registry: Arc::new(registry),
            packets_total,
            bytes_total,
            packet_loss,
            latency,
            tunnels_active,
            tunnel_failures,
            bgp_peers_up,
            bgp_routes,
            bgp_updates,
            ml_predictions,
            ml_inference_time,
            anomalies_detected,
        })
    }

    pub fn registry(&self) -> Arc<Registry> {
        self.registry.clone()
    }

    pub fn record_packet(&self, bytes: u64) {
        self.packets_total.inc();
        self.bytes_total.inc_by(bytes as f64);
    }

    pub fn record_latency(&self, latency_ms: f64) {
        self.latency.observe(latency_ms);
    }

    pub fn set_packet_loss(&self, loss: f64) {
        self.packet_loss.set(loss);
    }
}

impl Default for MetricsCollector {
    fn default() -> Self {
        Self::new().unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_collector() {
        let collector = MetricsCollector::new().unwrap();

        collector.record_packet(1500);
        collector.record_latency(10.5);
        collector.set_packet_loss(0.01);

        assert_eq!(collector.packets_total.get(), 1.0);
        assert_eq!(collector.bytes_total.get(), 1500.0);
    }
}
