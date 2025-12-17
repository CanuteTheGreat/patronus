//! Prometheus HTTP Exporter
//!
//! Serves metrics in Prometheus format on /metrics endpoint

use crate::metrics::MetricsCollector;
use axum::{
    Router,
    extract::State,
    response::{IntoResponse, Response},
    routing::get,
    http::StatusCode,
};
use prometheus::{Encoder, TextEncoder};
use std::sync::Arc;
use std::net::SocketAddr;

/// Prometheus metrics exporter
pub struct PrometheusExporter {
    collector: Arc<MetricsCollector>,
    addr: SocketAddr,
}

impl PrometheusExporter {
    pub fn new(collector: Arc<MetricsCollector>, addr: SocketAddr) -> Self {
        Self { collector, addr }
    }

    /// Start the Prometheus HTTP server
    pub async fn serve(self) -> Result<(), Box<dyn std::error::Error>> {
        let collector = self.collector.clone();

        // Start automatic metric collection
        collector.clone().start_collection().await;

        let app = Router::new()
            .route("/metrics", get(metrics_handler))
            .route("/health", get(health_handler))
            .with_state(self.collector);

        tracing::info!("Prometheus exporter listening on {}", self.addr);

        let listener = tokio::net::TcpListener::bind(&self.addr).await?;
        axum::serve(listener, app.into_make_service())
            .await?;

        Ok(())
    }
}

async fn metrics_handler(
    State(collector): State<Arc<MetricsCollector>>,
) -> Response {
    let encoder = TextEncoder::new();
    let metric_families = collector.registry().gather();

    let mut buffer = Vec::new();
    match encoder.encode(&metric_families, &mut buffer) {
        Ok(_) => {
            (
                StatusCode::OK,
                [("Content-Type", encoder.format_type())],
                buffer,
            ).into_response()
        }
        Err(e) => {
            tracing::error!("Failed to encode metrics: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to encode metrics: {}", e),
            ).into_response()
        }
    }
}

async fn health_handler() -> impl IntoResponse {
    (StatusCode::OK, "OK")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_exporter_creation() {
        let collector = Arc::new(MetricsCollector::new().unwrap());
        let addr = "127.0.0.1:9090".parse().unwrap();
        let _exporter = PrometheusExporter::new(collector, addr);
    }
}
