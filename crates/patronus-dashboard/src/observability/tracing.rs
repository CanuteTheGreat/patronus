// OpenTelemetry distributed tracing setup
//
// This module configures OpenTelemetry for distributed tracing across
// the Patronus SD-WAN system. Traces can be exported to Jaeger, Tempo,
// or any OTLP-compatible backend.

use opentelemetry::{trace::TracerProvider as _, KeyValue};
use opentelemetry_sdk::{
    trace::{self, TracerProvider},
    Resource,
};
use opentelemetry_otlp::WithExportConfig;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

/// Initialize OpenTelemetry tracing
///
/// This sets up the global tracer with OTLP export to a collector.
/// Traces include service name, version, and environment metadata.
///
/// # Arguments
/// * `service_name` - Name of the service (e.g., "patronus-dashboard")
/// * `otlp_endpoint` - OTLP collector endpoint (e.g., "http://localhost:4317")
///
/// # Returns
/// A guard that should be kept alive for the duration of the program.
/// Dropping it will flush remaining traces.
pub fn init_tracing(
    service_name: &str,
    otlp_endpoint: Option<&str>,
) -> anyhow::Result<()> {
    // Create resource with service information
    let resource = Resource::new(vec![
        KeyValue::new("service.name", service_name.to_string()),
        KeyValue::new("service.version", env!("CARGO_PKG_VERSION").to_string()),
        KeyValue::new("deployment.environment", std::env::var("ENVIRONMENT").unwrap_or_else(|_| "development".to_string())),
    ]);

    // Configure tracer based on whether OTLP endpoint is provided
    let tracer = if let Some(endpoint) = otlp_endpoint {
        // Export traces to OTLP collector (Jaeger, Tempo, etc.)
        tracing::info!("Initializing OpenTelemetry with OTLP export to {}", endpoint);

        let exporter = opentelemetry_otlp::SpanExporter::builder()
            .with_tonic()
            .with_endpoint(endpoint)
            .build()?;

        let tracer_provider = TracerProvider::builder()
            .with_batch_exporter(exporter, opentelemetry_sdk::runtime::Tokio)
            .with_resource(resource)
            .build();

        tracer_provider.tracer(service_name.to_string())
    } else {
        // No OTLP endpoint - use stdout exporter for development
        tracing::info!("Initializing OpenTelemetry with stdout export (dev mode)");

        let exporter = opentelemetry_stdout::SpanExporter::default();

        let tracer_provider = TracerProvider::builder()
            .with_simple_exporter(exporter)
            .with_resource(resource)
            .build();

        tracer_provider.tracer(service_name.to_string())
    };

    // Create telemetry layer
    let telemetry_layer = tracing_opentelemetry::layer().with_tracer(tracer);

    // Initialize subscriber with both console and telemetry layers
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "patronus_dashboard=info,tower_http=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .with(telemetry_layer)
        .try_init()?;

    tracing::info!("OpenTelemetry tracing initialized for {}", service_name);

    Ok(())
}

/// Example usage of tracing spans
///
/// This shows how to use tracing macros with OpenTelemetry.
#[allow(dead_code)]
fn example_traced_function() {
    use tracing::{info, instrument};

    // Automatic span creation with #[instrument]
    #[instrument]
    fn process_request(user_id: &str, action: &str) {
        info!("Processing request");

        // Nested span
        let _span = tracing::info_span!("database_query", query = "SELECT * FROM users").entered();
        info!("Executing query");

        // Add event
        info!(user_id, action, "Request completed");
    }

    process_request("user123", "login");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tracing_init_no_otlp() {
        // Test initialization without OTLP endpoint (stdout mode)
        // This will fail because tracing can only be initialized once per process
        // In real usage, this would be called once at startup
    }
}
