//! Patronus SD-WAN Kubernetes Operator
//!
//! This operator manages Patronus SD-WAN resources in Kubernetes,
//! enabling declarative configuration and GitOps workflows.

mod controllers;
pub mod crd;
mod health;
mod metrics;

use anyhow::Result;
use kube::Client;
use prometheus::{Encoder, TextEncoder};
use std::env;
use std::net::SocketAddr;
use tokio::net::TcpListener;
use tokio::signal;
use tracing::{info, warn, Level};
use tracing_subscriber::FmtSubscriber;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .with_target(false)
        .finish();

    tracing::subscriber::set_global_default(subscriber)?;

    info!("Starting Patronus SD-WAN Operator");

    // Initialize metrics
    let _metrics = metrics::Metrics::global();
    info!("Metrics initialized");

    // Get configuration from environment
    let patronus_api_url = env::var("PATRONUS_API_URL")
        .unwrap_or_else(|_| "http://patronus-api:8081".to_string());

    let metrics_port: u16 = env::var("METRICS_PORT")
        .unwrap_or_else(|_| "8080".to_string())
        .parse()
        .unwrap_or(8080);

    let health_port: u16 = env::var("HEALTH_PORT")
        .unwrap_or_else(|_| "8081".to_string())
        .parse()
        .unwrap_or(8081);

    info!("Patronus API URL: {}", patronus_api_url);
    info!("Metrics port: {}", metrics_port);
    info!("Health check port: {}", health_port);

    // Create health status
    let health_status = health::HealthStatus::new();
    info!("Health status initialized");

    // Start health check server
    let health_status_clone = health_status.clone();
    let health_handle = tokio::spawn(async move {
        let server = health::HealthServer::new(health_port, health_status_clone);
        if let Err(e) = server.run().await {
            warn!("Health check server error: {}", e);
        }
    });

    // Create Kubernetes client
    let client = Client::try_default().await?;
    info!("Connected to Kubernetes cluster");

    // Mark operator as ready
    health_status.set_ready(true);

    // Start metrics server
    let metrics_handle = tokio::spawn(async move {
        if let Err(e) = run_metrics_server(metrics_port).await {
            warn!("Metrics server error: {}", e);
        }
    });

    // Run controllers concurrently and handle shutdown gracefully
    tokio::select! {
        _ = controllers::site::run(client.clone(), patronus_api_url.clone()) => {
            info!("Site controller stopped");
        }
        _ = controllers::policy::run(client.clone(), patronus_api_url.clone()) => {
            info!("Policy controller stopped");
        }
        _ = metrics_handle => {
            info!("Metrics server stopped");
        }
        _ = health_handle => {
            info!("Health check server stopped");
        }
        _ = shutdown_signal() => {
            info!("Shutdown signal received, initiating graceful shutdown");
            health_status.set_ready(false);
            info!("Marked operator as not ready");
        }
    }

    info!("Patronus SD-WAN Operator stopped");
    Ok(())
}

/// Run metrics HTTP server
async fn run_metrics_server(port: u16) -> Result<()> {
    let addr: SocketAddr = ([0, 0, 0, 0], port).into();
    let listener = TcpListener::bind(&addr).await?;

    info!("Metrics server listening on http://{}/metrics", addr);

    loop {
        let (socket, _) = listener.accept().await?;

        tokio::spawn(async move {
            let mut buf = vec![0; 1024];

            // Read request (we don't parse it, just respond to any request)
            if socket.readable().await.is_ok() {
                let _ = socket.try_read(&mut buf);
            }

            // Gather metrics
            let encoder = TextEncoder::new();
            let metric_families = prometheus::gather();
            let mut buffer = Vec::new();

            if encoder.encode(&metric_families, &mut buffer).is_ok() {
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4\r\nContent-Length: {}\r\n\r\n{}",
                    buffer.len(),
                    String::from_utf8_lossy(&buffer)
                );

                let _ = socket.try_write(response.as_bytes());
            }
        });
    }
}

/// Wait for shutdown signal (SIGTERM, SIGINT, or Ctrl+C)
async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {
            info!("Received Ctrl+C signal");
        },
        _ = terminate => {
            info!("Received SIGTERM signal");
        },
    }
}
