//! Patronus SD-WAN Kubernetes Operator
//!
//! This operator manages Patronus SD-WAN resources in Kubernetes,
//! enabling declarative configuration and GitOps workflows.

mod controllers;
mod crd;
mod metrics;

use anyhow::Result;
use kube::Client;
use prometheus::{Encoder, TextEncoder};
use std::env;
use std::net::SocketAddr;
use tokio::net::TcpListener;
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

    info!("Patronus API URL: {}", patronus_api_url);
    info!("Metrics port: {}", metrics_port);

    // Create Kubernetes client
    let client = Client::try_default().await?;
    info!("Connected to Kubernetes cluster");

    // Start metrics server
    let metrics_handle = tokio::spawn(async move {
        if let Err(e) = run_metrics_server(metrics_port).await {
            warn!("Metrics server error: {}", e);
        }
    });

    // Run controllers concurrently
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
    }

    Ok(())
}

/// Run metrics HTTP server
async fn run_metrics_server(port: u16) -> Result<()> {
    let addr: SocketAddr = ([0, 0, 0, 0], port).into();
    let listener = TcpListener::bind(&addr).await?;

    info!("Metrics server listening on http://{}/metrics", addr);

    loop {
        let (mut socket, _) = listener.accept().await?;

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
