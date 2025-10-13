//! Patronus SD-WAN Kubernetes Operator
//!
//! This operator manages Patronus SD-WAN resources in Kubernetes,
//! enabling declarative configuration and GitOps workflows.

mod controllers;
mod crd;

use anyhow::Result;
use kube::Client;
use std::env;
use tracing::{info, Level};
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

    // Get Patronus API URL from environment
    let patronus_api_url = env::var("PATRONUS_API_URL")
        .unwrap_or_else(|_| "http://patronus-api:8081".to_string());

    info!("Patronus API URL: {}", patronus_api_url);

    // Create Kubernetes client
    let client = Client::try_default().await?;

    info!("Connected to Kubernetes cluster");

    // Run controllers concurrently
    tokio::select! {
        _ = controllers::site::run(client.clone(), patronus_api_url.clone()) => {
            info!("Site controller stopped");
        }
        _ = controllers::policy::run(client.clone(), patronus_api_url.clone()) => {
            info!("Policy controller stopped");
        }
    }

    Ok(())
}
