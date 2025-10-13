//! Policy controller implementation

use crate::crd::policy::{Policy, PolicyStatus};
use futures::StreamExt;
use kube::{
    api::{Api, Patch, PatchParams},
    client::Client,
    runtime::{
        controller::{Action, Controller},
        watcher::Config,
    },
    ResourceExt,
};
use serde_json::json;
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tracing::{debug, error, info, warn};

/// Policy controller error
#[derive(Error, Debug)]
pub enum PolicyError {
    #[error("Kubernetes API error: {0}")]
    KubeError(#[from] kube::Error),

    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),

    #[error("Patronus API error: {0}")]
    PatronusApiError(String),

    #[error("Invalid policy specification: {0}")]
    InvalidSpec(String),
}

/// Policy controller context
#[derive(Clone)]
pub struct Context {
    pub client: Client,
    pub patronus_api_url: String,
    pub http_client: reqwest::Client,
}

/// Reconcile a Policy resource
#[tracing::instrument(skip(policy, ctx), fields(policy_name = %policy.name_any()))]
pub async fn reconcile(policy: Arc<Policy>, ctx: Arc<Context>) -> Result<Action, PolicyError> {
    let policy_name = policy.name_any();
    let namespace = policy.namespace().unwrap_or_else(|| "default".to_string());

    info!("Reconciling policy: {}/{}", namespace, policy_name);

    let policies: Api<Policy> = Api::namespaced(ctx.client.clone(), &namespace);

    // Check if policy is being deleted
    if policy.metadata.deletion_timestamp.is_some() {
        info!("Policy is being deleted");
        return handle_deletion(&policy, &ctx).await;
    }

    // Validate spec
    if let Err(e) = validate_policy_spec(&policy.spec) {
        warn!("Invalid policy specification: {}", e);
        return Ok(Action::requeue(Duration::from_secs(300)));
    }

    // Create or update policy in Patronus
    match create_or_update_patronus_policy(&policy, &ctx).await {
        Ok(_) => {
            info!("Successfully created/updated policy in Patronus");
            update_policy_status(&policies, &policy_name, true).await?;
            Ok(Action::requeue(Duration::from_secs(300)))
        }
        Err(e) => {
            error!("Failed to create/update policy: {}", e);
            update_policy_status(&policies, &policy_name, false).await?;
            Ok(Action::requeue(Duration::from_secs(60)))
        }
    }
}

async fn handle_deletion(policy: &Policy, ctx: &Context) -> Result<Action, PolicyError> {
    let policy_name = policy.name_any();
    debug!("Deleting policy {} from Patronus", policy_name);

    // Call Patronus API to delete policy
    let response = ctx.http_client
        .delete(&format!("{}/api/v1/policies/{}", ctx.patronus_api_url, policy_name))
        .send()
        .await
        .map_err(|e| PolicyError::PatronusApiError(format!("HTTP request failed: {}", e)))?;

    if !response.status().is_success() && response.status().as_u16() != 404 {
        // 404 is ok - policy already deleted
        let status = response.status();
        let body = response.text().await.unwrap_or_else(|_| "unknown error".to_string());
        warn!("Failed to delete policy from Patronus: {} - {}", status, body);
    }

    info!("Successfully deleted policy {} from Patronus", policy_name);
    Ok(Action::await_change())
}

fn validate_policy_spec(spec: &crate::crd::policy::PolicySpec) -> Result<(), String> {
    if spec.priority < 0 || spec.priority > 1000 {
        return Err("Priority must be between 0 and 1000".to_string());
    }
    Ok(())
}

async fn create_or_update_patronus_policy(
    policy: &Policy,
    ctx: &Context,
) -> Result<(), PolicyError> {
    let policy_name = policy.name_any();

    // Build Patronus API request
    let request_body = serde_json::to_value(&policy.spec)
        .map_err(|e| PolicyError::SerializationError(e))?;

    debug!("Creating/updating policy in Patronus: {}", request_body);

    // Call Patronus API
    let response = ctx.http_client
        .put(&format!("{}/api/v1/policies/{}", ctx.patronus_api_url, policy_name))
        .json(&request_body)
        .send()
        .await
        .map_err(|e| PolicyError::PatronusApiError(format!("HTTP request failed: {}", e)))?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_else(|_| "unknown error".to_string());
        return Err(PolicyError::PatronusApiError(format!(
            "API returned {}: {}",
            status, body
        )));
    }

    info!("Successfully created/updated policy {} in Patronus", policy_name);
    Ok(())
}

async fn update_policy_status(
    policies: &Api<Policy>,
    name: &str,
    active: bool,
) -> Result<(), PolicyError> {
    let status = json!({
        "status": PolicyStatus {
            active: Some(active),
            matched_flows: Some(0),
            bytes_routed: Some(0),
        }
    });

    policies
        .patch_status(name, &PatchParams::default(), &Patch::Merge(&status))
        .await?;

    Ok(())
}

fn error_policy(_policy: Arc<Policy>, error: &PolicyError, _ctx: Arc<Context>) -> Action {
    error!("Reconciliation error: {}", error);
    Action::requeue(Duration::from_secs(60))
}

pub async fn run(client: Client, patronus_api_url: String) {
    let policies: Api<Policy> = Api::all(client.clone());

    let context = Arc::new(Context {
        client: client.clone(),
        patronus_api_url,
        http_client: reqwest::Client::new(),
    });

    Controller::new(policies, Config::default())
        .run(reconcile, error_policy, context)
        .for_each(|res| async move {
            match res {
                Ok(_) => {
                    info!("Reconciliation completed");
                }
                Err(e) => {
                    error!("Reconciliation error: {}", e);
                }
            }
        })
        .await;
}
