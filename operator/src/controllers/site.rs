//! Site controller implementation

use crate::crd::site::{Site, SitePhase, SiteStatus, ConditionStatus, SiteCondition};
use chrono::Utc;
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

/// Site controller error
#[derive(Error, Debug)]
pub enum SiteError {
    #[error("Kubernetes API error: {0}")]
    KubeError(#[from] kube::Error),

    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),

    #[error("Patronus API error: {0}")]
    PatronusApiError(String),

    #[error("Invalid site specification: {0}")]
    InvalidSpec(String),
}

/// Site controller context
#[derive(Clone)]
pub struct Context {
    /// Kubernetes client
    pub client: Client,

    /// Patronus API base URL
    pub patronus_api_url: String,

    /// HTTP client
    pub http_client: reqwest::Client,
}

/// Reconcile a Site resource
#[tracing::instrument(skip(site, ctx), fields(site_name = %site.name_any()))]
pub async fn reconcile(site: Arc<Site>, ctx: Arc<Context>) -> Result<Action, SiteError> {
    let site_name = site.name_any();
    let namespace = site.namespace().unwrap_or_else(|| "default".to_string());

    info!("Reconciling site: {}/{}", namespace, site_name);

    // Get API handle for this site
    let sites: Api<Site> = Api::namespaced(ctx.client.clone(), &namespace);

    // Check if site is being deleted
    if site.metadata.deletion_timestamp.is_some() {
        info!("Site is being deleted, running cleanup");
        return handle_deletion(&site, &ctx, &sites).await;
    }

    // Validate spec
    if let Err(e) = validate_site_spec(&site.spec) {
        warn!("Invalid site specification: {}", e);
        update_site_status(
            &sites,
            &site_name,
            SitePhase::Failed,
            &format!("Invalid specification: {}", e),
        )
        .await?;
        return Ok(Action::requeue(Duration::from_secs(300)));
    }

    // Create or update site in Patronus
    match create_or_update_patronus_site(&site, &ctx).await {
        Ok(_) => {
            info!("Successfully created/updated site in Patronus");
            update_site_status(&sites, &site_name, SitePhase::Active, "Site is active").await?;
            Ok(Action::requeue(Duration::from_secs(300)))
        }
        Err(e) => {
            error!("Failed to create/update site in Patronus: {}", e);
            update_site_status(
                &sites,
                &site_name,
                SitePhase::Failed,
                &format!("Failed to create/update: {}", e),
            )
            .await?;
            Ok(Action::requeue(Duration::from_secs(60)))
        }
    }
}

/// Handle site deletion
async fn handle_deletion(
    site: &Site,
    ctx: &Context,
    _sites: &Api<Site>,
) -> Result<Action, SiteError> {
    let site_name = site.name_any();

    // Delete from Patronus API
    match delete_patronus_site(&site_name, ctx).await {
        Ok(_) => {
            info!("Successfully deleted site from Patronus");
            // Remove finalizer (in production, we'd add this during creation)
            Ok(Action::await_change())
        }
        Err(e) => {
            error!("Failed to delete site from Patronus: {}", e);
            Ok(Action::requeue(Duration::from_secs(30)))
        }
    }
}

/// Validate site specification
fn validate_site_spec(spec: &crate::crd::site::SiteSpec) -> Result<(), String> {
    // Validate WireGuard public key format (base64, 44 characters ending in =)
    if spec.wireguard.public_key.len() != 44 {
        return Err("WireGuard public key must be 44 characters".to_string());
    }

    if !spec.wireguard.public_key.ends_with('=') {
        return Err("WireGuard public key must end with '='".to_string());
    }

    // Validate port range
    if spec.wireguard.listen_port == 0 {
        return Err("Listen port cannot be 0".to_string());
    }

    // Validate endpoints
    if spec.wireguard.endpoints.is_empty() {
        return Err("At least one endpoint is required".to_string());
    }

    for endpoint in &spec.wireguard.endpoints {
        if !endpoint.contains(':') {
            return Err(format!("Invalid endpoint format: {}", endpoint));
        }
    }

    Ok(())
}

/// Create or update site in Patronus
async fn create_or_update_patronus_site(
    site: &Site,
    _ctx: &Context,
) -> Result<(), SiteError> {
    let site_name = site.name_any();

    // Build Patronus API request
    let request_body = json!({
        "name": site_name,
        "location": site.spec.location,
        "public_key": site.spec.wireguard.public_key,
        "listen_port": site.spec.wireguard.listen_port,
        "endpoints": site.spec.wireguard.endpoints,
    });

    // Call Patronus API (this is a stub - in production would actually call API)
    debug!("Would create/update site in Patronus: {}", request_body);

    // Simulate API call
    // In production:
    // let response = ctx.http_client
    //     .post(&format!("{}/v1/sites", ctx.patronus_api_url))
    //     .json(&request_body)
    //     .send()
    //     .await
    //     .map_err(|e| SiteError::PatronusApiError(e.to_string()))?;

    Ok(())
}

/// Delete site from Patronus
async fn delete_patronus_site(
    site_name: &str,
    _ctx: &Context,
) -> Result<(), SiteError> {
    debug!("Would delete site from Patronus: {}", site_name);

    // In production:
    // let response = ctx.http_client
    //     .delete(&format!("{}/v1/sites/{}", ctx.patronus_api_url, site_name))
    //     .send()
    //     .await
    //     .map_err(|e| SiteError::PatronusApiError(e.to_string()))?;

    Ok(())
}

/// Update site status
async fn update_site_status(
    sites: &Api<Site>,
    name: &str,
    phase: SitePhase,
    message: &str,
) -> Result<(), SiteError> {
    let status = json!({
        "status": SiteStatus {
            phase: Some(phase.clone()),
            conditions: vec![SiteCondition {
                type_: "Ready".to_string(),
                status: if phase == SitePhase::Active {
                    ConditionStatus::True
                } else {
                    ConditionStatus::False
                },
                last_transition_time: Some(Utc::now().to_rfc3339()),
                reason: Some("Reconciled".to_string()),
                message: Some(message.to_string()),
            }],
            peers: None,
            active_paths: None,
            health_score: None,
        }
    });

    sites
        .patch_status(name, &PatchParams::default(), &Patch::Merge(&status))
        .await?;

    Ok(())
}

/// Handle reconciliation errors
fn error_policy(_site: Arc<Site>, error: &SiteError, _ctx: Arc<Context>) -> Action {
    error!("Reconciliation error: {}", error);
    Action::requeue(Duration::from_secs(60))
}

/// Run the Site controller
pub async fn run(client: Client, patronus_api_url: String) {
    let sites: Api<Site> = Api::all(client.clone());

    let context = Arc::new(Context {
        client: client.clone(),
        patronus_api_url,
        http_client: reqwest::Client::new(),
    });

    Controller::new(sites, Config::default())
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crd::site::{SiteSpec, WireGuardConfig};

    #[test]
    fn test_validate_site_spec() {
        let spec = SiteSpec {
            location: Some("Test".to_string()),
            wireguard: WireGuardConfig {
                public_key: "YjE2OTNkMWQxYzYwZGU3ZWZhMDU4MWU3YzU4MTU4MD0=".to_string(),
                listen_port: 51820,
                endpoints: vec!["192.168.1.1:51820".to_string()],
            },
            resources: None,
            mesh: None,
        };

        assert!(validate_site_spec(&spec).is_ok());
    }

    #[test]
    fn test_validate_invalid_key() {
        let spec = SiteSpec {
            location: None,
            wireguard: WireGuardConfig {
                public_key: "short".to_string(),
                listen_port: 51820,
                endpoints: vec!["192.168.1.1:51820".to_string()],
            },
            resources: None,
            mesh: None,
        };

        assert!(validate_site_spec(&spec).is_err());
    }

    #[test]
    fn test_validate_no_endpoints() {
        let spec = SiteSpec {
            location: None,
            wireguard: WireGuardConfig {
                public_key: "YjE2OTNkMWQxYzYwZGU3ZWZhMDU4MWU3YzU4MTU4MD0=".to_string(),
                listen_port: 51820,
                endpoints: vec![],
            },
            resources: None,
            mesh: None,
        };

        assert!(validate_site_spec(&spec).is_err());
    }
}
