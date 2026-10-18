//! Site controller implementation

use crate::crd::site::{ConditionStatus, Site, SiteCondition, SitePhase, SiteStatus};
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
    #[allow(dead_code)]
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
    use std::time::Instant;
    let start = Instant::now();

    let site_name = site.name_any();
    let namespace = site.namespace().unwrap_or_else(|| "default".to_string());

    info!("Reconciling site: {}/{}", namespace, site_name);

    // Get API handle for this site
    let sites: Api<Site> = Api::namespaced(ctx.client.clone(), &namespace);

    // Check if site is being deleted
    if site.metadata.deletion_timestamp.is_some() {
        info!("Site is being deleted, running cleanup");
        let result = handle_deletion(&site, &ctx, &sites).await;
        let duration = start.elapsed().as_secs_f64();

        let metrics = crate::metrics::Metrics::global();
        if result.is_ok() {
            metrics.record_reconcile_success("site", duration);
        } else {
            metrics.record_reconcile_error("site", "deletion_failed", duration);
        }

        return result;
    }

    // Validate spec
    if let Err(e) = validate_site_spec(&site.spec) {
        warn!("Invalid site specification: {}", e);
        let duration = start.elapsed().as_secs_f64();

        update_site_status(
            &sites,
            &site,
            SitePhase::Failed,
            &format!("Invalid specification: {}", e),
        )
        .await?;

        let metrics = crate::metrics::Metrics::global();
        metrics.record_reconcile_error("site", "validation_failed", duration);

        return Ok(Action::requeue(Duration::from_secs(300)));
    }

    // Create or update site in Patronus
    let result = match create_or_update_patronus_site(&site, &ctx).await {
        Ok(_) => {
            info!("Successfully created/updated site in Patronus");
            update_site_status(&sites, &site, SitePhase::Active, "Site is active").await?;
            Ok(Action::requeue(Duration::from_secs(300)))
        }
        Err(e) => {
            error!("Failed to create/update site in Patronus: {}", e);
            update_site_status(
                &sites,
                &site,
                SitePhase::Failed,
                &format!("Failed to create/update: {}", e),
            )
            .await?;
            Ok(Action::requeue(Duration::from_secs(60)))
        }
    };

    let duration = start.elapsed().as_secs_f64();
    let metrics = crate::metrics::Metrics::global();

    if result.is_ok() {
        metrics.record_reconcile_success("site", duration);
    } else {
        metrics.record_reconcile_error("site", "reconcile_failed", duration);
    }

    result
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
async fn create_or_update_patronus_site(site: &Site, ctx: &Context) -> Result<(), SiteError> {
    let site_name = site.name_any();

    // Build Patronus API request
    let request_body = json!({
        "name": site_name,
        "location": site.spec.location,
        "wireguard": {
            "public_key": site.spec.wireguard.public_key,
            "listen_port": site.spec.wireguard.listen_port,
            "endpoints": site.spec.wireguard.endpoints,
        },
        "resources": site.spec.resources.as_ref().map(|r| json!({
            "cpu": r.cpu,
            "memory": r.memory,
            "storage": r.storage,
        })),
        "mesh": site.spec.mesh.as_ref().map(|m| json!({
            "enabled": m.enabled,
            "peer_with": m.peer_with,
        })),
    });

    debug!("Creating/updating site in Patronus: {}", request_body);

    // Call Patronus API
    let response = ctx
        .http_client
        .put(format!(
            "{}/api/v1/sites/{}",
            ctx.patronus_api_url, site_name
        ))
        .json(&request_body)
        .send()
        .await
        .map_err(|e| SiteError::PatronusApiError(format!("HTTP request failed: {}", e)))?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response
            .text()
            .await
            .unwrap_or_else(|_| "unknown error".to_string());
        return Err(SiteError::PatronusApiError(format!(
            "API returned {}: {}",
            status, body
        )));
    }

    info!(
        "Successfully created/updated site {} in Patronus",
        site_name
    );
    Ok(())
}

/// Delete site from Patronus
async fn delete_patronus_site(site_name: &str, ctx: &Context) -> Result<(), SiteError> {
    debug!("Deleting site {} from Patronus", site_name);

    // Call Patronus API to delete site
    let response = ctx
        .http_client
        .delete(format!(
            "{}/api/v1/sites/{}",
            ctx.patronus_api_url, site_name
        ))
        .send()
        .await
        .map_err(|e| SiteError::PatronusApiError(format!("HTTP request failed: {}", e)))?;

    if !response.status().is_success() && response.status().as_u16() != 404 {
        // 404 is ok - site already deleted
        let status = response.status();
        let body = response
            .text()
            .await
            .unwrap_or_else(|_| "unknown error".to_string());
        return Err(SiteError::PatronusApiError(format!(
            "API returned {}: {}",
            status, body
        )));
    }

    info!("Successfully deleted site {} from Patronus", site_name);
    Ok(())
}

/// The status a reconcile should write, or `None` when `current` already says
/// the same thing.
///
/// Every status patch bumps the object's resourceVersion, and the controller
/// watches the Site itself, so a patch triggers another reconcile. Writing an
/// unchanged status (with a fresh timestamp) on every pass therefore looped
/// forever: each Site was reconciled, and the Patronus API called, every few
/// milliseconds. `lastTransitionTime` now only moves when the Ready condition
/// actually transitions, and an unchanged status is not written at all.
fn desired_site_status(
    current: Option<&SiteStatus>,
    phase: SitePhase,
    message: &str,
    now: &str,
) -> Option<SiteStatus> {
    let ready = if phase == SitePhase::Active {
        ConditionStatus::True
    } else {
        ConditionStatus::False
    };
    let current_ready = current.and_then(|s| s.conditions.iter().find(|c| c.type_ == "Ready"));

    let unchanged = matches!(
        (current, current_ready),
        (Some(cur), Some(cond))
            if cur.phase.as_ref() == Some(&phase)
                && cond.status == ready
                && cond.reason.as_deref() == Some("Reconciled")
                && cond.message.as_deref() == Some(message)
    );
    if unchanged {
        return None;
    }

    let last_transition_time = match current_ready {
        Some(cond) if cond.status == ready && cond.last_transition_time.is_some() => {
            cond.last_transition_time.clone()
        }
        _ => Some(now.to_string()),
    };

    Some(SiteStatus {
        phase: Some(phase),
        conditions: vec![SiteCondition {
            type_: "Ready".to_string(),
            status: ready,
            last_transition_time,
            reason: Some("Reconciled".to_string()),
            message: Some(message.to_string()),
        }],
        peers: None,
        active_paths: None,
        health_score: None,
    })
}

/// Update site status (no-op when it is already up to date)
async fn update_site_status(
    sites: &Api<Site>,
    site: &Site,
    phase: SitePhase,
    message: &str,
) -> Result<(), SiteError> {
    let Some(status) = desired_site_status(
        site.status.as_ref(),
        phase,
        message,
        &Utc::now().to_rfc3339(),
    ) else {
        debug!("Site status unchanged, not patching");
        return Ok(());
    };

    sites
        .patch_status(
            &site.name_any(),
            &PatchParams::default(),
            &Patch::Merge(&json!({ "status": status })),
        )
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

    fn status(phase: SitePhase, ready: ConditionStatus, msg: &str, t: &str) -> SiteStatus {
        SiteStatus {
            phase: Some(phase),
            conditions: vec![SiteCondition {
                type_: "Ready".to_string(),
                status: ready,
                last_transition_time: Some(t.to_string()),
                reason: Some("Reconciled".to_string()),
                message: Some(msg.to_string()),
            }],
            peers: None,
            active_paths: None,
            health_score: None,
        }
    }

    #[test]
    fn unchanged_status_is_not_rewritten() {
        let cur = status(
            SitePhase::Active,
            ConditionStatus::True,
            "Site is active",
            "T0",
        );
        assert!(
            desired_site_status(Some(&cur), SitePhase::Active, "Site is active", "T1").is_none()
        );

        let cur = status(
            SitePhase::Failed,
            ConditionStatus::False,
            "Failed to create/update: x",
            "T0",
        );
        assert!(desired_site_status(
            Some(&cur),
            SitePhase::Failed,
            "Failed to create/update: x",
            "T1"
        )
        .is_none());
    }

    #[test]
    fn first_status_and_transitions_get_a_new_timestamp() {
        let new = desired_site_status(None, SitePhase::Active, "Site is active", "T1").unwrap();
        assert_eq!(new.phase, Some(SitePhase::Active));
        assert_eq!(new.conditions[0].status, ConditionStatus::True);
        assert_eq!(
            new.conditions[0].last_transition_time.as_deref(),
            Some("T1")
        );

        let cur = status(
            SitePhase::Failed,
            ConditionStatus::False,
            "Failed to create/update: x",
            "T0",
        );
        let new =
            desired_site_status(Some(&cur), SitePhase::Active, "Site is active", "T1").unwrap();
        assert_eq!(new.conditions[0].status, ConditionStatus::True);
        assert_eq!(
            new.conditions[0].last_transition_time.as_deref(),
            Some("T1")
        );
    }

    #[test]
    fn message_change_without_transition_keeps_the_timestamp() {
        let cur = status(
            SitePhase::Failed,
            ConditionStatus::False,
            "Failed to create/update: x",
            "T0",
        );
        let new = desired_site_status(
            Some(&cur),
            SitePhase::Failed,
            "Failed to create/update: y",
            "T1",
        )
        .unwrap();
        assert_eq!(
            new.conditions[0].message.as_deref(),
            Some("Failed to create/update: y")
        );
        assert_eq!(
            new.conditions[0].last_transition_time.as_deref(),
            Some("T0")
        );
    }
}
