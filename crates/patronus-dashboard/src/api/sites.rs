//! Sites API endpoints

use axum::{
    extract::{Path, State},
    Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::{error::Result, state::AppState};

/// List all sites
pub async fn list_sites(State(state): State<Arc<AppState>>) -> Result<Json<Vec<SiteResponse>>> {
    let sites = state.db.list_sites().await?;

    let response: Vec<SiteResponse> = sites.into_iter().map(|s| s.into()).collect();

    Ok(Json(response))
}

/// Get site by ID
pub async fn get_site(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<SiteResponse>> {
    use std::str::FromStr;
    let site_id = patronus_sdwan::types::SiteId::from_str(&id)
        .map_err(|e| crate::error::ApiError::InvalidRequest(e.to_string()))?;

    let site = state
        .db
        .get_site(&site_id)
        .await?
        .ok_or_else(|| crate::error::ApiError::NotFound(format!("Site {} not found", id)))?;

    Ok(Json(site.into()))
}

/// Site response
#[derive(Debug, Serialize, Deserialize)]
pub struct SiteResponse {
    pub id: String,
    pub name: String,
    pub status: String,
    pub endpoints: Vec<EndpointResponse>,
    pub created_at: String,
    pub last_seen: String,
}

impl From<patronus_sdwan::types::Site> for SiteResponse {
    fn from(site: patronus_sdwan::types::Site) -> Self {
        Self {
            id: site.id.to_string(),
            name: site.name,
            status: format!("{:?}", site.status),
            endpoints: site.endpoints.into_iter().map(|e| e.into()).collect(),
            created_at: chrono::DateTime::<chrono::Utc>::from(site.created_at).to_rfc3339(),
            last_seen: chrono::DateTime::<chrono::Utc>::from(site.last_seen).to_rfc3339(),
        }
    }
}

/// Endpoint response
#[derive(Debug, Serialize, Deserialize)]
pub struct EndpointResponse {
    pub address: String,
    pub interface_type: String,
    pub cost_per_gb: f64,
    pub reachable: bool,
}

impl From<patronus_sdwan::types::Endpoint> for EndpointResponse {
    fn from(endpoint: patronus_sdwan::types::Endpoint) -> Self {
        Self {
            address: endpoint.address.to_string(),
            interface_type: endpoint.interface_type,
            cost_per_gb: endpoint.cost_per_gb,
            reachable: endpoint.reachable,
        }
    }
}
