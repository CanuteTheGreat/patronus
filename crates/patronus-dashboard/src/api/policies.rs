//! Policies API endpoints

use axum::{extract::{Path, State}, Json};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::{error::Result, state::AppState};

/// List all policies
pub async fn list_policies(
    State(_state): State<Arc<AppState>>,
) -> Result<Json<Vec<PolicyResponse>>> {
    // TODO: Integrate with PolicyEnforcer
    // For now, return empty list
    Ok(Json(vec![]))
}

/// Get policy by ID
pub async fn get_policy(
    State(_state): State<Arc<AppState>>,
    Path(_id): Path<String>,
) -> Result<Json<PolicyResponse>> {
    Err(crate::error::ApiError::NotFound(
        "Policy not found".to_string(),
    ))
}

/// Create policy
pub async fn create_policy(
    State(_state): State<Arc<AppState>>,
    Json(_req): Json<CreatePolicyRequest>,
) -> Result<Json<PolicyResponse>> {
    Err(crate::error::ApiError::Internal(
        "Not implemented".to_string(),
    ))
}

/// Policy response
#[derive(Debug, Serialize, Deserialize)]
pub struct PolicyResponse {
    pub id: String,
    pub name: String,
    pub namespace: String,
    pub pod_selector: serde_json::Value,
    pub policy_types: Vec<String>,
    pub enabled: bool,
    pub priority: u32,
}

/// Create policy request
#[derive(Debug, Serialize, Deserialize)]
pub struct CreatePolicyRequest {
    pub name: String,
    pub namespace: String,
    pub spec: serde_json::Value,
}
