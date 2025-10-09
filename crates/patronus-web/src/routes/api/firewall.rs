//! Firewall API endpoints

use axum::{
    extract::{Path, State},
    Json,
    response::{IntoResponse, Response},
    http::StatusCode,
};
use serde::{Deserialize, Serialize};
use crate::state::AppState;

#[derive(Debug, Serialize, Deserialize)]
pub struct FirewallRule {
    pub id: Option<u32>,
    pub action: String,
    pub interface: String,
    pub protocol: String,
    pub source: String,
    pub destination: String,
    pub port: String,
    pub description: String,
    pub enabled: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NatRule {
    pub id: Option<u32>,
    pub rule_type: String, // SNAT, DNAT, or NAT
    pub interface: String,
    pub source: String,
    pub destination: String,
    pub target: String,
    pub description: String,
    pub enabled: bool,
}

/// GET /api/firewall/rules
pub async fn list_rules(State(state): State<AppState>) -> Response {
    match state.firewall.list_rules().await {
        Ok(rules) => Json(rules).into_response(),
        Err(e) => {
            tracing::error!("Failed to list firewall rules: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
                "error": "Failed to list firewall rules"
            }))).into_response()
        }
    }
}

/// GET /api/firewall/rules/:id
pub async fn get_rule(State(state): State<AppState>, Path(id): Path<u32>) -> Response {
    match state.firewall.get_rule(id).await {
        Ok(Some(rule)) => Json(rule).into_response(),
        Ok(None) => (StatusCode::NOT_FOUND, Json(serde_json::json!({
            "error": "Rule not found"
        }))).into_response(),
        Err(e) => {
            tracing::error!("Failed to get firewall rule {}: {}", id, e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
                "error": "Failed to get firewall rule"
            }))).into_response()
        }
    }
}

/// POST /api/firewall/rules
pub async fn add_rule(State(state): State<AppState>, Json(rule): Json<FirewallRule>) -> Response {
    match state.firewall.add_rule(rule).await {
        Ok(id) => (StatusCode::CREATED, Json(serde_json::json!({
            "id": id,
            "message": "Rule created successfully"
        }))).into_response(),
        Err(e) => {
            tracing::error!("Failed to add firewall rule: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
                "error": format!("Failed to add rule: {}", e)
            }))).into_response()
        }
    }
}

/// PUT /api/firewall/rules/:id
pub async fn update_rule(
    State(state): State<AppState>,
    Path(id): Path<u32>,
    Json(rule): Json<FirewallRule>
) -> Response {
    match state.firewall.update_rule(id, rule).await {
        Ok(_) => Json(serde_json::json!({
            "message": "Rule updated successfully"
        })).into_response(),
        Err(e) => {
            tracing::error!("Failed to update firewall rule {}: {}", id, e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
                "error": format!("Failed to update rule: {}", e)
            }))).into_response()
        }
    }
}

/// DELETE /api/firewall/rules/:id
pub async fn delete_rule(State(state): State<AppState>, Path(id): Path<u32>) -> Response {
    match state.firewall.delete_rule(id).await {
        Ok(_) => Json(serde_json::json!({
            "message": "Rule deleted successfully"
        })).into_response(),
        Err(e) => {
            tracing::error!("Failed to delete firewall rule {}: {}", id, e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
                "error": format!("Failed to delete rule: {}", e)
            }))).into_response()
        }
    }
}

/// POST /api/firewall/rules/apply
pub async fn apply_rules(State(state): State<AppState>) -> Response {
    match state.firewall.apply_rules().await {
        Ok(_) => Json(serde_json::json!({
            "message": "Rules applied successfully"
        })).into_response(),
        Err(e) => {
            tracing::error!("Failed to apply firewall rules: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
                "error": format!("Failed to apply rules: {}", e)
            }))).into_response()
        }
    }
}

/// GET /api/firewall/nat
pub async fn list_nat_rules(State(state): State<AppState>) -> Response {
    match state.firewall.list_nat_rules().await {
        Ok(rules) => Json(rules).into_response(),
        Err(e) => {
            tracing::error!("Failed to list NAT rules: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
                "error": "Failed to list NAT rules"
            }))).into_response()
        }
    }
}

/// POST /api/firewall/nat
pub async fn add_nat_rule(State(state): State<AppState>, Json(rule): Json<NatRule>) -> Response {
    match state.firewall.add_nat_rule(rule).await {
        Ok(id) => (StatusCode::CREATED, Json(serde_json::json!({
            "id": id,
            "message": "NAT rule created successfully"
        }))).into_response(),
        Err(e) => {
            tracing::error!("Failed to add NAT rule: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
                "error": format!("Failed to add NAT rule: {}", e)
            }))).into_response()
        }
    }
}

/// DELETE /api/firewall/nat/:id
pub async fn delete_nat_rule(State(state): State<AppState>, Path(id): Path<u32>) -> Response {
    match state.firewall.delete_nat_rule(id).await {
        Ok(_) => Json(serde_json::json!({
            "message": "NAT rule deleted successfully"
        })).into_response(),
        Err(e) => {
            tracing::error!("Failed to delete NAT rule {}: {}", id, e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
                "error": format!("Failed to delete NAT rule: {}", e)
            }))).into_response()
        }
    }
}
