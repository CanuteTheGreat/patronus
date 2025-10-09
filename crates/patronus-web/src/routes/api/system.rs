//! System API endpoints

use axum::{
    extract::{Path, State},
    Json,
    response::{IntoResponse, Response},
    http::StatusCode,
};
use serde::{Deserialize, Serialize};
use crate::state::AppState;

#[derive(Debug, Serialize, Deserialize)]
pub struct User {
    pub id: u32,
    pub username: String,
    pub email: Option<String>,
    pub role: String,
    pub created_at: String,
    pub last_login: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Backup {
    pub id: u32,
    pub filename: String,
    pub created_at: String,
    pub size: u64,
    pub description: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Update {
    pub package: String,
    pub current_version: String,
    pub available_version: String,
    pub description: String,
    pub security: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Service {
    pub name: String,
    pub status: String,
    pub enabled: bool,
    pub description: String,
}

/// GET /api/system/users
pub async fn list_users(State(state): State<AppState>) -> Response {
    match state.system.list_users().await {
        Ok(users) => Json(users).into_response(),
        Err(e) => {
            tracing::error!("Failed to list users: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
                "error": "Failed to list users"
            }))).into_response()
        }
    }
}

/// GET /api/system/backups
pub async fn list_backups(State(state): State<AppState>) -> Response {
    match state.system.list_backups().await {
        Ok(backups) => Json(backups).into_response(),
        Err(e) => {
            tracing::error!("Failed to list backups: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
                "error": "Failed to list backups"
            }))).into_response()
        }
    }
}

/// POST /api/system/backups
pub async fn create_backup(State(state): State<AppState>) -> Response {
    match state.system.create_backup().await {
        Ok(backup_id) => (StatusCode::CREATED, Json(serde_json::json!({
            "id": backup_id,
            "message": "Backup created successfully"
        }))).into_response(),
        Err(e) => {
            tracing::error!("Failed to create backup: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
                "error": format!("Failed to create backup: {}", e)
            }))).into_response()
        }
    }
}

/// GET /api/system/updates
pub async fn list_updates(State(state): State<AppState>) -> Response {
    match state.system.check_updates().await {
        Ok(updates) => Json(updates).into_response(),
        Err(e) => {
            tracing::error!("Failed to check updates: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
                "error": "Failed to check updates"
            }))).into_response()
        }
    }
}

/// GET /api/system/services
pub async fn list_services(State(state): State<AppState>) -> Response {
    match state.system.list_services().await {
        Ok(services) => Json(services).into_response(),
        Err(e) => {
            tracing::error!("Failed to list services: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
                "error": "Failed to list services"
            }))).into_response()
        }
    }
}

/// POST /api/system/services/:name/start
pub async fn start_service(State(state): State<AppState>, Path(name): Path<String>) -> Response {
    match state.system.start_service(&name).await {
        Ok(_) => Json(serde_json::json!({
            "message": format!("Service {} started successfully", name)
        })).into_response(),
        Err(e) => {
            tracing::error!("Failed to start service {}: {}", name, e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
                "error": format!("Failed to start service: {}", e)
            }))).into_response()
        }
    }
}

/// POST /api/system/services/:name/stop
pub async fn stop_service(State(state): State<AppState>, Path(name): Path<String>) -> Response {
    match state.system.stop_service(&name).await {
        Ok(_) => Json(serde_json::json!({
            "message": format!("Service {} stopped successfully", name)
        })).into_response(),
        Err(e) => {
            tracing::error!("Failed to stop service {}: {}", name, e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
                "error": format!("Failed to stop service: {}", e)
            }))).into_response()
        }
    }
}

/// POST /api/system/services/:name/restart
pub async fn restart_service(State(state): State<AppState>, Path(name): Path<String>) -> Response {
    match state.system.restart_service(&name).await {
        Ok(_) => Json(serde_json::json!({
            "message": format!("Service {} restarted successfully", name)
        })).into_response(),
        Err(e) => {
            tracing::error!("Failed to restart service {}: {}", name, e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
                "error": format!("Failed to restart service: {}", e)
            }))).into_response()
        }
    }
}
