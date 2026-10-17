//! System API endpoints: users (auth store), configuration backups (real
//! files), services (systemd/OpenRC), updates (not implemented: 501).

use crate::state::{system::ServiceError, AppState};
use axum::{
    extract::{Path, State},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    Json,
};

fn error(code: StatusCode, msg: impl Into<String>) -> Response {
    (code, Json(serde_json::json!({ "error": msg.into() }))).into_response()
}

/// The web UI accounts from the auth user store, for display.
pub async fn users(state: &AppState) -> Vec<crate::templates::User> {
    let mut list = state.auth.user_store.list_users().await;
    list.sort_by_key(|u| u.id);
    list.into_iter()
        .map(|u| crate::templates::User {
            id: u.id,
            username: u.username,
            role: match u.role {
                crate::auth::UserRole::Admin => "admin",
                crate::auth::UserRole::Operator => "operator",
                crate::auth::UserRole::ReadOnly => "read-only",
            }
            .to_string(),
            is_active: u.enabled,
            created_at: u.created_at.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
            last_login_display: u
                .last_login
                .map(|t| t.format("%Y-%m-%d %H:%M:%S UTC").to_string())
                .unwrap_or_else(|| "never".to_string()),
        })
        .collect()
}

/// GET /api/system/users
pub async fn list_users(State(state): State<AppState>) -> Response {
    Json(users(&state).await).into_response()
}

/// GET /api/system/backups -- backup files with their real sizes.
pub async fn list_backups(State(state): State<AppState>) -> Response {
    match state.system.list_backups().await {
        Ok(b) => Json(b).into_response(),
        Err(e) => error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}

/// POST /api/system/backups -- export the config store to a new file.
pub async fn create_backup(State(state): State<AppState>) -> Response {
    match state.system.create_backup(&state.config_store).await {
        Ok(b) => (StatusCode::CREATED, Json(b)).into_response(),
        Err(e) => {
            tracing::error!("Failed to create backup: {e}");
            error(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to create backup: {e}"),
            )
        }
    }
}

/// GET /api/system/backups/:name -- download the file.
pub async fn download_backup(State(state): State<AppState>, Path(name): Path<String>) -> Response {
    match state.system.read_backup(&name).await {
        Ok(Some(bytes)) => (
            [
                (header::CONTENT_TYPE, "application/json".to_string()),
                (
                    header::CONTENT_DISPOSITION,
                    format!("attachment; filename=\"{name}\""),
                ),
            ],
            bytes,
        )
            .into_response(),
        Ok(None) => error(StatusCode::NOT_FOUND, "no such backup"),
        Err(e) => error(StatusCode::BAD_REQUEST, e.to_string()),
    }
}

/// DELETE /api/system/backups/:name
pub async fn delete_backup(State(state): State<AppState>, Path(name): Path<String>) -> Response {
    match state.system.delete_backup(&name).await {
        Ok(true) => {
            Json(serde_json::json!({ "message": format!("deleted {name}") })).into_response()
        }
        Ok(false) => error(StatusCode::NOT_FOUND, "no such backup"),
        Err(e) => error(StatusCode::BAD_REQUEST, e.to_string()),
    }
}

/// GET /api/system/updates -- not implemented. This used to announce a
/// `patronus-core 0.1.1` update on every box.
pub async fn list_updates() -> Response {
    error(
        StatusCode::NOT_IMPLEMENTED,
        format!(
            "Patronus {} does not check for updates itself. On Gentoo update through Portage: \
             `emaint sync -a && emerge -1u net-firewall/patronus` (or `emerge -uDN @world`).",
            env!("CARGO_PKG_VERSION")
        ),
    )
}

/// GET /api/system/services -- installed Patronus-related services and
/// their real state.
pub async fn list_services(State(state): State<AppState>) -> Response {
    match state.system.list_services().await {
        Ok(s) => Json(s).into_response(),
        Err(e) => error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}

async fn control(state: AppState, name: String, action: &str) -> Response {
    match state.system.control_service(&name, action).await {
        Ok(()) => Json(serde_json::json!({
            "message": format!("{action} {name}: done")
        }))
        .into_response(),
        Err(e @ ServiceError::NotManaged(_)) => error(StatusCode::NOT_FOUND, e.to_string()),
        Err(e) => {
            tracing::error!("{action} {name}: {e}");
            error(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("{action} {name} failed: {e}"),
            )
        }
    }
}

/// POST /api/system/services/:name/start
pub async fn start_service(State(state): State<AppState>, Path(name): Path<String>) -> Response {
    control(state, name, "start").await
}

/// POST /api/system/services/:name/stop
pub async fn stop_service(State(state): State<AppState>, Path(name): Path<String>) -> Response {
    control(state, name, "stop").await
}

/// POST /api/system/services/:name/restart
pub async fn restart_service(State(state): State<AppState>, Path(name): Path<String>) -> Response {
    control(state, name, "restart").await
}

/// This lane's API routes, mounted under `/api` by `routes::api_routes`
/// with one `.merge(system::router())` line.
pub fn router() -> axum::Router<AppState> {
    use axum::routing::{get, post};
    axum::Router::new()
        .route("/system/users", get(list_users))
        .route("/system/backups", get(list_backups).post(create_backup))
        .route(
            "/system/backups/:name",
            get(download_backup).delete(delete_backup),
        )
        .route("/system/updates", get(list_updates))
        .route("/system/services", get(list_services))
        .route("/system/services/:name/start", post(start_service))
        .route("/system/services/:name/stop", post(stop_service))
        .route("/system/services/:name/restart", post(restart_service))
}
