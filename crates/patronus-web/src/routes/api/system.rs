//! System API endpoints (lane H): web accounts, configuration backups
//! (create / download / upload / restore, admins only: backups carry
//! password hashes and VPN keys), services (systemd/OpenRC, through
//! `patronus applyd` as root), updates (not implemented: 501).

use crate::auth::{AdminUser, UserRole, UserUpdate};
use crate::state::{system::ServiceError, AppState};
use axum::{
    body::Bytes,
    extract::{Path, State},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::Deserialize;
use serde_json::json;

fn error(code: StatusCode, msg: impl Into<String>) -> Response {
    (code, Json(json!({ "error": msg.into() }))).into_response()
}

fn err(e: anyhow::Error) -> Response {
    let msg = e.to_string();
    let code = if msg.starts_with("Invalid") || msg.contains(": Invalid") {
        StatusCode::BAD_REQUEST
    } else if msg.starts_with("no such") {
        StatusCode::NOT_FOUND
    } else if msg.contains("could not be applied") {
        StatusCode::CONFLICT
    } else {
        StatusCode::INTERNAL_SERVER_ERROR
    };
    error(code, msg)
}

/// The web UI accounts from the auth user store, for display.
pub async fn users(state: &AppState) -> Vec<crate::templates::User> {
    state
        .auth
        .user_store
        .list_users()
        .await
        .into_iter()
        .map(|u| crate::templates::User {
            id: u.id,
            username: u.username,
            role: u.role.label().to_string(),
            role_key: u.role.as_str().to_string(),
            is_active: u.enabled,
            two_factor: u.two_factor,
            recovery_codes_left: u.recovery_codes_left,
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
    Json(state.auth.user_store.list_users().await).into_response()
}

#[derive(Debug, Deserialize)]
pub struct CreateUser {
    pub username: String,
    pub password: String,
    pub role: String,
}

/// POST /api/system/users (admin)
pub async fn create_user(
    State(state): State<AppState>,
    _admin: AdminUser,
    Json(req): Json<CreateUser>,
) -> Response {
    let Some(role) = UserRole::parse(&req.role) else {
        return error(
            StatusCode::BAD_REQUEST,
            format!("Invalid role {:?}: admin, operator or readonly", req.role),
        );
    };
    match state
        .auth
        .user_store
        .create_user(req.username, &req.password, role)
        .await
    {
        Ok(id) => {
            let _ = state
                .config_store
                .audit(
                    "web",
                    "create",
                    "user",
                    Some(&id.to_string()),
                    &serde_json::Value::Null,
                )
                .await;
            let u = state.auth.user_store.get_by_id(id).await;
            (
                StatusCode::CREATED,
                Json(json!({ "id": id, "user": u.as_ref().map(crate::auth::UserInfo::from) })),
            )
                .into_response()
        }
        Err(e) => err(e),
    }
}

/// PUT /api/system/users/:id (admin) {role?, enabled?, password?}. The
/// account's sessions end (it logs in again with the new role/password).
///
/// An admin cannot set their *own* password here: `POST /api/auth/password`
/// asks for the current one (throttled like login), and this route would
/// let anyone holding an admin's session skip that check, change the
/// owner's password and lock them out of their own router.
pub async fn update_user(
    State(state): State<AppState>,
    admin: AdminUser,
    Path(id): Path<u32>,
    Json(req): Json<UserUpdate>,
) -> Response {
    if id == admin.session.user_id && req.password.is_some() {
        return error(
            StatusCode::BAD_REQUEST,
            "Invalid request: change your own password under \"Your account\" \
             (POST /api/auth/password, which asks for the current password)",
        );
    }
    match state.auth.user_store.update_user(id, &req).await {
        Ok(u) => {
            let keep =
                (id == admin.session.user_id && req.role.is_none() && req.enabled != Some(false))
                    .then_some(admin.session_id.as_str());
            state.auth.session_store.drop_user(id, keep).await;
            Json(json!({ "ok": true, "user": crate::auth::UserInfo::from(&u) })).into_response()
        }
        Err(e) => err(e),
    }
}

/// DELETE /api/system/users/:id (admin; never the last enabled admin)
pub async fn delete_user(
    State(state): State<AppState>,
    admin: AdminUser,
    Path(id): Path<u32>,
) -> Response {
    if id == admin.session.user_id {
        return error(
            StatusCode::BAD_REQUEST,
            "Invalid request: you cannot delete the account you are logged in with",
        );
    }
    match state.auth.user_store.delete_user(id).await {
        Ok(true) => {
            state.auth.session_store.drop_user(id, None).await;
            Json(json!({ "ok": true })).into_response()
        }
        Ok(false) => error(StatusCode::NOT_FOUND, format!("no such user {id}")),
        Err(e) => err(e),
    }
}

/// POST /api/system/users/:id/2fa/reset (admin): turn the account's
/// two-factor login off (lost phone).
///
/// Not for the admin's *own* account: `POST /api/auth/2fa/disable` asks for
/// the password and a current code (throttled like login), and this route
/// would let anyone holding an admin's session strip the owner's second
/// factor without either. An admin locked out of their own 2FA isn't
/// logged in anyway; that is what `patronus users reset-2fa` is for.
pub async fn reset_2fa(
    State(state): State<AppState>,
    admin: AdminUser,
    Path(id): Path<u32>,
) -> Response {
    if id == admin.session.user_id {
        return error(
            StatusCode::BAD_REQUEST,
            "Invalid request: turn your own two-factor login off under \"Your account\" \
             (POST /api/auth/2fa/disable, which asks for the password and a current code)",
        );
    }
    match state.auth.user_store.totp_reset(id).await {
        Ok(true) => {
            state.auth.session_store.drop_user(id, None).await;
            Json(json!({ "ok": true })).into_response()
        }
        Ok(false) => error(StatusCode::NOT_FOUND, format!("no such user {id}")),
        Err(e) => err(e),
    }
}

/// GET /api/system/backups -- backup files with their real sizes.
pub async fn list_backups(State(state): State<AppState>) -> Response {
    match state.system.list_backups().await {
        Ok(b) => Json(b).into_response(),
        Err(e) => error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}

/// POST /api/system/backups -- export the config store to a new file.
pub async fn create_backup(State(state): State<AppState>, _admin: AdminUser) -> Response {
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

/// GET /api/system/backups/:name -- download the file (admin: it holds
/// password hashes and VPN keys).
pub async fn download_backup(
    State(state): State<AppState>,
    _admin: AdminUser,
    Path(name): Path<String>,
) -> Response {
    match state.system.read_backup(&name).await {
        Ok(Some(bytes)) => (
            [
                (header::CONTENT_TYPE, "application/json".to_string()),
                (
                    header::CONTENT_DISPOSITION,
                    format!("attachment; filename=\"{name}\""),
                ),
                (header::CACHE_CONTROL, "no-store".to_string()),
            ],
            bytes,
        )
            .into_response(),
        Ok(None) => error(StatusCode::NOT_FOUND, "no such backup"),
        Err(e) => error(StatusCode::BAD_REQUEST, e.to_string()),
    }
}

/// DELETE /api/system/backups/:name
pub async fn delete_backup(
    State(state): State<AppState>,
    _admin: AdminUser,
    Path(name): Path<String>,
) -> Response {
    match state.system.delete_backup(&name).await {
        Ok(true) => Json(json!({ "message": format!("deleted {name}") })).into_response(),
        Ok(false) => error(StatusCode::NOT_FOUND, "no such backup"),
        Err(e) => error(StatusCode::BAD_REQUEST, e.to_string()),
    }
}

/// POST /api/system/backups/:name/restore -- replace the configuration
/// with a stored backup and apply it (undone if any subsystem refuses it).
pub async fn restore_backup(
    State(state): State<AppState>,
    _admin: AdminUser,
    Path(name): Path<String>,
) -> Response {
    let doc = match state.system.backup_doc(&name).await {
        Ok(Some(d)) => d,
        Ok(None) => return error(StatusCode::NOT_FOUND, "no such backup"),
        Err(e) => return err(e),
    };
    match state.system.restore(&state.config_store, &doc, &name).await {
        Ok(lines) => {
            Json(json!({ "ok": true, "restored": name, "applied": lines })).into_response()
        }
        Err(e) => err(e),
    }
}

/// POST /api/system/restore -- upload an exported configuration (the
/// file's bytes as the body), keep it as a backup file and restore it.
pub async fn upload_restore(
    State(state): State<AppState>,
    _admin: AdminUser,
    body: Bytes,
) -> Response {
    let (b, doc) = match state.system.save_upload(&body).await {
        Ok(x) => x,
        Err(e) => return err(e),
    };
    match state
        .system
        .restore(&state.config_store, &doc, &b.name)
        .await
    {
        Ok(lines) => {
            Json(json!({ "ok": true, "restored": b.name, "applied": lines })).into_response()
        }
        Err(e) => err(e),
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
        Ok(()) => Json(json!({
            "message": format!("{action} {name}: done")
        }))
        .into_response(),
        Err(e @ ServiceError::NotManaged(_)) => error(StatusCode::NOT_FOUND, e.to_string()),
        Err(e) if e.to_string().contains("can only be restarted") => {
            error(StatusCode::BAD_REQUEST, e.to_string())
        }
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

/// Largest configuration upload accepted (an export is a few hundred KiB).
pub const MAX_UPLOAD: usize = 16 << 20;

/// This lane's API routes, mounted under `/api` by `routes::api_routes`
/// with one `.merge(system::router())` line.
pub fn router() -> axum::Router<AppState> {
    use axum::routing::{get, post, put};
    axum::Router::new()
        .route("/system/users", get(list_users).post(create_user))
        .route("/system/users/:id", put(update_user).delete(delete_user))
        .route("/system/users/:id/2fa/reset", post(reset_2fa))
        .route("/system/backups", get(list_backups).post(create_backup))
        .route(
            "/system/backups/:name",
            get(download_backup).delete(delete_backup),
        )
        .route("/system/backups/:name/restore", post(restore_backup))
        .route(
            "/system/restore",
            post(upload_restore).layer(axum::extract::DefaultBodyLimit::max(MAX_UPLOAD)),
        )
        .route("/system/updates", get(list_updates))
        .route("/system/services", get(list_services))
        .route("/system/services/:name/start", post(start_service))
        .route("/system/services/:name/stop", post(stop_service))
        .route("/system/services/:name/restart", post(restart_service))
}
