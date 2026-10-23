//! System API endpoints (lane H): web accounts, configuration backups
//! (create / download / upload / restore, admins only: backups carry
//! password hashes and VPN keys), services (systemd/OpenRC, through
//! `patronus applyd` as root), Portage updates, reboot/shutdown.

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
            state.auth.rbac.forget_user(id as i64).await;
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

/// After a restore that replaced the web accounts, end every session but
/// the caller's. Sessions cache the user id and role from login, so they
/// would otherwise outlive the restore for up to a day: an account the
/// backup doesn't have (say, one an intruder added, the usual reason to
/// restore an older backup) or one it has disabled, demoted or with
/// another password kept working until the session expired. The caller
/// keeps theirs only if their id is still the same enabled admin.
async fn end_sessions_after_restore(state: &AppState, admin: &AdminUser, doc: &serde_json::Value) {
    if !crate::state::system::restores_accounts(doc) {
        return;
    }
    let keep = match state.auth.user_store.get_by_id(admin.session.user_id).await {
        Some(u) if u.enabled && u.role.is_admin() && u.username == admin.session.username => {
            Some(admin.session_id.as_str())
        }
        _ => None,
    };
    state.auth.session_store.drop_all(keep).await;
}

/// POST /api/system/backups/:name/restore -- replace the configuration
/// with a stored backup and apply it (undone if any subsystem refuses it).
pub async fn restore_backup(
    State(state): State<AppState>,
    admin: AdminUser,
    Path(name): Path<String>,
) -> Response {
    let doc = match state.system.backup_doc(&name).await {
        Ok(Some(d)) => d,
        Ok(None) => return error(StatusCode::NOT_FOUND, "no such backup"),
        Err(e) => return err(e),
    };
    match state.system.restore(&state.config_store, &doc, &name).await {
        Ok(lines) => {
            end_sessions_after_restore(&state, &admin, &doc).await;
            Json(json!({ "ok": true, "restored": name, "applied": lines })).into_response()
        }
        Err(e) => err(e),
    }
}

/// POST /api/system/restore -- upload an exported configuration (the
/// file's bytes as the body), keep it as a backup file and restore it.
pub async fn upload_restore(
    State(state): State<AppState>,
    admin: AdminUser,
    headers: axum::http::HeaderMap,
    body: Bytes,
) -> Response {
    // an encrypted remote backup (PBK1): decrypt with X-Backup-Passphrase
    let body = if crate::backup_remote::is_encrypted(&body) {
        let Some(p) = headers
            .get("x-backup-passphrase")
            .and_then(|v| v.to_str().ok())
        else {
            return error(
                StatusCode::BAD_REQUEST,
                "Invalid backup: it is encrypted, send the passphrase in the X-Backup-Passphrase header",
            );
        };
        match crate::backup_remote::decrypt(&body, p) {
            Ok(plain) => Bytes::from(plain),
            Err(e) => return err(e),
        }
    } else {
        body
    };
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
            end_sessions_after_restore(&state, &admin, &doc).await;
            Json(json!({ "ok": true, "restored": b.name, "applied": lines })).into_response()
        }
        Err(e) => err(e),
    }
}

/// GET /api/system/updates -- Portage update state: whether this system
/// has Portage, the last finished check (what is pending, in particular a
/// newer Patronus) and the running/last job with its log tail.
pub async fn list_updates(State(_state): State<AppState>) -> Response {
    let mut v = match patronus_network::sysops::handle("update_status", &serde_json::Value::Null) {
        Ok(v) => v,
        Err(e) => return error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    };
    v["version"] = json!(env!("CARGO_PKG_VERSION"));
    if v["portage"] == false {
        v["note"] = json!(
            "This system has no Portage (emerge): Patronus updates through Portage on Gentoo \
             (`emaint sync -a && emerge -1u net-firewall/patronus`)."
        );
    }
    Json(v).into_response()
}

#[derive(Deserialize, Default)]
pub struct UpdateRequest {
    /// `patronus` (default) or `world` for an apply
    #[serde(default)]
    pub scope: Option<String>,
    /// check: sync the Portage tree first (default true)
    #[serde(default)]
    pub sync: Option<bool>,
}

async fn update_job(state: AppState, action: &str, req: UpdateRequest) -> Response {
    let params = json!({"scope": req.scope, "sync": req.sync});
    match state.system.system_op(action, params).await {
        Ok(v) => (StatusCode::ACCEPTED, Json(v)).into_response(),
        Err(e) => {
            let m = e.to_string();
            let code = if m.starts_with("Invalid") {
                StatusCode::BAD_REQUEST
            } else if m.contains("already running") {
                StatusCode::CONFLICT
            } else if m.contains("no Portage") {
                StatusCode::NOT_IMPLEMENTED
            } else {
                StatusCode::INTERNAL_SERVER_ERROR
            };
            error(code, m)
        }
    }
}

/// POST /api/system/updates/check -- sync the tree and list pending updates
/// (a background job; poll GET /api/system/updates).
pub async fn check_updates(
    State(state): State<AppState>,
    _admin: AdminUser,
    body: Option<Json<UpdateRequest>>,
) -> Response {
    update_job(state, "update_check", body.map(|b| b.0).unwrap_or_default()).await
}

/// POST /api/system/updates/apply -- `emerge` the Patronus package (or all
/// of @world) as a background job.
pub async fn apply_updates(
    State(state): State<AppState>,
    _admin: AdminUser,
    body: Option<Json<UpdateRequest>>,
) -> Response {
    update_job(state, "update_apply", body.map(|b| b.0).unwrap_or_default()).await
}

/// POST /api/system/reboot and /api/system/shutdown (admins; the box goes
/// down a few seconds after the answer).
async fn power(state: AppState, action: &str) -> Response {
    match state
        .system
        .system_op(action, serde_json::Value::Null)
        .await
    {
        Ok(v) => (StatusCode::ACCEPTED, Json(v)).into_response(),
        Err(e) => error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}

pub async fn reboot(State(state): State<AppState>, _admin: AdminUser) -> Response {
    power(state, "reboot").await
}

pub async fn shutdown(State(state): State<AppState>, _admin: AdminUser) -> Response {
    power(state, "shutdown").await
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

#[derive(Deserialize)]
pub struct FactoryReset {
    pub password: String,
    pub confirm: String,
}

/// POST /api/system/factory-reset {password, confirm: "RESET"} (admin, not
/// API keys): back the configuration up, then replace it with a first-boot
/// one (interface roles from patronus.toml, the safe default ruleset),
/// applied to the whole system. Web accounts are kept (so the admin can
/// still log in); groups, VPNs, services, rules and the like are gone. The
/// reset is a restore, so it is also kept as a revision.
pub async fn factory_reset(
    State(state): State<AppState>,
    admin: AdminUser,
    Json(req): Json<FactoryReset>,
) -> Response {
    if req.confirm != "RESET" {
        return error(
            StatusCode::BAD_REQUEST,
            "Invalid request: type RESET to confirm",
        );
    }
    if state
        .auth
        .user_store
        .verify_credentials(&admin.session.username, &req.password)
        .await
        .is_none()
    {
        return error(StatusCode::FORBIDDEN, "wrong password");
    }
    let backup = match state.system.create_backup(&state.config_store).await {
        Ok(b) => b,
        Err(e) => return err(e),
    };
    // the defaults are built on a scratch store; that future is not Send,
    // so it runs on a blocking thread
    let handle = tokio::runtime::Handle::current();
    let doc = tokio::task::spawn_blocking(move || {
        handle.block_on(async {
            let scratch = patronus_config::ConfigStore::open_in_memory()
                .await
                .map_err(|e| e.to_string())?;
            let bootstrap = patronus_config::defaults::Bootstrap::load(
                &patronus_config::defaults::default_bootstrap_path(),
            )
            .ok()
            .flatten();
            patronus_config::defaults::ensure_defaults(
                &scratch,
                bootstrap.as_ref(),
                &patronus_config::defaults::existing_interfaces(),
            )
            .await
            .map_err(|e| format!("building the defaults: {e}"))?;
            scratch.export_json().await.map_err(|e| e.to_string())
        })
    })
    .await;
    let doc = match doc {
        Ok(Ok(d)) => d,
        Ok(Err(e)) => return error(StatusCode::INTERNAL_SERVER_ERROR, e),
        Err(e) => return error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    };
    match state
        .system
        .restore(&state.config_store, &doc, "factory reset")
        .await
    {
        Ok(lines) => {
            Json(json!({ "ok": true, "backup": backup.name, "applied": lines })).into_response()
        }
        Err(e) => err(e),
    }
}

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
        .route("/system/updates/check", post(check_updates))
        .route("/system/updates/apply", post(apply_updates))
        .route("/system/factory-reset", post(factory_reset))
        .route("/system/reboot", post(reboot))
        .route("/system/shutdown", post(shutdown))
        .route("/system/services", get(list_services))
        .route("/system/services/:name/start", post(start_service))
        .route("/system/services/:name/stop", post(stop_service))
        .route("/system/services/:name/restart", post(restart_service))
}
