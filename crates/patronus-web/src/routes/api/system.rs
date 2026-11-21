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

/// GET /api/system/history -- the configuration revisions the store keeps
/// (every change is one), newest first: id, time, who, what.
pub async fn list_history(State(state): State<AppState>) -> Response {
    match state.config_store.list_revisions().await {
        Ok(revs) => Json(
            revs.into_iter()
                .map(|(id, at, user, summary)| {
                    json!({
                        "id": id,
                        "created_at": at,
                        "when": chrono::DateTime::from_timestamp(at, 0)
                            .map(|t| t.format("%Y-%m-%d %H:%M:%S UTC").to_string())
                            .unwrap_or_default(),
                        "user": user,
                        "summary": summary,
                    })
                })
                .collect::<Vec<_>>(),
        )
        .into_response(),
        Err(e) => error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}

/// Column names whose values never leave the box in a diff.
fn secret_column(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    [
        "password", "secret", "hash", "token", "key", "totp", "recovery", "psk",
    ]
    .iter()
    .any(|w| n.contains(w))
}

fn redact_row(row: &serde_json::Value) -> serde_json::Value {
    match row {
        serde_json::Value::Object(o) => serde_json::Value::Object(
            o.iter()
                .map(|(k, v)| {
                    if secret_column(k) && !v.is_null() {
                        (k.clone(), json!("(hidden)"))
                    } else {
                        (k.clone(), v.clone())
                    }
                })
                .collect(),
        ),
        other => other.clone(),
    }
}

/// What restoring `old` would change in `current`: per table, the rows the
/// restore would bring back (`restored`) and the rows it would remove
/// (`removed`). Rows are compared whole; secret columns are shown hidden
/// (a changed secret still shows as a different row, never its value).
pub(crate) fn config_diff(
    old: &serde_json::Value,
    current: &serde_json::Value,
) -> Vec<serde_json::Value> {
    use std::collections::BTreeSet;
    let empty = serde_json::Map::new();
    let (ot, ct) = (
        old.get("tables")
            .and_then(|t| t.as_object())
            .unwrap_or(&empty),
        current
            .get("tables")
            .and_then(|t| t.as_object())
            .unwrap_or(&empty),
    );
    let names: BTreeSet<&String> = ot.keys().chain(ct.keys()).collect();
    let rows =
        |t: &serde_json::Map<String, serde_json::Value>, n: &str| -> Vec<serde_json::Value> {
            t.get(n)
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default()
        };
    let mut out = Vec::new();
    for n in names {
        let (o, c) = (rows(ot, n), rows(ct, n));
        let restored: Vec<_> = o
            .iter()
            .filter(|r| !c.contains(r))
            .map(redact_row)
            .collect();
        let removed: Vec<_> = c
            .iter()
            .filter(|r| !o.contains(r))
            .map(redact_row)
            .collect();
        if restored.is_empty() && removed.is_empty() {
            continue;
        }
        out.push(json!({ "table": n, "restored": restored, "removed": removed }));
    }
    out
}

/// GET /api/system/history/:id/diff -- what restoring a revision would
/// change relative to the running configuration (admins: the rows can
/// hold addresses and account names).
pub async fn history_diff(
    State(state): State<AppState>,
    _admin: AdminUser,
    Path(id): Path<i64>,
) -> Response {
    let old = match state.config_store.revision_json(id).await {
        Ok(Some(d)) => d,
        Ok(None) => return error(StatusCode::NOT_FOUND, "no such revision"),
        Err(e) => return error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    };
    let current = match state.config_store.export_json().await {
        Ok(d) => d,
        Err(e) => return error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    };
    Json(json!({ "revision": id, "tables": config_diff(&old, &current) })).into_response()
}

/// POST /api/system/history/:id/restore -- put the configuration of one
/// revision back and apply it to the whole system (admins). The state it
/// replaces is kept as a new revision, so this can be undone the same way;
/// if any subsystem refuses the old configuration the restore is undone.
pub async fn restore_history(
    State(state): State<AppState>,
    admin: AdminUser,
    Path(id): Path<i64>,
) -> Response {
    let doc = match state.config_store.revision_json(id).await {
        Ok(Some(d)) => d,
        Ok(None) => return error(StatusCode::NOT_FOUND, "no such revision"),
        Err(e) => return error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    };
    match state
        .system
        .restore(&state.config_store, &doc, &format!("revision {id}"))
        .await
    {
        Ok(lines) => {
            end_sessions_after_restore(&state, &admin, &doc).await;
            Json(json!({ "ok": true, "restored": id, "applied": lines })).into_response()
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

/// GET /api/system/general -- the stored host name / domain / time zone
/// (a key that was never set is unmanaged: the system keeps its own value).
pub async fn get_general(State(state): State<AppState>) -> Response {
    match state.lan.general_overview().await {
        Ok(v) => Json(v).into_response(),
        Err(e) => error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}

/// PUT /api/system/general -- set host name, DNS domain and/or time zone and
/// apply them (an unknown time zone or bad name is refused and nothing
/// changes).
pub async fn put_general(
    State(state): State<AppState>,
    _admin: AdminUser,
    Json(i): Json<patronus_network::general::GeneralInput>,
) -> Response {
    match state.lan.save_general(i).await {
        Ok(()) => Json(json!({ "ok": true })).into_response(),
        Err(e) => {
            let m = e.to_string();
            let code = if m.contains("Invalid") {
                StatusCode::BAD_REQUEST
            } else {
                StatusCode::INTERNAL_SERVER_ERROR
            };
            error(code, m)
        }
    }
}

/// GET /api/system/ssh -- the managed OpenSSH server settings (public
/// keys and the host certificate only; there are no secrets in them).
pub async fn get_ssh(State(state): State<AppState>) -> Response {
    match state.lan.ssh_overview().await {
        Ok(v) => Json(v).into_response(),
        Err(e) => error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}

/// PUT /api/system/ssh -- port, listen interfaces/addresses, password and
/// root policy, user CA keys, per-user principals, host certificate. Bad
/// input is refused; a config sshd rejects is rolled back.
pub async fn put_ssh(
    State(state): State<AppState>,
    _admin: AdminUser,
    Json(i): Json<patronus_network::ssh::SshInput>,
) -> Response {
    match state.lan.save_ssh(i).await {
        Ok(()) => Json(json!({ "ok": true })).into_response(),
        Err(e) => {
            let m = e.to_string();
            let code = if m.contains("Invalid") {
                StatusCode::BAD_REQUEST
            } else {
                StatusCode::INTERNAL_SERVER_ERROR
            };
            error(code, m)
        }
    }
}

/// GET /api/system/web -- where the web UI listens: the effective settings
/// (store > patronus.toml > environment > built-in) and the raw stored values.
pub async fn get_web(State(state): State<AppState>) -> Response {
    match state.lan.web_overview().await {
        Ok(v) => Json(v).into_response(),
        Err(e) => error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}

/// PUT /api/system/web -- listen addresses, HTTPS port, HTTP redirect port
/// (0 = off), extra HTTPS ports ("none" = off), TLS certificate/key paths.
/// Absent = unchanged, empty = back to the lower layers, `reset` = forget all.
/// The firewall's anti-lockout rule follows at once; the listeners move when
/// the web UI is restarted (the answer says so), so a wrong value can be
/// corrected from the old address first.
pub async fn put_web(
    State(state): State<AppState>,
    _admin: AdminUser,
    Json(i): Json<patronus_config::webui::WebInput>,
) -> Response {
    match state.lan.save_web(i).await {
        Ok(()) => Json(json!({ "ok": true, "restart_required": true })).into_response(),
        Err(e) => {
            let m = e.to_string();
            let code = if m.contains("Invalid") {
                StatusCode::BAD_REQUEST
            } else {
                StatusCode::INTERNAL_SERVER_ERROR
            };
            error(code, m)
        }
    }
}

/// GET /api/system/ports -- the time's-up page port and the HAProxy stats
/// port/bind address: effective values, stored values and built-in defaults.
pub async fn get_ports(State(state): State<AppState>) -> Response {
    match state.lan.ports_overview().await {
        Ok(v) => Json(v).into_response(),
        Err(e) => error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}

/// PUT /api/system/ports -- `timeup_port`, `haproxy_stats_port`,
/// `haproxy_stats_bind`; absent = unchanged, 0 / empty = back to the lower
/// layers, `reset` = forget all. Refused: 0, a web UI port, SSH/DNS/DHCP/NTP
/// ports for the time page, a non-IP bind address.
pub async fn put_ports(
    State(state): State<AppState>,
    _admin: AdminUser,
    Json(i): Json<patronus_config::ports::PortsInput>,
) -> Response {
    match state.lan.save_ports(i).await {
        Ok(()) => Json(json!({ "ok": true, "restart_required": true })).into_response(),
        Err(e) => {
            let m = e.to_string();
            let code = if m.contains("Invalid") {
                StatusCode::BAD_REQUEST
            } else {
                StatusCode::INTERNAL_SERVER_ERROR
            };
            error(code, m)
        }
    }
}

pub async fn reboot(State(state): State<AppState>, _admin: AdminUser) -> Response {
    power(state, "reboot").await
}

/// Largest firmware image the upload takes (a router-tier sysupgrade tar is ~22 MiB).
const MAX_FIRMWARE: usize = 64 * 1024 * 1024;

/// GET /api/system/firmware: running build, uploaded / staged image (router tier, `patronus-flash`) and the boot
/// rollback state (`boot_guard`: trial / confirmed / reverted, boots left, previous image, settings, events).
pub async fn firmware_status(State(state): State<AppState>) -> Response {
    match state
        .system
        .system_op("firmware_status", serde_json::Value::Null)
        .await
    {
        Ok(v) => {
            bootguard_audit(&state, &v["boot_guard"]).await;
            Json(v).into_response()
        }
        Err(e) => err(e),
    }
}

static BOOTGUARD_AUDIT: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// The boot guard's events (trial armed, confirmed, failed, reverted by the bootloader, ...) happen before the web UI
/// runs; each one becomes an audit-log entry (user `boot-guard`) once, by its sequence number.
pub async fn bootguard_audit(state: &AppState, guard: &serde_json::Value) {
    let Some(events) = guard.get("events").and_then(|e| e.as_array()) else {
        return;
    };
    let _g = BOOTGUARD_AUDIT.lock().await;
    let key = "bootguard.audit_seq";
    let mut last: i64 = match state.config_store.load_system_config(key).await {
        Ok(v) => v.and_then(|v| v.parse().ok()).unwrap_or(0),
        Err(_) => return,
    };
    // a unit whose event log restarted (factory reset of the settings volume) counts from 1 again
    let max = events
        .iter()
        .filter_map(|e| e["seq"].as_i64())
        .max()
        .unwrap_or(0);
    if max < last {
        last = 0;
    }
    for e in events {
        let Some(seq) = e["seq"].as_i64() else {
            continue;
        };
        if seq <= last {
            continue;
        }
        let action = format!("boot-{}", e["event"].as_str().unwrap_or("event"));
        let _ = state
            .config_store
            .audit(
                "boot-guard",
                &action,
                "firmware",
                guard["running"].as_str(),
                &json!({ "detail": e["detail"], "time": e["time"], "seq": seq }),
            )
            .await;
        last = seq;
    }
    let _ = state
        .config_store
        .save_system_config(key, &last.to_string())
        .await;
}

/// PUT /api/system/firmware/boot-guard (admins): the boot rollback policy (boot-guard.conf).
pub async fn firmware_guard_put(
    State(state): State<AppState>,
    admin: AdminUser,
    Json(b): Json<serde_json::Value>,
) -> Response {
    let r = state
        .system
        .system_op("firmware_guard_set", b.clone())
        .await;
    let _ = state
        .config_store
        .audit(
            &admin.session.username,
            if r.is_ok() {
                "update"
            } else {
                "update-refused"
            },
            "boot_guard",
            None,
            &b,
        )
        .await;
    match r {
        Ok(v) => Json(v).into_response(),
        Err(e) => err(e),
    }
}

/// POST /api/system/firmware/rollback (admins): restart now; the bootloader restores the previous image.
pub async fn firmware_rollback(State(state): State<AppState>, admin: AdminUser) -> Response {
    match state
        .system
        .system_op("firmware_rollback", serde_json::Value::Null)
        .await
    {
        Ok(v) => {
            let _ = state
                .config_store
                .audit(&admin.session.username, "rollback", "firmware", None, &v)
                .await;
            let st = state.clone();
            tokio::spawn(async move {
                tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                if let Err(e) = st.system.system_op("reboot", serde_json::Value::Null).await {
                    tracing::error!("firmware rollback: restart failed: {e}");
                }
            });
            (StatusCode::ACCEPTED, Json(v)).into_response()
        }
        Err(e) => err(e),
    }
}

/// POST /api/system/firmware/confirm (admins): confirm the running trial image by hand.
pub async fn firmware_confirm(State(state): State<AppState>, admin: AdminUser) -> Response {
    match state
        .system
        .system_op("firmware_confirm", serde_json::Value::Null)
        .await
    {
        Ok(v) => {
            let _ = state
                .config_store
                .audit(&admin.session.username, "confirm", "firmware", None, &v)
                .await;
            Json(v).into_response()
        }
        Err(e) => err(e),
    }
}

/// POST /api/system/firmware (admins): the sysupgrade image as the request body; it is checked right away with
/// the box's own guards (`patronus-flash check`: board, metadata, checksums, flash sizes) and the verdict returned.
pub async fn firmware_upload(
    State(state): State<AppState>,
    admin: AdminUser,
    body: Bytes,
) -> Response {
    let path = patronus_network::sysops::firmware_upload_path();
    if body.len() < 1024 {
        return error(
            StatusCode::BAD_REQUEST,
            "Invalid image: the upload is empty or not a firmware image",
        );
    }
    let write = {
        let path = path.clone();
        tokio::task::spawn_blocking(move || -> std::io::Result<()> {
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;
            let tmp = path.with_extension("part");
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&tmp)?;
            f.write_all(&body)?;
            f.sync_all()?;
            std::fs::rename(&tmp, &path)
        })
        .await
    };
    if let Err(e) = write
        .map_err(|e| e.to_string())
        .and_then(|r| r.map_err(|e| e.to_string()))
    {
        return error(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("could not store the upload: {e}"),
        );
    }
    let r = state
        .system
        .system_op("firmware_check", serde_json::Value::Null)
        .await;
    let _ = state
        .config_store
        .audit(
            &admin.session.username,
            "upload",
            "firmware",
            None,
            &json!({ "ok": r.is_ok() }),
        )
        .await;
    match r {
        Ok(v) => Json(v).into_response(),
        Err(e) => {
            let _ = std::fs::remove_file(&path);
            err(e)
        }
    }
}

/// POST /api/system/firmware/install (admins): stage the checked upload (settings are kept) and restart the box
/// to install it. The answer comes before the restart.
pub async fn firmware_install(State(state): State<AppState>, admin: AdminUser) -> Response {
    match state
        .system
        .system_op("firmware_stage", serde_json::Value::Null)
        .await
    {
        Ok(v) => {
            let _ = state
                .config_store
                .audit(
                    &admin.session.username,
                    "install",
                    "firmware",
                    v.get("staged").and_then(|s| s.as_str()),
                    &v,
                )
                .await;
            let st = state.clone();
            tokio::spawn(async move {
                tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                if let Err(e) = st.system.system_op("reboot", serde_json::Value::Null).await {
                    tracing::error!("firmware install: restart failed: {e}");
                }
            });
            (StatusCode::ACCEPTED, Json(v)).into_response()
        }
        Err(e) => err(e),
    }
}

/// DELETE /api/system/firmware (admins): drop the uploaded and any staged image.
pub async fn firmware_discard(State(state): State<AppState>, _admin: AdminUser) -> Response {
    match state
        .system
        .system_op("firmware_discard", serde_json::Value::Null)
        .await
    {
        Ok(v) => Json(v).into_response(),
        Err(e) => err(e),
    }
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
    if crate::auth::confirm_password(&state, &admin.session.username, &req.password)
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
/// POST /api/system/capture -- packet capture for diagnostics (admins).
/// Body: `{"interface":"rtr-lan","host":"192.168.50.10","proto":"tcp",
/// "port":443,"count":50,"seconds":10}` (only `interface` is required; at
/// most 500 packets / 30 s). Answers the decoded one-line packet summaries.
async fn capture(
    State(state): State<AppState>,
    _admin: AdminUser,
    Json(req): Json<serde_json::Value>,
) -> Response {
    match state.system.system_op("capture", req).await {
        Ok(v) => Json(v).into_response(),
        Err(e) => {
            let m = e.to_string();
            let code = if m.contains("Invalid") {
                StatusCode::BAD_REQUEST
            } else if m.contains("not installed") {
                StatusCode::NOT_IMPLEMENTED
            } else {
                StatusCode::INTERNAL_SERVER_ERROR
            };
            error(code, m)
        }
    }
}

/// GET /api/system/speedtest -- settings, whether a test runs now, the
/// newest results.
async fn get_speedtest(State(state): State<AppState>) -> Response {
    use crate::state::speedtest;
    let store = &state.config_store;
    match (
        speedtest::settings(store).await,
        speedtest::history(store, 50).await,
    ) {
        (Ok(s), Ok(h)) => {
            Json(json!({"settings": s, "running": speedtest::running(), "results": h}))
                .into_response()
        }
        (Err(e), _) | (_, Err(e)) => err(e),
    }
}

/// POST /api/system/speedtest -- run a test now (admins; takes up to ~1 min).
async fn run_speedtest(State(state): State<AppState>, _admin: AdminUser) -> Response {
    match crate::state::speedtest::run(&state.config_store, "manual").await {
        Ok(r) => Json(r).into_response(),
        Err(e) if e.to_string().contains("already running") => {
            error(StatusCode::CONFLICT, e.to_string())
        }
        Err(e) => err(e),
    }
}

/// PUT /api/system/speedtest/settings -- `{"down_url","up_url","bytes_down",
/// "bytes_up","interval_hours"}` (admins).
async fn put_speedtest(
    State(state): State<AppState>,
    _admin: AdminUser,
    Json(i): Json<crate::state::speedtest::SettingsInput>,
) -> Response {
    match crate::state::speedtest::save_settings(&state.config_store, &i).await {
        Ok(s) => Json(s).into_response(),
        Err(e) => err(e),
    }
}

#[derive(Deserialize)]
struct HistoryQuery {
    hours: Option<i64>,
}

/// GET /api/stats/history?hours=24 -- CPU / memory (percent) and per-
/// interface throughput (bit/s) as 5-minute averages.
async fn stats_history(
    State(state): State<AppState>,
    axum::extract::Query(q): axum::extract::Query<HistoryQuery>,
) -> Response {
    use crate::state::stats;
    let hours = q.hours.unwrap_or(24).clamp(1, 24 * 400);
    let since = chrono::Utc::now().timestamp() - hours * 3600;
    let store = &state.config_store;
    let names = match stats::metrics(store, since).await {
        Ok(n) => n,
        Err(e) => return err(e),
    };
    let mut out = serde_json::Map::new();
    for m in names {
        match stats::series(store, &m, since).await {
            Ok(p) => {
                out.insert(m, json!(p));
            }
            Err(e) => return err(e),
        }
    }
    Json(json!({"hours": hours, "metrics": out})).into_response()
}

#[derive(Deserialize)]
struct UsageQuery {
    months: Option<usize>,
}

/// GET /api/stats/usage?months=3 -- per-interface traffic per accounting
/// month (newest first) and the data-cap settings.
async fn stats_usage(
    State(state): State<AppState>,
    axum::extract::Query(q): axum::extract::Query<UsageQuery>,
) -> Response {
    use crate::state::stats;
    let store = &state.config_store;
    match (
        stats::periods(store, q.months.unwrap_or(3).clamp(1, 24)).await,
        stats::settings(store).await,
    ) {
        (Ok(p), Ok(s)) => Json(json!({"periods": p, "settings": s})).into_response(),
        (Err(e), _) | (_, Err(e)) => err(e),
    }
}

/// PUT /api/stats/settings -- `{"month_start_day","cap_gb","cap_interface",
/// "retention_days"}` (admins).
async fn put_stats_settings(
    State(state): State<AppState>,
    _admin: AdminUser,
    Json(i): Json<crate::state::stats::SettingsInput>,
) -> Response {
    match crate::state::stats::save_settings(&state.config_store, &i).await {
        Ok(s) => Json(s).into_response(),
        Err(e) => err(e),
    }
}

/// POST /api/system/diag -- ping, traceroute, DNS lookup, neighbour
/// table, routing tables, listening sockets (admins). Body:
/// `{"tool":"ping","target":"192.0.2.1","count":3,"family":"auto","interface":""}`,
/// `{"tool":"traceroute","target":"example.com","max_hops":15}`,
/// `{"tool":"dns","name":"example.com","type":"AAAA","server":""}`,
/// `{"tool":"neighbors"|"routes"|"sockets"}`. Every field is validated
/// (patronus_network::diag); nothing reaches a shell.
async fn diag(
    State(state): State<AppState>,
    _admin: AdminUser,
    Json(req): Json<serde_json::Value>,
) -> Response {
    match state.system.system_op("diag", req).await {
        Ok(v) => Json(v).into_response(),
        Err(e) => {
            let m = e.to_string();
            let code = if m.contains("Invalid") {
                StatusCode::BAD_REQUEST
            } else if m.contains("not installed") {
                StatusCode::NOT_IMPLEMENTED
            } else if m.contains("no answer from") {
                StatusCode::GATEWAY_TIMEOUT
            } else {
                StatusCode::INTERNAL_SERVER_ERROR
            };
            error(code, m)
        }
    }
}

/// GET /api/system/packet-steering
async fn get_packet_steering(State(state): State<AppState>) -> Response {
    let on = state
        .firewall
        .store
        .load_system_config(patronus_network::sysctl::PACKET_STEERING_KEY)
        .await
        .ok()
        .flatten()
        .is_some_and(|v| v.trim() == "1");
    Json(serde_json::json!({ "enabled": on })).into_response()
}

#[derive(Deserialize)]
struct PacketSteeringBody {
    enabled: bool,
}

/// PUT /api/system/packet-steering {"enabled": true}: spread NIC queues
/// over all CPUs (RPS/XPS), applied now and at every boot.
async fn put_packet_steering(
    State(state): State<AppState>,
    _admin: AdminUser,
    Json(b): Json<PacketSteeringBody>,
) -> Response {
    let store = &state.firewall.store;
    let key = patronus_network::sysctl::PACKET_STEERING_KEY;
    if let Err(e) = store
        .save_system_config(key, if b.enabled { "1" } else { "0" })
        .await
    {
        return error(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to save: {e}"),
        );
    }
    let a = patronus_network::applyd::RemoteApplier::wrap(std::sync::Arc::new(
        patronus_network::SysctlApplier::default(),
    ));
    match a.apply(store).await {
        Ok(_) => Json(serde_json::json!({ "message": "Packet steering updated" })).into_response(),
        Err(e) => error(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Saved, but applying failed: {e}"),
        ),
    }
}

pub fn router() -> axum::Router<AppState> {
    use axum::routing::{get, post, put};
    axum::Router::new()
        .route(
            "/system/packet-steering",
            get(get_packet_steering).put(put_packet_steering),
        )
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
        .route("/system/history", get(list_history))
        .route("/system/history/:id/restore", post(restore_history))
        .route("/system/history/:id/diff", get(history_diff))
        .route("/system/updates", get(list_updates))
        .route("/system/updates/check", post(check_updates))
        .route("/system/updates/apply", post(apply_updates))
        .route("/system/factory-reset", post(factory_reset))
        .route("/system/capture", post(capture))
        .route("/system/diag", post(diag))
        .route("/system/speedtest", get(get_speedtest).post(run_speedtest))
        .route("/stats/history", get(stats_history))
        .route("/stats/usage", get(stats_usage))
        .route("/stats/settings", axum::routing::put(put_stats_settings))
        .route(
            "/system/speedtest/settings",
            axum::routing::put(put_speedtest),
        )
        .route("/system/general", get(get_general).put(put_general))
        .route("/system/ssh", get(get_ssh).put(put_ssh))
        .route("/system/web", get(get_web).put(put_web))
        .route("/system/ports", get(get_ports).put(put_ports))
        .route("/system/reboot", post(reboot))
        .route(
            "/system/firmware",
            get(firmware_status)
                .post(firmware_upload)
                .delete(firmware_discard)
                .layer(axum::extract::DefaultBodyLimit::max(MAX_FIRMWARE)),
        )
        .route("/system/firmware/install", post(firmware_install))
        .route(
            "/system/firmware/boot-guard",
            axum::routing::put(firmware_guard_put),
        )
        .route("/system/firmware/rollback", post(firmware_rollback))
        .route("/system/firmware/confirm", post(firmware_confirm))
        .route("/system/shutdown", post(shutdown))
        .route("/system/services", get(list_services))
        .route("/system/services/:name/start", post(start_service))
        .route("/system/services/:name/stop", post(stop_service))
        .route("/system/services/:name/restart", post(restart_service))
}
