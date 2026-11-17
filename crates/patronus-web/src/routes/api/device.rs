//! Device page of the router tier (`/device`, `/api/device/*`): SSH keys of the login accounts, LEDs, the
//! scheduled restart, this unit's own address (access point) and the online firmware check (`/api/system/firmware/feed*`).
//!
//! Everything runs as root through `patronus_network::apdev` (in-process when the web UI is root, else through
//! `patronus applyd`). Changes are admin-only and audited; reads are open to every signed-in user except the key
//! list, which only admins see.

use crate::auth::AdminUser;
use crate::state::AppState;
use askama::Template;
use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{delete, get, post},
    Json, Router,
};
use serde_json::{json, Value};

fn error(code: StatusCode, m: impl Into<String>) -> Response {
    (code, Json(json!({ "error": m.into() }))).into_response()
}

fn op_err(e: anyhow::Error) -> Response {
    let m = e.to_string();
    let code = if m.contains("Invalid") {
        StatusCode::BAD_REQUEST
    } else {
        StatusCode::INTERNAL_SERVER_ERROR
    };
    error(code, m)
}

async fn op(state: &AppState, name: &str, p: Value) -> Response {
    match state.system.system_op(name, p).await {
        Ok(v) => Json(v).into_response(),
        Err(e) => op_err(e),
    }
}

/// Run an admin change and audit it (`what` without secrets).
/// What the audit log records for a change: action, object, object id, details (no secrets).
struct Audit<'a>(&'a str, &'a str, Option<&'a str>, &'a Value);

async fn change(
    state: &AppState,
    admin: &AdminUser,
    name: &str,
    p: Value,
    a: Audit<'_>,
) -> Response {
    let Audit(action, object, id, what) = a;
    match state.system.system_op(name, p).await {
        Ok(v) => {
            let _ = state
                .config_store
                .audit(&admin.session.username, action, object, id, what)
                .await;
            Json(v).into_response()
        }
        Err(e) => {
            let _ = state
                .config_store
                .audit(
                    &admin.session.username,
                    &format!("{action}-refused"),
                    object,
                    id,
                    &json!({ "request": what, "error": e.to_string() }),
                )
                .await;
            op_err(e)
        }
    }
}

#[derive(Template)]
#[template(path = "device.html")]
pub struct DeviceTemplate {
    pub page: &'static str,
    pub can_modify: bool,
    pub ap_mode: bool,
}

pub async fn page(me: crate::auth::AuthUser) -> Response {
    crate::routes::pages::render(
        &DeviceTemplate {
            page: "device",
            can_modify: me.session.role.is_admin(),
            ap_mode: crate::routes::api::wifi::role() == crate::routes::api::setup::DeviceRole::Ap,
        },
        "device",
    )
}

// ---- LEDs ------------------------------------------------------------------

pub async fn leds_get(State(s): State<AppState>) -> Response {
    op(&s, "leds_get", Value::Null).await
}

pub async fn leds_put(
    State(s): State<AppState>,
    admin: AdminUser,
    Json(b): Json<Value>,
) -> Response {
    let on = match b.get("on").and_then(Value::as_bool) {
        Some(v) => v,
        None => return error(StatusCode::BAD_REQUEST, "Invalid: {\"on\": true|false}"),
    };
    change(
        &s,
        &admin,
        "leds_set",
        json!({ "on": on }),
        Audit("update", "leds", None, &json!({ "on": on })),
    )
    .await
}

// ---- scheduled restart -----------------------------------------------------

pub async fn restart_get(State(s): State<AppState>) -> Response {
    op(&s, "restart_schedule_get", Value::Null).await
}

pub async fn restart_put(
    State(s): State<AppState>,
    admin: AdminUser,
    Json(b): Json<Value>,
) -> Response {
    change(
        &s,
        &admin,
        "restart_schedule_set",
        b.clone(),
        Audit("update", "restart_schedule", None, &b),
    )
    .await
}

// ---- SSH keys ----------------------------------------------------------------

pub async fn keys_get(State(s): State<AppState>, _admin: AdminUser) -> Response {
    op(&s, "ssh_keys_get", Value::Null).await
}

pub async fn keys_add(
    State(s): State<AppState>,
    admin: AdminUser,
    Json(b): Json<Value>,
) -> Response {
    let user = b
        .get("user")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let key = b
        .get("key")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    // the audit records the key's type and comment, never more than that
    let kind = key.split_whitespace().next().unwrap_or("").to_string();
    change(
        &s,
        &admin,
        "ssh_keys_add",
        json!({ "user": user, "key": key }),
        Audit(
            "add",
            "ssh_key",
            Some(&user),
            &json!({ "user": user, "type": kind }),
        ),
    )
    .await
}

pub async fn keys_delete(
    State(s): State<AppState>,
    admin: AdminUser,
    Path((user, fp)): Path<(String, String)>,
) -> Response {
    change(
        &s,
        &admin,
        "ssh_keys_delete",
        json!({ "user": user, "fingerprint": fp }),
        Audit(
            "delete",
            "ssh_key",
            Some(&user),
            &json!({ "user": user, "fingerprint": fp }),
        ),
    )
    .await
}

// ---- this unit's address ---------------------------------------------------

pub async fn address_get(State(s): State<AppState>) -> Response {
    op(&s, "ap_address_get", Value::Null).await
}

pub async fn address_put(
    State(s): State<AppState>,
    admin: AdminUser,
    Json(b): Json<Value>,
) -> Response {
    change(
        &s,
        &admin,
        "ap_address_set",
        b.clone(),
        Audit("update", "ap_address", None, &b),
    )
    .await
}

/// POST /api/device/address/confirm: keep the new address. Only counts when this request reached the unit over one
/// of the NEW addresses (the Host header), which is the proof that the new address works.
pub async fn address_confirm(
    State(s): State<AppState>,
    admin: AdminUser,
    headers: HeaderMap,
) -> Response {
    let host = headers
        .get(axum::http::header::HOST)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("")
        .to_string();
    change(
        &s,
        &admin,
        "ap_address_confirm",
        json!({ "host": host }),
        Audit("confirm", "ap_address", None, &json!({ "host": host })),
    )
    .await
}

// ---- online firmware check ---------------------------------------------------

pub async fn feed_get(State(s): State<AppState>) -> Response {
    op(&s, "firmware_feed_get", Value::Null).await
}

pub async fn feed_put(
    State(s): State<AppState>,
    admin: AdminUser,
    Json(b): Json<Value>,
) -> Response {
    let feed = b
        .get("feed")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    change(
        &s,
        &admin,
        "firmware_feed_set",
        json!({ "feed": feed }),
        Audit("update", "firmware_feed", None, &json!({ "feed": feed })),
    )
    .await
}

/// POST /api/system/firmware/feed/check: is there a newer signed build? Nothing is downloaded or installed.
pub async fn feed_check(State(s): State<AppState>, _admin: AdminUser) -> Response {
    op(&s, "firmware_feed_check", Value::Null).await
}

/// POST /api/system/firmware/feed/download: fetch the signed feed's image into the upload slot and run the same
/// `patronus-flash check` as an upload. Installing stays the separate Install button.
pub async fn feed_download(State(s): State<AppState>, admin: AdminUser) -> Response {
    change(
        &s,
        &admin,
        "firmware_feed_download",
        Value::Null,
        Audit("download", "firmware", None, &Value::Null),
    )
    .await
}

pub fn pages() -> Router<AppState> {
    Router::new().route("/device", get(page))
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/device/leds", get(leds_get).put(leds_put))
        .route(
            "/device/restart-schedule",
            get(restart_get).put(restart_put),
        )
        .route("/device/ssh-keys", get(keys_get).post(keys_add))
        .route("/device/ssh-keys/:user/:fingerprint", delete(keys_delete))
        .route("/device/address", get(address_get).put(address_put))
        .route("/device/address/confirm", post(address_confirm))
        .route("/system/firmware/feed", get(feed_get).put(feed_put))
        .route("/system/firmware/feed/check", post(feed_check))
        .route("/system/firmware/feed/download", post(feed_download))
}
