//! External authentication servers for the web login (lane H): RADIUS.
//! Admin sessions only; the shared secret is never returned.

use crate::auth::AdminUser;
use crate::radius;
use crate::state::AppState;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Deserialize;
use serde_json::json;

fn error(code: StatusCode, msg: impl Into<String>) -> Response {
    (code, Json(json!({ "error": msg.into() }))).into_response()
}

/// GET /api/system/auth-servers
pub async fn list(State(state): State<AppState>, _a: AdminUser) -> Response {
    match radius::servers(&state.config_store).await {
        Ok(v) => Json(v).into_response(),
        Err(e) => error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}

#[derive(Deserialize)]
pub struct ServerInput {
    pub name: String,
    pub host: String,
    #[serde(default)]
    pub port: Option<u16>,
    /// radius (default) | ldap
    #[serde(default)]
    pub kind: Option<String>,
    /// RADIUS shared secret
    #[serde(default)]
    pub secret: String,
    /// LDAP: search start, search account, its password, user filter, TLS
    /// mode (none | starttls | ldaps) and the group whose members are operators
    #[serde(default)]
    pub base_dn: String,
    #[serde(default)]
    pub bind_dn: String,
    #[serde(default)]
    pub bind_password: String,
    #[serde(default)]
    pub user_filter: Option<String>,
    #[serde(default)]
    pub tls: Option<String>,
    #[serde(default)]
    pub operator_group: String,
    #[serde(default)]
    pub default_role: Option<String>,
    #[serde(default)]
    pub timeout_secs: Option<u32>,
}

/// POST /api/system/auth-servers
pub async fn create(
    State(state): State<AppState>,
    _a: AdminUser,
    Json(i): Json<ServerInput>,
) -> Response {
    let res = match i.kind.as_deref().unwrap_or("radius") {
        "radius" => {
            radius::add_server(
                &state.config_store,
                &i.name,
                &i.host,
                i.port,
                &i.secret,
                i.default_role.as_deref(),
                i.timeout_secs,
            )
            .await
        }
        "ldap" => {
            radius::add_ldap_server(
                &state.config_store,
                &radius::LdapInput {
                    name: i.name.clone(),
                    host: i.host.clone(),
                    port: i.port,
                    base_dn: i.base_dn.clone(),
                    bind_dn: i.bind_dn.clone(),
                    bind_password: i.bind_password.clone(),
                    user_filter: i.user_filter.clone(),
                    tls: i.tls.clone(),
                    operator_group: i.operator_group.clone(),
                    default_role: i.default_role.clone(),
                    timeout_secs: i.timeout_secs,
                },
            )
            .await
        }
        other => Err(anyhow::anyhow!("Invalid kind {other:?}: radius or ldap")),
    };
    match res {
        Ok(id) => (StatusCode::CREATED, Json(json!({"id": id}))).into_response(),
        Err(e) if e.to_string().starts_with("Invalid") => {
            error(StatusCode::BAD_REQUEST, e.to_string())
        }
        Err(e) => error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}

/// DELETE /api/system/auth-servers/:id
pub async fn remove(State(state): State<AppState>, _a: AdminUser, Path(id): Path<i64>) -> Response {
    match radius::delete_server(&state.config_store, id).await {
        Ok(true) => Json(json!({"ok": true})).into_response(),
        Ok(false) => error(StatusCode::NOT_FOUND, "no such server"),
        Err(e) => error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}

pub fn router() -> axum::Router<AppState> {
    use axum::routing::{delete, get};
    axum::Router::new()
        .route("/system/auth-servers", get(list).post(create))
        .route("/system/auth-servers/:id", delete(remove))
}
