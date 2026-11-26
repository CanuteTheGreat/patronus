//! Boot environments page and API (System > Boot environments): the ZFS boot environments and snapshots of a standard-tier
//! install, through `horcrux-be` as root (`patronus_network::bootenv`, sysops `be_list` / `be_op` via applyd).
//!
//! - `GET  /boot-environments`                 the page
//! - `GET  /api/system/boot-environments`      `horcrux-be list --json` + `available`
//! - `POST /api/system/boot-environments/:op`  {"name": "..."}: activate | destroy | snapshot | rollback | pin | unpin |
//!   destroy-snapshot (admin, audited)

use crate::state::AppState;
use askama::Template;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{Html, IntoResponse, Response},
    Json,
};
use serde_json::{json, Value};

#[derive(Template)]
#[template(path = "bootenv.html")]
pub struct BootEnvTemplate {
    pub page: &'static str,
    pub is_admin: bool,
}

pub async fn page(me: crate::auth::AuthUser) -> Response {
    match (BootEnvTemplate {
        page: "system",
        is_admin: me.session.role.is_admin(),
    })
    .render()
    {
        Ok(h) => Html(h.replace("@PATRONUS_VERSION@", env!("CARGO_PKG_VERSION"))).into_response(),
        Err(e) => {
            tracing::error!("render boot environments: {e}");
            (StatusCode::INTERNAL_SERVER_ERROR, "Failed to render page").into_response()
        }
    }
}

fn error(code: StatusCode, m: impl Into<String>) -> Response {
    (code, Json(json!({ "error": m.into() }))).into_response()
}

pub async fn list(State(s): State<AppState>, _me: crate::auth::AuthUser) -> Response {
    match s.system.system_op("be_list", Value::Null).await {
        Ok(v) => Json(v).into_response(),
        Err(e) => error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}

pub async fn run_op(
    State(s): State<AppState>,
    admin: crate::auth::AdminUser,
    Path(op): Path<String>,
    body: Option<Json<Value>>,
) -> Response {
    let name = body
        .as_ref()
        .and_then(|Json(b)| b.get("name"))
        .and_then(Value::as_str)
        .map(str::to_string);
    // validated here too, so a bad request never reaches the root helper
    if let Err(e) = patronus_network::bootenv::op_argv(&op, name.as_deref()) {
        return error(StatusCode::BAD_REQUEST, e.to_string());
    }
    match s
        .system
        .system_op("be_op", json!({ "op": op, "name": name }))
        .await
    {
        Ok(v) => {
            let _ = s
                .config_store
                .audit(
                    &admin.session.username,
                    &op,
                    "boot_environment",
                    name.as_deref(),
                    &json!({ "op": op, "name": name }),
                )
                .await;
            Json(v).into_response()
        }
        Err(e) => {
            let m = e.to_string();
            let code = if m.contains("Invalid") {
                StatusCode::BAD_REQUEST
            } else {
                StatusCode::CONFLICT
            };
            error(code, m)
        }
    }
}

pub fn router() -> axum::Router<AppState> {
    use axum::routing::{get, post};
    axum::Router::new()
        .route("/system/boot-environments", get(list))
        .route("/system/boot-environments/:op", post(run_op))
}

pub fn pages() -> axum::Router<AppState> {
    use axum::routing::get;
    axum::Router::new().route("/boot-environments", get(page))
}
