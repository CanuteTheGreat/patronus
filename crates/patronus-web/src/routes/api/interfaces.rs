//! Interfaces & L2 API (lane C). Mounted under `/api` by
//! `routes::api_routes` with one `.merge(interfaces::router())` line; the
//! `/interfaces` page is registered in `routes::build_router`.
//!
//! Errors: "Invalid ..." -> 400, anti-lockout refusals -> 409 (re-submit
//! with `"force": true`), apply failures -> 500 (the previous configuration
//! has been restored and re-applied by then).

use crate::state::interfaces::{
    BondBody, BridgeBody, InterfaceUpdate, PppoeBody, VlanBody, LOCKOUT,
};
use crate::state::AppState;
use axum::{
    extract::{ConnectInfo, Path, State},
    http::StatusCode,
    response::{Html, IntoResponse, Response},
    Json,
};
use serde::Deserialize;
use std::net::{IpAddr, SocketAddr};

fn client(ci: Option<ConnectInfo<SocketAddr>>) -> Option<IpAddr> {
    ci.map(|ConnectInfo(a)| a.ip())
}

fn result(r: anyhow::Result<patronus_config::ApplyReport>) -> Response {
    match r {
        Ok(rep) => Json(serde_json::json!({
            "message": "applied",
            "applied": rep.applied,
            "warnings": rep.warnings,
        }))
        .into_response(),
        Err(e) => {
            let msg = e.to_string();
            let status = if msg.starts_with(LOCKOUT) {
                StatusCode::CONFLICT
            } else if msg.contains("Invalid ") {
                StatusCode::BAD_REQUEST
            } else {
                tracing::error!("interfaces: {msg}");
                StatusCode::INTERNAL_SERVER_ERROR
            };
            (
                status,
                Json(serde_json::json!({
                    "error": msg,
                    "lockout": status == StatusCode::CONFLICT,
                })),
            )
                .into_response()
        }
    }
}

/// GET /api/interfaces
pub async fn overview(
    State(state): State<AppState>,
    ci: Option<ConnectInfo<SocketAddr>>,
) -> Response {
    match state.interfaces.overview(client(ci)).await {
        Ok(v) => Json(v).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

/// PUT /api/interfaces/:name
pub async fn update(
    State(state): State<AppState>,
    Path(name): Path<String>,
    ci: Option<ConnectInfo<SocketAddr>>,
    Json(u): Json<InterfaceUpdate>,
) -> Response {
    result(
        state
            .interfaces
            .update_interface(&name, u, client(ci))
            .await,
    )
}

#[derive(Debug, Deserialize, Default)]
#[serde(default)]
pub struct Force {
    pub force: bool,
}

/// POST /api/interfaces/:name/up  (also /api/network/interfaces/:name/up)
pub async fn up(
    State(state): State<AppState>,
    Path(name): Path<String>,
    ci: Option<ConnectInfo<SocketAddr>>,
    body: Option<Json<Force>>,
) -> Response {
    let f = body.map(|b| b.0.force).unwrap_or(false);
    result(
        state
            .interfaces
            .set_enabled(&name, true, client(ci), f)
            .await,
    )
}

/// POST /api/interfaces/:name/down
pub async fn down(
    State(state): State<AppState>,
    Path(name): Path<String>,
    ci: Option<ConnectInfo<SocketAddr>>,
    body: Option<Json<Force>>,
) -> Response {
    let f = body.map(|b| b.0.force).unwrap_or(false);
    result(
        state
            .interfaces
            .set_enabled(&name, false, client(ci), f)
            .await,
    )
}

/// POST /api/interfaces/vlans
pub async fn add_vlan(
    State(state): State<AppState>,
    ci: Option<ConnectInfo<SocketAddr>>,
    Json(b): Json<VlanBody>,
) -> Response {
    result(state.interfaces.upsert_vlan(b, client(ci)).await)
}

/// POST /api/interfaces/bonds
pub async fn add_bond(
    State(state): State<AppState>,
    ci: Option<ConnectInfo<SocketAddr>>,
    Json(b): Json<BondBody>,
) -> Response {
    result(state.interfaces.upsert_bond(b, client(ci)).await)
}

/// POST /api/interfaces/bridges
pub async fn add_bridge(
    State(state): State<AppState>,
    ci: Option<ConnectInfo<SocketAddr>>,
    Json(b): Json<BridgeBody>,
) -> Response {
    result(state.interfaces.upsert_bridge(b, client(ci)).await)
}

/// POST /api/interfaces/pppoe
pub async fn add_pppoe(
    State(state): State<AppState>,
    ci: Option<ConnectInfo<SocketAddr>>,
    Json(b): Json<PppoeBody>,
) -> Response {
    result(state.interfaces.upsert_pppoe(b, client(ci)).await)
}

async fn delete_virtual(
    kind: &str,
    state: AppState,
    name: String,
    ci: Option<ConnectInfo<SocketAddr>>,
    body: Option<Json<Force>>,
) -> Response {
    let f = body.map(|b| b.0.force).unwrap_or(false);
    result(
        state
            .interfaces
            .delete_virtual(kind, &name, client(ci), f)
            .await,
    )
}

macro_rules! delete_handler {
    ($fn:ident, $kind:literal) => {
        #[doc = concat!("DELETE /api/interfaces/", $kind, "/:name")]
        pub async fn $fn(
            State(state): State<AppState>,
            Path(name): Path<String>,
            ci: Option<ConnectInfo<SocketAddr>>,
            body: Option<Json<Force>>,
        ) -> Response {
            delete_virtual($kind, state, name, ci, body).await
        }
    };
}
delete_handler!(delete_vlan, "vlans");
delete_handler!(delete_bond, "bonds");
delete_handler!(delete_bridge, "bridges");
delete_handler!(delete_pppoe, "pppoe");

/// POST /api/interfaces/apply  (re-apply the stored configuration)
pub async fn apply(State(state): State<AppState>) -> Response {
    result(state.interfaces.apply().await)
}

#[derive(Debug, Deserialize)]
pub struct DhcpClientBody {
    pub client: String,
}

/// PUT /api/interfaces/dhcp-client  {"client": "dhcpcd"|"udhcpc"|""}
pub async fn set_dhcp_client(
    State(state): State<AppState>,
    Json(b): Json<DhcpClientBody>,
) -> Response {
    result(state.interfaces.set_dhcp_client(&b.client).await)
}

/// GET /api/network/interfaces (kernel list, legacy shape)
pub async fn legacy_list(State(state): State<AppState>) -> Response {
    match state.interfaces.list_template().await {
        Ok(v) => Json(v).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

/// GET /interfaces (the page; data comes from /api/interfaces)
pub async fn page() -> Response {
    use askama::Template;
    match crate::templates::InterfacesTemplate.render() {
        Ok(h) => Html(h).into_response(),
        Err(e) => {
            tracing::error!("render interfaces page: {e}");
            (StatusCode::INTERNAL_SERVER_ERROR, "Failed to render page").into_response()
        }
    }
}

/// This lane's API routes.
pub fn router() -> axum::Router<AppState> {
    use axum::routing::{delete, get, post, put};
    axum::Router::new()
        .route("/interfaces", get(overview))
        .route("/interfaces/apply", post(apply))
        .route("/interfaces/dhcp-client", put(set_dhcp_client))
        .route("/interfaces/vlans", post(add_vlan))
        .route("/interfaces/vlans/:name", delete(delete_vlan))
        .route("/interfaces/bonds", post(add_bond))
        .route("/interfaces/bonds/:name", delete(delete_bond))
        .route("/interfaces/bridges", post(add_bridge))
        .route("/interfaces/bridges/:name", delete(delete_bridge))
        .route("/interfaces/pppoe", post(add_pppoe))
        .route("/interfaces/pppoe/:name", delete(delete_pppoe))
        .route("/interfaces/:name", put(update))
        .route("/interfaces/:name/up", post(up))
        .route("/interfaces/:name/down", post(down))
        // legacy paths used by the network page / older clients
        .route("/network/interfaces", get(legacy_list))
        .route("/network/interfaces/:name", put(update))
        .route("/network/interfaces/:name/up", post(up))
        .route("/network/interfaces/:name/down", post(down))
}
