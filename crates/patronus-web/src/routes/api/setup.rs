//! First-boot setup wizard (`/setup`, `/api/setup/*`). One guided pass over
//! the settings a new router needs: which port is WAN and which is LAN, how
//! the WAN gets its address, the LAN address, and a DHCP pool for LAN
//! clients. It drives the same managers as the Interfaces and DHCP pages
//! (store -> applier -> kernel/daemon), so the result is persisted and
//! survives reboot; it adds only the "wizard completed" marker.

use crate::state::interfaces::InterfaceUpdate;
use crate::state::AppState;
use askama::Template;
use axum::{
    extract::{ConnectInfo, State},
    http::StatusCode,
    response::{Html, IntoResponse, Response},
    Json,
};
use serde::Deserialize;
use serde_json::json;
use std::net::SocketAddr;

const DONE_KEY: &str = "setup.completed";

#[derive(Template)]
#[template(path = "setup.html")]
pub struct SetupTemplate {
    pub page: &'static str,
    pub can_modify: bool,
}

pub async fn page(me: crate::auth::AuthUser) -> Response {
    match (SetupTemplate {
        page: "setup",
        can_modify: me.session.role.can_modify(),
    })
    .render()
    {
        Ok(h) => Html(h).into_response(),
        Err(e) => {
            tracing::error!("render setup: {e}");
            (StatusCode::INTERNAL_SERVER_ERROR, "Failed to render page").into_response()
        }
    }
}

fn error(code: StatusCode, m: impl Into<String>) -> Response {
    (code, Json(json!({ "error": m.into() }))).into_response()
}

async fn completed(state: &AppState) -> bool {
    patronus_network::lan::get_setting(&state.config_store, DONE_KEY)
        .await
        .ok()
        .flatten()
        .is_some_and(|v| v == "1")
}

/// GET /api/setup/status -> {completed, interfaces: [{name, role, up, addresses}]}
pub async fn status(State(state): State<AppState>) -> Response {
    let ov = match state.interfaces.overview(None).await {
        Ok(v) => v,
        Err(e) => return error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    };
    let ifs: Vec<_> = ov["devices"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter(|d| {
            matches!(
                d["kind"].as_str(),
                Some("ethernet") | Some("wlan") | Some("veth") | None
            )
                && d["master"].is_null()
        })
        .map(|d| {
            json!({
                "name": d["name"],
                "up": d["up"],
                "mac": d["mac"],
                "role": d["config"]["role"],
                "addresses": d["addresses"],
            })
        })
        .collect();
    Json(json!({ "completed": completed(&state).await, "interfaces": ifs })).into_response()
}

#[derive(Debug, Deserialize)]
pub struct SetupBody {
    pub wan_interface: String,
    /// `dhcp` (default) or `static`
    #[serde(default)]
    pub wan_mode: Option<String>,
    #[serde(default)]
    pub wan_ipv4: Option<String>,
    #[serde(default)]
    pub wan_gateway: Option<String>,
    pub lan_interface: String,
    /// CIDR, e.g. 192.168.1.1/24
    pub lan_ipv4: String,
    #[serde(default)]
    pub dhcp: bool,
    #[serde(default)]
    pub dhcp_start: Option<String>,
    #[serde(default)]
    pub dhcp_end: Option<String>,
    #[serde(default)]
    pub dns_servers: Option<String>,
    #[serde(default)]
    pub force: bool,
}

/// POST /api/setup/apply
pub async fn apply(
    State(state): State<AppState>,
    ci: Option<ConnectInfo<SocketAddr>>,
    _admin: crate::auth::AdminUser,
    Json(b): Json<SetupBody>,
) -> Response {
    if b.wan_interface == b.lan_interface {
        return error(
            StatusCode::BAD_REQUEST,
            "Invalid setup: WAN and LAN need different interfaces",
        );
    }
    let client = ci.map(|ConnectInfo(a)| a.ip());
    let static_wan = b.wan_mode.as_deref() == Some("static");
    let wan = InterfaceUpdate {
        role: Some("wan".into()),
        ipv4_mode: if static_wan { "static" } else { "dhcp" }.into(),
        ipv4: b.wan_ipv4.iter().cloned().collect(),
        gateway4: b.wan_gateway.clone().filter(|g| !g.is_empty()),
        ipv6_mode: "none".into(),
        force: b.force,
        ..Default::default()
    };
    let lan = InterfaceUpdate {
        role: Some("lan".into()),
        ipv4_mode: "static".into(),
        ipv4: vec![b.lan_ipv4.clone()],
        ipv6_mode: "none".into(),
        force: b.force,
        ..Default::default()
    };
    let mut applied = Vec::new();
    for (name, u) in [(&b.lan_interface, lan), (&b.wan_interface, wan)] {
        match state.interfaces.update_interface(name, u, client).await {
            Ok(r) => applied.extend(r.applied),
            Err(e) => {
                let m = e.to_string();
                let code = if m.starts_with(crate::state::interfaces::LOCKOUT) {
                    StatusCode::CONFLICT
                } else if m.contains("Invalid") {
                    StatusCode::BAD_REQUEST
                } else {
                    StatusCode::INTERNAL_SERVER_ERROR
                };
                return error(code, format!("{name}: {m}"));
            }
        }
    }
    #[cfg(feature = "dhcp")]
    if b.dhcp {
        let (Some(s), Some(e)) = (b.dhcp_start.clone(), b.dhcp_end.clone()) else {
            return error(
                StatusCode::BAD_REQUEST,
                "Invalid setup: the DHCP pool needs a start and an end address",
            );
        };
        let lan_ip = b.lan_ipv4.split('/').next().unwrap_or("").to_string();
        let pool = patronus_network::dhcp::PoolInput {
            interface: b.lan_interface.clone(),
            enabled: true,
            range_start: s,
            range_end: e,
            gateway: Some(lan_ip.clone()),
            dns_servers: b
                .dns_servers
                .clone()
                .filter(|d| !d.is_empty())
                .or(Some(lan_ip)),
            description: Some("created by the setup wizard".into()),
            ..Default::default()
        };
        if let Err(e) = state.lan.save_pool(None, pool).await {
            let m = e.to_string();
            let code = if m.contains("Invalid") {
                StatusCode::BAD_REQUEST
            } else {
                StatusCode::INTERNAL_SERVER_ERROR
            };
            return error(code, format!("DHCP pool: {m}"));
        }
        applied.push("dhcp".into());
    }
    #[cfg(not(feature = "dhcp"))]
    if b.dhcp {
        return error(
            StatusCode::NOT_IMPLEMENTED,
            "this build has no DHCP server (USE=dhcp)",
        );
    }
    let _ = patronus_network::lan::set_setting(&state.config_store, DONE_KEY, "1").await;
    let _ = state
        .config_store
        .audit(
            "web",
            "apply",
            "setup-wizard",
            None,
            &json!({"wan": b.wan_interface, "lan": b.lan_interface}),
        )
        .await;
    Json(json!({ "message": "applied", "applied": applied, "completed": true })).into_response()
}

/// POST /api/setup/complete: leave the wizard without changing anything.
pub async fn complete(State(state): State<AppState>, _admin: crate::auth::AdminUser) -> Response {
    match patronus_network::lan::set_setting(&state.config_store, DONE_KEY, "1").await {
        Ok(()) => Json(json!({ "completed": true })).into_response(),
        Err(e) => error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}

pub fn router() -> axum::Router<AppState> {
    use axum::routing::{get, post};
    axum::Router::new()
        .route("/setup/status", get(status))
        .route("/setup/apply", post(apply))
        .route("/setup/complete", post(complete))
}

pub fn pages() -> axum::Router<AppState> {
    use axum::routing::get;
    axum::Router::new().route("/setup", get(page))
}
