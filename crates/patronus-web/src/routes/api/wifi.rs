//! Wi-Fi page of an access point (`/wifi`, `/api/wifi*`) and the uplink
//! status of an access point (`/api/ap/uplink`).
//!
//! The settings live in the unit's access-point file (`/etc/patronus/ap.env`,
//! driven by `/usr/libexec/patronus/ap`), read and written as root through
//! `patronus_network::apwifi` (in-process when the web UI is root, else
//! through `patronus applyd`). Passphrases never come back in `GET
//! /api/wifi`; an administrator can reveal one network's key explicitly
//! (audited).
//!
//! The access-point role also hides the router-only pages: [`ap_role_guard`]
//! answers them with an explanation (your main router does this) instead of
//! controls that would do nothing useful, and refuses changes to the
//! router-only APIs.

use crate::routes::api::setup::DeviceRole;
use crate::state::AppState;
use askama::Template;
use axum::{
    extract::{Path, State},
    http::{Method, StatusCode},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde::Deserialize;
use serde_json::{json, Value};

fn error(code: StatusCode, m: impl Into<String>) -> Response {
    (code, Json(json!({ "error": m.into() }))).into_response()
}

fn op_err(e: anyhow::Error) -> Response {
    let m = e.to_string();
    let code = if m.contains("Invalid") {
        StatusCode::BAD_REQUEST
    } else if m.contains("no such network") {
        StatusCode::NOT_FOUND
    } else if m.contains("did not come up") {
        StatusCode::CONFLICT
    } else {
        StatusCode::INTERNAL_SERVER_ERROR
    };
    error(code, m)
}

/// This unit's role, read once.
pub fn role() -> DeviceRole {
    static R: std::sync::OnceLock<DeviceRole> = std::sync::OnceLock::new();
    *R.get_or_init(DeviceRole::from_env)
}

#[derive(Template)]
#[template(path = "wifi.html")]
pub struct WifiTemplate {
    pub page: &'static str,
    pub can_modify: bool,
    pub ap_mode: bool,
}

pub async fn page(me: crate::auth::AuthUser) -> Response {
    crate::routes::pages::render(
        &WifiTemplate {
            page: "wifi",
            can_modify: me.session.role.is_admin(),
            ap_mode: role() == DeviceRole::Ap,
        },
        "wifi",
    )
}

/// GET /api/wifi: settings (no passphrases), radio and BSS state.
pub async fn get_wifi(State(state): State<AppState>) -> Response {
    match state.system.system_op("wifi_get", Value::Null).await {
        Ok(v) => Json(v).into_response(),
        Err(e) => op_err(e),
    }
}

/// PUT /api/wifi (admins): change radios and/or networks, restart the
/// radios, roll back if they do not come up.
pub async fn put_wifi(
    State(state): State<AppState>,
    admin: crate::auth::AdminUser,
    Json(body): Json<Value>,
) -> Response {
    // what changed, for the audit log, without any passphrase
    let mut summary = body.clone();
    if let Some(nets) = summary.get_mut("networks").and_then(Value::as_array_mut) {
        for n in nets {
            if let Some(o) = n.as_object_mut() {
                let changed = o
                    .get("key")
                    .and_then(Value::as_str)
                    .is_some_and(|k| !k.is_empty());
                o.remove("key");
                if changed {
                    o.insert("key_changed".into(), json!(true));
                }
            }
        }
    }
    match state.system.system_op("wifi_set", body).await {
        Ok(v) => {
            let _ = state
                .config_store
                .audit(&admin.session.username, "update", "wifi", None, &summary)
                .await;
            Json(v).into_response()
        }
        Err(e) => op_err(e),
    }
}

/// GET /api/wifi/clients: stations on every BSS (signal, rates, band).
pub async fn clients(State(state): State<AppState>) -> Response {
    match state.system.system_op("wifi_clients", Value::Null).await {
        Ok(v) => Json(v).into_response(),
        Err(e) => op_err(e),
    }
}

#[derive(Deserialize)]
pub struct KickRequest {
    pub interface: String,
    pub mac: String,
}

/// POST /api/wifi/clients/kick (admins): disconnect one client from one BSS.
pub async fn kick(
    State(state): State<AppState>,
    admin: crate::auth::AdminUser,
    Json(k): Json<KickRequest>,
) -> Response {
    let p = json!({ "interface": k.interface, "mac": k.mac });
    match state.system.system_op("wifi_kick", p.clone()).await {
        Ok(v) => {
            let _ = state
                .config_store
                .audit(
                    &admin.session.username,
                    "kick",
                    "wifi_client",
                    Some(&k.mac),
                    &p,
                )
                .await;
            Json(v).into_response()
        }
        Err(e) => op_err(e),
    }
}

/// POST /api/wifi/networks/:id/reveal (admins, audited): one network's passphrase.
pub async fn reveal(
    State(state): State<AppState>,
    admin: crate::auth::AdminUser,
    Path(id): Path<String>,
) -> Response {
    match state
        .system
        .system_op("wifi_key", json!({ "id": id }))
        .await
    {
        Ok(v) => {
            let _ = state
                .config_store
                .audit(
                    &admin.session.username,
                    "reveal",
                    "wifi_key",
                    Some(&id),
                    &Value::Null,
                )
                .await;
            Json(v).into_response()
        }
        Err(e) => op_err(e),
    }
}

/// GET /api/ap/uplink: how this unit reaches the network (bridge address,
/// gateway, DNS, wired ports with link and speed).
pub async fn uplink() -> Response {
    let v = tokio::task::spawn_blocking(|| {
        patronus_network::apwifi::uplink(&patronus_network::apwifi::Paths::default(), "br-lan")
    })
    .await
    .unwrap_or(Value::Null);
    Json(json!({ "role": role().as_str(), "uplink": v })).into_response()
}

pub fn pages() -> Router<AppState> {
    Router::new().route("/wifi", get(page))
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/wifi", get(get_wifi).put(put_wifi))
        .route("/wifi/clients", get(clients))
        .route("/wifi/clients/kick", post(kick))
        .route("/wifi/networks/:id/reveal", post(reveal))
        .route("/ap/uplink", get(uplink))
}

// ---------------------------------------------------------------------------
// access-point role: router-only pages and APIs
// ---------------------------------------------------------------------------

/// Pages that configure what a router does for the network (addresses,
/// names, routes, per-device policy). An access point does none of it: the
/// main router does.
pub const AP_ROUTER_PAGES: &[(&str, &str)] = &[
    ("/routing", "Routing and gateways"),
    ("/dhcp", "DHCP server"),
    ("/dns", "DNS resolver"),
    ("/segmentation", "Device segmentation"),
    ("/segmentation/time", "Time limits"),
    ("/segmentation/dns", "DNS policy and logs"),
    ("/insights", "Traffic insights"),
];

/// API prefixes whose changes only make sense on a router.
const AP_ROUTER_APIS: &[&str] = &[
    "/api/dhcp",
    "/api/dns",
    "/api/ddns",
    "/api/routing",
    "/api/segmentation",
    "/api/setup/apply",
];

/// Which router-only page (if any) a request is for, on an access point.
pub fn ap_router_page(method: &Method, path: &str) -> Option<&'static str> {
    if method != Method::GET {
        return None;
    }
    let p = path.trim_end_matches('/');
    AP_ROUTER_PAGES
        .iter()
        .find(|(u, _)| *u == p)
        .map(|(_, title)| *title)
}

/// A change to a router-only API, on an access point.
pub fn ap_router_api_change(method: &Method, path: &str) -> bool {
    method != Method::GET
        && method != Method::HEAD
        && AP_ROUTER_APIS
            .iter()
            .any(|a| path == *a || path.starts_with(&format!("{a}/")))
}

#[derive(Template)]
#[template(path = "ap_notice.html")]
pub struct ApNoticeTemplate {
    pub page: &'static str,
    pub title: &'static str,
    pub gateway: String,
}

pub async fn ap_role_guard(
    req: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> Response {
    if role() != DeviceRole::Ap {
        return next.run(req).await;
    }
    let (m, path) = (req.method().clone(), req.uri().path().to_string());
    if let Some(title) = ap_router_page(&m, &path) {
        let gateway = patronus_network::apwifi::default_gateway(
            &std::fs::read_to_string("/proc/net/route").unwrap_or_default(),
        )
        .map(|(_, g)| g)
        .unwrap_or_default();
        return match (ApNoticeTemplate {
            page: title,
            title,
            gateway,
        })
        .render()
        {
            Ok(h) => Html(h).into_response(),
            Err(_) => error(StatusCode::INTERNAL_SERVER_ERROR, "Failed to render page"),
        };
    }
    if ap_router_api_change(&m, &path) {
        return error(
            StatusCode::CONFLICT,
            "this unit is an access point: addresses, names and routes for the network come from the main router, not from here",
        );
    }
    next.run(req).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn router_pages_and_apis_on_an_ap() {
        assert_eq!(ap_router_page(&Method::GET, "/dhcp"), Some("DHCP server"));
        assert_eq!(
            ap_router_page(&Method::GET, "/segmentation/time/"),
            Some("Time limits")
        );
        assert_eq!(ap_router_page(&Method::GET, "/wifi"), None);
        assert_eq!(ap_router_page(&Method::GET, "/firewall"), None);
        assert_eq!(ap_router_page(&Method::POST, "/dhcp"), None);
        assert!(ap_router_api_change(&Method::POST, "/api/dhcp/pools"));
        assert!(ap_router_api_change(&Method::PUT, "/api/routing/default"));
        assert!(ap_router_api_change(&Method::POST, "/api/setup/apply"));
        assert!(!ap_router_api_change(&Method::GET, "/api/dhcp/leases"));
        assert!(!ap_router_api_change(&Method::PUT, "/api/wifi"));
        assert!(!ap_router_api_change(&Method::POST, "/api/dnsx"));
        assert!(!ap_router_api_change(&Method::POST, "/api/system/reboot"));
    }

    #[test]
    fn absent_features_explain_hidden_entries() {
        use crate::routes::absent_features;
        let router_tier = ["dhcp", "dns", "segmentation", "wifi-ap"];
        let ap = absent_features(&router_tier, "embedded", DeviceRole::Ap);
        let find = |v: &[Value], f: &str| {
            v.iter()
                .find(|a| a["feature"] == f)
                .map(|a| a["reason"].as_str().unwrap().to_string())
        };
        assert!(find(&ap, "wireguard")
            .unwrap()
            .contains("router-tier image"));
        assert!(
            find(&ap, "dhcp").unwrap().contains("access point"),
            "built but the main router's job on an AP"
        );
        assert!(ap.iter().any(|a| a["label"] == "Routing, gateways and NAT"));
        let router = absent_features(&router_tier, "embedded", DeviceRole::Router);
        assert!(
            find(&router, "dhcp").is_none(),
            "a router that has DHCP does not list it"
        );
        assert!(find(&router, "ntp").unwrap().contains("router-tier"));
        let full = absent_features(&["wireguard", "ipsec"], "standard", DeviceRole::Router);
        assert!(find(&full, "wireguard").is_none());
        assert!(find(&full, "ha").unwrap().contains("USE flag"));
    }
}
