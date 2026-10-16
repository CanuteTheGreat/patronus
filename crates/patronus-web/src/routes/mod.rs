//! Web routes module
//!
//! Organizes all HTTP routes into logical modules:
//! - pages: HTML page handlers (renders Askama templates)
//! - api: REST API endpoints (returns JSON)

pub mod api;
pub mod pages;

use axum::{
    routing::{delete, get, post, put},
    Router,
};
use tower_http::services::ServeDir;

use crate::state::AppState;

/// Build the complete application router
pub fn build_router(
    state: AppState,
    _ws_broadcaster: std::sync::Arc<crate::websocket::WsBroadcaster>,
) -> Router {
    let app_state = state.clone();

    Router::new()
        // Public routes
        .route("/login", get(pages::login_page))
        // WebSocket routes (temporarily disabled due to handler issues)
        // .route("/ws/metrics", get(crate::websocket::ws_metrics_handler))
        // .route("/ws/logs", get(crate::websocket::ws_logs_handler))
        // Protected page routes (HTML) - require authentication
        .route("/", get(crate::simple_handlers::simple_index))
        .route("/firewall", get(pages::firewall))
        .route("/vpn", get(pages::vpn))
        .route("/network", get(pages::network))
        .route("/monitoring", get(pages::monitoring))
        .route("/system", get(pages::system))
        // Simple handler routes (working fallbacks)
        .route("/simple", get(crate::simple_handlers::simple_index))
        .route(
            "/simple/firewall",
            get(crate::simple_handlers::simple_firewall),
        )
        .route("/simple/status", get(crate::simple_handlers::simple_status))
        // API routes (JSON)
        .nest("/api", api_routes())
        // Static files
        .nest_service("/static", ServeDir::new("static"))
        // Attach application state
        .with_state(state)
        // Every page and API call except the login page/endpoint and static
        // assets requires a valid session (runs after session_middleware,
        // which is the outer layer and provides the SessionStore).
        .layer(axum::middleware::from_fn(require_session))
        // Session middleware
        .layer(axum::middleware::from_fn_with_state(
            app_state,
            crate::auth::session_middleware,
        ))
}

/// Paths reachable without a session.
fn is_public(method: &axum::http::Method, path: &str) -> bool {
    use axum::http::Method;
    path == "/login"
        || path.starts_with("/static/")
        || (method == Method::POST && path == "/api/auth/login")
}

/// Authentication gate for the whole UI and API.
///
/// Before this, only `/api/auth/me` and `/api/auth/logout` checked the
/// session: every other page and every management API (add/delete
/// firewall and NAT rules, WireGuard peers, interfaces up/down, backups,
/// service start/stop) answered anonymous requests.
///
/// Unauthenticated API calls get 401, unauthenticated page loads are
/// redirected to `/login`. State-changing API calls additionally need a
/// role that may modify configuration.
async fn require_session(
    req: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> axum::response::Response {
    use axum::extract::FromRequestParts;
    use axum::http::{header, Method, StatusCode};
    use axum::response::IntoResponse;

    let path = req.uri().path().to_string();
    if is_public(req.method(), &path) {
        return next.run(req).await;
    }

    let (mut parts, body) = req.into_parts();
    let session = crate::auth::AuthUser::from_request_parts(&mut parts, &())
        .await
        .map(|u| u.session);
    let is_api = path.starts_with("/api/");

    match session {
        Ok(session) => {
            let mutating = !matches!(parts.method, Method::GET | Method::HEAD | Method::OPTIONS);
            if is_api && mutating && path != "/api/auth/logout" && !session.role.can_modify() {
                return (
                    StatusCode::FORBIDDEN,
                    axum::Json(serde_json::json!({"error": "read-only account"})),
                )
                    .into_response();
            }
            next.run(axum::http::Request::from_parts(parts, body)).await
        }
        Err(_) if is_api => (
            StatusCode::UNAUTHORIZED,
            axum::Json(serde_json::json!({"error": "authentication required"})),
        )
            .into_response(),
        Err(_) => (StatusCode::SEE_OTHER, [(header::LOCATION, "/login")]).into_response(),
    }
}

/// Build API routes
fn api_routes() -> Router<AppState> {
    Router::new()
        // Authentication endpoints (public)
        .route("/auth/login", post(crate::auth::login))
        .route("/auth/logout", post(crate::auth::logout))
        .route("/auth/me", get(crate::auth::current_user))
        // Status endpoint
        .route("/status", get(api::status::system_status))
        // Firewall API
        .route(
            "/firewall/rules",
            get(api::firewall::list_rules).post(api::firewall::add_rule),
        )
        .route(
            "/firewall/rules/:id",
            get(api::firewall::get_rule)
                .put(api::firewall::update_rule)
                .delete(api::firewall::delete_rule),
        )
        .route("/firewall/rules/apply", post(api::firewall::apply_rules))
        .route(
            "/firewall/nat",
            get(api::firewall::list_nat_rules).post(api::firewall::add_nat_rule),
        )
        .route("/firewall/nat/:id", delete(api::firewall::delete_nat_rule))
        // VPN API
        .route(
            "/vpn/wireguard/peers",
            get(api::vpn::list_wg_peers).post(api::vpn::add_wg_peer),
        )
        .route("/vpn/wireguard/peers/:id", delete(api::vpn::delete_wg_peer))
        .route("/vpn/wireguard/config/:id", get(api::vpn::get_wg_config))
        .route(
            "/vpn/wireguard/qrcode/:id",
            get(api::vpn::get_wg_qrcode_svg),
        )
        .route(
            "/vpn/wireguard/qrcode/:id/png",
            get(api::vpn::get_wg_qrcode_png),
        )
        .route("/vpn/openvpn/tunnels", get(api::vpn::list_ovpn_tunnels))
        .route("/vpn/ipsec/tunnels", get(api::vpn::list_ipsec_tunnels))
        // Network API
        .route("/network/interfaces", get(api::network::list_interfaces))
        .route(
            "/network/interfaces/:name",
            put(api::network::update_interface),
        )
        .route(
            "/network/interfaces/:name/up",
            post(api::network::interface_up),
        )
        .route(
            "/network/interfaces/:name/down",
            post(api::network::interface_down),
        )
        .route("/network/dhcp/pools", get(api::network::list_dhcp_pools))
        .route("/network/dhcp/leases", get(api::network::list_dhcp_leases))
        .route("/network/dns/records", get(api::network::list_dns_records))
        .route("/network/routes", get(api::network::list_routes))
        // System API
        .route("/system/users", get(api::system::list_users))
        .route(
            "/system/backups",
            get(api::system::list_backups).post(api::system::create_backup),
        )
        .route("/system/updates", get(api::system::list_updates))
        .route("/system/services", get(api::system::list_services))
        .route(
            "/system/services/:name/start",
            post(api::system::start_service),
        )
        .route(
            "/system/services/:name/stop",
            post(api::system::stop_service),
        )
        .route(
            "/system/services/:name/restart",
            post(api::system::restart_service),
        )
}

#[cfg(test)]
mod auth_gate_tests {
    //! Regression tests: the management UI/API used to answer anonymous
    //! requests (only /api/auth/me and /api/auth/logout checked a session).
    use axum::body::Body;
    use axum::http::{header, Method, Request, StatusCode};
    use tower::ServiceExt;

    async fn app() -> (axum::Router, String) {
        let rule_manager = patronus_firewall::rules::RuleManager::new();
        let dir = std::env::temp_dir().join(format!("patronus-web-gate-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let config_store = patronus_config::store::ConfigStore::new(dir.join("config"));
        let state = crate::AppState::new(rule_manager, config_store)
            .await
            .unwrap();
        let pw = "Gate-Test-Passw0rd!".to_string();
        state
            .auth
            .user_store
            .provision_admin(Some(pw.clone()), &dir.join("pw"))
            .await
            .unwrap();
        let ws = std::sync::Arc::new(crate::WsBroadcaster::new());
        (super::build_router(state, ws), pw)
    }

    fn req(method: Method, uri: &str, cookie: Option<&str>, body: Option<&str>) -> Request<Body> {
        let mut b = Request::builder().method(method).uri(uri);
        if let Some(c) = cookie {
            b = b.header(header::COOKIE, c);
        }
        if body.is_some() {
            b = b.header(header::CONTENT_TYPE, "application/json");
        }
        b.body(
            body.map(|s| Body::from(s.to_string()))
                .unwrap_or_else(Body::empty),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn anonymous_api_calls_are_rejected() {
        let (app, _) = app().await;
        let rule = r#"{"name":"evil","action":"accept","interface":"any","protocol":"tcp","source":"any","destination":"any","port":"22","description":"","enabled":true,"chain":"input"}"#;
        for (m, uri, body) in [
            (Method::GET, "/api/status", None),
            (Method::GET, "/api/firewall/rules", None),
            (Method::POST, "/api/firewall/rules", Some(rule)),
            (Method::DELETE, "/api/firewall/rules/1", None),
            (Method::POST, "/api/system/backups", None),
            (Method::POST, "/api/system/services/sshd/stop", None),
            (Method::GET, "/api/vpn/wireguard/peers", None),
            (Method::POST, "/api/network/interfaces/eth0/down", None),
        ] {
            let r = app
                .clone()
                .oneshot(req(m.clone(), uri, None, body))
                .await
                .unwrap();
            assert_eq!(r.status(), StatusCode::UNAUTHORIZED, "{m} {uri}");
        }
        // A forged/unknown session cookie is no better.
        let r = app
            .clone()
            .oneshot(req(
                Method::GET,
                "/api/status",
                Some("session_id=forged"),
                None,
            ))
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn anonymous_pages_redirect_to_login() {
        let (app, _) = app().await;
        for uri in [
            "/",
            "/firewall",
            "/vpn",
            "/network",
            "/system",
            "/simple/status",
        ] {
            let r = app
                .clone()
                .oneshot(req(Method::GET, uri, None, None))
                .await
                .unwrap();
            assert_eq!(r.status(), StatusCode::SEE_OTHER, "{uri}");
            assert_eq!(r.headers()[header::LOCATION], "/login", "{uri}");
        }
        let r = app
            .clone()
            .oneshot(req(Method::GET, "/login", None, None))
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn logged_in_admin_reaches_the_api() {
        let (app, pw) = app().await;
        let bad = r#"{"username":"admin","password":"admin"}"#;
        let r = app
            .clone()
            .oneshot(req(Method::POST, "/api/auth/login", None, Some(bad)))
            .await
            .unwrap();
        assert_eq!(
            r.status(),
            StatusCode::UNAUTHORIZED,
            "admin/admin must not work"
        );

        let good = format!(r#"{{"username":"admin","password":"{pw}"}}"#);
        let r = app
            .clone()
            .oneshot(req(Method::POST, "/api/auth/login", None, Some(&good)))
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::OK);
        let cookie = r.headers()[header::SET_COOKIE]
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_string();

        let r = app
            .clone()
            .oneshot(req(Method::GET, "/api/auth/me", Some(&cookie), None))
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::OK);
        for uri in [
            "/api/status",
            "/api/vpn/wireguard/peers",
            "/api/system/backups",
        ] {
            let r = app
                .clone()
                .oneshot(req(Method::GET, uri, Some(&cookie), None))
                .await
                .unwrap();
            assert_ne!(r.status(), StatusCode::UNAUTHORIZED, "{uri}");
            assert_ne!(r.status(), StatusCode::FORBIDDEN, "{uri}");
        }
        let r = app
            .clone()
            .oneshot(req(Method::GET, "/firewall", Some(&cookie), None))
            .await
            .unwrap();
        assert_ne!(r.status(), StatusCode::SEE_OTHER);
    }
}
