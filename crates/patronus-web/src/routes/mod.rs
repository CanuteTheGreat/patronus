//! Web routes module
//!
//! Organizes all HTTP routes into logical modules:
//! - pages: HTML page handlers (renders Askama templates)
//! - api: REST API endpoints (returns JSON)

pub mod api;
pub mod pages;

use axum::{
    response::Redirect,
    routing::{get, post},
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
        .route("/", get(pages::dashboard))
        .route("/firewall", get(pages::firewall))
        .route("/vpn", get(api::vpn::page))
        .route("/network", get(pages::network))
        .route("/interfaces", get(api::interfaces::page))
        .route("/routing", get(api::routing::page))
        .route("/monitoring", get(pages::monitoring))
        .route("/system", get(pages::system))
        .merge(api::lan::pages())
        .merge(api::ha::pages())
        .merge(api::qos::pages())
        .merge(api::insights::pages())
        .merge(api::packages::pages())
        .merge(api::svc::pages())
        .merge(api::segmentation::pages())
        .merge(seg_time_pages())
        .merge(seg_dns_pages())
        .merge(api::setup::pages())
        // The old "simple" pages claimed services were operational and
        // listed invented "recent activity"; keep the URLs as redirects.
        .route("/simple", get(|| async { Redirect::to("/") }))
        .route(
            "/simple/firewall",
            get(|| async { Redirect::to("/firewall") }),
        )
        .route("/simple/status", get(|| async { Redirect::to("/system") }))
        // The favicon is compiled in, so it is served even when the
        // process's working directory has no static/ (the shipped image
        // and the OpenRC/systemd services): browsers request
        // /favicon.ico on every page and logged a 404 for it.
        .route(
            "/favicon.ico",
            get(|| brand_asset(BRAND_FAVICON_ICO, "image/x-icon")),
        )
        .route(
            "/favicon-32.png",
            get(|| brand_asset(BRAND_FAVICON_32, "image/png")),
        )
        .route(
            "/apple-touch-icon.png",
            get(|| brand_asset(BRAND_APPLE_TOUCH, "image/png")),
        )
        .route(
            "/brand/mark.png",
            get(|| brand_asset(BRAND_MARK, "image/png")),
        )
        .route(
            "/brand/wordmark.png",
            get(|| brand_asset(BRAND_WORDMARK, "image/png")),
        )
        .route(
            "/brand/full.png",
            get(|| brand_asset(BRAND_FULL, "image/png")),
        )
        // Prometheus/OpenMetrics text for collectors (session or API key)
        .route("/metrics", get(api::telemetry::metrics))
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
        // Outermost, so 401s, login redirects and errors get them too.
        .layer(axum::middleware::map_response(security_headers))
}

/// Browser hardening headers on every response (the SD-WAN dashboard,
/// `patronus-dashboard`, already sent these; the firewall's own UI didn't):
///
/// - `X-Frame-Options: DENY` + CSP `frame-ancestors 'none'`: no other site
///   can frame the management UI and trick an admin into clicking
///   "Delete"/"Restore" under an overlay (clickjacking). The session
///   cookie's `SameSite=Strict` already keeps a cross-site frame logged
///   out in current browsers; this doesn't depend on that.
/// - `X-Content-Type-Options: nosniff`: a response is never interpreted as
///   anything but its declared type.
/// - `Referrer-Policy: same-origin`: the router's address and page paths
///   don't leak to sites linked from the UI.
/// - `Cache-Control: no-store` unless the handler chose its own (the
///   favicon is cacheable): pages and API answers carry live config, user
///   lists and one-time recovery codes, which must not stay in the
///   browser's disk cache on a shared machine.
///
/// The CSP is only `frame-ancestors`: the templates use inline scripts.
async fn security_headers(mut res: axum::response::Response) -> axum::response::Response {
    use axum::http::{header, HeaderValue};
    let h = res.headers_mut();
    for (name, value) in [
        (header::X_FRAME_OPTIONS, "DENY"),
        (header::CONTENT_SECURITY_POLICY, "frame-ancestors 'none'"),
        (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
        (header::REFERRER_POLICY, "same-origin"),
        (header::CACHE_CONTROL, "no-store"),
    ] {
        h.entry(name).or_insert(HeaderValue::from_static(value));
    }
    res
}

// The official Patronus logo, cropped/scaled only (branding/README.md); compiled in
// so it is served even when the process has no static/ directory.
const BRAND_FAVICON_ICO: &[u8] = include_bytes!("../../static/brand/favicon.ico");
const BRAND_FAVICON_32: &[u8] = include_bytes!("../../static/brand/favicon-32.png");
const BRAND_APPLE_TOUCH: &[u8] = include_bytes!("../../static/brand/apple-touch-icon.png");
const BRAND_MARK: &[u8] = include_bytes!("../../static/brand/mark.png");
const BRAND_WORDMARK: &[u8] = include_bytes!("../../static/brand/wordmark.png");
const BRAND_FULL: &[u8] = include_bytes!("../../static/brand/full.png");

async fn brand_asset(
    bytes: &'static [u8],
    content_type: &'static str,
) -> impl axum::response::IntoResponse {
    use axum::http::header;
    (
        [
            (header::CONTENT_TYPE, content_type),
            (header::CACHE_CONTROL, "public, max-age=86400"),
        ],
        bytes,
    )
}

/// Paths reachable without a session.
fn is_public(method: &axum::http::Method, path: &str) -> bool {
    use axum::http::Method;
    path == "/login"
        || path == "/favicon.ico"
        || path == "/favicon-32.png"
        || path == "/apple-touch-icon.png"
        || path.starts_with("/brand/")
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
    // API key (Authorization: Bearer pat_... / X-API-Key): authenticates
    // on its own; a bad key is a 401, never a fallback to a cookie.
    if let Some(token) = crate::apikeys::request_token(&parts.headers) {
        let keys = parts
            .extensions
            .get::<crate::apikeys::ApiKeyStore>()
            .cloned();
        let key = match keys {
            Some(k) => k.verify(&token).await,
            None => None,
        };
        let Some(key) = key else {
            return (
                StatusCode::UNAUTHORIZED,
                axum::Json(serde_json::json!({"error": "invalid or expired API key"})),
            )
                .into_response();
        };
        // keys automate configuration; accounts, their own credentials and
        // key management are for people
        let people_only = (path.starts_with("/api/auth/") && path != "/api/auth/me")
            || path.starts_with("/api/system/api-keys")
            || path.starts_with("/api/system/auth-servers")
            || path.starts_with("/api/system/groups")
            || path.starts_with("/api/system/factory-reset")
            || path.starts_with("/api/system/backup-targets")
            || path.starts_with("/api/system/users");
        if !(path.starts_with("/api/") || path == "/metrics") || people_only {
            return (
                StatusCode::FORBIDDEN,
                axum::Json(serde_json::json!({"error": "not available to API keys"})),
            )
                .into_response();
        }
        if !key.role().can_modify()
            && !matches!(parts.method, Method::GET | Method::HEAD | Method::OPTIONS)
        {
            return (
                StatusCode::FORBIDDEN,
                axum::Json(serde_json::json!({"error": "read-only API key"})),
            )
                .into_response();
        }
        parts
            .extensions
            .insert(crate::apikeys::ApiKeyPrincipal(key));
        return next.run(axum::http::Request::from_parts(parts, body)).await;
    }
    let session = crate::auth::AuthUser::from_request_parts(&mut parts, &())
        .await
        .map(|u| u.session);
    let is_api = path.starts_with("/api/") || path == "/metrics";

    match session {
        Ok(session) => {
            let mutating = !matches!(parts.method, Method::GET | Method::HEAD | Method::OPTIONS);
            // a read-only account may still log out, change its own
            // password and manage its own second factor
            let own_account = path == "/api/auth/logout"
                || path == "/api/auth/password"
                || path.starts_with("/api/auth/2fa/");
            // Group membership replaces the coarse role: an account in a
            // group gets exactly the group's per-area privileges.
            if !session.role.is_admin() && !own_account {
                if let (Some(rbac), Some(area)) = (
                    parts.extensions.get::<crate::rbac::RbacStore>().cloned(),
                    crate::rbac::area_for_path(&path),
                ) {
                    if let Some(privs) = rbac.privileges_of(session.user_id as i64).await {
                        if !crate::rbac::allows(&privs, area, mutating) {
                            let msg = format!(
                                "your group has no {} access to {area}",
                                if mutating { "write" } else { "read" }
                            );
                            return if is_api {
                                (
                                    StatusCode::FORBIDDEN,
                                    axum::Json(serde_json::json!({"error": msg})),
                                )
                                    .into_response()
                            } else {
                                (StatusCode::FORBIDDEN, msg).into_response()
                            };
                        }
                        return next.run(axum::http::Request::from_parts(parts, body)).await;
                    }
                }
            }
            if is_api && mutating && !own_account && !session.role.can_modify() {
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

#[cfg(feature = "segmentation")]
fn seg_time_pages() -> Router<AppState> {
    api::seg_time::pages()
}
#[cfg(not(feature = "segmentation"))]
fn seg_time_pages() -> Router<AppState> {
    Router::new()
}
#[cfg(feature = "segmentation")]
fn seg_time_router() -> Router<AppState> {
    api::seg_time::router()
}
#[cfg(not(feature = "segmentation"))]
fn seg_time_router() -> Router<AppState> {
    Router::new()
}
#[cfg(all(feature = "dns", feature = "segmentation"))]
fn seg_dns_pages() -> Router<AppState> {
    api::seg_dns::pages()
}
#[cfg(all(feature = "dns", feature = "segmentation"))]
fn seg_dns_router() -> Router<AppState> {
    api::seg_dns::router()
}
#[cfg(not(all(feature = "dns", feature = "segmentation")))]
fn seg_dns_pages() -> Router<AppState> {
    Router::new()
}
#[cfg(not(all(feature = "dns", feature = "segmentation")))]
fn seg_dns_router() -> Router<AppState> {
    Router::new()
}

/// Build API routes.
///
/// Convention: each subsystem's endpoints live in `routes/api/<subsystem>.rs`
/// and are registered there in its own `router()`; this function only
/// merges them, one line per lane, so lanes never edit each other's routes.
fn api_routes() -> Router<AppState> {
    Router::new()
        .route("/auth/login", post(crate::auth::login))
        .route("/auth/logout", post(crate::auth::logout))
        .route("/auth/me", get(crate::auth::current_user))
        .route("/auth/password", post(crate::auth::change_password))
        .route("/auth/2fa/setup", post(crate::auth::totp_setup))
        .route("/auth/2fa/enable", post(crate::auth::totp_enable))
        .route("/auth/2fa/disable", post(crate::auth::totp_disable))
        .merge(api::status::router())
        .merge(api::firewall::router())
        .merge(api::lan::router())
        .merge(api::ha::router())
        .merge(api::qos::router())
        .merge(api::insights::router())
        .merge(api::packages::router())
        .merge(api::svc::router())
        .merge(api::segmentation::router())
        .merge(seg_time_router())
        .merge(seg_dns_router())
        .merge(api::vpn::router())
        .merge(api::network::router())
        .merge(api::routing::router())
        .merge(api::interfaces::router())
        .merge(api::system::router())
        .merge(api::apikeys::router())
        .merge(api::groups::router())
        .merge(api::backup_targets::router())
        .merge(api::setup::router())
        .merge(api::authservers::router())
        .merge(api::telemetry::router())
}

#[cfg(test)]
mod honesty_tests;

#[cfg(test)]
mod lane_fh_tests;

#[cfg(all(test, feature = "segmentation"))]
mod seg_tests;

#[cfg(test)]
mod auth_gate_tests {
    //! Regression tests: the management UI/API used to answer anonymous
    //! requests (only /api/auth/me and /api/auth/logout checked a session).
    use axum::body::Body;
    use axum::http::{header, Method, Request, StatusCode};
    use tower::ServiceExt;

    async fn app() -> (axum::Router, String) {
        let dir = std::env::temp_dir().join(format!("patronus-web-gate-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let config_store = std::sync::Arc::new(
            patronus_config::ConfigStore::open(dir.join("config.db"))
                .await
                .unwrap(),
        );
        // Render-only applier: these tests check auth, not nftables.
        let state = crate::AppState::new(
            config_store,
            std::sync::Arc::new(crate::state::firewall::NoopApplier),
        )
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

    /// Every response -- public page, 401, login redirect, logged-in API
    /// answer -- carries the anti-framing/nosniff/referrer headers and
    /// isn't cached; a handler's own Cache-Control (favicon) is kept.
    #[tokio::test]
    async fn every_response_has_the_security_headers() {
        let (app, pw) = app().await;
        let login = format!(r#"{{"username":"admin","password":"{pw}"}}"#);
        let r = app
            .clone()
            .oneshot(req(Method::POST, "/api/auth/login", None, Some(&login)))
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
        for (uri, c, want) in [
            ("/login", None, StatusCode::OK),
            ("/system", None, StatusCode::SEE_OTHER),
            ("/api/status", None, StatusCode::UNAUTHORIZED),
            ("/system", Some(cookie.as_str()), StatusCode::OK),
            ("/api/system/users", Some(cookie.as_str()), StatusCode::OK),
        ] {
            let r = app
                .clone()
                .oneshot(req(Method::GET, uri, c, None))
                .await
                .unwrap();
            assert_eq!(r.status(), want, "{uri}");
            let h = r.headers();
            assert_eq!(h[header::X_FRAME_OPTIONS], "DENY", "{uri}");
            assert_eq!(
                h[header::CONTENT_SECURITY_POLICY],
                "frame-ancestors 'none'",
                "{uri}"
            );
            assert_eq!(h[header::X_CONTENT_TYPE_OPTIONS], "nosniff", "{uri}");
            assert_eq!(h[header::REFERRER_POLICY], "same-origin", "{uri}");
            assert_eq!(h[header::CACHE_CONTROL], "no-store", "{uri}");
            assert_eq!(h.get_all(header::CACHE_CONTROL).iter().count(), 1, "{uri}");
        }
        let r = app
            .clone()
            .oneshot(req(Method::GET, "/favicon.ico", None, None))
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::OK);
        assert_eq!(r.headers()[header::CACHE_CONTROL], "public, max-age=86400");
        assert_eq!(r.headers()[header::X_FRAME_OPTIONS], "DENY");
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

    fn from_ip(mut r: Request<Body>, ip: &str) -> Request<Body> {
        let addr: std::net::SocketAddr = format!("{ip}:40000").parse().unwrap();
        r.extensions_mut().insert(axum::extract::ConnectInfo(addr));
        r
    }

    #[tokio::test]
    async fn repeated_failed_logins_lock_out_that_client_only() {
        let (app, pw) = app().await;
        let bad = r#"{"username":"admin","password":"not-the-password"}"#;
        let good = format!(r#"{{"username":"admin","password":"{pw}"}}"#);
        let attacker = "203.0.113.50";
        for i in 0..crate::auth::MAX_LOGIN_FAILURES {
            let r = app
                .clone()
                .oneshot(from_ip(
                    req(Method::POST, "/api/auth/login", None, Some(bad)),
                    attacker,
                ))
                .await
                .unwrap();
            assert_eq!(r.status(), StatusCode::UNAUTHORIZED, "attempt {i}");
        }
        // Locked out: even the right password is refused, with Retry-After.
        let r = app
            .clone()
            .oneshot(from_ip(
                req(Method::POST, "/api/auth/login", None, Some(&good)),
                attacker,
            ))
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(r.headers().get(header::SET_COOKIE).is_none());
        let retry: u64 = r.headers()[header::RETRY_AFTER]
            .to_str()
            .unwrap()
            .parse()
            .unwrap();
        assert!(retry > 0);
        // The legitimate admin on another address still gets in.
        let r = app
            .clone()
            .oneshot(from_ip(
                req(Method::POST, "/api/auth/login", None, Some(&good)),
                "192.0.2.10",
            ))
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn password_guesses_through_a_stolen_session_are_throttled() {
        // Re-auth endpoints (password change, 2FA setup) used to check the
        // password with no throttle: a stolen session cookie gave unlimited
        // guesses, and the right one let the thief change the password.
        let (app, pw) = app().await;
        let good = format!(r#"{{"username":"admin","password":"{pw}"}}"#);
        let r = app
            .clone()
            .oneshot(from_ip(
                req(Method::POST, "/api/auth/login", None, Some(&good)),
                "192.0.2.10",
            ))
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
        let thief = "203.0.113.77";
        let guess =
            r#"{"current_password":"guess-Passw0rd-1","new_password":"Thief-Owns-It-1234"}"#;
        for i in 0..crate::auth::MAX_LOGIN_FAILURES {
            let (uri, body) = if i % 2 == 0 {
                ("/api/auth/password", guess.to_string())
            } else {
                (
                    "/api/auth/2fa/setup",
                    r#"{"password":"guess-Passw0rd-2"}"#.to_string(),
                )
            };
            let r = app
                .clone()
                .oneshot(from_ip(
                    req(Method::POST, uri, Some(&cookie), Some(&body)),
                    thief,
                ))
                .await
                .unwrap();
            let s = r.status();
            // 501 = built without USE=totp: that endpoint checks nothing
            assert!(
                s == StatusCode::UNAUTHORIZED || s == StatusCode::NOT_IMPLEMENTED,
                "{uri} attempt {i}: {s}"
            );
            if s == StatusCode::NOT_IMPLEMENTED {
                // count it the same way through the password endpoint
                let r = app
                    .clone()
                    .oneshot(from_ip(
                        req(
                            Method::POST,
                            "/api/auth/password",
                            Some(&cookie),
                            Some(guess),
                        ),
                        thief,
                    ))
                    .await
                    .unwrap();
                assert_eq!(r.status(), StatusCode::UNAUTHORIZED, "attempt {i}");
            }
        }
        // Locked out: the right current password no longer changes anything.
        let right = format!(r#"{{"current_password":"{pw}","new_password":"Thief-Owns-It-1234"}}"#);
        let r = app
            .clone()
            .oneshot(from_ip(
                req(
                    Method::POST,
                    "/api/auth/password",
                    Some(&cookie),
                    Some(&right),
                ),
                thief,
            ))
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(r.headers().contains_key(header::RETRY_AFTER));
        // ...nor does logging in from that client...
        let r = app
            .clone()
            .oneshot(from_ip(
                req(Method::POST, "/api/auth/login", None, Some(&good)),
                thief,
            ))
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::TOO_MANY_REQUESTS);
        // ...and the owner, elsewhere, still has the original password.
        let r = app
            .clone()
            .oneshot(from_ip(
                req(Method::POST, "/api/auth/login", None, Some(&good)),
                "192.0.2.10",
            ))
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::OK, "password must be unchanged");
    }
}
