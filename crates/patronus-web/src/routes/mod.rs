//! Web routes module
//!
//! Organizes all HTTP routes into logical modules:
//! - pages: HTML page handlers (renders Askama templates)
//! - api: REST API endpoints (returns JSON)

pub mod api;
pub mod first_run;
pub mod legal;
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
    let access_log_state = state.clone();

    Router::new()
        // Public routes
        .route("/login", get(pages::login_page))
        .route("/first-run", get(first_run::page))
        .route(
            "/api/first-run",
            axum::routing::post(first_run::set_password),
        )
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
        .route("/diagnostics", get(pages::diagnostics))
        .merge(api::lan::pages())
        .merge(api::ha::pages())
        .merge(api::qos::pages())
        .merge(api::insights::pages())
        .merge(api::accesslog::pages())
        .merge(api::packages::pages())
        .merge(api::svc::pages())
        .merge(api::segmentation::pages())
        .merge(seg_time_pages())
        .merge(seg_dns_pages())
        .merge(api::setup::pages())
        .merge(api::wifi::pages())
        .merge(api::device::pages())
        .merge(legal::pages())
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
            "/brand/full.webp",
            get(|| brand_asset(BRAND_FULL, "image/webp")),
        )
        // Prometheus/OpenMetrics text for collectors (session or API key)
        .route("/metrics", get(api::telemetry::metrics))
        // API routes (JSON)
        .nest("/api", api_routes())
        // Static files
        .nest_service("/static", ServeDir::new("static"))
        // Attach application state
        .with_state(state)
        // An access point (PATRONUS_DEVICE_ROLE=ap) answers the router-only
        // pages with an explanation and refuses changes to their APIs (runs
        // after the session check below).
        .layer(axum::middleware::from_fn(api::wifi::ap_role_guard))
        // Every page and API call except the login page/endpoint and static
        // assets requires a valid session (runs after session_middleware,
        // which is the outer layer and provides the SessionStore).
        .layer(axum::middleware::from_fn_with_state(
            app_state.clone(),
            require_session,
        ))
        // Session middleware
        .layer(axum::middleware::from_fn_with_state(
            app_state,
            crate::auth::session_middleware,
        ))
        // Outermost, so 401s, login redirects and errors get them too.
        .layer(axum::middleware::map_response(security_headers))
        // The access log sees every answered request, the gate's 401s and
        // the login page included, so it wraps everything else.
        .layer(axum::middleware::from_fn_with_state(
            access_log_state,
            access_log_layer,
        ))
}

/// Records one `web_access_log` row per answered request (see
/// `state::accesslog`). The path group is the matched route template
/// (never the raw path or query string); who made the request is filled in
/// by the session gate and the login handler through the request's
/// [`accesslog::Slot`]. The body is counted as it is sent, so the row is
/// queued when the answer has been delivered (or dropped).
async fn access_log_layer(
    axum::extract::State(app_state): axum::extract::State<crate::AppState>,
    mut req: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> axum::response::Response {
    use crate::state::accesslog::{self, Entry, Slot};
    let log = app_state.access_log.clone();
    if !log.enabled() {
        return next.run(req).await;
    }
    let started = std::time::Instant::now();
    let timestamp_ms = chrono::Utc::now().timestamp_millis();
    let method = req.method().as_str().to_string();
    let group = accesslog::path_group(
        req.extensions()
            .get::<axum::extract::MatchedPath>()
            .map(|m| m.as_str()),
    );
    let client = req
        .extensions()
        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
        .map(|c| c.0.ip().to_string())
        .unwrap_or_else(|| "unknown".to_string());
    // the log page's own live polling would otherwise fill the log with
    // itself every couple of seconds
    let live_poll = method == "GET"
        && group.starts_with("/api/system/access-log")
        && req.uri().query().is_some_and(|q| q.contains("after_id="));
    let slot = Slot::default();
    req.extensions_mut().insert(slot.clone());
    let res = next.run(req).await;
    if live_poll {
        return res;
    }
    let status = res.status().as_u16();
    let duration_ms = started.elapsed().as_millis() as i64;
    let make = move |bytes: Option<i64>| {
        let who = slot.get();
        let (kind, name, key) = match who.principal {
            Some((k, n, id)) => (k, Some(n), id),
            None => ("anonymous", None, None),
        };
        // the attempted name is kept for sign-in failures only
        let attempted = if name.is_none() { who.attempted_user } else { None };
        log.record(Entry {
            timestamp_ms,
            client,
            principal_kind: kind,
            principal_name: name,
            api_key_id: key,
            attempted_user: attempted.filter(|a| !a.is_empty()),
            method,
            path_group: group,
            status,
            duration_ms,
            bytes,
        });
    };
    use http_body::Body as _;
    let (parts, body) = res.into_parts();
    if let Some(n) = body.size_hint().exact() {
        make(Some(n as i64));
        return axum::response::Response::from_parts(parts, body);
    }
    axum::response::Response::from_parts(
        parts,
        axum::body::Body::new(CountedBody {
            inner: body,
            bytes: 0,
            done: Some(Box::new(move |b| make(Some(b)))),
        }),
    )
}

/// Passes a body through and reports its size once it ended (or was
/// dropped by a client that went away).
struct CountedBody {
    inner: axum::body::Body,
    bytes: i64,
    done: Option<Box<dyn FnOnce(i64) + Send>>,
}

impl CountedBody {
    fn finish(&mut self) {
        if let Some(f) = self.done.take() {
            f(self.bytes);
        }
    }
}

impl http_body::Body for CountedBody {
    type Data = axum::body::Bytes;
    type Error = axum::Error;

    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
        let p = std::pin::Pin::new(&mut self.inner).poll_frame(cx);
        match &p {
            std::task::Poll::Ready(Some(Ok(f))) => {
                if let Some(d) = f.data_ref() {
                    self.bytes += d.len() as i64;
                }
            }
            std::task::Poll::Ready(None) | std::task::Poll::Ready(Some(Err(_))) => self.finish(),
            _ => {}
        }
        p
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> http_body::SizeHint {
        self.inner.size_hint()
    }
}

impl Drop for CountedBody {
    fn drop(&mut self) {
        self.finish();
    }
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
const BRAND_FULL: &[u8] = include_bytes!("../../static/brand/full.webp");

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
        || path == "/first-run"
        || (method == Method::POST && path == "/api/first-run")
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
    axum::extract::State(app_state): axum::extract::State<crate::AppState>,
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
    // A router that has no password yet only offers the set-a-password page.
    if app_state.auth.syslogin.first_run_pending() {
        return if path.starts_with("/api/") || path == "/metrics" {
            (
                StatusCode::FORBIDDEN,
                axum::Json(serde_json::json!({"error": "first-run setup required: create the administrator account at /first-run"})),
            )
                .into_response()
        } else {
            axum::response::Redirect::to("/first-run").into_response()
        };
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
        if let (Some(k), Some(slot)) = (
            key.as_ref(),
            parts.extensions.get::<crate::state::accesslog::Slot>(),
        ) {
            slot.api_key(k.id, &k.name);
        }
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
            || path.starts_with("/api/system/users")
            || path.starts_with("/api/system/access-log")
            || path.starts_with("/api/system/audit-log");
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
            if let Some(slot) = parts.extensions.get::<crate::state::accesslog::Slot>() {
                slot.user(&session.username);
            }
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
/// `(release file text, PATRONUS_TIER, BOARD)` of `/etc/patronus-release` (or `PATRONUS_RELEASE_FILE`);
/// the tier is `standard` when the file says nothing.
pub(crate) fn release_info() -> (String, String, Option<String>) {
    let release = std::fs::read_to_string(
        std::env::var("PATRONUS_RELEASE_FILE").unwrap_or_else(|_| "/etc/patronus-release".into()),
    )
    .unwrap_or_default();
    let tier = release
        .lines()
        .find_map(|l| l.strip_prefix("PATRONUS_TIER="))
        .unwrap_or("standard")
        .trim()
        .to_string();
    let board = release
        .lines()
        .find_map(|l| l.strip_prefix("BOARD="))
        .map(|b| b.trim().to_string());
    (release, tier, board)
}

/// GET /api/features: the optional features this build contains. The UI hides
/// navigation entries for the rest (a router build has no VPN, HA, QoS ...), and
/// their APIs answer "not built" instead of pretending.
async fn features() -> axum::Json<serde_json::Value> {
    macro_rules! built {
        ($($f:literal),*) => { { let mut v: Vec<&str> = Vec::new(); $( if cfg!(feature = $f) { v.push($f); } )* v } };
    }
    let list = built![
        "vlan",
        "pppoe",
        "dhcp",
        "dns",
        "ntp",
        "multiwan",
        "wireguard",
        "ipsec",
        "openvpn",
        "l2tp",
        "totp",
        "ha",
        "qos",
        "syslog",
        "netflow",
        "igmp",
        "mdns",
        "udp-relay",
        "nat64",
        "upnp",
        "vrf",
        "web-proxy",
        "reverse-proxy",
        "intrusion-detection",
        "dynamic-routing",
        "sdwan-edge",
        "ldap",
        "plugins",
        "segmentation",
        "wifi-ap",
        "guest"
    ];
    let role = api::wifi::role();
    let (_, tier, board) = release_info();
    axum::Json(serde_json::json!({
        "features": list,
        "role": role.as_str(),
        "tier": tier,
        "board": board,
        "wifi_backend": patronus_network::apwifi::Paths::default().present(),
        "absent": absent_features(&list, &tier, role),
        "board_settings": board_settings(),
    }))
}

/// Features that are the main router's job when this unit is an access point
/// (the System page list and the pages of left-out features explain that).
pub(crate) const AP_ROUTER_JOBS: &[&str] = &[
    "dhcp",
    "dns",
    "segmentation",
    "guest",
    "multiwan",
    "pppoe",
    "nat64",
    "upnp",
    "igmp",
    "qos",
    "ha",
    "sdwan-edge",
    "dynamic-routing",
    "vrf",
    "web-proxy",
    "reverse-proxy",
];

/// Settings the image declares for this hardware (`/run/patronus/board-settings.json`, or
/// `PATRONUS_BOARD_SETTINGS_FILE`): written by the board's scripts at boot and whenever their state changes
/// (e.g. the Slate's 5 GHz Wi-Fi uplink, off by default because its radio's firmware fails as client and access
/// point at once). Each entry is a typed key with its value, the board default, the allowed values, why the
/// default is what it is, where to change it and the live state. Shown on the System page; a board without the
/// file has none.
pub(crate) fn board_settings() -> Vec<serde_json::Value> {
    let path = std::env::var("PATRONUS_BOARD_SETTINGS_FILE")
        .unwrap_or_else(|_| "/run/patronus/board-settings.json".into());
    board_settings_from(&std::fs::read_to_string(path).unwrap_or_default())
}

/// Parse the board settings file: a JSON array of objects with string `key`, `label` and `value` (required) and
/// optional `default`, `allowed` (array of strings), `reason`, `how` and `state`. Malformed entries are skipped.
pub(crate) fn board_settings_from(text: &str) -> Vec<serde_json::Value> {
    let Ok(serde_json::Value::Array(items)) = serde_json::from_str::<serde_json::Value>(text)
    else {
        return Vec::new();
    };
    items
        .into_iter()
        .filter_map(|v| {
            let o = v.as_object()?;
            let s = |k: &str| o.get(k).and_then(|x| x.as_str()).map(str::to_string);
            let allowed: Vec<String> = o
                .get("allowed")
                .and_then(|a| a.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|x| x.as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default();
            Some(serde_json::json!({
                "key": s("key")?,
                "label": s("label")?,
                "value": s("value")?,
                "default": s("default"),
                "allowed": allowed,
                "reason": s("reason"),
                "how": s("how"),
                "state": s("state"),
            }))
        })
        .collect()
}

#[cfg(test)]
mod board_settings_tests {
    use super::board_settings_from;

    #[test]
    fn reads_typed_entries_and_skips_malformed_ones() {
        let v = board_settings_from(
            r#"[{"key":"UPLINK5","label":"5 GHz Wi-Fi uplink","value":"off","default":"off","allowed":["on","off"],
                 "reason":"firmware fails as client and AP","how":"UPLINK5=on in unit.conf","state":"off"},
                {"label":"no key"}, 7]"#,
        );
        assert_eq!(v.len(), 1);
        assert_eq!(v[0]["key"], "UPLINK5");
        assert_eq!(v[0]["value"], "off");
        assert_eq!(v[0]["allowed"], serde_json::json!(["on", "off"]));
        assert_eq!(v[0]["reason"], "firmware fails as client and AP");
    }

    #[test]
    fn missing_or_garbage_file_means_no_settings() {
        assert!(board_settings_from("").is_empty());
        assert!(board_settings_from("{\"key\":1}").is_empty());
        assert!(board_settings_from("not json").is_empty());
    }

    #[test]
    fn optional_fields_may_be_absent() {
        let v = board_settings_from(r#"[{"key":"K","label":"L","value":"x"}]"#);
        assert_eq!(v.len(), 1);
        assert!(v[0]["reason"].is_null());
        assert_eq!(v[0]["allowed"], serde_json::json!([]));
    }
}

/// What a user may look for and not find on this unit, and why: features
/// this build leaves out, and (on an access point) the router functions the
/// main router provides. Shown on the System page, so a hidden menu entry
/// is explained instead of silently missing.
pub fn absent_features(
    built: &[&str],
    tier: &str,
    role: api::setup::DeviceRole,
) -> Vec<serde_json::Value> {
    const OPTIONAL: &[(&str, &str)] = &[
        ("wireguard", "WireGuard VPN"),
        ("ipsec", "IPsec VPN"),
        ("openvpn", "OpenVPN"),
        ("l2tp", "L2TP VPN server"),
        ("ntp", "NTP time server for the network"),
        ("syslog", "Remote syslog forwarding"),
        ("ha", "High availability (VRRP)"),
        ("qos", "Traffic shaping (SQM)"),
        ("multiwan", "Multi-WAN failover / load balancing"),
        ("pppoe", "PPPoE WAN"),
        ("vlan", "VLANs"),
        ("netflow", "NetFlow export"),
        ("igmp", "IGMP proxy"),
        ("mdns", "mDNS repeater (device discovery across networks)"),
        (
            "udp-relay",
            "UDP broadcast relay (discovery across segments)",
        ),
        ("nat64", "NAT64 / DNS64"),
        ("upnp", "UPnP / NAT-PMP"),
        ("vrf", "VRFs"),
        ("web-proxy", "Web proxy"),
        ("reverse-proxy", "Reverse proxy / load balancer"),
        ("intrusion-detection", "Intrusion detection (Suricata)"),
        ("dynamic-routing", "BGP / OSPF"),
        ("sdwan-edge", "SD-WAN edge"),
        ("totp", "Two-factor login (TOTP)"),
        ("ldap", "LDAP / Active Directory login"),
        ("plugins", "Add-on packages"),
        ("dhcp", "DHCP server"),
        ("dns", "DNS resolver"),
        ("segmentation", "Device segmentation"),
        ("guest", "Guest network"),
    ];
    let ap = role == api::setup::DeviceRole::Ap;
    let router_job = AP_ROUTER_JOBS;
    let mut out = Vec::new();
    for (f, label) in OPTIONAL {
        let reason = if ap && router_job.contains(f) {
            "this unit is an access point: the main router does this for the network"
        } else if built.contains(f) {
            continue;
        } else if tier == "embedded" {
            "not included in this router-tier image (kept small for the device's flash and memory)"
        } else {
            "not built into this installation (its USE flag is off)"
        };
        out.push(serde_json::json!({ "feature": f, "label": label, "reason": reason }));
    }
    if ap {
        for (label, why) in [
            (
                "Routing, gateways and NAT",
                "this unit is an access point: the main router routes and translates addresses",
            ),
            (
                "Traffic insights",
                "this unit is an access point: traffic is bridged, the main router sees the flows",
            ),
        ] {
            out.push(serde_json::json!({ "feature": serde_json::Value::Null, "label": label, "reason": why }));
        }
    }
    out
}

fn api_routes() -> Router<AppState> {
    Router::new()
        .route("/features", get(features))
        .route("/auth/login", post(crate::auth::login))
        .route("/auth/logout", post(crate::auth::logout))
        .route("/auth/me", get(crate::auth::current_user))
        .route("/auth/password", post(crate::auth::change_password))
        .route("/auth/2fa/setup", post(crate::auth::totp_setup))
        .route("/auth/2fa/enable", post(crate::auth::totp_enable))
        .route("/auth/2fa/disable", post(crate::auth::totp_disable))
        .merge(api::status::router())
        .merge(api::firewall::router())
        .merge(api::states::router())
        .merge(api::lan::router())
        .merge(api::ha::router())
        .merge(api::qos::router())
        .merge(api::insights::router())
        .merge(api::insight_history::router())
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
        .merge(api::accesslog::router())
        .merge(api::apikeys::router())
        .merge(api::groups::router())
        .merge(api::backup_targets::router())
        .merge(api::setup::router())
        .merge(api::authservers::router())
        .merge(api::telemetry::router())
        .merge(api::wifi::router())
        .merge(api::wifi_uplink::router())
        .merge(api::device::router())
}

#[cfg(test)]
mod honesty_tests;
#[cfg(test)]
mod insight_api_tests;

#[cfg(test)]
mod lane_fh_tests;

#[cfg(all(test, feature = "segmentation"))]
mod seg_tests;

#[cfg(all(test, feature = "guest"))]
mod guest_tests;

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
            "/licenses",
            "/licenses/third-party.txt",
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

    /// System-account login end to end (shadow backend over a temp etc):
    /// groups decide the role, everything else is the same generic 401,
    /// the old built-in admin is read-only and then retired by the first
    /// system administrator, and a system account's password is the
    /// system's.
    #[tokio::test]
    async fn web_login_is_system_users_by_group_and_legacy_accounts_are_read_only() {
        use crate::syslogin::{Mode, SysLogin, WebAuthConfig};
        use patronus_network::sysauth::Backend;
        let dir = std::env::temp_dir().join(format!("patronus-web-sys-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let pw = "Sys-Passw0rd-Ok-1";
        let h = pwhash::sha512_crypt::hash(pw).unwrap();
        std::fs::write(dir.join("passwd"), "root:x:0:0::/r:/bin/sh\nboss:x:1000:1000::/h:/bin/sh\nviewer:x:1001:1001::/h:/bin/sh\nplain:x:1002:1002::/h:/bin/sh\n").unwrap();
        std::fs::write(dir.join("group"), "root:x:0:\nwheel:x:10:boss,root\nboss:x:1000:\nviewer:x:1001:\nplain:x:1002:\nauditors:x:2000:viewer\n").unwrap();
        std::fs::write(
            dir.join("shadow"),
            format!("root:{h}:1::::::\nboss:{h}:1::::::\nviewer:{h}:1::::::\nplain:{h}:1::::::\n"),
        )
        .unwrap();
        let config_store = std::sync::Arc::new(
            patronus_config::ConfigStore::open(dir.join("config.db"))
                .await
                .unwrap(),
        );
        let mut state = crate::AppState::new(
            config_store,
            std::sync::Arc::new(crate::state::firewall::NoopApplier),
        )
        .await
        .unwrap();
        let mut sys = SysLogin::new(
            WebAuthConfig {
                readonly_groups: vec!["auditors".into()],
                ..Default::default()
            },
            Mode::Direct(Backend::Shadow(dir.clone())),
        );
        sys.legacy_clamp = true;
        state.auth.syslogin = sys;
        // a pre-PAM account set: the built-in admin (an admin by role)
        state
            .auth
            .user_store
            .provision_admin(Some("Legacy-Passw0rd-1".into()), &dir.join("pw"))
            .await
            .unwrap();
        let app = super::build_router(state, std::sync::Arc::new(crate::WsBroadcaster::new()));
        let login = |u: &str, p: &str| {
            let app = app.clone();
            let body = format!(r#"{{"username":"{u}","password":"{p}"}}"#);
            async move {
                let r = app
                    .oneshot(req(Method::POST, "/api/auth/login", None, Some(&body)))
                    .await
                    .unwrap();
                let st = r.status();
                let cookie = r
                    .headers()
                    .get(header::SET_COOKIE)
                    .map(|c| c.to_str().unwrap().split(';').next().unwrap().to_string());
                let b = axum::body::to_bytes(r.into_body(), 1 << 20).await.unwrap();
                (st, cookie, String::from_utf8_lossy(&b).to_string())
            }
        };
        // legacy admin: signs in, but read-only
        let (st, _, b) = login("admin", "Legacy-Passw0rd-1").await;
        assert_eq!(st, StatusCode::OK, "{b}");
        assert!(
            b.contains("ReadOnly"),
            "legacy account must be read-only: {b}"
        );
        // generic refusals: wrong password, unknown, no group, root, bad name
        let mut bodies = Vec::new();
        for (u, p) in [
            ("boss", "wrong"),
            ("ghost", pw),
            ("plain", pw),
            ("root", pw),
        ] {
            let (st, cookie, b) = login(u, p).await;
            assert_eq!(st, StatusCode::UNAUTHORIZED, "{u}");
            assert!(cookie.is_none(), "{u}");
            bodies.push(b);
        }
        assert!(bodies.windows(2).all(|w| w[0] == w[1]), "{bodies:?}");
        // system users by group
        let (st, cookie, b) = login("viewer", pw).await;
        assert_eq!(st, StatusCode::OK, "{b}");
        assert!(b.contains("ReadOnly"), "{b}");
        let (st, cookie_boss, b) = login("boss", pw).await;
        assert_eq!(st, StatusCode::OK, "{b}");
        assert!(b.contains("Admin"), "{b}");
        let _ = cookie;
        // the first system administrator retired the built-in admin
        let (st, _, _) = login("admin", "Legacy-Passw0rd-1").await;
        assert_eq!(st, StatusCode::UNAUTHORIZED);
        // a system account cannot set a password here
        let r = app
            .clone()
            .oneshot(req(
                Method::POST,
                "/api/auth/password",
                cookie_boss.as_deref(),
                Some(&format!(
                    r#"{{"current_password":"{pw}","new_password":"Brand-New-Passw0rd-9"}}"#
                )),
            ))
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::BAD_REQUEST);
        let (st, _, _) = login("boss", pw).await;
        assert_eq!(st, StatusCode::OK, "the system password is unchanged");
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

    async fn body_json(r: axum::response::Response) -> serde_json::Value {
        let b = axum::body::to_bytes(r.into_body(), 1 << 20).await.unwrap();
        serde_json::from_slice(&b).unwrap_or(serde_json::Value::Null)
    }

    fn set_cookies(r: &axum::response::Response) -> Vec<String> {
        r.headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .map(|v| v.to_str().unwrap().to_string())
            .collect()
    }

    /// Browsers on HTTP/2 send every cookie as its own `cookie` header field.
    /// With any other cookie stored for the router's address (one an older
    /// firmware left there), the session cookie came second and was ignored:
    /// sign-in succeeded and every page bounced back to the login page.
    #[tokio::test]
    async fn session_cookie_in_a_later_cookie_field_is_honoured() {
        let (app, pw) = app().await;
        let login = format!(r#"{{"username":"admin","password":"{pw}"}}"#);
        let r = app
            .clone()
            .oneshot(req(Method::POST, "/api/auth/login", None, Some(&login)))
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::OK);
        let session = set_cookies(&r)[0].split(';').next().unwrap().to_string();
        for (fields, what) in [
            (
                vec!["Admin-Token=0123456789abcdef", session.as_str()],
                "foreign cookie first, own field",
            ),
            (
                vec![session.as_str(), "Admin-Token=0123456789abcdef"],
                "session first",
            ),
            (
                vec!["lang=Espa\u{f1}ol", session.as_str()],
                "non-ASCII cookie in its own field",
            ),
            (
                vec!["session_id=stale-0000", session.as_str()],
                "stale duplicate in front",
            ),
        ] {
            for uri in ["/", "/system", "/api/auth/me"] {
                let mut b = Request::builder().method(Method::GET).uri(uri);
                for f in &fields {
                    b = b.header(
                        header::COOKIE,
                        axum::http::HeaderValue::from_bytes(f.as_bytes()).unwrap(),
                    );
                }
                let r = app
                    .clone()
                    .oneshot(b.body(Body::empty()).unwrap())
                    .await
                    .unwrap();
                assert_eq!(r.status(), StatusCode::OK, "{what}: {uri}");
            }
        }
        // the same pairs in ONE field (HTTP/1.1), with a non-ASCII neighbour
        let one = format!("lang=Espa\u{f1}ol; {session}");
        let r = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/system")
                    .header(
                        header::COOKIE,
                        axum::http::HeaderValue::from_bytes(one.as_bytes()).unwrap(),
                    )
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            r.status(),
            StatusCode::OK,
            "non-ASCII pair in the same field"
        );
    }

    /// The login page and a successful sign-in remove cookies Patronus never
    /// sets (left at the address by a previous firmware), keep the session
    /// cookie, and the page clears the browser's HTTP cache for the address.
    #[tokio::test]
    async fn login_page_and_sign_in_clear_foreign_state() {
        let (app, pw) = app().await;
        let r = app
            .clone()
            .oneshot(req(
                Method::GET,
                "/login",
                Some("Admin-Token=abc; session_id=whatever; sysauth_https=x"),
                None,
            ))
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::OK);
        assert_eq!(r.headers()["clear-site-data"], "\"cache\"");
        let sc = set_cookies(&r);
        assert!(
            sc.iter()
                .any(|c| c.starts_with("Admin-Token=; Max-Age=0; Path=/")),
            "{sc:?}"
        );
        assert!(
            sc.iter()
                .any(|c| c.starts_with("sysauth_https=; Max-Age=0; Path=/")),
            "{sc:?}"
        );
        assert!(!sc.iter().any(|c| c.starts_with("session_id=")), "{sc:?}");
        // no foreign cookies: nothing is set
        let r = app
            .clone()
            .oneshot(req(Method::GET, "/login", None, None))
            .await
            .unwrap();
        assert!(set_cookies(&r).is_empty());

        let login = format!(r#"{{"username":"admin","password":"{pw}"}}"#);
        let r = app
            .clone()
            .oneshot(req(
                Method::POST,
                "/api/auth/login",
                Some("Admin-Token=abc"),
                Some(&login),
            ))
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::OK);
        let sc = set_cookies(&r);
        assert!(
            sc[0].starts_with("session_id=") && !sc[0].starts_with("session_id=;"),
            "{sc:?}"
        );
        assert!(
            sc.iter()
                .any(|c| c.starts_with("Admin-Token=; Max-Age=0; Path=/")),
            "{sc:?}"
        );
    }

    /// A refusal by the per-account back-off says so, with the wait, instead
    /// of "Invalid username or password" (which sent people hunting for a
    /// typo in a password that was right).
    #[tokio::test]
    async fn account_backoff_is_reported_as_such() {
        let (app, _) = app().await;
        let bad = r#"{"username":"ghost","password":"Wrong-Passw0rd!"}"#;
        // failures from different addresses: the per-address lockout stays off
        for i in 0..5 {
            let r = app
                .clone()
                .oneshot(from_ip(
                    req(Method::POST, "/api/auth/login", None, Some(bad)),
                    &format!("198.51.100.{}", i + 1),
                ))
                .await
                .unwrap();
            assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
            assert_eq!(body_json(r).await["error"], "Invalid username or password");
        }
        let r = app
            .clone()
            .oneshot(from_ip(
                req(Method::POST, "/api/auth/login", None, Some(bad)),
                "198.51.100.99",
            ))
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(r.headers().contains_key(header::RETRY_AFTER));
        let v = body_json(r).await;
        let msg = v["error"].as_str().unwrap();
        assert!(
            msg.starts_with("Too many failed sign-in attempts for this account; try again in "),
            "{msg}"
        );
        assert!(v["retry_after_secs"].as_u64().unwrap() >= 1);
    }

    /// The per-address lockout names the address and the wait.
    #[tokio::test]
    async fn address_lockout_message_names_the_wait() {
        let (app, _) = app().await;
        let bad = r#"{"username":"admin","password":"Wrong-Passw0rd!"}"#;
        for _ in 0..crate::auth::MAX_LOGIN_FAILURES {
            app.clone()
                .oneshot(from_ip(
                    req(Method::POST, "/api/auth/login", None, Some(bad)),
                    "203.0.113.77",
                ))
                .await
                .unwrap();
        }
        let r = app
            .clone()
            .oneshot(from_ip(
                req(Method::POST, "/api/auth/login", None, Some(bad)),
                "203.0.113.77",
            ))
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::TOO_MANY_REQUESTS);
        let v = body_json(r).await;
        let msg = v["error"].as_str().unwrap();
        assert!(
            msg.starts_with("Too many failed sign-in attempts from this address; try again in "),
            "{msg}"
        );
        assert!(msg.ends_with("minutes."), "{msg}");
    }
}
