//! Patronus Web Interface
//!
//! Provides the web-based management interface for Patronus.

use std::net::SocketAddr;

pub mod auth;
pub mod geo_centroid;
pub mod qrcode;
pub mod routes;
pub mod state;
pub mod templates;
pub mod tls;
#[cfg(feature = "totp")]
pub mod totp;
pub mod websocket;

pub use auth::{AdminUser, AuthUser, SessionStore};
pub use state::AppState;
pub use websocket::WsBroadcaster;

/// Create the web application router
pub fn create_app(state: AppState, ws_broadcaster: std::sync::Arc<WsBroadcaster>) -> axum::Router {
    routes::build_router(state, ws_broadcaster)
}

/// Wire up the background tasks (session cleanup, secret rotation,
/// websocket broadcasters) and build the router. Shared by both the
/// plain-HTTP and TLS listeners.
fn prepare_app(state: AppState) -> axum::Router {
    let ws_broadcaster = std::sync::Arc::new(WsBroadcaster::new());

    // Start session cleanup task
    let cleanup_state = state.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(3600));
        loop {
            interval.tick().await;
            cleanup_state.auth.session_store.cleanup_expired().await;
            cleanup_state.auth.login_throttle.cleanup_expired();
            tracing::debug!("Cleaned up expired sessions");
        }
    });

    // Start secret rotation enforcement task. `enforce_rotation_policy()` was
    // previously implemented but never actually invoked anywhere in the
    // codebase, so no secret was ever auto-rotated in a running process --
    // only ever on an ad-hoc call from a test. Run it on the same hourly
    // cadence as session cleanup.
    let rotation_state = state.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(3600));
        loop {
            interval.tick().await;
            match rotation_state.secrets.enforce_rotation_policy().await {
                Ok(result) => {
                    if !result.auto_rotated.is_empty() {
                        tracing::info!(
                            "Auto-rotated {} secret(s): {:?}",
                            result.auto_rotated.len(),
                            result.auto_rotated
                        );
                    }
                    if !result.needs_manual_rotation.is_empty() {
                        tracing::warn!(
                            "{} secret(s) need manual rotation: {:?}",
                            result.needs_manual_rotation.len(),
                            result.needs_manual_rotation
                        );
                    }
                }
                Err(e) => {
                    tracing::error!("Failed to enforce secret rotation policy: {}", e);
                }
            }
        }
    });

    // Start WebSocket broadcaster tasks (measured metrics only)
    websocket::start_metrics_broadcaster(ws_broadcaster.clone(), state.clone());

    create_app(state, ws_broadcaster)
}

/// Start the web server over plain HTTP. Kept for local development/tests;
/// the shipped binary serves TLS by default via [`serve_tls`] since the
/// dashboard is documented and configured as an HTTPS service.
pub async fn serve(addr: SocketAddr, state: AppState) -> anyhow::Result<()> {
    let app = prepare_app(state);

    tracing::info!("Starting web server on http://{}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    // Connect info: the login throttle keys failed attempts by client IP.
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;

    Ok(())
}

/// Start the web server over HTTPS using a self-signed certificate,
/// generating one on first run if none exists yet under `tls_dir`.
pub async fn serve_tls(
    addr: SocketAddr,
    state: AppState,
    tls_dir: &std::path::Path,
) -> anyhow::Result<()> {
    // Pick the crypto provider explicitly (Err = one is already installed).
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let app = with_secure_cookies(prepare_app(state));

    let tls_config = tls::ensure_self_signed_cert(tls_dir).await?;

    tracing::info!("Starting web server on https://{}", addr);

    axum_server::bind_rustls(addr, tls_config)
        .serve(app.into_make_service_with_connect_info::<SocketAddr>())
        .await?;

    Ok(())
}

/// Over HTTPS, every cookie the dashboard sets gets the `Secure`
/// attribute, so the browser never sends the session cookie over plain
/// HTTP. Without it, anyone who can get the browser to load
/// `http://<router>:8443/...` (an injected link or redirect on the LAN or
/// a hotel network) sees the admin session id in clear text.
///
/// Only the TLS listener uses this. The plain-HTTP [`serve`] (local
/// development, `patronus-cli web`) keeps cookies without `Secure`,
/// because browsers drop `Secure` cookies set over HTTP and login would
/// stop working there.
pub fn with_secure_cookies(app: axum::Router) -> axum::Router {
    app.layer(axum::middleware::map_response(
        |mut response: axum::response::Response| async move {
            mark_cookies_secure(response.headers_mut());
            response
        },
    ))
}

/// Add `; Secure` to every `Set-Cookie` header that lacks it.
fn mark_cookies_secure(headers: &mut axum::http::HeaderMap) {
    use axum::http::{header::SET_COOKIE, HeaderValue};
    if !headers.contains_key(SET_COOKIE) {
        return;
    }
    let cookies: Vec<HeaderValue> = headers
        .get_all(SET_COOKIE)
        .iter()
        .map(|v| match v.to_str() {
            Ok(s) if !has_secure_attribute(s) => {
                HeaderValue::from_str(&format!("{s}; Secure")).unwrap_or_else(|_| v.clone())
            }
            _ => v.clone(),
        })
        .collect();
    headers.remove(SET_COOKIE);
    for c in cookies {
        headers.append(SET_COOKIE, c);
    }
}

/// True if the cookie already has a `Secure` attribute. The name=value
/// pair is skipped, so a cookie whose value is "Secure" doesn't count.
fn has_secure_attribute(cookie: &str) -> bool {
    cookie
        .split(';')
        .skip(1)
        .any(|a| a.trim().eq_ignore_ascii_case("secure"))
}

#[cfg(test)]
mod secure_cookie_tests {
    use axum::body::Body;
    use axum::http::{header, HeaderMap, HeaderValue, Method, Request, StatusCode};
    use tower::ServiceExt;

    #[test]
    fn secure_is_added_once_to_every_cookie() {
        let mut h = HeaderMap::new();
        h.append(
            header::SET_COOKIE,
            HeaderValue::from_static("session_id=abc; HttpOnly; Path=/"),
        );
        h.append(
            header::SET_COOKIE,
            HeaderValue::from_static("other=1; Path=/; secure"),
        );
        h.append(header::SET_COOKIE, HeaderValue::from_static("trap=Secure"));
        super::mark_cookies_secure(&mut h);
        let got: Vec<&str> = h
            .get_all(header::SET_COOKIE)
            .iter()
            .map(|v| v.to_str().unwrap())
            .collect();
        assert_eq!(
            got,
            [
                "session_id=abc; HttpOnly; Path=/; Secure",
                "other=1; Path=/; secure",
                "trap=Secure; Secure",
            ]
        );

        let mut none = HeaderMap::new();
        super::mark_cookies_secure(&mut none);
        assert!(none.is_empty());
    }

    fn req(method: Method, uri: &str, cookie: Option<&str>, body: Option<String>) -> Request<Body> {
        let mut b = Request::builder().method(method).uri(uri);
        if let Some(c) = cookie {
            b = b.header(header::COOKIE, c);
        }
        if body.is_some() {
            b = b.header(header::CONTENT_TYPE, "application/json");
        }
        b.body(body.map(Body::from).unwrap_or_else(Body::empty))
            .unwrap()
    }

    fn set_cookie(r: &axum::response::Response) -> String {
        r.headers()[header::SET_COOKIE]
            .to_str()
            .unwrap()
            .to_string()
    }

    /// The real login and logout routes, behind the layer `serve_tls`
    /// uses, set `Secure` cookies; the plain-HTTP router does not.
    #[tokio::test]
    async fn the_tls_app_sets_secure_session_cookies() {
        let dir = std::env::temp_dir().join(format!(
            "patronus-web-secure-cookie-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let store = std::sync::Arc::new(
            patronus_config::ConfigStore::open(dir.join("config.db"))
                .await
                .unwrap(),
        );
        let state = crate::AppState::new(
            store,
            std::sync::Arc::new(crate::state::firewall::NoopApplier),
        )
        .await
        .unwrap();
        let pw = "Secure-Cookie-Passw0rd!".to_string();
        state
            .auth
            .user_store
            .provision_admin(Some(pw.clone()), &dir.join("pw"))
            .await
            .unwrap();
        let plain =
            crate::routes::build_router(state, std::sync::Arc::new(crate::WsBroadcaster::new()));
        let tls = super::with_secure_cookies(plain.clone());
        let login = format!(r#"{{"username":"admin","password":"{pw}"}}"#);

        let r = plain
            .clone()
            .oneshot(req(
                Method::POST,
                "/api/auth/login",
                None,
                Some(login.clone()),
            ))
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::OK);
        assert!(
            !super::has_secure_attribute(&set_cookie(&r)),
            "{}",
            set_cookie(&r)
        );

        let r = tls
            .clone()
            .oneshot(req(Method::POST, "/api/auth/login", None, Some(login)))
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::OK);
        let c = set_cookie(&r);
        assert!(
            c.starts_with("session_id=") && c.ends_with("; Secure"),
            "{c}"
        );
        assert!(
            c.contains("HttpOnly") && c.contains("SameSite=Strict"),
            "{c}"
        );
        let session = c.split(';').next().unwrap().to_string();

        let r = tls
            .oneshot(req(Method::POST, "/api/auth/logout", Some(&session), None))
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::OK);
        let c = set_cookie(&r);
        assert!(c.contains("Max-Age=0") && c.ends_with("; Secure"), "{c}");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
