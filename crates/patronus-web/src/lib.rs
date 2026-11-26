//! Patronus Web Interface
//!
//! Provides the web-based management interface for Patronus.

use std::net::SocketAddr;

pub mod apikeys;
pub mod auth;
pub mod backup_remote;
pub mod geo_centroid;
pub mod i18n;
#[cfg(feature = "ldap")]
pub mod ldap;
pub mod qrcode;
pub mod radius;
pub mod rbac;
pub mod routes;
pub mod server;
pub mod state;
pub mod syslogin;
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

    // Boot rollback (router tier): the guard's events become audit entries even when nobody opens the firmware page.
    // It writes its state to a world-readable file (PATRONUS_BOOTGUARD_STATUS) at boot and on every change.
    let guard_state = state.clone();
    tokio::spawn(async move {
        let path = std::env::var("PATRONUS_BOOTGUARD_STATUS")
            .unwrap_or_else(|_| "/run/patronus/boot-guard.json".into());
        let secs = std::env::var("PATRONUS_BOOTGUARD_AUDIT_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(60u64)
            .max(5);
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(secs));
        loop {
            interval.tick().await;
            let Ok(t) = tokio::fs::read_to_string(&path).await else {
                continue;
            };
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&t) {
                crate::routes::api::system::bootguard_audit(&guard_state, &v).await;
            }
        }
    });

    // Guest network: expire Wi-Fi vouchers (and follow a changed UTC offset) every minute.
    #[cfg(feature = "guest")]
    {
        let guest_state = state.clone();
        tokio::spawn(async move {
            let secs = std::env::var("PATRONUS_GUEST_TICK_SECS")
                .ok()
                .and_then(|s| s.parse::<u64>().ok())
                .filter(|s| *s > 0)
                .unwrap_or(60);
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(secs));
            let mut last = None;
            loop {
                interval.tick().await;
                guest_state.lan.guest_tick(&mut last).await;
            }
        });
    }

    // Remote / encrypted automatic backups: upload to every target that is due.
    let backup_state = state.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(60));
        loop {
            interval.tick().await;
            backup_state.backup_targets.run_due().await;
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
    #[cfg(feature = "tls-rustls")]
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let app = with_secure_cookies(prepare_app(state));

    let tls_config = tls::ensure_self_signed_cert(tls_dir).await?;

    tracing::info!("Starting web server on https://{}", addr);

    #[cfg(feature = "tls-rustls")]
    axum_server::bind_rustls(addr, tls_config)
        .serve(app.into_make_service_with_connect_info::<SocketAddr>())
        .await?;
    #[cfg(all(feature = "tls-openssl", not(feature = "tls-rustls")))]
    axum_server::bind_openssl(addr, tls_config)
        .serve(app.into_make_service_with_connect_info::<SocketAddr>())
        .await?;

    Ok(())
}

/// The `Location` of the HTTP -> HTTPS redirect: the host the client asked
/// for (any port stripped, an IPv6 literal keeps its brackets), the HTTPS
/// port (443 is omitted) and the original path and query. A missing or
/// unusable Host header falls back to `patronus`.
pub fn redirect_location(host_header: &str, path_and_query: &str, https_port: u16) -> String {
    let h = host_header.trim();
    let host = if let Some(rest) = h.strip_prefix('[') {
        match rest.split_once(']') {
            Some((a, _)) if !a.is_empty() => format!("[{a}]"),
            _ => String::new(),
        }
    } else {
        h.split(':').next().unwrap_or("").to_string()
    };
    // a Host header is attacker-controlled text that ends up in a header:
    // keep only hostname / address characters
    let host = if host.is_empty()
        || !host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '[' | ']' | ':'))
    {
        "patronus".to_string()
    } else {
        host
    };
    let pq = if path_and_query.starts_with('/') && !path_and_query.contains(['\r', '\n']) {
        path_and_query
    } else {
        "/"
    };
    if https_port == 443 {
        format!("https://{host}{pq}")
    } else {
        format!("https://{host}:{https_port}{pq}")
    }
}

fn redirect_app(https_port: u16) -> axum::Router {
    use axum::http::{header, HeaderMap, StatusCode, Uri};
    axum::Router::new().fallback(move |headers: HeaderMap, uri: Uri| async move {
        let host = headers
            .get(header::HOST)
            .and_then(|h| h.to_str().ok())
            .unwrap_or("");
        let pq = uri.path_and_query().map(|p| p.as_str()).unwrap_or("/");
        let loc = redirect_location(host, pq, https_port);
        (StatusCode::PERMANENT_REDIRECT, [(header::LOCATION, loc)])
    })
}

/// Plain-HTTP listener that only answers `308` to the HTTPS URL (OpenWrt-style
/// "http://192.168.1.1 -> https://192.168.1.1"). It serves nothing else: no
/// pages, no login, no cookies. `https_port` 443 is omitted from the Location.
pub async fn serve_http_redirect(addr: SocketAddr, https_port: u16) -> anyhow::Result<()> {
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(
        "HTTP redirect on http://{} -> https port {}",
        addr,
        https_port
    );
    axum::serve(listener, redirect_app(https_port)).await?;
    Ok(())
}

/// What [`serve_web`] bound.
#[derive(Debug, Clone, Default)]
pub struct Bound {
    pub https: Vec<SocketAddr>,
    pub redirect: Vec<SocketAddr>,
    pub failed: Vec<(SocketAddr, String)>,
}

/// Every address the settings ask for: (HTTPS addresses, redirect addresses).
pub fn listener_addrs(
    s: &patronus_config::webui::WebSettings,
) -> (Vec<SocketAddr>, Vec<SocketAddr>) {
    let ips: Vec<std::net::IpAddr> = s.listen.iter().filter_map(|a| a.parse().ok()).collect();
    let mut https = Vec::new();
    let mut redirect = Vec::new();
    for ip in &ips {
        for p in std::iter::once(&s.https_port).chain(s.extra_https_ports.iter()) {
            https.push(SocketAddr::new(*ip, *p));
        }
        if s.http_redirect_port != 0 {
            redirect.push(SocketAddr::new(*ip, s.http_redirect_port));
        }
    }
    (https, redirect)
}

/// Serve the web UI as the settings say: HTTPS on the main port and every
/// extra port, and a plain-HTTP listener that only redirects to the main
/// HTTPS port. Each address is bound on its own: one that cannot be bound
/// (port in use, no permission for a port below 1024) is logged and skipped,
/// and the call fails only when no HTTPS listener could be bound at all.
/// The redirect always points at the main HTTPS port.
pub async fn serve_web(
    settings: patronus_config::webui::WebSettings,
    state: AppState,
    tls_dir: &std::path::Path,
    on_bound: Option<tokio::sync::oneshot::Sender<Bound>>,
) -> anyhow::Result<()> {
    #[cfg(feature = "tls-rustls")]
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let app = with_secure_cookies(prepare_app(state));
    let tls_config =
        tls::configured_or_self_signed(&settings.tls_cert, &settings.tls_key, tls_dir).await?;
    let (https, redirect) = listener_addrs(&settings);
    let mut bound = Bound::default();
    let mut set = tokio::task::JoinSet::new();

    for addr in https {
        match std::net::TcpListener::bind(addr) {
            Ok(l) => {
                bound.https.push(addr);
                let app = app.clone();
                let cfg = tls_config.clone();
                #[cfg(feature = "tls-rustls")]
                let server = axum_server::from_tcp(l)
                    .acceptor(axum_server::tls_rustls::RustlsAcceptor::new(cfg));
                #[cfg(all(feature = "tls-openssl", not(feature = "tls-rustls")))]
                let server = axum_server::from_tcp(l)
                    .acceptor(axum_server::tls_openssl::OpenSSLAcceptor::new(cfg));
                tracing::info!("Web interface listening on https://{addr}");
                set.spawn(async move {
                    server
                        .serve(app.into_make_service_with_connect_info::<SocketAddr>())
                        .await
                        .map_err(|e| format!("https {addr}: {e}"))
                });
            }
            Err(e) => {
                tracing::error!("cannot listen on https://{addr}: {e}");
                bound.failed.push((addr, e.to_string()));
            }
        }
    }
    if bound.https.is_empty() {
        if let Some(tx) = on_bound {
            let _ = tx.send(bound.clone());
        }
        anyhow::bail!(
            "no HTTPS listener could be bound ({})",
            bound
                .failed
                .iter()
                .map(|(a, e)| format!("{a}: {e}"))
                .collect::<Vec<_>>()
                .join("; ")
        );
    }

    for addr in redirect {
        match std::net::TcpListener::bind(addr).and_then(|l| {
            l.set_nonblocking(true)?;
            tokio::net::TcpListener::from_std(l)
        }) {
            Ok(l) => {
                bound.redirect.push(addr);
                let port = settings.https_port;
                tracing::info!("HTTP redirect on http://{addr} -> https port {port}");
                set.spawn(async move {
                    axum::serve(l, redirect_app(port))
                        .await
                        .map_err(|e| format!("http redirect {addr}: {e}"))
                });
            }
            Err(e) => {
                tracing::error!("cannot listen on http://{addr}: {e}");
                bound.failed.push((addr, e.to_string()));
            }
        }
    }
    if let Some(tx) = on_bound {
        let _ = tx.send(bound);
    }
    while let Some(r) = set.join_next().await {
        match r {
            Ok(Ok(())) => {}
            Ok(Err(e)) => tracing::error!("listener ended: {e}"),
            Err(e) => tracing::error!("listener task: {e}"),
        }
    }
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

#[cfg(test)]
mod listener_tests {
    use super::*;
    use patronus_config::webui::WebSettings;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn redirect_location_keeps_host_path_and_omits_443() {
        assert_eq!(
            redirect_location("192.0.2.1", "/a?b=1", 443),
            "https://192.0.2.1/a?b=1"
        );
        assert_eq!(
            redirect_location("router.lan:80", "/", 8443),
            "https://router.lan:8443/"
        );
        assert_eq!(
            redirect_location("[fd00::1]:80", "/x", 443),
            "https://[fd00::1]/x"
        );
        // no / hostile Host header, odd path: never echoed into the header
        assert_eq!(redirect_location("", "/", 443), "https://patronus/");
        assert_eq!(
            redirect_location("evil.example\r\nSet-Cookie: x=1", "/", 443),
            "https://patronus/"
        );
        assert_eq!(redirect_location("a", "//evil", 443), "https://a//evil");
        assert_eq!(redirect_location("a", "*", 443), "https://a/");
    }

    #[test]
    fn addresses_follow_the_settings() {
        let mut s = WebSettings {
            listen: vec!["10.0.0.1".into(), "127.0.0.1".into()],
            extra_https_ports: vec![8443],
            ..WebSettings::default()
        };
        let (https, redirect) = listener_addrs(&s);
        let t = |v: &[SocketAddr]| v.iter().map(|a| a.to_string()).collect::<Vec<_>>();
        assert_eq!(
            t(&https),
            [
                "10.0.0.1:443",
                "10.0.0.1:8443",
                "127.0.0.1:443",
                "127.0.0.1:8443"
            ]
        );
        assert_eq!(t(&redirect), ["10.0.0.1:80", "127.0.0.1:80"]);
        s.http_redirect_port = 0;
        s.extra_https_ports.clear();
        let (https, redirect) = listener_addrs(&s);
        assert_eq!(t(&https), ["10.0.0.1:443", "127.0.0.1:443"]);
        assert!(redirect.is_empty());
    }

    fn free_port() -> u16 {
        std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    }

    async fn test_state(dir: &std::path::Path) -> AppState {
        let store = std::sync::Arc::new(
            patronus_config::ConfigStore::open(dir.join("config.db"))
                .await
                .unwrap(),
        );
        crate::AppState::new(
            store,
            std::sync::Arc::new(crate::state::firewall::NoopApplier),
        )
        .await
        .unwrap()
    }

    async fn http_get(addr: SocketAddr, host: &str) -> String {
        let mut c = tokio::net::TcpStream::connect(addr).await.unwrap();
        c.write_all(
            format!("GET /login?next=%2F HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .await
        .unwrap();
        let mut out = String::new();
        let _ = c.read_to_string(&mut out).await;
        out
    }

    /// The real listeners: the main HTTPS port, an extra one and the HTTP
    /// redirect all come up from the settings; the redirect answers 308 to the
    /// MAIN https port and serves nothing else; a port that is taken is
    /// skipped (logged) while the rest keep working; with every HTTPS port
    /// taken the call fails instead of running without a UI.
    #[tokio::test]
    async fn serve_web_binds_what_the_settings_say() {
        let dir =
            std::env::temp_dir().join(format!("patronus-web-listen-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let tls = dir.join("tls");
        let tls2 = tls.clone();
        let (https, extra, redirect, taken) = (free_port(), free_port(), free_port(), free_port());
        // `taken` stays bound for the whole test
        let _hold = std::net::TcpListener::bind(("127.0.0.1", taken)).unwrap();
        let s = WebSettings {
            listen: vec!["127.0.0.1".into()],
            https_port: https,
            extra_https_ports: vec![extra, taken],
            http_redirect_port: redirect,
            ..WebSettings::default()
        };
        let state = test_state(&dir).await;
        let (tx, rx) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move { serve_web(s, state, &tls2, Some(tx)).await });
        let bound = rx.await.unwrap();
        assert_eq!(
            bound.https.iter().map(|a| a.port()).collect::<Vec<_>>(),
            [https, extra]
        );
        assert_eq!(
            bound.redirect.iter().map(|a| a.port()).collect::<Vec<_>>(),
            [redirect]
        );
        assert_eq!(bound.failed.len(), 1);
        assert_eq!(bound.failed[0].0.port(), taken);

        let r = http_get(SocketAddr::from(([127, 0, 0, 1], redirect)), "192.0.2.1:80").await;
        assert!(r.starts_with("HTTP/1.1 308"), "{r}");
        assert!(
            r.to_lowercase().contains(&format!(
                "location: https://192.0.2.1:{https}/login?next=%2f"
            )),
            "{r}"
        );
        // both HTTPS ports accept connections, and a TLS port never answers plain HTTP with content
        for p in [https, extra] {
            let r = http_get(SocketAddr::from(([127, 0, 0, 1], p)), "x").await;
            assert!(
                !r.starts_with("HTTP/1.1 200") && !r.starts_with("HTTP/1.1 308"),
                "{r:?}"
            );
        }
        task.abort();

        // nothing to serve on: an error, not a silent no-UI process
        let s = WebSettings {
            listen: vec!["127.0.0.1".into()],
            https_port: taken,
            extra_https_ports: vec![],
            http_redirect_port: 0,
            ..WebSettings::default()
        };
        std::fs::create_dir_all(dir.join("x")).unwrap();
        let state = test_state(&dir.join("x")).await;
        let e = serve_web(s, state, &tls, None)
            .await
            .unwrap_err()
            .to_string();
        assert!(e.contains("no HTTPS listener could be bound"), "{e}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
