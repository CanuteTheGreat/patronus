//! The portal's HTTP side (served by patronus-web on `captive.http_port` and,
//! with TLS, `captive.https_port`). Clients only reach it through the
//! redirects of `inet patronus_portal` (or by its URL); which zone and which
//! session a request belongs to is decided by the *client address* (and its
//! MAC from the neighbour table), never by anything the client sends.
//!
//! - any `GET` on the HTTP listener: the splash page, or (zone setting
//!   `https_login`, default) a redirect to `https://<router>/` (port 443,
//!   which the portal table sends to the HTTPS listener) with the page the
//!   client asked for in `redirurl`;
//! - `GET /` (HTTPS): splash page, or the status page when signed in;
//! - `POST /login`: sign in (form fields `username`, `password`, `voucher`,
//!   `terms`, `redirurl`); 303 to the zone's after-login URL, the original
//!   page or `/status`;
//! - `GET /status`, `GET|POST /logout`: remaining time and the logout button;
//! - `GET /api/captive`: the RFC 8908 Captive Portal API (handed out as DHCP
//!   option 114), `application/captive+json`.

use crate::engine::{ClientCtx, LoginForm, Portal, Refused};
use crate::pages;
use crate::radius;
use axum::{
    extract::{ConnectInfo, Form, Query, State},
    http::{header, HeaderMap, Method, StatusCode, Uri},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

pub struct PortalHttp {
    pub portal: Arc<Portal>,
    /// Is this the HTTPS listener?
    pub tls: bool,
}

type St = Arc<PortalHttp>;

fn client_ip(a: &SocketAddr) -> Option<Ipv4Addr> {
    match a.ip() {
        IpAddr::V4(v) => Some(v),
        IpAddr::V6(v) => v.to_ipv4_mapped(),
    }
}

fn no_store(mut r: Response) -> Response {
    r.headers_mut().insert(
        header::CACHE_CONTROL,
        header::HeaderValue::from_static("no-store"),
    );
    r
}

fn html(code: StatusCode, body: String) -> Response {
    no_store((code, Html(body)).into_response())
}

fn redirect(code: StatusCode, to: &str) -> Response {
    match header::HeaderValue::from_str(to) {
        Ok(v) => no_store((code, [(header::LOCATION, v)]).into_response()),
        Err(_) => no_store(StatusCode::BAD_REQUEST.into_response()),
    }
}

fn urlencode(s: &str) -> String {
    s.bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) {
                (b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}

/// A redirect target the portal will follow: http(s), printable, no quotes.
fn safe_target(s: &str) -> bool {
    (s.starts_with("http://") || s.starts_with("https://"))
        && s.len() <= 2000
        && s.bytes()
            .all(|b| (0x21..0x7f).contains(&b) && !b"\"<>\\".contains(&b))
}

async fn ctx(st: &PortalHttp, peer: &SocketAddr) -> Option<ClientCtx> {
    st.portal.client(client_ip(peer)?).await
}

/// Router host as clients should see it.
async fn host_for(st: &PortalHttp, c: &ClientCtx) -> String {
    let g = st.portal.globals().await;
    if g.hostname.is_empty() {
        c.router.to_string()
    } else {
        g.hostname
    }
}

/// The status page of a signed-in client. Absolute, on the portal's own
/// port: once signed in, the router's standard ports are no longer redirected
/// to the portal for this client.
async fn status_url(st: &PortalHttp, c: &ClientCtx) -> String {
    let g = st.portal.globals().await;
    let host = if g.hostname.is_empty() {
        c.router.to_string()
    } else {
        g.hostname.clone()
    };
    if st.tls {
        format!("https://{host}:{}/status", g.https_port)
    } else {
        format!("http://{host}:{}/status", g.http_port)
    }
}

async fn landing(
    State(st): State<St>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    uri: Uri,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    let Some(c) = ctx(&st, &peer).await else {
        return html(StatusCode::NOT_FOUND, pages::not_a_zone());
    };
    if let Some(s) = st.portal.active(&c).await {
        if st.tls || !c.zone.https_login {
            let left = (s.expires > 0).then(|| s.expires - crate::engine::now());
            return html(StatusCode::OK, pages::status(&c.zone, "/logout", left, ""));
        }
        // signed in, on the HTTP listener by its port: the status page is on HTTPS
        // (port 443 of the router is the web UI again for a signed-in client)
        let tls = PortalHttp {
            portal: st.portal.clone(),
            tls: true,
        };
        return redirect(StatusCode::FOUND, &status_url(&tls, &c).await);
    }
    // what the client asked for before it was sent here (HTTP listener only)
    let orig = if st.tls {
        String::new()
    } else {
        let host = headers
            .get(header::HOST)
            .and_then(|h| h.to_str().ok())
            .unwrap_or("");
        let pq = uri.path_and_query().map(|p| p.as_str()).unwrap_or("/");
        let u = format!("http://{host}{pq}");
        if safe_target(&u) && !host.is_empty() {
            u
        } else {
            String::new()
        }
    };
    if !st.tls && c.zone.https_login {
        let host = host_for(&st, &c).await;
        let to = if orig.is_empty() {
            format!("https://{host}/")
        } else {
            format!("https://{host}/?redirurl={}", urlencode(&orig))
        };
        // 302 (not 307): every probe method lands on the page with a GET
        return redirect(StatusCode::FOUND, &to);
    }
    let redirurl = q
        .get("redirurl")
        .filter(|u| safe_target(u))
        .cloned()
        .unwrap_or(orig);
    html(
        StatusCode::OK,
        pages::splash(&c.zone, "/login", &redirurl, false),
    )
}

async fn login(
    State(st): State<St>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Form(f): Form<HashMap<String, String>>,
) -> Response {
    let Some(c) = ctx(&st, &peer).await else {
        return html(StatusCode::NOT_FOUND, pages::not_a_zone());
    };
    if !st.tls && c.zone.https_login {
        // never take a password over plain HTTP when the zone says HTTPS
        let host = host_for(&st, &c).await;
        return redirect(StatusCode::SEE_OTHER, &format!("https://{host}/"));
    }
    let get = |k: &str| f.get(k).cloned().unwrap_or_default();
    let form = LoginForm {
        username: get("username"),
        password: get("password"),
        voucher: get("voucher"),
        terms: matches!(get("terms").as_str(), "1" | "on" | "yes" | "true"),
    };
    let redirurl = get("redirurl");
    match st.portal.login(&c, &form).await {
        Ok(_) => {
            let to = if !c.zone.redirect_url.is_empty() {
                c.zone.redirect_url.clone()
            } else if safe_target(&redirurl) {
                redirurl
            } else {
                status_url(&st, &c).await
            };
            redirect(StatusCode::SEE_OTHER, &to)
        }
        Err(r) => {
            tracing::info!(
                "captive portal {}: login from {} refused: {r}",
                c.zone.name,
                c.ip
            );
            let code = match r {
                Refused::Unavailable(_) => StatusCode::SERVICE_UNAVAILABLE,
                Refused::Terms => StatusCode::BAD_REQUEST,
                _ => StatusCode::UNAUTHORIZED,
            };
            let safe = if safe_target(&redirurl) {
                redirurl
            } else {
                String::new()
            };
            html(code, pages::splash(&c.zone, "/login", &safe, true))
        }
    }
}

async fn status(State(st): State<St>, ConnectInfo(peer): ConnectInfo<SocketAddr>) -> Response {
    let Some(c) = ctx(&st, &peer).await else {
        return html(StatusCode::NOT_FOUND, pages::not_a_zone());
    };
    match st.portal.active(&c).await {
        Some(s) => {
            let left = (s.expires > 0).then(|| s.expires - crate::engine::now());
            html(StatusCode::OK, pages::status(&c.zone, "/logout", left, ""))
        }
        None => redirect(StatusCode::FOUND, "/"),
    }
}

async fn logout(
    State(st): State<St>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    method: Method,
) -> Response {
    let Some(c) = ctx(&st, &peer).await else {
        return html(StatusCode::NOT_FOUND, pages::not_a_zone());
    };
    let active = st.portal.active(&c).await;
    if method != Method::POST {
        // a GET never signs anyone out (link prefetchers, image tags)
        return match active {
            Some(s) => {
                let left = (s.expires > 0).then(|| s.expires - crate::engine::now());
                html(StatusCode::OK, pages::status(&c.zone, "/logout", left, ""))
            }
            None => html(StatusCode::OK, pages::signed_out(&c.zone, "/login")),
        };
    }
    if let Some(s) = active {
        st.portal
            .end(s.id, "logged out", radius::cause::USER_REQUEST)
            .await;
    }
    html(StatusCode::OK, pages::signed_out(&c.zone, "/login"))
}

/// RFC 8908 section 5.
async fn api(State(st): State<St>, ConnectInfo(peer): ConnectInfo<SocketAddr>) -> Response {
    let body = match ctx(&st, &peer).await {
        None => serde_json::json!({ "captive": false }),
        Some(c) => {
            let g = st.portal.globals().await;
            let host = if g.hostname.is_empty() {
                c.router.to_string()
            } else {
                g.hostname.clone()
            };
            let mut v = serde_json::json!({
                "captive": true,
                "user-portal-url": format!("https://{host}:{}/", g.https_port),
            });
            if let Some(s) = st.portal.active(&c).await {
                v["captive"] = false.into();
                v["can-extend-session"] = false.into();
                if s.expires > 0 {
                    v["seconds-remaining"] = (s.expires - crate::engine::now()).max(0).into();
                }
            }
            v
        }
    };
    let mut r = Json(body).into_response();
    r.headers_mut().insert(
        header::CONTENT_TYPE,
        header::HeaderValue::from_static("application/captive+json"),
    );
    no_store(r)
}

/// Plain-HTTP answers close their connection: a browser that kept a
/// redirected connection open would otherwise send its next request for that
/// host to the portal again after signing in (the kernel no longer redirects
/// new connections, but an open one stays where it was).
async fn close_http(req: axum::extract::Request, next: axum::middleware::Next) -> Response {
    let mut r = next.run(req).await;
    r.headers_mut().insert(
        header::CONNECTION,
        header::HeaderValue::from_static("close"),
    );
    r
}

pub fn router(portal: Arc<Portal>, tls: bool) -> Router {
    let r = Router::new()
        .route("/api/captive", get(api))
        .route("/login", post(login))
        .route("/logout", get(logout).post(logout))
        .route("/status", get(status))
        .fallback(landing)
        .with_state(Arc::new(PortalHttp { portal, tls }));
    if tls {
        r
    } else {
        r.layer(axum::middleware::from_fn(close_http))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn targets_and_encoding() {
        assert!(safe_target("http://example.org/a?b=c"));
        assert!(!safe_target("javascript:alert(1)"));
        assert!(!safe_target("http://a\"><script>"));
        assert_eq!(
            urlencode("http://x/?a=1&b"),
            "http%3A%2F%2Fx%2F%3Fa%3D1%26b"
        );
        assert_eq!(
            client_ip(&"[::ffff:10.0.0.5]:80".parse().unwrap()),
            Some("10.0.0.5".parse().unwrap())
        );
    }
}
