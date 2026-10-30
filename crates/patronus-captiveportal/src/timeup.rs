//! "Time's up" and grace-warning pages for parental time limits.
//!
//! Unlike the guest portal in [`crate::portal`] (in-memory state, started
//! from the CLI), this part reads the config store: the enforcement ticker in
//! `patronus_firewall::seg_time` writes one row per limited device into
//! `seg_time_state`, and the plain-HTTP requests of blocked devices (and, for
//! a short while, of devices in their grace period) are redirected to this
//! server by an nft rule. The page is chosen by the *client address* alone;
//! nothing a client sends is stored or trusted.
//!
//! Captive-portal detection of phones does the rest: Android probes
//! `/generate_204` and iOS `captive.apple.com`; any answer other than the
//! expected one makes the phone open this page by itself.

use axum::{
    extract::{ConnectInfo, State},
    http::{header, StatusCode, Uri},
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use patronus_config::ConfigStore;
use serde::Serialize;
use sqlx::Row;
use std::net::SocketAddr;
use std::sync::Arc;

/// What the ticker last decided for one device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TimeStatus {
    pub device: String,
    /// `ok` | `warn` | `blocked`
    pub state: String,
    /// `paused` | `window` | `quota` | ``
    pub reason: String,
    pub used_minutes: i64,
    pub limit_minutes: Option<i64>,
    pub remaining_minutes: Option<i64>,
    pub resume_at: String,
}

/// The row for a client address (`None`: not a limited device).
pub async fn status_for(store: &ConfigStore, ip: &str) -> Option<TimeStatus> {
    let pool = store.pool().ok()?;
    let r = sqlx::query(
        "SELECT COALESCE(d.name, 'this device'), s.state, s.reason, s.used_minutes, s.limit_minutes,
                s.remaining_minutes, s.resume_at
         FROM seg_time_state s LEFT JOIN seg_devices d ON d.id = s.device_id WHERE s.ip = ?",
    )
    .bind(ip)
    .fetch_optional(pool)
    .await
    .ok()??;
    Some(TimeStatus {
        device: r.get(0),
        state: r.get(1),
        reason: r.get(2),
        used_minutes: r.get(3),
        limit_minutes: r.get(4),
        remaining_minutes: r.get(5),
        resume_at: r.get(6),
    })
}

fn esc(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            '&' => "&amp;".to_string(),
            '<' => "&lt;".to_string(),
            '>' => "&gt;".to_string(),
            '"' => "&quot;".to_string(),
            '\'' => "&#39;".to_string(),
            c => c.to_string(),
        })
        .collect()
}

/// `(title, message, accent colour)` for a status.
pub fn words(st: Option<&TimeStatus>) -> (String, String, &'static str) {
    match st {
        Some(s) if s.state == "blocked" => {
            let back = if s.resume_at.is_empty() {
                String::new()
            } else {
                format!(" It comes back at <b>{}</b>.", esc(&s.resume_at))
            };
            let msg = match s.reason.as_str() {
                "quota" => format!(
                    "Today's internet time ({} minutes) is used up.{back}",
                    s.limit_minutes.unwrap_or(0)
                ),
                "window" => {
                    format!("The internet is switched off for this device right now.{back}")
                }
                "paused" => "A parent paused the internet for this device.".to_string(),
                _ => format!("Internet access is limited right now.{back}"),
            };
            ("Time's up".to_string(), msg, "#b3261e")
        }
        Some(s) if s.state == "warn" => {
            let left = s.remaining_minutes.unwrap_or(0);
            (
                format!("{left} minute{} left", if left == 1 { "" } else { "s" }),
                "Please finish up: the internet for this device switches off soon.".to_string(),
                "#b26a00",
            )
        }
        Some(_) => (
            "You're all set".to_string(),
            "Nothing is limiting this device right now.".to_string(),
            "#1b6e3c",
        ),
        None => (
            "No time limit".to_string(),
            "This device has no time limit.".to_string(),
            "#1b6e3c",
        ),
    }
}

/// The page (phone-sized, no scripts, no external resources).
pub fn render_page(st: Option<&TimeStatus>) -> String {
    let (title, msg, color) = words(st);
    let dev = st.map(|s| esc(&s.device)).unwrap_or_default();
    format!(
        "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\">\
<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
<title>{t} - Patronus</title><style>\
body{{margin:0;font-family:system-ui,sans-serif;background:#f4f5f7;color:#1c1b1f;display:flex;\
min-height:100vh;align-items:center;justify-content:center}}\
main{{background:#fff;max-width:420px;margin:16px;padding:28px 24px;border-radius:16px;\
box-shadow:0 2px 12px rgba(0,0,0,.12);text-align:center}}\
h1{{margin:0 0 12px;font-size:28px;color:{c}}}p{{font-size:17px;line-height:1.45;margin:8px 0}}\
small{{color:#666}}</style></head><body><main><h1>{t}</h1><p>{m}</p>\
<small>{d}</small></main></body></html>",
        t = title,
        c = color,
        m = msg,
        d = dev
    )
}

async fn page(
    State(store): State<Arc<ConfigStore>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    uri: Uri,
) -> Response {
    let st = status_for(&store, &peer.ip().to_string()).await;
    // Android connectivity probe: "204" means "internet works"; only a
    // device that is not limited gets it
    let ok = st.as_ref().is_none_or(|s| s.state == "ok");
    if ok && matches!(uri.path(), "/generate_204" | "/gen_204") {
        return StatusCode::NO_CONTENT.into_response();
    }
    (
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8"),
            (header::CACHE_CONTROL, "no-store"),
        ],
        render_page(st.as_ref()),
    )
        .into_response()
}

async fn status_json(
    State(store): State<Arc<ConfigStore>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
) -> Response {
    match status_for(&store, &peer.ip().to_string()).await {
        Some(s) => Json(s).into_response(),
        None => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "no time limit for this address"})),
        )
            .into_response(),
    }
}

/// Every path answers the status page of the caller.
pub fn router(store: Arc<ConfigStore>) -> Router {
    Router::new()
        .route("/status.json", get(status_json))
        .fallback(get(page))
        .with_state(store)
}

/// Serve on `addr` until the process stops.
pub async fn serve(store: Arc<ConfigStore>, addr: SocketAddr) -> std::io::Result<()> {
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(
        listener,
        router(store).into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn st(state: &str, reason: &str) -> TimeStatus {
        TimeStatus {
            device: "Emma's <tablet>".into(),
            state: state.into(),
            reason: reason.into(),
            used_minutes: 120,
            limit_minutes: Some(120),
            remaining_minutes: Some(0),
            resume_at: "Tue 06:00".into(),
        }
    }

    #[test]
    fn pages_say_what_is_going_on_and_escape_names() {
        let p = render_page(Some(&st("blocked", "quota")));
        assert!(p.contains("Time's up"));
        assert!(p.contains("120 minutes"));
        assert!(p.contains("Tue 06:00"));
        assert!(p.contains("Emma&#39;s &lt;tablet&gt;"));
        assert!(!p.contains("<tablet>"));
        let p = render_page(Some(&st("blocked", "window")));
        assert!(p.contains("switched off"));
        let p = render_page(Some(&st("blocked", "paused")));
        assert!(p.contains("paused"));
        let mut w = st("warn", "");
        w.remaining_minutes = Some(5);
        assert!(render_page(Some(&w)).contains("5 minutes left"));
        w.remaining_minutes = Some(1);
        assert!(render_page(Some(&w)).contains("1 minute left"));
        assert!(render_page(None).contains("no time limit"));
    }

    async fn store_with(ip: &str, state: &str) -> Arc<ConfigStore> {
        let s = ConfigStore::open_in_memory().await.unwrap();
        sqlx::query("INSERT INTO seg_groups (id, name) VALUES (11, 'kids')")
            .execute(s.pool().unwrap())
            .await
            .unwrap();
        sqlx::query("INSERT INTO seg_devices (id, name, group_id, kind, segment, ip4, state, created_at) VALUES (1, 'tablet', 11, 'wifi', '@lan', ?, 'active', 0)")
            .bind(ip)
            .execute(s.pool().unwrap())
            .await
            .unwrap();
        sqlx::query("INSERT INTO seg_time_state (device_id, ip, state, reason, used_minutes, limit_minutes, remaining_minutes, resume_at, updated_at) VALUES (1, ?, ?, 'quota', 60, 60, 0, '06:00', 0)")
            .bind(ip)
            .bind(state)
            .execute(s.pool().unwrap())
            .await
            .unwrap();
        Arc::new(s)
    }

    #[tokio::test]
    async fn serves_the_callers_own_status_over_http() {
        let store = store_with("127.0.0.1", "blocked").await;
        let app = router(store.clone()).into_make_service_with_connect_info::<SocketAddr>();
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
        let get = |path: &'static str| async move {
            let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            s.write_all(
                format!("GET {path} HTTP/1.0\r\nHost: connectivitycheck.gstatic.com\r\n\r\n")
                    .as_bytes(),
            )
            .await
            .unwrap();
            let mut out = String::new();
            s.read_to_string(&mut out).await.unwrap();
            out
        };
        let r = get("/generate_204").await;
        assert!(
            r.starts_with("HTTP/1.0 200"),
            "a blocked phone must NOT get 204: {r}"
        );
        assert!(r.contains("Time's up"));
        let r = get("/whatever/path?x=1").await;
        assert!(r.contains("Time's up"));
        let r = get("/status.json").await;
        assert!(r.contains("\"state\":\"blocked\"") && r.contains("\"reason\":\"quota\""));
        // the same device once the limit is lifted gets the "all fine" 204
        sqlx::query("UPDATE seg_time_state SET state = 'ok'")
            .execute(store.pool().unwrap())
            .await
            .unwrap();
        let r = get("/generate_204").await;
        assert!(r.starts_with("HTTP/1.0 204"), "{r}");
        // an address without a row: no limit, 404 on the json
        sqlx::query("DELETE FROM seg_time_state")
            .execute(store.pool().unwrap())
            .await
            .unwrap();
        assert!(get("/status.json").await.starts_with("HTTP/1.0 404"));
    }
}
