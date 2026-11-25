//! System log viewer API and page.
//!
//! - `GET /api/logs/system?since=&until=&min_priority=&unit=&identifier=&kernel=&q=&limit=&cursor=`
//!   the newest `limit` (default `logview.default_limit`, at most 2000) matching records,
//!   chronological, with "boot" separator items; `cursor` = the `older_cursor` of the
//!   previous answer;
//! - `GET /api/logs/system/stream?...&cursor=` Server-Sent Events (`line`, `boot`; the event
//!   id is the resume cursor, so a reconnect with `Last-Event-ID` loses nothing);
//! - `GET /api/logs/system/download?...&format=txt|json` the filtered view as a file;
//! - `GET|PUT /api/logs/system/settings` the typed `logview.*` settings (admins write).
//!
//! Page: `/logs`. The area is "system" (the RBAC default for paths outside the listed areas).

#![allow(clippy::result_large_err)]

use crate::auth::{AdminUser, AuthUser};
use crate::logview::{self, Filter};
use crate::state::AppState;
use askama::Template;
use axum::{
    extract::{Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{
        sse::{Event, KeepAlive, Sse},
        Html, IntoResponse, Response,
    },
    routing::get,
    Json,
};
use patronus_config::logview as cfg;
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::convert::Infallible;

type Q = Query<HashMap<String, String>>;

fn bad(msg: impl Into<String>) -> Response {
    (StatusCode::BAD_REQUEST, Json(json!({ "error": msg.into() }))).into_response()
}

fn limit_of(q: &HashMap<String, String>, s: &cfg::LogViewSettings) -> Result<usize, Response> {
    match q.get("limit").map(|v| v.trim()).filter(|v| !v.is_empty()) {
        None => Ok(s.default_limit as usize),
        Some(v) => match v.parse::<u32>() {
            Ok(n) if n >= 1 => Ok(n.min(s.max_limit) as usize),
            _ => Err(bad(format!("Invalid limit {v:?}: a number from 1 to {}", s.max_limit))),
        },
    }
}

async fn system_log(State(st): State<AppState>, _me: AuthUser, Query(q): Q) -> Response {
    let s = cfg::resolve(Some(&st.config_store)).await;
    let f = match Filter::from_query(&q) {
        Ok(f) => f,
        Err(e) => return bad(e),
    };
    let limit = match limit_of(&q, &s) {
        Ok(l) => l,
        Err(r) => return r,
    };
    let cursor = q.get("cursor").map(String::as_str).filter(|c| !c.is_empty());
    let page = logview::query(&s, &f, limit, cursor).await;
    Json(page.to_json()).into_response()
}

async fn stream(State(st): State<AppState>, _me: AuthUser, headers: HeaderMap, Query(q): Q) -> Response {
    let s = cfg::resolve(Some(&st.config_store)).await;
    let f = match Filter::from_query(&q) {
        Ok(f) => f,
        Err(e) => return bad(e),
    };
    let cursor = q
        .get("cursor")
        .cloned()
        .filter(|c| !c.is_empty())
        .or_else(|| headers.get("last-event-id").and_then(|v| v.to_str().ok()).map(String::from))
        .filter(|c| !c.is_empty());
    let hello = json!({"backend": logview::choose(&s).name(), "max_secs": s.stream_max_secs});
    let (tx, rx) = tokio::sync::mpsc::channel::<Value>(256);
    tokio::spawn(logview::follow(s, f, cursor, tx));
    let first = futures::stream::once(async move {
        Ok::<Event, Infallible>(Event::default().event("hello").data(hello.to_string()))
    });
    let rest = futures::stream::unfold(rx, |mut rx| async move {
        let v = rx.recv().await?;
        let mut ev = Event::default().event(v["type"].as_str().unwrap_or("line").to_string());
        if let Some(c) = v["cursor"].as_str() {
            ev = ev.id(c.to_string());
        }
        Some((Ok::<Event, Infallible>(ev.data(v.to_string())), rx))
    });
    let mut r = Sse::new(futures::StreamExt::chain(first, rest))
        .keep_alive(KeepAlive::default())
        .into_response();
    r.headers_mut().insert(header::CACHE_CONTROL, "no-cache".parse().unwrap());
    r.headers_mut().insert("x-accel-buffering", "no".parse().unwrap());
    r
}

async fn download(State(st): State<AppState>, _me: AuthUser, Query(q): Q) -> Response {
    let s = cfg::resolve(Some(&st.config_store)).await;
    let f = match Filter::from_query(&q) {
        Ok(f) => f,
        Err(e) => return bad(e),
    };
    let page = logview::query(&s, &f, s.download_max_lines as usize, None).await;
    let json_out = q.get("format").map(String::as_str) == Some("json");
    let (body, ctype, name) = if json_out {
        (
            serde_json::to_string_pretty(&json!({"entries": page.items})).unwrap_or_default(),
            "application/json",
            "patronus-system-log.json",
        )
    } else {
        (logview::download_text(&page.items), "text/plain; charset=utf-8", "patronus-system-log.txt")
    };
    (
        [
            (header::CONTENT_TYPE, ctype.to_string()),
            (header::CONTENT_DISPOSITION, format!("attachment; filename=\"{name}\"")),
        ],
        body,
    )
        .into_response()
}

async fn settings_json(st: &AppState) -> Response {
    let eff = cfg::resolve(Some(&st.config_store)).await;
    let stored: HashMap<String, String> = cfg::stored(&st.config_store).await.into_iter().collect();
    Json(json!({
        "effective": eff, "stored": stored, "defaults": cfg::LogViewSettings::default(),
        "backend_in_use": logview::choose(&eff).name(),
    }))
    .into_response()
}

async fn get_settings(State(st): State<AppState>, _me: AuthUser) -> Response {
    settings_json(&st).await
}

#[derive(Deserialize)]
struct SettingsInput {
    /// key (`logview.*`) -> value; an empty value = back to the built-in default.
    #[serde(default)]
    settings: HashMap<String, String>,
    #[serde(default)]
    reset: bool,
}

async fn put_settings(State(st): State<AppState>, _admin: AdminUser, Json(i): Json<SettingsInput>) -> Response {
    let changes: Vec<(String, String)> = i.settings.into_iter().collect();
    match cfg::save(&st.config_store, &changes, i.reset).await {
        Ok(()) => {
            let keys: Vec<String> = changes.iter().map(|c| c.0.clone()).collect();
            let _ = st
                .config_store
                .audit("web", "update", "logview_settings", None, &json!({"keys": keys, "reset": i.reset}))
                .await;
            settings_json(&st).await
        }
        Err(e) => {
            let m = e.to_string();
            let code = if m.contains("Invalid") { StatusCode::BAD_REQUEST } else { StatusCode::INTERNAL_SERVER_ERROR };
            (code, Json(json!({ "error": m }))).into_response()
        }
    }
}

pub fn router() -> axum::Router<AppState> {
    axum::Router::new()
        .route("/logs/system", get(system_log))
        .route("/logs/system/stream", get(stream))
        .route("/logs/system/download", get(download))
        .route("/logs/system/settings", get(get_settings).put(put_settings))
}

#[derive(Template)]
#[template(path = "system_log.html")]
struct SystemLogTemplate {
    page: &'static str,
    is_admin: bool,
}

async fn page(me: AuthUser) -> Response {
    match (SystemLogTemplate { page: "logs", is_admin: me.session.role.is_admin() }).render() {
        Ok(h) => Html(h).into_response(),
        Err(e) => {
            tracing::error!("render system log: {e}");
            (StatusCode::INTERNAL_SERVER_ERROR, "Failed to render page").into_response()
        }
    }
}

pub fn pages() -> axum::Router<AppState> {
    axum::Router::new().route("/logs", get(page))
}
