//! IDS alert browser API (USE=intrusion-detection), area `services` like the IDS page.
//!
//! - `GET  /api/svc/ids/alerts?from=&to=&window=24h&src=&dst=&sid=&q=&action=&limit=&offset=`
//! - `GET  /api/svc/ids/alerts/top?by=src|dst|sid&window=24h&limit=`
//! - `GET  /api/svc/ids/summary`                       the dashboard card
//! - `POST /api/svc/ids/alerts/{id}/suppress`          one-click suppress / threshold from an alert
//!   body `{"scope": "rule|source|destination", "kind": "suppress|limit", "seconds": 3600}`
//! - page `GET /svc/ids/alerts`
//!
//! The alerts are the `ids_alerts` table (copied from eve.json by the root task with retention);
//! a suppress/threshold goes through the same LAN manager path as the page's own forms (snapshot,
//! apply, undo when Suricata refuses it).

#![allow(clippy::result_large_err)]

use crate::state::AppState;
use askama::Template;
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Json,
};
use patronus_network::ids_alerts::{self, Filter};
use serde_json::{json, Value};
use std::collections::HashMap;

type Q = Query<HashMap<String, String>>;

fn err(e: impl std::fmt::Display) -> Response {
    let msg = e.to_string();
    let code = if msg.contains("Invalid") {
        StatusCode::BAD_REQUEST
    } else if msg.starts_with("no ") {
        StatusCode::NOT_FOUND
    } else {
        StatusCode::INTERNAL_SERVER_ERROR
    };
    (code, Json(json!({ "error": msg }))).into_response()
}

fn bad(msg: &str) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({ "error": format!("Invalid {msg}") })),
    )
        .into_response()
}

/// `1700000000`, an RFC 3339 time, or a local `YYYY-MM-DDTHH:MM` from a date picker.
fn parse_time(s: &str) -> Option<i64> {
    let s = s.trim();
    if let Ok(n) = s.parse::<i64>() {
        return Some(n);
    }
    if let Ok(d) = chrono::DateTime::parse_from_rfc3339(s) {
        return Some(d.timestamp());
    }
    for fmt in ["%Y-%m-%dT%H:%M", "%Y-%m-%dT%H:%M:%S"] {
        if let Ok(n) = chrono::NaiveDateTime::parse_from_str(s, fmt) {
            use chrono::TimeZone;
            return chrono::Local
                .from_local_datetime(&n)
                .single()
                .map(|d| d.timestamp());
        }
    }
    None
}

/// `window=24h|7d|30m` -> seconds.
fn window(s: &str) -> Option<i64> {
    let (n, unit) = s.split_at(s.len().checked_sub(1)?);
    let n: i64 = n.parse().ok()?;
    Some(
        n * match unit {
            "m" => 60,
            "h" => 3600,
            "d" => 86_400,
            _ => return None,
        },
    )
}

fn range(q: &HashMap<String, String>) -> Result<(Option<i64>, Option<i64>), Response> {
    let now = chrono::Utc::now().timestamp();
    let mut from = None;
    let mut to = None;
    if let Some(w) = q.get("window").filter(|w| !w.is_empty()) {
        from = Some(now - window(w).ok_or_else(|| bad("window (like 30m, 24h or 7d)"))?);
    }
    if let Some(f) = q.get("from").filter(|f| !f.is_empty()) {
        from = Some(parse_time(f).ok_or_else(|| bad("from (a time)"))?);
    }
    if let Some(t) = q.get("to").filter(|t| !t.is_empty()) {
        to = Some(parse_time(t).ok_or_else(|| bad("to (a time)"))?);
    }
    Ok((from, to))
}

fn num(q: &HashMap<String, String>, k: &str, def: i64) -> Result<i64, Response> {
    match q.get(k).filter(|v| !v.is_empty()) {
        None => Ok(def),
        Some(v) => v.parse().map_err(|_| bad(&format!("{k} (a number)"))),
    }
}

fn opt(q: &HashMap<String, String>, k: &str) -> Option<String> {
    q.get(k)
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

async fn alerts(State(st): State<AppState>, Query(q): Q) -> Response {
    let (from, to) = match range(&q) {
        Ok(r) => r,
        Err(r) => return r,
    };
    let sid = match opt(&q, "sid").map(|s| s.parse::<i64>()) {
        None => None,
        Some(Ok(n)) => Some(n),
        Some(Err(_)) => return bad("sid (a number)"),
    };
    let (limit, offset) = match (num(&q, "limit", 100), num(&q, "offset", 0)) {
        (Ok(l), Ok(o)) => (l, o),
        (Err(r), _) | (_, Err(r)) => return r,
    };
    let f = Filter {
        from,
        to,
        src: opt(&q, "src"),
        dst: opt(&q, "dst"),
        sid,
        q: opt(&q, "q"),
        action: opt(&q, "action"),
        limit,
        offset,
    };
    match ids_alerts::query(&st.config_store, &f).await {
        Ok((total, rows)) => Json(json!({"total": total, "limit": limit.clamp(1, 1000), "offset": offset.max(0), "alerts": rows}))
            .into_response(),
        Err(e) => err(e),
    }
}

async fn top(State(st): State<AppState>, Query(q): Q) -> Response {
    let (from, to) = match range(&q) {
        Ok(r) => r,
        Err(r) => return r,
    };
    let limit = match num(&q, "limit", 10) {
        Ok(l) => l,
        Err(r) => return r,
    };
    let by = q.get("by").map(String::as_str).unwrap_or("src");
    match ids_alerts::top(&st.config_store, by, from, to, limit).await {
        Ok(v) => Json(json!({"by": by, "top": v})).into_response(),
        Err(e) => err(e),
    }
}

async fn summary(State(st): State<AppState>) -> Response {
    match ids_alerts::summary(&st.config_store).await {
        Ok(v) => Json(v).into_response(),
        Err(e) => err(e),
    }
}

/// One click on an alert: suppress that rule (everywhere, for the source or for the destination)
/// or limit how often it fires.
async fn suppress(
    State(st): State<AppState>,
    Path(id): Path<i64>,
    body: Option<Json<Value>>,
) -> Response {
    let body = body.map(|b| b.0).unwrap_or(Value::Null);
    let row = sqlx::query_as::<_, (i64, String, String)>(
        "SELECT sid, src_ip, dst_ip FROM ids_alerts WHERE id = ?",
    )
    .bind(id)
    .fetch_optional(match st.config_store.pool() {
        Ok(p) => p,
        Err(e) => return err(e),
    })
    .await;
    let (sid, src, dst) = match row {
        Ok(Some(r)) => r,
        Ok(None) => return err(format!("no alert {id}")),
        Err(e) => return err(e),
    };
    if sid == 0 {
        return bad("alert (it carries no rule id)");
    }
    let scope = body["scope"].as_str().unwrap_or("rule");
    let kind = body["kind"].as_str().unwrap_or("suppress");
    let row = match (kind, scope) {
        ("suppress", "rule") => {
            json!({"sid": sid, "kind": "suppress", "track": "none", "note": format!("from alert {id}")})
        }
        ("suppress", "source") => {
            json!({"sid": sid, "kind": "suppress", "track": "by_src", "ip": src, "note": format!("from alert {id}")})
        }
        ("suppress", "destination") => {
            json!({"sid": sid, "kind": "suppress", "track": "by_dst", "ip": dst, "note": format!("from alert {id}")})
        }
        ("limit" | "threshold" | "both", "source" | "rule") => json!({
            "sid": sid, "kind": kind, "track": "by_src",
            "count": body["count"].as_i64().unwrap_or(1),
            "seconds": body["seconds"].as_i64().unwrap_or(3600),
            "note": format!("from alert {id}")}),
        ("limit" | "threshold" | "both", "destination") => json!({
            "sid": sid, "kind": kind, "track": "by_dst",
            "count": body["count"].as_i64().unwrap_or(1),
            "seconds": body["seconds"].as_i64().unwrap_or(3600),
            "note": format!("from alert {id}")}),
        _ => return bad(
            "suppress request (scope rule|source|destination, kind suppress|limit|threshold|both)",
        ),
    };
    match st
        .lan
        .svc_save_row("ids", "suppress", None, row.clone())
        .await
    {
        Ok(rid) => (StatusCode::CREATED, Json(json!({"id": rid, "entry": row}))).into_response(),
        Err(e) => err(e),
    }
}

#[derive(Template)]
#[template(path = "ids_alerts.html")]
struct AlertsPage {
    page: String,
    can_modify: bool,
}

async fn page(me: crate::auth::AuthUser) -> Response {
    match (AlertsPage {
        page: "svc-ids".into(),
        can_modify: me.session.role.can_modify(),
    })
    .render()
    {
        Ok(h) => Html(h).into_response(),
        Err(e) => {
            tracing::error!("render ids alerts page: {e}");
            (StatusCode::INTERNAL_SERVER_ERROR, "Failed to render page").into_response()
        }
    }
}

pub fn router() -> axum::Router<AppState> {
    axum::Router::new()
        .route("/svc/ids/alerts", get(alerts))
        .route("/svc/ids/alerts/top", get(top))
        .route("/svc/ids/alerts/:id/suppress", post(suppress))
        .route("/svc/ids/summary", get(summary))
}

pub fn pages() -> axum::Router<AppState> {
    axum::Router::new().route("/svc/ids/alerts", get(page))
}
