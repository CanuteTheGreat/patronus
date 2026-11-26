//! Router CVE exposure (`patronus_network::cve`, docs/CVE-EXPOSURE.md).
//!
//! - `GET  /api/cve`                 settings, defaults, the latest report, scan history, engine log
//! - `PUT  /api/cve/settings`        partial settings (validated)
//! - `POST /api/cve/scan`            ask the engine for a scan now ({"fetch": true} also refreshes the crate data)
//! - `GET  /api/cve/findings`        the findings (`?source=glsa|osv|image`, `?severity=high`)
//! - `GET  /api/cve/history`         scan history, newest first
//! - page `/security/cve-exposure`

use crate::state::AppState;
use askama::Template;
use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{Html, IntoResponse, Response},
    routing::{get, post, put},
    Json,
};
use patronus_network::cve::{self, SettingsIn};
use serde::Deserialize;
use serde_json::json;

fn err(e: impl std::fmt::Display) -> Response {
    let msg = e.to_string();
    let code = if msg.contains("Invalid") {
        StatusCode::BAD_REQUEST
    } else {
        StatusCode::INTERNAL_SERVER_ERROR
    };
    (code, Json(json!({ "error": msg }))).into_response()
}

async fn overview_json(s: &AppState) -> patronus_core::Result<serde_json::Value> {
    let st = &s.config_store;
    let settings = cve::load(st).await?;
    let report = cve::last_report(st).await?;
    let scan_requested: i64 = cve::state_get(st, "scan_requested")
        .await?
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let last_apply: i64 = cve::state_get(st, "last_apply")
        .await?
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let served: i64 = cve::state_get(st, "scan_served")
        .await?
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let pending = scan_requested > served;
    Ok(json!({
        "settings": settings,
        "defaults": cve::settings::Settings::default(),
        "policies": cve::settings::POLICIES,
        "now": cve::now(),
        "report": report,
        "scan_pending": pending,
        "last_apply": last_apply,
        "history": cve::scan_history(st, 60).await?,
        "log": cve::log_history(st, 40).await?,
        // this very binary's own crate list is linked in so the linker keeps it; the scan
        // reads the installed binaries' lists, not this process's
        "embedded_bytes": cve::inventory::keep(crate::PATRONUS_DEP_LIST),
    }))
}

async fn overview(State(s): State<AppState>) -> Response {
    match overview_json(&s).await {
        Ok(v) => Json(v).into_response(),
        Err(e) => err(e),
    }
}

async fn put_settings(State(s): State<AppState>, Json(i): Json<SettingsIn>) -> Response {
    if let Err(e) = cve::save(&s.config_store, &i).await {
        return err(e);
    }
    overview(State(s)).await
}

#[derive(Deserialize, Default)]
struct ScanIn {
    #[serde(default)]
    fetch: bool,
}

async fn scan(State(s): State<AppState>, body: Option<Json<ScanIn>>) -> Response {
    let st = &s.config_store;
    let now = cve::now();
    let fetch = body.map(|b| b.0.fetch).unwrap_or(false);
    let r = async {
        if fetch {
            cve::state_set(st, "fetch_requested", &now.to_string()).await?;
        }
        cve::state_set(st, "scan_requested", &now.to_string()).await
    }
    .await;
    match r {
        Ok(()) => (
            StatusCode::ACCEPTED,
            Json(json!({ "requested": now, "fetch": fetch })),
        )
            .into_response(),
        Err(e) => err(e),
    }
}

#[derive(Deserialize)]
struct FindingsQ {
    source: Option<String>,
    severity: Option<String>,
}

async fn findings(State(s): State<AppState>, Query(q): Query<FindingsQ>) -> Response {
    match cve::last_report(&s.config_store).await {
        Ok(r) => {
            let r = r.unwrap_or_default();
            let list: Vec<_> = r
                .findings
                .iter()
                .filter(|f| q.source.as_deref().map(|x| x == f.source).unwrap_or(true))
                .filter(|f| {
                    q.severity
                        .as_deref()
                        .map(|x| x == f.severity)
                        .unwrap_or(true)
                })
                .collect();
            Json(json!({ "verdict": r.verdict, "at": r.at, "findings": list })).into_response()
        }
        Err(e) => err(e),
    }
}

#[derive(Deserialize)]
struct HistQ {
    limit: Option<i64>,
}

async fn history(State(s): State<AppState>, Query(q): Query<HistQ>) -> Response {
    match cve::scan_history(&s.config_store, q.limit.unwrap_or(500)).await {
        Ok(h) => Json(json!({ "history": h })).into_response(),
        Err(e) => err(e),
    }
}

pub fn router() -> axum::Router<AppState> {
    axum::Router::new()
        .route("/cve", get(overview))
        .route("/cve/settings", put(put_settings))
        .route("/cve/scan", post(scan))
        .route("/cve/findings", get(findings))
        .route("/cve/history", get(history))
}

#[derive(Template)]
#[template(path = "cve.html")]
struct CveTemplate {
    page: &'static str,
    can_modify: bool,
}

async fn page(me: crate::auth::AuthUser) -> Response {
    match (CveTemplate {
        page: "cve",
        can_modify: me.session.role.can_modify(),
    })
    .render()
    {
        Ok(h) => Html(h.replace("@PATRONUS_VERSION@", env!("CARGO_PKG_VERSION"))).into_response(),
        Err(e) => {
            tracing::error!("render CVE exposure page: {e}");
            (StatusCode::INTERNAL_SERVER_ERROR, "Failed to render page").into_response()
        }
    }
}

pub fn pages() -> axum::Router<AppState> {
    axum::Router::new().route("/security/cve-exposure", get(page))
}
