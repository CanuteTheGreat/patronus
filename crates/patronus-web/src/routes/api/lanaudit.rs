//! LAN security audit (`patronus_network::lanaudit`, docs/LAN-AUDIT.md).
//!
//! - `GET    /api/lanaudit`                 settings, defaults, tools, recent scans, running?
//! - `PUT    /api/lanaudit/settings`        partial settings (validated, stored)
//! - `POST   /api/lanaudit/scan`            start a scan now (manual) -> {scan_id}
//! - `GET    /api/lanaudit/scans?limit=N`   recent scans
//! - `GET    /api/lanaudit/scans/:id`       one scan: hosts, open ports, findings
//! - `GET    /api/lanaudit/scans/:id/export.csv` open ports as CSV
//! - `GET    /api/lanaudit/scans/:id/export.pdf` a printable report
//! - page `/security/lan-audit`

use crate::state::AppState;
use askama::Template;
use axum::{
    extract::{Path, Query, State},
    http::{header, StatusCode},
    response::{Html, IntoResponse, Response},
    routing::{get, post, put},
    Json,
};
use patronus_network::lanaudit::{self, EventSink, SettingsIn};
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;

fn err(e: impl std::fmt::Display) -> Response {
    let msg = e.to_string();
    let code = if msg.contains("Invalid") {
        StatusCode::BAD_REQUEST
    } else if msg.contains("not found") {
        StatusCode::NOT_FOUND
    } else {
        StatusCode::INTERNAL_SERVER_ERROR
    };
    (code, Json(json!({ "error": msg }))).into_response()
}

/// An event sink that records a security event and delivers it to the
/// notification channels, exactly like the gateway/uplink monitors do.
fn event_sink(store: Arc<patronus_config::ConfigStore>) -> EventSink {
    EventSink {
        record: Box::new(move |kind, subject, severity, detail| {
            let store = store.clone();
            Box::pin(async move {
                let e = crate::state::telemetry::Event {
                    id: 0,
                    ts: chrono::Utc::now().timestamp(),
                    kind,
                    subject,
                    severity,
                    detail,
                };
                if let Err(err) = crate::state::telemetry::record(&store, &e).await {
                    tracing::warn!("lan-audit event: {err}");
                }
                crate::state::telemetry::deliver(store, e).await;
            })
        }),
    }
}

async fn overview(State(s): State<AppState>) -> Response {
    let st = &s.config_store;
    let settings = match lanaudit::load(st).await {
        Ok(v) => v,
        Err(e) => return err(e),
    };
    let scans = lanaudit::list_scans(st, 50).await.unwrap_or_default();
    let running = scans.iter().any(|x| x.state == "running");
    let (nmap, rustscan) = lanaudit::tools_present();
    Json(json!({
        "settings": settings,
        "defaults": lanaudit::Settings::default(),
        "severities": lanaudit::SEVERITIES,
        "tools": { "nmap": nmap, "rustscan": rustscan },
        "running": running,
        "scans": scans,
    }))
    .into_response()
}

async fn put_settings(State(s): State<AppState>, Json(i): Json<SettingsIn>) -> Response {
    match lanaudit::save(&s.config_store, &i).await {
        Ok(_) => overview(State(s)).await,
        Err(e) => err(e),
    }
}

async fn start_scan(State(s): State<AppState>) -> Response {
    let st = s.config_store.clone();
    // refuse a second scan while one is running
    if lanaudit::list_scans(&st, 1)
        .await
        .ok()
        .and_then(|v| v.into_iter().next())
        .is_some_and(|x| x.state == "running")
    {
        return (
            StatusCode::CONFLICT,
            Json(json!({ "error": "a scan is already running" })),
        )
            .into_response();
    }
    // run it in the background; the page polls the scans list
    let sink = Arc::new(event_sink(st.clone()));
    tokio::spawn(async move {
        if let Err(e) = lanaudit::run_scan(&st, "manual", Some(sink.as_ref())).await {
            tracing::warn!("manual LAN audit: {e}");
        }
    });
    (StatusCode::ACCEPTED, Json(json!({ "started": true }))).into_response()
}

#[derive(Deserialize)]
struct ListQ {
    limit: Option<i64>,
}

async fn list(State(s): State<AppState>, Query(q): Query<ListQ>) -> Response {
    match lanaudit::list_scans(&s.config_store, q.limit.unwrap_or(50)).await {
        Ok(v) => Json(json!({ "scans": v })).into_response(),
        Err(e) => err(e),
    }
}

async fn detail(State(s): State<AppState>, Path(id): Path<i64>) -> Response {
    match lanaudit::scan_detail(&s.config_store, id).await {
        Ok(v) => Json(v).into_response(),
        Err(e) => err(e),
    }
}

async fn export_csv(State(s): State<AppState>, Path(id): Path<i64>) -> Response {
    match lanaudit::scan_csv(&s.config_store, id).await {
        Ok(body) => (
            [
                (header::CONTENT_TYPE, "text/csv; charset=utf-8".to_string()),
                (
                    header::CONTENT_DISPOSITION,
                    format!("attachment; filename=\"lan-audit-{id}.csv\""),
                ),
            ],
            body,
        )
            .into_response(),
        Err(e) => err(e),
    }
}

async fn export_pdf(State(s): State<AppState>, Path(id): Path<i64>) -> Response {
    match lanaudit::scan_pdf(&s.config_store, id).await {
        Ok(body) => (
            [
                (header::CONTENT_TYPE, "application/pdf".to_string()),
                (
                    header::CONTENT_DISPOSITION,
                    format!("attachment; filename=\"lan-audit-{id}.pdf\""),
                ),
            ],
            body,
        )
            .into_response(),
        Err(e) => err(e),
    }
}

pub fn router() -> axum::Router<AppState> {
    axum::Router::new()
        .route("/lanaudit", get(overview))
        .route("/lanaudit/settings", put(put_settings))
        .route("/lanaudit/scan", post(start_scan))
        .route("/lanaudit/scans", get(list))
        .route("/lanaudit/scans/:id", get(detail))
        .route("/lanaudit/scans/:id/export.csv", get(export_csv))
        .route("/lanaudit/scans/:id/export.pdf", get(export_pdf))
}

#[derive(Template)]
#[template(path = "lanaudit.html")]
struct LanAuditTemplate {
    page: &'static str,
    can_modify: bool,
}

async fn page(me: crate::auth::AuthUser) -> Response {
    match (LanAuditTemplate {
        page: "lanaudit",
        can_modify: me.session.role.can_modify(),
    })
    .render()
    {
        Ok(h) => Html(h.replace("@PATRONUS_VERSION@", env!("CARGO_PKG_VERSION"))).into_response(),
        Err(e) => {
            tracing::error!("render lan-audit page: {e}");
            (StatusCode::INTERNAL_SERVER_ERROR, "Failed to render page").into_response()
        }
    }
}

pub fn pages() -> axum::Router<AppState> {
    axum::Router::new().route("/security/lan-audit", get(page))
}
