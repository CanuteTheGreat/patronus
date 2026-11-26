//! Security overview + one-click hardening baseline (`crate::security`, docs/SECURITY-OVERVIEW.md).
//!
//! - `GET  /api/security`                   grade, score and every check with its live evidence;
//!   `?cached=1`: an answer up to 30 s old, for the dashboard
//! - `GET  /api/security/baseline`          dry run: the change set + what it leaves alone and why
//! - `POST /api/security/baseline`          {token} apply the dry run's plan as ONE revision (admin)
//! - `POST /api/security/baseline/undo`     {revision} restore the revision taken before it (admin)
//! - `PUT  /api/security/settings`          thresholds (`security.*`, partial)
//! - `GET  /api/security/feeds?hours=N`     threat-feed catalog with hit counters and hourly history
//! - page `/security`

use crate::security::{self, SettingsIn};
use crate::state::AppState;
use askama::Template;
use axum::{
    extract::{ConnectInfo, Query, State},
    http::StatusCode,
    response::{Html, IntoResponse, Response},
    routing::{get, post, put},
    Json,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::sync::Mutex;

fn err(e: impl std::fmt::Display) -> Response {
    let msg = e.to_string();
    let code = if msg.contains("Invalid") {
        StatusCode::BAD_REQUEST
    } else if msg.contains("changed since") {
        StatusCode::CONFLICT
    } else {
        StatusCode::INTERNAL_SERVER_ERROR
    };
    (code, Json(json!({ "error": msg }))).into_response()
}

static CACHE: Mutex<Option<(std::time::Instant, Value)>> = Mutex::new(None);

async fn fresh(s: &AppState) -> Value {
    let v = security::overview(s).await;
    if let Ok(mut c) = CACHE.lock() {
        *c = Some((std::time::Instant::now(), v.clone()));
    }
    v
}

#[derive(Deserialize, Default)]
struct OverviewQ {
    #[serde(default)]
    cached: Option<u8>,
}

async fn overview(State(s): State<AppState>, Query(q): Query<OverviewQ>) -> Response {
    if q.cached == Some(1) {
        if let Ok(c) = CACHE.lock() {
            if let Some((t, v)) = c.as_ref() {
                if t.elapsed().as_secs() < 30 {
                    return Json(v.clone()).into_response();
                }
            }
        }
    }
    Json(fresh(&s).await).into_response()
}

async fn plan_for(s: &AppState, ci: Option<ConnectInfo<SocketAddr>>) -> security::Plan {
    let i = security::gather(s).await;
    let checks = security::run_checks(&i);
    let path = security::session_path(s, ci.map(|ConnectInfo(a)| a.ip())).await;
    security::plan(&i, &checks, &path)
}

async fn dry_run(State(s): State<AppState>, ci: Option<ConnectInfo<SocketAddr>>) -> Response {
    let p = plan_for(&s, ci).await;
    let newer = newer_revisions(&s).await;
    Json(json!({ "plan": p, "dry_run": true, "revisions_after_baseline": newer })).into_response()
}

#[derive(Deserialize)]
struct ApplyIn {
    token: String,
}

async fn apply(
    State(s): State<AppState>,
    me: crate::auth::AdminUser,
    ci: Option<ConnectInfo<SocketAddr>>,
    Json(b): Json<ApplyIn>,
) -> Response {
    let p = plan_for(&s, ci).await;
    if p.token != b.token {
        return err("the system changed since the dry run: review the changes again");
    }
    match security::apply_plan(&s, &p, &me.session.username).await {
        Ok((rev, lines)) => {
            let v = fresh(&s).await;
            Json(json!({ "ok": true, "revision_before": rev, "applied": lines, "overview": v }))
                .into_response()
        }
        Err(e) => err(e),
    }
}

/// Revisions taken after the last baseline (an undo rewinds them too).
async fn newer_revisions(s: &AppState) -> usize {
    let Some(rev) = s
        .config_store
        .load_system_config(security::K_BASELINE_REVISION)
        .await
        .ok()
        .flatten()
        .and_then(|v| v.parse::<i64>().ok())
    else {
        return 0;
    };
    s.config_store
        .list_revisions()
        .await
        .map(|r| r.iter().filter(|(id, ..)| *id > rev).count())
        .unwrap_or(0)
}

#[derive(Deserialize)]
struct UndoIn {
    revision: i64,
}

async fn undo(
    State(s): State<AppState>,
    me: crate::auth::AdminUser,
    Json(b): Json<UndoIn>,
) -> Response {
    let known = s
        .config_store
        .load_system_config(security::K_BASELINE_REVISION)
        .await
        .ok()
        .flatten()
        .and_then(|v| v.parse::<i64>().ok());
    if known != Some(b.revision) {
        return err(format!(
            "Invalid revision {}: the last baseline was taken before revision {}",
            b.revision,
            known
                .map(|k| k.to_string())
                .unwrap_or_else(|| "(none)".into())
        ));
    }
    match security::undo(&s, b.revision, &me.session.username).await {
        Ok(lines) => {
            let v = fresh(&s).await;
            Json(json!({ "ok": true, "restored": b.revision, "applied": lines, "overview": v }))
                .into_response()
        }
        Err(e) => err(e),
    }
}

async fn put_settings(
    State(s): State<AppState>,
    me: crate::auth::AuthUser,
    Json(i): Json<SettingsIn>,
) -> Response {
    if !me.session.role.can_modify() {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "read-only account" })),
        )
            .into_response();
    }
    if let Err(e) = s
        .config_store
        .snapshot(&me.session.username, "security overview settings")
        .await
    {
        return err(e);
    }
    match security::save_settings(&s.config_store, &i).await {
        Ok(v) => Json(json!({ "settings": v })).into_response(),
        Err(e) => err(e),
    }
}

#[derive(Deserialize, Default)]
struct FeedsQ {
    #[serde(default)]
    hours: Option<i64>,
}

async fn feeds(State(s): State<AppState>, Query(q): Query<FeedsQ>) -> Response {
    let hours = q.hours.unwrap_or(24).clamp(1, 24 * 366);
    let now = chrono::Utc::now().timestamp();
    let t = match s.firewall.threat_overview().await {
        Ok(t) => t,
        Err(e) => return err(e),
    };
    let series = security::feed_hit_series(&s.config_store, now - hours * 3600)
        .await
        .unwrap_or_default();
    Json(json!({ "threat": t, "series": series, "hours": hours, "now": now })).into_response()
}

pub fn router() -> axum::Router<AppState> {
    axum::Router::new()
        .route("/security", get(overview))
        .route("/security/baseline", get(dry_run).post(apply))
        .route("/security/baseline/undo", post(undo))
        .route("/security/settings", put(put_settings))
        .route("/security/feeds", get(feeds))
}

#[derive(Template)]
#[template(path = "security.html")]
struct SecurityTemplate {
    page: &'static str,
    can_modify: bool,
    is_admin: bool,
}

async fn page(me: crate::auth::AuthUser) -> Response {
    match (SecurityTemplate {
        page: "security",
        can_modify: me.session.role.can_modify(),
        is_admin: me.session.role.is_admin(),
    })
    .render()
    {
        Ok(h) => Html(h.replace("@PATRONUS_VERSION@", env!("CARGO_PKG_VERSION"))).into_response(),
        Err(e) => {
            tracing::error!("render security page: {e}");
            (StatusCode::INTERNAL_SERVER_ERROR, "Failed to render page").into_response()
        }
    }
}

pub fn pages() -> axum::Router<AppState> {
    axum::Router::new().route("/security", get(page))
}
