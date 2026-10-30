//! Per-device / per-group DNS policy and query logs (device segmentation,
//! "c2"). Needs the unbound resolver (feature `dns`).
//!
//! - `GET    /api/segmentation/dns/policies`               policies + rules + users + status
//! - `POST   /api/segmentation/dns/policies`               -> 201 {id}
//! - `PUT    /api/segmentation/dns/policies/{id}`          (partial)
//! - `DELETE /api/segmentation/dns/policies/{id}`          (detaches it)
//! - `POST   /api/segmentation/dns/policies/{id}/rules`    {action: block|allow|override, domain, address}
//! - `DELETE /api/segmentation/dns/policies/{id}/rules/{rid}`
//! - `POST   /api/segmentation/dns/assign`                 {kind: group|device, id, policy_id|null}
//! - `GET    /api/segmentation/dns/log?device=&q=&blocked=&since=&until=&limit=&before=`
//! - `GET    /api/segmentation/dns/log.csv` (same filters)
//! - `DELETE /api/segmentation/dns/log?device=`            clear
//! - `GET    /api/segmentation/dns/status`
//! - page `/segmentation/dns`

use crate::state::AppState;
use askama::Template;
use axum::{
    extract::{Path, Query, State},
    http::{header, StatusCode},
    response::{Html, IntoResponse, Response},
    routing::{delete, get, post, put},
    Json,
};
use patronus_network::seg_dns::{self, LogQuery, PolicyInput, RuleInput};
use serde::Deserialize;
use serde_json::json;

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

fn ok() -> Response {
    Json(json!({ "ok": true })).into_response()
}

async fn overview(State(s): State<AppState>) -> Response {
    match s.lan.seg_dns_overview().await {
        Ok(v) => Json(v).into_response(),
        Err(e) => err(e),
    }
}

async fn create(State(s): State<AppState>, Json(i): Json<PolicyInput>) -> Response {
    match s.lan.seg_dns_save_policy(None, i).await {
        Ok(id) => (StatusCode::CREATED, Json(json!({ "id": id }))).into_response(),
        Err(e) => err(e),
    }
}

async fn update(
    State(s): State<AppState>,
    Path(id): Path<i64>,
    Json(i): Json<PolicyInput>,
) -> Response {
    match s.lan.seg_dns_save_policy(Some(id), i).await {
        Ok(_) => ok(),
        Err(e) => err(e),
    }
}

async fn remove(State(s): State<AppState>, Path(id): Path<i64>) -> Response {
    match s.lan.seg_dns_delete_policy(id).await {
        Ok(()) => ok(),
        Err(e) => err(e),
    }
}

async fn add_rule(
    State(s): State<AppState>,
    Path(id): Path<i64>,
    Json(i): Json<RuleInput>,
) -> Response {
    match s.lan.seg_dns_add_rule(id, i).await {
        Ok(rid) => (StatusCode::CREATED, Json(json!({ "id": rid }))).into_response(),
        Err(e) => err(e),
    }
}

async fn del_rule(State(s): State<AppState>, Path((id, rid)): Path<(i64, i64)>) -> Response {
    match s.lan.seg_dns_delete_rule(id, rid).await {
        Ok(()) => ok(),
        Err(e) => err(e),
    }
}

#[derive(Deserialize)]
struct Assign {
    kind: String,
    id: i64,
    policy_id: Option<i64>,
}

async fn assign(State(s): State<AppState>, Json(a): Json<Assign>) -> Response {
    match s.lan.seg_dns_assign(&a.kind, a.id, a.policy_id).await {
        Ok(()) => ok(),
        Err(e) => err(e),
    }
}

async fn log(State(s): State<AppState>, Query(q): Query<LogQuery>) -> Response {
    match seg_dns::search_log(&s.config_store, &q).await {
        Ok(rows) => Json(json!({ "rows": rows })).into_response(),
        Err(e) => err(e),
    }
}

async fn log_csv(State(s): State<AppState>, Query(mut q): Query<LogQuery>) -> Response {
    q.limit = Some(q.limit.unwrap_or(5000));
    match seg_dns::search_log(&s.config_store, &q).await {
        Ok(rows) => (
            [
                (header::CONTENT_TYPE, "text/csv; charset=utf-8"),
                (
                    header::CONTENT_DISPOSITION,
                    "attachment; filename=\"dns-log.csv\"",
                ),
            ],
            seg_dns::to_csv(&rows),
        )
            .into_response(),
        Err(e) => err(e),
    }
}

#[derive(Deserialize)]
struct Clear {
    device: Option<i64>,
}

async fn clear(State(s): State<AppState>, Query(c): Query<Clear>) -> Response {
    match seg_dns::clear_log(&s.config_store, c.device).await {
        Ok(n) => Json(json!({ "deleted": n })).into_response(),
        Err(e) => err(e),
    }
}

async fn status(State(s): State<AppState>) -> Response {
    let path = seg_dns::log_path();
    let meta = std::fs::metadata(&path).ok();
    let rows: i64 = match s.config_store.pool() {
        Ok(p) => sqlx::query_scalar("SELECT COUNT(*) FROM seg_dns_log")
            .fetch_one(p)
            .await
            .unwrap_or(0),
        Err(_) => 0,
    };
    let last = crate::state::seg::LAST_INGEST
        .lock()
        .ok()
        .and_then(|g| g.clone());
    let clients = seg_dns::clients(&s.config_store).await.unwrap_or_default();
    let dns = s.lan.status("dns").await.unwrap_or(json!({}));
    Json(json!({
        "dns": dns,
        "enforced_devices": clients.len(),
        "log_file": path.to_string_lossy(),
        "log_file_exists": meta.is_some(),
        "log_file_bytes": meta.map(|m| m.len()),
        "log_rows": rows,
        "last_ingest": last.map(|(t, st)| json!({ "at": t, "lines": st.lines, "stored": st.stored })),
        "limits": "DNS-over-HTTPS cannot be blocked reliably: devices with a policy are redirected from port 53 and refused DNS-over-TLS (853); the family preset also answers the browsers' DoH canary names.",
    }))
    .into_response()
}

pub fn router() -> axum::Router<AppState> {
    axum::Router::new()
        .route("/segmentation/dns/policies", get(overview).post(create))
        .route("/segmentation/dns/policies/:id", put(update).delete(remove))
        .route("/segmentation/dns/policies/:id/rules", post(add_rule))
        .route(
            "/segmentation/dns/policies/:id/rules/:rid",
            delete(del_rule),
        )
        .route("/segmentation/dns/assign", post(assign))
        .route("/segmentation/dns/log", get(log).delete(clear))
        .route("/segmentation/dns/log.csv", get(log_csv))
        .route("/segmentation/dns/status", get(status))
}

#[derive(Template)]
#[template(path = "seg_dns.html")]
struct DnsTemplate {
    page: &'static str,
    can_modify: bool,
}

async fn page(me: crate::auth::AuthUser) -> Response {
    match (DnsTemplate {
        page: "dns-policy",
        can_modify: me.session.role.can_modify(),
    })
    .render()
    {
        Ok(h) => Html(h).into_response(),
        Err(e) => {
            tracing::error!("render DNS policy page: {e}");
            (StatusCode::INTERNAL_SERVER_ERROR, "Failed to render page").into_response()
        }
    }
}

pub fn pages() -> axum::Router<AppState> {
    axum::Router::new().route("/segmentation/dns", get(page))
}
