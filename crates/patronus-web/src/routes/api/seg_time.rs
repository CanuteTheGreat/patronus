//! Parental time limits (device segmentation, "e"): policies with weekly
//! windows and a daily active-time quota, attached to groups or devices, and
//! the parent actions (+N minutes today, pause, resume).
//!
//! - `GET    /api/segmentation/time/policies`
//! - `POST   /api/segmentation/time/policies`           -> 201 {id}
//! - `PUT    /api/segmentation/time/policies/{id}`      (partial; `windows` replaces)
//! - `DELETE /api/segmentation/time/policies/{id}`      (detaches it)
//! - `POST   /api/segmentation/time/assign`             {kind: group|device, id, policy_id|null}
//! - `GET    /api/segmentation/time/usage`              live per-device state
//! - `POST   /api/segmentation/devices/{id}/time/bonus` {minutes}
//! - `POST   /api/segmentation/devices/{id}/time/pause` / `.../resume`
//! - page `/segmentation/time`
//!
//! Every change is applied at once (`seg_time::refresh`: the nft sets move
//! without a firewall reload); the minute ticker (state/seg.rs) does the
//! accounting and the window edges.

use crate::state::AppState;
use askama::Template;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{Html, IntoResponse, Response},
    routing::{get, post, put},
    Json,
};
use patronus_firewall::schedule;
use patronus_firewall::seg_time::{self, PolicyIn};
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

async fn list(State(s): State<AppState>) -> Response {
    let st = &*s.config_store;
    let at = schedule::now();
    match (
        seg_time::list_policies(st).await,
        seg_time::usage_overview(st, at).await,
    ) {
        (Ok(p), Ok(u)) => Json(json!({
            "policies": p,
            "usage": u,
            "now": at.format("%Y-%m-%d %H:%M").to_string(),
            "limited_devices": u.len(),
        }))
        .into_response(),
        (Err(e), _) | (_, Err(e)) => err(e),
    }
}

async fn create(State(s): State<AppState>, Json(i): Json<PolicyIn>) -> Response {
    match seg_time::create_policy(&s.config_store, &i).await {
        Ok(id) => {
            // the first policy opens the "time's up" page port in the main firewall
            if let Err(e) = s.firewall.push().await {
                tracing::error!("firewall re-apply after a time policy was created: {e}");
            }
            let _ = seg_time::refresh(&s.config_store).await;
            (StatusCode::CREATED, Json(json!({ "id": id }))).into_response()
        }
        Err(e) => err(e),
    }
}

async fn update(
    State(s): State<AppState>,
    Path(id): Path<i64>,
    Json(i): Json<PolicyIn>,
) -> Response {
    match seg_time::update_policy(&s.config_store, id, &i).await {
        Ok(()) => applied(&s).await,
        Err(e) => err(e),
    }
}

async fn delete(State(s): State<AppState>, Path(id): Path<i64>) -> Response {
    match seg_time::delete_policy(&s.config_store, id).await {
        Ok(()) => {
            if let Err(e) = s.firewall.push().await {
                tracing::error!("firewall re-apply after a time policy was deleted: {e}");
            }
            applied(&s).await
        }
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
    match seg_time::assign(&s.config_store, &a.kind, a.id, a.policy_id).await {
        Ok(()) => applied(&s).await,
        Err(e) => err(e),
    }
}

async fn applied(s: &AppState) -> Response {
    match seg_time::refresh(&s.config_store).await {
        Ok(()) => Json(json!({ "ok": true })).into_response(),
        Err(e) => err(format!("saved, but not applied to nftables: {e}")),
    }
}

async fn usage(State(s): State<AppState>) -> Response {
    match seg_time::usage_overview(&s.config_store, schedule::now()).await {
        Ok(u) => Json(json!({ "usage": u })).into_response(),
        Err(e) => err(e),
    }
}

/// The usage day of a device (depends on its policy's reset hour).
async fn day_of(s: &AppState, device: i64) -> Result<String, String> {
    let at = schedule::now();
    match seg_time::load_targets(&s.config_store).await {
        Ok(t) => t
            .iter()
            .find(|t| t.device_id == device)
            .map(|t| seg_time::usage_day(at, t.policy.reset_hour))
            .ok_or_else(|| "device not found or it has no time policy".to_string()),
        Err(e) => Err(e.to_string()),
    }
}

#[derive(Deserialize)]
struct Bonus {
    minutes: i64,
}

async fn bonus(State(s): State<AppState>, Path(id): Path<i64>, Json(b): Json<Bonus>) -> Response {
    let day = match day_of(&s, id).await {
        Ok(d) => d,
        Err(m) => return err(m),
    };
    match seg_time::add_bonus(&s.config_store, &day, id, b.minutes).await {
        Ok(()) => applied(&s).await,
        Err(e) => err(e),
    }
}

async fn pause(State(s): State<AppState>, Path(id): Path<i64>) -> Response {
    set_pause(s, id, true).await
}

async fn resume(State(s): State<AppState>, Path(id): Path<i64>) -> Response {
    set_pause(s, id, false).await
}

async fn set_pause(s: AppState, id: i64, on: bool) -> Response {
    let day = match day_of(&s, id).await {
        Ok(d) => d,
        Err(m) => return err(m),
    };
    match seg_time::set_paused(&s.config_store, &day, id, on).await {
        Ok(()) => applied(&s).await,
        Err(e) => err(e),
    }
}

pub fn router() -> axum::Router<AppState> {
    axum::Router::new()
        .route("/segmentation/time/policies", get(list).post(create))
        .route(
            "/segmentation/time/policies/:id",
            put(update).delete(delete),
        )
        .route("/segmentation/time/assign", post(assign))
        .route("/segmentation/time/usage", get(usage))
        .route("/segmentation/devices/:id/time/bonus", post(bonus))
        .route("/segmentation/devices/:id/time/pause", post(pause))
        .route("/segmentation/devices/:id/time/resume", post(resume))
}

#[derive(Template)]
#[template(path = "seg_time.html")]
struct TimeTemplate {
    page: &'static str,
    can_modify: bool,
}

async fn page(me: crate::auth::AuthUser) -> Response {
    match (TimeTemplate {
        page: "time-limits",
        can_modify: me.session.role.can_modify(),
    })
    .render()
    {
        Ok(h) => Html(h).into_response(),
        Err(e) => {
            tracing::error!("render time limits: {e}");
            (StatusCode::INTERNAL_SERVER_ERROR, "Failed to render page").into_response()
        }
    }
}

pub fn pages() -> axum::Router<AppState> {
    axum::Router::new().route("/segmentation/time", get(page))
}
