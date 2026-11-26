//! Captive portal administration (USE=captive-portal): the sessions page
//! with disconnect, voucher rolls with their print sheets. Configuration
//! (zones, users, rolls, passthrough, ports) is the feature page
//! `/svc/captive` (`/api/svc/captive`).
//!
//! - `GET  /captive-portal`                               page
//! - `GET  /api/captive-portal/sessions?ended=N`          active sessions (+ the last N ended)
//! - `POST /api/captive-portal/sessions/:id/disconnect`   sign a client out
//! - `GET  /api/captive-portal/rolls`                     rolls with code / used counts
//! - `GET  /captive-portal/rolls/:id/print`               printable voucher sheet

use crate::state::AppState;
use askama::Template;
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use patronus_captiveportal::engine::{LiveSys, Portal};
use serde_json::{json, Value};
use sqlx::Row;
use std::collections::HashMap;
use std::sync::Arc;

#[derive(Template)]
#[template(path = "captive_portal.html")]
struct PageTemplate {
    page: String,
    can_modify: bool,
}

async fn page(me: crate::auth::AuthUser) -> Response {
    match (PageTemplate {
        page: "captive-portal".into(),
        can_modify: me.session.role.can_modify(),
    })
    .render()
    {
        Ok(h) => Html(h).into_response(),
        Err(e) => {
            tracing::error!("render captive portal page: {e}");
            (StatusCode::INTERNAL_SERVER_ERROR, "Failed to render page").into_response()
        }
    }
}

fn err(code: StatusCode, msg: impl ToString) -> Response {
    (code, Json(json!({"error": msg.to_string()}))).into_response()
}

async fn sessions(
    State(st): State<AppState>,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    let ended = q
        .get("ended")
        .and_then(|v| v.parse::<i64>().ok())
        .unwrap_or(0)
        .clamp(0, 1000);
    let portal = Portal::new(st.config_store.clone(), Arc::new(LiveSys));
    let now = patronus_network::lan::now();
    let list: Vec<Value> = portal
        .sessions(ended)
        .await
        .into_iter()
        .map(|s| {
            let mut v = serde_json::to_value(&s).unwrap_or(Value::Null);
            v["seconds_left"] = if s.ended.is_none() && s.expires > 0 {
                json!((s.expires - now).max(0))
            } else {
                Value::Null
            };
            v
        })
        .collect();
    let zones: Vec<Value> = patronus_network::captive::zones(&st.config_store)
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|z| json!({"name": z.name, "enabled": z.enabled, "interface": z.interface, "login": z.auth}))
        .collect();
    Json(json!({"sessions": list, "zones": zones, "now": now})).into_response()
}

async fn disconnect(State(st): State<AppState>, Path(id): Path<i64>) -> Response {
    match patronus_network::captive::request_disconnect(&st.config_store, id).await {
        Ok(0) => err(StatusCode::NOT_FOUND, format!("no active session {id}")),
        Ok(_) => Json(json!({"disconnecting": id})).into_response(),
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, e),
    }
}

async fn rolls(State(st): State<AppState>) -> Response {
    let Ok(pool) = st.config_store.pool() else {
        return err(StatusCode::INTERNAL_SERVER_ERROR, "store unavailable");
    };
    let rows = sqlx::query(
        "SELECT r.id, r.name, r.zone, r.count, r.minutes, \
         (SELECT count(*) FROM cp_vouchers v WHERE v.roll_id = r.id), \
         (SELECT count(*) FROM cp_vouchers v JOIN cp_voucher_use u ON u.code = v.code WHERE v.roll_id = r.id) \
         FROM cp_voucher_rolls r ORDER BY r.id",
    )
    .fetch_all(pool)
    .await;
    match rows {
        Ok(rows) => Json(json!(rows
            .iter()
            .map(|r| json!({
                "id": r.get::<i64, _>(0), "name": r.get::<String, _>(1), "zone": r.get::<String, _>(2),
                "count": r.get::<i64, _>(3), "minutes": r.get::<i64, _>(4),
                "codes": r.get::<i64, _>(5), "used": r.get::<i64, _>(6),
            }))
            .collect::<Vec<_>>()))
        .into_response(),
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, e),
    }
}

async fn print(
    State(st): State<AppState>,
    _me: crate::auth::AuthUser,
    Path(id): Path<i64>,
) -> Response {
    let Ok(pool) = st.config_store.pool() else {
        return err(StatusCode::INTERNAL_SERVER_ERROR, "store unavailable");
    };
    let Ok(Some(r)) = sqlx::query("SELECT name, zone, minutes FROM cp_voucher_rolls WHERE id = ?")
        .bind(id)
        .fetch_optional(pool)
        .await
    else {
        return err(StatusCode::NOT_FOUND, format!("no voucher roll {id}"));
    };
    let (name, zone, minutes): (String, String, i64) = (r.get(0), r.get(1), r.get(2));
    let Some(z) = patronus_network::captive::zones(&st.config_store)
        .await
        .unwrap_or_default()
        .into_iter()
        .find(|z| z.name == zone)
    else {
        return err(StatusCode::NOT_FOUND, format!("no zone {zone}"));
    };
    let codes = patronus_network::captive::roll_codes(&st.config_store, id)
        .await
        .unwrap_or_default();
    Html(patronus_captiveportal::pages::print_sheet(
        &z, &name, minutes, &codes,
    ))
    .into_response()
}

pub fn pages() -> Router<AppState> {
    Router::new()
        .route("/captive-portal", get(page))
        .route("/captive-portal/rolls/:id/print", get(print))
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/captive-portal/sessions", get(sessions))
        .route(
            "/api/captive-portal/sessions/:id/disconnect",
            post(disconnect),
        )
        .route("/api/captive-portal/rolls", get(rolls))
}
