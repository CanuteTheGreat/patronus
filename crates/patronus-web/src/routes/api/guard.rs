//! Brute-force protection (`patronus_firewall::guard`, docs/BRUTE-FORCE.md).
//!
//! - `GET    /api/guard`                    settings, defaults, active bans, counted failures, history, kernel state
//! - `PUT    /api/guard/settings`           partial settings (validated, applied, undone on failure)
//! - `POST   /api/guard/bans`               {address, secs?, reason?} manual ban -> 201
//! - `DELETE /api/guard/bans?address=ADDR`  lift a ban (address, or an IPv6 prefix such as 2001:db8::/64)
//! - `GET    /api/guard/history?limit=N`    ban history, newest first
//! - page `/security/brute-force`

use crate::state::AppState;
use askama::Template;
use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{Html, IntoResponse, Response},
    routing::{get, post, put},
    Json,
};
use patronus_config::applier::Applier;
use patronus_firewall::guard::{self, SettingsIn};
use serde::Deserialize;
use serde_json::json;
use std::sync::{Arc, OnceLock};

fn applier() -> Arc<dyn Applier> {
    static A: OnceLock<Arc<dyn Applier>> = OnceLock::new();
    A.get_or_init(|| patronus_network::applyd::RemoteApplier::wrap(Arc::new(guard::GuardApplier)))
        .clone()
}

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

async fn overview_json(s: &AppState) -> patronus_core::Result<serde_json::Value> {
    let st = &s.config_store;
    let settings = guard::load(st).await?;
    let now = guard::now();
    let active = guard::active_bans(st, now).await?;
    let failures = guard::recent_failures(st, now - settings.find_secs as i64).await?;
    let history = guard::history(st, 100, now).await?;
    let status = applier()
        .status(st)
        .await
        .unwrap_or_else(|e| json!({ "error": e.to_string() }));
    let lan: Vec<String> = if settings.exempt_lan {
        guard::lan_networks(st)
            .await
            .iter()
            .map(|n| n.to_string())
            .collect()
    } else {
        Vec::new()
    };
    Ok(json!({
        "settings": settings,
        "defaults": guard::Settings::default(),
        "sources": guard::SOURCES,
        "now": now,
        "active": active,
        "failures": failures,
        "history": history,
        "status": status,
        "exempt_networks": lan,
    }))
}

async fn overview(State(s): State<AppState>) -> Response {
    match overview_json(&s).await {
        Ok(v) => Json(v).into_response(),
        Err(e) => err(e),
    }
}

async fn put_settings(State(s): State<AppState>, Json(i): Json<SettingsIn>) -> Response {
    let st = &s.config_store;
    let before = match guard::load(st).await {
        Ok(b) => b,
        Err(e) => return err(e),
    };
    if let Err(e) = guard::save(st, &i).await {
        return err(e);
    }
    if let Err(e) = applier().apply(st).await {
        let _ = guard::write(st, &before).await;
        let _ = applier().apply(st).await;
        return err(format!(
            "could not apply the brute-force protection ({e}); settings left unchanged"
        ));
    }
    overview(State(s)).await
}

#[derive(Deserialize)]
struct BanIn {
    address: String,
    secs: Option<u64>,
    #[serde(default)]
    reason: String,
}

async fn ban(State(s): State<AppState>, Json(b): Json<BanIn>) -> Response {
    let st = &s.config_store;
    match guard::manual_ban(st, &b.address, b.secs, &b.reason).await {
        Ok(key) => {
            if let Err(e) = applier().apply(st).await {
                tracing::warn!("brute-force protection: ban stored, kernel sync failed: {e}");
            }
            (StatusCode::CREATED, Json(json!({ "address": key }))).into_response()
        }
        Err(e) => err(e),
    }
}

#[derive(Deserialize)]
struct AddrQ {
    address: String,
}

async fn unban(
    me: crate::auth::AuthUser,
    State(s): State<AppState>,
    Query(q): Query<AddrQ>,
) -> Response {
    let st = &s.config_store;
    let by = format!("web:{}", me.session.username);
    match guard::unban(st, &q.address, &by).await {
        Ok(n) => {
            if let Err(e) = applier().apply(st).await {
                tracing::warn!("brute-force protection: unban stored, kernel sync failed: {e}");
            }
            Json(json!({ "lifted": n })).into_response()
        }
        Err(e) => err(e),
    }
}

#[derive(Deserialize)]
struct HistQ {
    limit: Option<i64>,
}

async fn history(State(s): State<AppState>, Query(q): Query<HistQ>) -> Response {
    match guard::history(&s.config_store, q.limit.unwrap_or(500), guard::now()).await {
        Ok(h) => Json(json!({ "history": h })).into_response(),
        Err(e) => err(e),
    }
}

pub fn router() -> axum::Router<AppState> {
    axum::Router::new()
        .route("/guard", get(overview))
        .route("/guard/settings", put(put_settings))
        .route("/guard/bans", post(ban).delete(unban))
        .route("/guard/history", get(history))
}

#[derive(Template)]
#[template(path = "guard.html")]
struct GuardTemplate {
    page: &'static str,
    can_modify: bool,
}

async fn page(me: crate::auth::AuthUser) -> Response {
    match (GuardTemplate {
        page: "guard",
        can_modify: me.session.role.can_modify(),
    })
    .render()
    {
        Ok(h) => Html(h.replace("@PATRONUS_VERSION@", env!("CARGO_PKG_VERSION"))).into_response(),
        Err(e) => {
            tracing::error!("render brute-force page: {e}");
            (StatusCode::INTERNAL_SERVER_ERROR, "Failed to render page").into_response()
        }
    }
}

pub fn pages() -> axum::Router<AppState> {
    axum::Router::new().route("/security/brute-force", get(page))
}
