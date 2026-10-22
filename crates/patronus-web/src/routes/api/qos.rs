//! Traffic shaping API and page (lane C, USE=qos): `/api/qos`, `/qos`.
//! One root qdisc per interface (CAKE, fq_codel or a rate limit), applied
//! with `tc` through `patronus applyd` and re-applied at boot.

use crate::state::AppState;
use axum::{
    http::StatusCode,
    response::{Html, IntoResponse, Response},
    Json,
};
use serde_json::json;

#[cfg(feature = "qos")]
mod built {
    use super::*;
    use askama::Template;
    use axum::extract::{Path, State};
    use patronus_network::shaping;

    fn err(e: anyhow::Error) -> Response {
        let msg = e.to_string();
        let code = if msg.contains("Invalid") {
            StatusCode::BAD_REQUEST
        } else if msg.contains("no shaper") {
            StatusCode::NOT_FOUND
        } else {
            StatusCode::INTERNAL_SERVER_ERROR
        };
        (code, Json(json!({ "error": msg }))).into_response()
    }

    #[derive(Template)]
    #[template(path = "qos.html")]
    pub struct QosTemplate {
        pub page: &'static str,
        pub can_modify: bool,
    }

    pub async fn page(me: crate::auth::AuthUser) -> Response {
        match (QosTemplate {
            page: "qos",
            can_modify: me.session.role.can_modify(),
        })
        .render()
        {
            Ok(h) => Html(h).into_response(),
            Err(e) => {
                tracing::error!("render qos: {e}");
                (StatusCode::INTERNAL_SERVER_ERROR, "Failed to render page").into_response()
            }
        }
    }

    async fn overview(State(state): State<AppState>) -> Response {
        state
            .lan
            .qos_overview()
            .await
            .map(|v| Json(v).into_response())
            .unwrap_or_else(err)
    }

    async fn add(State(state): State<AppState>, Json(i): Json<shaping::ShaperInput>) -> Response {
        match state.lan.save_shaper(None, i).await {
            Ok(id) => (StatusCode::CREATED, Json(json!({"id": id}))).into_response(),
            Err(e) => err(e),
        }
    }

    async fn put(
        State(state): State<AppState>,
        Path(id): Path<i64>,
        Json(i): Json<shaping::ShaperInput>,
    ) -> Response {
        match state.lan.save_shaper(Some(id), i).await {
            Ok(_) => Json(json!({"ok": true})).into_response(),
            Err(e) => err(e),
        }
    }

    async fn del(State(state): State<AppState>, Path(id): Path<i64>) -> Response {
        match state.lan.delete_shaper(id).await {
            Ok(()) => Json(json!({"ok": true})).into_response(),
            Err(e) => err(e),
        }
    }

    pub fn router() -> axum::Router<AppState> {
        use axum::routing::get;
        axum::Router::new()
            .route("/qos", get(overview).post(add))
            .route("/qos/:id", axum::routing::put(put).delete(del))
    }
}

pub fn router() -> axum::Router<AppState> {
    #[cfg(feature = "qos")]
    {
        built::router()
    }
    #[cfg(not(feature = "qos"))]
    {
        axum::Router::new()
    }
}

/// The `/qos` page.
pub fn pages() -> axum::Router<AppState> {
    use axum::routing::get;
    #[cfg(feature = "qos")]
    let h = get(built::page);
    #[cfg(not(feature = "qos"))]
    let h = get(|| async {
        Html(
            "<!DOCTYPE html><html><head><title>Traffic shaping - Patronus</title></head><body>\
             <h1>Traffic shaping</h1><p>This Patronus build does not include traffic shaping. \
             Rebuild with <code>USE=qos</code> (emerge net-firewall/patronus).</p>\
             <p><a href=\"/\">Back to the dashboard</a></p></body></html>",
        )
        .into_response()
    });
    axum::Router::new().route("/qos", h)
}
