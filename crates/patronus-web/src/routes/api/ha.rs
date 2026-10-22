//! High availability API and page (lane G): `/api/ha`, `/ha`.
//!
//! Virtual IPs (VRRP failover via keepalived, or plain aliases), the node's
//! priority/peer, connection-state sync (conntrackd) and maintenance mode.
//! Every change goes store -> applier (keepalived/conntrackd through
//! `patronus applyd`) -> firewall (VRRP/sync ports) and is undone when the
//! applier refuses it. Compiled with `USE=ha`; without it the page says so.

use crate::state::AppState;
use axum::{
    http::StatusCode,
    response::{Html, IntoResponse, Response},
    Json,
};
use serde_json::json;

#[cfg(feature = "ha")]
mod built {
    use super::*;
    use crate::auth::AuthUser;
    use askama::Template;
    use axum::extract::{Path, State};
    use patronus_network::ha;

    fn err(e: anyhow::Error) -> Response {
        let msg = e.to_string();
        let code = if msg.contains("Invalid") {
            StatusCode::BAD_REQUEST
        } else if msg.contains("no virtual IP") {
            StatusCode::NOT_FOUND
        } else {
            StatusCode::INTERNAL_SERVER_ERROR
        };
        (code, Json(json!({ "error": msg }))).into_response()
    }

    #[derive(Template)]
    #[template(path = "ha.html")]
    pub struct HaTemplate {
        pub page: &'static str,
        pub can_modify: bool,
    }

    pub async fn page(me: AuthUser) -> Response {
        match (HaTemplate {
            page: "ha",
            can_modify: me.session.role.can_modify(),
        })
        .render()
        {
            Ok(h) => Html(h).into_response(),
            Err(e) => {
                tracing::error!("render ha: {e}");
                (StatusCode::INTERNAL_SERVER_ERROR, "Failed to render page").into_response()
            }
        }
    }

    /// The firewall carries the VRRP / state-sync rules: re-render it.
    async fn firewall(state: &AppState) -> Option<Response> {
        state.firewall.apply_rules().await.err().map(|e| {
            err(anyhow::anyhow!(
                "the HA configuration was applied but the firewall could not be updated: {e}"
            ))
        })
    }

    /// GET /api/ha -- settings (the VRRP password only for admins), virtual
    /// IPs, live status.
    async fn overview(State(state): State<AppState>, me: AuthUser) -> Response {
        match state.lan.ha_overview().await {
            Ok(mut v) => {
                if !me.session.role.is_admin() {
                    v["settings"]["password"] = json!("");
                }
                Json(v).into_response()
            }
            Err(e) => err(e),
        }
    }

    /// PUT /api/ha/settings
    async fn put_settings(
        State(state): State<AppState>,
        Json(i): Json<ha::SettingsInput>,
    ) -> Response {
        // open the ports first: a VRRP advert must not be dropped while keepalived starts
        let r = state.lan.save_ha_settings(i).await;
        if let Err(e) = r {
            return err(e);
        }
        if let Some(r) = firewall(&state).await {
            return r;
        }
        Json(json!({"ok": true})).into_response()
    }

    #[derive(serde::Deserialize)]
    struct Maintenance {
        enabled: bool,
    }

    /// POST /api/ha/maintenance {"enabled": bool} -- advertise the lowest
    /// priority so the peer takes the virtual IPs (and give them back).
    async fn maintenance(State(state): State<AppState>, Json(m): Json<Maintenance>) -> Response {
        match state
            .lan
            .save_ha_settings(ha::SettingsInput {
                maintenance: Some(m.enabled),
                ..Default::default()
            })
            .await
        {
            Ok(()) => Json(json!({"ok": true, "maintenance": m.enabled})).into_response(),
            Err(e) => err(e),
        }
    }

    /// POST /api/ha/vips
    async fn add_vip(State(state): State<AppState>, Json(i): Json<ha::VipInput>) -> Response {
        match state.lan.save_vip(None, i).await {
            Ok(id) => {
                if let Some(r) = firewall(&state).await {
                    return r;
                }
                (StatusCode::CREATED, Json(json!({"id": id}))).into_response()
            }
            Err(e) => err(e),
        }
    }

    /// PUT /api/ha/vips/:id
    async fn put_vip(
        State(state): State<AppState>,
        Path(id): Path<i64>,
        Json(i): Json<ha::VipInput>,
    ) -> Response {
        match state.lan.save_vip(Some(id), i).await {
            Ok(_) => {
                if let Some(r) = firewall(&state).await {
                    return r;
                }
                Json(json!({"ok": true})).into_response()
            }
            Err(e) => err(e),
        }
    }

    /// DELETE /api/ha/vips/:id
    async fn del_vip(State(state): State<AppState>, Path(id): Path<i64>) -> Response {
        match state.lan.delete_vip(id).await {
            Ok(()) => {
                if let Some(r) = firewall(&state).await {
                    return r;
                }
                Json(json!({"ok": true})).into_response()
            }
            Err(e) => err(e),
        }
    }

    pub fn router() -> axum::Router<AppState> {
        use axum::routing::{get, post, put};
        axum::Router::new()
            .route("/ha", get(overview))
            .route("/ha/settings", put(put_settings))
            .route("/ha/maintenance", post(maintenance))
            .route("/ha/vips", post(add_vip))
            .route("/ha/vips/:id", put(put_vip).delete(del_vip))
    }
}

pub fn router() -> axum::Router<AppState> {
    #[cfg(feature = "ha")]
    {
        built::router()
    }
    #[cfg(not(feature = "ha"))]
    {
        axum::Router::new()
    }
}

/// The `/ha` page.
pub fn pages() -> axum::Router<AppState> {
    use axum::routing::get;
    #[cfg(feature = "ha")]
    let h = get(built::page);
    #[cfg(not(feature = "ha"))]
    let h = get(|| async {
        Html(
            "<!DOCTYPE html><html><head><title>High availability - Patronus</title></head><body>\
             <h1>High availability</h1><p>This Patronus build does not include high availability. \
             Rebuild with <code>USE=ha</code> (emerge net-firewall/patronus).</p>\
             <p><a href=\"/\">Back to the dashboard</a></p></body></html>",
        )
        .into_response()
    });
    axum::Router::new().route("/ha", h)
}
