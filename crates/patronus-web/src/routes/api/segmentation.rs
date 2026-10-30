//! Device segmentation page and API (USE=segmentation): groups, enrolled
//! devices, group links, one-way service rules and the per-segment isolation
//! switch. See docs/design/device-segmentation.md.
//!
//! - `GET    /api/segmentation`                      everything + live state
//! - `GET    /api/segmentation/status`               same as above
//! - `GET/POST /api/segmentation/groups`, `PUT/DELETE .../groups/<id>`
//! - `GET/POST /api/segmentation/devices`, `PUT/DELETE .../devices/<id>`,
//!   `POST .../devices/<id>/revoke`
//! - `GET    /api/segmentation/discovered`           hosts seen but not enrolled
//! - `POST   /api/segmentation/discovered/<mac>/adopt`  {name?, group?, segment?}
//! - `GET/POST /api/segmentation/links`, `DELETE .../links/<id>`
//! - `GET/POST /api/segmentation/services`, `DELETE .../services/<id>`
//! - `POST   /api/segmentation/segments`             {segment, enabled, adopt?}
//! - `POST   /api/segmentation/preview`              the nft table, not applied
//!
//! A build without the flag answers 404 with the USE flag to enable.

use crate::state::AppState;
use axum::response::{Html, IntoResponse};

#[cfg(feature = "segmentation")]
mod built {
    use super::*;
    use askama::Template;
    use axum::extract::{Path, State};
    use axum::routing::{get, post, put};
    use axum::{http::StatusCode, response::Response, Json};
    use patronus_config::seg;
    use serde::Deserialize;
    use serde_json::{json, Value};

    pub fn err(e: anyhow::Error) -> Response {
        let msg = e.to_string();
        let code = if msg.contains("Invalid") || msg.contains("already exists") {
            StatusCode::BAD_REQUEST
        } else if msg.starts_with("no ") || msg.contains(": no ") {
            StatusCode::NOT_FOUND
        } else {
            StatusCode::INTERNAL_SERVER_ERROR
        };
        (code, Json(json!({ "error": msg }))).into_response()
    }

    #[derive(Template)]
    #[template(path = "segmentation.html")]
    pub struct SegTemplate {
        pub page: &'static str,
        pub can_modify: bool,
        pub wifi: bool,
    }

    pub async fn page(me: crate::auth::AuthUser) -> Response {
        let t = SegTemplate {
            page: "segmentation",
            can_modify: me.session.role.can_modify(),
            wifi: cfg!(feature = "wifi-ap"),
        };
        match t.render() {
            Ok(h) => Html(h).into_response(),
            Err(e) => {
                tracing::error!("render segmentation: {e}");
                (StatusCode::INTERNAL_SERVER_ERROR, "Failed to render page").into_response()
            }
        }
    }

    async fn overview(State(st): State<AppState>) -> Response {
        match st.lan.seg_overview().await {
            Ok(v) => Json(v).into_response(),
            Err(e) => err(e),
        }
    }
    async fn discovered(State(st): State<AppState>) -> Response {
        match st.lan.seg_discovered().await {
            Ok(v) => Json(v).into_response(),
            Err(e) => err(e),
        }
    }
    async fn preview(State(st): State<AppState>) -> Response {
        match st.lan.seg_preview().await {
            Ok(v) => Json(v).into_response(),
            Err(e) => err(e),
        }
    }
    async fn list_groups(State(st): State<AppState>) -> Response {
        match seg::list_groups(&st.config_store).await {
            Ok(v) => Json(v).into_response(),
            Err(e) => err(e.into()),
        }
    }
    async fn add_group(State(st): State<AppState>, Json(i): Json<seg::GroupInput>) -> Response {
        match st.lan.seg_group_save(None, i).await {
            Ok(id) => (StatusCode::CREATED, Json(json!({"id": id}))).into_response(),
            Err(e) => err(e),
        }
    }
    async fn put_group(
        State(st): State<AppState>,
        Path(id): Path<i64>,
        Json(i): Json<seg::GroupInput>,
    ) -> Response {
        match st.lan.seg_group_save(Some(id), i).await {
            Ok(_) => Json(json!({"ok": true})).into_response(),
            Err(e) => err(e),
        }
    }
    async fn del_group(State(st): State<AppState>, Path(id): Path<i64>) -> Response {
        match st.lan.seg_group_delete(id).await {
            Ok(()) => Json(json!({"ok": true})).into_response(),
            Err(e) => err(e),
        }
    }
    async fn list_devices(State(st): State<AppState>) -> Response {
        match seg::list_devices(&st.config_store).await {
            Ok(v) => Json(v).into_response(),
            Err(e) => err(e.into()),
        }
    }
    async fn add_device(State(st): State<AppState>, Json(i): Json<seg::DeviceInput>) -> Response {
        match st.lan.seg_device_create(i).await {
            Ok(d) => (StatusCode::CREATED, Json(d)).into_response(),
            Err(e) => err(e),
        }
    }
    #[derive(Deserialize)]
    pub struct DevicePatch {
        name: Option<String>,
        group: Option<String>,
        note: Option<String>,
    }
    async fn put_device(
        State(st): State<AppState>,
        Path(id): Path<i64>,
        Json(p): Json<DevicePatch>,
    ) -> Response {
        match st.lan.seg_device_update(id, p.name, p.group, p.note).await {
            Ok(d) => Json(d).into_response(),
            Err(e) => err(e),
        }
    }
    async fn revoke_device(State(st): State<AppState>, Path(id): Path<i64>) -> Response {
        match st.lan.seg_device_revoke(id).await {
            Ok(d) => Json(d).into_response(),
            Err(e) => err(e),
        }
    }
    async fn del_device(State(st): State<AppState>, Path(id): Path<i64>) -> Response {
        match st.lan.seg_device_delete(id).await {
            Ok(()) => Json(json!({"ok": true})).into_response(),
            Err(e) => err(e),
        }
    }
    #[derive(Deserialize, Default)]
    pub struct AdoptBody {
        name: Option<String>,
        group: Option<String>,
        segment: Option<String>,
    }
    async fn adopt(
        State(st): State<AppState>,
        Path(mac): Path<String>,
        body: Option<Json<AdoptBody>>,
    ) -> Response {
        let b = body.map(|b| b.0).unwrap_or_default();
        match st
            .lan
            .seg_adopt_host(&mac, b.name, b.group, b.segment)
            .await
        {
            Ok(d) => (StatusCode::CREATED, Json(d)).into_response(),
            Err(e) => err(e),
        }
    }
    async fn list_links(State(st): State<AppState>) -> Response {
        match seg::list_links(&st.config_store).await {
            Ok(v) => Json(v).into_response(),
            Err(e) => err(e.into()),
        }
    }
    #[derive(Deserialize)]
    pub struct LinkBody {
        a: String,
        b: String,
    }
    async fn add_link(State(st): State<AppState>, Json(l): Json<LinkBody>) -> Response {
        match st.lan.seg_link_add(&l.a, &l.b).await {
            Ok(id) => (StatusCode::CREATED, Json(json!({"id": id}))).into_response(),
            Err(e) => err(e),
        }
    }
    async fn del_link(State(st): State<AppState>, Path(id): Path<i64>) -> Response {
        match st.lan.seg_link_delete(id).await {
            Ok(()) => Json(json!({"ok": true})).into_response(),
            Err(e) => err(e),
        }
    }
    async fn list_services(State(st): State<AppState>) -> Response {
        match seg::list_services(&st.config_store).await {
            Ok(v) => Json(v).into_response(),
            Err(e) => err(e.into()),
        }
    }
    async fn add_service(State(st): State<AppState>, Json(i): Json<seg::ServiceInput>) -> Response {
        match st.lan.seg_service_add(i).await {
            Ok(id) => (StatusCode::CREATED, Json(json!({"id": id}))).into_response(),
            Err(e) => err(e),
        }
    }
    async fn del_service(State(st): State<AppState>, Path(id): Path<i64>) -> Response {
        match st.lan.seg_service_delete(id).await {
            Ok(()) => Json(json!({"ok": true})).into_response(),
            Err(e) => err(e),
        }
    }
    #[derive(Deserialize)]
    pub struct SegmentBody {
        segment: String,
        enabled: bool,
        #[serde(default = "yes")]
        adopt: bool,
    }
    fn yes() -> bool {
        true
    }
    async fn set_segment(State(st): State<AppState>, Json(b): Json<SegmentBody>) -> Response {
        match st.lan.seg_segment_set(&b.segment, b.enabled, b.adopt).await {
            Ok(v) => Json::<Value>(v).into_response(),
            Err(e) => err(e),
        }
    }

    pub fn router() -> axum::Router<AppState> {
        axum::Router::new()
            .route("/segmentation", get(overview))
            .route("/segmentation/status", get(overview))
            .route("/segmentation/groups", get(list_groups).post(add_group))
            .route("/segmentation/groups/:id", put(put_group).delete(del_group))
            .route("/segmentation/devices", get(list_devices).post(add_device))
            .route(
                "/segmentation/devices/:id",
                put(put_device).delete(del_device),
            )
            .route("/segmentation/devices/:id/revoke", post(revoke_device))
            .route("/segmentation/discovered", get(discovered))
            .route("/segmentation/discovered/:mac/adopt", post(adopt))
            .route("/segmentation/links", get(list_links).post(add_link))
            .route("/segmentation/links/:id", axum::routing::delete(del_link))
            .route(
                "/segmentation/services",
                get(list_services).post(add_service),
            )
            .route(
                "/segmentation/services/:id",
                axum::routing::delete(del_service),
            )
            .route("/segmentation/segments", post(set_segment))
            .route("/segmentation/preview", post(preview))
    }
}

#[cfg(feature = "segmentation")]
pub fn router() -> axum::Router<AppState> {
    built::router()
}
#[cfg(not(feature = "segmentation"))]
pub fn router() -> axum::Router<AppState> {
    axum::Router::new()
}

#[cfg(feature = "segmentation")]
pub fn pages() -> axum::Router<AppState> {
    axum::Router::new().route("/segmentation", axum::routing::get(built::page))
}
#[cfg(not(feature = "segmentation"))]
pub fn pages() -> axum::Router<AppState> {
    axum::Router::new().route("/segmentation", axum::routing::get(not_built))
}

#[cfg(not(feature = "segmentation"))]
async fn not_built() -> impl IntoResponse {
    (
        axum::http::StatusCode::NOT_FOUND,
        Html(
            "<!DOCTYPE html><html><head><title>Not built - Patronus</title></head><body>\
             <h1>Not part of this build</h1><p>This Patronus build does not include device \
             segmentation. Rebuild with <code>USE=segmentation</code>.</p>\
             <p><a href=\"/\">Back to the dashboard</a></p></body></html>",
        ),
    )
}
