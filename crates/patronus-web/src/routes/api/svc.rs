//! Feature pages (syslog, NetFlow, IGMP proxy, NAT64, L2TP, IDS, dynamic
//! routing, Wake-on-LAN): one generic page `/svc/<slug>` and API
//! `/api/svc/<slug>` over `patronus_network::svc` (see that module for the
//! field kinds and validation). A feature the binary was not built with
//! answers 404 with the USE flag to enable.
//!
//! - `GET    /api/svc`                           built-in feature list
//! - `GET    /api/svc/<slug>`                    settings, rows, schema, live status
//! - `PUT    /api/svc/<slug>`                    change settings (partial)
//! - `POST   /api/svc/<slug>/<coll>`             add a row  -> 201 {id}
//! - `PUT    /api/svc/<slug>/<coll>/<id>`        change a row (partial)
//! - `DELETE /api/svc/<slug>/<coll>/<id>`        delete a row
//! - `POST   /api/svc/<slug>/action/<name>`      press a button (wake, send test message)

use crate::state::AppState;
use askama::Template;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{Html, IntoResponse, Response},
    routing::get,
    Json,
};
use serde_json::{json, Value};

fn err(e: anyhow::Error) -> Response {
    let msg = e.to_string();
    let code = if msg.contains("Invalid") {
        StatusCode::BAD_REQUEST
    } else if msg.contains("in this build") || msg.starts_with("no ") || msg.contains(": no ") {
        StatusCode::NOT_FOUND
    } else {
        StatusCode::INTERNAL_SERVER_ERROR
    };
    (code, Json(json!({ "error": msg }))).into_response()
}

#[derive(Template)]
#[template(path = "svc.html")]
struct SvcTemplate {
    page: String,
    can_modify: bool,
    slug: String,
    title: String,
    blurb: String,
}

async fn page(Path(slug): Path<String>, me: crate::auth::AuthUser) -> Response {
    let Some(m) = patronus_network::svc::find(&slug) else {
        return (
            StatusCode::NOT_FOUND,
            Html(format!(
                "<!DOCTYPE html><html><head><title>Not built - Patronus</title></head><body>\
                 <h1>Not part of this build</h1><p>This Patronus build does not include the \
                 <code>{}</code> feature. Rebuild with its USE flag (see the Gentoo ebuild, \
                 <code>emerge net-firewall/patronus</code>).</p><p><a href=\"/\">Back to the \
                 dashboard</a></p></body></html>",
                slug.chars()
                    .filter(|c| c.is_ascii_alphanumeric())
                    .collect::<String>()
            )),
        )
            .into_response();
    };
    let spec = m.spec();
    match (SvcTemplate {
        page: format!("svc-{}", spec.slug),
        can_modify: me.session.role.can_modify(),
        slug: spec.slug.to_string(),
        title: spec.title.to_string(),
        blurb: spec.blurb.to_string(),
    })
    .render()
    {
        Ok(h) => Html(h).into_response(),
        Err(e) => {
            tracing::error!("render svc page: {e}");
            (StatusCode::INTERNAL_SERVER_ERROR, "Failed to render page").into_response()
        }
    }
}

async fn list() -> Json<Value> {
    Json(json!(patronus_network::svc::all()
        .iter()
        .map(|m| json!({"slug": m.spec().slug, "title": m.spec().title, "blurb": m.spec().blurb}))
        .collect::<Vec<_>>()))
}

async fn overview(State(st): State<AppState>, Path(slug): Path<String>) -> Response {
    match st.lan.svc_overview(&slug).await {
        Ok(v) => Json(v).into_response(),
        Err(e) => err(e),
    }
}

async fn put_settings(
    State(st): State<AppState>,
    Path(slug): Path<String>,
    Json(body): Json<Value>,
) -> Response {
    match st.lan.svc_put(&slug, body).await {
        Ok(()) => Json(json!({"ok": true})).into_response(),
        Err(e) => err(e),
    }
}

async fn add_row(
    State(st): State<AppState>,
    Path((slug, coll)): Path<(String, String)>,
    Json(body): Json<Value>,
) -> Response {
    match st.lan.svc_save_row(&slug, &coll, None, body).await {
        Ok(id) => (StatusCode::CREATED, Json(json!({"id": id}))).into_response(),
        Err(e) => err(e),
    }
}

async fn put_row(
    State(st): State<AppState>,
    Path((slug, coll, id)): Path<(String, String, i64)>,
    Json(body): Json<Value>,
) -> Response {
    match st.lan.svc_save_row(&slug, &coll, Some(id), body).await {
        Ok(_) => Json(json!({"ok": true})).into_response(),
        Err(e) => err(e),
    }
}

async fn del_row(
    State(st): State<AppState>,
    Path((slug, coll, id)): Path<(String, String, i64)>,
) -> Response {
    match st.lan.svc_delete_row(&slug, &coll, id).await {
        Ok(()) => Json(json!({"ok": true})).into_response(),
        Err(e) => err(e),
    }
}

async fn action(
    State(st): State<AppState>,
    Path((slug, name)): Path<(String, String)>,
    body: Option<Json<Value>>,
) -> Response {
    let body = body.map(|b| b.0).unwrap_or(Value::Null);
    match st.lan.svc_action(&slug, &name, body).await {
        Ok(v) => Json(v).into_response(),
        Err(e) => err(e),
    }
}

/// GET /api/svc/openvpn/export/:name -> the client's `.ovpn` profile (admin
/// sessions only: it contains the client's private key).
#[cfg(feature = "openvpn")]
async fn export_openvpn(
    State(st): State<AppState>,
    _admin: crate::auth::AdminUser,
    Path(name): Path<String>,
) -> Response {
    use axum::http::{header, StatusCode};
    if !name.chars().all(|c| c.is_ascii_alphanumeric() || "._:@+-".contains(c)) {
        return (StatusCode::BAD_REQUEST, Json(json!({"error": "Invalid client name"}))).into_response();
    }
    match patronus_network::openvpn_server::export_profile(&st.config_store, &name).await {
        Ok(p) => (
            [
                (header::CONTENT_TYPE, "application/x-openvpn-profile".to_string()),
                (header::CONTENT_DISPOSITION, format!("attachment; filename=\"{name}.ovpn\"")),
            ],
            p,
        )
            .into_response(),
        Err(e) => err(e.into()),
    }
}

pub fn router() -> axum::Router<AppState> {
    use axum::routing::{post, put};
    let r = axum::Router::new();
    #[cfg(feature = "openvpn")]
    let r = r.route("/svc/openvpn/export/:name", get(export_openvpn));
    r.route("/svc", get(list))
        .route("/svc/:slug", get(overview).put(put_settings))
        .route("/svc/:slug/action/:name", post(action))
        .route("/svc/:slug/:coll", post(add_row))
        .route("/svc/:slug/:coll/:id", put(put_row).delete(del_row))
}

pub fn pages() -> axum::Router<AppState> {
    axum::Router::new().route("/svc/:slug", get(page))
}
