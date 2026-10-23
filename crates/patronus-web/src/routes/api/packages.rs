//! Packages page and API (USE=plugins): optional components installed
//! through Portage and signed plugins. Admin sessions change things; a
//! build without USE=plugins answers 404 with the flag to enable.
//!
//! - `GET    /api/packages`                          components, jobs, plugins, trusted keys
//! - `POST   /api/packages/components/<id>/<action>` install | update | remove -> 202 {job}
//! - `GET    /api/packages/jobs/<id>/log`            tail of the emerge output
//! - `POST   /api/packages/plugins`                  body: a signed bundle -> 201
//! - `PUT    /api/packages/plugins/<name>`           {"enabled": bool}
//! - `DELETE /api/packages/plugins/<name>`
//! - `POST   /api/packages/keys` {label, public_key}, `DELETE /api/packages/keys/<id>`

use crate::state::AppState;
use axum::response::{Html, IntoResponse};

#[cfg(feature = "plugins")]
mod built {
    use super::*;
    use crate::auth::AdminUser;
    use askama::Template;
    use axum::extract::{Path, State};
    use axum::{http::StatusCode, response::Response, Json};
    use patronus_network::{packages, plugins};
    use serde_json::json;

    fn err(e: impl std::fmt::Display) -> Response {
        let msg = e.to_string();
        let code = if msg.contains("not a Portage system") {
            StatusCode::NOT_IMPLEMENTED
        } else if msg.contains("Invalid")
            || msg.contains("not newer")
            || msg.contains("another package job")
        {
            StatusCode::BAD_REQUEST
        } else if msg.starts_with("no ") || msg.contains("no component") {
            StatusCode::NOT_FOUND
        } else {
            StatusCode::INTERNAL_SERVER_ERROR
        };
        (code, Json(json!({ "error": msg }))).into_response()
    }

    #[derive(Template)]
    #[template(path = "packages.html")]
    pub struct PackagesTemplate {
        pub page: &'static str,
        pub is_admin: bool,
    }

    pub async fn page(me: crate::auth::AuthUser) -> Response {
        let t = PackagesTemplate {
            page: "packages",
            is_admin: me.session.role.is_admin(),
        };
        match t.render() {
            Ok(h) => Html(h).into_response(),
            Err(e) => {
                tracing::error!("render packages: {e}");
                (StatusCode::INTERNAL_SERVER_ERROR, "Failed to render page").into_response()
            }
        }
    }

    async fn overview(State(s): State<AppState>) -> Response {
        let store = s.lan.plugin_store();
        let sup = patronus_network::supervise::Supervisor::detect();
        let (o, l, k) = (
            packages::overview(&store).await,
            plugins::list(&store, &sup).await,
            plugins::trusted_keys(&store).await,
        );
        match (o, l, k) {
            (Ok(mut o), Ok(l), Ok(k)) => {
                o["plugins"] = json!(l);
                o["keys"] = json!(k
                    .iter()
                    .map(|(id, p)| json!({"key_id": id, "public_key": p}))
                    .collect::<Vec<_>>());
                Json(o).into_response()
            }
            (Err(e), _, _) | (_, Err(e), _) | (_, _, Err(e)) => err(e),
        }
    }

    async fn component(
        State(s): State<AppState>,
        _a: AdminUser,
        Path((id, action)): Path<(String, String)>,
    ) -> Response {
        let paths = patronus_network::supervise::NetPaths::default();
        match packages::start(&s.lan.plugin_store(), &paths, &id, &action).await {
            Ok(job) => (StatusCode::ACCEPTED, Json(json!({"job": job}))).into_response(),
            Err(e) => err(e),
        }
    }

    async fn job_log(State(s): State<AppState>, Path(id): Path<i64>) -> Response {
        match packages::job_log(&s.lan.plugin_store(), id).await {
            Ok(Some(t)) => Json(json!({"log": t})).into_response(),
            Ok(None) => err("no such job"),
            Err(e) => err(e),
        }
    }

    async fn install(State(s): State<AppState>, _a: AdminUser, body: String) -> Response {
        match s.lan.plugin_install(&body).await {
            Ok((m, updated)) => (
                StatusCode::CREATED,
                Json(json!({"name": m.name, "version": m.version, "updated": updated})),
            )
                .into_response(),
            Err(e) => err(e),
        }
    }

    #[derive(serde::Deserialize)]
    pub struct Enable {
        enabled: bool,
    }

    async fn enable(
        State(s): State<AppState>,
        _a: AdminUser,
        Path(name): Path<String>,
        Json(b): Json<Enable>,
    ) -> Response {
        match s.lan.plugin_enable(&name, b.enabled).await {
            Ok(true) => Json(json!({"ok": true})).into_response(),
            Ok(false) => err("no such plugin"),
            Err(e) => err(e),
        }
    }

    async fn remove(
        State(s): State<AppState>,
        _a: AdminUser,
        Path(name): Path<String>,
    ) -> Response {
        match s.lan.plugin_remove(&name).await {
            Ok(true) => Json(json!({"ok": true})).into_response(),
            Ok(false) => err("no such plugin"),
            Err(e) => err(e),
        }
    }

    #[derive(serde::Deserialize)]
    pub struct KeyIn {
        label: String,
        public_key: String,
    }

    async fn key_add(State(s): State<AppState>, _a: AdminUser, Json(k): Json<KeyIn>) -> Response {
        match s.lan.plugin_key_add(&k.label, &k.public_key).await {
            Ok(id) => (StatusCode::CREATED, Json(json!({"key_id": id}))).into_response(),
            Err(e) => err(e),
        }
    }

    async fn key_del(State(s): State<AppState>, _a: AdminUser, Path(id): Path<String>) -> Response {
        match s.lan.plugin_key_delete(&id).await {
            Ok(true) => Json(json!({"ok": true})).into_response(),
            Ok(false) => err("no such key"),
            Err(e) => err(e),
        }
    }

    pub fn router() -> axum::Router<AppState> {
        use axum::routing::{delete, get, post, put};
        axum::Router::new()
            .route("/packages", get(overview))
            .route("/packages/components/:id/:action", post(component))
            .route("/packages/jobs/:id/log", get(job_log))
            .route("/packages/plugins", post(install))
            .route("/packages/plugins/:name", put(enable).delete(remove))
            .route("/packages/keys", post(key_add))
            .route("/packages/keys/:id", delete(key_del))
    }
}

pub fn router() -> axum::Router<AppState> {
    #[cfg(feature = "plugins")]
    {
        built::router()
    }
    #[cfg(not(feature = "plugins"))]
    {
        axum::Router::new()
    }
}

pub fn pages() -> axum::Router<AppState> {
    use axum::routing::get;
    #[cfg(feature = "plugins")]
    let h = get(built::page);
    #[cfg(not(feature = "plugins"))]
    let h = get(|| async {
        Html(
            "<!DOCTYPE html><html><head><title>Packages - Patronus</title></head><body>\
             <h1>Packages</h1><p>This Patronus build does not include plugins and package \
             management. Rebuild with <code>USE=plugins</code> (emerge net-firewall/patronus).</p>\
             <p><a href=\"/\">Back to the dashboard</a></p></body></html>",
        )
        .into_response()
    });
    axum::Router::new().route("/packages", h)
}
