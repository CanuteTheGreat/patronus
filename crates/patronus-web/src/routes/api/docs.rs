//! The API description: `/api/openapi.json` (OpenAPI 3.1) and the reference page `/api/docs`.
//!
//! Both need a signed-in session or an API key like the rest of `/api`. The document is generated
//! from this crate's route table and types by `cargo run -p patronus-openapi` and compiled in
//! (`openapi/openapi.json`); CI fails when it is out of date, when a route is missing from it or
//! when a path in it is not served.

use askama::Template;
use axum::{
    http::header,
    response::{Html, IntoResponse, Response},
    routing::get,
    Router,
};

use crate::i18n::filters;
use crate::state::AppState;

/// The OpenAPI document served by this build.
pub const SPEC: &str = include_str!("../../../openapi/openapi.json");

#[derive(Template)]
#[template(path = "api_docs.html")]
pub struct ApiDocsTemplate {
    pub page: &'static str,
}

/// GET /api/openapi.json -- the OpenAPI 3.1 description of this API.
pub async fn spec() -> Response {
    (
        [(header::CONTENT_TYPE, "application/json; charset=utf-8")],
        SPEC,
    )
        .into_response()
}

/// GET /api/docs -- the API reference page (reads /api/openapi.json).
pub async fn page() -> Response {
    match (ApiDocsTemplate { page: "api-docs" }).render() {
        Ok(h) => Html(h.replace("@PATRONUS_VERSION@", env!("CARGO_PKG_VERSION"))).into_response(),
        Err(e) => {
            tracing::error!("render api docs: {e}");
            crate::i18n::api_error(
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "err-internal",
                &[],
            )
        }
    }
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/openapi.json", get(spec))
        .route("/docs", get(page))
}
