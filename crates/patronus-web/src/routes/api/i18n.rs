//! Language settings API: `/api/i18n` (what is available and what applies), `/api/i18n/me`
//! (the signed-in account's own language), `/api/i18n/system` (the system default, admins).

use axum::{
    extract::State, http::StatusCode, response::IntoResponse, routing::get, routing::put, Json,
    Router,
};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::auth::{AdminUser, AuthUser};
use crate::i18n::{self, api_error};
use crate::state::AppState;

/// One language the UI and the API's messages are available in.
#[derive(Debug, Serialize)]
pub struct LanguageInfo {
    /// Language tag, as used in `Accept-Language` and the settings (`de`).
    pub code: String,
    /// The language's own name (`Deutsch`).
    pub name: String,
}

/// The language settings as they apply to the caller.
#[derive(Debug, Serialize)]
pub struct LanguageOverview {
    /// The language this response is in.
    pub current: String,
    pub available: Vec<LanguageInfo>,
    /// The signed-in account's own choice (empty = follows the system default).
    pub user: String,
    /// The effective system default (`auto` = follow the browser).
    pub system: String,
    /// What is stored for the system default (empty = not set; the environment, patronus.toml
    /// or the built-in `auto` applies).
    pub system_stored: String,
}

/// Body of `PUT /api/i18n/me` and `PUT /api/i18n/system`.
#[derive(Debug, Deserialize)]
pub struct LanguageInput {
    /// A language tag with a catalog. Empty: for an account, back to the system default; for the
    /// system default, back to the lower layers. The system default also takes `auto`.
    pub language: String,
}

/// GET /api/i18n -- the available languages and the settings that apply to the caller.
pub async fn overview(State(state): State<AppState>, user: AuthUser) -> Json<LanguageOverview> {
    let id = user.session.user_id;
    let mine = if id == 0 {
        String::new()
    } else {
        state.auth.lang.user(id).await
    };
    Json(LanguageOverview {
        current: i18n::current(),
        available: i18n::languages()
            .into_iter()
            .map(|(code, name)| LanguageInfo {
                code: code.to_string(),
                name,
            })
            .collect(),
        user: mine,
        system: state.auth.lang.system_default().await,
        system_stored: patronus_config::uilang::stored(&state.config_store)
            .await
            .unwrap_or_default(),
    })
}

/// PUT /api/i18n/me -- the signed-in account's own language (any role; API keys have none).
pub async fn put_me(
    State(state): State<AppState>,
    user: AuthUser,
    Json(i): Json<LanguageInput>,
) -> impl IntoResponse {
    let id = user.session.user_id;
    if id == 0 {
        return api_error(StatusCode::FORBIDDEN, "err-key-no-language", &[]);
    }
    let lang = i.language.trim().to_string();
    if !lang.is_empty() && i18n::match_supported(&lang, &i18n::supported()).is_none() {
        return api_error(StatusCode::BAD_REQUEST, "err-bad-language", &[("v1", lang)]);
    }
    match state.auth.lang.set_user(id, &lang).await {
        Ok(()) => Json(json!({ "ok": true })).into_response(),
        Err(e) => api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "err-internal",
            &[("detail", e.to_string())],
        ),
    }
}

/// PUT /api/i18n/system -- the system default language (`auto`, a tag, or empty to clear).
pub async fn put_system(
    State(state): State<AppState>,
    _admin: AdminUser,
    Json(i): Json<LanguageInput>,
) -> impl IntoResponse {
    let lang = i.language.trim().to_string();
    if !lang.is_empty() && patronus_config::uilang::normalize(&lang).is_none() {
        return api_error(
            StatusCode::BAD_REQUEST,
            "err-bad-language-tag",
            &[("v1", lang)],
        );
    }
    if !lang.is_empty()
        && lang != patronus_config::uilang::AUTO
        && i18n::match_supported(&lang, &i18n::supported()).is_none()
    {
        return api_error(StatusCode::BAD_REQUEST, "err-bad-language", &[("v1", lang)]);
    }
    match state.auth.lang.set_system(&lang).await {
        Ok(()) => Json(json!({ "ok": true })).into_response(),
        Err(e) => api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "err-internal",
            &[("detail", e.to_string())],
        ),
    }
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/i18n", get(overview))
        .route("/i18n/me", put(put_me))
        .route("/i18n/system", put(put_system))
}
