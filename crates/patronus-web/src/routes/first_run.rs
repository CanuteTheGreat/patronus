//! First-run password setup (embedded/router images). There is no shipped
//! password: until the owner chooses one here, nothing else is served.
//! Reachable only on the management (LAN) side by the firewall's input rules.

use crate::state::AppState;
use askama::Template;
use axum::{
    extract::State,
    http::StatusCode,
    response::{Html, IntoResponse, Redirect, Response},
    Json,
};
use serde::Deserialize;
use serde_json::json;

#[derive(Template)]
#[template(path = "first_run.html")]
pub struct FirstRunTemplate;

/// GET /first-run: the form while setup is pending, else on to the login page.
pub async fn page() -> Response {
    if !crate::auth::first_run_pending() {
        return Redirect::to("/login").into_response();
    }
    match FirstRunTemplate.render() {
        Ok(h) => Html(h).into_response(),
        Err(e) => {
            tracing::error!("render first-run: {e}");
            (StatusCode::INTERNAL_SERVER_ERROR, "Failed to render page").into_response()
        }
    }
}

#[derive(Deserialize)]
pub struct Body {
    pub password: String,
    pub confirm: String,
}

/// POST /api/first-run {password, confirm}
pub async fn set_password(State(state): State<AppState>, Json(b): Json<Body>) -> Response {
    if !crate::auth::first_run_pending() {
        return (
            StatusCode::CONFLICT,
            Json(json!({"error": "an administrator password is already set"})),
        )
            .into_response();
    }
    if b.password != b.confirm {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Invalid password: the two entries differ"})),
        )
            .into_response();
    }
    match state.auth.user_store.create_first_admin(&b.password).await {
        Ok(()) => Json(json!({"message": "password set", "next": "/login"})).into_response(),
        Err(e) => {
            let m = e.to_string();
            let code = if m.contains("already set") {
                StatusCode::CONFLICT
            } else {
                StatusCode::BAD_REQUEST
            };
            (code, Json(json!({"error": m}))).into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::auth::{first_run_pending, UserStore, FIRST_RUN_PENDING};
    use std::sync::atomic::Ordering;

    // FIRST_RUN_PENDING is process-global: keep every assertion about it in this one test.
    #[tokio::test]
    async fn first_run_sets_the_password_once_and_never_ships_a_default() {
        let store = UserStore::in_memory().await;
        FIRST_RUN_PENDING.store(true, Ordering::SeqCst);
        assert!(first_run_pending());
        assert!(store.create_first_admin("short").await.is_err());
        assert!(store.create_first_admin("password").await.is_err());
        assert!(first_run_pending(), "a refused password must not end setup");
        store
            .create_first_admin("Correct-Horse-Battery-9")
            .await
            .unwrap();
        assert!(!first_run_pending());
        assert!(store
            .verify_credentials("admin", "Correct-Horse-Battery-9")
            .await
            .is_some());
        assert!(store.verify_credentials("admin", "admin").await.is_none());
        // the second submission cannot overwrite the first
        let again = store.create_first_admin("Another-Passw0rd-123").await;
        assert!(again.unwrap_err().to_string().contains("already set"));
        assert!(store
            .verify_credentials("admin", "Correct-Horse-Battery-9")
            .await
            .is_some());
    }
}
