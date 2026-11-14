//! First-run setup (embedded/router images). There is no shipped account or
//! password: until the owner creates the first administrator here (a system
//! user in the first admin group, signing in through PAM like any other
//! account), nothing else is served.
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
    pub username: String,
    pub password: String,
    pub confirm: String,
}

/// POST /api/first-run {username, password, confirm}
pub async fn set_password(State(state): State<AppState>, Json(b): Json<Body>) -> Response {
    if !crate::auth::first_run_pending() {
        return (
            StatusCode::CONFLICT,
            Json(json!({"error": "an administrator account already exists"})),
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
    let login = state.auth.syslogin.clone();
    let (user, pw) = (b.username.trim().to_string(), b.password);
    let r = tokio::task::spawn_blocking(move || login.create_first_account(&user, &pw)).await;
    match r {
        Ok(Ok(())) => {
            Json(json!({"message": "administrator created", "next": "/login"})).into_response()
        }
        Ok(Err(m)) => {
            let code = if m.contains("already exists") && m.starts_with("an administrator") {
                StatusCode::CONFLICT
            } else {
                StatusCode::BAD_REQUEST
            };
            (code, Json(json!({"error": m}))).into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

#[cfg(test)]
mod tests {
    use crate::auth::{first_run_pending, FIRST_RUN_PENDING};
    use crate::syslogin::{Mode, SysLogin, WebAuthConfig};
    use patronus_network::sysauth::{self, Backend};
    use std::sync::atomic::Ordering;

    // FIRST_RUN_PENDING is process-global: keep every assertion about it in this one test.
    #[tokio::test]
    async fn first_run_creates_one_system_admin_and_never_ships_a_default() {
        let d = tempfile::tempdir().unwrap();
        std::fs::write(d.path().join("passwd"), "root:x:0:0::/root:/bin/sh\n").unwrap();
        std::fs::write(d.path().join("group"), "root:x:0:\nwheel:x:10:root\n").unwrap();
        std::fs::write(d.path().join("shadow"), "root:*:1::::::\n").unwrap();
        let s = SysLogin::new(
            WebAuthConfig::default(),
            Mode::Direct(Backend::Shadow(d.path().into())),
        );
        assert!(
            !s.admin_account_exists(),
            "root in wheel is not an administrator"
        );
        FIRST_RUN_PENDING.store(true, Ordering::SeqCst);
        assert!(s.create_first_account("netadmin", "short-pw").is_err());
        assert!(s
            .create_first_account("root", "Correct-Horse-Battery-9")
            .is_err());
        assert!(s
            .create_first_account("a;b", "Correct-Horse-Battery-9")
            .is_err());
        assert!(
            first_run_pending(),
            "a refused submission must not end setup"
        );
        s.create_first_account("netadmin", "Correct-Horse-Battery-9")
            .unwrap();
        assert!(!first_run_pending());
        assert!(s.admin_account_exists());
        // a system user in patronus-admin, signing in like any other account
        assert_eq!(
            s.verify("netadmin", "Correct-Horse-Battery-9").await,
            Ok(crate::auth::UserRole::Admin)
        );
        assert!(s.verify("admin", "admin").await.is_err());
        let id = sysauth::lookup(&Backend::Shadow(d.path().into()), "netadmin").unwrap();
        assert!(id.uid >= 1000 && id.groups.iter().any(|g| g == "patronus-admin"));
        // the second submission cannot add another administrator
        let again = s.create_first_account("other", "Another-Passw0rd-123");
        assert!(again.unwrap_err().contains("already exists"));
        assert!(s.verify("other", "Another-Passw0rd-123").await.is_err());
    }
}
