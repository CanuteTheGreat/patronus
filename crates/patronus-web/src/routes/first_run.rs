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
pub struct FirstRunTemplate {
    /// minutes left in the setup window; 0 = closed (see `closed_reason`)
    pub minutes_left: u64,
    pub closed_reason: &'static str,
}

impl FirstRunTemplate {
    pub fn for_window(w: crate::syslogin::FirstRunWindow) -> Self {
        use crate::syslogin::FirstRunWindow as W;
        let (minutes_left, closed_reason) = match w {
            W::Open(m) => (m, ""),
            W::Expired => (0, "The setup window has closed. Restart the router (or its web service) and enter the new setup code within the hour."),
            W::Locked => (0, "Too many wrong setup codes. Restart the router (or its web service) to get a new one."),
            W::Closed => (0, "First-run setup is not open."),
        };
        Self {
            minutes_left,
            closed_reason,
        }
    }
}

/// GET /first-run: the form while setup is pending, else on to the login page.
pub async fn page(State(state): State<AppState>) -> Response {
    if !state.auth.syslogin.first_run_pending() {
        return Redirect::to("/login").into_response();
    }
    match FirstRunTemplate::for_window(state.auth.syslogin.first_run_window()).render() {
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
    /// proof of ownership: the setup code (console / root-only file) or the
    /// unit's existing root password
    #[serde(default)]
    pub setup_code: String,
}

/// POST /api/first-run {username, password, confirm, setup_code}
pub async fn set_password(State(state): State<AppState>, Json(b): Json<Body>) -> Response {
    if !state.auth.syslogin.first_run_pending() {
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
    let (user, pw, proof) = (b.username.trim().to_string(), b.password, b.setup_code);
    let r = tokio::task::spawn_blocking(move || {
        login
            .check_first_run_proof(&proof)
            .map_err(|m| (StatusCode::FORBIDDEN, m))?;
        login
            .create_first_account(&user, &pw)
            .map_err(|m| (StatusCode::BAD_REQUEST, m))
    })
    .await;
    match r {
        Ok(Ok(())) => {
            crate::syslogin::retire_first_run_code();
            Json(json!({"message": "administrator created", "next": "/login"})).into_response()
        }
        Ok(Err((code, m))) => {
            let code = if m.contains("already exists") && m.starts_with("an administrator") {
                StatusCode::CONFLICT
            } else {
                code
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
    use crate::syslogin::{Mode, SysLogin, WebAuthConfig};
    use patronus_network::sysauth::{self, Backend};

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
        s.set_first_run_pending(true);
        assert!(s.create_first_account("netadmin", "short-pw").is_err());
        assert!(s
            .create_first_account("root", "Correct-Horse-Battery-9")
            .is_err());
        assert!(s
            .create_first_account("a;b", "Correct-Horse-Battery-9")
            .is_err());
        assert!(
            s.first_run_pending(),
            "a refused submission must not end setup"
        );
        s.create_first_account("netadmin", "Correct-Horse-Battery-9")
            .unwrap();
        assert!(!s.first_run_pending());
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

    fn fixture(root_shadow: &str) -> (tempfile::TempDir, SysLogin) {
        let d = tempfile::tempdir().unwrap();
        std::fs::write(d.path().join("passwd"), "root:x:0:0::/root:/bin/sh\n").unwrap();
        std::fs::write(d.path().join("group"), "root:x:0:\n").unwrap();
        std::fs::write(
            d.path().join("shadow"),
            format!("root:{root_shadow}:1::::::\n"),
        )
        .unwrap();
        let s = SysLogin::new(
            WebAuthConfig::default(),
            Mode::Direct(Backend::Shadow(d.path().into())),
        );
        (d, s)
    }

    #[test]
    fn first_run_needs_the_setup_code_and_closes_after_wrong_tries() {
        use crate::syslogin::{FirstRunWindow, FIRST_RUN_MAX_FAILS};
        let (_d, s) = fixture("*");
        // nothing opened: no claim possible at all
        assert!(s.check_first_run_proof("anything").is_err());
        let code = s.open_first_run(std::time::Duration::from_secs(3600));
        assert_eq!(code.len(), 14, "XXXX-XXXX-XXXX: {code}");
        assert!(matches!(s.first_run_window(), FirstRunWindow::Open(60)));
        // a visitor without the code cannot claim the unit
        assert!(s.check_first_run_proof("").is_err());
        assert!(s.check_first_run_proof("AAAA-BBBB-CCCC").is_err());
        // a locked root ("*") is never a proof
        assert!(s.check_first_run_proof("*").is_err());
        // the owner's code works, also typed in lower case without dashes
        assert!(s
            .check_first_run_proof(&code.replace('-', "").to_lowercase())
            .is_ok());
        assert!(s.check_first_run_proof(&code).is_ok());
        // wrong tries lock the window, after which even the right code fails
        for _ in 0..FIRST_RUN_MAX_FAILS {
            let _ = s.check_first_run_proof("WRONG-CODE-0000");
        }
        assert_eq!(s.first_run_window(), FirstRunWindow::Locked);
        assert!(s.check_first_run_proof(&code).is_err());
        // a restart of the service opens a new window with a new code
        let code2 = s.open_first_run(std::time::Duration::from_secs(3600));
        assert_ne!(code, code2);
        assert!(s.check_first_run_proof(&code).is_err());
        assert!(s.check_first_run_proof(&code2).is_ok());
    }

    #[test]
    fn first_run_window_expires() {
        use crate::syslogin::FirstRunWindow;
        let (_d, s) = fixture("*");
        let code = s.open_first_run(std::time::Duration::from_millis(30));
        std::thread::sleep(std::time::Duration::from_millis(60));
        assert_eq!(s.first_run_window(), FirstRunWindow::Expired);
        assert!(s.check_first_run_proof(&code).is_err());
        let page = super::FirstRunTemplate::for_window(s.first_run_window());
        assert_eq!(page.minutes_left, 0);
        assert!(page.closed_reason.contains("closed"));
    }

    #[test]
    fn a_migrated_units_root_password_is_proof_of_ownership() {
        let hash = pwhash::sha512_crypt::hash("Old-OpenWrt-Root-pw").unwrap();
        let (_d, s) = fixture(&hash);
        s.open_first_run(std::time::Duration::from_secs(3600));
        assert!(s.check_first_run_proof("not-the-root-pw").is_err());
        assert!(s.check_first_run_proof("Old-OpenWrt-Root-pw").is_ok());
    }
}
