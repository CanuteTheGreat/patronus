//! IPsec road warriors API (lane F): `/api/vpn/ipsec/roadwarrior/*`.
//!
//! - `GET    /vpn/ipsec/roadwarrior`                      profiles with their users (no passwords, no keys)
//! - `POST   /vpn/ipsec/roadwarrior/profiles`             add a profile (CA + server certificate are made)
//! - `PUT|DELETE /vpn/ipsec/roadwarrior/profiles/:id`
//! - `POST   /vpn/ipsec/roadwarrior/profiles/:id/users`   add a user (EAP: a password is generated if
//!   empty and returned once; certificate profiles: a client certificate is issued)
//! - `PUT|DELETE /vpn/ipsec/roadwarrior/users/:id`
//! - `GET    /vpn/ipsec/roadwarrior/ca`                   the CA certificate (PEM)
//! - `GET    /vpn/ipsec/roadwarrior/export/:user_id/:format[?password=]`
//!   `mobileconfig` (iOS/macOS), `sswan` (Android strongSwan app), `ps1` (Windows PowerShell),
//!   `p12` (client certificate bundle). Certificate profiles need `password` (the PKCS#12
//!   password, 8+ characters). Operators and admins only: the files carry credentials.

use crate::auth::AuthUser;
use crate::state::tunnels::Kind;
use crate::state::AppState;
use axum::{
    extract::{Path, Query, State},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post, put},
    Json,
};
use patronus_network::ipsec_rw as rw;
use serde::Deserialize;
use serde_json::json;

fn error(code: StatusCode, msg: impl Into<String>) -> Response {
    (code, Json(json!({ "error": msg.into() }))).into_response()
}

fn err(e: anyhow::Error) -> Response {
    let msg = e.to_string();
    let code = if msg.starts_with("IPsec needs root") {
        StatusCode::NOT_IMPLEMENTED
    } else if msg.contains("Invalid") {
        StatusCode::BAD_REQUEST
    } else if msg.contains("no road-warrior") {
        StatusCode::NOT_FOUND
    } else {
        StatusCode::INTERNAL_SERVER_ERROR
    };
    error(code, msg)
}

async fn overview(State(state): State<AppState>) -> Response {
    let store = state.tunnels.store();
    let (profiles, users) = match (rw::list_profiles(store).await, rw::list_users(store).await) {
        (Ok(p), Ok(u)) => (p, u),
        (Err(e), _) | (_, Err(e)) => return err(anyhow::anyhow!("{e}")),
    };
    let ca = rw::ca_pem(store).await.ok().flatten();
    let rows: Vec<_> = profiles
        .iter()
        .map(|p| {
            json!({
                "profile": p,
                "users": users.iter().filter(|u| u.profile == p.name).collect::<Vec<_>>(),
            })
        })
        .collect();
    Json(json!({
        "profiles": rows,
        "ca": ca.as_ref().map(|c| json!({ "expires": rw::cert_expiry(c) })),
        "formats": ["mobileconfig", "sswan", "ps1", "p12"],
    }))
    .into_response()
}

async fn add_profile(State(state): State<AppState>, Json(t): Json<rw::ProfileInput>) -> Response {
    match state
        .tunnels
        .change(Kind::Ipsec, "add road-warrior profile", |s| async move {
            rw::save_profile(&s, None, &t).await
        })
        .await
    {
        Ok(id) => (StatusCode::CREATED, Json(json!({ "id": id }))).into_response(),
        Err(e) => err(e),
    }
}

async fn put_profile(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Json(t): Json<rw::ProfileInput>,
) -> Response {
    state
        .tunnels
        .change(Kind::Ipsec, "edit road-warrior profile", |s| async move {
            rw::save_profile(&s, Some(id), &t).await
        })
        .await
        .map(|_| Json(json!({ "ok": true })).into_response())
        .unwrap_or_else(err)
}

async fn del_profile(State(state): State<AppState>, Path(id): Path<i64>) -> Response {
    match state
        .tunnels
        .change(Kind::Ipsec, "delete road-warrior profile", |s| async move {
            rw::delete_profile(&s, id).await
        })
        .await
    {
        Ok(true) => Json(json!({ "ok": true })).into_response(),
        Ok(false) => error(
            StatusCode::NOT_FOUND,
            format!("no road-warrior profile {id}"),
        ),
        Err(e) => err(e),
    }
}

async fn profile_name(state: &AppState, id: i64) -> Option<String> {
    rw::list_profiles(state.tunnels.store())
        .await
        .ok()?
        .into_iter()
        .find(|p| p.id == id)
        .map(|p| p.name)
}

async fn add_user(
    State(state): State<AppState>,
    Path(pid): Path<i64>,
    Json(t): Json<rw::UserInput>,
) -> Response {
    let Some(profile) = profile_name(&state, pid).await else {
        return error(
            StatusCode::NOT_FOUND,
            format!("no road-warrior profile {pid}"),
        );
    };
    match state
        .tunnels
        .change(Kind::Ipsec, "add road-warrior user", |s| async move {
            rw::save_user(&s, &profile, None, &t).await
        })
        .await
    {
        // a generated password is shown once
        Ok((id, pw)) => (
            StatusCode::CREATED,
            Json(json!({ "id": id, "generated_password": pw })),
        )
            .into_response(),
        Err(e) => err(e),
    }
}

async fn user_profile(state: &AppState, uid: i64) -> Option<(String, String)> {
    rw::list_users(state.tunnels.store())
        .await
        .ok()?
        .into_iter()
        .find(|u| u.id == uid)
        .map(|u| (u.profile, u.username))
}

async fn put_user(
    State(state): State<AppState>,
    Path(uid): Path<i64>,
    Json(t): Json<rw::UserInput>,
) -> Response {
    let Some((profile, _)) = user_profile(&state, uid).await else {
        return error(StatusCode::NOT_FOUND, format!("no road-warrior user {uid}"));
    };
    state
        .tunnels
        .change(Kind::Ipsec, "edit road-warrior user", |s| async move {
            rw::save_user(&s, &profile, Some(uid), &t).await
        })
        .await
        .map(|_| Json(json!({ "ok": true })).into_response())
        .unwrap_or_else(err)
}

async fn del_user(State(state): State<AppState>, Path(uid): Path<i64>) -> Response {
    match state
        .tunnels
        .change(Kind::Ipsec, "delete road-warrior user", |s| async move {
            rw::delete_user(&s, uid).await
        })
        .await
    {
        Ok(true) => Json(json!({ "ok": true })).into_response(),
        Ok(false) => error(StatusCode::NOT_FOUND, format!("no road-warrior user {uid}")),
        Err(e) => err(e),
    }
}

fn download(content_type: &str, file: &str, body: impl Into<axum::body::Body>) -> Response {
    let safe: String = file
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_') {
                c
            } else {
                '_'
            }
        })
        .collect();
    (
        [
            (header::CONTENT_TYPE, content_type.to_string()),
            (
                header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{safe}\""),
            ),
            (header::CACHE_CONTROL, "no-store".to_string()),
        ],
        body.into(),
    )
        .into_response()
}

async fn get_ca(State(state): State<AppState>) -> Response {
    match rw::ca_pem(state.tunnels.store()).await {
        Ok(Some(c)) => download("application/x-pem-file", "patronus-ipsec-ca.pem", c),
        Ok(None) => error(
            StatusCode::NOT_FOUND,
            "no road-warrior CA yet: add a profile first",
        ),
        Err(e) => err(anyhow::anyhow!("{e}")),
    }
}

#[derive(Debug, Deserialize)]
struct ExportQuery {
    #[serde(default)]
    password: Option<String>,
}

async fn export(
    State(state): State<AppState>,
    user: AuthUser,
    Path((uid, format)): Path<(i64, String)>,
    Query(q): Query<ExportQuery>,
) -> Response {
    if !user.session.role.can_modify() {
        return error(
            StatusCode::FORBIDDEN,
            "client setup files carry credentials: operators and admins only",
        );
    }
    let store = state.tunnels.store();
    let Some((pname, uname)) = user_profile(&state, uid).await else {
        return error(StatusCode::NOT_FOUND, format!("no road-warrior user {uid}"));
    };
    let profile = match rw::list_profiles(store).await {
        Ok(v) => v.into_iter().find(|p| p.name == pname),
        Err(e) => return err(anyhow::anyhow!("{e}")),
    };
    let Some(profile) = profile else {
        return error(
            StatusCode::NOT_FOUND,
            format!("no road-warrior profile {pname}"),
        );
    };
    let ca = match rw::ca_pem(store).await {
        Ok(Some(c)) => c,
        Ok(None) => {
            return error(
                StatusCode::CONFLICT,
                "the IPsec CA does not exist yet (the profile has not been applied)",
            )
        }
        Err(e) => return err(anyhow::anyhow!("{e}")),
    };
    // certificate profiles ship the user's PKCS#12, protected with `password`
    let pw = q
        .password
        .as_deref()
        .map(str::trim)
        .filter(|p| !p.is_empty());
    let p12 = if profile.auth == "cert" {
        let Some(pw) = pw else {
            return error(
                StatusCode::BAD_REQUEST,
                "Invalid request: a certificate profile needs ?password= (the PKCS#12 password, 8+ characters)",
            );
        };
        match rw::client_p12(store, &pname, &uname, pw).await {
            Ok(b) => Some((b, pw.to_string())),
            Err(e) => return err(anyhow::anyhow!("{e}")),
        }
    } else {
        None
    };
    let stem = format!("{pname}-{uname}");
    match format.as_str() {
        "mobileconfig" => match rw::mobileconfig(
            &profile,
            &uname,
            &ca,
            p12.as_ref().map(|(b, p)| (b.as_slice(), p.as_str())),
        ) {
            Ok(x) => download(
                "application/x-apple-aspen-config",
                &format!("{stem}.mobileconfig"),
                x,
            ),
            Err(e) => err(anyhow::anyhow!("{e}")),
        },
        "sswan" => match rw::sswan(
            &profile,
            &uname,
            &ca,
            p12.as_ref().map(|(b, _)| b.as_slice()),
        ) {
            Ok(v) => download(
                "application/vnd.strongswan.profile",
                &format!("{stem}.sswan"),
                serde_json::to_string_pretty(&v).unwrap_or_default(),
            ),
            Err(e) => err(anyhow::anyhow!("{e}")),
        },
        "ps1" => download(
            "text/plain; charset=utf-8",
            &format!("{stem}.ps1"),
            rw::powershell(
                &profile,
                &uname,
                &ca,
                p12.as_ref().map(|(b, p)| (b.as_slice(), p.as_str())),
            ),
        ),
        "p12" => match p12 {
            Some((b, _)) => download("application/x-pkcs12", &format!("{stem}.p12"), b),
            None => error(
                StatusCode::BAD_REQUEST,
                "Invalid request: only certificate profiles have a client certificate",
            ),
        },
        o => error(
            StatusCode::BAD_REQUEST,
            format!("Invalid request: format {o:?} (mobileconfig, sswan, ps1 or p12)"),
        ),
    }
}

pub fn router() -> axum::Router<AppState> {
    axum::Router::new()
        .route("/vpn/ipsec/roadwarrior", get(overview))
        .route("/vpn/ipsec/roadwarrior/ca", get(get_ca))
        .route("/vpn/ipsec/roadwarrior/profiles", post(add_profile))
        .route(
            "/vpn/ipsec/roadwarrior/profiles/:id",
            put(put_profile).delete(del_profile),
        )
        .route("/vpn/ipsec/roadwarrior/profiles/:id/users", post(add_user))
        .route(
            "/vpn/ipsec/roadwarrior/users/:id",
            put(put_user).delete(del_user),
        )
        .route(
            "/vpn/ipsec/roadwarrior/export/:user_id/:format",
            get(export),
        )
}
