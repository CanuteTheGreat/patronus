//! Groups and privileges (RBAC): list / create / change / delete groups,
//! put accounts in them. Admin sessions only.

use crate::auth::AdminUser;
use crate::rbac::{GroupInput, AREAS};
use crate::state::AppState;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Deserialize;
use serde_json::json;

fn error(code: StatusCode, msg: impl Into<String>) -> Response {
    (code, Json(json!({ "error": msg.into() }))).into_response()
}

fn err(e: anyhow::Error) -> Response {
    let m = e.to_string();
    let c = if m.starts_with("Invalid") {
        StatusCode::BAD_REQUEST
    } else if m.starts_with("no such") {
        StatusCode::NOT_FOUND
    } else {
        StatusCode::INTERNAL_SERVER_ERROR
    };
    error(c, m)
}

/// GET /api/system/groups -> {areas, groups}
pub async fn list(State(s): State<AppState>, _a: AdminUser) -> Response {
    match s.auth.rbac.list().await {
        Ok(g) => Json(json!({
            "areas": AREAS.iter().map(|(k, d)| json!({"key": k, "description": d})).collect::<Vec<_>>(),
            "groups": g,
        }))
        .into_response(),
        Err(e) => err(e),
    }
}

pub async fn create(State(s): State<AppState>, _a: AdminUser, Json(g): Json<GroupInput>) -> Response {
    match s.auth.rbac.create(&g).await {
        Ok(id) => {
            let _ = s.config_store.audit("web", "create", "group", Some(&id.to_string()), &json!(g.privileges)).await;
            (StatusCode::CREATED, Json(json!({"id": id}))).into_response()
        }
        Err(e) => err(e),
    }
}

pub async fn update(State(s): State<AppState>, _a: AdminUser, Path(id): Path<i64>, Json(g): Json<GroupInput>) -> Response {
    match s.auth.rbac.update(id, &g).await {
        Ok(()) => {
            let _ = s.config_store.audit("web", "update", "group", Some(&id.to_string()), &json!(g.privileges)).await;
            Json(json!({"ok": true})).into_response()
        }
        Err(e) => err(e),
    }
}

pub async fn delete(State(s): State<AppState>, _a: AdminUser, Path(id): Path<i64>) -> Response {
    match s.auth.rbac.delete(id).await {
        Ok(()) => Json(json!({"ok": true})).into_response(),
        Err(e) => err(e),
    }
}

#[derive(Deserialize)]
pub struct Membership {
    pub group_id: Option<i64>,
}

/// PUT /api/system/users/:id/group {group_id|null}. Admins have every
/// privilege already, so they cannot be put in a group.
pub async fn set_group(State(s): State<AppState>, _a: AdminUser, Path(uid): Path<u32>, Json(m): Json<Membership>) -> Response {
    let Some(u) = s.auth.user_store.get_by_id(uid).await else {
        return error(StatusCode::NOT_FOUND, "no such account");
    };
    if u.role.is_admin() && m.group_id.is_some() {
        return error(StatusCode::BAD_REQUEST, "Invalid: admins have every privilege and cannot be put in a group");
    }
    match s.auth.rbac.set_member(uid as i64, m.group_id).await {
        Ok(()) => Json(json!({"ok": true})).into_response(),
        Err(e) => err(e),
    }
}

pub fn router() -> axum::Router<AppState> {
    use axum::routing::{get, put};
    axum::Router::new()
        .route("/system/groups", get(list).post(create))
        .route("/system/groups/:id", put(update).delete(delete))
        .route("/system/users/:id/group", put(set_group))
}
