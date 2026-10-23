//! Remote / encrypted backup targets: list / add / delete / run now.
//! Admin sessions only; passwords and passphrases are never returned.

use crate::auth::AdminUser;
use crate::backup_remote::TargetInput;
use crate::state::AppState;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;

fn err(e: anyhow::Error) -> Response {
    let m = e.to_string();
    let c = if m.starts_with("Invalid") {
        StatusCode::BAD_REQUEST
    } else if m.starts_with("no such") {
        StatusCode::NOT_FOUND
    } else if m.contains("failed") {
        StatusCode::BAD_GATEWAY
    } else {
        StatusCode::INTERNAL_SERVER_ERROR
    };
    (c, Json(json!({ "error": m }))).into_response()
}

pub async fn list(State(s): State<AppState>, _a: AdminUser) -> Response {
    match s.backup_targets.list().await {
        Ok(l) => Json(l).into_response(),
        Err(e) => err(e),
    }
}

pub async fn create(
    State(s): State<AppState>,
    _a: AdminUser,
    Json(t): Json<TargetInput>,
) -> Response {
    match s.backup_targets.create(&t).await {
        Ok(id) => {
            let _ = s
                .config_store
                .audit(
                    "web",
                    "create",
                    "backup-target",
                    Some(&id.to_string()),
                    &json!({"name": t.name}),
                )
                .await;
            (StatusCode::CREATED, Json(json!({"id": id}))).into_response()
        }
        Err(e) => err(e),
    }
}

pub async fn delete(State(s): State<AppState>, _a: AdminUser, Path(id): Path<i64>) -> Response {
    match s.backup_targets.delete(id).await {
        Ok(()) => Json(json!({"ok": true})).into_response(),
        Err(e) => err(e),
    }
}

/// POST /api/system/backup-targets/:id/run -> {file}
pub async fn run(State(s): State<AppState>, _a: AdminUser, Path(id): Path<i64>) -> Response {
    match s.backup_targets.run(id).await {
        Ok(f) => Json(json!({"ok": true, "file": f})).into_response(),
        Err(e) => err(e),
    }
}

pub fn router() -> axum::Router<AppState> {
    use axum::routing::{get, post};
    axum::Router::new()
        .route("/system/backup-targets", get(list).post(create))
        .route("/system/backup-targets/:id", axum::routing::delete(delete))
        .route("/system/backup-targets/:id/run", post(run))
}
