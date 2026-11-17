//! Config generations API (NixOS-style history on top of the revision store):
//! list, show, diff, roll back, pin, commit-confirmed (confirm / revert now),
//! and the declarative file export / import.
//!
//! The deadline of a commit-confirmed change is enforced by `patronus applyd`
//! (its own timer, root), never by this process: see
//! `patronus_network::applyd`. The web UI only arms it (the
//! [`change_set_layer`] middleware, header `X-Confirm-In: N`), shows the
//! countdown and sends Confirm / Revert now.

use crate::auth::{AdminUser, AuthUser};
use crate::state::AppState;
use axum::{
    body::{Body, Bytes},
    extract::{Path, Query, State},
    http::{header, HeaderValue, Method, Request, StatusCode},
    middleware::Next,
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Json,
};
use patronus_config::generations::{Generation, Pending, MAX_CONFIRM_MINUTES};
use patronus_config::{gendiff, genfile};
use serde::Deserialize;
use serde_json::{json, Value};

fn error(code: StatusCode, msg: impl Into<String>) -> Response {
    (code, Json(json!({ "error": msg.into() }))).into_response()
}

fn when(at: i64) -> String {
    chrono::DateTime::from_timestamp(at, 0)
        .map(|t| t.format("%Y-%m-%d %H:%M:%S UTC").to_string())
        .unwrap_or_default()
}

fn gen_json(g: &Generation) -> Value {
    json!({
        "id": g.id,
        "created_at": g.created_at,
        "when": when(g.created_at),
        "actor": g.actor,
        "message": g.message,
        "kind": g.kind,
        "hash": g.hash,
        "pinned": g.pinned,
        "live": g.live,
        "boot": g.boot,
    })
}

fn pending_json(p: &Pending, now: i64) -> Value {
    json!({
        "previous": p.previous,
        "generation": p.generation,
        "started": p.started,
        "deadline": p.deadline,
        "minutes": p.minutes,
        "actor": p.actor,
        "seconds_left": p.seconds_left(now),
    })
}

fn store_err(e: impl std::fmt::Display) -> Response {
    let m = e.to_string();
    let code = if m.contains("not found") {
        StatusCode::NOT_FOUND
    } else if m.contains("Invalid") {
        StatusCode::BAD_REQUEST
    } else {
        StatusCode::INTERNAL_SERVER_ERROR
    };
    error(code, m)
}

/// GET /api/system/generations
pub async fn list(State(state): State<AppState>) -> Response {
    let store = &state.config_store;
    let (gens, pending, drift) = match tokio::try_join!(
        store.generations(),
        store.pending(),
        store.has_unrecorded_changes()
    ) {
        Ok(x) => x,
        Err(e) => return store_err(e),
    };
    let now = chrono::Utc::now().timestamp();
    Json(json!({
        "generations": gens.iter().map(gen_json).collect::<Vec<_>>(),
        "pending": pending.as_ref().map(|p| pending_json(p, now)),
        "unrecorded_changes": drift,
        "watchdog": state.system.watchdog_available().await,
        "max_confirm_minutes": MAX_CONFIRM_MINUTES,
        "now": now,
    }))
    .into_response()
}

/// GET /api/system/generations/pending -- cheap enough for the banner to
/// poll on every page.
pub async fn get_pending(State(state): State<AppState>) -> Response {
    let store = &state.config_store;
    let now = chrono::Utc::now().timestamp();
    match (store.pending().await, store.last_revert().await) {
        (Ok(p), Ok(last)) => Json(json!({
            "pending": p.as_ref().map(|p| pending_json(p, now)),
            "last_revert": last,
            "now": now,
        }))
        .into_response(),
        (Err(e), _) | (_, Err(e)) => store_err(e),
    }
}

/// POST /api/system/generations/pending/confirm
pub async fn confirm(State(state): State<AppState>, admin: AdminUser) -> Response {
    match state
        .config_store
        .confirm_pending(&admin.session.username)
        .await
    {
        Ok(Some(p)) => Json(json!({"ok": true, "confirmed": p.generation})).into_response(),
        Ok(None) => error(
            StatusCode::NOT_FOUND,
            "no change is waiting for confirmation (it may already have been confirmed or reverted)",
        ),
        Err(e) => store_err(e),
    }
}

/// POST /api/system/generations/pending/revert-now
pub async fn revert_now(State(state): State<AppState>, admin: AdminUser) -> Response {
    let store = &state.config_store;
    let p = match store.pending().await {
        Ok(Some(p)) => p,
        Ok(None) => {
            return error(
                StatusCode::NOT_FOUND,
                "no change is waiting for confirmation: nothing to revert",
            )
        }
        Err(e) => return store_err(e),
    };
    match state.system.revert_now(store, &admin.session.username).await {
        Ok(new) => Json(json!({"ok": true, "reverted_to": p.previous, "generation": new}))
            .into_response(),
        Err(e) => error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}

/// GET /api/system/generations/:id -- metadata plus the declarative file
/// (secrets excluded).
pub async fn show(State(state): State<AppState>, Path(id): Path<i64>) -> Response {
    let store = &state.config_store;
    let g = match store.generation(id).await {
        Ok(Some(g)) => g,
        Ok(None) => return error(StatusCode::NOT_FOUND, format!("Generation {id} not found")),
        Err(e) => return store_err(e),
    };
    let doc = match store.generation_json(id).await {
        Ok(Some(d)) => d,
        Ok(None) => return error(StatusCode::NOT_FOUND, format!("Generation {id} not found")),
        Err(e) => return store_err(e),
    };
    let keys = match store.table_keys().await {
        Ok(k) => k,
        Err(e) => return store_err(e),
    };
    match genfile::to_yaml(&doc, &keys, false) {
        Ok(y) => Json(json!({"generation": gen_json(&g), "declarative": y})).into_response(),
        Err(e) => store_err(e),
    }
}

#[derive(Deserialize)]
pub struct DiffQuery {
    /// generation id or `live` (default: the generation before live)
    pub from: Option<String>,
    /// generation id or `live` (default: live)
    pub to: Option<String>,
}

/// GET /api/system/generations/diff?from=&to= -- structured diff and the
/// unified text diff of the declarative files. Secrets: `(changed)` only.
pub async fn diff(State(state): State<AppState>, Query(q): Query<DiffQuery>) -> Response {
    let store = &state.config_store;
    let to = q.to.unwrap_or_else(|| "live".into());
    let from = match q.from {
        Some(f) => f,
        None => match store.generations().await {
            Ok(g) if g.len() >= 2 => g[1].id.to_string(),
            Ok(_) => {
                return error(
                    StatusCode::BAD_REQUEST,
                    "Invalid request: fewer than two generations, nothing to compare",
                )
            }
            Err(e) => return store_err(e),
        },
    };
    let (a, b, keys) = match tokio::try_join!(
        store.document(&from),
        store.document(&to),
        store.table_keys()
    ) {
        Ok(x) => x,
        Err(e) => return store_err(e),
    };
    let text = match (
        genfile::to_yaml(&a, &keys, false),
        genfile::to_yaml(&b, &keys, false),
    ) {
        (Ok(x), Ok(y)) => gendiff::unified_diff(
            &x,
            &y,
            &format!("generation {from}"),
            &format!("generation {to}"),
        ),
        (Err(e), _) | (_, Err(e)) => return store_err(e),
    };
    Json(json!({
        "from": from,
        "to": to,
        "diff": gendiff::diff_docs(&a, &b, &keys),
        "text": text,
    }))
    .into_response()
}

/// POST /api/system/generations/:id/rollback -- restore generation `id` and
/// apply it; itself a new generation. With `X-Confirm-In: N` it is applied on
/// trial.
pub async fn rollback(
    State(state): State<AppState>,
    admin: AdminUser,
    Path(id): Path<i64>,
) -> Response {
    let doc = match state.config_store.generation_json(id).await {
        Ok(Some(d)) => d,
        Ok(None) => return error(StatusCode::NOT_FOUND, format!("Generation {id} not found")),
        Err(e) => return store_err(e),
    };
    match state
        .system
        .restore_as(
            &state.config_store,
            &doc,
            &format!("generation {id}"),
            &admin.session.username,
            "rollback",
        )
        .await
    {
        Ok(lines) => {
            super::system::end_sessions_after_restore(&state, &admin, &doc).await;
            Json(json!({"ok": true, "rolled_back_to": id, "applied": lines})).into_response()
        }
        Err(e) => super::system::err(e),
    }
}

#[derive(Deserialize)]
pub struct PinBody {
    pub pinned: bool,
}

/// POST /api/system/generations/:id/pin {"pinned": true|false}
pub async fn pin(
    State(state): State<AppState>,
    _admin: AdminUser,
    Path(id): Path<i64>,
    Json(b): Json<PinBody>,
) -> Response {
    match state.config_store.pin_generation(id, b.pinned).await {
        Ok(()) => Json(json!({"ok": true, "id": id, "pinned": b.pinned})).into_response(),
        Err(e) => store_err(e),
    }
}

#[derive(Deserialize)]
pub struct ExportQuery {
    /// `yaml` (default, the declarative file) or `json` (the backup)
    pub format: Option<String>,
    pub include_secrets: Option<bool>,
}

/// GET /api/system/config/export?format=yaml&include_secrets=true -- the
/// whole configuration as the declarative file (admins; secrets only when
/// asked for).
pub async fn export(
    State(state): State<AppState>,
    _admin: AdminUser,
    Query(q): Query<ExportQuery>,
) -> Response {
    let store = &state.config_store;
    let secrets = q.include_secrets.unwrap_or(false);
    let (doc, keys) = match tokio::try_join!(store.export_json(), store.table_keys()) {
        Ok(x) => x,
        Err(e) => return store_err(e),
    };
    let (body, ctype, ext) = match q.format.as_deref().unwrap_or("yaml") {
        "yaml" | "yml" => match genfile::to_yaml(&doc, &keys, secrets) {
            Ok(y) => (y, "application/yaml; charset=utf-8", "yaml"),
            Err(e) => return store_err(e),
        },
        "json" => (
            serde_json::to_string_pretty(&doc).unwrap_or_default() + "\n",
            "application/json",
            "json",
        ),
        other => {
            return error(
                StatusCode::BAD_REQUEST,
                format!("Invalid format {other:?} (yaml or json)"),
            )
        }
    };
    let name = format!(
        "patronus-config-{}.{ext}",
        chrono::Utc::now().format("%Y%m%d-%H%M%S")
    );
    (
        [
            (header::CONTENT_TYPE, ctype.to_string()),
            (
                header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{name}\""),
            ),
        ],
        body,
    )
        .into_response()
}

#[derive(Deserialize)]
pub struct ImportQuery {
    pub dry_run: Option<bool>,
}

/// POST /api/system/config/import[?dry_run=true] -- body: the declarative
/// file (or a JSON backup). Validates it and answers with the diff against
/// the live configuration; without `dry_run` it applies it as a new
/// generation (undone if any subsystem refuses it). `X-Confirm-In: N` applies
/// it on trial.
pub async fn import(
    State(state): State<AppState>,
    admin: AdminUser,
    Query(q): Query<ImportQuery>,
    body: Bytes,
) -> Response {
    let Ok(text) = std::str::from_utf8(&body) else {
        return error(StatusCode::BAD_REQUEST, "Invalid file: not UTF-8 text");
    };
    let preview = match genfile::prepare_import(&state.config_store, text).await {
        Ok(p) => p,
        Err(e) => return store_err(e),
    };
    let summary = preview.diff["summary"].clone();
    let shown = json!({
        "identical": preview.identical,
        "summary": summary,
        "diff": preview.diff,
        "text": preview.text_diff,
    });
    if q.dry_run.unwrap_or(false) {
        return Json(json!({"dry_run": true, "preview": shown})).into_response();
    }
    if preview.identical {
        return Json(json!({"ok": true, "unchanged": true, "preview": shown})).into_response();
    }
    match state
        .system
        .restore_as(
            &state.config_store,
            &preview.doc,
            "uploaded declarative file",
            &admin.session.username,
            "import",
        )
        .await
    {
        Ok(lines) => {
            super::system::end_sessions_after_restore(&state, &admin, &preview.doc).await;
            Json(json!({"ok": true, "applied": lines, "preview": shown})).into_response()
        }
        Err(e) => super::system::err(e),
    }
}

/// The Config generations page.
pub async fn page(me: AuthUser) -> Response {
    use askama::Template;
    let t = crate::templates::GenerationsTemplate {
        page: "generations",
        is_admin: me.session.role.is_admin(),
    };
    match t.render() {
        Ok(h) => Html(h).into_response(),
        Err(e) => {
            tracing::error!("render generations page: {e}");
            (StatusCode::INTERNAL_SERVER_ERROR, "Failed to render page").into_response()
        }
    }
}

pub fn pages() -> axum::Router<AppState> {
    axum::Router::new().route("/generations", get(page))
}

pub fn router() -> axum::Router<AppState> {
    axum::Router::new()
        .route("/system/generations", get(list))
        .route("/system/generations/pending", get(get_pending))
        .route("/system/generations/pending/confirm", post(confirm))
        .route("/system/generations/pending/revert-now", post(revert_now))
        .route("/system/generations/diff", get(diff))
        .route("/system/generations/:id", get(show))
        .route("/system/generations/:id/rollback", post(rollback))
        .route("/system/generations/:id/pin", post(pin))
        .route("/system/config/export", get(export))
        .route("/system/config/import", post(import))
}

// ---------------------------------------------------------------------------
// change-set middleware: commit message + commit-confirmed for ANY change
// ---------------------------------------------------------------------------

/// Requests that must never be wrapped: they are the confirmation itself.
fn exempt(path: &str) -> bool {
    path.starts_with("/api/system/generations/pending")
        || path.ends_with("/pin")
        || path.starts_with("/api/auth/")
}

fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn clean_commit_message(raw: &str) -> Option<String> {
    let m: String = percent_decode(raw)
        .chars()
        .filter(|c| !c.is_control())
        .take(200)
        .collect();
    let m = m.trim().to_string();
    (!m.is_empty()).then_some(m)
}

/// Wraps every changing API call that carries `X-Commit-Message` and/or
/// `X-Confirm-In: N`:
///
/// - the change becomes a generation with the user's message;
/// - with `X-Confirm-In` the previous generation and a deadline are stored
///   after the change applied (refused up front, changing nothing, when no
///   applyd timer is running to enforce it). The answer carries
///   `X-Pending-Deadline`, `X-Pending-Previous` and `X-Pending-Generation`.
///
/// Every page's "risky change" switch sets the header, so firewall,
/// interfaces, routes, VPN, import and rollback all get it without each
/// manager knowing.
pub async fn change_set_layer(
    State(state): State<AppState>,
    req: Request<Body>,
    next: Next,
) -> Response {
    let mutating = !matches!(*req.method(), Method::GET | Method::HEAD | Method::OPTIONS);
    let path = req.uri().path().to_string();
    // (a block: a borrow of the request must not live across an await)
    let (confirm, message) = {
        let hdr = |n: &str| {
            req.headers()
                .get(n)
                .and_then(|v| v.to_str().ok())
                .map(str::to_string)
        };
        (
            hdr("x-confirm-in"),
            hdr("x-commit-message").and_then(|m| clean_commit_message(&m)),
        )
    };
    if !mutating
        || !path.starts_with("/api/")
        || exempt(&path)
        || (confirm.is_none() && message.is_none())
    {
        return next.run(req).await;
    }
    let minutes = match confirm {
        None => None,
        Some(c) => match c.trim().parse::<i64>() {
            Ok(n) if (1..=MAX_CONFIRM_MINUTES).contains(&n) => Some(n),
            _ => {
                return error(
                    StatusCode::BAD_REQUEST,
                    format!("Invalid X-Confirm-In: minutes from 1 to {MAX_CONFIRM_MINUTES}"),
                )
            }
        },
    };
    if minutes.is_some() && !state.system.watchdog_available().await {
        return error(
            StatusCode::CONFLICT,
            "Cannot arm the auto-revert: patronus applyd, which enforces the deadline, is not running. Nothing was changed.",
        );
    }
    // who is changing it
    let (mut parts, body) = req.into_parts();
    let actor = match <AuthUser as axum::extract::FromRequestParts<()>>::from_request_parts(
        &mut parts,
        &(),
    )
    .await
    {
        Ok(u) => u.session.username,
        Err(_) => "api-key".to_string(),
    };
    let req = Request::from_parts(parts, body);
    let store = state.config_store.clone();
    let prev = match store
        .snapshot(&actor, "change made in the web UI")
        .await
    {
        Ok(p) => p,
        Err(e) => return store_err(e),
    };
    let mut res = next.run(req).await;
    if !res.status().is_success() {
        let _ = store.finish_change_set().await;
        return res;
    }
    let new = store.finish_change_set().await.ok().flatten();
    if let (Some(id), Some(m)) = (new, &message) {
        let _ = store.set_generation_message(id, m).await;
    }
    if let Some(n) = minutes {
        match store.start_pending(prev, n, &actor).await {
            Ok(Some(p)) => {
                for (k, v) in [
                    ("x-pending-deadline", p.deadline),
                    ("x-pending-previous", p.previous),
                    ("x-pending-generation", p.generation),
                ] {
                    if let Ok(v) = HeaderValue::from_str(&v.to_string()) {
                        res.headers_mut().insert(k, v);
                    }
                }
            }
            Ok(None) => {}
            Err(e) => tracing::warn!("arming the auto-revert: {e}"),
        }
    }
    res
}

#[cfg(test)]
mod unit {
    use super::*;

    #[test]
    fn commit_messages_are_decoded_and_bounded() {
        assert_eq!(
            clean_commit_message("open%20ssh%20for%20vendor").as_deref(),
            Some("open ssh for vendor")
        );
        assert_eq!(clean_commit_message("  %0A  "), None);
        assert_eq!(clean_commit_message("100%"), Some("100%".into()));
        assert_eq!(clean_commit_message(&"a".repeat(500)).unwrap().len(), 200);
    }

    #[test]
    fn the_confirmation_itself_is_never_wrapped() {
        assert!(exempt("/api/system/generations/pending/confirm"));
        assert!(exempt("/api/system/generations/7/pin"));
        assert!(!exempt("/api/system/generations/7/rollback"));
        assert!(!exempt("/api/firewall/rules"));
    }
}
