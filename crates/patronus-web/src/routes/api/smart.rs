//! S.M.A.R.T. disk health (USE=smart): the Hardware > S.M.A.R.T. page and its API. The poller
//! (`patronus smart run`, root) does the smartctl work; this reads what it stored and, for "start a
//! self-test", writes a request it picks up. A build without USE=smart answers 404 with the flag.
//!
//! The same routes answer under `/api/smart` and `/api/v1/smart`.
//!
//! - `GET  /api/v1/smart`                 status: enabled, smartctl installed, poller running, every disk
//! - `GET  /api/v1/smart/<disk>`          one disk: attributes, self-test log, history (`?samples=N`)
//! - `POST /api/v1/smart/test`            `{"type": "short"|"long", "device"?: "sda"}` start a self-test
//!   (every disk without `device`)
//! - `POST /api/v1/smart/<disk>/test`     `{"type": "short"|"long"}`
//!
//! Settings (interval, schedule, thresholds, notifications) are the `smart` feature page
//! (`/svc/smart`, `/api/svc/smart`).

use crate::state::AppState;

#[cfg(feature = "smart")]
mod built {
    use super::*;
    use askama::Template;
    use axum::extract::{Path, Query, State};
    use axum::{
        http::StatusCode,
        response::{Html, IntoResponse, Response},
        routing::{get, post},
        Json,
    };
    use patronus_network::smart::{self, Level, TestKind};
    use patronus_network::svc::Settings;
    use serde::Deserialize;
    use serde_json::{json, Value};

    fn err(e: impl std::fmt::Display) -> Response {
        let msg = e.to_string();
        let code = if msg.contains("Invalid") {
            StatusCode::BAD_REQUEST
        } else if msg.contains("no S.M.A.R.T. disk") {
            StatusCode::NOT_FOUND
        } else {
            StatusCode::INTERNAL_SERVER_ERROR
        };
        (code, Json(json!({ "error": msg }))).into_response()
    }

    #[derive(Template)]
    #[template(path = "smart.html")]
    struct SmartTemplate {
        page: &'static str,
        can_modify: bool,
    }

    async fn page(me: crate::auth::AuthUser) -> Response {
        match (SmartTemplate {
            page: "smart",
            can_modify: me.session.role.can_modify(),
        })
        .render()
        {
            Ok(h) => Html(h).into_response(),
            Err(e) => {
                tracing::error!("render smart page: {e}");
                (StatusCode::INTERNAL_SERVER_ERROR, "Failed to render page").into_response()
            }
        }
    }

    /// Why the list is empty, in words a person can act on. `None` when there are disks to show.
    pub fn empty_reason(enabled: bool, installed: bool, disks: &[smart::Stored]) -> Option<Value> {
        let (code, text) = if !enabled {
            (
                "disabled",
                "S.M.A.R.T. monitoring is switched off. Turn it on in the S.M.A.R.T. settings to start polling the disks.",
            )
        } else if !installed {
            (
                "no-smartctl",
                "smartctl is not installed on this system (smartmontools), so no disk can be read. Install it from Add-on packages.",
            )
        } else if disks.is_empty() {
            (
                "not-polled",
                "No disk has been polled yet. The first look happens shortly after monitoring starts; if this stays empty the poller is not running.",
            )
        } else if disks.iter().all(|d| !d.disk.smart_available) {
            (
                "no-smart-disk",
                "No S.M.A.R.T. capable disk: this system's disks do not report S.M.A.R.T. (virtual disks in a VM without it, SD cards and eMMC flash do not).",
            )
        } else {
            return None;
        };
        Some(json!({ "code": code, "text": text }))
    }

    pub async fn overview(State(st): State<AppState>) -> Response {
        let store = &st.config_store;
        let s = match Settings::load(store, smart::spec()).await {
            Ok(s) => s,
            Err(e) => return err(e),
        };
        let disks = match smart::latest(store).await {
            Ok(d) => d,
            Err(e) => return err(e),
        };
        let applier = st.lan.status("smart").await.unwrap_or(Value::Null);
        let enabled = s.b("enabled");
        let installed = smart::smartctl_bin().is_some();
        let count = |l: Level| disks.iter().filter(|d| d.level == l).count();
        Json(json!({
            "enabled": enabled,
            "smartctl_installed": installed,
            "poller_running": applier["running"].as_bool().unwrap_or(false),
            "poll_minutes": s.n("poll_minutes"),
            "last_checked": disks.iter().map(|d| d.at).max(),
            "summary": {
                "disks": disks.len(),
                "ok": count(Level::Ok),
                "warning": count(Level::Warning),
                "critical": count(Level::Critical),
                "unsupported": count(Level::Unsupported),
            },
            "empty": empty_reason(enabled, installed, &disks),
            "devices": disks.iter().map(smart::summary_json).collect::<Vec<_>>(),
        }))
        .into_response()
    }

    #[derive(Deserialize)]
    pub struct DetailQuery {
        samples: Option<i64>,
    }

    fn dev_path(name: &str) -> Result<String, Box<Response>> {
        let p = format!("/dev/{name}");
        if smart::valid_device(&p) {
            Ok(p)
        } else {
            Err(Box::new(err(format!("Invalid device {name:?}"))))
        }
    }

    pub async fn detail(
        State(st): State<AppState>,
        Path(name): Path<String>,
        Query(q): Query<DetailQuery>,
    ) -> Response {
        let dev = match dev_path(&name) {
            Ok(d) => d,
            Err(r) => return *r,
        };
        let store = &st.config_store;
        let Ok(Some(d)) = smart::latest_one(store, &dev).await else {
            return err(format!("no S.M.A.R.T. disk {dev}"));
        };
        let hist = smart::history(store, &dev, q.samples.unwrap_or(500).clamp(1, 20_000))
            .await
            .unwrap_or_default();
        Json(smart::detail_json(&d, &hist)).into_response()
    }

    #[derive(Deserialize)]
    pub struct TestBody {
        #[serde(rename = "type")]
        kind: Option<String>,
        device: Option<String>,
    }

    async fn start(st: &AppState, device: Option<String>, body: TestBody) -> Response {
        let Some(kind) = body.kind.as_deref().and_then(TestKind::parse) else {
            return err("Invalid test type: use \"short\" or \"long\"");
        };
        match smart::request_test(&st.config_store, device.as_deref(), kind).await {
            Ok(n) => (
                StatusCode::ACCEPTED,
                Json(json!({ "queued": n, "type": kind.as_str(),
                    "note": "the poller starts it within a few seconds; the result shows on the disk" })),
            )
                .into_response(),
            Err(e) => err(e),
        }
    }

    pub async fn test_all(State(st): State<AppState>, Json(b): Json<TestBody>) -> Response {
        let dev = b.device.clone().filter(|d| !d.is_empty());
        start(&st, dev, b).await
    }

    pub async fn test_one(
        State(st): State<AppState>,
        Path(name): Path<String>,
        Json(b): Json<TestBody>,
    ) -> Response {
        start(&st, Some(name), b).await
    }

    pub fn router() -> axum::Router<AppState> {
        let mut r = axum::Router::new();
        for base in ["/smart", "/v1/smart"] {
            r = r
                .route(base, get(overview))
                .route(&format!("{base}/test"), post(test_all))
                .route(&format!("{base}/:disk"), get(detail))
                .route(&format!("{base}/:disk/test"), post(test_one));
        }
        r
    }

    pub fn pages() -> axum::Router<AppState> {
        axum::Router::new().route("/smart", get(page))
    }
}

#[cfg(not(feature = "smart"))]
mod built {
    use super::*;
    use axum::{http::StatusCode, response::IntoResponse, routing::any, Json};

    async fn off() -> impl IntoResponse {
        (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "error": "S.M.A.R.T. monitoring is not built into this installation (its USE flag, smart, is off)"
            })),
        )
    }

    pub fn router() -> axum::Router<AppState> {
        axum::Router::new()
            .route("/smart", any(off))
            .route("/smart/*rest", any(off))
            .route("/v1/smart", any(off))
            .route("/v1/smart/*rest", any(off))
    }

    pub fn pages() -> axum::Router<AppState> {
        axum::Router::new().route(
            "/smart",
            axum::routing::get(|| async {
                crate::routes::pages::not_in_build(
                    StatusCode::NOT_FOUND,
                    "S.M.A.R.T. unavailable",
                    "S.M.A.R.T. disk health",
                    "",
                    "smart",
                )
            }),
        )
    }
}

pub fn router() -> axum::Router<AppState> {
    built::router()
}

pub fn pages() -> axum::Router<AppState> {
    built::pages()
}
