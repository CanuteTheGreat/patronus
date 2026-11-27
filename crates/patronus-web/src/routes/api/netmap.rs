//! Network map page and API (USE=netmap, lane w; docs/design/network-map.md).
//!
//! Signed in:
//! - `GET  /map`                              page (map, devices, advisor, sharing, settings)
//! - `GET  /api/map/graph`                    `infra-map/v1` graph (MACs + details)
//! - `GET  /api/map/devices`, `PUT /api/map/devices/:mac` {name?, class?, note?}
//! - `POST /api/map/discover`                 run a discovery round now
//! - `GET/POST /api/map/rules`, `DELETE /api/map/rules/:id`    class rules
//! - `GET/PUT /api/map/settings`              typed `map.*` settings
//! - `GET/POST /api/map/keys`, `DELETE /api/map/keys/:id`      read-only share keys (admin)
//! - `GET  /api/segmentation/advisor`, `POST /api/segmentation/advisor/apply` {segment, dry_run?}
//!
//! Public (a share key in `X-Map-Key` or `?key=`, never a session):
//! - `GET /map/live`                          read-only live map; the key rides in the URL fragment
//! - `GET /api/map/shared/graph`              graph (scope view; MACs/details only for detail=full)
//! - `GET /api/map/stats`                     flat counts for dashboard widgets (any scope, or signed in)
//! - `GET /ui-map/map.js`, `/ui-map/map.css`  the shared map component (compiled in)

use crate::state::AppState;

/// Paths of this module reachable without a session (the handlers check the share key).
pub fn is_public(path: &str) -> bool {
    cfg!(feature = "netmap")
        && (path == "/map/live"
            || path == "/api/map/stats"
            || path == "/api/map/shared/graph"
            || path == "/ui-map/map.js"
            || path == "/ui-map/map.css")
}

#[cfg(feature = "netmap")]
mod built {
    use super::*;
    use crate::state::netmap as nm;
    use askama::Template;
    use axum::extract::{Path, Query, State};
    use axum::http::{header, HeaderMap, StatusCode};
    use axum::response::IntoResponse;
    use axum::response::{Html, Response};
    use axum::routing::{delete, get, post, put};
    use axum::Json;
    use patronus_config::netmap;
    use serde::Deserialize;
    use serde_json::{json, Value};
    use std::collections::BTreeMap;

    const MAP_JS: &str = include_str!("../../../ui-map/map.js");
    const MAP_CSS: &str = include_str!("../../../ui-map/map.css");

    fn err(e: anyhow::Error) -> Response {
        let msg = e.to_string();
        let code = if msg.contains("Invalid") || msg.contains("already exists") {
            StatusCode::BAD_REQUEST
        } else if msg.starts_with("no ") || msg.contains(": no ") {
            StatusCode::NOT_FOUND
        } else {
            StatusCode::INTERNAL_SERVER_ERROR
        };
        (code, Json(json!({ "error": msg }))).into_response()
    }
    fn cerr(e: patronus_core::Error) -> Response {
        err(anyhow::anyhow!("{e}"))
    }

    #[derive(Template)]
    #[template(path = "netmap.html")]
    pub struct MapTemplate {
        pub page: &'static str,
        pub can_modify: bool,
        pub is_admin: bool,
        pub segmentation: bool,
    }

    #[derive(Template)]
    #[template(path = "netmap_live.html")]
    pub struct LiveTemplate {}

    pub async fn page(me: crate::auth::AuthUser) -> Response {
        let t = MapTemplate {
            page: "map",
            can_modify: me.session.role.can_modify(),
            is_admin: me.session.role.is_admin(),
            segmentation: cfg!(feature = "segmentation"),
        };
        match t.render() {
            Ok(h) => Html(h).into_response(),
            Err(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("render map: {e}"),
            )
                .into_response(),
        }
    }

    async fn live() -> Response {
        match (LiveTemplate {}).render() {
            Ok(h) => Html(h).into_response(),
            Err(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("render live map: {e}"),
            )
                .into_response(),
        }
    }

    async fn asset(body: &'static str, ct: &'static str) -> Response {
        (
            [
                (header::CONTENT_TYPE, ct),
                (header::CACHE_CONTROL, "public, max-age=3600"),
            ],
            body,
        )
            .into_response()
    }

    async fn graph(State(st): State<AppState>) -> Response {
        match nm::graph(&st.config_store, true).await {
            Ok(v) => Json(v).into_response(),
            Err(e) => err(e),
        }
    }

    async fn devices(State(st): State<AppState>) -> Response {
        let s = match netmap::load_settings(&st.config_store).await {
            Ok(s) => s,
            Err(e) => return cerr(e),
        };
        match netmap::list_devices(&st.config_store, &s, chrono::Utc::now().timestamp()).await {
            Ok(v) => Json(nm::devices_json(&v)).into_response(),
            Err(e) => cerr(e),
        }
    }

    #[derive(Deserialize)]
    struct LabelBody {
        name: Option<String>,
        class: Option<String>,
        note: Option<String>,
    }
    async fn put_device(
        State(st): State<AppState>,
        Path(mac): Path<String>,
        Json(b): Json<LabelBody>,
    ) -> Response {
        match netmap::set_label(
            &st.config_store,
            &mac,
            b.name.as_deref(),
            b.class.as_deref(),
            b.note.as_deref(),
        )
        .await
        {
            Ok(()) => {
                let _ = st
                    .config_store
                    .audit(
                        "web",
                        "update",
                        "map",
                        Some(&format!("label {mac}")),
                        &Value::Null,
                    )
                    .await;
                Json(json!({"ok": true})).into_response()
            }
            Err(e) => cerr(e),
        }
    }

    async fn discover(State(st): State<AppState>) -> Response {
        match nm::collect(&st.config_store).await {
            Ok(n) => Json(json!({"sightings": n})).into_response(),
            Err(e) => err(e),
        }
    }

    async fn rules(State(st): State<AppState>) -> Response {
        match netmap::list_rules(&st.config_store).await {
            Ok(v) => Json(
                json!({"rules": v, "builtin": netmap::BUILTIN_RULES, "classes": netmap::CLASSES}),
            )
            .into_response(),
            Err(e) => cerr(e),
        }
    }
    #[derive(Deserialize)]
    struct RuleBody {
        #[serde(default = "hostname")]
        field: String,
        pattern: String,
        class: String,
        #[serde(default = "prio")]
        priority: i64,
    }
    fn hostname() -> String {
        "hostname".into()
    }
    fn prio() -> i64 {
        100
    }
    async fn add_rule(State(st): State<AppState>, Json(b): Json<RuleBody>) -> Response {
        match netmap::add_rule(&st.config_store, &b.field, &b.pattern, &b.class, b.priority).await {
            Ok(id) => (StatusCode::CREATED, Json(json!({"id": id}))).into_response(),
            Err(e) => cerr(e),
        }
    }
    async fn del_rule(State(st): State<AppState>, Path(id): Path<i64>) -> Response {
        match netmap::delete_rule(&st.config_store, id).await {
            Ok(()) => Json(json!({"ok": true})).into_response(),
            Err(e) => cerr(e),
        }
    }

    async fn settings(State(st): State<AppState>) -> Response {
        match netmap::load_settings(&st.config_store).await {
            Ok(s) => Json(json!({
                "values": s.values,
                "settings": netmap::SETTINGS.iter().map(|(k, d, h)| json!({"key": k, "default": d, "help": h})).collect::<Vec<_>>(),
                "nmap_installed": has_bin("nmap"),
                "lldpctl_installed": has_bin("lldpctl"),
            }))
            .into_response(),
            Err(e) => cerr(e),
        }
    }
    fn has_bin(b: &str) -> bool {
        std::env::var_os("PATH")
            .map(|p| std::env::split_paths(&p).any(|d| d.join(b).is_file()))
            .unwrap_or(false)
    }
    async fn put_settings(
        State(st): State<AppState>,
        Json(b): Json<BTreeMap<String, String>>,
    ) -> Response {
        match netmap::save_settings(&st.config_store, &b).await {
            Ok(()) => {
                let _ = st
                    .config_store
                    .audit("web", "update", "map", Some("settings"), &json!(b))
                    .await;
                Json(json!({"ok": true})).into_response()
            }
            Err(e) => cerr(e),
        }
    }

    // --- share keys --------------------------------------------------------

    pub fn hash_key(k: &str) -> String {
        use sha2::Digest;
        sha2::Sha256::digest(k.as_bytes())
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }
    fn new_key() -> String {
        use rand::RngCore;
        let mut b = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut b);
        format!(
            "pmk_{}",
            b.iter().map(|x| format!("{x:02x}")).collect::<String>()
        )
    }

    async fn keys(me: crate::auth::AuthUser, State(st): State<AppState>) -> Response {
        if !me.session.role.is_admin() {
            return (
                StatusCode::FORBIDDEN,
                Json(json!({"error": "share keys are managed by administrators"})),
            )
                .into_response();
        }
        match netmap::list_keys(&st.config_store).await {
            Ok(v) => Json(v).into_response(),
            Err(e) => cerr(e),
        }
    }
    #[derive(Deserialize)]
    struct KeyBody {
        name: String,
        #[serde(default = "view")]
        scope: String,
        detail: Option<String>,
        /// days until it expires; absent or 0 = never
        expires_days: Option<i64>,
    }
    fn view() -> String {
        "view".into()
    }
    async fn add_key(
        me: crate::auth::AuthUser,
        State(st): State<AppState>,
        Json(b): Json<KeyBody>,
    ) -> Response {
        if !me.session.role.is_admin() {
            return (
                StatusCode::FORBIDDEN,
                Json(json!({"error": "share keys are managed by administrators"})),
            )
                .into_response();
        }
        let detail = match b.detail {
            Some(d) => d,
            None => match netmap::load_settings(&st.config_store).await {
                Ok(s) => s.get("share_detail").to_string(),
                Err(e) => return cerr(e),
            },
        };
        let exp = b
            .expires_days
            .filter(|d| *d > 0)
            .map(|d| chrono::Utc::now().timestamp() + d.min(3650) * 86400);
        let key = new_key();
        match netmap::create_key(
            &st.config_store,
            &b.name,
            &hash_key(&key),
            &b.scope,
            &detail,
            exp,
        )
        .await
        {
            Ok(id) => {
                let _ = st
                    .config_store
                    .audit(
                        &me.session.username,
                        "create",
                        "map",
                        Some(&format!("share key {}", b.name)),
                        &Value::Null,
                    )
                    .await;
                (
                    StatusCode::CREATED,
                    Json(json!({"id": id, "key": key, "live_path": format!("/map/live#k={key}")})),
                )
                    .into_response()
            }
            Err(e) => cerr(e),
        }
    }
    async fn del_key(
        me: crate::auth::AuthUser,
        State(st): State<AppState>,
        Path(id): Path<i64>,
    ) -> Response {
        if !me.session.role.is_admin() {
            return (
                StatusCode::FORBIDDEN,
                Json(json!({"error": "share keys are managed by administrators"})),
            )
                .into_response();
        }
        match netmap::delete_key(&st.config_store, id).await {
            Ok(()) => {
                let _ = st
                    .config_store
                    .audit(
                        &me.session.username,
                        "delete",
                        "map",
                        Some(&format!("share key {id}")),
                        &Value::Null,
                    )
                    .await;
                Json(json!({"ok": true})).into_response()
            }
            Err(e) => cerr(e),
        }
    }

    #[derive(Deserialize)]
    struct KeyQuery {
        key: Option<String>,
    }
    async fn shared_key(
        st: &AppState,
        headers: &HeaderMap,
        q: &KeyQuery,
    ) -> Option<netmap::ShareKey> {
        let k = headers
            .get("x-map-key")
            .and_then(|v| v.to_str().ok())
            .map(str::to_string)
            .or_else(|| q.key.clone())?;
        if !k.starts_with("pmk_") || k.len() > 80 {
            return None;
        }
        netmap::key_by_hash(
            &st.config_store,
            &hash_key(k.trim()),
            chrono::Utc::now().timestamp(),
        )
        .await
        .ok()
        .flatten()
    }
    fn denied() -> Response {
        (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "a valid map share key is required (X-Map-Key)"})),
        )
            .into_response()
    }

    async fn shared_graph(
        State(st): State<AppState>,
        headers: HeaderMap,
        Query(q): Query<KeyQuery>,
    ) -> Response {
        let Some(k) = shared_key(&st, &headers, &q).await else {
            return denied();
        };
        if k.scope != "view" {
            return (
                StatusCode::FORBIDDEN,
                Json(json!({"error": "this key may only read stats"})),
            )
                .into_response();
        }
        match nm::graph(&st.config_store, k.detail == "full").await {
            Ok(mut v) => {
                // a shared view never links into the admin UI
                if let Some(ns) = v["nodes"].as_array_mut() {
                    for n in ns {
                        if let Some(o) = n.as_object_mut() {
                            o.remove("href");
                        }
                    }
                }
                if let Some(fs) = v["findings"].as_array_mut() {
                    for f in fs {
                        if let Some(o) = f.as_object_mut() {
                            o.remove("action");
                        }
                    }
                }
                Json(v).into_response()
            }
            Err(e) => err(e),
        }
    }

    async fn stats(
        State(st): State<AppState>,
        me: Option<crate::auth::AuthUser>,
        headers: HeaderMap,
        Query(q): Query<KeyQuery>,
    ) -> Response {
        if me.is_none() && shared_key(&st, &headers, &q).await.is_none() {
            return denied();
        }
        match nm::stats(&st.config_store).await {
            Ok(v) => Json(v).into_response(),
            Err(e) => err(e),
        }
    }

    // --- advisor --------------------------------------------------------------

    async fn advisor(State(st): State<AppState>) -> Response {
        match nm::advisor(&st.config_store).await {
            Ok(v) => Json(v).into_response(),
            Err(e) => err(e),
        }
    }
    #[derive(Deserialize)]
    struct ApplyBody {
        segment: String,
        #[serde(default)]
        dry_run: bool,
    }
    #[cfg(feature = "segmentation")]
    async fn advisor_apply(State(st): State<AppState>, Json(b): Json<ApplyBody>) -> Response {
        match st.lan.map_advisor_apply(&b.segment, b.dry_run).await {
            Ok(v) => Json(v).into_response(),
            Err(e) => err(e),
        }
    }
    #[cfg(not(feature = "segmentation"))]
    async fn advisor_apply(Json(_b): Json<ApplyBody>) -> Response {
        (
            StatusCode::NOT_IMPLEMENTED,
            Json(json!({"error": "applying the plan needs device segmentation (USE=segmentation), which this build leaves out"})),
        )
            .into_response()
    }

    pub fn router() -> axum::Router<AppState> {
        axum::Router::new()
            .route("/map/graph", get(graph))
            .route("/map/devices", get(devices))
            .route("/map/devices/:mac", put(put_device))
            .route("/map/discover", post(discover))
            .route("/map/rules", get(rules).post(add_rule))
            .route("/map/rules/:id", delete(del_rule))
            .route("/map/settings", get(settings).put(put_settings))
            .route("/map/keys", get(keys).post(add_key))
            .route("/map/keys/:id", delete(del_key))
            .route("/map/shared/graph", get(shared_graph))
            .route("/map/stats", get(stats))
            .route("/segmentation/advisor", get(advisor))
            .route("/segmentation/advisor/apply", post(advisor_apply))
    }

    pub fn pages() -> axum::Router<AppState> {
        axum::Router::new()
            .route("/map", get(page))
            .route("/map/live", get(live))
            .route(
                "/ui-map/map.js",
                get(|| asset(MAP_JS, "text/javascript; charset=utf-8")),
            )
            .route(
                "/ui-map/map.css",
                get(|| asset(MAP_CSS, "text/css; charset=utf-8")),
            )
    }
}

#[cfg(feature = "netmap")]
pub use built::{pages, router};

#[cfg(not(feature = "netmap"))]
pub fn router() -> axum::Router<AppState> {
    axum::Router::new()
}
#[cfg(not(feature = "netmap"))]
pub fn pages() -> axum::Router<AppState> {
    axum::Router::new().route("/map", axum::routing::get(not_built))
}
#[cfg(not(feature = "netmap"))]
async fn not_built() -> impl axum::response::IntoResponse {
    crate::routes::pages::not_in_build(
        axum::http::StatusCode::NOT_IMPLEMENTED,
        "Network map",
        "Network map",
        "",
        "netmap",
    )
}

#[cfg(all(test, feature = "netmap"))]
mod tests {
    #[test]
    fn keys_hash_and_public_paths() {
        assert_eq!(super::built::hash_key("pmk_x").len(), 64);
        assert_ne!(
            super::built::hash_key("pmk_x"),
            super::built::hash_key("pmk_y")
        );
        assert!(super::is_public("/map/live"));
        assert!(super::is_public("/api/map/shared/graph"));
        assert!(!super::is_public("/api/map/graph"));
        assert!(!super::is_public("/api/map/keys"));
        assert!(!super::is_public("/map"));
    }
}
