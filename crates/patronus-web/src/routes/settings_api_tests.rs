//! `/api/settings` and the Advanced settings page through the real router:
//! listing with defaults, validation (400), unknown keys (404), admin-only
//! changes, reset, and the change surviving a backup document round trip.
//!
//! Only `network.ddns_refresh_secs` is changed here: the web-auth settings
//! are read from a process-wide cache that other tests in this binary use.

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use serde_json::{json, Value};
use std::sync::Arc;
use tower::ServiceExt;

const KEY: &str = "network.ddns_refresh_secs";

struct App {
    app: axum::Router,
    cookie: String,
    store: Arc<patronus_config::ConfigStore>,
}

async fn app() -> App {
    let dir = std::env::temp_dir().join(format!("patronus-web-settings-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let store = Arc::new(
        patronus_config::ConfigStore::open(dir.join("config.db"))
            .await
            .unwrap(),
    );
    let state = crate::AppState::new(store.clone(), Arc::new(crate::state::firewall::NoopApplier))
        .await
        .unwrap();
    let pw = "Settings-Test-Passw0rd!".to_string();
    state
        .auth
        .user_store
        .provision_admin(Some(pw.clone()), &dir.join("pw"))
        .await
        .unwrap();
    let app = super::build_router(state, Arc::new(crate::WsBroadcaster::new()));
    let login = format!(r#"{{"username":"admin","password":"{pw}"}}"#);
    let r = app
        .clone()
        .oneshot(req(Method::POST, "/api/auth/login", None, Some(&login)))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let cookie = r.headers()[header::SET_COOKIE]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string();
    App { app, cookie, store }
}

fn req(method: Method, uri: &str, cookie: Option<&str>, body: Option<&str>) -> Request<Body> {
    let mut b = Request::builder().method(method).uri(uri);
    if let Some(c) = cookie {
        b = b.header(header::COOKIE, c);
    }
    if body.is_some() {
        b = b.header(header::CONTENT_TYPE, "application/json");
    }
    b.body(
        body.map(|s| Body::from(s.to_string()))
            .unwrap_or_else(Body::empty),
    )
    .unwrap()
}

impl App {
    async fn call(
        &self,
        m: Method,
        uri: &str,
        cookie: bool,
        body: Option<Value>,
    ) -> (StatusCode, Value) {
        let body = body.map(|b| b.to_string());
        let c = cookie.then_some(self.cookie.as_str());
        let r = self
            .app
            .clone()
            .oneshot(req(m, uri, c, body.as_deref()))
            .await
            .unwrap();
        let status = r.status();
        let bytes = axum::body::to_bytes(r.into_body(), 10 << 20).await.unwrap();
        let text = String::from_utf8_lossy(&bytes).into_owned();
        (
            status,
            serde_json::from_str(&text).unwrap_or(Value::String(text)),
        )
    }
}

fn entry<'a>(list: &'a Value, key: &str) -> &'a Value {
    list["settings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["key"] == key)
        .unwrap_or_else(|| panic!("{key} missing from {list}"))
}

#[tokio::test]
async fn list_set_validate_reset_and_backup_round_trip() {
    let a = app().await;
    let def = patronus_config::settings::find(KEY).unwrap().default;

    // every registered key is listed with its default and documentation
    let (s, list) = a.call(Method::GET, "/api/settings", true, None).await;
    assert_eq!(s, StatusCode::OK, "{list}");
    assert_eq!(
        list["settings"].as_array().unwrap().len(),
        patronus_config::settings::REGISTRY.len()
    );
    let e = entry(&list, KEY);
    assert_eq!(e["value"], def);
    assert_eq!(e["is_default"], true);
    assert_eq!(e["kind"]["type"], "int");
    assert!(!e["doc"].as_str().unwrap().is_empty());

    // logins only, admins to change
    let (s, _) = a.call(Method::GET, "/api/settings", false, None).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    let (s, _) = a
        .call(
            Method::PUT,
            &format!("/api/settings/{KEY}"),
            false,
            Some(json!({"value": 7200})),
        )
        .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);

    // invalid values and unknown keys are refused, nothing stored
    let (s, b) = a
        .call(
            Method::PUT,
            &format!("/api/settings/{KEY}"),
            true,
            Some(json!({"value": 5})),
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{b}");
    assert!(b["error"].as_str().unwrap().contains("outside"), "{b}");
    let (s, _) = a
        .call(
            Method::PUT,
            &format!("/api/settings/{KEY}"),
            true,
            Some(json!({"value": "abc"})),
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let (s, _) = a
        .call(
            Method::PUT,
            "/api/settings/no.such_key",
            true,
            Some(json!({"value": 1})),
        )
        .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    assert_eq!(a.store.load_system_config(KEY).await.unwrap(), None);

    // a valid change is stored, listed as changed and audited
    let (s, b) = a
        .call(
            Method::PUT,
            &format!("/api/settings/{KEY}"),
            true,
            Some(json!({"value": "7200"})),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{b}");
    assert_eq!(b["value"], "7200");
    assert_eq!(b["is_default"], false);
    assert_eq!(
        patronus_config::settings::current_i64(KEY),
        7200,
        "cache refreshed"
    );
    assert_eq!(
        a.store.load_system_config(KEY).await.unwrap().as_deref(),
        Some("7200")
    );
    let audited: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_log WHERE entity_type = 'setting' AND entity_id = ?",
    )
    .bind(KEY)
    .fetch_one(a.store.pool().unwrap())
    .await
    .unwrap();
    assert_eq!(audited, 1);

    // the change is part of the configuration document (backup/restore)
    let doc = a.store.export_json().await.unwrap();
    let b2 = patronus_config::ConfigStore::open_in_memory()
        .await
        .unwrap();
    b2.import_json(&doc).await.unwrap();
    assert_eq!(
        patronus_config::settings::get(&b2, KEY).await.unwrap(),
        "7200"
    );

    // reset goes back to the default
    let (s, b) = a
        .call(Method::DELETE, &format!("/api/settings/{KEY}"), true, None)
        .await;
    assert_eq!(s, StatusCode::OK, "{b}");
    assert_eq!(b["value"], def);
    assert_eq!(b["is_default"], true);

    // the page renders and links back to System; System links to it
    let (s, page) = a.call(Method::GET, "/settings", true, None).await;
    assert_eq!(s, StatusCode::OK);
    let page = page.as_str().unwrap_or_default().to_string();
    assert!(
        page.contains("Advanced settings") && page.contains("/api/settings"),
        "{page}"
    );
    let (_, sys) = a.call(Method::GET, "/system", true, None).await;
    assert!(sys
        .as_str()
        .unwrap_or_default()
        .contains("href=\"/settings\""));
}
