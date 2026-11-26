//! The dashboard widgets API, the system activity API and the pages that use
//! them, driven through the real router with logged-in sessions: per-user
//! layouts and their isolation, validation, roles, defaults, the server-side
//! rendered page, settings, and the sampled process list with redaction.

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use serde_json::{json, Value};
use std::sync::Arc;
use tower::ServiceExt;

struct App {
    app: axum::Router,
    admin: String,
    store: Arc<patronus_config::ConfigStore>,
}

const PW: &str = "Dash-Test-Passw0rd!-91";

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

async fn app() -> App {
    let dir = std::env::temp_dir().join(format!("patronus-web-dash-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let store = Arc::new(
        patronus_config::ConfigStore::open(dir.join("config.db"))
            .await
            .unwrap(),
    );
    let state = crate::AppState::new(store.clone(), Arc::new(crate::state::firewall::NoopApplier))
        .await
        .unwrap();
    state
        .auth
        .user_store
        .provision_admin(Some(PW.to_string()), &dir.join("pw"))
        .await
        .unwrap();
    let app = super::build_router(state, Arc::new(crate::WsBroadcaster::new()));
    let mut a = App {
        app,
        admin: String::new(),
        store,
    };
    a.admin = a.login("admin").await;
    a
}

impl App {
    async fn login(&self, user: &str) -> String {
        let body = json!({"username": user, "password": PW}).to_string();
        let r = self
            .app
            .clone()
            .oneshot(req(Method::POST, "/api/auth/login", None, Some(&body)))
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::OK, "login {user}");
        r.headers()[header::SET_COOKIE]
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_string()
    }

    /// An account with `role`; returns its session cookie.
    async fn user(&self, name: &str, role: &str) -> String {
        let (s, v) = self
            .call(
                &self.admin,
                Method::POST,
                "/api/system/users",
                Some(json!({"username": name, "password": PW, "role": role})),
            )
            .await;
        assert_eq!(s, StatusCode::CREATED, "{v}");
        self.login(name).await
    }

    async fn raw(
        &self,
        cookie: Option<&str>,
        m: Method,
        uri: &str,
        body: Option<&str>,
    ) -> (StatusCode, String) {
        let r = self
            .app
            .clone()
            .oneshot(req(m, uri, cookie, body))
            .await
            .unwrap();
        let st = r.status();
        let bytes = axum::body::to_bytes(r.into_body(), 10 << 20).await.unwrap();
        (st, String::from_utf8_lossy(&bytes).into_owned())
    }

    async fn call(
        &self,
        cookie: &str,
        m: Method,
        uri: &str,
        body: Option<Value>,
    ) -> (StatusCode, Value) {
        let body = body.map(|b| b.to_string());
        let (s, t) = self.raw(Some(cookie), m, uri, body.as_deref()).await;
        (s, serde_json::from_str(&t).unwrap_or(Value::String(t)))
    }

    async fn get(&self, cookie: &str, uri: &str) -> (StatusCode, Value) {
        self.call(cookie, Method::GET, uri, None).await
    }
}

fn ids(v: &Value) -> Vec<String> {
    v["layout"]["widgets"]
        .as_array()
        .unwrap()
        .iter()
        .map(|w| w["id"].as_str().unwrap().to_string())
        .collect()
}

fn on(v: &Value, id: &str) -> bool {
    v["layout"]["widgets"]
        .as_array()
        .unwrap()
        .iter()
        .find(|w| w["id"] == id)
        .unwrap()["on"]
        .as_bool()
        .unwrap()
}

const LAYOUT: &str = "/api/v1/dashboard/layout";

/// A complete layout body: `first` (id, on) in this order, then every other widget of the
/// default layout in its default place and state (a client always sends the full list).
async fn full(a: &App, cookie: &str, first: &[(&str, bool)]) -> Value {
    let (_, d) = a.get(cookie, "/api/v1/dashboard/layout").await;
    let mut out: Vec<Value> = first.iter().map(|(id, on)| json!({"id": id, "on": on})).collect();
    for w in d["default"]["widgets"].as_array().unwrap() {
        if !first.iter().any(|(id, _)| w["id"] == *id) {
            out.push(w.clone());
        }
    }
    json!({"widgets": out})
}

#[tokio::test]
async fn a_user_who_never_customized_gets_the_default_layout() {
    let a = app().await;
    let (s, v) = a.get(&a.admin, LAYOUT).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["customized"], false);
    assert_eq!(v["user"], "admin");
    assert_eq!(v["layout"], v["default"]);
    assert_eq!(ids(&v)[0], "internet");
    assert!(on(&v, "system") && !on(&v, "activity"), "activity is opt-in");
    let reg = v["registry"].as_array().unwrap();
    assert!(reg.iter().any(|w| w["id"] == "activity" && w["title"] == "System activity"));
}

#[tokio::test]
async fn save_reorder_hide_and_reset_roundtrip() {
    let a = app().await;
    let put = full(&a, &a.admin, &[("system", true), ("services", true), ("internet", false), ("activity", true)]).await;
    let (s, v) = a.call(&a.admin, Method::PUT, LAYOUT, Some(put)).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["customized"], true);
    // the saved order comes first; widgets it never named follow at their default places
    assert_eq!(&ids(&v)[..4], ["system", "services", "internet", "activity"], "{:?}", ids(&v));
    assert!(!on(&v, "internet") && on(&v, "activity"));
    // a fresh read gives the same
    let (_, v2) = a.get(&a.admin, LAYOUT).await;
    assert_eq!(v2["layout"], v["layout"]);
    // the stored document is a config row
    let export = a.store.export_json().await.unwrap();
    assert_eq!(export["tables"]["dashboard_layouts"][0]["user"], "admin");
    // reset
    let (s, v) = a.call(&a.admin, Method::DELETE, LAYOUT, None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v["customized"], false);
    assert_eq!(v["layout"], v["default"]);
}

#[tokio::test]
async fn unknown_repeated_and_malformed_layouts_are_refused_and_change_nothing() {
    let a = app().await;
    let good = full(&a, &a.admin, &[("system", true)]).await;
    assert_eq!(a.call(&a.admin, Method::PUT, LAYOUT, Some(good)).await.0, StatusCode::OK);
    for bad in [
        json!({"widgets": [{"id": "nope", "on": true}]}),
        json!({"widgets": [{"id": "system", "on": true}, {"id": "system", "on": false}]}),
        json!({"widgets": [{"id": "system"}]}),
        json!({"widgets": "all"}),
        json!({"nothing": 1}),
        Value::String("x".into()),
        json!({"widgets": (0..70).map(|i| json!({"id": format!("w{i}"), "on": true})).collect::<Vec<_>>()}),
    ] {
        let (s, v) = a.call(&a.admin, Method::PUT, LAYOUT, Some(bad.clone())).await;
        assert!(
            s == StatusCode::BAD_REQUEST || s == StatusCode::UNPROCESSABLE_ENTITY,
            "{bad} -> {s} {v}"
        );
    }
    let (s, v) = a
        .call(&a.admin, Method::PUT, LAYOUT, Some(json!({"widgets": [{"id": "nope", "on": true}]})))
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert!(v["error"].as_str().unwrap().contains("nope"), "{v}");
    let (_, v) = a.get(&a.admin, LAYOUT).await;
    assert_eq!(ids(&v)[0], "system", "the earlier good layout is untouched");
}

#[tokio::test]
async fn layouts_are_private_to_each_user_and_read_only_users_keep_their_own() {
    let a = app().await;
    let viewer = a.user("viewer", "readonly").await;
    let op = a.user("operator1", "operator").await;
    let mine = full(&a, &a.admin, &[("services", true), ("system", false)]).await;
    assert_eq!(a.call(&a.admin, Method::PUT, LAYOUT, Some(mine)).await.0, StatusCode::OK);
    // the others still have the default
    for who in [&viewer, &op] {
        let (_, v) = a.get(who, LAYOUT).await;
        assert_eq!(v["customized"], false);
        assert_eq!(ids(&v)[0], "internet");
        assert!(on(&v, "system"));
    }
    // the read-only role may save ITS OWN layout (a display preference) ...
    let theirs = full(&a, &viewer, &[("traffic", true), ("internet", false)]).await;
    let (s, v) = a.call(&viewer, Method::PUT, LAYOUT, Some(theirs)).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["user"], "viewer");
    assert_eq!(ids(&v)[0], "traffic");
    // ... which neither changes the admin's nor the operator's
    let (_, v) = a.get(&a.admin, LAYOUT).await;
    assert_eq!(ids(&v)[0], "services");
    assert!(!on(&v, "system"));
    let (_, v) = a.get(&op, LAYOUT).await;
    assert_eq!(v["customized"], false);
    // resetting one user's layout leaves the others
    assert_eq!(a.call(&viewer, Method::DELETE, LAYOUT, None).await.0, StatusCode::OK);
    let (_, v) = a.get(&a.admin, LAYOUT).await;
    assert_eq!(v["customized"], true);
    // the request cannot name another user
    let (_, v) = a
        .call(&viewer, Method::PUT, "/api/v1/dashboard/layout?user=admin", Some(json!({"widgets": [{"id": "dhcp", "on": false}]})))
        .await;
    assert_eq!(v["user"], "viewer");
    let (_, v) = a.get(&a.admin, LAYOUT).await;
    assert_eq!(ids(&v)[0], "services");
    // one row per user in the store
    let rows = a.store.export_json().await.unwrap()["tables"]["dashboard_layouts"].as_array().unwrap().len();
    assert_eq!(rows, 2, "admin and viewer");
}

#[tokio::test]
async fn an_api_key_is_not_a_web_user_and_anonymous_calls_are_refused() {
    let a = app().await;
    let (s, k) = a
        .call(&a.admin, Method::POST, "/api/system/api-keys", Some(json!({"name": "dash-test", "scope": "operator"})))
        .await;
    assert_eq!(s, StatusCode::CREATED, "{k}");
    let token = k["token"].as_str().unwrap();
    let r = a
        .app
        .clone()
        .oneshot(
            Request::builder()
                .uri(LAYOUT)
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::FORBIDDEN);
    let (s, _) = a.raw(None, Method::GET, LAYOUT, None).await;
    assert!(s == StatusCode::UNAUTHORIZED || s.is_redirection(), "{s}");
    let (s, _) = a.raw(None, Method::PUT, LAYOUT, Some("{\"widgets\":[]}")).await;
    assert!(s == StatusCode::UNAUTHORIZED || s.is_redirection(), "{s}");
    let (s, _) = a.raw(None, Method::GET, "/api/v1/system/activity", None).await;
    assert!(s == StatusCode::UNAUTHORIZED || s.is_redirection(), "{s}");
}

fn position(html: &str, id: &str) -> Option<usize> {
    html.find(&format!("data-widget-id=\"{id}\""))
}

#[tokio::test]
async fn the_page_is_drawn_from_the_users_layout_on_the_server() {
    let a = app().await;
    let (s, html) = a.raw(Some(&a.admin), Method::GET, "/", None).await;
    assert_eq!(s, StatusCode::OK);
    let (i, f, sv) = (position(&html, "internet"), position(&html, "firewall-rules"), position(&html, "services"));
    assert!(i.is_some() && f.is_some() && sv.is_some() && i < f && f < sv, "default order");
    assert!(position(&html, "activity").is_none(), "off by default");
    assert!(html.contains("data-add=\"activity\""), "offered in the add list");
    assert!(!html.contains("Loading"), "no placeholders: the layout is rendered, not fetched");
    assert!(html.contains("id=\"dash-customize\"") && html.contains("id=\"dash-reset\""));
    // a saved layout changes the markup of the next page load
    let put = full(&a, &a.admin, &[("services", true), ("system", true), ("internet", false), ("activity", true)]).await;
    assert_eq!(a.call(&a.admin, Method::PUT, LAYOUT, Some(put)).await.0, StatusCode::OK);
    let (_, html) = a.raw(Some(&a.admin), Method::GET, "/", None).await;
    let (sv, sy, ac) = (position(&html, "services").unwrap(), position(&html, "system").unwrap(), position(&html, "activity").unwrap());
    assert!(sv < sy && sy < ac, "saved order drawn");
    assert!(position(&html, "internet").is_none(), "a hidden widget is not drawn");
    assert!(html.contains("data-add=\"internet\""));
    assert!(html.contains("id=\"activity-widget-table\""));
    // another user's page is unchanged
    let viewer = a.user("viewer2", "readonly").await;
    let (_, html) = a.raw(Some(&viewer), Method::GET, "/", None).await;
    assert!(position(&html, "internet").is_some() && position(&html, "activity").is_none());
}

#[tokio::test]
async fn settings_have_defaults_are_validated_and_only_admins_change_them() {
    let a = app().await;
    let (s, v) = a.get(&a.admin, "/api/v1/dashboard/settings").await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v["refresh_seconds"], 30);
    assert_eq!(v["activity_sample_secs"], 3);
    assert_eq!(v["tcp_timeout_secs"], 3);
    assert_eq!(v["tcp_tests_per_minute"], 30);
    let (s, _) = a.call(&a.admin, Method::PUT, "/api/v1/dashboard/settings", Some(json!({"refresh_seconds": 2}))).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let (s, _) = a.call(&a.admin, Method::PUT, "/api/v1/dashboard/settings", Some(json!({"bogus": 2}))).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let viewer = a.user("viewer3", "readonly").await;
    let (s, _) = a.call(&viewer, Method::PUT, "/api/v1/dashboard/settings", Some(json!({"refresh_seconds": 60}))).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (s, v) = a.call(&a.admin, Method::PUT, "/api/v1/dashboard/settings", Some(json!({"refresh_seconds": 60}))).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["refresh_seconds"], 60);
    let (_, html) = a.raw(Some(&a.admin), Method::GET, "/", None).await;
    assert!(html.contains("data-refresh=\"60\""), "the page uses the setting");
    // 0 = never refresh
    assert_eq!(a.call(&a.admin, Method::PUT, "/api/v1/dashboard/settings", Some(json!({"refresh_seconds": 0}))).await.0, StatusCode::OK);
    let (_, html) = a.raw(Some(&a.admin), Method::GET, "/", None).await;
    assert!(html.contains("data-refresh=\"0\""));
}

#[tokio::test]
async fn the_activity_api_lists_processes_sorts_filters_and_hides_secrets() {
    // a process whose command line carries secrets in several forms
    let mut child = std::process::Command::new("sh")
        .args(["-c", "sleep 60", "sh", "--password=hunter2-literal", "--api-token", "tok-literal-xyz", "--port", "8080"])
        .spawn()
        .unwrap();
    let a = app().await;
    let mut j = Value::Null;
    for _ in 0..100 {
        let (s, v) = a.get(&a.admin, "/api/v1/system/activity?limit=500").await;
        assert_eq!(s, StatusCode::OK, "{v}");
        if v["ready"] == true && v["processes"].as_array().is_some_and(|p| p.iter().any(|r| r["pid"] == child.id())) {
            j = v;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    }
    assert_eq!(j["ready"], true, "the sampler produced a snapshot");
    assert!(j["cpus"].as_u64().unwrap() >= 1);
    assert!(j["memory"]["total"].as_u64().unwrap() > 0);
    assert!(j["load"]["one"].is_number());
    let row = j["processes"].as_array().unwrap().iter().find(|r| r["pid"] == child.id()).unwrap().clone();
    let cmd = row["command"].as_str().unwrap();
    assert!(cmd.contains("--password=<redacted>") && cmd.contains("--api-token <redacted>") && cmd.contains("--port 8080"), "{cmd}");
    let all = j.to_string();
    assert!(!all.contains("hunter2-literal") && !all.contains("tok-literal-xyz"), "secrets left the API");
    for field in ["pid", "user", "name", "command", "cpu_percent", "rss_bytes", "threads", "state"] {
        assert!(row.get(field).is_some(), "row has {field}");
    }
    // sorting
    for key in ["cpu", "memory", "pid", "name", "user", "threads"] {
        let (s, v) = a.get(&a.admin, &format!("/api/v1/system/activity?sort={key}&order=asc&limit=500")).await;
        assert_eq!(s, StatusCode::OK, "{key}");
        let p = v["processes"].as_array().unwrap();
        assert!(!p.is_empty());
        if key == "pid" {
            let pids: Vec<u64> = p.iter().map(|r| r["pid"].as_u64().unwrap()).collect();
            assert!(pids.windows(2).all(|w| w[0] <= w[1]), "pid ascending");
        }
        if key == "memory" {
            let m: Vec<u64> = p.iter().map(|r| r["rss_bytes"].as_u64().unwrap()).collect();
            assert!(m.windows(2).all(|w| w[0] <= w[1]), "memory ascending");
        }
    }
    let (_, v) = a.get(&a.admin, "/api/v1/system/activity?sort=memory&order=desc&limit=500").await;
    let m: Vec<u64> = v["processes"].as_array().unwrap().iter().map(|r| r["rss_bytes"].as_u64().unwrap()).collect();
    assert!(m.windows(2).all(|w| w[0] >= w[1]), "memory descending");
    // limit and validation
    let (_, v) = a.get(&a.admin, "/api/v1/system/activity?limit=3").await;
    assert_eq!(v["processes"].as_array().unwrap().len(), 3.min(v["matched"].as_u64().unwrap() as usize));
    for bad in ["sort=bogus", "order=sideways", "limit=0", "limit=100000", "limit=x"] {
        let (s, _) = a.get(&a.admin, &format!("/api/v1/system/activity?{bad}")).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{bad}");
    }
    // the daemon filter keeps only that service's processes (none runs here: empty, not an error)
    let (s, v) = a.get(&a.admin, "/api/v1/system/activity?daemon=nonexistent-daemon").await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v["processes"], json!([]));
    // a read-only account may read it
    let viewer = a.user("viewer4", "readonly").await;
    assert_eq!(a.get(&viewer, "/api/v1/system/activity?limit=1").await.0, StatusCode::OK);
    // the page and its menu entry
    let (s, html) = a.raw(Some(&a.admin), Method::GET, "/activity", None).await;
    assert_eq!(s, StatusCode::OK);
    assert!(html.contains("System activity") && html.contains("data-sort=\"cpu\"") && html.contains("act-daemons"));
    assert!(html.contains("href=\"/activity\""), "menu entry");
    let _ = child.kill();
    let _ = child.wait();
}

#[tokio::test]
async fn the_diagnostics_page_offers_the_port_test() {
    let a = app().await;
    let (s, html) = a.raw(Some(&a.admin), Method::GET, "/diagnostics", None).await;
    assert_eq!(s, StatusCode::OK);
    assert!(html.contains("id=\"tcp-card\"") && html.contains("name=\"port\"") && html.contains("runDiag(event, 'tcp')"));
    // the typed settings the tool uses
    let (_, v) = a.get(&a.admin, "/api/v1/dashboard/settings").await;
    assert_eq!((v["tcp_timeout_secs"].as_u64(), v["tcp_tests_per_minute"].as_u64()), (Some(3), Some(30)));
}
