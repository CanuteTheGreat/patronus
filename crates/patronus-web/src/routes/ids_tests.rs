//! Router-level tests for the intrusion detection pages and API (USE=intrusion-detection). The
//! Suricata side is proven by ci/netlab/lane-j-ids.sh; here the applier is a recorder so the
//! alert browser, the one-click suppress, validation and undo-on-failure can be checked anywhere.

use async_trait::async_trait;
use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use patronus_config::applier::{ApplyReport, Phase};
use patronus_config::{Applier, ConfigStore};
use serde_json::{json, Value};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use tower::ServiceExt;

struct Fake {
    fail: AtomicBool,
    applies: AtomicUsize,
}

#[async_trait]
impl Applier for Fake {
    fn name(&self) -> &'static str {
        "ids"
    }
    fn phase(&self) -> Phase {
        Phase::Services
    }
    async fn apply(&self, _s: &ConfigStore) -> patronus_core::Result<ApplyReport> {
        self.applies.fetch_add(1, Ordering::SeqCst);
        if self.fail.load(Ordering::SeqCst) {
            return Err(patronus_core::Error::Network("ids refused it".into()));
        }
        let mut r = ApplyReport::default();
        r.applied("ok");
        Ok(r)
    }
    async fn render(&self, _s: &ConfigStore) -> patronus_core::Result<String> {
        Ok(String::new())
    }
    async fn status(&self, _s: &ConfigStore) -> patronus_core::Result<Value> {
        Ok(json!({"enabled": true}))
    }
}

const ADMIN_PW: &str = "Ids-Page-Admin-Passw0rd";

struct T {
    app: axum::Router,
    state: crate::AppState,
    fake: Arc<Fake>,
}

async fn setup() -> T {
    let dir = std::env::temp_dir().join(format!("patronus-web-ids-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("pw"), format!("{ADMIN_PW}\n")).unwrap();
    let store = Arc::new(ConfigStore::open(dir.join("config.db")).await.unwrap());
    let mut state = crate::AppState::new(store, Arc::new(crate::state::firewall::NoopApplier))
        .await
        .unwrap();
    state
        .auth
        .user_store
        .provision_admin(None, &dir.join("pw"))
        .await
        .unwrap();
    let fake = Arc::new(Fake {
        fail: AtomicBool::new(false),
        applies: AtomicUsize::new(0),
    });
    state.lan = Arc::new(crate::state::LanManager::with_appliers(
        state.config_store.clone(),
        vec![fake.clone()],
    ));
    let app = super::build_router(state.clone(), Arc::new(crate::WsBroadcaster::new()));
    T { app, state, fake }
}

impl T {
    async fn raw(
        &self,
        m: Method,
        uri: &str,
        cookie: Option<&str>,
        body: Option<String>,
    ) -> (StatusCode, String, axum::http::HeaderMap) {
        let mut b = Request::builder().method(m).uri(uri);
        if let Some(c) = cookie {
            b = b.header(header::COOKIE, c);
        }
        if body.is_some() {
            b = b.header(header::CONTENT_TYPE, "application/json");
        }
        let r = self
            .app
            .clone()
            .oneshot(
                b.body(body.map(Body::from).unwrap_or_else(Body::empty))
                    .unwrap(),
            )
            .await
            .unwrap();
        let (s, h) = (r.status(), r.headers().clone());
        let bytes = axum::body::to_bytes(r.into_body(), 16 << 20).await.unwrap();
        (s, String::from_utf8_lossy(&bytes).into_owned(), h)
    }

    async fn admin(&self) -> String {
        let (s, b, h) = self
            .raw(
                Method::POST,
                "/api/auth/login",
                None,
                Some(json!({"username": "admin", "password": ADMIN_PW}).to_string()),
            )
            .await;
        assert_eq!(s, StatusCode::OK, "{b}");
        h.get(header::SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_string()
    }

    async fn call(
        &self,
        cookie: &str,
        m: Method,
        uri: &str,
        body: Option<Value>,
    ) -> (StatusCode, Value) {
        let (s, b, _) = self
            .raw(m, uri, Some(cookie), body.map(|v| v.to_string()))
            .await;
        (s, serde_json::from_str(&b).unwrap_or(Value::String(b)))
    }
}

async fn alert(t: &T, ts: i64, sid: i64, src: &str, dst: &str, action: &str) -> i64 {
    sqlx::query(
        "INSERT INTO ids_alerts (ts, src_ip, src_port, dst_ip, dst_port, proto, sid, rev, signature, category, severity, action, iface) \
         VALUES (?,?,1234,?,80,'TCP',?,1,?,'Trojan',1,?,'eth0')",
    )
    .bind(ts)
    .bind(src)
    .bind(dst)
    .bind(sid)
    .bind(format!("ET TEST rule {sid}"))
    .bind(action)
    .execute(t.state.config_store.pool().unwrap())
    .await
    .unwrap()
    .last_insert_rowid()
}

#[tokio::test]
async fn alert_browser_filters_ranks_and_validates() {
    let t = setup().await;
    let c = t.admin().await;
    let now = chrono::Utc::now().timestamp();
    alert(&t, now - 300, 100, "10.0.0.5", "198.51.100.7", "allowed").await;
    alert(&t, now - 200, 100, "10.0.0.6", "198.51.100.7", "blocked").await;
    alert(&t, now - 100, 200, "10.1.0.9", "203.0.113.1", "allowed").await;
    alert(
        &t,
        now - 40 * 86_400,
        300,
        "10.0.0.5",
        "198.51.100.9",
        "allowed",
    )
    .await;

    let (s, b) = t
        .call(&c, Method::GET, "/api/svc/ids/alerts?window=24h", None)
        .await;
    assert_eq!(s, StatusCode::OK, "{b}");
    assert_eq!(b["total"], 3, "{b}");
    assert!(b["alerts"][0]["time"].as_i64() >= b["alerts"][1]["time"].as_i64());
    for (q, n) in [
        ("window=24h&sid=100", 2),
        ("window=24h&src=10.0.0.0/24", 2),
        ("window=24h&dst=203.0.113.1", 1),
        ("window=24h&action=blocked", 1),
        ("window=24h&q=rule%20200", 1),
        ("", 4),
        ("from=2000-01-01T00:00&to=2999-01-01T00:00", 4),
    ] {
        let (s, b) = t
            .call(&c, Method::GET, &format!("/api/svc/ids/alerts?{q}"), None)
            .await;
        assert_eq!(s, StatusCode::OK, "{q}: {b}");
        assert_eq!(b["total"], n, "{q}: {b}");
    }
    let (s, b) = t
        .call(
            &c,
            Method::GET,
            "/api/svc/ids/alerts?limit=1&offset=1",
            None,
        )
        .await;
    assert_eq!(
        (s, b["alerts"].as_array().unwrap().len(), b["total"].clone()),
        (StatusCode::OK, 1, json!(4))
    );
    for bad in [
        "src=not-an-address",
        "action=maybe",
        "sid=abc",
        "window=3x",
        "from=yesterday",
        "limit=many",
    ] {
        let (s, b) = t
            .call(&c, Method::GET, &format!("/api/svc/ids/alerts?{bad}"), None)
            .await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{bad}: {b}");
    }
    let (s, b) = t
        .call(
            &c,
            Method::GET,
            "/api/svc/ids/alerts/top?by=sid&window=24h",
            None,
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{b}");
    assert_eq!(
        (
            b["top"][0]["key"].clone(),
            b["top"][0]["count"].clone(),
            b["top"][0]["blocked"].clone()
        ),
        (json!("100"), json!(2), json!(1))
    );
    let (s, b) = t
        .call(
            &c,
            Method::GET,
            "/api/svc/ids/alerts/top?by=src&window=24h&limit=2",
            None,
        )
        .await;
    assert_eq!((s, b["top"].as_array().unwrap().len()), (StatusCode::OK, 2));
    let (s, _) = t
        .call(&c, Method::GET, "/api/svc/ids/alerts/top?by=nothing", None)
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let (s, b) = t.call(&c, Method::GET, "/api/svc/ids/summary", None).await;
    assert_eq!(
        (s, b["alerts_24h"].clone(), b["blocked_24h"].clone()),
        (StatusCode::OK, json!(3), json!(1))
    );
    // not for anonymous callers
    let (s, _, _) = t.raw(Method::GET, "/api/svc/ids/alerts", None, None).await;
    assert!(
        s == StatusCode::UNAUTHORIZED || s == StatusCode::SEE_OTHER || s == StatusCode::FORBIDDEN,
        "{s}"
    );
}

#[tokio::test]
async fn one_click_suppress_is_validated_applied_and_undone_on_failure() {
    let t = setup().await;
    let c = t.admin().await;
    let now = chrono::Utc::now().timestamp();
    let id = alert(&t, now - 10, 2900001, "10.0.0.5", "198.51.100.7", "allowed").await;
    let nosid = alert(&t, now - 10, 0, "10.0.0.5", "198.51.100.7", "allowed").await;
    let rows = |t: &T| {
        let p = t.state.config_store.pool().unwrap().clone();
        async move {
            sqlx::query_as::<_, (i64, String, Option<String>, Option<String>, Option<i64>)>(
                "SELECT sid, kind, track, ip, seconds FROM ids_suppress ORDER BY id",
            )
            .fetch_all(&p)
            .await
            .unwrap()
        }
    };
    let (s, b) = t
        .call(
            &c,
            Method::POST,
            "/api/svc/ids/alerts/999/suppress",
            Some(json!({"scope": "rule"})),
        )
        .await;
    assert_eq!(s, StatusCode::NOT_FOUND, "{b}");
    let (s, b) = t
        .call(
            &c,
            Method::POST,
            &format!("/api/svc/ids/alerts/{nosid}/suppress"),
            Some(json!({})),
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{b}");
    let (s, b) = t
        .call(
            &c,
            Method::POST,
            &format!("/api/svc/ids/alerts/{id}/suppress"),
            Some(json!({"scope": "galaxy"})),
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{b}");
    assert!(rows(&t).await.is_empty());

    let before = t.fake.applies.load(Ordering::SeqCst);
    let (s, b) = t
        .call(
            &c,
            Method::POST,
            &format!("/api/svc/ids/alerts/{id}/suppress"),
            Some(json!({"scope": "rule"})),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED, "{b}");
    assert_eq!(
        t.fake.applies.load(Ordering::SeqCst),
        before + 1,
        "the IDS was re-applied"
    );
    assert_eq!(
        rows(&t).await,
        vec![(2900001, "suppress".into(), Some("none".into()), None, None)]
    );
    let (s, b) = t
        .call(
            &c,
            Method::POST,
            &format!("/api/svc/ids/alerts/{id}/suppress"),
            Some(json!({"scope": "source"})),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED, "{b}");
    let (s, b) = t
        .call(
            &c,
            Method::POST,
            &format!("/api/svc/ids/alerts/{id}/suppress"),
            Some(json!({"scope": "destination", "kind": "limit", "seconds": 120})),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED, "{b}");
    let r = rows(&t).await;
    assert_eq!(
        r[1],
        (
            2900001,
            "suppress".into(),
            Some("by_src".into()),
            Some("10.0.0.5".into()),
            None
        )
    );
    assert_eq!(
        r[2],
        (
            2900001,
            "limit".into(),
            Some("by_dst".into()),
            None,
            Some(120)
        )
    );

    // the page lists the entries
    let (s, b) = t.call(&c, Method::GET, "/api/svc/ids", None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(
        b["collections"]["suppress"].as_array().unwrap().len(),
        3,
        "{b}"
    );

    // a refused apply undoes the entry
    t.fake.fail.store(true, Ordering::SeqCst);
    let (s, b) = t
        .call(
            &c,
            Method::POST,
            &format!("/api/svc/ids/alerts/{id}/suppress"),
            Some(json!({"scope": "rule", "kind": "threshold", "count": 3, "seconds": 60})),
        )
        .await;
    assert_eq!(s, StatusCode::INTERNAL_SERVER_ERROR, "{b}");
    assert!(
        b["error"].as_str().unwrap().contains("ids refused it"),
        "{b}"
    );
    assert_eq!(rows(&t).await.len(), 3, "the refused entry was taken back");
    t.fake.fail.store(false, Ordering::SeqCst);
}

#[tokio::test]
async fn page_validation_update_request_and_exports() {
    let t = setup().await;
    let c = t.admin().await;
    for (what, uri, body) in [
        (
            "ftp URL",
            "/api/svc/ids/sources",
            json!({"key": "a", "name": "A", "url": "ftp://x.example/a"}),
        ),
        (
            "path in the key",
            "/api/svc/ids/sources",
            json!({"key": "../a", "name": "A", "url": "https://x.example/a.tar.gz"}),
        ),
        (
            "scope",
            "/api/svc/ids/policies",
            json!({"scope": "galaxy", "target": "x", "action": "drop"}),
        ),
        (
            "policy action",
            "/api/svc/ids/policies",
            json!({"scope": "ruleset", "target": "x", "action": "boom"}),
        ),
        (
            "sid",
            "/api/svc/ids/overrides",
            json!({"sid": 0, "action": "disable"}),
        ),
        (
            "limit without tracking",
            "/api/svc/ids/suppress",
            json!({"sid": 5, "kind": "limit", "track": "none", "count": 1, "seconds": 5}),
        ),
        (
            "address without tracking",
            "/api/svc/ids/suppress",
            json!({"sid": 5, "kind": "suppress", "ip": "10.0.0.1"}),
        ),
        (
            "limit with an address",
            "/api/svc/ids/suppress",
            json!({"sid": 5, "kind": "limit", "track": "by_src", "ip": "10.0.0.1", "count": 1, "seconds": 5}),
        ),
    ] {
        let (s, b) = t.call(&c, Method::POST, uri, Some(body)).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{what}: {b}");
    }
    let (s, b) = t
        .call(
            &c,
            Method::PUT,
            "/api/svc/ids",
            Some(json!({"update_hour": 24})),
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{b}");

    // seeded sources: listed with URL and licence, all off
    let (s, b) = t.call(&c, Method::GET, "/api/svc/ids", None).await;
    assert_eq!(s, StatusCode::OK);
    let srcs = b["collections"]["sources"].as_array().unwrap();
    assert!(
        srcs.iter()
            .any(|r| r["key"] == "et-open"
                && r["url"].as_str().unwrap().contains("{suricata_version}")),
        "{b}"
    );
    assert!(srcs
        .iter()
        .all(|r| r["enabled"] == false && !r["licence"].as_str().unwrap().is_empty()));
    assert_eq!(b["settings"]["update_hour"], 3);
    assert_eq!(b["settings"]["alert_retention_days"], 30);

    // a source, a duplicate, a policy and its duplicate
    let (s, b) = t.call(&c, Method::POST, "/api/svc/ids/sources", Some(json!({"key": "mine", "name": "Mine", "url": "https://mirror.example/x.rules", "format": "rules", "enabled": true}))).await;
    assert_eq!(s, StatusCode::CREATED, "{b}");
    let (s, _) = t
        .call(
            &c,
            Method::POST,
            "/api/svc/ids/sources",
            Some(json!({"key": "mine", "name": "Again", "url": "https://mirror.example/y.rules"})),
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let (s, b) = t
        .call(
            &c,
            Method::POST,
            "/api/svc/ids/policies",
            Some(json!({"scope": "ruleset", "target": "mine", "action": "drop"})),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED, "{b}");
    let (s, _) = t
        .call(
            &c,
            Method::POST,
            "/api/svc/ids/policies",
            Some(json!({"scope": "ruleset", "target": "mine", "action": "alert"})),
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "one policy per rule set");
    let (s, b) = t
        .call(
            &c,
            Method::POST,
            "/api/svc/ids/overrides",
            Some(json!({"sid": 77, "action": "disable"})),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED, "{b}");
    let (s, _) = t
        .call(
            &c,
            Method::POST,
            "/api/svc/ids/overrides",
            Some(json!({"sid": 77, "action": "drop"})),
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "one override per SID");

    // "Update now" is a request that the (root) applier acts on
    let before = t.fake.applies.load(Ordering::SeqCst);
    let (s, b) = t
        .call(
            &c,
            Method::POST,
            "/api/svc/ids/action/update",
            Some(json!({})),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{b}");
    assert_eq!(t.fake.applies.load(Ordering::SeqCst), before + 1);
    let (asked, done) = patronus_network::ids_sets::update_request(&t.state.config_store).await;
    assert!(asked > 0 && done == 0, "{asked} {done}");

    // the configuration (export) carries the sources and policy but never the measured data
    alert(
        &t,
        chrono::Utc::now().timestamp(),
        1,
        "10.0.0.1",
        "10.0.0.2",
        "allowed",
    )
    .await;
    let ex = t.state.config_store.export_json().await.unwrap();
    let ex = ex.to_string();
    for must in [
        "ids_sources",
        "ids_policies",
        "ids_overrides",
        "ids_suppress",
    ] {
        assert!(ex.contains(must), "the export lacks {must}");
    }
    for never in [
        "ids_alerts",
        "ids_alert_pos",
        "ids_source_state",
        "ids_update_request",
    ] {
        assert!(
            !ex.contains(&format!("\"{never}\"")),
            "the export carries {never}"
        );
    }

    // the pages
    let (s, body, _) = t.raw(Method::GET, "/svc/ids/alerts", Some(&c), None).await;
    assert_eq!(s, StatusCode::OK);
    assert!(body.contains("id=\"ids-filter\"") && body.contains("Intrusion alerts"));
    let (s, body, _) = t.raw(Method::GET, "/svc/ids", Some(&c), None).await;
    assert_eq!(s, StatusCode::OK);
    assert!(body.contains("id=\"ids-alerts-link\"") && body.contains("svc-settings-form"));
}
