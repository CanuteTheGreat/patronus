//! Router-level tests for the S.M.A.R.T. page and API (USE=smart): the poller is not involved, disks are
//! stored the way the poller stores them, so the status, drill-down, self-test request, validation and
//! read-only protection can be checked anywhere.

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
        "smart"
    }
    fn phase(&self) -> Phase {
        Phase::Services
    }
    async fn apply(&self, _s: &ConfigStore) -> patronus_core::Result<ApplyReport> {
        self.applies.fetch_add(1, Ordering::SeqCst);
        if self.fail.load(Ordering::SeqCst) {
            return Err(patronus_core::Error::Network("guest refused it".into()));
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

const ADMIN_PW: &str = "Smart-Page-Admin-Passw0rd";

struct T {
    app: axum::Router,
    state: crate::AppState,
}

async fn setup() -> T {
    let dir = std::env::temp_dir().join(format!("patronus-web-smart-{}", uuid::Uuid::new_v4()));
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
    T { app, state }
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

use patronus_network::smart;

const ATA_OK: &str =
    include_str!("../../../patronus-network/tests/fixtures/smart/ata_healthy.json");
const ATA_FAILING: &str =
    include_str!("../../../patronus-network/tests/fixtures/smart/ata_failing.json");
const VIRTIO: &str =
    include_str!("../../../patronus-network/tests/fixtures/smart/virtio_nosmart.json");

fn named(report: &str, name: &str) -> String {
    let mut v: Value = serde_json::from_str(report).unwrap();
    v["device"]["name"] = json!(name);
    v.to_string()
}

async fn store_disk(t: &T, report: &str, name: &str) {
    let d = smart::parse_disk(&named(report, name)).unwrap();
    let th = smart::Thresholds {
        temp_warn: 50,
        temp_crit: 60,
        temp_hysteresis: 3,
        realloc_warn: 1,
        nvme_used_warn: 90,
    };
    smart::record(&t.state.config_store, &d, &th, 1_700_000_000)
        .await
        .unwrap();
}

#[tokio::test]
async fn the_page_says_why_it_is_empty() {
    let t = setup().await;
    let c = t.admin().await;
    // off, nothing polled
    let (s, b) = t.call(&c, Method::GET, "/api/v1/smart", None).await;
    assert_eq!(s, StatusCode::OK, "{b}");
    assert_eq!(b["enabled"], false);
    assert_eq!(b["empty"]["code"], "disabled");
    assert!(b["devices"].as_array().unwrap().is_empty());
    // the same answer under the short prefix
    let (s, b2) = t.call(&c, Method::GET, "/api/smart", None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(b2["empty"]["code"], "disabled");
    // a disk without S.M.A.R.T. only: the empty state names the cause (VM disk, SD card, eMMC)
    let (s, _) = t
        .call(
            &c,
            Method::PUT,
            "/api/svc/smart",
            Some(json!({"enabled": true})),
        )
        .await;
    assert_eq!(s, StatusCode::OK);
    store_disk(&t, VIRTIO, "/dev/vda").await;
    let (_, b) = t.call(&c, Method::GET, "/api/v1/smart", None).await;
    assert_eq!(b["summary"]["unsupported"], 1);
    assert_eq!(b["devices"][0]["smart_available"], false);
    assert!(b["devices"][0]["health"].is_null());
    assert!(
        b["empty"]["code"] == "no-smart-disk" || b["empty"]["code"] == "no-smartctl",
        "{}",
        b["empty"]
    );
}

#[tokio::test]
async fn status_and_drill_down_report_the_disks() {
    let t = setup().await;
    let c = t.admin().await;
    t.call(
        &c,
        Method::PUT,
        "/api/svc/smart",
        Some(json!({"enabled": true})),
    )
    .await;
    store_disk(&t, ATA_OK, "/dev/sda").await;
    store_disk(&t, ATA_FAILING, "/dev/sdb").await;
    let (s, b) = t.call(&c, Method::GET, "/api/v1/smart", None).await;
    assert_eq!(s, StatusCode::OK, "{b}");
    assert_eq!(b["summary"]["disks"], 2);
    assert_eq!(b["summary"]["ok"], 1);
    assert_eq!(b["summary"]["critical"], 1);
    let sda = &b["devices"][0];
    assert_eq!(sda["name"], "sda");
    assert_eq!(sda["health"], "PASSED");
    assert!(sda["temperature_c"].is_number());
    assert!(sda["power_on_hours"].is_number());
    let sdb = &b["devices"][1];
    assert_eq!(sdb["health"], "FAILED");
    assert_eq!(sdb["level"], "critical");
    assert!(sdb["reallocated_sectors"].as_u64().unwrap() > 0);
    assert!(sdb["reasons"]
        .as_array()
        .unwrap()
        .iter()
        .any(|r| r.as_str().unwrap().contains("FAILED")));
    assert_eq!(sdb["last_self_test"]["passed"], false);

    let (s, d) = t.call(&c, Method::GET, "/api/v1/smart/sdb", None).await;
    assert_eq!(s, StatusCode::OK, "{d}");
    assert!(!d["attributes"].as_array().unwrap().is_empty());
    assert_eq!(d["self_test_log"][0]["passed"], false);
    assert_eq!(d["history"].as_array().unwrap().len(), 1);
    assert_eq!(d["history"][0]["health"], false);
    let (s, d) = t.call(&c, Method::GET, "/api/v1/smart/nope", None).await;
    assert_eq!(s, StatusCode::NOT_FOUND, "{d}");
    // a name that is not a device name never reaches the store
    let (s, _) = t.call(&c, Method::GET, "/api/v1/smart/a%20b", None).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn a_self_test_is_queued_validated_and_refused_for_viewers() {
    let t = setup().await;
    let c = t.admin().await;
    t.call(
        &c,
        Method::PUT,
        "/api/svc/smart",
        Some(json!({"enabled": true})),
    )
    .await;
    store_disk(&t, ATA_OK, "/dev/sda").await;
    store_disk(&t, VIRTIO, "/dev/vda").await;

    let (s, b) = t
        .call(
            &c,
            Method::POST,
            "/api/v1/smart/sda/test",
            Some(json!({"type": "short"})),
        )
        .await;
    assert_eq!(s, StatusCode::ACCEPTED, "{b}");
    assert_eq!(b["queued"], 1);
    let (_, b) = t.call(&c, Method::GET, "/api/v1/smart", None).await;
    assert_eq!(b["devices"][0]["test_requested"], "short");
    // every disk that can: the one without S.M.A.R.T. is not queued
    let (s, b) = t
        .call(
            &c,
            Method::POST,
            "/api/v1/smart/test",
            Some(json!({"type": "long"})),
        )
        .await;
    assert_eq!(s, StatusCode::ACCEPTED, "{b}");
    assert_eq!(b["queued"], 1);
    // refusals
    let (s, _) = t
        .call(
            &c,
            Method::POST,
            "/api/v1/smart/sda/test",
            Some(json!({"type": "format"})),
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let (s, _) = t
        .call(&c, Method::POST, "/api/v1/smart/sda/test", Some(json!({})))
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let (s, _) = t
        .call(
            &c,
            Method::POST,
            "/api/v1/smart/vda/test",
            Some(json!({"type": "short"})),
        )
        .await;
    assert_eq!(
        s,
        StatusCode::BAD_REQUEST,
        "a disk without S.M.A.R.T. cannot be tested"
    );
    let (s, _) = t
        .call(
            &c,
            Method::POST,
            "/api/v1/smart/sdz/test",
            Some(json!({"type": "short"})),
        )
        .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    // the page action of the feature page goes through the same request path
    let (s, b) = t
        .call(
            &c,
            Method::POST,
            "/api/svc/smart/action/test-short",
            Some(json!({"device": "sda"})),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{b}");
    assert_eq!(b["queued"], 1);

    // a read-only account sees the disks but cannot start a test
    t.state
        .auth
        .user_store
        .create_user(
            "viewer".into(),
            "Viewer-Passw0rd-1",
            crate::auth::UserRole::ReadOnly,
        )
        .await
        .unwrap();
    let (s, b, h) = t
        .raw(
            Method::POST,
            "/api/auth/login",
            None,
            Some(json!({"username": "viewer", "password": "Viewer-Passw0rd-1"}).to_string()),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{b}");
    let vc = h
        .get(header::SET_COOKIE)
        .unwrap()
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string();
    let (s, _) = t.call(&vc, Method::GET, "/api/v1/smart", None).await;
    assert_eq!(s, StatusCode::OK);
    let (s, _) = t
        .call(
            &vc,
            Method::POST,
            "/api/v1/smart/sda/test",
            Some(json!({"type": "short"})),
        )
        .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn the_page_renders_and_is_in_the_navigation() {
    let t = setup().await;
    let c = t.admin().await;
    let (s, body, _) = t.raw(Method::GET, "/smart", Some(&c), None).await;
    assert_eq!(s, StatusCode::OK);
    assert!(body.contains("Disk health"));
    assert!(body.contains("href=\"/smart\""), "nav entry");
    assert!(body.contains("/svc/smart"), "link to the settings");
    // the settings page of the feature is the generic one
    let (s, b) = t.call(&c, Method::GET, "/api/svc/smart", None).await;
    assert_eq!(s, StatusCode::OK, "{b}");
    let keys: Vec<&str> = b["schema"]["fields"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["key"].as_str().unwrap())
        .collect();
    for k in [
        "enabled",
        "poll_minutes",
        "short_test_hours",
        "long_test_days",
        "temp_warn",
        "temp_crit",
        "notify",
        "retention_days",
    ] {
        assert!(keys.contains(&k), "{k} in {keys:?}");
    }
    // bad settings are refused, nothing hard-coded to fall back on
    let (s, _) = t
        .call(
            &c,
            Method::PUT,
            "/api/svc/smart",
            Some(json!({"poll_minutes": 0})),
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
}
