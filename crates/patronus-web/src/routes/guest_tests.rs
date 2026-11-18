//! Router-level tests for the guest network page and API (USE=guest). The kernel
//! side is proven by ci/netlab/lane-t-guest.sh (+ lane-t-guest-wifi.sh); here
//! the applier is a recorder so the API, validation, secrets handling, the
//! audit log and undo-on-failure can be checked anywhere.

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
        "guest"
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

const ADMIN_PW: &str = "Guest-Page-Admin-Passw0rd";

struct T {
    app: axum::Router,
    state: crate::AppState,
    fake: Arc<Fake>,
}

async fn setup() -> T {
    let dir = std::env::temp_dir().join(format!("patronus-web-guest-{}", uuid::Uuid::new_v4()));
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

#[tokio::test]
async fn guest_page_and_api_validate_apply_undo_and_keep_secrets() {
    let t = setup().await;
    let c = t.admin().await;

    // listed, with a schema that has every setting, the vouchers and the buttons
    let (s, b) = t.call(&c, Method::GET, "/api/svc", None).await;
    assert_eq!(s, StatusCode::OK);
    assert!(
        b.as_array().unwrap().iter().any(|f| f["slug"] == "guest"),
        "{b}"
    );
    let (s, b) = t.call(&c, Method::GET, "/api/svc/guest", None).await;
    assert_eq!(s, StatusCode::OK, "{b}");
    let keys: Vec<&str> = b["schema"]["fields"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["key"].as_str().unwrap())
        .collect();
    for k in [
        "enabled",
        "vlan_id",
        "address",
        "dhcp_start",
        "dhcp_end",
        "lease_minutes",
        "dns_servers",
        "internet_interface",
        "block_private",
        "isolate_clients",
        "router_ports",
        "egress_ports",
        "down_kbit",
        "up_kbit",
        "client_down_kbit",
        "client_up_kbit",
        "access",
        "schedule_from",
        "schedule_to",
        "schedule_days",
        "ssid",
        "wifi_psk",
    ] {
        assert!(keys.contains(&k), "the page has no {k} setting: {keys:?}");
    }
    assert_eq!(b["schema"]["collections"][0]["key"], "vouchers");
    let actions: Vec<&str> = b["schema"]["actions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| a["name"].as_str().unwrap())
        .collect();
    assert_eq!(
        actions,
        ["new_password", "voucher", "open", "close", "share"]
    );
    assert_eq!(b["settings"]["enabled"], false, "off by default");
    assert_eq!(
        b["settings"]["address"], "192.168.30.1/24",
        "defaults are shown"
    );

    // bad input: 400, nothing applied, nothing stored
    for body in [
        json!({"address": "192.168.30.1/31"}),
        json!({"dhcp_start": "10.1.1.1"}),
        json!({"router_ports": "tcp/70000"}),
        json!({"access": "schedule", "schedule_from": "08:00", "schedule_to": "08:00"}),
        json!({"wifi": true, "wifi_psk": "short"}),
        json!({"surprise": 1}),
    ] {
        let (s, b) = t
            .call(&c, Method::PUT, "/api/svc/guest", Some(body.clone()))
            .await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{body} -> {b}");
    }
    assert_eq!(t.fake.applies.load(Ordering::SeqCst), 0);

    // a valid change is stored, applied once and audited (no secret in the audit entry)
    let (s, b) = t
        .call(
            &c,
            Method::PUT,
            "/api/svc/guest",
            Some(json!({"vlan_id": 40, "address": "10.40.0.1/24", "client_down_kbit": 5000, "wifi": true, "wifi_psk": "hunter2-hunter2"})),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{b}");
    assert_eq!(t.fake.applies.load(Ordering::SeqCst), 1);
    let (_, b) = t.call(&c, Method::GET, "/api/svc/guest", None).await;
    assert_eq!(b["settings"]["vlan_id"], 40);
    assert_eq!(
        b["settings"]["wifi_psk"], "********",
        "the password is never returned"
    );
    assert!(!b.to_string().contains("hunter2-hunter2"));
    let audit: Vec<String> = sqlx::query_scalar(
        "SELECT COALESCE(details, '') FROM audit_log WHERE action = 'guest_settings'",
    )
    .fetch_all(t.state.config_store.pool().unwrap())
    .await
    .unwrap();
    assert!(
        !audit.is_empty() && audit.iter().all(|d| !d.contains("hunter2")),
        "{audit:?}"
    );

    // a refused apply is undone, for a setting and for a button
    t.fake.fail.store(true, Ordering::SeqCst);
    let (s, _) = t
        .call(
            &c,
            Method::PUT,
            "/api/svc/guest",
            Some(json!({"vlan_id": 50})),
        )
        .await;
    assert_eq!(s, StatusCode::INTERNAL_SERVER_ERROR);
    let (s, _) = t
        .call(
            &c,
            Method::POST,
            "/api/svc/guest/action/open",
            Some(json!({"minutes": 30})),
        )
        .await;
    assert_ne!(s, StatusCode::OK);
    t.fake.fail.store(false, Ordering::SeqCst);
    let (_, b) = t.call(&c, Method::GET, "/api/svc/guest", None).await;
    assert_eq!(
        b["settings"]["vlan_id"], 40,
        "a refused change was not undone: {b}"
    );
    assert_eq!(
        b["settings"]["open_until"], 0,
        "a refused button was not undone: {b}"
    );

    // buttons apply and answer; vouchers never list their code
    let before = t.fake.applies.load(Ordering::SeqCst);
    let (s, b) = t
        .call(
            &c,
            Method::POST,
            "/api/svc/guest/action/open",
            Some(json!({"minutes": 30})),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{b}");
    assert_eq!(
        t.fake.applies.load(Ordering::SeqCst),
        before + 1,
        "the Open button applies at once"
    );
    let (s, b) = t
        .call(
            &c,
            Method::POST,
            "/api/svc/guest/action/voucher",
            Some(json!({"name": "friday", "minutes": 30})),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{b}");
    let code = b["wifi_password"].as_str().unwrap().to_string();
    let (_, g) = t.call(&c, Method::GET, "/api/svc/guest", None).await;
    assert!(!g.to_string().contains(&code), "a voucher code is listed");
    assert_eq!(g["collections"]["vouchers"][0]["code"], "********");
    let (s, _) = t
        .call(&c, Method::POST, "/api/svc/guest/action/nope", None)
        .await;
    assert_ne!(s, StatusCode::OK);
    // the share card: password + the join-this-network text + a QR code, audited; it does not apply anything
    let applies = t.fake.applies.load(Ordering::SeqCst);
    let (s, b) = t
        .call(&c, Method::POST, "/api/svc/guest/action/share", None)
        .await;
    assert_eq!(s, StatusCode::OK, "{b}");
    assert_eq!(b["wifi_password"], "hunter2-hunter2");
    assert_eq!(b["uri"], "WIFI:T:WPA;S:Guest;P:hunter2-hunter2;;");
    assert!(b["qr_svg"].as_str().unwrap_or("").contains("<svg"), "{b}");
    assert_eq!(t.fake.applies.load(Ordering::SeqCst), applies);
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM audit_log WHERE action = 'guest_share'")
        .fetch_one(t.state.config_store.pool().unwrap())
        .await
        .unwrap();
    assert_eq!(n, 1, "revealing the password is audited");

    // the page itself renders, with its form and the Wi-Fi/voucher parts
    let (s, body, _) = t.raw(Method::GET, "/svc/guest", Some(&c), None).await;
    assert_eq!(s, StatusCode::OK);
    assert!(
        body.contains("Guest network")
            && body.contains("svc-settings-form")
            && body.contains("svc-collections"),
        "page body"
    );
    assert!(body.contains("svc-actions"), "the buttons are on the page");
}

#[tokio::test]
async fn the_navigation_marks_the_guest_page_unavailable_instead_of_hiding_it() {
    // the sidebar script keeps the entry and labels it when the build lacks the feature
    let t = setup().await;
    let c = t.admin().await;
    let (s, body, _) = t.raw(Method::GET, "/svc/guest", Some(&c), None).await;
    assert_eq!(s, StatusCode::OK);
    assert!(
        body.contains("href=\"/svc/guest\""),
        "the menu has a Guest network entry"
    );
    assert!(
        body.contains("nav-unavailable") && body.contains("(unavailable)"),
        "an unbuilt feature is labelled, not hidden"
    );
}
