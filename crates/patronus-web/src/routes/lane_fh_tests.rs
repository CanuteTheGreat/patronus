//! Router-level tests for lane F (VPN configuration) and lane H (web
//! accounts, two-factor login, backup restore). The kernel/daemon side is
//! proven by the netlab scenarios (ci/netlab/lane-h-system.sh,
//! ci/netlab/vpn-test.sh); here the appliers are recorders so the API,
//! the store and the undo-on-failure behaviour can be checked anywhere.

use async_trait::async_trait;
use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use patronus_config::applier::{ApplyReport, Phase};
use patronus_config::{Applier, ConfigStore};
use serde_json::{json, Value};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use tower::ServiceExt;

/// Counts applies; fails while `fail` is set.
struct Fake {
    name: &'static str,
    phase: Phase,
    fail: AtomicBool,
    applies: AtomicUsize,
}

impl Fake {
    fn new(name: &'static str, phase: Phase) -> Arc<Self> {
        Arc::new(Self {
            name,
            phase,
            fail: AtomicBool::new(false),
            applies: AtomicUsize::new(0),
        })
    }
}

#[async_trait]
impl Applier for Fake {
    fn name(&self) -> &'static str {
        self.name
    }
    fn phase(&self) -> Phase {
        self.phase
    }
    async fn apply(&self, _s: &ConfigStore) -> patronus_core::Result<ApplyReport> {
        self.applies.fetch_add(1, Ordering::SeqCst);
        if self.fail.load(Ordering::SeqCst) {
            return Err(patronus_core::Error::Network(format!(
                "{} refused it",
                self.name
            )));
        }
        let mut r = ApplyReport::default();
        r.applied("ok");
        Ok(r)
    }
    async fn render(&self, _s: &ConfigStore) -> patronus_core::Result<String> {
        Ok(String::new())
    }
    async fn status(&self, _s: &ConfigStore) -> patronus_core::Result<Value> {
        Ok(json!({"installed": true, "running": true, "sas": ""}))
    }
}

const ADMIN_PW: &str = "Lane-H-Admin-Passw0rd";

struct T {
    app: axum::Router,
    state: crate::AppState,
    dir: std::path::PathBuf,
    #[cfg_attr(not(feature = "wireguard"), allow(dead_code))]
    wg: Arc<Fake>,
    restore_fake: Arc<Fake>,
}

async fn state_at(dir: &std::path::Path) -> crate::AppState {
    let store = Arc::new(ConfigStore::open(dir.join("config.db")).await.unwrap());
    let state = crate::AppState::new(store, Arc::new(crate::state::firewall::NoopApplier))
        .await
        .unwrap();
    state
        .auth
        .user_store
        .provision_admin(None, &dir.join("pw"))
        .await
        .unwrap();
    state
}

async fn setup() -> T {
    let dir = std::env::temp_dir().join(format!("patronus-web-fh-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("pw"), format!("{ADMIN_PW}\n")).unwrap();
    let mut state = state_at(&dir).await;
    let wg = Fake::new("wireguard", Phase::Interfaces);
    let ipsec = Fake::new("ipsec", Phase::Services);
    state.tunnels = Arc::new(crate::state::TunnelsManager::with_appliers(
        state.config_store.clone(),
        Some(wg.clone()),
        Some(ipsec.clone()),
        Arc::new(crate::state::firewall::NoopApplier),
    ));
    let restore_fake = Fake::new("firewall", Phase::Firewall);
    state.system = Arc::new(
        crate::state::SystemManager::new(dir.join("backups"))
            .with_appliers(vec![restore_fake.clone(), wg.clone()]),
    );
    let app = super::build_router(state.clone(), Arc::new(crate::WsBroadcaster::new()));
    T {
        app,
        state,
        dir,
        wg,
        restore_fake,
    }
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

    async fn login(
        &self,
        user: &str,
        pw: &str,
        code: Option<&str>,
    ) -> (StatusCode, Option<String>, Value) {
        let mut body = json!({"username": user, "password": pw});
        if let Some(c) = code {
            body["totp_code"] = json!(c);
        }
        let (s, b, h) = self
            .raw(
                Method::POST,
                "/api/auth/login",
                None,
                Some(body.to_string()),
            )
            .await;
        let cookie = h
            .get(header::SET_COOKIE)
            .map(|c| c.to_str().unwrap().split(';').next().unwrap().to_string());
        (s, cookie, serde_json::from_str(&b).unwrap_or(Value::Null))
    }

    async fn admin(&self) -> String {
        let (s, c, b) = self.login("admin", ADMIN_PW, None).await;
        assert_eq!(s, StatusCode::OK, "{b}");
        c.unwrap()
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

#[cfg(all(feature = "wireguard", feature = "ipsec"))]
#[tokio::test]
async fn wireguard_and_ipsec_are_managed_through_the_api() {
    let t = setup().await;
    let c = t.admin().await;
    let (s, b) = t
        .call(
            &c,
            Method::POST,
            "/api/vpn/wireguard/tunnels",
            Some(json!({"addresses": "10.99.0.1/24", "endpoint": "vpn.example.net"})),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED, "{b}");
    assert_eq!(b["name"], "wg0");
    let server_pub = b["public_key"].as_str().unwrap().to_string();
    assert_eq!(server_pub.len(), 44);
    assert_eq!(t.wg.applies.load(Ordering::SeqCst), 1, "applied at once");

    let (s, b) = t
        .call(
            &c,
            Method::POST,
            "/api/vpn/wireguard/peers",
            Some(json!({"name": "laptop", "preshared_key": true})),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED, "{b}");
    let id = b["id"].as_i64().unwrap();
    assert_eq!(b["peer"]["allowed_ips"], "10.99.0.2/32");
    assert_eq!(b["peer"]["exportable"], true);
    assert!(b["peer"].get("private_key").is_none(), "{b}");

    // the client config: its private key, the server's key, the endpoint
    let (s, cfg, h) = t
        .raw(
            Method::GET,
            &format!("/api/vpn/wireguard/config/{id}"),
            Some(&c),
            None,
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{cfg}");
    assert!(h[header::CONTENT_DISPOSITION]
        .to_str()
        .unwrap()
        .contains("laptop.conf"));
    assert!(cfg.contains("PrivateKey = ") && cfg.contains(&format!("PublicKey = {server_pub}")));
    assert!(cfg.contains("Endpoint = vpn.example.net:51820") && cfg.contains("PresharedKey = "));
    let client_priv = cfg
        .lines()
        .find_map(|l| l.strip_prefix("PrivateKey = "))
        .unwrap()
        .to_string();
    let (s, svg, h) = t
        .raw(
            Method::GET,
            &format!("/api/vpn/wireguard/qrcode/{id}"),
            Some(&c),
            None,
        )
        .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(h[header::CONTENT_TYPE], "image/svg+xml");
    assert!(svg.contains("<svg"));

    // no key ever in the overview or the page
    let (_, ov, _) = t.raw(Method::GET, "/api/vpn", Some(&c), None).await;
    assert!(!ov.contains(&client_priv), "{ov}");
    assert!(ov.contains("laptop") && ov.contains(&server_pub));
    let (s, page, _) = t.raw(Method::GET, "/vpn", Some(&c), None).await;
    assert_eq!(s, StatusCode::OK);
    assert!(page.contains("data-tunnel=\"wg0\"") && page.contains("data-peer=\"laptop\""));
    assert!(!page.contains(&client_priv));

    // a refused apply leaves nothing behind
    t.wg.fail.store(true, Ordering::SeqCst);
    let (s, b) = t
        .call(
            &c,
            Method::POST,
            "/api/vpn/wireguard/peers",
            Some(json!({"name": "phone"})),
        )
        .await;
    assert_eq!(s, StatusCode::INTERNAL_SERVER_ERROR, "{b}");
    assert!(b["error"].as_str().unwrap().contains("refused"));
    t.wg.fail.store(false, Ordering::SeqCst);
    let (_, ov, _) = t.raw(Method::GET, "/api/vpn", Some(&c), None).await;
    assert!(!ov.contains("phone"), "rolled back: {ov}");
    // bad input is a 400
    let (s, _) = t
        .call(
            &c,
            Method::POST,
            "/api/vpn/wireguard/tunnels",
            Some(json!({"name": "bad name"})),
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);

    // IPsec: a generated PSK is shown once, never listed
    let (s, b) = t
        .call(
            &c,
            Method::POST,
            "/api/vpn/ipsec/connections",
            Some(json!({"name": "site-b", "local_address": "203.0.113.2", "remote_address": "198.51.100.2",
                        "local_ts": "192.168.50.0/24", "remote_ts": "10.2.0.0/16"})),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED, "{b}");
    let psk = b["generated_psk"].as_str().unwrap().to_string();
    assert_eq!(psk.len(), 40);
    let (_, ov, _) = t.raw(Method::GET, "/api/vpn", Some(&c), None).await;
    assert!(ov.contains("site-b") && !ov.contains(&psk), "{ov}");
    let (_, page, _) = t.raw(Method::GET, "/vpn", Some(&c), None).await;
    assert!(page.contains("data-ipsec=\"site-b\"") && !page.contains(&psk));
    let ipsec_id = serde_json::from_str::<Value>(&ov).unwrap()["ipsec"][0]["id"]
        .as_i64()
        .unwrap();
    let (s, _) = t
        .call(
            &c,
            Method::DELETE,
            &format!("/api/vpn/ipsec/connections/{ipsec_id}"),
            None,
        )
        .await;
    assert_eq!(s, StatusCode::OK);

    // read-only accounts see the page but cannot export keys
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
    let (_, rc, _) = t.login("viewer", "Viewer-Passw0rd-1", None).await;
    let rc = rc.unwrap();
    let (s, _) = t
        .call(
            &rc,
            Method::GET,
            &format!("/api/vpn/wireguard/config/{id}"),
            None,
        )
        .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (s, _) = t
        .call(
            &rc,
            Method::POST,
            "/api/vpn/wireguard/peers",
            Some(json!({"name": "x"})),
        )
        .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (_, page, _) = t.raw(Method::GET, "/vpn", Some(&rc), None).await;
    assert!(
        !page.contains("id=\"wg-peer-form\""),
        "no forms for read-only"
    );
}

#[tokio::test]
async fn accounts_persist_and_roles_are_enforced() {
    let t = setup().await;
    let c = t.admin().await;
    let (s, b) = t
        .call(
            &c,
            Method::POST,
            "/api/system/users",
            Some(json!({"username": "ops", "password": "Ops-Passw0rd-123", "role": "operator"})),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED, "{b}");
    let ops_id = b["id"].as_u64().unwrap();
    let (s, _) = t
        .call(
            &c,
            Method::POST,
            "/api/system/users",
            Some(json!({"username": "ro", "password": "short", "role": "readonly"})),
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "weak password refused");
    let (s, _) = t
        .call(
            &c,
            Method::POST,
            "/api/system/users",
            Some(json!({"username": "ro", "password": "Ro-Passw0rd-1234", "role": "readonly"})),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED);

    // operator: may change config, not accounts or backups
    let (_, oc, _) = t.login("ops", "Ops-Passw0rd-123", None).await;
    let oc = oc.unwrap();
    for (m, uri, body) in [
        (
            Method::POST,
            "/api/system/users",
            Some(json!({"username": "x", "password": "X-Passw0rd-12345", "role": "admin"})),
        ),
        (Method::POST, "/api/system/backups", None),
        (
            Method::POST,
            "/api/system/restore",
            Some(json!({"tables": {}})),
        ),
    ] {
        let (s, b) = t.call(&oc, m.clone(), uri, body).await;
        assert_eq!(s, StatusCode::FORBIDDEN, "{m} {uri}: {b}");
    }
    // read-only: no config changes, but its own password
    let (_, rc, _) = t.login("ro", "Ro-Passw0rd-1234", None).await;
    let rc = rc.unwrap();
    let (s, _) = t
        .call(
            &rc,
            Method::POST,
            "/api/vpn/wireguard/tunnels",
            Some(json!({})),
        )
        .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (s, b) = t
        .call(&rc, Method::POST, "/api/auth/password",
              Some(json!({"current_password": "Ro-Passw0rd-1234", "new_password": "Ro-New-Passw0rd-1"})))
        .await;
    assert_eq!(s, StatusCode::OK, "{b}");
    assert_eq!(
        t.login("ro", "Ro-Passw0rd-1234", None).await.0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        t.login("ro", "Ro-New-Passw0rd-1", None).await.0,
        StatusCode::OK
    );

    // demoting ends the account's sessions
    let (s, _) = t
        .call(
            &c,
            Method::PUT,
            &format!("/api/system/users/{ops_id}"),
            Some(json!({"role": "readonly"})),
        )
        .await;
    assert_eq!(s, StatusCode::OK);
    let (s, _) = t.call(&oc, Method::GET, "/api/status", None).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED, "old session gone");
    // disabled accounts cannot log in
    t.call(
        &c,
        Method::PUT,
        &format!("/api/system/users/{ops_id}"),
        Some(json!({"enabled": false})),
    )
    .await;
    assert_eq!(
        t.login("ops", "Ops-Passw0rd-123", None).await.0,
        StatusCode::UNAUTHORIZED
    );

    // the last admin stays; nobody deletes themselves
    let me = t.state.auth.user_store.get_user("admin").await.unwrap().id;
    let (s, b) = t
        .call(
            &c,
            Method::PUT,
            &format!("/api/system/users/{me}"),
            Some(json!({"role": "operator"})),
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{b}");
    let (s, _) = t
        .call(&c, Method::DELETE, &format!("/api/system/users/{me}"), None)
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);

    // a restart (new process over the same store) keeps every account
    let again = state_at(&t.dir).await;
    let names: Vec<String> = again
        .auth
        .user_store
        .list_users()
        .await
        .into_iter()
        .map(|u| u.username)
        .collect();
    assert_eq!(names, vec!["admin", "ops", "ro"]);
    let (_, page, _) = t.raw(Method::GET, "/system", Some(&c), None).await;
    assert!(page.contains("data-user=\"ops\"") && page.contains("id=\"user-form\""));
}

#[cfg(feature = "totp")]
#[tokio::test]
async fn two_factor_login_needs_the_code_after_enrolment() {
    let t = setup().await;
    let c = t.admin().await;
    let (s, b) = t
        .call(
            &c,
            Method::POST,
            "/api/auth/2fa/setup",
            Some(json!({"password": ADMIN_PW})),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{b}");
    let secret = b["secret"].as_str().unwrap().to_string();
    assert!(b["otpauth_uri"]
        .as_str()
        .unwrap()
        .starts_with("otpauth://totp/Patronus:admin?"));
    assert!(b["qr_svg"].as_str().unwrap().contains("<svg"));
    // not on yet: password alone still works
    assert_eq!(t.login("admin", ADMIN_PW, None).await.0, StatusCode::OK);
    let now = chrono::Utc::now().timestamp() as u64;
    let (s, b) = t
        .call(
            &c,
            Method::POST,
            "/api/auth/2fa/enable",
            Some(json!({"code": crate::totp::code_at(&secret, now).unwrap()})),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{b}");
    let recovery: Vec<String> = serde_json::from_value(b["recovery_codes"].clone()).unwrap();
    assert_eq!(recovery.len(), 10);

    let (s, cookie, b) = t.login("admin", ADMIN_PW, None).await;
    assert_eq!(
        (s, b["totp_required"].as_bool()),
        (StatusCode::UNAUTHORIZED, Some(true))
    );
    assert!(cookie.is_none(), "no session without the second factor");
    let (s, _, b) = t.login("admin", ADMIN_PW, Some("000000x")).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED, "{b}");
    let next = crate::totp::code_at(&secret, now + crate::totp::PERIOD).unwrap();
    let (s, cookie, b) = t.login("admin", ADMIN_PW, Some(&next)).await;
    assert_eq!(s, StatusCode::OK, "{b}");
    assert!(cookie.is_some());
    let (s, _, _) = t.login("admin", ADMIN_PW, Some(&next)).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED, "a code is accepted once");
    let (s, _, _) = t.login("admin", ADMIN_PW, Some(&recovery[3])).await;
    assert_eq!(s, StatusCode::OK, "recovery code");
    let (s, _, _) = t
        .login("admin", "wrong-password-xx", Some(&recovery[4]))
        .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED, "never without the password");

    // the accounts list shows it; an admin can reset someone else's
    let (_, users) = t.call(&c, Method::GET, "/api/system/users", None).await;
    assert_eq!(users[0]["two_factor"], true);
    assert_eq!(users[0]["recovery_codes_left"], 9);
    let id = users[0]["id"].as_u64().unwrap();
    let (s, _) = t
        .call(
            &c,
            Method::POST,
            &format!("/api/system/users/{id}/2fa/reset"),
            None,
        )
        .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(t.login("admin", ADMIN_PW, None).await.0, StatusCode::OK);
}

#[cfg(feature = "totp")]
#[tokio::test]
async fn turning_two_factor_on_or_off_ends_the_accounts_other_sessions() {
    let t = setup().await;
    let mine = t.admin().await;
    let other = t.admin().await;
    let tr = &t;
    let alive =
        move |c: String| async move { tr.call(&c, Method::GET, "/api/system/users", None).await.0 };
    assert_eq!(alive(other.clone()).await, StatusCode::OK);

    let (s, b) = t
        .call(
            &mine,
            Method::POST,
            "/api/auth/2fa/setup",
            Some(json!({"password": ADMIN_PW})),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{b}");
    let secret = b["secret"].as_str().unwrap().to_string();
    // setup alone changes nothing for login, so nothing ends yet
    assert_eq!(alive(other.clone()).await, StatusCode::OK);
    let now = chrono::Utc::now().timestamp() as u64;
    let (s, b) = t
        .call(
            &mine,
            Method::POST,
            "/api/auth/2fa/enable",
            Some(json!({"code": crate::totp::code_at(&secret, now).unwrap()})),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{b}");
    let recovery: Vec<String> = serde_json::from_value(b["recovery_codes"].clone()).unwrap();
    assert_eq!(
        alive(other).await,
        StatusCode::UNAUTHORIZED,
        "a password-only session must not survive two-factor being turned on"
    );
    assert_eq!(alive(mine.clone()).await, StatusCode::OK);

    let (s, again, b) = t.login("admin", ADMIN_PW, Some(&recovery[0])).await;
    assert_eq!(s, StatusCode::OK, "{b}");
    let again = again.unwrap();
    let (s, b) = t
        .call(
            &mine,
            Method::POST,
            "/api/auth/2fa/disable",
            Some(json!({"password": ADMIN_PW, "code": recovery[1]})),
        )
        .await;
    assert_eq!(
        (s, b["enabled"].as_bool()),
        (StatusCode::OK, Some(false)),
        "{b}"
    );
    assert_eq!(
        alive(again).await,
        StatusCode::UNAUTHORIZED,
        "turning two-factor off ends the other sessions"
    );
    assert_eq!(alive(mine).await, StatusCode::OK, "the caller's own stays");
}

#[cfg(feature = "totp")]
#[tokio::test]
async fn wrong_codes_confirming_two_factor_setup_hit_the_login_throttle() {
    async fn begin(t: &T, c: &str) -> String {
        let (s, b) = t
            .call(
                c,
                Method::POST,
                "/api/auth/2fa/setup",
                Some(json!({"password": ADMIN_PW})),
            )
            .await;
        assert_eq!(s, StatusCode::OK, "{b}");
        b["secret"].as_str().unwrap().to_string()
    }
    async fn enable(t: &T, c: &str, code: &str) -> (StatusCode, Value) {
        t.call(
            c,
            Method::POST,
            "/api/auth/2fa/enable",
            Some(json!({"code": code})),
        )
        .await
    }
    fn wrong_code(secret: &str) -> String {
        let now = chrono::Utc::now().timestamp() as u64;
        // wrong for every step accepted now or in the next half minute
        (0..1_000_000u32)
            .map(|n| format!("{n:06}"))
            .find(|c| (0..=30).all(|d| crate::totp::verify(secret, c, now + d, None).is_none()))
            .unwrap()
    }
    let right =
        |secret: &str| crate::totp::code_at(secret, chrono::Utc::now().timestamp() as u64).unwrap();
    let on = |t: &T| {
        let us = t.state.auth.user_store.clone();
        async move { us.get_user("admin").await.unwrap().two_factor() }
    };

    // Below the limit: a confirm with no setup started is not a guess and
    // does not count; after MAX-1 wrong codes the right one still works.
    let t = setup().await;
    let c = t.admin().await;
    let (s, _) = enable(&t, &c, "123456").await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let secret = begin(&t, &c).await;
    let wrong = wrong_code(&secret);
    for _ in 1..crate::auth::MAX_LOGIN_FAILURES {
        let (s, b) = enable(&t, &c, &wrong).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{b}");
    }
    let (s, b) = enable(&t, &c, &right(&secret)).await;
    assert_eq!(s, StatusCode::OK, "{b}");
    assert!(on(&t).await);

    // At the limit the client is locked out: even the right code is refused
    // and two-factor stays off.
    let t = setup().await;
    let c = t.admin().await;
    let secret = begin(&t, &c).await;
    let wrong = wrong_code(&secret);
    for _ in 0..crate::auth::MAX_LOGIN_FAILURES {
        let (s, b) = enable(&t, &c, &wrong).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{b}");
    }
    let (s, b) = enable(&t, &c, &right(&secret)).await;
    assert_eq!(s, StatusCode::TOO_MANY_REQUESTS, "{b}");
    assert!(
        !on(&t).await,
        "a locked-out client cannot turn two-factor on"
    );
    // the same budget as the login form
    assert_eq!(
        t.login("admin", ADMIN_PW, None).await.0,
        StatusCode::TOO_MANY_REQUESTS
    );
}

#[tokio::test]
async fn an_admin_cannot_set_their_own_password_without_the_current_one() {
    let t = setup().await;
    let c = t.admin().await;
    let me = t.state.auth.user_store.get_user("admin").await.unwrap().id;
    // the admin "set password" route skips the current-password check, so
    // it refuses one's own account (a stolen session must not lock the
    // owner out) ...
    let (s, b) = t
        .call(
            &c,
            Method::PUT,
            &format!("/api/system/users/{me}"),
            Some(json!({"password": "Stolen-Session-Pw-1"})),
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{b}");
    assert!(b.to_string().contains("/api/auth/password"), "{b}");
    assert_eq!(
        t.login("admin", "Stolen-Session-Pw-1", None).await.0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(t.login("admin", ADMIN_PW, None).await.0, StatusCode::OK);
    // ... and the refusal didn't end the admin's session
    let (s, _) = t.call(&c, Method::GET, "/api/status", None).await;
    assert_eq!(s, StatusCode::OK);
    // other edits of one's own row still work (nothing here changes)
    let (s, b) = t
        .call(
            &c,
            Method::PUT,
            &format!("/api/system/users/{me}"),
            Some(json!({"enabled": true})),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{b}");
    // setting another account's password is unchanged
    let (s, b) = t
        .call(
            &c,
            Method::POST,
            "/api/system/users",
            Some(json!({"username": "ops", "password": "Ops-Passw0rd-123", "role": "operator"})),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED, "{b}");
    let ops = b["id"].as_u64().unwrap();
    let (s, b) = t
        .call(
            &c,
            Method::PUT,
            &format!("/api/system/users/{ops}"),
            Some(json!({"password": "Ops-New-Passw0rd-1"})),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{b}");
    assert_eq!(
        t.login("ops", "Ops-New-Passw0rd-1", None).await.0,
        StatusCode::OK
    );
    // the page offers "Set password" for others only
    let (s, page, _) = t.raw(Method::GET, "/system", Some(&c), None).await;
    assert_eq!(s, StatusCode::OK);
    assert!(!page.contains(&format!("setPassword({me},")), "own row");
    assert!(page.contains(&format!("setPassword({ops},")), "other row");
}

#[tokio::test]
async fn backups_restore_from_the_list_and_from_an_upload() {
    let t = setup().await;
    let c = t.admin().await;
    let (s, b) = t.call(&c, Method::POST, "/api/system/backups", None).await;
    assert_eq!(s, StatusCode::CREATED, "{b}");
    let name = b["name"].as_str().unwrap().to_string();
    let (_, file, _) = t
        .raw(
            Method::GET,
            &format!("/api/system/backups/{name}"),
            Some(&c),
            None,
        )
        .await;
    // change the configuration after the backup
    t.call(
        &c,
        Method::POST,
        "/api/system/users",
        Some(json!({"username": "later", "password": "Later-Passw0rd-1", "role": "operator"})),
    )
    .await;
    t.state
        .config_store
        .save_system_config("test.marker", "after")
        .await
        .unwrap();
    let marker = || async {
        t.state
            .config_store
            .load_system_config("test.marker")
            .await
            .unwrap()
    };
    let applies = t.restore_fake.applies.load(Ordering::SeqCst);

    // restore the stored backup: config back, applied to every subsystem
    let (s, b) = t
        .call(
            &c,
            Method::POST,
            &format!("/api/system/backups/{name}/restore"),
            None,
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{b}");
    assert!(t.restore_fake.applies.load(Ordering::SeqCst) > applies);
    assert!(t.state.auth.user_store.get_user("later").await.is_none());
    assert_eq!(marker().await, None, "the store is the backup's again");
    let revs = t.state.config_store.list_revisions().await.unwrap();
    assert!(revs
        .iter()
        .any(|r| r.3.contains(&format!("before restore of {name}"))));

    // a subsystem refusing the restored config: undone, 409
    t.state
        .config_store
        .save_system_config("test.marker", "kept")
        .await
        .unwrap();
    t.restore_fake.fail.store(true, Ordering::SeqCst);
    let (s, b) = t
        .call(
            &c,
            Method::POST,
            &format!("/api/system/backups/{name}/restore"),
            None,
        )
        .await;
    assert_eq!(s, StatusCode::CONFLICT, "{b}");
    assert!(b["error"].as_str().unwrap().contains("undone"));
    assert_eq!(marker().await.as_deref(), Some("kept"));
    t.restore_fake.fail.store(false, Ordering::SeqCst);

    // upload: the downloaded file restores and is kept as a backup
    let (s, b, _) = t
        .raw(
            Method::POST,
            "/api/system/restore",
            Some(&c),
            Some(file.clone()),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{b}");
    let v: Value = serde_json::from_str(&b).unwrap();
    assert!(v["restored"].as_str().unwrap().ends_with("-upload.json"));
    assert_eq!(marker().await, None);
    let (_, list) = t.call(&c, Method::GET, "/api/system/backups", None).await;
    assert_eq!(list.as_array().unwrap().len(), 2);

    // junk is refused before anything changes
    for junk in [
        "not json",
        "{\"no\":\"tables\"}",
        "{\"tables\":{\"evil\":[]}}",
    ] {
        let (s, b, _) = t
            .raw(
                Method::POST,
                "/api/system/restore",
                Some(&c),
                Some(junk.into()),
            )
            .await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{junk}: {b}");
    }
    // a backup without an enabled admin keeps the current accounts
    let mut doc: Value = serde_json::from_str(&file).unwrap();
    doc["tables"]["web_users"] = json!([]);
    let (s, b, _) = t
        .raw(
            Method::POST,
            "/api/system/restore",
            Some(&c),
            Some(doc.to_string()),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{b}");
    assert!(b.contains("kept the current web accounts"));
    assert!(t.state.auth.user_store.get_user("admin").await.is_some());
    // a pre-accounts backup (no web_users at all) keeps them too
    doc["tables"].as_object_mut().unwrap().remove("web_users");
    let (s, _, _) = t
        .raw(
            Method::POST,
            "/api/system/restore",
            Some(&c),
            Some(doc.to_string()),
        )
        .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(t.login("admin", ADMIN_PW, None).await.0, StatusCode::OK);
}

#[tokio::test]
async fn service_control_refuses_unknown_and_self_stopping_services() {
    let t = setup().await;
    let c = t.admin().await;
    let (s, b) = t
        .call(
            &c,
            Method::POST,
            "/api/system/services/not-a-service/stop",
            None,
        )
        .await;
    assert_eq!(s, StatusCode::NOT_FOUND, "{b}");
}

#[cfg(not(feature = "wireguard"))]
#[tokio::test]
async fn without_use_wireguard_the_forms_say_how_to_get_them() {
    let t = setup().await;
    let c = t.admin().await;
    let (s, b) = t
        .call(
            &c,
            Method::POST,
            "/api/vpn/wireguard/tunnels",
            Some(json!({})),
        )
        .await;
    assert_eq!(s, StatusCode::NOT_IMPLEMENTED, "{b}");
    assert!(b["error"].as_str().unwrap().contains("USE=wireguard"));
    let (_, page, _) = t.raw(Method::GET, "/vpn", Some(&c), None).await;
    assert!(page.contains("id=\"wg-not-built\"") && !page.contains("id=\"wg-tunnel-form\""));
}

/// The container image runs patronus-web as user patronus with no root
/// broker: an IPsec tunnel can be neither written to /etc/swanctl nor
/// loaded. The API refuses it up front (501 naming applyd), stores nothing,
/// never calls the applier, and the page shows why instead of the form.
#[cfg(feature = "ipsec")]
#[tokio::test]
async fn unprivileged_without_applyd_ipsec_is_refused_up_front() {
    let dir = std::env::temp_dir().join(format!("patronus-web-fh-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("pw"), format!("{ADMIN_PW}\n")).unwrap();
    let mut state = state_at(&dir).await;
    let ipsec = Fake::new("ipsec", Phase::Services);
    state.tunnels = Arc::new(
        crate::state::TunnelsManager::with_appliers(
            state.config_store.clone(),
            None,
            Some(ipsec.clone()),
            Arc::new(crate::state::firewall::NoopApplier),
        )
        .with_privilege(|| (false, false)),
    );
    let t = T {
        app: super::build_router(state.clone(), Arc::new(crate::WsBroadcaster::new())),
        state,
        dir: dir.clone(),
        wg: Fake::new("wireguard", Phase::Interfaces),
        restore_fake: Fake::new("firewall", Phase::Firewall),
    };
    let c = t.admin().await;
    let (s, b) = t
        .call(
            &c,
            Method::POST,
            "/api/vpn/ipsec/connections",
            Some(json!({"name": "site-b", "remote_address": "198.51.100.2",
                        "local_ts": "192.168.50.0/24", "remote_ts": "10.2.0.0/16"})),
        )
        .await;
    assert_eq!(s, StatusCode::NOT_IMPLEMENTED, "{b}");
    let msg = b["error"].as_str().unwrap();
    assert!(
        msg.contains("IPsec needs root") && msg.contains("patronus applyd"),
        "{msg}"
    );
    assert_eq!(
        ipsec.applies.load(Ordering::SeqCst),
        0,
        "applier never called"
    );
    let (s, _) = t.call(&c, Method::POST, "/api/vpn/ipsec/apply", None).await;
    assert_eq!(s, StatusCode::NOT_IMPLEMENTED);
    let (_, ov) = t.call(&c, Method::GET, "/api/vpn", None).await;
    assert_eq!(ov["ipsec"], json!([]), "nothing stored: {ov}");
    assert!(
        ov["ipsec_unavailable"].as_str().unwrap().contains("applyd"),
        "{ov}"
    );
    let (_, page, _) = t.raw(Method::GET, "/vpn", Some(&c), None).await;
    assert!(page.contains("id=\"ipsec-unavailable\"") && !page.contains("id=\"ipsec-form\""));

    // with the broker running (or as root) the same request goes through
    assert!(crate::state::tunnels::ipsec_blocker(false, true).is_none());
    assert!(crate::state::tunnels::ipsec_blocker(true, false).is_none());
    let _ = std::fs::remove_dir_all(&t.dir);
}
