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

    // the accounts list shows it
    let (_, users) = t.call(&c, Method::GET, "/api/system/users", None).await;
    assert_eq!(users[0]["two_factor"], true);
    assert_eq!(users[0]["recovery_codes_left"], 9);
    let me = users[0]["id"].as_u64().unwrap();

    // the admin reset skips the password + code that /api/auth/2fa/disable
    // asks for, so it refuses one's own account: a stolen session must not
    // strip the owner's second factor
    let (s, b) = t
        .call(
            &c,
            Method::POST,
            &format!("/api/system/users/{me}/2fa/reset"),
            None,
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{b}");
    assert!(b.to_string().contains("/api/auth/2fa/disable"), "{b}");
    let (s, _, b) = t.login("admin", ADMIN_PW, None).await;
    assert_eq!(
        (s, b["totp_required"].as_bool()),
        (StatusCode::UNAUTHORIZED, Some(true)),
        "two-factor login is still on"
    );
    let (s, _) = t.call(&c, Method::GET, "/api/status", None).await;
    assert_eq!(s, StatusCode::OK, "the refusal didn't end the session");

    // an admin can still reset someone else's (lost phone)
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
    let us = &t.state.auth.user_store;
    let ops_secret = us.totp_begin(ops as u32).await.unwrap();
    us.totp_confirm(ops as u32, &crate::totp::code_at(&ops_secret, now).unwrap())
        .await
        .unwrap();
    assert_eq!(
        t.login("ops", "Ops-Passw0rd-123", None).await.0,
        StatusCode::UNAUTHORIZED
    );
    // the page offers "Reset 2FA" on the other account's row only
    let (s, page, _) = t.raw(Method::GET, "/system", Some(&c), None).await;
    assert_eq!(s, StatusCode::OK);
    assert!(
        !page.contains(&format!("/api/system/users/{me}/2fa/reset")),
        "own row"
    );
    assert!(
        page.contains(&format!("/api/system/users/{ops}/2fa/reset")),
        "other row"
    );
    let (s, b) = t
        .call(
            &c,
            Method::POST,
            &format!("/api/system/users/{ops}/2fa/reset"),
            None,
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{b}");
    assert_eq!(
        t.login("ops", "Ops-Passw0rd-123", None).await.0,
        StatusCode::OK
    );
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

/// A restore that replaces the accounts ends the sessions opened before
/// it (they cache user id and role): an account the backup doesn't have,
/// such as one an intruder added after it was taken, is out at once rather
/// than when its session expires a day later. The restoring admin stays
/// logged in while their account is still the same enabled admin.
#[tokio::test]
async fn a_restore_that_replaces_the_accounts_ends_the_other_sessions() {
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
    for (u, role) in [("intruder", "admin"), ("later", "operator")] {
        let (s, b) = t
            .call(
                &c,
                Method::POST,
                "/api/system/users",
                Some(json!({"username": u, "password": "Added-Later-Passw0rd", "role": role})),
            )
            .await;
        assert!(s.is_success(), "{u}: {s} {b}");
    }
    let tr = &t;
    let me = move |cookie: String| async move {
        tr.call(&cookie, Method::GET, "/api/auth/me", None).await.0
    };
    let (_, intruder, _) = t.login("intruder", "Added-Later-Passw0rd", None).await;
    let (_, later, _) = t.login("later", "Added-Later-Passw0rd", None).await;
    let (intruder, later) = (intruder.unwrap(), later.unwrap());
    let other_admin = t.admin().await;
    assert_eq!(me(intruder.clone()).await, StatusCode::OK);

    let (s, b) = t
        .call(
            &c,
            Method::POST,
            &format!("/api/system/backups/{name}/restore"),
            None,
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{b}");
    assert!(t.state.auth.user_store.get_user("intruder").await.is_none());
    assert_eq!(me(intruder).await, StatusCode::UNAUTHORIZED, "gone account");
    assert_eq!(me(later).await, StatusCode::UNAUTHORIZED, "gone account");
    assert_eq!(
        me(other_admin).await,
        StatusCode::UNAUTHORIZED,
        "another session of the admin (its password may differ now)"
    );
    assert_eq!(me(c.clone()).await, StatusCode::OK, "the restoring admin");

    // a document without an enabled admin keeps the accounts: no logout
    let other_admin = t.admin().await;
    let mut doc: Value = serde_json::from_str(&file).unwrap();
    let rows = doc["tables"]["web_users"].clone();
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
    assert_eq!(me(other_admin.clone()).await, StatusCode::OK);

    // the restoring admin's own account is another one in the backup
    // (renamed here): their session ends too
    let mut rows = rows;
    for r in rows.as_array_mut().unwrap() {
        if r["username"] == json!("admin") {
            r["username"] = json!("root");
        }
    }
    doc["tables"]["web_users"] = rows;
    let (s, b, _) = t
        .raw(
            Method::POST,
            "/api/system/restore",
            Some(&c),
            Some(doc.to_string()),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{b}");
    assert_eq!(me(c).await, StatusCode::UNAUTHORIZED);
    assert_eq!(me(other_admin).await, StatusCode::UNAUTHORIZED);
    let (s, _, b) = t.login("root", ADMIN_PW, None).await;
    assert_eq!(s, StatusCode::OK, "{b}");
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

impl T {
    /// A request with one extra header (API key tests).
    async fn with_header(
        &self,
        m: Method,
        uri: &str,
        header_name: &str,
        value: &str,
        body: Option<Value>,
    ) -> (StatusCode, Value) {
        let mut b = Request::builder()
            .method(m)
            .uri(uri)
            .header(header_name, value);
        if body.is_some() {
            b = b.header(header::CONTENT_TYPE, "application/json");
        }
        let r = self
            .app
            .clone()
            .oneshot(
                b.body(
                    body.map(|v| Body::from(v.to_string()))
                        .unwrap_or_else(Body::empty),
                )
                .unwrap(),
            )
            .await
            .unwrap();
        let s = r.status();
        let bytes = axum::body::to_bytes(r.into_body(), 1 << 20).await.unwrap();
        let text = String::from_utf8_lossy(&bytes).into_owned();
        (
            s,
            serde_json::from_str(&text).unwrap_or(Value::String(text)),
        )
    }
}

#[tokio::test]
async fn api_keys_authenticate_automation_with_least_privilege() {
    let t = setup().await;
    let c = t.admin().await;

    // admin creates a read-only and an operator key; the token is shown once
    let (s, b) = t
        .call(
            &c,
            Method::POST,
            "/api/system/api-keys",
            Some(json!({"name": "rustinion"})),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED, "{b}");
    let ro = b["token"].as_str().unwrap().to_string();
    assert!(ro.starts_with("pat_"));
    assert_eq!(b["key"]["scope"], "readonly");
    let ro_id = b["key"]["id"].as_i64().unwrap();
    let (s, b) = t
        .call(
            &c,
            Method::POST,
            "/api/system/api-keys",
            Some(json!({"name": "terraform", "scope": "operator", "expires_in_days": 30})),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED, "{b}");
    let op = b["token"].as_str().unwrap().to_string();
    // the list never has the token
    let (s, b) = t.call(&c, Method::GET, "/api/system/api-keys", None).await;
    assert_eq!(s, StatusCode::OK);
    assert!(
        !b.to_string().contains(&ro) && !b.to_string().contains(&op),
        "{b}"
    );
    assert_eq!(b.as_array().unwrap().len(), 2);
    // bad scope / name
    let (s, _) = t
        .call(
            &c,
            Method::POST,
            "/api/system/api-keys",
            Some(json!({"name": "x", "scope": "admin"})),
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);

    // read-only key: reads work with either header, writes are refused
    let bearer = format!("Bearer {ro}");
    let (s, b) = t
        .with_header(Method::GET, "/api/status", "authorization", &bearer, None)
        .await;
    assert_eq!(s, StatusCode::OK, "{b}");
    let (s, _) = t
        .with_header(Method::GET, "/api/firewall/rules", "x-api-key", &ro, None)
        .await;
    assert_eq!(s, StatusCode::OK);
    let (s, b) = t
        .with_header(Method::GET, "/api/auth/me", "authorization", &bearer, None)
        .await;
    assert_eq!(s, StatusCode::OK, "{b}");
    assert_eq!(b["username"], "api-key:rustinion");
    assert_eq!(b["role"], "ReadOnly");
    let rule = json!({"name":"k","action":"accept","interface":"any","protocol":"tcp","source":"any","destination":"any","port":"9","description":"","enabled":true,"chain":"input"});
    let (s, b) = t
        .with_header(
            Method::POST,
            "/api/firewall/rules",
            "authorization",
            &bearer,
            Some(rule.clone()),
        )
        .await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{b}");
    // keys never reach accounts, credentials or key management
    for (m, uri) in [
        (Method::GET, "/api/system/users"),
        (Method::GET, "/api/system/api-keys"),
        (Method::POST, "/api/auth/password"),
        (Method::POST, "/api/system/backups"),
    ] {
        let (s, _) = t
            .with_header(m.clone(), uri, "authorization", &bearer, None)
            .await;
        assert_eq!(s, StatusCode::FORBIDDEN, "{m} {uri}");
    }
    // pages are for people
    let (s, _) = t
        .with_header(Method::GET, "/firewall", "authorization", &bearer, None)
        .await;
    assert_eq!(s, StatusCode::FORBIDDEN);

    // operator key may change configuration, but is still no admin
    let opb = format!("Bearer {op}");
    let (s, b) = t
        .with_header(
            Method::POST,
            "/api/firewall/rules",
            "authorization",
            &opb,
            Some(rule),
        )
        .await;
    assert!(s.is_success(), "{s} {b}");
    let (s, _) = t
        .with_header(
            Method::POST,
            "/api/system/backups",
            "authorization",
            &opb,
            None,
        )
        .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (s, _) = t
        .with_header(
            Method::POST,
            "/api/system/api-keys",
            "authorization",
            &opb,
            Some(json!({"name": "escalate", "scope": "operator"})),
        )
        .await;
    assert_eq!(s, StatusCode::FORBIDDEN);

    // wrong / malformed keys are 401, and a cookie does not rescue them
    let (s, _) = t
        .with_header(
            Method::GET,
            "/api/status",
            "authorization",
            "Bearer pat_wrong",
            None,
        )
        .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    let (s, _) = t
        .with_header(Method::GET, "/api/status", "x-api-key", "nope", None)
        .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);

    // revoked -> 401 at once
    let (s, _) = t
        .call(
            &c,
            Method::DELETE,
            &format!("/api/system/api-keys/{ro_id}"),
            None,
        )
        .await;
    assert_eq!(s, StatusCode::OK);
    let (s, _) = t
        .with_header(Method::GET, "/api/status", "authorization", &bearer, None)
        .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    let (s, _) = t
        .call(&c, Method::DELETE, "/api/system/api-keys/99999", None)
        .await;
    assert_eq!(s, StatusCode::NOT_FOUND);

    // a read-only web account cannot create keys either
    let (s, _) = t
        .call(
            &c,
            Method::POST,
            "/api/system/users",
            Some(json!({"username":"viewer","password":"Viewer-Passw0rd-1","role":"readonly"})),
        )
        .await;
    assert!(s.is_success());
    let (s, vc, _) = t.login("viewer", "Viewer-Passw0rd-1", None).await;
    assert_eq!(s, StatusCode::OK);
    let (s, _) = t
        .call(
            vc.as_deref().unwrap(),
            Method::POST,
            "/api/system/api-keys",
            Some(json!({"name": "v"})),
        )
        .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn summary_metrics_events_and_hooks_serve_a_collector() {
    let t = setup().await;
    let c = t.admin().await;
    let (s, b) = t
        .call(
            &c,
            Method::POST,
            "/api/system/api-keys",
            Some(json!({"name": "collector"})),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED);
    let bearer = format!("Bearer {}", b["token"].as_str().unwrap());

    let (s, b) = t
        .with_header(
            Method::GET,
            "/api/status/summary",
            "authorization",
            &bearer,
            None,
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{b}");
    assert_eq!(b["product"], "patronus");
    assert_eq!(b["version"], env!("CARGO_PKG_VERSION"));
    for k in [
        "gateways",
        "gateway_groups",
        "vpn",
        "conntrack",
        "dhcp",
        "services",
        "firewall",
        "config",
    ] {
        assert!(b.get(k).is_some(), "summary lacks {k}: {b}");
    }
    assert!(
        b["firewall"]["rules_hash"]
            .as_str()
            .is_some_and(|h| h.len() == 16),
        "{b}"
    );

    let (s, body, h) = t.raw(Method::GET, "/metrics", Some(&c), None).await;
    assert_eq!(s, StatusCode::OK);
    assert!(h[header::CONTENT_TYPE]
        .to_str()
        .unwrap()
        .starts_with("text/plain"));
    assert!(body.contains("patronus_info{version=\""), "{body}");
    assert!(
        body.contains("# TYPE patronus_uptime_seconds gauge"),
        "{body}"
    );
    let (s, _, _) = t.raw(Method::GET, "/metrics", None, None).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED, "metrics need a session or key");

    // events: record two, read them back with the resume cursor
    for k in ["gateway_down", "tunnel_up"] {
        crate::state::telemetry::record(
            &t.state.config_store,
            &crate::state::telemetry::Event {
                id: 0,
                ts: 1,
                kind: k.into(),
                subject: "x".into(),
                severity: "info".into(),
                detail: String::new(),
            },
        )
        .await
        .unwrap();
    }
    let (s, b) = t
        .with_header(Method::GET, "/api/events", "authorization", &bearer, None)
        .await;
    assert_eq!(s, StatusCode::OK);
    let first = b[0]["id"].as_i64().unwrap();
    assert_eq!(b.as_array().unwrap().len(), 2);
    let (_, b) = t
        .with_header(
            Method::GET,
            &format!("/api/events?after={first}&kind=tunnel_up"),
            "authorization",
            &bearer,
            None,
        )
        .await;
    assert_eq!(b.as_array().unwrap().len(), 1);

    // webhooks are admin-only and never show the secret
    let (s, _) = t
        .with_header(
            Method::GET,
            "/api/system/hooks",
            "authorization",
            &bearer,
            None,
        )
        .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (s, b) = t
        .call(
            &c,
            Method::POST,
            "/api/system/hooks",
            Some(json!({"name": "ops", "url": "https://hooks.example/x", "secret": "hunter2hunter2", "kinds": "gateway_down"})),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED, "{b}");
    let (_, b) = t.call(&c, Method::GET, "/api/system/hooks", None).await;
    assert_eq!(b[0]["has_secret"], true);
    assert!(!b.to_string().contains("hunter2"), "{b}");
    let (s, _) = t
        .call(
            &c,
            Method::POST,
            "/api/system/hooks",
            Some(json!({"name": "bad", "url": "file:///etc/passwd"})),
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let id = b[0]["id"].as_i64().unwrap();
    let (s, _) = t
        .call(&c, Method::DELETE, &format!("/api/system/hooks/{id}"), None)
        .await;
    assert_eq!(s, StatusCode::OK);
}

#[tokio::test]
async fn updates_report_honestly_and_power_needs_an_admin() {
    let t = setup().await;
    let c = t.admin().await;
    let (s, b) = t.call(&c, Method::GET, "/api/system/updates", None).await;
    assert_eq!(s, StatusCode::OK, "{b}");
    assert_eq!(b["version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(b["job"]["state"], "none");
    // a viewer cannot start jobs or reboot
    let (s, _) = t
        .call(
            &c,
            Method::POST,
            "/api/system/users",
            Some(json!({"username":"viewer2","password":"Viewer-Passw0rd-2","role":"operator"})),
        )
        .await;
    assert!(s.is_success());
    let (_, vc, _) = t.login("viewer2", "Viewer-Passw0rd-2", None).await;
    let vc = vc.unwrap();
    for uri in [
        "/api/system/reboot",
        "/api/system/shutdown",
        "/api/system/updates/check",
        "/api/system/updates/apply",
    ] {
        let (s, _) = t.call(&vc, Method::POST, uri, Some(json!({}))).await;
        assert_eq!(s, StatusCode::FORBIDDEN, "{uri}");
    }
    // a bad scope is a 400, not a shell command: only reachable with Portage
    // or root, so here the request is refused one way or the other
    let (s, _) = t
        .call(
            &c,
            Method::POST,
            "/api/system/updates/apply",
            Some(json!({"scope": "x; rm -rf /"})),
        )
        .await;
    assert_ne!(s, StatusCode::ACCEPTED);
}

#[cfg(feature = "ha")]
#[tokio::test]
async fn ha_is_managed_through_the_api_and_undone_when_the_applier_refuses() {
    let dir = std::env::temp_dir().join(format!("patronus-web-ha-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("pw"), format!("{ADMIN_PW}\n")).unwrap();
    let mut state = state_at(&dir).await;
    let ha = Fake::new("ha", Phase::Services);
    state.lan = Arc::new(crate::state::LanManager::with_appliers(
        state.config_store.clone(),
        vec![ha.clone()],
    ));
    state
        .config_store
        .set_interface_role("eth1", Some("lan"))
        .await
        .unwrap();
    let app = super::build_router(state.clone(), Arc::new(crate::WsBroadcaster::new()));
    let t = T {
        app,
        state,
        dir,
        wg: Fake::new("wireguard", Phase::Interfaces),
        restore_fake: Fake::new("firewall", Phase::Firewall),
    };
    let c = t.admin().await;

    // virtual IP + settings; every change runs the applier
    let (s, b) = t
        .call(
            &c,
            Method::POST,
            "/api/ha/vips",
            Some(json!({"name":"lan-gw","interface":"@lan","address":"192.168.50.254/24"})),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED, "{b}");
    let id = b["id"].as_i64().unwrap();
    let (s, b) = t
        .call(
            &c,
            Method::PUT,
            "/api/ha/settings",
            Some(json!({"enabled": true, "priority": 150, "peer": "192.168.50.3"})),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{b}");
    assert!(ha.applies.load(Ordering::SeqCst) >= 2);
    let (s, b) = t.call(&c, Method::GET, "/api/ha", None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(b["settings"]["priority"], 150);
    assert_eq!(
        b["settings"]["password"].as_str().unwrap().len(),
        8,
        "admins see the VRRP password: {b}"
    );
    assert_eq!(b["vips"][0]["address"], "192.168.50.254/24");

    // bad input is a 400 and nothing changes
    for (m, uri, body) in [
        (
            Method::POST,
            "/api/ha/vips",
            json!({"name":"x","interface":"@lan","address":"192.168.50.0/24"}),
        ),
        (
            Method::POST,
            "/api/ha/vips",
            json!({"name":"lan-gw","interface":"@lan","address":"192.168.50.9/24"}),
        ),
        (Method::PUT, "/api/ha/settings", json!({"priority": 0})),
        (Method::PUT, "/api/ha/settings", json!({"peer": "nope"})),
    ] {
        let (s, _) = t.call(&c, m.clone(), uri, Some(body)).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{m} {uri}");
    }

    // the applier refusing (keepalived missing...) undoes the store write
    ha.fail.store(true, Ordering::SeqCst);
    let (s, b) = t
        .call(
            &c,
            Method::PUT,
            "/api/ha/settings",
            Some(json!({"priority": 200})),
        )
        .await;
    assert_eq!(s, StatusCode::INTERNAL_SERVER_ERROR, "{b}");
    let (_, b) = t.call(&c, Method::GET, "/api/ha", None).await;
    assert_eq!(
        b["settings"]["priority"], 150,
        "refused change was not undone: {b}"
    );
    ha.fail.store(false, Ordering::SeqCst);

    // maintenance mode
    let (s, _) = t
        .call(
            &c,
            Method::POST,
            "/api/ha/maintenance",
            Some(json!({"enabled": true})),
        )
        .await;
    assert_eq!(s, StatusCode::OK);
    let (_, b) = t.call(&c, Method::GET, "/api/ha", None).await;
    assert_eq!(b["settings"]["maintenance"], true);

    // a read-only account sees HA but not the password, and cannot change it
    let (s, _) = t
        .call(
            &c,
            Method::POST,
            "/api/system/users",
            Some(json!({"username":"viewer3","password":"Viewer-Passw0rd-3","role":"readonly"})),
        )
        .await;
    assert!(s.is_success());
    let (_, vc, _) = t.login("viewer3", "Viewer-Passw0rd-3", None).await;
    let vc = vc.unwrap();
    let (s, b) = t.call(&vc, Method::GET, "/api/ha", None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(b["settings"]["password"], "");
    let (s, _) = t
        .call(
            &vc,
            Method::PUT,
            "/api/ha/settings",
            Some(json!({"priority": 10})),
        )
        .await;
    assert_eq!(s, StatusCode::FORBIDDEN);

    // delete
    let (s, _) = t
        .call(&c, Method::DELETE, &format!("/api/ha/vips/{id}"), None)
        .await;
    assert_eq!(s, StatusCode::OK);
    let (s, _) = t
        .call(&c, Method::DELETE, &format!("/api/ha/vips/{id}"), None)
        .await;
    assert_eq!(
        s,
        StatusCode::INTERNAL_SERVER_ERROR
            .min(StatusCode::NOT_FOUND)
            .max(StatusCode::NOT_FOUND)
    );
    // the page renders
    let (s, body, _) = t.raw(Method::GET, "/ha", Some(&c), None).await;
    assert_eq!(s, StatusCode::OK);
    assert!(
        body.contains("High availability") && body.contains("id=\"ha-form\""),
        "{body}"
    );
}

#[tokio::test]
async fn npt_mappings_are_managed_through_the_nat_api() {
    let t = setup().await;
    let c = t.admin().await;
    let rule = |ext: &str, int: &str| {
        json!({"name":"npt-lan","rule_type":"NPT","interface":"@wan","source":"any","destination":"any",
               "target":int,"external_address":ext,"description":"","enabled":true,
               "protocol":null,"external_port":null,"reflection":false})
    };
    let (s, b) = t
        .call(
            &c,
            Method::POST,
            "/api/firewall/nat",
            Some(rule("2001:db8:50::/64", "fd00:50::/64")),
        )
        .await;
    assert!(s.is_success(), "{s} {b}");
    let (_, b) = t.call(&c, Method::GET, "/api/firewall/nat", None).await;
    let r = b
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["name"] == "npt-lan")
        .unwrap();
    assert_eq!(r["rule_type"], "NPTv6");
    assert_eq!(r["external_address"], "2001:db8:50::/64");
    assert_eq!(r["target"], "fd00:50::/64");
    for (e, i) in [
        ("2001:db8:50::/64", "fd00:50::/48"),
        ("203.0.113.0/24", "fd00:50::/64"),
        ("", "fd00:50::/64"),
    ] {
        let (s, _) = t
            .call(&c, Method::POST, "/api/firewall/nat", Some(rule(e, i)))
            .await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{e} {i}");
    }
    let (s, body, _) = t.raw(Method::GET, "/firewall", Some(&c), None).await;
    assert_eq!(s, StatusCode::OK);
    assert!(
        body.contains("tab-npt") && body.contains("2001:db8:50::/64"),
        "NPTv6 tab missing"
    );
}

#[tokio::test]
async fn radius_users_log_in_with_their_server_credentials_and_nothing_else_changes() {
    let t = setup().await;
    let c = t.admin().await;
    let srv = crate::radius::testserver::start(
        "shared-secret",
        vec![
            ("carol", "carols-radius-password"),
            ("admin", "radius-admin-password"),
        ],
    )
    .await;
    // no server yet: an unknown name is refused
    let (s, _, _) = t.login("carol", "carols-radius-password", None).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);

    let (s, b) = t
        .call(
            &c,
            Method::POST,
            "/api/system/auth-servers",
            Some(json!({"name":"corp","host":"127.0.0.1","port":srv.addr.port(),"secret":"shared-secret","default_role":"operator","timeout_secs":2})),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED, "{b}");
    // the list never shows the secret; admins only; a role of admin is refused
    let (_, b) = t
        .call(&c, Method::GET, "/api/system/auth-servers", None)
        .await;
    assert!(!b.to_string().contains("shared-secret"), "{b}");
    let (s, _) = t
        .call(
            &c,
            Method::POST,
            "/api/system/auth-servers",
            Some(json!({"name":"x","host":"h","secret":"s","default_role":"admin"})),
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);

    // carol logs in with her RADIUS password; the account is created with the default role
    let (s, cookie, b) = t.login("carol", "carols-radius-password", None).await;
    assert_eq!(s, StatusCode::OK, "{b}");
    assert_eq!(b["role"], "Operator");
    let cc = cookie.unwrap();
    let (s, me) = t.call(&cc, Method::GET, "/api/auth/me", None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(me["username"], "carol");
    // wrong password, and a password that only works locally for nobody
    let (s, _, _) = t.login("carol", "wrong", None).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    // the stored account has no usable local password
    let (_, users) = t.call(&c, Method::GET, "/api/system/users", None).await;
    let carol = users
        .as_array()
        .unwrap()
        .iter()
        .find(|u| u["username"] == "carol")
        .unwrap()
        .clone();
    assert_eq!(carol["role"], "Operator", "{carol}");
    assert!(
        !users.to_string().contains("!external"),
        "hash leaked: {users}"
    );

    // a local admin is never taken over by a RADIUS account of the same name
    let (s, _, _) = t.login("admin", "radius-admin-password", None).await;
    assert_eq!(
        s,
        StatusCode::UNAUTHORIZED,
        "RADIUS must not log in as a local-password account"
    );
    let (s, _, _) = t.login("admin", ADMIN_PW, None).await;
    assert_eq!(s, StatusCode::OK, "the local admin still logs in");

    // an admin can disable the external account: RADIUS acceptance no longer helps
    let id = carol["id"].as_i64().unwrap();
    let (s, _) = t
        .call(
            &c,
            Method::PUT,
            &format!("/api/system/users/{id}"),
            Some(json!({"enabled": false})),
        )
        .await;
    assert_eq!(s, StatusCode::OK);
    let (s, _, _) = t.login("carol", "carols-radius-password", None).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);

    // delete the server: carol (re-enabled) cannot log in any more
    let (s, _) = t
        .call(
            &c,
            Method::PUT,
            &format!("/api/system/users/{id}"),
            Some(json!({"enabled": true})),
        )
        .await;
    assert_eq!(s, StatusCode::OK);
    let (_, l) = t
        .call(&c, Method::GET, "/api/system/auth-servers", None)
        .await;
    let sid = l[0]["id"].as_i64().unwrap();
    let (s, _) = t
        .call(
            &c,
            Method::DELETE,
            &format!("/api/system/auth-servers/{sid}"),
            None,
        )
        .await;
    assert_eq!(s, StatusCode::OK);
    let (s, _, _) = t.login("carol", "carols-radius-password", None).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
}

#[cfg(feature = "qos")]
#[tokio::test]
async fn traffic_shaping_is_managed_through_the_api_and_undone_when_tc_refuses() {
    let dir = std::env::temp_dir().join(format!("patronus-web-qos-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("pw"), format!("{ADMIN_PW}\n")).unwrap();
    let mut state = state_at(&dir).await;
    let qos = Fake::new("qos", Phase::Services);
    state.lan = Arc::new(crate::state::LanManager::with_appliers(
        state.config_store.clone(),
        vec![qos.clone()],
    ));
    let app = super::build_router(state.clone(), Arc::new(crate::WsBroadcaster::new()));
    let t = T {
        app,
        state,
        dir,
        wg: Fake::new("wireguard", Phase::Interfaces),
        restore_fake: Fake::new("firewall", Phase::Firewall),
    };
    let c = t.admin().await;
    let (s, b) = t
        .call(
            &c,
            Method::POST,
            "/api/qos",
            Some(json!({"interface":"@wan","mode":"limit","rate_kbit":8000})),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED, "{b}");
    let id = b["id"].as_i64().unwrap();
    assert_eq!(qos.applies.load(Ordering::SeqCst), 1);
    for body in [
        json!({"interface":"@wan","mode":"fq_codel"}),
        json!({"interface":"@lan","mode":"cake"}),
        json!({"interface":"@lan","mode":"limit","rate_kbit":1}),
        json!({"interface":"@lan","mode":"teleport"}),
    ] {
        let (s, _) = t
            .call(&c, Method::POST, "/api/qos", Some(body.clone()))
            .await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{body}");
    }
    let (s, _) = t
        .call(
            &c,
            Method::PUT,
            &format!("/api/qos/{id}"),
            Some(json!({"rate_kbit": 16000})),
        )
        .await;
    assert_eq!(s, StatusCode::OK);
    qos.fail.store(true, Ordering::SeqCst);
    let (s, _) = t
        .call(
            &c,
            Method::PUT,
            &format!("/api/qos/{id}"),
            Some(json!({"rate_kbit": 99000})),
        )
        .await;
    assert_eq!(s, StatusCode::INTERNAL_SERVER_ERROR);
    qos.fail.store(false, Ordering::SeqCst);
    let (_, b) = t.call(&c, Method::GET, "/api/qos", None).await;
    assert_eq!(
        b["shapers"][0]["rate_kbit"], 16000,
        "refused change was not undone: {b}"
    );
    let (s, body, _) = t.raw(Method::GET, "/qos", Some(&c), None).await;
    assert_eq!(s, StatusCode::OK);
    assert!(body.contains("Traffic shaping") && body.contains("id=\"qos-form\""));
    let (s, _) = t
        .call(&c, Method::DELETE, &format!("/api/qos/{id}"), None)
        .await;
    assert_eq!(s, StatusCode::OK);
    let (s, _) = t
        .call(&c, Method::DELETE, &format!("/api/qos/{id}"), None)
        .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

#[cfg(feature = "syslog")]
#[tokio::test]
async fn feature_pages_validate_apply_undo_and_report_what_is_not_built() {
    let dir = std::env::temp_dir().join(format!("patronus-web-svc-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("pw"), format!("{ADMIN_PW}\n")).unwrap();
    let mut state = state_at(&dir).await;
    let syslog = Fake::new("syslog", Phase::Services);
    state.lan = Arc::new(crate::state::LanManager::with_appliers(
        state.config_store.clone(),
        vec![syslog.clone()],
    ));
    let app = super::build_router(state.clone(), Arc::new(crate::WsBroadcaster::new()));
    let t = T {
        app,
        state,
        dir,
        wg: Fake::new("wireguard", Phase::Interfaces),
        restore_fake: Fake::new("firewall", Phase::Firewall),
    };
    let c = t.admin().await;

    // the list of built features and one feature's overview with its schema
    let (s, b) = t.call(&c, Method::GET, "/api/svc", None).await;
    assert_eq!(s, StatusCode::OK);
    assert!(
        b.as_array().unwrap().iter().any(|f| f["slug"] == "syslog"),
        "{b}"
    );
    let (s, b) = t.call(&c, Method::GET, "/api/svc/syslog", None).await;
    assert_eq!(s, StatusCode::OK, "{b}");
    assert_eq!(b["schema"]["collections"][0]["key"], "targets");
    assert!(b["collections"]["targets"].as_array().unwrap().is_empty());

    // validation answers 400 and applies nothing
    for body in [
        json!({"host": "a b"}),
        json!({"host": "10.0.0.5", "port": 0}),
        json!({"host": "10.0.0.5", "proto": "icmp"}),
        json!({}),
    ] {
        let (s, _) = t
            .call(
                &c,
                Method::POST,
                "/api/svc/syslog/targets",
                Some(body.clone()),
            )
            .await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{body}");
    }
    assert_eq!(syslog.applies.load(Ordering::SeqCst), 0);

    // a valid row is stored and applied once; a refused edit is undone
    let (s, b) = t
        .call(
            &c,
            Method::POST,
            "/api/svc/syslog/targets",
            Some(json!({"host": "10.0.0.5", "severity": "warning"})),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED, "{b}");
    let id = b["id"].as_i64().unwrap();
    assert_eq!(syslog.applies.load(Ordering::SeqCst), 1);
    syslog.fail.store(true, Ordering::SeqCst);
    let (s, _) = t
        .call(
            &c,
            Method::PUT,
            &format!("/api/svc/syslog/targets/{id}"),
            Some(json!({"port": 6514})),
        )
        .await;
    assert_eq!(s, StatusCode::INTERNAL_SERVER_ERROR);
    syslog.fail.store(false, Ordering::SeqCst);
    let (_, b) = t.call(&c, Method::GET, "/api/svc/syslog", None).await;
    assert_eq!(
        b["collections"]["targets"][0]["port"], 514,
        "refused change was not undone: {b}"
    );

    // the page renders; a feature the binary was not built with says so
    let (s, body, _) = t.raw(Method::GET, "/svc/syslog", Some(&c), None).await;
    assert_eq!(s, StatusCode::OK);
    assert!(body.contains("svc-settings-form") && body.contains("Syslog"));
    let (s, _) = t.call(&c, Method::GET, "/api/svc/nothing", None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let (s, body, _) = t.raw(Method::GET, "/svc/nothing", Some(&c), None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    assert!(body.contains("Not part of this build"));

    // delete, twice
    let (s, _) = t
        .call(
            &c,
            Method::DELETE,
            &format!("/api/svc/syslog/targets/{id}"),
            None,
        )
        .await;
    assert_eq!(s, StatusCode::OK);
    let (s, _) = t
        .call(
            &c,
            Method::DELETE,
            &format!("/api/svc/syslog/targets/{id}"),
            None,
        )
        .await;
    assert_eq!(s, StatusCode::NOT_FOUND);

    // Wake-on-LAN keeps its hosts without an applier
    let (s, b) = t
        .call(
            &c,
            Method::POST,
            "/api/svc/wol/hosts",
            Some(json!({"name": "nas", "mac": "AA:BB:CC:DD:EE:FF"})),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED, "{b}");
    let (s, _) = t
        .call(
            &c,
            Method::POST,
            "/api/svc/wol/action/wake",
            Some(json!({"mac": "nope"})),
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
}
