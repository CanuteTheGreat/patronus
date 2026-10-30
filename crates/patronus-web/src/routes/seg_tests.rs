//! Router-level tests for device segmentation (lane s): page, API, undo on a
//! failed apply, read-only accounts and RBAC. The kernel side (nft table,
//! proxy ARP, isolated ports) is proven by ci/netlab/lane-s-segmentation.sh;
//! here the appliers are recorders that capture what would be loaded.

use async_trait::async_trait;
use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use patronus_config::applier::{ApplyReport, Phase};
use patronus_config::{Applier, ConfigStore};
use serde_json::{json, Value};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use tower::ServiceExt;

/// Stands in for the `firewall` applier: records the segmentation fragment the
/// real renderer produces from the store, fails on demand.
struct Fw {
    fail: AtomicBool,
    last: Mutex<String>,
    runs: Mutex<Vec<&'static str>>,
}

struct Rec {
    name: &'static str,
    phase: Phase,
    fw: Arc<Fw>,
}

#[async_trait]
impl Applier for Rec {
    fn name(&self) -> &'static str {
        self.name
    }
    fn phase(&self) -> Phase {
        self.phase
    }
    async fn apply(&self, s: &ConfigStore) -> patronus_core::Result<ApplyReport> {
        self.fw.runs.lock().unwrap().push(self.name);
        if self.name == "firewall" {
            if self.fw.fail.load(Ordering::SeqCst) {
                return Err(patronus_core::Error::Firewall(
                    "nft refused the ruleset".into(),
                ));
            }
            let r = patronus_firewall::seg_rules::seg_rules(s).await?;
            *self.fw.last.lock().unwrap() = r.script;
        }
        let mut r = ApplyReport::default();
        r.applied("ok");
        Ok(r)
    }
    async fn render(&self, _s: &ConfigStore) -> patronus_core::Result<String> {
        Ok(String::new())
    }
}

const ADMIN_PW: &str = "Seg-Admin-Passw0rd";

struct T {
    app: axum::Router,
    state: crate::AppState,
    fw: Arc<Fw>,
}

async fn setup() -> T {
    let dir = std::env::temp_dir().join(format!("patronus-web-seg-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("pw"), format!("{ADMIN_PW}\n")).unwrap();
    let store = Arc::new(ConfigStore::open(dir.join("config.db")).await.unwrap());
    let mut state =
        crate::AppState::new(store.clone(), Arc::new(crate::state::firewall::NoopApplier))
            .await
            .unwrap();
    state
        .auth
        .user_store
        .provision_admin(None, &dir.join("pw"))
        .await
        .unwrap();
    // a LAN: bridge br0 with 192.168.50.1/24, a DHCP pool .100-.199
    let p = store.pool().unwrap();
    for q in [
        "INSERT INTO interfaces (name, enabled, role, updated_at) VALUES ('br0',1,'lan',0)",
        "INSERT INTO interface_addresses (interface_name, address, prefix_len, family) VALUES ('br0','192.168.50.1',24,'ipv4')",
        "INSERT INTO dhcp_pools (interface, enabled, range_start, range_end, lease_time, updated_at) VALUES ('@lan',1,'192.168.50.100','192.168.50.199',3600,0)",
    ] {
        sqlx::query(q).execute(p).await.unwrap();
    }
    let fw = Arc::new(Fw {
        fail: AtomicBool::new(false),
        last: Mutex::new(String::new()),
        runs: Mutex::new(Vec::new()),
    });
    let mk = |name, phase| -> Arc<dyn Applier> {
        Arc::new(Rec {
            name,
            phase,
            fw: fw.clone(),
        })
    };
    state.lan = Arc::new(crate::state::LanManager::with_appliers(
        store,
        vec![
            mk("segmentation", Phase::Interfaces),
            mk("dhcp", Phase::Services),
            mk("wifi", Phase::Services),
            mk("firewall", Phase::Firewall),
        ],
    ));
    let app = super::build_router(state.clone(), Arc::new(crate::WsBroadcaster::new()));
    T { app, state, fw }
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

    async fn login(&self, user: &str, pw: &str) -> String {
        let (s, b, h) = self
            .raw(
                Method::POST,
                "/api/auth/login",
                None,
                Some(json!({"username": user, "password": pw}).to_string()),
            )
            .await;
        assert_eq!(s, StatusCode::OK, "{b}");
        h.get(header::SET_COOKIE)
            .map(|c| c.to_str().unwrap().split(';').next().unwrap().to_string())
            .unwrap()
    }

    async fn call(
        &self,
        c: &str,
        m: Method,
        uri: &str,
        body: Option<Value>,
    ) -> (StatusCode, Value) {
        let (s, b, _) = self.raw(m, uri, Some(c), body.map(|v| v.to_string())).await;
        (s, serde_json::from_str(&b).unwrap_or(Value::String(b)))
    }
}

#[tokio::test]
async fn upgrade_state_is_off_and_the_page_renders() {
    let t = setup().await;
    let c = t.login("admin", ADMIN_PW).await;
    let (s, v) = t.call(&c, Method::GET, "/api/segmentation", None).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(
        v["enforced"], false,
        "nothing is isolated until the operator opts in"
    );
    assert_eq!(v["segments"][0]["segment"], "@lan");
    assert_eq!(v["segments"][0]["enabled"], false);
    assert_eq!(v["segments"][0]["subnets"][0], "192.168.50.0/24");
    let names: Vec<&str> = v["groups"]
        .as_array()
        .unwrap()
        .iter()
        .map(|g| g["name"].as_str().unwrap())
        .collect();
    assert!(
        names.contains(&"home") && names.contains(&"quarantine"),
        "{names:?}"
    );
    assert!(v["notes"]["wired"]
        .as_str()
        .unwrap()
        .contains("unmanaged switch"));
    let (s, page, _) = t.raw(Method::GET, "/segmentation", Some(&c), None).await;
    assert_eq!(s, StatusCode::OK);
    assert!(
        page.contains("Device segmentation") && page.contains("seg-segments"),
        "page rendered"
    );
    assert!(page.contains("href=\"/segmentation\""), "nav link");
    // unauthenticated: login, not the page
    let (s, _, _) = t.raw(Method::GET, "/api/segmentation", None, None).await;
    assert!(
        s == StatusCode::UNAUTHORIZED || s == StatusCode::SEE_OTHER || s == StatusCode::FOUND,
        "{s}"
    );
}

#[tokio::test]
async fn enabling_adopts_then_devices_are_managed_and_revocation_reaches_the_ruleset() {
    let t = setup().await;
    let c = t.login("admin", ADMIN_PW).await;
    // a reservation that exists before isolation is turned on
    sqlx::query("INSERT INTO dhcp_static_mappings (pool_id, mac, ip, hostname, updated_at) VALUES (1,'02:aa:00:00:00:30','192.168.50.30','printer',0)")
        .execute(t.state.config_store.pool().unwrap())
        .await
        .unwrap();
    let (s, v) = t
        .call(
            &c,
            Method::POST,
            "/api/segmentation/segments",
            Some(json!({"segment": "@lan", "enabled": true})),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["adoption"]["adopted"].as_array().unwrap().len(), 1, "{v}");
    let script = t.fw.last.lock().unwrap().clone();
    assert!(
        script.contains("02:aa:00:00:00:30") && script.contains("hook forward priority -10"),
        "{script}"
    );
    assert_eq!(
        t.fw.runs
            .lock()
            .unwrap()
            .iter()
            .rev()
            .take(4)
            .cloned()
            .collect::<Vec<_>>(),
        vec!["wifi", "firewall", "dhcp", "segmentation"], // most recent first
        "L2 first, then DHCP reservations, then the firewall (a revoked device is cut there), then the access point"
    );

    // groups, a device, a link, a service
    let (s, g) = t
        .call(
            &c,
            Method::POST,
            "/api/segmentation/groups",
            Some(json!({"name": "iot", "intra": true, "internet": "allow"})),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED, "{g}");
    let (s, d) = t
        .call(&c, Method::POST, "/api/segmentation/devices", Some(json!({"name": "cam", "mac": "02:AA:00:00:00:40", "group": "iot", "segment": "@lan"})))
        .await;
    assert_eq!(s, StatusCode::CREATED, "{d}");
    assert_eq!(d["ip4"], "192.168.50.2", "outside the DHCP range");
    let cam = d["id"].as_i64().unwrap();
    let (s, _) = t
        .call(
            &c,
            Method::POST,
            "/api/segmentation/links",
            Some(json!({"a": "iot", "b": "home"})),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED);
    let (s, b) = t
        .call(&c, Method::POST, "/api/segmentation/services", Some(json!({"name": "p-cam", "src": "device:printer", "dst": "device:cam", "proto": "tcp", "ports": "8080"})))
        .await;
    assert_eq!(s, StatusCode::CREATED, "{b}");
    let script = t.fw.last.lock().unwrap().clone();
    assert!(
        script.contains("02:aa:00:00:00:40")
            && script.contains("th dport { 8080 }")
            && script.contains("link"),
        "{script}"
    );

    // revoke: re-rendered in the same request, device gone from every set
    let (s, r) = t
        .call(
            &c,
            Method::POST,
            &format!("/api/segmentation/devices/{cam}/revoke"),
            None,
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{r}");
    assert_eq!(r["state"], "revoked");
    let script = t.fw.last.lock().unwrap().clone();
    assert!(
        !script.contains("02:aa:00:00:00:40") && !script.contains("192.168.50.2,"),
        "{script}"
    );
    assert!(
        !script.contains("svc0_"),
        "the service rule to the revoked device is gone: {script}"
    );
    // the preview endpoint renders without applying
    let (s, p) = t
        .call(
            &c,
            Method::POST,
            "/api/segmentation/preview",
            Some(json!({})),
        )
        .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(p["active"], true);
    assert!(p["script"]
        .as_str()
        .unwrap()
        .contains("table inet patronus_seg"));
    // switching off renders a bare teardown
    let (s, _) = t
        .call(
            &c,
            Method::POST,
            "/api/segmentation/segments",
            Some(json!({"segment": "@lan", "enabled": false})),
        )
        .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(
        t.fw.last.lock().unwrap().as_str(),
        "add table inet patronus_seg\ndelete table inet patronus_seg\n"
    );
}

#[tokio::test]
async fn a_failed_apply_undoes_the_change() {
    let t = setup().await;
    let c = t.login("admin", ADMIN_PW).await;
    t.fw.fail.store(true, Ordering::SeqCst);
    let (s, b) = t
        .call(
            &c,
            Method::POST,
            "/api/segmentation/devices",
            Some(json!({"name": "tv", "mac": "02:aa:00:00:00:50"})),
        )
        .await;
    assert_eq!(s, StatusCode::INTERNAL_SERVER_ERROR, "{b}");
    assert!(b["error"].as_str().unwrap().contains("nft refused"));
    t.fw.fail.store(false, Ordering::SeqCst);
    let (_, v) = t
        .call(&c, Method::GET, "/api/segmentation/devices", None)
        .await;
    assert_eq!(v, json!([]), "store rolled back: {v}");
    let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM dhcp_static_mappings")
        .fetch_one(t.state.config_store.pool().unwrap())
        .await
        .unwrap();
    assert_eq!(n, 0, "the reservation went with it");
    // and enabling a segment that fails leaves it off
    t.fw.fail.store(true, Ordering::SeqCst);
    let (s, _) = t
        .call(
            &c,
            Method::POST,
            "/api/segmentation/segments",
            Some(json!({"segment": "@lan", "enabled": true})),
        )
        .await;
    assert_eq!(s, StatusCode::INTERNAL_SERVER_ERROR);
    t.fw.fail.store(false, Ordering::SeqCst);
    let (_, v) = t.call(&c, Method::GET, "/api/segmentation", None).await;
    assert_eq!(v["segments"][0]["enabled"], false);
}

#[tokio::test]
async fn bad_input_is_a_400_not_a_script() {
    let t = setup().await;
    let c = t.login("admin", ADMIN_PW).await;
    for (url, body) in [
        (
            "/api/segmentation/groups",
            json!({"name": "x\"; flush ruleset; \"", "internet": "allow"}),
        ),
        (
            "/api/segmentation/groups",
            json!({"name": "ok", "internet": "maybe"}),
        ),
        (
            "/api/segmentation/devices",
            json!({"name": "a b", "mac": "02:aa:00:00:00:50"}),
        ),
        (
            "/api/segmentation/devices",
            json!({"name": "a", "mac": "nope"}),
        ),
        (
            "/api/segmentation/devices",
            json!({"name": "a", "mac": "02:aa:00:00:00:50", "ip4": "10.9.9.9"}),
        ),
        ("/api/segmentation/links", json!({"a": "home", "b": "home"})),
        (
            "/api/segmentation/services",
            json!({"name": "s", "src": "device:ghost", "dst": "group:home", "proto": "tcp", "ports": "1"}),
        ),
        (
            "/api/segmentation/segments",
            json!({"segment": "lan\"; drop", "enabled": true}),
        ),
    ] {
        let (s, b) = t.call(&c, Method::POST, url, Some(body.clone())).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{url} {body}: {b}");
        assert!(b["error"].as_str().unwrap().contains("Invalid"), "{b}");
    }
    let (s, _) = t
        .call(&c, Method::DELETE, "/api/segmentation/devices/999", None)
        .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    // built-in groups cannot be deleted
    let (_, g) = t
        .call(&c, Method::GET, "/api/segmentation/groups", None)
        .await;
    let home = g
        .as_array()
        .unwrap()
        .iter()
        .find(|g| g["name"] == "home")
        .unwrap()["id"]
        .as_i64()
        .unwrap();
    let (s, _) = t
        .call(
            &c,
            Method::DELETE,
            &format!("/api/segmentation/groups/{home}"),
            None,
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn read_only_accounts_can_look_but_not_change() {
    let t = setup().await;
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
    let v = t.login("viewer", "Viewer-Passw0rd-1").await;
    let (s, _) = t.call(&v, Method::GET, "/api/segmentation", None).await;
    assert_eq!(s, StatusCode::OK);
    let (s, _) = t
        .call(
            &v,
            Method::POST,
            "/api/segmentation/groups",
            Some(json!({"name": "x", "internet": "allow"})),
        )
        .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (s, _) = t
        .call(
            &v,
            Method::POST,
            "/api/segmentation/segments",
            Some(json!({"segment": "@lan", "enabled": true})),
        )
        .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (_, page, _) = t.raw(Method::GET, "/segmentation", Some(&v), None).await;
    assert!(page.contains("const CAN_MODIFY = false"));
}

#[test]
fn segmentation_is_an_rbac_area() {
    assert!(crate::rbac::AREAS.iter().any(|(a, _)| *a == "segmentation"));
    assert_eq!(
        crate::rbac::area_for_path("/api/segmentation/devices"),
        Some("segmentation")
    );
    assert_eq!(
        crate::rbac::area_for_path("/segmentation"),
        Some("segmentation")
    );
    assert!(patronus_config::accounts::AREAS.contains(&"segmentation"));
}

// ---- per-device Wi-Fi credentials (USE=wifi-ap) -----------------------------------

#[cfg(feature = "wifi-ap")]
mod wifi {
    use super::*;

    async fn net(t: &T, c: &str, security: &str) -> i64 {
        let (s, b) = t
            .call(
                c,
                Method::POST,
                "/api/segmentation/wifi/networks",
                Some(json!({"name": "home", "ssid": "HomeNet", "ifname": "wlan0", "security": security, "segment": "@lan"})),
            )
            .await;
        assert_eq!(s, StatusCode::CREATED, "{b}");
        b["id"].as_i64().unwrap()
    }

    #[tokio::test]
    async fn a_device_gets_its_own_passphrase_once_and_no_listing_carries_it() {
        let t = setup().await;
        let c = t.login("admin", ADMIN_PW).await;
        net(&t, &c, "wpa2").await;
        let (s, d) = t
            .call(
                &c,
                Method::POST,
                "/api/segmentation/wifi/devices",
                Some(json!({"name": "phone", "network": "home"})),
            )
            .await;
        assert_eq!(s, StatusCode::CREATED, "{d}");
        let secret = d["secret"].as_str().unwrap().to_string();
        assert_eq!(secret.len(), 23);
        assert_eq!(d["device"]["state"], "pending");
        assert!(d["qr"]
            .as_str()
            .unwrap()
            .starts_with("WIFI:T:WPA;S:HomeNet;P:"));
        assert!(d["qr_svg"].as_str().unwrap().contains("<svg"));
        // nothing that lists things shows the secret
        for url in [
            "/api/segmentation/wifi",
            "/api/segmentation",
            "/api/segmentation/devices",
            "/api/segmentation/wifi/stations",
        ] {
            let (_, body, _) = t.raw(Method::GET, url, Some(&c), None).await;
            assert!(!body.contains(&secret), "{url} leaked a passphrase");
        }
        // the hostapd side would be applied
        assert!(t.fw.runs.lock().unwrap().contains(&"wifi"));
        // revealing needs an administrator and leaves an audit row
        let cid = d["credential_id"].as_i64().unwrap();
        let (s, r) = t
            .call(
                &c,
                Method::POST,
                &format!("/api/segmentation/wifi/credentials/{cid}/reveal"),
                Some(json!({})),
            )
            .await;
        assert_eq!(s, StatusCode::OK, "{r}");
        assert_eq!(r["secret"], secret.as_str());
        let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM audit_log WHERE action = 'reveal' AND entity_type = 'wifi_credential'")
            .fetch_one(t.state.config_store.pool().unwrap())
            .await
            .unwrap();
        assert_eq!(n, 1, "an audited reveal");
        // an operator (not an admin) cannot
        t.state
            .auth
            .user_store
            .create_user(
                "op".into(),
                "Operator-Passw0rd-1",
                crate::auth::UserRole::Operator,
            )
            .await
            .unwrap();
        let o = t.login("op", "Operator-Passw0rd-1").await;
        let (s, _) = t
            .call(
                &o,
                Method::POST,
                &format!("/api/segmentation/wifi/credentials/{cid}/reveal"),
                Some(json!({})),
            )
            .await;
        assert_eq!(s, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn revoke_and_rotate_reach_the_applier_and_enrolment_secret_is_admin_only() {
        let t = setup().await;
        let c = t.login("admin", ADMIN_PW).await;
        net(&t, &c, "wpa2").await;
        let (_, d) = t
            .call(
                &c,
                Method::POST,
                "/api/segmentation/wifi/devices",
                Some(json!({"name": "laptop", "network": "home", "mac": "02:AA:00:00:00:11"})),
            )
            .await;
        assert_eq!(d["device"]["state"], "active");
        let did = d["device"]["id"].as_i64().unwrap();
        let old = d["secret"].as_str().unwrap().to_string();
        let (s, r) = t
            .call(
                &c,
                Method::POST,
                &format!("/api/segmentation/wifi/devices/{did}/rotate"),
                Some(json!({"grace_minutes": 0})),
            )
            .await;
        assert_eq!(s, StatusCode::OK, "{r}");
        assert_ne!(r["secret"], old.as_str());
        let (_, w) = t
            .call(&c, Method::GET, "/api/segmentation/wifi", None)
            .await;
        let creds = w["credentials"].as_array().unwrap();
        assert_eq!(creds.iter().filter(|c| c["state"] == "active").count(), 1);
        assert_eq!(
            creds.iter().filter(|c| c["state"] == "revoked").count(),
            1,
            "the old passphrase is revoked"
        );
        let cid = creds.iter().find(|c| c["state"] == "active").unwrap()["id"]
            .as_i64()
            .unwrap();
        let (s, _) = t
            .call(
                &c,
                Method::POST,
                &format!("/api/segmentation/wifi/credentials/{cid}/revoke"),
                Some(json!({})),
            )
            .await;
        assert_eq!(s, StatusCode::OK);
        let (s, _) = t
            .call(
                &c,
                Method::POST,
                &format!("/api/segmentation/wifi/credentials/{cid}/revoke"),
                Some(json!({})),
            )
            .await;
        assert_eq!(s, StatusCode::NOT_FOUND, "already revoked");
        // enrolment network: the shared secret is shown only through the audited admin reveal
        let (s, b) = t
            .call(&c, Method::POST, "/api/segmentation/wifi/networks", Some(json!({"name": "guests", "ssid": "Guests", "ifname": "wlan1", "unknown_policy": "enrol"})))
            .await;
        assert_eq!(s, StatusCode::CREATED, "{b}");
        let nid = b["id"].as_i64().unwrap();
        let (_, w) = t
            .call(&c, Method::GET, "/api/segmentation/wifi", None)
            .await;
        let guests = w["networks"]
            .as_array()
            .unwrap()
            .iter()
            .find(|n| n["name"] == "guests")
            .unwrap()
            .clone();
        assert_eq!(guests["has_enrol_secret"], true);
        assert!(guests.get("enrol_secret").is_none());
        let (s, r) = t
            .call(
                &c,
                Method::POST,
                &format!("/api/segmentation/wifi/networks/{nid}/enrol-secret/reveal"),
                Some(json!({})),
            )
            .await;
        assert_eq!(s, StatusCode::OK, "{r}");
        assert_eq!(r["secret"].as_str().unwrap().len(), 23);
    }

    #[tokio::test]
    async fn bad_wifi_input_is_a_400_and_a_failed_apply_undoes_it() {
        let t = setup().await;
        let c = t.login("admin", ADMIN_PW).await;
        for body in [
            json!({"name": "x", "ssid": "bad\nssid", "ifname": "wlan0"}),
            json!({"name": "x", "ssid": "ok", "ifname": "wlan0; reboot"}),
            json!({"name": "x", "ssid": "ok", "ifname": "wlan0", "channel": 99}),
            json!({"name": "x", "ssid": "ok", "ifname": "wlan0", "security": "open"}),
            json!({"name": "x", "ssid": "ok", "ifname": "wlan0", "country": "usa"}),
        ] {
            let (s, b) = t
                .call(
                    &c,
                    Method::POST,
                    "/api/segmentation/wifi/networks",
                    Some(body.clone()),
                )
                .await;
            assert_eq!(s, StatusCode::BAD_REQUEST, "{body}: {b}");
        }
        net(&t, &c, "wpa3").await;
        let (s, _) = t
            .call(
                &c,
                Method::POST,
                "/api/segmentation/wifi/devices",
                Some(json!({"name": "phone", "network": "home"})),
            )
            .await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "WPA3-only needs a MAC");
        t.fw.fail.store(true, Ordering::SeqCst);
        let (s, _) = t
            .call(
                &c,
                Method::POST,
                "/api/segmentation/wifi/devices",
                Some(json!({"name": "phone", "network": "home", "mac": "02:aa:00:00:00:21"})),
            )
            .await;
        assert_eq!(s, StatusCode::INTERNAL_SERVER_ERROR);
        t.fw.fail.store(false, Ordering::SeqCst);
        let (_, w) = t
            .call(&c, Method::GET, "/api/segmentation/wifi", None)
            .await;
        assert_eq!(w["credentials"], json!([]), "rolled back");
        let (_, d) = t
            .call(&c, Method::GET, "/api/segmentation/devices", None)
            .await;
        assert_eq!(d, json!([]));
    }
}
