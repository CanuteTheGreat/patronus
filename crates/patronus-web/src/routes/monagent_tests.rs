//! Router-level tests for the monitoring-agent pages (Zabbix agent, Telegraf) and
//! the typed `/metrics` settings. The daemons are proven by the applier tests in
//! patronus-network and by ci/netlab/lane-u-monagents.sh; here the appliers are
//! recorders so the API, validation, secret masking, the audit log, undo on a
//! refused apply and the `/metrics` gate can be checked anywhere.

use async_trait::async_trait;
use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{header, Method, Request, StatusCode};
use patronus_config::applier::{ApplyReport, Phase};
use patronus_config::{Applier, ConfigStore};
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use tower::ServiceExt;

struct Fake {
    name: &'static str,
    fail: AtomicBool,
    applies: AtomicUsize,
}

#[async_trait]
impl Applier for Fake {
    fn name(&self) -> &'static str {
        self.name
    }
    fn phase(&self) -> Phase {
        Phase::Services
    }
    async fn apply(&self, _s: &ConfigStore) -> patronus_core::Result<ApplyReport> {
        self.applies.fetch_add(1, Ordering::SeqCst);
        if self.fail.load(Ordering::SeqCst) {
            return Err(patronus_core::Error::Network("agent refused it".into()));
        }
        let mut r = ApplyReport::default();
        r.applied("ok");
        Ok(r)
    }
    async fn render(&self, _s: &ConfigStore) -> patronus_core::Result<String> {
        Ok(String::new())
    }
    async fn status(&self, _s: &ConfigStore) -> patronus_core::Result<Value> {
        Ok(json!({}))
    }
}

const ADMIN_PW: &str = "Mon-Agents-Admin-Passw0rd";

struct T {
    app: axum::Router,
    state: crate::AppState,
    zabbix: Arc<Fake>,
    telegraf: Arc<Fake>,
}

async fn setup() -> T {
    let dir = std::env::temp_dir().join(format!("patronus-web-monagent-{}", uuid::Uuid::new_v4()));
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
    let mk = |name| {
        Arc::new(Fake {
            name,
            fail: AtomicBool::new(false),
            applies: AtomicUsize::new(0),
        })
    };
    let (zabbix, telegraf) = (mk("zabbix"), mk("telegraf"));
    state.lan = Arc::new(crate::state::LanManager::with_appliers(
        state.config_store.clone(),
        vec![zabbix.clone(), telegraf.clone()],
    ));
    let app = super::build_router(state.clone(), Arc::new(crate::WsBroadcaster::new()));
    T {
        app,
        state,
        zabbix,
        telegraf,
    }
}

impl T {
    async fn send(
        &self,
        m: Method,
        uri: &str,
        headers: &[(header::HeaderName, String)],
        peer: Option<&str>,
        body: Option<String>,
    ) -> (StatusCode, String, axum::http::HeaderMap) {
        let mut b = Request::builder().method(m).uri(uri);
        for (k, v) in headers {
            b = b.header(k, v);
        }
        if body.is_some() {
            b = b.header(header::CONTENT_TYPE, "application/json");
        }
        let mut req = b
            .body(body.map(Body::from).unwrap_or_else(Body::empty))
            .unwrap();
        if let Some(p) = peer {
            let addr: SocketAddr = format!("{p}:40000").parse().unwrap();
            req.extensions_mut().insert(ConnectInfo(addr));
        }
        let r = self.app.clone().oneshot(req).await.unwrap();
        let (s, h) = (r.status(), r.headers().clone());
        let bytes = axum::body::to_bytes(r.into_body(), 16 << 20).await.unwrap();
        (s, String::from_utf8_lossy(&bytes).into_owned(), h)
    }

    async fn admin(&self) -> String {
        let (s, b, h) = self
            .send(
                Method::POST,
                "/api/auth/login",
                &[],
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
            .send(
                m,
                uri,
                &[(header::COOKIE, cookie.to_string())],
                None,
                body.map(|v| v.to_string()),
            )
            .await;
        (s, serde_json::from_str(&b).unwrap_or(Value::String(b)))
    }
}

#[tokio::test]
async fn zabbix_page_validates_masks_the_key_applies_and_undoes() {
    let t = setup().await;
    let c = t.admin().await;
    let (s, b) = t.call(&c, Method::GET, "/api/svc", None).await;
    assert_eq!(s, StatusCode::OK);
    for slug in ["zabbix", "telegraf", "metrics"] {
        assert!(
            b.as_array().unwrap().iter().any(|f| f["slug"] == slug),
            "{slug} not listed: {b}"
        );
    }
    let (s, b) = t.call(&c, Method::GET, "/api/svc/zabbix", None).await;
    assert_eq!(s, StatusCode::OK, "{b}");
    assert_eq!(b["settings"]["enabled"], false, "off by default");
    assert_eq!(b["settings"]["listen_port"], 10050);
    assert_eq!(
        b["settings"]["listen_iface"], "@lan",
        "the LAN only, by default"
    );
    assert_eq!(b["settings"]["remote_commands"], "off");
    let keys: Vec<&str> = b["schema"]["fields"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["key"].as_str().unwrap())
        .collect();
    for k in [
        "enabled",
        "hostname",
        "listen_iface",
        "listen_port",
        "psk_identity",
        "psk",
        "active_server",
    ] {
        assert!(keys.contains(&k), "no {k}: {keys:?}");
    }
    assert_eq!(b["schema"]["collections"][0]["key"], "servers");

    // bad input: 400, nothing applied
    for body in [
        json!({"psk": "not-hex-not-hex-not-hex-not-hex-xx"}),
        json!({"remote_commands": "on"}),
        json!({"listen_port": 0}),
        json!({"hostname": "a\nb"}),
        json!({"active_server": "bad host"}),
        json!({"surprise": 1}),
    ] {
        let (s, b) = t
            .call(&c, Method::PUT, "/api/svc/zabbix", Some(body.clone()))
            .await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{body} -> {b}");
    }
    let (s, _) = t
        .call(
            &c,
            Method::POST,
            "/api/svc/zabbix/servers",
            Some(json!({"host": "x;rm"})),
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert_eq!(t.zabbix.applies.load(Ordering::SeqCst), 0);

    let psk = "0123456789abcdef0123456789abcdef";
    let (s, b) = t
        .call(
            &c,
            Method::PUT,
            "/api/svc/zabbix",
            Some(json!({"enabled": true, "psk": psk, "psk_identity": "rtr"})),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{b}");
    assert_eq!(t.zabbix.applies.load(Ordering::SeqCst), 1);
    let (s, _) = t
        .call(
            &c,
            Method::POST,
            "/api/svc/zabbix/servers",
            Some(json!({"host": "zbx.example.net"})),
        )
        .await;
    assert!(s.is_success(), "{s}");
    let (_, b) = t.call(&c, Method::GET, "/api/svc/zabbix", None).await;
    assert_eq!(
        b["settings"]["psk"], "********",
        "the key is never returned"
    );
    assert!(!b.to_string().contains(psk));
    assert_eq!(b["collections"]["servers"][0]["host"], "zbx.example.net");
    let audit: Vec<String> = sqlx::query_scalar("SELECT COALESCE(details, '') FROM audit_log")
        .fetch_all(t.state.config_store.pool().unwrap())
        .await
        .unwrap();
    assert!(audit.iter().all(|d| !d.contains(psk)), "{audit:?}");
    // writing the mask back keeps the stored key
    let (s, _) = t
        .call(
            &c,
            Method::PUT,
            "/api/svc/zabbix",
            Some(json!({"psk": "********", "listen_port": 10051})),
        )
        .await;
    assert_eq!(s, StatusCode::OK);
    let stored: Option<String> =
        sqlx::query_scalar("SELECT value FROM lan_settings WHERE key = 'zabbix.psk'")
            .fetch_optional(t.state.config_store.pool().unwrap())
            .await
            .unwrap();
    assert_eq!(stored.as_deref(), Some(psk));

    // a refused apply is undone
    t.zabbix.fail.store(true, Ordering::SeqCst);
    let (s, _) = t
        .call(
            &c,
            Method::PUT,
            "/api/svc/zabbix",
            Some(json!({"listen_port": 10099})),
        )
        .await;
    assert!(s.is_server_error() || s == StatusCode::BAD_REQUEST, "{s}");
    let (_, b) = t.call(&c, Method::GET, "/api/svc/zabbix", None).await;
    assert_eq!(b["settings"]["listen_port"], 10051, "undone");
}

#[tokio::test]
async fn telegraf_page_validates_the_url_and_masks_the_token() {
    let t = setup().await;
    let c = t.admin().await;
    let (s, b) = t.call(&c, Method::GET, "/api/svc/telegraf", None).await;
    assert_eq!(s, StatusCode::OK, "{b}");
    assert_eq!(b["settings"]["output"], "prometheus_client");
    assert_eq!(b["settings"]["listen_port"], 9273);
    assert_eq!(b["settings"]["in_conntrack"], true);
    assert_eq!(
        b["settings"]["in_nft"], false,
        "the privileged input is opt-in"
    );
    for body in [
        json!({"url": "http://x\"y"}),
        json!({"url": "ftp://host"}),
        json!({"url": "http://h\nx"}),
        json!({"output": "exec"}),
        json!({"interval": 1}),
        json!({"nft_tables": "inet x; drop"}),
        json!({"token": "short"}),
    ] {
        let (s, b) = t
            .call(&c, Method::PUT, "/api/svc/telegraf", Some(body.clone()))
            .await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{body} -> {b}");
    }
    assert_eq!(t.telegraf.applies.load(Ordering::SeqCst), 0);
    let (s, b) = t
        .call(
            &c,
            Method::PUT,
            "/api/svc/telegraf",
            Some(json!({"enabled": true, "output": "influxdb_v2", "url": "https://influx.example:8086",
                        "token": "tok-0123456789", "organization": "home", "bucket": "router"})),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{b}");
    let (_, b) = t.call(&c, Method::GET, "/api/svc/telegraf", None).await;
    assert_eq!(b["settings"]["token"], "********");
    assert!(!b.to_string().contains("tok-0123456789"));
}

#[tokio::test]
async fn metrics_endpoint_follows_its_typed_settings() {
    let t = setup().await;
    let c = t.admin().await;
    let cookie = |c: &str| vec![(header::COOKIE, c.to_string())];
    let get = |hs: Vec<(header::HeaderName, String)>, peer: Option<&'static str>| {
        let t = &t;
        async move { t.send(Method::GET, "/metrics", &hs, peer, None).await }
    };
    // defaults = today's behaviour: a login is required, a session is enough
    assert_eq!(
        get(vec![], Some("192.168.50.9")).await.0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        get(cookie(&c), Some("192.168.50.9")).await.0,
        StatusCode::OK
    );

    // a scrape token replaces the login for /metrics only
    let (s, _) = t
        .call(
            &c,
            Method::PUT,
            "/api/svc/metrics",
            Some(json!({"token": "scrape-token-123"})),
        )
        .await;
    assert_eq!(s, StatusCode::OK);
    let bearer = |v: &str| vec![(header::AUTHORIZATION, format!("Bearer {v}"))];
    let (s, body, _) = get(bearer("scrape-token-123"), Some("192.168.50.9")).await;
    assert_eq!(s, StatusCode::OK);
    assert!(body.contains("patronus_"), "{body}");
    assert_eq!(
        get(bearer("scrape-token-124"), Some("192.168.50.9"))
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    // the token opens nothing else
    let (s, _, _) = t
        .send(
            Method::GET,
            "/api/status",
            &bearer("scrape-token-123"),
            Some("192.168.50.9"),
            None,
        )
        .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    // and is never shown
    let (_, b) = t.call(&c, Method::GET, "/api/svc/metrics", None).await;
    assert_eq!(b["settings"]["token"], "********");

    // an allowed source network binds everyone, token and session included
    let (s, _) = t
        .call(
            &c,
            Method::PUT,
            "/api/svc/metrics",
            Some(json!({"allowed_source": "192.168.50.0/24"})),
        )
        .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(
        get(bearer("scrape-token-123"), Some("192.168.50.9"))
            .await
            .0,
        StatusCode::OK
    );
    assert_eq!(
        get(bearer("scrape-token-123"), Some("203.0.113.5")).await.0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        get(cookie(&c), Some("203.0.113.5")).await.0,
        StatusCode::FORBIDDEN
    );
    let (s, _) = t
        .call(
            &c,
            Method::PUT,
            "/api/svc/metrics",
            Some(json!({"allowed_source": "not a network"})),
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);

    // the switch: off answers 404 to everybody
    let (s, _) = t
        .call(
            &c,
            Method::PUT,
            "/api/svc/metrics",
            Some(json!({"enabled": false})),
        )
        .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(
        get(bearer("scrape-token-123"), Some("192.168.50.9"))
            .await
            .0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        get(cookie(&c), Some("192.168.50.9")).await.0,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn navigation_lists_the_monitoring_pages() {
    let t = setup().await;
    let c = t.admin().await;
    let (s, body, _) = t
        .send(
            Method::GET,
            "/svc/zabbix",
            &[(header::COOKIE, c.clone())],
            None,
            None,
        )
        .await;
    assert_eq!(s, StatusCode::OK);
    for href in ["/svc/metrics", "/svc/zabbix", "/svc/telegraf"] {
        assert!(
            body.contains(&format!("href=\"{href}\"")),
            "{href} missing from the menu"
        );
    }
}
