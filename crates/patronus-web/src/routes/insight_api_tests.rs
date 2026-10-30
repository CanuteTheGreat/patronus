//! The insight history and uplink health API, driven through the real
//! router with a logged-in session: honest empty states, validation, the
//! numbers that were recorded, privacy controls and the probe configuration.

use crate::state::{insight, uplink};
use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use serde_json::{json, Value};
use std::sync::Arc;
use tower::ServiceExt;

struct App {
    app: axum::Router,
    cookie: String,
    store: Arc<patronus_config::ConfigStore>,
}

async fn app() -> App {
    let dir = std::env::temp_dir().join(format!("patronus-web-insight-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let store = Arc::new(
        patronus_config::ConfigStore::open(dir.join("config.db"))
            .await
            .unwrap(),
    );
    let state = crate::AppState::new(store.clone(), Arc::new(crate::state::firewall::NoopApplier))
        .await
        .unwrap();
    let pw = "Insight-Test-Passw0rd!".to_string();
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
    async fn call(&self, m: Method, uri: &str, body: Option<Value>) -> (StatusCode, Value) {
        let body = body.map(|b| b.to_string());
        let r = self
            .app
            .clone()
            .oneshot(req(m, uri, Some(&self.cookie), body.as_deref()))
            .await
            .unwrap();
        let status = r.status();
        let bytes = axum::body::to_bytes(r.into_body(), 10 << 20).await.unwrap();
        let text = String::from_utf8_lossy(&bytes).into_owned();
        for f in super::honesty_tests::FIXTURE_MARKERS {
            assert!(!text.contains(f), "{uri} answered fixture text {f:?}");
        }
        (
            status,
            serde_json::from_str(&text).unwrap_or(Value::String(text)),
        )
    }
    async fn get(&self, uri: &str) -> (StatusCode, Value) {
        self.call(Method::GET, uri, None).await
    }
}

fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

fn row(ip: &str, dir: &'static str, cc: &str, asn: u32, bytes: u64) -> insight::UsageRow {
    insight::UsageRow {
        key: (insight::bucket_of(now()), ip.into(), dir, cc.into(), asn),
        org: format!("Org of AS{asn}"),
        agg: insight::Agg {
            bytes,
            packets: bytes / 100,
            flows: 2,
        },
    }
}

#[tokio::test]
async fn an_empty_router_answers_with_empty_states_not_invented_numbers() {
    let a = app().await;
    for path in ["/api/insights/countries", "/api/insights/asns"] {
        let (s, v) = a.get(path).await;
        assert_eq!(s, StatusCode::OK, "{path}: {v}");
        assert_eq!(v["rows"], json!([]));
        assert_eq!(v["recorded_rows"], 0);
        assert_eq!(
            v["databases"]["country"]["present"], false,
            "no database downloaded: said so"
        );
        assert_eq!(v["databases"]["asn"]["present"], false);
        assert!(v["databases"]["attribution"]
            .as_str()
            .unwrap()
            .contains("DB-IP"));
    }
    let (s, v) = a.get("/api/insights/devices").await;
    assert_eq!(
        (s, &v["rows"], &v["segmentation"]),
        (StatusCode::OK, &json!([]), &json!(false))
    );
    let (s, v) = a.get("/api/uplinks/sla").await;
    assert_eq!((s, &v["sla"]), (StatusCode::OK, &json!([])));
    let (s, v) = a.get("/api/uplinks/health").await;
    assert_eq!((s, &v["samples"]), (StatusCode::OK, &json!([])));
    let (s, v) = a.get("/api/uplinks/outages").await;
    assert_eq!((s, &v["outages"]), (StatusCode::OK, &json!([])));
    let (s, v) = a.get("/api/uplinks/probes").await;
    assert_eq!((s, &v["rows"]), (StatusCode::OK, &json!([])));
    let (s, v) = a.get("/api/insights/settings").await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(
        (
            v["enabled"].clone(),
            v["retention_days"].clone(),
            v["top_n"].clone()
        ),
        (json!(true), json!(30), json!(200))
    );
    let (s, v) = a.get("/api/insights/database").await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v["asn"]["present"], false);
    assert!(v["default_asn_url"]
        .as_str()
        .unwrap()
        .contains("dbip-asn-lite-"));
    let (s, page) = a.call(Method::GET, "/insights", None).await;
    assert_eq!(s, StatusCode::OK);
    let page = page.as_str().unwrap();
    for id in [
        "tab-countries",
        "tab-asns",
        "tab-devices",
        "tab-uplinks",
        "tab-settings",
        "uplink-cards",
        "probe-form",
        "DB-IP",
    ] {
        assert!(page.contains(id), "page lacks {id}");
    }
}

#[tokio::test]
async fn bad_parameters_are_400_unknown_devices_404() {
    let a = app().await;
    for q in [
        "window=5m",
        "window=abc",
        "window=",
        "limit=0",
        "limit=5000",
        "limit=x",
    ] {
        let (s, v) = a.get(&format!("/api/insights/countries?{q}")).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{q}: {v}");
    }
    let (s, _) = a.get("/api/insights/asns?device=nonesuch").await;
    assert_eq!(
        s,
        StatusCode::NOT_FOUND,
        "a device name that does not exist"
    );
    let (s, _) = a.get("/api/insights/asns?device=192.168.50.10").await;
    assert_eq!(s, StatusCode::OK, "an address always works");
    let (s, _) = a.get("/api/insights/devices/nonesuch").await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    for q in ["since=abc", "since=-5", "points=3", "points=99999"] {
        let (s, _) = a.get(&format!("/api/uplinks/health?{q}")).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{q}");
    }
    let (s, _) = a.get("/api/uplinks/sla?window=2m").await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let (s, _) = a
        .call(
            Method::PUT,
            "/api/insights/settings",
            Some(json!({"retention_days": 0})),
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let (s, _) = a
        .call(
            Method::PUT,
            "/api/insights/database",
            Some(json!({"asn_url": "ftp://x/y"})),
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let (s, _) = a
        .call(
            Method::PUT,
            "/api/uplinks/settings",
            Some(json!({"sla_target": 101})),
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let (s, _) = a
        .call(
            Method::POST,
            "/api/insights/exclusions",
            Some(json!({"kind": "ip", "ref": "nonsense"})),
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let (s, _) = a
        .call(
            Method::DELETE,
            "/api/insights/exclusions?kind=ip&ref=10.0.0.1",
            None,
        )
        .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let (s, _) = a
        .call(Method::DELETE, "/api/insights/exclusions", None)
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn recorded_traffic_is_ranked_per_country_asn_and_device() {
    let a = app().await;
    insight::flush(
        &a.store,
        &[
            row("192.168.50.10", "down", "AU", 64500, 9000),
            row("192.168.50.10", "up", "AU", 64500, 1000),
            row("192.168.50.20", "down", "DE", 64501, 500),
            row("192.168.50.20", "down", "--", 0, 70),
        ],
    )
    .await
    .unwrap();
    let (s, v) = a.get("/api/insights/countries?window=24h").await;
    assert_eq!(s, StatusCode::OK);
    let r = v["rows"].as_array().unwrap();
    assert_eq!(
        r.iter()
            .map(|x| x["country"].as_str().unwrap())
            .collect::<Vec<_>>(),
        ["AU", "DE", "--"]
    );
    assert_eq!(
        (
            r[0]["down_bytes"].clone(),
            r[0]["up_bytes"].clone(),
            r[0]["bytes"].clone()
        ),
        (json!(9000), json!(1000), json!(10000))
    );
    assert_eq!(v["recorded_rows"], 4);
    let (_, v) = a.get("/api/insights/asns?device=192.168.50.20").await;
    let r = v["rows"].as_array().unwrap();
    assert_eq!(r.len(), 2, "only that device's networks: {v}");
    assert_eq!(
        (r[0]["asn"].clone(), r[0]["org"].clone()),
        (json!(64501), json!("Org of AS64501"))
    );
    let (_, v) = a.get("/api/insights/devices").await;
    assert_eq!(v["rows"][0]["ip"], "192.168.50.10");
    assert_eq!(v["rows"][0]["top_country"], "AU");
    assert_eq!(
        v["rows"][0]["device"],
        Value::Null,
        "no device model: keyed by IP"
    );
    let (s, v) = a.get("/api/insights/devices/192.168.50.10?window=7d").await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v["ips"], json!(["192.168.50.10"]));
    assert_eq!(v["countries"][0]["country"], "AU");
    let tl = v["timeline"].as_array().unwrap();
    assert!(
        tl.len() >= 168,
        "zero-filled hourly points over 7 days: {}",
        tl.len()
    );
    assert_eq!(
        tl.iter()
            .map(|p| p["down_bytes"].as_i64().unwrap())
            .sum::<i64>(),
        9000
    );
    let (_, v) = a.get("/api/insights/timeline?window=1h").await;
    assert!(!v["points"].as_array().unwrap().is_empty());
    // a window that excludes the data
    let b = insight::bucket_of(now()) - 3 * 86_400;
    sqlx::query("UPDATE ins_usage SET bucket = ?")
        .bind(b)
        .execute(a.store.pool().unwrap())
        .await
        .unwrap();
    let (_, v) = a.get("/api/insights/countries?window=24h").await;
    assert_eq!(v["rows"], json!([]));
    let (_, v) = a.get("/api/insights/countries?window=7d").await;
    assert_eq!(v["rows"].as_array().unwrap().len(), 3);
}

#[tokio::test]
async fn privacy_exclusions_forget_history_and_clearing_deletes_everything() {
    let a = app().await;
    insight::flush(
        &a.store,
        &[
            row("192.168.50.10", "down", "AU", 1, 100),
            row("192.168.60.5", "down", "AU", 1, 100),
        ],
    )
    .await
    .unwrap();
    let (s, v) = a
        .call(
            Method::POST,
            "/api/insights/exclusions",
            Some(json!({"kind": "ip", "ref": "192.168.60.0/24"})),
        )
        .await;
    assert_eq!(
        (s, v["forgotten_rows"].clone()),
        (StatusCode::CREATED, json!(1))
    );
    let (_, v) = a.get("/api/insights/devices").await;
    assert_eq!(v["rows"].as_array().unwrap().len(), 1);
    let (_, v) = a.get("/api/insights/exclusions").await;
    assert_eq!(v["rows"], json!([{"kind": "ip", "ref": "192.168.60.0/24"}]));
    let (s, _) = a
        .call(
            Method::DELETE,
            "/api/insights/exclusions?kind=ip&ref=192.168.60.0%2F24",
            None,
        )
        .await;
    assert_eq!(s, StatusCode::OK);
    let (s, v) = a.call(Method::DELETE, "/api/insights/history", None).await;
    assert_eq!((s, v["deleted_rows"].clone()), (StatusCode::OK, json!(1)));
    let (_, v) = a.get("/api/insights/countries").await;
    assert_eq!(v["recorded_rows"], 0);
    // both changes are audited
    let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM audit_log WHERE entity_type IN ('insight_exclusion','insight_history')")
        .fetch_one(a.store.pool().unwrap())
        .await
        .unwrap();
    assert_eq!(n, 2);
}

#[tokio::test]
async fn settings_round_trip_and_switching_collection_off_is_reported() {
    let a = app().await;
    let (s, v) = a
        .call(
            Method::PUT,
            "/api/insights/settings",
            Some(json!({"enabled": false, "retention_days": 14, "top_n": 50})),
        )
        .await;
    assert_eq!(
        (s, v["retention_days"].clone(), v["enabled"].clone()),
        (StatusCode::OK, json!(14), json!(false))
    );
    let (_, v) = a.get("/api/insights/countries").await;
    assert_eq!(
        v["settings"]["enabled"], false,
        "the page can say collection is off"
    );
    let (s, v) = a
        .call(
            Method::PUT,
            "/api/insights/database",
            Some(json!({"asn_url": "https://mirror.example/asn.csv.gz", "refresh_days": 7})),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(
        (v["asn"]["db_url"].clone(), v["asn"]["refresh_days"].clone()),
        (json!("https://mirror.example/asn.csv.gz"), json!(7))
    );
}

async fn add_gateways(a: &App) {
    for (n, i) in [("WAN", "@wan"), ("LTE", "opt1")] {
        sqlx::query("INSERT INTO route_gateways (name, interface, family, monitor_enabled, loss_threshold, latency_threshold, updated_at) VALUES (?,?,'inet',1,20,500,0)")
            .bind(n)
            .bind(i)
            .execute(a.store.pool().unwrap())
            .await
            .unwrap();
    }
}

#[tokio::test]
async fn probe_configuration_is_validated_audited_and_listed() {
    let a = app().await;
    let (s, v) = a.call(Method::POST, "/api/uplinks/probes", Some(json!({"gateway": "WAN", "kind": "dns", "target": "1.1.1.1", "name": "example.com"}))).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "no such gateway yet: {v}");
    add_gateways(&a).await;
    let (s, v) = a.call(Method::POST, "/api/uplinks/probes", Some(json!({"gateway": "WAN", "kind": "dns", "target": "1.1.1.1", "name": "example.com", "critical": true}))).await;
    assert_eq!(s, StatusCode::CREATED, "{v}");
    let id = v["id"].as_i64().unwrap();
    for bad in [
        json!({"gateway": "WAN", "kind": "dns", "target": "1.1.1.1", "name": "example.com"}),
        json!({"gateway": "WAN", "kind": "tcp", "target": "1.1.1.1"}),
        json!({"gateway": "WAN", "kind": "tcp", "target": "host.example", "port": 80}),
        json!({"gateway": "WAN", "kind": "icmp", "target": "1.1.1.1"}),
        json!({"gateway": "WAN", "kind": "http", "target": "gopher://x"}),
    ] {
        let (s, v) = a
            .call(Method::POST, "/api/uplinks/probes", Some(bad.clone()))
            .await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{bad}: {v}");
    }
    let (s, _) = a
        .call(
            Method::POST,
            "/api/uplinks/probes",
            Some(json!({"gateway": "LTE", "kind": "tcp", "target": "9.9.9.9", "port": 443})),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED);
    let (_, v) = a.get("/api/uplinks/probes").await;
    let rows = v["rows"].as_array().unwrap();
    assert_eq!(rows.len(), 2);
    assert_eq!(
        (
            rows[0]["kind"].clone(),
            rows[0]["port"].clone(),
            rows[0]["critical"].clone()
        ),
        (json!("dns"), json!(53), json!(true))
    );
    let (s, _) = a.call(Method::PUT, &format!("/api/uplinks/probes/{id}"), Some(json!({"gateway": "WAN", "kind": "dns", "target": "9.9.9.9", "name": "example.org", "enabled": false}))).await;
    assert_eq!(s, StatusCode::OK);
    let (_, v) = a.get("/api/uplinks/probes").await;
    assert_eq!(
        (
            v["rows"][0]["target"].clone(),
            v["rows"][0]["enabled"].clone(),
            v["rows"][0]["critical"].clone()
        ),
        (json!("9.9.9.9"), json!(false), json!(false))
    );
    let (s, _) = a
        .call(
            Method::PUT,
            "/api/uplinks/probes/9999",
            Some(json!({"gateway": "WAN", "kind": "tcp", "target": "1.1.1.1", "port": 80})),
        )
        .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let (s, _) = a
        .call(Method::DELETE, &format!("/api/uplinks/probes/{id}"), None)
        .await;
    assert_eq!(s, StatusCode::OK);
    let (s, _) = a
        .call(Method::DELETE, &format!("/api/uplinks/probes/{id}"), None)
        .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let n: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM audit_log WHERE entity_type = 'uplink_probe'")
            .fetch_one(a.store.pool().unwrap())
            .await
            .unwrap();
    assert!(n >= 4, "create x2, update, delete are audited: {n}");
}

#[tokio::test]
async fn uplink_history_sla_and_outages_come_from_the_recorded_samples() {
    use patronus_network::uplink_probe::{ProbeKind, ProbeResult};
    let a = app().await;
    let t0 = now() - 3600 * 3 - (now() % 60);
    let ok_probe = ProbeResult {
        id: 1,
        kind: ProbeKind::Dns,
        target: "example.com @1.1.1.1".into(),
        critical: true,
        ok: true,
        last_ok: true,
        rtt_ms: Some(9.0),
        fails: 0,
        error: None,
    };
    for i in 0..180 {
        let (state, rtt) = if (60..70).contains(&i) {
            ("down", None)
        } else {
            ("online", Some(20.0 + (i % 5) as f64))
        };
        let gw = uplink::GwView {
            name: "WAN".into(),
            state: state.into(),
            rtt_ms: rtt,
            loss_pct: Some(if rtt.is_none() { 100.0 } else { 0.0 }),
            probes: vec![ok_probe.clone()],
        };
        uplink::record(&a.store, t0 + i * 60, &[gw]).await.unwrap();
    }
    let (s, v) = a.get("/api/uplinks/sla?window=24h&series=1").await;
    assert_eq!(s, StatusCode::OK);
    let w = &v["sla"][0];
    assert_eq!(w["gateway"], "WAN");
    assert_eq!(w["samples"], 180);
    assert_eq!(w["down_minutes"], 10);
    let avail = w["availability_pct"].as_f64().unwrap();
    assert!((avail - 94.44).abs() < 0.01, "{avail}");
    assert!(w["rtt_avg_ms"].as_f64().unwrap() > 20.0);
    assert!(
        v["series"]["WAN"].as_array().unwrap().len() >= 3,
        "hourly bars: {}",
        v["series"]
    );
    let (_, v) = a.get("/api/uplinks/sla?window=24h&gateway=LTE").await;
    assert_eq!(v["sla"], json!([]));
    let (_, v) = a
        .get("/api/uplinks/health?since=6h&points=60&gateway=WAN")
        .await;
    let pts = v["samples"].as_array().unwrap();
    assert!(!pts.is_empty() && pts.len() <= 60, "{}", pts.len());
    assert!(
        pts.iter().any(|p| p["state"] == "down"),
        "the outage shows in the thinned series"
    );
    let (_, v) = a.get("/api/uplinks/outages?window=7d").await;
    let o = v["outages"].as_array().unwrap();
    assert_eq!(o.len(), 1, "{v}");
    assert_eq!(
        (
            o[0]["gateway"].clone(),
            o[0]["minutes"].clone(),
            o[0]["ongoing"].clone()
        ),
        (json!("WAN"), json!(10), json!(false))
    );
    // the SLA settings drive the breach alert: persisted and returned with the SLA answer
    let (s, v) = a
        .call(
            Method::PUT,
            "/api/uplinks/settings",
            Some(json!({"sla_target": 99.9})),
        )
        .await;
    assert_eq!((s, v["sla_target"].clone()), (StatusCode::OK, json!(99.9)));
    let (_, v) = a.get("/api/uplinks/sla").await;
    assert_eq!(v["target"], 99.9);
}

#[tokio::test]
async fn the_gateway_status_endpoint_reads_the_live_monitor() {
    let a = app().await;
    let (s, v) = a.get("/api/uplinks/status").await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(
        v["gateways"],
        json!([]),
        "no gateway configured: empty list, no fixture rows"
    );
    if std::process::Command::new("ip").arg("-V").output().is_err() {
        // resolving gateways reads the kernel's routes with `ip`
        eprintln!("no ip(8) here: the gateway half of this test needs iproute2");
        return;
    }
    add_gateways(&a).await;
    let (s, v) = a.get("/api/uplinks/status").await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let mut names: Vec<&str> = v["gateways"]
        .as_array()
        .unwrap()
        .iter()
        .map(|g| g["name"].as_str().unwrap())
        .collect();
    names.sort_unstable();
    assert_eq!(names, ["LTE", "WAN"]);
    assert!(
        v["gateways"][0]["probes"].is_array(),
        "probe results travel with the status"
    );
}

/// The page's script must at least parse: cargo cannot check inline JS.
#[test]
fn the_insights_page_script_is_valid_javascript() {
    let t = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("templates/insights.html"),
    )
    .unwrap();
    let s = t
        .split("<script>")
        .nth(1)
        .unwrap()
        .split("</script>")
        .next()
        .unwrap();
    assert!(
        !s.contains("{%") && !s.contains("{{") && !s.contains("{#"),
        "askama would parse this"
    );
    let dir = std::env::temp_dir().join(format!("insights-js-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let f = dir.join("page.js");
    std::fs::write(&f, s).unwrap();
    match std::process::Command::new("node")
        .arg("--check")
        .arg(&f)
        .output()
    {
        Ok(o) => assert!(
            o.status.success(),
            "node --check: {}",
            String::from_utf8_lossy(&o.stderr)
        ),
        Err(_) => eprintln!("node not installed: JS syntax not checked here"),
    }
    let _ = std::fs::remove_dir_all(&dir);
}
