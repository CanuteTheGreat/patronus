//! The dashboard's Overview / Topology / SLA / Traffic / Security pages read
//! GraphQL fields (`overview`, `links`, `slaPolicies`, `trafficStats`,
//! `securityEvents`, ...). These tests seed a real (in-memory) store and run
//! the real schema as an authenticated user: the answers must reflect that
//! data, and an empty store must give empty lists (no fixtures).

use patronus_dashboard::{
    auth::jwt::{Claims, TokenType},
    graphql::{self, AuthContext},
    security::audit::AuditEvent,
    state::AppState,
};
use patronus_sdwan::types::{
    Endpoint, FlowRecord, Path, PathId, PathMetrics, PathStatus, Site, SiteId, SiteStatus,
};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

fn auth(role: &str) -> AuthContext {
    AuthContext::new(Some(Claims {
        sub: "u1".into(),
        email: "qa@errant.solutions".into(),
        role: role.into(),
        iat: 0,
        exp: 9_999_999_999,
        token_type: TokenType::Access,
        jti: "j1".into(),
    }))
}

async fn run(state: &Arc<AppState>, role: &str, q: &str) -> async_graphql::Response {
    let schema = graphql::build_schema(state.clone());
    schema
        .execute(async_graphql::Request::new(q).data(auth(role)))
        .await
}

fn site(name: &str, port: u16, status: SiteStatus) -> Site {
    Site {
        id: SiteId::generate(),
        name: name.into(),
        public_key: vec![1; 32],
        endpoints: vec![Endpoint {
            address: format!("192.0.2.{}:{}", port % 200 + 1, port)
                .parse()
                .unwrap(),
            interface_type: "fiber".into(),
            cost_per_gb: 0.0,
            reachable: true,
        }],
        created_at: SystemTime::now(),
        last_seen: SystemTime::now(),
        status,
    }
}

fn metrics(latency: f64, loss: f64) -> PathMetrics {
    PathMetrics {
        latency_ms: latency,
        jitter_ms: 1.0,
        packet_loss_pct: loss,
        bandwidth_mbps: 100.0,
        mtu: 1420,
        measured_at: SystemTime::now(),
        score: 90,
    }
}

const PAGES: &str = r#"{
  overview { totalSites activeSites totalLinks healthyLinks avgLatency totalThroughput packetLoss }
  recentAlerts { id severity message siteId }
  linkMetrics { timestamp throughput latency packetLoss }
  links { id sourceId targetId status latency bandwidth utilization }
  slaPolicies { id name targetLatency currentLatency compliance violations currentAvailability }
  trafficStats { siteId siteName totalBytes totalPackets applications { name bytes packets percentage } }
  securityEvents { id severity type source blocked }
  threatStats { total blocked allowed byType { type count } }
}"#;

#[tokio::test]
async fn an_empty_store_gives_empty_pages() {
    let state = Arc::new(AppState::new(":memory:").await.unwrap());
    let r = run(&state, "admin", PAGES).await;
    assert!(r.errors.is_empty(), "{:?}", r.errors);
    let d = r.data.into_json().unwrap();
    assert_eq!(d["overview"]["totalSites"], 0);
    assert_eq!(d["overview"]["totalLinks"], 0);
    for k in [
        "recentAlerts",
        "links",
        "slaPolicies",
        "trafficStats",
        "securityEvents",
    ] {
        assert_eq!(d[k].as_array().unwrap().len(), 0, "{k}");
    }
    assert_eq!(d["threatStats"]["total"], 0);
}

#[tokio::test]
async fn pages_reflect_the_stored_sites_paths_flows_and_audit_log() {
    let state = Arc::new(AppState::new(":memory:").await.unwrap());
    let hq = site("hq", 51820, SiteStatus::Active);
    let branch = site("branch", 51821, SiteStatus::Inactive);
    state.db.upsert_site(&hq).await.unwrap();
    state.db.upsert_site(&branch).await.unwrap();

    let mk = |src: &Site, dst: &Site, status| Path {
        id: PathId::new(0),
        src_site: src.id,
        dst_site: dst.id,
        src_endpoint: src.endpoints[0].address,
        dst_endpoint: dst.endpoints[0].address,
        wg_interface: None,
        metrics: PathMetrics::default(),
        status,
    };
    let up = state
        .db
        .insert_path(&mk(&hq, &branch, PathStatus::Up))
        .await
        .unwrap();
    let down = state
        .db
        .insert_path(&mk(&branch, &hq, PathStatus::Down))
        .await
        .unwrap();
    // `up`: 3 samples, one breaks the 100 ms latency target
    for l in [20.0, 250.0, 30.0] {
        state.db.record_metrics(up, &metrics(l, 0.0)).await.unwrap();
    }
    state
        .db
        .record_metrics(down, &metrics(40.0, 100.0))
        .await
        .unwrap();

    let flow = |dst_port: u16, bytes: u64, packets: u64| FlowRecord {
        flow_id: 0,
        src_ip: "10.0.0.2".into(),
        dst_ip: "10.1.0.2".into(),
        src_port: 40000 + dst_port % 1000,
        dst_port,
        protocol: 6,
        path_id: up.as_u64(),
        policy_id: None,
        started_at: SystemTime::now() - Duration::from_secs(10),
        last_seen_at: SystemTime::now(),
        bytes_tx: bytes,
        bytes_rx: 0,
        packets_tx: packets,
        packets_rx: 0,
        status: "active".into(),
    };
    state.db.upsert_flow(&flow(443, 3000, 3)).await.unwrap();
    state.db.upsert_flow(&flow(5060, 1000, 1)).await.unwrap();

    state
        .audit_logger
        .log(
            AuditEvent::LoginAttempt {
                success: false,
                reason: Some("bad password".into()),
            },
            None,
            Some("x@errant.solutions".into()),
            Some("203.0.113.9".parse().unwrap()),
            None,
        )
        .await
        .unwrap();

    let r = run(&state, "admin", PAGES).await;
    assert!(r.errors.is_empty(), "{:?}", r.errors);
    let d = r.data.into_json().unwrap();

    let o = &d["overview"];
    assert_eq!(o["totalSites"], 2);
    assert_eq!(o["activeSites"], 1);
    assert_eq!(o["totalLinks"], 2);
    assert_eq!(o["healthyLinks"], 1);

    // site offline + path down
    let alerts = d["recentAlerts"].as_array().unwrap();
    assert_eq!(alerts.len(), 2, "{alerts:?}");
    assert!(alerts.iter().all(|a| a["severity"] == "critical"));

    let links = d["links"].as_array().unwrap();
    assert_eq!(links.len(), 2);
    let l_up = links.iter().find(|l| l["status"] == "healthy").unwrap();
    assert_eq!(l_up["sourceId"], hq.id.to_string());
    assert_eq!(l_up["bandwidth"], 100.0);
    assert!(l_up["utilization"].as_f64().unwrap() > 0.0);

    let sla = d["slaPolicies"].as_array().unwrap();
    assert_eq!(sla.len(), 2);
    let s_up = sla.iter().find(|s| s["name"] == "hq -> branch").unwrap();
    assert_eq!(s_up["violations"], 1);
    assert!((s_up["compliance"].as_f64().unwrap() - 200.0 / 3.0).abs() < 0.01);
    assert_eq!(s_up["currentLatency"], 30.0);

    let t = d["trafficStats"].as_array().unwrap();
    assert_eq!(t.len(), 1);
    assert_eq!(t[0]["siteName"], "hq");
    assert_eq!(t[0]["totalBytes"], 4000);
    let apps: Vec<&str> = t[0]["applications"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| a["name"].as_str().unwrap())
        .collect();
    assert_eq!(apps, vec!["Web", "VoIP"]);

    let ev = d["securityEvents"].as_array().unwrap();
    assert_eq!(ev.len(), 1);
    assert_eq!(ev[0]["type"], "login_attempt");
    assert_eq!(ev[0]["source"], "203.0.113.9");
    assert_eq!(ev[0]["blocked"], true);
    assert_eq!(d["threatStats"]["blocked"], 1);
    assert_eq!(d["threatStats"]["byType"][0]["type"], "login_attempt");
}

#[tokio::test]
async fn security_views_are_admin_only_and_the_rest_need_a_login() {
    let state = Arc::new(AppState::new(":memory:").await.unwrap());
    let r = run(&state, "viewer", "{ securityEvents { id } }").await;
    assert!(!r.errors.is_empty(), "a viewer must not read audit data");
    let r = run(&state, "viewer", "{ threatStats { total } }").await;
    assert!(!r.errors.is_empty());
    // a viewer may read the operational pages
    let r = run(&state, "viewer", "{ overview { totalSites } links { id } }").await;
    assert!(r.errors.is_empty(), "{:?}", r.errors);
    // no credentials at all: refused
    let schema = graphql::build_schema(state);
    let r = schema
        .execute(
            async_graphql::Request::new("{ overview { totalSites } }").data(AuthContext::new(None)),
        )
        .await;
    assert!(!r.errors.is_empty());
}
