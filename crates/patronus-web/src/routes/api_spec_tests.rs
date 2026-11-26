//! The OpenAPI document against the real router: every API route the running router serves is in
//! the document, and every operation in the document is served. (The source scan in
//! `patronus-openapi` runs the same comparison without building the router; this one cannot be
//! fooled by a route registered in a way the scanner does not read.)

use std::collections::BTreeSet;

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use tower::ServiceExt;

const METHODS: [&str; 5] = ["get", "post", "put", "delete", "patch"];

async fn app() -> (axum::Router, String) {
    let dir = std::env::temp_dir().join(format!("patronus-web-spec-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let store = std::sync::Arc::new(
        patronus_config::ConfigStore::open(dir.join("config.db"))
            .await
            .unwrap(),
    );
    let state = crate::AppState::new(
        store,
        std::sync::Arc::new(crate::state::firewall::NoopApplier),
    )
    .await
    .unwrap();
    let pw = "Spec-Test-Passw0rd!".to_string();
    state
        .auth
        .user_store
        .provision_admin(Some(pw.clone()), &dir.join("pw"))
        .await
        .unwrap();
    let ws = std::sync::Arc::new(crate::WsBroadcaster::new());
    (super::build_router(state, ws), pw)
}

async fn login(app: &axum::Router, pw: &str) -> String {
    let body = format!(r#"{{"username":"admin","password":"{pw}"}}"#);
    let r = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/auth/login")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    r.headers()[header::SET_COOKIE]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string()
}

/// (method, path) of every route of the router, read from its Debug output (axum lists each
/// path and, per path, the methods that have a handler).
fn router_routes(app: &axum::Router) -> BTreeSet<(String, String)> {
    let dbg = format!("{app:?}");
    let paths_at = dbg
        .find("paths: {")
        .expect("Node paths in the router's Debug output");
    let routes_at = dbg
        .find("routes: {")
        .expect("routes in the router's Debug output");
    // routes: {RouteId(n): MethodRouter(MethodRouter { get: .., head: .., ...}), ...}
    // paths:  {RouteId(n): "/path", ...}
    let mut path_of = std::collections::BTreeMap::new();
    let paths = &dbg[paths_at + "paths: {".len()..];
    let mut rest = paths;
    while let Some(i) = rest.find("RouteId(") {
        let r = &rest[i + 8..];
        let (id, r2) = r.split_once("): \"").expect("route id");
        let (path, tail) = r2.split_once('"').expect("path");
        path_of.insert(id.to_string(), path.to_string());
        rest = tail;
        if tail.starts_with('}') {
            break;
        }
    }
    let routes = &dbg[routes_at..paths_at.max(routes_at)];
    let mut out = BTreeSet::new();
    let mut chunks: Vec<&str> = routes.split("RouteId(").skip(1).collect();
    if chunks.is_empty() {
        // field order differs: routes come after the paths
        chunks = dbg[routes_at..].split("RouteId(").skip(1).collect();
    }
    for c in chunks {
        let Some((id, body)) = c.split_once("): ") else {
            continue;
        };
        let Some(path) = path_of.get(id) else {
            continue;
        };
        if !body.starts_with("MethodRouter(") {
            continue; // a nested service (static files): no method list
        }
        for m in METHODS {
            if !body.contains(&format!(" {m}: None")) {
                out.insert((m.to_string(), normalise(path)));
            }
        }
    }
    out
}

/// axum `:id` / `*rest` -> OpenAPI `{id}`.
fn normalise(p: &str) -> String {
    p.split('/')
        .map(
            |s| match s.strip_prefix(':').or_else(|| s.strip_prefix('*')) {
                Some(n) => format!("{{{n}}}"),
                None => s.to_string(),
            },
        )
        .collect::<Vec<_>>()
        .join("/")
}

fn is_api(p: &str) -> bool {
    p.starts_with("/api/") || p == "/metrics"
}

fn spec_ops() -> BTreeSet<(String, String)> {
    let doc: serde_json::Value =
        serde_json::from_str(crate::routes::api::docs::SPEC).expect("spec json");
    let mut out = BTreeSet::new();
    for (path, item) in doc["paths"].as_object().expect("paths") {
        for m in item.as_object().expect("item").keys() {
            out.insert((m.clone(), path.clone()));
        }
    }
    out
}

#[tokio::test]
async fn every_route_of_the_router_is_in_the_openapi_document() {
    let (app, _) = app().await;
    let served: BTreeSet<(String, String)> = router_routes(&app)
        .into_iter()
        .filter(|(_, p)| is_api(p))
        .collect();
    assert!(
        served.len() > 200,
        "read only {} routes from the router",
        served.len()
    );
    let doc = spec_ops();
    let missing: Vec<String> = served
        .difference(&doc)
        .map(|(m, p)| format!("{} {p}", m.to_uppercase()))
        .collect();
    assert!(
        missing.is_empty(),
        "served by the router but not in openapi/openapi.json (run `cargo run -p patronus-openapi`): {missing:?}"
    );
    let extra: Vec<String> = doc
        .difference(&served)
        .map(|(m, p)| format!("{} {p}", m.to_uppercase()))
        .collect();
    assert!(
        extra.is_empty(),
        "in openapi/openapi.json but not served by this build: {extra:?}"
    );
}

#[tokio::test]
async fn the_document_and_the_reference_page_need_a_sign_in() {
    let (app, pw) = app().await;
    for uri in ["/api/openapi.json", "/api/docs"] {
        let r = app
            .clone()
            .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(
            r.status(),
            StatusCode::UNAUTHORIZED,
            "{uri} answers anonymous callers"
        );
    }
    let cookie = login(&app, &pw).await;
    let r = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/openapi.json")
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    assert!(r.headers()[header::CONTENT_TYPE]
        .to_str()
        .unwrap()
        .starts_with("application/json"));
    let b = axum::body::to_bytes(r.into_body(), 4 << 20).await.unwrap();
    let doc: serde_json::Value = serde_json::from_slice(&b).unwrap();
    assert_eq!(doc["openapi"], "3.1.0");
    assert!(doc["paths"]["/api/firewall/rules"]["get"].is_object());
    let r = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/docs")
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let b = axum::body::to_bytes(r.into_body(), 4 << 20).await.unwrap();
    let html = String::from_utf8_lossy(&b);
    assert!(html.contains("id=\"api-list\"") && html.contains("/api/openapi.json"));
}
