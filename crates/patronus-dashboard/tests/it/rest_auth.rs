//! REST API v1 authentication / authorization tests.
//!
//! Regression coverage for the dashboard's REST routes being mounted without
//! `auth_middleware`, which let unauthenticated clients create, replace and
//! delete firewall (NetworkPolicy) rules. Also covers DELETE/GET by the
//! `policy-<n>` id the API itself returns (previously a 400).

use axum::{
    body::Body,
    http::{header, Method, Request, StatusCode},
    Router,
};
use patronus_dashboard::{
    api,
    auth::{jwt, users::UserRole},
    state::AppState,
};
use std::sync::Arc;
use tower::ServiceExt;

struct TestApp {
    router: Router,
    state: Arc<AppState>,
    _dir: tempfile::TempDir,
}

async fn test_app() -> TestApp {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("dashboard.db");
    let state = Arc::new(AppState::new(db_path.to_str().unwrap()).await.unwrap());
    let router = Router::new()
        .nest("/api/v1", api::routes(state.clone()))
        .with_state(state.clone());
    TestApp {
        router,
        state,
        _dir: dir,
    }
}

/// Create an active user with `role` and return a valid access token for it.
async fn token_for(state: &AppState, email: &str, role: UserRole) -> String {
    let user = state
        .user_repository
        .create_user(email, "Test User", "unused-password-hash", role)
        .await
        .unwrap();
    jwt::generate_tokens(&user.id, &user.email, user.role.as_str())
        .unwrap()
        .access_token
}

fn policy_body() -> String {
    serde_json::json!({
        "name": "deny-all",
        "namespace": "default",
        "spec": {
            "pod_selector": {},
            "policy_types": ["Ingress"]
        }
    })
    .to_string()
}

fn request(method: Method, uri: &str, token: Option<&str>, body: Option<String>) -> Request<Body> {
    let mut builder = Request::builder().method(method).uri(uri);
    if let Some(t) = token {
        builder = builder.header(header::AUTHORIZATION, format!("Bearer {}", t));
    }
    match body {
        Some(b) => builder
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(b))
            .unwrap(),
        None => builder.body(Body::empty()).unwrap(),
    }
}

async fn status_of(app: &TestApp, req: Request<Body>) -> StatusCode {
    app.router.clone().oneshot(req).await.unwrap().status()
}

async fn json_of(app: &TestApp, req: Request<Body>) -> (StatusCode, serde_json::Value) {
    let resp = app.router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let value = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, value)
}

#[tokio::test]
async fn unauthenticated_policy_writes_are_rejected_with_401() {
    let app = test_app().await;

    let post = request(Method::POST, "/api/v1/policies", None, Some(policy_body()));
    assert_eq!(status_of(&app, post).await, StatusCode::UNAUTHORIZED);

    let put = request(
        Method::PUT,
        "/api/v1/policies/policy-1",
        None,
        Some(policy_body()),
    );
    assert_eq!(status_of(&app, put).await, StatusCode::UNAUTHORIZED);

    let delete = request(Method::DELETE, "/api/v1/policies/policy-1", None, None);
    assert_eq!(status_of(&app, delete).await, StatusCode::UNAUTHORIZED);

    let delete_bare = request(Method::DELETE, "/api/v1/policies/1", None, None);
    assert_eq!(status_of(&app, delete_bare).await, StatusCode::UNAUTHORIZED);

    // Nothing reached the enforcer.
    assert!(app.state.policy_enforcer.list_policies().await.is_empty());
}

#[tokio::test]
async fn unauthenticated_reads_are_rejected_with_401() {
    let app = test_app().await;
    for uri in [
        "/api/v1/policies",
        "/api/v1/policies/policy-1",
        "/api/v1/sites",
        "/api/v1/paths",
        "/api/v1/flows",
        "/api/v1/metrics/summary",
        "/api/v1/auth/me",
    ] {
        let req = request(Method::GET, uri, None, None);
        assert_eq!(
            status_of(&app, req).await,
            StatusCode::UNAUTHORIZED,
            "{uri}"
        );
    }
}

#[tokio::test]
async fn invalid_or_revoked_tokens_are_rejected_with_401() {
    let app = test_app().await;

    let garbage = request(
        Method::DELETE,
        "/api/v1/policies/policy-1",
        Some("not-a-jwt"),
        None,
    );
    assert_eq!(status_of(&app, garbage).await, StatusCode::UNAUTHORIZED);

    let no_bearer = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/policies")
        .header(header::AUTHORIZATION, "Basic YWRtaW46YWRtaW4=")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(policy_body()))
        .unwrap();
    assert_eq!(status_of(&app, no_bearer).await, StatusCode::UNAUTHORIZED);

    // A valid token for a user that doesn't exist.
    let ghost = jwt::generate_tokens("no-such-user", "ghost@example.com", "admin")
        .unwrap()
        .access_token;
    let req = request(
        Method::POST,
        "/api/v1/policies",
        Some(&ghost),
        Some(policy_body()),
    );
    assert_eq!(status_of(&app, req).await, StatusCode::UNAUTHORIZED);

    // A revoked token for a real admin.
    let token = token_for(&app.state, "revoked@example.com", UserRole::Admin).await;
    let claims = jwt::validate_token(&token).unwrap();
    app.state
        .token_revocation
        .revoke_token(
            claims.jti.clone(),
            claims.sub.clone(),
            "logout".to_string(),
            chrono::Utc::now() + chrono::Duration::hours(1),
        )
        .await
        .unwrap();
    let req = request(Method::GET, "/api/v1/policies", Some(&token), None);
    assert_eq!(status_of(&app, req).await, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn public_auth_routes_stay_reachable_without_a_token() {
    let app = test_app().await;
    // Malformed bodies get a body-validation error from the handler's
    // extractor, not a 401 from the auth layer -- i.e. the route is public.
    for uri in [
        "/api/v1/auth/login",
        "/api/v1/auth/refresh",
        "/api/v1/auth/init-admin",
    ] {
        let req = request(Method::POST, uri, None, Some("{}".to_string()));
        assert_eq!(
            status_of(&app, req).await,
            StatusCode::UNPROCESSABLE_ENTITY,
            "{uri}"
        );
    }
}

#[tokio::test]
async fn viewer_can_read_but_not_write_policies() {
    let app = test_app().await;
    let token = token_for(&app.state, "viewer@example.com", UserRole::Viewer).await;

    let list = request(Method::GET, "/api/v1/policies", Some(&token), None);
    assert_eq!(status_of(&app, list).await, StatusCode::OK);

    let me = request(Method::GET, "/api/v1/auth/me", Some(&token), None);
    assert_eq!(status_of(&app, me).await, StatusCode::OK);

    let post = request(
        Method::POST,
        "/api/v1/policies",
        Some(&token),
        Some(policy_body()),
    );
    assert_eq!(status_of(&app, post).await, StatusCode::FORBIDDEN);

    let delete = request(
        Method::DELETE,
        "/api/v1/policies/policy-1",
        Some(&token),
        None,
    );
    assert_eq!(status_of(&app, delete).await, StatusCode::FORBIDDEN);

    assert!(app.state.policy_enforcer.list_policies().await.is_empty());
}

#[tokio::test]
async fn operator_can_create_get_and_delete_policy_by_returned_id() {
    let app = test_app().await;
    let token = token_for(&app.state, "operator@example.com", UserRole::Operator).await;

    let (status, created) = json_of(
        &app,
        request(
            Method::POST,
            "/api/v1/policies",
            Some(&token),
            Some(policy_body()),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let id = created["id"].as_str().unwrap().to_string();
    assert!(id.starts_with("policy-"), "unexpected id format: {id}");

    // The id exactly as returned must round-trip (was a 400 before).
    let get = request(
        Method::GET,
        &format!("/api/v1/policies/{id}"),
        Some(&token),
        None,
    );
    assert_eq!(status_of(&app, get).await, StatusCode::OK);

    let delete = request(
        Method::DELETE,
        &format!("/api/v1/policies/{id}"),
        Some(&token),
        None,
    );
    assert_eq!(status_of(&app, delete).await, StatusCode::OK);
    assert!(app.state.policy_enforcer.list_policies().await.is_empty());

    // Garbage ids are still a client error.
    let bad = request(
        Method::DELETE,
        "/api/v1/policies/not-a-policy",
        Some(&token),
        None,
    );
    assert_eq!(status_of(&app, bad).await, StatusCode::BAD_REQUEST);
}
