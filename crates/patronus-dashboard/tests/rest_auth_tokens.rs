//! REST API v1 token-handling tests, complementing tests/rest_auth.rs:
//! an admin token forged with the old hardcoded signing secret, refresh
//! tokens used as API credentials, revoked tokens, viewer write attempts and
//! a viewer changing its own password -- all through the real router.

use axum::{
    body::Body,
    http::{Request, StatusCode},
    Router,
};
use patronus_dashboard::{
    api,
    auth::{hash_password, jwt, UserRole},
    state::AppState,
};
use serde_json::{json, Value};
use std::sync::Arc;
use tower::ServiceExt;

const ADMIN_PW: &str = "Adm1n-Passw0rd!x";
const VIEWER_PW: &str = "V1ewer-Passw0rd!x";

async fn app() -> (Router, Arc<AppState>) {
    let state = Arc::new(AppState::new(":memory:").await.unwrap());
    let router = Router::new()
        .nest("/api/v1", api::routes(state.clone()))
        .with_state(state.clone());
    (router, state)
}

async fn call(
    app: &Router,
    method: &str,
    uri: &str,
    token: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut req = Request::builder().method(method).uri(uri);
    if let Some(t) = token {
        req = req.header("authorization", format!("Bearer {}", t));
    }
    let req = match body {
        Some(b) => req
            .header("content-type", "application/json")
            .body(Body::from(b.to_string()))
            .unwrap(),
        None => req.body(Body::empty()).unwrap(),
    };
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .unwrap();
    let v = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, v)
}

async fn login(app: &Router, email: &str, pw: &str) -> (String, String) {
    let (s, v) = call(
        app,
        "POST",
        "/api/v1/auth/login",
        None,
        Some(json!({"email": email, "password": pw})),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "login failed: {v}");
    (
        v["access_token"].as_str().unwrap().to_string(),
        v["refresh_token"].as_str().unwrap().to_string(),
    )
}

fn policy_body() -> Value {
    json!({
        "name": "deny-all",
        "namespace": "default",
        "spec": {
            "pod_selector": {"match_labels": {}, "match_expressions": []},
            "policy_types": ["Ingress"],
            "ingress": [],
            "egress": [],
            "priority": 100
        }
    })
}

#[tokio::test]
async fn anonymous_requests_are_rejected() {
    let (app, _) = app().await;
    for (m, u) in [
        ("GET", "/api/v1/sites"),
        ("GET", "/api/v1/paths"),
        ("GET", "/api/v1/policies"),
        ("GET", "/api/v1/flows"),
        ("GET", "/api/v1/metrics/summary"),
        ("GET", "/api/v1/auth/me"),
        ("DELETE", "/api/v1/policies/1"),
    ] {
        let (s, _) = call(&app, m, u, None, None).await;
        assert_eq!(s, StatusCode::UNAUTHORIZED, "{m} {u} must need a token");
    }
    let (s, _) = call(&app, "POST", "/api/v1/policies", None, Some(policy_body())).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn forged_and_garbage_tokens_are_rejected() {
    let (app, _) = app().await;
    // An admin token minted with the old hardcoded signing secret.
    let now = chrono::Utc::now().timestamp();
    let forged = jsonwebtoken::encode(
        &jsonwebtoken::Header::default(),
        &json!({"sub": "x", "email": "x@x.x", "role": "admin", "iat": now,
                "exp": now + 900, "jti": "forged", "token_type": "access"}),
        &jsonwebtoken::EncodingKey::from_secret(b"your-secret-key-change-in-production"),
    )
    .unwrap();
    let (s, _) = call(&app, "GET", "/api/v1/sites", Some(&forged), None).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    let (s, _) = call(&app, "GET", "/api/v1/sites", Some("not.a.jwt"), None).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn admin_can_read_write_and_viewer_is_read_only() {
    let (app, state) = app().await;

    let (s, v) = call(
        &app,
        "POST",
        "/api/v1/auth/init-admin",
        None,
        Some(json!({"email": "admin@example.test", "name": "Admin", "password": ADMIN_PW, "role": "admin"})),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let (admin, admin_refresh) = login(&app, "admin@example.test", ADMIN_PW).await;

    // /auth/me now actually sees the caller.
    let (s, v) = call(&app, "GET", "/api/v1/auth/me", Some(&admin), None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v["email"], "admin@example.test");

    // A refresh token is not an API credential.
    let (s, _) = call(&app, "GET", "/api/v1/sites", Some(&admin_refresh), None).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);

    let (s, _) = call(&app, "GET", "/api/v1/sites", Some(&admin), None).await;
    assert_eq!(s, StatusCode::OK);
    let (s, v) = call(
        &app,
        "POST",
        "/api/v1/policies",
        Some(&admin),
        Some(policy_body()),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let pid = v["id"].as_str().unwrap().to_string();
    // The id the API hands out must work on the per-policy routes.
    let (s, v) = call(
        &app,
        "GET",
        &format!("/api/v1/policies/{pid}"),
        Some(&admin),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK, "GET by returned id {pid}: {v}");

    // Viewer: reads OK, writes forbidden.
    state
        .user_repository
        .create_user(
            "viewer@example.test",
            "Viewer",
            &hash_password(VIEWER_PW).unwrap(),
            UserRole::Viewer,
        )
        .await
        .unwrap();
    let (viewer, _) = login(&app, "viewer@example.test", VIEWER_PW).await;
    let (s, v) = call(&app, "GET", "/api/v1/policies", Some(&viewer), None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v.as_array().unwrap().len(), 1);
    let (s, _) = call(
        &app,
        "POST",
        "/api/v1/policies",
        Some(&viewer),
        Some(policy_body()),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (s, _) = call(
        &app,
        "DELETE",
        &format!("/api/v1/policies/{pid}"),
        Some(&viewer),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    // ...but a viewer may still change their own password.
    let (s, v) = call(
        &app,
        "POST",
        "/api/v1/auth/change-password",
        Some(&viewer),
        Some(json!({"old_password": VIEWER_PW, "new_password": "N3w-V1ewer-Pass!"})),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");

    // Admin deletes; the policy is really gone.
    let (s, _) = call(
        &app,
        "DELETE",
        &format!("/api/v1/policies/{pid}"),
        Some(&admin),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let (_, v) = call(&app, "GET", "/api/v1/policies", Some(&admin), None).await;
    assert!(v.as_array().unwrap().is_empty());

    // A revoked (logged-out) token is refused.
    let claims = jwt::validate_token(&admin).unwrap();
    state
        .token_revocation
        .revoke_token(
            claims.jti.clone(),
            claims.sub.clone(),
            "logout".into(),
            chrono::Utc::now() + chrono::Duration::minutes(15),
        )
        .await
        .unwrap();
    let (s, _) = call(&app, "GET", "/api/v1/sites", Some(&admin), None).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
}
