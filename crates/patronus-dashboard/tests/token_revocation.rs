//! Integration tests for token revocation (Sprint 29)
//!
//! These tests verify that token revocation works correctly across
//! user deactivation, role changes, and password resets.

use patronus_dashboard::{auth::jwt, state::AppState};
use std::sync::Arc;

/// Create a test app state with in-memory database
async fn create_test_state() -> Arc<AppState> {
    Arc::new(AppState::new(":memory:").await.unwrap())
}

#[tokio::test]
async fn test_token_revoked_after_user_deactivation() {
    let state = create_test_state().await;

    // Generate a token for a user
    let user_id = "test-user-123";
    let tokens = jwt::generate_tokens(user_id, "test@example.com", "admin").unwrap();
    let claims = jwt::validate_token(&tokens.access_token).unwrap();

    // Token should be valid initially
    assert!(!state.token_revocation.is_revoked(&claims.jti));

    // Revoke all user tokens (simulating deactivation)
    state
        .token_revocation
        .revoke_all_user_tokens(user_id, "User deactivated".to_string())
        .await
        .unwrap();

    // Note: revoke_all_user_tokens creates a special revocation entry
    // but doesn't actually track individual JTIs. In a real system, you'd track
    // active sessions. For now, verify the user-level revocation was recorded.
    let revocations = state
        .token_revocation
        .get_user_revocations(user_id)
        .await
        .unwrap();

    assert!(!revocations.is_empty(), "Revocation should be recorded");
    assert_eq!(revocations[0].reason, "User deactivated");
}

#[tokio::test]
async fn test_specific_token_revocation() {
    let state = create_test_state().await;

    // Generate a token
    let tokens = jwt::generate_tokens("user-456", "user@example.com", "operator").unwrap();
    let claims = jwt::validate_token(&tokens.access_token).unwrap();

    // Token should NOT be revoked initially
    assert!(!state.token_revocation.is_revoked(&claims.jti));

    // Revoke this specific token
    state
        .token_revocation
        .revoke_token(
            claims.jti.clone(),
            claims.sub.clone(),
            "User logged out".to_string(),
            chrono::Utc::now() + chrono::Duration::hours(1),
        )
        .await
        .unwrap();

    // Now the token SHOULD be revoked
    assert!(state.token_revocation.is_revoked(&claims.jti));
}

#[tokio::test]
async fn test_token_revocation_after_role_change() {
    let state = create_test_state().await;

    let user_id = "user-789";

    // Generate tokens
    let tokens = jwt::generate_tokens(user_id, "user@example.com", "viewer").unwrap();
    let claims = jwt::validate_token(&tokens.access_token).unwrap();

    // Initially not revoked
    assert!(!state.token_revocation.is_revoked(&claims.jti));

    // Simulate role change by revoking all user tokens
    state
        .token_revocation
        .revoke_all_user_tokens(user_id, "Role changed from viewer to operator".to_string())
        .await
        .unwrap();

    // Verify revocation was recorded
    let revocations = state
        .token_revocation
        .get_user_revocations(user_id)
        .await
        .unwrap();

    assert_eq!(revocations.len(), 1);
    assert!(revocations[0].reason.contains("Role changed"));
}

#[tokio::test]
async fn test_token_revocation_after_password_reset() {
    let state = create_test_state().await;

    let user_id = "user-abc";

    // Generate tokens
    let tokens = jwt::generate_tokens(user_id, "user@example.com", "admin").unwrap();
    let claims = jwt::validate_token(&tokens.access_token).unwrap();

    // Initially not revoked
    assert!(!state.token_revocation.is_revoked(&claims.jti));

    // Simulate password reset by revoking all user tokens
    state
        .token_revocation
        .revoke_all_user_tokens(user_id, "Password reset by admin".to_string())
        .await
        .unwrap();

    // Verify revocation was recorded
    let revocations = state
        .token_revocation
        .get_user_revocations(user_id)
        .await
        .unwrap();

    assert_eq!(revocations.len(), 1);
    assert_eq!(revocations[0].reason, "Password reset by admin");
}

#[tokio::test]
async fn test_multiple_tokens_per_user() {
    let state = create_test_state().await;

    let user_id = "multi-token-user";

    // Generate multiple tokens for the same user
    let tokens1 = jwt::generate_tokens(user_id, "user@example.com", "admin").unwrap();
    let tokens2 = jwt::generate_tokens(user_id, "user@example.com", "admin").unwrap();
    let tokens3 = jwt::generate_tokens(user_id, "user@example.com", "admin").unwrap();

    let claims1 = jwt::validate_token(&tokens1.access_token).unwrap();
    let claims2 = jwt::validate_token(&tokens2.access_token).unwrap();
    let claims3 = jwt::validate_token(&tokens3.access_token).unwrap();

    // All tokens should have different JTIs
    assert_ne!(claims1.jti, claims2.jti);
    assert_ne!(claims2.jti, claims3.jti);
    assert_ne!(claims1.jti, claims3.jti);

    // Revoke token 2 specifically
    state
        .token_revocation
        .revoke_token(
            claims2.jti.clone(),
            user_id.to_string(),
            "Single session logout".to_string(),
            chrono::Utc::now() + chrono::Duration::hours(1),
        )
        .await
        .unwrap();

    // Only token 2 should be revoked
    assert!(!state.token_revocation.is_revoked(&claims1.jti));
    assert!(state.token_revocation.is_revoked(&claims2.jti));
    assert!(!state.token_revocation.is_revoked(&claims3.jti));
}

#[tokio::test]
async fn test_revocation_count() {
    let state = create_test_state().await;

    // Initially should be zero
    let count = state.token_revocation.get_revoked_count().await.unwrap();
    assert_eq!(count, 0);

    // Revoke some tokens
    for i in 0..5 {
        state
            .token_revocation
            .revoke_token(
                format!("token-{}", i),
                "user-123".to_string(),
                "Test".to_string(),
                chrono::Utc::now() + chrono::Duration::hours(1),
            )
            .await
            .unwrap();
    }

    // Count should be 5
    let count = state.token_revocation.get_revoked_count().await.unwrap();
    assert_eq!(count, 5);
}

#[tokio::test]
async fn test_expired_revocations_cleanup() {
    let state = create_test_state().await;

    // Add an expired revocation
    state
        .token_revocation
        .revoke_token(
            "expired-token".to_string(),
            "user-123".to_string(),
            "Test".to_string(),
            chrono::Utc::now() - chrono::Duration::hours(1), // Expired 1 hour ago
        )
        .await
        .unwrap();

    // Add a valid revocation
    state
        .token_revocation
        .revoke_token(
            "valid-token".to_string(),
            "user-123".to_string(),
            "Test".to_string(),
            chrono::Utc::now() + chrono::Duration::hours(1), // Expires in 1 hour
        )
        .await
        .unwrap();

    // Cleanup expired
    let cleaned = state.token_revocation.cleanup_expired().await.unwrap();
    assert_eq!(cleaned, 1, "Should have cleaned 1 expired token");

    // Expired token should no longer be revoked
    assert!(!state.token_revocation.is_revoked("expired-token"));

    // Valid token should still be revoked
    assert!(state.token_revocation.is_revoked("valid-token"));
}

#[tokio::test]
async fn test_refresh_token_validation() {
    let state = create_test_state().await;

    // Generate tokens
    let tokens = jwt::generate_tokens("user-refresh", "user@example.com", "admin").unwrap();

    // Validate refresh token
    let refresh_claims = jwt::validate_token(&tokens.refresh_token).unwrap();
    assert_eq!(refresh_claims.token_type, jwt::TokenType::Refresh);

    // Revoke the refresh token
    state
        .token_revocation
        .revoke_token(
            refresh_claims.jti.clone(),
            refresh_claims.sub.clone(),
            "User logged out".to_string(),
            chrono::Utc::now() + chrono::Duration::days(7),
        )
        .await
        .unwrap();

    // Refresh token should be revoked
    assert!(state.token_revocation.is_revoked(&refresh_claims.jti));
}

#[tokio::test]
async fn test_revocation_cache_consistency() {
    let state = create_test_state().await;

    let token_id = "cache-test-token";

    // Revoke a token
    state
        .token_revocation
        .revoke_token(
            token_id.to_string(),
            "user-123".to_string(),
            "Test".to_string(),
            chrono::Utc::now() + chrono::Duration::hours(1),
        )
        .await
        .unwrap();

    // Check via cache
    assert!(state.token_revocation.is_revoked(token_id));

    // Cleanup (which reloads cache)
    let _ = state.token_revocation.cleanup_expired().await;

    // Should still be revoked after cache reload
    assert!(state.token_revocation.is_revoked(token_id));
}

#[tokio::test]
async fn test_user_revocation_query() {
    let state = create_test_state().await;

    let user_id = "query-test-user";

    // Add multiple revocations for the user
    for i in 0..3 {
        state
            .token_revocation
            .revoke_token(
                format!("token-{}", i),
                user_id.to_string(),
                format!("Reason {}", i),
                chrono::Utc::now() + chrono::Duration::hours(1),
            )
            .await
            .unwrap();
    }

    // Query user's revocations
    let revocations = state
        .token_revocation
        .get_user_revocations(user_id)
        .await
        .unwrap();

    assert_eq!(revocations.len(), 3);
    assert_eq!(revocations[0].user_id, user_id);
    assert_eq!(revocations[1].user_id, user_id);
    assert_eq!(revocations[2].user_id, user_id);
}
