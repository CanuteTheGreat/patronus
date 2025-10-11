// GraphQL Schema - Schema builder and configuration
//
// This module builds the complete GraphQL schema with queries,
// mutations, and subscriptions.

use async_graphql::{Schema, EmptySubscription};
use crate::graphql::{
    queries::QueryRoot,
    mutations::MutationRoot,
    subscriptions::SubscriptionRoot,
};
use std::sync::Arc;
use crate::state::AppState;

/// The complete GraphQL schema type
pub type AppSchema = Schema<QueryRoot, MutationRoot, SubscriptionRoot>;

/// Build the GraphQL schema with all resolvers
///
/// This creates a schema configured with:
/// - Query operations (read-only)
/// - Mutation operations (write)
/// - Subscription operations (real-time streams)
/// - Query complexity limits
/// - Query depth limits
/// - Custom error formatting
pub fn build_schema(state: Arc<AppState>) -> AppSchema {
    Schema::build(QueryRoot, MutationRoot, SubscriptionRoot)
        // Add application state to context
        .data(state)
        // Limit query complexity to prevent DoS
        .limit_complexity(100)
        // Limit query depth to prevent deeply nested queries
        .limit_depth(10)
        // Enable introspection (disable in production if needed)
        .enable_federation()
        .enable_subscription_in_federation()
        .finish()
}

/// Build a simpler schema without subscriptions (for testing)
#[allow(dead_code)]
pub fn build_simple_schema(state: Arc<AppState>) -> Schema<QueryRoot, MutationRoot, EmptySubscription> {
    Schema::build(QueryRoot, MutationRoot, EmptySubscription)
        .data(state)
        .limit_complexity(100)
        .limit_depth(10)
        .finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::AppState;
    use async_graphql::*;

    async fn create_test_state() -> Arc<AppState> {
        // Create minimal test state with in-memory database
        Arc::new(AppState::new(":memory:").await.unwrap())
    }

    #[tokio::test]
    async fn test_schema_builds() {
        let state = create_test_state().await;
        let schema = build_schema(state);

        // Verify schema is valid
        assert!(schema.sdl().len() > 0);
    }

    #[tokio::test]
    async fn test_simple_query() {
        let state = create_test_state().await;
        let schema = build_schema(state);

        // Test basic health query
        let query = r#"
            query {
                health
            }
        "#;

        let result = schema.execute(query).await;
        assert!(result.errors.is_empty());

        let data = result.data.into_json().unwrap();
        assert_eq!(data["health"], "OK");
    }

    #[tokio::test]
    async fn test_version_query() {
        let state = create_test_state().await;
        let schema = build_schema(state);

        let query = r#"
            query {
                version
            }
        "#;

        let result = schema.execute(query).await;
        assert!(result.errors.is_empty());

        let data = result.data.into_json().unwrap();
        assert_eq!(data["version"], "v2.0.0");
    }

    #[tokio::test]
    async fn test_sites_query() {
        let state = create_test_state().await;
        let schema = build_schema(state);

        // Create auth context with admin user
        let auth_ctx = crate::graphql::AuthContext::new(Some(crate::auth::jwt::Claims {
            sub: "test-user".to_string(),
            email: "test@example.com".to_string(),
            role: "admin".to_string(),
            iat: 0,
            exp: 9999999999,
            token_type: crate::auth::jwt::TokenType::Access,
            jti: "test-jti".to_string(),
        }));

        let query = r#"
            query {
                sites {
                    id
                    name
                    status
                }
            }
        "#;

        let req = async_graphql::Request::new(query).data(auth_ctx);
        let result = schema.execute(req).await;
        assert!(result.errors.is_empty());

        let data = result.data.into_json().unwrap();
        assert!(data["sites"].is_array());
    }

    #[tokio::test]
    async fn test_metrics_query() {
        let state = create_test_state().await;
        let schema = build_schema(state);

        let query = r#"
            query {
                metrics {
                    timestamp
                    throughputMbps
                    packetsPerSecond
                    activeFlows
                    avgLatencyMs
                    avgPacketLoss
                    cpuUsage
                    memoryUsage
                }
            }
        "#;

        let result = schema.execute(query).await;
        // Metrics should now return real data
        assert!(result.errors.is_empty(), "Metrics query failed with errors: {:?}", result.errors);

        let data = result.data.into_json().unwrap();
        assert!(data["metrics"]["cpuUsage"].as_f64().unwrap() >= 0.0);
        assert!(data["metrics"]["memoryUsage"].as_f64().unwrap() >= 0.0);
    }

    #[tokio::test]
    async fn test_create_site_mutation() {
        let state = create_test_state().await;
        let schema = build_schema(state);

        // Create auth context with operator user
        let auth_ctx = crate::graphql::AuthContext::new(Some(crate::auth::jwt::Claims {
            sub: "test-user".to_string(),
            email: "test@example.com".to_string(),
            role: "operator".to_string(),
            iat: 0,
            exp: 9999999999,
            token_type: crate::auth::jwt::TokenType::Access,
            jti: "test-jti".to_string(),
        }));

        let query = r#"
            mutation {
                createSite(input: {
                    name: "Test Site"
                    location: "US-West"
                }) {
                    id
                    name
                    location
                    status
                }
            }
        "#;

        let req = async_graphql::Request::new(query).data(auth_ctx);
        let result = schema.execute(req).await;
        assert!(result.errors.is_empty(), "createSite mutation failed with errors: {:?}", result.errors);

        let data = result.data.into_json().unwrap();
        assert_eq!(data["createSite"]["name"], "Test Site");
        assert_eq!(data["createSite"]["location"], "US-West");
    }

    #[tokio::test]
    async fn test_complexity_limit() {
        let state = create_test_state().await;
        let schema = build_schema(state);

        // Create auth context with admin user
        let auth_ctx = crate::graphql::AuthContext::new(Some(crate::auth::jwt::Claims {
            sub: "test-user".to_string(),
            email: "test@example.com".to_string(),
            role: "admin".to_string(),
            iat: 0,
            exp: 9999999999,
            token_type: crate::auth::jwt::TokenType::Access,
            jti: "test-jti".to_string(),
        }));

        // Create a complex query (removed metrics since it's not implemented)
        let query = r#"
            query {
                sites {
                    id
                    name
                    status
                    endpointCount
                    createdAt
                    updatedAt
                }
                paths {
                    id
                    sourceSiteId
                    destinationSiteId
                    latencyMs
                    packetLoss
                    bandwidthMbps
                }
                policies {
                    id
                    name
                    priority
                    enabled
                }
            }
        "#;

        let req = async_graphql::Request::new(query).data(auth_ctx);
        let result = schema.execute(req).await;
        // This should succeed as it's within complexity limits
        assert!(result.errors.is_empty(), "Query failed with errors: {:?}", result.errors);
    }

    #[tokio::test]
    async fn test_introspection_query() {
        let state = create_test_state().await;
        let schema = build_schema(state);

        let query = r#"
            query {
                __schema {
                    queryType {
                        name
                    }
                    mutationType {
                        name
                    }
                    subscriptionType {
                        name
                    }
                }
            }
        "#;

        let result = schema.execute(query).await;
        assert!(result.errors.is_empty());

        let data = result.data.into_json().unwrap();
        assert_eq!(data["__schema"]["queryType"]["name"], "QueryRoot");
        assert_eq!(data["__schema"]["mutationType"]["name"], "MutationRoot");
        assert_eq!(data["__schema"]["subscriptionType"]["name"], "SubscriptionRoot");
    }
}
