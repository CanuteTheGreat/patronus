// GraphQL API v2 - Modern API Gateway
//
// This module provides a GraphQL API for Patronus SD-WAN management,
// offering a more flexible and efficient alternative to REST endpoints.

pub mod auth;
pub mod schema;
pub mod types;
pub mod queries;
pub mod mutations;
pub mod subscriptions;

pub use auth::{AuthContext, require_auth, require_role, require_min_role};
pub use schema::{build_schema, AppSchema};

use async_graphql::{Context, Result};
use crate::state::AppState;
use std::sync::Arc;

/// Helper to get AppState from GraphQL context
pub fn get_state<'a>(ctx: &'a Context<'_>) -> Result<&'a Arc<AppState>> {
    ctx.data::<Arc<AppState>>()
        .map_err(|_| "AppState not found in context".into())
}
