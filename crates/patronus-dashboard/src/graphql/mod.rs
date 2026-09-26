// GraphQL API v2 - Modern API Gateway
//
// This module provides a GraphQL API for Patronus SD-WAN management,
// offering a more flexible and efficient alternative to REST endpoints.

pub mod auth;
pub mod mutations;
pub mod queries;
pub mod schema;
pub mod subscriptions;
pub mod types;

pub use auth::{require_auth, require_min_role, require_role, AuthContext};
pub use schema::{build_schema, AppSchema};

use crate::state::AppState;
use async_graphql::{Context, Result};
use std::sync::Arc;

/// Helper to get AppState from GraphQL context
pub fn get_state<'a>(ctx: &'a Context<'_>) -> Result<&'a Arc<AppState>> {
    ctx.data::<Arc<AppState>>()
        .map_err(|_| "AppState not found in context".into())
}
