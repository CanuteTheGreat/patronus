//! API endpoints

pub mod auth;
pub mod flows;
pub mod metrics;
pub mod paths;
pub mod policies;
pub mod sites;

use axum::{
    middleware::{from_fn, from_fn_with_state},
    routing::{get, post},
    Router,
};
use std::sync::Arc;

use crate::state::AppState;

/// REST API v1 router (mounted at `/api/v1`).
///
/// Only login, token refresh and first-run admin creation are public.
/// Every other route sits behind [`crate::auth::middleware::auth_middleware`]
/// (valid, unrevoked bearer token for an active user), which also puts the
/// caller's claims in the request extensions that `/auth/me` and
/// `/auth/change-password` read. Policy writes additionally require the
/// Operator role. Before this was wired, the middleware existed but was
/// never attached, so anyone could create/replace/delete firewall policies
/// without credentials.
pub fn routes(state: Arc<AppState>) -> Router<Arc<AppState>> {
    use axum::routing::{delete, put};

    let public = Router::new()
        .route("/auth/login", post(auth::login))
        .route("/auth/refresh", post(auth::refresh))
        .route("/auth/init-admin", post(auth::init_admin));

    let policy_writes = Router::new()
        .route("/policies", post(policies::create_policy))
        .route("/policies/:id", put(policies::update_policy))
        .route("/policies/:id", delete(policies::delete_policy))
        .route_layer(from_fn(crate::auth::middleware::require_operator));

    let protected = Router::new()
        .route("/auth/me", get(auth::me))
        .route("/auth/change-password", post(auth::change_password))
        // Sites
        .route("/sites", get(sites::list_sites))
        .route("/sites/:id", get(sites::get_site))
        // Paths
        .route("/paths", get(paths::list_paths))
        .route("/paths/:id", get(paths::get_path))
        .route("/paths/:id/metrics", get(paths::get_path_metrics))
        // Flows
        .route("/flows", get(flows::list_flows))
        // Policies
        .route("/policies", get(policies::list_policies))
        .route("/policies/:id", get(policies::get_policy))
        .merge(policy_writes)
        // Metrics
        .route("/metrics/summary", get(metrics::get_summary))
        .route("/metrics/timeseries", get(metrics::get_timeseries))
        .route_layer(from_fn_with_state(
            state,
            crate::auth::middleware::auth_middleware,
        ));

    public.merge(protected)
}
