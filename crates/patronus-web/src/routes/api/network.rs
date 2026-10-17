//! Network API endpoints

use crate::state::AppState;
use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};

/// GET /api/network/routes -- the kernel's main routing table (IPv4+IPv6).
pub async fn list_routes(State(state): State<AppState>) -> Response {
    match state.network.list_routes().await {
        Ok(routes) => Json(routes).into_response(),
        Err(e) => {
            tracing::error!("Failed to list routes: {}", e);
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({
                    "error": format!("cannot read the routing table: {e}")
                })),
            )
                .into_response()
        }
    }
}

/// This lane's API routes, mounted under `/api` by `routes::api_routes`
/// with one `.merge(network::router())` line.
pub fn router() -> axum::Router<AppState> {
    // /network/interfaces* moved to routes/api/interfaces.rs (lane C);
    // DHCP/DNS/NTP/DDNS live in routes/api/lan.rs (lane D: /api/dhcp/*, ...)
    use axum::routing::get;
    axum::Router::new().route("/network/routes", get(list_routes))
}
