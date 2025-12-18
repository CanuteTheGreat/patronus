//! Patronus Web Interface
//!
//! Provides the web-based management interface for Patronus.

use std::net::SocketAddr;

pub mod auth;
pub mod handlers;
pub mod qrcode;
pub mod routes;
pub mod simple_handlers;
pub mod state;
pub mod templates;
pub mod websocket;

pub use state::AppState;
pub use auth::{SessionStore, AuthUser, AdminUser};
pub use websocket::WsBroadcaster;

/// Create the web application router
pub fn create_app(
    state: AppState,
    ws_broadcaster: std::sync::Arc<WsBroadcaster>,
) -> axum::Router {
    routes::build_router(state, ws_broadcaster)
}

/// Start the web server
pub async fn serve(addr: SocketAddr, state: AppState) -> anyhow::Result<()> {
    let ws_broadcaster = std::sync::Arc::new(WsBroadcaster::new());

    // Start session cleanup task
    let cleanup_state = state.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(3600));
        loop {
            interval.tick().await;
            cleanup_state.auth.session_store.cleanup_expired().await;
            tracing::debug!("Cleaned up expired sessions");
        }
    });

    // Start WebSocket broadcaster tasks
    websocket::start_metrics_broadcaster(ws_broadcaster.clone(), state.clone());
    websocket::start_log_broadcaster(ws_broadcaster.clone());

    let app = create_app(state, ws_broadcaster);

    tracing::info!("Starting web server on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
