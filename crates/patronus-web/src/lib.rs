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

pub use auth::{AdminUser, AuthUser, SessionStore};
pub use state::AppState;
pub use websocket::WsBroadcaster;

/// Create the web application router
pub fn create_app(state: AppState, ws_broadcaster: std::sync::Arc<WsBroadcaster>) -> axum::Router {
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

    // Start secret rotation enforcement task. `enforce_rotation_policy()` was
    // previously implemented but never actually invoked anywhere in the
    // codebase, so no secret was ever auto-rotated in a running process --
    // only ever on an ad-hoc call from a test. Run it on the same hourly
    // cadence as session cleanup.
    let rotation_state = state.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(3600));
        loop {
            interval.tick().await;
            match rotation_state.secrets.enforce_rotation_policy().await {
                Ok(result) => {
                    if !result.auto_rotated.is_empty() {
                        tracing::info!(
                            "Auto-rotated {} secret(s): {:?}",
                            result.auto_rotated.len(),
                            result.auto_rotated
                        );
                    }
                    if !result.needs_manual_rotation.is_empty() {
                        tracing::warn!(
                            "{} secret(s) need manual rotation: {:?}",
                            result.needs_manual_rotation.len(),
                            result.needs_manual_rotation
                        );
                    }
                }
                Err(e) => {
                    tracing::error!("Failed to enforce secret rotation policy: {}", e);
                }
            }
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
