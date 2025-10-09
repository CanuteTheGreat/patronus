//! Patronus Web Interface
//!
//! Provides the web-based management interface for Patronus.

use std::net::SocketAddr;

pub mod auth;
pub mod handlers;
pub mod routes;
pub mod state;
pub mod templates;

pub use state::AppState;
pub use auth::{SessionStore, AuthUser, AdminUser};

/// Create the web application router
pub fn create_app(state: AppState, session_store: SessionStore) -> axum::Router {
    routes::build_router(state, session_store)
}

/// Start the web server
pub async fn serve(addr: SocketAddr, state: AppState) -> anyhow::Result<()> {
    let session_store = SessionStore::new();

    // Start session cleanup task
    let cleanup_store = session_store.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(3600));
        loop {
            interval.tick().await;
            cleanup_store.cleanup_expired().await;
            tracing::debug!("Cleaned up expired sessions");
        }
    });

    let app = create_app(state, session_store);

    tracing::info!("Starting web server on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
