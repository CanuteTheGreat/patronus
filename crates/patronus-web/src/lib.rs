//! Patronus Web Interface
//!
//! Provides the web-based management interface for Patronus.

use std::net::SocketAddr;

pub mod handlers;
pub mod routes;
pub mod state;
pub mod templates;

pub use state::AppState;

/// Create the web application router
pub fn create_app(state: AppState) -> axum::Router {
    routes::build_router(state)
}

/// Start the web server
pub async fn serve(addr: SocketAddr, state: AppState) -> anyhow::Result<()> {
    let app = create_app(state);

    tracing::info!("Starting web server on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
