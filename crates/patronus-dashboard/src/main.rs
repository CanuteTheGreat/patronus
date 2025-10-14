//! Patronus SD-WAN Enterprise Dashboard
//!
//! Centralized management and monitoring interface for multi-site SD-WAN deployments.

use axum::{
    extract::ws::{WebSocket, WebSocketUpgrade},
    routing::{get, post},
    Router,
    body::Body,
};
use std::net::SocketAddr;
use std::sync::Arc;
use tower_http::{
    cors::CorsLayer,
    services::ServeDir,
    trace::{DefaultMakeSpan, TraceLayer},
    set_header::SetResponseHeaderLayer,
};
use axum::http::{header, HeaderValue};
use tracing::{info, Level};
use tracing_subscriber::{fmt, prelude::*, EnvFilter};
use futures::{StreamExt, SinkExt};

mod api;
mod auth;
mod cache;
mod error;
mod graphql;
mod ha;
mod observability;
mod security;
mod state;
mod ws;

use crate::{observability::DashboardMetrics, state::AppState};
use async_graphql::http::{GraphQLPlaygroundConfig, playground_source};
use async_graphql_axum::{GraphQLRequest, GraphQLResponse};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize tracing
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("patronus_dashboard=info,tower_http=debug")),
        )
        .init();

    info!("Starting Patronus SD-WAN Dashboard");

    // Initialize Prometheus metrics exporter
    let metrics_handle = metrics_exporter_prometheus::PrometheusBuilder::new()
        .install_recorder()
        .expect("Failed to install Prometheus recorder");

    info!("Prometheus metrics exporter initialized");

    // Initialize metrics collector
    let metrics = DashboardMetrics::new();

    // Initialize application state
    let state = AppState::new("dashboard.db").await?;
    let state = Arc::new(state);

    info!("Application state initialized");

    // Build GraphQL schema
    let schema = graphql::build_schema(state.clone());
    info!("GraphQL schema initialized");

    // Build router with security headers and monitoring
    let app = Router::new()
        // Health checks
        .route("/health", get(health_check))
        .route("/health/live", get(liveness_check))
        .route("/health/ready", get(readiness_check))
        // Prometheus metrics
        .route("/metrics", get(move || async move {
            metrics_handle.render()
        }))
        // API v1 routes (REST)
        .nest("/api/v1", api_routes())
        // API v2 routes (GraphQL)
        .route("/api/v2/graphql", post(graphql_handler).get(graphql_playground))
        .route("/api/v2/graphql/ws", get(graphql_ws_handler))
        // WebSocket routes
        .route("/ws/metrics", get(ws::metrics_handler))
        .route("/ws/events", get(ws::events_handler))
        // Static file serving
        .nest_service("/assets", ServeDir::new("static/assets"))
        // SPA fallback - must be last to catch all unmatched routes
        .fallback(spa_fallback)
        // Add middleware layers (order matters - last added = first executed)
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(DefaultMakeSpan::default().level(Level::INFO)),
        )
        // Security headers
        .layer(SetResponseHeaderLayer::if_not_present(
            header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            header::X_FRAME_OPTIONS,
            HeaderValue::from_static("DENY"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            header::X_XSS_PROTECTION,
            HeaderValue::from_static("1; mode=block"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            header::STRICT_TRANSPORT_SECURITY,
            HeaderValue::from_static("max-age=31536000; includeSubDomains"),
        ))
        .layer(CorsLayer::permissive())
        .layer(axum::Extension(schema))
        .with_state(state);

    // Start server
    let addr = SocketAddr::from(([0, 0, 0, 0], 8443));
    info!("Dashboard server listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

/// API v1 routes
fn api_routes() -> Router<Arc<AppState>> {
    use axum::routing::{delete, put};

    Router::new()
        // Authentication (public routes)
        .route("/auth/login", post(api::auth::login))
        .route("/auth/refresh", post(api::auth::refresh))
        .route("/auth/init-admin", post(api::auth::init_admin))
        // Protected routes (require authentication)
        .route("/auth/me", get(api::auth::me))
        .route("/auth/change-password", post(api::auth::change_password))
        // Sites
        .route("/sites", get(api::sites::list_sites))
        .route("/sites/:id", get(api::sites::get_site))
        // Paths
        .route("/paths", get(api::paths::list_paths))
        .route("/paths/:id", get(api::paths::get_path))
        .route("/paths/:id/metrics", get(api::paths::get_path_metrics))
        // Flows
        .route("/flows", get(api::flows::list_flows))
        // Policies
        .route("/policies", get(api::policies::list_policies))
        .route("/policies", post(api::policies::create_policy))
        .route("/policies/:id", get(api::policies::get_policy))
        .route("/policies/:id", put(api::policies::update_policy))
        .route("/policies/:id", delete(api::policies::delete_policy))
        // Metrics
        .route("/metrics/summary", get(api::metrics::get_summary))
        .route("/metrics/timeseries", get(api::metrics::get_timeseries))
}

/// Basic health check endpoint
async fn health_check() -> &'static str {
    "OK"
}

/// Liveness probe (Kubernetes-style)
async fn liveness_check() -> &'static str {
    "alive"
}

/// Readiness probe (Kubernetes-style)
async fn readiness_check() -> &'static str {
    "ready"
}

/// GraphQL query/mutation handler
async fn graphql_handler(
    axum::extract::State(state): axum::extract::State<Arc<AppState>>,
    schema: axum::Extension<graphql::AppSchema>,
    headers: axum::http::HeaderMap,
    req: GraphQLRequest,
) -> GraphQLResponse {
    // Extract JWT token from Authorization header
    let claims = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|auth| {
            // Remove "Bearer " prefix
            if auth.starts_with("Bearer ") {
                Some(&auth[7..])
            } else {
                None
            }
        })
        .and_then(|token| {
            // Validate JWT token
            auth::jwt::validate_token(token).ok()
        })
        .and_then(|claims| {
            // Check if token is revoked (Sprint 29)
            if state.token_revocation.is_revoked(&claims.jti) {
                None // Token revoked, reject it
            } else {
                Some(claims)
            }
        });

    // Create auth context
    let auth_context = graphql::AuthContext::new(claims);

    // Execute query with auth context
    schema
        .execute(req.into_inner().data(auth_context))
        .await
        .into()
}

/// GraphQL Playground UI
async fn graphql_playground() -> impl axum::response::IntoResponse {
    axum::response::Html(playground_source(
        GraphQLPlaygroundConfig::new("/api/v2/graphql")
    ))
}

/// GraphQL WebSocket handler for subscriptions
async fn graphql_ws_handler(
    ws: WebSocketUpgrade,
    axum::extract::State(state): axum::extract::State<Arc<AppState>>,
    schema: axum::Extension<graphql::AppSchema>,
) -> impl axum::response::IntoResponse {
    ws.on_upgrade(move |socket| graphql_ws_connection(socket, state, schema.0))
}

/// Handle GraphQL WebSocket connection
async fn graphql_ws_connection(
    socket: WebSocket,
    _state: Arc<AppState>,
    schema: graphql::AppSchema,
) {
    use async_graphql::http::{WebSocketProtocols, WsMessage, ALL_WEBSOCKET_PROTOCOLS};
    use axum::extract::ws::Message;

    let (mut sender, mut receiver) = socket.split();

    // Create a simple message handler
    // This is a simplified implementation for now
    // Full GraphQL-WS protocol can be added later if needed
    while let Some(Ok(msg)) = receiver.next().await {
        match msg {
            Message::Text(text) => {
                // Parse as GraphQL request and execute
                if let Ok(request) = serde_json::from_str::<serde_json::Value>(&text) {
                    // Check if it's a subscription request
                    if let Some(query) = request.get("query").and_then(|q| q.as_str()) {
                        // Execute the query
                        let gql_request = async_graphql::Request::new(query);
                        let response = schema.execute(gql_request).await;

                        // Send response
                        if let Ok(json) = serde_json::to_string(&response) {
                            let _ = sender.send(Message::Text(json.into())).await;
                        }
                    }
                }
            }
            Message::Close(_) => {
                break;
            }
            _ => {}
        }
    }
}

/// SPA fallback handler - serves index.html for all non-API routes
async fn spa_fallback() -> impl axum::response::IntoResponse {
    use axum::http::{StatusCode, Uri};
    use axum::response::Response;
    use std::fs;

    // Try to read index.html
    match fs::read_to_string("static/index.html") {
        Ok(contents) => Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "text/html")
            .body(Body::from(contents))
            .unwrap(),
        Err(_) => Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Body::from("404 - Frontend not built. Run: ./build-frontend.sh"))
            .unwrap(),
    }
}
