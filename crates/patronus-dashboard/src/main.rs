//! Patronus SD-WAN Enterprise Dashboard
//!
//! Centralized management and monitoring interface for multi-site SD-WAN deployments.
#![allow(dead_code)]

use axum::http::{header, HeaderValue};
use axum::{
    body::Body,
    extract::ws::{WebSocket, WebSocketUpgrade},
    routing::{get, post},
    Router,
};
use futures::{SinkExt, StreamExt};
use std::net::SocketAddr;
use std::sync::Arc;
use tower_http::{
    cors::CorsLayer,
    services::ServeDir,
    set_header::SetResponseHeaderLayer,
    trace::{DefaultMakeSpan, TraceLayer},
};
use tracing::{info, Level};

use patronus_dashboard::{api, auth, graphql, ha, observability, state, ws};

use async_graphql::http::{playground_source, GraphQLPlaygroundConfig};
use async_graphql_axum::{GraphQLRequest, GraphQLResponse};
use observability::DashboardMetrics;
use state::AppState;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize tracing with OpenTelemetry support.
    // Set OTLP_ENDPOINT to export to a collector (Jaeger, Tempo, etc.);
    // otherwise traces are emitted to stdout for local development.
    let otlp_endpoint = std::env::var("OTLP_ENDPOINT").ok();
    observability::tracing::init_tracing("patronus-dashboard", otlp_endpoint.as_deref())?;

    info!("Starting Patronus SD-WAN Dashboard");

    // Initialize Prometheus metrics exporter
    let metrics_handle = metrics_exporter_prometheus::PrometheusBuilder::new()
        .install_recorder()
        .expect("Failed to install Prometheus recorder");

    info!("Prometheus metrics exporter initialized");

    // Initialize metrics collector
    let _metrics = DashboardMetrics::new();

    // HA / data-dir configuration, read from the env vars docker-compose.ha.yml
    // sets for every dashboard instance (PATRONUS_NODE_ID, PATRONUS_NODE_ADDR,
    // PATRONUS_PEERS, PATRONUS_DATA_DIR, PATRONUS_DB_PATH,
    // PATRONUS_ELECTION_TIMEOUT, PATRONUS_HEARTBEAT_INTERVAL). All are
    // optional: a plain single-node run (no env vars set) behaves exactly as
    // before, with HA disabled (`state.ha == None`).
    let db_path = std::env::var("PATRONUS_DB_PATH").unwrap_or_else(|_| "dashboard.db".to_string());

    // JWT signing secret: PATRONUS_JWT_SECRET (shared by all HA nodes) or a
    // persisted random secret file next to the DB. Refuse to start otherwise
    // -- there is no fixed fallback secret.
    match auth::jwt::init_from_env(&db_path) {
        Ok(auth::jwt::SecretSource::Env) => {
            info!(
                "JWT signing secret loaded from {}",
                auth::jwt::JWT_SECRET_ENV
            )
        }
        Ok(auth::jwt::SecretSource::ExistingFile(p)) => {
            info!("JWT signing secret loaded from {}", p.display())
        }
        Ok(auth::jwt::SecretSource::GeneratedFile(p)) => info!(
            "Generated new JWT signing secret at {} (set {} to share one secret across HA nodes)",
            p.display(),
            auth::jwt::JWT_SECRET_ENV
        ),
        Err(e) => anyhow::bail!("JWT signing secret setup failed: {}", e),
    }

    // Initialize application state
    let mut state = AppState::new(&db_path).await?;

    let node_id_env = std::env::var("PATRONUS_NODE_ID").ok();
    if let Some(node_id) = node_id_env {
        let node_addr_str =
            std::env::var("PATRONUS_NODE_ADDR").unwrap_or_else(|_| "0.0.0.0:8443".to_string());
        let node_addr: SocketAddr = node_addr_str
            .parse()
            .unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], 8443)));

        let peers: Vec<String> = std::env::var("PATRONUS_PEERS")
            .unwrap_or_default()
            .split(',')
            .map(|p| p.trim())
            .filter(|p| !p.is_empty())
            .map(|p| p.to_string())
            .collect();

        let data_dir =
            std::env::var("PATRONUS_DATA_DIR").unwrap_or_else(|_| "./data/raft".to_string());
        let election_timeout: u64 = std::env::var("PATRONUS_ELECTION_TIMEOUT")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(5);
        let heartbeat_interval: u64 = std::env::var("PATRONUS_HEARTBEAT_INTERVAL")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(1);

        // Ensure the sled data dir exists (sled::open will also create it,
        // but fail loudly here if the path is unusable, e.g. permissions).
        std::fs::create_dir_all(&data_dir).ok();

        // Sled-backed distributed state store (ha::state::DistributedState)
        // -- real persistence for cluster metadata, shared across restarts.
        match ha::state::DistributedState::new(&data_dir, "cluster") {
            Ok(dstate) => {
                let metadata = ha::state::ClusterMetadata {
                    version: env!("CARGO_PKG_VERSION").to_string(),
                    cluster_id: node_id.clone(),
                    created_at: chrono::Utc::now(),
                };
                if let Err(e) = dstate.set("node_metadata", &metadata) {
                    tracing::warn!("Failed to persist HA node metadata to sled: {}", e);
                }
                state.distributed_state = Some(Arc::new(dstate));
            }
            Err(e) => {
                tracing::warn!(
                    "Failed to open sled distributed-state store at {}: {}",
                    data_dir,
                    e
                );
            }
        }

        let cluster_state = Arc::new(ha::cluster::ClusterState::new(node_id.clone()));
        // Replicated operation log: every write (sites, policies, users,
        // token revocations, ...) is committed on a majority of nodes before
        // it is acknowledged, so failover never loses data and all nodes
        // converge on the same state.
        let replog_dir = std::path::Path::new(&data_dir).join("replog");
        let replog = ha::replication::ReplicationLog::open(&replog_dir).map_err(|e| {
            anyhow::anyhow!(
                "cannot open HA replication log at {}: {}",
                replog_dir.display(),
                e
            )
        })?;
        // Address peers use to reach this node; defaults to <node_id>:<port>,
        // which matches docker-compose.ha.yml's hostnames.
        let advertise_addr = std::env::var("PATRONUS_ADVERTISE_ADDR")
            .ok()
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| format!("{}:{}", node_id, node_addr.port()));
        let election = Arc::new(
            ha::election::LeaderElection::new(
                cluster_state,
                node_id.clone(),
                node_addr,
                peers.clone(),
                election_timeout,
                heartbeat_interval,
            )
            .with_advertise_addr(advertise_addr)
            .with_replication(replog, state.state_machine.clone()),
        );

        info!(
            node_id = %node_id,
            %node_addr,
            ?peers,
            election_timeout,
            heartbeat_interval,
            "HA leader election enabled"
        );

        // Run the election + heartbeat loops as background tasks alongside
        // the axum server, matching this codebase's existing pattern of
        // spawning long-running background workers from main() (see
        // policy_enforcer.start() / metrics_collector.start() / etc. above,
        // which do the same thing one layer down inside AppState::new).
        election.clone().start();

        state.ha = Some(election);
    } else {
        info!("PATRONUS_NODE_ID not set -- running as a standalone single-node dashboard (HA disabled)");
    }

    let state = Arc::new(state);
    api::edge::spawn_staleness_task(state.clone());

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
        // HA leader election RPC (node-to-node) + live status
        .merge(ha::rpc::routes())
        // Prometheus metrics
        .route(
            "/metrics",
            get(move || async move { metrics_handle.render() }),
        )
        // API v1 routes (REST)
        .nest("/api/v1", api::routes(state.clone()))
        // API v2 routes (GraphQL)
        .route(
            "/api/v2/graphql",
            post(graphql_handler).get(graphql_playground),
        )
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
    let addr: SocketAddr = std::env::var("PATRONUS_NODE_ADDR")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], 8443)));
    info!("Dashboard server listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
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
            auth.strip_prefix("Bearer ")
        })
        .and_then(|token| {
            // Validate JWT token
            auth::jwt::validate_token(token).ok()
        })
        .filter(|claims| claims.token_type == auth::jwt::TokenType::Access)
        .filter(|claims| !state.token_revocation.is_revoked(&claims.jti));

    // Same rule as the REST middleware: the account must still exist and be
    // active, so deactivating a user cuts off their outstanding tokens.
    let claims = match claims {
        Some(c) => match state.user_repository.get_user(&c.sub).await {
            Ok(Some(user)) if user.is_active => Some(c),
            _ => None,
        },
        None => None,
    };

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
    axum::response::Html(playground_source(GraphQLPlaygroundConfig::new(
        "/api/v2/graphql",
    )))
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
                            let _ = sender.send(Message::Text(json)).await;
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
    use axum::http::StatusCode;
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
            .body(Body::from(
                "404 - Frontend not built. Run: ./build-frontend.sh",
            ))
            .unwrap(),
    }
}
