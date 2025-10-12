//! WebSocket handlers for real-time updates (Sprint 27 Enhanced)
//!
//! This module provides WebSocket endpoints with JWT authentication
//! for streaming real-time metrics and events to dashboard clients.

use axum::{
    extract::{ws::{Message, WebSocket, WebSocketUpgrade}, Query, State},
    response::{IntoResponse, Response},
};
use futures::{sink::SinkExt, stream::StreamExt};
use serde::Deserialize;
use std::sync::Arc;
use tracing::{debug, info, warn};

use crate::{auth::jwt, state::AppState};

/// Query parameters for WebSocket authentication
#[derive(Debug, Deserialize)]
pub struct WsAuthQuery {
    /// JWT token for authentication
    token: Option<String>,
}

/// Handle metrics WebSocket connections (Sprint 27 Enhanced)
///
/// Streams real-time system metrics to connected clients.
/// Requires authentication via JWT token in query parameter.
///
/// **Example:** `ws://localhost:8443/ws/metrics?token=<jwt>`
pub async fn metrics_handler(
    ws: WebSocketUpgrade,
    Query(auth): Query<WsAuthQuery>,
    State(state): State<Arc<AppState>>,
) -> Response {
    // Validate JWT token (Sprint 27 Enhancement)
    let claims = match auth.token {
        Some(token) => match jwt::validate_token(&token) {
            Ok(claims) => {
                // Check if token is revoked (Sprint 29)
                if state.token_revocation.is_revoked(&claims.jti) {
                    warn!("WebSocket metrics connection rejected: token revoked");
                    return axum::http::StatusCode::UNAUTHORIZED.into_response();
                }
                Some(claims)
            }
            Err(e) => {
                warn!("WebSocket metrics connection rejected: invalid token - {}", e);
                return axum::http::StatusCode::UNAUTHORIZED.into_response();
            }
        },
        None => {
            warn!("WebSocket metrics connection rejected: no token provided");
            return axum::http::StatusCode::UNAUTHORIZED.into_response();
        }
    };

    info!(
        user = %claims.as_ref().map(|c| c.sub.as_str()).unwrap_or("unknown"),
        "WebSocket metrics connection authenticated"
    );

    ws.on_upgrade(move |socket| metrics_socket(socket, state, claims))
}

/// Handle events WebSocket connections (Sprint 27 Enhanced)
///
/// Streams real-time event notifications to connected clients.
/// Requires authentication via JWT token in query parameter.
///
/// **Example:** `ws://localhost:8443/ws/events?token=<jwt>`
pub async fn events_handler(
    ws: WebSocketUpgrade,
    Query(auth): Query<WsAuthQuery>,
    State(state): State<Arc<AppState>>,
) -> Response {
    // Validate JWT token (Sprint 27 Enhancement)
    let claims = match auth.token {
        Some(token) => match jwt::validate_token(&token) {
            Ok(claims) => {
                // Check if token is revoked (Sprint 29)
                if state.token_revocation.is_revoked(&claims.jti) {
                    warn!("WebSocket events connection rejected: token revoked");
                    return axum::http::StatusCode::UNAUTHORIZED.into_response();
                }
                Some(claims)
            }
            Err(e) => {
                warn!("WebSocket events connection rejected: invalid token - {}", e);
                return axum::http::StatusCode::UNAUTHORIZED.into_response();
            }
        },
        None => {
            warn!("WebSocket events connection rejected: no token provided");
            return axum::http::StatusCode::UNAUTHORIZED.into_response();
        }
    };

    info!(
        user = %claims.as_ref().map(|c| c.sub.as_str()).unwrap_or("unknown"),
        "WebSocket events connection authenticated"
    );

    ws.on_upgrade(move |socket| events_socket(socket, state, claims))
}

/// Metrics WebSocket handler (Sprint 27 Enhanced)
async fn metrics_socket(socket: WebSocket, state: Arc<AppState>, _claims: Option<jwt::Claims>) {
    // Increment connection counter
    {
        let mut counter = state.ws_connections.write().await;
        *counter += 1;
        info!(connections = *counter, "Metrics WebSocket client connected");
    }

    let (mut sender, mut receiver) = socket.split();

    // Subscribe to metrics updates
    let mut rx = state.metrics_tx.subscribe();

    // Spawn task to send updates to client
    let mut send_task = tokio::spawn(async move {
        while let Ok(update) = rx.recv().await {
            let json = serde_json::to_string(&update).unwrap();
            if sender.send(Message::Text(json.into())).await.is_err() {
                break;
            }
        }
    });

    // Handle incoming messages (ping/pong)
    let mut recv_task = tokio::spawn(async move {
        while let Some(Ok(msg)) = receiver.next().await {
            match msg {
                Message::Close(_) => break,
                Message::Ping(_ping) => {
                    debug!("Received ping");
                    // Pong is handled automatically by axum
                }
                _ => {}
            }
        }
    });

    // Wait for either task to finish
    tokio::select! {
        _ = (&mut send_task) => recv_task.abort(),
        _ = (&mut recv_task) => send_task.abort(),
    }

    // Decrement connection counter
    {
        let mut counter = state.ws_connections.write().await;
        *counter -= 1;
        info!(connections = *counter, "Metrics WebSocket client disconnected");
    }
}

/// Events WebSocket handler (Sprint 27 Enhanced)
async fn events_socket(socket: WebSocket, state: Arc<AppState>, _claims: Option<jwt::Claims>) {
    // Increment connection counter
    {
        let mut counter = state.ws_connections.write().await;
        *counter += 1;
        info!(connections = *counter, "Events WebSocket client connected");
    }

    let (mut sender, mut receiver) = socket.split();

    // Subscribe to event updates
    let mut rx = state.events_tx.subscribe();

    // Spawn task to send updates to client
    let mut send_task = tokio::spawn(async move {
        while let Ok(event) = rx.recv().await {
            let json = serde_json::to_string(&event).unwrap();
            if sender.send(Message::Text(json.into())).await.is_err() {
                break;
            }
        }
    });

    // Handle incoming messages
    let mut recv_task = tokio::spawn(async move {
        while let Some(Ok(msg)) = receiver.next().await {
            match msg {
                Message::Close(_) => break,
                _ => {}
            }
        }
    });

    // Wait for either task to finish
    tokio::select! {
        _ = (&mut send_task) => recv_task.abort(),
        _ = (&mut recv_task) => send_task.abort(),
    }

    // Decrement connection counter
    {
        let mut counter = state.ws_connections.write().await;
        *counter -= 1;
        info!(connections = *counter, "Events WebSocket client disconnected");
    }
}
