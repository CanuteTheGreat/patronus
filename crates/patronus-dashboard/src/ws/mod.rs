//! WebSocket handlers for real-time updates

use axum::{
    extract::{ws::{Message, WebSocket, WebSocketUpgrade}, State},
    response::Response,
};
use futures::{sink::SinkExt, stream::StreamExt};
use std::sync::Arc;
use tracing::{debug, info};

use crate::state::AppState;

/// Handle metrics WebSocket connections
pub async fn metrics_handler(
    ws: WebSocketUpgrade,
    State(state): State<Arc<AppState>>,
) -> Response {
    ws.on_upgrade(move |socket| metrics_socket(socket, state))
}

/// Handle events WebSocket connections
pub async fn events_handler(
    ws: WebSocketUpgrade,
    State(state): State<Arc<AppState>>,
) -> Response {
    ws.on_upgrade(move |socket| events_socket(socket, state))
}

/// Metrics WebSocket handler
async fn metrics_socket(socket: WebSocket, state: Arc<AppState>) {
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
            if sender.send(Message::Text(json)).await.is_err() {
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

/// Events WebSocket handler
async fn events_socket(socket: WebSocket, state: Arc<AppState>) {
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
            if sender.send(Message::Text(json)).await.is_err() {
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
