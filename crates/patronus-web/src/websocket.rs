//! WebSocket support for real-time updates
//!
//! Provides WebSocket connections for:
//! - Real-time system metrics
//! - Live firewall logs
//! - VPN connection events
//! - System alerts and notifications

use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        State,
    },
    response::IntoResponse,
};
use futures::{sink::SinkExt, stream::StreamExt};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::broadcast;
use tokio::time::{interval, Duration};

/// WebSocket message types
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum WsMessage {
    /// System metrics update
    SystemMetrics {
        cpu: f64,
        memory: f64,
        disk: f64,
        network_rx: u64,
        network_tx: u64,
    },

    /// Firewall event
    FirewallEvent {
        timestamp: String,
        action: String,
        source: String,
        destination: String,
        protocol: String,
        port: u16,
    },

    /// VPN connection event
    VpnEvent {
        timestamp: String,
        peer: String,
        event_type: String, // connected, disconnected, handshake
        remote_ip: Option<String>,
    },

    /// System alert
    Alert {
        timestamp: String,
        severity: String,
        component: String,
        message: String,
    },

    /// Log entry
    LogEntry {
        timestamp: String,
        level: String,
        component: String,
        message: String,
    },

    /// Ping/Pong for keepalive
    Ping,
    Pong,
}

/// WebSocket broadcast channel
#[derive(Clone)]
pub struct WsBroadcaster {
    tx: broadcast::Sender<WsMessage>,
}

impl Default for WsBroadcaster {
    fn default() -> Self {
        Self::new()
    }
}

impl WsBroadcaster {
    pub fn new() -> Self {
        let (tx, _) = broadcast::channel(100);
        Self { tx }
    }

    /// Broadcast a message to all connected clients
    pub fn broadcast(&self, msg: WsMessage) {
        let _ = self.tx.send(msg);
    }

    /// Subscribe to broadcasts
    pub fn subscribe(&self) -> broadcast::Receiver<WsMessage> {
        self.tx.subscribe()
    }
}

/// WebSocket handler for metrics stream
pub async fn ws_metrics_handler(
    ws: WebSocketUpgrade,
    State(state): State<crate::state::AppState>,
    State(broadcaster): State<Arc<WsBroadcaster>>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_metrics_socket(socket, state, broadcaster))
}

/// WebSocket handler for log stream
pub async fn ws_logs_handler(
    ws: WebSocketUpgrade,
    State(broadcaster): State<Arc<WsBroadcaster>>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_logs_socket(socket, broadcaster))
}

/// Handle WebSocket connection for metrics
async fn handle_metrics_socket(
    socket: WebSocket,
    _state: crate::state::AppState,
    broadcaster: Arc<WsBroadcaster>,
) {
    let (mut sender, mut receiver) = socket.split();

    // Subscribe to broadcasts
    let mut rx = broadcaster.subscribe();

    // Spawn task to send broadcasts to this client
    let mut send_task = tokio::spawn(async move {
        while let Ok(msg) = rx.recv().await {
            let json = match serde_json::to_string(&msg) {
                Ok(j) => j,
                Err(e) => {
                    tracing::error!("Failed to serialize WebSocket message: {}", e);
                    continue;
                }
            };

            if sender.send(Message::Text(json)).await.is_err() {
                break;
            }
        }
    });

    // Spawn task to receive messages from client (mostly ping/pong)
    let mut recv_task = tokio::spawn(async move {
        while let Some(Ok(msg)) = receiver.next().await {
            match msg {
                Message::Text(text) => {
                    if let Ok(WsMessage::Ping) = serde_json::from_str::<WsMessage>(&text) {
                        // Respond with pong (handled by send task via broadcaster)
                    }
                }
                Message::Close(_) => break,
                _ => {}
            }
        }
    });

    // Wait for either task to finish
    tokio::select! {
        _ = &mut send_task => recv_task.abort(),
        _ = &mut recv_task => send_task.abort(),
    };

    tracing::debug!("WebSocket connection closed");
}

/// Handle WebSocket connection for logs
async fn handle_logs_socket(socket: WebSocket, broadcaster: Arc<WsBroadcaster>) {
    let (mut sender, mut receiver) = socket.split();
    let mut rx = broadcaster.subscribe();

    // Filter for log entries only
    let mut send_task = tokio::spawn(async move {
        while let Ok(msg) = rx.recv().await {
            // Only send log entries on this channel
            if matches!(msg, WsMessage::LogEntry { .. }) {
                let json = match serde_json::to_string(&msg) {
                    Ok(j) => j,
                    Err(_) => continue,
                };

                if sender.send(Message::Text(json)).await.is_err() {
                    break;
                }
            }
        }
    });

    let mut recv_task = tokio::spawn(async move {
        while let Some(Ok(msg)) = receiver.next().await {
            if matches!(msg, Message::Close(_)) {
                break;
            }
        }
    });

    tokio::select! {
        _ = &mut send_task => recv_task.abort(),
        _ = &mut recv_task => send_task.abort(),
    };
}

/// Start background task that measures and broadcasts system metrics
/// (CPU over the last second, memory, root filesystem, throughput in
/// bits/s) while anyone is subscribed. This used to broadcast random
/// numbers.
pub fn start_metrics_broadcaster(broadcaster: Arc<WsBroadcaster>, _state: crate::state::AppState) {
    use crate::state::host;
    tokio::spawn(async move {
        let mut interval = interval(Duration::from_secs(1));

        loop {
            interval.tick().await;
            if broadcaster.tx.receiver_count() == 0 {
                continue;
            }
            let s = host::sample(Duration::from_millis(500)).await;
            let metrics = WsMessage::SystemMetrics {
                cpu: s.cpu_percent.unwrap_or(0.0),
                memory: host::memory().map(|m| m.0).unwrap_or(0.0),
                disk: host::disk_percent("/").unwrap_or(0.0),
                network_rx: s.rx_rate() * 8,
                network_tx: s.tx_rate() * 8,
            };

            broadcaster.broadcast(metrics);
        }
    });
}

// There is deliberately no log broadcaster: the one that was here
// broadcast invented log lines ("DHCP lease assigned to 00:11:22:33:44:55")
// every 2 s. Log entries reach clients only from a real source.

/// Broadcast a firewall event
pub fn broadcast_firewall_event(
    broadcaster: &WsBroadcaster,
    action: &str,
    source: &str,
    destination: &str,
    protocol: &str,
    port: u16,
) {
    broadcaster.broadcast(WsMessage::FirewallEvent {
        timestamp: chrono::Utc::now().to_rfc3339(),
        action: action.to_string(),
        source: source.to_string(),
        destination: destination.to_string(),
        protocol: protocol.to_string(),
        port,
    });
}

/// Broadcast a VPN event
pub fn broadcast_vpn_event(
    broadcaster: &WsBroadcaster,
    peer: &str,
    event_type: &str,
    remote_ip: Option<&str>,
) {
    broadcaster.broadcast(WsMessage::VpnEvent {
        timestamp: chrono::Utc::now().to_rfc3339(),
        peer: peer.to_string(),
        event_type: event_type.to_string(),
        remote_ip: remote_ip.map(|s| s.to_string()),
    });
}

/// Broadcast a system alert
pub fn broadcast_alert(
    broadcaster: &WsBroadcaster,
    severity: &str,
    component: &str,
    message: &str,
) {
    broadcaster.broadcast(WsMessage::Alert {
        timestamp: chrono::Utc::now().to_rfc3339(),
        severity: severity.to_string(),
        component: component.to_string(),
        message: message.to_string(),
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_broadcaster_creation() {
        let broadcaster = WsBroadcaster::new();
        let _rx = broadcaster.subscribe();
        // Should not panic
    }

    #[test]
    fn test_message_serialization() {
        let msg = WsMessage::SystemMetrics {
            cpu: 50.0,
            memory: 60.0,
            disk: 70.0,
            network_rx: 1000,
            network_tx: 2000,
        };

        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("system_metrics"));
        assert!(json.contains("50.0"));
    }

    #[test]
    fn test_broadcast() {
        let broadcaster = WsBroadcaster::new();
        let mut rx = broadcaster.subscribe();

        let msg = WsMessage::Ping;
        broadcaster.broadcast(msg.clone());

        // Should receive the message
        let received = rx.try_recv();
        assert!(received.is_ok());
    }
}
