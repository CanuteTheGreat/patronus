//! BFD-based health monitoring
//!
//! This module integrates BFD (Bidirectional Forwarding Detection) with the
//! health monitoring system, providing sub-second failure detection.

use super::bfd::{BfdConfig, BfdSession, BfdState};
use super::{PathHealth, PathStatus};
use crate::types::PathId;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::SystemTime;
use tokio::sync::{mpsc, RwLock};
use tracing::{error, info};

/// BFD health monitor that tracks path health using BFD sessions
pub struct BfdHealthMonitor {
    /// Active BFD sessions mapped by path ID
    sessions: Arc<RwLock<HashMap<PathId, Arc<BfdSession>>>>,

    /// Current health status derived from BFD state
    health_cache: Arc<RwLock<HashMap<PathId, PathHealth>>>,

    /// Channel for receiving BFD state changes
    state_rx: Arc<RwLock<Option<mpsc::Receiver<(PathId, BfdState)>>>>,
}

impl BfdHealthMonitor {
    /// Create a new BFD health monitor
    pub fn new() -> Self {
        Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
            health_cache: Arc::new(RwLock::new(HashMap::new())),
            state_rx: Arc::new(RwLock::new(None)),
        }
    }

    /// Add a BFD session for a path
    ///
    /// # Arguments
    ///
    /// * `path_id` - Path to monitor
    /// * `local_addr` - Local address to bind BFD session
    /// * `remote_addr` - Remote peer address for BFD
    ///
    /// # Returns
    ///
    /// Result indicating success or error
    pub async fn add_session(
        &self,
        path_id: PathId,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let config = BfdConfig {
            local_discriminator: rand::random(),
            desired_min_tx_interval: 300_000, // 300ms
            required_min_rx_interval: 300_000, // 300ms
            detect_mult: 3, // 3 * 300ms = 900ms detection time
            local_addr,
            remote_addr,
        };

        let session = Arc::new(BfdSession::new(config));

        // Create state change channel
        let (state_tx, _state_rx) = mpsc::channel(100);

        // Store session
        {
            let mut sessions = self.sessions.write().await;
            sessions.insert(path_id.clone(), session.clone());
        }

        // Initialize health as Down (will be updated when BFD comes up)
        {
            let mut cache = self.health_cache.write().await;
            cache.insert(
                path_id.clone(),
                PathHealth {
                    path_id: path_id.clone(),
                    latency_ms: 0.0,
                    packet_loss_pct: 100.0,
                    jitter_ms: 0.0,
                    health_score: 0.0,
                    status: PathStatus::Down,
                    last_checked: SystemTime::now(),
                },
            );
        }

        // Start BFD session
        let session_clone = session.clone();
        let path_id_clone = path_id.clone();
        tokio::spawn(async move {
            if let Err(e) = session_clone.start(state_tx).await {
                error!("BFD session failed for path {}: {}", path_id_clone, e);
            }
        });

        info!(
            "BFD session started for path {}: {} -> {}",
            path_id, local_addr, remote_addr
        );

        Ok(())
    }

    /// Remove a BFD session for a path
    pub async fn remove_session(&self, path_id: &PathId) {
        let mut sessions = self.sessions.write().await;
        if sessions.remove(path_id).is_some() {
            info!("BFD session removed for path {}", path_id);
        }

        let mut cache = self.health_cache.write().await;
        cache.remove(path_id);
    }

    /// Get current health for a path
    pub async fn get_path_health(&self, path_id: &PathId) -> Option<PathHealth> {
        let cache = self.health_cache.read().await;
        cache.get(path_id).cloned()
    }

    /// Get all monitored paths
    pub async fn get_all_health(&self) -> HashMap<PathId, PathHealth> {
        let cache = self.health_cache.read().await;
        cache.clone()
    }

    /// Start monitoring BFD state changes
    ///
    /// This spawns a background task that listens for BFD state changes
    /// and updates the health cache accordingly.
    ///
    /// # Arguments
    ///
    /// * `state_change_tx` - Optional channel to forward state changes to failover engine
    ///
    /// # Returns
    ///
    /// JoinHandle for the monitoring task
    pub fn start_monitoring(
        self: Arc<Self>,
        state_change_tx: Option<mpsc::Sender<(PathId, PathHealth)>>,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            loop {
                // Check all sessions for state changes
                let sessions = {
                    let sessions_guard = self.sessions.read().await;
                    sessions_guard.clone()
                };

                for (path_id, session) in sessions {
                    let current_state = session.state().await;

                    // Get current health from cache
                    let current_health = {
                        let cache = self.health_cache.read().await;
                        cache.get(&path_id).cloned()
                    };

                    // Convert BFD state to PathHealth
                    let new_health = self.bfd_state_to_health(&path_id, current_state).await;

                    // Check if state changed
                    if let Some(old_health) = current_health {
                        if old_health.status != new_health.status {
                            info!(
                                "BFD path {} state changed: {:?} -> {:?}",
                                path_id, old_health.status, new_health.status
                            );

                            // Update cache
                            {
                                let mut cache = self.health_cache.write().await;
                                cache.insert(path_id.clone(), new_health.clone());
                            }

                            // Notify subscribers
                            if let Some(ref tx) = state_change_tx {
                                let _ = tx.send((path_id.clone(), new_health.clone())).await;
                            }
                        }
                    } else {
                        // First health check - store it
                        let mut cache = self.health_cache.write().await;
                        cache.insert(path_id.clone(), new_health);
                    }
                }

                // Check every 100ms for state changes
                tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
            }
        })
    }

    /// Convert BFD state to PathHealth
    async fn bfd_state_to_health(&self, path_id: &PathId, state: BfdState) -> PathHealth {
        let (status, health_score, packet_loss_pct) = match state {
            BfdState::Up => (PathStatus::Up, 100.0, 0.0),
            BfdState::Init => (PathStatus::Degraded, 50.0, 50.0),
            BfdState::Down => (PathStatus::Down, 0.0, 100.0),
            BfdState::AdminDown => (PathStatus::Down, 0.0, 100.0),
        };

        PathHealth {
            path_id: path_id.clone(),
            latency_ms: 0.0, // BFD doesn't measure latency
            packet_loss_pct,
            jitter_ms: 0.0, // BFD doesn't measure jitter
            health_score,
            status,
            last_checked: SystemTime::now(),
        }
    }

    /// Get BFD session for a path
    pub async fn get_session(&self, path_id: &PathId) -> Option<Arc<BfdSession>> {
        let sessions = self.sessions.read().await;
        sessions.get(path_id).cloned()
    }

    /// Get statistics about BFD sessions
    pub async fn get_stats(&self) -> BfdHealthStats {
        let sessions = self.sessions.read().await;
        let mut stats = BfdHealthStats {
            total_sessions: sessions.len(),
            up_sessions: 0,
            init_sessions: 0,
            down_sessions: 0,
        };

        for session in sessions.values() {
            match session.state().await {
                BfdState::Up => stats.up_sessions += 1,
                BfdState::Init => stats.init_sessions += 1,
                BfdState::Down | BfdState::AdminDown => stats.down_sessions += 1,
            }
        }

        stats
    }
}

/// Statistics about BFD health monitoring
#[derive(Debug, Clone)]
pub struct BfdHealthStats {
    /// Total number of BFD sessions
    pub total_sessions: usize,

    /// Number of sessions in Up state
    pub up_sessions: usize,

    /// Number of sessions in Init state
    pub init_sessions: usize,

    /// Number of sessions in Down state
    pub down_sessions: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_bfd_health_monitor_creation() {
        let monitor = BfdHealthMonitor::new();

        let stats = monitor.get_stats().await;
        assert_eq!(stats.total_sessions, 0);
    }

    #[tokio::test]
    async fn test_add_session() {
        let monitor = BfdHealthMonitor::new();
        let path_id = PathId::new(1);

        let local_addr: SocketAddr = "127.0.0.1:3784".parse().unwrap();
        let remote_addr: SocketAddr = "127.0.0.1:3785".parse().unwrap();

        let result = monitor.add_session(path_id.clone(), local_addr, remote_addr).await;
        assert!(result.is_ok());

        // Check session was added
        let session = monitor.get_session(&path_id).await;
        assert!(session.is_some());

        // Check initial health
        let health = monitor.get_path_health(&path_id).await;
        assert!(health.is_some());
        assert_eq!(health.unwrap().status, PathStatus::Down);
    }

    #[tokio::test]
    async fn test_remove_session() {
        let monitor = BfdHealthMonitor::new();
        let path_id = PathId::new(2);

        let local_addr: SocketAddr = "127.0.0.1:3784".parse().unwrap();
        let remote_addr: SocketAddr = "127.0.0.1:3785".parse().unwrap();

        monitor.add_session(path_id.clone(), local_addr, remote_addr).await.unwrap();
        assert!(monitor.get_session(&path_id).await.is_some());

        monitor.remove_session(&path_id).await;
        assert!(monitor.get_session(&path_id).await.is_none());
    }

    #[tokio::test]
    async fn test_bfd_state_to_health() {
        let monitor = BfdHealthMonitor::new();
        let path_id = PathId::new(3);

        let health_up = monitor.bfd_state_to_health(&path_id, BfdState::Up).await;
        assert_eq!(health_up.status, PathStatus::Up);
        assert_eq!(health_up.health_score, 100.0);

        let health_down = monitor.bfd_state_to_health(&path_id, BfdState::Down).await;
        assert_eq!(health_down.status, PathStatus::Down);
        assert_eq!(health_down.health_score, 0.0);

        let health_init = monitor.bfd_state_to_health(&path_id, BfdState::Init).await;
        assert_eq!(health_init.status, PathStatus::Degraded);
        assert_eq!(health_init.health_score, 50.0);
    }
}
