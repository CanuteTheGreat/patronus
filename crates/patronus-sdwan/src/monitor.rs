//! Path monitoring - real-time quality measurement

use crate::{database::Database, types::*, Error, Result};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info};

/// Path monitor measures quality metrics for all paths
pub struct PathMonitor {
    db: Arc<Database>,
    running: Arc<RwLock<bool>>,
}

impl PathMonitor {
    /// Create a new path monitor
    pub fn new(db: Arc<Database>) -> Self {
        Self {
            db,
            running: Arc::new(RwLock::new(false)),
        }
    }

    /// Start the path monitor
    pub async fn start(&self) -> Result<()> {
        let mut running = self.running.write().await;
        if *running {
            return Ok(());
        }

        info!("Starting path monitor");
        *running = true;

        // TODO: Start probe sender task
        // TODO: Start metrics collector task

        Ok(())
    }

    /// Stop the path monitor
    pub async fn stop(&self) -> Result<()> {
        let mut running = self.running.write().await;
        if !*running {
            return Ok(());
        }

        info!("Stopping path monitor");
        *running = false;

        Ok(())
    }

    /// Send probe packet on a path
    pub async fn send_probe(&self, path_id: PathId) -> Result<()> {
        debug!(path_id = %path_id, "Sending path probe");
        // TODO: Implement probe sending
        Ok(())
    }

    /// Handle probe response
    pub async fn handle_probe_response(
        &self,
        path_id: PathId,
        response: PathProbeResponse,
    ) -> Result<()> {
        debug!(path_id = %path_id, "Received probe response");
        // TODO: Calculate metrics
        // TODO: Update database
        Ok(())
    }

    /// Get current metrics for a path
    pub async fn get_metrics(&self, path_id: PathId) -> Result<PathMetrics> {
        // TODO: Query from database
        Ok(PathMetrics::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_path_monitor_creation() {
        let db = Arc::new(Database::new(":memory:").await.unwrap());
        let monitor = PathMonitor::new(db);

        assert!(monitor.start().await.is_ok());
        assert!(monitor.stop().await.is_ok());
    }
}
