//! Routing engine - intelligent path selection

use crate::{database::Database, types::*, Error, Result};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::info;

/// Routing engine selects best path for each flow
pub struct RoutingEngine {
    db: Arc<Database>,
    running: Arc<RwLock<bool>>,
}

impl RoutingEngine {
    /// Create a new routing engine
    pub fn new(db: Arc<Database>) -> Self {
        Self {
            db,
            running: Arc::new(RwLock::new(false)),
        }
    }

    /// Start the routing engine
    pub async fn start(&self) -> Result<()> {
        let mut running = self.running.write().await;
        if *running {
            return Ok(());
        }

        info!("Starting routing engine");
        *running = true;

        // TODO: Load routing policies from database
        // TODO: Start flow monitor task

        Ok(())
    }

    /// Stop the routing engine
    pub async fn stop(&self) -> Result<()> {
        let mut running = self.running.write().await;
        if !*running {
            return Ok(());
        }

        info!("Stopping routing engine");
        *running = false;

        Ok(())
    }

    /// Select best path for a flow
    pub async fn select_path(&self, flow: &FlowKey) -> Result<PathId> {
        // TODO: Implement path selection algorithm
        // TODO: Apply routing policies
        // TODO: Consider path quality metrics

        Ok(PathId::new(1))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_routing_engine_creation() {
        let db = Arc::new(Database::new(":memory:").await.unwrap());
        let engine = RoutingEngine::new(db);

        assert!(engine.start().await.is_ok());
        assert!(engine.stop().await.is_ok());
    }
}
