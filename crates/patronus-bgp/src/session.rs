//! BGP session management

use crate::{error::Result, neighbor::NeighborState};

/// BGP session
#[derive(Debug)]
pub struct BgpSession {
    /// Session state
    state: NeighborState,
}

impl BgpSession {
    /// Create a new BGP session
    pub fn new() -> Self {
        Self {
            state: NeighborState::Idle,
        }
    }

    /// Get session state
    pub fn state(&self) -> NeighborState {
        self.state
    }

    /// Start session (stub)
    pub async fn start(&mut self) -> Result<()> {
        self.state = NeighborState::Connect;
        Ok(())
    }

    /// Stop session (stub)
    pub async fn stop(&mut self) -> Result<()> {
        self.state = NeighborState::Idle;
        Ok(())
    }
}

impl Default for BgpSession {
    fn default() -> Self {
        Self::new()
    }
}
