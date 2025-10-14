// BGP Finite State Machine (RFC 4271)
//
// This implements the BGP-4 FSM defined in RFC 4271 Section 8.
// The FSM controls the BGP session lifecycle and handles state transitions.

use crate::error::{BgpError, Result};
use crate::neighbor::NeighborState;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, RwLock};
use tokio::time::{interval, sleep};
use tracing::{debug, error, info, warn};

/// BGP FSM events
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BgpEvent {
    /// Manual Start event
    ManualStart,

    /// Manual Stop event
    ManualStop,

    /// Automatic Start event
    AutomaticStart,

    /// TCP connection confirmed
    TcpConnectionConfirmed,

    /// TCP connection fails
    TcpConnectionFails,

    /// BGP OPEN message received
    BgpOpen,

    /// BGP OPEN message with errors
    BgpHeaderErr,

    /// BGP OPEN message with errors
    BgpOpenMsgErr,

    /// KEEPALIVE message received
    KeepAliveMsg,

    /// UPDATE message received
    UpdateMsg,

    /// UPDATE message with errors
    UpdateMsgErr,

    /// NOTIFICATION message received
    NotifMsg,

    /// Hold Timer expires
    HoldTimerExpires,

    /// Keepalive Timer expires
    KeepAliveTimerExpires,

    /// Connection Retry Timer expires
    ConnectRetryTimerExpires,
}

/// BGP FSM configuration
#[derive(Debug, Clone)]
pub struct FsmConfig {
    /// Hold time in seconds (default: 90)
    pub hold_time: u16,

    /// Keepalive time in seconds (default: 30)
    pub keepalive_time: u16,

    /// Connect retry time in seconds (default: 120)
    pub connect_retry_time: u16,

    /// Local AS number
    pub local_asn: u32,

    /// Local BGP identifier (router ID)
    pub local_bgp_id: u32,

    /// Remote AS number
    pub remote_asn: u32,

    /// Peer address
    pub peer_addr: String,
}

impl Default for FsmConfig {
    fn default() -> Self {
        Self {
            hold_time: 90,
            keepalive_time: 30,
            connect_retry_time: 120,
            local_asn: 65000,
            local_bgp_id: 0x01010101, // 1.1.1.1
            remote_asn: 65001,
            peer_addr: "0.0.0.0".to_string(),
        }
    }
}

/// BGP Finite State Machine
pub struct BgpFsm {
    config: FsmConfig,
    state: Arc<RwLock<NeighborState>>,
    connect_retry_counter: Arc<RwLock<u32>>,
    hold_time: Arc<RwLock<Duration>>,
    keepalive_time: Arc<RwLock<Duration>>,
    last_update_time: Arc<RwLock<Instant>>,
    connection: Arc<RwLock<Option<TcpStream>>>,
    event_tx: mpsc::UnboundedSender<BgpEvent>,
    event_rx: Arc<RwLock<mpsc::UnboundedReceiver<BgpEvent>>>,
}

impl BgpFsm {
    /// Create a new BGP FSM
    pub fn new(config: FsmConfig) -> Self {
        let (event_tx, event_rx) = mpsc::unbounded_channel();

        Self {
            config,
            state: Arc::new(RwLock::new(NeighborState::Idle)),
            connect_retry_counter: Arc::new(RwLock::new(0)),
            hold_time: Arc::new(RwLock::new(Duration::from_secs(90))),
            keepalive_time: Arc::new(RwLock::new(Duration::from_secs(30))),
            last_update_time: Arc::new(RwLock::new(Instant::now())),
            connection: Arc::new(RwLock::new(None)),
            event_tx,
            event_rx: Arc::new(RwLock::new(event_rx)),
        }
    }

    /// Get current state
    pub async fn state(&self) -> NeighborState {
        *self.state.read().await
    }

    /// Send event to FSM
    pub fn send_event(&self, event: BgpEvent) -> Result<()> {
        self.event_tx
            .send(event)
            .map_err(|_| BgpError::ProtocolError("Failed to send event".into()))?;
        Ok(())
    }

    /// Start FSM event loop
    pub async fn run(self: Arc<Self>) -> Result<()> {
        info!("Starting BGP FSM event loop");

        // Start timers
        self.start_timers().await;

        // Event processing loop
        let mut event_rx = self.event_rx.write().await;

        while let Some(event) = event_rx.recv().await {
            let current_state = *self.state.read().await;

            debug!("FSM: state={:?}, event={:?}", current_state, event);

            if let Err(e) = self.process_event(current_state, event).await {
                error!("FSM error: {}", e);
            }
        }

        info!("BGP FSM event loop terminated");
        Ok(())
    }

    /// Process FSM event
    async fn process_event(&self, state: NeighborState, event: BgpEvent) -> Result<()> {
        match (state, &event) {
            // Idle state
            (NeighborState::Idle, BgpEvent::ManualStart | BgpEvent::AutomaticStart) => {
                self.transition_to_connect().await?;
            }

            // Connect state
            (NeighborState::Connect, BgpEvent::TcpConnectionConfirmed) => {
                self.transition_to_opensent().await?;
            }
            (NeighborState::Connect, BgpEvent::TcpConnectionFails) => {
                self.transition_to_active().await?;
            }
            (NeighborState::Connect, BgpEvent::ConnectRetryTimerExpires) => {
                self.retry_connection().await?;
            }
            (NeighborState::Connect, BgpEvent::ManualStop) => {
                self.transition_to_idle().await?;
            }

            // Active state
            (NeighborState::Active, BgpEvent::TcpConnectionConfirmed) => {
                self.transition_to_opensent().await?;
            }
            (NeighborState::Active, BgpEvent::ConnectRetryTimerExpires) => {
                self.retry_connection().await?;
            }
            (NeighborState::Active, BgpEvent::ManualStop) => {
                self.transition_to_idle().await?;
            }

            // OpenSent state
            (NeighborState::OpenSent, BgpEvent::BgpOpen) => {
                self.transition_to_openconfirm().await?;
            }
            (NeighborState::OpenSent, BgpEvent::BgpHeaderErr | BgpEvent::BgpOpenMsgErr) => {
                self.send_notification_and_stop().await?;
            }
            (NeighborState::OpenSent, BgpEvent::TcpConnectionFails) => {
                self.transition_to_active().await?;
            }
            (NeighborState::OpenSent, BgpEvent::ManualStop) => {
                self.transition_to_idle().await?;
            }

            // OpenConfirm state
            (NeighborState::OpenConfirm, BgpEvent::KeepAliveMsg) => {
                self.transition_to_established().await?;
            }
            (NeighborState::OpenConfirm, BgpEvent::KeepAliveTimerExpires) => {
                self.send_keepalive().await?;
            }
            (NeighborState::OpenConfirm, BgpEvent::HoldTimerExpires) => {
                self.send_notification_and_stop().await?;
            }
            (NeighborState::OpenConfirm, BgpEvent::NotifMsg) => {
                self.transition_to_idle().await?;
            }
            (NeighborState::OpenConfirm, BgpEvent::ManualStop) => {
                self.transition_to_idle().await?;
            }

            // Established state
            (NeighborState::Established, BgpEvent::UpdateMsg) => {
                self.process_update().await?;
            }
            (NeighborState::Established, BgpEvent::KeepAliveMsg) => {
                self.process_keepalive().await?;
            }
            (NeighborState::Established, BgpEvent::KeepAliveTimerExpires) => {
                self.send_keepalive().await?;
            }
            (NeighborState::Established, BgpEvent::HoldTimerExpires) => {
                self.send_notification_and_stop().await?;
            }
            (NeighborState::Established, BgpEvent::UpdateMsgErr) => {
                self.send_notification_and_stop().await?;
            }
            (NeighborState::Established, BgpEvent::NotifMsg) => {
                self.transition_to_idle().await?;
            }
            (NeighborState::Established, BgpEvent::ManualStop) => {
                self.transition_to_idle().await?;
            }

            // Unhandled combinations
            _ => {
                warn!(
                    "Unhandled FSM transition: state={:?}, event={:?}",
                    state, event
                );
            }
        }

        Ok(())
    }

    /// Start FSM timers
    async fn start_timers(&self) {
        // Connect Retry Timer
        let fsm = Arc::new(self.clone_weak());
        tokio::spawn(async move {
            let mut timer = interval(Duration::from_secs(fsm.config.connect_retry_time as u64));
            loop {
                timer.tick().await;
                let state = *fsm.state.read().await;
                if state == NeighborState::Connect || state == NeighborState::Active {
                    let _ = fsm.send_event(BgpEvent::ConnectRetryTimerExpires);
                }
            }
        });

        // Keepalive Timer
        let fsm = Arc::new(self.clone_weak());
        tokio::spawn(async move {
            let mut timer = interval(*fsm.keepalive_time.read().await);
            loop {
                timer.tick().await;
                let state = *fsm.state.read().await;
                if state == NeighborState::OpenConfirm || state == NeighborState::Established {
                    let _ = fsm.send_event(BgpEvent::KeepAliveTimerExpires);
                }
            }
        });

        // Hold Timer
        let fsm = Arc::new(self.clone_weak());
        tokio::spawn(async move {
            loop {
                sleep(Duration::from_secs(1)).await;
                let state = *fsm.state.read().await;

                if state == NeighborState::OpenSent
                    || state == NeighborState::OpenConfirm
                    || state == NeighborState::Established
                {
                    let last_update = *fsm.last_update_time.read().await;
                    let hold_time = *fsm.hold_time.read().await;

                    if last_update.elapsed() >= hold_time {
                        let _ = fsm.send_event(BgpEvent::HoldTimerExpires);
                    }
                }
            }
        });
    }

    /// Transition to Connect state
    async fn transition_to_connect(&self) -> Result<()> {
        info!("FSM: Transitioning to Connect state");
        *self.state.write().await = NeighborState::Connect;
        *self.connect_retry_counter.write().await = 0;

        // Initiate TCP connection (stub)
        self.initiate_tcp_connection().await?;

        Ok(())
    }

    /// Transition to Active state
    async fn transition_to_active(&self) -> Result<()> {
        info!("FSM: Transitioning to Active state");
        *self.state.write().await = NeighborState::Active;

        // Close any existing connection
        *self.connection.write().await = None;

        Ok(())
    }

    /// Transition to OpenSent state
    async fn transition_to_opensent(&self) -> Result<()> {
        info!("FSM: Transitioning to OpenSent state");
        *self.state.write().await = NeighborState::OpenSent;

        // Send OPEN message (stub)
        self.send_open().await?;

        // Reset hold timer
        *self.last_update_time.write().await = Instant::now();

        Ok(())
    }

    /// Transition to OpenConfirm state
    async fn transition_to_openconfirm(&self) -> Result<()> {
        info!("FSM: Transitioning to OpenConfirm state");
        *self.state.write().await = NeighborState::OpenConfirm;

        // Send KEEPALIVE (stub)
        self.send_keepalive().await?;

        // Reset hold timer
        *self.last_update_time.write().await = Instant::now();

        Ok(())
    }

    /// Transition to Established state
    async fn transition_to_established(&self) -> Result<()> {
        info!("FSM: Transitioning to Established state");
        *self.state.write().await = NeighborState::Established;

        // Reset hold timer
        *self.last_update_time.write().await = Instant::now();

        Ok(())
    }

    /// Transition to Idle state
    async fn transition_to_idle(&self) -> Result<()> {
        info!("FSM: Transitioning to Idle state");
        *self.state.write().await = NeighborState::Idle;

        // Close connection
        *self.connection.write().await = None;

        // Reset counters
        *self.connect_retry_counter.write().await = 0;

        Ok(())
    }

    /// Retry connection
    async fn retry_connection(&self) -> Result<()> {
        let mut counter = self.connect_retry_counter.write().await;
        *counter += 1;

        debug!("Retrying connection (attempt {})", *counter);

        self.transition_to_connect().await
    }

    /// Send NOTIFICATION and stop
    async fn send_notification_and_stop(&self) -> Result<()> {
        warn!("Sending NOTIFICATION and stopping");
        // Send NOTIFICATION (stub)
        self.transition_to_idle().await
    }

    // Stub implementations for protocol messages
    async fn initiate_tcp_connection(&self) -> Result<()> {
        debug!("Initiating TCP connection to {}", self.config.peer_addr);
        // Stub: would attempt TCP connection to peer
        Ok(())
    }

    async fn send_open(&self) -> Result<()> {
        debug!("Sending OPEN message");
        // Stub: would send BGP OPEN message
        Ok(())
    }

    async fn send_keepalive(&self) -> Result<()> {
        debug!("Sending KEEPALIVE message");
        // Stub: would send BGP KEEPALIVE message
        *self.last_update_time.write().await = Instant::now();
        Ok(())
    }

    async fn process_update(&self) -> Result<()> {
        debug!("Processing UPDATE message");
        // Stub: would process BGP UPDATE message
        *self.last_update_time.write().await = Instant::now();
        Ok(())
    }

    async fn process_keepalive(&self) -> Result<()> {
        debug!("Processing KEEPALIVE message");
        *self.last_update_time.write().await = Instant::now();
        Ok(())
    }

    // Helper to clone weak references for timers
    fn clone_weak(&self) -> Self {
        Self {
            config: self.config.clone(),
            state: Arc::clone(&self.state),
            connect_retry_counter: Arc::clone(&self.connect_retry_counter),
            hold_time: Arc::clone(&self.hold_time),
            keepalive_time: Arc::clone(&self.keepalive_time),
            last_update_time: Arc::clone(&self.last_update_time),
            connection: Arc::clone(&self.connection),
            event_tx: self.event_tx.clone(),
            event_rx: Arc::clone(&self.event_rx),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_fsm_creation() {
        let config = FsmConfig::default();
        let fsm = BgpFsm::new(config);

        assert_eq!(fsm.state().await, NeighborState::Idle);
    }

    #[tokio::test]
    async fn test_fsm_manual_start() {
        let config = FsmConfig::default();
        let fsm = Arc::new(BgpFsm::new(config));

        fsm.send_event(BgpEvent::ManualStart).unwrap();

        // Process event
        let event = {
            let mut rx = fsm.event_rx.write().await;
            rx.recv().await.unwrap()
        };

        fsm.process_event(NeighborState::Idle, event).await.unwrap();

        assert_eq!(fsm.state().await, NeighborState::Connect);
    }

    #[tokio::test]
    async fn test_fsm_state_transitions() {
        let config = FsmConfig::default();
        let fsm = Arc::new(BgpFsm::new(config));

        // Idle -> Connect
        fsm.transition_to_connect().await.unwrap();
        assert_eq!(fsm.state().await, NeighborState::Connect);

        // Connect -> OpenSent
        fsm.transition_to_opensent().await.unwrap();
        assert_eq!(fsm.state().await, NeighborState::OpenSent);

        // OpenSent -> OpenConfirm
        fsm.transition_to_openconfirm().await.unwrap();
        assert_eq!(fsm.state().await, NeighborState::OpenConfirm);

        // OpenConfirm -> Established
        fsm.transition_to_established().await.unwrap();
        assert_eq!(fsm.state().await, NeighborState::Established);

        // Established -> Idle
        fsm.transition_to_idle().await.unwrap();
        assert_eq!(fsm.state().await, NeighborState::Idle);
    }

    #[tokio::test]
    async fn test_fsm_error_handling() {
        let config = FsmConfig::default();
        let fsm = Arc::new(BgpFsm::new(config));

        // Transition to OpenSent
        fsm.transition_to_opensent().await.unwrap();
        assert_eq!(fsm.state().await, NeighborState::OpenSent);

        // Header error should go to Idle
        fsm.process_event(NeighborState::OpenSent, BgpEvent::BgpHeaderErr)
            .await
            .unwrap();

        assert_eq!(fsm.state().await, NeighborState::Idle);
    }
}
