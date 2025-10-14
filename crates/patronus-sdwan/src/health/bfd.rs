// Bidirectional Forwarding Detection (BFD) implementation
// RFC 5880 - Bidirectional Forwarding Detection
//
// BFD provides sub-second failure detection for network paths.
// It's much faster than traditional health checking mechanisms.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, RwLock};
use tokio::time::{interval, sleep};
use tracing::{debug, error, info, warn};

/// BFD packet format (simplified version of RFC 5880)
#[derive(Debug, Clone)]
pub struct BfdPacket {
    /// Version (3 bits) + Diagnostic (5 bits)
    pub vers_diag: u8,
    /// State (2 bits) + Poll (1 bit) + Final (1 bit) + Control Plane Independent (1 bit) + Auth Present (1 bit) + Demand (1 bit) + Multipoint (1 bit)
    pub state_flags: u8,
    /// Detection time multiplier
    pub detect_mult: u8,
    /// Length of the BFD Control packet in bytes
    pub length: u8,
    /// My discriminator
    pub my_discriminator: u32,
    /// Your discriminator
    pub your_discriminator: u32,
    /// Desired min TX interval (microseconds)
    pub desired_min_tx_interval: u32,
    /// Required min RX interval (microseconds)
    pub required_min_rx_interval: u32,
    /// Required min echo RX interval (microseconds)
    pub required_min_echo_rx_interval: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BfdState {
    AdminDown = 0,
    Down = 1,
    Init = 2,
    Up = 3,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BfdDiagnostic {
    None = 0,
    ControlDetectionTimeExpired = 1,
    EchoFunctionFailed = 2,
    NeighborSignaledSessionDown = 3,
    ForwardingPlaneReset = 4,
    PathDown = 5,
    ConcatenatedPathDown = 6,
    AdministrativelyDown = 7,
    ReverseConcatenatedPathDown = 8,
}

/// BFD session configuration
#[derive(Debug, Clone)]
pub struct BfdConfig {
    /// Local discriminator (unique identifier for this session)
    pub local_discriminator: u32,
    /// Desired minimum TX interval (microseconds)
    pub desired_min_tx_interval: u32,
    /// Required minimum RX interval (microseconds)
    pub required_min_rx_interval: u32,
    /// Detection time multiplier
    pub detect_mult: u8,
    /// Local address to bind to
    pub local_addr: SocketAddr,
    /// Remote address to send to
    pub remote_addr: SocketAddr,
}

impl Default for BfdConfig {
    fn default() -> Self {
        Self {
            local_discriminator: rand::random(),
            desired_min_tx_interval: 300_000, // 300ms
            required_min_rx_interval: 300_000, // 300ms
            detect_mult: 3,
            local_addr: "0.0.0.0:3784".parse().unwrap(), // BFD control port
            remote_addr: "127.0.0.1:3784".parse().unwrap(),
        }
    }
}

/// BFD session state
pub struct BfdSession {
    config: BfdConfig,
    state: Arc<RwLock<BfdState>>,
    remote_discriminator: Arc<RwLock<u32>>,
    last_rx: Arc<RwLock<Instant>>,
    diagnostic: Arc<RwLock<BfdDiagnostic>>,
    tx_interval: Arc<RwLock<Duration>>,
    rx_interval: Arc<RwLock<Duration>>,
    detection_time: Arc<RwLock<Duration>>,
}

impl BfdSession {
    pub fn new(config: BfdConfig) -> Self {
        let tx_interval = Duration::from_micros(config.desired_min_tx_interval as u64);
        let rx_interval = Duration::from_micros(config.required_min_rx_interval as u64);
        let detection_time = rx_interval * config.detect_mult as u32;

        Self {
            config,
            state: Arc::new(RwLock::new(BfdState::Down)),
            remote_discriminator: Arc::new(RwLock::new(0)),
            last_rx: Arc::new(RwLock::new(Instant::now())),
            diagnostic: Arc::new(RwLock::new(BfdDiagnostic::None)),
            tx_interval: Arc::new(RwLock::new(tx_interval)),
            rx_interval: Arc::new(RwLock::new(rx_interval)),
            detection_time: Arc::new(RwLock::new(detection_time)),
        }
    }

    /// Get current session state
    pub async fn state(&self) -> BfdState {
        *self.state.read().await
    }

    /// Get current diagnostic code
    pub async fn diagnostic(&self) -> BfdDiagnostic {
        *self.diagnostic.read().await
    }

    /// Check if session is up
    pub async fn is_up(&self) -> bool {
        *self.state.read().await == BfdState::Up
    }

    /// Start BFD session
    pub async fn start(
        self: Arc<Self>,
        state_tx: mpsc::Sender<BfdState>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        info!(
            "Starting BFD session: local={}, remote={}",
            self.config.local_addr, self.config.remote_addr
        );

        // Bind UDP socket
        let socket = Arc::new(UdpSocket::bind(self.config.local_addr).await?);
        socket.connect(self.config.remote_addr).await?;

        // Set initial state to Down
        *self.state.write().await = BfdState::Down;

        // Start TX task
        let session_tx = Arc::clone(&self);
        let socket_tx = Arc::clone(&socket);
        tokio::spawn(async move {
            if let Err(e) = session_tx.tx_task(socket_tx).await {
                error!("BFD TX task error: {}", e);
            }
        });

        // Start RX task
        let session_rx = Arc::clone(&self);
        let socket_rx = Arc::clone(&socket);
        tokio::spawn(async move {
            if let Err(e) = session_rx.rx_task(socket_rx).await {
                error!("BFD RX task error: {}", e);
            }
        });

        // Start detection timer task
        let session_detect = Arc::clone(&self);
        tokio::spawn(async move {
            if let Err(e) = session_detect.detection_task(state_tx).await {
                error!("BFD detection task error: {}", e);
            }
        });

        Ok(())
    }

    /// TX task - sends BFD control packets
    async fn tx_task(&self, socket: Arc<UdpSocket>) -> Result<(), Box<dyn std::error::Error>> {
        loop {
            let tx_interval = *self.tx_interval.read().await;
            let mut timer = interval(tx_interval);

            loop {
                timer.tick().await;

                let packet = self.create_packet().await;
                let bytes = packet.to_bytes();

                match socket.send(&bytes).await {
                    Ok(_) => {
                        debug!(
                            "Sent BFD packet: state={:?}, my_disc={}, your_disc={}",
                            *self.state.read().await,
                            packet.my_discriminator,
                            packet.your_discriminator
                        );
                    }
                    Err(e) => {
                        warn!("Failed to send BFD packet: {}", e);
                    }
                }
            }
        }
    }

    /// RX task - receives BFD control packets
    async fn rx_task(&self, socket: Arc<UdpSocket>) -> Result<(), Box<dyn std::error::Error>> {
        let mut buf = vec![0u8; 1500];

        loop {
            match socket.recv(&mut buf).await {
                Ok(len) => {
                    if let Some(packet) = BfdPacket::from_bytes(&buf[..len]) {
                        debug!(
                            "Received BFD packet: state={:?}, my_disc={}, your_disc={}",
                            packet.state(),
                            packet.my_discriminator,
                            packet.your_discriminator
                        );

                        self.handle_rx_packet(packet).await;
                    }
                }
                Err(e) => {
                    warn!("Failed to receive BFD packet: {}", e);
                    sleep(Duration::from_millis(100)).await;
                }
            }
        }
    }

    /// Detection timer task - monitors for timeout
    async fn detection_task(
        &self,
        state_tx: mpsc::Sender<BfdState>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut timer = interval(Duration::from_millis(100));

        loop {
            timer.tick().await;

            let current_state = *self.state.read().await;
            let last_rx = *self.last_rx.read().await;
            let detection_time = *self.detection_time.read().await;

            // Only check timeout if we're in Init or Up state
            if current_state == BfdState::Init || current_state == BfdState::Up {
                if last_rx.elapsed() > detection_time {
                    warn!("BFD session timeout detected");

                    // Move to Down state
                    *self.state.write().await = BfdState::Down;
                    *self.diagnostic.write().await = BfdDiagnostic::ControlDetectionTimeExpired;

                    // Notify state change
                    let _ = state_tx.send(BfdState::Down).await;
                }
            }
        }
    }

    /// Handle received packet
    async fn handle_rx_packet(&self, packet: BfdPacket) {
        // Update last RX time
        *self.last_rx.write().await = Instant::now();

        // Verify packet is for us
        let your_disc = packet.your_discriminator;
        if your_disc != 0 && your_disc != self.config.local_discriminator {
            debug!("Received packet with wrong discriminator");
            return;
        }

        // Save remote discriminator
        if packet.my_discriminator != 0 {
            *self.remote_discriminator.write().await = packet.my_discriminator;
        }

        // State machine
        let current_state = *self.state.read().await;
        let remote_state = packet.state();

        let new_state = match (current_state, remote_state) {
            // From Down state
            (BfdState::Down, BfdState::Down) => BfdState::Init,
            (BfdState::Down, BfdState::Init) => BfdState::Up,
            (BfdState::Down, BfdState::Up) => BfdState::Up,

            // From Init state
            (BfdState::Init, BfdState::Up) => BfdState::Up,
            (BfdState::Init, BfdState::Init) => BfdState::Init,
            (BfdState::Init, BfdState::Down) => BfdState::Down,

            // From Up state
            (BfdState::Up, BfdState::Down) => BfdState::Down,

            // Stay in current state for other combinations
            _ => current_state,
        };

        if new_state != current_state {
            info!("BFD state transition: {:?} -> {:?}", current_state, new_state);
            *self.state.write().await = new_state;
        }

        // Update intervals if needed
        let remote_min_tx = Duration::from_micros(packet.desired_min_tx_interval as u64);
        let local_min_rx = *self.rx_interval.read().await;
        let negotiated_rx = std::cmp::max(remote_min_tx, local_min_rx);

        if negotiated_rx != *self.detection_time.read().await / self.config.detect_mult as u32 {
            *self.detection_time.write().await = negotiated_rx * self.config.detect_mult as u32;
        }
    }

    /// Create BFD control packet
    async fn create_packet(&self) -> BfdPacket {
        let state = *self.state.read().await;
        let diag = *self.diagnostic.read().await;
        let remote_disc = *self.remote_discriminator.read().await;

        BfdPacket {
            vers_diag: (1 << 5) | (diag as u8), // Version 1
            state_flags: (state as u8) << 6,
            detect_mult: self.config.detect_mult,
            length: 24, // Minimum BFD packet size
            my_discriminator: self.config.local_discriminator,
            your_discriminator: remote_disc,
            desired_min_tx_interval: self.config.desired_min_tx_interval,
            required_min_rx_interval: self.config.required_min_rx_interval,
            required_min_echo_rx_interval: 0,
        }
    }
}

impl BfdPacket {
    /// Convert packet to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(24);

        bytes.push(self.vers_diag);
        bytes.push(self.state_flags);
        bytes.push(self.detect_mult);
        bytes.push(self.length);
        bytes.extend_from_slice(&self.my_discriminator.to_be_bytes());
        bytes.extend_from_slice(&self.your_discriminator.to_be_bytes());
        bytes.extend_from_slice(&self.desired_min_tx_interval.to_be_bytes());
        bytes.extend_from_slice(&self.required_min_rx_interval.to_be_bytes());
        bytes.extend_from_slice(&self.required_min_echo_rx_interval.to_be_bytes());

        bytes
    }

    /// Parse packet from bytes
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 24 {
            return None;
        }

        Some(Self {
            vers_diag: bytes[0],
            state_flags: bytes[1],
            detect_mult: bytes[2],
            length: bytes[3],
            my_discriminator: u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
            your_discriminator: u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]),
            desired_min_tx_interval: u32::from_be_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]),
            required_min_rx_interval: u32::from_be_bytes([bytes[16], bytes[17], bytes[18], bytes[19]]),
            required_min_echo_rx_interval: u32::from_be_bytes([bytes[20], bytes[21], bytes[22], bytes[23]]),
        })
    }

    /// Get state from packet
    pub fn state(&self) -> BfdState {
        match (self.state_flags >> 6) & 0x03 {
            0 => BfdState::AdminDown,
            1 => BfdState::Down,
            2 => BfdState::Init,
            3 => BfdState::Up,
            _ => BfdState::Down,
        }
    }

    /// Get diagnostic from packet
    pub fn diagnostic(&self) -> BfdDiagnostic {
        match self.vers_diag & 0x1F {
            0 => BfdDiagnostic::None,
            1 => BfdDiagnostic::ControlDetectionTimeExpired,
            2 => BfdDiagnostic::EchoFunctionFailed,
            3 => BfdDiagnostic::NeighborSignaledSessionDown,
            4 => BfdDiagnostic::ForwardingPlaneReset,
            5 => BfdDiagnostic::PathDown,
            6 => BfdDiagnostic::ConcatenatedPathDown,
            7 => BfdDiagnostic::AdministrativelyDown,
            8 => BfdDiagnostic::ReverseConcatenatedPathDown,
            _ => BfdDiagnostic::None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bfd_packet_serialization() {
        let packet = BfdPacket {
            vers_diag: (1 << 5) | 0,
            state_flags: (BfdState::Up as u8) << 6,
            detect_mult: 3,
            length: 24,
            my_discriminator: 12345,
            your_discriminator: 67890,
            desired_min_tx_interval: 300_000,
            required_min_rx_interval: 300_000,
            required_min_echo_rx_interval: 0,
        };

        let bytes = packet.to_bytes();
        let parsed = BfdPacket::from_bytes(&bytes).unwrap();

        assert_eq!(parsed.my_discriminator, packet.my_discriminator);
        assert_eq!(parsed.your_discriminator, packet.your_discriminator);
        assert_eq!(parsed.state(), BfdState::Up);
    }

    #[tokio::test]
    async fn test_bfd_session_creation() {
        let config = BfdConfig::default();
        let session = BfdSession::new(config);

        assert_eq!(session.state().await, BfdState::Down);
        assert!(!session.is_up().await);
    }

    #[tokio::test]
    async fn test_bfd_state_machine() {
        let config = BfdConfig::default();
        let session = BfdSession::new(config);

        // Initial state is Down
        assert_eq!(session.state().await, BfdState::Down);

        // Simulate receiving packet in Down state from remote in Init state
        let packet = BfdPacket {
            vers_diag: (1 << 5),
            state_flags: (BfdState::Init as u8) << 6,
            detect_mult: 3,
            length: 24,
            my_discriminator: 99999,
            your_discriminator: session.config.local_discriminator,
            desired_min_tx_interval: 300_000,
            required_min_rx_interval: 300_000,
            required_min_echo_rx_interval: 0,
        };

        session.handle_rx_packet(packet).await;

        // Should transition to Up
        assert_eq!(session.state().await, BfdState::Up);
        assert!(session.is_up().await);
    }
}
