//! Patronus BGP Integration
//!
//! This crate provides BGP (Border Gateway Protocol) integration for Patronus SD-WAN,
//! enabling dynamic route advertisement and learning from upstream routers.

pub mod config;
pub mod error;
pub mod fsm;
pub mod manager;
pub mod messages;
pub mod neighbor;
pub mod route;
pub mod session;

pub use config::{BgpConfig, NeighborConfig, RouteMapConfig};
pub use error::{BgpError, Result};
pub use fsm::{BgpEvent, BgpFsm, FsmConfig};
pub use manager::BgpManager;
pub use messages::{BgpMessage, KeepaliveMessage, NotificationMessage, OpenMessage, UpdateMessage};
pub use neighbor::BgpNeighbor;
pub use route::{BgpRoute, RouteAction};
pub use session::BgpSession;

/// BGP protocol version
pub const BGP_VERSION: u8 = 4;

/// Default BGP port
pub const BGP_PORT: u16 = 179;
