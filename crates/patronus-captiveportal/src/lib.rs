//! Patronus Captive Portal
//!
//! Enterprise-grade guest WiFi authentication with vouchers, social login,
//! bandwidth management, and comprehensive access control.

pub mod auth;
pub mod bandwidth;
pub mod portal;
pub mod sessions;
pub mod vouchers;

pub use auth::{AuthMethod, AuthProvider};
pub use bandwidth::BandwidthLimiter;
pub use portal::CaptivePortal;
pub use sessions::{ClientSession, SessionManager};
pub use vouchers::{Voucher, VoucherManager};
