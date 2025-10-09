//! Patronus Captive Portal
//!
//! Enterprise-grade guest WiFi authentication with vouchers, social login,
//! bandwidth management, and comprehensive access control.

pub mod portal;
pub mod auth;
pub mod vouchers;
pub mod sessions;
pub mod bandwidth;

pub use portal::CaptivePortal;
pub use auth::{AuthProvider, AuthMethod};
pub use vouchers::{VoucherManager, Voucher};
pub use sessions::{SessionManager, ClientSession};
pub use bandwidth::BandwidthLimiter;
