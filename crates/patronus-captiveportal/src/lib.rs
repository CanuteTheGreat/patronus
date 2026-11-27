//! Patronus captive portal runtime (lane x) and the "time's up" page of
//! parental time limits.
//!
//! With feature `portal` (USE=captive-portal): the sign-in pages
//! ([`http`], [`pages`]), the session engine ([`engine`]: login backends
//! none / local users / vouchers / RADIUS, idle and hard timeouts, per-client
//! `tc` bandwidth, disconnects) and the RADIUS client ([`radius`]). The
//! configuration and the `inet patronus_portal` nft table are
//! `patronus_network::captive`; patronus-web serves the listeners and runs
//! the session ticker. See docs/CAPTIVE-PORTAL.md.

#[cfg(feature = "portal")]
pub mod engine;
#[cfg(feature = "portal")]
pub mod http;
#[cfg(feature = "portal")]
pub mod pages;
#[cfg(feature = "portal")]
pub mod radius;
pub mod timeup;
