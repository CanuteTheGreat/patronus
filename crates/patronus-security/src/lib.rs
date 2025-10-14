//! Advanced Security Module
//!
//! Provides mTLS, Zero Trust, and Policy Engine capabilities

pub mod mtls;
pub mod zerotrust;
pub mod policy;
pub mod pki;

pub use mtls::{MtlsConfig, MtlsManager};
pub use zerotrust::{ZeroTrustPolicy, ZeroTrustEngine};
pub use policy::{PolicyEngine, Policy, PolicyDecision};
pub use pki::{CertificateAuthority, Certificate};
