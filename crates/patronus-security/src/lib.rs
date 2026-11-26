//! Advanced Security Module
//!
//! Provides mTLS, Zero Trust, and Policy Engine capabilities

pub mod ca;
pub mod mtls;
pub mod pki;
pub mod policy;
pub mod zerotrust;

pub use ca::{
    CaConfig, CaError, CaPolicy, CaState, CaStore, CertProfile, CertStatus,
    CertificateAuthority as CaBackend, IssueOptions, IssuedCertificate, IssuedCrl, RevokeReason,
};
pub use mtls::{MtlsConfig, MtlsManager};
pub use pki::{Certificate, CertificateAuthority};
pub use policy::{Policy, PolicyDecision, PolicyEngine};
pub use zerotrust::{ZeroTrustEngine, ZeroTrustPolicy};
