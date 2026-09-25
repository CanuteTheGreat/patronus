//! Self-Healing Networks
//!
//! Automatic detection and remediation of network issues

pub mod detector;
pub mod healing_loop;
pub mod remediation;

pub use detector::{Issue, IssueDetector, IssueSeverity, IssueType};
pub use healing_loop::{HealingLoop, HealingStats};
pub use remediation::{
    RemediationAction, RemediationAttempt, RemediationEngine, RemediationExecutor,
    RemediationStatus,
};
