//! Self-Healing Networks
//!
//! Automatic detection and remediation of network issues

pub mod detector;
pub mod remediation;
pub mod healing_loop;

pub use detector::{Issue, IssueDetector, IssueType, IssueSeverity};
pub use remediation::{RemediationAction, RemediationAttempt, RemediationEngine, RemediationExecutor, RemediationStatus};
pub use healing_loop::{HealingLoop, HealingStats};
