// GraphQL Types - Domain models for the API
//
// These types represent the core SD-WAN entities exposed via GraphQL.

use async_graphql::{SimpleObject, Enum, InputObject};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Site information
#[derive(Debug, Clone, Serialize, Deserialize, SimpleObject)]
#[graphql(name = "Site")]
pub struct GqlSite {
    /// Unique site identifier
    pub id: String,

    /// Human-readable site name
    pub name: String,

    /// Site location/region
    pub location: Option<String>,

    /// Number of active endpoints at this site
    pub endpoint_count: i32,

    /// Site status
    pub status: SiteStatus,

    /// When the site was created
    pub created_at: DateTime<Utc>,

    /// Last update timestamp
    pub updated_at: DateTime<Utc>,
}

/// Site status enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Enum)]
pub enum SiteStatus {
    /// Site is fully operational
    Active,

    /// Site is degraded but operational
    Degraded,

    /// Site is offline
    Offline,

    /// Site is in maintenance mode
    Maintenance,
}

/// Network path between sites
#[derive(Debug, Clone, Serialize, Deserialize, SimpleObject)]
#[graphql(name = "Path")]
pub struct GqlPath {
    /// Unique path identifier
    pub id: String,

    /// Source site ID
    pub source_site_id: String,

    /// Destination site ID
    pub destination_site_id: String,

    /// Path latency in milliseconds
    pub latency_ms: f64,

    /// Packet loss percentage (0-100)
    pub packet_loss: f64,

    /// Available bandwidth in Mbps
    pub bandwidth_mbps: f64,

    /// Path quality score (0-100)
    pub quality_score: f64,

    /// Path status
    pub status: PathStatus,

    /// Last time path metrics were updated
    pub last_updated: DateTime<Utc>,
}

/// Path status enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Enum)]
pub enum PathStatus {
    /// Path is optimal
    Optimal,

    /// Path is usable but degraded
    Degraded,

    /// Path has failed
    Failed,
}

/// Traffic policy
#[derive(Debug, Clone, Serialize, Deserialize, SimpleObject)]
#[graphql(name = "Policy")]
pub struct GqlPolicy {
    /// Unique policy identifier
    pub id: String,

    /// Policy name
    pub name: String,

    /// Policy description
    pub description: Option<String>,

    /// Policy priority (higher = more important)
    pub priority: i32,

    /// Traffic matching rules (JSON)
    pub match_rules: String,

    /// Action to take (allow, deny, route, qos)
    pub action: PolicyAction,

    /// Whether policy is currently active
    pub enabled: bool,

    /// Number of packets matched by this policy
    pub packets_matched: i64,

    /// Number of bytes matched by this policy
    pub bytes_matched: i64,

    /// When the policy was created
    pub created_at: DateTime<Utc>,
}

/// Policy action enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Enum)]
pub enum PolicyAction {
    /// Allow traffic
    Allow,

    /// Deny traffic
    Deny,

    /// Route via specific path
    Route,

    /// Apply QoS treatment
    Qos,
}

/// Real-time metrics
#[derive(Debug, Clone, Serialize, Deserialize, SimpleObject)]
#[graphql(name = "Metrics")]
pub struct GqlMetrics {
    /// Timestamp of metrics
    pub timestamp: DateTime<Utc>,

    /// Total throughput in Mbps
    pub throughput_mbps: f64,

    /// Total packets per second
    pub packets_per_second: i64,

    /// Number of active flows
    pub active_flows: i64,

    /// Average latency across all paths (ms)
    pub avg_latency_ms: f64,

    /// Average packet loss across all paths (%)
    pub avg_packet_loss: f64,

    /// CPU utilization (0-100)
    pub cpu_usage: f64,

    /// Memory utilization (0-100)
    pub memory_usage: f64,
}

/// User information
#[derive(Debug, Clone, Serialize, Deserialize, SimpleObject)]
#[graphql(name = "User")]
pub struct GqlUser {
    /// User ID
    pub id: String,

    /// Email address
    pub email: String,

    /// User role
    pub role: UserRole,

    /// Whether user is active
    pub active: bool,

    /// When the user was created
    pub created_at: DateTime<Utc>,

    /// Last login timestamp
    pub last_login: Option<DateTime<Utc>>,
}

/// User role enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Enum)]
pub enum UserRole {
    /// Full administrative access
    Admin,

    /// Can modify configuration
    Operator,

    /// Read-only access
    Viewer,
}

/// Audit log entry
#[derive(Debug, Clone, Serialize, Deserialize, SimpleObject)]
#[graphql(name = "AuditLog")]
pub struct GqlAuditLog {
    /// Log entry ID
    pub id: String,

    /// User who performed the action
    pub user_id: String,

    /// Event type
    pub event_type: String,

    /// Event description
    pub description: String,

    /// Source IP address
    pub ip_address: String,

    /// Timestamp of event
    pub timestamp: DateTime<Utc>,

    /// Additional event data (JSON)
    pub metadata: Option<String>,
}

// Input types for mutations

/// Input for creating a new site
#[derive(Debug, Clone, InputObject)]
pub struct CreateSiteInput {
    /// Site name
    pub name: String,

    /// Site location/region
    pub location: Option<String>,
}

/// Input for updating a site
#[derive(Debug, Clone, InputObject)]
pub struct UpdateSiteInput {
    /// Site ID to update
    pub id: String,

    /// New site name
    pub name: Option<String>,

    /// New location
    pub location: Option<String>,

    /// New status
    pub status: Option<SiteStatus>,
}

/// Input for creating a policy
#[derive(Debug, Clone, InputObject)]
pub struct CreatePolicyInput {
    /// Policy name
    pub name: String,

    /// Policy description
    pub description: Option<String>,

    /// Priority (higher = more important)
    pub priority: i32,

    /// Traffic matching rules (JSON string)
    pub match_rules: String,

    /// Action to take
    pub action: PolicyAction,
}

/// Input for updating a policy
#[derive(Debug, Clone, InputObject)]
pub struct UpdatePolicyInput {
    /// Policy ID to update
    pub id: String,

    /// New name
    pub name: Option<String>,

    /// New description
    pub description: Option<String>,

    /// New priority
    pub priority: Option<i32>,

    /// New match rules
    pub match_rules: Option<String>,

    /// New action
    pub action: Option<PolicyAction>,

    /// Enable/disable policy
    pub enabled: Option<bool>,
}

/// Input for creating a user
#[derive(Debug, Clone, InputObject)]
pub struct CreateUserInput {
    /// Email address
    pub email: String,

    /// Initial password
    pub password: String,

    /// User role
    pub role: UserRole,
}

/// Pagination input
#[derive(Debug, Clone, InputObject)]
pub struct PaginationInput {
    /// Number of items to return (max 100)
    pub limit: Option<i32>,

    /// Number of items to skip
    pub offset: Option<i32>,
}

/// Filter input for queries
#[derive(Debug, Clone, InputObject)]
pub struct FilterInput {
    /// Filter by status
    pub status: Option<String>,

    /// Filter by date range (start)
    pub from_date: Option<DateTime<Utc>>,

    /// Filter by date range (end)
    pub to_date: Option<DateTime<Utc>>,

    /// Search text
    pub search: Option<String>,
}
