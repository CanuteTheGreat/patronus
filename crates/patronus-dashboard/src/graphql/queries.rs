// GraphQL Queries - Read operations
//
// This module implements all GraphQL query resolvers for fetching data.

use async_graphql::{Context, Object, Result};
use chrono::{DateTime, Utc};
use crate::graphql::{
    types::*,
    get_state,
};

/// Root query object
pub struct QueryRoot;

#[Object]
impl QueryRoot {
    /// Get a site by ID (requires authentication)
    async fn site(&self, ctx: &Context<'_>, id: String) -> Result<Option<GqlSite>> {
        // Require authentication
        let _auth = crate::graphql::require_auth(ctx)?;

        let state = get_state(ctx)?;

        // Fetch from database
        use patronus_sdwan::types::SiteId;
        let site_id: SiteId = id.parse().map_err(|_| async_graphql::Error::new("Invalid site ID"))?;

        match state.db.get_site(&site_id).await {
            Ok(Some(site)) => {
                Ok(Some(GqlSite {
                    id: site.id.to_string(),
                    name: site.name,
                    location: None,
                    endpoint_count: site.endpoints.len() as i32,
                    status: match site.status {
                        patronus_sdwan::types::SiteStatus::Active => SiteStatus::Active,
                        patronus_sdwan::types::SiteStatus::Degraded => SiteStatus::Degraded,
                        patronus_sdwan::types::SiteStatus::Inactive => SiteStatus::Offline,
                    },
                    created_at: DateTime::from_timestamp(
                        site.created_at.duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64,
                        0
                    ).unwrap_or_else(|| Utc::now()),
                    updated_at: DateTime::from_timestamp(
                        site.last_seen.duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64,
                        0
                    ).unwrap_or_else(|| Utc::now()),
                }))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(async_graphql::Error::new(format!("Database error: {}", e))),
        }
    }

    /// List all sites with optional filtering and pagination (requires authentication)
    async fn sites(
        &self,
        ctx: &Context<'_>,
        _filter: Option<FilterInput>,
        _pagination: Option<PaginationInput>,
    ) -> Result<Vec<GqlSite>> {
        // Require authentication
        let _auth = crate::graphql::require_auth(ctx)?;

        let state = get_state(ctx)?;

        // Fetch from database
        match state.db.list_sites().await {
            Ok(sites) => {
                let gql_sites: Vec<GqlSite> = sites.into_iter().map(|site| {
                    GqlSite {
                        id: site.id.to_string(),
                        name: site.name,
                        location: None,
                        endpoint_count: site.endpoints.len() as i32,
                        status: match site.status {
                            patronus_sdwan::types::SiteStatus::Active => SiteStatus::Active,
                            patronus_sdwan::types::SiteStatus::Degraded => SiteStatus::Degraded,
                            patronus_sdwan::types::SiteStatus::Inactive => SiteStatus::Offline,
                        },
                        created_at: DateTime::from_timestamp(
                            site.created_at.duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64,
                            0
                        ).unwrap_or_else(|| Utc::now()),
                        updated_at: DateTime::from_timestamp(
                            site.last_seen.duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64,
                            0
                        ).unwrap_or_else(|| Utc::now()),
                    }
                }).collect();

                Ok(gql_sites)
            }
            Err(e) => Err(async_graphql::Error::new(format!("Database error: {}", e))),
        }
    }

    /// Get total count of sites
    async fn site_count(&self, ctx: &Context<'_>, _filter: Option<FilterInput>) -> Result<i32> {
        let state = get_state(ctx)?;

        // Fetch count from database
        match state.db.count_sites().await {
            Ok(count) => Ok(count as i32),
            Err(e) => Err(async_graphql::Error::new(format!("Database error: {}", e))),
        }
    }

    /// Get a path by ID
    async fn path(&self, ctx: &Context<'_>, id: String) -> Result<Option<GqlPath>> {
        let state = get_state(ctx)?;

        // Parse path ID
        use patronus_sdwan::types::PathId;
        let path_id = id.parse::<u64>()
            .map_err(|_| async_graphql::Error::new("Invalid path ID"))?;
        let path_id = PathId::new(path_id);

        // Fetch path from database
        match state.db.get_path(path_id).await {
            Ok(path) => {
                // Get latest metrics for this path
                let metrics = state.db.get_latest_metrics(path_id).await.ok();

                Ok(Some(GqlPath {
                    id: path.id.as_u64().to_string(),
                    source_site_id: path.src_site.to_string(),
                    destination_site_id: path.dst_site.to_string(),
                    latency_ms: metrics.as_ref().map(|m| m.latency_ms).unwrap_or(0.0),
                    packet_loss: metrics.as_ref().map(|m| m.packet_loss_pct).unwrap_or(0.0),
                    bandwidth_mbps: metrics.as_ref().map(|m| m.bandwidth_mbps).unwrap_or(0.0),
                    quality_score: metrics.as_ref().map(|m| m.score as f64).unwrap_or(0.0),
                    status: match path.status {
                        patronus_sdwan::types::PathStatus::Up => PathStatus::Optimal,
                        patronus_sdwan::types::PathStatus::Degraded => PathStatus::Degraded,
                        patronus_sdwan::types::PathStatus::Down => PathStatus::Failed,
                    },
                    last_updated: metrics.as_ref().map(|m| {
                        DateTime::from_timestamp(
                            m.measured_at.duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64,
                            0
                        ).unwrap_or_else(|| Utc::now())
                    }).unwrap_or_else(|| Utc::now()),
                }))
            }
            Err(e) => {
                // Path not found or database error
                if e.to_string().contains("no rows") {
                    Ok(None)
                } else {
                    Err(async_graphql::Error::new(format!("Database error: {}", e)))
                }
            }
        }
    }

    /// List all paths with optional filtering
    async fn paths(
        &self,
        ctx: &Context<'_>,
        _source_site_id: Option<String>,
        _destination_site_id: Option<String>,
        _pagination: Option<PaginationInput>,
    ) -> Result<Vec<GqlPath>> {
        let state = get_state(ctx)?;

        // Fetch all paths from database
        match state.db.list_paths().await {
            Ok(paths) => {
                let mut gql_paths = Vec::new();

                for path in paths {
                    // Get latest metrics for each path (best effort)
                    let metrics = state.db.get_latest_metrics(path.id).await.ok();

                    gql_paths.push(GqlPath {
                        id: path.id.as_u64().to_string(),
                        source_site_id: path.src_site.to_string(),
                        destination_site_id: path.dst_site.to_string(),
                        latency_ms: metrics.as_ref().map(|m| m.latency_ms).unwrap_or(0.0),
                        packet_loss: metrics.as_ref().map(|m| m.packet_loss_pct).unwrap_or(0.0),
                        bandwidth_mbps: metrics.as_ref().map(|m| m.bandwidth_mbps).unwrap_or(0.0),
                        quality_score: metrics.as_ref().map(|m| m.score as f64).unwrap_or(0.0),
                        status: match path.status {
                            patronus_sdwan::types::PathStatus::Up => PathStatus::Optimal,
                            patronus_sdwan::types::PathStatus::Degraded => PathStatus::Degraded,
                            patronus_sdwan::types::PathStatus::Down => PathStatus::Failed,
                        },
                        last_updated: metrics.as_ref().map(|m| {
                            DateTime::from_timestamp(
                                m.measured_at.duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64,
                                0
                            ).unwrap_or_else(|| Utc::now())
                        }).unwrap_or_else(|| Utc::now()),
                    });
                }

                Ok(gql_paths)
            }
            Err(e) => Err(async_graphql::Error::new(format!("Database error: {}", e))),
        }
    }

    /// Get a policy by ID
    async fn policy(&self, ctx: &Context<'_>, id: String) -> Result<Option<GqlPolicy>> {
        let state = get_state(ctx)?;

        // Parse policy ID
        let policy_id = id.parse::<u64>()
            .map_err(|_| async_graphql::Error::new("Invalid policy ID"))?;

        // Fetch from database
        match state.db.get_policy(policy_id).await {
            Ok(Some(policy)) => {
                // Get traffic stats (Sprint 30)
                let stats = state.traffic_stats.get_policy_stats(policy_id).await.unwrap_or_default();

                Ok(Some(GqlPolicy {
                    id: policy.id.to_string(),
                    name: policy.name,
                    description: None,
                    priority: policy.priority as i32,
                    match_rules: serde_json::to_string(&policy.match_rules).unwrap_or_default(),
                    action: PolicyAction::Route, // TODO: Map from PathPreference to PolicyAction
                    enabled: policy.enabled,
                    packets_matched: stats.packets_matched as i64,
                    bytes_matched: stats.bytes_matched as i64,
                    created_at: Utc::now(), // TODO: Add created_at to RoutingPolicy type
                }))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(async_graphql::Error::new(format!("Database error: {}", e))),
        }
    }

    /// List all policies with optional filtering
    async fn policies(
        &self,
        ctx: &Context<'_>,
        _filter: Option<FilterInput>,
        _pagination: Option<PaginationInput>,
    ) -> Result<Vec<GqlPolicy>> {
        let state = get_state(ctx)?;

        // Fetch from database
        match state.db.list_policies().await {
            Ok(policies) => {
                // Get all traffic stats in one go (Sprint 30)
                let all_stats = state.traffic_stats.get_all_policy_stats().await;

                let gql_policies: Vec<GqlPolicy> = policies.into_iter().map(|policy| {
                    let stats = all_stats.get(&policy.id).cloned().unwrap_or_default();

                    GqlPolicy {
                        id: policy.id.to_string(),
                        name: policy.name,
                        description: None,
                        priority: policy.priority as i32,
                        match_rules: serde_json::to_string(&policy.match_rules).unwrap_or_default(),
                        action: PolicyAction::Route, // TODO: Map from PathPreference to PolicyAction
                        enabled: policy.enabled,
                        packets_matched: stats.packets_matched as i64,
                        bytes_matched: stats.bytes_matched as i64,
                        created_at: Utc::now(), // TODO: Add created_at to RoutingPolicy type
                    }
                }).collect();

                Ok(gql_policies)
            }
            Err(e) => Err(async_graphql::Error::new(format!("Database error: {}", e))),
        }
    }

    /// Get current system metrics
    async fn metrics(&self, ctx: &Context<'_>) -> Result<GqlMetrics> {
        let state = get_state(ctx)?;

        // Get current metrics from collector
        let metrics = state.metrics_collector.get_current_metrics().await;

        Ok(GqlMetrics {
            timestamp: DateTime::from_timestamp(
                metrics.timestamp.duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64,
                0
            ).unwrap_or_else(|| Utc::now()),
            throughput_mbps: metrics.throughput_mbps,
            packets_per_second: metrics.packets_per_second as i64,
            active_flows: metrics.active_flows as i64,
            avg_latency_ms: metrics.avg_latency_ms,
            avg_packet_loss: metrics.avg_packet_loss,
            cpu_usage: metrics.cpu_usage,
            memory_usage: metrics.memory_usage,
        })
    }

    /// Get metrics history over time range
    async fn metrics_history(
        &self,
        ctx: &Context<'_>,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
        _interval_seconds: Option<i32>,
    ) -> Result<Vec<GqlMetrics>> {
        let state = get_state(ctx)?;

        // Convert DateTime<Utc> to SystemTime
        let from_ts = std::time::UNIX_EPOCH + std::time::Duration::from_secs(from.timestamp() as u64);
        let to_ts = std::time::UNIX_EPOCH + std::time::Duration::from_secs(to.timestamp() as u64);

        // Get metrics history from database
        match state.db.get_system_metrics_history(from_ts, to_ts).await {
            Ok(history) => {
                let gql_metrics: Vec<GqlMetrics> = history.into_iter().map(|m| {
                    GqlMetrics {
                        timestamp: DateTime::from_timestamp(
                            m.timestamp.duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64,
                            0
                        ).unwrap_or_else(|| Utc::now()),
                        throughput_mbps: m.throughput_mbps,
                        packets_per_second: m.packets_per_second as i64,
                        active_flows: m.active_flows as i64,
                        avg_latency_ms: m.avg_latency_ms,
                        avg_packet_loss: m.avg_packet_loss,
                        cpu_usage: m.cpu_usage,
                        memory_usage: m.memory_usage,
                    }
                }).collect();

                Ok(gql_metrics)
            }
            Err(e) => Err(async_graphql::Error::new(format!("Database error: {}", e))),
        }
    }

    /// Get a user by ID (admin only)
    async fn user(&self, ctx: &Context<'_>, id: String) -> Result<Option<GqlUser>> {
        // Require admin role
        let _auth = crate::graphql::require_role(ctx, crate::auth::users::UserRole::Admin)?;

        let state = get_state(ctx)?;

        // Fetch from database
        match state.user_repository.get_user(&id).await {
            Ok(Some(user)) => {
                Ok(Some(GqlUser {
                    id: user.id,
                    email: user.email,
                    role: match user.role {
                        crate::auth::users::UserRole::Admin => UserRole::Admin,
                        crate::auth::users::UserRole::Operator => UserRole::Operator,
                        crate::auth::users::UserRole::Viewer => UserRole::Viewer,
                    },
                    active: user.is_active,
                    created_at: user.created_at,
                    last_login: user.last_login,
                }))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(async_graphql::Error::new(format!("Database error: {}", e))),
        }
    }

    /// List all users (admin only)
    async fn users(
        &self,
        ctx: &Context<'_>,
        _pagination: Option<PaginationInput>,
    ) -> Result<Vec<GqlUser>> {
        // Require admin role
        let _auth = crate::graphql::require_role(ctx, crate::auth::users::UserRole::Admin)?;

        let state = get_state(ctx)?;

        // Fetch from database
        match state.user_repository.list_users().await {
            Ok(users) => {
                let gql_users: Vec<GqlUser> = users.into_iter().map(|user| {
                    GqlUser {
                        id: user.id,
                        email: user.email,
                        role: match user.role {
                            crate::auth::users::UserRole::Admin => UserRole::Admin,
                            crate::auth::users::UserRole::Operator => UserRole::Operator,
                            crate::auth::users::UserRole::Viewer => UserRole::Viewer,
                        },
                        active: user.is_active,
                        created_at: user.created_at,
                        last_login: user.last_login,
                    }
                }).collect();

                Ok(gql_users)
            }
            Err(e) => Err(async_graphql::Error::new(format!("Database error: {}", e))),
        }
    }

    /// Get audit logs with optional filters (admin only) - Sprint 25
    async fn audit_logs(
        &self,
        ctx: &Context<'_>,
        user_id: Option<String>,
        event_type: Option<String>,
        severity: Option<String>,
        since: Option<DateTime<Utc>>,
        until: Option<DateTime<Utc>>,
        limit: Option<i32>,
    ) -> Result<Vec<GqlAuditLog>> {
        // Require admin role
        let _auth = crate::graphql::require_role(ctx, crate::auth::users::UserRole::Admin)?;

        let state = get_state(ctx)?;

        // Get audit logs from audit logger
        let logs = state.audit_logger.get_logs(
            event_type,
            severity,
            since,
            until,
            limit.unwrap_or(100) as i64,
        ).await
            .map_err(|e| async_graphql::Error::new(format!("Failed to get audit logs: {}", e)))?;

        // Filter by user_id if provided
        let logs = if let Some(uid) = user_id {
            logs.into_iter()
                .filter(|log| log.user_id.as_ref().map(|id| id == &uid).unwrap_or(false))
                .collect()
        } else {
            logs
        };

        // Convert to GraphQL type
        let gql_logs: Vec<GqlAuditLog> = logs.into_iter().map(|log| {
            GqlAuditLog {
                id: log.id.to_string(),
                user_id: log.user_id.unwrap_or_else(|| "system".to_string()),
                event_type: log.event_type,
                description: log.event_data,
                ip_address: log.ip_address.unwrap_or_else(|| "unknown".to_string()),
                timestamp: log.timestamp,
                metadata: Some(format!("{{\"success\": {}, \"severity\": \"{}\"}}", log.success, log.severity)),
            }
        }).collect();

        Ok(gql_logs)
    }

    /// Get mutation-specific audit logs (admin only) - Sprint 25
    async fn mutation_logs(
        &self,
        ctx: &Context<'_>,
        limit: Option<i32>,
    ) -> Result<Vec<GqlAuditLog>> {
        // Require admin role
        let _auth = crate::graphql::require_role(ctx, crate::auth::users::UserRole::Admin)?;

        let state = get_state(ctx)?;

        // Get mutation logs
        let logs = state.audit_logger.get_mutation_logs(limit.unwrap_or(100) as i64).await
            .map_err(|e| async_graphql::Error::new(format!("Failed to get mutation logs: {}", e)))?;

        // Convert to GraphQL type
        let gql_logs: Vec<GqlAuditLog> = logs.into_iter().map(|log| {
            GqlAuditLog {
                id: log.id.to_string(),
                user_id: log.user_id.unwrap_or_else(|| "system".to_string()),
                event_type: log.event_type,
                description: log.event_data,
                ip_address: log.ip_address.unwrap_or_else(|| "unknown".to_string()),
                timestamp: log.timestamp,
                metadata: Some(format!("{{\"success\": {}, \"severity\": \"{}\", \"user_email\": \"{}\"}}",
                    log.success,
                    log.severity,
                    log.user_email.unwrap_or_else(|| "unknown".to_string())
                )),
            }
        }).collect();

        Ok(gql_logs)
    }

    /// Health check endpoint
    async fn health(&self, ctx: &Context<'_>) -> Result<String> {
        let _state = get_state(ctx)?;
        Ok("OK".to_string())
    }

    /// API version information
    async fn version(&self, ctx: &Context<'_>) -> Result<String> {
        let _state = get_state(ctx)?;
        Ok("v2.0.0".to_string())
    }
}
