// GraphQL Subscriptions - Real-time updates
//
// This module implements GraphQL subscription resolvers for streaming
// real-time updates to clients via WebSocket.

use async_graphql::{Context, Subscription, Result};
use futures::Stream;
use std::time::Duration;
use chrono::{DateTime, Utc};
use crate::graphql::{
    types::*,
    get_state,
};

/// Root subscription object
pub struct SubscriptionRoot;

#[Subscription]
impl SubscriptionRoot {
    /// Subscribe to real-time metrics updates (Sprint 26)
    async fn metrics_stream(
        &self,
        ctx: &Context<'_>,
        interval_seconds: Option<i32>,
    ) -> Result<impl Stream<Item = GqlMetrics>> {
        let state = get_state(ctx)?;
        let interval = interval_seconds.unwrap_or(10).max(5).min(60);
        let metrics_collector = state.metrics_collector.clone();

        // Create a stream that polls metrics at the specified interval
        Ok(async_stream::stream! {
            let mut interval_timer = tokio::time::interval(Duration::from_secs(interval as u64));

            loop {
                interval_timer.tick().await;

                // Fetch real metrics from the MetricsCollector (Sprint 26)
                let system_metrics = metrics_collector.get_current_metrics().await;

                yield GqlMetrics {
                    timestamp: Utc::now(),
                    throughput_mbps: system_metrics.throughput_mbps,
                    packets_per_second: system_metrics.packets_per_second as i64,
                    active_flows: system_metrics.active_flows as i64,
                    avg_latency_ms: system_metrics.avg_latency_ms,
                    avg_packet_loss: system_metrics.avg_packet_loss,
                    cpu_usage: system_metrics.cpu_usage,
                    memory_usage: system_metrics.memory_usage,
                };
            }
        })
    }

    /// Subscribe to path status changes (Sprint 26)
    async fn path_updates(
        &self,
        ctx: &Context<'_>,
        site_id: Option<String>,
    ) -> Result<impl Stream<Item = GqlPath>> {
        let state = get_state(ctx)?;
        let db = state.db.clone();

        // Create a stream that emits path updates when they change
        Ok(async_stream::stream! {
            let mut interval = tokio::time::interval(Duration::from_secs(15));

            loop {
                interval.tick().await;

                // Fetch all paths from database (Sprint 26)
                match db.list_paths().await {
                    Ok(paths) => {
                        for path in paths {
                            // Filter by site_id if provided
                            if let Some(ref filter_site) = site_id {
                                let src_site_str = path.src_site.to_string();
                                let dst_site_str = path.dst_site.to_string();
                                if &src_site_str != filter_site && &dst_site_str != filter_site {
                                    continue;
                                }
                            }

                            // Get latest metrics for this path
                            if let Ok(metrics) = db.get_latest_metrics(path.id).await {
                                // Determine path status based on quality score
                                let status = if metrics.score >= 80 {
                                    PathStatus::Optimal
                                } else if metrics.score >= 50 {
                                    PathStatus::Degraded
                                } else {
                                    PathStatus::Failed
                                };

                                yield GqlPath {
                                    id: path.id.to_string(),
                                    source_site_id: path.src_site.to_string(),
                                    destination_site_id: path.dst_site.to_string(),
                                    latency_ms: metrics.latency_ms,
                                    packet_loss: metrics.packet_loss_pct,
                                    bandwidth_mbps: metrics.bandwidth_mbps,
                                    quality_score: metrics.score as f64,
                                    status,
                                    last_updated: Utc::now(),
                                };
                            }
                        }
                    }
                    Err(_) => {
                        // Continue on error, will retry on next interval
                    }
                }
            }
        })
    }

    /// Subscribe to site status changes (Sprint 26)
    async fn site_updates(
        &self,
        ctx: &Context<'_>,
    ) -> Result<impl Stream<Item = GqlSite>> {
        let state = get_state(ctx)?;
        let db = state.db.clone();

        Ok(async_stream::stream! {
            let mut interval = tokio::time::interval(Duration::from_secs(30));

            loop {
                interval.tick().await;

                // Fetch all sites from database (Sprint 26)
                match db.list_sites().await {
                    Ok(sites) => {
                        for site in sites {
                            // Count endpoints for this site
                            let endpoint_count = site.endpoints.len() as i32;

                            // Determine site status based on site.status
                            let status = match site.status {
                                patronus_sdwan::types::SiteStatus::Active => SiteStatus::Active,
                                patronus_sdwan::types::SiteStatus::Inactive => SiteStatus::Offline,
                                patronus_sdwan::types::SiteStatus::Degraded => SiteStatus::Degraded,
                            };

                            yield GqlSite {
                                id: site.id.to_string(),
                                name: site.name.clone(),
                                location: None, // Site doesn't have location field
                                endpoint_count,
                                status,
                                created_at: Utc::now(), // Convert SystemTime to DateTime later if needed
                                updated_at: Utc::now(), // Convert last_seen to DateTime later if needed
                            };
                        }
                    }
                    Err(_) => {
                        // Continue on error, will retry on next interval
                    }
                }
            }
        })
    }

    /// Subscribe to policy match events (Sprint 26)
    async fn policy_events(
        &self,
        ctx: &Context<'_>,
        policy_id: Option<String>,
    ) -> Result<impl Stream<Item = PolicyEvent>> {
        let state = get_state(ctx)?;
        let db = state.db.clone();

        Ok(async_stream::stream! {
            let mut interval = tokio::time::interval(Duration::from_secs(10));

            loop {
                interval.tick().await;

                // Fetch policy statistics from database (Sprint 26)
                match db.list_policies().await {
                    Ok(policies) => {
                        for policy in policies {
                            // Filter by policy_id if provided
                            if let Some(ref filter_id) = policy_id {
                                if &policy.id.to_string() != filter_id {
                                    continue;
                                }
                            }

                            // Get policy statistics (placeholder - would come from eBPF in production)
                            yield PolicyEvent {
                                policy_id: policy.id.to_string(),
                                timestamp: Utc::now(),
                                packets: 0, // Would be populated from eBPF stats
                                bytes: 0,   // Would be populated from eBPF stats
                            };
                        }
                    }
                    Err(_) => {
                        // Continue on error, will retry on next interval
                    }
                }
            }
        })
    }

    /// Subscribe to audit log events (admin only) - Sprint 26
    async fn audit_events(
        &self,
        ctx: &Context<'_>,
    ) -> Result<impl Stream<Item = GqlAuditLog>> {
        // Require admin role (Sprint 26)
        let _auth = crate::graphql::require_role(ctx, crate::auth::users::UserRole::Admin)?;

        let state = get_state(ctx)?;
        let audit_logger = state.audit_logger.clone();

        Ok(async_stream::stream! {
            let mut interval = tokio::time::interval(Duration::from_secs(15));
            let mut last_id: i64 = 0;

            loop {
                interval.tick().await;

                // Stream new audit events since last check (Sprint 26)
                match audit_logger.get_logs(
                    None,  // event_type
                    None,  // severity
                    None,  // since
                    None,  // until
                    100,   // limit
                ).await {
                    Ok(logs) => {
                        for log in logs {
                            // Only emit logs we haven't seen yet
                            if log.id > last_id {
                                last_id = log.id;

                                yield GqlAuditLog {
                                    id: log.id.to_string(),
                                    user_id: log.user_id.unwrap_or_else(|| "system".to_string()),
                                    event_type: log.event_type,
                                    description: log.event_data,
                                    ip_address: log.ip_address.unwrap_or_else(|| "unknown".to_string()),
                                    timestamp: log.timestamp,
                                    metadata: Some(format!("{{\"success\": {}, \"severity\": \"{}\"}}", log.success, log.severity)),
                                };
                            }
                        }
                    }
                    Err(_) => {
                        // Continue on error, will retry on next interval
                    }
                }
            }
        })
    }

    /// Subscribe to system alerts (Sprint 26)
    async fn system_alerts(
        &self,
        ctx: &Context<'_>,
        severity: Option<AlertSeverity>,
    ) -> Result<impl Stream<Item = SystemAlert>> {
        let state = get_state(ctx)?;
        let db = state.db.clone();
        let metrics_collector = state.metrics_collector.clone();

        Ok(async_stream::stream! {
            let mut interval = tokio::time::interval(Duration::from_secs(30));

            loop {
                interval.tick().await;

                // Generate alerts based on system health (Sprint 26)
                let system_metrics = metrics_collector.get_current_metrics().await;

                // Check CPU usage
                if system_metrics.cpu_usage > 90.0 {
                    let alert_severity = AlertSeverity::Critical;
                    if severity.is_none() || severity == Some(alert_severity) {
                        yield SystemAlert {
                            id: uuid::Uuid::new_v4().to_string(),
                            severity: alert_severity,
                            title: "Critical CPU Usage".to_string(),
                            message: format!("CPU usage at {:.1}%", system_metrics.cpu_usage),
                            timestamp: Utc::now(),
                            resolved: false,
                        };
                    }
                } else if system_metrics.cpu_usage > 75.0 {
                    let alert_severity = AlertSeverity::Warning;
                    if severity.is_none() || severity == Some(alert_severity) {
                        yield SystemAlert {
                            id: uuid::Uuid::new_v4().to_string(),
                            severity: alert_severity,
                            title: "High CPU Usage".to_string(),
                            message: format!("CPU usage at {:.1}%", system_metrics.cpu_usage),
                            timestamp: Utc::now(),
                            resolved: false,
                        };
                    }
                }

                // Check memory usage
                if system_metrics.memory_usage > 90.0 {
                    let alert_severity = AlertSeverity::Critical;
                    if severity.is_none() || severity == Some(alert_severity) {
                        yield SystemAlert {
                            id: uuid::Uuid::new_v4().to_string(),
                            severity: alert_severity,
                            title: "Critical Memory Usage".to_string(),
                            message: format!("Memory usage at {:.1}%", system_metrics.memory_usage),
                            timestamp: Utc::now(),
                            resolved: false,
                        };
                    }
                }

                // Check path health
                match db.list_paths().await {
                    Ok(paths) => {
                        for path in paths {
                            if let Ok(metrics) = db.get_latest_metrics(path.id).await {
                                // High latency alert
                                if metrics.latency_ms > 200.0 {
                                    let alert_severity = AlertSeverity::Warning;
                                    if severity.is_none() || severity == Some(alert_severity) {
                                        yield SystemAlert {
                                            id: uuid::Uuid::new_v4().to_string(),
                                            severity: alert_severity,
                                            title: "High Path Latency".to_string(),
                                            message: format!("Path {} experiencing {:.1}ms latency", path.id, metrics.latency_ms),
                                            timestamp: Utc::now(),
                                            resolved: false,
                                        };
                                    }
                                }

                                // Packet loss alert
                                if metrics.packet_loss_pct > 2.0 {
                                    let alert_severity = AlertSeverity::Warning;
                                    if severity.is_none() || severity == Some(alert_severity) {
                                        yield SystemAlert {
                                            id: uuid::Uuid::new_v4().to_string(),
                                            severity: alert_severity,
                                            title: "Path Packet Loss".to_string(),
                                            message: format!("Path {} experiencing {:.2}% packet loss", path.id, metrics.packet_loss_pct),
                                            timestamp: Utc::now(),
                                            resolved: false,
                                        };
                                    }
                                }

                                // Low quality score
                                if metrics.score < 50 {
                                    let alert_severity = AlertSeverity::Critical;
                                    if severity.is_none() || severity == Some(alert_severity) {
                                        yield SystemAlert {
                                            id: uuid::Uuid::new_v4().to_string(),
                                            severity: alert_severity,
                                            title: "Path Quality Degraded".to_string(),
                                            message: format!("Path {} quality score: {}", path.id, metrics.score),
                                            timestamp: Utc::now(),
                                            resolved: false,
                                        };
                                    }
                                }
                            }
                        }
                    }
                    Err(_) => {
                        // Continue on error
                    }
                }
            }
        })
    }
}

/// Policy event for subscription
#[derive(Debug, Clone, async_graphql::SimpleObject)]
pub struct PolicyEvent {
    /// Policy ID
    pub policy_id: String,

    /// Event timestamp
    pub timestamp: DateTime<Utc>,

    /// Number of packets matched
    pub packets: i64,

    /// Number of bytes matched
    pub bytes: i64,
}

/// System alert
#[derive(Debug, Clone, async_graphql::SimpleObject)]
pub struct SystemAlert {
    /// Alert ID
    pub id: String,

    /// Alert severity
    pub severity: AlertSeverity,

    /// Alert title
    pub title: String,

    /// Alert message
    pub message: String,

    /// When alert was triggered
    pub timestamp: DateTime<Utc>,

    /// Whether alert has been resolved
    pub resolved: bool,
}

/// Alert severity levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, async_graphql::Enum)]
pub enum AlertSeverity {
    /// Critical alert requiring immediate attention
    Critical,

    /// Warning alert
    Warning,

    /// Informational alert
    Info,
}
