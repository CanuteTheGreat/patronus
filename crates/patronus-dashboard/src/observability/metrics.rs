//! Metrics collection and Prometheus export

use metrics::{counter, describe_counter, describe_gauge, describe_histogram, gauge, histogram};
use std::sync::Arc;
use std::time::Instant;

/// Dashboard metrics collector
#[derive(Clone)]
pub struct DashboardMetrics {
    start_time: Arc<Instant>,
}

impl DashboardMetrics {
    /// Create new metrics collector
    pub fn new() -> Self {
        Self::register_metrics();
        Self {
            start_time: Arc::new(Instant::now()),
        }
    }

    /// Register all metrics with descriptions
    fn register_metrics() {
        // HTTP metrics
        describe_counter!(
            "http_requests_total",
            "Total number of HTTP requests received"
        );
        describe_histogram!(
            "http_request_duration_seconds",
            "HTTP request duration in seconds"
        );
        describe_counter!("http_requests_errors_total", "Total number of HTTP errors");

        // Authentication metrics
        describe_counter!("auth_login_attempts_total", "Total login attempts");
        describe_counter!("auth_login_success_total", "Successful login attempts");
        describe_counter!("auth_login_failures_total", "Failed login attempts");
        describe_counter!("auth_token_refresh_total", "Token refresh operations");

        // Database metrics
        describe_histogram!(
            "db_query_duration_seconds",
            "Database query duration in seconds"
        );
        describe_counter!("db_queries_total", "Total database queries");
        describe_counter!("db_errors_total", "Database errors");

        // WebSocket metrics
        describe_gauge!("websocket_connections_active", "Active WebSocket connections");
        describe_counter!(
            "websocket_messages_sent_total",
            "Total WebSocket messages sent"
        );
        describe_counter!(
            "websocket_messages_received_total",
            "Total WebSocket messages received"
        );

        // SD-WAN metrics
        describe_gauge!("sdwan_sites_total", "Total number of sites");
        describe_gauge!("sdwan_paths_total", "Total number of paths");
        describe_gauge!("sdwan_paths_active", "Number of active paths");
        describe_gauge!("sdwan_policies_total", "Total number of policies");
        describe_histogram!(
            "sdwan_path_latency_ms",
            "Path latency in milliseconds"
        );
        describe_gauge!(
            "sdwan_path_packet_loss_pct",
            "Path packet loss percentage"
        );

        // System metrics
        describe_gauge!("system_uptime_seconds", "System uptime in seconds");
        describe_gauge!("system_memory_usage_bytes", "Memory usage in bytes");
        describe_gauge!("active_users_total", "Number of active users");
    }

    /// Record HTTP request
    pub fn record_http_request(&self, method: &str, path: &str, status: u16, duration_ms: f64) {
        let labels = [
            ("method", method.to_string()),
            ("path", path.to_string()),
            ("status", status.to_string()),
        ];

        counter!("http_requests_total", &labels).increment(1);
        histogram!("http_request_duration_seconds", &labels).record(duration_ms / 1000.0);

        if status >= 400 {
            counter!("http_requests_errors_total", &labels).increment(1);
        }
    }

    /// Record login attempt
    pub fn record_login_attempt(&self, success: bool) {
        counter!("auth_login_attempts_total").increment(1);

        if success {
            counter!("auth_login_success_total").increment(1);
        } else {
            counter!("auth_login_failures_total").increment(1);
        }
    }

    /// Record token refresh
    pub fn record_token_refresh(&self) {
        counter!("auth_token_refresh_total").increment(1);
    }

    /// Record database query
    pub fn record_db_query(&self, query_type: &str, duration_ms: f64, error: bool) {
        let labels = [("type", query_type.to_string())];

        counter!("db_queries_total", &labels).increment(1);
        histogram!("db_query_duration_seconds", &labels).record(duration_ms / 1000.0);

        if error {
            counter!("db_errors_total", &labels).increment(1);
        }
    }

    /// Update WebSocket connection count
    pub fn set_websocket_connections(&self, count: i64) {
        gauge!("websocket_connections_active").set(count as f64);
    }

    /// Record WebSocket message
    pub fn record_websocket_message(&self, sent: bool) {
        if sent {
            counter!("websocket_messages_sent_total").increment(1);
        } else {
            counter!("websocket_messages_received_total").increment(1);
        }
    }

    /// Update SD-WAN metrics
    pub fn update_sdwan_metrics(
        &self,
        sites: usize,
        paths_total: usize,
        paths_active: usize,
        policies: usize,
    ) {
        gauge!("sdwan_sites_total").set(sites as f64);
        gauge!("sdwan_paths_total").set(paths_total as f64);
        gauge!("sdwan_paths_active").set(paths_active as f64);
        gauge!("sdwan_policies_total").set(policies as f64);
    }

    /// Record path metrics
    pub fn record_path_metrics(&self, path_id: &str, latency_ms: f64, packet_loss_pct: f64) {
        let labels = [("path_id", path_id.to_string())];

        histogram!("sdwan_path_latency_ms", &labels).record(latency_ms);
        gauge!("sdwan_path_packet_loss_pct", &labels).set(packet_loss_pct);
    }

    /// Update system uptime
    pub fn update_uptime(&self) {
        let uptime_secs = self.start_time.elapsed().as_secs() as f64;
        gauge!("system_uptime_seconds").set(uptime_secs);
    }

    /// Update memory usage
    pub fn update_memory_usage(&self, bytes: u64) {
        gauge!("system_memory_usage_bytes").set(bytes as f64);
    }

    /// Update active users count
    pub fn update_active_users(&self, count: usize) {
        gauge!("active_users_total").set(count as f64);
    }

    // High Availability Metrics

    /// Record cluster node count
    pub fn update_cluster_nodes(&self, total: usize, healthy: usize) {
        gauge!("cluster_nodes_total").set(total as f64);
        gauge!("cluster_nodes_healthy").set(healthy as f64);
    }

    /// Record leadership status
    pub fn set_is_leader(&self, is_leader: bool) {
        gauge!("cluster_is_leader").set(if is_leader { 1.0 } else { 0.0 });
    }

    /// Record leader election
    pub fn record_leader_election(&self, node_id: &str, term: u64) {
        counter!("cluster_elections_total").increment(1);
        gauge!("cluster_current_term").set(term as f64);
        counter!("cluster_elections_by_node", "node_id" => node_id.to_string()).increment(1);
    }

    /// Record heartbeat sent/received
    pub fn record_heartbeat(&self, sent: bool) {
        if sent {
            counter!("cluster_heartbeats_sent_total").increment(1);
        } else {
            counter!("cluster_heartbeats_received_total").increment(1);
        }
    }

    /// Record state replication operation
    pub fn record_state_replication(&self, operation: &str, success: bool) {
        counter!("cluster_state_replications_total", "operation" => operation.to_string(), "success" => success.to_string()).increment(1);
    }

    /// Record failover event
    pub fn record_failover(&self, from_node: &str, to_node: &str) {
        counter!("cluster_failovers_total", "from_node" => from_node.to_string(), "to_node" => to_node.to_string()).increment(1);
    }

    /// Update distributed state size
    pub fn update_state_size(&self, bytes: u64) {
        gauge!("cluster_state_size_bytes").set(bytes as f64);
    }
}

impl Default for DashboardMetrics {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_creation() {
        let metrics = DashboardMetrics::new();
        // Should not panic
        metrics.record_http_request("GET", "/api/health", 200, 10.5);
        metrics.record_login_attempt(true);
        metrics.update_uptime();
    }

    #[test]
    fn test_login_metrics() {
        let metrics = DashboardMetrics::new();
        metrics.record_login_attempt(true);
        metrics.record_login_attempt(false);
        metrics.record_token_refresh();
    }

    #[test]
    fn test_sdwan_metrics() {
        let metrics = DashboardMetrics::new();
        metrics.update_sdwan_metrics(5, 20, 18, 10);
        metrics.record_path_metrics("path-1", 25.5, 0.1);
    }
}
