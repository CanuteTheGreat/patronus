//! Prometheus metrics exporter
//!
//! Exports SD-WAN metrics in Prometheus exposition format.

use crate::health::{HealthMonitor, PathStatus};
use crate::failover::FailoverEngine;
use std::sync::Arc;
use std::fmt::Write as FmtWrite;

/// Prometheus metrics exporter
pub struct PrometheusExporter {
    health_monitor: Arc<HealthMonitor>,
    failover_engine: Arc<FailoverEngine>,
}

impl PrometheusExporter {
    /// Create a new Prometheus exporter
    pub fn new(
        health_monitor: Arc<HealthMonitor>,
        failover_engine: Arc<FailoverEngine>,
    ) -> Self {
        Self {
            health_monitor,
            failover_engine,
        }
    }

    /// Generate Prometheus metrics in exposition format
    pub async fn export_metrics(&self) -> String {
        let mut output = String::new();

        // Add header
        writeln!(output, "# HELP patronus_sdwan_info SD-WAN instance information").unwrap();
        writeln!(output, "# TYPE patronus_sdwan_info gauge").unwrap();
        writeln!(output, "patronus_sdwan_info{{version=\"0.2.0\"}} 1").unwrap();
        writeln!(output).unwrap();

        // Path health metrics
        self.export_path_health_metrics(&mut output).await;

        // Failover metrics
        self.export_failover_metrics(&mut output).await;

        output
    }

    /// Export path health metrics
    async fn export_path_health_metrics(&self, output: &mut String) {
        // Health score
        writeln!(output, "# HELP patronus_sdwan_path_health_score Path health score (0-100)").unwrap();
        writeln!(output, "# TYPE patronus_sdwan_path_health_score gauge").unwrap();

        let health_map = self.health_monitor.get_all_health().await;
        for (path_id, health) in health_map {
            writeln!(
                output,
                "patronus_sdwan_path_health_score{{path_id=\"{}\"}} {:.2}",
                path_id, health.health_score
            ).unwrap();
        }
        writeln!(output).unwrap();

        // Latency
        writeln!(output, "# HELP patronus_sdwan_path_latency_ms Path latency in milliseconds").unwrap();
        writeln!(output, "# TYPE patronus_sdwan_path_latency_ms gauge").unwrap();

        for (path_id, health) in self.health_monitor.get_all_health().await {
            writeln!(
                output,
                "patronus_sdwan_path_latency_ms{{path_id=\"{}\"}} {:.2}",
                path_id, health.latency_ms
            ).unwrap();
        }
        writeln!(output).unwrap();

        // Packet loss
        writeln!(output, "# HELP patronus_sdwan_path_packet_loss_pct Path packet loss percentage").unwrap();
        writeln!(output, "# TYPE patronus_sdwan_path_packet_loss_pct gauge").unwrap();

        for (path_id, health) in self.health_monitor.get_all_health().await {
            writeln!(
                output,
                "patronus_sdwan_path_packet_loss_pct{{path_id=\"{}\"}} {:.2}",
                path_id, health.packet_loss_pct
            ).unwrap();
        }
        writeln!(output).unwrap();

        // Jitter
        writeln!(output, "# HELP patronus_sdwan_path_jitter_ms Path jitter in milliseconds").unwrap();
        writeln!(output, "# TYPE patronus_sdwan_path_jitter_ms gauge").unwrap();

        for (path_id, health) in self.health_monitor.get_all_health().await {
            writeln!(
                output,
                "patronus_sdwan_path_jitter_ms{{path_id=\"{}\"}} {:.2}",
                path_id, health.jitter_ms
            ).unwrap();
        }
        writeln!(output).unwrap();

        // Path status
        writeln!(output, "# HELP patronus_sdwan_path_status Path status (1=up, 0.5=degraded, 0=down)").unwrap();
        writeln!(output, "# TYPE patronus_sdwan_path_status gauge").unwrap();

        for (path_id, health) in self.health_monitor.get_all_health().await {
            let status_value = match health.status {
                PathStatus::Up => 1.0,
                PathStatus::Degraded => 0.5,
                PathStatus::Down => 0.0,
            };
            writeln!(
                output,
                "patronus_sdwan_path_status{{path_id=\"{}\",status=\"{}\"}} {:.1}",
                path_id, health.status.as_str(), status_value
            ).unwrap();
        }
        writeln!(output).unwrap();
    }

    /// Export failover metrics
    async fn export_failover_metrics(&self, output: &mut String) {
        // Failover policies
        writeln!(output, "# HELP patronus_sdwan_failover_policies_total Total number of failover policies").unwrap();
        writeln!(output, "# TYPE patronus_sdwan_failover_policies_total gauge").unwrap();

        let policies = self.failover_engine.get_policies().await;
        let enabled_policies = policies.iter().filter(|p| p.enabled).count();
        writeln!(output, "patronus_sdwan_failover_policies_total{{}} {}", policies.len()).unwrap();
        writeln!(output, "patronus_sdwan_failover_policies_total{{enabled=\"true\"}} {}", enabled_policies).unwrap();
        writeln!(output).unwrap();

        // Active path per policy
        writeln!(output, "# HELP patronus_sdwan_failover_active_path Active path for each policy (1=primary, 0=backup)").unwrap();
        writeln!(output, "# TYPE patronus_sdwan_failover_active_path gauge").unwrap();

        for policy in &policies {
            if let Some(state) = self.failover_engine.get_state(policy.policy_id).await {
                let using_primary = if state.using_primary { 1 } else { 0 };
                writeln!(
                    output,
                    "patronus_sdwan_failover_active_path{{policy_id=\"{}\",policy_name=\"{}\",active_path=\"{}\"}} {}",
                    policy.policy_id, policy.name, state.active_path_id, using_primary
                ).unwrap();
            }
        }
        writeln!(output).unwrap();

        // Failover count
        writeln!(output, "# HELP patronus_sdwan_failover_count_total Total number of failovers per policy").unwrap();
        writeln!(output, "# TYPE patronus_sdwan_failover_count_total counter").unwrap();

        for policy in &policies {
            if let Some(state) = self.failover_engine.get_state(policy.policy_id).await {
                writeln!(
                    output,
                    "patronus_sdwan_failover_count_total{{policy_id=\"{}\",policy_name=\"{}\"}} {}",
                    policy.policy_id, policy.name, state.failover_count
                ).unwrap();
            }
        }
        writeln!(output).unwrap();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::Database;
    use crate::health::{HealthConfig, PathHealth};
    use crate::types::PathId;
    use crate::failover::FailoverPolicy;
    use std::net::IpAddr;

    async fn create_test_exporter() -> (Arc<PrometheusExporter>, Arc<HealthMonitor>, Arc<FailoverEngine>) {
        let db = Arc::new(Database::new_in_memory().await.unwrap());
        let health_config = HealthConfig::default();
        let health_monitor = Arc::new(HealthMonitor::new(db.clone(), health_config).await.unwrap());
        let failover_engine = Arc::new(FailoverEngine::new(db, health_monitor.clone()));

        let exporter = Arc::new(PrometheusExporter::new(health_monitor.clone(), failover_engine.clone()));

        (exporter, health_monitor, failover_engine)
    }

    #[tokio::test]
    async fn test_export_empty_metrics() {
        let (exporter, _, _) = create_test_exporter().await;

        let output = exporter.export_metrics().await;

        // Should contain headers
        assert!(output.contains("patronus_sdwan_info"));
        assert!(output.contains("version=\"0.2.0\""));
    }

    #[tokio::test]
    async fn test_export_path_health_metrics() {
        let (exporter, health_monitor, _) = create_test_exporter().await;

        // Add some health data
        let path1 = PathId::new(1);
        let target1: IpAddr = "192.168.1.1".parse().unwrap();
        health_monitor.check_path_health(&path1, target1).await.unwrap();

        let output = exporter.export_metrics().await;

        // Should contain path health metrics
        assert!(output.contains("patronus_sdwan_path_health_score"));
        assert!(output.contains("patronus_sdwan_path_latency_ms"));
        assert!(output.contains("patronus_sdwan_path_packet_loss_pct"));
        assert!(output.contains("patronus_sdwan_path_jitter_ms"));
        assert!(output.contains("patronus_sdwan_path_status"));

        // Should contain path ID
        assert!(output.contains(&format!("path_id=\"{}\"", path1)));
    }

    #[tokio::test]
    async fn test_export_multiple_paths() {
        let (exporter, health_monitor, _) = create_test_exporter().await;

        // Add multiple paths
        let path1 = PathId::new(1);
        let path2 = PathId::new(2);
        let target: IpAddr = "192.168.1.1".parse().unwrap();

        health_monitor.check_path_health(&path1, target).await.unwrap();
        health_monitor.check_path_health(&path2, target).await.unwrap();

        let output = exporter.export_metrics().await;

        // Should contain both paths
        assert!(output.contains(&format!("path_id=\"{}\"", path1)));
        assert!(output.contains(&format!("path_id=\"{}\"", path2)));
    }

    #[tokio::test]
    async fn test_export_failover_metrics() {
        let (exporter, _, failover_engine) = create_test_exporter().await;

        // Add a failover policy
        let policy = FailoverPolicy::new(
            1,
            "test-policy".to_string(),
            PathId::new(10),
            vec![PathId::new(20)],
        );
        failover_engine.add_policy(policy).await.unwrap();

        let output = exporter.export_metrics().await;

        // Should contain failover metrics
        assert!(output.contains("patronus_sdwan_failover_policies_total"));
        assert!(output.contains("patronus_sdwan_failover_active_path"));
        assert!(output.contains("patronus_sdwan_failover_count_total"));

        // Should show 1 policy
        assert!(output.contains("patronus_sdwan_failover_policies_total{} 1"));
        assert!(output.contains("policy_name=\"test-policy\""));
    }

    #[tokio::test]
    async fn test_prometheus_format_validity() {
        let (exporter, health_monitor, _) = create_test_exporter().await;

        let path1 = PathId::new(1);
        let target: IpAddr = "192.168.1.1".parse().unwrap();
        health_monitor.check_path_health(&path1, target).await.unwrap();

        let output = exporter.export_metrics().await;

        // Check Prometheus format rules
        // 1. Each metric should have HELP and TYPE
        let help_count = output.matches("# HELP").count();
        let type_count = output.matches("# TYPE").count();
        assert_eq!(help_count, type_count);

        // 2. Metric lines should not start with #
        for line in output.lines() {
            if !line.starts_with('#') && !line.is_empty() {
                // Should contain metric name and value
                assert!(line.contains(' '));
            }
        }

        // 3. Values should be numeric
        let metric_lines: Vec<&str> = output
            .lines()
            .filter(|l| !l.starts_with('#') && !l.is_empty())
            .collect();

        for line in metric_lines {
            let parts: Vec<&str> = line.rsplitn(2, ' ').collect();
            if parts.len() == 2 {
                // Last part should be a valid number
                let value = parts[0];
                assert!(value.parse::<f64>().is_ok() || value == "NaN");
            }
        }
    }

    #[tokio::test]
    async fn test_path_status_encoding() {
        let (exporter, health_monitor, _) = create_test_exporter().await;

        let path1 = PathId::new(1);
        let target: IpAddr = "192.168.1.1".parse().unwrap();
        health_monitor.check_path_health(&path1, target).await.unwrap();

        let output = exporter.export_metrics().await;

        // Path status should be encoded as numeric
        // up=1.0, degraded=0.5, down=0.0
        assert!(output.contains("patronus_sdwan_path_status"));

        // Should have a status label
        let has_status_label = output.contains("status=\"up\"")
            || output.contains("status=\"degraded\"")
            || output.contains("status=\"down\"");
        assert!(has_status_label);
    }
}
