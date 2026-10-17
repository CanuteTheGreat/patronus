//! Monitoring state. Lane I replaces the fixtures below with real data.

use std::sync::Arc;
use tokio::sync::RwLock;

use super::SystemManager;

/// Monitoring operations
pub struct MonitoringManager {
    alerts: Arc<RwLock<Vec<crate::templates::Alert>>>,
    /// Real-time threat intelligence database, fed by live external feeds
    /// (EmergingThreats compromised-IP list, and AbuseIPDB if an API key is
    /// configured). This backs the "AI Threats" dashboard widget with
    /// genuine external detections -- see `get_ai_threats`.
    threat_intel_db: Arc<patronus_ai::ThreatIntelDB>,
}

impl Default for MonitoringManager {
    fn default() -> Self {
        Self::new()
    }
}

impl MonitoringManager {
    pub fn new() -> Self {
        let threat_intel_db = Arc::new(patronus_ai::ThreatIntelDB::new());

        // Kick off the live threat feed aggregator in the background. This
        // hits real external sources (EmergingThreats compromised-ips.txt
        // needs no API key; AbuseIPDB would need one via with_abuseipdb,
        // not configured here) on an hourly interval and populates
        // threat_intel_db with real entries.
        let feed_aggregator = Arc::new(patronus_ai::ThreatFeedAggregator::new(
            Arc::clone(&threat_intel_db),
            std::time::Duration::from_secs(3600),
        ));
        tokio::spawn(async move {
            feed_aggregator.start().await;
        });

        let default_alerts = vec![
            crate::templates::Alert {
                id: 1,
                alert_type: "Performance".to_string(),
                severity: "warning".to_string(),
                component: "eth0".to_string(),
                message: "High CPU usage detected on eth0".to_string(),
                timestamp: "2024-01-15 14:30:00".to_string(),
                acknowledged: false,
            },
            crate::templates::Alert {
                id: 2,
                alert_type: "VPN".to_string(),
                severity: "info".to_string(),
                component: "wireguard".to_string(),
                message: "New WireGuard peer connected".to_string(),
                timestamp: "2024-01-15 14:25:00".to_string(),
                acknowledged: true,
            },
        ];

        Self {
            alerts: Arc::new(RwLock::new(default_alerts)),
            threat_intel_db,
        }
    }

    pub async fn get_current_metrics(&self) -> anyhow::Result<crate::templates::SystemMetrics> {
        let cpu_percent = SystemManager::get_cpu_usage();
        let (memory_percent, _) = SystemManager::get_memory_info();
        let disk_percent = SystemManager::get_disk_usage();

        Ok(crate::templates::SystemMetrics {
            cpu_percent,
            memory_percent,
            disk_percent,
            network_rx_rate: 1_234_567,
            network_tx_rate: 987_654,
        })
    }

    pub async fn get_interface_stats(
        &self,
    ) -> anyhow::Result<Vec<crate::templates::InterfaceStats>> {
        let mut stats = Vec::new();

        if let Ok(content) = std::fs::read_to_string("/proc/net/dev") {
            for line in content.lines().skip(2) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 10 {
                    let name = parts[0].trim_end_matches(':');
                    if name == "lo" {
                        continue;
                    }

                    let rx_bytes: u64 = parts[1].parse().unwrap_or(0);
                    let tx_bytes: u64 = parts[9].parse().unwrap_or(0);
                    let rx_packets: u64 = parts[2].parse().unwrap_or(0);
                    let tx_packets: u64 = parts[10].parse().unwrap_or(0);
                    let rx_errors: u64 = parts[3].parse().unwrap_or(0);
                    let tx_errors: u64 = parts[11].parse().unwrap_or(0);

                    stats.push(crate::templates::InterfaceStats {
                        name: name.to_string(),
                        rx_rate: format_bytes(rx_bytes),
                        tx_rate: format_bytes(tx_bytes),
                        rx_packets: format!("{}", rx_packets),
                        tx_packets: format!("{}", tx_packets),
                        errors: format!("{}", rx_errors + tx_errors),
                    });
                }
            }
        }

        if stats.is_empty() {
            stats.push(crate::templates::InterfaceStats {
                name: "eth0".to_string(),
                rx_rate: "1.23 GB".to_string(),
                tx_rate: "987 MB".to_string(),
                rx_packets: "1000000".to_string(),
                tx_packets: "800000".to_string(),
                errors: "0".to_string(),
            });
        }

        Ok(stats)
    }

    pub async fn get_top_connections(
        &self,
        limit: usize,
    ) -> anyhow::Result<Vec<crate::templates::Connection>> {
        let connections = vec![
            crate::templates::Connection {
                protocol: "TCP".to_string(),
                source: "192.168.1.100:54321".to_string(),
                destination: "192.168.1.1:8443".to_string(),
                bytes: "1.2 MB".to_string(),
                packets: "1024".to_string(),
                duration: "5m 30s".to_string(),
            },
            crate::templates::Connection {
                protocol: "UDP".to_string(),
                source: "203.0.113.50:51820".to_string(),
                destination: "10.99.0.1:51820".to_string(),
                bytes: "256 KB".to_string(),
                packets: "512".to_string(),
                duration: "2h 15m".to_string(),
            },
        ];

        Ok(connections.into_iter().take(limit).collect())
    }

    pub async fn get_recent_alerts(
        &self,
        limit: usize,
    ) -> anyhow::Result<Vec<crate::templates::Alert>> {
        let alerts = self.alerts.read().await;
        Ok(alerts.iter().take(limit).cloned().collect())
    }

    /// AI Threats widget: recent detections pulled from the live threat
    /// intelligence database (`patronus-ai`'s `ThreatIntelDB`), which is
    /// populated by the `ThreatFeedAggregator` background task started in
    /// `new()` (EmergingThreats compromised-IP feed today; AbuseIPDB too if
    /// an API key were configured). This is real external threat data, not
    /// a synthetic ML pipeline -- the full `ThreatDetectionEngine` (which
    /// also does local anomaly detection on live traffic via
    /// `patronus-ai::engine::ThreatDetectionEngine::observe_flow`) is not
    /// wired up anywhere yet because nothing in the codebase feeds it real
    /// eBPF/XDP flow telemetry (`patronus-ebpf`'s collector exists but
    /// nothing calls `observe_flow` with live packet data). Until that flow
    /// pipeline is wired, confidence/detection_method/ml_model fields below
    /// reflect "external feed" rather than "local ML classifier".
    pub async fn get_ai_threats(
        &self,
        limit: usize,
    ) -> anyhow::Result<Vec<crate::templates::AiThreat>> {
        let blocklist = self.threat_intel_db.get_blocklist().await;
        let mut threats = Vec::new();

        for ip in blocklist.into_iter().take(limit) {
            let entries = self.threat_intel_db.get_threats(&ip).await;
            let Some(best) = entries
                .iter()
                .max_by(|a, b| a.confidence.total_cmp(&b.confidence))
            else {
                continue;
            };

            let category = best
                .categories
                .first()
                .map(|c| format!("{:?}", c))
                .unwrap_or_else(|| "Unknown".to_string());

            threats.push(crate::templates::AiThreat {
                id: threats.len() as u32 + 1,
                timestamp: best.last_seen.to_rfc3339(),
                threat_type: category.clone(),
                source_ip: ip.clone(),
                destination: "this host".to_string(),
                severity: if best.confidence >= 0.9 {
                    "critical".to_string()
                } else if best.confidence >= 0.75 {
                    "high".to_string()
                } else if best.confidence >= 0.5 {
                    "medium".to_string()
                } else {
                    "low".to_string()
                },
                confidence: (best.confidence * 100.0).round(),
                blocked: false,
                description: best
                    .description
                    .clone()
                    .unwrap_or_else(|| format!("{} reported by threat intelligence feed", ip)),
                raw_packet: String::new(),
                detection_method: format!("{:?}", best.source),
                ml_model: "external-feed".to_string(),
                anomaly_score: format!("{:.2}", best.confidence),
                port: String::new(),
                protocol: String::new(),
                packet_count: String::new(),
                bytes: String::new(),
                geoip_display: best
                    .country
                    .clone()
                    .unwrap_or_else(|| "Unknown".to_string()),
                threat_intel_display: format!("{:?}", best.source),
                recommended_action: "Review and block if confirmed malicious".to_string(),
            });
        }

        Ok(threats)
    }

    /// Attack map widget. Uses the same real threat-intel blocklist data
    /// as `get_ai_threats` (EmergingThreats-style compromised-IP feed) and
    /// plots each entry at its reported country's centroid via
    /// `crate::geo_centroid::country_centroid`. This is a deliberate
    /// approximation, not per-IP geolocation: this project's GeoIP setup
    /// (`patronus-firewall::geoip::GeoIpManager`) only resolves ISO
    /// country codes, not city-level lat/lon, and is gated behind the
    /// `geoip` Cargo feature + a GeoLite2/legacy database file on disk --
    /// true per-IP coordinates aren't available without that. A country
    /// centroid is good enough for "attacks are coming from roughly here"
    /// on a dashboard map.
    ///
    /// Entries with no `country` on the threat-intel record, or whose
    /// country code isn't in the (deliberately partial) centroid table,
    /// are skipped rather than plotted at a fabricated location.
    ///
    /// A real per-block-event log (timestamped firewall/IDS block
    /// decisions, e.g. via nftables `log` + a journald/syslog consumer, or
    /// a counter-object poll loop) would let this show actual block
    /// events instead of "currently known bad IPs" -- that's still a real
    /// gap, just a separate and larger piece of work than this.
    pub async fn get_attack_map_data(&self) -> anyhow::Result<Vec<crate::templates::AttackEvent>> {
        let blocklist = self.threat_intel_db.get_blocklist().await;
        let mut events = Vec::new();

        for ip in blocklist {
            let entries = self.threat_intel_db.get_threats(&ip).await;
            let Some(best) = entries
                .iter()
                .max_by(|a, b| a.confidence.total_cmp(&b.confidence))
            else {
                continue;
            };

            let Some(country) = best.country.as_deref() else {
                continue;
            };
            let Some((latitude, longitude)) = crate::geo_centroid::country_centroid(country) else {
                continue;
            };

            let attack_type = best
                .categories
                .first()
                .map(|c| format!("{:?}", c))
                .unwrap_or_else(|| "Unknown".to_string());

            let severity = if best.confidence >= 0.9 {
                "critical"
            } else if best.confidence >= 0.75 {
                "high"
            } else if best.confidence >= 0.5 {
                "medium"
            } else {
                "low"
            }
            .to_string();

            events.push(crate::templates::AttackEvent {
                latitude,
                longitude,
                source_country: country.to_string(),
                attack_type,
                timestamp: best.last_seen.to_rfc3339(),
                severity,
            });
        }

        Ok(events)
    }

    /// Live logs widget: backed by the real system journal via
    /// `patronus-monitoring::status::StatusPageManager::get_logs`, which
    /// shells out to `journalctl --output=json`. On Gentoo hosts running
    /// OpenRC without the `systemd` USE flag there is no journald, so this
    /// returns an empty list in that case (see doc comment on `get_logs`)
    /// rather than fabricating log lines.
    pub async fn get_live_logs(
        &self,
        limit: u32,
    ) -> anyhow::Result<Vec<crate::templates::LogEntry>> {
        let entries = patronus_monitoring::status::StatusPageManager::get_logs(None, None, limit)
            .await
            .map_err(|e| anyhow::anyhow!("{}", e))?;

        Ok(entries
            .into_iter()
            .map(|e| {
                let timestamp = e
                    .timestamp
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| {
                        chrono::DateTime::<chrono::Utc>::from_timestamp(
                            d.as_secs() as i64,
                            d.subsec_nanos(),
                        )
                        .map(|dt| dt.to_rfc3339())
                        .unwrap_or_default()
                    })
                    .unwrap_or_default();

                let level_color = match e.severity.as_str() {
                    "emergency" | "alert" | "critical" | "error" => "#ff4444",
                    "warning" => "#ffaa00",
                    "notice" | "info" => "#00aaff",
                    _ => "#888888",
                }
                .to_string();

                crate::templates::LogEntry {
                    timestamp,
                    level: e.severity,
                    component: e.source.unwrap_or(e.facility),
                    message: e.message,
                    level_color,
                }
            })
            .collect())
    }
}

fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;

    if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}
