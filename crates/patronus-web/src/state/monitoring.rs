//! Monitoring state: live metrics, per-interface throughput, the
//! connection-tracking table, the threat-intel feed and the system journal.
//!
//! This file used to return fixtures: fixed network rates (1 234 567 /
//! 987 654 B/s), an "eth0" row when /proc/net/dev was unreadable, two
//! invented "top connections" and two alerts from January 2024. Alerts have
//! no producer yet (lane I), so the list is honestly empty.

use std::sync::Arc;

/// Monitoring operations
pub struct MonitoringManager {
    /// Real-time threat intelligence database, fed by live external feeds
    /// (EmergingThreats compromised-IP list, and AbuseIPDB if an API key is
    /// configured). This backs the threat-feed widget -- see
    /// `get_ai_threats`.
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

        Self { threat_intel_db }
    }

    /// CPU, memory, disk and total throughput, measured over `sample`.
    pub fn metrics_from(&self, sample: &super::host::Sample) -> crate::templates::SystemMetrics {
        crate::templates::SystemMetrics {
            cpu_percent: sample.cpu_percent.unwrap_or(0.0),
            memory_percent: super::host::memory().map(|m| m.0).unwrap_or(0.0),
            disk_percent: super::host::disk_percent("/").unwrap_or(0.0),
            network_rx_rate: sample.rx_rate(),
            network_tx_rate: sample.tx_rate(),
        }
    }

    pub async fn get_current_metrics(&self) -> anyhow::Result<crate::templates::SystemMetrics> {
        let s = super::host::sample(std::time::Duration::from_millis(250)).await;
        Ok(self.metrics_from(&s))
    }

    /// Per-interface rates (over the sample window) and counters.
    pub fn interface_stats_from(
        &self,
        sample: &super::host::Sample,
    ) -> Vec<crate::templates::InterfaceStats> {
        sample
            .interfaces
            .iter()
            .map(|(n, rx, tx, _)| crate::templates::InterfaceStats {
                name: n.name.clone(),
                rx_rate: format_rate(*rx),
                tx_rate: format_rate(*tx),
                rx_packets: n.rx_packets.to_string(),
                tx_packets: n.tx_packets.to_string(),
                errors: (n.rx_errors + n.tx_errors).to_string(),
            })
            .collect()
    }

    pub async fn get_interface_stats(
        &self,
    ) -> anyhow::Result<Vec<crate::templates::InterfaceStats>> {
        let s = super::host::sample(std::time::Duration::from_millis(250)).await;
        Ok(self.interface_stats_from(&s))
    }

    /// The largest flows in the kernel's connection-tracking table
    /// (/proc/net/nf_conntrack, else `conntrack -L`). Errors say why the
    /// table could not be read.
    pub async fn get_top_connections(
        &self,
        limit: usize,
    ) -> anyhow::Result<Vec<crate::templates::Connection>> {
        tokio::task::spawn_blocking(move || {
            let text = match std::fs::read_to_string("/proc/net/nf_conntrack") {
                Ok(t) => t,
                Err(proc_err) => {
                    match std::process::Command::new("conntrack")
                        .args(["-L", "-o", "extended"])
                        .output()
                    {
                        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).into_owned(),
                        Ok(o) => anyhow::bail!(
                            "connection tracking table unreadable: /proc/net/nf_conntrack: {proc_err}; conntrack: {}",
                            String::from_utf8_lossy(&o.stderr).trim()
                        ),
                        Err(e) => anyhow::bail!(
                            "connection tracking table unreadable: /proc/net/nf_conntrack: {proc_err}; conntrack: {e}"
                        ),
                    }
                }
            };
            let mut flows = parse_conntrack(&text);
            flows.sort_by_key(|f| std::cmp::Reverse(f.0));
            Ok(flows.into_iter().take(limit).map(|(_, c)| c).collect())
        })
        .await?
    }

    /// No alert producer exists yet (lane I): an honest empty list.
    pub async fn get_recent_alerts(
        &self,
        _limit: usize,
    ) -> anyhow::Result<Vec<crate::templates::Alert>> {
        Ok(Vec::new())
    }

    /// Threat-feed widget: recent entries from the live threat
    /// intelligence database (`patronus-ai`'s `ThreatIntelDB`), populated
    /// by the `ThreatFeedAggregator` started in `new()`. This is external
    /// feed data, not a local ML classifier: nothing feeds live flows into
    /// `ThreatDetectionEngine` yet, so detection_method/ml_model say
    /// "external feed" and `blocked` is false (no automatic blocking).
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
                severity: severity(best.confidence),
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

    /// Live logs widget: backed by the real system journal via
    /// `patronus-monitoring::status::StatusPageManager::get_logs`, which
    /// shells out to `journalctl --output=json`. On Gentoo hosts running
    /// OpenRC without the `systemd` USE flag there is no journald, so this
    /// returns an empty list in that case rather than fabricating lines.
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

fn severity(confidence: f64) -> String {
    if confidence >= 0.9 {
        "critical"
    } else if confidence >= 0.75 {
        "high"
    } else if confidence >= 0.5 {
        "medium"
    } else {
        "low"
    }
    .to_string()
}

/// "12.3 KiB/s"
pub fn format_rate(bytes_per_sec: u64) -> String {
    format!("{}/s", super::vpn::format_bytes(bytes_per_sec))
}

/// Parse conntrack entries (/proc/net/nf_conntrack lines start with
/// `ipv4 2 tcp 6 ...`, `conntrack -L -o extended` lines too). Returns
/// (total bytes, row) per flow; bytes/packets are only known when
/// nf_conntrack_acct is on, the age only with nf_conntrack_timestamp.
pub fn parse_conntrack(text: &str) -> Vec<(u64, crate::templates::Connection)> {
    const PROTOS: &[&str] = &[
        "tcp", "udp", "icmp", "icmpv6", "sctp", "dccp", "gre", "udplite", "unknown",
    ];
    let mut out = Vec::new();
    for line in text.lines() {
        let words: Vec<&str> = line.split_whitespace().collect();
        let Some(proto) = words.iter().find(|w| PROTOS.contains(w)) else {
            continue;
        };
        let first = |k: &str| {
            words
                .iter()
                .find_map(|w| w.strip_prefix(k).and_then(|v| v.strip_prefix('=')))
        };
        let sum = |k: &str| -> Option<u64> {
            let v: Vec<u64> = words
                .iter()
                .filter_map(|w| w.strip_prefix(k).and_then(|v| v.strip_prefix('=')))
                .filter_map(|v| v.parse().ok())
                .collect();
            (!v.is_empty()).then(|| v.iter().sum())
        };
        let (Some(src), Some(dst)) = (first("src"), first("dst")) else {
            continue;
        };
        let ep = |a: &str, p: Option<&str>| match p {
            Some(p) if a.contains(':') => format!("[{a}]:{p}"),
            Some(p) => format!("{a}:{p}"),
            None => a.to_string(),
        };
        let bytes = sum("bytes");
        out.push((
            bytes.unwrap_or(0),
            crate::templates::Connection {
                protocol: proto.to_uppercase(),
                source: ep(src, first("sport")),
                destination: ep(dst, first("dport")),
                bytes: bytes
                    .map(super::vpn::format_bytes)
                    .unwrap_or_else(|| "— (accounting off)".into()),
                packets: sum("packets")
                    .map(|p| p.to_string())
                    .unwrap_or_else(|| "—".into()),
                duration: first("delta-time")
                    .and_then(|v| v.parse().ok())
                    .map(super::host::format_duration)
                    .unwrap_or_else(|| "—".into()),
            },
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conntrack_flows_come_from_the_kernel_table() {
        let proc = "\
ipv4     2 tcp      6 431999 ESTABLISHED src=192.168.50.10 dst=198.51.100.10 sport=40000 dport=80 packets=10 bytes=800 src=198.51.100.10 dst=203.0.113.2 sport=80 dport=40000 packets=8 bytes=9000 [ASSURED] mark=0 delta-time=125 use=1
ipv6     10 udp      17 29 src=fd00::10 dst=2001:db8::53 sport=5353 dport=53 src=2001:db8::53 dst=fd00::10 sport=53 dport=5353 mark=0 use=1
ipv4     2 icmp     1 29 src=192.168.50.10 dst=198.51.100.10 type=8 code=0 id=7 packets=1 bytes=84 src=198.51.100.10 dst=192.168.50.10 type=0 code=0 id=7 packets=1 bytes=84 mark=0 use=1
";
        let mut f = parse_conntrack(proc);
        assert_eq!(f.len(), 3);
        f.sort_by_key(|x| std::cmp::Reverse(x.0));
        let (bytes, c) = &f[0];
        assert_eq!(*bytes, 9800, "both directions");
        assert_eq!(c.protocol, "TCP");
        assert_eq!(c.source, "192.168.50.10:40000");
        assert_eq!(c.destination, "198.51.100.10:80");
        assert_eq!(c.packets, "18");
        assert_eq!(c.duration, "2 min");
        let udp = &f.iter().find(|x| x.1.protocol == "UDP").unwrap().1;
        assert_eq!(udp.source, "[fd00::10]:5353");
        assert_eq!(udp.bytes, "— (accounting off)");
        assert_eq!(udp.duration, "—");
        let icmp = &f.iter().find(|x| x.1.protocol == "ICMP").unwrap().1;
        assert_eq!(icmp.destination, "198.51.100.10");
        assert!(parse_conntrack("").is_empty());
    }

    #[tokio::test]
    async fn no_invented_alerts_or_interfaces() {
        let m = MonitoringManager::new();
        assert!(m.get_recent_alerts(20).await.unwrap().is_empty());
        let empty = super::super::host::Sample::default();
        assert!(m.interface_stats_from(&empty).is_empty());
        let metrics = m.metrics_from(&empty);
        assert_eq!(metrics.network_rx_rate, 0);
        assert_eq!(metrics.network_tx_rate, 0);
    }
}
