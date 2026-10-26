// GraphQL views for the dashboard pages (Overview, Topology, SLA, Traffic,
// Security).
//
// Every value here is derived from live state: the SD-WAN database (sites,
// paths, recorded path metrics, flows), the audit log, and the SD-WAN
// engines' own logic (`sla::summarize`, `dpi::DpiEngine`, `qos::QosClass`).
// Nothing is canned: with no sites/paths/flows each list is simply empty.
//
// The builders are pure functions over plain data so they can be unit tested
// without a database; the resolvers in `queries.rs` only fetch and call them.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::SystemTime;

use async_graphql::SimpleObject;
use chrono::{DateTime, Utc};
use patronus_sdwan::{
    dpi::DpiEngine,
    qos::QosClass,
    sla::{summarize, SlaConfig},
    types::{FlowKey, FlowRecord, Path, PathMetrics, PathStatus, Site, SiteStatus},
};

use crate::security::audit::AuditLog;

/// Availability every SLA policy row is measured against (percent).
pub const TARGET_AVAILABILITY_PCT: f64 = 99.0;

#[derive(Debug, Clone, PartialEq, SimpleObject)]
pub struct Overview {
    pub total_sites: i32,
    pub active_sites: i32,
    pub total_links: i32,
    pub healthy_links: i32,
    /// Mean of each path's latest measured latency (ms), 0 without data.
    pub avg_latency: f64,
    /// Mbps, from the metrics collector.
    pub total_throughput: f64,
    /// Mean of each path's latest measured loss (%), 0 without data.
    pub packet_loss: f64,
}

#[derive(Debug, Clone, PartialEq, SimpleObject)]
pub struct Alert {
    pub id: String,
    /// `critical` | `warning` | `info`
    pub severity: String,
    pub message: String,
    pub timestamp: DateTime<Utc>,
    pub site_id: String,
}

#[derive(Debug, Clone, PartialEq, SimpleObject)]
pub struct LinkMetric {
    pub timestamp: DateTime<Utc>,
    pub throughput: f64,
    pub latency: f64,
    pub packet_loss: f64,
}

#[derive(Debug, Clone, PartialEq, SimpleObject)]
pub struct Link {
    pub id: String,
    pub source_id: String,
    pub target_id: String,
    /// `healthy` | `degraded` | `down`
    pub status: String,
    pub latency: f64,
    pub bandwidth: f64,
    /// 0..1: the path's live flow throughput over its bandwidth.
    pub utilization: f64,
}

#[derive(Debug, Clone, PartialEq, SimpleObject)]
pub struct SecurityEvent {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    /// `critical` | `high` | `medium` | `low`
    pub severity: String,
    #[graphql(name = "type")]
    pub kind: String,
    pub source: String,
    pub destination: String,
    pub description: String,
    pub blocked: bool,
}

#[derive(Debug, Clone, PartialEq, SimpleObject)]
pub struct ThreatTypeCount {
    #[graphql(name = "type")]
    pub kind: String,
    pub count: i32,
}

#[derive(Debug, Clone, PartialEq, SimpleObject)]
pub struct ThreatStats {
    pub total: i32,
    pub blocked: i32,
    pub allowed: i32,
    pub by_type: Vec<ThreatTypeCount>,
}

#[derive(Debug, Clone, PartialEq, SimpleObject)]
pub struct SlaPolicy {
    pub id: String,
    pub name: String,
    pub description: String,
    pub target_latency: f64,
    pub target_packet_loss: f64,
    pub target_availability: f64,
    pub current_latency: f64,
    pub current_packet_loss: f64,
    pub current_availability: f64,
    /// Percent of the last 24 h of samples inside every target.
    pub compliance: f64,
    /// Samples in the last 24 h that broke a target.
    pub violations: i32,
}

#[derive(Debug, Clone, PartialEq, SimpleObject)]
pub struct AppTraffic {
    pub name: String,
    pub bytes: i64,
    pub packets: i64,
    pub percentage: f64,
}

#[derive(Debug, Clone, PartialEq, SimpleObject)]
pub struct SiteTraffic {
    pub site_id: String,
    pub site_name: String,
    pub total_bytes: i64,
    pub total_packets: i64,
    pub applications: Vec<AppTraffic>,
}

/// A path with its latest recorded metrics (`None` = never measured).
pub type PathView = (Path, Option<PathMetrics>);

pub fn link_status(s: PathStatus) -> &'static str {
    match s {
        PathStatus::Up => "healthy",
        PathStatus::Degraded => "degraded",
        PathStatus::Down => "down",
    }
}

fn ts(t: SystemTime) -> DateTime<Utc> {
    t.duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|d| DateTime::from_timestamp(d.as_secs() as i64, 0))
        .unwrap_or_else(Utc::now)
}

fn mean(v: impl Iterator<Item = f64>) -> f64 {
    let (sum, n) = v
        .filter(|x| x.is_finite())
        .fold((0.0, 0usize), |(s, n), x| (s + x, n + 1));
    if n == 0 {
        0.0
    } else {
        sum / n as f64
    }
}

pub fn build_overview(sites: &[Site], paths: &[PathView], throughput_mbps: f64) -> Overview {
    Overview {
        total_sites: sites.len() as i32,
        active_sites: sites
            .iter()
            .filter(|s| s.status == SiteStatus::Active)
            .count() as i32,
        total_links: paths.len() as i32,
        healthy_links: paths
            .iter()
            .filter(|(p, _)| p.status == PathStatus::Up)
            .count() as i32,
        avg_latency: mean(paths.iter().filter_map(|(_, m)| m.map(|m| m.latency_ms))),
        total_throughput: if throughput_mbps.is_finite() {
            throughput_mbps
        } else {
            0.0
        },
        packet_loss: mean(
            paths
                .iter()
                .filter_map(|(_, m)| m.map(|m| m.packet_loss_pct)),
        ),
    }
}

/// Alerts for what is wrong right now: sites that are down/degraded and
/// paths that are down/degraded. Newest first, at most `limit`.
pub fn build_alerts(
    sites: &[Site],
    paths: &[PathView],
    names: &HashMap<String, String>,
    limit: usize,
) -> Vec<Alert> {
    let name = |id: &str| names.get(id).cloned().unwrap_or_else(|| id.to_string());
    let mut out = Vec::new();
    for s in sites {
        let (severity, what) = match s.status {
            SiteStatus::Active => continue,
            SiteStatus::Degraded => ("warning", "is degraded"),
            SiteStatus::Inactive => ("critical", "is offline"),
        };
        out.push(Alert {
            id: format!("site-{}-{}", s.id, what.replace(' ', "-")),
            severity: severity.into(),
            message: format!("Site {} {}", s.name, what),
            timestamp: ts(s.last_seen),
            site_id: s.id.to_string(),
        });
    }
    for (p, m) in paths {
        let (severity, what) = match p.status {
            PathStatus::Up => continue,
            PathStatus::Degraded => ("warning", "is degraded"),
            PathStatus::Down => ("critical", "is down"),
        };
        let detail = m
            .map(|m| {
                format!(
                    " (latency {:.1} ms, loss {:.1} %)",
                    m.latency_ms, m.packet_loss_pct
                )
            })
            .unwrap_or_default();
        out.push(Alert {
            id: format!("path-{}-{}", p.id, what.replace(' ', "-")),
            severity: severity.into(),
            message: format!(
                "Path {} -> {} {}{}",
                name(&p.src_site.to_string()),
                name(&p.dst_site.to_string()),
                what,
                detail
            ),
            timestamp: m.map(|m| ts(m.measured_at)).unwrap_or_else(Utc::now),
            site_id: p.src_site.to_string(),
        });
    }
    out.sort_by(|a, b| b.timestamp.cmp(&a.timestamp).then(a.id.cmp(&b.id)));
    out.truncate(limit);
    out
}

/// Bits per second of live flow traffic per path id.
pub fn path_throughput_bps(flows: &[FlowRecord]) -> HashMap<u64, f64> {
    let mut out: HashMap<u64, f64> = HashMap::new();
    for f in flows {
        let secs = f
            .last_seen_at
            .duration_since(f.started_at)
            .map(|d| d.as_secs())
            .unwrap_or(0)
            .max(1);
        let bits = (f.bytes_tx.saturating_add(f.bytes_rx)) as f64 * 8.0;
        *out.entry(f.path_id).or_default() += bits / secs as f64;
    }
    out
}

pub fn build_links(paths: &[PathView], bps: &HashMap<u64, f64>) -> Vec<Link> {
    paths
        .iter()
        .map(|(p, m)| {
            let bandwidth = m.map(|m| m.bandwidth_mbps).unwrap_or(0.0);
            let used_mbps = bps.get(&p.id.as_u64()).copied().unwrap_or(0.0) / 1_000_000.0;
            Link {
                id: p.id.to_string(),
                source_id: p.src_site.to_string(),
                target_id: p.dst_site.to_string(),
                status: link_status(p.status).into(),
                latency: m.map(|m| m.latency_ms).unwrap_or(0.0),
                bandwidth,
                utilization: if bandwidth > 0.0 {
                    (used_mbps / bandwidth).clamp(0.0, 1.0)
                } else {
                    0.0
                },
            }
        })
        .collect()
}

/// One SLA row per path that has recorded samples, scored over `history`
/// (the path's last 24 h of measurements) with the default targets.
pub fn build_sla_policies(
    paths: &[Path],
    history: &HashMap<u64, Vec<PathMetrics>>,
    names: &HashMap<String, String>,
) -> Vec<SlaPolicy> {
    let cfg = SlaConfig::default();
    let name = |id: &str| names.get(id).cloned().unwrap_or_else(|| id.to_string());
    let mut out = Vec::new();
    for p in paths {
        let Some(samples) = history.get(&p.id.as_u64()) else {
            continue;
        };
        let tuples: Vec<(f64, f64, f64)> = samples
            .iter()
            .map(|m| (m.latency_ms, m.packet_loss_pct, m.jitter_ms))
            .collect();
        let (Some(sum), Some(last)) = (summarize(&cfg, &tuples), samples.last()) else {
            continue;
        };
        out.push(SlaPolicy {
            id: p.id.to_string(),
            name: format!(
                "{} -> {}",
                name(&p.src_site.to_string()),
                name(&p.dst_site.to_string())
            ),
            description: format!(
                "Latency <= {} ms, loss <= {} %, jitter <= {} ms; {} samples in the last 24 h",
                cfg.target_latency_ms,
                cfg.target_packet_loss_pct,
                cfg.target_jitter_ms,
                sum.samples
            ),
            target_latency: cfg.target_latency_ms as f64,
            target_packet_loss: cfg.target_packet_loss_pct as f64,
            target_availability: TARGET_AVAILABILITY_PCT,
            current_latency: last.latency_ms,
            current_packet_loss: last.packet_loss_pct,
            current_availability: sum.availability_pct,
            compliance: sum.compliance_pct,
            violations: sum.violations as i32,
        });
    }
    out.sort_by(|a, b| a.name.cmp(&b.name).then(a.id.cmp(&b.id)));
    out
}

/// Application class of a flow. Flow records carry no payload, so this is
/// the DPI engine's port classification (payload classifiers see an empty
/// packet and decline); a fresh engine per call keeps its flow cache from
/// growing without bound.
pub fn classify_flows(flows: &[FlowRecord]) -> Vec<(&FlowRecord, &'static str)> {
    let dpi = DpiEngine::new();
    flows
        .iter()
        .map(|f| {
            let app = match (f.src_ip.parse::<IpAddr>(), f.dst_ip.parse::<IpAddr>()) {
                (Ok(src_ip), Ok(dst_ip)) => dpi
                    .classify_packet(
                        &[],
                        &FlowKey {
                            src_ip,
                            dst_ip,
                            src_port: f.src_port,
                            dst_port: f.dst_port,
                            protocol: f.protocol,
                        },
                    )
                    .as_str(),
                _ => "Unknown",
            };
            (f, app)
        })
        .collect()
}

/// QoS class name for an application name returned by [`classify_flows`].
pub fn qos_class_of(app: &str) -> &'static str {
    use patronus_sdwan::dpi::ApplicationType as A;
    let t = match app {
        "Web" => A::Web,
        "Video" => A::Video,
        "VoIP" => A::VoIP,
        "Gaming" => A::Gaming,
        "FileTransfer" => A::FileTransfer,
        "Database" => A::Database,
        _ => A::Unknown,
    };
    QosClass::from_app_type(t).as_str()
}

/// Traffic per originating site and application, from the live flows.
pub fn build_traffic(flows: &[FlowRecord], paths: &[Path], sites: &[Site]) -> Vec<SiteTraffic> {
    let path_src: HashMap<u64, String> = paths
        .iter()
        .map(|p| (p.id.as_u64(), p.src_site.to_string()))
        .collect();
    let names: HashMap<String, String> = sites
        .iter()
        .map(|s| (s.id.to_string(), s.name.clone()))
        .collect();
    // site -> app -> (bytes, packets)
    let mut acc: HashMap<String, HashMap<&'static str, (u64, u64)>> = HashMap::new();
    for (f, app) in classify_flows(flows) {
        let Some(site) = path_src.get(&f.path_id) else {
            continue;
        };
        let e = acc.entry(site.clone()).or_default().entry(app).or_default();
        e.0 = e.0.saturating_add(f.bytes_tx).saturating_add(f.bytes_rx);
        e.1 =
            e.1.saturating_add(f.packets_tx)
                .saturating_add(f.packets_rx);
    }
    let mut out: Vec<SiteTraffic> = acc
        .into_iter()
        .map(|(site, apps)| {
            let total_bytes: u64 = apps.values().map(|a| a.0).sum();
            let total_packets: u64 = apps.values().map(|a| a.1).sum();
            let mut applications: Vec<AppTraffic> = apps
                .into_iter()
                .map(|(name, (bytes, packets))| AppTraffic {
                    name: name.into(),
                    bytes: bytes.min(i64::MAX as u64) as i64,
                    packets: packets.min(i64::MAX as u64) as i64,
                    percentage: if total_bytes > 0 {
                        bytes as f64 / total_bytes as f64 * 100.0
                    } else {
                        0.0
                    },
                })
                .collect();
            applications.sort_by(|a, b| b.bytes.cmp(&a.bytes).then(a.name.cmp(&b.name)));
            SiteTraffic {
                site_name: names.get(&site).cloned().unwrap_or_else(|| site.clone()),
                site_id: site,
                total_bytes: total_bytes.min(i64::MAX as u64) as i64,
                total_packets: total_packets.min(i64::MAX as u64) as i64,
                applications,
            }
        })
        .collect();
    out.sort_by(|a, b| {
        b.total_bytes
            .cmp(&a.total_bytes)
            .then(a.site_id.cmp(&b.site_id))
    });
    out
}

/// Security events and totals from the dashboard's audit log: anything that
/// failed (a refused login, a rejected token ...) is a *blocked* event; a
/// successful event is only listed when it is not routine (severity above
/// info).
pub fn build_security(logs: &[AuditLog]) -> (Vec<SecurityEvent>, ThreatStats) {
    let relevant: Vec<&AuditLog> = logs
        .iter()
        .filter(|l| !l.success || l.severity != "info")
        .collect();
    let events: Vec<SecurityEvent> = relevant
        .iter()
        .map(|l| SecurityEvent {
            id: l.id.to_string(),
            timestamp: l.timestamp,
            severity: match l.severity.as_str() {
                "critical" => "critical",
                "warning" => "medium",
                _ => "low",
            }
            .into(),
            kind: l.event_type.clone(),
            source: l
                .ip_address
                .clone()
                .or_else(|| l.user_email.clone())
                .unwrap_or_else(|| "unknown".into()),
            destination: "dashboard".into(),
            description: l.event_data.clone(),
            blocked: !l.success,
        })
        .collect();
    let blocked = events.iter().filter(|e| e.blocked).count();
    let mut by: std::collections::BTreeMap<String, i32> = Default::default();
    for e in &events {
        *by.entry(e.kind.clone()).or_default() += 1;
    }
    let stats = ThreatStats {
        total: events.len() as i32,
        blocked: blocked as i32,
        allowed: (events.len() - blocked) as i32,
        by_type: by
            .into_iter()
            .map(|(kind, count)| ThreatTypeCount { kind, count })
            .collect(),
    };
    (events, stats)
}

#[cfg(test)]
mod tests {
    use super::*;
    use patronus_sdwan::types::{PathId, SiteId};
    use std::time::Duration;

    fn site(name: &str, status: SiteStatus) -> Site {
        Site {
            id: SiteId::generate(),
            name: name.into(),
            public_key: vec![],
            endpoints: vec![],
            created_at: SystemTime::now(),
            last_seen: SystemTime::now(),
            status,
        }
    }

    fn path(id: u64, a: &Site, b: &Site, status: PathStatus) -> Path {
        Path {
            id: PathId::new(id),
            src_site: a.id,
            dst_site: b.id,
            src_endpoint: "192.0.2.1:51820".parse().unwrap(),
            dst_endpoint: "192.0.2.2:51820".parse().unwrap(),
            wg_interface: None,
            metrics: PathMetrics::default(),
            status,
        }
    }

    fn metrics(latency: f64, loss: f64, jitter: f64, bw: f64) -> PathMetrics {
        PathMetrics {
            latency_ms: latency,
            jitter_ms: jitter,
            packet_loss_pct: loss,
            bandwidth_mbps: bw,
            mtu: 1420,
            measured_at: SystemTime::now(),
            score: 90,
        }
    }

    fn flow(path_id: u64, dst_port: u16, bytes: u64, packets: u64) -> FlowRecord {
        FlowRecord {
            flow_id: 1,
            src_ip: "10.0.0.2".into(),
            dst_ip: "10.1.0.2".into(),
            src_port: 40000,
            dst_port,
            protocol: 6,
            path_id,
            policy_id: None,
            started_at: SystemTime::now() - Duration::from_secs(10),
            last_seen_at: SystemTime::now(),
            bytes_tx: bytes,
            bytes_rx: 0,
            packets_tx: packets,
            packets_rx: 0,
            status: "active".into(),
        }
    }

    #[test]
    fn nothing_known_gives_empty_views_not_fixtures() {
        let o = build_overview(&[], &[], 0.0);
        assert_eq!((o.total_sites, o.total_links, o.avg_latency), (0, 0, 0.0));
        assert!(build_alerts(&[], &[], &HashMap::new(), 10).is_empty());
        assert!(build_links(&[], &HashMap::new()).is_empty());
        assert!(build_sla_policies(&[], &HashMap::new(), &HashMap::new()).is_empty());
        assert!(build_traffic(&[], &[], &[]).is_empty());
        let (e, s) = build_security(&[]);
        assert!(e.is_empty() && s.total == 0 && s.by_type.is_empty());
    }

    #[test]
    fn overview_and_alerts_follow_site_and_path_state() {
        let a = site("hq", SiteStatus::Active);
        let b = site("branch", SiteStatus::Inactive);
        let p1 = path(1, &a, &b, PathStatus::Up);
        let p2 = path(2, &b, &a, PathStatus::Down);
        let paths: Vec<PathView> = vec![
            (p1, Some(metrics(20.0, 0.0, 1.0, 100.0))),
            (p2, Some(metrics(40.0, 100.0, 1.0, 100.0))),
        ];
        let sites = vec![a.clone(), b.clone()];
        let o = build_overview(&sites, &paths, 12.5);
        assert_eq!(
            (
                o.total_sites,
                o.active_sites,
                o.total_links,
                o.healthy_links
            ),
            (2, 1, 2, 1)
        );
        assert!((o.avg_latency - 30.0).abs() < 1e-9);
        assert!((o.packet_loss - 50.0).abs() < 1e-9);
        assert_eq!(o.total_throughput, 12.5);

        let names: HashMap<String, String> = sites
            .iter()
            .map(|s| (s.id.to_string(), s.name.clone()))
            .collect();
        let alerts = build_alerts(&sites, &paths, &names, 10);
        assert_eq!(alerts.len(), 2); // branch offline + path 2 down; p1 and hq are fine
        assert!(alerts.iter().all(|a| a.severity == "critical"));
        assert!(alerts
            .iter()
            .any(|a| a.message.contains("Site branch is offline")));
        assert!(alerts
            .iter()
            .any(|a| a.message.contains("branch -> hq is down")));
        assert_eq!(build_alerts(&sites, &paths, &names, 1).len(), 1);
    }

    #[test]
    fn links_report_status_and_utilization_from_live_flows() {
        let a = site("a", SiteStatus::Active);
        let b = site("b", SiteStatus::Active);
        let paths: Vec<PathView> = vec![
            (
                path(7, &a, &b, PathStatus::Degraded),
                Some(metrics(5.0, 2.0, 1.0, 10.0)),
            ),
            (path(8, &b, &a, PathStatus::Up), None),
        ];
        // 625_000 bytes over ~10 s = 0.5 Mbps on a 10 Mbps path
        let bps = path_throughput_bps(&[flow(7, 443, 6_250_000, 10)]);
        let links = build_links(&paths, &bps);
        assert_eq!(links[0].status, "degraded");
        assert!(
            (links[0].utilization - 0.5).abs() < 0.1,
            "{}",
            links[0].utilization
        );
        assert_eq!(links[1].status, "healthy");
        assert_eq!((links[1].bandwidth, links[1].utilization), (0.0, 0.0));
    }

    #[test]
    fn sla_rows_are_scored_from_recorded_history_and_skip_unmeasured_paths() {
        let a = site("a", SiteStatus::Active);
        let b = site("b", SiteStatus::Active);
        let p = path(3, &a, &b, PathStatus::Up);
        let unmeasured = path(4, &b, &a, PathStatus::Up);
        let names: HashMap<String, String> = [&a, &b]
            .iter()
            .map(|s| (s.id.to_string(), s.name.clone()))
            .collect();
        let mut hist = HashMap::new();
        hist.insert(
            3,
            vec![
                metrics(20.0, 0.0, 1.0, 0.0),
                metrics(300.0, 0.0, 1.0, 0.0), // breaks latency
                metrics(30.0, 0.0, 1.0, 0.0),
                metrics(25.0, 0.0, 1.0, 0.0),
            ],
        );
        let rows = build_sla_policies(&[p, unmeasured], &hist, &names);
        assert_eq!(rows.len(), 1);
        let r = &rows[0];
        assert_eq!(r.name, "a -> b");
        assert_eq!(r.violations, 1);
        assert!((r.compliance - 75.0).abs() < 1e-9);
        assert_eq!(r.current_latency, 25.0);
        assert_eq!(r.target_latency, 100.0);
        assert!((r.current_availability - 100.0).abs() < 1e-9);
    }

    #[test]
    fn traffic_is_classified_per_site_by_application() {
        let a = site("hq", SiteStatus::Active);
        let b = site("branch", SiteStatus::Active);
        let p = path(5, &a, &b, PathStatus::Up);
        let flows = vec![
            flow(5, 443, 3000, 3),  // Web
            flow(5, 5060, 1000, 1), // VoIP (SIP)
            flow(5, 22, 6000, 6),   // FileTransfer
            flow(5, 61234, 100, 1), // Unknown
            flow(99, 443, 5000, 5), // path not known: not attributed
        ];
        let t = build_traffic(&flows, &[p], &[a.clone(), b]);
        assert_eq!(t.len(), 1);
        assert_eq!(t[0].site_name, "hq");
        assert_eq!(t[0].total_bytes, 10_100);
        assert_eq!(t[0].total_packets, 11);
        let apps: Vec<(&str, i64)> = t[0]
            .applications
            .iter()
            .map(|a| (a.name.as_str(), a.bytes))
            .collect();
        assert_eq!(
            apps,
            vec![
                ("FileTransfer", 6000),
                ("Web", 3000),
                ("VoIP", 1000),
                ("Unknown", 100)
            ]
        );
        let pct: f64 = t[0].applications.iter().map(|a| a.percentage).sum();
        assert!((pct - 100.0).abs() < 1e-9);
        assert_eq!(qos_class_of("VoIP"), "RealTime");
        assert_eq!(qos_class_of("FileTransfer"), "Bulk");
        assert_eq!(qos_class_of("nonsense"), "Standard");
    }

    fn log(id: i64, kind: &str, success: bool, severity: &str) -> AuditLog {
        AuditLog {
            id,
            timestamp: Utc::now(),
            user_id: None,
            user_email: Some("a@errant.solutions".into()),
            ip_address: if success {
                None
            } else {
                Some("203.0.113.9".into())
            },
            user_agent: None,
            event_type: kind.into(),
            event_data: "x".into(),
            success,
            severity: severity.into(),
        }
    }

    #[test]
    fn security_counts_failed_events_as_blocked_and_skips_routine_ones() {
        let logs = vec![
            log(1, "login_attempt", false, "warning"),
            log(2, "login_attempt", false, "warning"),
            log(3, "token_revoke", true, "warning"),
            log(4, "token_refresh", true, "info"), // routine: not listed
            log(5, "kill_switch", false, "critical"),
        ];
        let (events, stats) = build_security(&logs);
        assert_eq!(events.len(), 4);
        assert_eq!((stats.total, stats.blocked, stats.allowed), (4, 3, 1));
        let login = stats
            .by_type
            .iter()
            .find(|t| t.kind == "login_attempt")
            .unwrap();
        assert_eq!(login.count, 2);
        assert_eq!(events[0].source, "203.0.113.9");
        assert_eq!(events[0].severity, "medium");
        assert_eq!(events[3].severity, "critical");
        assert_eq!(events[2].source, "a@errant.solutions");
    }
}
