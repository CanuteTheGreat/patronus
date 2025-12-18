//! Comprehensive System Metrics Collection
//!
//! Collects metrics from all Patronus subsystems for monitoring,
//! alerting, and capacity planning.

use prometheus::{
    Registry, Counter, Gauge, HistogramOpts,
    Opts, CounterVec, GaugeVec, HistogramVec,
};
use std::sync::Arc;
use tokio::time::{interval, Duration};
use sysinfo::{System, Disks, Networks, Components};

/// Central metrics collector for all Patronus subsystems
pub struct MetricsCollector {
    registry: Registry,

    // System metrics
    cpu_usage: Gauge,
    memory_usage: Gauge,
    memory_total: Gauge,
    disk_usage: GaugeVec,
    disk_total: GaugeVec,
    system_load: GaugeVec,
    system_uptime: Gauge,
    cpu_temperature: GaugeVec,

    // Network interface metrics
    interface_rx_bytes: GaugeVec,
    interface_tx_bytes: GaugeVec,
    interface_rx_packets: GaugeVec,
    interface_tx_packets: GaugeVec,
    interface_rx_errors: GaugeVec,
    interface_tx_errors: GaugeVec,
    interface_rx_dropped: GaugeVec,
    interface_tx_dropped: GaugeVec,
    interface_speed: GaugeVec,

    // Firewall metrics
    firewall_packets_total: CounterVec,
    firewall_bytes_total: CounterVec,
    firewall_connections_active: Gauge,
    firewall_connections_total: Counter,
    firewall_rules_count: Gauge,
    firewall_rule_hits: CounterVec,
    firewall_nat_translations: Gauge,

    // VPN metrics
    vpn_sessions_active: GaugeVec,
    vpn_sessions_total: CounterVec,
    vpn_bytes_rx: CounterVec,
    vpn_bytes_tx: CounterVec,
    vpn_tunnel_status: GaugeVec,

    // DHCP metrics
    dhcp_leases_active: Gauge,
    dhcp_leases_total: Counter,
    dhcp_requests: CounterVec,

    // DNS metrics
    dns_queries_total: CounterVec,
    dns_query_duration: HistogramVec,
    dns_cache_hits: Counter,
    dns_cache_misses: Counter,
    dns_blocked_queries: CounterVec,

    // HA metrics
    ha_state: GaugeVec,
    ha_failovers_total: Counter,
    ha_sync_errors: Counter,
    ha_last_sync: Gauge,

    // IDS/IPS metrics
    ids_alerts_total: CounterVec,
    ids_packets_processed: Counter,
    ids_packets_dropped: Counter,
    ids_signatures_loaded: Gauge,

    // QoS metrics
    qos_bandwidth_used: GaugeVec,
    qos_bandwidth_limit: GaugeVec,
    qos_packets_shaped: CounterVec,
    qos_packets_dropped: CounterVec,

    // Certificate metrics
    cert_expiry_days: GaugeVec,
    cert_renewals_total: CounterVec,
    cert_errors_total: CounterVec,

    // Web UI metrics
    http_requests_total: CounterVec,
    http_request_duration: HistogramVec,
    http_requests_in_flight: Gauge,

    // Service health
    service_up: GaugeVec,
    service_restarts: CounterVec,
}

impl MetricsCollector {
    pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let registry = Registry::new();

        // System metrics
        let cpu_usage = Gauge::with_opts(Opts::new(
            "patronus_cpu_usage_percent",
            "Current CPU usage percentage"
        ))?;
        registry.register(Box::new(cpu_usage.clone()))?;

        let memory_usage = Gauge::with_opts(Opts::new(
            "patronus_memory_used_bytes",
            "Current memory usage in bytes"
        ))?;
        registry.register(Box::new(memory_usage.clone()))?;

        let memory_total = Gauge::with_opts(Opts::new(
            "patronus_memory_total_bytes",
            "Total system memory in bytes"
        ))?;
        registry.register(Box::new(memory_total.clone()))?;

        let disk_usage = GaugeVec::new(
            Opts::new("patronus_disk_used_bytes", "Disk space used in bytes"),
            &["device", "mount_point"]
        )?;
        registry.register(Box::new(disk_usage.clone()))?;

        let disk_total = GaugeVec::new(
            Opts::new("patronus_disk_total_bytes", "Total disk space in bytes"),
            &["device", "mount_point"]
        )?;
        registry.register(Box::new(disk_total.clone()))?;

        let system_load = GaugeVec::new(
            Opts::new("patronus_system_load", "System load average"),
            &["period"]
        )?;
        registry.register(Box::new(system_load.clone()))?;

        let system_uptime = Gauge::with_opts(Opts::new(
            "patronus_uptime_seconds",
            "System uptime in seconds"
        ))?;
        registry.register(Box::new(system_uptime.clone()))?;

        let cpu_temperature = GaugeVec::new(
            Opts::new("patronus_cpu_temperature_celsius", "CPU temperature"),
            &["core"]
        )?;
        registry.register(Box::new(cpu_temperature.clone()))?;

        // Network interface metrics
        let interface_rx_bytes = GaugeVec::new(
            Opts::new("patronus_interface_rx_bytes_total", "Total bytes received"),
            &["interface"]
        )?;
        registry.register(Box::new(interface_rx_bytes.clone()))?;

        let interface_tx_bytes = GaugeVec::new(
            Opts::new("patronus_interface_tx_bytes_total", "Total bytes transmitted"),
            &["interface"]
        )?;
        registry.register(Box::new(interface_tx_bytes.clone()))?;

        let interface_rx_packets = GaugeVec::new(
            Opts::new("patronus_interface_rx_packets_total", "Total packets received"),
            &["interface"]
        )?;
        registry.register(Box::new(interface_rx_packets.clone()))?;

        let interface_tx_packets = GaugeVec::new(
            Opts::new("patronus_interface_tx_packets_total", "Total packets transmitted"),
            &["interface"]
        )?;
        registry.register(Box::new(interface_tx_packets.clone()))?;

        let interface_rx_errors = GaugeVec::new(
            Opts::new("patronus_interface_rx_errors_total", "Total receive errors"),
            &["interface"]
        )?;
        registry.register(Box::new(interface_rx_errors.clone()))?;

        let interface_tx_errors = GaugeVec::new(
            Opts::new("patronus_interface_tx_errors_total", "Total transmit errors"),
            &["interface"]
        )?;
        registry.register(Box::new(interface_tx_errors.clone()))?;

        let interface_rx_dropped = GaugeVec::new(
            Opts::new("patronus_interface_rx_dropped_total", "Total receive dropped"),
            &["interface"]
        )?;
        registry.register(Box::new(interface_rx_dropped.clone()))?;

        let interface_tx_dropped = GaugeVec::new(
            Opts::new("patronus_interface_tx_dropped_total", "Total transmit dropped"),
            &["interface"]
        )?;
        registry.register(Box::new(interface_tx_dropped.clone()))?;

        let interface_speed = GaugeVec::new(
            Opts::new("patronus_interface_speed_bps", "Interface speed in bits per second"),
            &["interface"]
        )?;
        registry.register(Box::new(interface_speed.clone()))?;

        // Firewall metrics
        let firewall_packets_total = CounterVec::new(
            Opts::new("patronus_firewall_packets_total", "Total packets processed"),
            &["chain", "action"]
        )?;
        registry.register(Box::new(firewall_packets_total.clone()))?;

        let firewall_bytes_total = CounterVec::new(
            Opts::new("patronus_firewall_bytes_total", "Total bytes processed"),
            &["chain", "action"]
        )?;
        registry.register(Box::new(firewall_bytes_total.clone()))?;

        let firewall_connections_active = Gauge::with_opts(Opts::new(
            "patronus_firewall_connections_active",
            "Active connection tracking entries"
        ))?;
        registry.register(Box::new(firewall_connections_active.clone()))?;

        let firewall_connections_total = Counter::with_opts(Opts::new(
            "patronus_firewall_connections_total",
            "Total connections tracked"
        ))?;
        registry.register(Box::new(firewall_connections_total.clone()))?;

        let firewall_rules_count = Gauge::with_opts(Opts::new(
            "patronus_firewall_rules_count",
            "Number of active firewall rules"
        ))?;
        registry.register(Box::new(firewall_rules_count.clone()))?;

        let firewall_rule_hits = CounterVec::new(
            Opts::new("patronus_firewall_rule_hits_total", "Firewall rule hit counter"),
            &["rule_id", "action"]
        )?;
        registry.register(Box::new(firewall_rule_hits.clone()))?;

        let firewall_nat_translations = Gauge::with_opts(Opts::new(
            "patronus_firewall_nat_translations_active",
            "Active NAT translations"
        ))?;
        registry.register(Box::new(firewall_nat_translations.clone()))?;

        // VPN metrics
        let vpn_sessions_active = GaugeVec::new(
            Opts::new("patronus_vpn_sessions_active", "Active VPN sessions"),
            &["type", "server"]
        )?;
        registry.register(Box::new(vpn_sessions_active.clone()))?;

        let vpn_sessions_total = CounterVec::new(
            Opts::new("patronus_vpn_sessions_total", "Total VPN sessions created"),
            &["type", "server"]
        )?;
        registry.register(Box::new(vpn_sessions_total.clone()))?;

        let vpn_bytes_rx = CounterVec::new(
            Opts::new("patronus_vpn_bytes_rx_total", "Total VPN bytes received"),
            &["type", "server", "user"]
        )?;
        registry.register(Box::new(vpn_bytes_rx.clone()))?;

        let vpn_bytes_tx = CounterVec::new(
            Opts::new("patronus_vpn_bytes_tx_total", "Total VPN bytes transmitted"),
            &["type", "server", "user"]
        )?;
        registry.register(Box::new(vpn_bytes_tx.clone()))?;

        let vpn_tunnel_status = GaugeVec::new(
            Opts::new("patronus_vpn_tunnel_up", "VPN tunnel status (1=up, 0=down)"),
            &["type", "name", "remote"]
        )?;
        registry.register(Box::new(vpn_tunnel_status.clone()))?;

        // DHCP metrics
        let dhcp_leases_active = Gauge::with_opts(Opts::new(
            "patronus_dhcp_leases_active",
            "Active DHCP leases"
        ))?;
        registry.register(Box::new(dhcp_leases_active.clone()))?;

        let dhcp_leases_total = Counter::with_opts(Opts::new(
            "patronus_dhcp_leases_total",
            "Total DHCP leases issued"
        ))?;
        registry.register(Box::new(dhcp_leases_total.clone()))?;

        let dhcp_requests = CounterVec::new(
            Opts::new("patronus_dhcp_requests_total", "DHCP requests by type"),
            &["type"]  // DISCOVER, REQUEST, RELEASE, etc.
        )?;
        registry.register(Box::new(dhcp_requests.clone()))?;

        // DNS metrics
        let dns_queries_total = CounterVec::new(
            Opts::new("patronus_dns_queries_total", "Total DNS queries"),
            &["type", "result"]  // A, AAAA, CNAME | NOERROR, NXDOMAIN, SERVFAIL
        )?;
        registry.register(Box::new(dns_queries_total.clone()))?;

        let dns_query_duration = HistogramVec::new(
            HistogramOpts::new("patronus_dns_query_duration_seconds", "DNS query duration"),
            &["type"]
        )?;
        registry.register(Box::new(dns_query_duration.clone()))?;

        let dns_cache_hits = Counter::with_opts(Opts::new(
            "patronus_dns_cache_hits_total",
            "DNS cache hits"
        ))?;
        registry.register(Box::new(dns_cache_hits.clone()))?;

        let dns_cache_misses = Counter::with_opts(Opts::new(
            "patronus_dns_cache_misses_total",
            "DNS cache misses"
        ))?;
        registry.register(Box::new(dns_cache_misses.clone()))?;

        let dns_blocked_queries = CounterVec::new(
            Opts::new("patronus_dns_blocked_queries_total", "Blocked DNS queries"),
            &["list", "domain"]
        )?;
        registry.register(Box::new(dns_blocked_queries.clone()))?;

        // HA metrics
        let ha_state = GaugeVec::new(
            Opts::new("patronus_ha_state", "HA state (1=master, 0=backup)"),
            &["node"]
        )?;
        registry.register(Box::new(ha_state.clone()))?;

        let ha_failovers_total = Counter::with_opts(Opts::new(
            "patronus_ha_failovers_total",
            "Total HA failovers"
        ))?;
        registry.register(Box::new(ha_failovers_total.clone()))?;

        let ha_sync_errors = Counter::with_opts(Opts::new(
            "patronus_ha_sync_errors_total",
            "Configuration sync errors"
        ))?;
        registry.register(Box::new(ha_sync_errors.clone()))?;

        let ha_last_sync = Gauge::with_opts(Opts::new(
            "patronus_ha_last_sync_timestamp",
            "Timestamp of last successful sync"
        ))?;
        registry.register(Box::new(ha_last_sync.clone()))?;

        // IDS/IPS metrics
        let ids_alerts_total = CounterVec::new(
            Opts::new("patronus_ids_alerts_total", "IDS/IPS alerts"),
            &["severity", "category", "signature"]
        )?;
        registry.register(Box::new(ids_alerts_total.clone()))?;

        let ids_packets_processed = Counter::with_opts(Opts::new(
            "patronus_ids_packets_processed_total",
            "Packets processed by IDS/IPS"
        ))?;
        registry.register(Box::new(ids_packets_processed.clone()))?;

        let ids_packets_dropped = Counter::with_opts(Opts::new(
            "patronus_ids_packets_dropped_total",
            "Packets dropped by IPS"
        ))?;
        registry.register(Box::new(ids_packets_dropped.clone()))?;

        let ids_signatures_loaded = Gauge::with_opts(Opts::new(
            "patronus_ids_signatures_loaded",
            "Number of loaded IDS signatures"
        ))?;
        registry.register(Box::new(ids_signatures_loaded.clone()))?;

        // QoS metrics
        let qos_bandwidth_used = GaugeVec::new(
            Opts::new("patronus_qos_bandwidth_used_bps", "Current bandwidth usage"),
            &["interface", "class"]
        )?;
        registry.register(Box::new(qos_bandwidth_used.clone()))?;

        let qos_bandwidth_limit = GaugeVec::new(
            Opts::new("patronus_qos_bandwidth_limit_bps", "Bandwidth limit"),
            &["interface", "class"]
        )?;
        registry.register(Box::new(qos_bandwidth_limit.clone()))?;

        let qos_packets_shaped = CounterVec::new(
            Opts::new("patronus_qos_packets_shaped_total", "Packets shaped by QoS"),
            &["interface", "class"]
        )?;
        registry.register(Box::new(qos_packets_shaped.clone()))?;

        let qos_packets_dropped = CounterVec::new(
            Opts::new("patronus_qos_packets_dropped_total", "Packets dropped by QoS"),
            &["interface", "class", "reason"]
        )?;
        registry.register(Box::new(qos_packets_dropped.clone()))?;

        // Certificate metrics
        let cert_expiry_days = GaugeVec::new(
            Opts::new("patronus_cert_expiry_days", "Days until certificate expiry"),
            &["domain", "issuer"]
        )?;
        registry.register(Box::new(cert_expiry_days.clone()))?;

        let cert_renewals_total = CounterVec::new(
            Opts::new("patronus_cert_renewals_total", "Certificate renewals"),
            &["domain", "status"]
        )?;
        registry.register(Box::new(cert_renewals_total.clone()))?;

        let cert_errors_total = CounterVec::new(
            Opts::new("patronus_cert_errors_total", "Certificate errors"),
            &["domain", "error_type"]
        )?;
        registry.register(Box::new(cert_errors_total.clone()))?;

        // Web UI metrics
        let http_requests_total = CounterVec::new(
            Opts::new("patronus_http_requests_total", "HTTP requests"),
            &["method", "path", "status"]
        )?;
        registry.register(Box::new(http_requests_total.clone()))?;

        let http_request_duration = HistogramVec::new(
            HistogramOpts::new("patronus_http_request_duration_seconds", "HTTP request duration"),
            &["method", "path"]
        )?;
        registry.register(Box::new(http_request_duration.clone()))?;

        let http_requests_in_flight = Gauge::with_opts(Opts::new(
            "patronus_http_requests_in_flight",
            "HTTP requests currently being processed"
        ))?;
        registry.register(Box::new(http_requests_in_flight.clone()))?;

        // Service health
        let service_up = GaugeVec::new(
            Opts::new("patronus_service_up", "Service health (1=up, 0=down)"),
            &["service"]
        )?;
        registry.register(Box::new(service_up.clone()))?;

        let service_restarts = CounterVec::new(
            Opts::new("patronus_service_restarts_total", "Service restart count"),
            &["service"]
        )?;
        registry.register(Box::new(service_restarts.clone()))?;

        Ok(Self {
            registry,
            cpu_usage,
            memory_usage,
            memory_total,
            disk_usage,
            disk_total,
            system_load,
            system_uptime,
            cpu_temperature,
            interface_rx_bytes,
            interface_tx_bytes,
            interface_rx_packets,
            interface_tx_packets,
            interface_rx_errors,
            interface_tx_errors,
            interface_rx_dropped,
            interface_tx_dropped,
            interface_speed,
            firewall_packets_total,
            firewall_bytes_total,
            firewall_connections_active,
            firewall_connections_total,
            firewall_rules_count,
            firewall_rule_hits,
            firewall_nat_translations,
            vpn_sessions_active,
            vpn_sessions_total,
            vpn_bytes_rx,
            vpn_bytes_tx,
            vpn_tunnel_status,
            dhcp_leases_active,
            dhcp_leases_total,
            dhcp_requests,
            dns_queries_total,
            dns_query_duration,
            dns_cache_hits,
            dns_cache_misses,
            dns_blocked_queries,
            ha_state,
            ha_failovers_total,
            ha_sync_errors,
            ha_last_sync,
            ids_alerts_total,
            ids_packets_processed,
            ids_packets_dropped,
            ids_signatures_loaded,
            qos_bandwidth_used,
            qos_bandwidth_limit,
            qos_packets_shaped,
            qos_packets_dropped,
            cert_expiry_days,
            cert_renewals_total,
            cert_errors_total,
            http_requests_total,
            http_request_duration,
            http_requests_in_flight,
            service_up,
            service_restarts,
        })
    }

    /// Get the Prometheus registry for export
    pub fn registry(&self) -> &Registry {
        &self.registry
    }

    /// Start automatic metrics collection
    pub async fn start_collection(self: Arc<Self>) {
        let mut sys_interval = interval(Duration::from_secs(5));
        let mut net_interval = interval(Duration::from_secs(1));

        let collector = self.clone();
        tokio::spawn(async move {
            loop {
                sys_interval.tick().await;
                collector.collect_system_metrics().await;
            }
        });

        let collector = self.clone();
        tokio::spawn(async move {
            loop {
                net_interval.tick().await;
                collector.collect_network_metrics().await;
            }
        });
    }

    /// Collect system metrics
    async fn collect_system_metrics(&self) {
        let mut sys = System::new_all();
        sys.refresh_all();

        // CPU usage
        let cpus = sys.cpus();
        if !cpus.is_empty() {
            let cpu_usage: f64 = cpus.iter()
                .map(|p| p.cpu_usage() as f64)
                .sum::<f64>() / cpus.len() as f64;
            self.cpu_usage.set(cpu_usage);
        }

        // Memory
        self.memory_usage.set(sys.used_memory() as f64);
        self.memory_total.set(sys.total_memory() as f64);

        // Disk usage - using separate Disks struct
        let disks = Disks::new_with_refreshed_list();
        for disk in disks.list() {
            let mount_point = disk.mount_point().to_string_lossy().to_string();
            let device = disk.name().to_string_lossy().to_string();

            self.disk_usage
                .with_label_values(&[&device, &mount_point])
                .set((disk.total_space() - disk.available_space()) as f64);
            self.disk_total
                .with_label_values(&[&device, &mount_point])
                .set(disk.total_space() as f64);
        }

        // Load average
        let load_avg = System::load_average();
        self.system_load.with_label_values(&["1m"]).set(load_avg.one);
        self.system_load.with_label_values(&["5m"]).set(load_avg.five);
        self.system_load.with_label_values(&["15m"]).set(load_avg.fifteen);

        // Uptime
        self.system_uptime.set(System::uptime() as f64);

        // CPU temperature - using separate Components struct
        let components = Components::new_with_refreshed_list();
        for component in components.list() {
            let label = component.label();
            if label.to_lowercase().contains("cpu") || label.to_lowercase().contains("core") {
                let temp = component.temperature();
                self.cpu_temperature
                    .with_label_values(&[label])
                    .set(temp as f64);
            }
        }
    }

    /// Collect network interface metrics
    async fn collect_network_metrics(&self) {
        // Use separate Networks struct from sysinfo 0.31+
        let mut networks = Networks::new_with_refreshed_list();
        networks.refresh();

        for (interface_name, network) in networks.list() {
            let name = interface_name.as_str();

            // Received stats
            self.interface_rx_bytes
                .with_label_values(&[name])
                .set(network.total_received() as f64);
            self.interface_tx_bytes
                .with_label_values(&[name])
                .set(network.total_transmitted() as f64);
            self.interface_rx_packets
                .with_label_values(&[name])
                .set(network.total_packets_received() as f64);
            self.interface_tx_packets
                .with_label_values(&[name])
                .set(network.total_packets_transmitted() as f64);
            self.interface_rx_errors
                .with_label_values(&[name])
                .set(network.total_errors_on_received() as f64);
            self.interface_tx_errors
                .with_label_values(&[name])
                .set(network.total_errors_on_transmitted() as f64);
        }
    }

    // Public API for subsystems to report metrics

    pub fn record_firewall_packet(&self, chain: &str, action: &str, bytes: u64) {
        self.firewall_packets_total
            .with_label_values(&[chain, action])
            .inc();
        self.firewall_bytes_total
            .with_label_values(&[chain, action])
            .inc_by(bytes as f64);
    }

    pub fn set_firewall_connections(&self, count: i64) {
        self.firewall_connections_active.set(count as f64);
    }

    pub fn record_vpn_session(&self, vpn_type: &str, server: &str) {
        self.vpn_sessions_total
            .with_label_values(&[vpn_type, server])
            .inc();
    }

    pub fn set_vpn_active_sessions(&self, vpn_type: &str, server: &str, count: i64) {
        self.vpn_sessions_active
            .with_label_values(&[vpn_type, server])
            .set(count as f64);
    }

    pub fn record_dns_query(&self, query_type: &str, result: &str, duration_secs: f64) {
        self.dns_queries_total
            .with_label_values(&[query_type, result])
            .inc();
        self.dns_query_duration
            .with_label_values(&[query_type])
            .observe(duration_secs);
    }

    pub fn record_ids_alert(&self, severity: &str, category: &str, signature: &str) {
        self.ids_alerts_total
            .with_label_values(&[severity, category, signature])
            .inc();
    }

    pub fn set_certificate_expiry(&self, domain: &str, issuer: &str, days: i64) {
        self.cert_expiry_days
            .with_label_values(&[domain, issuer])
            .set(days as f64);
    }

    pub fn record_http_request(&self, method: &str, path: &str, status: u16, duration_secs: f64) {
        self.http_requests_total
            .with_label_values(&[method, path, &status.to_string()])
            .inc();
        self.http_request_duration
            .with_label_values(&[method, path])
            .observe(duration_secs);
    }

    pub fn set_service_health(&self, service: &str, healthy: bool) {
        self.service_up
            .with_label_values(&[service])
            .set(if healthy { 1.0 } else { 0.0 });
    }
}
