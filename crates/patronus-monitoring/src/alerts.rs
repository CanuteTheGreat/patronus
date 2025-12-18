//! Alert Manager
//!
//! Proactive monitoring with configurable alert rules and notifications.
//! Integrates with Prometheus Alertmanager and supports multiple notification channels.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tokio::time::{interval, Duration};

/// Alert severity levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AlertSeverity {
    Critical,
    Warning,
    Info,
}

/// Alert rule definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertRule {
    pub name: String,
    pub severity: AlertSeverity,
    pub description: String,
    pub condition: AlertCondition,
    pub duration: Duration,  // How long condition must be true
    pub enabled: bool,
}

/// Alert conditions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AlertCondition {
    /// CPU usage above threshold
    CpuUsageAbove { percent: f64 },
    /// Memory usage above threshold
    MemoryUsageAbove { percent: f64 },
    /// Disk usage above threshold
    DiskUsageAbove { mount: String, percent: f64 },
    /// Interface down
    InterfaceDown { interface: String },
    /// High packet loss
    PacketLossAbove { interface: String, percent: f64 },
    /// VPN tunnel down
    VpnTunnelDown { name: String },
    /// Certificate expiring soon
    CertificateExpiring { domain: String, days: u32 },
    /// HA failover occurred
    HaFailover,
    /// Service unhealthy
    ServiceDown { service: String },
    /// IDS alerts spike
    IdsAlertsSpike { threshold: u64, window_secs: u64 },
    /// Firewall connection limit
    ConnectionsAbove { threshold: u64 },
    /// Custom Prometheus query
    PrometheusQuery { query: String, threshold: f64 },
}

/// Alert notification channel
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NotificationChannel {
    /// Email notification
    Email {
        to: Vec<String>,
        smtp_server: String,
        from: String,
    },
    /// Slack webhook
    Slack {
        webhook_url: String,
        channel: String,
    },
    /// Discord webhook
    Discord {
        webhook_url: String,
    },
    /// PagerDuty
    PagerDuty {
        integration_key: String,
    },
    /// Telegram
    Telegram {
        bot_token: String,
        chat_id: String,
    },
    /// Webhook (generic)
    Webhook {
        url: String,
        method: String,
        headers: HashMap<String, String>,
    },
    /// Syslog
    Syslog {
        server: String,
        facility: String,
    },
}

/// Fired alert
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FiredAlert {
    pub rule_name: String,
    pub severity: AlertSeverity,
    pub description: String,
    pub fired_at: chrono::DateTime<chrono::Utc>,
    pub details: HashMap<String, String>,
}

pub struct AlertManager {
    rules: Vec<AlertRule>,
    channels: Vec<NotificationChannel>,
    active_alerts: HashMap<String, FiredAlert>,
}

impl AlertManager {
    pub fn new() -> Self {
        Self {
            rules: Vec::new(),
            channels: Vec::new(),
            active_alerts: HashMap::new(),
        }
    }

    /// Add an alert rule
    pub fn add_rule(&mut self, rule: AlertRule) {
        self.rules.push(rule);
    }

    /// Add a notification channel
    pub fn add_channel(&mut self, channel: NotificationChannel) {
        self.channels.push(channel);
    }

    /// Start monitoring and alerting
    pub async fn start(mut self) {
        let mut check_interval = interval(Duration::from_secs(30));

        loop {
            check_interval.tick().await;
            self.evaluate_rules().await;
        }
    }

    async fn evaluate_rules(&mut self) {
        // Collect enabled rules and their evaluation results
        let mut rule_evaluations = Vec::new();

        for rule in &self.rules {
            if !rule.enabled {
                continue;
            }

            let condition_met = self.check_condition(&rule.condition).await;
            rule_evaluations.push((rule.clone(), condition_met));
        }

        // Process evaluations
        for (rule, condition_met) in rule_evaluations {
            if condition_met {
                self.fire_alert(&rule).await;
            } else {
                self.resolve_alert(&rule.name).await;
            }
        }
    }

    async fn check_condition(&self, condition: &AlertCondition) -> bool {
        match condition {
            AlertCondition::CpuUsageAbove { percent } => {
                // Query system CPU usage
                // This would integrate with MetricsCollector
                false  // Placeholder
            }
            AlertCondition::MemoryUsageAbove { percent } => {
                false  // Placeholder
            }
            AlertCondition::CertificateExpiring { domain, days } => {
                // Check certificate expiry
                false  // Placeholder
            }
            AlertCondition::ServiceDown { service } => {
                // Check service health
                false  // Placeholder
            }
            _ => false,
        }
    }

    async fn fire_alert(&mut self, rule: &AlertRule) {
        // Check if alert already fired
        if self.active_alerts.contains_key(&rule.name) {
            return;
        }

        let alert = FiredAlert {
            rule_name: rule.name.clone(),
            severity: rule.severity,
            description: rule.description.clone(),
            fired_at: chrono::Utc::now(),
            details: HashMap::new(),
        };

        tracing::warn!(
            "Alert fired: {} - {}",
            alert.rule_name,
            alert.description
        );

        // Send notifications
        for channel in &self.channels {
            self.send_notification(channel, &alert).await;
        }

        self.active_alerts.insert(rule.name.clone(), alert);
    }

    async fn resolve_alert(&mut self, rule_name: &str) {
        if let Some(alert) = self.active_alerts.remove(rule_name) {
            tracing::info!("Alert resolved: {}", alert.rule_name);

            // Send resolution notifications
            for channel in &self.channels {
                self.send_resolution(channel, &alert).await;
            }
        }
    }

    async fn send_notification(&self, channel: &NotificationChannel, alert: &FiredAlert) {
        match channel {
            NotificationChannel::Email { to, smtp_server, from } => {
                self.send_email(to, smtp_server, from, alert).await;
            }
            NotificationChannel::Slack { webhook_url, channel: slack_channel } => {
                self.send_slack(webhook_url, slack_channel, alert).await;
            }
            NotificationChannel::Discord { webhook_url } => {
                self.send_discord(webhook_url, alert).await;
            }
            NotificationChannel::PagerDuty { integration_key } => {
                self.send_pagerduty(integration_key, alert).await;
            }
            NotificationChannel::Telegram { bot_token, chat_id } => {
                self.send_telegram(bot_token, chat_id, alert).await;
            }
            NotificationChannel::Webhook { url, method, headers } => {
                self.send_webhook(url, method, headers, alert).await;
            }
            NotificationChannel::Syslog { server, facility } => {
                self.send_syslog(server, facility, alert).await;
            }
        }
    }

    async fn send_resolution(&self, channel: &NotificationChannel, alert: &FiredAlert) {
        // Similar to send_notification but with "resolved" message
    }

    async fn send_email(&self, to: &[String], smtp_server: &str, from: &str, alert: &FiredAlert) {
        tracing::debug!("Sending email alert to {:?}", to);
        // Implementation using lettre crate
    }

    async fn send_slack(&self, webhook_url: &str, channel: &str, alert: &FiredAlert) {
        let severity_emoji = match alert.severity {
            AlertSeverity::Critical => "🔴",
            AlertSeverity::Warning => "⚠️",
            AlertSeverity::Info => "ℹ️",
        };

        let payload = serde_json::json!({
            "channel": channel,
            "username": "Patronus Alerts",
            "icon_emoji": ":shield:",
            "attachments": [{
                "color": match alert.severity {
                    AlertSeverity::Critical => "danger",
                    AlertSeverity::Warning => "warning",
                    AlertSeverity::Info => "good",
                },
                "title": format!("{} {}", severity_emoji, alert.rule_name),
                "text": alert.description,
                "fields": [
                    {
                        "title": "Severity",
                        "value": format!("{:?}", alert.severity),
                        "short": true
                    },
                    {
                        "title": "Time",
                        "value": alert.fired_at.to_rfc3339(),
                        "short": true
                    }
                ]
            }]
        });

        if let Err(e) = reqwest::Client::new()
            .post(webhook_url)
            .json(&payload)
            .send()
            .await
        {
            tracing::error!("Failed to send Slack notification: {}", e);
        }
    }

    async fn send_discord(&self, webhook_url: &str, alert: &FiredAlert) {
        let color = match alert.severity {
            AlertSeverity::Critical => 0xFF0000,  // Red
            AlertSeverity::Warning => 0xFFA500,   // Orange
            AlertSeverity::Info => 0x00FF00,      // Green
        };

        let payload = serde_json::json!({
            "embeds": [{
                "title": format!("🛡️ Patronus Alert: {}", alert.rule_name),
                "description": alert.description,
                "color": color,
                "fields": [
                    {
                        "name": "Severity",
                        "value": format!("{:?}", alert.severity),
                        "inline": true
                    },
                    {
                        "name": "Time",
                        "value": alert.fired_at.to_rfc3339(),
                        "inline": true
                    }
                ],
                "timestamp": alert.fired_at.to_rfc3339()
            }]
        });

        if let Err(e) = reqwest::Client::new()
            .post(webhook_url)
            .json(&payload)
            .send()
            .await
        {
            tracing::error!("Failed to send Discord notification: {}", e);
        }
    }

    async fn send_pagerduty(&self, integration_key: &str, alert: &FiredAlert) {
        let payload = serde_json::json!({
            "routing_key": integration_key,
            "event_action": "trigger",
            "payload": {
                "summary": format!("{}: {}", alert.rule_name, alert.description),
                "severity": match alert.severity {
                    AlertSeverity::Critical => "critical",
                    AlertSeverity::Warning => "warning",
                    AlertSeverity::Info => "info",
                },
                "source": "patronus-firewall",
                "timestamp": alert.fired_at.to_rfc3339(),
            }
        });

        if let Err(e) = reqwest::Client::new()
            .post("https://events.pagerduty.com/v2/enqueue")
            .json(&payload)
            .send()
            .await
        {
            tracing::error!("Failed to send PagerDuty alert: {}", e);
        }
    }

    async fn send_telegram(&self, bot_token: &str, chat_id: &str, alert: &FiredAlert) {
        let message = format!(
            "🛡️ *Patronus Alert*\n\n*{}*\n{}\n\nSeverity: {:?}\nTime: {}",
            alert.rule_name,
            alert.description,
            alert.severity,
            alert.fired_at.format("%Y-%m-%d %H:%M:%S UTC")
        );

        let url = format!("https://api.telegram.org/bot{}/sendMessage", bot_token);
        let payload = serde_json::json!({
            "chat_id": chat_id,
            "text": message,
            "parse_mode": "Markdown"
        });

        if let Err(e) = reqwest::Client::new()
            .post(&url)
            .json(&payload)
            .send()
            .await
        {
            tracing::error!("Failed to send Telegram notification: {}", e);
        }
    }

    async fn send_webhook(&self, url: &str, method: &str, headers: &HashMap<String, String>, alert: &FiredAlert) {
        let client = reqwest::Client::new();
        let mut request = match method.to_uppercase().as_str() {
            "POST" => client.post(url),
            "PUT" => client.put(url),
            _ => client.post(url),
        };

        for (key, value) in headers {
            request = request.header(key, value);
        }

        let payload = serde_json::to_value(alert).unwrap();

        if let Err(e) = request.json(&payload).send().await {
            tracing::error!("Failed to send webhook notification: {}", e);
        }
    }

    async fn send_syslog(&self, server: &str, facility: &str, alert: &FiredAlert) {
        // Implementation using syslog crate
        tracing::debug!("Sending syslog to {}", server);
    }

    /// Create common alert rule presets
    pub fn load_default_rules(&mut self) {
        // High CPU usage
        self.add_rule(AlertRule {
            name: "HighCpuUsage".to_string(),
            severity: AlertSeverity::Warning,
            description: "CPU usage above 80%".to_string(),
            condition: AlertCondition::CpuUsageAbove { percent: 80.0 },
            duration: Duration::from_secs(300),  // 5 minutes
            enabled: true,
        });

        // High memory usage
        self.add_rule(AlertRule {
            name: "HighMemoryUsage".to_string(),
            severity: AlertSeverity::Warning,
            description: "Memory usage above 90%".to_string(),
            condition: AlertCondition::MemoryUsageAbove { percent: 90.0 },
            duration: Duration::from_secs(300),
            enabled: true,
        });

        // Disk space critical
        self.add_rule(AlertRule {
            name: "DiskSpaceCritical".to_string(),
            severity: AlertSeverity::Critical,
            description: "Root filesystem above 95%".to_string(),
            condition: AlertCondition::DiskUsageAbove {
                mount: "/".to_string(),
                percent: 95.0,
            },
            duration: Duration::from_secs(60),
            enabled: true,
        });

        // Certificate expiring
        self.add_rule(AlertRule {
            name: "CertificateExpiringSoon".to_string(),
            severity: AlertSeverity::Warning,
            description: "SSL certificate expiring in 14 days".to_string(),
            condition: AlertCondition::CertificateExpiring {
                domain: "*".to_string(),
                days: 14,
            },
            duration: Duration::from_secs(3600),  // 1 hour
            enabled: true,
        });

        // HA failover
        self.add_rule(AlertRule {
            name: "HAFailover".to_string(),
            severity: AlertSeverity::Critical,
            description: "High availability failover occurred".to_string(),
            condition: AlertCondition::HaFailover,
            duration: Duration::from_secs(0),  // Immediate
            enabled: true,
        });
    }
}

impl Default for AlertManager {
    fn default() -> Self {
        let mut manager = Self::new();
        manager.load_default_rules();
        manager
    }
}
