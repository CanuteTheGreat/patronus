use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tracing::{info, warn};

/// Threat intelligence source
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ThreatSource {
    AbuseIPDB,
    AlienVault,
    ThreatFox,
    EmergingThreats,
    Custom(String),
}

/// Threat category
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum ThreatCategory {
    Malware,
    Botnet,
    Scanner,
    BruteForce,
    DDoS,
    Spam,
    Phishing,
    C2Server,
    Tor,
    Proxy,
    Unknown,
}

/// Threat intelligence entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIntelEntry {
    pub ip: String,
    pub categories: Vec<ThreatCategory>,
    pub confidence: f64,
    pub last_seen: DateTime<Utc>,
    pub source: ThreatSource,
    pub description: Option<String>,
    pub country: Option<String>,
    pub asn: Option<u32>,
}

/// Threat intelligence database
pub struct ThreatIntelDB {
    entries: Arc<RwLock<HashMap<String, Vec<ThreatIntelEntry>>>>,
    blocklist: Arc<RwLock<HashSet<String>>>,
}

impl ThreatIntelDB {
    pub fn new() -> Self {
        Self {
            entries: Arc::new(RwLock::new(HashMap::new())),
            blocklist: Arc::new(RwLock::new(HashSet::new())),
        }
    }

    /// Add a threat entry
    pub async fn add_entry(&self, entry: ThreatIntelEntry) {
        let mut entries = self.entries.write().await;
        entries.entry(entry.ip.clone())
            .or_insert_with(Vec::new)
            .push(entry.clone());

        // Add to blocklist if confidence is high
        if entry.confidence > 0.7 {
            let mut blocklist = self.blocklist.write().await;
            blocklist.insert(entry.ip.clone());
        }
    }

    /// Check if an IP is in the threat database
    pub async fn is_threat(&self, ip: &str) -> bool {
        self.blocklist.read().await.contains(ip)
    }

    /// Get threat intelligence for an IP
    pub async fn get_threats(&self, ip: &str) -> Vec<ThreatIntelEntry> {
        self.entries.read().await
            .get(ip)
            .cloned()
            .unwrap_or_default()
    }

    /// Get all blocked IPs
    pub async fn get_blocklist(&self) -> Vec<String> {
        self.blocklist.read().await.iter().cloned().collect()
    }

    /// Clear old entries
    pub async fn cleanup_old_entries(&self, max_age: Duration) {
        let cutoff = Utc::now() - chrono::Duration::from_std(max_age).unwrap();
        let mut entries = self.entries.write().await;

        for entry_list in entries.values_mut() {
            entry_list.retain(|e| e.last_seen > cutoff);
        }

        entries.retain(|_, v| !v.is_empty());

        // Rebuild blocklist
        let mut blocklist = self.blocklist.write().await;
        blocklist.clear();

        for (ip, entry_list) in entries.iter() {
            if entry_list.iter().any(|e| e.confidence > 0.7) {
                blocklist.insert(ip.clone());
            }
        }
    }
}

impl Default for ThreatIntelDB {
    fn default() -> Self {
        Self::new()
    }
}

/// AbuseIPDB feed configuration
#[derive(Debug, Clone)]
pub struct AbuseIPDBConfig {
    pub api_key: String,
    pub confidence_threshold: u32,  // 0-100
}

/// Threat intelligence feed aggregator
pub struct ThreatFeedAggregator {
    db: Arc<ThreatIntelDB>,
    http_client: Client,
    abuseipdb_config: Option<AbuseIPDBConfig>,
    update_interval: Duration,
}

impl ThreatFeedAggregator {
    pub fn new(db: Arc<ThreatIntelDB>, update_interval: Duration) -> Self {
        Self {
            db,
            http_client: Client::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .unwrap(),
            abuseipdb_config: None,
            update_interval,
        }
    }

    /// Configure AbuseIPDB integration
    pub fn with_abuseipdb(mut self, api_key: String) -> Self {
        self.abuseipdb_config = Some(AbuseIPDBConfig {
            api_key,
            confidence_threshold: 75,
        });
        self
    }

    /// Start periodic feed updates
    pub async fn start(self: Arc<Self>) {
        info!("Starting threat intelligence feed aggregator");

        let mut interval = tokio::time::interval(self.update_interval);

        loop {
            interval.tick().await;

            // Update from various sources
            if let Err(e) = self.update_all_feeds().await {
                warn!("Failed to update threat feeds: {}", e);
            }

            // Cleanup old entries (>30 days)
            self.db.cleanup_old_entries(Duration::from_secs(30 * 24 * 3600)).await;
        }
    }

    async fn update_all_feeds(&self) -> Result<()> {
        let mut tasks = Vec::new();

        // AbuseIPDB
        if self.abuseipdb_config.is_some() {
            let self_clone = Arc::new(self.clone());
            tasks.push(tokio::spawn(async move {
                self_clone.update_abuseipdb().await
            }));
        }

        // EmergingThreats (free list)
        let self_clone = Arc::new(self.clone());
        tasks.push(tokio::spawn(async move {
            self_clone.update_emerging_threats().await
        }));

        // Wait for all updates
        for task in tasks {
            if let Err(e) = task.await {
                warn!("Threat feed update task failed: {}", e);
            }
        }

        Ok(())
    }

    async fn update_abuseipdb(&self) -> Result<()> {
        let config = self.abuseipdb_config.as_ref()
            .context("AbuseIPDB not configured")?;

        info!("Updating AbuseIPDB threat feed");

        // Get blocklist from AbuseIPDB
        let url = format!(
            "https://api.abuseipdb.com/api/v2/blacklist?confidenceMinimum={}",
            config.confidence_threshold
        );

        let response = self.http_client
            .get(&url)
            .header("Key", &config.api_key)
            .header("Accept", "application/json")
            .send()
            .await
            .context("Failed to fetch AbuseIPDB data")?;

        if !response.status().is_success() {
            return Err(anyhow::anyhow!("AbuseIPDB API returned error: {}", response.status()));
        }

        #[derive(Deserialize)]
        struct AbuseIPDBResponse {
            data: Vec<AbuseIPDBEntry>,
        }

        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct AbuseIPDBEntry {
            ip_address: String,
            abuse_confidence_score: u32,
            country_code: Option<String>,
        }

        let data: AbuseIPDBResponse = response.json().await
            .context("Failed to parse AbuseIPDB response")?;

        // Add to database
        for entry in data.data {
            let threat_entry = ThreatIntelEntry {
                ip: entry.ip_address,
                categories: vec![ThreatCategory::Unknown],  // AbuseIPDB doesn't provide detailed categories
                confidence: entry.abuse_confidence_score as f64 / 100.0,
                last_seen: Utc::now(),
                source: ThreatSource::AbuseIPDB,
                description: Some(format!("AbuseIPDB confidence: {}", entry.abuse_confidence_score)),
                country: entry.country_code,
                asn: None,
            };

            self.db.add_entry(threat_entry).await;
        }

        info!("AbuseIPDB feed updated");
        Ok(())
    }

    async fn update_emerging_threats(&self) -> Result<()> {
        info!("Updating EmergingThreats feed");

        // Fetch Emerging Threats compromised IPs list
        let url = "https://rules.emergingthreats.net/blockrules/compromised-ips.txt";

        let response = self.http_client
            .get(url)
            .send()
            .await
            .context("Failed to fetch EmergingThreats data")?;

        if !response.status().is_success() {
            return Err(anyhow::anyhow!("EmergingThreats fetch failed: {}", response.status()));
        }

        let text = response.text().await?;

        // Parse IP list
        for line in text.lines() {
            let line = line.trim();

            // Skip comments and empty lines
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            // Validate IP
            if line.parse::<IpAddr>().is_ok() {
                let threat_entry = ThreatIntelEntry {
                    ip: line.to_string(),
                    categories: vec![ThreatCategory::Malware, ThreatCategory::Botnet],
                    confidence: 0.8,
                    last_seen: Utc::now(),
                    source: ThreatSource::EmergingThreats,
                    description: Some("EmergingThreats compromised IP".to_string()),
                    country: None,
                    asn: None,
                };

                self.db.add_entry(threat_entry).await;
            }
        }

        info!("EmergingThreats feed updated");
        Ok(())
    }

    /// Check an IP against threat intelligence
    pub async fn check_ip(&self, ip: &str) -> Option<ThreatIntelEntry> {
        let threats = self.db.get_threats(ip).await;

        // Return highest confidence threat (use total_cmp to handle NaN safely)
        threats.into_iter()
            .max_by(|a, b| a.confidence.total_cmp(&b.confidence))
    }
}

impl Clone for ThreatFeedAggregator {
    fn clone(&self) -> Self {
        Self {
            db: Arc::clone(&self.db),
            http_client: self.http_client.clone(),
            abuseipdb_config: self.abuseipdb_config.clone(),
            update_interval: self.update_interval,
        }
    }
}

/// Threat reputation scorer
pub struct ReputationScorer {
    threat_db: Arc<ThreatIntelDB>,
}

impl ReputationScorer {
    pub fn new(threat_db: Arc<ThreatIntelDB>) -> Self {
        Self { threat_db }
    }

    /// Calculate reputation score for an IP (0-1, 1=good, 0=bad)
    pub async fn score_ip(&self, ip: &str) -> f64 {
        let threats = self.threat_db.get_threats(ip).await;

        if threats.is_empty() {
            return 1.0;  // No threat data = assume good
        }

        // Worst threat confidence becomes the reputation penalty
        let max_threat_confidence = threats.iter()
            .map(|t| t.confidence)
            .fold(0.0, f64::max);

        1.0 - max_threat_confidence
    }

    /// Get threat categories for an IP
    pub async fn get_categories(&self, ip: &str) -> Vec<ThreatCategory> {
        let threats = self.threat_db.get_threats(ip).await;

        let mut categories = HashSet::new();
        for threat in threats {
            for category in threat.categories {
                categories.insert(category);
            }
        }

        categories.into_iter().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_threat_db() {
        let db = ThreatIntelDB::new();

        let entry = ThreatIntelEntry {
            ip: "1.2.3.4".to_string(),
            categories: vec![ThreatCategory::Malware],
            confidence: 0.9,
            last_seen: Utc::now(),
            source: ThreatSource::EmergingThreats,
            description: None,
            country: None,
            asn: None,
        };

        db.add_entry(entry).await;

        assert!(db.is_threat("1.2.3.4").await);
        assert!(!db.is_threat("5.6.7.8").await);

        let threats = db.get_threats("1.2.3.4").await;
        assert_eq!(threats.len(), 1);
        assert_eq!(threats[0].confidence, 0.9);
    }

    #[tokio::test]
    async fn test_reputation_scorer() {
        let db = Arc::new(ThreatIntelDB::new());
        let scorer = ReputationScorer::new(Arc::clone(&db));

        // No data = good reputation
        let score = scorer.score_ip("1.2.3.4").await;
        assert_eq!(score, 1.0);

        // Add threat data
        let entry = ThreatIntelEntry {
            ip: "1.2.3.4".to_string(),
            categories: vec![ThreatCategory::Malware],
            confidence: 0.8,
            last_seen: Utc::now(),
            source: ThreatSource::Custom("test".to_string()),
            description: None,
            country: None,
            asn: None,
        };

        db.add_entry(entry).await;

        // Bad reputation
        let score = scorer.score_ip("1.2.3.4").await;
        assert!((score - 0.2).abs() < 0.01);  // 1.0 - 0.8, use approximate comparison
    }
}
