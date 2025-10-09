//! Configuration storage backend

use patronus_core::{Error, Result, types::{FirewallRule, NatRule, ChainType, FirewallAction, Protocol, PortSpec, NatType}};
use serde::{Deserialize, Serialize};
use sqlx::{sqlite::SqlitePool, Row};
use std::path::{Path, PathBuf};
use std::net::IpAddr;

/// Configuration store
pub struct ConfigStore {
    db_path: PathBuf,
    pool: Option<SqlitePool>,
}

impl ConfigStore {
    /// Create a new config store
    pub fn new(db_path: PathBuf) -> Self {
        Self {
            db_path,
            pool: None,
        }
    }

    /// Initialize the configuration store
    pub async fn init(&mut self) -> Result<()> {
        tracing::info!("Initializing config store at {:?}", self.db_path);

        // Create parent directory if it doesn't exist
        if let Some(parent) = self.db_path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| Error::Config(format!("Failed to create config directory: {}", e)))?;
        }

        // Connect to SQLite database
        let db_url = format!("sqlite://{}", self.db_path.display());
        let pool = SqlitePool::connect(&db_url)
            .await
            .map_err(|e| Error::Config(format!("Failed to connect to database: {}", e)))?;

        // Load and execute schema
        let schema = include_str!("schema.sql");
        sqlx::query(schema)
            .execute(&pool)
            .await
            .map_err(|e| Error::Config(format!("Failed to initialize schema: {}", e)))?;

        self.pool = Some(pool);
        tracing::info!("Config store initialized");
        Ok(())
    }

    /// Get database pool
    fn pool(&self) -> Result<&SqlitePool> {
        self.pool
            .as_ref()
            .ok_or_else(|| Error::Config("Database not initialized".to_string()))
    }

    /// Save a system configuration value
    pub async fn save_system_config(&self, key: &str, value: &str) -> Result<()> {
        let now = chrono::Utc::now().timestamp();

        sqlx::query(
            "INSERT INTO system_config (key, value, updated_at) VALUES (?, ?, ?)
             ON CONFLICT(key) DO UPDATE SET value = ?, updated_at = ?"
        )
        .bind(key)
        .bind(value)
        .bind(now)
        .bind(value)
        .bind(now)
        .execute(self.pool()?)
        .await
        .map_err(|e| Error::Config(format!("Failed to save system config: {}", e)))?;

        Ok(())
    }

    /// Load a system configuration value
    pub async fn load_system_config(&self, key: &str) -> Result<Option<String>> {
        let row = sqlx::query("SELECT value FROM system_config WHERE key = ?")
            .bind(key)
            .fetch_optional(self.pool()?)
            .await
            .map_err(|e| Error::Config(format!("Failed to load system config: {}", e)))?;

        Ok(row.map(|r| r.get(0)))
    }

    /// Save a firewall rule
    pub async fn save_firewall_rule(&self, rule: &FirewallRule) -> Result<i64> {
        let now = chrono::Utc::now().timestamp();
        let sport_json = rule.sport.as_ref().map(|p| serde_json::to_string(p).unwrap());
        let dport_json = rule.dport.as_ref().map(|p| serde_json::to_string(p).unwrap());

        let result = sqlx::query(
            "INSERT INTO firewall_rules
             (name, enabled, chain, action, source, destination, protocol, sport, dport,
              interface_in, interface_out, comment, priority, created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
        )
        .bind(&rule.name)
        .bind(rule.enabled as i32)
        .bind(rule.chain.to_string())
        .bind(rule.action.to_string())
        .bind(&rule.source)
        .bind(&rule.destination)
        .bind(rule.protocol.as_ref().map(|p| p.to_string()))
        .bind(sport_json)
        .bind(dport_json)
        .bind(&rule.interface_in)
        .bind(&rule.interface_out)
        .bind(&rule.comment)
        .bind(0) // priority
        .bind(now)
        .bind(now)
        .execute(self.pool()?)
        .await
        .map_err(|e| Error::Config(format!("Failed to save firewall rule: {}", e)))?;

        Ok(result.last_insert_rowid())
    }

    /// Load all firewall rules
    pub async fn load_firewall_rules(&self) -> Result<Vec<FirewallRule>> {
        let rows = sqlx::query(
            "SELECT id, name, enabled, chain, action, source, destination, protocol,
                    sport, dport, interface_in, interface_out, comment
             FROM firewall_rules
             ORDER BY priority ASC, id ASC"
        )
        .fetch_all(self.pool()?)
        .await
        .map_err(|e| Error::Config(format!("Failed to load firewall rules: {}", e)))?;

        let mut rules = Vec::new();
        for row in rows {
            let chain = match row.get::<String, _>("chain").as_str() {
                "input" => ChainType::Input,
                "output" => ChainType::Output,
                "forward" => ChainType::Forward,
                _ => ChainType::Input,
            };

            let action = match row.get::<String, _>("action").as_str() {
                "accept" => FirewallAction::Accept,
                "drop" => FirewallAction::Drop,
                "reject" => FirewallAction::Reject,
                _ => FirewallAction::Drop,
            };

            let protocol = row.get::<Option<String>, _>("protocol")
                .map(|p| match p.as_str() {
                    "tcp" => Protocol::Tcp,
                    "udp" => Protocol::Udp,
                    "icmp" => Protocol::Icmp,
                    _ => Protocol::All,
                });

            let sport = row.get::<Option<String>, _>("sport")
                .and_then(|s| serde_json::from_str(&s).ok());

            let dport = row.get::<Option<String>, _>("dport")
                .and_then(|s| serde_json::from_str(&s).ok());

            rules.push(FirewallRule {
                id: Some(row.get::<i64, _>("id") as u64),
                name: row.get("name"),
                enabled: row.get::<i32, _>("enabled") != 0,
                chain,
                action,
                source: row.get("source"),
                destination: row.get("destination"),
                protocol,
                sport,
                dport,
                interface_in: row.get("interface_in"),
                interface_out: row.get("interface_out"),
                comment: row.get("comment"),
            });
        }

        Ok(rules)
    }

    /// Delete a firewall rule
    pub async fn delete_firewall_rule(&self, id: u64) -> Result<()> {
        sqlx::query("DELETE FROM firewall_rules WHERE id = ?")
            .bind(id as i64)
            .execute(self.pool()?)
            .await
            .map_err(|e| Error::Config(format!("Failed to delete firewall rule: {}", e)))?;

        Ok(())
    }

    /// Save a NAT rule
    pub async fn save_nat_rule(&self, rule: &NatRule) -> Result<i64> {
        let now = chrono::Utc::now().timestamp();
        let dport_json = rule.dport.as_ref().map(|p| serde_json::to_string(p).unwrap());

        let (nat_type_str, to_address, to_port) = match &rule.nat_type {
            NatType::Masquerade => ("masquerade".to_string(), None, None),
            NatType::Snat { to_address } => ("snat".to_string(), Some(to_address.to_string()), None),
            NatType::Dnat { to_address, to_port } => ("dnat".to_string(), Some(to_address.to_string()), *to_port),
        };

        let result = sqlx::query(
            "INSERT INTO nat_rules
             (name, enabled, nat_type, to_address, to_port, source, destination, protocol,
              dport, interface_out, comment, priority, created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
        )
        .bind(&rule.name)
        .bind(rule.enabled as i32)
        .bind(nat_type_str)
        .bind(to_address)
        .bind(to_port.map(|p| p as i64))
        .bind(&rule.source)
        .bind(&rule.destination)
        .bind(rule.protocol.as_ref().map(|p| p.to_string()))
        .bind(dport_json)
        .bind(&rule.interface_out)
        .bind(&rule.comment)
        .bind(0) // priority
        .bind(now)
        .bind(now)
        .execute(self.pool()?)
        .await
        .map_err(|e| Error::Config(format!("Failed to save NAT rule: {}", e)))?;

        Ok(result.last_insert_rowid())
    }

    /// Load all NAT rules
    pub async fn load_nat_rules(&self) -> Result<Vec<NatRule>> {
        let rows = sqlx::query(
            "SELECT id, name, enabled, nat_type, to_address, to_port, source, destination,
                    protocol, dport, interface_out, comment
             FROM nat_rules
             ORDER BY priority ASC, id ASC"
        )
        .fetch_all(self.pool()?)
        .await
        .map_err(|e| Error::Config(format!("Failed to load NAT rules: {}", e)))?;

        let mut rules = Vec::new();
        for row in rows {
            let nat_type = match row.get::<String, _>("nat_type").as_str() {
                "masquerade" => NatType::Masquerade,
                "snat" => {
                    let addr: String = row.get("to_address");
                    NatType::Snat {
                        to_address: addr.parse().unwrap(),
                    }
                }
                "dnat" => {
                    let addr: String = row.get("to_address");
                    let port: Option<i64> = row.get("to_port");
                    NatType::Dnat {
                        to_address: addr.parse().unwrap(),
                        to_port: port.map(|p| p as u16),
                    }
                }
                _ => NatType::Masquerade,
            };

            let protocol = row.get::<Option<String>, _>("protocol")
                .map(|p| match p.as_str() {
                    "tcp" => Protocol::Tcp,
                    "udp" => Protocol::Udp,
                    "icmp" => Protocol::Icmp,
                    _ => Protocol::All,
                });

            let dport = row.get::<Option<String>, _>("dport")
                .and_then(|s| serde_json::from_str(&s).ok());

            rules.push(NatRule {
                id: Some(row.get::<i64, _>("id") as u64),
                name: row.get("name"),
                enabled: row.get::<i32, _>("enabled") != 0,
                nat_type,
                source: row.get("source"),
                destination: row.get("destination"),
                protocol,
                dport,
                interface_out: row.get("interface_out"),
                comment: row.get("comment"),
            });
        }

        Ok(rules)
    }

    /// Delete a NAT rule
    pub async fn delete_nat_rule(&self, id: u64) -> Result<()> {
        sqlx::query("DELETE FROM nat_rules WHERE id = ?")
            .bind(id as i64)
            .execute(self.pool()?)
            .await
            .map_err(|e| Error::Config(format!("Failed to delete NAT rule: {}", e)))?;

        Ok(())
    }

    /// Create a configuration backup
    pub async fn create_backup(&self, name: &str, description: Option<&str>) -> Result<i64> {
        // Gather all configuration
        let firewall_rules = self.load_firewall_rules().await?;
        let nat_rules = self.load_nat_rules().await?;

        let backup = serde_json::json!({
            "version": "1.0",
            "firewall_rules": firewall_rules,
            "nat_rules": nat_rules,
        });

        let now = chrono::Utc::now().timestamp();
        let result = sqlx::query(
            "INSERT INTO config_backups (name, description, config_json, created_at)
             VALUES (?, ?, ?, ?)"
        )
        .bind(name)
        .bind(description)
        .bind(backup.to_string())
        .bind(now)
        .execute(self.pool()?)
        .await
        .map_err(|e| Error::Config(format!("Failed to create backup: {}", e)))?;

        tracing::info!("Created configuration backup: {}", name);
        Ok(result.last_insert_rowid())
    }
}
