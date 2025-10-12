//! Database operations for SD-WAN

use crate::{types::*, Result};
use sqlx::{sqlite::SqlitePool, Row};
use tracing::{debug, info};
use serde_json;

/// Database for SD-WAN state
pub struct Database {
    pool: SqlitePool,
}

impl Database {
    /// Create a new database connection
    pub async fn new(path: &str) -> Result<Self> {
        let url = if path == ":memory:" {
            "sqlite::memory:".to_string()
        } else {
            format!("sqlite://{}", path)
        };

        info!(url = %url, "Connecting to SD-WAN database");

        let pool = SqlitePool::connect(&url).await?;

        let db = Self { pool };

        // Run migrations
        db.migrate().await?;

        Ok(db)
    }

    /// Create a new in-memory database (for testing)
    pub async fn new_in_memory() -> Result<Self> {
        Self::new(":memory:").await
    }

    /// Get a reference to the connection pool
    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }

    /// Run database migrations
    async fn migrate(&self) -> Result<()> {
        debug!("Running database migrations");

        // Sites table
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS sdwan_sites (
                site_id TEXT PRIMARY KEY,
                site_name TEXT NOT NULL,
                public_key BLOB NOT NULL,
                created_at INTEGER NOT NULL,
                last_seen INTEGER NOT NULL,
                status TEXT CHECK(status IN ('active', 'inactive', 'degraded')) NOT NULL
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        // Endpoints table
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS sdwan_endpoints (
                endpoint_id INTEGER PRIMARY KEY AUTOINCREMENT,
                site_id TEXT NOT NULL,
                address TEXT NOT NULL,
                interface_type TEXT NOT NULL,
                cost_per_gb REAL NOT NULL,
                reachable INTEGER NOT NULL,
                FOREIGN KEY (site_id) REFERENCES sdwan_sites(site_id)
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        // Paths table
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS sdwan_paths (
                path_id INTEGER PRIMARY KEY AUTOINCREMENT,
                src_site_id TEXT NOT NULL,
                dst_site_id TEXT NOT NULL,
                src_endpoint TEXT NOT NULL,
                dst_endpoint TEXT NOT NULL,
                wg_interface TEXT,
                status TEXT CHECK(status IN ('up', 'down', 'degraded')) NOT NULL,
                FOREIGN KEY (src_site_id) REFERENCES sdwan_sites(site_id),
                FOREIGN KEY (dst_site_id) REFERENCES sdwan_sites(site_id),
                UNIQUE(src_site_id, dst_site_id, src_endpoint, dst_endpoint)
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        // Path metrics table
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS sdwan_path_metrics (
                metric_id INTEGER PRIMARY KEY AUTOINCREMENT,
                path_id INTEGER NOT NULL,
                timestamp INTEGER NOT NULL,
                latency_ms REAL NOT NULL,
                jitter_ms REAL NOT NULL,
                packet_loss_pct REAL NOT NULL,
                bandwidth_mbps REAL NOT NULL,
                mtu INTEGER NOT NULL,
                score INTEGER NOT NULL,
                FOREIGN KEY (path_id) REFERENCES sdwan_paths(path_id)
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            r#"
            CREATE INDEX IF NOT EXISTS idx_path_metrics_time
            ON sdwan_path_metrics(path_id, timestamp)
            "#,
        )
        .execute(&self.pool)
        .await?;

        // Routing policies table
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS sdwan_policies (
                policy_id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                priority INTEGER NOT NULL,
                match_rules TEXT NOT NULL,
                path_preference TEXT NOT NULL,
                enabled INTEGER NOT NULL
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        // System metrics table
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS sdwan_system_metrics (
                metric_id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp INTEGER NOT NULL,
                throughput_mbps REAL NOT NULL,
                packets_per_second INTEGER NOT NULL,
                active_flows INTEGER NOT NULL,
                avg_latency_ms REAL NOT NULL,
                avg_packet_loss REAL NOT NULL,
                cpu_usage REAL NOT NULL,
                memory_usage REAL NOT NULL
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            r#"
            CREATE INDEX IF NOT EXISTS idx_system_metrics_time
            ON sdwan_system_metrics(timestamp)
            "#,
        )
        .execute(&self.pool)
        .await?;

        // Policy traffic statistics table (Sprint 30)
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS sdwan_policy_stats (
                stat_id INTEGER PRIMARY KEY AUTOINCREMENT,
                policy_id INTEGER NOT NULL,
                timestamp INTEGER NOT NULL,
                packets_matched INTEGER NOT NULL,
                bytes_matched INTEGER NOT NULL,
                active_flows INTEGER NOT NULL,
                FOREIGN KEY (policy_id) REFERENCES sdwan_policies(policy_id)
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            r#"
            CREATE INDEX IF NOT EXISTS idx_policy_stats_time
            ON sdwan_policy_stats(policy_id, timestamp)
            "#,
        )
        .execute(&self.pool)
        .await?;

        // Path health monitoring table (Sprint 31)
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS sdwan_path_health (
                health_id INTEGER PRIMARY KEY AUTOINCREMENT,
                path_id TEXT NOT NULL,
                timestamp INTEGER NOT NULL,
                latency_ms REAL NOT NULL,
                packet_loss_pct REAL NOT NULL,
                jitter_ms REAL NOT NULL,
                health_score REAL NOT NULL,
                status TEXT CHECK(status IN ('up', 'degraded', 'down')) NOT NULL
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            r#"
            CREATE INDEX IF NOT EXISTS idx_path_health_path_time
            ON sdwan_path_health(path_id, timestamp)
            "#,
        )
        .execute(&self.pool)
        .await?;

        // Failover policies table (Sprint 31)
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS sdwan_failover_policies (
                policy_id INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                primary_path_id TEXT NOT NULL,
                backup_path_ids TEXT NOT NULL,
                failover_threshold REAL NOT NULL DEFAULT 50.0,
                failback_threshold REAL NOT NULL DEFAULT 80.0,
                failback_delay_secs INTEGER NOT NULL DEFAULT 60,
                enabled INTEGER NOT NULL DEFAULT 1
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        // Failover events table (Sprint 31)
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS sdwan_failover_events (
                event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                policy_id INTEGER NOT NULL,
                event_type TEXT CHECK(event_type IN ('triggered', 'completed', 'failed', 'policy_enabled', 'policy_disabled')) NOT NULL,
                from_path_id TEXT,
                to_path_id TEXT,
                reason TEXT NOT NULL,
                timestamp INTEGER NOT NULL,
                FOREIGN KEY (policy_id) REFERENCES sdwan_failover_policies(policy_id)
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            r#"
            CREATE INDEX IF NOT EXISTS idx_failover_events_policy_time
            ON sdwan_failover_events(policy_id, timestamp)
            "#,
        )
        .execute(&self.pool)
        .await?;

        info!("Database migrations completed");
        Ok(())
    }

    /// Insert or update a site
    pub async fn upsert_site(&self, site: &Site) -> Result<()> {
        let created_at = site.created_at
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let last_seen = site.last_seen
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        sqlx::query(
            r#"
            INSERT INTO sdwan_sites (site_id, site_name, public_key, created_at, last_seen, status)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(site_id) DO UPDATE SET
                site_name = excluded.site_name,
                public_key = excluded.public_key,
                last_seen = excluded.last_seen,
                status = excluded.status
            "#,
        )
        .bind(site.id.to_string())
        .bind(&site.name)
        .bind(&site.public_key)
        .bind(created_at)
        .bind(last_seen)
        .bind(site.status.to_string())
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Get a site by ID
    pub async fn get_site(&self, site_id: &SiteId) -> Result<Option<Site>> {
        let row = sqlx::query(
            r#"
            SELECT site_id, site_name, public_key, created_at, last_seen, status
            FROM sdwan_sites
            WHERE site_id = ?
            "#,
        )
        .bind(site_id.to_string())
        .fetch_optional(&self.pool)
        .await?;

        if let Some(row) = row {
            let site_id: String = row.try_get("site_id")?;
            let site_name: String = row.try_get("site_name")?;
            let public_key: Vec<u8> = row.try_get("public_key")?;
            let created_at: i64 = row.try_get("created_at")?;
            let last_seen: i64 = row.try_get("last_seen")?;
            let status: String = row.try_get("status")?;

            let status = match status.as_str() {
                "active" => SiteStatus::Active,
                "inactive" => SiteStatus::Inactive,
                "degraded" => SiteStatus::Degraded,
                _ => SiteStatus::Inactive,
            };

            Ok(Some(Site {
                id: site_id.parse().unwrap(),
                name: site_name,
                public_key,
                endpoints: Vec::new(), // TODO: Load endpoints
                created_at: std::time::UNIX_EPOCH + std::time::Duration::from_secs(created_at as u64),
                last_seen: std::time::UNIX_EPOCH + std::time::Duration::from_secs(last_seen as u64),
                status,
            }))
        } else {
            Ok(None)
        }
    }

    /// List all sites
    pub async fn list_sites(&self) -> Result<Vec<Site>> {
        let rows = sqlx::query(
            r#"
            SELECT site_id, site_name, public_key, created_at, last_seen, status
            FROM sdwan_sites
            ORDER BY site_name
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        let mut sites = Vec::new();
        for row in rows {
            let site_id: String = row.try_get("site_id")?;
            let site_name: String = row.try_get("site_name")?;
            let public_key: Vec<u8> = row.try_get("public_key")?;
            let created_at: i64 = row.try_get("created_at")?;
            let last_seen: i64 = row.try_get("last_seen")?;
            let status: String = row.try_get("status")?;

            let status = match status.as_str() {
                "active" => SiteStatus::Active,
                "inactive" => SiteStatus::Inactive,
                "degraded" => SiteStatus::Degraded,
                _ => SiteStatus::Inactive,
            };

            sites.push(Site {
                id: site_id.parse().unwrap(),
                name: site_name,
                public_key,
                endpoints: Vec::new(),
                created_at: std::time::UNIX_EPOCH + std::time::Duration::from_secs(created_at as u64),
                last_seen: std::time::UNIX_EPOCH + std::time::Duration::from_secs(last_seen as u64),
                status,
            });
        }

        Ok(sites)
    }

    /// Count total number of sites
    pub async fn count_sites(&self) -> Result<i64> {
        let row = sqlx::query(
            r#"
            SELECT COUNT(*) as count
            FROM sdwan_sites
            "#,
        )
        .fetch_one(&self.pool)
        .await?;

        Ok(row.try_get("count")?)
    }

    /// Insert a path
    pub async fn insert_path(&self, path: &Path) -> Result<PathId> {
        let result = sqlx::query(
            r#"
            INSERT INTO sdwan_paths (src_site_id, dst_site_id, src_endpoint, dst_endpoint, wg_interface, status)
            VALUES (?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(path.src_site.to_string())
        .bind(path.dst_site.to_string())
        .bind(path.src_endpoint.to_string())
        .bind(path.dst_endpoint.to_string())
        .bind(&path.wg_interface)
        .bind(path.status.to_string())
        .execute(&self.pool)
        .await?;

        Ok(PathId::new(result.last_insert_rowid() as u64))
    }

    /// Record path metrics
    pub async fn record_metrics(&self, path_id: PathId, metrics: &PathMetrics) -> Result<()> {
        let timestamp = metrics.measured_at
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        sqlx::query(
            r#"
            INSERT INTO sdwan_path_metrics (
                path_id, timestamp, latency_ms, jitter_ms, packet_loss_pct,
                bandwidth_mbps, mtu, score
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(path_id.as_u64() as i64)
        .bind(timestamp)
        .bind(metrics.latency_ms)
        .bind(metrics.jitter_ms)
        .bind(metrics.packet_loss_pct)
        .bind(metrics.bandwidth_mbps)
        .bind(metrics.mtu as i32)
        .bind(metrics.score as i32)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Store path metrics (alias for record_metrics)
    pub async fn store_path_metrics(&self, path_id: PathId, metrics: &PathMetrics) -> Result<()> {
        self.record_metrics(path_id, metrics).await
    }

    /// Get path by ID
    pub async fn get_path(&self, path_id: PathId) -> Result<Path> {
        let row = sqlx::query(
            r#"
            SELECT path_id, src_site_id, dst_site_id, src_endpoint, dst_endpoint, wg_interface, status
            FROM sdwan_paths
            WHERE path_id = ?
            "#,
        )
        .bind(path_id.as_u64() as i64)
        .fetch_one(&self.pool)
        .await?;

        let src_site: String = row.try_get("src_site_id")?;
        let dst_site: String = row.try_get("dst_site_id")?;
        let src_endpoint: String = row.try_get("src_endpoint")?;
        let dst_endpoint: String = row.try_get("dst_endpoint")?;
        let wg_interface: Option<String> = row.try_get("wg_interface")?;
        let status: String = row.try_get("status")?;

        let status = match status.as_str() {
            "up" => PathStatus::Up,
            "down" => PathStatus::Down,
            "degraded" => PathStatus::Degraded,
            _ => PathStatus::Down,
        };

        Ok(Path {
            id: path_id,
            src_site: src_site.parse().unwrap(),
            dst_site: dst_site.parse().unwrap(),
            src_endpoint: src_endpoint.parse().unwrap(),
            dst_endpoint: dst_endpoint.parse().unwrap(),
            wg_interface,
            metrics: PathMetrics::default(),
            status,
        })
    }

    /// List all paths
    pub async fn list_paths(&self) -> Result<Vec<Path>> {
        let rows = sqlx::query(
            r#"
            SELECT path_id, src_site_id, dst_site_id, src_endpoint, dst_endpoint, wg_interface, status
            FROM sdwan_paths
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        let mut paths = Vec::new();
        for row in rows {
            let path_id: i64 = row.try_get("path_id")?;
            let src_site: String = row.try_get("src_site_id")?;
            let dst_site: String = row.try_get("dst_site_id")?;
            let src_endpoint: String = row.try_get("src_endpoint")?;
            let dst_endpoint: String = row.try_get("dst_endpoint")?;
            let wg_interface: Option<String> = row.try_get("wg_interface")?;
            let status: String = row.try_get("status")?;

            let status = match status.as_str() {
                "up" => PathStatus::Up,
                "down" => PathStatus::Down,
                "degraded" => PathStatus::Degraded,
                _ => PathStatus::Down,
            };

            paths.push(Path {
                id: PathId::new(path_id as u64),
                src_site: src_site.parse().unwrap(),
                dst_site: dst_site.parse().unwrap(),
                src_endpoint: src_endpoint.parse().unwrap(),
                dst_endpoint: dst_endpoint.parse().unwrap(),
                wg_interface,
                metrics: PathMetrics::default(),
                status,
            });
        }

        Ok(paths)
    }

    /// Update path status
    pub async fn update_path_status(&self, path_id: PathId, status: PathStatus) -> Result<()> {
        sqlx::query(
            r#"
            UPDATE sdwan_paths
            SET status = ?
            WHERE path_id = ?
            "#,
        )
        .bind(status.to_string())
        .bind(path_id.as_u64() as i64)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Get latest metrics for a path
    pub async fn get_latest_metrics(&self, path_id: PathId) -> Result<PathMetrics> {
        let row = sqlx::query(
            r#"
            SELECT latency_ms, jitter_ms, packet_loss_pct, bandwidth_mbps, mtu, score, timestamp
            FROM sdwan_path_metrics
            WHERE path_id = ?
            ORDER BY timestamp DESC
            LIMIT 1
            "#,
        )
        .bind(path_id.as_u64() as i64)
        .fetch_one(&self.pool)
        .await?;

        let timestamp: i64 = row.try_get("timestamp")?;

        Ok(PathMetrics {
            latency_ms: row.try_get("latency_ms")?,
            jitter_ms: row.try_get("jitter_ms")?,
            packet_loss_pct: row.try_get("packet_loss_pct")?,
            bandwidth_mbps: row.try_get("bandwidth_mbps")?,
            mtu: row.try_get::<i32, _>("mtu")? as u16,
            measured_at: std::time::UNIX_EPOCH + std::time::Duration::from_secs(timestamp as u64),
            score: row.try_get::<i32, _>("score")? as u8,
        })
    }

    /// Insert or update a routing policy
    pub async fn upsert_policy(&self, policy: &crate::policy::RoutingPolicy) -> Result<()> {
        let match_rules = serde_json::to_string(&policy.match_rules)?;
        let path_preference = serde_json::to_string(&policy.path_preference)?;

        sqlx::query(
            r#"
            INSERT INTO sdwan_policies (policy_id, name, priority, match_rules, path_preference, enabled)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(policy_id) DO UPDATE SET
                name = excluded.name,
                priority = excluded.priority,
                match_rules = excluded.match_rules,
                path_preference = excluded.path_preference,
                enabled = excluded.enabled
            "#,
        )
        .bind(policy.id as i64)
        .bind(&policy.name)
        .bind(policy.priority as i32)
        .bind(match_rules)
        .bind(path_preference)
        .bind(policy.enabled as i32)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Get a routing policy by ID
    pub async fn get_policy(&self, policy_id: u64) -> Result<Option<crate::policy::RoutingPolicy>> {
        let row = sqlx::query(
            r#"
            SELECT policy_id, name, priority, match_rules, path_preference, enabled
            FROM sdwan_policies
            WHERE policy_id = ?
            "#,
        )
        .bind(policy_id as i64)
        .fetch_optional(&self.pool)
        .await?;

        if let Some(row) = row {
            let policy_id: i64 = row.try_get("policy_id")?;
            let name: String = row.try_get("name")?;
            let priority: i32 = row.try_get("priority")?;
            let match_rules_json: String = row.try_get("match_rules")?;
            let path_preference_json: String = row.try_get("path_preference")?;
            let enabled: i32 = row.try_get("enabled")?;

            let match_rules: crate::policy::MatchRules = serde_json::from_str(&match_rules_json)?;
            let path_preference: crate::policy::PathPreference = serde_json::from_str(&path_preference_json)?;

            Ok(Some(crate::policy::RoutingPolicy {
                id: policy_id as u64,
                name,
                priority: priority as u32,
                match_rules,
                path_preference,
                enabled: enabled != 0,
            }))
        } else {
            Ok(None)
        }
    }

    /// List all routing policies
    pub async fn list_policies(&self) -> Result<Vec<crate::policy::RoutingPolicy>> {
        let rows = sqlx::query(
            r#"
            SELECT policy_id, name, priority, match_rules, path_preference, enabled
            FROM sdwan_policies
            ORDER BY priority DESC, name
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        let mut policies = Vec::new();
        for row in rows {
            let policy_id: i64 = row.try_get("policy_id")?;
            let name: String = row.try_get("name")?;
            let priority: i32 = row.try_get("priority")?;
            let match_rules_json: String = row.try_get("match_rules")?;
            let path_preference_json: String = row.try_get("path_preference")?;
            let enabled: i32 = row.try_get("enabled")?;

            let match_rules: crate::policy::MatchRules = serde_json::from_str(&match_rules_json)?;
            let path_preference: crate::policy::PathPreference = serde_json::from_str(&path_preference_json)?;

            policies.push(crate::policy::RoutingPolicy {
                id: policy_id as u64,
                name,
                priority: priority as u32,
                match_rules,
                path_preference,
                enabled: enabled != 0,
            });
        }

        Ok(policies)
    }

    /// Delete a routing policy
    pub async fn delete_policy(&self, policy_id: u64) -> Result<()> {
        sqlx::query(
            r#"
            DELETE FROM sdwan_policies
            WHERE policy_id = ?
            "#,
        )
        .bind(policy_id as i64)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Store system-wide metrics snapshot
    pub async fn store_system_metrics(&self, metrics: &crate::metrics::SystemMetrics) -> Result<()> {
        let timestamp = metrics.timestamp
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        sqlx::query(
            r#"
            INSERT INTO sdwan_system_metrics (
                timestamp, throughput_mbps, packets_per_second, active_flows,
                avg_latency_ms, avg_packet_loss, cpu_usage, memory_usage
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(timestamp)
        .bind(metrics.throughput_mbps)
        .bind(metrics.packets_per_second as i64)
        .bind(metrics.active_flows as i64)
        .bind(metrics.avg_latency_ms)
        .bind(metrics.avg_packet_loss)
        .bind(metrics.cpu_usage)
        .bind(metrics.memory_usage)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Get latest system metrics
    pub async fn get_latest_system_metrics(&self) -> Result<crate::metrics::SystemMetrics> {
        let row = sqlx::query(
            r#"
            SELECT timestamp, throughput_mbps, packets_per_second, active_flows,
                   avg_latency_ms, avg_packet_loss, cpu_usage, memory_usage
            FROM sdwan_system_metrics
            ORDER BY timestamp DESC
            LIMIT 1
            "#,
        )
        .fetch_one(&self.pool)
        .await?;

        let timestamp: i64 = row.try_get("timestamp")?;

        Ok(crate::metrics::SystemMetrics {
            timestamp: std::time::UNIX_EPOCH + std::time::Duration::from_secs(timestamp as u64),
            throughput_mbps: row.try_get("throughput_mbps")?,
            packets_per_second: row.try_get::<i64, _>("packets_per_second")? as u64,
            active_flows: row.try_get::<i64, _>("active_flows")? as u64,
            avg_latency_ms: row.try_get("avg_latency_ms")?,
            avg_packet_loss: row.try_get("avg_packet_loss")?,
            cpu_usage: row.try_get("cpu_usage")?,
            memory_usage: row.try_get("memory_usage")?,
            path_metrics: std::collections::HashMap::new(), // Path metrics loaded separately
        })
    }

    /// Get system metrics history over time range
    pub async fn get_system_metrics_history(
        &self,
        from: std::time::SystemTime,
        to: std::time::SystemTime,
    ) -> Result<Vec<crate::metrics::SystemMetrics>> {
        let from_ts = from.duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;
        let to_ts = to.duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;

        let rows = sqlx::query(
            r#"
            SELECT timestamp, throughput_mbps, packets_per_second, active_flows,
                   avg_latency_ms, avg_packet_loss, cpu_usage, memory_usage
            FROM sdwan_system_metrics
            WHERE timestamp >= ? AND timestamp <= ?
            ORDER BY timestamp ASC
            "#,
        )
        .bind(from_ts)
        .bind(to_ts)
        .fetch_all(&self.pool)
        .await?;

        let mut metrics_list = Vec::new();
        for row in rows {
            let timestamp: i64 = row.try_get("timestamp")?;

            metrics_list.push(crate::metrics::SystemMetrics {
                timestamp: std::time::UNIX_EPOCH + std::time::Duration::from_secs(timestamp as u64),
                throughput_mbps: row.try_get("throughput_mbps")?,
                packets_per_second: row.try_get::<i64, _>("packets_per_second")? as u64,
                active_flows: row.try_get::<i64, _>("active_flows")? as u64,
                avg_latency_ms: row.try_get("avg_latency_ms")?,
                avg_packet_loss: row.try_get("avg_packet_loss")?,
                cpu_usage: row.try_get("cpu_usage")?,
                memory_usage: row.try_get("memory_usage")?,
                path_metrics: std::collections::HashMap::new(),
            });
        }

        Ok(metrics_list)
    }

    /// Clean up old metrics data (retention policy)
    pub async fn cleanup_old_metrics(&self, older_than: std::time::SystemTime) -> Result<u64> {
        let timestamp = older_than.duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;

        // Clean up path metrics
        let path_result = sqlx::query(
            r#"
            DELETE FROM sdwan_path_metrics
            WHERE timestamp < ?
            "#,
        )
        .bind(timestamp)
        .execute(&self.pool)
        .await?;

        // Clean up system metrics
        let system_result = sqlx::query(
            r#"
            DELETE FROM sdwan_system_metrics
            WHERE timestamp < ?
            "#,
        )
        .bind(timestamp)
        .execute(&self.pool)
        .await?;

        // Clean up policy stats (Sprint 30)
        let policy_result = sqlx::query(
            r#"
            DELETE FROM sdwan_policy_stats
            WHERE timestamp < ?
            "#,
        )
        .bind(timestamp)
        .execute(&self.pool)
        .await?;

        Ok(path_result.rows_affected() + system_result.rows_affected() + policy_result.rows_affected())
    }

    /// Store policy traffic statistics (Sprint 30)
    pub async fn store_policy_stats(&self, stats: &crate::traffic_stats::PolicyStats) -> Result<()> {
        let timestamp = stats.last_updated
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        sqlx::query(
            r#"
            INSERT INTO sdwan_policy_stats (
                policy_id, timestamp, packets_matched, bytes_matched, active_flows
            )
            VALUES (?, ?, ?, ?, ?)
            "#,
        )
        .bind(stats.policy_id as i64)
        .bind(timestamp)
        .bind(stats.packets_matched as i64)
        .bind(stats.bytes_matched as i64)
        .bind(stats.active_flows as i64)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Get latest policy statistics (Sprint 30)
    pub async fn get_latest_policy_stats(&self, policy_id: u64) -> Result<Option<crate::traffic_stats::PolicyStats>> {
        let row = sqlx::query(
            r#"
            SELECT policy_id, timestamp, packets_matched, bytes_matched, active_flows
            FROM sdwan_policy_stats
            WHERE policy_id = ?
            ORDER BY timestamp DESC
            LIMIT 1
            "#,
        )
        .bind(policy_id as i64)
        .fetch_optional(&self.pool)
        .await?;

        if let Some(row) = row {
            let timestamp: i64 = row.try_get("timestamp")?;

            Ok(Some(crate::traffic_stats::PolicyStats {
                policy_id,
                packets_matched: row.try_get::<i64, _>("packets_matched")? as u64,
                bytes_matched: row.try_get::<i64, _>("bytes_matched")? as u64,
                active_flows: row.try_get::<i64, _>("active_flows")? as u64,
                last_updated: std::time::UNIX_EPOCH + std::time::Duration::from_secs(timestamp as u64),
                first_seen: std::time::UNIX_EPOCH + std::time::Duration::from_secs(timestamp as u64),
            }))
        } else {
            Ok(None)
        }
    }

    /// Get policy statistics history over time range (Sprint 30)
    pub async fn get_policy_stats_history(
        &self,
        policy_id: u64,
        from: std::time::SystemTime,
        to: std::time::SystemTime,
    ) -> Result<Vec<crate::traffic_stats::PolicyStats>> {
        let from_ts = from.duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;
        let to_ts = to.duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;

        let rows = sqlx::query(
            r#"
            SELECT policy_id, timestamp, packets_matched, bytes_matched, active_flows
            FROM sdwan_policy_stats
            WHERE policy_id = ? AND timestamp >= ? AND timestamp <= ?
            ORDER BY timestamp ASC
            "#,
        )
        .bind(policy_id as i64)
        .bind(from_ts)
        .bind(to_ts)
        .fetch_all(&self.pool)
        .await?;

        let mut stats_list = Vec::new();
        for row in rows {
            let timestamp: i64 = row.try_get("timestamp")?;

            stats_list.push(crate::traffic_stats::PolicyStats {
                policy_id,
                packets_matched: row.try_get::<i64, _>("packets_matched")? as u64,
                bytes_matched: row.try_get::<i64, _>("bytes_matched")? as u64,
                active_flows: row.try_get::<i64, _>("active_flows")? as u64,
                last_updated: std::time::UNIX_EPOCH + std::time::Duration::from_secs(timestamp as u64),
                first_seen: std::time::UNIX_EPOCH + std::time::Duration::from_secs(timestamp as u64),
            });
        }

        Ok(stats_list)
    }

    /// Delete a site and cascade to related records (Sprint 30)
    pub async fn delete_site(&self, site_id: &SiteId) -> Result<u64> {
        // Start a transaction
        let mut tx = self.pool.begin().await?;

        // Delete paths where this site is source or destination
        let paths_result = sqlx::query(
            r#"
            DELETE FROM sdwan_paths
            WHERE src_site_id = ? OR dst_site_id = ?
            "#,
        )
        .bind(site_id.to_string())
        .bind(site_id.to_string())
        .execute(&mut *tx)
        .await?;

        // Delete endpoints
        let endpoints_result = sqlx::query(
            r#"
            DELETE FROM sdwan_endpoints
            WHERE site_id = ?
            "#,
        )
        .bind(site_id.to_string())
        .execute(&mut *tx)
        .await?;

        // Delete the site
        let site_result = sqlx::query(
            r#"
            DELETE FROM sdwan_sites
            WHERE site_id = ?
            "#,
        )
        .bind(site_id.to_string())
        .execute(&mut *tx)
        .await?;

        // Commit transaction
        tx.commit().await?;

        Ok(paths_result.rows_affected() + endpoints_result.rows_affected() + site_result.rows_affected())
    }

    /// Count paths associated with a site (Sprint 30)
    pub async fn count_site_paths(&self, site_id: &SiteId) -> Result<i64> {
        let row = sqlx::query(
            r#"
            SELECT COUNT(*) as count
            FROM sdwan_paths
            WHERE src_site_id = ? OR dst_site_id = ?
            "#,
        )
        .bind(site_id.to_string())
        .bind(site_id.to_string())
        .fetch_one(&self.pool)
        .await?;

        Ok(row.try_get("count")?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::SystemTime;

    #[tokio::test]
    async fn test_database_creation() {
        let db = Database::new(":memory:").await;
        assert!(db.is_ok());
    }

    #[tokio::test]
    async fn test_site_storage() {
        let db = Database::new(":memory:").await.unwrap();

        let site = Site {
            id: SiteId::generate(),
            name: "test-site".to_string(),
            public_key: vec![1, 2, 3, 4],
            endpoints: Vec::new(),
            created_at: SystemTime::now(),
            last_seen: SystemTime::now(),
            status: SiteStatus::Active,
        };

        // Insert site
        db.upsert_site(&site).await.unwrap();

        // Retrieve site
        let retrieved = db.get_site(&site.id).await.unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().name, "test-site");
    }

    #[tokio::test]
    async fn test_list_sites() {
        let db = Database::new(":memory:").await.unwrap();

        // Insert multiple sites
        for i in 0..3 {
            let site = Site {
                id: SiteId::generate(),
                name: format!("site-{}", i),
                public_key: vec![i as u8],
                endpoints: Vec::new(),
                created_at: SystemTime::now(),
                last_seen: SystemTime::now(),
                status: SiteStatus::Active,
            };
            db.upsert_site(&site).await.unwrap();
        }

        let sites = db.list_sites().await.unwrap();
        assert_eq!(sites.len(), 3);
    }
}
