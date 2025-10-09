//! Database operations for SD-WAN

use crate::{types::*, Error, Result};
use sqlx::{sqlite::SqlitePool, Row};
use tracing::{debug, info};

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
