//! Schema migrations for the config store.
//!
//! Every `migrations/NNNN_<lane>_<description>.sql` file is compiled in by
//! `build.rs` and applied once, in version order, inside its own
//! transaction; applied versions are recorded in `schema_migrations`.
//! Lanes own disjoint version ranges (see [`LANE_RANGES`]) so migrations
//! written in parallel never collide.

use patronus_core::{Error, Result};
use sqlx::sqlite::SqlitePool;
use sqlx::Row;

/// One schema migration.
#[derive(Debug)]
pub struct Migration {
    pub version: u32,
    pub name: &'static str,
    pub sql: &'static str,
}

include!(concat!(env!("OUT_DIR"), "/migrations.rs"));

/// Migration number range owned by each lane (inclusive). A migration
/// outside its lane's range fails the `lane_ranges_are_respected` test.
pub const LANE_RANGES: &[(&str, u32, u32)] = &[
    ("a", 1, 99),      // foundation: store, sysctl, revisions
    ("b", 100, 199),   // firewall & NAT
    ("c", 200, 299),   // interfaces & L2
    ("d", 300, 399),   // LAN services (DHCP/DNS/NTP/DDNS)
    ("e", 400, 499),   // WAN & routing
    ("f", 500, 599),   // VPN
    ("g", 600, 699),   // data-plane HA
    ("h", 700, 799),   // system/admin (users, backups, certs)
    ("i", 800, 899),   // observability & diagnostics
    ("j", 900, 999),   // security services & shaping
    ("k", 1000, 1099), // SD-WAN
    ("m", 1100, 1199), // differentiators (eBPF, AI, GitOps, plugins)
    ("n", 1200, 1299), // stub-elimination pass: RBAC, backups, PD, proxy, OpenVPN, VRF
    ("s", 1300, 1399), // device segmentation: groups, devices, isolation, Wi-Fi credentials, DNS/time policy
];

/// Whether `version` is recorded in `schema_migrations`, read inside the caller's transaction.
async fn is_applied(conn: &mut sqlx::SqliteConnection, version: u32) -> Result<bool> {
    let count: i64 = sqlx::query("SELECT count(*) FROM schema_migrations WHERE version = ?")
        .bind(version as i64)
        .fetch_one(conn)
        .await
        .map_err(|e| Error::Config(format!("recheck migration {version}: {e}")))?
        .get(0);
    Ok(count > 0)
}

/// Apply every migration that has not been applied yet. Returns the
/// versions applied by this call.
pub async fn run(pool: &SqlitePool) -> Result<Vec<u32>> {
    sqlx::raw_sql(
        "CREATE TABLE IF NOT EXISTS schema_migrations (
             version INTEGER PRIMARY KEY,
             name TEXT NOT NULL,
             applied_at INTEGER NOT NULL
         )",
    )
    .execute(pool)
    .await
    .map_err(|e| Error::Config(format!("create schema_migrations: {e}")))?;

    let applied: Vec<u32> = sqlx::query("SELECT version FROM schema_migrations")
        .fetch_all(pool)
        .await
        .map_err(|e| Error::Config(format!("read schema_migrations: {e}")))?
        .iter()
        .map(|r| r.get::<i64, _>(0) as u32)
        .collect();

    let mut done = Vec::new();
    for m in MIGRATIONS {
        if applied.contains(&m.version) {
            continue;
        }
        // BEGIN IMMEDIATE takes the write lock up front, so a second process
        // opening the same fresh store (web + applyd + CLI after a factory
        // reset) waits here instead of racing to INSERT the same version
        // ("UNIQUE constraint failed: schema_migrations.version").
        let mut tx = pool
            .begin_with("BEGIN IMMEDIATE")
            .await
            .map_err(|e| Error::Config(format!("begin migration {}: {e}", m.version)))?;
        if is_applied(&mut tx, m.version).await? {
            // another process applied it while we waited for the lock
            continue;
        }
        sqlx::raw_sql(m.sql).execute(&mut *tx).await.map_err(|e| {
            Error::Config(format!("migration {:04}_{} failed: {e}", m.version, m.name))
        })?;
        sqlx::query("INSERT INTO schema_migrations (version, name, applied_at) VALUES (?, ?, ?)")
            .bind(m.version as i64)
            .bind(m.name)
            .bind(chrono::Utc::now().timestamp())
            .execute(&mut *tx)
            .await
            .map_err(|e| Error::Config(format!("record migration {}: {e}", m.version)))?;
        tx.commit()
            .await
            .map_err(|e| Error::Config(format!("commit migration {}: {e}", m.version)))?;
        tracing::info!("applied config migration {:04}_{}", m.version, m.name);
        done.push(m.version);
    }
    Ok(done)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Two processes opening one fresh store at once must both succeed (web
    /// and applyd after a console-menu factory reset used to crash with a
    /// UNIQUE constraint failure on schema_migrations.version).
    #[test]
    fn concurrent_first_open_does_not_race() {
        use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions};
        use std::time::Duration;
        let dir = std::env::temp_dir().join(format!("pat-mig-race-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("config.db");
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(6));
        let mut threads = Vec::new();
        for _ in 0..6 {
            let db = db.clone();
            let barrier = barrier.clone();
            threads.push(std::thread::spawn(move || {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap();
                rt.block_on(async {
                    let opts = SqliteConnectOptions::new()
                        .filename(&db)
                        .create_if_missing(true)
                        .journal_mode(SqliteJournalMode::Delete)
                        .busy_timeout(Duration::from_secs(30));
                    let pool = SqlitePoolOptions::new()
                        .max_connections(1)
                        .connect_with(opts)
                        .await
                        .unwrap();
                    barrier.wait();
                    run(&pool).await
                })
            }));
        }
        let mut applied = 0;
        for t in threads {
            applied += t
                .join()
                .unwrap()
                .expect("migration run must not fail")
                .len();
        }
        assert_eq!(
            applied,
            MIGRATIONS.len(),
            "each migration applied exactly once"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The re-check under the write lock is what stops a process that waited for the lock from
    /// applying a migration another process already recorded (the race test above only hits it by
    /// timing), so pin both answers deterministically.
    #[tokio::test]
    async fn is_applied_reflects_schema_migrations() {
        use sqlx::sqlite::SqlitePoolOptions;
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::raw_sql(
            "CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at INTEGER NOT NULL)",
        )
        .execute(&pool)
        .await
        .unwrap();
        let mut conn = pool.acquire().await.unwrap();
        assert!(!is_applied(&mut conn, 7).await.unwrap());
        sqlx::query("INSERT INTO schema_migrations VALUES (7, 'x', 0)")
            .execute(&mut *conn)
            .await
            .unwrap();
        assert!(is_applied(&mut conn, 7).await.unwrap());
        assert!(!is_applied(&mut conn, 8).await.unwrap());
    }

    #[test]
    fn lane_ranges_are_respected() {
        for m in MIGRATIONS {
            let lane = m.name.split('_').next().unwrap_or("");
            let range = LANE_RANGES
                .iter()
                .find(|(l, _, _)| *l == lane)
                .unwrap_or_else(|| {
                    panic!(
                        "migration {:04}_{}: unknown lane {lane:?}",
                        m.version, m.name
                    )
                });
            assert!(
                (range.1..=range.2).contains(&m.version),
                "migration {:04}_{} is outside lane {lane}'s range {}..={}",
                m.version,
                m.name,
                range.1,
                range.2
            );
        }
    }

    #[test]
    fn migrations_are_sorted_and_unique() {
        let v: Vec<u32> = MIGRATIONS.iter().map(|m| m.version).collect();
        let mut s = v.clone();
        s.sort();
        s.dedup();
        assert_eq!(v, s);
        assert!(v.contains(&1) && v.contains(&2));
    }
}
