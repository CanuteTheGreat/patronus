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
];

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
        let mut tx = pool
            .begin()
            .await
            .map_err(|e| Error::Config(format!("begin migration {}: {e}", m.version)))?;
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
