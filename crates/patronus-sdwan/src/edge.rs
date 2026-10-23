//! Edge enrollment and configuration distribution for the SD-WAN dashboard.
//!
//! Each Patronus appliance runs an edge agent (`patronus edge run`,
//! `patronus_network::edge`) that enrolls with a one-time token, then pulls
//! the desired overlay configuration (peers, their keys, endpoints, subnets)
//! and reports path measurements. This module is the dashboard's side:
//! enrollment tokens, edge records (overlay address, subnets, credential
//! digest) and the helpers that validate and allocate them. HTTP handlers are
//! in `patronus-dashboard`'s `api/edge.rs`; writes are replicated to the HA
//! nodes as `ReplicatedOp`s.
//!
//! Secrets are never stored: tokens and edge credentials are 256-bit random
//! values, only their SHA-256 digest is kept.

use crate::Result;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use patronus_network::ipnetwork::Ipv4Network;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::{sqlite::SqlitePool, Row};
use std::net::Ipv4Addr;

/// The overlay every edge gets an address from.
pub const OVERLAY: &str = "10.99.0.0/16";
pub const TOKEN_PREFIX: &str = "pedge_enroll_";
pub const CREDENTIAL_PREFIX: &str = "pedge_auth_";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EdgeRecord {
    pub site_id: String,
    /// SHA-256 (hex) of the edge's credential
    pub token_digest: String,
    pub overlay_ip: String,
    /// LAN prefixes behind the edge
    pub subnets: Vec<String>,
    pub listen_port: u16,
    pub enrolled_at: i64,
    pub last_heartbeat: i64,
}

/// 256-bit random secret with a recognisable prefix.
pub fn new_secret(prefix: &str) -> String {
    use rand::RngCore;
    let mut b = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut b);
    format!("{prefix}{}", URL_SAFE_NO_PAD.encode(b))
}

pub fn digest(secret: &str) -> String {
    let d = Sha256::digest(secret.as_bytes());
    d.iter().map(|b| format!("{b:02x}")).collect()
}

/// The next free overlay address (10.99.0.1 upward, skipping network/broadcast).
pub fn allocate_overlay(existing: &[EdgeRecord]) -> Option<Ipv4Addr> {
    let net: Ipv4Network = OVERLAY.parse().ok()?;
    let used: std::collections::HashSet<Ipv4Addr> = existing
        .iter()
        .filter_map(|e| e.overlay_ip.parse().ok())
        .collect();
    let base = u32::from(net.network());
    (1..net.size() - 1)
        .map(|i| Ipv4Addr::from(base + i))
        .find(|a| !used.contains(a))
}

/// Validate the LAN prefixes an edge announces: IPv4 networks (host bits zero),
/// not overlapping the overlay, not overlapping another edge's subnets.
pub fn check_subnets(
    subnets: &[String],
    others: &[EdgeRecord],
    me: Option<&str>,
) -> std::result::Result<Vec<String>, String> {
    let overlay: Ipv4Network = OVERLAY.parse().map_err(|_| "overlay".to_string())?;
    let mut out: Vec<Ipv4Network> = Vec::new();
    for s in subnets {
        let n: Ipv4Network = s
            .trim()
            .parse()
            .map_err(|_| format!("subnet {s:?} is not an IPv4 address/prefix"))?;
        if n.ip() != n.network() {
            return Err(format!(
                "subnet {s:?} has host bits set (use {}/{})",
                n.network(),
                n.prefix()
            ));
        }
        if n.prefix() < 8 || n.prefix() > 30 {
            return Err(format!("subnet {s:?}: prefix length must be 8 to 30"));
        }
        if overlaps(&n, &overlay) {
            return Err(format!("subnet {s:?} overlaps the overlay {OVERLAY}"));
        }
        for o in others.iter().filter(|o| Some(o.site_id.as_str()) != me) {
            for os in &o.subnets {
                if let Ok(on) = os.parse::<Ipv4Network>() {
                    if overlaps(&n, &on) {
                        return Err(format!("subnet {s:?} overlaps {os} of site {}", o.site_id));
                    }
                }
            }
        }
        if out.iter().any(|x| overlaps(x, &n)) {
            return Err(format!(
                "subnet {s:?} overlaps another subnet in the request"
            ));
        }
        out.push(n);
    }
    Ok(out
        .iter()
        .map(|n| format!("{}/{}", n.network(), n.prefix()))
        .collect())
}

fn overlaps(a: &Ipv4Network, b: &Ipv4Network) -> bool {
    a.contains(b.network()) || b.contains(a.network())
}

pub async fn init(pool: &SqlitePool) -> Result<()> {
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS sdwan_edge_tokens (
            token_digest TEXT PRIMARY KEY,
            label TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            used_at INTEGER
        )",
    )
    .execute(pool)
    .await?;
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS sdwan_edges (
            site_id TEXT PRIMARY KEY,
            token_digest TEXT NOT NULL UNIQUE,
            overlay_ip TEXT NOT NULL UNIQUE,
            subnets TEXT NOT NULL,
            listen_port INTEGER NOT NULL,
            enrolled_at INTEGER NOT NULL,
            last_heartbeat INTEGER NOT NULL DEFAULT 0
        )",
    )
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn put_token(
    pool: &SqlitePool,
    digest: &str,
    label: &str,
    created_at: i64,
) -> Result<()> {
    sqlx::query("INSERT OR IGNORE INTO sdwan_edge_tokens (token_digest, label, created_at) VALUES (?, ?, ?)")
        .bind(digest)
        .bind(label)
        .bind(created_at)
        .execute(pool)
        .await?;
    Ok(())
}

/// Is `digest` an unused enrollment token?
pub async fn token_unused(pool: &SqlitePool, digest: &str) -> Result<bool> {
    let r =
        sqlx::query("SELECT 1 FROM sdwan_edge_tokens WHERE token_digest = ? AND used_at IS NULL")
            .bind(digest)
            .fetch_optional(pool)
            .await?;
    Ok(r.is_some())
}

pub async fn consume_token(pool: &SqlitePool, digest: &str, used_at: i64) -> Result<()> {
    sqlx::query(
        "UPDATE sdwan_edge_tokens SET used_at = ? WHERE token_digest = ? AND used_at IS NULL",
    )
    .bind(used_at)
    .bind(digest)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn upsert_edge(pool: &SqlitePool, e: &EdgeRecord) -> Result<()> {
    sqlx::query(
        "INSERT INTO sdwan_edges (site_id, token_digest, overlay_ip, subnets, listen_port, enrolled_at, last_heartbeat)
         VALUES (?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(site_id) DO UPDATE SET
            token_digest = excluded.token_digest, subnets = excluded.subnets,
            listen_port = excluded.listen_port, last_heartbeat = excluded.last_heartbeat",
    )
    .bind(&e.site_id)
    .bind(&e.token_digest)
    .bind(&e.overlay_ip)
    .bind(e.subnets.join(","))
    .bind(i64::from(e.listen_port))
    .bind(e.enrolled_at)
    .bind(e.last_heartbeat)
    .execute(pool)
    .await?;
    Ok(())
}

/// Mark the edge's site seen now (`status`: active / degraded / inactive).
pub async fn touch_site(pool: &SqlitePool, site_id: &str, ts: i64, status: &str) -> Result<()> {
    sqlx::query("UPDATE sdwan_sites SET last_seen = ?, status = ? WHERE site_id = ?")
        .bind(ts)
        .bind(status)
        .bind(site_id)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn delete_edge(pool: &SqlitePool, site_id: &str) -> Result<bool> {
    let r = sqlx::query("DELETE FROM sdwan_edges WHERE site_id = ?")
        .bind(site_id)
        .execute(pool)
        .await?;
    Ok(r.rows_affected() > 0)
}

pub async fn touch_edge(pool: &SqlitePool, site_id: &str, ts: i64) -> Result<()> {
    sqlx::query("UPDATE sdwan_edges SET last_heartbeat = ? WHERE site_id = ?")
        .bind(ts)
        .bind(site_id)
        .execute(pool)
        .await?;
    Ok(())
}

fn row(r: &sqlx::sqlite::SqliteRow) -> EdgeRecord {
    EdgeRecord {
        site_id: r.get(0),
        token_digest: r.get(1),
        overlay_ip: r.get(2),
        subnets: r
            .get::<String, _>(3)
            .split(',')
            .filter(|s| !s.is_empty())
            .map(String::from)
            .collect(),
        listen_port: r.get::<i64, _>(4) as u16,
        enrolled_at: r.get(5),
        last_heartbeat: r.get(6),
    }
}

const COLS: &str =
    "site_id, token_digest, overlay_ip, subnets, listen_port, enrolled_at, last_heartbeat";

pub async fn list_edges(pool: &SqlitePool) -> Result<Vec<EdgeRecord>> {
    let rows = sqlx::query(&format!(
        "SELECT {COLS} FROM sdwan_edges ORDER BY enrolled_at, site_id"
    ))
    .fetch_all(pool)
    .await?;
    Ok(rows.iter().map(row).collect())
}

pub async fn edge_by_digest(pool: &SqlitePool, digest: &str) -> Result<Option<EdgeRecord>> {
    let r = sqlx::query(&format!(
        "SELECT {COLS} FROM sdwan_edges WHERE token_digest = ?"
    ))
    .bind(digest)
    .fetch_optional(pool)
    .await?;
    Ok(r.as_ref().map(row))
}

pub async fn get_edge(pool: &SqlitePool, site_id: &str) -> Result<Option<EdgeRecord>> {
    let r = sqlx::query(&format!("SELECT {COLS} FROM sdwan_edges WHERE site_id = ?"))
        .bind(site_id)
        .fetch_optional(pool)
        .await?;
    Ok(r.as_ref().map(row))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(id: &str, ip: &str, subnets: &[&str]) -> EdgeRecord {
        EdgeRecord {
            site_id: id.into(),
            token_digest: digest(id),
            overlay_ip: ip.into(),
            subnets: subnets.iter().map(|s| s.to_string()).collect(),
            listen_port: 51820,
            enrolled_at: 1,
            last_heartbeat: 0,
        }
    }

    #[test]
    fn secrets_are_random_and_only_their_digest_is_comparable() {
        let a = new_secret(TOKEN_PREFIX);
        let b = new_secret(TOKEN_PREFIX);
        assert!(a.starts_with(TOKEN_PREFIX) && a != b && a.len() > 40);
        assert_eq!(digest("x"), digest("x"));
        assert_ne!(digest("x"), digest("y"));
        assert_eq!(
            digest("abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn overlay_addresses_are_handed_out_in_order_and_reused() {
        assert_eq!(allocate_overlay(&[]).unwrap().to_string(), "10.99.0.1");
        let e = [rec("a", "10.99.0.1", &[]), rec("b", "10.99.0.2", &[])];
        assert_eq!(allocate_overlay(&e).unwrap().to_string(), "10.99.0.3");
        let gap = [rec("a", "10.99.0.1", &[]), rec("c", "10.99.0.3", &[])];
        assert_eq!(allocate_overlay(&gap).unwrap().to_string(), "10.99.0.2");
    }

    #[test]
    fn subnets_are_validated_against_the_overlay_and_other_sites() {
        let other = [rec("b", "10.99.0.2", &["192.168.60.0/24"])];
        assert_eq!(
            check_subnets(&["192.168.50.0/24".into()], &other, None).unwrap(),
            vec!["192.168.50.0/24"]
        );
        for bad in [
            "nope",
            "192.168.50.1/24",
            "10.99.5.0/24",
            "192.168.60.0/25",
            "192.168.0.0/16",
            "0.0.0.0/0",
            "fd00::/64",
        ] {
            assert!(check_subnets(&[bad.into()], &other, None).is_err(), "{bad}");
        }
        // an edge may re-announce its own subnet
        assert!(check_subnets(&["192.168.60.0/24".into()], &other, Some("b")).is_ok());
        assert!(check_subnets(
            &["192.168.50.0/24".into(), "192.168.50.0/25".into()],
            &[],
            None
        )
        .is_err());
    }

    #[tokio::test]
    async fn tokens_are_single_use_and_edges_round_trip() {
        let db = crate::database::Database::new_in_memory().await.unwrap();
        let pool = db.pool();
        init(pool).await.unwrap();
        let t = new_secret(TOKEN_PREFIX);
        put_token(pool, &digest(&t), "lab", 10).await.unwrap();
        assert!(token_unused(pool, &digest(&t)).await.unwrap());
        assert!(!token_unused(pool, &digest("other")).await.unwrap());
        consume_token(pool, &digest(&t), 11).await.unwrap();
        assert!(
            !token_unused(pool, &digest(&t)).await.unwrap(),
            "a token works once"
        );
        let e = rec(
            "site-a",
            "10.99.0.1",
            &["192.168.50.0/24", "192.168.51.0/24"],
        );
        upsert_edge(pool, &e).await.unwrap();
        assert_eq!(
            edge_by_digest(pool, &e.token_digest).await.unwrap(),
            Some(e.clone())
        );
        touch_edge(pool, "site-a", 99).await.unwrap();
        assert_eq!(
            get_edge(pool, "site-a")
                .await
                .unwrap()
                .unwrap()
                .last_heartbeat,
            99
        );
        assert_eq!(list_edges(pool).await.unwrap().len(), 1);
        assert!(delete_edge(pool, "site-a").await.unwrap());
        assert!(!delete_edge(pool, "site-a").await.unwrap());
    }
}
