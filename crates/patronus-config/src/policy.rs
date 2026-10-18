//! Policy routing contract between the firewall (lane B) and routing
//! (lane E). A firewall rule's `gateway` names a gateway or gateway group;
//! the firewall marks the packets the rule matches with that name's mark
//! (`meta mark set`), and the routes phase keeps one routing table per
//! gateway / group, numbered like the mark, reached through an
//! `ip rule fwmark <mark> lookup <mark>`.

use crate::store::ConfigStore;
use patronus_core::{Error, Result};
use sqlx::Row;
use std::collections::BTreeMap;

/// Marks / table numbers of gateways: base + `route_gateways.id`.
pub const GATEWAY_MARK_BASE: u32 = 0x1_0000;
/// Marks / table numbers of gateway groups: base + `route_gateway_groups.id`.
pub const GROUP_MARK_BASE: u32 = 0x2_0000;

fn mark(base: u32, id: i64) -> Option<u32> {
    (1..0x1_0000).contains(&id).then(|| base + id as u32)
}

/// The mark (and routing table) of gateway row `id`.
pub fn gateway_mark(id: i64) -> Option<u32> {
    mark(GATEWAY_MARK_BASE, id)
}

/// The mark (and routing table) of gateway group row `id`.
pub fn group_mark(id: i64) -> Option<u32> {
    mark(GROUP_MARK_BASE, id)
}

/// Every gateway and group name with its mark.
pub async fn policy_marks(store: &ConfigStore) -> Result<BTreeMap<String, u32>> {
    let mut out = BTreeMap::new();
    for (table, f) in [
        ("route_gateways", gateway_mark as fn(i64) -> Option<u32>),
        ("route_gateway_groups", group_mark),
    ] {
        let rows = sqlx::query(&format!("SELECT id, name FROM {table}"))
            .fetch_all(store.pool()?)
            .await
            .map_err(|e| Error::Config(format!("read {table}: {e}")))?;
        for r in rows {
            if let Some(m) = f(r.get::<i64, _>(0)) {
                out.insert(r.get::<String, _>(1), m);
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn gateways_and_groups_get_distinct_marks() {
        let s = ConfigStore::open_in_memory().await.unwrap();
        for n in ["A", "B"] {
            sqlx::query(
                "INSERT INTO route_gateways (name, interface, updated_at) VALUES (?, '@wan', 0)",
            )
            .bind(n)
            .execute(s.pool().unwrap())
            .await
            .unwrap();
        }
        sqlx::query("INSERT INTO route_gateway_groups (name, updated_at) VALUES ('G', 0)")
            .execute(s.pool().unwrap())
            .await
            .unwrap();
        let m = policy_marks(&s).await.unwrap();
        assert_eq!(m["A"], 0x1_0001);
        assert_eq!(m["B"], 0x1_0002);
        assert_eq!(m["G"], 0x2_0001);
        assert_eq!(gateway_mark(0), None);
        assert_eq!(gateway_mark(0xffff), Some(0x1_ffff));
        assert_eq!(
            gateway_mark(0x1_0000),
            None,
            "would collide with the group range"
        );
        assert_eq!(group_mark(-1), None);
    }
}
