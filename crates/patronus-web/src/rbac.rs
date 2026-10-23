//! Groups and privileges (RBAC) for web accounts.
//!
//! A group grants `read` or `write` on named areas of the product
//! (firewall, interfaces, routing, vpn, services, qos, ha, dashboard,
//! system). An account in a group gets exactly the group's privileges
//! instead of what its coarse role would allow; admins ignore groups.
//! Account/key/backup management stays admin-only whatever a group says.
//! Enforcement is in `routes::require_session`, for pages and the API.

use patronus_config::ConfigStore;
use serde::{Deserialize, Serialize};
use sqlx::Row;
use std::collections::BTreeMap;
use std::sync::Arc;

pub const AREAS: &[(&str, &str)] = &[
    ("dashboard", "Dashboard, status, monitoring, events"),
    ("firewall", "Firewall rules, NAT, aliases"),
    ("interfaces", "Interfaces, VLANs, bridges, bonds, PPPoE"),
    ("routing", "Routes, gateways, gateway groups"),
    ("vpn", "WireGuard, IPsec, OpenVPN"),
    ("services", "DHCP, DNS, NTP and other LAN services"),
    ("qos", "Traffic shaping"),
    ("ha", "High availability"),
    ("system", "System settings, updates, service control, power"),
];

/// The area a request path belongs to; `None` = not restricted by groups
/// (login/logout, one's own password and 2FA, static assets).
pub fn area_for_path(path: &str) -> Option<&'static str> {
    if path.starts_with("/static/") || path.starts_with("/api/auth/") || path == "/login" {
        return None;
    }
    let p = path.strip_prefix("/api").unwrap_or(path);
    let first = p.trim_start_matches('/').split('/').next().unwrap_or("");
    Some(match first {
        "" | "status" | "metrics" | "events" | "monitoring" | "telemetry" | "simple" => "dashboard",
        "firewall" => "firewall",
        "interfaces" | "network" => "interfaces",
        "routing" => "routing",
        "vpn" => "vpn",
        "dhcp" | "dns" | "ntp" | "svc" | "lan" => "services",
        "qos" => "qos",
        "ha" => "ha",
        // everything else, including unknown API paths, needs "system"
        _ => "system",
    })
}

#[derive(Debug, Clone, Serialize)]
pub struct Group {
    pub id: i64,
    pub name: String,
    pub description: String,
    pub privileges: BTreeMap<String, String>,
    pub members: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct GroupInput {
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub privileges: BTreeMap<String, String>,
}

/// May a holder of `privs` make a request needing `write` on `area`?
pub fn allows(privs: &BTreeMap<String, String>, area: &str, write: bool) -> bool {
    match privs.get(area).map(String::as_str) {
        Some("write") => true,
        Some("read") => !write,
        _ => false,
    }
}

fn validate(g: &GroupInput) -> anyhow::Result<()> {
    let name = g.name.trim();
    if name.is_empty()
        || name.len() > 64
        || !name
            .chars()
            .all(|c| c.is_alphanumeric() || "-_. ".contains(c))
    {
        anyhow::bail!(
            "Invalid group name {:?}: 1-64 letters, digits, space . - _",
            g.name
        );
    }
    for (a, l) in &g.privileges {
        if !AREAS.iter().any(|(k, _)| k == a) {
            anyhow::bail!("Invalid privilege area {a:?}");
        }
        if l != "read" && l != "write" {
            anyhow::bail!("Invalid privilege level {l:?} for {a}: read or write");
        }
    }
    Ok(())
}

#[derive(Clone)]
pub struct RbacStore {
    store: Arc<ConfigStore>,
}

impl RbacStore {
    pub fn new(store: Arc<ConfigStore>) -> Self {
        Self { store }
    }
    fn pool(&self) -> anyhow::Result<&sqlx::SqlitePool> {
        self.store.pool().map_err(|e| anyhow::anyhow!("{e}"))
    }

    pub async fn list(&self) -> anyhow::Result<Vec<Group>> {
        let pool = self.pool()?;
        let rows =
            sqlx::query("SELECT id, name, description, privileges FROM rbac_groups ORDER BY name")
                .fetch_all(pool)
                .await?;
        let mut out = Vec::new();
        for r in rows {
            let id: i64 = r.get(0);
            let members: Vec<String> = sqlx::query_scalar(
                "SELECT u.username FROM rbac_members m JOIN web_users u ON u.id = m.user_id \
                 WHERE m.group_id = ? ORDER BY u.username",
            )
            .bind(id)
            .fetch_all(pool)
            .await?;
            out.push(Group {
                id,
                name: r.get(1),
                description: r.get(2),
                privileges: serde_json::from_str(&r.get::<String, _>(3)).unwrap_or_default(),
                members,
            });
        }
        Ok(out)
    }

    pub async fn create(&self, g: &GroupInput) -> anyhow::Result<i64> {
        validate(g)?;
        let r = sqlx::query(
            "INSERT INTO rbac_groups (name, description, privileges, created_at) VALUES (?, ?, ?, ?)",
        )
        .bind(g.name.trim())
        .bind(&g.description)
        .bind(serde_json::to_string(&g.privileges)?)
        .bind(chrono::Utc::now().timestamp())
        .execute(self.pool()?)
        .await
        .map_err(|e| {
            if e.to_string().contains("UNIQUE") {
                anyhow::anyhow!("Invalid group name: {:?} exists already", g.name)
            } else {
                e.into()
            }
        })?;
        Ok(r.last_insert_rowid())
    }

    pub async fn update(&self, id: i64, g: &GroupInput) -> anyhow::Result<()> {
        validate(g)?;
        let r = sqlx::query(
            "UPDATE rbac_groups SET name = ?, description = ?, privileges = ? WHERE id = ?",
        )
        .bind(g.name.trim())
        .bind(&g.description)
        .bind(serde_json::to_string(&g.privileges)?)
        .bind(id)
        .execute(self.pool()?)
        .await?;
        if r.rows_affected() == 0 {
            anyhow::bail!("no such group");
        }
        Ok(())
    }

    pub async fn delete(&self, id: i64) -> anyhow::Result<()> {
        let pool = self.pool()?;
        let r = sqlx::query("DELETE FROM rbac_groups WHERE id = ?")
            .bind(id)
            .execute(pool)
            .await?;
        if r.rows_affected() == 0 {
            anyhow::bail!("no such group");
        }
        sqlx::query("DELETE FROM rbac_members WHERE group_id = ?")
            .bind(id)
            .execute(pool)
            .await?;
        Ok(())
    }

    /// Put an account in a group (or take it out with `None`).
    pub async fn set_member(&self, user_id: i64, group: Option<i64>) -> anyhow::Result<()> {
        let pool = self.pool()?;
        match group {
            None => {
                sqlx::query("DELETE FROM rbac_members WHERE user_id = ?")
                    .bind(user_id)
                    .execute(pool)
                    .await?;
            }
            Some(gid) => {
                let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM rbac_groups WHERE id = ?")
                    .bind(gid)
                    .fetch_one(pool)
                    .await?;
                if n == 0 {
                    anyhow::bail!("no such group");
                }
                sqlx::query(
                    "INSERT INTO rbac_members (user_id, group_id) VALUES (?, ?) \
                             ON CONFLICT(user_id) DO UPDATE SET group_id = excluded.group_id",
                )
                .bind(user_id)
                .bind(gid)
                .execute(pool)
                .await?;
            }
        }
        Ok(())
    }

    pub async fn forget_user(&self, user_id: i64) {
        if let Ok(p) = self.pool() {
            let _ = sqlx::query("DELETE FROM rbac_members WHERE user_id = ?")
                .bind(user_id)
                .execute(p)
                .await;
        }
    }

    /// The privileges of the group an account is in; `None` = no group.
    pub async fn privileges_of(&self, user_id: i64) -> Option<BTreeMap<String, String>> {
        let pool = self.pool().ok()?;
        let raw: Option<String> = sqlx::query_scalar(
            "SELECT g.privileges FROM rbac_members m JOIN rbac_groups g ON g.id = m.group_id WHERE m.user_id = ?",
        )
        .bind(user_id)
        .fetch_optional(pool)
        .await
        .ok()?;
        raw.map(|r| serde_json::from_str(&r).unwrap_or_default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_map_to_areas() {
        assert_eq!(area_for_path("/api/firewall/rules"), Some("firewall"));
        assert_eq!(area_for_path("/firewall"), Some("firewall"));
        assert_eq!(area_for_path("/api/dhcp/pools"), Some("services"));
        assert_eq!(area_for_path("/api/system/backups"), Some("system"));
        assert_eq!(area_for_path("/api/unknown-thing"), Some("system"));
        assert_eq!(area_for_path("/"), Some("dashboard"));
        assert_eq!(area_for_path("/api/auth/password"), None);
    }

    #[test]
    fn levels() {
        let mut p = BTreeMap::new();
        p.insert("vpn".to_string(), "read".to_string());
        p.insert("firewall".to_string(), "write".to_string());
        assert!(allows(&p, "vpn", false));
        assert!(!allows(&p, "vpn", true));
        assert!(allows(&p, "firewall", true));
        assert!(!allows(&p, "routing", false));
    }
}
