//! GitOps for web accounts and RBAC groups (`kind: User`, `kind: Group`).
//!
//! Accounts and groups are rows of `web_users`, `rbac_groups` and
//! `rbac_members` that patronus-web reads at login and on every request, so
//! "applying" them is just writing the rows: [`AccountsApplier`] has nothing
//! to push to the system. Resource names are the account / group names.
//!
//! ```yaml
//! - apiVersion: patronus.firewall/v1
//!   kind: User
//!   metadata: { name: alice }
//!   spec:
//!     role: operator                      # admin | operator | readonly
//!     password_hash: "$argon2id$v=19$..." # `patronus users hash-password`; kept when omitted
//!     enabled: true
//!     groups: [vpn-admins]                # at most one RBAC group
//! - apiVersion: patronus.firewall/v1
//!   kind: Group
//!   metadata: { name: vpn-admins }
//!   spec:
//!     description: manage VPNs
//!     privileges: { vpn: write, dashboard: read }
//! ```
//!
//! Only the password *hash* goes into git. The last enabled admin is never
//! deleted, demoted or disabled by a repository; an account that does not
//! exist yet needs a hash.

use crate::applier::{Applier, ApplyReport, Phase};
use crate::declarative::{spec_value, DeclarativeConfig, ResourceKind};
use crate::store::ConfigStore;
use async_trait::async_trait;
use patronus_core::{Error, Result};
use serde::Deserialize;
use sqlx::Row;
use std::collections::BTreeMap;

/// Areas a group can grant (mirror of `patronus_web::rbac::AREAS`).
pub const AREAS: &[&str] = &[
    "dashboard",
    "firewall",
    "interfaces",
    "routing",
    "vpn",
    "services",
    "qos",
    "ha",
    "system",
];

fn invalid(m: impl std::fmt::Display) -> Error {
    Error::Config(format!("Invalid {m}"))
}

fn db(what: &'static str) -> impl Fn(sqlx::Error) -> Error {
    move |e| Error::Config(format!("{what}: {e}"))
}

#[derive(Debug, Deserialize)]
struct UserSpec {
    #[serde(default)]
    role: Option<String>,
    #[serde(default)]
    password_hash: Option<String>,
    #[serde(default)]
    enabled: Option<bool>,
    #[serde(default)]
    groups: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct GroupSpec {
    #[serde(default)]
    description: String,
    #[serde(default)]
    privileges: BTreeMap<String, String>,
}

fn check_name(what: &str, n: &str) -> Result<()> {
    if n.is_empty()
        || n.len() > 64
        || !n
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '@' | ' '))
    {
        return Err(invalid(format!(
            "{what} name {n:?}: 1-64 letters, digits, '.', '_', '-', '@' or space"
        )));
    }
    Ok(())
}

/// Accounts and RBAC groups from the repository.
#[derive(Debug, Default, Clone)]
pub struct AccountsApplier;

async fn enabled_admins_except(store: &ConfigStore, username: &str) -> Result<i64> {
    Ok(sqlx::query(
        "SELECT COUNT(*) FROM web_users WHERE role = 'admin' AND enabled = 1 AND username != ?",
    )
    .bind(username)
    .fetch_one(store.pool()?)
    .await
    .map_err(db("count admins"))?
    .get(0))
}

async fn upsert_user(store: &ConfigStore, name: &str, spec: &UserSpec) -> Result<()> {
    check_name("user", name)?;
    let pool = store.pool()?;
    let role = match spec
        .role
        .as_deref()
        .map(str::trim)
        .filter(|r| !r.is_empty())
    {
        Some(r @ ("admin" | "operator" | "readonly")) => Some(r.to_string()),
        Some(r) => return Err(invalid(format!("role {r:?}: admin, operator or readonly"))),
        None => None,
    };
    if let Some(h) = &spec.password_hash {
        if !h.starts_with("$argon2") {
            return Err(invalid(
                "password_hash: an argon2 hash (`patronus users hash-password`), never a password",
            ));
        }
    }
    if spec.groups.len() > 1 {
        return Err(invalid("groups: an account is in at most one group"));
    }
    // resolve the group first: nothing is written for a user that cannot be placed
    let gid: Option<i64> = match spec.groups.first() {
        Some(g) => {
            let gid: Option<i64> = sqlx::query_scalar("SELECT id FROM rbac_groups WHERE name = ?")
                .bind(g)
                .fetch_optional(pool)
                .await
                .map_err(db("read rbac_groups"))?;
            Some(gid.ok_or_else(|| {
                invalid(format!(
                    "user {name}: group {g:?} does not exist (declare it as a Group)"
                ))
            })?)
        }
        None => None,
    };
    let now = chrono::Utc::now().timestamp();
    let cur: Option<(i64, String, i64)> =
        sqlx::query_as("SELECT id, role, enabled FROM web_users WHERE username = ?")
            .bind(name)
            .fetch_optional(pool)
            .await
            .map_err(db("read web_users"))?;
    let id = match cur {
        Some((id, cur_role, cur_enabled)) => {
            let new_role = role.clone().unwrap_or(cur_role.clone());
            let new_enabled = spec.enabled.unwrap_or(cur_enabled != 0);
            if cur_role == "admin"
                && cur_enabled != 0
                && (new_role != "admin" || !new_enabled)
                && enabled_admins_except(store, name).await? == 0
            {
                return Err(invalid(format!(
                    "change: {name} is the last enabled admin and cannot be demoted or disabled"
                )));
            }
            sqlx::query("UPDATE web_users SET role = ?, enabled = ?, updated_at = ? WHERE id = ?")
                .bind(&new_role)
                .bind(new_enabled as i64)
                .bind(now)
                .bind(id)
                .execute(pool)
                .await
                .map_err(db("update web_users"))?;
            if let Some(h) = &spec.password_hash {
                sqlx::query("UPDATE web_users SET password_hash = ? WHERE id = ?")
                    .bind(h)
                    .bind(id)
                    .execute(pool)
                    .await
                    .map_err(db("update password"))?;
            }
            id
        }
        None => {
            let Some(h) = &spec.password_hash else {
                return Err(invalid(format!(
                    "user {name}: a new account needs password_hash"
                )));
            };
            sqlx::query(
                "INSERT INTO web_users (username, password_hash, role, enabled, created_at, updated_at)
                 VALUES (?, ?, ?, ?, ?, ?)",
            )
            .bind(name)
            .bind(h)
            .bind(role.unwrap_or_else(|| "readonly".into()))
            .bind(spec.enabled.unwrap_or(true) as i64)
            .bind(now)
            .bind(now)
            .execute(pool)
            .await
            .map_err(db("insert web_users"))?
            .last_insert_rowid()
        }
    };
    match gid {
        Some(gid) => {
            sqlx::query(
                "INSERT INTO rbac_members (user_id, group_id) VALUES (?, ?)
                 ON CONFLICT(user_id) DO UPDATE SET group_id = excluded.group_id",
            )
            .bind(id)
            .bind(gid)
            .execute(pool)
            .await
            .map_err(db("set membership"))?;
        }
        None => {
            sqlx::query("DELETE FROM rbac_members WHERE user_id = ?")
                .bind(id)
                .execute(pool)
                .await
                .map_err(db("clear membership"))?;
        }
    }
    Ok(())
}

async fn upsert_group(store: &ConfigStore, name: &str, spec: &GroupSpec) -> Result<()> {
    check_name("group", name)?;
    for (a, l) in &spec.privileges {
        if !AREAS.contains(&a.as_str()) {
            return Err(invalid(format!("privilege area {a:?}")));
        }
        if l != "read" && l != "write" {
            return Err(invalid(format!(
                "privilege level {l:?} for {a}: read or write"
            )));
        }
    }
    let privs = serde_json::to_string(&spec.privileges).expect("map serializes");
    sqlx::query(
        "INSERT INTO rbac_groups (name, description, privileges, created_at) VALUES (?, ?, ?, ?)
         ON CONFLICT(name) DO UPDATE SET description = excluded.description,
             privileges = excluded.privileges",
    )
    .bind(name)
    .bind(&spec.description)
    .bind(privs)
    .bind(chrono::Utc::now().timestamp())
    .execute(store.pool()?)
    .await
    .map_err(db("save rbac_groups"))?;
    Ok(())
}

#[async_trait]
impl Applier for AccountsApplier {
    fn name(&self) -> &'static str {
        "accounts"
    }

    fn phase(&self) -> Phase {
        Phase::Services
    }

    async fn apply(&self, store: &ConfigStore) -> Result<ApplyReport> {
        let mut rep = ApplyReport::default();
        let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM web_users")
            .fetch_one(store.pool()?)
            .await
            .map_err(db("count web_users"))?;
        rep.applied(format!(
            "{n} web account(s); patronus-web reads them from the store at login"
        ));
        Ok(rep)
    }

    async fn render(&self, store: &ConfigStore) -> Result<String> {
        let rows = sqlx::query("SELECT username, role, enabled FROM web_users ORDER BY username")
            .fetch_all(store.pool()?)
            .await
            .map_err(db("read web_users"))?;
        Ok(rows
            .iter()
            .map(|r| {
                format!(
                    "{} {} {}\n",
                    r.get::<String, _>(0),
                    r.get::<String, _>(1),
                    if r.get::<i64, _>(2) != 0 {
                        "enabled"
                    } else {
                        "disabled"
                    }
                )
            })
            .collect())
    }

    fn resource_kinds(&self) -> &'static [ResourceKind] {
        &[ResourceKind::User, ResourceKind::Group]
    }

    async fn upsert_resource(&self, store: &ConfigStore, config: &DeclarativeConfig) -> Result<()> {
        let v = spec_value(config)?;
        let name = &config.metadata.name;
        match config.kind {
            ResourceKind::User => {
                let s: UserSpec = serde_json::from_value(v.clone())
                    .map_err(|e| invalid(format!("user {name}: {e}")))?;
                upsert_user(store, name, &s).await
            }
            ResourceKind::Group => {
                let s: GroupSpec = serde_json::from_value(v.clone())
                    .map_err(|e| invalid(format!("group {name}: {e}")))?;
                upsert_group(store, name, &s).await
            }
            _ => Err(invalid("resource kind for the accounts applier")),
        }
    }

    async fn delete_resource(
        &self,
        store: &ConfigStore,
        kind: &ResourceKind,
        name: &str,
    ) -> Result<()> {
        let pool = store.pool()?;
        match kind {
            ResourceKind::User => {
                let cur: Option<(i64, String, i64)> =
                    sqlx::query_as("SELECT id, role, enabled FROM web_users WHERE username = ?")
                        .bind(name)
                        .fetch_optional(pool)
                        .await
                        .map_err(db("read web_users"))?;
                let Some((id, role, enabled)) = cur else {
                    return Ok(());
                };
                if role == "admin" && enabled != 0 && enabled_admins_except(store, name).await? == 0
                {
                    return Err(invalid(format!(
                        "delete: {name} is the last enabled admin; the repository cannot remove it"
                    )));
                }
                sqlx::query("DELETE FROM rbac_members WHERE user_id = ?")
                    .bind(id)
                    .execute(pool)
                    .await
                    .map_err(db("delete membership"))?;
                sqlx::query("DELETE FROM web_users WHERE id = ?")
                    .bind(id)
                    .execute(pool)
                    .await
                    .map_err(db("delete web_users"))?;
                Ok(())
            }
            ResourceKind::Group => {
                let gid: Option<i64> =
                    sqlx::query_scalar("SELECT id FROM rbac_groups WHERE name = ?")
                        .bind(name)
                        .fetch_optional(pool)
                        .await
                        .map_err(db("read rbac_groups"))?;
                if let Some(gid) = gid {
                    sqlx::query("DELETE FROM rbac_members WHERE group_id = ?")
                        .bind(gid)
                        .execute(pool)
                        .await
                        .map_err(db("delete membership"))?;
                    sqlx::query("DELETE FROM rbac_groups WHERE id = ?")
                        .bind(gid)
                        .execute(pool)
                        .await
                        .map_err(db("delete rbac_groups"))?;
                }
                Ok(())
            }
            _ => Err(invalid("resource kind for the accounts applier")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::declarative::ConfigParser;

    fn parse(y: &str) -> Vec<DeclarativeConfig> {
        ConfigParser::parse_yaml(y).unwrap()
    }

    const HASH: &str = "$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHQ$aGFzaGhhc2hoYXNoaGFzaA";

    #[tokio::test]
    async fn users_and_groups_are_written_and_guarded() {
        let s = ConfigStore::open_in_memory().await.unwrap();
        let a = AccountsApplier;
        // the admin the box was installed with
        sqlx::query("INSERT INTO web_users (username, password_hash, role, enabled, created_at, updated_at) VALUES ('admin', 'x', 'admin', 1, 0, 0)")
            .execute(s.pool().unwrap())
            .await
            .unwrap();
        let docs = parse(&format!(
            "- apiVersion: patronus.firewall/v1\n  kind: Group\n  metadata: {{ name: vpn-admins }}\n  spec: {{ description: x, privileges: {{ vpn: write, dashboard: read }} }}\n\
             - apiVersion: patronus.firewall/v1\n  kind: User\n  metadata: {{ name: alice }}\n  spec: {{ role: operator, password_hash: \"{HASH}\", groups: [vpn-admins] }}\n"
        ));
        assert_eq!(docs.len(), 2);
        for d in &docs {
            a.upsert_resource(&s, d).await.unwrap();
        }
        let (role, en, g): (String, i64, String) = sqlx::query_as(
            "SELECT u.role, u.enabled, g.name FROM web_users u JOIN rbac_members m ON m.user_id = u.id JOIN rbac_groups g ON g.id = m.group_id WHERE u.username = 'alice'",
        )
        .fetch_one(s.pool().unwrap())
        .await
        .unwrap();
        assert_eq!(
            (role.as_str(), en, g.as_str()),
            ("operator", 1, "vpn-admins")
        );
        let privs: String =
            sqlx::query_scalar("SELECT privileges FROM rbac_groups WHERE name = 'vpn-admins'")
                .fetch_one(s.pool().unwrap())
                .await
                .unwrap();
        assert!(privs.contains("\"vpn\":\"write\""), "{privs}");
        // an update keeps the hash when none is given and can disable
        let upd = parse("- apiVersion: patronus.firewall/v1\n  kind: User\n  metadata: { name: alice }\n  spec: { role: readonly, enabled: false }\n");
        a.upsert_resource(&s, &upd[0]).await.unwrap();
        let (role, en, h): (String, i64, String) = sqlx::query_as(
            "SELECT role, enabled, password_hash FROM web_users WHERE username = 'alice'",
        )
        .fetch_one(s.pool().unwrap())
        .await
        .unwrap();
        assert_eq!((role.as_str(), en, h.as_str()), ("readonly", 0, HASH));
        let members: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM rbac_members")
            .fetch_one(s.pool().unwrap())
            .await
            .unwrap();
        assert_eq!(members, 0, "no groups listed: membership removed");
        // refusals
        let bad = |y: &str| {
            parse(&format!("- apiVersion: patronus.firewall/v1\n  kind: User\n  metadata: {{ name: {y} }}\n  spec: {{}}\n"))
        };
        for (n, spec) in [
            ("bob", "{ role: operator }"),
            ("bob", "{ role: root, password_hash: \"$argon2id$x\" }"),
            ("bob", "{ password_hash: hunter2 }"),
            ("bob", "{ password_hash: \"$argon2id$x\", groups: [nope] }"),
            ("bob", "{ password_hash: \"$argon2id$x\", groups: [a, b] }"),
            ("bad/name", "{ password_hash: \"$argon2id$x\" }"),
        ] {
            let mut d = bad(n);
            d[0].spec =
                crate::declarative::ResourceSpec::Generic(serde_yaml::from_str(spec).unwrap());
            let e = a.upsert_resource(&s, &d[0]).await.unwrap_err().to_string();
            assert!(e.contains("Invalid"), "{n} {spec}: {e}");
        }
        let g = parse("- apiVersion: patronus.firewall/v1\n  kind: Group\n  metadata: { name: g }\n  spec: { privileges: { nope: write } }\n");
        assert!(a.upsert_resource(&s, &g[0]).await.is_err());
        let g = parse("- apiVersion: patronus.firewall/v1\n  kind: Group\n  metadata: { name: g }\n  spec: { privileges: { vpn: admin } }\n");
        assert!(a.upsert_resource(&s, &g[0]).await.is_err());
        // the last admin is protected
        let demote = parse("- apiVersion: patronus.firewall/v1\n  kind: User\n  metadata: { name: admin }\n  spec: { role: readonly }\n");
        assert!(a.upsert_resource(&s, &demote[0]).await.is_err());
        let off = parse("- apiVersion: patronus.firewall/v1\n  kind: User\n  metadata: { name: admin }\n  spec: { enabled: false }\n");
        assert!(a.upsert_resource(&s, &off[0]).await.is_err());
        assert!(a
            .delete_resource(&s, &ResourceKind::User, "admin")
            .await
            .is_err());
        // deletes
        a.delete_resource(&s, &ResourceKind::User, "alice")
            .await
            .unwrap();
        a.delete_resource(&s, &ResourceKind::Group, "vpn-admins")
            .await
            .unwrap();
        a.delete_resource(&s, &ResourceKind::User, "alice")
            .await
            .unwrap();
        let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM web_users")
            .fetch_one(s.pool().unwrap())
            .await
            .unwrap();
        assert_eq!(n, 1);
    }
}
