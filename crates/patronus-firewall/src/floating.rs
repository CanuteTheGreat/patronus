//! Floating rules, interface groups and limiters (lane B).
//!
//! * An interface group is a named list of interfaces (device names or
//!   `@role` tokens) rendered as the nft set `ifgrp_<name>` (type ifname).
//!   A rule references it as `group:<name>`; adding a member only changes
//!   the set, never the rule.
//! * A floating rule names several interfaces (and/or groups) and a
//!   direction instead of one interface. Quick floating rules are placed
//!   before the interface rules, non-quick ones after them.
//! * A limiter is a named rate cap a rule can reference.

use crate::nftables::{ifgroup_set_name, is_valid_alias_name, is_valid_interface_name, LimiterSpec};
use patronus_config::store::ConfigStore;
use patronus_core::types::{ChainType, RuleDirection};
use patronus_core::{Error, Result};
use sqlx::Row;

/// Resolved roles: role name -> device names.
pub use crate::applier::Roles;

/// A stored interface group.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct IfGroup {
    #[serde(default)]
    pub name: String,
    /// Device names or `@role` tokens.
    pub members: Vec<String>,
    #[serde(default)]
    pub description: Option<String>,
}

/// A stored limiter.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Limiter {
    /// Taken from the URL on `PUT /limiters/:name`.
    #[serde(default)]
    pub name: String,
    pub rate_kbit: u32,
    #[serde(default = "default_burst")]
    pub burst_kb: u32,
    #[serde(default = "default_per_source")]
    pub per_source: bool,
    #[serde(default)]
    pub description: Option<String>,
}

fn default_burst() -> u32 {
    128
}
fn default_per_source() -> bool {
    true
}

impl Limiter {
    pub fn spec(&self) -> LimiterSpec {
        LimiterSpec {
            rate_kbit: self.rate_kbit,
            burst_kb: self.burst_kb,
            per_source: self.per_source,
        }
    }
}

/// A member is a device name or an `@role` token.
pub fn is_valid_member(m: &str) -> bool {
    match m.strip_prefix('@') {
        Some(r) => patronus_config::store::is_valid_role(&r.to_ascii_lowercase()),
        None => is_valid_interface_name(m),
    }
}

/// Group names become nft set names: same rule as alias names.
pub fn is_valid_group_name(n: &str) -> bool {
    is_valid_alias_name(n)
}

/// Validate a group (name, members) before it is stored.
pub fn validate_group(g: &IfGroup) -> Result<()> {
    if !is_valid_group_name(&g.name) {
        return Err(Error::Firewall(format!(
            "Invalid interface group name {:?} (a letter, then letters, digits or _; at most 31)",
            g.name
        )));
    }
    for m in &g.members {
        if !is_valid_member(m) {
            return Err(Error::Firewall(format!(
                "Invalid interface group member {m:?} (a device name or @role)"
            )));
        }
    }
    Ok(())
}

/// Validate a limiter before it is stored.
pub fn validate_limiter(l: &Limiter) -> Result<()> {
    if !is_valid_alias_name(&l.name) {
        return Err(Error::Firewall(format!(
            "Invalid limiter name {:?} (a letter, then letters, digits or _; at most 31)",
            l.name
        )));
    }
    if l.rate_kbit == 0 || l.rate_kbit > 100_000_000 {
        return Err(Error::Firewall(format!(
            "Invalid limiter rate {} kbit/s",
            l.rate_kbit
        )));
    }
    if l.burst_kb == 0 || l.burst_kb > 1_000_000 {
        return Err(Error::Firewall(format!(
            "Invalid limiter burst {} kB",
            l.burst_kb
        )));
    }
    Ok(())
}

fn db(what: &'static str) -> impl Fn(sqlx::Error) -> Error {
    move |e| Error::Config(format!("{what}: {e}"))
}

pub async fn load_groups(store: &ConfigStore) -> Result<Vec<IfGroup>> {
    let rows = sqlx::query(
        "SELECT name, members, description FROM firewall_interface_groups ORDER BY name",
    )
    .fetch_all(store.pool()?)
    .await
    .map_err(db("load interface groups"))?;
    rows.iter()
        .map(|r| {
            let name: String = r.get(0);
            Ok(IfGroup {
                members: serde_json::from_str(&r.get::<String, _>(1)).map_err(|e| {
                    Error::Config(format!("interface group {name:?}: unreadable members: {e}"))
                })?,
                description: r.get(2),
                name,
            })
        })
        .collect()
}

pub async fn save_group(store: &ConfigStore, g: &IfGroup) -> Result<()> {
    validate_group(g)?;
    sqlx::query(
        "INSERT INTO firewall_interface_groups (name, members, description, updated_at)
         VALUES (?, ?, ?, ?)
         ON CONFLICT(name) DO UPDATE SET members = excluded.members,
             description = excluded.description, updated_at = excluded.updated_at",
    )
    .bind(&g.name)
    .bind(serde_json::to_string(&g.members).unwrap_or_else(|_| "[]".into()))
    .bind(&g.description)
    .bind(chrono::Utc::now().timestamp())
    .execute(store.pool()?)
    .await
    .map_err(db("save interface group"))?;
    Ok(())
}

pub async fn delete_group(store: &ConfigStore, name: &str) -> Result<bool> {
    let r = sqlx::query("DELETE FROM firewall_interface_groups WHERE name = ?")
        .bind(name)
        .execute(store.pool()?)
        .await
        .map_err(db("delete interface group"))?;
    Ok(r.rows_affected() > 0)
}

pub async fn load_limiters(store: &ConfigStore) -> Result<Vec<Limiter>> {
    let rows = sqlx::query(
        "SELECT name, rate_kbit, burst_kb, per_source, description
         FROM firewall_limiters ORDER BY name",
    )
    .fetch_all(store.pool()?)
    .await
    .map_err(db("load limiters"))?;
    Ok(rows
        .iter()
        .map(|r| Limiter {
            name: r.get(0),
            rate_kbit: r.get::<i64, _>(1).clamp(0, u32::MAX as i64) as u32,
            burst_kb: r.get::<i64, _>(2).clamp(0, u32::MAX as i64) as u32,
            per_source: r.get::<i64, _>(3) != 0,
            description: r.get(4),
        })
        .collect())
}

pub async fn save_limiter(store: &ConfigStore, l: &Limiter) -> Result<()> {
    validate_limiter(l)?;
    sqlx::query(
        "INSERT INTO firewall_limiters (name, rate_kbit, burst_kb, per_source, description, updated_at)
         VALUES (?, ?, ?, ?, ?, ?)
         ON CONFLICT(name) DO UPDATE SET rate_kbit = excluded.rate_kbit,
             burst_kb = excluded.burst_kb, per_source = excluded.per_source,
             description = excluded.description, updated_at = excluded.updated_at",
    )
    .bind(&l.name)
    .bind(l.rate_kbit as i64)
    .bind(l.burst_kb as i64)
    .bind(l.per_source as i64)
    .bind(&l.description)
    .bind(chrono::Utc::now().timestamp())
    .execute(store.pool()?)
    .await
    .map_err(db("save limiter"))?;
    Ok(())
}

pub async fn delete_limiter(store: &ConfigStore, name: &str) -> Result<bool> {
    let r = sqlx::query("DELETE FROM firewall_limiters WHERE name = ?")
        .bind(name)
        .execute(store.pool()?)
        .await
        .map_err(db("delete limiter"))?;
    Ok(r.rows_affected() > 0)
}

/// Devices behind a member (`@role` resolved through `roles`).
pub fn member_devices(member: &str, roles: &Roles) -> Vec<String> {
    match member.strip_prefix('@') {
        Some(role) => roles
            .get(&role.to_ascii_lowercase())
            .cloned()
            .unwrap_or_default(),
        None => vec![member.to_string()],
    }
}

/// `add set` + `add element` lines for every group (the set exists even
/// when a group has no member yet, so a rule that names it still loads).
pub fn groups_script(groups: &[IfGroup], roles: &Roles) -> String {
    let mut s = String::new();
    for g in groups {
        let set = ifgroup_set_name(&g.name);
        s.push_str(&format!(
            "add set inet patronus {set} {{ type ifname; comment \"interface group {}\"; }}\n",
            g.name
        ));
        let mut devs: Vec<String> = g
            .members
            .iter()
            .flat_map(|m| member_devices(m, roles))
            .filter(|d| is_valid_interface_name(d))
            .collect();
        devs.sort();
        devs.dedup();
        if !devs.is_empty() {
            let list: Vec<String> = devs.iter().map(|d| format!("\"{d}\"")).collect();
            s.push_str(&format!(
                "add element inet patronus {set} {{ {} }}\n",
                list.join(", ")
            ));
        }
    }
    s
}

/// Replace one group's members in the running set (flush + add element):
/// a member change needs no ruleset reload. Fails if the set is missing
/// (a new group needs a full apply first).
pub fn update_group_script(g: &IfGroup, roles: &Roles) -> String {
    let set = ifgroup_set_name(&g.name);
    let mut s = format!("flush set inet patronus {set}\n");
    let mut devs: Vec<String> = g
        .members
        .iter()
        .flat_map(|m| member_devices(m, roles))
        .filter(|d| is_valid_interface_name(d))
        .collect();
    devs.sort();
    devs.dedup();
    if !devs.is_empty() {
        let list: Vec<String> = devs.iter().map(|d| format!("\"{d}\"")).collect();
        s.push_str(&format!(
            "add element inet patronus {set} {{ {} }}\n",
            list.join(", ")
        ));
    }
    s
}

/// nft interface expressions for a list of selectors (device name, `@role`
/// or `group:NAME`), one per rendered rule: all plain devices share one
/// anonymous set, every group is its own set match. An empty list means
/// "any interface" (one entry, `None`).
pub fn selector_exprs(
    kw: &str,
    selectors: &[String],
    roles: &Roles,
    groups: &[IfGroup],
) -> std::result::Result<Vec<Option<String>>, String> {
    if selectors.is_empty() {
        return Ok(vec![None]);
    }
    let mut devs: Vec<String> = Vec::new();
    let mut sets: Vec<String> = Vec::new();
    for sel in selectors {
        if let Some(g) = sel.strip_prefix("group:") {
            if !groups.iter().any(|x| x.name == g) {
                return Err(format!("unknown interface group {g:?}"));
            }
            let e = format!("{kw} @{}", ifgroup_set_name(g));
            if !sets.contains(&e) {
                sets.push(e);
            }
        } else {
            if !is_valid_member(sel) {
                return Err(format!("invalid interface {sel:?}"));
            }
            devs.extend(member_devices(sel, roles));
        }
    }
    devs.sort();
    devs.dedup();
    let mut out: Vec<Option<String>> = Vec::new();
    if !devs.is_empty() {
        let list: Vec<String> = devs.iter().map(|d| format!("\"{d}\"")).collect();
        out.push(Some(if devs.len() == 1 {
            format!("{kw} {}", list[0])
        } else {
            format!("{kw} {{ {} }}", list.join(", "))
        }));
    }
    out.extend(sets.into_iter().map(Some));
    if out.is_empty() {
        // only unassigned roles: nothing to match
        return Err("none of its interfaces exists".to_string());
    }
    Ok(out)
}

/// (chain, direction keyword) combinations a floating rule renders in.
pub fn floating_hooks(dir: RuleDirection) -> Vec<(ChainType, &'static str)> {
    match dir {
        RuleDirection::In => vec![(ChainType::Input, "iifname"), (ChainType::Forward, "iifname")],
        RuleDirection::Out => vec![
            (ChainType::Output, "oifname"),
            (ChainType::Forward, "oifname"),
        ],
        RuleDirection::Any => vec![
            (ChainType::Input, "iifname"),
            (ChainType::Forward, "iifname"),
            (ChainType::Output, "oifname"),
            (ChainType::Forward, "oifname"),
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roles() -> Roles {
        let mut r = Roles::new();
        r.insert("lan".into(), vec!["eth1".into(), "eth2".into()]);
        r.insert("wan".into(), vec!["eth0".into()]);
        r
    }

    fn group(name: &str, m: &[&str]) -> IfGroup {
        IfGroup {
            name: name.into(),
            members: m.iter().map(|s| s.to_string()).collect(),
            description: None,
        }
    }

    #[test]
    fn group_script_follows_members_and_roles() {
        let s = groups_script(&[group("trusted", &["@lan", "wg0"])], &roles());
        assert!(s.contains("add set inet patronus ifgrp_trusted { type ifname;"));
        assert!(s.contains("add element inet patronus ifgrp_trusted { \"eth1\", \"eth2\", \"wg0\" }"));
        // empty group: the set still exists
        let s = groups_script(&[group("empty", &[])], &roles());
        assert!(s.contains("ifgrp_empty") && !s.contains("add element"));
    }

    #[test]
    fn selectors_mix_devices_roles_and_groups() {
        let g = [group("trusted", &["eth1"])];
        let e = selector_exprs(
            "iifname",
            &["eth9".into(), "@wan".into(), "group:trusted".into()],
            &roles(),
            &g,
        )
        .unwrap();
        assert_eq!(
            e,
            vec![
                Some("iifname { \"eth0\", \"eth9\" }".to_string()),
                Some("iifname @ifgrp_trusted".to_string())
            ]
        );
        assert_eq!(
            selector_exprs("oifname", &[], &roles(), &g).unwrap(),
            vec![None]
        );
        assert!(selector_exprs("iifname", &["group:nope".into()], &roles(), &g).is_err());
        assert!(selector_exprs("iifname", &["a\" }; drop".into()], &roles(), &g).is_err());
        // a role nobody holds matches nothing: refuse instead of widening
        assert!(selector_exprs("iifname", &["@opt3".into()], &roles(), &g).is_err());
    }

    #[test]
    fn validation_refuses_injection_and_nonsense() {
        assert!(validate_group(&group("ok_1", &["eth0", "@lan"])).is_ok());
        assert!(validate_group(&group("bad name", &[])).is_err());
        assert!(validate_group(&group("g", &["eth0\" }"])).is_err());
        let l = Limiter {
            name: "cap".into(),
            rate_kbit: 1000,
            burst_kb: 128,
            per_source: true,
            description: None,
        };
        assert!(validate_limiter(&l).is_ok());
        assert!(validate_limiter(&Limiter { rate_kbit: 0, ..l.clone() }).is_err());
        assert!(validate_limiter(&Limiter { name: "a b".into(), ..l }).is_err());
    }

    #[test]
    fn hooks_by_direction() {
        assert_eq!(floating_hooks(RuleDirection::In).len(), 2);
        assert_eq!(floating_hooks(RuleDirection::Any).len(), 4);
    }
}
