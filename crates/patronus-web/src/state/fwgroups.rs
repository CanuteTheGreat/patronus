//! Interface groups, limiters, overload tables and rule categories in the
//! web process (lane B). Validation, storage and the rendering live in
//! `patronus_firewall::floating` / `nftables`; this adds the edit lock,
//! the live nft updates, the audit trail and the shapes the API returns.

use super::firewall::FirewallManager;
use patronus_firewall::floating::{self, IfGroup, Limiter};
use serde::Serialize;

/// One overload table as shown on the Firewall page.
#[derive(Debug, Clone, Serialize)]
pub struct OverloadTable {
    pub name: String,
    /// Rule ids that feed it.
    pub rules: Vec<u32>,
    /// Blocked sources (IPv4 and IPv6) with the seconds left, if known.
    pub entries: Vec<OverloadEntry>,
}

#[derive(Debug, Clone, Serialize)]
pub struct OverloadEntry {
    pub address: String,
    pub expires_secs: Option<u64>,
}

/// Rows of the "where is this used" lists.
#[derive(Debug, Clone, Serialize)]
pub struct Usage {
    pub rules: Vec<u32>,
}

impl FirewallManager {
    // ---------------------------------------------------------------
    // interface groups
    // ---------------------------------------------------------------

    pub async fn list_groups(&self) -> anyhow::Result<Vec<IfGroup>> {
        floating::load_groups(&self.store).await.map_err(Self::e)
    }

    /// Rule ids that reference `group:NAME`.
    async fn group_users(&self, name: &str) -> anyhow::Result<Vec<u32>> {
        let key = format!("group:{name}");
        Ok(self
            .store
            .load_firewall_rules()
            .await
            .map_err(Self::e)?
            .into_iter()
            .filter(|r| {
                r.interface_in.as_deref() == Some(&key)
                    || r.interface_out.as_deref() == Some(&key)
                    || r.ext.interfaces.iter().any(|i| *i == key)
            })
            .filter_map(|r| r.id.map(|i| i as u32))
            .collect())
    }

    pub async fn save_group(&self, g: IfGroup) -> anyhow::Result<bool> {
        floating::validate_group(&g).map_err(|e| anyhow::anyhow!("Invalid request: {e}"))?;
        let _l = self.edit.lock().await;
        let old = self
            .list_groups()
            .await?
            .into_iter()
            .find(|x| x.name == g.name);
        self.snapshot(format!("save interface group {}", g.name))
            .await?;
        floating::save_group(&self.store, &g)
            .await
            .map_err(Self::e)?;
        // an existing group: swap the members in the live set; a new one
        // needs the set created by a full apply
        let live = if old.is_some() {
            let roles = patronus_firewall::applier::load_roles(&self.store)
                .await
                .map_err(Self::e)?;
            patronus_firewall::nftables::execute_nft_script(&floating::update_group_script(
                &g, &roles,
            ))
            .is_ok()
        } else {
            false
        };
        if !live {
            if let Err(e) = self.push().await {
                match &old {
                    Some(o) => {
                        let _ = floating::save_group(&self.store, o).await;
                    }
                    None => {
                        let _ = floating::delete_group(&self.store, &g.name).await;
                    }
                }
                return Err(e);
            }
        }
        self.audit(
            if old.is_some() { "update" } else { "create" },
            "interface_group",
            &g.name,
            serde_json::to_value(&g).unwrap_or_default(),
        )
        .await;
        Ok(live)
    }

    pub async fn delete_group(&self, name: &str) -> anyhow::Result<()> {
        let _l = self.edit.lock().await;
        let Some(old) = self.list_groups().await?.into_iter().find(|g| g.name == name) else {
            anyhow::bail!("Interface group {name} not found");
        };
        let users = self.group_users(name).await?;
        if !users.is_empty() {
            anyhow::bail!(
                "Invalid request: interface group {name} is used by rule(s) {}",
                users
                    .iter()
                    .map(u32::to_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
        self.snapshot(format!("delete interface group {name}"))
            .await?;
        floating::delete_group(&self.store, name)
            .await
            .map_err(Self::e)?;
        if let Err(e) = self.push().await {
            let _ = floating::save_group(&self.store, &old).await;
            return Err(e);
        }
        self.audit("delete", "interface_group", name, serde_json::Value::Null)
            .await;
        Ok(())
    }

    // ---------------------------------------------------------------
    // limiters
    // ---------------------------------------------------------------

    pub async fn list_limiters(&self) -> anyhow::Result<Vec<Limiter>> {
        floating::load_limiters(&self.store)
            .await
            .map_err(Self::e)
    }

    pub async fn limiter_users(&self, name: &str) -> anyhow::Result<Vec<u32>> {
        Ok(self
            .store
            .load_firewall_rules()
            .await
            .map_err(Self::e)?
            .into_iter()
            .filter(|r| r.ext.limiter.as_deref() == Some(name))
            .filter_map(|r| r.id.map(|i| i as u32))
            .collect())
    }

    pub async fn save_limiter(&self, l: Limiter) -> anyhow::Result<()> {
        floating::validate_limiter(&l).map_err(|e| anyhow::anyhow!("Invalid request: {e}"))?;
        let _g = self.edit.lock().await;
        let old = self
            .list_limiters()
            .await?
            .into_iter()
            .find(|x| x.name == l.name);
        self.snapshot(format!("save limiter {}", l.name)).await?;
        floating::save_limiter(&self.store, &l)
            .await
            .map_err(Self::e)?;
        if let Err(e) = self.push().await {
            match &old {
                Some(o) => {
                    let _ = floating::save_limiter(&self.store, o).await;
                }
                None => {
                    let _ = floating::delete_limiter(&self.store, &l.name).await;
                }
            }
            return Err(e);
        }
        self.audit(
            if old.is_some() { "update" } else { "create" },
            "limiter",
            &l.name,
            serde_json::to_value(&l).unwrap_or_default(),
        )
        .await;
        Ok(())
    }

    pub async fn delete_limiter(&self, name: &str) -> anyhow::Result<()> {
        let _g = self.edit.lock().await;
        let Some(old) = self
            .list_limiters()
            .await?
            .into_iter()
            .find(|l| l.name == name)
        else {
            anyhow::bail!("Limiter {name} not found");
        };
        let users = self.limiter_users(name).await?;
        if !users.is_empty() {
            anyhow::bail!(
                "Invalid request: limiter {name} is used by rule(s) {}",
                users
                    .iter()
                    .map(u32::to_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
        self.snapshot(format!("delete limiter {name}")).await?;
        floating::delete_limiter(&self.store, name)
            .await
            .map_err(Self::e)?;
        if let Err(e) = self.push().await {
            let _ = floating::save_limiter(&self.store, &old).await;
            return Err(e);
        }
        self.audit("delete", "limiter", name, serde_json::Value::Null)
            .await;
        Ok(())
    }

    // ---------------------------------------------------------------
    // overload tables and categories
    // ---------------------------------------------------------------

    /// Overload tables named by rules, with the sources currently in them
    /// (read from the kernel; empty when nft cannot be read).
    pub async fn overload_tables(&self) -> anyhow::Result<Vec<OverloadTable>> {
        let mut by_name: std::collections::BTreeMap<String, Vec<u32>> = Default::default();
        for r in self.store.load_firewall_rules().await.map_err(Self::e)? {
            if let (Some(o), Some(id)) = (&r.ext.overload, r.id) {
                by_name.entry(o.clone()).or_default().push(id as u32);
            }
        }
        Ok(by_name
            .into_iter()
            .map(|(name, rules)| {
                let mut entries = Vec::new();
                for fam in ["v4", "v6"] {
                    entries.extend(read_set_entries(&format!("ov_{name}_{fam}")));
                }
                OverloadTable {
                    name,
                    rules,
                    entries,
                }
            })
            .collect())
    }

    /// Release one source (`Some(addr)`) or every source (`None`) from an
    /// overload table.
    pub async fn release_overload(&self, name: &str, addr: Option<&str>) -> anyhow::Result<()> {
        if !patronus_firewall::nftables::is_valid_alias_name(name) {
            anyhow::bail!("Invalid overload table name {name:?}");
        }
        let sets = [format!("ov_{name}_v4"), format!("ov_{name}_v6")];
        let _g = self.edit.lock().await;
        match addr {
            None => {
                for s in &sets {
                    // a family that has no rule has no set: not an error
                    let _ = patronus_firewall::nftables::execute_nft_command(&[
                        "flush", "set", "inet", "patronus", s,
                    ]);
                }
            }
            Some(a) => {
                let ip: std::net::IpAddr = a
                    .parse()
                    .map_err(|_| anyhow::anyhow!("Invalid address {a:?}"))?;
                let set = if ip.is_ipv4() { &sets[0] } else { &sets[1] };
                patronus_firewall::nftables::execute_nft_command(&[
                    "delete",
                    "element",
                    "inet",
                    "patronus",
                    set,
                    &format!("{{ {ip} }}"),
                ])
                .map_err(Self::e)?;
            }
        }
        self.audit(
            "release",
            "overload",
            name,
            serde_json::json!({ "address": addr }),
        )
        .await;
        Ok(())
    }

    /// Category names in use, with the number of rules in each.
    pub async fn categories(&self) -> anyhow::Result<Vec<(String, usize)>> {
        let mut m: std::collections::BTreeMap<String, usize> = Default::default();
        for r in self.store.load_firewall_rules().await.map_err(Self::e)? {
            if let Some(c) = r.ext.category {
                *m.entry(c).or_default() += 1;
            }
        }
        Ok(m.into_iter().collect())
    }
}

/// Elements of a dynamic set from `nft -j list set`.
fn read_set_entries(set: &str) -> Vec<OverloadEntry> {
    let Ok(out) =
        patronus_firewall::nftables::execute_nft_command(&["-j", "list", "set", "inet", "patronus", set])
    else {
        return Vec::new();
    };
    parse_set_json(&out)
}

pub(crate) fn parse_set_json(json: &str) -> Vec<OverloadEntry> {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(json) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for item in v["nftables"].as_array().into_iter().flatten() {
        for e in item["set"]["elem"].as_array().into_iter().flatten() {
            let (val, exp) = match e {
                serde_json::Value::String(s) => (Some(s.clone()), None),
                o => (
                    o["elem"]["val"].as_str().map(str::to_string),
                    o["elem"]["expires"].as_u64(),
                ),
            };
            if let Some(address) = val {
                out.push(OverloadEntry {
                    address,
                    expires_secs: exp,
                });
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nft_set_json_is_parsed_with_expiry() {
        let j = r#"{"nftables":[{"metainfo":{}},{"set":{"name":"ov_x_v4","elem":[
            {"elem":{"val":"192.0.2.9","timeout":600,"expires":590}}, "192.0.2.10"]}}]}"#;
        let e = parse_set_json(j);
        assert_eq!(e.len(), 2);
        assert_eq!(e[0].address, "192.0.2.9");
        assert_eq!(e[0].expires_secs, Some(590));
        assert_eq!(e[1].address, "192.0.2.10");
        assert!(parse_set_json("not json").is_empty());
        assert!(parse_set_json(r#"{"nftables":[{"set":{"name":"x"}}]}"#).is_empty());
    }
}
