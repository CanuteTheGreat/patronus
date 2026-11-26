//! `patronus interfaces assign|roles`: the WAN / LAN / MGMT / OPT roles in the config store.
//!
//! The roles in patronus.toml are only read at the first boot (once the store has roles, the
//! store wins). The console menu's "Assign interfaces" therefore writes the file AND runs
//! `patronus interfaces assign --from-bootstrap` (installer profile `roles_sync_cmd`), so a
//! reassignment after the first boot really reaches the firewall.

use colored::Colorize;
use patronus_config::defaults::{self, Bootstrap};
use std::path::{Path, PathBuf};

use super::apply;

pub async fn assign(
    db: Option<&Path>,
    from_bootstrap: bool,
    bootstrap: Option<PathBuf>,
    wan: Option<String>,
    lan: Option<String>,
    opt: Vec<String>,
) -> anyhow::Result<()> {
    let store = apply::open_store(db).await?;
    let b = if from_bootstrap {
        let path = bootstrap.unwrap_or_else(defaults::default_bootstrap_path);
        Bootstrap::load(&path)
            .map_err(|e| anyhow::anyhow!("{e}"))?
            .ok_or_else(|| anyhow::anyhow!("{} does not exist", path.display()))?
    } else {
        // --wan/--lan/--opt name only those roles: a dedicated management network
        // (role mgmt, set up by the installer) stays where it is
        let mgmt = store
            .interfaces_with_role("mgmt")
            .await
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        Bootstrap {
            wan: wan.into_iter().collect(),
            lan: lan.into_iter().filter(|l| !l.is_empty()).collect(),
            mgmt,
            opt,
            ..Default::default()
        }
    };
    let actor = std::env::var("SUDO_USER")
        .ok()
        .filter(|u| !u.is_empty())
        .map(|u| format!("console:{u}"))
        .unwrap_or_else(|| "console".into());
    let roles = defaults::reassign_roles(&store, &b, &defaults::existing_interfaces(), &actor)
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    for (iface, role) in &roles {
        println!(
            "{} interface {iface} -> {}",
            "•".cyan(),
            role.to_uppercase()
        );
    }
    Ok(())
}

pub async fn roles(db: Option<&Path>) -> anyhow::Result<()> {
    let store = apply::open_store(db).await?;
    let mut r = store
        .interface_roles()
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    r.sort_by_key(|(_, role)| role_order(role));
    if r.is_empty() {
        println!("(no interface has a role)");
    }
    for (iface, role) in r {
        println!("{:<6} {iface}", role.to_uppercase());
    }
    Ok(())
}

fn role_order(role: &str) -> (u8, u32) {
    match role {
        "wan" => (0, 0),
        "lan" => (1, 0),
        "mgmt" => (2, 0),
        r => (3, r.trim_start_matches("opt").parse().unwrap_or(u32::MAX)),
    }
}

#[cfg(test)]
mod tests {
    use super::role_order;

    #[test]
    fn roles_list_wan_lan_mgmt_then_opt_in_number_order() {
        let mut v = vec!["opt10", "lan", "opt2", "mgmt", "wan", "opt1"];
        v.sort_by_key(|r| role_order(r));
        assert_eq!(v, vec!["wan", "lan", "mgmt", "opt1", "opt2", "opt10"]);
    }
}
