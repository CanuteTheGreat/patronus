//! First-boot defaults: interface roles from `/etc/patronus/patronus.toml`
//! and the safe default ruleset.
//!
//! A fresh Patronus box must route LAN -> WAN and stay manageable without
//! anyone touching the UI first, so on the first `patronus apply` (or the
//! first `patronus-web` start when no boot unit ran, e.g. in a container)
//! the store is seeded with:
//!
//! | rule | origin | what |
//! |---|---|---|
//! | Anti-lockout | system | input, `@mgmt`, tcp 22 + 8443 accept |
//! | Allow LAN to firewall | default | input, `@lan` accept |
//! | Allow LAN to any | default | forward, `@lan` accept |
//! | Outbound NAT | default | postrouting, `@wan` masquerade |
//! | ip_forward v4/v6 | default | `net.ipv4.ip_forward=1`, `net.ipv6.conf.all.forwarding=1` |
//!
//! Everything else -- in particular anything arriving on the WAN -- hits
//! the base ruleset's `policy drop`. Defaults are seeded once (deleting
//! one is respected on the next boot); the anti-lockout rule is a system
//! rule that the API refuses to delete.
//!
//! `@mgmt` is resolved by the firewall applier to the LAN interfaces, or to
//! the WAN if there is no LAN (single-NIC box, like pfSense), or to every
//! interface if no role is assigned at all -- so the box can always be
//! reached to finish setting it up.

use crate::store::{ConfigStore, RuleOrigin};
use patronus_core::types::{
    ChainType, FirewallAction, FirewallRule, NatRule, NatType, PortSpec, Protocol,
};
use patronus_core::{Error, Result};
use std::path::{Path, PathBuf};

/// Installed bootstrap file (written by the installer / catalyst ISO).
pub const DEFAULT_BOOTSTRAP_PATH: &str = "/etc/patronus/patronus.toml";

/// `system_config` key recording that the defaults were seeded.
pub const DEFAULTS_SEEDED_KEY: &str = "defaults_seeded_at";

/// Ports the anti-lockout rule keeps open: SSH and the web UI.
pub const ANTI_LOCKOUT_PORTS: &[u16] = &[22, 8443];

/// The bootstrap file path: `$PATRONUS_BOOTSTRAP` or the default.
pub fn default_bootstrap_path() -> PathBuf {
    std::env::var_os("PATRONUS_BOOTSTRAP")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_BOOTSTRAP_PATH))
}

/// Interface roles read from the `[network]` section of patronus.toml.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Bootstrap {
    pub wan: Vec<String>,
    pub lan: Vec<String>,
}

#[derive(serde::Deserialize, Default)]
struct BootstrapFile {
    #[serde(default)]
    network: NetworkSection,
}

#[derive(serde::Deserialize, Default)]
struct NetworkSection {
    wan_interface: Option<String>,
    lan_interface: Option<String>,
    #[serde(default)]
    wan_interfaces: Vec<String>,
    #[serde(default)]
    lan_interfaces: Vec<String>,
}

impl Bootstrap {
    /// Parse patronus.toml text.
    pub fn parse(text: &str) -> Result<Self> {
        let f: BootstrapFile =
            toml::from_str(text).map_err(|e| Error::Config(format!("patronus.toml: {e}")))?;
        let mut b = Bootstrap {
            wan: f.network.wan_interfaces,
            lan: f.network.lan_interfaces,
        };
        if let Some(w) = f.network.wan_interface {
            b.wan.insert(0, w);
        }
        if let Some(l) = f.network.lan_interface {
            b.lan.insert(0, l);
        }
        b.wan.retain(|s| !s.trim().is_empty());
        b.lan.retain(|s| !s.trim().is_empty());
        b.wan.dedup();
        b.lan.dedup();
        Ok(b)
    }

    /// Load the bootstrap file; `Ok(None)` if it does not exist.
    pub fn load(path: &Path) -> Result<Option<Self>> {
        match std::fs::read_to_string(path) {
            Ok(t) => Self::parse(&t).map(Some),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(Error::Config(format!("read {}: {e}", path.display()))),
        }
    }
}

/// Network interfaces present in the current network namespace
/// (`/sys/class/net`, which `ip netns exec` remounts per namespace).
pub fn existing_interfaces() -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir("/sys/class/net")
        .map(|d| {
            d.filter_map(|e| e.ok())
                .map(|e| e.file_name().to_string_lossy().to_string())
                .collect()
        })
        .unwrap_or_default();
    v.sort();
    v
}

/// What [`ensure_defaults`] changed.
#[derive(Debug, Default, Clone, serde::Serialize)]
pub struct SeedReport {
    pub roles_assigned: Vec<(String, String)>,
    pub defaults_seeded: bool,
    pub warnings: Vec<String>,
}

/// Assign interface roles from the bootstrap file (only while the store has
/// no roles at all -- once roles exist the store wins) and seed the default
/// ruleset once. Safe to call at every boot.
pub async fn ensure_defaults(
    store: &ConfigStore,
    bootstrap: Option<&Bootstrap>,
    existing: &[String],
) -> Result<SeedReport> {
    let mut rep = SeedReport::default();

    if store.interface_roles().await?.is_empty() {
        if let Some(b) = bootstrap {
            for (role, names) in [("wan", &b.wan), ("lan", &b.lan)] {
                for n in names {
                    if existing.iter().any(|e| e == n) {
                        store.set_interface_role(n, Some(role)).await?;
                        rep.roles_assigned.push((n.clone(), role.to_string()));
                    } else {
                        let w = format!(
                            "patronus.toml names {role} interface {n:?}, which does not exist \
                             (present: {}); not assigned",
                            existing.join(", ")
                        );
                        tracing::warn!("{w}");
                        rep.warnings.push(w);
                    }
                }
            }
        }
        if store.interface_roles().await?.is_empty() {
            let w = "no interface has a WAN/LAN role: management access (anti-lockout) is \
                     open on every interface and nothing is forwarded until roles are \
                     assigned ([network] in patronus.toml, or the Interfaces page)"
                .to_string();
            tracing::warn!("{w}");
            rep.warnings.push(w);
        }
    }

    if store
        .load_system_config(DEFAULTS_SEEDED_KEY)
        .await?
        .is_none()
    {
        seed_default_rules(store).await?;
        store
            .save_system_config(DEFAULTS_SEEDED_KEY, &chrono::Utc::now().to_rfc3339())
            .await?;
        store
            .audit(
                "system",
                "seed_defaults",
                "config",
                None,
                &serde_json::json!({"roles": rep.roles_assigned}),
            )
            .await?;
        rep.defaults_seeded = true;
    }
    Ok(rep)
}

/// The default rows (see the module docs).
pub fn default_filter_rules() -> Vec<(FirewallRule, RuleOrigin)> {
    let mut anti = FirewallRule::new(
        "Anti-lockout".into(),
        ChainType::Input,
        FirewallAction::Accept,
    );
    anti.interface_in = Some("@mgmt".into());
    anti.protocol = Some(Protocol::Tcp);
    anti.dport = Some(PortSpec::Multiple(ANTI_LOCKOUT_PORTS.to_vec()));
    anti.comment = Some("Anti-lockout: SSH and web UI from LAN (system rule)".into());

    let mut lan_fw = FirewallRule::new(
        "Allow LAN to firewall".into(),
        ChainType::Input,
        FirewallAction::Accept,
    );
    lan_fw.interface_in = Some("@lan".into());
    lan_fw.comment = Some("Default: LAN may reach the firewall itself".into());

    let mut lan_any = FirewallRule::new(
        "Allow LAN to any".into(),
        ChainType::Forward,
        FirewallAction::Accept,
    );
    lan_any.interface_in = Some("@lan".into());
    lan_any.comment = Some("Default: LAN may reach any destination".into());

    vec![
        (anti, RuleOrigin::System),
        (lan_fw, RuleOrigin::Default),
        (lan_any, RuleOrigin::Default),
    ]
}

/// The default NAT rows.
pub fn default_nat_rules() -> Vec<NatRule> {
    let mut masq = NatRule::new("Outbound NAT".into(), NatType::Masquerade);
    masq.interface_out = Some("@wan".into());
    masq.comment = Some("Default: masquerade everything leaving the WAN".into());
    vec![masq]
}

/// Default sysctls (key, value).
pub const DEFAULT_SYSCTLS: &[(&str, &str)] = &[
    ("net.ipv4.ip_forward", "1"),
    ("net.ipv6.conf.all.forwarding", "1"),
];

async fn seed_default_rules(store: &ConfigStore) -> Result<()> {
    for (rule, origin) in default_filter_rules() {
        store.insert_firewall_rule(&rule, origin).await?;
    }
    for rule in default_nat_rules() {
        store.insert_nat_rule(&rule, RuleOrigin::Default).await?;
    }
    for (k, v) in DEFAULT_SYSCTLS {
        store.set_sysctl(k, v, RuleOrigin::Default).await?;
    }
    tracing::info!("seeded the default ruleset (anti-lockout, LAN->any, outbound NAT, ip_forward)");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_installed_patronus_toml_and_lists() {
        let b = Bootstrap::parse(
            "[system]\nhostname='x'\n[network]\nwan_interface = \"eth0\"\nlan_interface = \"eth1\"\n",
        )
        .unwrap();
        assert_eq!(b.wan, vec!["eth0"]);
        assert_eq!(b.lan, vec!["eth1"]);
        let b = Bootstrap::parse("[network]\nlan_interfaces=['eth1','eth2']\n").unwrap();
        assert!(b.wan.is_empty());
        assert_eq!(b.lan, vec!["eth1", "eth2"]);
        assert_eq!(Bootstrap::parse("").unwrap(), Bootstrap::default());
    }

    #[tokio::test]
    async fn seeds_once_assigns_existing_roles_and_respects_deletions() {
        let s = ConfigStore::open_in_memory().await.unwrap();
        let b = Bootstrap {
            wan: vec!["wan0".into()],
            lan: vec!["lan0".into(), "ghost0".into()],
        };
        let existing = vec!["lo".to_string(), "lan0".into(), "wan0".into()];
        let r = ensure_defaults(&s, Some(&b), &existing).await.unwrap();
        assert!(r.defaults_seeded);
        assert_eq!(r.warnings.len(), 1, "{:?}", r.warnings); // ghost0
        assert_eq!(s.interfaces_with_role("lan").await.unwrap(), vec!["lan0"]);
        assert_eq!(s.interfaces_with_role("wan").await.unwrap(), vec!["wan0"]);
        let rules = s.load_firewall_rules_with_origin().await.unwrap();
        assert_eq!(rules.len(), 3);
        assert_eq!(rules[0].1, RuleOrigin::System);
        assert_eq!(s.load_nat_rules().await.unwrap().len(), 1);
        assert_eq!(s.load_sysctls().await.unwrap().len(), 2);

        // User deletes "Allow LAN to any"; the next boot must not re-add it.
        let lan_any = rules
            .iter()
            .find(|(r, _)| r.name == "Allow LAN to any")
            .unwrap();
        s.delete_firewall_rule(lan_any.0.id.unwrap()).await.unwrap();
        let r = ensure_defaults(&s, Some(&b), &existing).await.unwrap();
        assert!(!r.defaults_seeded);
        assert_eq!(s.load_firewall_rules().await.unwrap().len(), 2);
    }

    #[tokio::test]
    async fn store_roles_win_over_the_bootstrap_file() {
        let s = ConfigStore::open_in_memory().await.unwrap();
        s.set_interface_role("eth5", Some("lan")).await.unwrap();
        let b = Bootstrap {
            wan: vec!["eth0".into()],
            lan: vec!["eth1".into()],
        };
        ensure_defaults(&s, Some(&b), &["eth0".into(), "eth1".into(), "eth5".into()])
            .await
            .unwrap();
        assert_eq!(s.interfaces_with_role("lan").await.unwrap(), vec!["eth5"]);
        assert!(s.interfaces_with_role("wan").await.unwrap().is_empty());
    }
}
