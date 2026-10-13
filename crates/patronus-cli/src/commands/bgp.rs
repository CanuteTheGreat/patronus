//! BGP command handlers
//!
//! Wires the `patronus bgp` subcommand to the real `patronus-bgp` crate
//! (RFC 4271 config/manager/neighbor/FSM types) instead of printing
//! hardcoded fake output. State (neighbors + advertised networks) is
//! persisted in a `bgp:` section of the main config.yaml, the same file
//! `patronus init` already seeds with a `bgp: {enabled, asn, router_id}`
//! stub -- this makes that stub actually mean something.

use crate::BgpCommands;
use colored::Colorize;
use patronus_bgp::{BgpConfig, BgpManager, NeighborConfig as BgpNeighborConfig};
use serde::{Deserialize, Serialize};
use std::fs;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;

/// On-disk representation of the `bgp:` section of config.yaml.
///
/// Mirrors (and extends with `neighbors`/`networks`) the stub written by
/// `patronus init` in commands/init.rs.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct BgpSection {
    #[serde(default)]
    enabled: bool,
    #[serde(default)]
    asn: Option<u32>,
    #[serde(default)]
    router_id: Option<String>,
    #[serde(default)]
    neighbors: Vec<PersistedNeighbor>,
    #[serde(default)]
    networks: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedNeighbor {
    address: String,
    asn: u32,
}

/// Local ASN/router-id used when the config file hasn't set one yet.
/// Private-use ASN range (RFC 6996) so this never collides with a real
/// deployment's actual assignment; callers are expected to edit
/// config.yaml's `bgp.asn`/`bgp.router_id` for production use.
const DEFAULT_LOCAL_ASN: u32 = 65000;
const DEFAULT_ROUTER_ID: &str = "0.0.0.0";

fn load_full_config(path: &Path) -> anyhow::Result<serde_yaml::Value> {
    if !path.exists() {
        anyhow::bail!(
            "Config file {} not found. Run `patronus init` first.",
            path.display()
        );
    }
    let content = fs::read_to_string(path)?;
    Ok(serde_yaml::from_str(&content)?)
}

fn extract_bgp_section(doc: &serde_yaml::Value) -> anyhow::Result<BgpSection> {
    match doc.get("bgp") {
        Some(v) => Ok(serde_yaml::from_value(v.clone())?),
        None => Ok(BgpSection::default()),
    }
}

fn save_bgp_section(
    path: &Path,
    mut doc: serde_yaml::Value,
    bgp: &BgpSection,
) -> anyhow::Result<()> {
    let mapping = doc
        .as_mapping_mut()
        .ok_or_else(|| anyhow::anyhow!("config.yaml root is not a mapping"))?;
    mapping.insert(
        serde_yaml::Value::String("bgp".to_string()),
        serde_yaml::to_value(bgp)?,
    );
    fs::write(path, serde_yaml::to_string(&doc)?)?;
    Ok(())
}

/// Build a real patronus_bgp::BgpConfig (and construct a real BgpManager
/// from it) out of the persisted config.yaml bgp section.
fn build_bgp_manager(bgp: &BgpSection) -> anyhow::Result<BgpManager> {
    let router_id = IpAddr::from_str(bgp.router_id.as_deref().unwrap_or(DEFAULT_ROUTER_ID))?;
    let neighbors = bgp
        .neighbors
        .iter()
        .map(|n| -> anyhow::Result<BgpNeighborConfig> {
            Ok(BgpNeighborConfig {
                ip: IpAddr::from_str(&n.address)?,
                asn: n.asn,
                description: None,
                password: None,
                timers: None,
                route_map_in: None,
                route_map_out: None,
                next_hop_self: false,
            })
        })
        .collect::<anyhow::Result<Vec<_>>>()?;

    let networks = bgp
        .networks
        .iter()
        .map(|n| -> anyhow::Result<patronus_bgp::config::NetworkConfig> {
            Ok(patronus_bgp::config::NetworkConfig {
                prefix: n.parse()?,
                route_map: None,
            })
        })
        .collect::<anyhow::Result<Vec<_>>>()?;

    let config = BgpConfig {
        asn: bgp.asn.unwrap_or(DEFAULT_LOCAL_ASN),
        router_id,
        neighbors,
        networks,
        route_maps: vec![],
        timers: Default::default(),
    };

    Ok(BgpManager::new(config))
}

pub async fn handle_bgp_command(action: BgpCommands, config_path: PathBuf) -> anyhow::Result<()> {
    match action {
        BgpCommands::Peer { address, asn } => {
            // Validate the IP eagerly so a bad --address fails before we
            // touch disk.
            IpAddr::from_str(&address)
                .map_err(|e| anyhow::anyhow!("invalid --address '{address}': {e}"))?;

            let doc = load_full_config(&config_path)?;
            let mut bgp = extract_bgp_section(&doc)?;
            bgp.enabled = true;
            if bgp.asn.is_none() {
                bgp.asn = Some(DEFAULT_LOCAL_ASN);
            }
            if bgp.router_id.is_none() {
                bgp.router_id = Some(DEFAULT_ROUTER_ID.to_string());
            }

            if let Some(existing) = bgp.neighbors.iter_mut().find(|n| n.address == address) {
                existing.asn = asn;
            } else {
                bgp.neighbors.push(PersistedNeighbor {
                    address: address.clone(),
                    asn,
                });
            }

            // Round-trip through the real patronus-bgp types before
            // persisting, so a malformed entry is rejected instead of
            // silently written to disk.
            let manager = build_bgp_manager(&bgp)?;

            save_bgp_section(&config_path, doc, &bgp)?;

            println!(
                "{} Configured BGP peer {} (AS{}) in {}",
                "✓".green(),
                address,
                asn,
                config_path.display()
            );
            println!(
                "  Local ASN {} now has {} configured neighbor(s)",
                manager.asn(),
                manager.neighbors().len()
            );
        }

        BgpCommands::Status => {
            let doc = load_full_config(&config_path)?;
            let bgp = extract_bgp_section(&doc)?;

            if !bgp.enabled || bgp.neighbors.is_empty() {
                println!(
                    "{} BGP is not configured (bgp.enabled={}, {} neighbor(s)).",
                    "i".bright_blue(),
                    bgp.enabled,
                    bgp.neighbors.len()
                );
                println!("  Add a peer with: patronus bgp peer --address <ip> --asn <asn>");
                return Ok(());
            }

            let mut manager = build_bgp_manager(&bgp)?;
            println!("BGP Status");
            println!("  Local ASN:   {}", manager.asn());
            println!(
                "  Router ID:   {}",
                bgp.router_id.as_deref().unwrap_or(DEFAULT_ROUTER_ID)
            );
            println!("  Neighbors:   {}", manager.neighbors().len());

            // Drive the real (stubbed, non-networked) FSM transition so
            // the reported state reflects what patronus-bgp actually does
            // today (transitions Idle -> Connect on start()) rather than
            // a fabricated "established" string.
            manager.start().await?;
            for (ip, neighbor) in manager.neighbors() {
                println!(
                    "    - {} (AS{}): {:?}",
                    ip,
                    neighbor.remote_asn(),
                    neighbor.state()
                );
            }
            println!(
                "{}",
                "  Note: real TCP/BGP session establishment is not yet implemented in \
                 patronus-bgp (neighbor.connect() is a stub) -- state reflects FSM \
                 wiring, not a live peering session."
                    .dimmed()
            );
        }

        BgpCommands::Routes => {
            let doc = load_full_config(&config_path)?;
            let bgp = extract_bgp_section(&doc)?;
            let manager = build_bgp_manager(&bgp)?;

            println!("Configured networks (advertised via config):");
            if bgp.networks.is_empty() {
                println!("  (none configured)");
            } else {
                for net in &bgp.networks {
                    println!("  {}", net);
                }
            }

            println!("Learned routes (via established BGP sessions):");
            if manager.routes().is_empty() {
                println!("  (none -- no established sessions; see `patronus bgp status`)");
            } else {
                for route in manager.routes() {
                    println!("  {:?}", route);
                }
            }
        }
    }
    Ok(())
}
