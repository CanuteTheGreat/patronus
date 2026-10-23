//! `patronus bgp`: the command-line side of the BGP/OSPF page. Sessions and
//! networks live in the config store (the same rows the web UI edits) and are
//! applied by the FRR applier (`/etc/frr/frr.conf`, `/etc/frr/daemons`, restart
//! of the `frr` service); the old in-tree BGP implementation is gone.
//! Needs root (writes /etc/frr, restarts FRR) and USE=dynamic-routing.

use crate::BgpCommands;
use std::path::PathBuf;

#[cfg(not(feature = "dynamic-routing"))]
pub async fn handle_bgp_command(_action: BgpCommands, _db: Option<PathBuf>) -> anyhow::Result<()> {
    anyhow::bail!(
        "this Patronus build has no dynamic routing: rebuild with USE=dynamic-routing \
         (emerge net-firewall/patronus, which pulls in net-misc/frr)"
    )
}

#[cfg(feature = "dynamic-routing")]
pub async fn handle_bgp_command(action: BgpCommands, db: Option<PathBuf>) -> anyhow::Result<()> {
    use colored::Colorize;
    use patronus_config::Applier;
    use patronus_network::frr::{FrrApplier, FrrSvc};
    use patronus_network::svc::{self, Svc};
    use serde_json::json;

    let store = crate::commands::apply::open_store(db.as_deref()).await?;
    let applier = FrrApplier::default();
    match action {
        BgpCommands::Peer {
            address,
            asn,
            local_asn,
            router_id,
        } => {
            let spec = FrrSvc.spec();
            let mut settings = json!({"bgp_enabled": true});
            if let Some(a) = local_asn {
                settings["bgp_asn"] = json!(a);
            }
            if let Some(r) = &router_id {
                settings["router_id"] = json!(r);
            }
            FrrSvc.put(&store, &settings).await?;
            // an existing neighbour with this address is updated
            let rows = svc::raw_rows(&store, &spec.colls[0]).await?;
            let existing = rows
                .iter()
                .find(|r| r["address"].as_str() == Some(address.as_str()))
                .and_then(|r| r["id"].as_i64());
            FrrSvc
                .save_row(
                    &store,
                    "bgp_neighbors",
                    existing,
                    &json!({"address": address, "remote_as": asn}),
                )
                .await?;
            let rep = applier.apply(&store).await?;
            for l in rep.applied.iter().chain(rep.warnings.iter()) {
                println!("  {l}");
            }
            println!(
                "{} BGP neighbour {address} (AS{asn}) configured and applied",
                "✓".green()
            );
        }
        BgpCommands::Status => {
            let st = applier.status(&store).await?;
            if !st["bgp_enabled"].as_bool().unwrap_or(false) {
                println!("BGP is off (add a neighbour: patronus bgp peer --address IP --asn N --router-id IP)");
                return Ok(());
            }
            println!(
                "FRR installed: {}, running: {}",
                st["installed"], st["running"]
            );
            let sessions = st["bgp_sessions"].as_array().cloned().unwrap_or_default();
            if sessions.is_empty() {
                println!("no BGP sessions reported (is FRR running?)");
            }
            for s in sessions {
                println!(
                    "  {:<40} AS{:<10} {:<12} prefixes received: {}",
                    s["peer"].as_str().unwrap_or("?"),
                    s["remote_as"],
                    s["state"].as_str().unwrap_or("?"),
                    s["prefixes_received"]
                );
            }
        }
        BgpCommands::Routes => {
            let st = applier.status(&store).await?;
            let routes = st["kernel_bgp_routes"]
                .as_array()
                .cloned()
                .unwrap_or_default();
            if routes.is_empty() {
                println!("no BGP routes in the kernel routing table");
            }
            for r in routes {
                println!("{}", r.as_str().unwrap_or(""));
            }
        }
    }
    Ok(())
}
