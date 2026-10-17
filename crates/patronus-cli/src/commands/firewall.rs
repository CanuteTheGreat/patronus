//! `patronus firewall apply|flush`
//!
//! `apply` is `patronus apply --phase firewall`: it loads every filter and
//! NAT rule from the config store and loads them as one atomic nftables
//! transaction (it used to build an empty in-memory `RuleManager`, so the
//! boot unit always applied a ruleset with no user rules at all).
//! `flush` removes the Patronus table.

use crate::FirewallCommands;
use colored::Colorize;
use patronus_config::applier::Phase;
use std::path::PathBuf;

use super::apply::{self, ApplyOptions};

pub async fn handle_firewall_command(
    action: FirewallCommands,
    db: Option<PathBuf>,
) -> anyhow::Result<()> {
    match action {
        FirewallCommands::Apply { bootstrap, dry_run } => {
            apply::run(ApplyOptions {
                db,
                bootstrap,
                phases: Some(vec![Phase::Firewall]),
                dry_run,
            })
            .await
        }
        FirewallCommands::Flush => {
            apply::flush_firewall().await?;
            println!("{} Firewall rules flushed", "✓".green());
            Ok(())
        }
    }
}
