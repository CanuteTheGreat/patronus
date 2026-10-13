//! Firewall command handler
//!
//! Wires the `patronus firewall apply`/`patronus firewall flush`
//! subcommands to the real `patronus-firewall` crate. Before this,
//! `patronus-firewall.service`'s `ExecStart=/usr/bin/patronus firewall
//! apply` / `ExecStop=/usr/bin/patronus firewall flush` referenced CLI
//! subcommands that simply did not exist in `patronus-cli`'s `Commands`
//! enum -- any fresh (re)start of that unit would fail immediately.

use crate::FirewallCommands;
use colored::Colorize;
use patronus_firewall::rules::RuleManager;

pub async fn handle_firewall_command(action: FirewallCommands) -> anyhow::Result<()> {
    let rule_manager = RuleManager::new();

    match action {
        FirewallCommands::Apply => {
            rule_manager
                .initialize()
                .await
                .map_err(|e| anyhow::anyhow!("failed to initialize nftables table/chains: {e}"))?;
            rule_manager
                .apply_all()
                .await
                .map_err(|e| anyhow::anyhow!("failed to apply firewall rules: {e}"))?;
            println!(
                "{} Firewall rules applied ({} filter rule(s), {} NAT rule(s))",
                "✓".green(),
                rule_manager.list_filter_rules().await?.len(),
                rule_manager.list_nat_rules().await?.len(),
            );
        }
        FirewallCommands::Flush => {
            rule_manager
                .flush()
                .await
                .map_err(|e| anyhow::anyhow!("failed to flush firewall rules: {e}"))?;
            println!("{} Firewall rules flushed", "✓".green());
        }
    }

    Ok(())
}
