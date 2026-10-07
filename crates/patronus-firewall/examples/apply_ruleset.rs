//! Real nftables ruleset harness for CI "firewall live traffic" testing.
//! Drives the ACTUAL patronus_firewall::RuleManager code path (which
//! shells out to the real `nft` binary against the real kernel netfilter
//! subsystem) to install a real ruleset, then idles so the CI driver
//! script can send real traffic at this process's network namespace and
//! observe what actually gets through.
//!
//! This is also the harness used for the filter.rs-class boundary/edge
//! case: it accepts a `--wide-open-cidr-then-narrow` mode that installs
//! a real `0.0.0.0/0` (and `::/0`) CIDR rule ordered before a narrower
//! deny, proving the real nftables evaluation order handles the full-
//! range CIDR correctly (no crash, no incorrect precedence) end to end.
use clap::Parser;
use patronus_core::types::{ChainType, FirewallAction, FirewallRule, PortSpec, Protocol};
use patronus_firewall::RuleManager;

#[derive(Parser, Debug)]
struct Args {
    /// Comma-separated TCP ports to explicitly ACCEPT in the input chain.
    #[arg(long, default_value = "80,443")]
    allow_tcp_ports: String,
    /// CIDR to explicitly ACCEPT in the input chain (e.g. an SD-WAN overlay range).
    #[arg(long)]
    allow_cidr: Option<String>,
    /// CIDR to explicitly DROP in the input chain.
    #[arg(long)]
    deny_cidr: Option<String>,
    /// Edge-case mode: install a real 0.0.0.0/0 allow rule ordered
    /// *before* a narrower deny, to prove nft's real rule-order
    /// evaluation handles the full-range CIDR boundary correctly.
    #[arg(long, default_value_t = false)]
    wide_open_cidr_then_narrow_deny: bool,
    #[arg(long)]
    narrow_deny_cidr: Option<String>,
    #[arg(long, default_value_t = 300)]
    hold_secs: u64,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();

    let mgr = RuleManager::new();
    mgr.initialize().await?;

    let mut rule_no = 0u64;
    let mut next_name = || {
        rule_no += 1;
        format!("ci-rule-{}", rule_no)
    };

    for port_str in args.allow_tcp_ports.split(',').filter(|s| !s.is_empty()) {
        let port: u16 = port_str.trim().parse()?;
        let mut rule = FirewallRule::new(next_name(), ChainType::Input, FirewallAction::Accept);
        rule.protocol = Some(Protocol::Tcp);
        rule.dport = Some(PortSpec::Single(port));
        rule.comment = Some(format!("CI: allow tcp/{}", port));
        mgr.add_filter_rule(rule).await?;
    }

    if let Some(cidr) = &args.allow_cidr {
        let mut rule = FirewallRule::new(next_name(), ChainType::Input, FirewallAction::Accept);
        rule.source = Some(cidr.clone());
        rule.comment = Some(format!("CI: allow cidr {}", cidr));
        mgr.add_filter_rule(rule).await?;
    }

    if let Some(cidr) = &args.deny_cidr {
        let mut rule = FirewallRule::new(next_name(), ChainType::Input, FirewallAction::Drop);
        rule.source = Some(cidr.clone());
        rule.comment = Some(format!("CI: deny cidr {}", cidr));
        mgr.add_filter_rule(rule).await?;
    }

    if args.wide_open_cidr_then_narrow_deny {
        // Real /0 CIDR edge case: ordered FIRST (nft evaluates rules
        // top-to-bottom within a chain), so if /0 handling were broken
        // (e.g. a naive bitshift-based matcher panicking or wrongly
        // matching everything/nothing) this would show up as either a
        // crash here or as the narrower deny below being an incorrect
        // no-op in the real traffic test downstream.
        let mut wide = FirewallRule::new(next_name(), ChainType::Input, FirewallAction::Accept);
        wide.protocol = Some(Protocol::Tcp);
        wide.source = Some("0.0.0.0/0".to_string());
        wide.comment = Some("CI: edge-case /0 accept, ordered first".to_string());
        mgr.add_filter_rule(wide).await?;

        if let Some(narrow) = &args.narrow_deny_cidr {
            let mut deny = FirewallRule::new(next_name(), ChainType::Input, FirewallAction::Drop);
            deny.source = Some(narrow.clone());
            deny.comment = Some(format!("CI: edge-case narrow deny after /0, {}", narrow));
            mgr.add_filter_rule(deny).await?;
        }
    }

    let ruleset = mgr.get_nftables_ruleset().await?;
    println!("RULESET_APPLIED_OK");
    println!("---- real `nft list table` output ----");
    println!("{}", ruleset);
    println!("---- end ruleset ----");

    tokio::time::sleep(std::time::Duration::from_secs(args.hold_secs)).await;
    Ok(())
}
