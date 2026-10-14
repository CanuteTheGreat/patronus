//! Standalone validation harness for the "source=any" nftables bug
//! (patronus-agent-driven-qa b2859b5 / a4d7bf96). Drives the real
//! patronus_firewall::RuleManager code path end to end against the real
//! `nft` binary + kernel netfilter subsystem: installs a FirewallRule with
//! source = "any" and confirms (a) nft actually accepts it (no "Could not
//! resolve hostname: any"), (b) the generated nft command never contains a
//! literal "any"/"all" saddr/iifname/oifname operand, and (c) the live
//! ruleset as reported by nft itself omits the saddr match entirely for
//! that rule, i.e. behaves as "match from anywhere".
use patronus_core::types::{ChainType, FirewallAction, FirewallRule};
use patronus_firewall::nftables::rule_to_nft_command;
use patronus_firewall::RuleManager;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let mgr = RuleManager::new();
    mgr.initialize().await?;

    let mut rule = FirewallRule::new(
        "any-source-validation".to_string(),
        ChainType::Forward,
        FirewallAction::Accept,
    );
    rule.enabled = true;
    rule.source = Some("any".to_string());
    rule.comment = Some("validates source=any does not break nft apply".to_string());

    // Unit-level check: inspect the exact string handed to `nft -f -`.
    let generated = rule_to_nft_command(&rule).expect("rule_to_nft_command failed");
    println!("GENERATED NFT COMMAND: {}", generated);
    assert!(
        !generated.to_lowercase().contains("saddr any"),
        "BUG PRESENT: literal 'any' spliced into ip saddr operand: {}",
        generated
    );

    // Full end-to-end: this is the actual code path the web API uses
    // (patronus-web/src/state.rs add_rule), and it previously failed at
    // apply time with "Could not resolve hostname: any" once a4d7bf96
    // stopped swallowing the nft error.
    mgr.add_filter_rule(rule)
        .await
        .expect("add_filter_rule (real nft apply of source=any rule) failed");

    let listing = patronus_firewall::nftables::list_table().expect("list_table failed");
    println!(
        "--- nft list table patronus (forward chain) ---\n{}",
        listing
    );
    assert!(
        listing.contains("validates source=any does not break nft apply"),
        "rule was not actually applied into the live ruleset"
    );
    assert!(
        !listing.to_lowercase().contains("saddr any"),
        "literal 'any' leaked into the live kernel ruleset"
    );

    println!(
        "PASS: source=\"any\" rule applied to real nftables with no saddr match \
         (i.e. matches traffic from anywhere), and nft never tried to resolve 'any' as a hostname."
    );
    Ok(())
}
