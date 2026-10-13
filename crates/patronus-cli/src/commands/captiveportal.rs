//! Captive portal command handler
//!
//! Wires the `patronus captiveportal serve` subcommand to the real
//! `patronus-captiveportal` crate (guest WiFi auth, vouchers, bandwidth
//! limiting, session management -- 1397 LOC with recent real security
//! fixes: auth-bypass close, MAC-address validation, and passing tests)
//! which had zero runtime usage anywhere in the shipped binaries -- the
//! same "real work stranded, never wired in" pattern `patronus bgp` was
//! fixed for. This starts the actual `CaptivePortal` axum HTTP server
//! (login/voucher/session/admin routes) instead of the crate sitting
//! compiled-but-unreachable.

use colored::Colorize;
use patronus_captiveportal::portal::PortalConfig;
use patronus_captiveportal::CaptivePortal;

pub async fn handle_captiveportal_command(
    addr: Option<String>,
    interface: Option<String>,
) -> anyhow::Result<()> {
    let mut config = PortalConfig {
        enabled: true,
        ..PortalConfig::default()
    };

    if let Some(addr) = addr {
        config.listen_addr = addr
            .parse()
            .map_err(|e| anyhow::anyhow!("invalid --addr '{addr}': {e}"))?;
    }
    if let Some(interface) = interface {
        config.interface = interface;
    }

    println!(
        "{}",
        "Starting Patronus Captive Portal...".bright_blue().bold()
    );
    println!("  Interface:    {}", config.interface);
    println!("  Listening on: http://{}", config.listen_addr);
    println!(
        "  Auth method(s): {:?}, vouchers: {}",
        config.auth_methods, config.enable_vouchers
    );

    let portal = CaptivePortal::new(config)
        .map_err(|e| anyhow::anyhow!("failed to initialize captive portal: {e}"))?;

    portal
        .serve()
        .await
        .map_err(|e| anyhow::anyhow!("captive portal server error: {e}"))?;

    Ok(())
}
