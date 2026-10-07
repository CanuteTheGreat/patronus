//! Real WireGuard tunnel harness for CI "firewall/SD-WAN live traffic"
//! testing. Drives the ACTUAL patronus_sdwan::peering::PeeringManager
//! code path (the same `ip link add type wireguard` / `wg set` / `ip
//! addr add` commands Patronus itself issues in production) to stand
//! up a real kernel WireGuard interface and peer it with a remote site,
//! using a real in-memory sqlite-backed Database and real x25519
//! keypairs - no mocking of the SD-WAN library itself.
//!
//! Usage (must run as root, CAP_NET_ADMIN, with the `wireguard` kernel
//! module available - `ip link add type wireguard` support):
//!   real_wireguard_tunnel --role server --listen-port 51820
//!   real_wireguard_tunnel --role client --listen-port 51821 \
//!       --peer-endpoint <server-ip>:51820 --peer-pubkey-file /shared/server.pub
//!
//! Each side prints its own public key to stdout on a line prefixed
//! "PUBKEY=" so the other side (or the orchestrating CI shell) can wire
//! up the peering without a side channel.
use base64::{engine::general_purpose::STANDARD, Engine};
use clap::Parser;
use patronus_sdwan::database::Database;
use patronus_sdwan::peering::PeeringManager;
use patronus_sdwan::types::{Endpoint, Site, SiteId, SiteStatus};
use std::sync::Arc;
use std::time::SystemTime;

#[derive(Parser, Debug)]
struct Args {
    #[arg(long)]
    role: String,
    #[arg(long)]
    listen_port: u16,
    #[arg(long, default_value = "patronus-wg0")]
    iface: String,
    #[arg(long)]
    peer_endpoint: Option<String>,
    #[arg(long)]
    peer_pubkey_file: Option<String>,
    #[arg(long)]
    own_pubkey_out: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();

    let db = Arc::new(Database::new_in_memory().await?);
    let own_site_id = SiteId::generate();
    let mgr = PeeringManager::new(db, own_site_id, args.iface.clone(), args.listen_port);

    mgr.initialize_interface().await?;

    let pubkey_b64 = STANDARD.encode(mgr.public_key().as_bytes());
    println!("PUBKEY={}", pubkey_b64);
    if let Some(path) = &args.own_pubkey_out {
        std::fs::write(path, &pubkey_b64)?;
    }

    if let (Some(endpoint), Some(pubkey_file)) = (&args.peer_endpoint, &args.peer_pubkey_file) {
        // Wait for the peer's pubkey file to show up (simple file-based
        // rendezvous across the two sibling containers' shared bind mount).
        let mut peer_pubkey_b64 = String::new();
        for _ in 0..60 {
            if let Ok(s) = std::fs::read_to_string(pubkey_file) {
                if !s.trim().is_empty() {
                    peer_pubkey_b64 = s.trim().to_string();
                    break;
                }
            }
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        }
        if peer_pubkey_b64.is_empty() {
            anyhow::bail!("peer pubkey never appeared at {}", pubkey_file);
        }
        let peer_pubkey_bytes = STANDARD.decode(peer_pubkey_b64.as_bytes())?;

        let peer_site = Site {
            id: SiteId::generate(),
            name: format!("peer-of-{}", args.role),
            public_key: peer_pubkey_bytes,
            endpoints: vec![Endpoint {
                address: endpoint.parse()?,
                interface_type: "ci-veth".to_string(),
                cost_per_gb: 0.0,
                reachable: true,
            }],
            created_at: SystemTime::now(),
            last_seen: SystemTime::now(),
            status: SiteStatus::Active,
        };

        mgr.add_peer(&peer_site).await?;
        println!("PEER_ADDED={}", endpoint);
    }

    // Print the real interface state so the CI log has hard evidence
    // this is a genuine kernel WireGuard interface, not a stub.
    let ip_out = std::process::Command::new("ip")
        .args(["addr", "show", &args.iface])
        .output()?;
    println!("IFACE_STATE:\n{}", String::from_utf8_lossy(&ip_out.stdout));
    let wg_out = std::process::Command::new("wg").args(["show"]).output()?;
    println!("WG_SHOW:\n{}", String::from_utf8_lossy(&wg_out.stdout));

    // Keep the process (and interface) alive so the CI driver can send
    // real traffic through it before tearing down.
    let hold_secs: u64 = std::env::var("HOLD_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(120);
    tokio::time::sleep(std::time::Duration::from_secs(hold_secs)).await;
    Ok(())
}
