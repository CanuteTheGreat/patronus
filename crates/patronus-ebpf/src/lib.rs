//! Patronus eBPF/XDP Firewall
//!
//! Ultra-high-performance packet filtering using eBPF and XDP (eXpress Data Path).
//!
//! ## Why This Is Revolutionary
//!
//! FreeBSD (pfSense/OPNsense) CAN'T do this! This is a Linux-exclusive advantage:
//!
//! - **10-100x faster** than traditional firewalls
//! - Processes packets in kernel space BEFORE network stack
//! - DDoS mitigation at wire speed
//! - Programmable packet filtering with C/Rust
//! - Zero-copy packet processing
//! - Per-CPU scaling
//!
//! ## Performance
//!
//! - Traditional firewall: ~1-5 Gbps
//! - nftables: ~10-20 Gbps
//! - **eBPF/XDP: 50-100 Gbps** on commodity hardware!
//!
//! ## Use Cases
//!
//! 1. DDoS mitigation at ISP scale
//! 2. High-frequency trading networks
//! 3. CDN edge servers
//! 4. Cloud provider infrastructure
//! 5. 100G+ datacenter networks

pub mod xdp;
pub mod maps;
pub mod programs;
pub mod stats;
pub mod sdwan;

pub use xdp::{XdpFirewall, XdpMode, XdpAction};
pub use maps::{BpfMap, MapType};
pub use programs::FirewallProgram;
pub use stats::XdpStats;
pub use sdwan::{SdwanFastPath, TunnelEndpoint, LinkMetrics};
