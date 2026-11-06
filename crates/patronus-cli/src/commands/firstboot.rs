//! First-boot LAN seeding for router images (`[firstboot]` in patronus.toml).
//!
//! ```toml
//! [network]
//! lan_interface = "br-lan"
//! wan_interface = "eth1"
//! [firstboot]
//! lan_address = "192.168.1.1/24"   # OpenWrt-style default LAN IP
//! wan_dhcp    = true               # the WAN port is a DHCP client
//! dhcp_start  = "192.168.1.100"    # optional pool (needs the dhcp feature)
//! dhcp_end    = "192.168.1.249"
//! ```
//!
//! Applied once: the `firstboot.lan_seeded` setting records it, after which the
//! store (Interfaces / DHCP pages, the setup wizard) is the single source of truth.

use patronus_config::store::ConfigStore;
use patronus_config::Bootstrap;
use patronus_network::lan::{get_setting, set_setting};
use patronus_network::netconf::{NetConfig, V4Mode};
use std::path::Path;

const SEEDED: &str = "firstboot.lan_seeded";

#[derive(serde::Deserialize, Default)]
struct File {
    #[serde(default)]
    firstboot: Section,
}

#[derive(serde::Deserialize, Default)]
struct Section {
    lan_address: Option<String>,
    /// WAN port gets its address by DHCP (the usual ISP/modem case).
    wan_dhcp: Option<bool>,
    dhcp_start: Option<String>,
    dhcp_end: Option<String>,
}

/// Returns a one-line report when something was seeded.
pub async fn seed_lan(
    store: &ConfigStore,
    bootstrap_path: &Path,
    b: Option<&Bootstrap>,
) -> anyhow::Result<Option<String>> {
    let (Some(b), Ok(text)) = (b, std::fs::read_to_string(bootstrap_path)) else {
        return Ok(None);
    };
    let f: File = toml::from_str(&text).unwrap_or_default();
    let (Some(addr), Some(lan)) = (f.firstboot.lan_address.as_deref(), b.lan.first()) else {
        return Ok(None);
    };
    if get_setting(store, SEEDED).await.ok().flatten().is_some() {
        return Ok(None);
    }
    let net: patronus_network::ipnetwork::IpNetwork = addr
        .parse()
        .map_err(|e| anyhow::anyhow!("[firstboot] lan_address {addr:?}: {e}"))?;
    let mut cfg = NetConfig::load(store)
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    {
        let i = cfg.iface_mut(lan);
        i.role = Some("lan".into());
        i.ipv4_mode = V4Mode::Static;
        i.ipv4 = vec![net];
    }
    if f.firstboot.wan_dhcp == Some(true) {
        if let Some(wan) = b.wan.first() {
            let i = cfg.iface_mut(wan);
            i.role = Some("wan".into());
            i.ipv4_mode = V4Mode::Dhcp;
        }
    }
    cfg.save(store).await.map_err(|e| anyhow::anyhow!("{e}"))?;
    let mut msg = format!("LAN {lan} -> {addr}");
    #[cfg(feature = "dhcp-server")]
    if let (Some(s), Some(e)) = (
        f.firstboot.dhcp_start.as_deref(),
        f.firstboot.dhcp_end.as_deref(),
    ) {
        let ip = addr.split('/').next().unwrap_or("").to_string();
        let pool = patronus_network::dhcp::PoolInput {
            interface: lan.clone(),
            enabled: true,
            range_start: s.into(),
            range_end: e.into(),
            gateway: Some(ip.clone()),
            dns_servers: Some(ip),
            description: Some("first-boot default".into()),
            ..Default::default()
        }
        .validate()
        .map_err(|e| anyhow::anyhow!("{e}"))?;
        patronus_network::dhcp::upsert_pool(store, None, &pool)
            .await
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        msg.push_str(&format!(", DHCP {s}-{e}"));
    }
    #[cfg(not(feature = "dhcp-server"))]
    let _ = (&f.firstboot.dhcp_start, &f.firstboot.dhcp_end);
    set_setting(store, SEEDED, "1")
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    Ok(Some(msg))
}
