//! `patronus wifi-event`: what hostapd's `hostapd_cli -a` script runs when a
//! station joins with a Patronus key id (USE=wifi-ap). A device that was
//! pending (created without a MAC) learns its MAC here, becomes active, and the
//! affected appliers run: segmentation (L2), dhcp (reservation), the firewall
//! (the nft binding) and wifi (the PSK entry becomes MAC-bound, live).

use super::apply;
use patronus_config::seg;
use patronus_config::seg_wifi;
use std::net::Ipv4Addr;
use std::path::PathBuf;

/// Appliers a newly bound device needs, in order.
const APPLIERS: &[&str] = &["segmentation", "dhcp", "firewall", "wifi"];

#[cfg(feature = "dhcp-server")]
async fn lease_for(store: &patronus_config::ConfigStore, mac: &str) -> Option<Ipv4Addr> {
    // DHCP follows the association within a moment: look for the lease a few seconds
    for _ in 0..12 {
        if let Ok(ls) =
            patronus_network::dhcp::leases(store, &patronus_network::lan::LanEnv::system()).await
        {
            if let Some(l) = ls.iter().find(|l| {
                l.family == "ipv4" && l.state == "active" && l.mac.eq_ignore_ascii_case(mac)
            }) {
                return l.ip.parse().ok();
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
    None
}

#[cfg(not(feature = "dhcp-server"))]
async fn lease_for(_store: &patronus_config::ConfigStore, _mac: &str) -> Option<Ipv4Addr> {
    None
}

pub async fn event(
    db: Option<PathBuf>,
    iface: String,
    mac: String,
    keyid: String,
) -> anyhow::Result<()> {
    let mac = seg::norm_mac(&mac).map_err(|e| anyhow::anyhow!("{e}"))?;
    let store = apply::open_store(db.as_deref()).await?;
    let Some(id) = seg_wifi::parse_keyid(&keyid) else {
        println!("wifi-event {iface}: key id {keyid:?} is not a Patronus device (ignored)");
        return Ok(());
    };
    let Some(before) = seg::get_device(&store, id)
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?
    else {
        println!("wifi-event {iface}: no device {id} (ignored)");
        return Ok(());
    };
    if before.state == "active" && before.mac.as_deref() == Some(mac.as_str()) {
        let _ = seg::touch(&store, &mac, before.ip4.as_deref().unwrap_or("")).await;
        return Ok(()); // a roam or reconnect of a bound device: nothing to change
    }
    let hint = lease_for(&store, &mac).await;
    let Some(d) = seg_wifi::bind_pending(&store, &keyid, &mac, hint)
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?
    else {
        return Ok(());
    };
    store
        .audit(
            "system",
            "wifi_enrol",
            "seg_device",
            Some(&d.name),
            &serde_json::json!({"mac": mac, "iface": iface, "ip": d.ip4}),
        )
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    println!(
        "wifi-event {iface}: {} joined as {mac}, bound to {}",
        d.name,
        d.ip4.clone().unwrap_or_default()
    );
    let reg = apply::registry();
    for n in APPLIERS {
        if let Some(a) = reg.by_name(n) {
            match a.apply(&store).await {
                Ok(r) => println!("  {n}: {}", r.applied.join("; ")),
                Err(e) => eprintln!("  {n}: {e}"),
            }
        }
    }
    Ok(())
}
