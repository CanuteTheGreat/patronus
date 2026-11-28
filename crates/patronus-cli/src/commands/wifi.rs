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

/// `patronus wifi-chan run NAME`: the automatic-channel service of one Wi-Fi network. Every few seconds it
/// looks whether tonight's re-check is due (the network's `recheck_time`, once a day) or a re-check was
/// requested from the API/UI, and runs it (`WifiApplier::recheck`: samples, hysteresis, CSA).
#[cfg(feature = "wifi-ap")]
pub async fn chan_run(db: Option<PathBuf>, name: String) -> anyhow::Result<()> {
    use chrono::{Datelike, Timelike};
    use patronus_config::seg_wifi_chan;
    use patronus_network::wifichan;
    use patronus_network::wireless::WifiApplier;
    let store = apply::open_store(db.as_deref()).await?;
    let applier = WifiApplier::default();
    let poll = std::time::Duration::from_secs(
        std::env::var("PATRONUS_WIFI_CHAN_POLL")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(15),
    );
    loop {
        if let Ok(Some(n)) = seg_wifi::network_by_name(&store, &name).await {
            if n.enabled && n.channel == 0 {
                if let Ok(Some(st)) = seg_wifi_chan::get_state(&store, n.id).await {
                    let now = chrono::Local::now();
                    let today = i64::from(now.date_naive().num_days_from_ce());
                    let nightly = n.chan.recheck
                        && wifichan::due(
                            now.hour() * 60 + now.minute(),
                            today,
                            &n.chan.recheck_time,
                            st.last_day,
                        );
                    if nightly || st.requested_at.is_some() {
                        match applier.recheck(&store, n.id).await {
                            Ok(m) => println!("wifi-chan {name}: {m}"),
                            Err(e) => eprintln!("wifi-chan {name}: {e}"),
                        }
                        let _ = seg_wifi_chan::mark_checked(&store, n.id, nightly.then_some(today))
                            .await;
                    }
                }
            }
        }
        tokio::time::sleep(poll).await;
    }
}

/// `patronus wifi-chan recheck NAME`: one re-check now (samples, hysteresis, CSA), for a hand run.
#[cfg(feature = "wifi-ap")]
pub async fn chan_recheck(db: Option<PathBuf>, name: String) -> anyhow::Result<()> {
    use patronus_network::wireless::WifiApplier;
    let store = apply::open_store(db.as_deref()).await?;
    let n = seg_wifi::network_by_name(&store, &name)
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?
        .ok_or_else(|| anyhow::anyhow!("no Wi-Fi network {name:?}"))?;
    let m = WifiApplier::default()
        .recheck(&store, n.id)
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    println!("{m}");
    Ok(())
}

/// `patronus wifi-chan status`: the channel of every network and why.
#[cfg(feature = "wifi-ap")]
pub async fn chan_status(db: Option<PathBuf>) -> anyhow::Result<()> {
    use patronus_config::seg_wifi_chan;
    let store = apply::open_store(db.as_deref()).await?;
    for n in seg_wifi::list_networks(&store)
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?
    {
        if n.channel != 0 {
            println!("{}: fixed channel {}", n.name, n.channel);
            continue;
        }
        match seg_wifi_chan::get_state(&store, n.id)
            .await
            .map_err(|e| anyhow::anyhow!("{e}"))?
        {
            Some(s) => println!(
                "{}: automatic, channel {} - {}",
                n.name, s.channel, s.reason
            ),
            None => println!("{}: automatic, not measured yet", n.name),
        }
        for h in seg_wifi_chan::history(&store, n.id, 10)
            .await
            .map_err(|e| anyhow::anyhow!("{e}"))?
        {
            println!("  {} {:<6} {}", h.at, h.event, h.reason);
        }
    }
    Ok(())
}

/// `patronus wifi-chan radios`: radio + hostapd capabilities and every network's effective plan.
#[cfg(feature = "wifi-ap")]
pub async fn radios(db: Option<PathBuf>, as_json: bool) -> anyhow::Result<()> {
    use patronus_network::radio;
    use patronus_network::wireless::WifiApplier;
    let store = apply::open_store(db.as_deref()).await?;
    let a = WifiApplier::default();
    let h = a.hostapd_caps();
    let radios = radio::radios();
    let nets = seg_wifi::list_networks(&store)
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let mut plans = Vec::new();
    for n in &nets {
        // reading a network's radio sets its country's regulatory domain first (as an apply does)
        plans.push(match a.plan_of(n, &h) {
            Ok(p) => serde_json::json!({"network": n.name, "plan": p}),
            Err(e) => serde_json::json!({"network": n.name, "error": e.to_string()}),
        });
    }
    if as_json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({"hostapd": h, "radios": radios, "networks": plans}))?
        );
        return Ok(());
    }
    if h.installed {
        println!(
            "hostapd {}: Wi-Fi 6 {}, Wi-Fi 7 {}, multi-link {}",
            h.version,
            if h.ax { "yes" } else { "no" },
            if h.be { "yes" } else { "no" },
            if h.mld { "yes" } else { "no" }
        );
    } else {
        println!("hostapd: not installed");
    }
    for r in &radios {
        println!("{} ({}): {}", r.phy, r.ifaces.join(", "), r.supports.join(", "));
        for o in &r.offer {
            match &o.reason {
                None => println!(
                    "  {}: up to {} at {} MHz",
                    o.band,
                    o.max_standard,
                    o.widths.iter().max().unwrap_or(&20)
                ),
                Some(why) => println!("  {}: not available: {why}", o.band),
            }
        }
    }
    for p in &plans {
        let name = p["network"].as_str().unwrap_or("");
        if let Some(e) = p["error"].as_str() {
            println!("network {name}: NOT STARTED: {e}");
            continue;
        }
        let pl = &p["plan"];
        println!(
            "network {name}: {} at {} MHz{}",
            pl["standard"].as_str().unwrap_or(""),
            pl["width"],
            pl["links"]
                .as_array()
                .filter(|l| !l.is_empty())
                .map(|l| format!(", multi-link +{} link(s)", l.len()))
                .unwrap_or_default()
        );
        for w in pl["warnings"].as_array().into_iter().flatten() {
            println!("  warning: {}", w.as_str().unwrap_or(""));
        }
        for w in pl["notes"].as_array().into_iter().flatten() {
            println!("  {}", w.as_str().unwrap_or(""));
        }
    }
    Ok(())
}
