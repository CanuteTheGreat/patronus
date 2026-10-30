//! seg-spike nft <config.json>            -> nftables script on stdout
//! seg-spike hostapd <config.json> <dir>  -> <dir>/hostapd.conf + <dir>/wpa_psk_file
use seg_spike::{render_hostapd, render_nft, Config};
use std::{env, fs, process::exit};

fn main() {
    let a: Vec<String> = env::args().collect();
    if a.len() < 3 {
        eprintln!("usage: seg-spike nft <cfg> | seg-spike hostapd <cfg> <outdir>");
        exit(2);
    }
    let text = fs::read_to_string(&a[2]).unwrap_or_else(|e| {
        eprintln!("{}: {e}", a[2]);
        exit(1)
    });
    let cfg: Config = serde_json::from_str(&text).unwrap_or_else(|e| {
        eprintln!("bad config: {e}");
        exit(1)
    });
    let r = match a[1].as_str() {
        "nft" => render_nft(&cfg).map(|s| print!("{s}")),
        "hostapd" if a.len() == 4 => render_hostapd(&cfg).and_then(|h| {
            fs::create_dir_all(&a[3]).map_err(|e| e.to_string())?;
            fs::write(format!("{}/hostapd.conf", a[3]), h.conf).map_err(|e| e.to_string())?;
            fs::write(format!("{}/wpa_psk_file", a[3]), h.psk_file).map_err(|e| e.to_string())?;
            Ok(())
        }),
        _ => Err("unknown command".into()),
    };
    if let Err(e) = r {
        eprintln!("error: {e}");
        exit(1);
    }
}
