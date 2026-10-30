//! `patronus ipdb`: the DB-IP lite country + ASN databases behind the
//! traffic insight (and the GeoIP alias sets). `update` is what the monthly
//! job (`patronus-ipdb.timer`, or `/etc/cron.monthly/patronus-ipdb` on
//! OpenRC) runs; the web UI's feed task and `Refresh` button use the same
//! code. A database that is still fresh is left alone unless `--force`.

use super::apply::open_store;
use patronus_firewall::{asn, feeds};
use std::path::PathBuf;

fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

/// Refresh both databases (when due, or `force`). Fails (exit status 1) when
/// a database could not be refreshed AND is missing; a failed refresh next to
/// an older usable file only warns, the job retries next month.
pub async fn update(db: Option<PathBuf>, force: bool) -> anyhow::Result<()> {
    let store = open_store(db.as_deref()).await?;
    let out = asn::refresh_ip_databases(&store, &feeds::CurlFetcher, force, now()).await;
    let mut missing = vec![];
    for (name, r) in out {
        match r {
            Ok(true) => println!("{name}: updated"),
            Ok(false) => println!("{name}: still fresh, nothing to do (--force downloads anyway)"),
            Err(e) => {
                let present = match name.as_str() {
                    "country" => feeds::geoip_db_path().exists(),
                    _ => asn::asn_db_path().exists(),
                };
                eprintln!(
                    "{name}: refresh failed: {e}{}",
                    if present {
                        " (keeping the older file)"
                    } else {
                        ""
                    }
                );
                if !present {
                    missing.push(name);
                }
            }
        }
    }
    if missing.is_empty() {
        Ok(())
    } else {
        anyhow::bail!("no usable database for: {}", missing.join(", "))
    }
}

/// Where the databases are and how old they are.
pub async fn status(db: Option<PathBuf>) -> anyhow::Result<()> {
    let store = open_store(db.as_deref()).await?;
    let g = feeds::geoip_status(&store).await?;
    let a = asn::asn_status(&store).await?;
    println!(
        "country  {}  {} bytes  updated {:?}  {}",
        feeds::geoip_db_path().display(),
        g.size_bytes,
        g.updated,
        g.status
    );
    println!(
        "asn      {}  {} bytes  updated {:?}  {}",
        asn::asn_db_path().display(),
        a.size_bytes,
        a.updated,
        a.status
    );
    println!("IP geolocation by DB-IP.com (CC BY 4.0)");
    Ok(())
}
