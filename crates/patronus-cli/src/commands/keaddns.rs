//! `patronus kea-ddns`: Kea DDNS (USE=kea-ddns).
//!
//! `run` is the long-lived RFC 2136 receiver (started by the applier as
//! `patronus-daemon@kea-ddns-sink` from a generated JSON file); `show` prints
//! the configuration the stored settings resolve to, secret hidden.

use crate::KeaDdnsCommands;
use std::path::PathBuf;

#[cfg(not(feature = "kea-ddns"))]
pub async fn run(_a: KeaDdnsCommands, _db: Option<PathBuf>) -> anyhow::Result<()> {
    anyhow::bail!("this Patronus build has no Kea DDNS: rebuild with USE=kea-ddns")
}

#[cfg(feature = "kea-ddns")]
pub async fn run(action: KeaDdnsCommands, db: Option<PathBuf>) -> anyhow::Result<()> {
    use patronus_config::Applier;
    use patronus_network::keaddns;
    match action {
        KeaDdnsCommands::Run { conf, stats } => {
            // blocking engine: threads + blocking sockets, no async runtime needed
            tokio::task::spawn_blocking(move || keaddns::engine::run(&conf, stats.as_deref()))
                .await?
                .map_err(|e| anyhow::anyhow!(e))
        }
        KeaDdnsCommands::Show => {
            let store = super::apply::open_store(db.as_deref()).await?;
            print!(
                "{}",
                keaddns::KeaDdnsApplier::default().render(&store).await?
            );
            Ok(())
        }
    }
}
