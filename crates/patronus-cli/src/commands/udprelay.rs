//! `patronus udp-relay`: the UDP broadcast relay (USE=udp-relay).
//!
//! `run` is the long-lived relay engine (started by the applier as
//! `patronus-daemon@udp-relay` from a generated JSON file); `show` prints the
//! configuration the stored rules resolve to.

use crate::UdpRelayCommands;
use std::path::PathBuf;

#[cfg(not(feature = "udp-relay"))]
pub async fn run(_a: UdpRelayCommands, _db: Option<PathBuf>) -> anyhow::Result<()> {
    anyhow::bail!("this Patronus build has no UDP broadcast relay: rebuild with USE=udp-relay")
}

#[cfg(feature = "udp-relay")]
pub async fn run(action: UdpRelayCommands, db: Option<PathBuf>) -> anyhow::Result<()> {
    use patronus_network::udprelay;
    match action {
        UdpRelayCommands::Run { conf, stats } => {
            // blocking engine: threads + poll(2), no async runtime needed
            tokio::task::spawn_blocking(move || udprelay::engine::run(&conf, stats.as_deref()))
                .await?
        }
        UdpRelayCommands::Show => {
            let store = super::apply::open_store(db.as_deref()).await?;
            print!("{}", udprelay::render(&udprelay::load(&store).await?));
            Ok(())
        }
    }
}
