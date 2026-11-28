//! `patronus dhcp6-relay`: the DHCPv6 relay agent (USE=dhcp6-relay).
//!
//! `run` is the long-lived relay engine (started by the applier as
//! `patronus-daemon@dhcp6-relay` from a generated JSON file); `show` prints the
//! configuration the stored rules resolve to.

use crate::Dhcp6RelayCommands;
use std::path::PathBuf;

#[cfg(not(feature = "dhcp6-relay"))]
pub async fn run(_a: Dhcp6RelayCommands, _db: Option<PathBuf>) -> anyhow::Result<()> {
    anyhow::bail!("this Patronus build has no DHCPv6 relay: rebuild with USE=dhcp6-relay")
}

#[cfg(feature = "dhcp6-relay")]
pub async fn run(action: Dhcp6RelayCommands, db: Option<PathBuf>) -> anyhow::Result<()> {
    use patronus_network::dhcp6relay;
    match action {
        Dhcp6RelayCommands::Run { conf, stats } => {
            // blocking engine: threads + poll(2), no async runtime needed
            tokio::task::spawn_blocking(move || dhcp6relay::engine::run(&conf, stats.as_deref()))
                .await?
        }
        Dhcp6RelayCommands::Show => {
            let store = super::apply::open_store(db.as_deref()).await?;
            print!("{}", dhcp6relay::render(&dhcp6relay::load(&store).await?));
            Ok(())
        }
    }
}
