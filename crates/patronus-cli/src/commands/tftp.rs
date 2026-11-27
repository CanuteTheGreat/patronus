//! `patronus tftp`: the TFTP server (USE=tftp).
//!
//! `run` is the long-lived server (started by the applier as
//! `patronus-daemon@tftp` from a generated JSON file); `show` prints the
//! configuration the stored settings resolve to.

use crate::TftpCommands;
use std::path::PathBuf;

#[cfg(not(feature = "tftp"))]
pub async fn run(_a: TftpCommands, _db: Option<PathBuf>) -> anyhow::Result<()> {
    anyhow::bail!("this Patronus build has no TFTP server: rebuild with USE=tftp")
}

#[cfg(feature = "tftp")]
pub async fn run(action: TftpCommands, db: Option<PathBuf>) -> anyhow::Result<()> {
    use patronus_network::tftp;
    match action {
        TftpCommands::Run { conf, stats } => {
            if !tftp::engine::kernel_ok() {
                anyhow::bail!("the TFTP server needs Linux 5.6 or newer (openat2)");
            }
            // blocking engine: threads + blocking sockets, no async runtime needed
            tokio::task::spawn_blocking(move || tftp::engine::run(&conf, stats.as_deref()))
                .await?
                .map_err(|e| anyhow::anyhow!(e))
        }
        TftpCommands::Show => {
            let store = super::apply::open_store(db.as_deref()).await?;
            print!("{}", tftp::render(&tftp::load(&store).await?));
            Ok(())
        }
    }
}
