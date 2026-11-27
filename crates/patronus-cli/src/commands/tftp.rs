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

/// `patronus tftp run --conf FILE [--stats FILE]` exactly as the supervisor starts it: run the
/// server on this (single) thread and return the exit code. `None` = some other command line.
#[cfg(feature = "tftp")]
pub fn daemon_from_args() -> Option<i32> {
    let a: Vec<String> = std::env::args().collect();
    if a.len() < 3 || a[1] != "tftp" || a[2] != "run" {
        return None;
    }
    let (mut conf, mut stats) = (None, None);
    let mut it = a[3..].iter();
    while let Some(k) = it.next() {
        match k.as_str() {
            "--conf" => conf = it.next().cloned(),
            "--stats" => stats = it.next().cloned(),
            _ => return None, // unusual flags: the normal command line parser handles (and explains) them
        }
    }
    let conf = conf?;
    if !patronus_network::tftp::engine::kernel_ok() {
        eprintln!("patronus tftp: the TFTP server needs Linux 5.6 or newer (openat2)");
        return Some(1);
    }
    match patronus_network::tftp::engine::run(
        std::path::Path::new(&conf),
        stats.as_deref().map(std::path::Path::new),
    ) {
        Ok(()) => Some(0),
        Err(e) => {
            eprintln!("patronus tftp: {e}");
            Some(1)
        }
    }
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
