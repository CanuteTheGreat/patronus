//! `patronus rfc2136`: the RFC 2136 dynamic DNS client (USE=rfc2136).
//!
//! `run` is the long-lived engine (started by the applier as
//! `patronus-daemon@rfc2136` from a generated JSON file); `show` prints the
//! configuration the stored clients resolve to (secrets masked).

use crate::Rfc2136Commands;
use std::path::PathBuf;

#[cfg(not(feature = "rfc2136"))]
pub async fn run(_a: Rfc2136Commands, _db: Option<PathBuf>) -> anyhow::Result<()> {
    anyhow::bail!("this Patronus build has no RFC 2136 client: rebuild with USE=rfc2136")
}

#[cfg(feature = "rfc2136")]
pub async fn run(action: Rfc2136Commands, db: Option<PathBuf>) -> anyhow::Result<()> {
    use patronus_network::rfc2136;
    match action {
        Rfc2136Commands::Run { conf, stats } => {
            // blocking engine: a timer loop around nsupdate, no async runtime needed
            tokio::task::spawn_blocking(move || rfc2136::engine::run(&conf, stats.as_deref()))
                .await?
        }
        Rfc2136Commands::Show => {
            let store = super::apply::open_store(db.as_deref()).await?;
            print!(
                "{}",
                rfc2136::render_public(&rfc2136::load(&store, "nsupdate").await?)
            );
            Ok(())
        }
    }
}
