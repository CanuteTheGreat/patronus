//! `patronus applyd`: the root apply broker for the unprivileged web UI
//! (protocol and client in `patronus_network::applyd`). Besides serving
//! requests it refreshes dynamic DNS every five minutes: WAN address changes
//! happen without any UI action.

use super::apply::{open_store, registry};
use std::path::PathBuf;

pub async fn run(
    db: Option<PathBuf>,
    socket: Option<PathBuf>,
    group: String,
) -> anyhow::Result<()> {
    let store = open_store(db.as_deref()).await?;
    let socket = socket.unwrap_or_else(patronus_network::applyd::socket_path);
    let reg = registry();
    if let Some(ddns) = reg.by_name("ddns") {
        let store = open_store(db.as_deref()).await?;
        tokio::spawn(async move {
            let mut t = tokio::time::interval(std::time::Duration::from_secs(300));
            loop {
                t.tick().await;
                if let Err(e) = ddns.apply(&store).await {
                    tracing::warn!("dynamic DNS refresh: {e}");
                }
            }
        });
    }
    patronus_network::applyd::serve(reg, store, &socket, Some(&group))
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))
}
