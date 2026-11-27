//! Captive portal runtime in the web process (USE=captive-portal): the portal
//! listeners (`captive.http_port`, and `captive.https_port` with TLS) and the
//! session ticker (`patronus_captiveportal::engine::Portal::tick` every
//! `captive.poll_secs`). The listeners exist only while at least one zone is
//! enabled, and follow port and certificate changes without a restart.
//!
//! Adding a client to the portal's nft sets, `tc` classes and conntrack
//! cleanup need CAP_NET_ADMIN, which the patronus-web units grant (systemd
//! AmbientCapabilities, OpenRC `capabilities=`), the same as the time-limit
//! ticker of device segmentation.

use patronus_captiveportal::engine::{LiveSys, Portal};
use patronus_config::ConfigStore;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::task::JoinHandle;

#[derive(PartialEq, Eq, Clone, Debug)]
struct Want {
    http: u16,
    https: u16,
    cert: String,
    key: String,
}

async fn any_zone_enabled(store: &ConfigStore) -> bool {
    patronus_network::captive::zones(store)
        .await
        .map(|z| z.iter().any(|z| z.enabled))
        .unwrap_or(false)
}

async fn start_listeners(portal: Arc<Portal>, w: &Want) -> Vec<JoinHandle<()>> {
    #[cfg(feature = "tls-rustls")]
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let mut v = Vec::new();
    let http_addr = SocketAddr::from(([0, 0, 0, 0], w.http));
    let app = patronus_captiveportal::http::router(portal.clone(), false);
    v.push(tokio::spawn(async move {
        match tokio::net::TcpListener::bind(http_addr).await {
            Ok(l) => {
                tracing::info!("captive portal listening on http://{http_addr}");
                if let Err(e) =
                    axum::serve(l, app.into_make_service_with_connect_info::<SocketAddr>()).await
                {
                    tracing::error!("captive portal http {http_addr}: {e}");
                }
            }
            Err(e) => tracing::error!("captive portal: cannot listen on {http_addr}: {e}"),
        }
    }));
    // HTTPS: the portal's own certificate, else the web UI's (configured or self-signed)
    let (cert, key) = if w.cert.is_empty() {
        let s = patronus_config::webui::resolve(Some(&portal.store)).await;
        (s.tls_cert, s.tls_key)
    } else {
        (w.cert.clone(), w.key.clone())
    };
    let tls =
        match crate::tls::configured_or_self_signed(&cert, &key, &crate::tls::default_tls_dir())
            .await
        {
            Ok(t) => t,
            Err(e) => {
                tracing::error!("captive portal: no TLS certificate ({e:#}); HTTPS portal off");
                return v;
            }
        };
    let https_addr = SocketAddr::from(([0, 0, 0, 0], w.https));
    let app = patronus_captiveportal::http::router(portal, true);
    v.push(tokio::spawn(async move {
        match std::net::TcpListener::bind(https_addr) {
            Ok(l) => {
                tracing::info!("captive portal listening on https://{https_addr}");
                #[cfg(feature = "tls-rustls")]
                let server = axum_server::from_tcp(l)
                    .acceptor(axum_server::tls_rustls::RustlsAcceptor::new(tls));
                #[cfg(all(feature = "tls-openssl", not(feature = "tls-rustls")))]
                let server = axum_server::from_tcp(l)
                    .acceptor(axum_server::tls_openssl::OpenSSLAcceptor::new(tls));
                if let Err(e) = server
                    .serve(app.into_make_service_with_connect_info::<SocketAddr>())
                    .await
                {
                    tracing::error!("captive portal https {https_addr}: {e}");
                }
            }
            Err(e) => tracing::error!("captive portal: cannot listen on {https_addr}: {e}"),
        }
    }));
    v
}

/// Listeners + session ticker, for the life of the web process.
pub fn spawn(store: Arc<ConfigStore>) {
    tokio::spawn(async move {
        let portal = Arc::new(Portal::new(store.clone(), Arc::new(LiveSys)));
        portal.restore().await;
        let mut running: Option<(Want, Vec<JoinHandle<()>>)> = None;
        loop {
            let g = portal.globals().await;
            let want = any_zone_enabled(&store).await.then(|| Want {
                http: g.http_port,
                https: g.https_port,
                cert: g.tls_cert.clone(),
                key: g.tls_key.clone(),
            });
            let same = match (&running, &want) {
                (Some((w, _)), Some(n)) => w == n,
                (None, None) => true,
                _ => false,
            };
            if !same {
                if let Some((_, hs)) = running.take() {
                    for h in hs {
                        h.abort();
                    }
                    tracing::info!("captive portal listeners stopped");
                }
                if let Some(w) = want {
                    let hs = start_listeners(portal.clone(), &w).await;
                    running = Some((w, hs));
                }
            }
            portal.tick(&g).await;
            tokio::time::sleep(std::time::Duration::from_secs(g.poll_secs)).await;
        }
    });
}
