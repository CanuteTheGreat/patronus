//! VPN API and page (lane F): `/api/vpn/*` and `/vpn`.
//!
//! Live state (always): `GET /api/vpn/wireguard/peers` (`wg show`),
//! `GET /api/vpn/ipsec/tunnels` (`swanctl --list-sas`).
//!
//! Configuration (USE=wireguard / USE=ipsec; otherwise 501 naming the USE
//! flag to rebuild with):
//! - `GET  /api/vpn`                                tunnels, peers, IPsec connections (no keys)
//! - `POST /api/vpn/wireguard/tunnels`              add a tunnel (key pair generated)
//! - `PUT|DELETE /api/vpn/wireguard/tunnels/:name`
//! - `POST /api/vpn/wireguard/peers`                add a peer (no public key = Patronus
//!   generates the client's key pair)
//! - `PUT|DELETE /api/vpn/wireguard/peers/:id`
//! - `GET  /api/vpn/wireguard/config/:id`           client config (wg-quick), operators/admins
//! - `GET  /api/vpn/wireguard/qrcode/:id[/png]`     the same as a QR code
//! - `POST /api/vpn/wireguard/apply`                re-apply from the store
//! - `POST /api/vpn/ipsec/connections`              add an IKEv2 tunnel (a PSK is generated
//!   if empty and returned once)
//! - `PUT|DELETE /api/vpn/ipsec/connections/:id`
//! - `POST /api/vpn/ipsec/apply`

use crate::auth::AuthUser;
use crate::state::tunnels::Kind;
use crate::state::AppState;
use axum::{
    extract::{Path, State},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;

fn error(code: StatusCode, msg: impl Into<String>) -> Response {
    (code, Json(json!({ "error": msg.into() }))).into_response()
}

fn err(e: anyhow::Error) -> Response {
    let msg = e.to_string();
    let code = if (msg.contains("USE=") && msg.contains("not built"))
        || msg.starts_with("IPsec needs root")
    {
        StatusCode::NOT_IMPLEMENTED
    } else if msg.contains("Invalid") {
        StatusCode::BAD_REQUEST
    } else if msg.starts_with("no WireGuard") || msg.starts_with("no IPsec") {
        StatusCode::NOT_FOUND
    } else {
        StatusCode::INTERNAL_SERVER_ERROR
    };
    error(code, msg)
}

fn unavailable(msg: String) -> Response {
    error(StatusCode::SERVICE_UNAVAILABLE, msg)
}

/// GET /api/vpn/wireguard/peers -- live peers of every WireGuard interface.
pub async fn list_wg_peers(State(state): State<AppState>) -> Response {
    match state.vpn.list_wireguard_peers().await {
        Ok(peers) => Json(peers).into_response(),
        Err(e) => unavailable(format!("cannot read WireGuard state: {e}")),
    }
}

/// GET /api/vpn/ipsec/tunnels -- live IKE SAs.
pub async fn list_ipsec_tunnels(State(state): State<AppState>) -> Response {
    let s = state.vpn.snapshot().await;
    match s.ipsec_error {
        Some(e) => unavailable(format!("cannot read IPsec state: {e}")),
        None => Json(s.ipsec_tunnels).into_response(),
    }
}

/// GET /api/vpn/openvpn/tunnels -- OpenVPN is neither managed nor
/// monitored: say so rather than return an empty list that reads as "none".
pub async fn list_ovpn_tunnels() -> Response {
    error(
        StatusCode::NOT_IMPLEMENTED,
        "OpenVPN is not managed or monitored by Patronus",
    )
}

// --- configuration ---------------------------------------------------------

#[cfg(feature = "wireguard")]
mod wg {
    use super::*;
    use patronus_network::wireguard as w;

    fn ae(e: patronus_core::Error) -> anyhow::Error {
        anyhow::anyhow!("{e}")
    }

    pub async fn overview(state: &AppState) -> anyhow::Result<serde_json::Value> {
        let s = state.tunnels.store();
        let tunnels = w::list_interfaces(s).await.map_err(ae)?;
        let peers = w::list_peers(s).await.map_err(ae)?;
        Ok(json!({ "tunnels": tunnels, "peers": peers }))
    }

    pub async fn add_tunnel(
        State(state): State<AppState>,
        Json(i): Json<w::InterfaceInput>,
    ) -> Response {
        let r = state
            .tunnels
            .change(Kind::WireGuard, "add WireGuard tunnel", |s| async move {
                w::save_interface(&s, None, &i).await
            })
            .await;
        match r {
            Ok(name) => {
                let pubkey = w::list_interfaces(state.tunnels.store())
                    .await
                    .ok()
                    .and_then(|v| v.into_iter().find(|t| t.name == name))
                    .map(|t| t.public_key)
                    .unwrap_or_default();
                (
                    StatusCode::CREATED,
                    Json(json!({ "name": name, "public_key": pubkey })),
                )
                    .into_response()
            }
            Err(e) => err(e),
        }
    }

    pub async fn put_tunnel(
        State(state): State<AppState>,
        Path(name): Path<String>,
        Json(i): Json<w::InterfaceInput>,
    ) -> Response {
        state
            .tunnels
            .change(Kind::WireGuard, "edit WireGuard tunnel", |s| async move {
                w::save_interface(&s, Some(&name), &i).await
            })
            .await
            .map(|n| Json(json!({ "ok": true, "name": n })).into_response())
            .unwrap_or_else(err)
    }

    pub async fn del_tunnel(State(state): State<AppState>, Path(name): Path<String>) -> Response {
        let exists = w::list_interfaces(state.tunnels.store())
            .await
            .is_ok_and(|v| v.iter().any(|t| t.name == name));
        if !exists {
            return error(
                StatusCode::NOT_FOUND,
                format!("no WireGuard tunnel {name:?}"),
            );
        }
        let n2 = name.clone();
        match state
            .tunnels
            .change(Kind::WireGuard, "delete WireGuard tunnel", |s| async move {
                w::delete_interface(&s, &n2).await
            })
            .await
        {
            Ok(true) => Json(json!({ "ok": true })).into_response(),
            Ok(false) => error(
                StatusCode::NOT_FOUND,
                format!("no WireGuard tunnel {name:?}"),
            ),
            Err(e) => err(e),
        }
    }

    pub async fn add_peer(State(state): State<AppState>, Json(p): Json<w::PeerInput>) -> Response {
        let r = state
            .tunnels
            .change(Kind::WireGuard, "add WireGuard peer", |s| async move {
                w::save_peer(&s, None, &p).await
            })
            .await;
        match r {
            Ok(id) => {
                let peer = w::list_peers(state.tunnels.store())
                    .await
                    .ok()
                    .and_then(|v| v.into_iter().find(|p| p.id == id));
                (StatusCode::CREATED, Json(json!({ "id": id, "peer": peer }))).into_response()
            }
            Err(e) => err(e),
        }
    }

    pub async fn put_peer(
        State(state): State<AppState>,
        Path(id): Path<i64>,
        Json(p): Json<w::PeerInput>,
    ) -> Response {
        state
            .tunnels
            .change(Kind::WireGuard, "edit WireGuard peer", |s| async move {
                w::save_peer(&s, Some(id), &p).await
            })
            .await
            .map(|_| Json(json!({ "ok": true })).into_response())
            .unwrap_or_else(err)
    }

    pub async fn del_peer(State(state): State<AppState>, Path(id): Path<i64>) -> Response {
        let exists = w::list_peers(state.tunnels.store())
            .await
            .is_ok_and(|v| v.iter().any(|p| p.id == id));
        if !exists {
            return error(StatusCode::NOT_FOUND, format!("no WireGuard peer {id}"));
        }
        match state
            .tunnels
            .change(Kind::WireGuard, "delete WireGuard peer", |s| async move {
                w::delete_peer(&s, id).await
            })
            .await
        {
            Ok(true) => Json(json!({ "ok": true })).into_response(),
            Ok(false) => error(StatusCode::NOT_FOUND, format!("no WireGuard peer {id}")),
            Err(e) => err(e),
        }
    }

    /// (peer name, client config) of a peer whose private key Patronus holds.
    pub async fn client_config(
        state: &AppState,
        id: i64,
    ) -> Result<(String, String), Box<Response>> {
        let s = state.tunnels.store();
        let peers = w::list_peers(s).await.map_err(|e| Box::new(err(ae(e))))?;
        let peer = peers.into_iter().find(|p| p.id == id).ok_or_else(|| {
            Box::new(error(
                StatusCode::NOT_FOUND,
                format!("no WireGuard peer {id}"),
            ))
        })?;
        let iface = w::list_interfaces(s)
            .await
            .map_err(|e| Box::new(err(ae(e))))?
            .into_iter()
            .find(|t| t.name == peer.interface)
            .ok_or_else(|| Box::new(error(StatusCode::NOT_FOUND, "the peer's tunnel is gone")))?;
        match w::client_config(&iface, &peer) {
            Ok(Some(c)) => Ok((peer.name, c)),
            Ok(None) => Err(Box::new(error(
                StatusCode::CONFLICT,
                format!(
                    "{} was added with its own public key: its private key (and so its config) \
                     only exists on that device",
                    peer.name
                ),
            ))),
            Err(e) => Err(Box::new(err(ae(e)))),
        }
    }
}

#[cfg(feature = "ipsec")]
mod ipsec {
    use super::*;
    use patronus_network::ipsec as x;

    pub async fn overview(state: &AppState) -> anyhow::Result<serde_json::Value> {
        let t = x::list_tunnels(state.tunnels.store())
            .await
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        Ok(json!(t))
    }

    pub async fn add(State(state): State<AppState>, Json(t): Json<x::TunnelInput>) -> Response {
        match state
            .tunnels
            .change(Kind::Ipsec, "add IPsec tunnel", |s| async move {
                x::save_tunnel(&s, None, &t).await
            })
            .await
        {
            // a generated PSK is shown once: the other side needs it
            Ok((id, psk)) => (
                StatusCode::CREATED,
                Json(json!({ "id": id, "generated_psk": psk })),
            )
                .into_response(),
            Err(e) => err(e),
        }
    }

    pub async fn put(
        State(state): State<AppState>,
        Path(id): Path<i64>,
        Json(t): Json<x::TunnelInput>,
    ) -> Response {
        state
            .tunnels
            .change(Kind::Ipsec, "edit IPsec tunnel", |s| async move {
                x::save_tunnel(&s, Some(id), &t).await
            })
            .await
            .map(|_| Json(json!({ "ok": true })).into_response())
            .unwrap_or_else(err)
    }

    pub async fn del(State(state): State<AppState>, Path(id): Path<i64>) -> Response {
        let exists = x::list_tunnels(state.tunnels.store())
            .await
            .is_ok_and(|v| v.iter().any(|t| t.id == id));
        if !exists {
            return error(StatusCode::NOT_FOUND, format!("no IPsec tunnel {id}"));
        }
        match state
            .tunnels
            .change(Kind::Ipsec, "delete IPsec tunnel", |s| async move {
                x::delete_tunnel(&s, id).await
            })
            .await
        {
            Ok(true) => Json(json!({ "ok": true })).into_response(),
            Ok(false) => error(StatusCode::NOT_FOUND, format!("no IPsec tunnel {id}")),
            Err(e) => err(e),
        }
    }
}

#[cfg(not(all(feature = "wireguard", feature = "ipsec")))]
fn not_built(what: &str, flag: &str) -> Response {
    error(
        StatusCode::NOT_IMPLEMENTED,
        format!("{what} support is not built into this Patronus (rebuild with USE={flag})"),
    )
}

/// GET /api/vpn -- the stored VPN configuration (never any key).
async fn overview(State(state): State<AppState>) -> Response {
    #[allow(unused_mut)]
    let mut out = json!({ "features": patronus_network::vpn_features() });
    // built in but not usable by this process (container image): say why
    if let Some(why) = state.tunnels.ipsec_unavailable() {
        out["ipsec_unavailable"] = json!(why);
    }
    #[cfg(feature = "wireguard")]
    match wg::overview(&state).await {
        Ok(v) => out["wireguard"] = v,
        Err(e) => return err(e),
    }
    #[cfg(feature = "ipsec")]
    match ipsec::overview(&state).await {
        Ok(v) => out["ipsec"] = v,
        Err(e) => return err(e),
    }
    let _ = &state;
    Json(out).into_response()
}

/// Client config / QR need a role that may change the configuration:
/// they carry the client's private key.
fn may_export(user: &AuthUser) -> Option<Response> {
    (!user.session.role.can_modify()).then(|| {
        error(
            StatusCode::FORBIDDEN,
            "client configs carry private keys: operators and admins only",
        )
    })
}

/// GET /api/vpn/wireguard/config/:id
async fn get_wg_config(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<i64>,
) -> Response {
    if let Some(r) = may_export(&user) {
        return r;
    }
    #[cfg(feature = "wireguard")]
    {
        match wg::client_config(&state, id).await {
            Ok((name, c)) => {
                let file: String = name
                    .chars()
                    .map(|c| {
                        if c.is_ascii_alphanumeric() || c == '-' {
                            c
                        } else {
                            '_'
                        }
                    })
                    .collect();
                (
                    [
                        (
                            header::CONTENT_TYPE,
                            "text/plain; charset=utf-8".to_string(),
                        ),
                        (
                            header::CONTENT_DISPOSITION,
                            format!("attachment; filename=\"{file}.conf\""),
                        ),
                        (header::CACHE_CONTROL, "no-store".to_string()),
                    ],
                    c,
                )
                    .into_response()
            }
            Err(r) => *r,
        }
    }
    #[cfg(not(feature = "wireguard"))]
    {
        let _ = (&state, id, header::CONTENT_TYPE);
        not_built("WireGuard", "wireguard")
    }
}

/// GET /api/vpn/wireguard/qrcode/:id (SVG) and /png
async fn qr(state: AppState, user: AuthUser, id: i64, png: bool) -> Response {
    if let Some(r) = may_export(&user) {
        return r;
    }
    #[cfg(feature = "wireguard")]
    {
        let (_, c) = match wg::client_config(&state, id).await {
            Ok(x) => x,
            Err(r) => return *r,
        };
        let r = if png {
            crate::qrcode::generate_qr_code_png(&c).map(|b| ("image/png", b))
        } else {
            crate::qrcode::generate_qr_code_svg(&c).map(|s| ("image/svg+xml", s.into_bytes()))
        };
        match r {
            Ok((ct, body)) => (
                [
                    (header::CONTENT_TYPE, ct),
                    (header::CACHE_CONTROL, "no-store"),
                ],
                body,
            )
                .into_response(),
            Err(e) => error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
        }
    }
    #[cfg(not(feature = "wireguard"))]
    {
        let _ = (&state, id, png);
        not_built("WireGuard", "wireguard")
    }
}

async fn get_wg_qr(State(state): State<AppState>, user: AuthUser, Path(id): Path<i64>) -> Response {
    qr(state, user, id, false).await
}

async fn get_wg_qr_png(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<i64>,
) -> Response {
    qr(state, user, id, true).await
}

async fn apply(state: AppState, k: Kind) -> Response {
    match state.tunnels.reapply(k).await {
        Ok(lines) => Json(json!({ "ok": true, "applied": lines })).into_response(),
        Err(e) => err(e),
    }
}

async fn wg_apply(State(state): State<AppState>) -> Response {
    apply(state, Kind::WireGuard).await
}

async fn ipsec_apply(State(state): State<AppState>) -> Response {
    apply(state, Kind::Ipsec).await
}

/// This lane's API routes, mounted under `/api` by `routes::api_routes`
/// with one `.merge(vpn::router())` line.
pub fn router() -> axum::Router<AppState> {
    use axum::routing::{get, post};
    #[allow(unused_mut)]
    let mut r = axum::Router::new()
        .route("/vpn", get(overview))
        .route("/vpn/wireguard/config/:id", get(get_wg_config))
        .route("/vpn/wireguard/qrcode/:id", get(get_wg_qr))
        .route("/vpn/wireguard/qrcode/:id/png", get(get_wg_qr_png))
        .route("/vpn/wireguard/apply", post(wg_apply))
        .route("/vpn/ipsec/apply", post(ipsec_apply))
        .route("/vpn/openvpn/tunnels", get(list_ovpn_tunnels))
        .route("/vpn/ipsec/tunnels", get(list_ipsec_tunnels));
    #[cfg(feature = "wireguard")]
    {
        use axum::routing::put;
        r = r
            .route("/vpn/wireguard/tunnels", post(wg::add_tunnel))
            .route(
                "/vpn/wireguard/tunnels/:name",
                put(wg::put_tunnel).delete(wg::del_tunnel),
            )
            .route(
                "/vpn/wireguard/peers",
                get(list_wg_peers).post(wg::add_peer),
            )
            .route(
                "/vpn/wireguard/peers/:id",
                put(wg::put_peer).delete(wg::del_peer),
            );
    }
    #[cfg(not(feature = "wireguard"))]
    {
        let nb = || async { not_built("WireGuard", "wireguard") };
        r = r
            .route("/vpn/wireguard/tunnels", post(nb))
            .route("/vpn/wireguard/tunnels/:name", axum::routing::any(nb))
            .route("/vpn/wireguard/peers", get(list_wg_peers).post(nb))
            .route("/vpn/wireguard/peers/:id", axum::routing::any(nb));
    }
    #[cfg(feature = "ipsec")]
    {
        use axum::routing::put;
        r = r.route("/vpn/ipsec/connections", post(ipsec::add)).route(
            "/vpn/ipsec/connections/:id",
            put(ipsec::put).delete(ipsec::del),
        );
    }
    #[cfg(not(feature = "ipsec"))]
    {
        let nb = || async { not_built("IPsec", "ipsec") };
        r = r
            .route("/vpn/ipsec/connections", post(nb))
            .route("/vpn/ipsec/connections/:id", axum::routing::any(nb));
    }
    r
}

// --- page ------------------------------------------------------------------

/// GET /vpn
pub async fn page(State(state): State<AppState>, user: AuthUser) -> Response {
    let s = state.vpn.snapshot().await;
    #[allow(unused_mut)]
    let mut t = crate::templates::VpnTemplate {
        page: "vpn",
        wg_peers: s.wg_peers,
        wg_error: s.wg_error.unwrap_or_default(),
        ipsec_tunnels: s.ipsec_tunnels,
        ipsec_error: s.ipsec_error.unwrap_or_default(),
        ipsec_not_running: s.ipsec_not_running,
        has_wireguard: cfg!(feature = "wireguard"),
        has_ipsec: cfg!(feature = "ipsec"),
        ipsec_unavailable: state.tunnels.ipsec_unavailable().unwrap_or_default(),
        can_modify: user.session.role.can_modify(),
        tunnels: Vec::new(),
        peers: Vec::new(),
        connections: Vec::new(),
        config_error: String::new(),
    };
    #[cfg(feature = "wireguard")]
    {
        use patronus_network::wireguard as w;
        let st = state.tunnels.store();
        match (w::list_interfaces(st).await, w::list_peers(st).await) {
            (Ok(ifs), Ok(ps)) => {
                t.tunnels = ifs
                    .into_iter()
                    .map(|i| crate::templates::WgTunnelRow {
                        peers: ps.iter().filter(|p| p.interface == i.name).count(),
                        name: i.name,
                        enabled: i.enabled,
                        public_key: i.public_key,
                        listen_port: i.listen_port,
                        addresses: i.addresses,
                        endpoint: i.endpoint.unwrap_or_default(),
                        client_dns: i.client_dns.unwrap_or_default(),
                        client_allowed_ips: i.client_allowed_ips,
                        description: i.description.unwrap_or_default(),
                    })
                    .collect();
                t.peers =
                    ps.into_iter()
                        .map(|p| {
                            let live = t.wg_peers.iter().find(|l| {
                                l.interface == p.interface && l.public_key == p.public_key
                            });
                            crate::templates::WgPeerRow {
                                id: p.id,
                                interface: p.interface.clone(),
                                name: p.name.clone(),
                                enabled: p.enabled,
                                public_key: p.public_key.clone(),
                                allowed_ips: p.allowed_ips.clone(),
                                endpoint: p.endpoint.clone().unwrap_or_default(),
                                keepalive: p
                                    .persistent_keepalive
                                    .map(|k| k.to_string())
                                    .unwrap_or_default(),
                                exportable: p.exportable,
                                has_psk: p.has_psk,
                                status: live
                                    .map(|l| l.status.clone())
                                    .unwrap_or_else(|| "not in the kernel".into()),
                                connected: live.is_some_and(|l| l.connected),
                                handshake: live
                                    .and_then(|l| l.last_handshake.clone())
                                    .unwrap_or_else(|| "never".into()),
                                transfer: live.map(|l| l.transfer.clone()).unwrap_or_default(),
                                description: p.description.clone().unwrap_or_default(),
                            }
                        })
                        .collect();
            }
            (Err(e), _) | (_, Err(e)) => t.config_error = e.to_string(),
        }
    }
    #[cfg(feature = "ipsec")]
    {
        match patronus_network::ipsec::list_tunnels(state.tunnels.store()).await {
            Ok(v) => {
                t.connections = v
                    .into_iter()
                    .map(|c| {
                        let sa = format!("{}{}", patronus_network::ipsec::CONN_PREFIX, c.name);
                        let live = t.ipsec_tunnels.iter().find(|l| l.name == sa);
                        crate::templates::IpsecConnRow {
                            id: c.id,
                            enabled: c.enabled,
                            local_address: c.local_address.unwrap_or_default(),
                            remote_address: c.remote_address,
                            local_id: c.local_id.unwrap_or_default(),
                            remote_id: c.remote_id.unwrap_or_default(),
                            local_ts: c.local_ts,
                            remote_ts: c.remote_ts,
                            start_action: c.start_action,
                            state: live
                                .map(|l| l.status.clone())
                                .unwrap_or_else(|| "no SA".into()),
                            established: live.is_some_and(|l| l.status == "ESTABLISHED"),
                            description: c.description.unwrap_or_default(),
                            name: c.name,
                        }
                    })
                    .collect();
            }
            Err(e) => t.config_error = e.to_string(),
        }
    }
    let _ = &state;
    crate::routes::pages::render(&t, "VPN")
}
