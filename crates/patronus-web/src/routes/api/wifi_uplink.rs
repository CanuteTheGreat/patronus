//! Wi-Fi client uplinks (USE=wifi-client): a wireless device that joins an upstream access point as a WAN
//! (typically the backup uplink of a gateway group). The device becomes an uplink through the normal
//! interface settings (role, DHCP) and gateways; this API only manages the association.
//!
//! - `GET /api/wifi/uplinks`: every uplink with its live state (associated, BSSID, signal, lease address)
//!   and, when it is not connected, a readable `problem`
//! - `PUT /api/wifi/uplinks/:device`: create or update (admins), `{"ssid", "security", "psk", "bssid",
//!   "enabled", "description"}`; an empty `psk` keeps the stored one
//! - `DELETE /api/wifi/uplinks/:device`: remove (admins); wpa_supplicant stops
//!
//! The passphrase is never returned (`has_psk`). A change is snapshotted (config history), written, applied
//! (wpa_supplicant through applyd), and undone if the apply fails.

use crate::state::AppState;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::{json, Value};

fn error(code: StatusCode, m: impl std::fmt::Display) -> Response {
    (code, Json(json!({ "error": m.to_string() }))).into_response()
}

#[cfg(feature = "wifi-client")]
mod imp {
    use super::*;
    use patronus_config::Applier;
    use patronus_network::wifi_client::{self, WifiClientApplier, WifiClientInput};
    use std::sync::Arc;

    fn applier() -> Arc<dyn Applier> {
        patronus_network::applyd::RemoteApplier::wrap(Arc::new(WifiClientApplier::default()))
    }

    /// One change at a time (snapshot -> write -> apply -> undo must not interleave).
    fn edit_lock() -> &'static tokio::sync::Mutex<()> {
        static L: std::sync::OnceLock<tokio::sync::Mutex<()>> = std::sync::OnceLock::new();
        L.get_or_init(|| tokio::sync::Mutex::new(()))
    }

    pub async fn list(State(state): State<AppState>) -> Response {
        match applier().status(&state.config_store).await {
            Ok(v) => Json(v).into_response(),
            Err(e) => error(StatusCode::INTERNAL_SERVER_ERROR, e),
        }
    }

    /// Write `new` (None = delete) for `device`, apply, put the old row back if the apply fails.
    async fn change(
        state: &AppState,
        user: &str,
        device: &str,
        new: Option<WifiClientInput>,
    ) -> Response {
        let _g = edit_lock().lock().await;
        let store = &state.config_store;
        let old = match wifi_client::get(store, device).await {
            Ok(o) => o,
            Err(e) => return error(StatusCode::INTERNAL_SERVER_ERROR, e),
        };
        if let Some(i) = &new {
            if let Err(e) = i.validated(old.as_ref()) {
                return error(StatusCode::BAD_REQUEST, format!("Invalid input: {e}"));
            }
        } else if old.is_none() {
            return error(
                StatusCode::NOT_FOUND,
                format!("no Wi-Fi uplink on {device}"),
            );
        }
        let what = if new.is_some() { "update" } else { "delete" };
        let _ = store
            .snapshot(user, &format!("before Wi-Fi uplink {what} {device}"))
            .await;
        let written = match &new {
            Some(i) => wifi_client::save(store, i).await.map(Some),
            None => wifi_client::delete(store, device).await.map(|_| None),
        };
        let saved = match written {
            Ok(s) => s,
            Err(e) => return error(StatusCode::INTERNAL_SERVER_ERROR, e),
        };
        match applier().apply(store).await {
            Ok(rep) => {
                let details = saved
                    .as_ref()
                    .map(|c| c.public())
                    .unwrap_or_else(|| json!({ "device": device }));
                let _ = store
                    .audit(user, what, "wifi_uplink", Some(device), &details)
                    .await;
                Json(json!({
                    "ok": true,
                    "uplink": saved.map(|c| c.public()),
                    "applied": rep.applied,
                    "warnings": rep.warnings,
                }))
                .into_response()
            }
            Err(e) => {
                // undo: the previous row (with its secret) or no row
                let undo = match &old {
                    Some(o) => wifi_client::save(
                        store,
                        &WifiClientInput {
                            device: o.device.clone(),
                            enabled: Some(o.enabled),
                            ssid: o.ssid.clone(),
                            security: Some(o.security.as_str().to_string()),
                            psk: o.psk.clone(),
                            bssid: o.bssid.clone(),
                            description: o.description.clone(),
                        },
                    )
                    .await
                    .map(|_| ()),
                    None => wifi_client::delete(store, device).await.map(|_| ()),
                };
                let _ = applier().apply(store).await;
                let undone = if undo.is_ok() {
                    "the previous setting was put back"
                } else {
                    "the previous setting could NOT be put back"
                };
                error(
                    StatusCode::CONFLICT,
                    format!("Wi-Fi uplink {device}: apply failed ({e}); {undone}"),
                )
            }
        }
    }

    pub async fn put(
        State(state): State<AppState>,
        admin: crate::auth::AdminUser,
        Path(device): Path<String>,
        Json(mut body): Json<Value>,
    ) -> Response {
        if let Some(o) = body.as_object_mut() {
            o.insert("device".into(), json!(device));
        }
        let input: WifiClientInput = match serde_json::from_value(body) {
            Ok(i) => i,
            Err(e) => return error(StatusCode::BAD_REQUEST, format!("Invalid input: {e}")),
        };
        change(&state, &admin.session.username, &device, Some(input)).await
    }

    pub async fn delete(
        State(state): State<AppState>,
        admin: crate::auth::AdminUser,
        Path(device): Path<String>,
    ) -> Response {
        change(&state, &admin.session.username, &device, None).await
    }
}

#[cfg(not(feature = "wifi-client"))]
mod imp {
    use super::*;
    async fn off() -> Response {
        error(
            StatusCode::NOT_IMPLEMENTED,
            "Wi-Fi uplinks need Patronus built with USE=wifi-client",
        )
    }
    pub async fn list() -> Response {
        off().await
    }
    pub async fn put() -> Response {
        off().await
    }
    pub async fn delete() -> Response {
        off().await
    }
}

/// API routes, mounted under `/api` with one `.merge(wifi_uplink::router())`.
pub fn router() -> axum::Router<AppState> {
    use axum::routing::{get, put};
    axum::Router::new()
        .route("/wifi/uplinks", get(imp::list))
        .route("/wifi/uplinks/:device", put(imp::put).delete(imp::delete))
}

#[cfg(test)]
mod tests {
    #[test]
    fn routes_build() {
        let _ = super::router();
    }
}
