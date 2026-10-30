//! Per-device Wi-Fi credentials (USE=wifi-ap): networks, devices with their own
//! passphrase, rotation, revocation, audited reveal, live stations. Same
//! contract as the rest of the segmentation page: snapshot -> write -> run the
//! `segmentation`, `dhcp`, `wifi` and `firewall` appliers -> undo on failure.
//!
//! Passphrases are returned once when a device is created or rotated, or by an
//! explicit admin reveal that writes an audit row; no listing ever carries one.

use super::LanManager;
use patronus_config::seg::{self, DeviceInput};
use patronus_config::seg_wifi::{self, NetworkInput};
use serde_json::{json, Value};

fn e(e: patronus_core::Error) -> anyhow::Error {
    anyhow::anyhow!("{e}")
}

use super::segmentation::APPLIERS;

fn issued_json(i: &seg_wifi::Issued) -> Value {
    json!({
        "device": i.device,
        "credential_id": i.credential_id,
        "network": i.network,
        "ssid": i.ssid,
        "security": i.security,
        "secret": i.secret,
        "qr": i.qr,
        "qr_svg": crate::qrcode::generate_qr_code_svg(&i.qr).ok(),
        "note": "This passphrase is shown once. A later look needs an administrator and is recorded in the audit log.",
    })
}

impl LanManager {
    pub async fn wifi_overview(&self) -> anyhow::Result<Value> {
        let s = &*self.store;
        Ok(json!({
            "networks": seg_wifi::list_networks(s).await.map_err(e)?,
            "credentials": seg_wifi::list_credentials(s).await.map_err(e)?,
            "status": self.status("wifi").await?,
            "notes": {
                "wpa2": "WPA2 per-device passphrases are added and revoked live, without restarting the access point.",
                "wpa3": "WPA3 (SAE) per-device passwords are read by hostapd only at start: adding, rotating or revoking one restarts the access point and every station reconnects for a few seconds. WPA2 is the default for that reason.",
                "pending": "A device created without a MAC joins with its own passphrase once; the router learns its MAC at that join and binds the passphrase to it. Unused passphrases expire after 24 hours.",
                "unknown": "'enrol' lets unknown devices join with a shared secret that grants nothing: they get an address and reach DHCP/DNS/ping only (quarantine) until you approve them.",
                "random_mac": "A phone that uses a new random MAC on every connection cannot be bound to a MAC: turn on 'fixed' or 'private per network' in its Wi-Fi settings.",
            },
        }))
    }

    pub async fn wifi_network_save(&self, id: Option<i64>, i: NetworkInput) -> anyhow::Result<i64> {
        let _g = self.edit.lock().await;
        let what = format!("Wi-Fi network {}", i.name);
        let snap = self.begin(&what).await?;
        let id = match id {
            Some(id) => {
                seg_wifi::update_network(&self.store, id, &i)
                    .await
                    .map_err(e)?;
                id
            }
            None => seg_wifi::create_network(&self.store, &i).await.map_err(e)?,
        };
        self.commit(&what, snap, APPLIERS).await?;
        Ok(id)
    }

    pub async fn wifi_network_delete(&self, id: i64) -> anyhow::Result<()> {
        let _g = self.edit.lock().await;
        let what = format!("delete Wi-Fi network {id}");
        let snap = self.begin(&what).await?;
        seg_wifi::delete_network(&self.store, id).await.map_err(e)?;
        self.commit(&what, snap, APPLIERS).await
    }

    /// New enrolment secret for `unknown_policy=enrol` (shown once).
    pub async fn wifi_enrol_rotate(&self, id: i64) -> anyhow::Result<Value> {
        let _g = self.edit.lock().await;
        let what = format!("rotate the enrolment secret of Wi-Fi network {id}");
        let snap = self.begin(&what).await?;
        let s = seg_wifi::rotate_enrol_secret(&self.store, id)
            .await
            .map_err(e)?;
        self.commit(&what, snap, APPLIERS).await?;
        Ok(json!({"secret": s}))
    }

    /// A device with its own passphrase; the secret is in the answer, once.
    pub async fn wifi_device_create(&self, i: DeviceInput, network: &str) -> anyhow::Result<Value> {
        let _g = self.edit.lock().await;
        let what = format!("Wi-Fi device {}", i.name);
        let snap = self.begin(&what).await?;
        let issued = seg_wifi::create_wifi_device(&self.store, &i, network)
            .await
            .map_err(e)?;
        self.commit(&what, snap, APPLIERS).await?;
        Ok(issued_json(&issued))
    }

    pub async fn wifi_rotate(&self, device_id: i64, grace_secs: i64) -> anyhow::Result<Value> {
        let _g = self.edit.lock().await;
        let what = format!("rotate the Wi-Fi passphrase of device {device_id}");
        let snap = self.begin(&what).await?;
        let issued = seg_wifi::rotate(&self.store, device_id, grace_secs.clamp(0, 7 * 86400))
            .await
            .map_err(e)?;
        self.commit(&what, snap, APPLIERS).await?;
        Ok(issued_json(&issued))
    }

    pub async fn wifi_revoke_credential(&self, cred_id: i64) -> anyhow::Result<()> {
        let _g = self.edit.lock().await;
        let what = format!("revoke Wi-Fi credential {cred_id}");
        let snap = self.begin(&what).await?;
        seg_wifi::revoke_credential(&self.store, cred_id)
            .await
            .map_err(e)?;
        self.commit(&what, snap, APPLIERS).await
    }

    /// Reveal a stored passphrase (the caller is an administrator); audited.
    pub async fn wifi_reveal(&self, cred_id: i64, user: &str) -> anyhow::Result<Value> {
        let (secret, ssid, security) = seg_wifi::reveal(&self.store, cred_id).await.map_err(e)?;
        self.store
            .audit(
                user,
                "reveal",
                "wifi_credential",
                Some(&cred_id.to_string()),
                &Value::Null,
            )
            .await
            .map_err(e)?;
        let qr = seg_wifi::wifi_uri(&ssid, &secret, &security);
        Ok(json!({
            "secret": secret, "ssid": ssid, "qr": qr,
            "qr_svg": crate::qrcode::generate_qr_code_svg(&qr).ok(),
        }))
    }

    pub async fn wifi_enrol_reveal(&self, network_id: i64, user: &str) -> anyhow::Result<Value> {
        let secret = seg_wifi::enrol_secret(&self.store, network_id)
            .await
            .map_err(e)?;
        self.store
            .audit(
                user,
                "reveal",
                "wifi_enrol_secret",
                Some(&network_id.to_string()),
                &Value::Null,
            )
            .await
            .map_err(e)?;
        Ok(json!({"secret": secret}))
    }

    /// Live stations of every running network, with the device they belong to.
    pub async fn wifi_stations(&self) -> anyhow::Result<Value> {
        let st = self.status("wifi").await?;
        let devices = seg::list_devices(&self.store).await.map_err(e)?;
        let mut out = Vec::new();
        for n in st["networks"].as_array().into_iter().flatten() {
            for s in n["stations"].as_array().into_iter().flatten() {
                let mac = s["mac"].as_str().unwrap_or("");
                let d = devices.iter().find(|d| d.mac.as_deref() == Some(mac));
                out.push(json!({
                    "network": n["network"], "mac": mac, "authorized": s["authorized"],
                    "device": d.map(|d| d.name.clone()), "group": d.map(|d| d.group.clone()),
                }));
            }
        }
        Ok(json!(out))
    }
}
