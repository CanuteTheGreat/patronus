//! HA configuration sync, web side (lane G phase 2, docs/HA-MAINTENANCE.md).
//!
//! Source node: a background task looks every `ha.cfgsync.check_secs` whether the switched-on
//! sections changed and pushes them (`POST /api/ha/sync/receive` on the peer) with curl: HTTPS,
//! the peer's public key pinned (`--pinnedpubkey`, so the API key is never sent to a server that
//! is not the peer), the key and the body on stdin. Target node: `receive` merges the sections into
//! its own configuration and applies it through `SystemManager::restore` (revision kept, undone
//! and re-applied when an applier refuses), then answers with the result; the source records it.

#![cfg(feature = "ha")]

use crate::state::AppState;
use patronus_config::hasync;
use patronus_network::{ha, ha_sync};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicI64, Ordering};

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub fn b64(data: &[u8]) -> String {
    let mut o = String::new();
    for c in data.chunks(3) {
        let n = (u32::from(c[0]) << 16)
            | (u32::from(*c.get(1).unwrap_or(&0)) << 8)
            | u32::from(*c.get(2).unwrap_or(&0));
        for i in 0..4 {
            if i <= c.len() {
                o.push(B64[((n >> (18 - 6 * i)) & 63) as usize] as char);
            } else {
                o.push('=');
            }
        }
    }
    o
}

fn unb64(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let (mut acc, mut bits) = (0u32, 0);
    for ch in s.bytes().filter(|b| !b.is_ascii_whitespace() && *b != b'=') {
        let v = B64.iter().position(|b| *b == ch)? as u32;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    Some(out)
}

/// One DER element at the start of `d`: (tag, content, whole element length).
fn tlv(d: &[u8]) -> Option<(u8, &[u8], usize)> {
    let tag = *d.first()?;
    let l0 = *d.get(1)? as usize;
    let (len, hdr) = if l0 < 0x80 {
        (l0, 2)
    } else {
        let n = l0 & 0x7f;
        if n == 0 || n > 4 {
            return None;
        }
        let mut l = 0usize;
        for b in d.get(2..2 + n)? {
            l = (l << 8) | *b as usize;
        }
        (l, 2 + n)
    };
    let content = d.get(hdr..hdr + len)?;
    Some((tag, content, hdr + len))
}

/// `sha256//<base64>` pin (curl's `--pinnedpubkey`) of the first certificate in a PEM.
pub fn spki_pin(pem: &str) -> Option<String> {
    let b = pem.split("-----BEGIN CERTIFICATE-----").nth(1)?;
    let b = b.split("-----END CERTIFICATE-----").next()?;
    let der = unb64(b)?;
    let (_, cert, _) = tlv(&der)?;
    let (_, tbs, _) = tlv(cert)?;
    let mut rest = tbs;
    // optional [0] version, then serial, signature, issuer, validity, subject
    let (t, _, n) = tlv(rest)?;
    if t == 0xA0 {
        rest = &rest[n..];
    }
    for _ in 0..5 {
        let (_, _, n) = tlv(rest)?;
        rest = &rest[n..];
    }
    let (t, _, n) = tlv(rest)?;
    if t != 0x30 {
        return None;
    }
    Some(format!("sha256//{}", b64(&Sha256::digest(&rest[..n]))))
}

/// This node's own pin (what the other node's settings need).
pub async fn own_pin(state: &AppState) -> Option<String> {
    let w = patronus_config::webui::load(&state.config_store)
        .await
        .ok()?;
    let path = if w.tls_cert.is_empty() {
        crate::tls::default_tls_dir().join("cert.pem")
    } else {
        std::path::PathBuf::from(&w.tls_cert)
    };
    spki_pin(&std::fs::read_to_string(path).ok()?)
}

pub fn hash_of(doc: &Value) -> String {
    Sha256::digest(hasync::canonical(doc).as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

#[derive(Debug)]
pub struct Pushed {
    pub sections: Vec<String>,
    pub hash: String,
    pub unchanged: bool,
    pub message: String,
}

fn quote(s: &str) -> String {
    crate::state::telemetry::curl_quote(s)
}

/// curl with the config on stdin; returns (HTTP status, body).
async fn curl(cfg: String) -> anyhow::Result<(u16, String)> {
    use tokio::io::AsyncWriteExt;
    let mut child = tokio::process::Command::new("curl")
        .args(["-K", "-"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| anyhow::anyhow!("cannot run curl: {e}"))?;
    if let Some(mut si) = child.stdin.take() {
        si.write_all(cfg.as_bytes()).await?;
    }
    let out = child.wait_with_output().await?;
    if !out.status.success() {
        let e = String::from_utf8_lossy(&out.stderr).trim().to_string();
        anyhow::bail!(
            "{}",
            if e.is_empty() {
                format!("curl failed ({})", out.status)
            } else {
                e
            }
        );
    }
    let text = String::from_utf8_lossy(&out.stdout).to_string();
    let (body, code) = text.rsplit_once('\n').unwrap_or(("", &text));
    Ok((code.trim().parse().unwrap_or(0), body.to_string()))
}

fn host_name() -> String {
    std::fs::read_to_string("/etc/hostname")
        .unwrap_or_default()
        .trim()
        .to_string()
}

/// Push the switched-on sections now. `force` pushes even when nothing changed since the last
/// good push. Every attempt is recorded in the history; a refusal by the peer is an `Err` with
/// the peer's own words.
pub async fn push(state: &AppState, force: bool) -> anyhow::Result<Pushed> {
    let store = &state.config_store;
    let s = ha_sync::sync_settings(store)
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let hs = ha::settings(store)
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let base = ha_sync::peer_base(&s, hs.peer.as_deref()).ok_or_else(|| {
        anyhow::anyhow!("Invalid: no peer address (set the peer URL or the HA peer)")
    })?;
    let pin = s
        .peer_pin
        .clone()
        .ok_or_else(|| anyhow::anyhow!("Invalid: no peer TLS pin"))?;
    if s.api_key.is_empty() {
        anyhow::bail!("Invalid: no API key for the peer");
    }
    let doc = hasync::export_sections(store, &s.sections)
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let hash = hash_of(&doc);
    if !force
        && ha_sync::last_pushed_hash(store)
            .await
            .map_err(|e| anyhow::anyhow!("{e}"))?
            .as_deref()
            == Some(hash.as_str())
    {
        return Ok(Pushed {
            sections: s.sections,
            hash,
            unchanged: true,
            message: "the peer already has this configuration".into(),
        });
    }
    let body = json!({"source": host_name(), "hash": hash, "config": doc}).to_string();
    let cfg = format!(
        "url = {}\nrequest = \"POST\"\nsilent\nshow-error\ninsecure\npinnedpubkey = {}\nmax-time = {}\n\
         user-agent = \"Patronus-HA-Sync/1.0\"\nheader = \"Content-Type: application/json\"\n\
         header = {}\nwrite-out = \"\\n%{{http_code}}\"\ndata-binary = {}\n",
        quote(&format!("{base}/api/ha/sync/receive")),
        quote(&pin),
        s.timeout_secs,
        quote(&format!("Authorization: Bearer {}", s.api_key)),
        quote(&body),
    );
    let t0 = std::time::Instant::now();
    let r = curl(cfg).await;
    let ms = t0.elapsed().as_millis() as i64;
    let result: anyhow::Result<String> = match r {
        Err(e) => Err(anyhow::anyhow!("cannot reach the peer: {e}")),
        Ok((code, text)) => {
            let j: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
            if (200..300).contains(&code) {
                Ok(j["message"].as_str().unwrap_or("applied").to_string())
            } else {
                Err(anyhow::anyhow!(
                    "the peer refused (HTTP {code}): {}",
                    j["error"].as_str().unwrap_or(text.trim())
                ))
            }
        }
    };
    let (ok, msg) = match &result {
        Ok(m) => (true, m.clone()),
        Err(e) => (false, e.to_string()),
    };
    let _ = ha_sync::record(
        store,
        "push",
        &base,
        &s.sections,
        ok,
        &msg,
        ms,
        if ok { &hash } else { "" },
    )
    .await;
    let kind = if ok { "info" } else { "warning" };
    let e = crate::state::telemetry::Event {
        id: 0,
        ts: chrono::Utc::now().timestamp(),
        kind: "ha_sync".into(),
        subject: base.clone(),
        severity: kind.into(),
        detail: if ok {
            format!("configuration pushed ({}): {msg}", s.sections.join(", "))
        } else {
            format!("configuration push failed: {msg}")
        },
    };
    let _ = crate::state::telemetry::record(store, &e).await;
    result.map(|message| Pushed {
        sections: s.sections,
        hash,
        unchanged: false,
        message,
    })
}

/// The target side: merge, apply, keep a revision, undo on refusal. Returns the message for the
/// source. Errors are the reason the pushed configuration was NOT applied.
pub async fn receive(state: &AppState, body: &Value) -> anyhow::Result<String> {
    let store = &state.config_store;
    let s = ha_sync::sync_settings(store)
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let source = body["source"].as_str().unwrap_or("peer").to_string();
    let t0 = std::time::Instant::now();
    let done = |ok: bool, msg: String, secs: Vec<String>, hash: String| {
        let store = store.clone();
        let source = source.clone();
        async move {
            let _ = ha_sync::record(
                &store,
                "receive",
                &source,
                &secs,
                ok,
                &msg,
                t0.elapsed().as_millis() as i64,
                &hash,
            )
            .await;
            let e = crate::state::telemetry::Event {
                id: 0,
                ts: chrono::Utc::now().timestamp(),
                kind: "ha_sync".into(),
                subject: source,
                severity: if ok { "info" } else { "warning" }.into(),
                detail: if ok {
                    format!("configuration received: {msg}")
                } else {
                    format!("configuration from the peer NOT applied: {msg}")
                },
            };
            let _ = crate::state::telemetry::record(&store, &e).await;
        }
    };
    if !s.accept {
        anyhow::bail!(
            "this node does not accept pushed configuration (HA configuration sync is off here)"
        );
    }
    if s.push {
        anyhow::bail!("this node is itself a sync source (it pushes its configuration)");
    }
    let cfg = body
        .get("config")
        .ok_or_else(|| anyhow::anyhow!("Invalid sync request: no 'config'"))?;
    let secs: Vec<String> = cfg["sections"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    let hash = body["hash"].as_str().unwrap_or_default().to_string();
    let r: anyhow::Result<String> = async {
        let local = store
            .export_json()
            .await
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        let merged = hasync::merge(&local, cfg).map_err(|e| anyhow::anyhow!("{e}"))?;
        // nothing different: no revision, no re-apply
        let mine = hasync::export_sections(store, &secs)
            .await
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        if hasync::canonical(&mine) == hasync::canonical(cfg) {
            return Ok("already up to date".to_string());
        }
        let notes = state
            .system
            .restore(store, &merged, &format!("HA sync from {source}"))
            .await?;
        Ok(format!(
            "applied {} ({} step(s))",
            secs.join(", "),
            notes.len()
        ))
    }
    .await;
    match &r {
        Ok(m) => done(true, m.clone(), secs, hash).await,
        Err(e) => done(false, e.to_string(), secs, String::new()).await,
    }
    r
}

static LAST_ATTEMPT: AtomicI64 = AtomicI64::new(0);

/// The source node's background task: push when the switched-on sections changed.
pub fn spawn_pusher(state: AppState) {
    tokio::spawn(async move {
        loop {
            let s = match ha_sync::sync_settings(&state.config_store).await {
                Ok(s) => s,
                Err(_) => {
                    tokio::time::sleep(std::time::Duration::from_secs(20)).await;
                    continue;
                }
            };
            let wait = u64::from(s.check_secs);
            if s.push && !s.api_key.is_empty() {
                let now = chrono::Utc::now().timestamp();
                let last = LAST_ATTEMPT.load(Ordering::Relaxed);
                let failed_recently = last != 0
                    && now - last < i64::from(s.retry_secs)
                    && ha_sync::status(&state.config_store)
                        .await
                        .map(|v| v["last_push"]["ok"] == false)
                        .unwrap_or(false);
                if !failed_recently {
                    match push(&state, false).await {
                        Ok(p) if p.unchanged => {}
                        Ok(_) => LAST_ATTEMPT.store(now, Ordering::Relaxed),
                        Err(e) => {
                            LAST_ATTEMPT.store(now, Ordering::Relaxed);
                            tracing::warn!("HA sync: {e}");
                        }
                    }
                }
            }
            tokio::time::sleep(std::time::Duration::from_secs(wait)).await;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_round_trips() {
        for d in [
            &b""[..],
            b"a",
            b"ab",
            b"abc",
            b"abcd",
            &[0xff, 0xfe, 0x00, 0x10],
        ] {
            assert_eq!(unb64(&b64(d)).unwrap(), d);
        }
        assert_eq!(b64(b"Man"), "TWFu");
        assert_eq!(b64(b"Ma"), "TWE=");
    }

    #[cfg(feature = "tls-rustls")]
    #[test]
    fn pin_matches_the_public_key_of_a_generated_certificate() {
        let c = rcgen::generate_simple_self_signed(vec!["fw.lan".to_string()]).unwrap();
        let pem = c.serialize_pem().unwrap();
        let spki = c.get_key_pair().public_key_der();
        let pin = spki_pin(&pem).unwrap();
        assert!(pin.starts_with("sha256//") && pin.len() == 8 + 44, "{pin}");
        // the SPKI of the cert is the key pair's public key DER (rcgen: SubjectPublicKeyInfo)
        let want = format!("sha256//{}", b64(&Sha256::digest(&spki)));
        assert_eq!(pin, want);
        assert!(spki_pin("not a cert").is_none());
    }

    #[test]
    fn hash_ignores_key_order() {
        assert_eq!(
            hash_of(&json!({"a":1,"b":[1,2]})),
            hash_of(&serde_json::from_str::<Value>(r#"{"b":[1,2],"a":1}"#).unwrap())
        );
    }
}
