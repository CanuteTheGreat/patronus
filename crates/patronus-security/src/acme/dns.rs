//! DNS-01 providers behind one trait.  New providers add one impl and one
//! arm in [`DnsProviderConfig::build`].

use super::rfc2136::{build_update, send, TsigAlgorithm, TsigKey, UpdateOp};
use super::AcmeError;
use async_trait::async_trait;
use base64::Engine;
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Publishes and removes the `_acme-challenge` TXT record.
#[async_trait]
pub trait DnsProvider: Send + Sync {
    /// Short name for logs and the UI ("cloudflare", "rfc2136").
    fn name(&self) -> &'static str;
    async fn present(&self, fqdn: &str, value: &str) -> Result<(), AcmeError>;
    async fn cleanup(&self, fqdn: &str, value: &str) -> Result<(), AcmeError>;
}

/// Typed provider settings (the declarative-config shape).  Secrets are
/// carried as strings here and are never printed by `Debug`.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "provider", rename_all = "kebab-case")]
pub enum DnsProviderConfig {
    Rfc2136 {
        /// `host:port` of the primary that accepts updates.
        server: String,
        /// Zone apex the update is addressed to.
        zone: String,
        #[serde(default)]
        tsig_key_name: String,
        #[serde(default = "default_alg")]
        tsig_algorithm: String,
        /// Base64 TSIG secret (empty = unsigned, only for ACL-protected servers).
        #[serde(default)]
        tsig_secret: String,
        #[serde(default = "default_ttl")]
        ttl: u32,
        #[serde(default = "default_timeout")]
        timeout_secs: u64,
    },
    Cloudflare {
        api_token: String,
        /// API base; typed so tests and proxies can point elsewhere.
        #[serde(default = "default_cf_base")]
        api_base: String,
        #[serde(default = "default_ttl")]
        ttl: u32,
        #[serde(default = "default_timeout")]
        timeout_secs: u64,
    },
}

fn default_alg() -> String {
    "hmac-sha256".into()
}
fn default_ttl() -> u32 {
    60
}
fn default_timeout() -> u64 {
    10
}
fn default_cf_base() -> String {
    "https://api.cloudflare.com/client/v4".into()
}

impl std::fmt::Debug for DnsProviderConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Rfc2136 {
                server,
                zone,
                tsig_key_name,
                ..
            } => f
                .debug_struct("Rfc2136")
                .field("server", server)
                .field("zone", zone)
                .field("tsig_key_name", tsig_key_name)
                .finish_non_exhaustive(),
            Self::Cloudflare { api_base, .. } => f
                .debug_struct("Cloudflare")
                .field("api_base", api_base)
                .finish_non_exhaustive(),
        }
    }
}

impl DnsProviderConfig {
    pub fn build(&self) -> Result<Box<dyn DnsProvider>, AcmeError> {
        match self {
            Self::Rfc2136 {
                server,
                zone,
                tsig_key_name,
                tsig_algorithm,
                tsig_secret,
                ttl,
                timeout_secs,
            } => {
                if server.is_empty() || zone.is_empty() {
                    return Err(AcmeError::Config("rfc2136 needs server and zone".into()));
                }
                let key = if tsig_secret.is_empty() {
                    None
                } else {
                    if tsig_key_name.is_empty() {
                        return Err(AcmeError::Config("rfc2136 tsig_key_name missing".into()));
                    }
                    let secret = base64::engine::general_purpose::STANDARD
                        .decode(tsig_secret.trim())
                        .map_err(|_| AcmeError::Config("tsig_secret is not base64".into()))?;
                    Some(TsigKey {
                        name: tsig_key_name.clone(),
                        algorithm: TsigAlgorithm::parse(tsig_algorithm)?,
                        secret,
                    })
                };
                Ok(Box::new(Rfc2136 {
                    server: server.clone(),
                    zone: zone.clone(),
                    key,
                    ttl: *ttl,
                    timeout: Duration::from_secs(*timeout_secs),
                }))
            }
            Self::Cloudflare {
                api_token,
                api_base,
                ttl,
                timeout_secs,
            } => {
                if api_token.is_empty() {
                    return Err(AcmeError::Config("cloudflare api_token missing".into()));
                }
                let http = reqwest::Client::builder()
                    .timeout(Duration::from_secs(*timeout_secs))
                    .build()
                    .map_err(|e| AcmeError::Dns(e.to_string()))?;
                Ok(Box::new(Cloudflare {
                    token: api_token.clone(),
                    base: api_base.trim_end_matches('/').to_string(),
                    ttl: *ttl,
                    http,
                }))
            }
        }
    }
}

pub struct Rfc2136 {
    server: String,
    zone: String,
    key: Option<TsigKey>,
    ttl: u32,
    timeout: Duration,
}

impl Rfc2136 {
    async fn update(&self, fqdn: &str, value: &str, op: UpdateOp) -> Result<(), AcmeError> {
        let mut idb = [0u8; 2];
        getrandom::getrandom(&mut idb).map_err(|e| AcmeError::Dns(e.to_string()))?;
        let id = u16::from_be_bytes(idb);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let msg = build_update(
            id,
            &self.zone,
            fqdn,
            value,
            self.ttl,
            op,
            self.key.as_ref(),
            now,
            300,
        )?;
        send(&self.server, &msg, id, self.timeout).await
    }
}

#[async_trait]
impl DnsProvider for Rfc2136 {
    fn name(&self) -> &'static str {
        "rfc2136"
    }
    async fn present(&self, fqdn: &str, value: &str) -> Result<(), AcmeError> {
        self.update(fqdn, value, UpdateOp::Add).await
    }
    async fn cleanup(&self, fqdn: &str, value: &str) -> Result<(), AcmeError> {
        self.update(fqdn, value, UpdateOp::Remove).await
    }
}

pub struct Cloudflare {
    token: String,
    base: String,
    ttl: u32,
    http: reqwest::Client,
}

#[derive(Deserialize)]
struct CfEnvelope<T> {
    success: bool,
    #[serde(default)]
    errors: Vec<serde_json::Value>,
    result: Option<T>,
}

impl Cloudflare {
    async fn call<T: for<'de> Deserialize<'de>>(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<serde_json::Value>,
    ) -> Result<T, AcmeError> {
        let mut r = self
            .http
            .request(method, format!("{}{}", self.base, path))
            .bearer_auth(&self.token);
        if let Some(b) = body {
            r = r.json(&b);
        }
        let resp = r
            .send()
            .await
            .map_err(|e| AcmeError::Dns(format!("cloudflare: {e}")))?;
        let env: CfEnvelope<T> = resp
            .json()
            .await
            .map_err(|e| AcmeError::Dns(format!("cloudflare reply: {e}")))?;
        match (env.success, env.result) {
            (true, Some(r)) => Ok(r),
            _ => Err(AcmeError::Dns(format!(
                "cloudflare refused: {:?}",
                env.errors
            ))),
        }
    }

    /// Longest-suffix zone match for `fqdn`.
    async fn zone_id(&self, fqdn: &str) -> Result<String, AcmeError> {
        let labels: Vec<&str> = fqdn.trim_end_matches('.').split('.').collect();
        for i in 0..labels.len().saturating_sub(1) {
            let cand = labels[i..].join(".");
            let zones: Vec<serde_json::Value> = self
                .call(reqwest::Method::GET, &format!("/zones?name={cand}"), None)
                .await?;
            if let Some(id) = zones.first().and_then(|z| z["id"].as_str()) {
                return Ok(id.to_string());
            }
        }
        Err(AcmeError::Dns(format!("no Cloudflare zone for {fqdn}")))
    }
}

#[async_trait]
impl DnsProvider for Cloudflare {
    fn name(&self) -> &'static str {
        "cloudflare"
    }
    async fn present(&self, fqdn: &str, value: &str) -> Result<(), AcmeError> {
        let zid = self.zone_id(fqdn).await?;
        let _: serde_json::Value = self
            .call(
                reqwest::Method::POST,
                &format!("/zones/{zid}/dns_records"),
                Some(serde_json::json!({"type":"TXT","name":fqdn,"content":value,"ttl":self.ttl.max(60)})),
            )
            .await?;
        Ok(())
    }
    async fn cleanup(&self, fqdn: &str, value: &str) -> Result<(), AcmeError> {
        let zid = self.zone_id(fqdn).await?;
        let recs: Vec<serde_json::Value> = self
            .call(
                reqwest::Method::GET,
                &format!("/zones/{zid}/dns_records?type=TXT&name={fqdn}"),
                None,
            )
            .await?;
        for r in recs {
            let content = r["content"].as_str().unwrap_or("").trim_matches('"');
            if content == value {
                if let Some(id) = r["id"].as_str() {
                    let _: serde_json::Value = self
                        .call(
                            reqwest::Method::DELETE,
                            &format!("/zones/{zid}/dns_records/{id}"),
                            None,
                        )
                        .await?;
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_roundtrip_and_debug_hides_secrets() {
        let c: DnsProviderConfig =
            serde_json::from_str(r#"{"provider":"cloudflare","api_token":"SECRETTOKEN"}"#).unwrap();
        assert!(!format!("{c:?}").contains("SECRETTOKEN"));
        let r: DnsProviderConfig = serde_json::from_str(
            r#"{"provider":"rfc2136","server":"127.0.0.1:53","zone":"example.org","tsig_key_name":"k","tsig_secret":"c2VjcmV0"}"#,
        )
        .unwrap();
        assert!(!format!("{r:?}").contains("c2VjcmV0"));
        assert!(r.build().is_ok());
    }

    #[test]
    fn rfc2136_rejects_bad_config() {
        let c = DnsProviderConfig::Rfc2136 {
            server: "".into(),
            zone: "z".into(),
            tsig_key_name: "".into(),
            tsig_algorithm: default_alg(),
            tsig_secret: "".into(),
            ttl: 60,
            timeout_secs: 1,
        };
        assert!(c.build().is_err());
        let c = DnsProviderConfig::Rfc2136 {
            server: "h:53".into(),
            zone: "z".into(),
            tsig_key_name: "k".into(),
            tsig_algorithm: default_alg(),
            tsig_secret: "!!notbase64".into(),
            ttl: 60,
            timeout_secs: 1,
        };
        assert!(c.build().is_err());
    }

    #[test]
    fn cloudflare_needs_token() {
        let c = DnsProviderConfig::Cloudflare {
            api_token: "".into(),
            api_base: default_cf_base(),
            ttl: 60,
            timeout_secs: 1,
        };
        assert!(c.build().is_err());
    }
}
