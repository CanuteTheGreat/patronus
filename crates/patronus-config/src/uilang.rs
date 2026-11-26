//! The system-wide default language of the web UI and the API's messages.
//!
//! Layers, lowest to highest (a higher layer replaces a lower one):
//!
//! 1. built-in: `auto` = follow the browser's `Accept-Language`, English when no catalog
//!    matches;
//! 2. environment `PATRONUS_UI_LANGUAGE` (an image's deployment default);
//! 3. `[ui] language = "de"` of `/etc/patronus/patronus.toml`;
//! 4. the config store (`system_config` key `ui.language`, set on the System page or through
//!    `PUT /api/i18n/system`, carried by export/plan/apply, backups and GitOps).
//!
//! An account's own language (`web_users.language`) and the browser's choice on the login page
//! come before this default; the order is decided in `patronus-web` (`i18n::choose`).

use crate::store::ConfigStore;
use patronus_core::{Error, Result};

pub const K_LANGUAGE: &str = "ui.language";
/// Built-in default: follow the browser.
pub const AUTO: &str = "auto";
/// Shown when no catalog matches what the browser asks for.
pub const FALLBACK_LANGUAGE: &str = "en";
pub const ENV_LANGUAGE: &str = "PATRONUS_UI_LANGUAGE";

/// A language tag as the UI accepts it (`de`, `pt-br`), or `auto`; None = not a tag.
pub fn normalize(s: &str) -> Option<String> {
    let t = s.trim().to_ascii_lowercase().replace('_', "-");
    if t == AUTO {
        return Some(t);
    }
    let ok = !t.is_empty()
        && t.len() <= 16
        && t.split('-').enumerate().all(|(i, p)| {
            let n = p.len();
            p.chars().all(|c| c.is_ascii_alphanumeric())
                && if i == 0 {
                    (2..=3).contains(&n)
                } else {
                    (1..=8).contains(&n)
                }
        });
    ok.then_some(t)
}

pub fn from_env_with(get: impl Fn(&str) -> Option<String>) -> Option<String> {
    get(ENV_LANGUAGE).and_then(|v| normalize(&v))
}

/// Layer 3: `[ui] language` of patronus.toml text.
pub fn from_toml(text: &str) -> Option<String> {
    #[derive(serde::Deserialize, Default)]
    struct File {
        #[serde(default)]
        ui: Ui,
    }
    #[derive(serde::Deserialize, Default)]
    struct Ui {
        language: Option<String>,
    }
    let f: File = toml::from_str(text).ok()?;
    f.ui.language.and_then(|v| normalize(&v))
}

/// The effective system default (`auto` or a language tag).
pub async fn resolve(store: Option<&ConfigStore>) -> String {
    let path = crate::defaults::default_bootstrap_path();
    let toml = std::fs::read_to_string(path).unwrap_or_default();
    let mut v = AUTO.to_string();
    if let Some(e) = from_env_with(|k| std::env::var(k).ok()) {
        v = e;
    }
    if let Some(t) = from_toml(&toml) {
        v = t;
    }
    if let Some(st) = store {
        if let Some(s) = stored(st).await.and_then(|s| normalize(&s)) {
            v = s;
        }
    }
    v
}

/// The raw stored value (None = not set).
pub async fn stored(store: &ConfigStore) -> Option<String> {
    store
        .load_system_config(K_LANGUAGE)
        .await
        .ok()
        .flatten()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

/// Store the default; an empty value clears it (back to the lower layers). Whether a catalog
/// exists for the tag is checked by the caller (the web crate knows its catalogs).
pub async fn save(store: &ConfigStore, value: &str) -> Result<()> {
    let v = value.trim();
    if v.is_empty() {
        return store.save_system_config(K_LANGUAGE, "").await;
    }
    match normalize(v) {
        Some(n) => store.save_system_config(K_LANGUAGE, &n).await,
        None => Err(Error::Config(format!(
            "Invalid language '{v}': use a language tag such as en or de, or auto"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tags_are_normalised_and_junk_refused() {
        assert_eq!(normalize(" DE ").as_deref(), Some("de"));
        assert_eq!(normalize("pt_BR").as_deref(), Some("pt-br"));
        assert_eq!(normalize("AUTO").as_deref(), Some("auto"));
        assert_eq!(normalize("../etc"), None);
        assert_eq!(normalize("x"), None);
        assert_eq!(normalize(""), None);
    }

    #[test]
    fn layers_toml_and_env() {
        assert_eq!(
            from_toml("[ui]\nlanguage = \"de\"\n").as_deref(),
            Some("de")
        );
        assert_eq!(from_toml("[web]\nhttps_port = 443\n"), None);
        assert_eq!(
            from_env_with(|k| (k == ENV_LANGUAGE).then(|| "fr".to_string())).as_deref(),
            Some("fr")
        );
        assert_eq!(from_env_with(|_| None), None);
    }

    #[tokio::test]
    async fn store_layer_wins_and_clears() {
        let store = ConfigStore::open_in_memory().await.expect("store");
        assert_eq!(stored(&store).await, None);
        save(&store, "de").await.expect("save");
        assert_eq!(stored(&store).await.as_deref(), Some("de"));
        assert_eq!(resolve(Some(&store)).await, "de");
        assert!(save(&store, "not a tag!").await.is_err());
        save(&store, "").await.expect("clear");
        assert_eq!(stored(&store).await, None);
    }
}
