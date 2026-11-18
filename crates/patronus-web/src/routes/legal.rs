//! Open-source licenses (`/licenses`, `/licenses/third-party.txt`) and the About links shown on the System page.
//!
//! Everything is served from the box: the page needs no network. The license bundle is the file
//! `ci/third-party-licenses.py` generates for a release (`THIRD-PARTY-LICENSES.txt`, shipped gzip-compressed).
//! Where it is not installed the page says why instead of linking to nothing (the router tier leaves it out to
//! fit the flash budget; a package install carries it by default).
//!
//! Settings (system configuration, so they are part of export/plan/apply and generations; the environment variable
//! overrides, like `PATRONUS_RELEASE_FILE`):
//! - `legal.licenses_file`  path of the bundle (`.gz` is served as it is with `Content-Encoding: gzip`);
//!   default [`DEFAULT_LICENSES_FILE`]; an explicitly empty value turns the bundle off.
//!   Environment: `PATRONUS_LICENSES_FILE`.
//! - `about.site_url`       base address of the product site for the privacy and update-policy links.
//! - `about.source_url`     address of the public source code.

use crate::state::AppState;
use askama::Template;
use axum::{
    extract::State,
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Router,
};

pub const CFG_LICENSES_FILE: &str = "legal.licenses_file";
pub const CFG_SITE_URL: &str = "about.site_url";
pub const CFG_SOURCE_URL: &str = "about.source_url";
pub const DEFAULT_LICENSES_FILE: &str = "/usr/share/doc/patronus/THIRD-PARTY-LICENSES.txt.gz";
pub const DEFAULT_SITE_URL: &str = "https://patronus.errant.solutions";
pub const DEFAULT_SOURCE_URL: &str = "https://github.com/CanuteTheGreat/patronus";
/// Largest bundle the page will serve (the real one is a few MB uncompressed).
pub const MAX_BUNDLE_BYTES: u64 = 32 * 1024 * 1024;

/// Links of the About card (System page) and the licenses page.
#[derive(Clone, Debug)]
pub struct AboutLinks {
    pub site_url: String,
    pub source_url: String,
}

async fn setting(state: &AppState, key: &'static str) -> Option<String> {
    state
        .config_store
        .load_system_config(key)
        .await
        .ok()
        .flatten()
}

/// A configured http(s) address, trailing slashes removed; anything else falls back to the default.
fn clean_url(v: Option<String>, default: &str) -> String {
    match v.map(|s| s.trim().trim_end_matches('/').to_string()) {
        Some(u)
            if (u.starts_with("https://") || u.starts_with("http://"))
                && !u
                    .chars()
                    .any(|c| c.is_whitespace() || c.is_control() || c == '"') =>
        {
            u
        }
        _ => default.to_string(),
    }
}

pub async fn about_links(state: &AppState) -> AboutLinks {
    AboutLinks {
        site_url: clean_url(setting(state, CFG_SITE_URL).await, DEFAULT_SITE_URL),
        source_url: clean_url(setting(state, CFG_SOURCE_URL).await, DEFAULT_SOURCE_URL),
    }
}

/// What the bundle looks like on this box.
#[derive(Debug, PartialEq)]
pub enum Bundle {
    Present { path: String, bytes: u64 },
    Omitted { reason: String },
}

/// `Some(path)` = serve this file; `None` = switched off by an explicitly empty setting.
async fn bundle_path(state: &AppState) -> Option<String> {
    if let Ok(p) = std::env::var("PATRONUS_LICENSES_FILE") {
        return Some(p).filter(|p| !p.trim().is_empty());
    }
    match setting(state, CFG_LICENSES_FILE).await {
        None => Some(DEFAULT_LICENSES_FILE.to_string()),
        Some(p) if p.trim().is_empty() => None,
        Some(p) => Some(p.trim().to_string()),
    }
}

pub fn inspect(path: Option<&str>, embedded_tier: bool) -> Bundle {
    let Some(path) = path else {
        return Bundle::Omitted {
            reason: format!("Switched off: the setting {CFG_LICENSES_FILE} is empty."),
        };
    };
    match std::fs::metadata(path) {
        Ok(m) if m.is_file() && m.len() > 0 && m.len() <= MAX_BUNDLE_BYTES => Bundle::Present {
            path: path.to_string(),
            bytes: m.len(),
        },
        Ok(m) if m.is_file() && m.len() > MAX_BUNDLE_BYTES => Bundle::Omitted {
            reason: format!(
                "The file {path} is larger than the {} MiB this page serves.",
                MAX_BUNDLE_BYTES / 1024 / 1024
            ),
        },
        _ if embedded_tier => Bundle::Omitted {
            reason: format!(
                "Router-tier images leave the license bundle out to fit the flash budget (the file would be {path}). \
                 The same text is attached to every release and is on the product site; \
                 set {CFG_LICENSES_FILE} to a file you copy onto the device to serve it here."
            ),
        },
        _ => Bundle::Omitted {
            reason: format!(
                "The file {path} is not installed on this system. The patronus package installs it; \
                 reinstall the package, or point {CFG_LICENSES_FILE} at your own copy."
            ),
        },
    }
}

#[derive(Template)]
#[template(path = "licenses.html")]
pub struct LicensesTemplate {
    pub page: &'static str,
    pub version: String,
    pub bundle_present: bool,
    pub bundle_size: String,
    pub bundle_gz: bool,
    pub omitted_reason: String,
    pub embedded_tier: bool,
    pub site_url: String,
    pub source_url: String,
}

fn size_text(b: u64) -> String {
    if b >= 1024 * 1024 {
        format!("{:.1} MiB", b as f64 / 1024.0 / 1024.0)
    } else {
        format!("{} KiB", b.div_ceil(1024))
    }
}

/// GET /licenses
pub async fn page(State(state): State<AppState>) -> Response {
    let links = about_links(&state).await;
    let (_, tier, _) = super::release_info();
    let embedded_tier = tier == "embedded";
    let path = bundle_path(&state).await;
    let b = inspect(path.as_deref(), embedded_tier);
    let (present, size, gz, reason) = match &b {
        Bundle::Present { path, bytes } => (
            true,
            size_text(*bytes),
            path.ends_with(".gz"),
            String::new(),
        ),
        Bundle::Omitted { reason } => (false, String::new(), false, reason.clone()),
    };
    super::pages::render(
        &LicensesTemplate {
            page: "licenses",
            version: env!("CARGO_PKG_VERSION").to_string(),
            bundle_present: present,
            bundle_size: size,
            bundle_gz: gz,
            omitted_reason: reason,
            embedded_tier,
            site_url: links.site_url,
            source_url: links.source_url,
        },
        "licenses",
    )
}

/// GET /licenses/third-party.txt: the bundle, as plain text (or a text that says why it is not here).
pub async fn bundle_text(State(state): State<AppState>) -> Response {
    let (_, tier, _) = super::release_info();
    let path = bundle_path(&state).await;
    match inspect(path.as_deref(), tier == "embedded") {
        Bundle::Present { path, .. } => match std::fs::read(&path) {
            Ok(bytes) => {
                let mut r =
                    ([(header::CONTENT_TYPE, "text/plain; charset=utf-8")], bytes).into_response();
                if path.ends_with(".gz") {
                    r.headers_mut().insert(
                        header::CONTENT_ENCODING,
                        header::HeaderValue::from_static("gzip"),
                    );
                }
                r
            }
            Err(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Cannot read {path}: {e}"),
            )
                .into_response(),
        },
        // 200, not 404: the address is a link of the page template, and what it says is the reason.
        Bundle::Omitted { reason } => (
            [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
            format!("The third-party license list is not on this device.\n{reason}\n"),
        )
            .into_response(),
    }
}

pub fn pages() -> Router<AppState> {
    Router::new()
        .route("/licenses", get(page))
        .route("/licenses/third-party.txt", get(bundle_text))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls_are_checked_and_defaulted() {
        assert_eq!(clean_url(None, "https://d"), "https://d");
        assert_eq!(
            clean_url(Some("https://x.test/".into()), "https://d"),
            "https://x.test"
        );
        assert_eq!(
            clean_url(Some("javascript:alert(1)".into()), "https://d"),
            "https://d"
        );
        assert_eq!(
            clean_url(Some("https://x\"y".into()), "https://d"),
            "https://d"
        );
    }

    #[test]
    fn missing_bundle_gives_a_reason_per_tier() {
        let p = "/nonexistent/patronus-licenses.txt.gz";
        match inspect(Some(p), false) {
            Bundle::Omitted { reason } => {
                assert!(reason.contains(p) && reason.contains("package"), "{reason}")
            }
            b => panic!("{b:?}"),
        }
        match inspect(Some(p), true) {
            Bundle::Omitted { reason } => assert!(reason.contains("flash budget"), "{reason}"),
            b => panic!("{b:?}"),
        }
        match inspect(None, false) {
            Bundle::Omitted { reason } => assert!(reason.contains(CFG_LICENSES_FILE)),
            b => panic!("{b:?}"),
        }
    }

    #[test]
    fn present_bundle_is_reported_with_its_size() {
        let d = std::env::temp_dir().join(format!("pat-lic-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let f = d.join("t.txt");
        std::fs::write(&f, b"abc").unwrap();
        assert_eq!(
            inspect(f.to_str(), false),
            Bundle::Present {
                path: f.display().to_string(),
                bytes: 3
            }
        );
        std::fs::write(&f, b"").unwrap();
        assert!(
            matches!(inspect(f.to_str(), false), Bundle::Omitted { .. }),
            "empty file counts as missing"
        );
        std::fs::remove_dir_all(&d).ok();
    }
}
