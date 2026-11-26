//! Configuration import page and API (System > Import, also offered by the first-run setup wizard): bring the
//! configuration of a pfSense / OPNsense box (`config.xml`) or an OpenWrt router (`sysupgrade -b` backup) over, with
//! the same importers as `patronus import pfsense` / `patronus import-uci` (crate patronus-import).
//!
//! - `GET  /import`                          the page
//! - `POST /api/system/import/:kind/plan`    body = the file; `?maps=OLD=NEW,...`: what would be imported, nothing written
//! - `POST /api/system/import/:kind/apply`   (admin) the same, then written into the configuration and applied; the
//!   previous configuration is kept as a revision and put back (and re-applied) when an applier refuses the result
//!
//! `kind` is `pfsense` (pfSense and OPNsense share the config.xml format) or `openwrt`.

use crate::state::AppState;
use askama::Template;
use axum::{
    body::Bytes,
    extract::{Path, Query, State},
    http::StatusCode,
    response::{Html, IntoResponse, Response},
    Json,
};
use serde::Deserialize;
use serde_json::json;

/// The largest file the page accepts (a pfSense config.xml with RRD data runs to a few MB).
pub const MAX_IMPORT: usize = 32 << 20;

#[derive(Template)]
#[template(path = "import.html")]
pub struct ImportTemplate {
    pub page: &'static str,
    pub is_admin: bool,
    pub available: bool,
}

pub async fn page(me: crate::auth::AuthUser) -> Response {
    match (ImportTemplate {
        page: "system",
        is_admin: me.session.role.is_admin(),
        available: cfg!(feature = "import"),
    })
    .render()
    {
        Ok(h) => Html(h.replace("@PATRONUS_VERSION@", env!("CARGO_PKG_VERSION"))).into_response(),
        Err(e) => {
            tracing::error!("render import page: {e}");
            (StatusCode::INTERNAL_SERVER_ERROR, "Failed to render page").into_response()
        }
    }
}

fn error(code: StatusCode, m: impl Into<String>) -> Response {
    (code, Json(json!({ "error": m.into() }))).into_response()
}

#[derive(Debug, Default, Deserialize)]
pub struct ImportQuery {
    /// `OLD=NEW` pairs separated by commas: an interface / port name of the old box -> the Patronus device.
    #[serde(default)]
    pub maps: Option<String>,
}

#[cfg(feature = "import")]
impl ImportQuery {
    fn map_list(&self) -> Vec<String> {
        self.maps
            .as_deref()
            .unwrap_or("")
            .split([',', '\n', ' '])
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect()
    }
}

/// A parsed import: the human-readable plan and a way to write it.
#[cfg(feature = "import")]
enum Prepared {
    /// the plan + the port maps chosen by role (shown above the plan)
    Pfsense(patronus_import::pfsense::PfPlan, Vec<String>),
    Openwrt(patronus_import::uci::Plan),
}

#[cfg(feature = "import")]
impl Prepared {
    fn render(&self) -> String {
        match self {
            Prepared::Pfsense(p, auto) => {
                let mut s = String::new();
                for a in auto {
                    s.push_str(&format!("port matched by role: {a}\n"));
                }
                s + &patronus_import::pfsense::render(p, true)
            }
            Prepared::Openwrt(p) => patronus_import::uci::render(p, true),
        }
    }

    async fn write(
        &self,
        store: &patronus_config::store::ConfigStore,
    ) -> anyhow::Result<Vec<String>> {
        match self {
            Prepared::Pfsense(p, _) => patronus_import::pfsense::apply(store, p).await,
            Prepared::Openwrt(p) => patronus_import::uci::apply(store, p).await,
        }
    }
}

/// Parse the uploaded file. Errors are user errors (400): wrong format, bad map, unreadable archive.
#[cfg(feature = "import")]
async fn prepare(
    kind: &str,
    q: &ImportQuery,
    body: &[u8],
    roles: &[(String, String)],
) -> Result<Prepared, String> {
    use patronus_import::{pfsense, uci};
    if body.is_empty() {
        return Err("Invalid import: the file is empty".into());
    }
    let maps =
        uci::parse_maps(&q.map_list()).map_err(|e| format!("Invalid interface mapping: {e}"))?;
    match kind {
        "pfsense" => {
            let xml = std::str::from_utf8(body).map_err(|_| {
                "Invalid import: a config.xml is text (UTF-8), this file is not".to_string()
            })?;
            // ports the user did not map go to the port with the same role on this box (wan, lan, optN)
            let auto = pfsense::role_maps(xml, roles, &maps);
            let notes: Vec<String> = auto.iter().map(|(o, n)| format!("{o} -> {n}")).collect();
            let mut maps = maps;
            maps.extend(auto);
            pfsense::build_plan(xml, &maps)
                .map(|p| Prepared::Pfsense(p, notes))
                .map_err(|e| format!("Invalid config.xml: {e:#}"))
        }
        "openwrt" => {
            // the importer reads a sysupgrade tarball (or a directory) from disk: a private scratch file, removed after
            let dir = tempfile::Builder::new()
                .prefix("patronus-import-")
                .tempdir()
                .map_err(|e| format!("could not create a scratch directory: {e}"))?;
            let file = dir.path().join("backup.tar.gz");
            tokio::fs::write(&file, body)
                .await
                .map_err(|e| format!("could not store the upload: {e}"))?;
            let f = file.clone();
            let loaded = tokio::task::spawn_blocking(move || uci::load_input_full(&f))
                .await
                .map_err(|e| format!("reading the backup failed: {e}"))?
                .map_err(|e| {
                    format!(
                        "Invalid OpenWrt backup (expected the .tar.gz of `sysupgrade -b`): {e:#}"
                    )
                })?;
            let (files, extras) = loaded;
            Ok(Prepared::Openwrt(uci::build_plan_with(
                &files, &extras, &maps,
            )))
        }
        other => Err(format!(
            "Invalid import kind {other:?}: use pfsense (pfSense / OPNsense config.xml) or openwrt"
        )),
    }
}

/// POST /api/system/import/:kind/plan -- what an import would do; nothing is written.
pub async fn plan(
    State(s): State<AppState>,
    _me: crate::auth::AuthUser,
    Path(kind): Path<String>,
    Query(q): Query<ImportQuery>,
    body: Bytes,
) -> Response {
    #[cfg(feature = "import")]
    {
        let roles = s.config_store.interface_roles().await.unwrap_or_default();
        match prepare(&kind, &q, &body, &roles).await {
            Ok(p) => Json(json!({ "kind": kind, "plan": p.render() })).into_response(),
            Err(m) => error(StatusCode::BAD_REQUEST, m),
        }
    }
    #[cfg(not(feature = "import"))]
    {
        let _ = (s, kind, q, body);
        unavailable()
    }
}

/// POST /api/system/import/:kind/apply (admins) -- import, write, apply; undone as a whole when it cannot be applied.
pub async fn apply(
    State(s): State<AppState>,
    admin: crate::auth::AdminUser,
    Path(kind): Path<String>,
    Query(q): Query<ImportQuery>,
    body: Bytes,
) -> Response {
    #[cfg(feature = "import")]
    {
        let roles = s.config_store.interface_roles().await.unwrap_or_default();
        let p = match prepare(&kind, &q, &body, &roles).await {
            Ok(p) => p,
            Err(m) => return error(StatusCode::BAD_REQUEST, m),
        };
        let what = match kind.as_str() {
            "pfsense" => "a pfSense/OPNsense config.xml",
            _ => "an OpenWrt backup",
        };
        let user = admin.session.username.clone();
        match s
            .system
            .import_and_apply(&s.config_store, &user, what, p.write(&s.config_store))
            .await
        {
            Ok((written, applied)) => {
                let _ = s
                    .config_store
                    .audit(
                        &user,
                        "import",
                        "config",
                        Some(&kind),
                        &json!({ "maps": q.map_list() }),
                    )
                    .await;
                Json(json!({ "ok": true, "kind": kind, "plan": p.render(), "written": written, "applied": applied }))
                    .into_response()
            }
            Err(e) => error(StatusCode::CONFLICT, e.to_string()),
        }
    }
    #[cfg(not(feature = "import"))]
    {
        let _ = (s, admin, kind, q, body);
        unavailable()
    }
}

#[cfg(not(feature = "import"))]
fn unavailable() -> Response {
    error(
        StatusCode::NOT_IMPLEMENTED,
        "this build has no configuration importer (USE=uci-import)",
    )
}

pub fn router() -> axum::Router<AppState> {
    use axum::routing::post;
    axum::Router::new()
        .route("/system/import/:kind/plan", post(plan))
        .route("/system/import/:kind/apply", post(apply))
        .layer(axum::extract::DefaultBodyLimit::max(MAX_IMPORT))
}

pub fn pages() -> axum::Router<AppState> {
    use axum::routing::get;
    axum::Router::new().route("/import", get(page))
}

#[cfg(all(test, feature = "import"))]
mod tests {
    use super::*;

    const XML: &str = r#"<?xml version="1.0"?>
<pfsense>
  <system><hostname>fw1</hostname><domain>example.lan</domain></system>
  <interfaces>
    <wan><enable/><if>em0</if><ipaddr>dhcp</ipaddr></wan>
    <lan><enable/><if>em1</if><ipaddr>192.168.7.1</ipaddr><subnet>24</subnet></lan>
  </interfaces>
</pfsense>"#;

    #[tokio::test]
    async fn pfsense_plan_names_the_mapped_ports() {
        let q = ImportQuery {
            maps: Some("em0=eth0, em1=eth1".into()),
        };
        let p = prepare("pfsense", &q, XML.as_bytes(), &[])
            .await
            .expect("plan");
        let text = p.render();
        assert!(text.contains("eth1"), "{text}");
        assert!(text.contains("192.168.7.1"), "{text}");
        assert!(text.contains("fw1"), "{text}");
    }

    #[tokio::test]
    async fn unmapped_ports_follow_this_box_roles_and_the_plan_says_so() {
        let roles = vec![
            ("enp0s1".to_string(), "wan".to_string()),
            ("enp0s2".to_string(), "lan".to_string()),
        ];
        let p = prepare("pfsense", &ImportQuery::default(), XML.as_bytes(), &roles)
            .await
            .expect("plan");
        let text = p.render();
        assert!(
            text.contains("port matched by role: em1 -> enp0s2"),
            "{text}"
        );
        assert!(text.contains("enp0s2"), "{text}");
        // an explicit map wins over the role
        let q = ImportQuery {
            maps: Some("em1=eth7".into()),
        };
        let text = prepare("pfsense", &q, XML.as_bytes(), &roles)
            .await
            .expect("plan")
            .render();
        assert!(
            !text.contains("em1 -> enp0s2") && text.contains("eth7"),
            "{text}"
        );
    }

    #[tokio::test]
    async fn bad_input_is_a_user_error() {
        let q = ImportQuery::default();
        assert!(prepare("pfsense", &q, b"", &[]).await.is_err());
        assert!(prepare("pfsense", &q, b"\xff\xfe", &[]).await.is_err());
        assert!(prepare("pfsense", &q, b"<not-xml", &[]).await.is_err());
        assert!(prepare("sonicwall", &q, XML.as_bytes(), &[]).await.is_err());
        assert!(prepare("openwrt", &q, b"not a tarball", &[]).await.is_err());
        let bad = ImportQuery {
            maps: Some("nonsense".into()),
        };
        assert!(prepare("pfsense", &bad, XML.as_bytes(), &[]).await.is_err());
    }

    #[test]
    fn maps_split_on_commas_spaces_and_lines() {
        let q = ImportQuery {
            maps: Some("a=b, c=d\ne=f".into()),
        };
        assert_eq!(q.map_list(), vec!["a=b", "c=d", "e=f"]);
        assert!(ImportQuery::default().map_list().is_empty());
    }
}
