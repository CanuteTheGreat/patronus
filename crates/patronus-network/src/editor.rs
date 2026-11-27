//! Default text editor (System page, `PUT /api/system/editor`, GitOps `kind: DefaultEditor`).
//!
//! Store and validation live in `patronus_config::editor` (the one row `system_editor`, written by
//! patronus.toml `[system] editor`, the API and GitOps). This module is the applier: it turns the
//! stored choice into the system's editor, as root, at every boot and after every change.
//!
//! * standard tier: `default-editor set <choice>` (the tool shipped with the image: writes
//!   `/etc/default-editor.conf` and `/etc/env.d/99editor`, runs env-update; init-neutral). A choice
//!   whose binary is missing is refused with the package to install instead of the tool's silent
//!   fallback: `neovim` needs `app-editors/neovim` (USE=neovim of the package, optional everywhere
//!   but the router tier).
//! * embedded tier: no `default-editor` tool (busybox only); the applier writes
//!   `/etc/default-editor.conf`, which `/etc/profile.d/10-editor.sh` reads at login. Only `vi` and
//!   an installed absolute path are accepted.
//!
//! No stored row = never touched: a hand-edited editor survives.

use crate::general::write_atomic;
use crate::lan::{invalid, LanEnv};
use async_trait::async_trait;
use patronus_config::applier::{Applier, ApplyReport, Phase};
use patronus_config::editor as cfg;
use patronus_config::store::ConfigStore;
use patronus_config::{DeclarativeConfig, ResourceKind};
use patronus_core::{Error, Result};
use serde_json::{json, Value};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;

/// The tool of the image (`gentoo/live-iso/common/overlay/usr/sbin/default-editor`).
pub const TOOL: &str = "/usr/sbin/default-editor";
const CONF: &str = "/etc/default-editor.conf";
const ENVD: &str = "/etc/env.d/99editor";
/// The one GitOps resource of this kind.
pub const RESOURCE_NAME: &str = "default-editor";

/// Where the tool looks for each named editor (the same lists as the tool's `path_of`).
pub fn candidates(choice: &str) -> Vec<String> {
    match choice {
        "vim" => vec!["/usr/bin/vim", "/bin/vim", "/usr/sbin/vim"],
        "neovim" => vec!["/usr/bin/nvim"],
        "nano" => vec!["/bin/nano", "/usr/bin/nano"],
        "vi" => vec!["/usr/bin/vi", "/bin/vi"],
        p => vec![p],
    }
    .into_iter()
    .map(String::from)
    .collect()
}

/// The package that provides a named editor (for the "not installed" message).
fn package(choice: &str) -> Option<&'static str> {
    match choice {
        "vim" => Some("app-editors/vim"),
        "neovim" => Some("app-editors/neovim"),
        "nano" => Some("app-editors/nano"),
        _ => None,
    }
}

fn is_exec(p: &Path) -> bool {
    std::fs::metadata(p)
        .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

/// The installed binary of `choice` under `env` (`None` = not installed).
pub fn installed(env: &LanEnv, choice: &str) -> Option<String> {
    candidates(choice)
        .into_iter()
        .find(|c| is_exec(&env.path(c)))
}

/// `EDITOR_CHOICE` of a conf file's text (the last assignment wins, like the tool).
pub fn conf_choice(text: &str) -> Option<String> {
    text.lines()
        .filter_map(|l| l.trim().strip_prefix("EDITOR_CHOICE="))
        .map(|v| {
            v.split(['#', ' ', '\t'])
                .next()
                .unwrap_or("")
                .trim_matches('"')
                .to_string()
        })
        .rfind(|v| !v.is_empty())
}

/// `EDITOR` of the generated `/etc/env.d/99editor`.
fn envd_editor(text: &str) -> Option<String> {
    text.lines()
        .find_map(|l| l.strip_prefix("EDITOR="))
        .map(|v| v.trim_matches('"').to_string())
        .filter(|v| !v.is_empty())
}

fn embedded_at(env: &LanEnv) -> bool {
    cfg::embedded_tier_at(&env.path("/etc/patronus-release"))
}

/// What the page and `GET /api/system/editor` show.
pub async fn overview(store: &ConfigStore, env: &LanEnv, embedded: bool) -> Result<Value> {
    let stored = cfg::get(store).await?;
    let conf = std::fs::read_to_string(env.path(CONF)).unwrap_or_default();
    let effective = std::fs::read_to_string(env.path(ENVD))
        .ok()
        .and_then(|t| envd_editor(&t));
    let choices: Vec<Value> = cfg::choices(embedded)
        .into_iter()
        .map(|(name, why)| {
            json!({
                "name": name,
                "available": why.is_none(),
                // omitted on this tier: the reason is shown, the entry is never hidden
                "reason": why,
                "installed": installed(env, name),
                "package": package(name),
            })
        })
        .collect();
    Ok(json!({
        "settings": { "editor": stored },
        "default": if embedded { cfg::EMBEDDED_DEFAULT } else { cfg::DEFAULT },
        "configured": conf_choice(&conf),
        "effective": effective,
        "embedded": embedded,
        "accepts": if embedded {
            "vi (busybox) or the absolute path of an installed editor"
        } else {
            "vim, neovim, nano, vi or an absolute path"
        },
        "choices": choices,
    }))
}

#[derive(Clone, Default)]
pub struct EditorApplier {
    env: LanEnv,
}

impl EditorApplier {
    pub fn new(env: LanEnv) -> Self {
        Self { env }
    }

    fn not_installed(&self, choice: &str, embedded: bool) -> Error {
        let how = match (package(choice), embedded) {
            (Some(p), false) => format!("emerge {p}"),
            (Some(_), true) => "this tier does not carry it".to_string(),
            (None, _) => "install it or choose another editor".to_string(),
        };
        invalid(format!(
            "editor {choice:?}: {} is not installed ({how})",
            candidates(choice).join(" or ")
        ))
    }

    fn run_tool(&self, choice: &str) -> Result<()> {
        let tool = self.env.path(TOOL);
        if !is_exec(&tool) {
            return Err(Error::Service(format!(
                "{TOOL} is not installed: the default editor cannot be applied"
            )));
        }
        let mut cmd = Command::new(&tool);
        cmd.arg("set").arg(choice);
        if self.env.root == Path::new("/") {
            cmd.env_remove("DEFAULT_EDITOR_ROOT");
        } else {
            cmd.env("DEFAULT_EDITOR_ROOT", &self.env.root);
        }
        let out = cmd
            .output()
            .map_err(|e| Error::Service(format!("run default-editor: {e}")))?;
        if !out.status.success() {
            return Err(Error::Service(format!(
                "default-editor set {choice} failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            )));
        }
        Ok(())
    }
}

#[async_trait]
impl Applier for EditorApplier {
    fn name(&self) -> &'static str {
        "editor"
    }

    fn phase(&self) -> Phase {
        Phase::Services
    }

    fn resource_kinds(&self) -> &'static [ResourceKind] {
        &[ResourceKind::DefaultEditor]
    }

    async fn upsert_resource(&self, store: &ConfigStore, config: &DeclarativeConfig) -> Result<()> {
        let v = patronus_config::declarative::spec_value(config)?;
        if config.metadata.name != RESOURCE_NAME {
            return Err(invalid(format!(
                "DefaultEditor name {:?}: the system has one default editor, name the resource {RESOURCE_NAME:?}",
                config.metadata.name
            )));
        }
        if let Some(k) = v
            .as_object()
            .and_then(|o| o.keys().find(|k| *k != "editor"))
        {
            return Err(invalid(format!(
                "DefaultEditor spec field {k:?}: only `editor` is known"
            )));
        }
        let choice = v
            .get("editor")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("DefaultEditor spec: `editor` (a string) is required"))?;
        cfg::save(store, choice, embedded_at(&self.env)).await?;
        Ok(())
    }

    async fn delete_resource(
        &self,
        store: &ConfigStore,
        kind: &ResourceKind,
        _name: &str,
    ) -> Result<()> {
        if *kind != ResourceKind::DefaultEditor {
            return Err(invalid("resource kind for the editor applier"));
        }
        // back to unmanaged: the system keeps the editor it has
        cfg::set(store, None).await
    }

    async fn apply(&self, store: &ConfigStore) -> Result<ApplyReport> {
        let mut rep = ApplyReport::default();
        let Some(stored) = cfg::get(store).await? else {
            rep.applied("default editor not configured (the system's editor is untouched)");
            return Ok(rep);
        };
        let embedded = embedded_at(&self.env);
        let choice = cfg::check(&stored, embedded)?;
        if installed(&self.env, &choice).is_none() {
            return Err(self.not_installed(&choice, embedded));
        }
        let conf_text = std::fs::read_to_string(self.env.path(CONF)).unwrap_or_default();
        let conf_ok = conf_choice(&conf_text).as_deref() == Some(choice.as_str());
        if embedded {
            // busybox tier: /etc/profile.d/10-editor.sh reads the conf at login
            let text = format!(
                "# System default text editor (patronus: the declarative key system.editor).\n\
                 # vi | /absolute/path\nEDITOR_CHOICE={choice}\n"
            );
            if write_atomic(&self.env.path(CONF), &text, 0o644)? {
                rep.applied(format!("default editor {choice}"));
            } else {
                rep.applied(format!("default editor {choice} already in effect"));
            }
            return Ok(rep);
        }
        let envd_ok = std::fs::read_to_string(self.env.path(ENVD))
            .ok()
            .and_then(|t| envd_editor(&t))
            .map(|e| is_exec(&self.env.path(&e)))
            .unwrap_or(false);
        if conf_ok && envd_ok {
            rep.applied(format!("default editor {choice} already in effect"));
            return Ok(rep);
        }
        self.run_tool(&choice)?;
        rep.applied(format!("default editor {choice}"));
        Ok(rep)
    }

    async fn render(&self, store: &ConfigStore) -> Result<String> {
        Ok(format!(
            "## default editor\neditor={}\n",
            cfg::get(store).await?.as_deref().unwrap_or("(unmanaged)")
        ))
    }

    async fn status(&self, store: &ConfigStore) -> Result<Value> {
        overview(store, &self.env, embedded_at(&self.env)).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lan::testutil;
    use patronus_config::declarative::{Metadata, ResourceSpec};

    /// The real tool of the image, installed into the test root.
    fn install_tool(t: &testutil::TestEnv) {
        let src = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../gentoo/live-iso/common/overlay/usr/sbin/default-editor");
        let dst = t.env.path(TOOL);
        std::fs::create_dir_all(dst.parent().unwrap()).unwrap();
        std::fs::copy(&src, &dst).unwrap();
        std::fs::set_permissions(&dst, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    fn bin(t: &testutil::TestEnv, abs: &str) {
        let p = t.env.path(abs);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, "#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    fn envd(t: &testutil::TestEnv) -> String {
        testutil::read(t, ENVD)
    }

    fn res(name: &str, spec: Value) -> DeclarativeConfig {
        DeclarativeConfig {
            api_version: "patronus.firewall/v1".into(),
            kind: ResourceKind::DefaultEditor,
            metadata: Metadata {
                name: name.into(),
                description: None,
                labels: None,
                annotations: None,
            },
            spec: ResourceSpec::Generic(spec),
        }
    }

    #[tokio::test]
    async fn unset_touches_nothing_then_set_runs_the_tool_and_is_idempotent() {
        let t = testutil::env(&[]);
        install_tool(&t);
        bin(&t, "/usr/bin/vim");
        bin(&t, "/usr/bin/nvim");
        let s = testutil::store().await;
        let a = EditorApplier::new(t.env.clone());
        a.apply(&s).await.unwrap();
        assert_eq!(envd(&t), "");
        assert!(!t.env.path(CONF).exists());

        cfg::save(&s, "vim", false).await.unwrap();
        let r = a.apply(&s).await.unwrap();
        assert!(
            r.applied[0].contains("default editor vim"),
            "{:?}",
            r.applied
        );
        assert!(envd(&t).contains("EDITOR=\"/usr/bin/vim\""), "{}", envd(&t));
        assert!(envd(&t).contains("VISUAL=\"/usr/bin/vim\""));
        assert_eq!(
            conf_choice(&testutil::read(&t, CONF)).as_deref(),
            Some("vim")
        );
        // second apply: nothing to do
        let r = a.apply(&s).await.unwrap();
        assert!(r.applied[0].contains("already"), "{:?}", r.applied);

        cfg::save(&s, "neovim", false).await.unwrap();
        a.apply(&s).await.unwrap();
        assert!(
            envd(&t).contains("EDITOR=\"/usr/bin/nvim\""),
            "{}",
            envd(&t)
        );
        assert_eq!(
            conf_choice(&testutil::read(&t, CONF)).as_deref(),
            Some("neovim")
        );
    }

    #[tokio::test]
    async fn a_missing_binary_is_refused_with_the_package_and_nothing_is_written() {
        let t = testutil::env(&[]);
        install_tool(&t);
        bin(&t, "/usr/bin/vim");
        let s = testutil::store().await;
        let a = EditorApplier::new(t.env.clone());
        cfg::save(&s, "neovim", false).await.unwrap();
        let e = a.apply(&s).await.unwrap_err().to_string();
        assert!(
            e.contains("Invalid editor") && e.contains("emerge app-editors/neovim"),
            "{e}"
        );
        assert_eq!(envd(&t), "");
        cfg::save(&s, "/opt/none/bin/ed", false).await.unwrap();
        let e = a.apply(&s).await.unwrap_err().to_string();
        assert!(
            e.contains("/opt/none/bin/ed") && e.contains("not installed"),
            "{e}"
        );
    }

    #[tokio::test]
    async fn an_absolute_path_is_applied_and_a_missing_tool_is_reported() {
        let t = testutil::env(&[]);
        bin(&t, "/opt/ed/bin/ed");
        let s = testutil::store().await;
        let a = EditorApplier::new(t.env.clone());
        cfg::save(&s, "/opt/ed/bin/ed", false).await.unwrap();
        let e = a.apply(&s).await.unwrap_err().to_string();
        assert!(e.contains("default-editor is not installed"), "{e}");
        install_tool(&t);
        a.apply(&s).await.unwrap();
        assert!(
            envd(&t).contains("EDITOR=\"/opt/ed/bin/ed\""),
            "{}",
            envd(&t)
        );
    }

    #[tokio::test]
    async fn embedded_tier_accepts_vi_or_a_path_writes_only_the_conf_and_explains_the_rest() {
        let t = testutil::env(&[]);
        std::fs::create_dir_all(t.env.path("/etc")).unwrap();
        std::fs::write(
            t.env.path("/etc/patronus-release"),
            "PATRONUS_TIER=embedded\nBOARD=test\n",
        )
        .unwrap();
        bin(&t, "/bin/vi");
        let s = testutil::store().await;
        let a = EditorApplier::new(t.env.clone());
        // vim cannot even be stored on this tier (the GitOps path validates by tier)
        let e = a
            .upsert_resource(&s, &res(RESOURCE_NAME, json!({"editor": "vim"})))
            .await
            .unwrap_err()
            .to_string();
        assert!(
            e.contains("Invalid") && e.contains("flash budget") && e.contains("busybox"),
            "{e}"
        );
        assert_eq!(cfg::get(&s).await.unwrap(), None);
        a.upsert_resource(&s, &res(RESOURCE_NAME, json!({"editor": "vi"})))
            .await
            .unwrap();
        a.apply(&s).await.unwrap();
        assert_eq!(
            conf_choice(&testutil::read(&t, CONF)).as_deref(),
            Some("vi")
        );
        assert_eq!(envd(&t), "", "no env.d on the router tier");
        assert!(a.apply(&s).await.unwrap().applied[0].contains("already"));
        // the overview lists vim/neovim/nano with their reasons, vi without
        let o = overview(&s, &t.env, true).await.unwrap();
        let c = o["choices"].as_array().unwrap();
        assert_eq!(c.len(), 4);
        for n in ["vim", "neovim", "nano"] {
            let e = c.iter().find(|x| x["name"] == n).unwrap();
            assert_eq!(e["available"], false);
            assert!(e["reason"].as_str().unwrap().len() > 20, "{e}");
        }
        assert_eq!(
            c.iter().find(|x| x["name"] == "vi").unwrap()["available"],
            true
        );
        assert_eq!(o["embedded"], true);
        // a stored value this tier refuses (restored backup) fails the apply with the reason
        cfg::set(&s, Some("vim")).await.unwrap();
        assert!(a
            .apply(&s)
            .await
            .unwrap_err()
            .to_string()
            .contains("flash budget"));
    }

    #[tokio::test]
    async fn gitops_resource_is_validated_stored_and_deleted() {
        let t = testutil::env(&[]);
        let s = testutil::store().await;
        let a = EditorApplier::new(t.env.clone());
        assert_eq!(a.resource_kinds(), &[ResourceKind::DefaultEditor]);
        a.upsert_resource(&s, &res(RESOURCE_NAME, json!({"editor": "Neovim"})))
            .await
            .unwrap();
        assert_eq!(cfg::get(&s).await.unwrap().as_deref(), Some("neovim"));
        for (name, spec, want) in [
            ("other", json!({"editor": "vim"}), "name the resource"),
            (RESOURCE_NAME, json!({"editor": "emacs"}), "Invalid editor"),
            (RESOURCE_NAME, json!({"editor": 5}), "required"),
            (RESOURCE_NAME, json!({}), "required"),
            (
                RESOURCE_NAME,
                json!({"editor": "vim", "x": 1}),
                "only `editor`",
            ),
        ] {
            let e = a
                .upsert_resource(&s, &res(name, spec))
                .await
                .unwrap_err()
                .to_string();
            assert!(e.contains(want), "{e}");
        }
        assert_eq!(cfg::get(&s).await.unwrap().as_deref(), Some("neovim"));
        a.delete_resource(&s, &ResourceKind::DefaultEditor, RESOURCE_NAME)
            .await
            .unwrap();
        assert_eq!(cfg::get(&s).await.unwrap(), None);
        assert!(a
            .delete_resource(&s, &ResourceKind::Group, "x")
            .await
            .is_err());
    }

    #[test]
    fn conf_and_envd_parsing() {
        assert_eq!(
            conf_choice("# c\nEDITOR_CHOICE=vim\nEDITOR_CHOICE=\"neovim\" # x\n").as_deref(),
            Some("neovim")
        );
        assert_eq!(conf_choice("# nothing\n"), None);
        assert_eq!(
            envd_editor("# x\nEDITOR=\"/usr/bin/vim\"\nVISUAL=\"/usr/bin/vim\"\n").as_deref(),
            Some("/usr/bin/vim")
        );
    }
}
