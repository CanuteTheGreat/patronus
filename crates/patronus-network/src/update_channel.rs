//! The update channel and mirror on the device: renders the typed
//! `update.*` settings ([`patronus_config::updates`]) into Portage
//! configuration, as root (sysops action `update_channel_apply`, and before
//! every update check and apply).
//!
//! Files written (every one starts with a "managed by Patronus" line and is
//! rewritten whole; nothing else in /etc/portage is touched):
//!
//! * `repos.conf/patronus.conf`: the Patronus overlay (location, sync type, mirror);
//! * `package.accept_keywords/patronus-channel`: what the channel accepts;
//! * `package.mask/patronus-channel`: what it refuses (the live ebuild outside
//!   `development`);
//! * `package.mask/patronus-channel-prerelease`: the `_alpha`/`_beta`/`_pre`/`_rc`
//!   ebuilds the synced overlay carries, on `stable` only (regenerated after
//!   every sync by the check job, see [`prerelease_mask_script`]);
//! * `binrepos.conf/patronus.conf`: the optional binary package host (removed
//!   when none is set).

use patronus_config::updates::{Channel, UpdateSettings, REPO_NAME};
use patronus_core::{Error, Result};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

pub const HEADER: &str =
    "# managed by Patronus (System > Updates, settings update.*): edits are replaced\n";
pub const PACKAGE: &str = "net-firewall/patronus";
const PRERELEASE_TAGS: [&str; 4] = ["_alpha", "_beta", "_pre", "_rc"];

/// Portage keyword of the machine's architecture.
pub fn arch_keyword() -> &'static str {
    match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        "riscv64" => "riscv",
        "x86" => "x86",
        "arm" => "arm",
        "powerpc64" => "ppc64",
        _ => "amd64",
    }
}

/// Where the rendered files go.
#[derive(Debug, Clone)]
pub struct PortagePaths {
    pub etc_portage: PathBuf,
}

impl Default for PortagePaths {
    fn default() -> Self {
        Self {
            etc_portage: std::env::var_os("PATRONUS_PORTAGE_CONFIGROOT")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("/etc/portage")),
        }
    }
}

/// Pre-release ebuilds of the overlay directory (`=net-firewall/patronus-<v>` atoms).
pub fn prerelease_atoms(repo_location: &Path) -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(repo_location.join(PACKAGE))
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| {
            let n = e.file_name().to_string_lossy().into_owned();
            let stem = n.strip_suffix(".ebuild")?.to_string();
            let ver = stem.strip_prefix("patronus-")?;
            PRERELEASE_TAGS
                .iter()
                .any(|t| ver.contains(t))
                .then(|| format!("={}-{ver}", PACKAGE))
        })
        .collect();
    v.sort();
    v
}

/// The files for `s` (relative to /etc/portage), `None` content = remove.
pub fn render(
    s: &UpdateSettings,
    arch: &str,
    prerelease: &[String],
) -> Vec<(String, Option<String>)> {
    let mut repos = format!(
        "{HEADER}[{REPO_NAME}]\nlocation = {}\nsync-type = {}\nsync-uri = {}\nauto-sync = yes\npriority = 50\n",
        s.repo_location,
        s.sync_type(),
        s.overlay_uri
    );
    if s.sync_type() == "git" {
        repos.push_str("sync-depth = 1\n");
    }
    let kw = match s.channel {
        // releases are ~arch before 1.0; the accounts carry no keywords
        Channel::Stable | Channel::Testing => format!(
            "{HEADER}{PACKAGE} ~{arch}\nacct-user/patronus **\nacct-group/patronus **\n"
        ),
        Channel::Development => format!(
            "{HEADER}{PACKAGE} ~{arch}\n={PACKAGE}-9999 **\nacct-user/patronus **\nacct-group/patronus **\n"
        ),
    };
    let mask = match s.channel {
        Channel::Stable | Channel::Testing => format!("{HEADER}={PACKAGE}-9999\n"),
        Channel::Development => HEADER.to_string(),
    };
    let pre = match s.channel {
        Channel::Stable => {
            let mut t = HEADER.to_string();
            for a in prerelease {
                t.push_str(a);
                t.push('\n');
            }
            Some(t)
        }
        _ => None,
    };
    let bin = (!s.binhost_uri.is_empty()).then(|| {
        format!(
            "{HEADER}[{REPO_NAME}]\npriority = 20\nsync-uri = {}\n",
            s.binhost_uri
        )
    });
    vec![
        ("repos.conf/patronus.conf".into(), Some(repos)),
        ("package.accept_keywords/patronus-channel".into(), Some(kw)),
        ("package.mask/patronus-channel".into(), Some(mask)),
        ("package.mask/patronus-channel-prerelease".into(), pre),
        ("binrepos.conf/patronus.conf".into(), bin),
    ]
}

/// `/etc/portage/<dir>` may be a plain file (Portage accepts both): turn it
/// into a directory keeping its content as `<dir>/local`.
fn ensure_dir(p: &Path) -> Result<()> {
    if p.is_file() {
        let tmp = p.with_extension("patronus-move");
        std::fs::rename(p, &tmp).map_err(|e| Error::Config(format!("{}: {e}", p.display())))?;
        std::fs::create_dir_all(p).map_err(|e| Error::Config(format!("{}: {e}", p.display())))?;
        std::fs::rename(&tmp, p.join("local"))
            .map_err(|e| Error::Config(format!("{}: {e}", p.display())))?;
    }
    std::fs::create_dir_all(p).map_err(|e| Error::Config(format!("{}: {e}", p.display())))
}

/// Write the files for `s` under `paths`; returns what was written/removed.
pub fn apply(s: &UpdateSettings, paths: &PortagePaths) -> Result<Value> {
    s.validate()?;
    let pre = prerelease_atoms(Path::new(&s.repo_location));
    let mut written = Vec::new();
    let mut removed = Vec::new();
    for (rel, content) in render(s, arch_keyword(), &pre) {
        let f = paths.etc_portage.join(&rel);
        match content {
            Some(c) => {
                if let Some(d) = f.parent() {
                    ensure_dir(d)?;
                }
                let tmp = f.with_extension("tmp-patronus");
                std::fs::write(&tmp, c)
                    .and_then(|_| std::fs::rename(&tmp, &f))
                    .map_err(|e| Error::Config(format!("{}: {e}", f.display())))?;
                written.push(rel);
            }
            None => {
                if f.exists() {
                    std::fs::remove_file(&f)
                        .map_err(|e| Error::Config(format!("{}: {e}", f.display())))?;
                    removed.push(rel);
                }
            }
        }
    }
    Ok(json!({
        "channel": s.channel.as_str(),
        "overlay_uri": s.overlay_uri,
        "binhost_uri": s.binhost_uri,
        "written": written,
        "removed": removed,
        "masked_prereleases": pre.len(),
    }))
}

/// Shell run by the check job right after the sync: the stable channel's
/// pre-release mask must cover the ebuilds that sync just brought in.
pub fn prerelease_mask_script(s: &UpdateSettings, paths: &PortagePaths) -> String {
    let f = paths
        .etc_portage
        .join("package.mask/patronus-channel-prerelease");
    if s.channel != Channel::Stable {
        return format!("rm -f '{}'; ", f.display());
    }
    let d = Path::new(&s.repo_location).join(PACKAGE);
    let globs: Vec<String> = PRERELEASE_TAGS
        .iter()
        .map(|t| format!("'{}'/patronus-*{t}*.ebuild", d.display()))
        .collect();
    format!(
        "mkdir -p '{dir}'; {{ printf '%s\\n' '{hdr}'; for e in {globs}; do [ -e \"$e\" ] || continue; b=${{e##*/}}; echo \"={PACKAGE}-${{b#patronus-}}\" | sed 's/\\.ebuild$//'; done; }} > '{f}.tmp' && mv '{f}.tmp' '{f}'; ",
        dir = f.parent().unwrap_or(Path::new("/")).display(),
        hdr = HEADER.trim_end().replace('\'', ""),
        globs = globs.join(" "),
        f = f.display(),
    )
}

/// Settings from the `channel_settings` member of sysops params, if any.
pub fn from_params(params: &Value) -> Result<Option<UpdateSettings>> {
    match params.get("channel_settings") {
        None | Some(Value::Null) => Ok(None),
        Some(v) => serde_json::from_value::<UpdateSettings>(v.clone())
            .map(Some)
            .map_err(|e| Error::Config(format!("Invalid update settings: {e}"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings(ch: Channel, repo: &Path) -> UpdateSettings {
        UpdateSettings {
            channel: ch,
            repo_location: repo.display().to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn each_channel_renders_its_keywords_and_masks() {
        let r = Path::new("/var/db/repos/patronus");
        let pre = vec!["=net-firewall/patronus-1.0.0_rc1".to_string()];
        let f = |ch| render(&settings(ch, r), "arm64", &pre);
        let get = |v: &Vec<(String, Option<String>)>, k: &str| {
            v.iter().find(|(n, _)| n == k).unwrap().1.clone()
        };
        let st = f(Channel::Stable);
        assert!(get(&st, "repos.conf/patronus.conf")
            .unwrap()
            .contains("sync-uri = https://github.com/CanuteTheGreat/patronus-overlay.git\n"));
        assert!(get(&st, "package.accept_keywords/patronus-channel")
            .unwrap()
            .contains("net-firewall/patronus ~arm64\n"));
        assert!(get(&st, "package.mask/patronus-channel")
            .unwrap()
            .contains("=net-firewall/patronus-9999\n"));
        assert!(get(&st, "package.mask/patronus-channel-prerelease")
            .unwrap()
            .contains("=net-firewall/patronus-1.0.0_rc1\n"));
        assert_eq!(get(&st, "binrepos.conf/patronus.conf"), None);
        let te = f(Channel::Testing);
        assert_eq!(get(&te, "package.mask/patronus-channel-prerelease"), None);
        assert!(get(&te, "package.mask/patronus-channel")
            .unwrap()
            .contains("9999"));
        let dv = f(Channel::Development);
        assert!(!get(&dv, "package.mask/patronus-channel")
            .unwrap()
            .contains("9999"));
        assert!(get(&dv, "package.accept_keywords/patronus-channel")
            .unwrap()
            .contains("=net-firewall/patronus-9999 **\n"));
    }

    #[test]
    fn apply_writes_files_converts_plain_files_and_removes_stale_ones() {
        let d = tempfile::tempdir().unwrap();
        let repo = d.path().join("repo");
        std::fs::create_dir_all(repo.join(PACKAGE)).unwrap();
        for e in [
            "patronus-0.2.0.ebuild",
            "patronus-0.3.0_rc2.ebuild",
            "patronus-9999.ebuild",
            "metadata.xml",
        ] {
            std::fs::write(repo.join(PACKAGE).join(e), "").unwrap();
        }
        let etc = d.path().join("etc");
        std::fs::create_dir_all(&etc).unwrap();
        // an admin's single-file package.mask is kept as package.mask/local
        std::fs::write(etc.join("package.mask"), "=dev-lang/foo-1\n").unwrap();
        let paths = PortagePaths {
            etc_portage: etc.clone(),
        };
        let mut s = settings(Channel::Stable, &repo);
        s.binhost_uri = "https://pkgs.example.org/patronus".into();
        let out = apply(&s, &paths).unwrap();
        assert_eq!(out["masked_prereleases"], 1);
        assert_eq!(
            std::fs::read_to_string(etc.join("package.mask/local")).unwrap(),
            "=dev-lang/foo-1\n"
        );
        let pre =
            std::fs::read_to_string(etc.join("package.mask/patronus-channel-prerelease")).unwrap();
        assert!(pre.contains("=net-firewall/patronus-0.3.0_rc2\n"), "{pre}");
        assert!(!pre.contains("0.2.0"));
        assert!(etc.join("binrepos.conf/patronus.conf").exists());
        // switching to development drops the pre-release mask and the binhost
        s.channel = Channel::Development;
        s.binhost_uri.clear();
        let out = apply(&s, &paths).unwrap();
        assert!(!etc
            .join("package.mask/patronus-channel-prerelease")
            .exists());
        assert!(!etc.join("binrepos.conf/patronus.conf").exists());
        assert_eq!(out["removed"].as_array().unwrap().len(), 2);
        // invalid settings never touch the files
        s.overlay_uri = "nonsense".into();
        assert!(apply(&s, &paths).is_err());
    }

    #[test]
    fn post_sync_script_matches_the_rust_mask() {
        let d = tempfile::tempdir().unwrap();
        let repo = d.path().join("repo");
        std::fs::create_dir_all(repo.join(PACKAGE)).unwrap();
        for e in [
            "patronus-0.2.0.ebuild",
            "patronus-1.0.0_beta1.ebuild",
            "patronus-1.0.0_rc1.ebuild",
        ] {
            std::fs::write(repo.join(PACKAGE).join(e), "").unwrap();
        }
        let etc = d.path().join("etc");
        let paths = PortagePaths {
            etc_portage: etc.clone(),
        };
        let s = settings(Channel::Stable, &repo);
        let sh = prerelease_mask_script(&s, &paths);
        let st = std::process::Command::new("sh")
            .arg("-c")
            .arg(&sh)
            .status()
            .unwrap();
        assert!(st.success(), "{sh}");
        let got =
            std::fs::read_to_string(etc.join("package.mask/patronus-channel-prerelease")).unwrap();
        let mut lines: Vec<&str> = got.lines().filter(|l| !l.starts_with('#')).collect();
        lines.sort();
        assert_eq!(lines, prerelease_atoms(&repo), "{got}");
        assert!(got.starts_with("# managed by Patronus"), "{got}");
        let dev = settings(Channel::Testing, &repo);
        let st = std::process::Command::new("sh")
            .arg("-c")
            .arg(prerelease_mask_script(&dev, &paths))
            .status()
            .unwrap();
        assert!(st.success());
        assert!(!etc
            .join("package.mask/patronus-channel-prerelease")
            .exists());
    }
}
