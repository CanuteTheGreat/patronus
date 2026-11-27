//! The system default text editor as a declarative setting.
//!
//! One key in four places, all validated here: `[system] editor = "vim"` in patronus.toml
//! (seeded once on a new install), `PUT /api/system/editor` and the System page, and the GitOps
//! resource `kind: DefaultEditor`. The store holds one row (`system_editor`); a box without a row
//! never has its editor touched, so a hand-edited `/etc/default-editor.conf` survives an upgrade.
//! The applier (`patronus_network::editor`) turns the choice into `default-editor set <choice>`.
//!
//! Accepted values: `vim`, `neovim`, `nano`, `vi` or an absolute path. The embedded router tier
//! has no room for vim (7 MB image): it accepts only `vi` (busybox) or an absolute path of an
//! editor the owner installed, and says why for each value it leaves out.

use crate::store::ConfigStore;
use patronus_core::{Error, Result};
use sqlx::Row;
use std::path::Path;

/// The editors known by name (the `default-editor` tool resolves each to a binary).
pub const NAMES: &[&str] = &["vim", "neovim", "nano", "vi"];

/// The value a new install is seeded with (embedded tier: [`EMBEDDED_DEFAULT`]).
pub const DEFAULT: &str = "vim";

/// The embedded tier's only named editor: the busybox applet already in the image.
pub const EMBEDDED_DEFAULT: &str = "vi";

/// Longest accepted absolute path.
const MAX_PATH: usize = 255;

fn invalid(msg: impl std::fmt::Display) -> Error {
    Error::Config(format!("Invalid {msg}"))
}

/// Whether the release file (`/etc/patronus-release`, or `$PATRONUS_RELEASE_FILE`) says
/// `PATRONUS_TIER=embedded`.
pub fn embedded_tier() -> bool {
    let p =
        std::env::var("PATRONUS_RELEASE_FILE").unwrap_or_else(|_| "/etc/patronus-release".into());
    embedded_tier_at(Path::new(&p))
}

/// [`embedded_tier`] for a given release file.
pub fn embedded_tier_at(release: &Path) -> bool {
    std::fs::read_to_string(release)
        .unwrap_or_default()
        .lines()
        .find_map(|l| l.strip_prefix("PATRONUS_TIER="))
        .map(|t| t.trim() == "embedded")
        .unwrap_or(false)
}

/// Why `choice` (a named editor) is not offered on the embedded tier; `None` = offered.
pub fn omission_reason(choice: &str, embedded: bool) -> Option<&'static str> {
    if !embedded {
        return None;
    }
    match choice {
        "vim" => Some(
            "vim and its runtime files do not fit the router tier's flash budget; the tier ships busybox vi \
             (the same modal editor)",
        ),
        "neovim" => Some(
            "neovim and its runtime files do not fit the router tier's flash budget; use busybox vi or an \
             absolute path of an editor you installed",
        ),
        "nano" => Some("nano is not part of the router tier; use busybox vi or an absolute path"),
        _ => None,
    }
}

/// Every named choice with whether this tier offers it and, if not, the reason.
pub fn choices(embedded: bool) -> Vec<(&'static str, Option<&'static str>)> {
    NAMES
        .iter()
        .map(|n| (*n, omission_reason(n, embedded)))
        .collect()
}

/// Validate a choice and return its canonical form (names lower-cased, a path as given).
/// Errors start with "Invalid" (the API answers 400) and name what is accepted.
pub fn check(choice: &str, embedded: bool) -> Result<String> {
    let t = choice.trim();
    let accepted = if embedded {
        "vi (busybox) or the absolute path of an installed editor"
    } else {
        "vim, neovim, nano, vi or an absolute path"
    };
    if t.is_empty() {
        return Err(invalid(format!("editor: empty (use {accepted})")));
    }
    if t.starts_with('/') {
        let ok = t.len() <= MAX_PATH
            && !t.ends_with('/')
            && t.split('/')
                .skip(1)
                .all(|p| !p.is_empty() && p != "." && p != "..")
            && t.bytes().all(|b| {
                b.is_ascii_alphanumeric() || matches!(b, b'/' | b'_' | b'-' | b'.' | b'+')
            });
        return if ok {
            Ok(t.to_string())
        } else {
            Err(invalid(format!(
                "editor path {choice:?}: an absolute path of letters, digits and / _ - . + only, \
                 no '..', no trailing slash"
            )))
        };
    }
    let name = t.to_ascii_lowercase();
    if !NAMES.contains(&name.as_str()) {
        return Err(invalid(format!("editor {choice:?}: use {accepted}")));
    }
    if let Some(why) = omission_reason(&name, embedded) {
        return Err(invalid(format!(
            "editor {name:?} on this tier: {why} (use {accepted})"
        )));
    }
    Ok(name)
}

/// The stored choice (`None` = never set: the system keeps its own).
pub async fn get(store: &ConfigStore) -> Result<Option<String>> {
    let row = sqlx::query("SELECT choice FROM system_editor WHERE id = 1")
        .fetch_optional(store.pool()?)
        .await
        .map_err(|e| Error::Config(format!("read editor setting: {e}")))?;
    Ok(row
        .map(|r| r.get::<String, _>(0))
        .filter(|v| !v.trim().is_empty()))
}

/// Store an already validated choice (`None` = back to unmanaged).
pub async fn set(store: &ConfigStore, choice: Option<&str>) -> Result<()> {
    let pool = store.pool()?;
    let err = |e: sqlx::Error| Error::Config(format!("write editor setting: {e}"));
    match choice {
        Some(c) => {
            sqlx::query(
                "INSERT INTO system_editor (id, choice, updated_at) VALUES (1, ?, ?)
                 ON CONFLICT(id) DO UPDATE SET choice = excluded.choice, updated_at = excluded.updated_at",
            )
            .bind(c)
            .bind(chrono::Utc::now().timestamp())
            .execute(pool)
            .await
            .map_err(err)?;
        }
        None => {
            sqlx::query("DELETE FROM system_editor WHERE id = 1")
                .execute(pool)
                .await
                .map_err(err)?;
        }
    }
    Ok(())
}

/// Validate and store `choice`.
pub async fn save(store: &ConfigStore, choice: &str, embedded: bool) -> Result<String> {
    let c = check(choice, embedded)?;
    set(store, Some(&c)).await?;
    Ok(c)
}

/// Seed the choice of patronus.toml's `[system] editor` when nothing is stored yet. A value
/// this tier refuses is reported as a warning instead of failing the first boot.
pub async fn seed(store: &ConfigStore, choice: &str, embedded: bool) -> Result<Option<String>> {
    if get(store).await?.is_some() {
        return Ok(None);
    }
    match check(choice, embedded) {
        Ok(c) => {
            set(store, Some(&c)).await?;
            Ok(None)
        }
        Err(e) => Ok(Some(format!(
            "patronus.toml [system] editor ignored: {}",
            e.to_string().trim_start_matches("Configuration error: ")
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_and_paths_are_validated() {
        assert_eq!(check(" Neovim ", false).unwrap(), "neovim");
        assert_eq!(check("nano", false).unwrap(), "nano");
        assert_eq!(check("/usr/bin/emacs", false).unwrap(), "/usr/bin/emacs");
        for bad in [
            "",
            "emacs",
            "nvim",
            "vim -u NONE",
            "/usr/bin/vim\nx",
            "/usr/bin/../x",
            "/",
            "/usr/bin/",
            "/a b",
            "/a//b",
            "~/vim",
            "bin/vim",
            "/x;rm",
            "/x\"y",
            "/x#y",
        ] {
            let e = check(bad, false).unwrap_err().to_string();
            assert!(e.contains("Invalid editor"), "{bad:?}: {e}");
        }
        let long = format!("/{}", "a".repeat(300));
        assert!(check(&long, false).is_err());
    }

    #[test]
    fn embedded_tier_takes_only_vi_or_a_path_and_says_why() {
        assert_eq!(check("vi", true).unwrap(), "vi");
        assert_eq!(check("/opt/ed/bin/ed", true).unwrap(), "/opt/ed/bin/ed");
        for n in ["vim", "neovim", "nano"] {
            let e = check(n, true).unwrap_err().to_string();
            assert!(e.contains("Invalid") && e.contains("busybox"), "{n}: {e}");
        }
        let c = choices(true);
        assert!(c.iter().find(|(n, _)| *n == "vi").unwrap().1.is_none());
        assert!(c.iter().filter(|(_, r)| r.is_some()).count() == 3);
        assert!(choices(false).iter().all(|(_, r)| r.is_none()));
    }

    #[test]
    fn release_file_decides_the_tier() {
        let d = tempfile::tempdir().unwrap();
        let f = d.path().join("rel");
        assert!(!embedded_tier_at(&f));
        std::fs::write(&f, "PATRONUS_TIER=embedded\nBOARD=x\n").unwrap();
        assert!(embedded_tier_at(&f));
        std::fs::write(&f, "PATRONUS_TIER=standard\n").unwrap();
        assert!(!embedded_tier_at(&f));
    }

    #[tokio::test]
    async fn store_round_trip_and_seed_only_when_unset() {
        let s = ConfigStore::open_in_memory().await.unwrap();
        assert_eq!(get(&s).await.unwrap(), None);
        assert_eq!(seed(&s, "vim", false).await.unwrap(), None);
        assert_eq!(get(&s).await.unwrap().as_deref(), Some("vim"));
        // the UI changed it: a later seed (new patronus.toml) does not overwrite
        save(&s, "neovim", false).await.unwrap();
        assert_eq!(seed(&s, "vim", false).await.unwrap(), None);
        assert_eq!(get(&s).await.unwrap().as_deref(), Some("neovim"));
        // a refused value stores nothing
        assert!(save(&s, "emacs", false).await.is_err());
        assert_eq!(get(&s).await.unwrap().as_deref(), Some("neovim"));
        set(&s, None).await.unwrap();
        assert_eq!(get(&s).await.unwrap(), None);
        // an embedded box seeded with vim keeps unmanaged and warns
        let w = seed(&s, "vim", true).await.unwrap().unwrap();
        assert!(
            w.contains("[system] editor") && w.contains("busybox"),
            "{w}"
        );
        assert_eq!(get(&s).await.unwrap(), None);
    }
}
