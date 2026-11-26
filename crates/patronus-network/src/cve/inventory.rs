//! What is installed: the crate list compiled into each Patronus binary (read back from
//! the binary file itself, so the view shows the installed build and not the running
//! process or the source tree) and, on the router tier, the image's package manifest.

use serde::{Deserialize, Serialize};
use std::io::Read;
use std::path::{Path, PathBuf};

/// Embed the dependency list of this binary (see `build_support/dep_list.rs`):
/// `patronus_network::embed_dependency_list!();` in the binary's crate root, a
/// `build.rs` that calls `write_dep_list()`, and one reference from live code
/// (`patronus_network::cve::inventory::keep(PATRONUS_DEP_LIST)`) so the linker keeps it.
#[macro_export]
macro_rules! embed_dependency_list {
    () => {
        #[used]
        pub static PATRONUS_DEP_LIST: &str =
            include_str!(concat!(env!("OUT_DIR"), "/patronus-deps.txt"));
    };
}

/// Keeps the embedded list referenced from live code.
pub fn keep(list: &'static str) -> usize {
    std::hint::black_box(list).len()
}

// The markers are assembled at run time: a literal here would be compiled into the
// scanner's own binary and be read as an embedded list.
fn begin_marker() -> Vec<u8> {
    [std::hint::black_box("@@PATRONUS-"), "DEPS-BEGIN/1@@"]
        .concat()
        .into_bytes()
}
fn end_marker() -> Vec<u8> {
    [std::hint::black_box("@@PATRONUS-"), "DEPS-END@@"]
        .concat()
        .into_bytes()
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct BinaryInventory {
    pub path: String,
    pub binary: String,
    pub version: String,
    /// `lockfile-closure`, or `unavailable` when the build had no Cargo.lock
    pub scope: String,
    /// (name, version, source kind)
    pub crates: Vec<(String, String, String)>,
}

pub fn parse_block(block: &str, path: &str) -> Option<BinaryInventory> {
    let mut inv = BinaryInventory {
        path: path.to_string(),
        ..Default::default()
    };
    for line in block.lines() {
        let mut it = line.split_whitespace();
        match it.next() {
            Some("binary") => inv.binary = it.next().unwrap_or("").into(),
            Some("version") => inv.version = it.next().unwrap_or("").into(),
            Some("scope") => inv.scope = it.next().unwrap_or("").into(),
            Some("crate") => {
                let (Some(n), Some(v)) = (it.next(), it.next()) else {
                    continue;
                };
                inv.crates
                    .push((n.into(), v.into(), it.next().unwrap_or("").into()));
            }
            _ => {}
        }
    }
    (!inv.binary.is_empty()).then_some(inv)
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    hay.windows(needle.len()).position(|w| w == needle)
}

/// Find the embedded list inside a binary. Reads the file in chunks (no whole binary in
/// memory) and stops at the end marker; `max_bytes` bounds the amount read.
pub fn read_embedded(path: &Path, max_bytes: u64) -> Option<BinaryInventory> {
    let mut f = std::fs::File::open(path).ok()?;
    let (b, e) = (begin_marker(), end_marker());
    let mut buf: Vec<u8> = Vec::new();
    let mut chunk = vec![0u8; 1 << 20];
    let mut total = 0u64;
    let mut start: Option<usize> = None;
    loop {
        let n = f.read(&mut chunk).ok()?;
        if n == 0 {
            break;
        }
        total += n as u64;
        buf.extend_from_slice(&chunk[..n]);
        if start.is_none() {
            if let Some(i) = find(&buf, &b) {
                start = Some(i);
            } else {
                // keep the tail: the marker can straddle two chunks
                let keep = b.len().min(buf.len());
                let cut = buf.len() - keep;
                buf.drain(..cut);
            }
        }
        if let Some(s) = start {
            if let Some(i) = find(&buf[s..], &e) {
                let text = String::from_utf8_lossy(&buf[s..s + i]).to_string();
                return parse_block(&text, &path.to_string_lossy());
            }
            if buf.len() - s > (8 << 20) {
                return None;
            }
        }
        if total > max_bytes {
            return None;
        }
    }
    None
}

/// Binaries to read: the configured list, or every `patronus*` executable in the usual
/// directories (symlinks resolved, each file once).
pub fn candidate_binaries(configured: &[String], dirs: &[&str]) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::new();
    let mut add = |p: PathBuf| {
        if let Ok(c) = std::fs::canonicalize(&p) {
            if c.is_file() && !out.contains(&c) {
                out.push(c);
            }
        }
    };
    if !configured.is_empty() {
        for c in configured {
            add(PathBuf::from(c));
        }
        return out;
    }
    for d in dirs {
        let Ok(rd) = std::fs::read_dir(d) else { continue };
        for e in rd.flatten() {
            if e.file_name().to_string_lossy().starts_with("patronus") {
                add(e.path());
            }
        }
    }
    if let Ok(me) = std::env::current_exe() {
        add(me);
    }
    out.sort();
    out
}

// ---------------------------------------------------------------------------
// router tier: the image's package manifest
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct ManifestPackage {
    pub name: String,
    pub version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct GateFinding {
    pub package: String,
    pub installed: String,
    pub advisory: String,
    pub title: String,
    pub fixed_in: Vec<String>,
    pub url: String,
}

/// The gate result recorded at image build time (`ci/check-image-advisories.py`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct GateResult {
    pub checked_at: String,
    /// where the advisories came from, e.g. `Alpine secdb v3.22 main+community`
    pub source: String,
    pub findings: Vec<GateFinding>,
    /// advisories the build accepted on purpose (id -> reason)
    #[serde(default)]
    pub accepted: Vec<(String, String)>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct Manifest {
    pub schema: u32,
    pub image: String,
    pub built: String,
    pub version: String,
    /// `alpine`, `gentoo`, ...: names the distribution the package versions belong to
    pub distribution: String,
    pub packages: Vec<ManifestPackage>,
    #[serde(default)]
    pub gate: Option<GateResult>,
}

pub fn read_manifest(path: &Path) -> Option<Manifest> {
    let meta = std::fs::metadata(path).ok()?;
    if meta.len() > (4 << 20) {
        return None;
    }
    let m: Manifest = serde_json::from_slice(&std::fs::read(path).ok()?).ok()?;
    (m.schema == 1).then_some(m)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    const BLOCK: &str = "@@PATRONUS-DEPS-BEGIN/1@@\nbinary patronus-web\nversion 0.2.1\nscope lockfile-closure\ncrate h2 0.3.20 registry\ncrate serde 1.0.200 registry\n@@PATRONUS-DEPS-END@@\n";

    #[test]
    fn parses_a_block() {
        let i = parse_block(BLOCK, "/usr/bin/x").unwrap();
        assert_eq!(i.binary, "patronus-web");
        assert_eq!(i.crates.len(), 2);
        assert_eq!(i.crates[0], ("h2".into(), "0.3.20".into(), "registry".into()));
    }

    #[test]
    fn finds_the_block_across_a_chunk_edge() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("patronus-fake");
        let mut f = std::fs::File::create(&p).unwrap();
        // 1 MiB - 7 bytes of padding: the begin marker straddles the first chunk edge
        f.write_all(&vec![0x7fu8; (1 << 20) - 7]).unwrap();
        f.write_all(BLOCK.as_bytes()).unwrap();
        f.write_all(&vec![0u8; 4096]).unwrap();
        drop(f);
        let i = read_embedded(&p, 64 << 20).unwrap();
        assert_eq!(i.binary, "patronus-web");
        assert_eq!(i.crates.len(), 2);
        // a binary without a list gives nothing, not an empty "clean" inventory
        let q = d.path().join("other");
        std::fs::write(&q, b"nothing here").unwrap();
        assert!(read_embedded(&q, 1 << 20).is_none());
    }

    #[test]
    fn candidates_resolve_symlinks_once() {
        let d = tempfile::tempdir().unwrap();
        let real = d.path().join("patronus-cli");
        std::fs::write(&real, b"x").unwrap();
        std::os::unix::fs::symlink(&real, d.path().join("patronus")).unwrap();
        let v = candidate_binaries(&[], &[d.path().to_str().unwrap()]);
        assert!(v.iter().filter(|p| p.ends_with("patronus-cli")).count() == 1);
        assert!(!v.iter().any(|p| p.ends_with("patronus") && !p.ends_with("patronus-cli")));
    }

    #[test]
    fn manifest_needs_schema_one() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("m.json");
        std::fs::write(&p, r#"{"schema":1,"image":"ax1800","built":"2026-11-25","version":"0.2","distribution":"alpine","packages":[{"name":"busybox","version":"1.36.1-r5"}]}"#).unwrap();
        assert_eq!(read_manifest(&p).unwrap().packages.len(), 1);
        std::fs::write(&p, r#"{"schema":2,"image":"","built":"","version":"","distribution":"","packages":[]}"#).unwrap();
        assert!(read_manifest(&p).is_none());
    }
}
