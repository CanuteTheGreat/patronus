// Shared by the build scripts of the shipped binaries (`include!`d, not a crate).
//
// Writes $OUT_DIR/patronus-deps.txt: the Rust crates that belong to ONE binary, taken from
// the workspace Cargo.lock as the closure of the binary's package over its dependency
// edges. The text is compiled into the binary (`patronus_network::embed_dependency_list!`)
// and read back by the router's CVE exposure view (`patronus_network::cve`), so the view
// lists what is installed, not what the source tree says today.
//
// Honest limit: the lockfile edges include optional and target-specific dependencies, so
// the list can name a crate that a given feature set or platform does not compile in.
// The view says "may include", never "compiled in".

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

#[derive(Default, Clone)]
struct LockPkg {
    name: String,
    version: String,
    source: String,
    deps: Vec<String>,
}

fn parse_lock(text: &str) -> Vec<LockPkg> {
    let mut out: Vec<LockPkg> = Vec::new();
    let mut cur: Option<LockPkg> = None;
    let mut in_deps = false;
    for raw in text.lines() {
        let line = raw.trim();
        if line == "[[package]]" {
            if let Some(p) = cur.take() {
                out.push(p);
            }
            cur = Some(LockPkg::default());
            in_deps = false;
            continue;
        }
        let Some(p) = cur.as_mut() else { continue };
        if in_deps {
            if line == "]" {
                in_deps = false;
            } else if let Some(s) = line.trim_end_matches(',').strip_prefix('"') {
                if let Some(s) = s.strip_suffix('"') {
                    p.deps.push(s.to_string());
                }
            }
            continue;
        }
        let kv = |k: &str| -> Option<String> {
            let rest = line.strip_prefix(k)?.trim_start().strip_prefix('=')?.trim();
            Some(rest.trim_matches('"').to_string())
        };
        if line.starts_with("dependencies") && line.ends_with('[') {
            in_deps = true;
        } else if let Some(v) = kv("name") {
            p.name = v;
        } else if let Some(v) = kv("version") {
            p.version = v;
        } else if let Some(v) = kv("source") {
            p.source = v;
        }
    }
    if let Some(p) = cur.take() {
        out.push(p);
    }
    out
}

/// "name", "name version" or "name version (source)" -> index into `pkgs`.
fn resolve(pkgs: &[LockPkg], dep: &str) -> Option<usize> {
    let mut it = dep.split_whitespace();
    let name = it.next()?;
    let ver = it.next();
    let mut found = None;
    for (i, p) in pkgs.iter().enumerate() {
        if p.name == name && ver.map(|v| v == p.version).unwrap_or(true) {
            if found.is_some() && ver.is_none() {
                return None;
            }
            found = Some(i);
        }
    }
    found
}

pub fn dependency_list(lock_text: &str, root: &str) -> String {
    let pkgs = parse_lock(lock_text);
    let mut seen: BTreeSet<usize> = BTreeSet::new();
    let mut todo: Vec<usize> = pkgs
        .iter()
        .enumerate()
        .filter(|(_, p)| p.name == root)
        .map(|(i, _)| i)
        .collect();
    while let Some(i) = todo.pop() {
        if !seen.insert(i) {
            continue;
        }
        for d in &pkgs[i].deps {
            if let Some(j) = resolve(&pkgs, d) {
                todo.push(j);
            }
        }
    }
    let mut rows: BTreeMap<(String, String), String> = BTreeMap::new();
    for i in seen {
        let p = &pkgs[i];
        // workspace members have no source: they are Patronus itself, not a third party
        if p.source.is_empty() {
            continue;
        }
        let kind = if p.source.starts_with("registry+") {
            "registry"
        } else if p.source.starts_with("git+") {
            "git"
        } else {
            "other"
        };
        rows.insert((p.name.clone(), p.version.clone()), kind.to_string());
    }
    let mut s = String::new();
    let _ = writeln!(s, "@@PATRONUS-DEPS-BEGIN/1@@");
    let _ = writeln!(
        s,
        "binary {}",
        std::env::var("CARGO_PKG_NAME").unwrap_or_default()
    );
    let _ = writeln!(
        s,
        "version {}",
        std::env::var("CARGO_PKG_VERSION").unwrap_or_default()
    );
    let _ = writeln!(s, "scope lockfile-closure");
    for ((n, v), k) in rows {
        let _ = writeln!(s, "crate {n} {v} {k}");
    }
    let _ = writeln!(s, "@@PATRONUS-DEPS-END@@");
    s
}

pub fn write_dep_list() {
    let manifest = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_default();
    let name = std::env::var("CARGO_PKG_NAME").unwrap_or_default();
    let out = std::path::PathBuf::from(std::env::var("OUT_DIR").unwrap_or_default());
    // the workspace lockfile: two levels up from crates/<name>, or next to the crate
    let mut text = String::new();
    let mut p = std::path::PathBuf::from(&manifest);
    for _ in 0..4 {
        let c = p.join("Cargo.lock");
        if let Ok(t) = std::fs::read_to_string(&c) {
            println!("cargo:rerun-if-changed={}", c.display());
            text = t;
            break;
        }
        if !p.pop() {
            break;
        }
    }
    let body = if text.is_empty() {
        // no lockfile at build time: say so instead of embedding an empty "clean" list
        format!(
            "@@PATRONUS-DEPS-BEGIN/1@@\nbinary {name}\nversion {}\nscope unavailable\n@@PATRONUS-DEPS-END@@\n",
            std::env::var("CARGO_PKG_VERSION").unwrap_or_default()
        )
    } else {
        dependency_list(&text, &name)
    };
    std::fs::write(out.join("patronus-deps.txt"), body).expect("write patronus-deps.txt");
    println!("cargo:rerun-if-changed=build.rs");
}
