//! OpenAPI 3.1 document + UI/API coverage table, generated from the patronus-web sources.

pub mod coverage;
pub mod scan;
pub mod schema;
pub mod spec;

use std::path::{Path, PathBuf};

pub struct Output {
    /// (path relative to the repository root, file content)
    pub files: Vec<(PathBuf, String)>,
    /// Things CI must fail on (unreadable routes, pages without an API and not exempted).
    pub problems: Vec<String>,
}

/// The document is read at runtime by patronus-web (compiled in) from here; `docs/` carries
/// a published copy.
pub const SPEC_IN_CRATE: &str = "crates/patronus-web/openapi/openapi.json";
pub const SPEC_IN_DOCS: &str = "docs/openapi.json";
pub const COVERAGE_MD: &str = "docs/API-COVERAGE.md";

pub fn workspace_version(root: &Path) -> String {
    let t = std::fs::read_to_string(root.join("Cargo.toml")).unwrap_or_default();
    let mut in_pkg = false;
    for l in t.lines() {
        let l = l.trim();
        if l.starts_with('[') {
            in_pkg = l == "[workspace.package]";
        } else if in_pkg {
            if let Some(v) = l.strip_prefix("version") {
                if let Some(q) = v.split('"').nth(1) {
                    return q.to_string();
                }
            }
        }
    }
    "0.0.0".into()
}

/// The same document with every object's keys in sorted order, whatever order the `Map` type of
/// the build keeps (cargo feature unification can switch `serde_json` to insertion order).
fn sorted(v: serde_json::Value) -> serde_json::Value {
    use serde_json::Value;
    match v {
        Value::Object(m) => {
            let mut keys: Vec<String> = m.keys().cloned().collect();
            keys.sort();
            let mut out = serde_json::Map::new();
            let mut m = m;
            for k in keys {
                if let Some(x) = m.remove(&k) {
                    out.insert(k, sorted(x));
                }
            }
            Value::Object(out)
        }
        Value::Array(a) => Value::Array(a.into_iter().map(sorted).collect()),
        x => x,
    }
}

pub fn generate(root: &Path) -> Result<Output, String> {
    let scan = scan::scan(root)?;
    let mut problems = scan.unparsed.clone();
    let mut built = spec::build(&scan, &workspace_version(root))?;
    built.spec = sorted(built.spec);
    let mut json = serde_json::to_string_pretty(&built.spec).map_err(|e| e.to_string())?;
    json.push('\n');
    // the copy compiled into patronus-web is compact (it ships in the router-tier image)
    let compact = serde_json::to_string(&built.spec).map_err(|e| e.to_string())?;
    let rows = coverage::page_rows(&scan, root)?;
    let ex = coverage::exempt(root);
    problems.extend(coverage::exempt_problems(&rows, &ex));
    let md = coverage::markdown(&rows, &built.ops, &ex);
    Ok(Output {
        files: vec![
            (PathBuf::from(SPEC_IN_CRATE), compact),
            (PathBuf::from(SPEC_IN_DOCS), json),
            (PathBuf::from(COVERAGE_MD), md),
        ],
        problems,
    })
}
