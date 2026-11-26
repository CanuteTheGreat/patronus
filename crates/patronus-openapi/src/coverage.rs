//! UI page -> API coverage: which pages talk to which API operations, and which pages have none.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use crate::scan::Scan;
use crate::spec::{is_api_path, served_routes};

#[derive(Debug, Clone)]
pub struct PageRow {
    pub path: String,
    pub template: Option<String>,
    /// URLs the template's scripts call, as written (`/api/vpn/peers/` = followed by an id).
    pub urls: BTreeSet<String>,
    /// OpenAPI paths those URLs match.
    pub apis: BTreeSet<String>,
}

fn template_text(dir: &Path, name: &str, seen: &mut BTreeSet<String>, out: &mut String) {
    if name == "base.html" || name == "theme_head.html" || !seen.insert(name.to_string()) {
        return;
    }
    let Ok(t) = fs::read_to_string(dir.join(name)) else {
        return;
    };
    out.push_str(&t);
    out.push('\n');
    let mut rest = t.as_str();
    while let Some(i) = rest.find("{%") {
        let tail = &rest[i..];
        let end = tail.find("%}").unwrap_or(tail.len());
        let tag = &tail[2..end];
        if tag.contains("include") || tag.contains("extends") {
            if let Some(q1) = tag.find('"') {
                if let Some(q2) = tag[q1 + 1..].find('"') {
                    let n = tag[q1 + 1..q1 + 1 + q2].to_string();
                    template_text(dir, &n, seen, out);
                }
            }
        }
        rest = &tail[end.min(tail.len())..];
        if rest.len() < 2 {
            break;
        }
        rest = &rest[2..];
    }
}

/// `/api/...` URLs in a template's scripts. A URL cut at `${` or ending in `/` is a prefix
/// (an id or a name follows).
pub fn api_urls(text: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let b = text.as_bytes();
    let mut i = 0;
    while let Some(p) = text[i..].find("/api/") {
        let start = i + p;
        let mut end = start;
        while end < b.len() {
            let c = b[end] as char;
            if c.is_ascii_alphanumeric() || "/_-.:".contains(c) {
                end += 1;
            } else {
                break;
            }
        }
        let u = &text[start..end];
        // '/api/' alone, or part of a longer word (`/apis/`)
        let dynamic = end < b.len()
            && matches!(b[end] as char, '$' | '\'' | '"' | '`' | '+' | ' ')
            && (u.ends_with('/')
                || text[end..].starts_with("${")
                || text[end..].starts_with("' +")
                || text[end..].starts_with("\" +")
                || text[end..].starts_with("' ")
                || text[end..].starts_with("+"));
        let mut u = u.to_string();
        if u.len() > 5 {
            if dynamic && !u.ends_with('/') {
                u.push('/');
            }
            out.insert(u);
        }
        i = end.max(start + 5);
    }
    out
}

/// `'/foo/bar'` string literals (not `/api/...`) of a template's scripts.
fn quoted_paths(text: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let b = text.as_bytes();
    let mut i = 0;
    while i < b.len() {
        let q = b[i] as char;
        if (q == '\'' || q == '"') && i + 1 < b.len() && b[i + 1] == b'/' {
            let mut j = i + 1;
            while j < b.len() && (b[j].is_ascii_alphanumeric() || b"/_-.:".contains(&b[j])) {
                j += 1;
            }
            let u = &text[i + 1..j];
            let closes =
                j < b.len() && (b[j] as char == q || b[j] == b'?' || b[j] == b'+' || b[j] == b'$');
            if closes && u.len() > 1 && !u.starts_with("/api") && !u.starts_with("//") {
                let mut u = u.to_string();
                if matches!(b[j], b'+' | b'$') && !u.ends_with('/') {
                    u.push('/');
                }
                out.insert(u);
            }
            i = j;
        } else {
            i += 1;
        }
    }
    out
}

fn seg_match(spec: &[&str], url: &[&str], prefix: bool) -> bool {
    if prefix {
        if url.len() > spec.len() {
            return false;
        }
    } else if url.len() != spec.len() {
        return false;
    }
    url.iter()
        .zip(spec)
        .all(|(u, s)| u == s || (s.starts_with('{') && s.ends_with('}')) || u.starts_with(':'))
}

pub fn match_api(url: &str, spec_paths: &BTreeSet<String>) -> BTreeSet<String> {
    let dynamic = url.ends_with('/');
    let u: Vec<&str> = url.trim_end_matches('/').split('/').collect();
    spec_paths
        .iter()
        .filter(|p| {
            let s: Vec<&str> = p.split('/').collect();
            if dynamic {
                // an id follows: the spec path has at least one more segment
                s.len() > u.len() && seg_match(&s, &u, true)
            } else {
                seg_match(&s, &u, false)
            }
        })
        .cloned()
        .collect()
}

pub fn page_rows(scan: &Scan, root: &Path) -> Result<Vec<PageRow>, String> {
    let served = served_routes(scan)?;
    let spec_paths: BTreeSet<String> = served
        .iter()
        .filter(|s| is_api_path(&s.path))
        .map(|s| s.path.clone())
        .collect();
    let tdir = root.join("crates/patronus-web/templates");
    let mut rows: BTreeMap<String, PageRow> = BTreeMap::new();
    for s in &served {
        if is_api_path(&s.path) || s.method != "get" || s.is_closure {
            continue;
        }
        let Some(fi) = scan.resolve(&s.file, &s.handler_ref) else {
            continue;
        };
        let Some(tname) = fi
            .body_idents
            .iter()
            .find_map(|i| scan.templates.get(&(fi.file.clone(), i.clone())))
            .cloned()
        else {
            continue;
        };
        if tname == "not_built.html" || tname == "ap_notice.html" {
            continue;
        }
        let mut text = String::new();
        template_text(&tdir, &tname, &mut BTreeSet::new(), &mut text);
        let mut urls = api_urls(&text);
        // a helper that prepends the prefix: call('GET', '/stats/history')
        if text.contains("'/api' +") || text.contains("\"/api\" +") || text.contains("`/api${") {
            for u in quoted_paths(&text) {
                urls.insert(format!("/api{u}"));
            }
        }
        let mut apis = BTreeSet::new();
        for u in &urls {
            apis.extend(match_api(u, &spec_paths));
        }
        rows.entry(s.path.clone()).or_insert(PageRow {
            path: s.path.clone(),
            template: Some(tname),
            urls,
            apis,
        });
    }
    Ok(rows.into_values().collect())
}

/// `crates/patronus-openapi/page-api-exempt.txt`: `<page path> <reason>` per line.
pub fn exempt(root: &Path) -> BTreeMap<String, String> {
    let mut m = BTreeMap::new();
    let t = fs::read_to_string(root.join("crates/patronus-openapi/page-api-exempt.txt"))
        .unwrap_or_default();
    for l in t.lines() {
        let l = l.trim();
        if l.is_empty() || l.starts_with('#') {
            continue;
        }
        let (p, r) = l.split_once(char::is_whitespace).unwrap_or((l, ""));
        m.insert(p.to_string(), r.trim().to_string());
    }
    m
}

/// Problems with the exemption list: a page without an API that is not listed, or a listed page
/// that now has an API (or no longer exists).
pub fn exempt_problems(rows: &[PageRow], ex: &BTreeMap<String, String>) -> Vec<String> {
    let mut p = Vec::new();
    for r in rows {
        let none = r.apis.is_empty();
        match (none, ex.get(&r.path)) {
            (true, None) => p.push(format!(
                "page {} calls no API operation: give it an API or list it with a reason in crates/patronus-openapi/page-api-exempt.txt",
                r.path
            )),
            (false, Some(_)) => p.push(format!(
                "page {} now uses the API: remove it from page-api-exempt.txt",
                r.path
            )),
            _ => {}
        }
    }
    for k in ex.keys() {
        if !rows.iter().any(|r| &r.path == k) {
            p.push(format!(
                "page-api-exempt.txt lists {k}, which is not a page route"
            ));
        }
    }
    p
}

pub fn markdown(
    rows: &[PageRow],
    spec_ops: &[(String, String)],
    ex: &BTreeMap<String, String>,
) -> String {
    let mut s = String::new();
    s.push_str("# UI page / API coverage\n\n");
    s.push_str("Generated by `cargo run -p patronus-openapi` from the page handlers, the templates' scripts and the\n");
    s.push_str("route table (CI fails when this file is out of date). A page \"uses\" an API path when its template's\n");
    s.push_str(
        "scripts call it (a URL that ends in `/` or `${`-style id counts every path below it).\n",
    );
    s.push_str("The OpenAPI document is [openapi.json](openapi.json); on a running box it is at `/api/docs`.\n\n");
    let with: Vec<&PageRow> = rows.iter().filter(|r| !r.apis.is_empty()).collect();
    let without: Vec<&PageRow> = rows.iter().filter(|r| r.apis.is_empty()).collect();
    s.push_str(&format!(
        "Pages: {}. With an API: {}. Without: {}.\n\n",
        rows.len(),
        with.len(),
        without.len()
    ));
    s.push_str("## Pages and the API paths they use\n\n| Page | Template | API paths used |\n|---|---|---|\n");
    for r in rows {
        let apis = if r.apis.is_empty() {
            "none".to_string()
        } else {
            let v: Vec<String> = r.apis.iter().map(|a| format!("`{a}`")).collect();
            if v.len() > 6 {
                format!("{} paths: {}, ...", v.len(), v[..6].join(", "))
            } else {
                v.join(", ")
            }
        };
        s.push_str(&format!(
            "| `{}` | {} | {} |\n",
            r.path,
            r.template.as_deref().unwrap_or("?"),
            apis
        ));
    }
    s.push_str("\n## Pages without an API\n\n");
    if without.is_empty() {
        s.push_str("None.\n");
    } else {
        s.push_str("| Page | Why |\n|---|---|\n");
        for r in &without {
            s.push_str(&format!(
                "| `{}` | {} |\n",
                r.path,
                ex.get(&r.path)
                    .map(String::as_str)
                    .unwrap_or("(not listed)")
            ));
        }
    }
    let used: BTreeSet<&String> = rows.iter().flat_map(|r| r.apis.iter()).collect();
    let mut unused: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (m, p) in spec_ops {
        if !used.contains(p) {
            let tag = if p == "/metrics" {
                "metrics".to_string()
            } else {
                p.trim_start_matches("/api/")
                    .split('/')
                    .next()
                    .unwrap_or("")
                    .to_string()
            };
            unused
                .entry(tag)
                .or_default()
                .push(format!("{} {}", m.to_uppercase(), p));
        }
    }
    let n: usize = unused.values().map(|v| v.len()).sum();
    s.push_str(&format!(
        "\n## API operations no page calls ({n} of {})\n\nThese are reachable only through the API (automation, GitOps, the CLI) or are called from the shared layout.\n\n",
        spec_ops.len()
    ));
    for (tag, v) in &unused {
        s.push_str(&format!(
            "- **{tag}**: {}\n",
            v.iter()
                .map(|x| format!("`{x}`"))
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    s
}
