//! Gentoo Linux Security Advisories: read from the local GLSA XML files (the tree's
//! `metadata/glsa`, the same data `glsa-check` from app-portage/gentoolkit reads) and
//! matched against the installed packages in `/var/db/pkg`.
//!
//! Reading the files directly keeps the check small and testable and does not start
//! a Python interpreter on the router; a stale or missing tree is reported as
//! "unknown" or "stale", never as "clean" (`Freshness`).

use super::version::{gentoo_range_matches, split_pf, GentooVersion};
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Range {
    pub op: String,
    pub version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GlsaPackage {
    /// `category/name`
    pub name: String,
    pub slot: Option<String>,
    pub vulnerable: Vec<Range>,
    pub unaffected: Vec<Range>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Glsa {
    pub id: String,
    pub title: String,
    pub synopsis: String,
    pub announced: String,
    pub revised: String,
    /// `trivial`, `low`, `normal` or `high` (the GLSA's impact type)
    pub impact: String,
    pub bugs: Vec<String>,
    pub packages: Vec<GlsaPackage>,
    pub references: Vec<(String, String)>,
}

fn unescape(s: &str) -> String {
    s.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
}

/// `(attributes, inner text)` of every `<tag ...>inner</tag>` in `xml`, in order.
/// The GLSA schema does not nest the tags read here inside themselves.
fn elements<'a>(xml: &'a str, tag: &str) -> Vec<(String, &'a str)> {
    let open = format!("<{tag}");
    let close = format!("</{tag}>");
    let mut out = Vec::new();
    let mut pos = 0;
    while let Some(i) = xml[pos..].find(&open) {
        let start = pos + i;
        let after = start + open.len();
        match xml.as_bytes().get(after) {
            Some(b' ') | Some(b'>') | Some(b'/') | Some(b'\n') | Some(b'\t') | Some(b'\r') => {}
            _ => {
                pos = after;
                continue;
            }
        }
        let Some(gt) = xml[after..].find('>') else {
            break;
        };
        let attrs_end = after + gt;
        let attrs = xml[after..attrs_end].trim_end_matches('/').to_string();
        if xml[..attrs_end].ends_with('/') {
            out.push((attrs, ""));
            pos = attrs_end + 1;
            continue;
        }
        let inner_start = attrs_end + 1;
        let Some(end) = xml[inner_start..].find(&close) else {
            break;
        };
        out.push((attrs, &xml[inner_start..inner_start + end]));
        pos = inner_start + end + close.len();
    }
    out
}

fn attr(attrs: &str, name: &str) -> Option<String> {
    let key = format!("{name}=\"");
    let mut from = 0;
    while let Some(i) = attrs[from..].find(&key) {
        let at = from + i;
        if at == 0 || attrs.as_bytes()[at - 1].is_ascii_whitespace() {
            let rest = &attrs[at + key.len()..];
            return rest.find('"').map(|e| unescape(&rest[..e]));
        }
        from = at + key.len();
    }
    None
}

fn first_text(xml: &str, tag: &str) -> String {
    elements(xml, tag)
        .first()
        .map(|(_, t)| unescape(t.trim()))
        .unwrap_or_default()
}

pub fn parse(xml: &str) -> Option<Glsa> {
    let g = elements(xml, "glsa");
    let (gattrs, _) = g.first()?;
    let id = attr(gattrs, "id")?;
    let mut packages = Vec::new();
    for (pa, inner) in elements(xml, "package") {
        let Some(name) = attr(&pa, "name") else {
            continue;
        };
        let ranges = |tag: &str| -> Vec<Range> {
            elements(inner, tag)
                .into_iter()
                .filter_map(|(a, t)| {
                    Some(Range {
                        op: attr(&a, "range")?,
                        version: unescape(t.trim()),
                    })
                })
                .collect()
        };
        let slot = elements(inner, "vulnerable")
            .first()
            .and_then(|(a, _)| attr(a, "slot"))
            .filter(|s| s != "*");
        packages.push(GlsaPackage {
            name,
            slot,
            vulnerable: ranges("vulnerable"),
            unaffected: ranges("unaffected"),
        });
    }
    let impact = elements(xml, "impact")
        .first()
        .and_then(|(a, _)| attr(a, "type"))
        .unwrap_or_else(|| "normal".into());
    let revised = elements(xml, "revised")
        .first()
        .map(|(_, t)| t.trim().to_string())
        .unwrap_or_default();
    let references = elements(xml, "uri")
        .into_iter()
        .filter_map(|(a, t)| Some((attr(&a, "link")?, unescape(t.trim()))))
        .collect();
    Some(Glsa {
        id,
        title: first_text(xml, "title"),
        synopsis: first_text(xml, "synopsis"),
        announced: first_text(xml, "announced"),
        revised,
        impact,
        bugs: elements(xml, "bug")
            .into_iter()
            .map(|(_, t)| t.trim().to_string())
            .collect(),
        packages,
        references,
    })
}

/// What reading the advisory directory found.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GlsaSet {
    pub advisories: Vec<Glsa>,
    pub files: usize,
    pub skipped: usize,
    /// newest file modification time (unix seconds), None when there are no files
    pub newest_mtime: Option<i64>,
}

const MAX_FILE: u64 = 2 << 20;
const MAX_FILES: usize = 50_000;

pub fn load_dir(dir: &Path) -> GlsaSet {
    let mut set = GlsaSet::default();
    let Ok(rd) = std::fs::read_dir(dir) else {
        return set;
    };
    for e in rd.flatten() {
        let name = e.file_name().to_string_lossy().to_string();
        if !(name.starts_with("glsa-") && name.ends_with(".xml")) {
            continue;
        }
        if set.files >= MAX_FILES {
            set.skipped += 1;
            continue;
        }
        let Ok(md) = e.metadata() else { continue };
        set.files += 1;
        if md.len() > MAX_FILE {
            set.skipped += 1;
            continue;
        }
        if let Ok(m) = md.modified() {
            if let Ok(d) = m.duration_since(std::time::UNIX_EPOCH) {
                let t = d.as_secs() as i64;
                set.newest_mtime = Some(set.newest_mtime.map_or(t, |o| o.max(t)));
            }
        }
        match std::fs::read_to_string(e.path()).ok().and_then(|t| parse(&t)) {
            Some(g) => set.advisories.push(g),
            None => set.skipped += 1,
        }
    }
    set.advisories.sort_by(|a, b| a.id.cmp(&b.id));
    set
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct InstalledPackage {
    /// `category/name`
    pub name: String,
    pub version: String,
    pub slot: Option<String>,
}

/// Read `/var/db/pkg/<category>/<name>-<version>/`.
pub fn installed(db: &Path) -> Vec<InstalledPackage> {
    let mut out = Vec::new();
    let Ok(cats) = std::fs::read_dir(db) else {
        return out;
    };
    for c in cats.flatten() {
        let cat = c.file_name().to_string_lossy().to_string();
        if cat.starts_with('.') || !c.path().is_dir() {
            continue;
        }
        let Ok(pkgs) = std::fs::read_dir(c.path()) else {
            continue;
        };
        for p in pkgs.flatten() {
            let pf = p.file_name().to_string_lossy().to_string();
            if pf.starts_with('.') || pf.starts_with("-MERGING-") {
                continue;
            }
            let Some((name, ver)) = split_pf(&pf) else {
                continue;
            };
            let slot = std::fs::read_to_string(p.path().join("SLOT"))
                .ok()
                .map(|s| s.trim().split('/').next().unwrap_or("").to_string())
                .filter(|s| !s.is_empty());
            out.push(InstalledPackage {
                name: format!("{cat}/{name}"),
                version: ver.raw,
                slot,
            });
        }
    }
    out.sort_by(|a, b| a.name.cmp(&b.name).then(a.version.cmp(&b.version)));
    out
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GlsaHit {
    pub glsa: String,
    pub package: String,
    pub installed: String,
    /// versions at which the package is no longer affected, ascending
    pub fixed_in: Vec<String>,
    pub title: String,
    pub impact: String,
    pub url: String,
}

fn pkg_vulnerable(p: &GlsaPackage, v: &GentooVersion, slot: Option<&str>) -> bool {
    if let (Some(want), Some(have)) = (p.slot.as_deref(), slot) {
        if want != have {
            return false;
        }
    }
    let vuln = p
        .vulnerable
        .iter()
        .any(|r| gentoo_range_matches(&r.op, &r.version, v));
    let fixed = p
        .unaffected
        .iter()
        .any(|r| gentoo_range_matches(&r.op, &r.version, v));
    vuln && !fixed
}

/// Versions that end the exposure of `installed`: the unaffected bounds above it.
pub fn fixed_versions(p: &GlsaPackage, installed: &GentooVersion) -> Vec<String> {
    let mut v: Vec<GentooVersion> = p
        .unaffected
        .iter()
        .filter(|r| matches!(r.op.as_str(), "ge" | "rge" | "gt" | "rgt" | "eq"))
        .filter_map(|r| GentooVersion::parse(r.version.trim_end_matches('*')))
        .filter(|f| f > installed)
        .collect();
    v.sort();
    v.dedup();
    v.into_iter().map(|g| g.raw).collect()
}

pub fn find_hits(set: &GlsaSet, installed: &[InstalledPackage]) -> Vec<GlsaHit> {
    let mut hits = Vec::new();
    for g in &set.advisories {
        for p in &g.packages {
            for ip in installed.iter().filter(|i| i.name == p.name) {
                let Some(v) = GentooVersion::parse(&ip.version) else {
                    continue;
                };
                if pkg_vulnerable(p, &v, ip.slot.as_deref()) {
                    hits.push(GlsaHit {
                        glsa: g.id.clone(),
                        package: ip.name.clone(),
                        installed: ip.version.clone(),
                        fixed_in: fixed_versions(p, &v),
                        title: g.title.clone(),
                        impact: g.impact.clone(),
                        url: format!("https://security.gentoo.org/glsa/{}", g.id),
                    });
                }
            }
        }
    }
    hits
}

#[cfg(test)]
mod tests {
    use super::*;

    pub const JOBLIB: &str = include_str!("../../tests/data/glsa-202401-01.xml");

    #[test]
    fn parses_a_real_advisory() {
        let g = parse(JOBLIB).unwrap();
        assert_eq!(g.id, "202401-01");
        assert_eq!(g.title, "Joblib: Arbitrary Code Execution");
        assert_eq!(g.impact, "high");
        assert_eq!(g.bugs, vec!["873151"]);
        assert_eq!(g.packages.len(), 1);
        assert_eq!(g.packages[0].name, "dev-python/joblib");
        assert_eq!(g.packages[0].unaffected[0].op, "ge");
        assert_eq!(g.references[0].1, "CVE-2022-21797");
    }

    fn pkg(name: &str, v: &str) -> InstalledPackage {
        InstalledPackage {
            name: name.into(),
            version: v.into(),
            slot: Some("0".into()),
        }
    }

    #[test]
    fn affected_fixed_and_other_packages() {
        let set = GlsaSet {
            advisories: vec![parse(JOBLIB).unwrap()],
            ..Default::default()
        };
        let hits = find_hits(
            &set,
            &[
                pkg("dev-python/joblib", "1.1.0-r1"),
                pkg("dev-python/joblib", "1.2.0"),
                pkg("dev-python/other", "0.1"),
            ],
        );
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].installed, "1.1.0-r1");
        assert_eq!(hits[0].fixed_in, vec!["1.2.0"]);
        assert_eq!(hits[0].url, "https://security.gentoo.org/glsa/202401-01");
    }

    #[test]
    fn slot_and_unaffected_branches() {
        let xml = r#"<glsa id="202001-02"><title>T</title><impact type="normal"><p>x</p></impact>
          <affected><package name="dev-lang/foo" auto="yes" arch="*">
            <unaffected range="ge">2.0</unaffected>
            <unaffected range="rge">1.5.3-r1</unaffected>
            <vulnerable range="lt">2.0</vulnerable>
          </package></affected></glsa>"#;
        let set = GlsaSet {
            advisories: vec![parse(xml).unwrap()],
            ..Default::default()
        };
        // 1.5.3-r1 is the backported fix of the 1.5 branch
        assert!(find_hits(&set, &[pkg("dev-lang/foo", "1.5.3-r1")]).is_empty());
        let h = find_hits(&set, &[pkg("dev-lang/foo", "1.5.3")]);
        assert_eq!(h.len(), 1);
        assert_eq!(h[0].fixed_in, vec!["1.5.3-r1", "2.0"]);
        assert_eq!(h[0].impact, "normal");
    }

    #[test]
    fn installed_reads_the_package_db() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("dev-python/joblib-1.1.0-r1");
        std::fs::create_dir_all(&p).unwrap();
        std::fs::write(p.join("SLOT"), "0/1\n").unwrap();
        std::fs::create_dir_all(d.path().join("sys-apps/-MERGING-foo-1.0")).unwrap();
        let v = installed(d.path());
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].name, "dev-python/joblib");
        assert_eq!(v[0].version, "1.1.0-r1");
        assert_eq!(v[0].slot.as_deref(), Some("0"));
    }

    #[test]
    fn load_dir_counts_and_times_the_files() {
        let d = tempfile::tempdir().unwrap();
        std::fs::write(d.path().join("glsa-202401-01.xml"), JOBLIB).unwrap();
        std::fs::write(d.path().join("glsa-broken.xml"), "<html>").unwrap();
        std::fs::write(d.path().join("README"), "x").unwrap();
        let s = load_dir(d.path());
        assert_eq!(s.files, 2);
        assert_eq!(s.advisories.len(), 1);
        assert_eq!(s.skipped, 1);
        assert!(s.newest_mtime.is_some());
        assert_eq!(load_dir(&d.path().join("missing")).files, 0);
    }
}
