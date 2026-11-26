//! Rust crate advisories from OSV (crates.io ecosystem: the RustSec database plus GitHub
//! advisories). The data comes as ONE public archive (`all.zip`, a few MB) that is
//! downloaded on a schedule, size-capped, reduced to the fields the view needs and cached
//! on disk. Matching happens on the router, so no crate name or version ever leaves it
//! (the OSV query API would send both).

use super::version::SemVer;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::Read;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Event {
    /// `introduced`, `fixed` or `last_affected`
    pub kind: String,
    pub version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Advisory {
    pub id: String,
    pub aliases: Vec<String>,
    pub summary: String,
    pub url: String,
    pub events: Vec<Event>,
    /// explicitly listed affected versions
    pub versions: Vec<String>,
    /// RustSec notices that are not vulnerabilities: `unmaintained`, `unsound`, `notice`
    #[serde(default)]
    pub informational: Option<String>,
    /// `high`, `medium`, `low` when the database rates it (GitHub advisories do)
    #[serde(default)]
    pub severity: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OsvDb {
    /// crate name -> advisories
    pub crates: BTreeMap<String, Vec<Advisory>>,
    pub advisories: usize,
    /// when the archive was downloaded (unix seconds)
    pub fetched_at: i64,
    pub source_url: String,
    pub archive_bytes: u64,
    pub withdrawn_skipped: usize,
}

/// Reduce one OSV record. A withdrawn advisory yields nothing.
pub fn parse_record(json: &str) -> Option<(Vec<(String, Advisory)>, bool)> {
    let v: serde_json::Value = serde_json::from_str(json).ok()?;
    let id = v.get("id")?.as_str()?.to_string();
    if v.get("withdrawn").is_some() {
        return Some((Vec::new(), true));
    }
    let strs = |x: Option<&serde_json::Value>| -> Vec<String> {
        x.and_then(|a| a.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|s| s.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default()
    };
    let mut aliases = strs(v.get("aliases"));
    aliases.extend(
        strs(v.get("related"))
            .into_iter()
            .filter(|r| r.starts_with("CVE-")),
    );
    aliases.sort();
    aliases.dedup();
    let summary = v
        .get("summary")
        .and_then(|s| s.as_str())
        .unwrap_or("")
        .chars()
        .take(300)
        .collect::<String>();
    let mut url = String::new();
    if let Some(refs) = v.get("references").and_then(|r| r.as_array()) {
        for pick in ["ADVISORY", "WEB"] {
            if let Some(u) = refs.iter().find_map(|r| {
                (r.get("type").and_then(|t| t.as_str()) == Some(pick))
                    .then(|| r.get("url").and_then(|u| u.as_str()))
                    .flatten()
            }) {
                url = u.to_string();
                break;
            }
        }
    }
    if url.is_empty() {
        url = if id.starts_with("RUSTSEC-") {
            format!("https://rustsec.org/advisories/{id}.html")
        } else {
            format!("https://osv.dev/vulnerability/{id}")
        };
    }
    let severity = match v
        .get("database_specific")
        .and_then(|d| d.get("severity"))
        .and_then(|s| s.as_str())
        .map(|s| s.to_ascii_uppercase())
        .as_deref()
    {
        Some("CRITICAL") | Some("HIGH") => "high",
        Some("MODERATE") | Some("MEDIUM") => "medium",
        Some("LOW") => "low",
        _ => "",
    }
    .to_string();
    let mut out = Vec::new();
    for a in v.get("affected")?.as_array()? {
        let p = a.get("package")?;
        if p.get("ecosystem").and_then(|e| e.as_str()) != Some("crates.io") {
            continue;
        }
        let name = p.get("name")?.as_str()?.to_string();
        let mut events = Vec::new();
        for r in a
            .get("ranges")
            .and_then(|r| r.as_array())
            .into_iter()
            .flatten()
        {
            if r.get("type").and_then(|t| t.as_str()) == Some("GIT") {
                continue;
            }
            for e in r
                .get("events")
                .and_then(|e| e.as_array())
                .into_iter()
                .flatten()
            {
                for kind in ["introduced", "fixed", "last_affected"] {
                    if let Some(ver) = e.get(kind).and_then(|x| x.as_str()) {
                        events.push(Event {
                            kind: kind.into(),
                            version: ver.into(),
                        });
                    }
                }
            }
        }
        out.push((
            name,
            Advisory {
                id: id.clone(),
                aliases: aliases.clone(),
                summary: summary.clone(),
                url: url.clone(),
                events,
                versions: strs(a.get("versions")),
                informational: a
                    .get("database_specific")
                    .and_then(|d| d.get("informational"))
                    .and_then(|i| i.as_str())
                    .map(String::from),
                severity: severity.clone(),
            },
        ));
    }
    Some((out, false))
}

impl Advisory {
    /// OSV evaluation: walk the events in version order; `introduced` switches on at
    /// or above its version, `fixed` switches off at or above, `last_affected` off above.
    pub fn affects(&self, v: &SemVer) -> bool {
        if self
            .versions
            .iter()
            .filter_map(|s| SemVer::parse(s))
            .any(|x| &x == v)
        {
            return true;
        }
        let mut ev: Vec<(SemVer, &str)> = self
            .events
            .iter()
            .filter_map(|e| {
                let ver = if e.version == "0" {
                    "0.0.0-0"
                } else {
                    &e.version
                };
                Some((SemVer::parse(ver)?, e.kind.as_str()))
            })
            .collect();
        // an introduced event at the same version as a fixed one applies after it
        ev.sort_by(|a, b| {
            a.0.cmp(&b.0)
                .then((a.1 == "introduced").cmp(&(b.1 == "introduced")))
        });
        let mut affected = false;
        for (ver, kind) in &ev {
            match *kind {
                "introduced" if v >= ver => affected = true,
                "fixed" if v >= ver => affected = false,
                "last_affected" if v > ver => affected = false,
                _ => {}
            }
        }
        affected
    }

    /// The versions that end the exposure above `v`, ascending.
    pub fn fixed_above(&self, v: &SemVer) -> Vec<String> {
        let mut f: Vec<SemVer> = self
            .events
            .iter()
            .filter(|e| e.kind == "fixed")
            .filter_map(|e| SemVer::parse(&e.version))
            .filter(|x| x > v)
            .collect();
        f.sort();
        f.dedup();
        f.into_iter().map(|s| s.raw).collect()
    }
}

const MAX_RECORD: u64 = 1 << 20;
const MAX_RECORDS: usize = 200_000;
/// Cap on the unpacked size of everything read from the archive (zip-bomb guard).
const MAX_UNPACKED: u64 = 512 << 20;

/// Build the compact database from the downloaded archive bytes.
pub fn build_from_zip(bytes: &[u8], source_url: &str, now: i64) -> Result<OsvDb, String> {
    let mut zip = zip::ZipArchive::new(std::io::Cursor::new(bytes))
        .map_err(|e| format!("not a zip archive: {e}"))?;
    let mut db = OsvDb {
        fetched_at: now,
        source_url: source_url.to_string(),
        archive_bytes: bytes.len() as u64,
        ..Default::default()
    };
    let mut unpacked = 0u64;
    for i in 0..zip.len().min(MAX_RECORDS) {
        let mut f = zip.by_index(i).map_err(|e| format!("zip entry {i}: {e}"))?;
        if !f.name().ends_with(".json") || f.size() > MAX_RECORD {
            continue;
        }
        unpacked += f.size();
        if unpacked > MAX_UNPACKED {
            return Err("archive unpacks to more than the allowed size".into());
        }
        let mut s = String::new();
        if f.by_ref().take(MAX_RECORD).read_to_string(&mut s).is_err() {
            continue;
        }
        match parse_record(&s) {
            Some((_, true)) => db.withdrawn_skipped += 1,
            Some((rows, false)) => {
                if !rows.is_empty() {
                    db.advisories += 1;
                }
                for (name, adv) in rows {
                    db.crates.entry(name).or_default().push(adv);
                }
            }
            None => {}
        }
    }
    if db.advisories == 0 {
        return Err("the archive holds no crates.io advisory".into());
    }
    Ok(db)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CrateHit {
    pub binary: String,
    pub name: String,
    pub version: String,
    pub id: String,
    pub aliases: Vec<String>,
    pub summary: String,
    pub url: String,
    pub fixed_in: Vec<String>,
    pub informational: Option<String>,
    pub severity: String,
}

pub fn find_hits(db: &OsvDb, binary: &str, crates: &[(String, String)]) -> Vec<CrateHit> {
    let mut out = Vec::new();
    for (name, ver) in crates {
        let Some(advs) = db.crates.get(name) else {
            continue;
        };
        let Some(v) = SemVer::parse(ver) else {
            continue;
        };
        for a in advs {
            if a.affects(&v) {
                out.push(CrateHit {
                    binary: binary.to_string(),
                    name: name.clone(),
                    version: ver.clone(),
                    id: a.id.clone(),
                    aliases: a.aliases.clone(),
                    summary: a.summary.clone(),
                    url: a.url.clone(),
                    fixed_in: a.fixed_above(&v),
                    informational: a.informational.clone(),
                    severity: a.severity.clone(),
                });
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const H2: &str = include_str!("../../tests/data/RUSTSEC-2024-0003.json");

    fn sv(s: &str) -> SemVer {
        SemVer::parse(s).unwrap()
    }

    #[test]
    fn reduces_a_real_record() {
        let (rows, withdrawn) = parse_record(H2).unwrap();
        assert!(!withdrawn);
        assert_eq!(rows.len(), 1);
        let (name, a) = &rows[0];
        assert_eq!(name, "h2");
        assert_eq!(a.id, "RUSTSEC-2024-0003");
        assert!(a.aliases.contains(&"GHSA-8r5v-vm4m-4g25".to_string()));
        assert!(a.url.starts_with("https://rustsec.org/advisories/"));
    }

    #[test]
    fn range_evaluation_two_branches() {
        let (rows, _) = parse_record(H2).unwrap();
        let a = &rows[0].1;
        assert!(a.affects(&sv("0.3.23")));
        assert!(!a.affects(&sv("0.3.24")));
        assert!(!a.affects(&sv("0.3.30"))); // inside the gap between the branches? no: 0.4.0 introduces
        assert!(a.affects(&sv("0.4.1")));
        assert!(!a.affects(&sv("0.4.2")));
        assert!(!a.affects(&sv("1.0.0")));
        assert_eq!(a.fixed_above(&sv("0.3.20")), vec!["0.3.24", "0.4.2"]);
    }

    #[test]
    fn last_affected_and_exact_versions() {
        let a = Advisory {
            id: "X".into(),
            aliases: vec![],
            summary: String::new(),
            url: String::new(),
            events: vec![
                Event {
                    kind: "introduced".into(),
                    version: "0".into(),
                },
                Event {
                    kind: "last_affected".into(),
                    version: "1.2.0".into(),
                },
            ],
            versions: vec!["3.0.0".into()],
            informational: None,
            severity: String::new(),
        };
        assert!(a.affects(&sv("1.2.0")));
        assert!(!a.affects(&sv("1.2.1")));
        assert!(a.affects(&sv("3.0.0")));
    }

    #[test]
    fn informational_notices_and_ratings_are_kept() {
        let (rows, _) = parse_record(
            r#"{"id":"RUSTSEC-2025-0012","summary":"`backoff` is unmaintained.","affected":[{"package":{"name":"backoff","ecosystem":"crates.io"},
               "ranges":[{"type":"SEMVER","events":[{"introduced":"0.0.0-0"}]}],"database_specific":{"informational":"unmaintained"}}]}"#,
        )
        .unwrap();
        assert_eq!(rows[0].1.informational.as_deref(), Some("unmaintained"));
        assert!(rows[0].1.affects(&sv("0.4.0")), "no fixed event: every version is covered");
        assert!(rows[0].1.fixed_above(&sv("0.4.0")).is_empty());
        let (rows, _) = parse_record(
            r#"{"id":"GHSA-x","database_specific":{"severity":"MODERATE"},"affected":[{"package":{"name":"a","ecosystem":"crates.io"},"ranges":[]}]}"#,
        )
        .unwrap();
        assert_eq!(rows[0].1.severity, "medium");
    }

    #[test]
    fn withdrawn_records_are_dropped() {
        let (rows, w) =
            parse_record(r#"{"id":"GHSA-x","withdrawn":"2024-01-01T00:00:00Z","affected":[]}"#)
                .unwrap();
        assert!(w && rows.is_empty());
    }

    #[test]
    fn zip_round_trip_and_matching() {
        use std::io::Write;
        let mut buf = Vec::new();
        {
            let mut w = zip::ZipWriter::new(std::io::Cursor::new(&mut buf));
            let o = zip::write::SimpleFileOptions::default();
            w.start_file("RUSTSEC-2024-0003.json", o).unwrap();
            w.write_all(H2.as_bytes()).unwrap();
            w.start_file("notes.txt", o).unwrap();
            w.write_all(b"ignored").unwrap();
            w.finish().unwrap();
        }
        let db = build_from_zip(&buf, "https://example.test/all.zip", 1000).unwrap();
        assert_eq!(db.advisories, 1);
        let hits = find_hits(
            &db,
            "patronus-web",
            &[
                ("h2".into(), "0.3.20".into()),
                ("h2".into(), "0.4.5".into()),
                ("serde".into(), "1.0.1".into()),
            ],
        );
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].version, "0.3.20");
        assert!(build_from_zip(b"not a zip", "u", 0).is_err());
    }
}
