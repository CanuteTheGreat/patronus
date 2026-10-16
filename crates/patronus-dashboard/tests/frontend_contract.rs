//! Frontend <-> GraphQL schema contract test.
//!
//! The shipped dashboard UI (repo-root `frontend/`, built into `./static`
//! and served by every patronus-dashboard node) talks to this crate only via
//! GraphQL documents embedded as gql`...` literals. Nothing ever checked
//! those documents against the real schema, so pages could (and did) ship
//! asking for fields the API has never had -- the Sites page could only ever
//! render an error. This test extracts every document from `frontend/src`
//! and validates it against the real schema built from a real AppState.
//!
//! Documents are executed WITHOUT credentials, so resolvers refuse to run
//! (no side effects); only schema-validation errors fail the test.

use patronus_dashboard::{graphql, state::AppState};
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Pages whose queries target SD-WAN/overview/security data that the API
/// does not expose yet. Wiring those features into the dashboard API/UI was
/// assigned (owner, 2026-10-16) to the dedicated SD-WAN wiring work. This is
/// a ratchet: the test FAILS once a listed file validates, so it must be
/// removed from this list in the same change that wires it.
const PENDING_SDWAN_WIRING: &[&str] = &[
    "components/Dashboard.tsx",
    "components/Security.tsx",
    "components/SLA.tsx",
    "components/Topology.tsx",
    "components/Traffic.tsx",
];

fn frontend_src() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../frontend/src")
}

fn collect(dir: &Path, out: &mut Vec<PathBuf>) {
    for e in std::fs::read_dir(dir).unwrap() {
        let p = e.unwrap().path();
        if p.is_dir() {
            collect(&p, out);
        } else if matches!(p.extension().and_then(|x| x.to_str()), Some("ts" | "tsx")) {
            out.push(p);
        }
    }
}

fn documents(src: &str) -> Vec<String> {
    let mut docs = Vec::new();
    let mut rest = src;
    while let Some(i) = rest.find("gql`") {
        rest = &rest[i + 4..];
        let end = rest.find('`').expect("unterminated gql literal");
        docs.push(rest[..end].to_string());
        rest = &rest[end + 1..];
    }
    docs
}

fn is_validation_error(msg: &str) -> bool {
    let m = msg.to_ascii_lowercase();
    [
        "unknown field",
        "unknown type",
        "unknown argument",
        "cannot query field",
        "not defined by operation",
        "unknown fragment",
        "must have a selection",
        "must not have a selection",
        "expected type",
        "parse error",
        "syntax error",
    ]
    .iter()
    .any(|k| m.contains(k))
}

#[tokio::test]
async fn every_frontend_graphql_document_matches_the_schema() {
    let state = Arc::new(AppState::new(":memory:").await.unwrap());
    let schema = graphql::build_schema(state);

    let mut files = Vec::new();
    collect(&frontend_src(), &mut files);
    assert!(!files.is_empty(), "frontend/src not found");

    let mut checked = 0;
    let mut failures = Vec::new();
    let mut pending_ok = Vec::new();
    for f in files {
        let rel = f
            .strip_prefix(frontend_src())
            .unwrap()
            .to_string_lossy()
            .replace('\\', "/");
        let pending = PENDING_SDWAN_WIRING.contains(&rel.as_str());
        let src = std::fs::read_to_string(&f).unwrap();
        let mut file_errors = Vec::new();
        for doc in documents(&src) {
            checked += 1;
            let resp = schema
                .execute(async_graphql::Request::new(doc.clone()))
                .await;
            for e in resp.errors {
                if is_validation_error(&e.message) {
                    file_errors.push(format!("{rel}: {}", e.message));
                }
            }
        }
        if pending {
            if file_errors.is_empty() {
                pending_ok.push(rel);
            }
        } else {
            failures.extend(file_errors);
        }
    }
    assert!(
        checked >= 3,
        "expected to find gql documents, found {checked}"
    );
    assert!(
        failures.is_empty(),
        "frontend GraphQL documents do not match the schema:\n{}",
        failures.join("\n")
    );
    assert!(
        pending_ok.is_empty(),
        "these pages now validate -- remove them from PENDING_SDWAN_WIRING: {pending_ok:?}"
    );
}

#[test]
fn extractor_finds_documents() {
    let docs = documents("const A = gql`\n query A { x }\n`\nconst B = gql`mutation { y }`");
    assert_eq!(docs.len(), 2);
    assert!(docs[1].contains("mutation"));
}
