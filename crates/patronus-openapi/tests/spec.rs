//! CI gate for the API description: the committed OpenAPI document and coverage table match the
//! sources, every route the sources register is in the document, and the document is well formed.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use patronus_openapi::{generate, scan, spec};

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

#[test]
fn generated_files_are_current() {
    let out = generate(&root()).expect("generate");
    assert!(
        out.problems.is_empty(),
        "problems:\n{}",
        out.problems.join("\n")
    );
    for (rel, content) in &out.files {
        let on_disk = std::fs::read_to_string(root().join(rel)).unwrap_or_default();
        assert!(
            on_disk == *content,
            "{} is out of date: run `cargo run -p patronus-openapi` and commit the result",
            rel.display()
        );
    }
}

#[test]
fn every_api_route_is_in_the_document() {
    let sc = scan::scan(&root()).expect("scan");
    assert!(
        sc.unparsed.is_empty(),
        "unreadable routes: {:?}",
        sc.unparsed
    );
    let served = spec::served_routes(&sc).expect("routes");
    let doc: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(root().join(patronus_openapi::SPEC_IN_DOCS))
            .expect("docs/openapi.json"),
    )
    .expect("json");
    let mut missing = Vec::new();
    let mut n = 0;
    for s in served.iter().filter(|s| spec::is_api_path(&s.path)) {
        n += 1;
        if doc["paths"][&s.path][&s.method].is_null() {
            missing.push(format!("{} {}", s.method.to_uppercase(), s.path));
        }
    }
    assert!(
        n > 200,
        "only {n} API routes found: the scanner lost the route table"
    );
    assert!(
        missing.is_empty(),
        "routes missing from docs/openapi.json: {missing:?}"
    );
    // the document has nothing the sources do not serve
    let have: BTreeSet<(String, String)> = served
        .iter()
        .filter(|s| spec::is_api_path(&s.path))
        .map(|s| (s.method.clone(), s.path.clone()))
        .collect();
    for (path, item) in doc["paths"].as_object().expect("paths") {
        for m in item.as_object().expect("item").keys() {
            assert!(
                have.contains(&(m.clone(), path.clone())),
                "{m} {path} is in the document but not in the sources"
            );
        }
    }
}

#[test]
fn document_is_well_formed() {
    let doc: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(root().join(patronus_openapi::SPEC_IN_DOCS)).expect("read"),
    )
    .expect("json");
    assert_eq!(doc["openapi"], "3.1.0");
    assert_eq!(
        doc["info"]["version"],
        patronus_openapi::workspace_version(&root())
    );
    // every $ref resolves
    fn walk(v: &serde_json::Value, doc: &serde_json::Value, bad: &mut Vec<String>) {
        match v {
            serde_json::Value::Object(m) => {
                if let Some(r) = m.get("$ref").and_then(|r| r.as_str()) {
                    let ptr = r.trim_start_matches('#');
                    if doc.pointer(ptr).is_none() {
                        bad.push(r.to_string());
                    }
                }
                m.values().for_each(|x| walk(x, doc, bad));
            }
            serde_json::Value::Array(a) => a.iter().for_each(|x| walk(x, doc, bad)),
            _ => {}
        }
    }
    let mut bad = Vec::new();
    walk(&doc, &doc, &mut bad);
    assert!(bad.is_empty(), "dangling $ref: {bad:?}");
    // operationIds are unique and every {param} of a path is declared
    let mut ids = BTreeSet::new();
    for (path, item) in doc["paths"].as_object().unwrap() {
        let tmpl: Vec<&str> = path
            .split('/')
            .filter_map(|s| s.strip_prefix('{').and_then(|s| s.strip_suffix('}')))
            .collect();
        for (m, op) in item.as_object().unwrap() {
            let id = op["operationId"].as_str().expect("operationId");
            assert!(ids.insert(id.to_string()), "duplicate operationId {id}");
            assert!(
                op["responses"]["200"].is_object(),
                "{m} {path}: no 200 response"
            );
            let declared: Vec<&str> = op["parameters"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter(|p| p["in"] == "path")
                        .filter_map(|p| p["name"].as_str())
                        .collect()
                })
                .unwrap_or_default();
            for t in &tmpl {
                assert!(
                    declared.contains(t),
                    "{m} {path}: path parameter {t} not declared"
                );
            }
        }
    }
}

#[test]
fn the_ui_pages_are_checked_against_the_api() {
    let sc = scan::scan(&root()).expect("scan");
    let rows = patronus_openapi::coverage::page_rows(&sc, &root()).expect("pages");
    assert!(rows.len() >= 15, "only {} UI pages found", rows.len());
    let ex = patronus_openapi::coverage::exempt(&root());
    let p = patronus_openapi::coverage::exempt_problems(&rows, &ex);
    assert!(p.is_empty(), "{p:?}");
}

#[test]
fn scanner_reads_nested_chains() {
    // a tiny tree: closures, cfg stubs, `any`, a let-bound method router
    let dir = std::env::temp_dir().join(format!("oa-test-{}", std::process::id()));
    let web = dir.join("crates/patronus-web/src/routes/api");
    std::fs::create_dir_all(&web).unwrap();
    std::fs::create_dir_all(dir.join("crates/patronus-web/templates")).unwrap();
    std::fs::write(
        web.join("thing.rs"),
        r#"
        /// GET /api/thing -- list the things
        async fn list() -> axum::Json<Vec<Thing>> { todo!() }
        async fn put_one(axum::extract::Path(id): axum::extract::Path<u32>, axum::Json(t): axum::Json<Thing>) {}
        /// One thing.
        #[derive(serde::Serialize, serde::Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Thing { display_name: String, size: Option<u32>, #[serde(default)] tags: Vec<String> }
        pub fn router() -> axum::Router {
            let h = get(list).post(|| async {});
            axum::Router::new().route("/thing", h).route("/thing/:id", put(put_one).delete(put_one))
        }
        #[cfg(test)] mod t { fn x() { axum::Router::new().route("/never", get(list)); } }
        "#,
    )
    .unwrap();
    std::fs::write(
        dir.join("Cargo.toml"),
        "[workspace.package]\nversion = \"9.9.9\"\n",
    )
    .unwrap();
    let sc = scan::scan(&dir).expect("scan");
    assert!(sc.unparsed.is_empty(), "{:?}", sc.unparsed);
    let b = spec::build(&sc, "9.9.9").expect("build");
    let ops: BTreeSet<String> = b.ops.iter().map(|(m, p)| format!("{m} {p}")).collect();
    assert_eq!(
        ops,
        [
            "get /api/thing",
            "post /api/thing",
            "put /api/thing/{id}",
            "delete /api/thing/{id}"
        ]
        .iter()
        .map(|s| s.to_string())
        .collect()
    );
    let get = &b.spec["paths"]["/api/thing"]["get"];
    assert_eq!(get["summary"], "List the things");
    let schema = &b.spec["components"]["schemas"]["Thing"];
    assert_eq!(schema["properties"]["displayName"]["type"], "string");
    assert_eq!(schema["required"], serde_json::json!(["displayName"]));
    let put = &b.spec["paths"]["/api/thing/{id}"]["put"];
    assert_eq!(put["parameters"][0]["name"], "id");
    assert_eq!(put["parameters"][0]["schema"]["type"], "integer");
    assert!(put["requestBody"]["content"]["application/json"]["schema"]["$ref"].is_string());
    let _ = std::fs::remove_dir_all(&dir);
}
