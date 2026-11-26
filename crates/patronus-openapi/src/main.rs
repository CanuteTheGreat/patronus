//! `cargo run -p patronus-openapi` rewrites the OpenAPI document and the coverage table;
//! `--check` only compares (exit 1 when a file is out of date).

use std::path::PathBuf;
use std::process::ExitCode;

fn main() -> ExitCode {
    let mut root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut check = false;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--check" => check = true,
            "--root" => root = PathBuf::from(args.next().unwrap_or_default()),
            other => {
                eprintln!("usage: patronus-openapi [--check] [--root DIR] (got {other})");
                return ExitCode::from(2);
            }
        }
    }
    let out = match patronus_openapi::generate(&root) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("patronus-openapi: {e}");
            return ExitCode::FAILURE;
        }
    };
    let mut bad = false;
    for p in &out.problems {
        eprintln!("problem: {p}");
        bad = true;
    }
    for (rel, content) in &out.files {
        let path = root.join(rel);
        if check {
            if std::fs::read_to_string(&path).ok().as_deref() != Some(content.as_str()) {
                eprintln!(
                    "out of date: {} (run `cargo run -p patronus-openapi`)",
                    rel.display()
                );
                bad = true;
            }
        } else {
            if let Some(d) = path.parent() {
                let _ = std::fs::create_dir_all(d);
            }
            if let Err(e) = std::fs::write(&path, content) {
                eprintln!("{}: {e}", path.display());
                return ExitCode::FAILURE;
            }
            println!("wrote {}", rel.display());
        }
    }
    if bad {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}
