//! All integration tests of this crate, linked into ONE test binary.
//!
//! Each file in this directory used to be its own `tests/<name>.rs` binary,
//! and every one of them statically linked the whole crate plus its
//! dependency tree: dozens of large links per CI run, which is what drove
//! the test job's memory peak. One binary = one link. Run a single former
//! file with `cargo test --test it <module>::` (e.g. a filter on the
//! module name).

mod health_check_test;
mod policy_lifecycle_test;
mod site_lifecycle_test;
