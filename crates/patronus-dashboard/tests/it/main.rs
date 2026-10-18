//! All integration tests of this crate, linked into ONE test binary.
//!
//! Each file in this directory used to be its own `tests/<name>.rs` binary,
//! and every one of them statically linked the whole crate plus its
//! dependency tree: dozens of large links per CI run, which is what drove
//! the test job's memory peak. One binary = one link. Run a single former
//! file with `cargo test --test it <module>::` (e.g. a filter on the
//! module name).

mod cache_system;
mod frontend_contract;
mod ha_replication;
mod rest_auth;
mod rest_auth_tokens;
mod token_revocation;
mod traffic_statistics;
mod websocket_events;
