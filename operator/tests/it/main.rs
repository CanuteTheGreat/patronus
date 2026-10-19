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

use kube::{api::Api, Resource, ResourceExt};
use serde::de::DeserializeOwned;
use std::{fmt::Debug, time::Duration};

/// Lists `api` until every name in `want` is in the result, or 10 s pass,
/// and returns the last list's items either way (the caller's assertion then
/// reports what was really there).
///
/// A LIST sent right after a successful create can come back without the
/// new object on the CI k3s: run 456 (`test_multiple_sites`) and run 467
/// (`test_policy_priority`, `[50, 100]` instead of `[50, 100, 200]`) both
/// failed that way, although the operator log shows it already reconciling
/// the "missing" object. A single immediate list is therefore not a valid
/// way to check that creates happened.
pub(crate) async fn list_until_present<K>(api: &Api<K>, want: &[String]) -> Vec<K>
where
    K: Resource + Clone + DeserializeOwned + Debug,
{
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        let items = api
            .list(&Default::default())
            .await
            .expect("Failed to list objects")
            .items;
        let names: Vec<String> = items.iter().map(|o| o.name_any()).collect();
        if want.iter().all(|w| names.contains(w)) || tokio::time::Instant::now() >= deadline {
            return items;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}
