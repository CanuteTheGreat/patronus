# CI triggers (patronus)

CI work runs **when its inputs change**, not on a clock (owner principle 2026-11-06: "if there is something to do, do it").

- Heavy workflows (nightly-*, live-iso-*, mutation, test-depth, ...) trigger on a push to `main` with `paths:` filters naming what they build or test.
  Docs/README/site-only pushes start none of them.
- Bursts coalesce: they use a `replace:` concurrency group, so the ci-supersede-sweeper keeps every started run and only the NEWEST unstarted one.
  A started run is never cancelled by a push.
- A cron stays only where the thing it checks has no change signal (upstream package trees/base images, external services, elapsed time).
  Each such cron has a comment in its workflow saying why. Priority (not the clock) handles contention: heavy workflows are matched by file name
  in the sweeper's -20 class (ctg-infrastructure `ollivanders/forgejo/ci-supersede-sweeper`).
- File names such as `nightly-*.yml` are kept on purpose (the sweeper's priority rule matches them); they are not nightly any more.

| workflow file | name | triggers |
|---|---|---|
| `build-ci-base.yml` | Build Patronus CI base image | push main (paths: 2 filters); cron 0 6 * * 0 (safety net, see comment in file); dispatch |
| `deploy-site.yml` | Deploy Patronus site | push main (paths: 4 filters); dispatch |
| `live-iso-server-openrc-aarch64.yml` | Live ISO (server-openrc-aarch64) | push main tags (paths: 7 filters); dispatch |
| `live-iso-server-openrc-x86_64.yml` | Live ISO (server-openrc-x86_64) | push main tags (paths: 7 filters); dispatch |
| `live-iso.yml` | Live ISO (moved) | dispatch |
| `nightly-firewall-traffic-test.yml` | Nightly Firewall / SD-WAN Live Traffic Test | push main (paths: 7 filters); dispatch |
| `nightly-realistic-installer-test.yml` | Nightly Realistic Installer Test | push main (paths: 8 filters); dispatch |
| `nightly-test-depth.yml` | Nightly test depth (mutation baseline, deep netlab, upgrade) | push main (paths: 7 filters); dispatch |
| `release.yml` | Release | push  tags (all paths); dispatch |
| `rust-ci.yml` | Rust CI | push main (all paths); pull_request; cron 30 22 * * 1 (safety net, see comment in file); dispatch |
| `windows-check.yml` | windows-check | dispatch |
