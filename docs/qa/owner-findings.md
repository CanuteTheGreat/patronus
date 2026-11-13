# Owner-found issues and the checks that cover their class

Rule (owner, 2026-11-04): every project gets automatic QA that finds things so the owner does not have to. When the owner
finds a bug by hand, add a check for that CLASS of bug, then add a row here. `ci/ux-qa/check_owner_findings.py` (run in CI)
fails when a row names no check or a check file that does not exist. Horcrux's table (`docs/qa/owner-findings.md` in the horcrux repo)
is the master list for the shared live-installer; rows below are the classes that apply to Patronus.

| # | date | finding (as the owner saw it) | class | check(s) |
|---|------|-------------------------------|-------|----------|
| 1 | 2026-11-12 | (Horcrux) VNC console button overlay covered the guest screen | an element overlays a canvas/iframe/video | `ci/ux-qa/ux_crawl.py` (canvas-overlay on every page; Patronus has no VM console today) |
| 2 | 2026-11-12 | (Horcrux) dashboard cards/stats not clickable | summary/stat card that is not a link | `ci/ux-qa/ux_crawl.py` (unlinked-summary, fails on `/`) |
| 3 | 2026-11-12 | (Horcrux) installed /etc/os-release said live/installer, hostname as VARIANT, internal build name, private Forgejo HOME_URL. Patronus's vendored installer was behind the master and still shipped it | os-release sanity on installed systems | `ci/ux-qa/test_patronus_os_release.py`, `ci/ux-qa/check_os_release.py`, `gentoo/live-iso/sync-common.sh` (`--check` in CI) |
| 4 | 2026-11-12 | (Horcrux) private Forgejo URL in a public artifact | private URL/host in any public artifact | `ci/ux-qa/check_public_text.py` (docs + the UX lane scans the built UI and the ISO rootfs) |
| 5 | 2026-11-12 | (Horcrux) blank web UI after a hand-deployed build | UI does not load / uncaught JS error in real Firefox | `ci/ux-qa/ux_crawl.py` (js-error, blank), `frontend/scripts/phone-layout-gate.py` |
| 7 | 2026-11-12 | (Horcrux) Docker's FORWARD DROP killed VM NAT | NAT/forwarding with Docker present | `gentoo/live-iso/common/headless_gates.py` (vendored; gate docker-does-not-break-vm-nat-forwarding) |
