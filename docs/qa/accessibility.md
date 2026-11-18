# Accessibility gate

Every CI run drives the web UI's ten most used pages in a real browser and runs axe-core on each one. A violation of
impact serious or critical fails the job.

- Pages: sign-in, dashboard, interfaces, firewall rules, NAT (port forwards tab), DHCP, DNS, VPN, Wi-Fi, system
  (users and groups). Each is checked at 1280 px and 390 px wide, in light and in dark.
- Inputs: `ci/a11y/a11y-config.json` (page list, widths, colour schemes, axe tags, impact threshold) and
  `ci/a11y/axe-allowlist.json` (justified false positives; empty today; an entry needs a rule, a page and a reason, and
  an entry that matches nothing fails the gate).
- axe-core is vendored in `ci/a11y/vendor/` with its licence; the config pins its SHA-256, so nothing is fetched at test
  time. To update it, replace the file, then update `axe_version` and `axe_sha256`.
- Run it: `ci/a11y/run-e2e.sh <image>` (same harness as the sign-in browser check), or with `WEB_BIN=<patronus-web
  binary>` to run a locally built binary. `--browsers firefox,chromium` and `--pages id,id` narrow or widen the run;
  the report with every failing node is written to `$A11Y_REPORT` (default `/tmp/a11y-report.json`).
- Findings below the threshold (moderate, minor) are printed as warnings; the pages are clean of those today too.

Adding a page: append it to `pages` in the config (`wait_for` is a selector that proves the page rendered, `click`
opens a tab first).
