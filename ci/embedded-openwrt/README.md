# ci/embedded-openwrt: the embedded tier's kernel tracks its LTS line

The GL-AX1800 / GL-AR750S images boot **OpenWrt's kernel byte for byte** (no Patronus kernel patches: the Wi-Fi/board fixes
are userland and rebuilt modules). OpenWrt's release branch lags kernel.org's LTS point releases, so the kernel (and the kmods
that must match its vermagic) is rebuilt from the pinned OpenWrt tag with **only the kernel version and tarball hash changed**.

| file | role |
|---|---|
| `kernel.pin` | `OWRT_TAG`, `KERNEL_LINE` (the LTS line; configuration, not code), `KERNEL_PATCH`, `KERNEL_SHA256` |
| `kernel-track.sh` | `--print` / `--check` (red when the pin lags kernel.org by more than `MAX_LAG_DAYS`, default 3) / `--bump` (rewrites the two pin lines) |
| `build-owrt.sh <ax1800\|virt\|slate> <out>` | builds OpenWrt from the tag with the pinned kernel in a throwaway debian:trixie container on an x86_64 host; output: images, kmod apks, SDK |
| `kmods-*.list` | the kmod packages each target's image needs (the `kmods.pin` closure) |
| `patches/<line>.<patch>/` | OpenWrt patches refreshed for exactly that kernel (stable moved a context the tag did not know) |
| `tests/run.sh` | host tests of the tracker (CI, no network) |
| `tests/prep-check.sh` | container test: prepares the pinned tree per target (`PREP_ONLY=1`) and proves every kernel patch applies (`patch-survey.sh`), minutes instead of a 1-2 h build; run it first when a bump fails |

Chain (automatic, the project agent host's cron `kernel-track`, daily): `--bump` shows a newer patch -> a queued job builds the three targets,
uploads the artefacts as Forgejo generic packages, moves the pins (`stock.pin`, `kmods.pin`, `wifi-kmods/sdk.pin`,
`wifi-kmods/wifi-kmods.pin`), runs the gates, ff-merges, builds the per-unit AP images and queues a **house-AP window flash**
(`~/.hermes/state/home-routers/flash-queue/`, started by cron `ap-window-flash-gate` at 00:55 America/Los_Angeles; flashes only
01:00-05:00, .10 first). The CI workflow `kernel-track.yml` is the alarm if that chain stalls (red = the pin lags > 3 days).

## When a patch no longer applies
`build-owrt.sh` stops in `toolchain/kernel-headers` with `Patch failed! Please fix .../backport-6.12/NNN-...patch`. Take the failing
hunk's reject (`<build_dir>/linux-<ver>/**/*.rej`), adapt the patch to the new context (keep the upstream change, never drop
the patch), save it as `patches/<line>.<patch>/<same name>`; the next build overlays it. 6.12.118 needed `623-v6.18-pppoe-remove-rwlock-usage.patch`
(stable changed `__delete_item()`/`delete_item()` to take the socket).

## Not covered
The Slate (GL-AR750S) keeps OpenWrt's kernel in NOR; moving it needs a flash whose rollback is proven (docs/embedded-routers.md,
"Kernel tracking"). Its image is built (`slate`) but not flashed by the window job.
