# Default text editor

The system default editor (`EDITOR` / `VISUAL` of every login shell, `git commit`, `crontab -e`, `visudo`, `sudoedit`) is one declarative
setting, `system.editor`, with four equivalent ways to set it:

| Where | How |
|---|---|
| `patronus.toml` | `[system]` `editor = "vim"`. Read once, on the first boot of a new install; an upgraded store is never touched |
| System page | *Default text editor* card (admins) |
| API | `GET` / `PUT /api/system/editor`, body `{"editor": "neovim"}` |
| GitOps | `kind: DefaultEditor`, `metadata.name: default-editor`, `spec: {editor: neovim}` (see GITOPS-RESOURCES.md) |

Values: `vim` (the default), `neovim`, `nano`, `vi` or an absolute path (letters, digits and `/ _ - . + ` only, no `..`). Anything else is
refused with `Invalid editor ...` (API: 400, GitOps: the sync reports it) and nothing changes. A named editor or path whose binary is not
installed is refused too, with the package to install (`emerge app-editors/neovim`) and the change is rolled back.

The store is one row (`system_editor`, migration `0790_h_default_editor.sql`). With no row Patronus never touches the editor: a hand-edited
`/etc/default-editor.conf` survives. The applier (`patronus-network/src/editor.rs`, run at every boot and after every change) runs
`default-editor set <choice>` (the tool shipped on the image: writes `/etc/default-editor.conf` and `/etc/env.d/99editor`, runs `env-update`;
the same on OpenRC and systemd).

## neovim is optional

`app-editors/neovim` is not in the base set. It comes with `USE=neovim` of `net-firewall/patronus` (both the source ebuild and the image
ebuild), or `emerge app-editors/neovim` by hand; `default-editor set neovim` needs its `/usr/bin/nvim`. vim stays the default and is always
installed.

## Embedded (router) tier

vim and neovim do not fit the flash budget, and there is no `default-editor` tool (busybox only). The setting accepts only `vi` (busybox,
the tier's default) or the absolute path of an editor the owner installed; the applier writes `/etc/default-editor.conf`, which
`/etc/profile.d/10-editor.sh` reads at login. `vim`, `neovim` and `nano` are refused with the reason, and the System page lists them with
the reason instead of hiding them. The tier is read from `PATRONUS_TIER=embedded` in `/etc/patronus-release`.

Proofs: claim C1790 (`docs/claims-ledger.txt`), `ci/netlab/lane-n-default-editor.sh`, and the unit tests in both `editor.rs` files.
