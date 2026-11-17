# Config generations

Patronus keeps its configuration the way NixOS keeps a system: every change that is applied is a numbered
**generation**. You can see what differs between any two, go back to one, apply a risky change on trial so that
the router puts the old configuration back by itself if you lose access, and move the whole configuration around
as one readable file.

It is built on the configuration history that was already there (`config_revisions`, `patronus config rollback`,
`/api/system/history`), not next to it. Existing revisions were copied in with their ids, so "rollback 17" still
means the same state.

## Generations

A generation is a full copy of the configuration document (`ConfigStore::export_json`, every lane's tables, never
the measured-history tables in `NON_CONFIG_TABLES`) with

- a number: monotonic, **never reused** (SQLite AUTOINCREMENT), also not after pruning;
- the time, the **actor** (the web user, `cli`, `gitops`, `commit-confirm`, `system`) and a **kind**
  (`change`, `baseline`, `migrated`, `rollback`, `import`, `revert`);
- the **commit message**: the manager's own ("create firewall rule x"), or the one you typed (the
  `X-Commit-Message` header, the import form's message field);
- the content hash (SHA-256 of the canonical document, independent of row order).

Markers: **live** is the newest generation, **boot** is the one the next boot loads (it differs from live only while
a commit-confirmed change waits for its confirmation), **pinned** ones are never pruned. Retention keeps the newest 200
plus the live, boot-default and pinned generations and the two a pending commit-confirm refers to.

How a change becomes a generation: managers call `ConfigStore::snapshot()` before they write, as they always did.
That seals the change set that was open before (the configuration as it is becomes a generation carrying that change
set's actor and message), makes sure the current state is itself a generation (the one to roll back to; a `baseline`
when something wrote the store outside a change set) and opens the next change set. Reading the list seals too, so
the newest generation is always the live configuration. A change that ended identical to the newest generation
records nothing, so a change a manager undid after a failed apply leaves no generation.

Rollback = restore the document, apply it, and that is **a new generation** (`rollback to generation N`), so it can be
rolled back too. Anti-lockout system rules are re-added whatever the document says
(`defaults::ensure_system_rules`).

### CLI

    patronus config generations [--json]       time, actor, kind, markers, message
    patronus config show ID [--json] [--include-secrets]
    patronus config diff [FROM] [TO]           ids or `live`; one argument = vs live; none = live vs the one before
    patronus config rollback ID [--confirm-in N]
    patronus config pin ID [--unpin]
    patronus config revisions                  the old name of `generations`

### API (admins change, everyone signed in reads)

    GET  /api/system/generations                list + pending + watchdog + unrecorded_changes
    GET  /api/system/generations/:id            metadata + the declarative file (no secrets)
    GET  /api/system/generations/diff?from=&to= structured diff + unified text (ids or `live`)
    POST /api/system/generations/:id/rollback
    POST /api/system/generations/:id/pin        {"pinned": true}
    GET  /api/system/history                    the old list, same data

### Diff

`diff_docs` compares two documents per table, per row (keyed by the table's primary key) and per field, and
`unified_diff` compares their declarative files as text. **Secrets are never shown**: VPN private keys and PSKs,
password and token hashes, TOTP secrets and recovery codes, enrolment secrets, and the value of a key/value setting
whose key names a secret (`smtp.password`). A changed secret reads `(changed)`; an added or removed row shows
`(secret)` in its place. Detection is by column name (`gendiff::looks_secret`).

## Commit-confirmed changes

Apply a change **on trial**: `X-Confirm-In: N` (minutes, 1 to 120) on any changing API call, or `--confirm-in N` on
`patronus config rollback|import`. The web UI has an **Auto-revert in N min** switch in the top bar: while it is on,
every change from every page (firewall, interfaces, routes, VPN, import, rollback, ...) is sent with the header.

What is stored (in the store, so a web restart or a reboot keeps it): the previous generation, the applied
generation, the deadline. The boot default stays the previous generation while pending. Further changes made while
pending are covered by the same deadline; confirming keeps all of them.

**Who reverts.** Not the web process and not your session: `patronus applyd`, the root daemon, runs a timer that
looks at the pending state every second and, at the deadline, puts the previous generation's configuration back in
the store (clearing the pending state first, so a boot loads the safe state), applies every applier under the same
lock as any other apply, and records a `revert` generation (actor `commit-confirm`). It is a plain async task in the
daemon, not a systemd timer, so it behaves the same under OpenRC and systemd (both ship `patronus-applyd`).

- The option is **refused up front, changing nothing**, when no applyd timer is running (`409` from the API,
  an error from the CLI). A timer that cannot fire is worse than none.
- **Reboot while pending.** `patronus apply` at boot: deadline passed -> the previous generation is restored into the
  store before the appliers run (the box boots the safe configuration); otherwise the change on trial is enforced
  again and applyd's timer resumes the countdown.
- **Confirm** works from any admin session on any network path: `POST /api/system/generations/pending/confirm`,
  `patronus config confirm`, or the banner. **Revert now**: `.../pending/revert-now`, `patronus config revert-now`.
  The confirm and revert endpoints are never themselves wrapped in a new trial.
- Anti-lockout rules always hold (the store refuses to delete them and import re-adds them), so the LAN client can
  always reach SSH and the web UI to confirm or revert.
- The banner (every page) shows a live countdown with **Confirm** and **Revert now**.

## The declarative file

    patronus config export --declarative [--include-secrets] [-o FILE]     GET /api/system/config/export?format=yaml
    patronus config import FILE [--dry-run] [--confirm-in N] [--no-apply]  POST /api/system/config/import[?dry_run=true]

One YAML document, `patronus_config_version: 1`, tables sorted by name, rows by primary key (key columns first, the
other columns alphabetical), empty tables left out, no timestamps: **export -> import -> export is byte-identical**
and `git diff` shows exactly what changed. It carries the same tables as the JSON backup, so measured history
(traffic insight, uplink samples), the audit log and the generations themselves are never in it.

**Secrets** are left out unless you ask (`--include-secrets`, written 0600; the API download needs an admin). An
import keeps the stored secret of every row it matches by key; a **new** row that needs a secret the file lacks is
refused by the database constraint with the table and column named. The JSON backup (`config export`) still carries
everything and still imports.

An import is validated by loading it into a scratch store, shown as a diff against live (structured and unified
text), applied atomically (reverted if an applier refuses it), and recorded as a generation of kind `import`. The web
upload does the same with a **Validate and show the diff** step before **Apply**.

The GitOps engine (`patronus gitops`) still reads its own per-resource files; it does not consume this file yet.

## The page

**Config generations** (`/generations`, Advanced section of the menu): the list with live / boot / pinned markers,
message, actor and time; tick two to compare, **Diff vs live** per row, **Show** (the declarative file of that
generation), **Roll back**, **Pin**, the export/import card with the diff preview. Honest empty states: with no
generation yet it says the first change creates one; when applyd is not running it says why auto-revert is unavailable.
Below 900 px the table drops two columns and the menu is the usual drawer.

## Proof

- unit: `crates/patronus-config/src/{generations,gendiff,genfile}.rs`
- web API: `crates/patronus-web/src/routes/lane_fh_tests.rs` (generations_*, commit_confirm_*, the_declarative_file_*)
- kernel state and real traffic: `ci/netlab/journey-config-generations.sh` (real 1-minute deadline, Confirm past the
  deadline, web restart while pending, reboot with the deadline passed and not passed, CLI rollback on trial,
  import on trial, anti-lockout)
- real VM, OpenRC and systemd images: `tools/vmtest/scenarios/config_commit_confirm.py`
  (`.forgejo/workflows/vmtest.yml`, job `commit-confirm`; it needs a daily ISO built after this feature landed and
  records a note instead of failing on an older ISO)
- claims C7, C73, C74 in `docs/claims-ledger.txt`
