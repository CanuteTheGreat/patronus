# Notification matchers

A notification channel (email, ntfy, Telegram, Discord, Slack, signed webhook; System > Events and notifications)
used to filter by a list of event kinds and one minimum severity. It now names a **matcher**: a small tree that decides
which events the channel gets.

## The tree

| node | meaning |
|---|---|
| `all` | every child matches (no child: every event) |
| `any` | at least one child matches (needs a child) |
| `not` | its single child does not match (exactly one child) |
| `kind` | the event kind is one of `kinds` (the kinds the box raises: `GET /api/system/matchers/limits`) |
| `severity` | the event severity is at least `min` (`info`, `warning`, `critical`) |
| `subject` | the event's subject (gateway, tunnel or interface name) matches `glob` (`*` any run, `?` one character, case-sensitive) |
| `calendar` | the box's local time is inside the window: `days` (`mon`..`sun`), `start`, `end` (`HH:MM`); `end` before `start` runs past midnight and belongs to the day it starts on (Friday 22:00-06:00 covers Saturday 03:00); `start` = `end` is the whole day |

JSON (API, export) and YAML (GitOps) use the same shape:

```yaml
- apiVersion: patronus.firewall/v1
  kind: NotifyMatcher
  metadata: { name: night-wan }
  spec:
    description: WAN trouble on weekday nights, never guest links
    tree:
      op: all
      items:
        - { op: kind, kinds: [gateway_down, uplink_sla_breach] }
        - { op: calendar, days: [mon, tue, wed, thu, fri], start: "22:00", end: "06:00" }
        - op: not
          items: [ { op: subject, glob: "guest*" } ]
```

The time zone is the box's (System > General); the window is wall-clock time, so a daylight-saving change moves it with
the clock (the skipped hour never occurs, the repeated hour matches twice). Tests move the clock with
`PATRONUS_FAKE_TIME_FILE` (`YYYY-MM-DD HH:MM`), the same hook as firewall schedules.

## Limits (settings, not constants)

`system_config` keys, defaults in brackets: `notify.matcher_max_depth` (8), `notify.matcher_max_nodes` (64),
`notify.matcher_max_items` (32, per group and per kind list), `notify.matcher_max_glob_len` (64),
`notify.preview_events` (50, how many past events a preview judges). A tree over a limit is refused with HTTP 400.

## Channels

`event_hooks.matcher` names the matcher a channel uses. A channel made through the old API (`kinds`, `min_severity`, no
`matcher`) gets a matcher called `auto-<channel>` built from them, and deleting the channel deletes that matcher;
migration `0795_h_notify_matchers.sql` does the same for every channel that exists when the box is upgraded, so nothing
changes for existing setups (a unit test proves the equivalence for every kind-list x severity combination). A channel
row with no matcher (a configuration exported before this feature) keeps filtering by its own kinds and severity. A
matcher a channel uses cannot be deleted. "Send test" always sends.

## API (admin)

| | |
|---|---|
| `GET /api/system/matchers` | every matcher with the channels using it |
| `GET /api/system/matchers/limits` | limits, event kinds, severities, weekdays (for the editor) |
| `PUT /api/system/matchers/{name}` | `{"description", "tree"}`, created or replaced, validated (400 with the reason) |
| `DELETE /api/system/matchers/{name}` | 400 while a channel uses it |
| `POST /api/system/matchers/preview` | `{"tree"}` (not saved): the last events of the event log, each `matched` or not, judged at the local time it happened |
| `POST /api/system/events/try` | `{"kind", "subject", "severity", "send"}`: which channels would get such an event right now (judged at the box's local time); with `send` true it is delivered to them (nothing is written to the event log) |
| `PUT /api/system/hooks/{id}/matcher` | `{"matcher": "name"}`; `""` = the channel's own kinds and severity |
| `POST /api/system/hooks` | also takes `"matcher"` |

Matchers are rows of `notify_matchers`: they are part of export/import, configuration revisions and the declarative
config (`patronus gitops`, kind `NotifyMatcher`; see GITOPS-RESOURCES.md).

## The editor

System > Events and notifications > Notification matchers. The tree is nested lists; every row has Move up / Move down /
Indent (into the group above) / Outdent / Remove buttons. With a row focused, `Alt`+arrows do the same and `Delete`
removes it; dragging a row onto another row's top or bottom edge moves it before/after, onto the middle of a group
moves it inside. A refused move (a second item in a "not", a group inside itself, too deep) is announced in the status
line and changes nothing. A calendar leaf has seven weekday toggle buttons (`aria-pressed`) and two time pickers. "Try an event" names the channels an event of your choice would reach right now, and can send it. Preview
shows "N of M recent events would be sent" and a Yes/No column (text, not only colour). The page follows the device's
light/dark setting and works at phone width.

## Proof

`ci/netlab/lane-h-notify-matchers.sh` (real binaries, local webhook receiver, fake clock: inside the window, outside it,
past midnight, a non-window weekday; nested any/all/not; a migrated legacy channel still delivers),
`ci/netlab/lane-h-notify-matchers-ui.sh` (`ci/notify-matchers-page-e2e.py`, Firefox, 1280 and 390 px, light and dark),
unit tests in `patronus-config` (`notify_matcher`: nesting, not, calendar edges, midnight, DST, limits, migration
equivalence) and `patronus-web` (`state::telemetry`), and the router-image gates (`ci/embedded-aarch64/ax1800/qemu-gate.sh`,
`ci/embedded-mips/slate/qemu-gate.py`: a matcher is saved on the image and an event reaches a webhook on the emulator's
host). README claim C187.
