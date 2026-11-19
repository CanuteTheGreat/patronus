# Automatic Wi-Fi channel choice (standard tier, USE=wifi-ap)

A Wi-Fi network (`seg_wifi_networks`, one hostapd per network) has a channel of `auto` by default. Patronus
looks at the neighbours when the radio starts, picks the quietest channel, re-checks every night and moves the radio
only when another channel is clearly and repeatedly better. A fixed channel (`channel = N`) keeps working exactly as
before: it is never measured and never moved. Networks that existed before this feature keep their fixed channel.

The router tier (GL-AX1800 and other OpenWrt-based images) has the same feature in shell
(`ap-chan`, embedded-routers.md 12.19); this is the same rule set in Rust (`patronus-network/src/wifichan.rs`).

## Why not hostapd's own ACS

ACS measures once, at start, and only busy time. A running radio's survey of its own channel adds up for hours and
includes the radio's own traffic, while every other channel is only seen in short scans, so comparing survey numbers
across channels favours leaving a channel that was merely busy with our own clients. Here every candidate gets the
same kind of sample.

## What is measured and how it is scored

Per sample, every candidate channel (and, on 2.4 GHz, every channel of the band, because neighbours between the
candidates matter) is scanned `rounds` times for `dwell` ms. A radio that has not started yet scans normally; a running
radio scans with `ap-force` (the driver leaves its channel for one dwell at a time), or through a temporary managed
interface of the same phy when the driver has no AP scans. The channel in use is measured over the same window from
its survey counters with this radio's own airtime (station byte counters over their bit rates) subtracted. An access
point whose last beacon is older than the measurement has left and is ignored (the kernel keeps a BSS for about 30 s).

Score, lower is better, in airtime percent:

- the block's busy percent (the primary channel counted twice, the other 20 MHz channels of a 40/80 MHz block once)
- plus `bss_cost` points for every other access point heard on the block (at most 10 counted; weaker than `min_signal`
  ignored; this machine's own radios never count)
- plus, on 2.4 GHz, up to 10 points per neighbour 1-4 channels away, by overlap and by how far above the -82 dBm
  clear-channel threshold it is heard (a strong neighbour on channel 3 hurts 1 and 6, not 11).

Equal best scores keep the channel in use. Channels the regulatory domain disables (`iw phy info`: disabled / no IR)
are not candidates, and at 40/80 MHz neither is a block that contains one.

## When it runs

- **Radio start** (boot, a crashed hostapd, the first apply of the network, a changed candidate list or width): the
  applier measures an idle radio, writes the choice into the store (`seg_wifi_chan_state`) with the reason and every
  candidate's numbers, and renders `channel=<N>` into hostapd.conf. A running radio is never measured by a plain apply:
  SSID, credential and other changes keep the recorded channel, so they never move or restart the radio because of
  the channel. If the measurement fails the previous channel (else the first candidate) is used, with a warning and a
  history note; the nightly check measures again.
- **Nightly** (`recheck_time`, default 03:30 local, empty = never; once a day, within the hour after that time) and on
  request (**Re-check now** in the UI, `POST /api/segmentation/wifi/networks/<id>/recheck-channel`): the per-network
  service `patronus wifi-chan run <network>` (OpenRC `patronus-wifi-chan.<network>`, systemd
  `patronus-wifi-chan@<network>.service`, started and stopped by `patronus apply` with the network) takes `confirm`
  samples `confirm_gap` seconds apart. Every sample must name the same better channel, at least `hysteresis` percent and
  `min_gain` points below the channel in use. Then the radio moves.
- **How it moves**: `hostapd_cli chan_switch` (channel switch announcement, `csa_count` beacons): hostapd keeps
  running and stations follow without disconnecting. hostapd's own files are rewritten to the new channel without a
  restart, so the next apply finds nothing to do. A driver without `channel_switch` (`iw phy info`), or `csa = off`,
  restarts the radio onto the new channel instead (all stations reconnect for a few seconds); the UI says which of the
  two applies per radio.

Every start pick, sample, stay and move is a history entry (`seg_wifi_chan_history`, newest `history` kept) with the
channel, busy percent, neighbours, score and the reason in words. Both tables are measured state, not configuration:
export, revisions and rollback neither carry nor rewind them.

## Settings

All typed columns of `seg_wifi_networks` (migration `1360_s_wifi_autochan.sql`), validated in
`patronus-config/src/seg_wifi_chan.rs`, in the API (`channel` is a number or `"auto"`, the rest flat beside it), the
Wi-Fi tab (Segmentation > Wi-Fi: **Channel settings**) and the exported document (`patronus config export`; the tuning
is part of the `seg_wifi_networks` rows). Defaults are documented in code and equal the migration's column defaults (a
test compares them).

| key | default | range | meaning |
|---|---|---|---|
| `channel` | auto | `auto` or a channel of the band | 0 in the store = auto |
| `chanlist` | empty | list of channels of the band | candidates; empty = 2.4 GHz 1,6,11; 5 GHz the non-radar channels (40 MHz: 36,44,149,157; 80 MHz: 36,149). Radar channels only when listed (hostapd then waits out the channel availability check) |
| `width` | 20 | 20, 40, 80 (5 GHz only) | HT40+/- and VHT80 lines are written for 40/80; plain 20 MHz renders exactly as before |
| `recheck` | on | on/off | nightly re-check |
| `recheck_time` | 03:30 | `HH:MM` or empty | local time |
| `hysteresis` | 20 | 0..90 % | a move needs the score this many percent lower |
| `min_gain` | 10 | 0..100 | ... and this many points lower |
| `confirm` | 3 | 1..10 | samples that must agree |
| `confirm_gap` | 300 | 0..3600 s | between those samples |
| `csa` | auto | auto, off | off = always move by restart |
| `csa_count` | 10 | 1..50 | beacons the switch is announced for |
| `rounds` | 3 | 1..20 | scans of each channel per sample |
| `dwell` | 105 | 20..500 ms | per scan |
| `bss_cost` | 2 | 0..20 | points per neighbouring access point |
| `min_signal` | -90 | -100..-30 dBm | weaker neighbours are ignored |
| `history` | 200 | 10..5000 | entries kept |

Changing any of the tuning keys is live: it restarts nothing. A running radio is measured again only when its recorded
channel is no longer a candidate (a new `chanlist`) or the `width` changed; switching `channel` between auto and a number
takes effect at once (a restart only if the channel differs).

## API

`GET /api/segmentation/wifi`: each network's `channel` (`"auto"` or the number) and settings; `status.networks[].channel`
(`auto`, live `channel`, `width`, `reason`, `candidates` with score / busy / neighbours, `csa_capable`, how it moves,
`last_check`, `recheck_time`); `channels.<network id>` = `{state, history}`. `PUT /api/segmentation/wifi/networks/<id>`
takes the settings (absent keys keep their values; an update with no `channel` keeps the old one).
CLI: `patronus wifi-chan status` (channel + reason + history per network), `patronus wifi-chan recheck <network>` (one
re-check now), `patronus wifi-chan run <network>` (the service). `PATRONUS_WIFI_CHAN_POLL` (seconds, default 15) is how
often the service looks for a due or requested re-check.

## Not covered

- Units of one network on separate boxes do not coordinate (the router tier does, embedded-routers.md 12.17/12.19):
  another Patronus box nearby is simply a neighbour and costs its points. Radios of the same box are measured one
  after the other (the applier loop), and their own BSSIDs never count.
- Real-radio behaviour (how much airtime a driver reports, whether `scan ap-force` works) is only proven on the
  simulated radios of mac80211_hwsim; drivers vary. The fallbacks (temporary scan interface, scan without dwell,
  restart instead of CSA) are there for that.

## Proof

- `crates/patronus-network/src/wifichan.rs` tests: parsing, scoring on both bands (own radios, weak neighbours, 2.4 GHz
  overlap, 5 GHz block neighbours, own airtime subtracted, ties keep the channel in use), hysteresis, the nightly
  window, switch arguments and hostapd lines per width, vanished access points.
- `crates/patronus-network/src/wireless.rs` tests with a fake radio: measured at start, kept while running, CSA move
  without a restart and with hostapd's files following, hysteresis, restart fallback (no driver support / `csa = off`),
  failed measurement fallback, fixed channels untouched, switching between fixed and automatic.
- `crates/patronus-config` tests: defaults equal the migration, input forms of `channel`, validation, an old row
  keeps its fixed channel, state/history retention, export leaves measured tables out.
- `ci/netlab/lane-s-wifi-chan-hwsim.sh` (run by `ci/netlab/wifi-hwsim.sh`, the `wifi-hwsim` job of nightly-test-depth):
  real hostapd on simulated radios with neighbour access points on other channels; the start pick avoids them, the API
  shows why, a repeated apply does nothing, tuning is live, "re-check now" moves by CSA with hostapd's pid unchanged
  and a connected station following without a disconnect, hysteresis keeps the radio, `csa = off` moves by restart,
  and a reboot measures again. Claim C84 in `docs/claims-ledger.txt`.
