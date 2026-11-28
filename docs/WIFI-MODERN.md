# Wi-Fi 6, 6E and 7 on the standard tier (USE=wifi-ap)

A Wi-Fi network (`seg_wifi_networks`, one hostapd per network) runs the newest 802.11 generation its radio AND the
installed hostapd support, on 2.4, 5 or 6 GHz, at up to 160 MHz (5/6 GHz) or 320 MHz (6 GHz, Wi-Fi 7), and a Wi-Fi 7
network can span several bands as one multi-link access point. Nothing is assumed: the radio is read with `iw phy`
and hostapd's build options are read from its binary, and the UI only offers what both can do.

Code: `patronus-config/src/seg_wifi_gen.rs` (settings, validation), `seg_wifi_chan.rs` (6 GHz channels, 160/320 MHz
blocks, operating classes), `patronus-network/src/radio.rs` (capability probe), `wifigen.rs` (asked for vs. what
runs), `wireless.rs` + `wifichan.rs` (hostapd.conf, channel switch). Migration `1370_s_wifi_modern.sql`.

## Settings (declarative: API, UI, export/import, GitOps)

| key | default | meaning |
|-----|---------|---------|
| `band` | `2g` | `2g`, `5g` or `6g` |
| `width` | `20` | MHz: 20/40 on 2.4 GHz; 20/40/80/160 on 5 GHz; 20/40/80/160/320 on 6 GHz |
| `standard` | `auto` | `auto` (newest supported), `n` (Wi-Fi 4), `ac` (Wi-Fi 5, 5 GHz), `ax` (Wi-Fi 6/6E), `be` (Wi-Fi 7) |
| `bss_color` | `0` | HE BSS colour 1-63; 0 = derived from the network name (stable, differs between our networks) |
| `discovery` | `auto` | 6 GHz discovery frames: `auto`, `probe` (unsolicited broadcast probe responses), `fils`, `off` |
| `discovery_interval` | `20` | time units between discovery frames, 1-20 |
| `mlo_links` | empty | Wi-Fi 7 multi-link: extra links `band/channel/width`, e.g. `6g/37/320` |
| `mlo_wait` | `20` | seconds every link gets to come up before the network falls back to one link |
| `country` | `US` | regulatory domain; set with `iw reg set` before the radio is read |

Existing networks get `standard = auto`: after the upgrade a Wi-Fi 6 radio with a hostapd built with 802.11ax runs
Wi-Fi 6 on the same channel and width.

## Rules

- **auto climbs, explicit never lies.** `auto` runs the newest generation both the radio (`HE Iftypes: AP`,
  `EHT Iftypes: AP` on that band) and hostapd (`CONFIG_IEEE80211AX` / `CONFIG_IEEE80211BE`) support. An explicit
  generation above that runs at the best supported one, with a warning naming the missing piece (the card, or the
  hostapd build option). A width the radio cannot carry at that generation is narrowed to the widest it can, with a
  warning. With no radio information at all (no `iw`), nothing is narrowed and `auto` keeps the Wi-Fi 4/5 behaviour.
- **6 GHz is WPA3-SAE only.** The store refuses `wpa2` and `wpa2_wpa3` on 6 GHz (and for multi-link) with the
  reason; hostapd gets `sae_pwe=1` (hash-to-element only) and `ieee80211w=2`. A new 6 GHz network defaults to WPA3.
- **6 GHz fails closed.** Before a 6 GHz network starts, every 20 MHz channel of its block must be open for an
  access point in the regulatory domain in force (not `disabled`, not `no IR`). Otherwise the network stays off and
  the status says why. wireless-regdb marks US 6 GHz `PASSIVE-SCAN`, so on Linux a 6 GHz access point does not start
  with country US unless the driver manages its own regulatory domain; EU countries (for example DE: LPI,
  5945-6425 MHz) open the lower part of the band.
- **Preferred scanning channels.** The automatic channel on 6 GHz chooses among the PSC channels (5, 21, 37, ...
  229), one per block at the width, because 6 GHz clients look for access points there first.
- **Discovery frames only when the driver sends them.** `auto` uses unsolicited broadcast probe responses when the
  driver advertises `UNSOL_BCAST_PROBE_RESP`, else FILS discovery (`FILS_DISCOVERY`), else none (6 GHz clients then
  find the network on its PSC channel). mac80211_hwsim has neither.
- **Operating class and centre channels.** 6 GHz uses `op_class` 131/132/133/134/137 for 20/40/80/160/320 MHz.
  320 MHz uses the 320-1 channelization (centres 31, 95, 159) and 320-2 (centre 191) for channels 193-221; HE
  describes the 160 MHz half that holds the primary channel. 5 GHz 160 MHz blocks are 36-64 and 100-128 (both
  contain radar channels: hostapd waits out the channel availability check, 60 s, before it transmits).
- **Multi-link (MLO).** `mlo_links` adds links on the other bands of the same radio (one SSID, one AP MLD: one
  hostapd with one configuration per link, `mld_ap=1`). It needs Wi-Fi 7 on every link, WPA3, a hostapd with AP MLD
  support (2.11 or newer with `CONFIG_IEEE80211BE`), a 6 GHz link the regulatory domain opens, and finally a
  driver that supports MLO as an access point, which `iw` does not report. So the applier tries: every link must
  report `state=ENABLED` within `mlo_wait` seconds; if one does not, the network restarts on its first link, the
  warning says "your card or driver does not support it", and it is not tried again until the links change.
- **Per-device credentials.** On 2.4/5 GHz WPA2 per-MAC passphrases stay live (`wpa_psk_file`, no restart). On 6 GHz
  and for multi-link, per-device credentials are WPA3-SAE passwords bound to the device's MAC
  (`sae_password=...|mac=...`); hostapd reads those at start, so adding, rotating or revoking one restarts the access
  point. A device without a known MAC joins through the enrolment secret first (SAE has no wildcard entry that
  reports which password was used; password identifiers would, but most phones do not support them).

## Gentoo packaging

`net-wireless/hostapd-2.11` (stable on amd64/arm64) and `2.12` build `CONFIG_IEEE80211AX` and `CONFIG_IEEE80211BE`.
Wi-Fi 7 and multi-link need that floor: `USE=wifi7` (default on) pulls `>=net-wireless/hostapd-2.11`; without it any
hostapd works and Wi-Fi 7 settings run as Wi-Fi 6 with the warning above. Debian and Ubuntu build hostapd without
`CONFIG_IEEE80211BE` (Ubuntu 25.10's 2.11 included), Debian trixie ships 2.10.

## What is proven, and where

- Unit tests: channel math, validation, capability parsing (real `iw phy` output of mac80211_hwsim in
  `patronus-network/src/testdata/`, plus a Wi-Fi 5 radio derived from it), the plan (auto, explicit, narrowed widths,
  6 GHz fail-closed, discovery, multi-link degradation), the rendered hostapd.conf, and the applier's multi-link
  fallback.
- `ci/netlab/lane-s-wifi-modern-hwsim.sh` (nightly, `wifi-hwsim` job): real associations of a real wpa_supplicant
  with the router's hostapd on mac80211_hwsim (kernel 7.0, `mlo=1`), hostapd/wpa_supplicant 2.12 built with the
  Gentoo ebuild's options: Wi-Fi 6 at 80 and 160 MHz on 5 GHz, Wi-Fi 6E at 160 MHz on 6 GHz with a per-device SAE
  password, the US fail-closed case, Wi-Fi 7 at 320 MHz, a two-link (5 + 6 GHz) multi-link association, and the
  degradation on the distribution's older hostapd.
- **Not proven on real hardware.** No real Wi-Fi 6E or Wi-Fi 7 card has been tested yet. mac80211_hwsim implements
  the 802.11 state machines, not a radio: real drivers differ in which features they expose as an access point (many
  Wi-Fi 7 client cards do not do 6 GHz or MLO in AP mode at all; that is exactly what the capability probe reports).
