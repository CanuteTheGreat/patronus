# seg-spike (throw-away spike for docs/design/device-segmentation.md)

Detached from the workspace (`[workspace]` in Cargo.toml). `cargo test` = 6 unit tests.

- `src/lib.rs`  config -> nftables segmentation table + hostapd `wpa_psk_file` / `hostapd.conf`
- `lab/netns-isolation.sh`  proof (b), network namespaces, run as root in the Patronus lab VM
- `lab/hwsim-run.sh` + `lab/hwsim-inner.sh`  proof (a), mac80211_hwsim radios on an rw-man host (x86_64, kernel with the module), hostapd 2.10 + wpa_supplicant in a throw-away privileged container
- `lab/dns-run.sh` + `lab/dns-views.sh`  proof for (c), unbound views / rebinding / query log
- `evidence/`  the captured outputs of the runs

No code was copied from SPR (BSD-3-Clause, https://github.com/spr-networks/super); the ideas are
re-implemented. If a later change does copy any SPR file, keep its BSD-3 notice next to it.
