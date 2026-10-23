Scenarios here are NOT run by CI (run.sh and the workflow only glob `ci/netlab/lane-*.sh`).

- `lane-n-upnp.sh`: miniupnpd starts, discovery works and the firewall rules are
  correct, but AddPortMapping answers 501 with Debian's miniupnpd-nftables 2.3.1 in the
  lab (the nftables backend's tables/chains are not set up by the daemon alone).
  Move it back to `ci/netlab/` once the mapping step passes.
- `lane-n-dhcp6pd.sh`: the WAN gets dhcpcd with `ia_pd`, but no delegated prefix
  appeared on the LAN port in the lab within 90 s (needs the ISC dhcpd prefix6 + radvd
  ISP side debugged). Move it back once it passes.
- `lane-n-vrf.sh`: the lab host here has no vrf.ko (the scenario skips), but CI's runners
  do: in CI run 6062 it passed the "bad plans refused" step and then exited silently
  (exit 56 from the runner) at the first kernel check after adding the member. Needs a
  run on a VRF-capable host to debug (likely the member enslave/route assertions).
