Scenarios here are NOT run by CI (run.sh and the workflow only glob `ci/netlab/lane-*.sh`).

- `lane-n-upnp.sh`: miniupnpd starts, discovery works and the firewall rules are
  correct, but AddPortMapping answers 501 with Debian's miniupnpd-nftables 2.3.1 in the
  lab (the nftables backend's tables/chains are not set up by the daemon alone).
  Move it back to `ci/netlab/` once the mapping step passes.
- `lane-n-dhcp6pd.sh`: the WAN gets dhcpcd with `ia_pd`, but no delegated prefix
  appeared on the LAN port in the lab within 90 s (needs the ISC dhcpd prefix6 + radvd
  ISP side debugged). Move it back once it passes.
