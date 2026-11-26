# Importing a pfSense / OPNsense configuration

```
patronus import pfsense config.xml [--plan] [--map OLDDEV=NEWDEV]... [--yes]
```

Reads a `config.xml` exported from pfSense CE or OPNsense (the alias `patronus import opnsense`
works too; the root element tells the two apart). Without `--yes` (or with `--plan`) it only
prints the plan and writes nothing. With `--yes` it writes the config store; then review with
`patronus apply --dry-run` and run `patronus apply`.

## From the web UI

System > Import (`/import`, also linked from the first-run setup wizard) does the same without a shell: pick
pfSense/OPNsense (`config.xml`) or OpenWrt (the `sysupgrade -b` / LuCI "Generate archive" `.tar.gz`), choose the
file, optionally give port names as `OLD=NEW` pairs, press Preview (the plan, nothing written), then Import and
apply (admins). The import keeps the current configuration as a revision first and applies the result to the whole
system at once; if writing or applying any part fails, the previous configuration is put back and re-applied and
the page says which part refused it. API: `POST /api/system/import/{pfsense|openwrt}/plan` and `.../apply`, the
file as the request body, `?maps=em0=eth0,em1=eth1`. The CLI and the page share one importer (crate
`patronus-import`); the web feature `import` follows USE=uci-import.

An imported file usually carries the old box's LAN address. When it differs from the address your browser uses,
the router moves to it while applying and the answer to Import is lost: after 30 s without an answer (or when the
connection drops) the page says so and names the new address from the preview (`open https://NEW/`), plus
System > Configuration history for the revision kept before the import. Proof: netlab `lane-n-import-ui.sh`
(Firefox on the LAN client: preview, import + kernel/nftables state, then an import that moves the LAN address),
`ci/a11y` page `import`.

Secrets (PPPoE and WireGuard keys, IPsec pre-shared keys) are written to the store but never
printed: the report shows `(set)`.

## --map

pfSense names devices after the driver (`em0`, `igb1`, `vtnet0`). Give the names on this box:
`--map em0=eth0 --map em1=eth1`. VLAN devices follow their parent (`em1.20` becomes `eth1.20`).
A port you do not map follows its role: the old box's `wan`, `lan` and `optN` ports go to the ports that have the
same role on this box (Interfaces, console menu 1 or `patronus interfaces assign`); the plan starts with a
`port matched by role: em0 -> eth0` line for each. A port with no matching role here keeps its old name and the
plan says so. The console menu's import item (20) relies on this, so assign WAN / LAN / OPT first.

## Imported

- System: host name, time zone, NTP servers.
- Interfaces (`wan`, `lan`, `optN`): device, role, enabled, MTU, IPv4 static/DHCP/PPPoE, IPv6
  static/DHCPv6/SLAAC; `track6` becomes DHCPv6 prefix delegation from the WAN to that interface.
- VLANs and PPPoE links (the PPPoE password is decoded and stored).
- Gateways, gateway groups, static routes (to a gateway with a fixed address).
- Aliases: host, network and port aliases (pfSense `<aliases>` and OPNsense Firewall > Alias).
  Rules refer to them as `$name`.
- Firewall rules: pass/block/reject, protocol, source/destination (address, network, alias, an
  interface name meaning that interface's subnet), ports, disabled, log, IPv4/IPv6.
- Port forwards, 1:1 NAT of single addresses.
- DHCP servers (range, lease time, domain, DNS) and static mappings.
- DNS host overrides and domain overrides (pfSense Unbound, OPNsense Unbound plus).
- WireGuard tunnels and peers (pfSense package, OPNsense plugin).
- IPsec IKEv2 pre-shared-key site-to-site tunnels (Patronus default proposals are used).

## Covered by default

The automatic anti-lockout rule, the default LAN allow rule, the allow rules pfSense generates for
port forwards, and automatic/hybrid outbound NAT.

## Listed for manual work

Everything else appears under `unmapped` in plain words, never silently dropped: rules with
"not" or floating rules, URL/GeoIP aliases, OpenVPN servers and clients, IKEv1 or certificate
IPsec, mobile IPsec, outbound NAT rules, virtual IPs, certificates, users, shapers, captive
portal, bridges/LAGG, DHCPv6 server, and installed packages.
