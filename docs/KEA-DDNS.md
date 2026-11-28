# Kea DDNS: DHCP clients in DNS (USE=kea-ddns)

Every DHCP client gets a DNS name (A / AAAA) and a reverse name (PTR) when it
gets a lease, and loses them when the lease is released or expires. This is the
function of pfSense's and OPNsense's Kea DDNS pages.

Page: **DHCP client DNS (Kea DDNS)** (`/svc/kea-ddns`). API: `/api/svc/kea-ddns`.
CLI: `patronus kea-ddns show`. Claim C1354.

## How it works

```
client --DHCP--> kea-dhcp4 / kea-dhcp6 --name change request (loopback)--> kea-dhcp-ddns (D2)
                                                                              |
                                          RFC 2136 UPDATE, TSIG-signed        v
                      local mode:    built-in receiver 127.0.0.1:5335  --> unbound-control local_data --> Unbound
                      external mode: your DNS server (BIND, Knot, PowerDNS, Windows DNS, ...)
```

* **Needs the Kea DHCP backend** (USE=kea; `dhcp.backend` = `kea`, or `auto` with
  Kea installed). With the dnsmasq backend the page refuses to switch on and says why
  (dnsmasq already names its own leases through the DNS page).
* **Local mode** (default): Unbound is a resolver and cannot take RFC 2136 updates, so
  Patronus runs a small receiver (`patronus kea-ddns run`, supervised as
  `patronus-daemon@kea-ddns-sink`, OpenRC and systemd). It answers UPDATE messages on a
  loopback port only, and
  * requires a valid TSIG signature (HMAC-SHA256/384/512, 300 s time window); an unsigned,
    wrongly signed or replayed update is refused and changes nothing;
  * serves only the configured zones (the forward zone and the reverse zones derived from
    the DHCP pools), and only A, AAAA, PTR and DHCID records;
  * applies the RFC 2136 rules (prerequisites, add, delete) atomically, so a conflicting
    client cannot take over another client's name (Kea's DHCID check);
  * keeps at most `max_records` records, in a state file (`/var/lib/patronus/net`, 0600), and
    publishes them into the running Unbound with `unbound-control local_data`. They are
    pushed again every few seconds, so an Unbound restart or a DNS re-apply does not lose them.
* **External mode**: D2 sends the same signed updates to the server you name; nothing runs
  on the router besides D2. The server must hold the same TSIG key and allow updates to the zones.
* The daemon (D2) is `kea-dhcp-ddns` from net-misc/kea, supervised as
  `patronus-daemon@kea-ddns-d2`.

## Settings (all typed keys `kea-ddns.*`, in the declarative configuration)

| key | default | meaning |
|---|---|---|
| enabled | off | master switch |
| mode | local | `local` (router's Unbound) or `external` (RFC 2136 server) |
| forward_zone | DNS page's local domain | zone for client names; should match the domain the DHCP pools hand out |
| reverse | on | also register PTR names (reverse zones come from the pools' subnets) |
| server, server_port | 127.0.0.1, 53 | external mode: the server (an address) |
| key_name, algorithm, secret | patronus-ddns, hmac-sha256, generated | TSIG key. Local mode: leave the secret empty and a random 256-bit key is generated; external mode: the key the server holds (base64) |
| local_port, d2_port | 5335, 53001 | loopback ports of the receiver and of D2 |
| override_client_update, replace_client_name, generated_prefix, update_on_renew | off, when-not-present, host, off | Kea's `ddns-*` parameters |
| unbound_socket | /run/unbound.ctl | local mode: unbound-control socket |
| max_records | 4096 | receiver record cap |

## Security

* The TSIG secret is a write-only field: the API shows `********`, `patronus kea-ddns show`
  and plans/exports of the applier hide it. The two generated files that hold it
  (`kea-dhcp-ddns.conf`, `kea-ddns-sink.json`) are mode 0600 and are deleted when the feature
  is switched off. Like every credential, it is part of a full configuration backup.
* The receiver listens on 127.0.0.1 only, so no firewall rule is needed or created.
* The generated D2 configuration is validated with `kea-dhcp-ddns -t` before it replaces a
  working one.
* Switching the feature off stops D2 and the receiver, removes the registered names from
  Unbound and the `dhcp-ddns` block from Kea's configuration.

## Known limits

* A name registered by DDNS replaces static data of the same name that the DNS page published
  (Unbound's `local_data_remove` works on whole names); give static mappings and DDNS clients
  different names.
* Router tiers (embedded images) use dnsmasq for DHCP and do not carry Kea, so they do not offer this page.
* DDNS for DHCPv6 works through the same D2 (pools served by Kea); prefix-relative pools need dnsmasq.

## Proof

* `ci/netlab/lane-j-kea-ddns.sh`: real Kea + D2 + Unbound + a real DHCP client and a real BIND
  server (external mode); `ci/netlab/lane-j-kea-ddns-ui.sh` + `ci/kea-ddns-page-e2e.py`: the page in Firefox.
* Unit tests in `crates/patronus-network/src/keaddns.rs` (TSIG, the RFC 2136 rules, compression, limits).
