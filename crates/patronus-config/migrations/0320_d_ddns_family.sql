-- Lane d: which address families a DDNS client publishes.
--   ipv4 (default, the old behaviour): A record from the interface's IPv4
--   ipv6: AAAA from the interface's global IPv6 (a /128 from DHCPv6 IA_NA
--         on a WAN counts)
--   both: one name, A and AAAA (one row per name; the table stays
--         UNIQUE(provider, hostname))
ALTER TABLE ddns_clients ADD COLUMN family TEXT NOT NULL DEFAULT 'ipv4';
