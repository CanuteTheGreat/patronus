-- Lane d: per-static-mapping lease options (OpenWrt parity).
--   lease_time: NULL = the pool's lease time, 0 = infinite, else seconds
--   dns_record: 1 = publish <hostname>.<dns.local_domain> -> ip as a DNS
--               record even while the device is offline
ALTER TABLE dhcp_static_mappings ADD COLUMN lease_time INTEGER;
ALTER TABLE dhcp_static_mappings ADD COLUMN dns_record INTEGER NOT NULL DEFAULT 0;
