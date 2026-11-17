-- Lane c: pinned DHCPv6 client DUID per interface (colon-separated hex bytes,
-- e.g. 00:04:...). dhcpcd uses exactly this DUID so a replaced router keeps
-- the prefix its ISP delegated to the old one. NULL = dhcpcd's own DUID.
ALTER TABLE interfaces ADD COLUMN dhcp6_duid TEXT;
