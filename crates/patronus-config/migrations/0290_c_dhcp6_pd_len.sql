-- Lane c: size of the delegated prefix the WAN asks the ISP for (DHCPv6 IA_PD prefix-length
-- hint, 48-64; a /56 is the usual home allocation). NULL = no hint (the ISP picks).
ALTER TABLE interfaces ADD COLUMN dhcp6_pd_len INTEGER;
