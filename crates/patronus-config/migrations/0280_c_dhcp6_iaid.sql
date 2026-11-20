-- Lane c: DHCPv6 IAID per interface (one number for IA_NA and IA_PD). The ISP keys a
-- binding on DUID + IAID: with the old router's DUID and IAID a replaced router gets the
-- same address and delegated prefix at once (another IAID gets NoPrefixAvail until the old
-- binding expires). NULL = the client's default (IA_NA from the MAC, IA_PD 1).
ALTER TABLE interfaces ADD COLUMN dhcp6_iaid INTEGER;
