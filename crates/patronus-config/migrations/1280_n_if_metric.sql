-- Route metric of the default route an interface's DHCP lease installs (lower = preferred uplink).
-- NULL = the role's default (wan 100, opt N 200+N). Lets a Wi-Fi router rank a 5 GHz uplink ahead of a 2.4 GHz one.
ALTER TABLE interfaces ADD COLUMN metric INTEGER;
