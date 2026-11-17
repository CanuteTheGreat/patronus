-- Lane c: Wi-Fi client (STA) uplinks (USE=wifi-client). One row per wireless device that joins an
-- upstream access point with wpa_supplicant; the device is then an ordinary interface in `interfaces`
-- (role wan/optN, ipv4_mode dhcp, metric) and a member of gateway groups (failover) like any WAN.
CREATE TABLE IF NOT EXISTS wifi_clients (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    device      TEXT NOT NULL UNIQUE,
    enabled     INTEGER NOT NULL DEFAULT 1,
    ssid        TEXT NOT NULL,
    -- open | wpa2 | wpa3 | wpa2-wpa3
    security    TEXT NOT NULL DEFAULT 'wpa2',
    -- passphrase (8-63 chars) or 64 hex digits; never returned by the API
    psk         TEXT,
    -- pin to one access point (aa:bb:cc:dd:ee:ff) or empty
    bssid       TEXT,
    description TEXT,
    updated_at  INTEGER
);
