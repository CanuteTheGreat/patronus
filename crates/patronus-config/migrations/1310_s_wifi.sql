-- Lane S (device segmentation): per-device Wi-Fi credentials when Patronus
-- runs the access point (hostapd). One row of seg_wifi_networks = one SSID on
-- one radio interface; seg_wifi_creds = one passphrase of one device on one
-- network, bound to the device's MAC (WPA2 per-MAC PSK file entries reload
-- live; WPA3-SAE passwords need a hostapd restart). Secrets are stored like
-- WireGuard keys and IPsec PSKs (the 0600 store); the API never lists them.

CREATE TABLE IF NOT EXISTS seg_wifi_networks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,                 -- [a-z0-9_-]{1,32}
    ifname TEXT NOT NULL UNIQUE,               -- wlan interface that supports AP mode
    ssid TEXT NOT NULL,
    band TEXT NOT NULL DEFAULT '2g',           -- 2g | 5g
    channel INTEGER NOT NULL DEFAULT 6,
    country TEXT NOT NULL DEFAULT 'US',
    security TEXT NOT NULL DEFAULT 'wpa2',     -- wpa2 | wpa2_wpa3 | wpa3
    segment TEXT NOT NULL,                     -- the bridge (role token or name) the AP joins
    unknown_policy TEXT NOT NULL DEFAULT 'reject',  -- reject | enrol
    enrol_secret TEXT,                         -- shared secret of unknown_policy=enrol: grants nothing
    enabled INTEGER NOT NULL DEFAULT 1,
    updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS seg_wifi_creds (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id INTEGER NOT NULL REFERENCES seg_devices(id) ON DELETE CASCADE,
    network_id INTEGER NOT NULL REFERENCES seg_wifi_networks(id) ON DELETE CASCADE,
    kind TEXT NOT NULL,                        -- psk | sae | psk+sae (one secret, both lines)
    secret TEXT NOT NULL,
    state TEXT NOT NULL DEFAULT 'active',      -- pending (MAC not learned yet) | active | revoked
    created_at INTEGER NOT NULL,
    revoked_at INTEGER,
    expires_at INTEGER,                        -- pending credentials expire; a rotated one keeps working until then
    UNIQUE(network_id, secret)
);
