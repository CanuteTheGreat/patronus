-- Guest network (USE=guest, patronus-network/src/guest.rs): Wi-Fi vouchers, extra
-- passphrases for the guest SSID that stop working after `minutes` (counted from
-- updated_at, 0 = never). All other guest settings are `guest.*` keys of lan_settings.
CREATE TABLE IF NOT EXISTS guest_vouchers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    code TEXT NOT NULL,
    minutes INTEGER NOT NULL DEFAULT 1440,
    updated_at INTEGER NOT NULL
);
