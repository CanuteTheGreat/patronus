//! Approximate country-centroid lookup table for the attack-map dashboard
//! widget (`MonitoringManager::get_attack_map_data`).
//!
//! This intentionally does NOT attempt per-IP lat/lon geolocation -- that
//! would require a MaxMind GeoLite2-City (or similar) database with
//! per-record coordinates, which isn't part of this project's GeoIP setup
//! (`patronus-firewall::geoip::GeoIpManager` only resolves ISO country
//! codes, not city-level coordinates, and is gated behind the `geoip`
//! Cargo feature). A country-to-centroid table is a reasonable, honest
//! stand-in: it's good enough to plot "attacks are coming from roughly
//! here" on a world map without fabricating precision the underlying data
//! doesn't have.
//!
//! Covers the countries that actually show up in real threat-intel feeds
//! (EmergingThreats / AbuseIPDB compromised-host lists skew heavily toward
//! a well-known set of hosting/eyeball countries); anything not in this
//! table returns `None` and the caller should skip plotting that entry
//! rather than guessing (0, 0) -- plotting unknown origins at Null Island
//! would be worse than just omitting them.

/// Returns an approximate (latitude, longitude) centroid for an ISO
/// 3166-1 alpha-2 country code (case-insensitive). Returns `None` for
/// codes not in the table.
pub fn country_centroid(country_code: &str) -> Option<(f64, f64)> {
    let code = country_code.to_ascii_uppercase();
    let (lat, lon) = match code.as_str() {
        "US" => (37.0902, -95.7129),
        "CA" => (56.1304, -106.3468),
        "MX" => (23.6345, -102.5528),
        "BR" => (-14.2350, -51.9253),
        "AR" => (-38.4161, -63.6167),
        "GB" => (55.3781, -3.4360),
        "IE" => (53.1424, -7.6921),
        "FR" => (46.2276, 2.2137),
        "DE" => (51.1657, 10.4515),
        "NL" => (52.1326, 5.2913),
        "BE" => (50.5039, 4.4699),
        "LU" => (49.8153, 6.1296),
        "CH" => (46.8182, 8.2275),
        "AT" => (47.5162, 14.5501),
        "IT" => (41.8719, 12.5674),
        "ES" => (40.4637, -3.7492),
        "PT" => (39.3999, -8.2245),
        "PL" => (51.9194, 19.1451),
        "CZ" => (49.8175, 15.4730),
        "SK" => (48.6690, 19.6990),
        "HU" => (47.1625, 19.5033),
        "RO" => (45.9432, 24.9668),
        "BG" => (42.7339, 25.4858),
        "GR" => (39.0742, 21.8243),
        "SE" => (60.1282, 18.6435),
        "NO" => (60.4720, 8.4689),
        "DK" => (56.2639, 9.5018),
        "FI" => (61.9241, 25.7482),
        "IS" => (64.9631, -19.0208),
        "UA" => (48.3794, 31.1656),
        "BY" => (53.7098, 27.9534),
        "MD" => (47.4116, 28.3699),
        "RU" => (61.5240, 105.3188),
        "TR" => (38.9637, 35.2433),
        "CY" => (35.1264, 33.4299),
        "IL" => (31.0461, 34.8516),
        "SA" => (23.8859, 45.0792),
        "AE" => (23.4241, 53.8478),
        "IR" => (32.4279, 53.6880),
        "IQ" => (33.2232, 43.6793),
        "EG" => (26.8206, 30.8025),
        "ZA" => (-30.5595, 22.9375),
        "NG" => (9.0820, 8.6753),
        "KE" => (-0.0236, 37.9062),
        "MA" => (31.7917, -7.0926),
        "IN" => (20.5937, 78.9629),
        "PK" => (30.3753, 69.3451),
        "BD" => (23.6850, 90.3563),
        "CN" => (35.8617, 104.1954),
        "HK" => (22.3193, 114.1694),
        "TW" => (23.6978, 120.9605),
        "JP" => (36.2048, 138.2529),
        "KR" => (35.9078, 127.7669),
        "KP" => (40.3399, 127.5101),
        "VN" => (14.0583, 108.2772),
        "TH" => (15.8700, 100.9925),
        "ID" => (-0.7893, 113.9213),
        "MY" => (4.2105, 101.9758),
        "SG" => (1.3521, 103.8198),
        "PH" => (12.8797, 121.7740),
        "AU" => (-25.2744, 133.7751),
        "NZ" => (-40.9006, 174.8860),
        "KZ" => (48.0196, 66.9237),
        "UZ" => (41.3775, 64.5853),
        _ => return None,
    };
    Some((lat, lon))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_code_returns_centroid() {
        assert_eq!(country_centroid("US"), Some((37.0902, -95.7129)));
        // case-insensitive
        assert_eq!(country_centroid("us"), Some((37.0902, -95.7129)));
    }

    #[test]
    fn unknown_code_returns_none() {
        assert_eq!(country_centroid("ZZ"), None);
        assert_eq!(country_centroid(""), None);
    }
}
