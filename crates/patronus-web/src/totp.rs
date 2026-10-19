//! TOTP (RFC 6238 over RFC 4226 HOTP, HMAC-SHA1, 6 digits, 30 s) for the
//! web accounts' second factor (USE=totp), plus recovery codes. Compatible
//! with every authenticator app (otpauth:// URI / QR code).

use hmac::{Hmac, Mac};
use sha2::Digest;

pub const PERIOD: u64 = 30;
pub const DIGITS: u32 = 6;
pub const ISSUER: &str = "Patronus";
/// Steps accepted on either side of now (clock skew).
pub const SKEW: u64 = 1;
pub const RECOVERY_CODES: usize = 10;

const B32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// RFC 4648 base32 without padding.
pub fn base32_encode(data: &[u8]) -> String {
    let mut out = String::new();
    let (mut buf, mut bits) = (0u32, 0u32);
    for &b in data {
        buf = (buf << 8) | b as u32;
        bits += 8;
        while bits >= 5 {
            out.push(B32[((buf >> (bits - 5)) & 31) as usize] as char);
            bits -= 5;
        }
    }
    if bits > 0 {
        out.push(B32[((buf << (5 - bits)) & 31) as usize] as char);
    }
    out
}

/// Decode base32 (case-insensitive, spaces and `=` ignored).
pub fn base32_decode(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let (mut buf, mut bits) = (0u32, 0u32);
    for c in s.chars().filter(|c| !c.is_whitespace() && *c != '=') {
        let v = B32
            .iter()
            .position(|&x| x as char == c.to_ascii_uppercase())? as u32;
        buf = (buf << 5) | v;
        bits += 5;
        if bits >= 8 {
            out.push((buf >> (bits - 8)) as u8);
            bits -= 8;
        }
    }
    Some(out)
}

/// A new 160-bit secret, base32.
pub fn generate_secret() -> String {
    use rand::RngCore;
    let mut k = [0u8; 20];
    rand::rngs::OsRng.fill_bytes(&mut k);
    base32_encode(&k)
}

/// HOTP value of `key` at `counter`.
pub fn hotp(key: &[u8], counter: u64) -> u32 {
    let mut mac = Hmac::<sha1::Sha1>::new_from_slice(key).expect("HMAC takes any key length");
    mac.update(&counter.to_be_bytes());
    let h = mac.finalize().into_bytes();
    let o = (h[h.len() - 1] & 0x0f) as usize;
    let v = u32::from_be_bytes([h[o] & 0x7f, h[o + 1], h[o + 2], h[o + 3]]);
    v % 10u32.pow(DIGITS)
}

/// The code for `secret` at unix time `t` (zero-padded).
pub fn code_at(secret: &str, t: u64) -> Option<String> {
    let key = base32_decode(secret)?;
    Some(format!(
        "{:0w$}",
        hotp(&key, t / PERIOD),
        w = DIGITS as usize
    ))
}

/// The step `code` belongs to (now +- [`SKEW`]), if it is valid and newer
/// than `last_step` (each code is accepted once).
pub fn verify(secret: &str, code: &str, now: u64, last_step: Option<u64>) -> Option<u64> {
    let code: String = code.chars().filter(|c| !c.is_whitespace()).collect();
    if code.len() != DIGITS as usize || !code.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let key = base32_decode(secret)?;
    let step = now / PERIOD;
    (step.saturating_sub(SKEW)..=step + SKEW).find(|s| {
        last_step.is_none_or(|l| *s > l)
            && format!("{:0w$}", hotp(&key, *s), w = DIGITS as usize) == code
    })
}

/// otpauth:// URI for authenticator apps.
pub fn otpauth_uri(account: &str, secret: &str) -> String {
    let enc = |s: &str| -> String {
        s.bytes()
            .map(|b| {
                if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
                    (b as char).to_string()
                } else {
                    format!("%{b:02X}")
                }
            })
            .collect()
    };
    format!(
        "otpauth://totp/{}:{}?secret={secret}&issuer={}&algorithm=SHA1&digits={DIGITS}&period={PERIOD}",
        enc(ISSUER),
        enc(account),
        enc(ISSUER)
    )
}

/// New recovery codes (`xxxxx-xxxxx`, 50 bits each) and their digests.
pub fn generate_recovery_codes() -> (Vec<String>, Vec<String>) {
    use rand::Rng;
    const CS: &[u8] = b"abcdefghjkmnpqrstuvwxyz23456789";
    let mut rng = rand::rngs::OsRng;
    let codes: Vec<String> = (0..RECOVERY_CODES)
        .map(|_| {
            let mut c: String = (0..10)
                .map(|_| CS[rng.gen_range(0..CS.len())] as char)
                .collect();
            c.insert(5, '-');
            c
        })
        .collect();
    let hashes = codes.iter().map(|c| recovery_digest(c)).collect();
    (codes, hashes)
}

/// SHA-256 hex of a normalised recovery code.
pub fn recovery_digest(code: &str) -> String {
    let norm: String = code
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_lowercase())
        .collect();
    sha2::Sha256::digest(norm.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc6238_sha1_test_vectors() {
        // RFC 6238 appendix B, SHA1, key "12345678901234567890", 8 digits;
        // the 6-digit codes are the last 6 digits.
        let secret = base32_encode(b"12345678901234567890");
        assert_eq!(secret, "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
        for (t, want8) in [
            (59u64, "94287082"),
            (1111111109, "07081804"),
            (1111111111, "14050471"),
            (1234567890, "89005924"),
            (2000000000, "69279037"),
            (20000000000, "65353130"),
        ] {
            assert_eq!(code_at(&secret, t).unwrap(), want8[2..], "t={t}");
        }
        assert_eq!(base32_decode(&secret).unwrap(), b"12345678901234567890");
        assert_eq!(base32_decode("gezd gnbv"), base32_decode("GEZDGNBV"));
        assert!(base32_decode("not base32!").is_none());
    }

    #[test]
    fn verify_accepts_skew_once_and_rejects_junk() {
        let s = generate_secret();
        assert_eq!(base32_decode(&s).unwrap().len(), 20);
        let now = 1_760_000_000u64;
        let c = code_at(&s, now).unwrap();
        let step = now / PERIOD;
        assert_eq!(verify(&s, &c, now, None), Some(step));
        assert_eq!(
            verify(&s, &c, now + PERIOD, None),
            Some(step),
            "30 s late is ok"
        );
        assert_eq!(verify(&s, &c, now + 3 * PERIOD, None), None, "too late");
        assert_eq!(verify(&s, &c, now, Some(step)), None, "a code works once");
        let prev = code_at(&s, now - PERIOD).unwrap();
        assert_eq!(
            verify(&s, &prev, now, Some(step)),
            None,
            "older than the last one"
        );
        assert_eq!(verify(&s, &format!(" {c} "), now, None), Some(step));
        for bad in ["", "12345", "1234567", "abcdef"] {
            assert_eq!(verify(&s, bad, now, None), None, "{bad}");
        }
        let uri = otpauth_uri("ad min", &s);
        assert!(
            uri.starts_with("otpauth://totp/Patronus:ad%20min?secret="),
            "{uri}"
        );
        assert!(uri.contains("&digits=6&period=30"));
    }

    #[test]
    fn recovery_codes_are_unique_and_hashed() {
        let (codes, hashes) = generate_recovery_codes();
        assert_eq!(codes.len(), RECOVERY_CODES);
        let mut u = codes.clone();
        u.sort();
        u.dedup();
        assert_eq!(u.len(), RECOVERY_CODES);
        assert_eq!(recovery_digest(&codes[0]), hashes[0]);
        assert_eq!(recovery_digest(&codes[0].to_uppercase()), hashes[0]);
        assert_eq!(recovery_digest(&codes[0].replace('-', "")), hashes[0]);
        assert!(!hashes
            .iter()
            .any(|h| codes.iter().any(|c| h.contains(c.as_str()))));
    }
}
