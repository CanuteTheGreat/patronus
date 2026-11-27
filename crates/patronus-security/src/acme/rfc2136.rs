//! Native RFC 2136 dynamic DNS update client with RFC 8945 TSIG signing.
//!
//! Only what DNS-01 needs: add and remove one TXT record in a zone, sent to a
//! typed server address, signed with a typed TSIG key.  No external `nsupdate`
//! process.  The wire format is built by hand and unit-tested against
//! known-answer structure checks plus a MAC re-computation.

use super::AcmeError;
use hmac::{Hmac, Mac};
use sha2::{Sha256, Sha384, Sha512};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

const TYPE_SOA: u16 = 6;
const TYPE_TXT: u16 = 16;
const TYPE_TSIG: u16 = 250;
const CLASS_IN: u16 = 1;
const CLASS_NONE: u16 = 254;
const CLASS_ANY: u16 = 255;
const OPCODE_UPDATE: u16 = 5;

/// TSIG HMAC algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TsigAlgorithm {
    HmacSha256,
    HmacSha384,
    HmacSha512,
}

impl TsigAlgorithm {
    pub fn parse(s: &str) -> Result<Self, AcmeError> {
        match s.trim().trim_end_matches('.').to_ascii_lowercase().as_str() {
            "hmac-sha256" | "" => Ok(Self::HmacSha256),
            "hmac-sha384" => Ok(Self::HmacSha384),
            "hmac-sha512" => Ok(Self::HmacSha512),
            other => Err(AcmeError::Config(format!(
                "unsupported TSIG algorithm {other:?} (hmac-sha256, hmac-sha384, hmac-sha512)"
            ))),
        }
    }

    fn wire_name(self) -> &'static str {
        match self {
            Self::HmacSha256 => "hmac-sha256",
            Self::HmacSha384 => "hmac-sha384",
            Self::HmacSha512 => "hmac-sha512",
        }
    }

    fn mac(self, key: &[u8], data: &[u8]) -> Vec<u8> {
        match self {
            Self::HmacSha256 => {
                let mut m = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("hmac key");
                m.update(data);
                m.finalize().into_bytes().to_vec()
            }
            Self::HmacSha384 => {
                let mut m = <Hmac<Sha384> as Mac>::new_from_slice(key).expect("hmac key");
                m.update(data);
                m.finalize().into_bytes().to_vec()
            }
            Self::HmacSha512 => {
                let mut m = <Hmac<Sha512> as Mac>::new_from_slice(key).expect("hmac key");
                m.update(data);
                m.finalize().into_bytes().to_vec()
            }
        }
    }
}

/// A TSIG key (name, algorithm and raw secret).  `Debug` hides the secret.
#[derive(Clone)]
pub struct TsigKey {
    pub name: String,
    pub algorithm: TsigAlgorithm,
    pub secret: Vec<u8>,
}

impl std::fmt::Debug for TsigKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TsigKey")
            .field("name", &self.name)
            .field("algorithm", &self.algorithm)
            .field("secret", &"<hidden>")
            .finish()
    }
}

fn put_name(out: &mut Vec<u8>, name: &str, lower: bool) -> Result<(), AcmeError> {
    let name = name.trim_end_matches('.');
    if !name.is_empty() {
        for label in name.split('.') {
            if label.is_empty() || label.len() > 63 {
                return Err(AcmeError::Config(format!("bad DNS name {name:?}")));
            }
            out.push(label.len() as u8);
            if lower {
                out.extend(label.to_ascii_lowercase().as_bytes());
            } else {
                out.extend(label.as_bytes());
            }
        }
    }
    out.push(0);
    Ok(())
}

fn txt_rdata(value: &str) -> Result<Vec<u8>, AcmeError> {
    let mut r = Vec::new();
    let b = value.as_bytes();
    if b.is_empty() {
        r.push(0);
    }
    for chunk in b.chunks(255) {
        r.push(chunk.len() as u8);
        r.extend(chunk);
    }
    Ok(r)
}

/// What to do with the TXT record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpdateOp {
    Add,
    Remove,
}

/// Build an UPDATE message (unsigned when `key` is None).  `now` is the TSIG
/// time (seconds since the epoch), `fudge` the allowed skew.
#[allow(clippy::too_many_arguments)]
pub fn build_update(
    id: u16,
    zone: &str,
    name: &str,
    value: &str,
    ttl: u32,
    op: UpdateOp,
    key: Option<&TsigKey>,
    now: u64,
    fudge: u16,
) -> Result<Vec<u8>, AcmeError> {
    let mut m = Vec::new();
    m.extend(id.to_be_bytes());
    m.extend((OPCODE_UPDATE << 11).to_be_bytes());
    m.extend(1u16.to_be_bytes()); // ZOCOUNT
    m.extend(0u16.to_be_bytes()); // PRCOUNT
    m.extend(1u16.to_be_bytes()); // UPCOUNT
    m.extend(0u16.to_be_bytes()); // ADCOUNT
    put_name(&mut m, zone, false)?;
    m.extend(TYPE_SOA.to_be_bytes());
    m.extend(CLASS_IN.to_be_bytes());
    put_name(&mut m, name, false)?;
    m.extend(TYPE_TXT.to_be_bytes());
    let rdata = txt_rdata(value)?;
    match op {
        UpdateOp::Add => {
            m.extend(CLASS_IN.to_be_bytes());
            m.extend(ttl.to_be_bytes());
        }
        UpdateOp::Remove => {
            m.extend(CLASS_NONE.to_be_bytes());
            m.extend(0u32.to_be_bytes());
        }
    }
    m.extend((rdata.len() as u16).to_be_bytes());
    m.extend(rdata);
    if let Some(k) = key {
        sign(&mut m, id, k, now, fudge)?;
    }
    Ok(m)
}

fn sign(msg: &mut Vec<u8>, id: u16, key: &TsigKey, now: u64, fudge: u16) -> Result<(), AcmeError> {
    let mut alg = Vec::new();
    put_name(&mut alg, key.algorithm.wire_name(), true)?;
    let mut kname = Vec::new();
    put_name(&mut kname, &key.name, true)?;
    let time48 = &now.to_be_bytes()[2..];
    // MAC input: message, then TSIG variables (RFC 8945 4.3.3).
    let mut data = msg.clone();
    data.extend(&kname);
    data.extend(CLASS_ANY.to_be_bytes());
    data.extend(0u32.to_be_bytes());
    data.extend(&alg);
    data.extend(time48);
    data.extend(fudge.to_be_bytes());
    data.extend(0u16.to_be_bytes()); // error
    data.extend(0u16.to_be_bytes()); // other len
    let mac = key.algorithm.mac(&key.secret, &data);
    let mut rdata = Vec::new();
    rdata.extend(&alg);
    rdata.extend(time48);
    rdata.extend(fudge.to_be_bytes());
    rdata.extend((mac.len() as u16).to_be_bytes());
    rdata.extend(&mac);
    rdata.extend(id.to_be_bytes());
    rdata.extend(0u16.to_be_bytes());
    rdata.extend(0u16.to_be_bytes());
    msg.extend(&kname);
    msg.extend(TYPE_TSIG.to_be_bytes());
    msg.extend(CLASS_ANY.to_be_bytes());
    msg.extend(0u32.to_be_bytes());
    msg.extend((rdata.len() as u16).to_be_bytes());
    msg.extend(rdata);
    // ARCOUNT 0 -> 1
    msg[10] = 0;
    msg[11] = 1;
    Ok(())
}

/// Response check: same id, QR set, opcode UPDATE, RCODE 0.
pub fn check_response(id: u16, resp: &[u8]) -> Result<(), AcmeError> {
    if resp.len() < 12 {
        return Err(AcmeError::Dns("short DNS UPDATE response".into()));
    }
    let rid = u16::from_be_bytes([resp[0], resp[1]]);
    if rid != id {
        return Err(AcmeError::Dns("DNS UPDATE response id mismatch".into()));
    }
    let flags = u16::from_be_bytes([resp[2], resp[3]]);
    if flags & 0x8000 == 0 {
        return Err(AcmeError::Dns("DNS UPDATE reply is not a response".into()));
    }
    let rcode = flags & 0xf;
    if rcode != 0 {
        let name = match rcode {
            1 => "FORMERR",
            2 => "SERVFAIL",
            3 => "NXDOMAIN",
            4 => "NOTIMP",
            5 => "REFUSED (check allow-update / TSIG key)",
            9 => "NOTAUTH (zone or TSIG key not accepted)",
            _ => "error",
        };
        return Err(AcmeError::Dns(format!(
            "DNS UPDATE rejected: rcode {rcode} {name}"
        )));
    }
    Ok(())
}

/// Send one update to `server` (`host:port`), UDP first, TCP when truncated.
pub async fn send(server: &str, msg: &[u8], id: u16, timeout: Duration) -> Result<(), AcmeError> {
    let addr: std::net::SocketAddr = tokio::net::lookup_host(server)
        .await
        .map_err(|e| AcmeError::Dns(format!("resolve {server}: {e}")))?
        .next()
        .ok_or_else(|| AcmeError::Dns(format!("no address for {server}")))?;
    let bind = if addr.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    };
    let sock = UdpSocket::bind(bind)
        .await
        .map_err(|e| AcmeError::Dns(e.to_string()))?;
    sock.send_to(msg, addr)
        .await
        .map_err(|e| AcmeError::Dns(e.to_string()))?;
    let mut buf = vec![0u8; 4096];
    let n = tokio::time::timeout(timeout, sock.recv_from(&mut buf))
        .await
        .map_err(|_| AcmeError::Dns(format!("DNS UPDATE to {server} timed out")))?
        .map_err(|e| AcmeError::Dns(e.to_string()))?
        .0;
    let truncated = n >= 4 && (buf[2] & 0x02) != 0;
    if !truncated {
        return check_response(id, &buf[..n]);
    }
    let mut tcp = tokio::time::timeout(timeout, TcpStream::connect(addr))
        .await
        .map_err(|_| AcmeError::Dns("DNS UPDATE tcp connect timed out".into()))?
        .map_err(|e| AcmeError::Dns(e.to_string()))?;
    let mut framed = (msg.len() as u16).to_be_bytes().to_vec();
    framed.extend(msg);
    tcp.write_all(&framed)
        .await
        .map_err(|e| AcmeError::Dns(e.to_string()))?;
    let mut len = [0u8; 2];
    tokio::time::timeout(timeout, tcp.read_exact(&mut len))
        .await
        .map_err(|_| AcmeError::Dns("DNS UPDATE tcp read timed out".into()))?
        .map_err(|e| AcmeError::Dns(e.to_string()))?;
    let mut body = vec![0u8; u16::from_be_bytes(len) as usize];
    tcp.read_exact(&mut body)
        .await
        .map_err(|e| AcmeError::Dns(e.to_string()))?;
    check_response(id, &body)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> TsigKey {
        TsigKey {
            name: "acme-key".into(),
            algorithm: TsigAlgorithm::HmacSha256,
            secret: b"0123456789abcdef0123456789abcdef".to_vec(),
        }
    }

    #[test]
    fn unsigned_update_has_expected_header() {
        let m = build_update(
            0x1234,
            "example.org",
            "_acme-challenge.example.org",
            "tok",
            60,
            UpdateOp::Add,
            None,
            0,
            300,
        )
        .unwrap();
        assert_eq!(&m[0..2], &[0x12, 0x34]);
        assert_eq!(u16::from_be_bytes([m[2], m[3]]) >> 11, OPCODE_UPDATE);
        assert_eq!(&m[4..12], &[0, 1, 0, 0, 0, 1, 0, 0]);
        // zone name labels
        assert_eq!(&m[12..20], b"\x07example");
    }

    #[test]
    fn signed_update_counts_tsig_and_mac_verifies() {
        let k = key();
        let m = build_update(
            7,
            "example.org",
            "_acme-challenge.example.org",
            "v",
            60,
            UpdateOp::Add,
            Some(&k),
            1_700_000_000,
            300,
        )
        .unwrap();
        assert_eq!(&m[10..12], &[0, 1]);
        // Recompute: strip the TSIG RR, restore ARCOUNT, MAC must match.
        let mut kname = Vec::new();
        put_name(&mut kname, "acme-key", true).unwrap();
        let pos = m
            .windows(kname.len())
            .rposition(|w| w == kname.as_slice())
            .unwrap();
        let mut body = m[..pos].to_vec();
        body[10] = 0;
        body[11] = 0;
        let mut alg = Vec::new();
        put_name(&mut alg, "hmac-sha256", true).unwrap();
        let mut data = body;
        data.extend(&kname);
        data.extend(CLASS_ANY.to_be_bytes());
        data.extend(0u32.to_be_bytes());
        data.extend(&alg);
        data.extend(&1_700_000_000u64.to_be_bytes()[2..]);
        data.extend(300u16.to_be_bytes());
        data.extend([0, 0, 0, 0]);
        let mac = k.algorithm.mac(&k.secret, &data);
        assert!(m.windows(mac.len()).any(|w| w == mac.as_slice()));
    }

    #[test]
    fn remove_uses_class_none() {
        let m = build_update(
            1,
            "example.org",
            "x.example.org",
            "v",
            60,
            UpdateOp::Remove,
            None,
            0,
            300,
        )
        .unwrap();
        let tail = &m[m.len() - 2 - 2 - 1 - 4 - 2..];
        assert!(tail.windows(2).any(|w| w == CLASS_NONE.to_be_bytes()));
    }

    #[test]
    fn long_txt_is_chunked() {
        let r = txt_rdata(&"a".repeat(300)).unwrap();
        assert_eq!(r[0], 255);
        assert_eq!(r[256], 45);
    }

    #[test]
    fn bad_names_rejected() {
        assert!(build_update(1, "a..b", "x.a..b", "v", 1, UpdateOp::Add, None, 0, 1).is_err());
    }

    #[test]
    fn response_rcodes() {
        let mut ok = vec![0, 9, 0xa8, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        assert!(check_response(9, &ok).is_ok());
        assert!(check_response(8, &ok).is_err());
        ok[3] = 5;
        let e = check_response(9, &ok).unwrap_err().to_string();
        assert!(e.contains("REFUSED"));
        assert!(check_response(9, &[0; 3]).is_err());
    }

    #[test]
    fn key_debug_hides_secret() {
        assert!(!format!("{:?}", key()).contains("0123456789"));
    }

    #[test]
    fn algorithm_parse() {
        assert_eq!(
            TsigAlgorithm::parse("HMAC-SHA512.").unwrap(),
            TsigAlgorithm::HmacSha512
        );
        assert!(TsigAlgorithm::parse("hmac-md5").is_err());
    }
}
