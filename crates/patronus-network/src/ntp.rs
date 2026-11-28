//! NTP server (lane D): chrony serving time to the LAN.
//!
//! With `ntp.enabled=1` Patronus owns `/etc/chrony/chrony.conf` (the file
//! Gentoo's `chronyd` OpenRC script and systemd unit read; the old module
//! wrote it but was never compiled, and installed its own systemd unit):
//! upstream servers from `ntp.servers`, `allow` lines for the subnets of
//! `ntp.interfaces` (default `@lan`), and `local stratum 10` so clients
//! keep getting time while the upstreams are unreachable. Turning the
//! server off keeps chrony as a client with the same upstreams (the box
//! still needs a correct clock) and drops the `allow` lines. Patronus never
//! touches a chrony.conf it has not written unless the server is enabled.
//!
//! Two additions (docs/NTP-GPS-ACL.md):
//!
//! * **Access list.** `ntp.acl_allow` / `ntp.acl_deny` are extra CIDR
//!   blocks written as chrony `allow` / `deny` lines after the interface
//!   subnets (chrony applies the most specific match, a `deny` wins a tie);
//!   `ntp.acl_mode=explicit` serves ONLY the explicit allow list.
//!   `ntp.ratelimit` adds chrony's response rate limiting.
//! * **GPS / PPS reference clock.** `ntp.gps.*` describes a serial GPS
//!   receiver (and optionally a kernel PPS device). Patronus then manages
//!   gpsd (`/etc/conf.d/gpsd`) and renders `refclock SHM 0` (NMEA time)
//!   plus `refclock PPS` locked to it, so the router becomes a stratum 1
//!   source that survives an unreachable internet.

use crate::lan::{self, invalid, LanEnv, ManagedFile};
use async_trait::async_trait;
use patronus_config::applier::{Applier, ApplyReport, Phase};
use patronus_config::store::ConfigStore;
use patronus_core::{Error, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

pub const CHRONY_CONF: &str = "/etc/chrony/chrony.conf";
pub const CHRONYD_BIN: &str = "/usr/sbin/chronyd";
pub const SERVICE: &str = "chronyd";
pub const GPSD_BIN: &str = "/usr/sbin/gpsd";
pub const GPSD_CONF: &str = "/etc/conf.d/gpsd";
pub const GPSD_SERVICE: &str = "gpsd";
/// Baud rates a GPS receiver is realistically configured for.
pub const GPS_BAUDS: [u32; 8] = [4800, 9600, 19200, 38400, 57600, 115200, 230400, 460800];

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NtpSettings {
    pub enabled: bool,
    pub servers: Vec<String>,
    pub interfaces: Vec<String>,
    /// `interfaces` (subnets of the served interfaces + explicit lists) or
    /// `explicit` (only `acl_allow`).
    pub acl_mode: String,
    pub acl_allow: Vec<String>,
    pub acl_deny: Vec<String>,
    pub ratelimit: bool,
    pub gps: GpsSettings,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GpsSettings {
    pub enabled: bool,
    /// Serial device of the receiver, e.g. `/dev/ttyUSB0`.
    pub device: String,
    pub baud: u32,
    /// Kernel PPS device (`/dev/pps0`); empty = NMEA time only (~ms).
    pub pps_device: String,
    /// Seconds added to the NMEA time (serial/NMEA latency), -1..1.
    pub offset: f64,
    /// Prefer this clock over network sources.
    pub prefer: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NtpInput {
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub servers: Option<String>,
    #[serde(default)]
    pub interfaces: Option<String>,
    #[serde(default)]
    pub acl_mode: Option<String>,
    #[serde(default)]
    pub acl_allow: Option<String>,
    #[serde(default)]
    pub acl_deny: Option<String>,
    #[serde(default)]
    pub ratelimit: Option<bool>,
    #[serde(default)]
    pub gps_enabled: Option<bool>,
    #[serde(default)]
    pub gps_device: Option<String>,
    /// A number or a string of digits (an HTML `<select>` posts strings).
    #[serde(default, deserialize_with = "num_or_string")]
    pub gps_baud: Option<u32>,
    #[serde(default)]
    pub gps_pps_device: Option<String>,
    #[serde(default)]
    pub gps_offset: Option<f64>,
    #[serde(default)]
    pub gps_prefer: Option<bool>,
}

fn num_or_string<'de, D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Option<u32>, D::Error> {
    use serde::de::Error;
    match Option::<Value>::deserialize(d)? {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Number(n)) => n
            .as_u64()
            .and_then(|v| u32::try_from(v).ok())
            .map(Some)
            .ok_or_else(|| D::Error::custom("a baud rate is a whole number")),
        Some(Value::String(t)) if t.trim().is_empty() => Ok(None),
        Some(Value::String(t)) => t
            .trim()
            .parse()
            .map(Some)
            .map_err(|_| D::Error::custom("a baud rate is a whole number")),
        Some(_) => Err(D::Error::custom("a baud rate is a whole number")),
    }
}

fn split(s: &str) -> Vec<String> {
    s.split([',', ' ', '\n'])
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .map(String::from)
        .collect()
}

fn check_server(s: &str) -> Result<String> {
    if s.parse::<std::net::IpAddr>().is_ok() || lan::valid_dns_name(s, false) {
        Ok(s.to_ascii_lowercase())
    } else {
        Err(invalid(format!("NTP server {s:?}")))
    }
}

/// An ACL entry: an IP or a CIDR block. `/0` is refused (that would serve
/// the whole internet); a bare address becomes a host route.
pub fn check_acl(s: &str) -> Result<String> {
    let bad = || {
        invalid(format!(
            "NTP access list entry {s:?} (want an address or CIDR block)"
        ))
    };
    let (a, len) = match s.split_once('/') {
        Some((a, l)) => (a, Some(l.parse::<u8>().map_err(|_| bad())?)),
        None => (s, None),
    };
    let ip: std::net::IpAddr = a.parse().map_err(|_| bad())?;
    let max = if ip.is_ipv4() { 32 } else { 128 };
    let len = len.unwrap_or(max);
    if len > max {
        return Err(bad());
    }
    if len == 0 {
        return Err(invalid(format!(
            "NTP access list entry {s:?}: a /0 block would serve the whole internet"
        )));
    }
    Ok(if len == max {
        ip.to_string()
    } else {
        format!("{ip}/{len}")
    })
}

/// `/dev/ttyUSB0`, `/dev/ttyAMA0`, `/dev/serial/by-id/usb-u-blox_...`, `/dev/gps0`.
pub fn check_gps_device(s: &str) -> Result<String> {
    let ok_name = |n: &str| {
        !n.is_empty()
            && n.len() <= 120
            && n.chars()
                .all(|c| c.is_ascii_alphanumeric() || "._:-".contains(c))
            && !n.starts_with('.')
    };
    let ok = s
        .strip_prefix("/dev/serial/by-id/")
        .or_else(|| s.strip_prefix("/dev/serial/by-path/"))
        .or_else(|| s.strip_prefix("/dev/tty"))
        .or_else(|| s.strip_prefix("/dev/gps"))
        .is_some_and(ok_name);
    if ok {
        Ok(s.to_string())
    } else {
        Err(invalid(format!(
            "GPS device {s:?} (want /dev/ttyUSB0, /dev/ttyAMA0, /dev/serial/by-id/..., /dev/gps0)"
        )))
    }
}

pub fn check_pps_device(s: &str) -> Result<String> {
    match s.strip_prefix("/dev/pps") {
        Some(n) if !n.is_empty() && n.len() <= 3 && n.chars().all(|c| c.is_ascii_digit()) => {
            Ok(s.to_string())
        }
        _ => Err(invalid(format!("PPS device {s:?} (want /dev/pps0)"))),
    }
}

pub async fn settings(store: &ConfigStore) -> Result<NtpSettings> {
    Ok(NtpSettings {
        enabled: lan::flag(&lan::setting_or(store, "ntp.enabled", "0").await?),
        servers: split(&lan::setting_or(store, "ntp.servers", "pool.ntp.org").await?),
        interfaces: split(&lan::setting_or(store, "ntp.interfaces", "@lan").await?),
        acl_mode: lan::setting_or(store, "ntp.acl_mode", "interfaces").await?,
        acl_allow: split(&lan::setting_or(store, "ntp.acl_allow", "").await?),
        acl_deny: split(&lan::setting_or(store, "ntp.acl_deny", "").await?),
        ratelimit: lan::flag(&lan::setting_or(store, "ntp.ratelimit", "0").await?),
        gps: GpsSettings {
            enabled: lan::flag(&lan::setting_or(store, "ntp.gps.enabled", "0").await?),
            device: lan::setting_or(store, "ntp.gps.device", "/dev/ttyUSB0").await?,
            baud: lan::setting_or(store, "ntp.gps.baud", "9600")
                .await?
                .parse()
                .unwrap_or(9600),
            pps_device: lan::setting_or(store, "ntp.gps.pps_device", "").await?,
            offset: lan::setting_or(store, "ntp.gps.offset", "0")
                .await?
                .parse()
                .unwrap_or(0.0),
            prefer: lan::flag(&lan::setting_or(store, "ntp.gps.prefer", "0").await?),
        },
    })
}

pub async fn save_settings(store: &ConfigStore, i: &NtpInput) -> Result<()> {
    let mut kv = Vec::new();
    if let Some(e) = i.enabled {
        kv.push(("ntp.enabled", if e { "1" } else { "0" }.to_string()));
    }
    if let Some(s) = &i.servers {
        let v = split(s)
            .iter()
            .map(|x| check_server(x))
            .collect::<Result<Vec<_>>>()?;
        if v.is_empty() {
            return Err(invalid("NTP servers: at least one upstream server"));
        }
        kv.push(("ntp.servers", v.join(",")));
    }
    if let Some(s) = &i.interfaces {
        let v = split(s)
            .iter()
            .map(|x| lan::check_iface_spec(x))
            .collect::<Result<Vec<_>>>()?;
        kv.push(("ntp.interfaces", v.join(",")));
    }
    if let Some(m) = &i.acl_mode {
        if !matches!(m.as_str(), "interfaces" | "explicit") {
            return Err(invalid("NTP access mode: interfaces or explicit"));
        }
        kv.push(("ntp.acl_mode", m.clone()));
    }
    let acl = |v: &str| -> Result<String> {
        let mut l = split(v)
            .iter()
            .map(|x| check_acl(x))
            .collect::<Result<Vec<_>>>()?;
        l.sort();
        l.dedup();
        Ok(l.join(","))
    };
    if let Some(a) = &i.acl_allow {
        kv.push(("ntp.acl_allow", acl(a)?));
    }
    if let Some(a) = &i.acl_deny {
        kv.push(("ntp.acl_deny", acl(a)?));
    }
    if let Some(r) = i.ratelimit {
        kv.push(("ntp.ratelimit", if r { "1" } else { "0" }.into()));
    }
    if let Some(e) = i.gps_enabled {
        kv.push(("ntp.gps.enabled", if e { "1" } else { "0" }.into()));
    }
    if let Some(d) = &i.gps_device {
        kv.push(("ntp.gps.device", check_gps_device(d.trim())?));
    }
    if let Some(b) = i.gps_baud {
        if !GPS_BAUDS.contains(&b) {
            return Err(invalid(format!("GPS baud rate {b} (one of {GPS_BAUDS:?})")));
        }
        kv.push(("ntp.gps.baud", b.to_string()));
    }
    if let Some(d) = &i.gps_pps_device {
        let d = d.trim();
        kv.push((
            "ntp.gps.pps_device",
            if d.is_empty() {
                String::new()
            } else {
                check_pps_device(d)?
            },
        ));
    }
    if let Some(o) = i.gps_offset {
        if !o.is_finite() || !(-1.0..=1.0).contains(&o) {
            return Err(invalid("GPS offset: between -1 and 1 second"));
        }
        kv.push(("ntp.gps.offset", format!("{o}")));
    }
    if let Some(p) = i.gps_prefer {
        kv.push(("ntp.gps.prefer", if p { "1" } else { "0" }.into()));
    }
    for (k, v) in kv {
        lan::set_setting(store, k, &v).await?;
    }
    Ok(())
}

/// `/etc/chrony/chrony.conf`.
pub fn render(s: &NtpSettings, allow: &[String], pps_ok: bool) -> String {
    let mut c = lan::header("#", "chrony: NTP client and LAN time server");
    for sv in &s.servers {
        let kind = if sv.starts_with("pool.") || sv.contains(".pool.") {
            "pool"
        } else {
            "server"
        };
        c.push_str(&format!("{kind} {sv} iburst\n"));
    }
    c.push_str("driftfile /var/lib/chrony/drift\nmakestep 1.0 3\nrtcsync\n");
    if s.gps.enabled {
        c.push_str(&render_gps(&s.gps, pps_ok));
    }
    if s.enabled {
        let derived: &[String] = if s.acl_mode == "explicit" { &[] } else { allow };
        for n in derived.iter().chain(s.acl_allow.iter()) {
            c.push_str(&format!("allow {n}\n"));
        }
        for n in &s.acl_deny {
            c.push_str(&format!("deny {n}\n"));
        }
        if s.ratelimit {
            c.push_str("ratelimit interval 3 burst 8 leak 2\n");
        }
        c.push_str(
            "# keep serving the LAN while the upstreams are unreachable\nlocal stratum 10\n",
        );
    }
    c
}

/// chrony reference clocks for the receiver: NMEA time through gpsd's
/// shared memory segment 0 and, with a PPS device, the pulse locked to it
/// (the pulse alone only says WHEN a second starts, NMEA says WHICH one).
/// `pps_ok` = the PPS device exists now: chronyd refuses to start when a
/// `refclock PPS` names a device that is missing, which would also stop the
/// router's own time sync, so a missing pulse device falls back to NMEA only
/// (with a warning) until the next apply finds it.
pub fn render_gps(g: &GpsSettings, pps_ok: bool) -> String {
    let mut c = String::from("# GPS reference clock (gpsd -> shared memory segment 0)\n");
    let pref = if g.prefer { " prefer" } else { "" };
    if g.pps_device.is_empty() || !pps_ok {
        c.push_str(&format!(
            "refclock SHM 0 refid GPS offset {} delay 0.2 poll 4{pref}\n",
            g.offset
        ));
    } else {
        c.push_str(&format!(
            "refclock SHM 0 refid NMEA offset {} delay 0.2 poll 4 noselect\n\
             refclock PPS {} refid PPS lock NMEA poll 4{pref}\n",
            g.offset, g.pps_device
        ));
    }
    c
}

/// `/etc/conf.d/gpsd` (read by Gentoo's OpenRC script and systemd unit).
pub fn render_gpsd(g: &GpsSettings) -> String {
    let mut c = lan::header("#", "gpsd: GPS receiver for the NTP reference clock");
    c.push_str(&format!(
        "GPSD_OPTIONS=\"-n -s {}\"\nDEVICES=\"{}{}\"\n",
        g.baud,
        g.device,
        if g.pps_device.is_empty() {
            String::new()
        } else {
            format!(" {}", g.pps_device)
        }
    ));
    c
}

#[derive(Clone, Default)]
pub struct NtpApplier {
    env: LanEnv,
}

impl NtpApplier {
    pub fn new(env: LanEnv) -> Self {
        Self { env }
    }

    fn pps_ok(&self, s: &NtpSettings, rep: &mut ApplyReport) -> bool {
        if !s.gps.enabled || s.gps.pps_device.is_empty() {
            return false;
        }
        let ok = self.env.path(&s.gps.pps_device).exists();
        if !ok {
            rep.warn(format!(
                "PPS device {} does not exist: using the GPS time without the pulse until it appears",
                s.gps.pps_device
            ));
        }
        ok
    }

    /// gpsd follows `ntp.gps.enabled`; the chrony.conf above already holds
    /// (or no longer holds) the refclock lines.
    fn gpsd(&self, s: &NtpSettings, rep: &mut ApplyReport) -> Result<()> {
        let managed = lan::is_managed(&self.env, GPSD_CONF);
        if !s.gps.enabled && !managed {
            return Ok(());
        }
        if s.gps.enabled && !self.env.has_binary(GPSD_BIN) {
            return Err(Error::Service(
                "the GPS reference clock needs gpsd but /usr/sbin/gpsd is not installed \
                 (emerge sci-geosciences/gpsd, USE=gps)"
                    .into(),
            ));
        }
        if !s.gps.enabled {
            if self.env.services.is_running(GPSD_SERVICE) {
                let _ = self.env.services.disable(GPSD_SERVICE);
                self.env.services.stop(GPSD_SERVICE)?;
            }
            rep.applied("GPS reference clock off (gpsd stopped)");
            return Ok(());
        }
        if !self.env.path(&s.gps.device).exists() && self.env.root == std::path::Path::new("/") {
            rep.warn(format!("GPS device {} does not exist (yet)", s.gps.device));
        }
        let changed = lan::install(
            &self.env,
            &ManagedFile {
                path: GPSD_CONF,
                content: render_gpsd(&s.gps),
                mode: 0o644,
                group: None,
                check: None,
            },
        )?;
        lan::reconcile(&self.env, GPSD_SERVICE, true, changed, GPSD_CONF, rep)?;
        rep.applied(format!(
            "GPS reference clock on {} @ {} baud{}",
            s.gps.device,
            s.gps.baud,
            if s.gps.pps_device.is_empty() {
                String::new()
            } else {
                format!(", PPS {}", s.gps.pps_device)
            }
        ));
        Ok(())
    }

    async fn allow(
        &self,
        store: &ConfigStore,
        s: &NtpSettings,
        rep: &mut ApplyReport,
    ) -> Result<Vec<String>> {
        let addrs = self.env.addrs()?;
        let mut nets = Vec::new();
        for spec in &s.interfaces {
            let devs = lan::resolve_iface(store, spec).await?;
            if devs.is_empty() {
                rep.warn(format!(
                    "NTP on {spec}: interface role is not assigned, skipped"
                ));
            }
            for a in addrs.iter().filter(|a| devs.contains(&a.ifname)) {
                if a.addr.is_ipv4() || a.is_global_v6() {
                    if let Some(n) = a.network() {
                        nets.push(n.to_string());
                    }
                }
            }
        }
        nets.sort();
        nets.dedup();
        Ok(nets)
    }
}

#[async_trait]
impl Applier for NtpApplier {
    fn name(&self) -> &'static str {
        "ntp"
    }

    fn phase(&self) -> Phase {
        Phase::Services
    }

    async fn apply(&self, store: &ConfigStore) -> Result<ApplyReport> {
        let mut rep = ApplyReport::default();
        let s = settings(store).await?;
        let managed = lan::is_managed(&self.env, CHRONY_CONF);
        if !s.enabled && !s.gps.enabled && !managed {
            rep.applied("NTP server disabled (chrony config untouched)");
            return Ok(rep);
        }
        if !self.env.has_binary(CHRONYD_BIN) {
            return Err(Error::Service(
                "the NTP server needs chrony but /usr/sbin/chronyd is not installed \
                 (emerge net-misc/chrony, USE=ntp)"
                    .into(),
            ));
        }
        let allow = self.allow(store, &s, &mut rep).await?;
        if s.enabled && allow.is_empty() {
            rep.warn("NTP server enabled but no served interface has an address");
        }
        let pps_ok = self.pps_ok(&s, &mut rep);
        let changed = lan::install(
            &self.env,
            &ManagedFile {
                path: CHRONY_CONF,
                content: render(&s, &allow, pps_ok),
                mode: 0o644,
                group: None,
                check: Some(vec![CHRONYD_BIN, "-p", "-f", "{}"]),
            },
        )?;
        if changed {
            rep.applied(format!("wrote {CHRONY_CONF}"));
        }
        lan::reconcile(&self.env, SERVICE, true, changed, CHRONY_CONF, &mut rep)?;
        self.gpsd(&s, &mut rep)?;
        rep.applied(format!(
            "NTP server {} ({} subnet(s))",
            if s.enabled { "on" } else { "off, client only" },
            allow.len()
        ));
        Ok(rep)
    }

    async fn render(&self, store: &ConfigStore) -> Result<String> {
        let mut rep = ApplyReport::default();
        let s = settings(store).await?;
        if !s.enabled && !s.gps.enabled {
            return Ok("# NTP server disabled\n".into());
        }
        let allow = self.allow(store, &s, &mut rep).await?;
        let pps_ok = self.pps_ok(&s, &mut rep);
        let mut out = format!(
            "## {CHRONY_CONF} (chronyd)\n{}",
            render(&s, &allow, pps_ok)
        );
        if s.gps.enabled {
            out.push_str(&format!("## {GPSD_CONF} (gpsd)\n{}", render_gpsd(&s.gps)));
        }
        Ok(out)
    }

    async fn status(&self, store: &ConfigStore) -> Result<Value> {
        let s = settings(store).await?;
        Ok(json!({
            "enabled": s.enabled,
            "available": self.env.has_binary(CHRONYD_BIN),
            "running": self.env.services.is_running(SERVICE),
            "gps": {
                "enabled": s.gps.enabled,
                "available": self.env.has_binary(GPSD_BIN),
                "running": self.env.services.is_running(GPSD_SERVICE),
                "device_present": self.env.path(&s.gps.device).exists(),
                "pps_present": !s.gps.pps_device.is_empty()
                    && self.env.path(&s.gps.pps_device).exists(),
            },
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lan::testutil::{self, read};
    use crate::lan::ServiceControl;

    #[tokio::test]
    async fn serves_lan_subnets_and_leaves_foreign_config_alone() {
        let t = testutil::env(&[CHRONYD_BIN]);
        let s = testutil::store().await;
        std::fs::create_dir_all(t.env.path("/etc/chrony")).unwrap();
        std::fs::write(t.env.path(CHRONY_CONF), "server my.own.server\n").unwrap();
        let a = NtpApplier::new(t.env.clone());
        a.apply(&s).await.unwrap();
        assert_eq!(read(&t, CHRONY_CONF), "server my.own.server\n");
        save_settings(
            &s,
            &NtpInput {
                enabled: Some(true),
                servers: Some("0.pool.ntp.org, 192.0.2.123".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        a.apply(&s).await.unwrap();
        let c = read(&t, CHRONY_CONF);
        for want in [
            "pool 0.pool.ntp.org iburst",
            "server 192.0.2.123 iburst",
            "allow 192.168.50.0/24",
            "allow fd00:50::/64",
            "local stratum 10",
        ] {
            assert!(c.contains(want), "missing {want:?} in\n{c}");
        }
        assert!(!c.contains("203.0.113"), "never serve the WAN");
        assert!(t.services.is_running(SERVICE));
        save_settings(
            &s,
            &NtpInput {
                enabled: Some(false),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        a.apply(&s).await.unwrap();
        let c = read(&t, CHRONY_CONF);
        assert!(!c.contains("allow ") && c.contains("pool 0.pool.ntp.org"));
        assert!(save_settings(
            &s,
            &NtpInput {
                servers: Some("bad_host".into()),
                ..Default::default()
            }
        )
        .await
        .is_err());
    }

    #[test]
    fn baud_may_arrive_as_a_string_from_the_page() {
        let i: NtpInput = serde_json::from_str(r#"{"gps_baud":"115200"}"#).unwrap();
        assert_eq!(i.gps_baud, Some(115200));
        let i: NtpInput = serde_json::from_str(r#"{"gps_baud":9600}"#).unwrap();
        assert_eq!(i.gps_baud, Some(9600));
        assert!(serde_json::from_str::<NtpInput>(r#"{"gps_baud":"fast"}"#).is_err());
        assert_eq!(serde_json::from_str::<NtpInput>("{}").unwrap().gps_baud, None);
    }

    #[test]
    fn acl_entries_are_validated() {
        assert_eq!(check_acl("192.0.2.7").unwrap(), "192.0.2.7");
        assert_eq!(check_acl("10.1.0.0/16").unwrap(), "10.1.0.0/16");
        assert_eq!(check_acl("2001:db8::/32").unwrap(), "2001:db8::/32");
        assert_eq!(check_acl("192.0.2.7/32").unwrap(), "192.0.2.7");
        for bad in [
            "0.0.0.0/0",
            "::/0",
            "10.0.0.0/33",
            "foo",
            "10.0.0.0/x",
            "all",
            "",
        ] {
            assert!(check_acl(bad).is_err(), "{bad:?} must be refused");
        }
    }

    #[test]
    fn device_names_are_validated() {
        for ok in [
            "/dev/ttyUSB0",
            "/dev/ttyAMA0",
            "/dev/serial/by-id/usb-u-blox_7-if00",
            "/dev/gps0",
        ] {
            assert!(check_gps_device(ok).is_ok(), "{ok}");
        }
        for bad in [
            "/dev/sda",
            "ttyUSB0",
            "/dev/tty",
            "/dev/ttyUSB0 -x",
            "/dev/../etc/passwd",
            "/dev/serial/by-id/../x",
            "/dev/tty\nx",
        ] {
            assert!(check_gps_device(bad).is_err(), "{bad:?}");
        }
        assert!(check_pps_device("/dev/pps0").is_ok());
        for bad in ["/dev/pps", "/dev/ppsx", "/dev/pps0;ls", "/dev/ttyS0"] {
            assert!(check_pps_device(bad).is_err(), "{bad:?}");
        }
    }

    #[tokio::test]
    async fn acl_and_gps_render_and_gpsd_follows() {
        let t = testutil::env(&[CHRONYD_BIN, GPSD_BIN]);
        let s = testutil::store().await;
        let a = NtpApplier::new(t.env.clone());
        // the pulse device is missing first: NMEA only, chronyd would not start otherwise
        std::fs::create_dir_all(t.env.path("/dev")).unwrap();
        save_settings(
            &s,
            &NtpInput {
                enabled: Some(true),
                acl_allow: Some("10.9.0.0/24, 10.9.0.0/24, 198.51.100.5".into()),
                acl_deny: Some("192.168.50.99".into()),
                ratelimit: Some(true),
                gps_enabled: Some(true),
                gps_device: Some("/dev/ttyUSB1".into()),
                gps_baud: Some(38400),
                gps_pps_device: Some("/dev/pps0".into()),
                gps_offset: Some(0.125),
                gps_prefer: Some(true),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let rep = a.apply(&s).await.unwrap();
        assert!(rep.warnings.iter().any(|w| w.contains("/dev/pps0")), "{:?}", rep.warnings);
        let c = read(&t, CHRONY_CONF);
        assert!(c.contains("refclock SHM 0 refid GPS") && !c.contains("refclock PPS"), "{c}");
        std::fs::write(t.env.path("/dev/pps0"), "").unwrap();
        a.apply(&s).await.unwrap();
        let c = read(&t, CHRONY_CONF);
        for want in [
            "allow 192.168.50.0/24",
            "allow 10.9.0.0/24\n",
            "allow 198.51.100.5\n",
            "deny 192.168.50.99\n",
            "ratelimit interval 3 burst 8 leak 2",
            "refclock SHM 0 refid NMEA offset 0.125 delay 0.2 poll 4 noselect",
            "refclock PPS /dev/pps0 refid PPS lock NMEA poll 4 prefer",
        ] {
            assert!(c.contains(want), "missing {want:?} in\n{c}");
        }
        assert_eq!(c.matches("allow 10.9.0.0/24").count(), 1, "deduplicated");
        assert!(c.find("allow 10.9").unwrap() < c.find("deny 192").unwrap());
        let g = read(&t, GPSD_CONF);
        assert!(g.contains("GPSD_OPTIONS=\"-n -s 38400\""), "{g}");
        assert!(g.contains("DEVICES=\"/dev/ttyUSB1 /dev/pps0\""), "{g}");
        assert!(t.services.is_running(GPSD_SERVICE));
        // explicit mode: only the explicit list is served; NMEA only without PPS
        save_settings(
            &s,
            &NtpInput {
                acl_mode: Some("explicit".into()),
                gps_pps_device: Some("".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        a.apply(&s).await.unwrap();
        let c = read(&t, CHRONY_CONF);
        assert!(
            !c.contains("192.168.50.0/24") && c.contains("allow 10.9.0.0/24"),
            "{c}"
        );
        assert!(
            c.contains("refclock SHM 0 refid GPS offset 0.125") && !c.contains("refclock PPS"),
            "{c}"
        );
        // GPS off: refclock lines gone, gpsd stopped
        save_settings(
            &s,
            &NtpInput {
                gps_enabled: Some(false),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        a.apply(&s).await.unwrap();
        assert!(!read(&t, CHRONY_CONF).contains("refclock"));
        assert!(!t.services.is_running(GPSD_SERVICE));
    }

    #[tokio::test]
    async fn gps_without_gpsd_installed_is_an_error_and_bad_input_is_refused() {
        let t = testutil::env(&[CHRONYD_BIN]);
        let s = testutil::store().await;
        let a = NtpApplier::new(t.env.clone());
        save_settings(
            &s,
            &NtpInput {
                gps_enabled: Some(true),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let e = a.apply(&s).await.unwrap_err().to_string();
        assert!(e.contains("gpsd"), "{e}");
        for i in [
            NtpInput {
                gps_baud: Some(1234),
                ..Default::default()
            },
            NtpInput {
                gps_offset: Some(5.0),
                ..Default::default()
            },
            NtpInput {
                gps_offset: Some(f64::NAN),
                ..Default::default()
            },
            NtpInput {
                acl_mode: Some("all".into()),
                ..Default::default()
            },
            NtpInput {
                acl_deny: Some("0.0.0.0/0".into()),
                ..Default::default()
            },
        ] {
            assert!(save_settings(&s, &i).await.is_err());
        }
    }
}
