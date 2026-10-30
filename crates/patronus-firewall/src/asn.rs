//! ASN enrichment for the traffic insight (device segmentation, part d).
//!
//! DB-IP "IP to ASN Lite" (`dbip-asn-lite-YYYY-MM.csv.gz`, CC-BY 4.0, no
//! account or licence key; redistribution with attribution is allowed) lines
//! are `start,end,asn,"organisation"`. [`AsnDb`] keeps sorted ranges and
//! answers by binary search; [`Enricher`] pairs it with the country database
//! of [`crate::feeds::GeoDb`] so one lookup yields country + ASN. The refresh
//! code mirrors the country database's (same fetcher, same retry rules, same
//! `system_config` keys layout) and is run by patronus-web's feed task and by
//! the monthly `patronus ipdb update` job.

use crate::feeds::{self, check_url, feeds_dir, Fetcher, GeoDb};
use patronus_config::ConfigStore;
use patronus_core::{Error, Result};
use std::net::IpAddr;
use std::path::PathBuf;

const MAX_ASN_BYTES: u64 = 256 * 1024 * 1024;

pub const CFG_ASN_URL: &str = "insight.asn.db_url";
pub const CFG_ASN_DAYS: &str = "insight.asn.refresh_days";
pub const CFG_ASN_UPDATED: &str = "insight.asn.db_updated";
pub const CFG_ASN_ATTEMPT: &str = "insight.asn.db_attempt";
pub const CFG_ASN_STATUS: &str = "insight.asn.db_status";

/// The decompressed ASN database file.
pub fn asn_db_path() -> PathBuf {
    feeds_dir().join("dbip-asn-lite.csv")
}

/// DB-IP publishes `dbip-asn-lite-YYYY-MM.csv.gz` once a month: this month's
/// file first, last month's as the fallback (a new month's file appears a
/// day or so late).
pub fn default_asn_urls(now: i64) -> Vec<String> {
    feeds::default_geoip_urls(now)
        .into_iter()
        .map(|u| u.replace("dbip-country-lite-", "dbip-asn-lite-"))
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AsnInfo {
    pub asn: u32,
    pub org: String,
}

type V4 = (u32, u32, u32, u32); // start, end, asn, org index
type V6 = (u128, u128, u32, u32);

/// Parsed DB-IP ASN database.
#[derive(Debug, Default)]
pub struct AsnDb {
    v4: Vec<V4>,
    v6: Vec<V6>,
    orgs: Vec<String>,
}

/// One CSV line split at the commas that are outside double quotes.
fn csv_fields(line: &str) -> Vec<String> {
    let mut out = Vec::with_capacity(4);
    let mut cur = String::new();
    let mut quoted = false;
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '"' if quoted && chars.peek() == Some(&'"') => {
                cur.push('"');
                chars.next();
            }
            '"' => quoted = !quoted,
            ',' if !quoted => out.push(std::mem::take(&mut cur)),
            c => cur.push(c),
        }
    }
    out.push(cur);
    out
}

impl AsnDb {
    /// Parse `start,end,asn,org` lines. Rows with ASN 0 (unrouted space),
    /// reversed ranges and unparsable lines are skipped.
    pub fn parse(text: &str) -> AsnDb {
        let mut db = AsnDb::default();
        let mut org_ix: std::collections::HashMap<String, u32> = Default::default();
        for line in text.lines() {
            let f = csv_fields(line);
            if f.len() < 3 {
                continue;
            }
            let Ok(asn) = f[2].trim().trim_start_matches("AS").parse::<u32>() else {
                continue;
            };
            if asn == 0 {
                continue;
            }
            let org = f.get(3).map(|s| s.trim().to_string()).unwrap_or_default();
            let oi = *org_ix.entry(org.clone()).or_insert_with(|| {
                db.orgs.push(org);
                (db.orgs.len() - 1) as u32
            });
            match (f[0].trim().parse::<IpAddr>(), f[1].trim().parse::<IpAddr>()) {
                (Ok(IpAddr::V4(a)), Ok(IpAddr::V4(b))) if a <= b => {
                    db.v4.push((a.into(), b.into(), asn, oi))
                }
                (Ok(IpAddr::V6(a)), Ok(IpAddr::V6(b))) if a <= b => {
                    db.v6.push((a.into(), b.into(), asn, oi))
                }
                _ => {}
            }
        }
        db.v4.sort_unstable_by_key(|r| r.0);
        db.v6.sort_unstable_by_key(|r| r.0);
        db
    }

    pub fn len(&self) -> usize {
        self.v4.len() + self.v6.len()
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn lookup(&self, ip: IpAddr) -> Option<AsnInfo> {
        let (asn, oi) = match ip {
            IpAddr::V4(a) => {
                let x = u32::from(a);
                let i = self.v4.partition_point(|r| r.0 <= x);
                let r = self.v4.get(i.checked_sub(1)?)?;
                (x <= r.1).then_some((r.2, r.3))?
            }
            IpAddr::V6(a) => {
                let x = u128::from(a);
                let i = self.v6.partition_point(|r| r.0 <= x);
                let r = self.v6.get(i.checked_sub(1)?)?;
                (x <= r.1).then_some((r.2, r.3))?
            }
        };
        Some(AsnInfo {
            asn,
            org: self.orgs[oi as usize].clone(),
        })
    }
}

/// Country + ASN of an address.
#[derive(Debug, Default)]
pub struct Enricher {
    pub geo: Option<GeoDb>,
    pub asn: Option<AsnDb>,
    paths: Option<(PathBuf, PathBuf)>,
    geo_stamp: Option<std::time::SystemTime>,
    asn_stamp: Option<std::time::SystemTime>,
}

fn mtime(p: &std::path::Path) -> Option<std::time::SystemTime> {
    std::fs::metadata(p).and_then(|m| m.modified()).ok()
}

impl Enricher {
    pub fn new(geo: Option<GeoDb>, asn: Option<AsnDb>) -> Self {
        Self {
            geo,
            asn,
            paths: None,
            geo_stamp: None,
            asn_stamp: None,
        }
    }

    /// Load both databases from the feeds directory.
    pub fn load() -> Self {
        Self::load_from(feeds::geoip_db_path(), asn_db_path())
    }

    /// Load from explicit files (tests, `PATRONUS_FEEDS_DIR` aside).
    pub fn load_from(geo: PathBuf, asn: PathBuf) -> Self {
        let mut e = Self {
            paths: Some((geo, asn)),
            ..Self::default()
        };
        e.reload_if_changed();
        e
    }

    /// Re-read a database whose file changed since it was last loaded (the
    /// monthly refresh replaces the files while the collector runs).
    pub fn reload_if_changed(&mut self) -> bool {
        let mut changed = false;
        let (gp, ap) = self
            .paths
            .clone()
            .unwrap_or_else(|| (feeds::geoip_db_path(), asn_db_path()));
        let gm = mtime(&gp);
        if gm != self.geo_stamp {
            self.geo = std::fs::read(&gp)
                .ok()
                .map(|b| GeoDb::parse(&String::from_utf8_lossy(&b)));
            self.geo_stamp = gm;
            changed = true;
        }
        let am = mtime(&ap);
        if am != self.asn_stamp {
            self.asn = std::fs::read(&ap)
                .ok()
                .map(|b| AsnDb::parse(&String::from_utf8_lossy(&b)));
            self.asn_stamp = am;
            changed = true;
        }
        changed
    }

    /// `(country code or "--", asn or 0, organisation)`.
    pub fn lookup(&self, ip: IpAddr) -> (String, u32, String) {
        let cc = self
            .geo
            .as_ref()
            .and_then(|g| g.lookup(ip))
            .unwrap_or_else(|| "--".into());
        match self.asn.as_ref().and_then(|a| a.lookup(ip)) {
            Some(a) => (cc, a.asn, a.org),
            None => (cc, 0, String::new()),
        }
    }
}

// ---------------------------------------------------------------------
// settings and refresh
// ---------------------------------------------------------------------

#[derive(Debug, Clone, serde::Serialize, PartialEq)]
pub struct AsnDbStatus {
    /// Empty = the DB-IP monthly download.
    pub db_url: String,
    pub refresh_days: u64,
    pub updated: Option<i64>,
    pub attempt: Option<i64>,
    pub status: String,
    pub present: bool,
    pub size_bytes: u64,
}

pub async fn asn_status(store: &ConfigStore) -> Result<AsnDbStatus> {
    asn_status_at(store, &asn_db_path()).await
}

pub async fn asn_status_at(store: &ConfigStore, p: &std::path::Path) -> Result<AsnDbStatus> {
    let meta = std::fs::metadata(p).ok();
    let get = |k: &'static str| async move { store.load_system_config(k).await };
    Ok(AsnDbStatus {
        db_url: get(CFG_ASN_URL).await?.unwrap_or_default(),
        refresh_days: get(CFG_ASN_DAYS)
            .await?
            .and_then(|v| v.parse().ok())
            .unwrap_or(30),
        updated: get(CFG_ASN_UPDATED).await?.and_then(|v| v.parse().ok()),
        attempt: get(CFG_ASN_ATTEMPT).await?.and_then(|v| v.parse().ok()),
        status: get(CFG_ASN_STATUS)
            .await?
            .unwrap_or_else(|| "not downloaded yet".into()),
        present: meta.is_some(),
        size_bytes: meta.map(|m| m.len()).unwrap_or(0),
    })
}

/// Save the ASN database URL (empty = DB-IP) and refresh interval.
pub async fn set_asn_config(store: &ConfigStore, db_url: &str, refresh_days: u64) -> Result<()> {
    let u = db_url.trim();
    if !u.is_empty() {
        check_url(u)?;
    }
    if !(1..=365).contains(&refresh_days) {
        return Err(Error::Config(
            "Invalid request: refresh: 1 to 365 days".into(),
        ));
    }
    store.save_system_config(CFG_ASN_URL, u).await?;
    store
        .save_system_config(CFG_ASN_DAYS, &refresh_days.to_string())
        .await
}

/// Download (if due or `force`d) the ASN database into [`asn_db_path`].
/// Returns whether a new file was written. A failed download keeps the old
/// file and is retried after 15 minutes.
pub async fn refresh_asn_db(
    store: &ConfigStore,
    fetcher: &dyn Fetcher,
    force: bool,
    now: i64,
) -> Result<bool> {
    refresh_asn_db_to(store, fetcher, force, now, &asn_db_path()).await
}

/// [`refresh_asn_db`] writing to an explicit file.
pub async fn refresh_asn_db_to(
    store: &ConfigStore,
    fetcher: &dyn Fetcher,
    force: bool,
    now: i64,
    p: &std::path::Path,
) -> Result<bool> {
    let st = asn_status_at(store, p).await?;
    let fresh = st.present
        && st
            .updated
            .map(|u| now - u < (st.refresh_days * 86_400) as i64)
            .unwrap_or(false);
    let recently_failed = st
        .attempt
        .map(|a| now - a < 900 && st.updated.map(|u| u < a).unwrap_or(true))
        .unwrap_or(false);
    if !force && (fresh || recently_failed) {
        return Ok(false);
    }
    let urls = if st.db_url.is_empty() {
        default_asn_urls(now)
    } else {
        vec![st.db_url.clone()]
    };
    store
        .save_system_config(CFG_ASN_ATTEMPT, &now.to_string())
        .await?;
    let mut last_err = String::new();
    for u in urls {
        match fetcher.fetch(&u, MAX_ASN_BYTES).await {
            Ok(bytes) => {
                let db = AsnDb::parse(&String::from_utf8_lossy(&bytes));
                if db.len() < 10 {
                    last_err = format!("{u}: not a DB-IP ASN database ({} usable rows)", db.len());
                    continue;
                }
                let dir = p.parent().map(|d| d.to_path_buf()).unwrap_or_default();
                std::fs::create_dir_all(&dir)
                    .map_err(|e| Error::Config(format!("create {}: {e}", dir.display())))?;
                let tmp = dir.join(".dbip-asn.tmp");
                std::fs::write(&tmp, &bytes)
                    .and_then(|_| std::fs::rename(&tmp, p))
                    .map_err(|e| Error::Config(format!("write {}: {e}", p.display())))?;
                store
                    .save_system_config(CFG_ASN_UPDATED, &now.to_string())
                    .await?;
                store
                    .save_system_config(
                        CFG_ASN_STATUS,
                        &format!("ok: {} ranges from {u}", db.len()),
                    )
                    .await?;
                return Ok(true);
            }
            Err(e) => last_err = format!("{u}: {e}"),
        }
    }
    store
        .save_system_config(CFG_ASN_STATUS, &format!("error: {last_err}"))
        .await?;
    Err(Error::Config(format!("ASN database: {last_err}")))
}

/// Refresh both lookup databases when due (`force` = now). Returns one line
/// per database. Used by the web feed task and `patronus ipdb update`.
pub async fn refresh_ip_databases(
    store: &ConfigStore,
    fetcher: &dyn Fetcher,
    force: bool,
    now: i64,
) -> Vec<(String, std::result::Result<bool, String>)> {
    vec![
        (
            "country".to_string(),
            feeds::refresh_geoip_db(store, fetcher, force, now)
                .await
                .map_err(|e| e.to_string()),
        ),
        (
            "asn".to_string(),
            refresh_asn_db(store, fetcher, force, now)
                .await
                .map_err(|e| e.to_string()),
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;

    const ASN_CSV: &str = "\
\"1.0.0.0\",\"1.0.0.255\",\"13335\",\"CLOUDFLARENET\"
1.0.1.0,1.0.3.255,56203,\"Gtelecom, Pty Ltd\"
8.8.8.0,8.8.8.255,15169,GOOGLE
9.9.9.0,9.9.9.255,0,Unrouted
2001:db8::,2001:db8:ffff:ffff:ffff:ffff:ffff:ffff,64496,\"Doc \"\"Net\"\"\"
5.5.5.9,5.5.5.1,1,reversed range
garbage line
";

    #[test]
    fn parse_handles_quotes_commas_v6_and_skips_junk() {
        let db = AsnDb::parse(ASN_CSV);
        assert_eq!(
            db.len(),
            4,
            "unrouted (asn 0), reversed and junk rows are skipped"
        );
        let a = db.lookup("1.0.2.7".parse().unwrap()).unwrap();
        assert_eq!((a.asn, a.org.as_str()), (56203, "Gtelecom, Pty Ltd"));
        let d = db.lookup("2001:db8::1".parse().unwrap()).unwrap();
        assert_eq!((d.asn, d.org.as_str()), (64496, "Doc \"Net\""));
    }

    #[test]
    fn lookup_range_edges() {
        let db = AsnDb::parse(ASN_CSV);
        let at = |s: &str| db.lookup(s.parse().unwrap()).map(|a| a.asn);
        assert_eq!(at("1.0.0.0"), Some(13335), "first address");
        assert_eq!(at("1.0.0.255"), Some(13335), "last address");
        assert_eq!(at("1.0.1.0"), Some(56203), "next range starts right after");
        assert_eq!(at("0.255.255.255"), None, "before the first range");
        assert_eq!(at("1.0.4.0"), None, "after the last range, in the gap");
        assert_eq!(at("9.9.9.9"), None, "asn 0 rows are not data");
        assert_eq!(at("255.255.255.255"), None);
        assert_eq!(at("2001:db8:ffff:ffff:ffff:ffff:ffff:ffff"), Some(64496));
        assert_eq!(at("2001:db9::"), None);
        assert_eq!(at("::1"), None);
    }

    #[test]
    fn unsorted_input_is_sorted_before_searching() {
        let db = AsnDb::parse("8.8.8.0,8.8.8.255,15169,G\n1.0.0.0,1.0.0.255,13335,C\n");
        assert_eq!(db.lookup("1.0.0.5".parse().unwrap()).unwrap().asn, 13335);
        assert_eq!(db.lookup("8.8.8.8".parse().unwrap()).unwrap().asn, 15169);
    }

    #[test]
    fn enricher_gives_country_and_asn_and_dashes_for_unknown() {
        let geo = GeoDb::parse("1.0.0.0,1.0.0.255,AU\n8.8.8.0,8.8.8.255,US\n");
        let e = Enricher::new(Some(geo), Some(AsnDb::parse(ASN_CSV)));
        assert_eq!(
            e.lookup("8.8.8.8".parse().unwrap()),
            ("US".into(), 15169, "GOOGLE".into())
        );
        assert_eq!(
            e.lookup("1.0.2.1".parse().unwrap()),
            ("--".into(), 56203, "Gtelecom, Pty Ltd".into()),
            "asn known, country not"
        );
        assert_eq!(
            e.lookup("7.7.7.7".parse().unwrap()),
            ("--".into(), 0, String::new())
        );
        assert_eq!(Enricher::default().lookup("8.8.8.8".parse().unwrap()).1, 0);
    }

    #[test]
    fn default_urls_are_this_and_last_month() {
        // 2026-01-15 -> January and December of the year before
        let u = default_asn_urls(1_768_435_200);
        assert_eq!(
            u,
            vec![
                "https://download.db-ip.com/free/dbip-asn-lite-2026-01.csv.gz",
                "https://download.db-ip.com/free/dbip-asn-lite-2025-12.csv.gz"
            ]
        );
    }

    struct MapFetcher(Mutex<HashMap<String, Vec<u8>>>, Mutex<Vec<String>>);
    #[async_trait::async_trait]
    impl Fetcher for MapFetcher {
        async fn fetch(&self, url: &str, _max: u64) -> Result<Vec<u8>> {
            self.1.lock().unwrap().push(url.to_string());
            self.0
                .lock()
                .unwrap()
                .get(url)
                .cloned()
                .ok_or_else(|| Error::Config("HTTP 404".into()))
        }
    }

    fn big_csv() -> Vec<u8> {
        (0..20)
            .map(|i| format!("10.{i}.0.0,10.{i}.0.255,{},Org{i}\n", 64000 + i))
            .collect::<String>()
            .into_bytes()
    }

    #[tokio::test]
    async fn refresh_falls_back_to_last_month_retries_and_replaces_file() {
        let dir = tempfile::tempdir().unwrap();
        let asn_file = dir.path().join("asn.csv");
        let geo_file = dir.path().join("geo.csv");
        let store = ConfigStore::open(dir.path().join("c.db").to_str().unwrap())
            .await
            .unwrap();
        let now = 1_768_435_200; // 2026-01-15
        let urls = default_asn_urls(now);
        // this month 404, last month OK
        let f = MapFetcher(
            Mutex::new([(urls[1].clone(), big_csv())].into()),
            Mutex::new(vec![]),
        );
        assert!(refresh_asn_db_to(&store, &f, false, now, &asn_file)
            .await
            .unwrap());
        assert_eq!(f.1.lock().unwrap().len(), 2, "tried this month, then last");
        let st = asn_status_at(&store, &asn_file).await.unwrap();
        assert!(
            st.present && st.status.starts_with("ok: 20 ranges"),
            "{st:?}"
        );
        assert_eq!(st.updated, Some(now));
        // fresh: no second download
        assert!(!refresh_asn_db_to(&store, &f, false, now + 100, &asn_file)
            .await
            .unwrap());
        assert_eq!(f.1.lock().unwrap().len(), 2);
        // forced with garbage: error recorded, old file kept
        let bad = MapFetcher(
            Mutex::new(
                [
                    (urls[0].clone(), b"nope".to_vec()),
                    (urls[1].clone(), b"nope".to_vec()),
                ]
                .into(),
            ),
            Mutex::new(vec![]),
        );
        let later = now + 40 * 86_400;
        assert!(refresh_asn_db_to(&store, &bad, true, later, &asn_file)
            .await
            .is_err());
        let st = asn_status_at(&store, &asn_file).await.unwrap();
        assert!(st.status.starts_with("error:"), "{}", st.status);
        assert_eq!(st.updated, Some(now), "a failed download is not an update");
        assert!(AsnDb::parse(&std::fs::read_to_string(&asn_file).unwrap()).len() == 20);
        // due again after refresh_days, but a recent failure is not hammered
        assert!(
            !refresh_asn_db_to(&store, &bad, false, later + 60, &asn_file)
                .await
                .unwrap()
        );
        // the enricher loads the file and reloads when it changes
        let mut e = Enricher::load_from(geo_file.clone(), asn_file.clone());
        assert_eq!(e.lookup("10.3.0.9".parse().unwrap()).1, 64003);
        assert!(!e.reload_if_changed());
        std::fs::write(&asn_file, "10.3.0.0,10.3.0.255,65001,New\n").unwrap();
        // make sure mtime differs even on coarse filesystems
        let t = std::time::SystemTime::now() + std::time::Duration::from_secs(5);
        std::fs::File::options()
            .write(true)
            .open(&asn_file)
            .unwrap()
            .set_modified(t)
            .unwrap();
        assert!(e.reload_if_changed());
        assert_eq!(e.lookup("10.3.0.9".parse().unwrap()).1, 65001);
    }

    #[tokio::test]
    async fn config_validation() {
        let dir = tempfile::tempdir().unwrap();
        let store = ConfigStore::open(dir.path().join("c.db").to_str().unwrap())
            .await
            .unwrap();
        assert!(set_asn_config(&store, "ftp://x", 30).await.is_err());
        assert!(set_asn_config(&store, "", 0).await.is_err());
        assert!(set_asn_config(&store, "", 366).await.is_err());
        set_asn_config(&store, "https://mirror.example/asn.csv.gz", 7)
            .await
            .unwrap();
        let st = asn_status(&store).await.unwrap();
        assert_eq!(
            (st.db_url.as_str(), st.refresh_days),
            ("https://mirror.example/asn.csv.gz", 7)
        );
    }
}
