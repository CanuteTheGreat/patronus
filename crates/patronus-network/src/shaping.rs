//! Traffic shaping (lane C, USE=qos): one root (egress) qdisc per interface
//! from the store's `qos_shapers`, applied with `tc` and re-applied at boot.
//!
//! - `cake`: CAKE at the given bandwidth (fair queueing per flow and host,
//!   fixes bufferbloat; needs sch_cake);
//! - `fq_codel`: fq_codel without a limit;
//! - `limit`: a token bucket filter capping the rate (plain rate limit).
//!
//! Traffic *leaving* the interface is shaped: put the shaper on the WAN to
//! shape upload, on the LAN to shape download. Devices Patronus shaped
//! earlier and that are no longer configured get their root qdisc removed
//! (tracked in `/var/lib/patronus/qos-devices`); qdiscs it did not create
//! are never touched.

use crate::lan::{self, check_description, db_err, invalid, now, LanEnv};
use async_trait::async_trait;
use patronus_config::applier::{Applier, ApplyReport, Phase};
use patronus_config::store::ConfigStore;
use patronus_core::{Error, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::Row;
use std::sync::Arc;

pub const MIN_KBIT: u32 = 64;
pub const MAX_KBIT: u32 = 100_000_000;
const TRACK_FILE: &str = "/var/lib/patronus/qos-devices";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Shaper {
    pub id: i64,
    pub interface: String,
    pub mode: String,
    pub rate_kbit: Option<u32>,
    pub enabled: bool,
    pub description: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ShaperInput {
    #[serde(default)]
    pub interface: Option<String>,
    #[serde(default)]
    pub mode: Option<String>,
    #[serde(default)]
    pub rate_kbit: Option<u32>,
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub description: Option<String>,
}

pub async fn list(store: &ConfigStore) -> Result<Vec<Shaper>> {
    let rows = sqlx::query(
        "SELECT id, interface, mode, rate_kbit, enabled, description FROM qos_shapers ORDER BY interface",
    )
    .fetch_all(store.pool()?)
    .await
    .map_err(db_err("read qos_shapers"))?;
    Ok(rows
        .iter()
        .map(|r| Shaper {
            id: r.get(0),
            interface: r.get(1),
            mode: r.get(2),
            rate_kbit: r.get::<Option<i64>, _>(3).map(|v| v as u32),
            enabled: r.get::<i64, _>(4) != 0,
            description: r.get(5),
        })
        .collect())
}

pub async fn save(store: &ConfigStore, id: Option<i64>, i: &ShaperInput) -> Result<i64> {
    let all = list(store).await?;
    let cur = match id {
        Some(id) => Some(
            all.iter()
                .find(|s| s.id == id)
                .cloned()
                .ok_or_else(|| Error::Config(format!("no shaper {id}")))?,
        ),
        None => None,
    };
    let interface = match (&i.interface, &cur) {
        (Some(n), _) => lan::check_iface_spec(n)?,
        (None, Some(c)) => c.interface.clone(),
        (None, None) => return Err(invalid("shaper: an interface is required")),
    };
    if all
        .iter()
        .any(|s| s.interface == interface && Some(s.id) != id)
    {
        return Err(invalid(format!("shaper: {interface} already has one")));
    }
    let mode = match (i.mode.as_deref(), &cur) {
        (Some(m @ ("cake" | "fq_codel" | "limit")), _) => m.to_string(),
        (Some(m), _) => return Err(invalid(format!("mode {m:?}: cake, fq_codel or limit"))),
        (None, Some(c)) => c.mode.clone(),
        (None, None) => {
            return Err(invalid(
                "shaper: a mode is required (cake, fq_codel, limit)",
            ))
        }
    };
    let rate = match (i.rate_kbit, &cur) {
        (Some(r), _) => Some(r),
        (None, Some(c)) if mode != "fq_codel" => c.rate_kbit,
        _ => None,
    };
    let rate = if mode == "fq_codel" { None } else { rate };
    if mode != "fq_codel" {
        match rate {
            None => return Err(invalid(format!("{mode}: a rate in kbit/s is required"))),
            Some(r) if !(MIN_KBIT..=MAX_KBIT).contains(&r) => {
                return Err(invalid(format!("rate: {MIN_KBIT}-{MAX_KBIT} kbit/s")))
            }
            _ => {}
        }
    }
    let description = match (&i.description, &cur) {
        (Some(d), _) => check_description(Some(d))?,
        (None, Some(c)) => c.description.clone(),
        (None, None) => None,
    };
    let enabled = i
        .enabled
        .or(cur.as_ref().map(|c| c.enabled))
        .unwrap_or(true);
    let sql = if id.is_some() {
        "UPDATE qos_shapers SET interface=?, mode=?, rate_kbit=?, enabled=?, description=?, updated_at=? WHERE id=?"
    } else {
        "INSERT INTO qos_shapers (interface, mode, rate_kbit, enabled, description, updated_at) VALUES (?,?,?,?,?,?)"
    };
    let mut q = sqlx::query(sql)
        .bind(&interface)
        .bind(&mode)
        .bind(rate.map(i64::from))
        .bind(enabled as i64)
        .bind(&description)
        .bind(now());
    if let Some(id) = id {
        q = q.bind(id);
    }
    let r = q
        .execute(store.pool()?)
        .await
        .map_err(|e| Error::Config(format!("save shaper: {e}")))?;
    Ok(id.unwrap_or_else(|| r.last_insert_rowid()))
}

pub async fn delete(store: &ConfigStore, id: i64) -> Result<()> {
    let r = sqlx::query("DELETE FROM qos_shapers WHERE id = ?")
        .bind(id)
        .execute(store.pool()?)
        .await
        .map_err(db_err("delete shaper"))?;
    if r.rows_affected() == 0 {
        return Err(Error::Config(format!("no shaper {id}")));
    }
    Ok(())
}

/// The `tc qdisc replace dev DEV root ...` arguments after `root`.
pub fn qdisc_args(mode: &str, rate_kbit: Option<u32>) -> Vec<String> {
    let rate = rate_kbit.unwrap_or(0);
    match mode {
        "cake" => vec!["cake".into(), "bandwidth".into(), format!("{rate}kbit")],
        "limit" => {
            // burst: 10 ms worth of the rate, never below 32 KiB
            let burst = (u64::from(rate) * 1000 / 8 / 100).max(32768);
            vec![
                "tbf".into(),
                "rate".into(),
                format!("{rate}kbit"),
                "burst".into(),
                burst.to_string(),
                "latency".into(),
                "50ms".into(),
            ]
        }
        _ => vec!["fq_codel".into()],
    }
}

/// Runs `tc` (a seam for tests).
pub trait Tc: Send + Sync {
    fn run(&self, args: &[String]) -> Result<String>;
}

pub struct SystemTc;

impl Tc for SystemTc {
    fn run(&self, args: &[String]) -> Result<String> {
        let o = std::process::Command::new("tc")
            .args(args)
            .output()
            .map_err(|e| Error::Network(format!("tc: {e} (emerge sys-apps/iproute2)")))?;
        if o.status.success() {
            Ok(String::from_utf8_lossy(&o.stdout).into_owned())
        } else {
            Err(Error::Network(format!(
                "`tc {}` failed: {}",
                args.join(" "),
                String::from_utf8_lossy(&o.stderr).trim()
            )))
        }
    }
}

/// The qdisc kind at the root of `dev` (`cake`, `tbf`, `fq_codel`, `noqueue`, ...).
pub fn root_kind(tc_show: &str) -> Option<String> {
    tc_show.lines().find_map(|l| {
        let mut w = l.split_whitespace();
        if w.next()? != "qdisc" {
            return None;
        }
        let kind = w.next()?;
        l.contains(" root").then(|| kind.to_string())
    })
}

#[derive(Clone)]
pub struct ShapingApplier {
    env: LanEnv,
    tc: Arc<dyn Tc>,
}

impl Default for ShapingApplier {
    fn default() -> Self {
        Self::new(LanEnv::system(), Arc::new(SystemTc))
    }
}

impl ShapingApplier {
    pub fn new(env: LanEnv, tc: Arc<dyn Tc>) -> Self {
        Self { env, tc }
    }

    fn live(&self) -> bool {
        self.env.root == std::path::Path::new("/")
    }

    async fn wanted(
        &self,
        store: &ConfigStore,
        rep: &mut ApplyReport,
    ) -> Result<Vec<(String, Shaper)>> {
        let mut v = Vec::new();
        for s in list(store).await?.into_iter().filter(|s| s.enabled) {
            let devs = lan::resolve_iface(store, &s.interface).await?;
            if devs.is_empty() {
                rep.warn(format!(
                    "shaper on {} skipped: not assigned to any interface",
                    s.interface
                ));
                continue;
            }
            for d in devs {
                v.push((d, s.clone()));
            }
        }
        Ok(v)
    }
}

#[async_trait]
impl Applier for ShapingApplier {
    fn name(&self) -> &'static str {
        "qos"
    }

    fn phase(&self) -> Phase {
        Phase::Services
    }

    async fn apply(&self, store: &ConfigStore) -> Result<ApplyReport> {
        let mut rep = ApplyReport::default();
        let want = self.wanted(store, &mut rep).await?;
        let prev: Vec<String> = std::fs::read_to_string(self.env.path(TRACK_FILE))
            .ok()
            .and_then(|t| serde_json::from_str(&t).ok())
            .unwrap_or_default();
        if want.is_empty() && prev.is_empty() {
            rep.applied("no traffic shaping configured (qdiscs untouched)");
            return Ok(rep);
        }
        let mut kept: Vec<String> = Vec::new();
        for dev in &prev {
            if !want.iter().any(|(d, _)| d == dev) && self.live() {
                let args: Vec<String> = ["qdisc", "del", "dev", dev, "root"]
                    .iter()
                    .map(|s| s.to_string())
                    .collect();
                match self.tc.run(&args) {
                    Ok(_) => rep.applied(format!("removed the shaper from {dev}")),
                    // device or qdisc already gone
                    Err(e)
                        if e.to_string().contains("Cannot find")
                            || e.to_string().contains("No such")
                            || e.to_string().contains("Cannot delete") => {}
                    Err(e) => {
                        rep.warn(e.to_string());
                        kept.push(dev.clone());
                    }
                }
            }
        }
        let mut failed = Vec::new();
        for (dev, s) in &want {
            if self.live() {
                let mut args: Vec<String> = ["qdisc", "replace", "dev", dev, "root"]
                    .iter()
                    .map(|s| s.to_string())
                    .collect();
                args.extend(qdisc_args(&s.mode, s.rate_kbit));
                match self.tc.run(&args) {
                    Ok(_) => rep.applied(format!(
                        "{dev}: {}{}",
                        s.mode,
                        s.rate_kbit
                            .map(|r| format!(" {r} kbit/s"))
                            .unwrap_or_default()
                    )),
                    Err(e) => {
                        failed.push(format!("{dev}: {e}"));
                        continue;
                    }
                }
            }
            kept.push(dev.clone());
        }
        let path = self.env.path(TRACK_FILE);
        if let Some(d) = path.parent() {
            let _ = std::fs::create_dir_all(d);
        }
        let _ = std::fs::write(&path, serde_json::to_string(&kept).unwrap_or_default());
        if !failed.is_empty() {
            return Err(Error::Network(format!(
                "traffic shaping could not be applied: {} (CAKE needs the sch_cake kernel module)",
                failed.join("; ")
            )));
        }
        Ok(rep)
    }

    async fn render(&self, store: &ConfigStore) -> Result<String> {
        let mut rep = ApplyReport::default();
        let want = self.wanted(store, &mut rep).await?;
        if want.is_empty() {
            return Ok("# no traffic shaping\n".into());
        }
        Ok(want
            .iter()
            .map(|(d, s)| {
                format!(
                    "tc qdisc replace dev {d} root {}\n",
                    qdisc_args(&s.mode, s.rate_kbit).join(" ")
                )
            })
            .collect())
    }

    /// `{shapers: [{dev, mode, rate_kbit, kernel: <root qdisc kind or null>, active}]}`
    async fn status(&self, store: &ConfigStore) -> Result<Value> {
        let mut rep = ApplyReport::default();
        let want = self.wanted(store, &mut rep).await?;
        let me = self.clone();
        Ok(tokio::task::spawn_blocking(move || {
            let rows: Vec<Value> = want
                .iter()
                .map(|(dev, s)| {
                    let kernel = me
                        .tc
                        .run(&["qdisc".into(), "show".into(), "dev".into(), dev.clone()])
                        .ok()
                        .and_then(|t| root_kind(&t));
                    let expect = match s.mode.as_str() {
                        "limit" => "tbf",
                        m => m,
                    };
                    json!({"dev": dev, "mode": s.mode, "rate_kbit": s.rate_kbit,
                           "kernel": kernel, "active": kernel.as_deref() == Some(expect)})
                })
                .collect();
            json!({"shapers": rows})
        })
        .await
        .unwrap_or(Value::Null))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lan::testutil;
    use std::sync::Mutex;

    #[derive(Default)]
    struct FakeTc {
        calls: Mutex<Vec<String>>,
        fail_cake: bool,
    }
    impl Tc for FakeTc {
        fn run(&self, a: &[String]) -> Result<String> {
            let line = a.join(" ");
            self.calls.lock().unwrap().push(line.clone());
            if self.fail_cake && line.contains("cake") {
                return Err(Error::Network("Unknown qdisc \"cake\"".into()));
            }
            Ok(String::new())
        }
    }

    #[test]
    fn qdisc_arguments_per_mode() {
        assert_eq!(
            qdisc_args("cake", Some(50_000)).join(" "),
            "cake bandwidth 50000kbit"
        );
        assert_eq!(qdisc_args("fq_codel", None).join(" "), "fq_codel");
        let l = qdisc_args("limit", Some(8000)).join(" ");
        assert_eq!(l, "tbf rate 8000kbit burst 32768 latency 50ms");
        // a fast link gets a bigger burst
        assert!(qdisc_args("limit", Some(1_000_000))
            .join(" ")
            .contains("burst 1250000 "));
    }

    #[test]
    fn root_qdisc_kind_is_read_from_tc_output() {
        let t = "qdisc tbf 8001: root refcnt 2 rate 8Mbit burst 32Kb lat 50ms\nqdisc ingress ffff: parent ffff:fff1 ----------------\n";
        assert_eq!(root_kind(t).as_deref(), Some("tbf"));
        assert_eq!(
            root_kind("qdisc noqueue 0: root refcnt 2 \n").as_deref(),
            Some("noqueue")
        );
        assert_eq!(root_kind(""), None);
    }

    #[tokio::test]
    async fn shapers_are_validated_stored_and_applied_with_tc() {
        let s = testutil::store().await;
        for (inp, why) in [
            (
                ShaperInput {
                    interface: Some("@wan".into()),
                    mode: Some("weird".into()),
                    ..Default::default()
                },
                "cake, fq_codel or limit",
            ),
            (
                ShaperInput {
                    interface: Some("@wan".into()),
                    mode: Some("cake".into()),
                    ..Default::default()
                },
                "rate in kbit/s is required",
            ),
            (
                ShaperInput {
                    interface: Some("@wan".into()),
                    mode: Some("limit".into()),
                    rate_kbit: Some(1),
                    ..Default::default()
                },
                "rate:",
            ),
            (
                ShaperInput {
                    mode: Some("cake".into()),
                    rate_kbit: Some(1000),
                    ..Default::default()
                },
                "interface is required",
            ),
        ] {
            let e = save(&s, None, &inp).await.unwrap_err().to_string();
            assert!(e.contains("Invalid") && e.contains(why), "{e}");
        }
        let id = save(
            &s,
            None,
            &ShaperInput {
                interface: Some("@wan".into()),
                mode: Some("limit".into()),
                rate_kbit: Some(8000),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert!(save(
            &s,
            None,
            &ShaperInput {
                interface: Some("@wan".into()),
                mode: Some("fq_codel".into()),
                ..Default::default()
            }
        )
        .await
        .unwrap_err()
        .to_string()
        .contains("already has one"));
        let t = testutil::env(&[]);
        let tc = Arc::new(FakeTc::default());
        let a = ShapingApplier::new(t.env.clone(), tc.clone());
        // a fake root is "dry": nothing is run, the plan is rendered
        let r = a.apply(&s).await.unwrap();
        assert!(tc.calls.lock().unwrap().is_empty(), "{r:?}");
        let render = a.render(&s).await.unwrap();
        assert_eq!(
            render,
            "tc qdisc replace dev rtr-wan root tbf rate 8000kbit burst 32768 latency 50ms\n"
        );
        assert_eq!(list(&s).await.unwrap()[0].rate_kbit, Some(8000));
        delete(&s, id).await.unwrap();
        assert!(delete(&s, id).await.is_err());
        assert_eq!(a.render(&s).await.unwrap(), "# no traffic shaping\n");
    }
}
