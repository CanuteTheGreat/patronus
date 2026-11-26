//! IDS alert history (USE=intrusion-detection): Suricata's `eve.json` alerts copied into the
//! `ids_alerts` table (root task; the web UI reads the table), with retention, and the queries of
//! the alert browser: filter by time / source / destination / SID / text / action, top talkers,
//! and the dashboard summary. `ids_alerts` and `ids_alert_pos` are in `NON_CONFIG_TABLES`: a
//! backup, export or rollback neither carries nor rewinds them.
//!
//! Retention is two typed settings (`ids.alert_retention_days`, `ids.alert_max_rows`) enforced by
//! [`prune`] on every collector pass, so the table cannot grow without bound.

use crate::lan::{db_err, invalid, now};
use patronus_config::store::ConfigStore;
use patronus_core::Result;
use serde_json::{json, Value};
use sqlx::Row;
use std::io::{Read, Seek, SeekFrom};
use std::os::unix::fs::MetadataExt;
use std::path::Path;

/// Most eve.json bytes read in one pass.
const CHUNK: u64 = 4 * 1024 * 1024;

fn eve_time(s: &str) -> Option<i64> {
    // 2026-11-25T17:13:00.123456+0000
    chrono::DateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S%.f%z")
        .ok()
        .map(|d| d.timestamp())
}

/// Copy new alerts of `eve` into the table; returns how many were stored.
pub async fn ingest(store: &ConfigStore, eve: &Path) -> Result<usize> {
    let pool = store.pool()?;
    let Ok(md) = std::fs::metadata(eve) else {
        return Ok(0);
    };
    let (ino, len) = (md.ino() as i64, md.len());
    let (mut pos_ino, mut pos): (i64, i64) =
        sqlx::query("SELECT inode, offset FROM ids_alert_pos WHERE id = 1")
            .fetch_optional(pool)
            .await
            .map_err(db_err("read ids_alert_pos"))?
            .map(|r| (r.get(0), r.get(1)))
            .unwrap_or((ino, 0));
    if pos_ino != ino || (pos as u64) > len {
        // rotated or truncated: start at the top of the new file
        pos_ino = ino;
        pos = 0;
    }
    if (pos as u64) == len {
        save_pos(store, pos_ino, pos).await?;
        return Ok(0);
    }
    let mut f = std::fs::File::open(eve)
        .map_err(|e| patronus_core::Error::Service(format!("{}: {e}", eve.display())))?;
    f.seek(SeekFrom::Start(pos as u64))
        .map_err(|e| patronus_core::Error::Service(format!("seek: {e}")))?;
    let mut buf = Vec::new();
    f.take(CHUNK)
        .read_to_end(&mut buf)
        .map_err(|e| patronus_core::Error::Service(format!("read: {e}")))?;
    // only whole lines: a half-written last line is read next time
    let end = buf
        .iter()
        .rposition(|b| *b == b'\n')
        .map(|i| i + 1)
        .unwrap_or(0);
    let text = String::from_utf8_lossy(&buf[..end]);
    let mut tx = pool.begin().await.map_err(db_err("begin"))?;
    let mut n = 0;
    for l in text.lines() {
        if !l.contains("\"alert\"") {
            continue;
        }
        let Ok(j) = serde_json::from_str::<Value>(l) else {
            continue;
        };
        if j["event_type"] != "alert" {
            continue;
        }
        let ts = j["timestamp"]
            .as_str()
            .and_then(eve_time)
            .unwrap_or_else(now);
        let a = &j["alert"];
        sqlx::query(
            "INSERT INTO ids_alerts (ts, src_ip, src_port, dst_ip, dst_port, proto, sid, rev, signature, category, severity, action, iface) \
             VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
        )
        .bind(ts)
        .bind(j["src_ip"].as_str().unwrap_or(""))
        .bind(j["src_port"].as_i64())
        .bind(j["dest_ip"].as_str().unwrap_or(""))
        .bind(j["dest_port"].as_i64())
        .bind(j["proto"].as_str().unwrap_or(""))
        .bind(a["signature_id"].as_i64().unwrap_or(0))
        .bind(a["rev"].as_i64().unwrap_or(0))
        .bind(a["signature"].as_str().unwrap_or(""))
        .bind(a["category"].as_str().unwrap_or(""))
        .bind(a["severity"].as_i64().unwrap_or(3))
        .bind(a["action"].as_str().unwrap_or("allowed"))
        .bind(j["in_iface"].as_str().unwrap_or(""))
        .execute(&mut *tx)
        .await
        .map_err(db_err("store alert"))?;
        n += 1;
    }
    tx.commit().await.map_err(db_err("commit"))?;
    save_pos(store, pos_ino, pos + end as i64).await?;
    Ok(n)
}

async fn save_pos(store: &ConfigStore, ino: i64, off: i64) -> Result<()> {
    sqlx::query(
        "INSERT INTO ids_alert_pos (id, inode, offset) VALUES (1, ?, ?) \
         ON CONFLICT(id) DO UPDATE SET inode = excluded.inode, offset = excluded.offset",
    )
    .bind(ino)
    .bind(off)
    .execute(store.pool()?)
    .await
    .map_err(db_err("write ids_alert_pos"))?;
    Ok(())
}

/// Retention: drop alerts older than `days`, then the oldest beyond `max_rows`.
pub async fn prune(store: &ConfigStore, days: i64, max_rows: i64) -> Result<u64> {
    let pool = store.pool()?;
    let a = sqlx::query("DELETE FROM ids_alerts WHERE ts < ?")
        .bind(now() - days.max(1) * 86_400)
        .execute(pool)
        .await
        .map_err(db_err("prune alerts"))?
        .rows_affected();
    let b = sqlx::query(
        "DELETE FROM ids_alerts WHERE id <= (SELECT id FROM ids_alerts ORDER BY id DESC LIMIT 1 OFFSET ?)",
    )
    .bind(max_rows.max(1000))
    .execute(pool)
    .await
    .map_err(db_err("prune alerts"))?
    .rows_affected();
    Ok(a + b)
}

#[derive(Debug, Default, Clone)]
pub struct Filter {
    pub from: Option<i64>,
    pub to: Option<i64>,
    /// An address or an address/prefix.
    pub src: Option<String>,
    pub dst: Option<String>,
    pub sid: Option<i64>,
    /// Text in the signature or category.
    pub q: Option<String>,
    /// allowed | blocked
    pub action: Option<String>,
    pub limit: i64,
    pub offset: i64,
}

enum Bind {
    I(i64),
    S(String),
}

fn with_binds<'q>(
    sql: &'q str,
    binds: &'q [Bind],
) -> sqlx::query::Query<'q, sqlx::Sqlite, sqlx::sqlite::SqliteArguments<'q>> {
    let mut q = sqlx::query(sql);
    for b in binds {
        q = match b {
            Bind::I(v) => q.bind(*v),
            Bind::S(s) => q.bind(s.as_str()),
        };
    }
    q
}

enum Ip {
    One(String),
    Net(ipnetwork::IpNetwork),
}

fn parse_ip(s: &Option<String>, what: &str) -> Result<Option<Ip>> {
    let Some(s) = s.as_deref().map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(None);
    };
    if let Ok(a) = s.parse::<std::net::IpAddr>() {
        return Ok(Some(Ip::One(a.to_string())));
    }
    s.parse::<ipnetwork::IpNetwork>()
        .map(|n| Some(Ip::Net(n)))
        .map_err(|_| {
            invalid(format!(
                "{what} filter {s:?} (an address or address/prefix)"
            ))
        })
}

fn net_has(n: &ipnetwork::IpNetwork, ip: &str) -> bool {
    ip.parse::<std::net::IpAddr>()
        .map(|a| n.contains(a))
        .unwrap_or(false)
}

fn row_json(r: &sqlx::sqlite::SqliteRow) -> Value {
    json!({
        "id": r.get::<i64, _>(0), "time": r.get::<i64, _>(1),
        "src_ip": r.get::<String, _>(2), "src_port": r.get::<Option<i64>, _>(3),
        "dst_ip": r.get::<String, _>(4), "dst_port": r.get::<Option<i64>, _>(5),
        "proto": r.get::<String, _>(6), "sid": r.get::<i64, _>(7), "rev": r.get::<i64, _>(8),
        "signature": r.get::<String, _>(9), "category": r.get::<String, _>(10),
        "severity": r.get::<i64, _>(11), "action": r.get::<String, _>(12), "iface": r.get::<String, _>(13),
    })
}

const COLS: &str = "id, ts, src_ip, src_port, dst_ip, dst_port, proto, sid, rev, signature, category, severity, action, iface";
/// Rows looked at when a prefix filter has to be applied in code.
const SCAN_CAP: i64 = 50_000;

/// (matching alerts in total, the page asked for), newest first.
pub async fn query(store: &ConfigStore, f: &Filter) -> Result<(i64, Vec<Value>)> {
    let src = parse_ip(&f.src, "source")?;
    let dst = parse_ip(&f.dst, "destination")?;
    if let Some(a) = &f.action {
        if !matches!(a.as_str(), "allowed" | "blocked") {
            return Err(invalid("action filter (allowed or blocked)"));
        }
    }
    let mut w = vec!["1=1".to_string()];
    if f.from.is_some() {
        w.push("ts >= ?".into());
    }
    if f.to.is_some() {
        w.push("ts <= ?".into());
    }
    if f.sid.is_some() {
        w.push("sid = ?".into());
    }
    if f.q.as_deref().is_some_and(|q| !q.is_empty()) {
        w.push("(signature LIKE ? ESCAPE '\\' OR category LIKE ? ESCAPE '\\')".into());
    }
    if f.action.is_some() {
        w.push("action = ?".into());
    }
    if let Some(Ip::One(_)) = &src {
        w.push("src_ip = ?".into());
    }
    if let Some(Ip::One(_)) = &dst {
        w.push("dst_ip = ?".into());
    }
    let wh = w.join(" AND ");
    let mut binds: Vec<Bind> = Vec::new();
    if let Some(v) = f.from {
        binds.push(Bind::I(v));
    }
    if let Some(v) = f.to {
        binds.push(Bind::I(v));
    }
    if let Some(v) = f.sid {
        binds.push(Bind::I(v));
    }
    if let Some(t) = f.q.as_deref().filter(|q| !q.is_empty()) {
        let like = format!(
            "%{}%",
            t.replace('\\', "\\\\")
                .replace('%', "\\%")
                .replace('_', "\\_")
        );
        binds.push(Bind::S(like.clone()));
        binds.push(Bind::S(like));
    }
    if let Some(a) = &f.action {
        binds.push(Bind::S(a.clone()));
    }
    if let Some(Ip::One(a)) = &src {
        binds.push(Bind::S(a.clone()));
    }
    if let Some(Ip::One(a)) = &dst {
        binds.push(Bind::S(a.clone()));
    }
    let pool = store.pool()?;
    let limit = f.limit.clamp(1, 1000);
    let offset = f.offset.max(0);
    let nets = matches!(src, Some(Ip::Net(_))) || matches!(dst, Some(Ip::Net(_)));
    if !nets {
        let sql = format!("SELECT COUNT(*) FROM ids_alerts WHERE {wh}");
        let total: i64 = with_binds(&sql, &binds)
            .fetch_one(pool)
            .await
            .map_err(db_err("count alerts"))?
            .get(0);
        let sql = format!(
            "SELECT {COLS} FROM ids_alerts WHERE {wh} ORDER BY ts DESC, id DESC LIMIT {limit} OFFSET {offset}"
        );
        let rows = with_binds(&sql, &binds)
            .fetch_all(pool)
            .await
            .map_err(db_err("read alerts"))?;
        return Ok((total, rows.iter().map(row_json).collect()));
    }
    let sql = format!(
        "SELECT {COLS} FROM ids_alerts WHERE {wh} ORDER BY ts DESC, id DESC LIMIT {SCAN_CAP}"
    );
    let rows = with_binds(&sql, &binds)
        .fetch_all(pool)
        .await
        .map_err(db_err("read alerts"))?;
    let keep: Vec<Value> = rows
        .iter()
        .filter(|r| {
            let ok = |ip: &Option<Ip>, col: usize| match ip {
                Some(Ip::Net(n)) => net_has(n, &r.get::<String, _>(col)),
                _ => true,
            };
            ok(&src, 2) && ok(&dst, 4)
        })
        .map(row_json)
        .collect();
    let total = keep.len() as i64;
    Ok((
        total,
        keep.into_iter()
            .skip(offset as usize)
            .take(limit as usize)
            .collect(),
    ))
}

/// Top talkers: `by` = src | dst | sid, within the time range.
pub async fn top(
    store: &ConfigStore,
    by: &str,
    from: Option<i64>,
    to: Option<i64>,
    limit: i64,
) -> Result<Vec<Value>> {
    let (key, extra) = match by {
        "src" => ("src_ip", "src_ip AS k, '' AS label"),
        "dst" => ("dst_ip", "dst_ip AS k, '' AS label"),
        "sid" => ("sid", "CAST(sid AS TEXT) AS k, MAX(signature) AS label"),
        _ => return Err(invalid("top list (src, dst or sid)")),
    };
    let sql = format!(
        "SELECT {extra}, COUNT(*) AS n, SUM(action = 'blocked') AS blocked, MAX(ts) AS last \
         FROM ids_alerts WHERE ts >= ? AND ts <= ? GROUP BY {key} ORDER BY n DESC, last DESC LIMIT ?"
    );
    let rows = sqlx::query(&sql)
        .bind(from.unwrap_or(0))
        .bind(to.unwrap_or(i64::MAX))
        .bind(limit.clamp(1, 100))
        .fetch_all(store.pool()?)
        .await
        .map_err(db_err("top alerts"))?;
    Ok(rows
        .iter()
        .map(|r| {
            json!({"key": r.get::<String, _>(0), "label": r.get::<String, _>(1), "count": r.get::<i64, _>(2),
                   "blocked": r.get::<Option<i64>, _>(3).unwrap_or(0), "last": r.get::<i64, _>(4)})
        })
        .collect())
}

/// Dashboard numbers: alerts and blocks in the last 24 h plus the top three rules and sources.
pub async fn summary(store: &ConfigStore) -> Result<Value> {
    let since = now() - 86_400;
    let r = sqlx::query(
        "SELECT COUNT(*), COALESCE(SUM(action = 'blocked'), 0) FROM ids_alerts WHERE ts >= ?",
    )
    .bind(since)
    .fetch_one(store.pool()?)
    .await
    .map_err(db_err("alert summary"))?;
    Ok(json!({
        "alerts_24h": r.get::<i64, _>(0),
        "blocked_24h": r.get::<i64, _>(1),
        "top_rules": top(store, "sid", Some(since), None, 3).await?,
        "top_sources": top(store, "src", Some(since), None, 3).await?,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn eve_line(ts: &str, sid: i64, src: &str, dst: &str, action: &str) -> String {
        format!(
            "{{\"timestamp\":\"{ts}\",\"event_type\":\"alert\",\"in_iface\":\"eth0\",\"src_ip\":\"{src}\",\"src_port\":1234,\"dest_ip\":\"{dst}\",\"dest_port\":80,\"proto\":\"TCP\",\"alert\":{{\"action\":\"{action}\",\"signature_id\":{sid},\"rev\":1,\"signature\":\"Sig {sid} 100%_x\",\"category\":\"Trojan\",\"severity\":1}}}}\n"
        )
    }

    #[tokio::test]
    async fn alerts_are_collected_once_filtered_and_pruned() {
        let s = crate::lan::testutil::store().await;
        let d = tempfile::tempdir().unwrap();
        let eve = d.path().join("eve.json");
        let nowt = chrono::Utc::now();
        let t = |secs: i64| {
            (nowt - chrono::Duration::seconds(secs))
                .format("%Y-%m-%dT%H:%M:%S.000000+0000")
                .to_string()
        };
        let mut body = String::from("{\"event_type\":\"stats\"}\n");
        body.push_str(&eve_line(
            &t(300),
            100,
            "10.0.0.5",
            "198.51.100.7",
            "allowed",
        ));
        body.push_str(&eve_line(
            &t(200),
            100,
            "10.0.0.6",
            "198.51.100.7",
            "blocked",
        ));
        body.push_str(&eve_line(
            &t(100),
            200,
            "10.1.0.9",
            "203.0.113.1",
            "allowed",
        ));
        std::fs::write(&eve, &body).unwrap();
        assert_eq!(ingest(&s, &eve).await.unwrap(), 3);
        assert_eq!(ingest(&s, &eve).await.unwrap(), 0, "nothing is read twice");
        // a half-written line is left for the next pass
        let half = eve_line(&t(50), 300, "10.0.0.7", "198.51.100.8", "allowed");
        let (a, b) = half.split_at(40);
        {
            use std::io::Write;
            let mut f = std::fs::OpenOptions::new().append(true).open(&eve).unwrap();
            f.write_all(a.as_bytes()).unwrap();
        }
        assert_eq!(ingest(&s, &eve).await.unwrap(), 0);
        {
            use std::io::Write;
            let mut f = std::fs::OpenOptions::new().append(true).open(&eve).unwrap();
            f.write_all(b.as_bytes()).unwrap();
        }
        assert_eq!(ingest(&s, &eve).await.unwrap(), 1);

        let f = |g: &dyn Fn(&mut Filter)| {
            let mut x = Filter {
                limit: 50,
                ..Default::default()
            };
            g(&mut x);
            x
        };
        assert_eq!(query(&s, &f(&|_| {})).await.unwrap().0, 4);
        let (n, rows) = query(&s, &f(&|x| x.sid = Some(100))).await.unwrap();
        assert_eq!((n, rows.len()), (2, 2));
        assert!(
            rows[0]["time"].as_i64() >= rows[1]["time"].as_i64(),
            "newest first"
        );
        assert_eq!(
            query(&s, &f(&|x| x.src = Some("10.0.0.5".into())))
                .await
                .unwrap()
                .0,
            1
        );
        assert_eq!(
            query(&s, &f(&|x| x.src = Some("10.0.0.0/24".into())))
                .await
                .unwrap()
                .0,
            3
        );
        assert_eq!(
            query(&s, &f(&|x| x.dst = Some("203.0.113.0/24".into())))
                .await
                .unwrap()
                .0,
            1
        );
        assert_eq!(
            query(&s, &f(&|x| x.action = Some("blocked".into())))
                .await
                .unwrap()
                .0,
            1
        );
        assert_eq!(
            query(&s, &f(&|x| x.q = Some("100%_x".into())))
                .await
                .unwrap()
                .0,
            4,
            "LIKE wildcards are escaped"
        );
        assert_eq!(
            query(&s, &f(&|x| x.q = Some("%".into()))).await.unwrap().0,
            4
        );
        assert_eq!(
            query(&s, &f(&|x| x.q = Some("nomatch".into())))
                .await
                .unwrap()
                .0,
            0
        );
        assert_eq!(
            query(&s, &f(&|x| x.from = Some(nowt.timestamp() - 150)))
                .await
                .unwrap()
                .0,
            2
        );
        assert_eq!(
            query(&s, &f(&|x| x.to = Some(nowt.timestamp() - 150)))
                .await
                .unwrap()
                .0,
            2
        );
        let (n, rows) = query(
            &s,
            &f(&|x| {
                x.limit = 1;
                x.offset = 1;
            }),
        )
        .await
        .unwrap();
        assert_eq!((n, rows.len()), (4, 1));
        assert!(query(&s, &f(&|x| x.src = Some("x; DROP".into())))
            .await
            .is_err());
        assert!(query(&s, &f(&|x| x.action = Some("both".into())))
            .await
            .is_err());

        let t = top(&s, "src", None, None, 10).await.unwrap();
        assert_eq!(t.len(), 4);
        let t = top(&s, "sid", None, None, 10).await.unwrap();
        assert_eq!(
            (
                t[0]["key"].as_str(),
                t[0]["count"].as_i64(),
                t[0]["blocked"].as_i64()
            ),
            (Some("100"), Some(2), Some(1))
        );
        assert!(top(&s, "bogus", None, None, 10).await.is_err());
        let sm = summary(&s).await.unwrap();
        assert_eq!(
            (sm["alerts_24h"].as_i64(), sm["blocked_24h"].as_i64()),
            (Some(4), Some(1))
        );

        // rotation: a new file starts over
        std::fs::remove_file(&eve).unwrap();
        std::fs::write(
            &eve,
            eve_line(&t_now(), 400, "10.0.0.8", "198.51.100.9", "allowed"),
        )
        .unwrap();
        assert_eq!(ingest(&s, &eve).await.unwrap(), 1);

        // retention: by age and by count
        sqlx::query("UPDATE ids_alerts SET ts = ts - 100 * 86400 WHERE sid = 200")
            .execute(s.pool().unwrap())
            .await
            .unwrap();
        assert_eq!(prune(&s, 30, 1_000_000).await.unwrap(), 1);
        for i in 0..1100 {
            sqlx::query("INSERT INTO ids_alerts (ts, sid) VALUES (?, 1)")
                .bind(now() - i)
                .execute(s.pool().unwrap())
                .await
                .unwrap();
        }
        prune(&s, 30, 1000).await.unwrap();
        let left: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM ids_alerts")
            .fetch_one(s.pool().unwrap())
            .await
            .unwrap();
        assert_eq!(left, 1000, "max rows keeps the newest ones");
    }

    fn t_now() -> String {
        chrono::Utc::now()
            .format("%Y-%m-%dT%H:%M:%S.000000+0000")
            .to_string()
    }
}
