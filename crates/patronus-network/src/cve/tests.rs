use super::*;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;

const JOBLIB: &str = include_str!("../../tests/data/glsa-202401-01.xml");
const H2: &str = include_str!("../../tests/data/RUSTSEC-2024-0003.json");

struct Lab {
    dir: tempfile::TempDir,
    s: Settings,
}

fn script(path: &Path, body: &str) {
    std::fs::write(path, format!("#!/bin/sh\n{body}\n")).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

fn lab(installed: &[(&str, &str)]) -> Lab {
    let dir = tempfile::tempdir().unwrap();
    let r = dir.path();
    let glsa = r.join("glsa");
    std::fs::create_dir_all(&glsa).unwrap();
    std::fs::write(glsa.join("glsa-202401-01.xml"), JOBLIB).unwrap();
    let pkg = r.join("pkg");
    for (n, v) in installed {
        let p = pkg.join(format!("{n}-{v}"));
        std::fs::create_dir_all(&p).unwrap();
        std::fs::write(p.join("SLOT"), "0\n").unwrap();
    }
    std::fs::create_dir_all(&pkg).unwrap();
    // portageq: the tree offers joblib 1.3.2
    script(&r.join("portageq"), "echo dev-python/joblib-1.3.2");
    // a Patronus binary that carries a crate list
    let bin = r.join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    let mut f = std::fs::File::create(bin.join("patronus-web")).unwrap();
    f.write_all(&[0u8; 5000]).unwrap();
    let begin = ["@@PATRONUS-", "DEPS-BEGIN/1@@"].concat();
    let end = ["@@PATRONUS-", "DEPS-END@@"].concat();
    write!(
        f,
        "{begin}\nbinary patronus-web\nversion 0.2.1\nscope lockfile-closure\ncrate h2 0.3.20 registry\ncrate serde 1.0.200 registry\n{end}\n"
    )
    .unwrap();
    let s = Settings {
        glsa_dir: glsa.to_string_lossy().into(),
        pkg_db: pkg.to_string_lossy().into(),
        data_dir: r.join("data").to_string_lossy().into(),
        portageq: r.join("portageq").to_string_lossy().into(),
        emerge: r.join("emerge").to_string_lossy().into(),
        manifest_path: r.join("manifest.json").to_string_lossy().into(),
        binaries: vec![bin.join("patronus-web").to_string_lossy().into()],
        fetch: false,
        ..Default::default()
    };
    Lab { dir, s }
}

fn write_bin(l: &Lab, crates: &str) {
    std::fs::write(
        &l.s.binaries[0],
        format!(
            "{}\nbinary patronus-web\nversion 1\nscope lockfile-closure\n{crates}{}\n",
            ["@@PATRONUS-", "DEPS-BEGIN/1@@"].concat(),
            ["@@PATRONUS-", "DEPS-END@@"].concat()
        ),
    )
    .unwrap();
}

fn seed_osv(l: &Lab, fetched_at: i64) {
    let (rows, _) = osv::parse_record(H2).unwrap();
    let mut db = osv::OsvDb {
        fetched_at,
        source_url: "https://example.test/all.zip".into(),
        advisories: 1,
        ..Default::default()
    };
    for (n, a) in rows {
        db.crates.entry(n).or_default().push(a);
    }
    std::fs::create_dir_all(&l.s.data_dir).unwrap();
    std::fs::write(osv_cache_path(&l.s), serde_json::to_vec(&db).unwrap()).unwrap();
}

fn touch_glsa(l: &Lab, t: i64) {
    let p = Path::new(&l.s.glsa_dir).join("glsa-202401-01.xml");
    let f = std::fs::File::options().write(true).open(p).unwrap();
    f.set_modified(std::time::UNIX_EPOCH + Duration::from_secs(t as u64))
        .unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn standard_tier_affected_with_update_and_crate_hit() {
    let l = lab(&[("dev-python/joblib", "1.1.0-r1"), ("sys-apps/other", "2.0")]);
    let now = now();
    seed_osv(&l, now - 3600);
    touch_glsa(&l, now - 86400);
    let r = scan(&l.s, now).await;
    assert_eq!(r.tier, "standard");
    assert_eq!(r.verdict, "affected");
    let g = r.findings.iter().find(|f| f.source == "glsa").unwrap();
    assert_eq!(g.subject, "dev-python/joblib");
    assert_eq!(g.advisory, "GLSA-202401-01");
    assert_eq!(g.severity, "high");
    assert_eq!(g.fixed_in, vec!["1.2.0"]);
    assert_eq!(g.update, "available");
    assert_eq!(g.update_version, "1.3.2");
    assert!(g.aliases.contains(&"CVE-2022-21797".to_string()));
    let c = r.findings.iter().find(|f| f.source == "osv").unwrap();
    assert_eq!(
        (c.subject.as_str(), c.installed.as_str(), c.binary.as_str()),
        ("h2", "0.3.20", "patronus-web")
    );
    assert_eq!(c.fixed_in, vec!["0.3.24", "0.4.2"]);
    assert_eq!(c.update, "needs-release");
    assert_eq!(r.crates_checked, 2);
    assert_eq!(r.packages_checked, 2);
    assert_eq!(apply_atoms(&r, 10), vec![">=dev-python/joblib-1.2.0"]);
}

#[tokio::test(flavor = "multi_thread")]
async fn no_update_when_the_tree_has_nothing_better() {
    let l = lab(&[("dev-python/joblib", "1.1.0-r1")]);
    script(Path::new(&l.s.portageq), "echo dev-python/joblib-1.1.0-r1");
    let r = scan(&l.s, now()).await;
    let g = r.findings.iter().find(|f| f.source == "glsa").unwrap();
    assert_eq!(g.update, "none");
    assert!(apply_atoms(&r, 10).is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn missing_or_old_data_is_never_clean() {
    // fixed package, but no advisory directory content at all -> unknown, not clean
    let l = lab(&[("dev-python/joblib", "1.3.2")]);
    std::fs::remove_file(Path::new(&l.s.glsa_dir).join("glsa-202401-01.xml")).unwrap();
    seed_osv(&l, now() - 60);
    write_bin(&l, "crate serde 1.0.200 registry\n");
    let r = scan(&l.s, now()).await;
    assert_eq!(r.verdict, "unknown");
    assert!(r
        .reasons
        .iter()
        .any(|x| x.contains("no Gentoo security advisories")));

    // data present and nothing affected, but both sets are 20 days old -> stale
    let l = lab(&[("dev-python/joblib", "1.3.2")]);
    let n = now();
    seed_osv(&l, n - 20 * 86400);
    touch_glsa(&l, n - 20 * 86400);
    write_bin(&l, "crate serde 1.0.200 registry\n");
    let r = scan(&l.s, n).await;
    assert_eq!(r.verdict, "stale", "{:?}", r.reasons);
    assert!(r.glsa.stale && r.osv.stale);

    // fresh data and nothing affected -> clean
    let l = lab(&[("dev-python/joblib", "1.3.2")]);
    seed_osv(&l, n - 60);
    touch_glsa(&l, n - 60);
    std::fs::write(&l.s.binaries[0], b"plain binary").unwrap();
    let r = scan(&l.s, n).await;
    assert_eq!(
        r.verdict, "unknown",
        "no embedded list: crates cannot be called clean"
    );
    write_bin(&l, "crate serde 1.0.200 registry\n");
    let r = scan(&l.s, n).await;
    assert_eq!(r.verdict, "clean", "{:?}", r.reasons);
}

#[tokio::test(flavor = "multi_thread")]
async fn router_tier_reads_the_manifest_and_the_gate() {
    let l = lab(&[]);
    let n = now();
    let day = chrono::DateTime::from_timestamp(n - 86400, 0)
        .unwrap()
        .format("%Y-%m-%d")
        .to_string();
    std::fs::write(
        &l.s.manifest_path,
        serde_json::json!({
            "schema": 1, "image": "ax1800", "built": day, "version": "0.2.1", "distribution": "alpine",
            "packages": [{"name":"busybox","version":"1.36.1-r5"},{"name":"curl","version":"8.5.0-r0"}],
            "gate": {"checked_at": day, "source": "Alpine secdb v3.20",
                "findings": [{"package":"curl","installed":"8.5.0-r0","advisory":"CVE-2024-0001","title":"curl: x","fixed_in":["8.5.0-r1"],"url":"https://example.test/CVE-2024-0001"}]}
        })
        .to_string(),
    )
    .unwrap();
    seed_osv(&l, n - 100);
    let r = scan(&l.s, n).await;
    assert_eq!(r.tier, "router");
    assert_eq!(r.packages_checked, 2);
    let img = r.findings.iter().find(|f| f.source == "image").unwrap();
    assert_eq!(img.subject, "curl");
    assert_eq!(img.update, "needs-release");
    assert!(r.glsa.detail.contains("Alpine secdb"));
    assert_eq!(r.verdict, "affected");
}

#[tokio::test(flavor = "multi_thread")]
async fn record_keeps_first_seen_prunes_fixed_and_emits_one_event() {
    let l = lab(&[("dev-python/joblib", "1.1.0-r1")]);
    let store = ConfigStore::open_in_memory().await.unwrap();
    let n = now();
    seed_osv(&l, n);
    let r1 = record(&store, &l.s, scan(&l.s, n - 7200).await)
        .await
        .unwrap();
    let first = r1.findings[0].first_seen;
    let r2 = record(&store, &l.s, scan(&l.s, n).await).await.unwrap();
    assert_eq!(
        r2.findings.iter().map(|f| f.first_seen).min().unwrap(),
        first
    );
    let ev: i64 = sqlx::query("SELECT count(*) FROM system_events WHERE kind='cve_exposure'")
        .fetch_one(store.pool().unwrap())
        .await
        .unwrap()
        .get(0);
    assert_eq!(ev, 1, "only the first scan found something new");
    // the package is upgraded: its findings go away, the crate finding stays
    std::fs::remove_dir_all(Path::new(&l.s.pkg_db).join("dev-python")).unwrap();
    let p = Path::new(&l.s.pkg_db).join("dev-python/joblib-1.3.2");
    std::fs::create_dir_all(&p).unwrap();
    let r3 = record(&store, &l.s, scan(&l.s, n + 10).await)
        .await
        .unwrap();
    assert!(r3.findings.iter().all(|f| f.source != "glsa"));
    let left: i64 = sqlx::query("SELECT count(*) FROM cve_findings WHERE source='glsa'")
        .fetch_one(store.pool().unwrap())
        .await
        .unwrap()
        .get(0);
    assert_eq!(left, 0);
    assert_eq!(scan_history(&store, 10).await.unwrap().len(), 3);
    assert!(last_report(&store).await.unwrap().is_some());
}

#[tokio::test(flavor = "multi_thread")]
async fn settings_round_trip_and_policy_apply_in_the_window() {
    let l = lab(&[("dev-python/joblib", "1.1.0-r1")]);
    let store = ConfigStore::open_in_memory().await.unwrap();
    let marker = l.dir.path().join("emerge-args");
    script(
        Path::new(&l.s.emerge),
        &format!("echo \"$@\" > {}", marker.display()),
    );
    let mut i = SettingsIn {
        glsa_dir: Some(l.s.glsa_dir.clone()),
        pkg_db: Some(l.s.pkg_db.clone()),
        data_dir: Some(l.s.data_dir.clone()),
        portageq: Some(l.s.portageq.clone()),
        emerge: Some(l.s.emerge.clone()),
        manifest_path: Some(l.s.manifest_path.clone()),
        binaries: Some(l.s.binaries.clone()),
        fetch: Some(false),
        ..Default::default()
    };
    save(&store, &i).await.unwrap();
    // policy notify: a scan is made, nothing is installed
    let r = tick(&store).await.unwrap().unwrap();
    assert_eq!(r.verdict, "affected");
    assert!(!marker.exists());
    // another tick right away: nothing is due
    assert!(tick(&store).await.unwrap().is_none());
    // policy apply with a window that covers every minute but one: installs the fix once
    i = SettingsIn {
        security_updates: Some("apply".into()),
        window: Some("00:00-23:59".into()),
        scan_interval_secs: Some(60),
        ..Default::default()
    };
    save(&store, &i).await.unwrap();
    state_set(&store, "scan_requested", &(now() + 5).to_string())
        .await
        .unwrap();
    let minute = local_minute_of_day();
    let r = tick(&store).await.unwrap().unwrap();
    if minute < 23 * 60 + 59 {
        let args = std::fs::read_to_string(&marker).unwrap();
        assert!(args.contains(">=dev-python/joblib-1.2.0"), "{args}");
        assert!(args.contains("--oneshot") && args.contains("--with-bdeps=y"));
        let log = log_history(&store, 10).await.unwrap();
        assert!(log.iter().any(|x| x.kind == "apply" && x.ok));
        let _ = r;
        // the second request inside the minimum interval does not install again
        std::fs::remove_file(&marker).unwrap();
        state_set(&store, "scan_requested", &(now() + 10).to_string())
            .await
            .unwrap();
        tick(&store).await.unwrap();
        assert!(!marker.exists());
    }
    // outside the window nothing is installed: a one-minute window that is not now
    let off = (minute + 120) % (24 * 60);
    let w = format!(
        "{:02}:{:02}-{:02}:{:02}",
        off / 60,
        off % 60,
        (off + 1) / 60 % 24,
        (off + 1) % 60
    );
    save(
        &store,
        &SettingsIn {
            window: Some(w),
            apply_min_interval_secs: Some(60),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    sqlx::query("DELETE FROM cve_state WHERE key='last_apply'")
        .execute(store.pool().unwrap())
        .await
        .unwrap();
    state_set(&store, "scan_requested", &(now() + 20).to_string())
        .await
        .unwrap();
    tick(&store).await.unwrap();
    assert!(!marker.exists());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_failing_emerge_is_logged_and_not_retried_at_once() {
    let l = lab(&[("dev-python/joblib", "1.1.0-r1")]);
    script(Path::new(&l.s.emerge), "echo conflict >&2; exit 1");
    let store = ConfigStore::open_in_memory().await.unwrap();
    assert!(!apply_updates(&store, &l.s, &[">=dev-python/joblib-1.2.0".into()]).await);
    let log = log_history(&store, 5).await.unwrap();
    assert!(!log[0].ok && log[0].detail.contains("conflict"));
}

#[tokio::test(flavor = "multi_thread")]
async fn fetch_reduces_a_downloaded_archive_and_keeps_the_old_data_on_failure() {
    use std::io::Write;
    let l = lab(&[]);
    // a local file served by curl's file:// is refused by --proto =http,https: serve over http
    let mut buf = Vec::new();
    {
        let mut w = zip::ZipWriter::new(std::io::Cursor::new(&mut buf));
        w.start_file(
            "RUSTSEC-2024-0003.json",
            zip::write::SimpleFileOptions::default(),
        )
        .unwrap();
        w.write_all(H2.as_bytes()).unwrap();
        w.finish().unwrap();
    }
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let body = buf.clone();
    std::thread::spawn(move || {
        for _ in 0..2 {
            if let Ok((mut c, _)) = listener.accept() {
                use std::io::Read;
                let mut tmp = [0u8; 2048];
                let _ = c.read(&mut tmp);
                let _ = write!(
                    c,
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = c.write_all(&body);
            }
        }
    });
    let mut s = l.s.clone();
    s.osv_url = format!("http://127.0.0.1:{port}/all.zip");
    let db = fetch_osv(&s, 1234).await.unwrap();
    assert_eq!(db.advisories, 1);
    assert_eq!(load_osv(&s).unwrap().fetched_at, 1234);
    // too large for the cap: refused, the cache stays
    let mut small = s.clone();
    small.osv_max_bytes = 10;
    assert!(fetch_osv(&small, 5).await.is_err());
    assert_eq!(load_osv(&s).unwrap().fetched_at, 1234);
    // nothing listens any more: an error, the cache stays
    s.osv_url = "http://127.0.0.1:9/all.zip".into();
    assert!(fetch_osv(&s, 6).await.is_err());
    assert_eq!(load_osv(&s).unwrap().fetched_at, 1234);
}
