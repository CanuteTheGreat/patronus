//! HA maintenance mode with a confirmed hand-off (lane G, gap E of
//! docs/design/proxmox-9.3-ideas.md).
//!
//! Entering maintenance is a procedure, not a flag:
//! 1. **check the peer**: watch it for `peer_check_secs`; it must prove it is alive
//!    (VRRP adverts arriving while this node is BACKUP, conntrackd packets arriving when state sync
//!    is on, or - unicast peer, this node MASTER - the peer's web port answering) and, when state
//!    sync is on, that the sync channel is up. Otherwise it **refuses with the reasons** unless `force`;
//! 2. lower the advertised priority (the store setting `ha.maintenance`);
//! 3. **wait** (typed `ha.handoff_timeout`) until this node is BACKUP and carries none of the
//!    carp virtual IPs, reporting progress; on timeout the priority is put back and the answer
//!    is an error (nothing is left half-way);
//! 4. leaving puts the priority back and waits (same timeout) for the node to be healthy again.
//!
//! The procedure is written against the [`Node`] trait so the timing logic is unit tested with a
//! fake node; [`SystemNode`] is the real one (keepalived stats, conntrackd, the peer's port).

use crate::ha::{self, Settings};
use async_trait::async_trait;
use patronus_config::store::ConfigStore;
use patronus_core::{Error, Result};
use serde::Serialize;
use serde_json::Value;
use std::collections::BTreeMap;
use std::time::Duration;

/// What one look at the node and its peer shows.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct Snapshot {
    /// `MASTER` / `BACKUP` / `FAULT` ... (None = unknown)
    pub state: Option<String>,
    pub keepalived_running: bool,
    pub enabled: bool,
    /// carp virtual IPs configured / of them present on this node
    pub carp_vips: usize,
    pub carp_present: usize,
    /// VRRP adverts received since keepalived started (sum over instances), None = unreadable
    pub adverts_received: Option<u64>,
    pub sync_expected: bool,
    pub conntrackd_running: bool,
    /// conntrackd packets received (sync channel), None = unreadable
    pub sync_received: Option<u64>,
    /// a peer address is configured / its web port answered (None = not asked)
    pub peer_set: bool,
    pub peer_port_open: Option<bool>,
}

/// The verdict of the peer check.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PeerHealth {
    pub healthy: bool,
    /// plain-words reasons it is not (empty when healthy)
    pub problems: Vec<String>,
    /// what proved it alive
    pub evidence: Vec<String>,
}

/// Judge the peer from two looks `peer_check_secs` apart. Pure.
pub fn judge_peer(a: &Snapshot, b: &Snapshot) -> PeerHealth {
    let mut problems = Vec::new();
    let mut evidence = Vec::new();
    if !b.enabled {
        problems.push("high availability is switched off on this node".to_string());
    } else if b.carp_vips == 0 {
        problems.push(
            "no failover (carp) virtual IP is configured: there is nothing to hand over".into(),
        );
    } else if !b.keepalived_running {
        problems.push("keepalived is not running on this node".into());
    }
    if !problems.is_empty() {
        return PeerHealth {
            healthy: false,
            problems,
            evidence,
        };
    }
    let grew = |x: Option<u64>, y: Option<u64>| matches!((x, y), (Some(x), Some(y)) if y > x);
    let backup = b.state.as_deref() == Some("BACKUP");
    let mut alive = false;
    if backup {
        // a BACKUP node only is one because it hears a better master: adverts must keep coming
        if grew(a.adverts_received, b.adverts_received) {
            alive = true;
            evidence.push("the peer's VRRP adverts are arriving".to_string());
        } else {
            problems.push("no VRRP advert from the peer arrived while it was watched".into());
        }
    }
    if b.sync_expected {
        if !b.conntrackd_running {
            problems.push("connection-state sync is on but conntrackd is not running".into());
        } else if grew(a.sync_received, b.sync_received) {
            alive = true;
            evidence.push("the connection-state sync channel is up".to_string());
        } else {
            problems.push(
                "connection-state sync is on but no packet from the peer arrived: established connections would be cut"
                    .into(),
            );
        }
    }
    if !alive && !backup && b.peer_set {
        match b.peer_port_open {
            Some(true) => {
                alive = true;
                evidence.push("the peer's web port answers".to_string());
            }
            _ => problems.push("the peer does not answer on its web port".into()),
        }
    }
    if !alive && problems.is_empty() {
        problems.push(
            "cannot tell whether the peer is alive (multicast VRRP, no state sync, no peer address): set the peer address or use force"
                .into(),
        );
    }
    PeerHealth {
        healthy: alive && problems.is_empty(),
        problems,
        evidence,
    }
}

/// True when this node has handed everything over.
pub fn handed_over(s: &Snapshot) -> bool {
    s.state.as_deref() == Some("BACKUP") && s.carp_present == 0
}

/// Parse keepalived's SIGUSR2 stats file: instance -> adverts received.
pub fn parse_keepalived_stats(text: &str) -> BTreeMap<String, u64> {
    let mut out = BTreeMap::new();
    let mut cur: Option<String> = None;
    let mut in_adverts = false;
    for l in text.lines() {
        let t = l.trim();
        if let Some(n) = t.strip_prefix("VRRP Instance:") {
            cur = Some(n.trim().to_string());
            in_adverts = false;
        } else if t.starts_with("Advertisements:") {
            in_adverts = true;
        } else if let (true, Some(n), Some(v)) = (in_adverts, &cur, t.strip_prefix("Received:")) {
            if let Ok(v) = v.trim().parse::<u64>() {
                out.insert(n.clone(), v);
            }
            in_adverts = false;
        } else if t.ends_with(':') && !t.starts_with("Advertisements") {
            // another section of the instance
            in_adverts = false;
        }
    }
    out
}

/// `conntrackd -s network` -> packets received on the sync channel.
pub fn parse_conntrackd_recv(text: &str) -> Option<u64> {
    for l in text.lines() {
        let t = l.trim();
        if t.ends_with("Pckts recv") {
            // "12 Pckts sent\t34 Pckts recv"
            let before = t.trim_end_matches("Pckts recv").trim();
            return before.rsplit(char::is_whitespace).next()?.parse().ok();
        }
    }
    None
}

// ---------------------------------------------------------------------------
// progress
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Progress {
    /// idle | checking | handoff | in_maintenance | leaving | failed
    pub phase: &'static str,
    pub message: String,
    /// why: `manual` or the automatic trigger (`firmware upgrade`, `restart`, ...)
    pub reason: String,
    pub vips_total: usize,
    pub vips_left: usize,
    pub started: i64,
    pub updated: i64,
}

impl Progress {
    pub fn idle() -> Self {
        Self {
            phase: "idle",
            message: String::new(),
            reason: String::new(),
            vips_total: 0,
            vips_left: 0,
            started: 0,
            updated: 0,
        }
    }
}

/// How the procedure reaches the node (real or fake).
#[async_trait]
pub trait Node: Send + Sync {
    async fn snapshot(&self, probe_peer: bool) -> Result<Snapshot>;
    async fn settings(&self) -> Result<Settings>;
    /// store + apply the maintenance flag (`auto` = entered by an upgrade/restart)
    async fn set_maintenance(&self, on: bool, auto: bool) -> Result<()>;
    async fn sleep(&self, d: Duration);
    fn now(&self) -> i64;
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Outcome {
    pub maintenance: bool,
    /// the hand-over was confirmed (false only with `force` when the peer could not be proven)
    pub confirmed: bool,
    pub waited_secs: u64,
    pub message: String,
}

const POLL: Duration = Duration::from_secs(1);

fn refuse(msg: String) -> Error {
    crate::lan::invalid(&msg)
}

/// Enter maintenance and wait until the peer carries the addresses.
pub async fn enter(
    node: &dyn Node,
    force: bool,
    auto: bool,
    reason: &str,
    progress: &(dyn Fn(Progress) + Send + Sync),
) -> Result<Outcome> {
    let started = node.now();
    let mut p = Progress {
        phase: "checking",
        message: "checking that the peer is healthy".into(),
        reason: reason.to_string(),
        vips_total: 0,
        vips_left: 0,
        started,
        updated: started,
    };
    progress(p.clone());
    let s = node.settings().await?;
    let first = node.snapshot(true).await?;
    if !first.enabled || first.carp_vips == 0 {
        // nothing to hand over: maintenance is only the flag
        if !force && !auto {
            p.phase = "failed";
            p.message = "high availability has no virtual IP on this node".into();
            progress(p.clone());
            return Err(refuse(p.message.clone()));
        }
        if auto {
            // an upgrade / restart on a node without HA just goes ahead
            p.phase = "idle";
            p.message = "no HA virtual IP: nothing to hand over".into();
            progress(p);
            return Ok(Outcome {
                maintenance: false,
                confirmed: true,
                waited_secs: 0,
                message: "no HA virtual IP: nothing to hand over".into(),
            });
        }
    }
    let mut proven = true;
    if !force {
        node.sleep(Duration::from_secs(s.peer_check_secs.into()))
            .await;
        let second = node.snapshot(true).await?;
        let h = judge_peer(&first, &second);
        if !h.healthy {
            let msg = format!(
                "maintenance refused, the peer is not healthy: {}",
                h.problems.join("; ")
            );
            p.phase = "failed";
            p.message = msg.clone();
            p.updated = node.now();
            progress(p);
            return Err(refuse(msg));
        }
    } else {
        proven = false;
    }
    p.phase = "handoff";
    p.vips_total = first.carp_vips;
    p.vips_left = first.carp_present;
    p.message = "priority lowered, waiting for the peer to take the virtual IPs".into();
    progress(p.clone());
    node.set_maintenance(true, auto).await?;
    if force {
        // the operator accepted the risk: do not wait for a peer that may not exist
        p.phase = "in_maintenance";
        p.message = "maintenance on (forced, hand-over not waited for)".into();
        p.updated = node.now();
        progress(p);
        return Ok(Outcome {
            maintenance: true,
            confirmed: false,
            waited_secs: 0,
            message: "maintenance on (forced, hand-over not confirmed)".into(),
        });
    }
    let timeout = u64::from(s.handoff_timeout);
    let mut waited = 0u64;
    loop {
        let now = node.snapshot(false).await?;
        p.vips_left = now.carp_present;
        p.updated = node.now();
        if handed_over(&now) {
            p.phase = "in_maintenance";
            p.vips_left = 0;
            p.message = format!("handed over to the peer after {waited} s: this node is BACKUP");
            progress(p.clone());
            return Ok(Outcome {
                maintenance: true,
                confirmed: proven,
                waited_secs: waited,
                message: p.message,
            });
        }
        if waited >= timeout {
            break;
        }
        p.message = format!(
            "waiting for the peer: {} of {} virtual IPs still here, state {}",
            now.carp_present,
            first.carp_vips,
            now.state.as_deref().unwrap_or("unknown")
        );
        progress(p.clone());
        node.sleep(POLL).await;
        waited += POLL.as_secs();
    }
    // the peer did not take over: put everything back, never leave a half hand-over
    let back = node.set_maintenance(false, false).await;
    let msg = format!(
        "the peer did not take the virtual IPs within {timeout} s: maintenance cancelled{}",
        match back {
            Ok(()) => String::new(),
            Err(e) => format!(" (and the priority could not be restored: {e})"),
        }
    );
    p.phase = "failed";
    p.message = msg.clone();
    p.updated = node.now();
    progress(p);
    Err(Error::Config(msg))
}

/// Leave maintenance and wait until this node is healthy again (adverts / sync flowing).
pub async fn leave(
    node: &dyn Node,
    reason: &str,
    progress: &(dyn Fn(Progress) + Send + Sync),
) -> Result<Outcome> {
    let s = node.settings().await?;
    let started = node.now();
    let mut p = Progress {
        phase: "leaving",
        message: "restoring the priority".into(),
        reason: reason.to_string(),
        vips_total: 0,
        vips_left: 0,
        started,
        updated: started,
    };
    progress(p.clone());
    node.set_maintenance(false, false).await?;
    let timeout = u64::from(s.rejoin_timeout);
    let mut waited = 0u64;
    let mut prev = node.snapshot(true).await?;
    loop {
        node.sleep(POLL).await;
        waited += POLL.as_secs();
        let now = node.snapshot(true).await?;
        let h = judge_peer(&prev, &now);
        // a MASTER without a visible peer (peer down) is still a fine, serving node
        let serving =
            now.keepalived_running && matches!(now.state.as_deref(), Some("MASTER" | "BACKUP"));
        if serving
            && (h.healthy
                || now.state.as_deref() == Some("MASTER") && waited >= u64::from(s.peer_check_secs))
        {
            p.phase = "idle";
            p.message = format!(
                "maintenance left after {waited} s: node is {}",
                now.state.as_deref().unwrap_or("?")
            );
            p.updated = node.now();
            progress(p.clone());
            return Ok(Outcome {
                maintenance: false,
                confirmed: h.healthy,
                waited_secs: waited,
                message: p.message,
            });
        }
        if waited >= timeout {
            p.phase = "failed";
            p.message = format!(
                "maintenance left, but the node is not healthy after {timeout} s: {}",
                h.problems.join("; ")
            );
            p.updated = node.now();
            progress(p.clone());
            return Err(Error::Config(p.message));
        }
        p.message = format!("waiting for the node to rejoin its peer ({waited} s)");
        p.updated = node.now();
        progress(p.clone());
        prev = now;
    }
}

// ---------------------------------------------------------------------------
// the real node
// ---------------------------------------------------------------------------

/// Applies the maintenance flag through the caller (the web layer commits it through the config
/// generations); everything else is read from the live system.
#[async_trait]
pub trait MaintenanceSetter: Send + Sync {
    async fn set(&self, on: bool, auto: bool) -> anyhow::Result<()>;
}

/// `status` = the HA applier's status JSON (through `patronus applyd` when the web UI is
/// unprivileged), `store` = the settings.
pub struct SystemNode<'a> {
    pub store: &'a ConfigStore,
    pub status: &'a (dyn Fn() -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<Value>> + Send>,
    > + Send
             + Sync),
    pub setter: &'a dyn MaintenanceSetter,
}

#[async_trait]
impl Node for SystemNode<'_> {
    async fn snapshot(&self, probe_peer: bool) -> Result<Snapshot> {
        let s = ha::settings(self.store).await?;
        let st = (self.status)()
            .await
            .map_err(|e| Error::Config(e.to_string()))?;
        let carp: Vec<&Value> = st["vips"]
            .as_array()
            .map(|a| a.iter().filter(|v| v["mode"] == "carp").collect())
            .unwrap_or_default();
        let sync_expected = s.sync;
        let ct_running = st["conntrackd"].as_bool().unwrap_or(false);
        let mut snap = Snapshot {
            state: st["state"].as_str().map(str::to_string),
            keepalived_running: st["keepalived"].as_bool().unwrap_or(false),
            enabled: s.enabled,
            carp_vips: carp.len(),
            carp_present: carp.iter().filter(|v| v["present"] == true).count(),
            adverts_received: st["adverts_received"].as_u64(),
            sync_expected,
            conntrackd_running: ct_running,
            sync_received: st["sync_received"].as_u64(),
            peer_set: s.peer.is_some(),
            peer_port_open: None,
        };
        if probe_peer {
            if let Some(peer) = &s.peer {
                snap.peer_port_open = Some(tcp_open(peer, 443).await);
            }
        }
        Ok(snap)
    }

    async fn settings(&self) -> Result<Settings> {
        ha::settings(self.store).await
    }

    async fn set_maintenance(&self, on: bool, auto: bool) -> Result<()> {
        self.setter
            .set(on, auto)
            .await
            .map_err(|e| Error::Config(e.to_string()))
    }

    async fn sleep(&self, d: Duration) {
        tokio::time::sleep(d).await
    }

    fn now(&self) -> i64 {
        crate::lan::now()
    }
}

async fn tcp_open(host: &str, port: u16) -> bool {
    let addr = if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    };
    matches!(
        tokio::time::timeout(Duration::from_secs(2), tokio::net::TcpStream::connect(addr)).await,
        Ok(Ok(_))
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    fn snap(state: &str, present: usize, adverts: u64) -> Snapshot {
        Snapshot {
            state: Some(state.into()),
            keepalived_running: true,
            enabled: true,
            carp_vips: 2,
            carp_present: present,
            adverts_received: Some(adverts),
            ..Snapshot::default()
        }
    }

    #[test]
    fn parses_keepalived_stats_and_conntrackd() {
        let t = "VRRP Instance: PAT_eth1_51\n  Advertisements:\n    Received: 12\n    Sent: 0\n  Became master: 0\nVRRP Instance: PAT_eth0_52\n  Advertisements:\n    Received: 30\n    Sent: 1\n";
        let m = parse_keepalived_stats(t);
        assert_eq!(m.len(), 2);
        assert_eq!(m.values().sum::<u64>(), 42);
        let c = "network statistics:\n\trecv:\n\t\tMalformed messages: 0\nUDP traffic (active device=eth1):\n\t100 Bytes sent\t200 Bytes recv\n\t7 Pckts sent\t9 Pckts recv\n";
        assert_eq!(parse_conntrackd_recv(c), Some(9));
        assert_eq!(parse_conntrackd_recv("nothing"), None);
    }

    #[test]
    fn backup_needs_growing_adverts() {
        let h = judge_peer(&snap("BACKUP", 0, 5), &snap("BACKUP", 0, 9));
        assert!(h.healthy, "{h:?}");
        let h = judge_peer(&snap("BACKUP", 0, 5), &snap("BACKUP", 0, 5));
        assert!(!h.healthy);
        assert!(h.problems[0].contains("no VRRP advert"), "{h:?}");
    }

    #[test]
    fn master_needs_sync_or_peer_port_and_never_guesses() {
        // multicast, no sync, no peer address: cannot tell
        let h = judge_peer(&snap("MASTER", 2, 0), &snap("MASTER", 2, 0));
        assert!(!h.healthy);
        assert!(h.problems[0].contains("cannot tell"), "{h:?}");
        // unicast peer answering
        let mut b = snap("MASTER", 2, 0);
        b.peer_set = true;
        b.peer_port_open = Some(true);
        assert!(judge_peer(&snap("MASTER", 2, 0), &b).healthy);
        b.peer_port_open = Some(false);
        assert!(!judge_peer(&snap("MASTER", 2, 0), &b).healthy);
        // sync on: the channel must carry packets
        let mut a = snap("MASTER", 2, 0);
        a.sync_expected = true;
        a.conntrackd_running = true;
        a.sync_received = Some(10);
        let mut b = a.clone();
        assert!(!judge_peer(&a, &b).healthy, "no packets in the window");
        b.sync_received = Some(14);
        assert!(judge_peer(&a, &b).healthy);
        b.conntrackd_running = false;
        assert!(!judge_peer(&a, &b).healthy);
    }

    #[test]
    fn nothing_to_hand_over_is_reported() {
        let mut b = snap("MASTER", 0, 0);
        b.carp_vips = 0;
        assert!(judge_peer(&b, &b).problems[0].contains("nothing to hand over"));
        b.carp_vips = 2;
        b.keepalived_running = false;
        assert!(judge_peer(&b, &b).problems[0].contains("keepalived is not running"));
    }

    /// A node whose state evolves with the number of snapshots taken.
    struct Fake {
        settings: Settings,
        script: Mutex<Vec<Snapshot>>,
        last: Mutex<Snapshot>,
        maint: Mutex<Vec<(bool, bool)>>,
        slept: Mutex<u64>,
    }

    impl Fake {
        fn new(script: Vec<Snapshot>) -> Self {
            let settings = Settings {
                handoff_timeout: 5,
                peer_check_secs: 2,
                rejoin_timeout: 10,
                ..Settings::default()
            };
            Self {
                settings,
                last: Mutex::new(script[0].clone()),
                script: Mutex::new(script),
                maint: Mutex::new(vec![]),
                slept: Mutex::new(0),
            }
        }
    }

    #[async_trait]
    impl Node for Fake {
        async fn snapshot(&self, _p: bool) -> Result<Snapshot> {
            let mut s = self.script.lock().unwrap();
            if !s.is_empty() {
                *self.last.lock().unwrap() = s.remove(0);
            }
            Ok(self.last.lock().unwrap().clone())
        }
        async fn settings(&self) -> Result<Settings> {
            Ok(self.settings.clone())
        }
        async fn set_maintenance(&self, on: bool, auto: bool) -> Result<()> {
            self.maint.lock().unwrap().push((on, auto));
            Ok(())
        }
        async fn sleep(&self, d: Duration) {
            *self.slept.lock().unwrap() += d.as_secs();
        }
        fn now(&self) -> i64 {
            1000 + *self.slept.lock().unwrap() as i64
        }
    }

    fn noop(_: Progress) {}

    #[tokio::test]
    async fn refuses_when_the_peer_is_silent_and_changes_nothing() {
        let n = Fake::new(vec![snap("BACKUP", 0, 5), snap("BACKUP", 0, 5)]);
        let e = enter(&n, false, false, "manual", &noop).await.unwrap_err();
        assert!(e.to_string().contains("not healthy"), "{e}");
        assert!(n.maint.lock().unwrap().is_empty(), "priority must not move");
    }

    #[tokio::test]
    async fn force_skips_the_check_and_the_wait() {
        let n = Fake::new(vec![snap("MASTER", 2, 0), snap("MASTER", 2, 0)]);
        let o = enter(&n, true, false, "manual", &noop).await.unwrap();
        assert!(o.maintenance && !o.confirmed);
        assert_eq!(*n.maint.lock().unwrap(), vec![(true, false)]);
    }

    #[tokio::test]
    async fn waits_until_backup_with_no_vips_and_reports_progress() {
        let mut peer = snap("MASTER", 2, 0);
        peer.peer_set = true;
        peer.peer_port_open = Some(true);
        let n = Fake::new(vec![
            peer.clone(),
            peer.clone(),
            snap("MASTER", 2, 0), // first poll: still master
            snap("BACKUP", 1, 3), // address leaving
            snap("BACKUP", 0, 4), // done
        ]);
        let seen = Mutex::new(Vec::new());
        let cb = |p: Progress| seen.lock().unwrap().push((p.phase, p.vips_left));
        let o = enter(&n, false, true, "firmware upgrade", &cb)
            .await
            .unwrap();
        assert!(o.maintenance && o.confirmed);
        assert_eq!(*n.maint.lock().unwrap(), vec![(true, true)]);
        let seen = seen.lock().unwrap();
        assert_eq!(seen.first().unwrap().0, "checking");
        assert!(seen.iter().any(|(ph, left)| *ph == "handoff" && *left == 2));
        assert_eq!(*seen.last().unwrap(), ("in_maintenance", 0));
    }

    #[tokio::test]
    async fn timeout_puts_the_priority_back() {
        let mut peer = snap("MASTER", 2, 0);
        peer.peer_set = true;
        peer.peer_port_open = Some(true);
        let n = Fake::new(vec![peer.clone(), peer.clone(), snap("MASTER", 2, 0)]);
        let e = enter(&n, false, false, "manual", &noop).await.unwrap_err();
        assert!(e.to_string().contains("did not take"), "{e}");
        assert_eq!(
            *n.maint.lock().unwrap(),
            vec![(true, false), (false, false)]
        );
    }

    #[tokio::test]
    async fn automatic_entry_without_ha_just_goes_ahead() {
        let mut off = snap("MASTER", 0, 0);
        off.enabled = false;
        off.carp_vips = 0;
        let n = Fake::new(vec![off]);
        let o = enter(&n, false, true, "restart", &noop).await.unwrap();
        assert!(!o.maintenance);
        assert!(n.maint.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn leave_waits_for_a_healthy_node() {
        let n = Fake::new(vec![
            snap("BACKUP", 0, 1),
            snap("BACKUP", 0, 1),
            snap("BACKUP", 0, 1),
            snap("BACKUP", 0, 3),
        ]);
        let o = leave(&n, "restart", &noop).await.unwrap();
        assert!(!o.maintenance && o.confirmed);
        assert_eq!(*n.maint.lock().unwrap(), vec![(false, false)]);
    }

    #[tokio::test]
    async fn leave_times_out_with_a_reason() {
        let n = Fake::new(vec![snap("FAULT", 0, 1)]);
        let e = leave(&n, "restart", &noop).await.unwrap_err();
        assert!(e.to_string().contains("not healthy"), "{e}");
    }
}
