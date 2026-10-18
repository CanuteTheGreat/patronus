//! Real 3-node HA replication test (QA finding 2026-10-16: HA nodes did not
//! replicate data; a site created on the old leader was missing on the new
//! leader after failover and the three nodes ended with three different
//! site lists).
//!
//! Three complete dashboard nodes (real AppState + SQLite files + sled
//! replication logs) run in-process, each serving the real `/ha/*` routes on
//! its own 127.0.0.1 port and talking to the others over real HTTP.

use patronus_dashboard::{
    auth::jwt::CLUSTER_TOKEN_HEADER,
    ha::{
        cluster::{ClusterState, NodeRole},
        election::LeaderElection,
        replication::{ReplicatedOp, ReplicatedUser, ReplicationLog},
    },
    state::AppState,
};
use patronus_sdwan::types::{Site, SiteId, SiteStatus};
use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::{Duration, Instant};

struct Node {
    id: String,
    state: Arc<AppState>,
    ha: Arc<LeaderElection>,
    server: tokio::task::JoinHandle<()>,
    _dir: tempfile::TempDir,
}

impl Node {
    fn kill(&self) {
        self.ha.stop();
        self.server.abort();
    }
}

async fn start_cluster(n: usize) -> Vec<Node> {
    let mut listeners = Vec::new();
    for _ in 0..n {
        listeners.push(tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap());
    }
    let addrs: Vec<String> = listeners
        .iter()
        .map(|l| l.local_addr().unwrap().to_string())
        .collect();

    let mut nodes = Vec::new();
    for (i, listener) in listeners.into_iter().enumerate() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("dashboard.db");
        let mut state = AppState::new(db.to_str().unwrap()).await.unwrap();
        let id = format!("node{}", i + 1);
        let peers: Vec<String> = addrs
            .iter()
            .enumerate()
            .filter(|(j, _)| *j != i)
            .map(|(_, a)| a.clone())
            .collect();
        let ha = Arc::new(
            LeaderElection::new_with_durations(
                Arc::new(ClusterState::new(id.clone())),
                id.clone(),
                addrs[i].parse().unwrap(),
                peers,
                Duration::from_millis(400),
                Duration::from_millis(100),
            )
            .with_advertise_addr(addrs[i].clone())
            .with_replication(
                ReplicationLog::open(dir.path().join("replog")).unwrap(),
                state.state_machine.clone(),
            ),
        );
        state.ha = Some(ha.clone());
        let state = Arc::new(state);
        let app = patronus_dashboard::ha::rpc::routes().with_state(state.clone());
        let server = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        ha.clone().start();
        nodes.push(Node {
            id,
            state,
            ha,
            server,
            _dir: dir,
        });
    }
    nodes
}

async fn wait_leader(nodes: &[&Node]) -> usize {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let leaders: Vec<usize> = nodes
            .iter()
            .enumerate()
            .filter(|(_, n)| n.ha.get_role() == NodeRole::Leader)
            .map(|(i, _)| i)
            .collect();
        if leaders.len() == 1 {
            // Make sure the others agree on who it is.
            let lid = nodes[leaders[0]].id.clone();
            let mut agree = true;
            for n in nodes {
                if n.ha.status().await.leader_id.as_deref() != Some(lid.as_str()) {
                    agree = false;
                }
            }
            if agree {
                return leaders[0];
            }
        }
        assert!(Instant::now() < deadline, "no stable leader elected");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

fn site(name: &str) -> Site {
    Site {
        id: SiteId::generate(),
        name: name.to_string(),
        public_key: vec![7; 32],
        endpoints: Vec::new(),
        created_at: std::time::SystemTime::now(),
        last_seen: std::time::SystemTime::now(),
        status: SiteStatus::Active,
    }
}

async fn site_names(n: &Node) -> BTreeSet<String> {
    n.state
        .db
        .list_sites()
        .await
        .unwrap()
        .into_iter()
        .map(|s| s.name)
        .collect()
}

async fn wait_sites(n: &Node, want: &BTreeSet<String>) {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let got = site_names(n).await;
        if &got == want {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "{} has sites {:?}, expected {:?}",
            n.id,
            got,
            want
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn writes_replicate_and_survive_leader_failover() {
    let nodes = start_cluster(3).await;
    let all: Vec<&Node> = nodes.iter().collect();
    let leader = wait_leader(&all).await;
    let follower = (leader + 1) % 3;

    // Write on the leader.
    nodes[leader]
        .state
        .replicate(ReplicatedOp::UpsertSite(site("hq")))
        .await
        .unwrap();
    // Write through a follower (forwarded to the leader).
    nodes[follower]
        .state
        .replicate(ReplicatedOp::UpsertSite(site("branch-1")))
        .await
        .unwrap();
    // The follower that took the write can read it back immediately.
    assert!(site_names(&nodes[follower]).await.contains("branch-1"));

    // Users replicate too (an admin created on one node can log in anywhere).
    nodes[follower]
        .state
        .replicate(ReplicatedOp::CreateUser(ReplicatedUser {
            id: "u-ops".into(),
            email: "ops@example.test".into(),
            name: "Ops".into(),
            role: "operator".into(),
            password_hash: "$argon2id$dummy".into(),
            created_at: chrono::Utc::now(),
            is_active: true,
        }))
        .await
        .unwrap();

    let want: BTreeSet<String> = ["hq", "branch-1"].iter().map(|s| s.to_string()).collect();
    for n in &nodes {
        wait_sites(n, &want).await;
    }
    for n in &nodes {
        let deadline = Instant::now() + Duration::from_secs(5);
        while n
            .state
            .user_repository
            .get_user("u-ops")
            .await
            .unwrap()
            .is_none()
        {
            assert!(Instant::now() < deadline, "user missing on {}", n.id);
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    // Kill the leader: the new leader must already hold every write.
    let old_leader_id = nodes[leader].id.clone();
    nodes[leader].kill();
    let survivors: Vec<&Node> = nodes.iter().filter(|n| n.id != old_leader_id).collect();
    let new_leader = wait_leader(&survivors).await;
    assert_ne!(survivors[new_leader].id, old_leader_id);
    assert_eq!(site_names(survivors[new_leader]).await, want);

    // Keep writing with 2 of 3 nodes (still a majority), through both.
    survivors[new_leader]
        .state
        .replicate(ReplicatedOp::UpsertSite(site("branch-2")))
        .await
        .unwrap();
    survivors[1 - new_leader]
        .state
        .replicate(ReplicatedOp::UpsertSite(site("branch-3")))
        .await
        .unwrap();
    let want: BTreeSet<String> = ["hq", "branch-1", "branch-2", "branch-3"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    for n in &survivors {
        wait_sites(n, &want).await;
    }
    // Identical site lists (same ids, not just names) on both survivors.
    let ids = |n: &Node| {
        let st = n.state.clone();
        async move {
            st.db
                .list_sites()
                .await
                .unwrap()
                .into_iter()
                .map(|s| s.id.to_string())
                .collect::<BTreeSet<_>>()
        }
    };
    assert_eq!(ids(survivors[0]).await, ids(survivors[1]).await);

    let st = survivors[new_leader].ha.status().await;
    assert!(st.commit_index >= 4 && st.applied_index == st.commit_index);

    for n in &nodes {
        n.kill();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn minority_cannot_commit_writes() {
    let nodes = start_cluster(3).await;
    let all: Vec<&Node> = nodes.iter().collect();
    let leader = wait_leader(&all).await;
    // Isolate the leader by killing both followers.
    for (i, n) in nodes.iter().enumerate() {
        if i != leader {
            n.kill();
        }
    }
    let err = nodes[leader]
        .state
        .replicate(ReplicatedOp::UpsertSite(site("lost")))
        .await;
    assert!(err.is_err(), "a lone node must not acknowledge a write");
    assert!(!site_names(&nodes[leader]).await.contains("lost"));
    nodes[leader].kill();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ha_rpcs_require_the_cluster_token() {
    let nodes = start_cluster(3).await;
    let all: Vec<&Node> = nodes.iter().collect();
    let _ = wait_leader(&all).await;
    let addr = nodes[0].ha.status().await.peers[0].clone();
    let client = reqwest::Client::new();
    let forged = serde_json::json!({
        "op": {"op": "CreateUser", "data": {
            "id": "intruder", "email": "x@example.test", "name": "x", "role": "admin",
            "password_hash": "x", "created_at": chrono::Utc::now(), "is_active": true}}
    });
    for (path, body) in [
        ("/ha/submit", forged.clone()),
        (
            "/ha/heartbeat",
            serde_json::json!({"term": 999, "leader_id": "evil"}),
        ),
        (
            "/ha/vote",
            serde_json::json!({"term": 999, "candidate_id": "evil"}),
        ),
    ] {
        let r = client
            .post(format!("http://{addr}{path}"))
            .json(&body)
            .send()
            .await
            .unwrap();
        assert_eq!(
            r.status(),
            401,
            "{path} must reject callers without the token"
        );
        let r = client
            .post(format!("http://{addr}{path}"))
            .header(CLUSTER_TOKEN_HEADER, "0".repeat(64))
            .json(&body)
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 401, "{path} must reject a wrong token");
    }
    tokio::time::sleep(Duration::from_millis(500)).await;
    for n in &nodes {
        assert!(n
            .state
            .user_repository
            .get_user("intruder")
            .await
            .unwrap()
            .is_none());
    }
    // /ha/status stays readable for the UI cluster panel.
    let r = client
        .get(format!("http://{addr}/ha/status"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);

    // /ha/cluster (the UI's cluster view) names the same leader from every
    // node and lists all three members.
    let leader_id = nodes
        .iter()
        .find(|n| n.ha.get_role() == NodeRole::Leader)
        .map(|n| n.id.clone())
        .unwrap();
    for peer in nodes[0].ha.status().await.peers {
        let v: serde_json::Value = client
            .get(format!("http://{peer}/ha/cluster"))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(v["ha_enabled"], true);
        assert_eq!(v["leader_id"], leader_id.as_str());
        let members = v["members"].as_array().unwrap();
        assert_eq!(members.len(), 3);
        assert!(members.iter().all(|m| m["reachable"] == true));
        assert_eq!(
            members
                .iter()
                .filter(|m| m["status"]["role"] == serde_json::json!(NodeRole::Leader))
                .count(),
            1
        );
    }
    for n in &nodes {
        n.kill();
    }
}
