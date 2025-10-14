//! Distributed Consensus and State Replication

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;
use chrono::{DateTime, Utc};
use anyhow::Result;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum NodeRole {
    Leader,
    Follower,
    Candidate,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsensusNode {
    pub id: Uuid,
    pub region_id: Uuid,
    pub role: NodeRole,
    pub term: u64,
    pub voted_for: Option<Uuid>,
    pub last_heartbeat: DateTime<Utc>,
}

impl ConsensusNode {
    pub fn new(region_id: Uuid) -> Self {
        Self {
            id: Uuid::new_v4(),
            region_id,
            role: NodeRole::Follower,
            term: 0,
            voted_for: None,
            last_heartbeat: Utc::now(),
        }
    }

    pub fn become_candidate(&mut self) {
        self.role = NodeRole::Candidate;
        self.term += 1;
        self.voted_for = Some(self.id);
        tracing::info!("Node {} became candidate for term {}", self.id, self.term);
    }

    pub fn become_leader(&mut self) {
        self.role = NodeRole::Leader;
        tracing::info!("Node {} became leader for term {}", self.id, self.term);
    }

    pub fn become_follower(&mut self, term: u64) {
        self.role = NodeRole::Follower;
        self.term = term;
        self.voted_for = None;
        tracing::info!("Node {} became follower for term {}", self.id, self.term);
    }

    pub fn is_leader(&self) -> bool {
        self.role == NodeRole::Leader
    }

    pub fn heartbeat(&mut self) {
        self.last_heartbeat = Utc::now();
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    pub index: u64,
    pub term: u64,
    pub command: String,
    pub data: serde_json::Value,
    pub timestamp: DateTime<Utc>,
}

impl LogEntry {
    pub fn new(index: u64, term: u64, command: impl Into<String>, data: serde_json::Value) -> Self {
        Self {
            index,
            term,
            command: command.into(),
            data,
            timestamp: Utc::now(),
        }
    }
}

pub struct ConsensusCluster {
    nodes: HashMap<Uuid, ConsensusNode>,
    log: Vec<LogEntry>,
    commit_index: u64,
    leader_id: Option<Uuid>,
}

impl ConsensusCluster {
    pub fn new() -> Self {
        Self {
            nodes: HashMap::new(),
            log: Vec::new(),
            commit_index: 0,
            leader_id: None,
        }
    }

    pub fn add_node(&mut self, node: ConsensusNode) -> Uuid {
        let node_id = node.id;
        self.nodes.insert(node_id, node);
        tracing::info!("Added node to consensus cluster: {}", node_id);
        node_id
    }

    pub fn get_leader(&self) -> Option<&ConsensusNode> {
        self.leader_id.and_then(|id| self.nodes.get(&id))
    }

    pub fn elect_leader(&mut self, candidate_id: &Uuid) -> Result<()> {
        let node = self.nodes.get_mut(candidate_id)
            .ok_or_else(|| anyhow::anyhow!("Node not found"))?;

        // Simple leader election (in production, use Raft consensus)
        node.become_leader();
        self.leader_id = Some(*candidate_id);

        // Set others as followers
        let term = node.term;
        for (id, other_node) in self.nodes.iter_mut() {
            if id != candidate_id {
                other_node.become_follower(term);
            }
        }

        tracing::info!("Elected leader: {}", candidate_id);

        Ok(())
    }

    pub fn append_entry(&mut self, command: impl Into<String>, data: serde_json::Value) -> Result<u64> {
        let leader = self.get_leader()
            .ok_or_else(|| anyhow::anyhow!("No leader elected"))?;

        let index = self.log.len() as u64;
        let term = leader.term;

        let entry = LogEntry::new(index, term, command, data);
        self.log.push(entry);

        tracing::debug!("Appended log entry at index {}", index);

        Ok(index)
    }

    pub fn commit(&mut self, index: u64) -> Result<()> {
        if index >= self.log.len() as u64 {
            anyhow::bail!("Invalid commit index");
        }

        self.commit_index = index;
        tracing::info!("Committed log up to index {}", index);

        Ok(())
    }

    pub fn get_log(&self) -> &[LogEntry] {
        &self.log
    }

    pub fn get_committed_entries(&self) -> &[LogEntry] {
        &self.log[..=self.commit_index as usize]
    }

    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    pub fn has_quorum(&self) -> bool {
        let active_nodes = self.nodes.values()
            .filter(|n| {
                let elapsed = Utc::now()
                    .signed_duration_since(n.last_heartbeat)
                    .num_seconds();
                elapsed < 30 // 30 second timeout
            })
            .count();

        active_nodes > self.nodes.len() / 2
    }
}

impl Default for ConsensusCluster {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_consensus_node_creation() {
        let region_id = Uuid::new_v4();
        let node = ConsensusNode::new(region_id);

        assert_eq!(node.region_id, region_id);
        assert_eq!(node.role, NodeRole::Follower);
        assert_eq!(node.term, 0);
    }

    #[test]
    fn test_node_role_transitions() {
        let region_id = Uuid::new_v4();
        let mut node = ConsensusNode::new(region_id);

        assert_eq!(node.role, NodeRole::Follower);

        node.become_candidate();
        assert_eq!(node.role, NodeRole::Candidate);
        assert_eq!(node.term, 1);

        node.become_leader();
        assert_eq!(node.role, NodeRole::Leader);
        assert!(node.is_leader());

        node.become_follower(2);
        assert_eq!(node.role, NodeRole::Follower);
        assert_eq!(node.term, 2);
    }

    #[test]
    fn test_log_entry_creation() {
        let data = serde_json::json!({"site_id": "site-123"});
        let entry = LogEntry::new(0, 1, "create_site", data);

        assert_eq!(entry.index, 0);
        assert_eq!(entry.term, 1);
        assert_eq!(entry.command, "create_site");
    }

    #[test]
    fn test_cluster_creation() {
        let cluster = ConsensusCluster::new();

        assert_eq!(cluster.node_count(), 0);
        assert!(cluster.get_leader().is_none());
    }

    #[test]
    fn test_add_nodes() {
        let mut cluster = ConsensusCluster::new();

        let node1 = ConsensusNode::new(Uuid::new_v4());
        let node2 = ConsensusNode::new(Uuid::new_v4());

        cluster.add_node(node1);
        cluster.add_node(node2);

        assert_eq!(cluster.node_count(), 2);
    }

    #[test]
    fn test_leader_election() {
        let mut cluster = ConsensusCluster::new();

        let node = ConsensusNode::new(Uuid::new_v4());
        let node_id = node.id;
        cluster.add_node(node);

        cluster.elect_leader(&node_id).unwrap();

        let leader = cluster.get_leader().unwrap();
        assert_eq!(leader.id, node_id);
        assert!(leader.is_leader());
    }

    #[test]
    fn test_append_entry() {
        let mut cluster = ConsensusCluster::new();

        let node = ConsensusNode::new(Uuid::new_v4());
        let node_id = node.id;
        cluster.add_node(node);
        cluster.elect_leader(&node_id).unwrap();

        let data = serde_json::json!({"site_id": "site-123"});
        let index = cluster.append_entry("create_site", data).unwrap();

        assert_eq!(index, 0);
        assert_eq!(cluster.log.len(), 1);
    }

    #[test]
    fn test_commit() {
        let mut cluster = ConsensusCluster::new();

        let node = ConsensusNode::new(Uuid::new_v4());
        let node_id = node.id;
        cluster.add_node(node);
        cluster.elect_leader(&node_id).unwrap();

        let data = serde_json::json!({"site_id": "site-123"});
        let index = cluster.append_entry("create_site", data).unwrap();

        cluster.commit(index).unwrap();

        assert_eq!(cluster.commit_index, 0);
    }

    #[test]
    fn test_get_committed_entries() {
        let mut cluster = ConsensusCluster::new();

        let node = ConsensusNode::new(Uuid::new_v4());
        let node_id = node.id;
        cluster.add_node(node);
        cluster.elect_leader(&node_id).unwrap();

        let data1 = serde_json::json!({"id": "1"});
        let data2 = serde_json::json!({"id": "2"});

        cluster.append_entry("cmd1", data1).unwrap();
        cluster.append_entry("cmd2", data2).unwrap();

        cluster.commit(0).unwrap();

        let committed = cluster.get_committed_entries();
        assert_eq!(committed.len(), 1);
        assert_eq!(committed[0].command, "cmd1");
    }

    #[test]
    fn test_append_without_leader_fails() {
        let mut cluster = ConsensusCluster::new();

        let data = serde_json::json!({"test": "data"});
        let result = cluster.append_entry("test", data);

        assert!(result.is_err());
    }

    #[test]
    fn test_quorum() {
        let mut cluster = ConsensusCluster::new();

        let mut node1 = ConsensusNode::new(Uuid::new_v4());
        node1.heartbeat();
        cluster.add_node(node1);

        let mut node2 = ConsensusNode::new(Uuid::new_v4());
        node2.heartbeat();
        cluster.add_node(node2);

        let mut node3 = ConsensusNode::new(Uuid::new_v4());
        node3.heartbeat();
        cluster.add_node(node3);

        assert!(cluster.has_quorum());
    }
}
