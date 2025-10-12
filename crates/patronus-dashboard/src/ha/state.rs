//! Distributed state management using Sled embedded database

use anyhow::Result;
use serde::{Deserialize, Serialize};
use sled::Db;
use std::sync::Arc;
use tracing::{debug, info};

/// Distributed state manager for sharing data across cluster nodes
pub struct DistributedState {
    db: Arc<Db>,
    namespace: String,
}

impl DistributedState {
    /// Create a new distributed state manager
    pub fn new(data_dir: &str, namespace: &str) -> Result<Self> {
        let db = sled::open(data_dir)?;
        info!("Opened distributed state database at {}", data_dir);

        Ok(Self {
            db: Arc::new(db),
            namespace: namespace.to_string(),
        })
    }

    /// Get the full key with namespace prefix
    fn namespaced_key(&self, key: &str) -> String {
        format!("{}:{}", self.namespace, key)
    }

    /// Set a value in the distributed state
    pub fn set<T: Serialize>(&self, key: &str, value: &T) -> Result<()> {
        let serialized = serde_json::to_vec(value)?;
        let namespaced_key = self.namespaced_key(key);

        self.db.insert(namespaced_key.as_bytes(), serialized)?;
        debug!("Set key: {}", namespaced_key);

        Ok(())
    }

    /// Get a value from the distributed state
    pub fn get<T: for<'de> Deserialize<'de>>(&self, key: &str) -> Result<Option<T>> {
        let namespaced_key = self.namespaced_key(key);

        if let Some(bytes) = self.db.get(namespaced_key.as_bytes())? {
            let value: T = serde_json::from_slice(&bytes)?;
            debug!("Got key: {}", namespaced_key);
            Ok(Some(value))
        } else {
            debug!("Key not found: {}", namespaced_key);
            Ok(None)
        }
    }

    /// Delete a value from the distributed state
    pub fn delete(&self, key: &str) -> Result<()> {
        let namespaced_key = self.namespaced_key(key);
        self.db.remove(namespaced_key.as_bytes())?;
        debug!("Deleted key: {}", namespaced_key);
        Ok(())
    }

    /// Check if a key exists
    pub fn exists(&self, key: &str) -> Result<bool> {
        let namespaced_key = self.namespaced_key(key);
        Ok(self.db.contains_key(namespaced_key.as_bytes())?)
    }

    /// Get all keys with a prefix
    pub fn get_keys_with_prefix(&self, prefix: &str) -> Result<Vec<String>> {
        let full_prefix = self.namespaced_key(prefix);
        let mut keys = Vec::new();

        for item in self.db.scan_prefix(full_prefix.as_bytes()) {
            let (key, _) = item?;
            if let Ok(key_str) = String::from_utf8(key.to_vec()) {
                // Remove namespace prefix before returning
                let prefix_len = self.namespace.len() + 1; // +1 for the ':'
                if key_str.len() > prefix_len {
                    keys.push(key_str[prefix_len..].to_string());
                }
            }
        }

        Ok(keys)
    }

    /// Delete all keys with a prefix
    pub fn delete_prefix(&self, prefix: &str) -> Result<usize> {
        let full_prefix = self.namespaced_key(prefix);
        let mut count = 0;

        let keys_to_delete: Vec<_> = self
            .db
            .scan_prefix(full_prefix.as_bytes())
            .filter_map(|r| r.ok())
            .map(|(k, _)| k)
            .collect();

        for key in keys_to_delete {
            self.db.remove(&key)?;
            count += 1;
        }

        debug!("Deleted {} keys with prefix: {}", count, full_prefix);
        Ok(count)
    }

    /// Flush data to disk
    pub fn flush(&self) -> Result<usize> {
        Ok(self.db.flush()?)
    }

    /// Get database size in bytes
    pub fn size_on_disk(&self) -> Result<u64> {
        Ok(self.db.size_on_disk()?)
    }

    /// Export a snapshot of the database
    pub fn export_snapshot(&self) -> Result<Vec<(String, Vec<u8>)>> {
        let mut snapshot = Vec::new();
        let prefix = format!("{}:", self.namespace);

        for item in self.db.scan_prefix(prefix.as_bytes()) {
            let (key, value) = item?;
            if let Ok(key_str) = String::from_utf8(key.to_vec()) {
                snapshot.push((key_str, value.to_vec()));
            }
        }

        info!("Exported snapshot with {} entries", snapshot.len());
        Ok(snapshot)
    }

    /// Import a snapshot into the database
    pub fn import_snapshot(&self, snapshot: Vec<(String, Vec<u8>)>) -> Result<()> {
        for (key, value) in snapshot {
            self.db.insert(key.as_bytes(), value)?;
        }

        self.db.flush()?;
        info!("Imported snapshot with entries");
        Ok(())
    }

    /// Clear all data in this namespace
    pub fn clear(&self) -> Result<usize> {
        self.delete_prefix("")
    }

    /// Watch a key for changes
    pub fn watch(&self, key: &str) -> sled::Subscriber {
        let namespaced_key = self.namespaced_key(key);
        self.db.watch_prefix(namespaced_key.as_bytes())
    }

    /// Batch write operations
    pub fn batch_write<F>(&self, f: F) -> Result<()>
    where
        F: FnOnce(&mut Batch) -> Result<()>,
    {
        let mut batch = Batch::new(self.db.clone(), &self.namespace);
        f(&mut batch)?;
        batch.commit()?;
        Ok(())
    }
}

/// Batch operations for atomic writes
pub struct Batch {
    db: Arc<Db>,
    namespace: String,
    batch: sled::Batch,
}

impl Batch {
    fn new(db: Arc<Db>, namespace: &str) -> Self {
        Self {
            db,
            namespace: namespace.to_string(),
            batch: sled::Batch::default(),
        }
    }

    fn namespaced_key(&self, key: &str) -> String {
        format!("{}:{}", self.namespace, key)
    }

    /// Insert a value in the batch
    pub fn insert<T: Serialize>(&mut self, key: &str, value: &T) -> Result<()> {
        let serialized = serde_json::to_vec(value)?;
        let namespaced_key = self.namespaced_key(key);
        self.batch.insert(namespaced_key.as_bytes(), serialized);
        Ok(())
    }

    /// Remove a key in the batch
    pub fn remove(&mut self, key: &str) {
        let namespaced_key = self.namespaced_key(key);
        self.batch.remove(namespaced_key.as_bytes());
    }

    /// Commit the batch
    fn commit(self) -> Result<()> {
        self.db.apply_batch(self.batch)?;
        Ok(())
    }
}

/// Session data stored in distributed state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionData {
    pub user_id: String,
    pub token_id: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub last_activity: chrono::DateTime<chrono::Utc>,
    pub metadata: serde_json::Value,
}

impl SessionData {
    pub fn new(user_id: String, token_id: String) -> Self {
        let now = chrono::Utc::now();
        Self {
            user_id,
            token_id,
            created_at: now,
            last_activity: now,
            metadata: serde_json::Value::Null,
        }
    }

    pub fn update_activity(&mut self) {
        self.last_activity = chrono::Utc::now();
    }
}

/// Cluster metadata stored in distributed state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterMetadata {
    pub version: String,
    pub cluster_id: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_state_creation() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let state = DistributedState::new(
            temp_dir.path().to_str().unwrap(),
            "test",
        )?;

        assert_eq!(state.namespace, "test");
        Ok(())
    }

    #[test]
    fn test_set_and_get() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let state = DistributedState::new(
            temp_dir.path().to_str().unwrap(),
            "test",
        )?;

        #[derive(Serialize, Deserialize, PartialEq, Debug)]
        struct TestData {
            value: i32,
        }

        let data = TestData { value: 42 };
        state.set("key1", &data)?;

        let retrieved: Option<TestData> = state.get("key1")?;
        assert_eq!(retrieved, Some(data));

        Ok(())
    }

    #[test]
    fn test_delete() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let state = DistributedState::new(
            temp_dir.path().to_str().unwrap(),
            "test",
        )?;

        state.set("key1", &"value1")?;
        assert!(state.exists("key1")?);

        state.delete("key1")?;
        assert!(!state.exists("key1")?);

        Ok(())
    }

    #[test]
    fn test_prefix_operations() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let state = DistributedState::new(
            temp_dir.path().to_str().unwrap(),
            "test",
        )?;

        state.set("user:1", &"alice")?;
        state.set("user:2", &"bob")?;
        state.set("session:1", &"xyz")?;

        let user_keys = state.get_keys_with_prefix("user:")?;
        assert_eq!(user_keys.len(), 2);

        let deleted = state.delete_prefix("user:")?;
        assert_eq!(deleted, 2);

        let remaining_user_keys = state.get_keys_with_prefix("user:")?;
        assert_eq!(remaining_user_keys.len(), 0);

        // Session key should still exist
        assert!(state.exists("session:1")?);

        Ok(())
    }

    #[test]
    fn test_batch_operations() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let state = DistributedState::new(
            temp_dir.path().to_str().unwrap(),
            "test",
        )?;

        state.batch_write(|batch| {
            batch.insert("key1", &"value1")?;
            batch.insert("key2", &"value2")?;
            batch.insert("key3", &"value3")?;
            Ok(())
        })?;

        let val1: Option<String> = state.get("key1")?;
        let val2: Option<String> = state.get("key2")?;
        let val3: Option<String> = state.get("key3")?;

        assert_eq!(val1, Some("value1".to_string()));
        assert_eq!(val2, Some("value2".to_string()));
        assert_eq!(val3, Some("value3".to_string()));

        Ok(())
    }

    #[test]
    fn test_session_data() {
        let session = SessionData::new("user123".to_string(), "token456".to_string());

        assert_eq!(session.user_id, "user123");
        assert_eq!(session.token_id, "token456");
        assert_eq!(session.created_at, session.last_activity);
    }
}
