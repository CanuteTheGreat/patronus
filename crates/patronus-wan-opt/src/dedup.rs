//! Data Deduplication
//!
//! Uses content-defined chunking and SHA-256 hashing to detect and eliminate
//! duplicate data across the WAN

use sha2::{Sha256, Digest};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use serde::{Deserialize, Serialize};

/// Chunk size for deduplication (default 4KB)
const DEFAULT_CHUNK_SIZE: usize = 4096;

/// Deduplication statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DedupStats {
    pub total_bytes: u64,
    pub unique_bytes: u64,
    pub duplicate_bytes: u64,
    pub chunks_total: u64,
    pub chunks_unique: u64,
    pub chunks_duplicate: u64,
}

impl DedupStats {
    /// Calculate deduplication ratio
    pub fn dedup_ratio(&self) -> f64 {
        if self.total_bytes == 0 {
            0.0
        } else {
            self.duplicate_bytes as f64 / self.total_bytes as f64
        }
    }

    /// Calculate space savings percentage
    pub fn space_savings_pct(&self) -> f64 {
        self.dedup_ratio() * 100.0
    }
}

/// Chunk hash (SHA-256)
type ChunkHash = [u8; 32];

/// Data deduplicator
pub struct Deduplicator {
    chunk_size: usize,
    chunk_store: Arc<RwLock<HashMap<ChunkHash, Vec<u8>>>>,
    stats: Arc<RwLock<DedupStats>>,
}

impl Deduplicator {
    /// Create new deduplicator
    pub fn new() -> Self {
        Self {
            chunk_size: DEFAULT_CHUNK_SIZE,
            chunk_store: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(RwLock::new(DedupStats::default())),
        }
    }

    /// Create deduplicator with custom chunk size
    pub fn with_chunk_size(chunk_size: usize) -> Self {
        Self {
            chunk_size,
            chunk_store: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(RwLock::new(DedupStats::default())),
        }
    }

    /// Deduplicate data, returns chunk hashes
    pub async fn deduplicate(&self, data: &[u8]) -> Vec<ChunkHash> {
        let mut hashes = Vec::new();
        let mut chunk_store = self.chunk_store.write().await;
        let mut stats = self.stats.write().await;

        stats.total_bytes += data.len() as u64;

        for chunk in data.chunks(self.chunk_size) {
            let hash = Self::hash_chunk(chunk);
            stats.chunks_total += 1;

            if chunk_store.contains_key(&hash) {
                // Duplicate chunk
                stats.chunks_duplicate += 1;
                stats.duplicate_bytes += chunk.len() as u64;
            } else {
                // Unique chunk
                chunk_store.insert(hash, chunk.to_vec());
                stats.chunks_unique += 1;
                stats.unique_bytes += chunk.len() as u64;
            }

            hashes.push(hash);
        }

        hashes
    }

    /// Reconstruct data from chunk hashes
    pub async fn reconstruct(&self, hashes: &[ChunkHash]) -> Option<Vec<u8>> {
        let chunk_store = self.chunk_store.read().await;
        let mut data = Vec::new();

        for hash in hashes {
            if let Some(chunk) = chunk_store.get(hash) {
                data.extend_from_slice(chunk);
            } else {
                // Missing chunk
                return None;
            }
        }

        Some(data)
    }

    /// Get statistics
    pub async fn get_stats(&self) -> DedupStats {
        self.stats.read().await.clone()
    }

    /// Clear chunk store (for testing)
    pub async fn clear(&self) {
        let mut chunk_store = self.chunk_store.write().await;
        let mut stats = self.stats.write().await;
        chunk_store.clear();
        *stats = DedupStats::default();
    }

    /// Hash a chunk using SHA-256
    fn hash_chunk(data: &[u8]) -> ChunkHash {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.finalize().into()
    }
}

impl Default for Deduplicator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_deduplication() {
        let dedup = Deduplicator::new();

        let data = b"Hello, World!".repeat(10);
        let hashes = dedup.deduplicate(&data).await;

        assert!(!hashes.is_empty());

        let reconstructed = dedup.reconstruct(&hashes).await.unwrap();
        assert_eq!(reconstructed, data);
    }

    #[tokio::test]
    async fn test_duplicate_detection() {
        let dedup = Deduplicator::with_chunk_size(10);

        // First pass
        let data1 = b"0123456789ABCDEFGHIJ";
        let hashes1 = dedup.deduplicate(data1).await;

        // Second pass with same data
        let hashes2 = dedup.deduplicate(data1).await;

        // Should have same hashes
        assert_eq!(hashes1, hashes2);

        let stats = dedup.get_stats().await;
        assert!(stats.duplicate_bytes > 0);
        assert!(stats.dedup_ratio() > 0.0);
    }

    #[tokio::test]
    async fn test_dedup_stats() {
        let dedup = Deduplicator::with_chunk_size(5);

        let data = b"AAAAABBBBBCCCCCDDDDD"; // 20 bytes, 4 chunks
        dedup.deduplicate(data).await;

        let stats = dedup.get_stats().await;
        assert_eq!(stats.total_bytes, 20);
        assert_eq!(stats.chunks_total, 4);
        assert_eq!(stats.chunks_unique, 4);

        // Add duplicate data
        dedup.deduplicate(data).await;

        let stats = dedup.get_stats().await;
        assert_eq!(stats.total_bytes, 40);
        assert_eq!(stats.chunks_total, 8);
        assert_eq!(stats.chunks_unique, 4);
        assert_eq!(stats.chunks_duplicate, 4);
        assert_eq!(stats.space_savings_pct(), 50.0);
    }
}
