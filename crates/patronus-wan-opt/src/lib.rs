//! WAN Optimization Module
//!
//! Provides WAN optimization techniques for improving throughput and reducing bandwidth:
//! - Data deduplication
//! - Protocol optimization
//! - Compression
//! - Forward Error Correction (FEC)

pub mod compression;
pub mod dedup;
pub mod fec;
pub mod protocol;

pub use compression::{CompressionType, Compressor};
pub use dedup::{DedupStats, Deduplicator};
pub use fec::{FecDecoder, FecEncoder, FecStats};
pub use protocol::{ProtocolOptimizer, ProtocolType};
