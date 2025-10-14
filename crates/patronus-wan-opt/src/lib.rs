//! WAN Optimization Module
//!
//! Provides WAN optimization techniques for improving throughput and reducing bandwidth:
//! - Data deduplication
//! - Protocol optimization
//! - Compression
//! - Forward Error Correction (FEC)

pub mod dedup;
pub mod protocol;
pub mod compression;
pub mod fec;

pub use dedup::{Deduplicator, DedupStats};
pub use protocol::{ProtocolOptimizer, ProtocolType};
pub use compression::{Compressor, CompressionType};
pub use fec::{FecEncoder, FecDecoder, FecStats};
