// WAN optimization via LZ4 compression
//
// LZ4 is chosen for its excellent balance of:
// - High compression/decompression speed (GBps)
// - Reasonable compression ratios (typically 2-3x for text/logs)
// - Low CPU overhead
// - Well-tested and widely used

use std::io::{self, Read, Write};
use thiserror::Error;
use tracing::debug;

/// Compression errors
#[derive(Error, Debug)]
pub enum CompressionError {
    #[error("LZ4 compression failed: {0}")]
    CompressionFailed(String),

    #[error("LZ4 decompression failed: {0}")]
    DecompressionFailed(String),

    #[error("IO error: {0}")]
    Io(#[from] io::Error),

    #[error("Invalid compressed data")]
    InvalidData,
}

/// Compression level (0-16)
/// - 0: No compression (passthrough)
/// - 1-9: Fast mode (default: 1)
/// - 10-16: High compression mode
pub type CompressionLevel = u32;

/// Compression configuration
#[derive(Debug, Clone)]
pub struct CompressionConfig {
    /// Compression level (0-16)
    pub level: CompressionLevel,

    /// Minimum payload size to compress (bytes)
    /// Payloads smaller than this are not compressed
    pub min_compress_size: usize,

    /// Whether compression is enabled
    pub enabled: bool,
}

impl Default for CompressionConfig {
    fn default() -> Self {
        Self {
            level: 1, // Fast mode
            min_compress_size: 128, // Skip very small packets
            enabled: true,
        }
    }
}

/// LZ4 compression engine
pub struct CompressionEngine {
    config: CompressionConfig,
    stats: CompressionStats,
}

/// Compression statistics
#[derive(Debug, Clone, Default)]
pub struct CompressionStats {
    /// Total bytes before compression
    pub bytes_in: u64,

    /// Total bytes after compression
    pub bytes_out: u64,

    /// Number of packets compressed
    pub packets_compressed: u64,

    /// Number of packets skipped (too small or disabled)
    pub packets_skipped: u64,

    /// Number of compression errors
    pub errors: u64,
}

impl CompressionStats {
    /// Calculate compression ratio
    pub fn compression_ratio(&self) -> f64 {
        if self.bytes_in == 0 {
            return 1.0;
        }
        self.bytes_in as f64 / self.bytes_out as f64
    }

    /// Calculate percentage saved
    pub fn bytes_saved_pct(&self) -> f64 {
        if self.bytes_in == 0 {
            return 0.0;
        }
        ((self.bytes_in - self.bytes_out) as f64 / self.bytes_in as f64) * 100.0
    }

    /// Reset statistics
    pub fn reset(&mut self) {
        self.bytes_in = 0;
        self.bytes_out = 0;
        self.packets_compressed = 0;
        self.packets_skipped = 0;
        self.errors = 0;
    }
}

impl CompressionEngine {
    /// Create a new compression engine
    pub fn new(config: CompressionConfig) -> Self {
        Self {
            config,
            stats: CompressionStats::default(),
        }
    }

    /// Create with default configuration
    pub fn default_config() -> Self {
        Self::new(CompressionConfig::default())
    }

    /// Compress data
    pub fn compress(&mut self, data: &[u8]) -> Result<Vec<u8>, CompressionError> {
        // Skip if disabled
        if !self.config.enabled {
            self.stats.packets_skipped += 1;
            return Ok(data.to_vec());
        }

        // Skip if too small
        if data.len() < self.config.min_compress_size {
            self.stats.packets_skipped += 1;
            return Ok(data.to_vec());
        }

        // Compress with LZ4
        let compressed = lz4::block::compress(data, Some(lz4::block::CompressionMode::FAST(self.config.level as i32)), false)
            .map_err(|e| CompressionError::CompressionFailed(e.to_string()))?;

        // Only use compressed data if it's actually smaller
        let result = if compressed.len() < data.len() {
            self.stats.bytes_in += data.len() as u64;
            self.stats.bytes_out += compressed.len() as u64;
            self.stats.packets_compressed += 1;

            debug!(
                "Compressed packet: {} -> {} bytes ({:.1}% reduction)",
                data.len(),
                compressed.len(),
                100.0 * (1.0 - compressed.len() as f64 / data.len() as f64)
            );

            compressed
        } else {
            self.stats.bytes_in += data.len() as u64;
            self.stats.bytes_out += data.len() as u64;
            self.stats.packets_skipped += 1;

            debug!(
                "Compression not beneficial: {} -> {} bytes, using original",
                data.len(),
                compressed.len()
            );

            data.to_vec()
        };

        Ok(result)
    }

    /// Decompress data
    pub fn decompress(&mut self, data: &[u8], max_size: Option<i32>) -> Result<Vec<u8>, CompressionError> {
        // Skip if disabled or empty
        if !self.config.enabled || data.is_empty() {
            return Ok(data.to_vec());
        }

        // Set a reasonable maximum size if not specified (10 MB)
        let max_size = max_size.unwrap_or(10 * 1024 * 1024);

        // Decompress with LZ4
        let decompressed = lz4::block::decompress(data, Some(max_size))
            .map_err(|e| CompressionError::DecompressionFailed(e.to_string()))?;

        debug!(
            "Decompressed packet: {} -> {} bytes",
            data.len(),
            decompressed.len()
        );

        Ok(decompressed)
    }

    /// Compress with streaming API
    pub fn compress_stream<R: Read, W: Write>(
        &mut self,
        reader: &mut R,
        writer: &mut W,
    ) -> Result<(), CompressionError> {
        let mut encoder = lz4::EncoderBuilder::new()
            .level(self.config.level)
            .build(writer)?;

        io::copy(reader, &mut encoder)?;

        let (_, result) = encoder.finish();
        result?;

        Ok(())
    }

    /// Decompress with streaming API
    pub fn decompress_stream<R: Read, W: Write>(
        &mut self,
        reader: R,
        writer: &mut W,
    ) -> Result<(), CompressionError> {
        let mut decoder = lz4::Decoder::new(reader)?;
        io::copy(&mut decoder, writer)?;
        Ok(())
    }

    /// Get compression statistics
    pub fn stats(&self) -> &CompressionStats {
        &self.stats
    }

    /// Reset statistics
    pub fn reset_stats(&mut self) {
        self.stats.reset();
    }

    /// Get configuration
    pub fn config(&self) -> &CompressionConfig {
        &self.config
    }

    /// Update configuration
    pub fn set_config(&mut self, config: CompressionConfig) {
        self.config = config;
    }
}

/// Compressed packet wrapper
#[derive(Debug, Clone)]
pub struct CompressedPacket {
    /// Whether the data is compressed
    pub compressed: bool,

    /// Compressed or original data
    pub data: Vec<u8>,

    /// Original size (if compressed)
    pub original_size: Option<usize>,
}

impl CompressedPacket {
    /// Create from compressed data
    pub fn compressed(data: Vec<u8>, original_size: usize) -> Self {
        Self {
            compressed: true,
            data,
            original_size: Some(original_size),
        }
    }

    /// Create from uncompressed data
    pub fn uncompressed(data: Vec<u8>) -> Self {
        Self {
            compressed: false,
            data,
            original_size: None,
        }
    }

    /// Serialize to bytes with compression flag
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut result = Vec::with_capacity(self.data.len() + 9);

        // Flags (1 byte): bit 0 = compressed
        result.push(if self.compressed { 1 } else { 0 });

        // Original size (4 bytes, big-endian)
        let orig_size = self.original_size.unwrap_or(self.data.len()) as u32;
        result.extend_from_slice(&orig_size.to_be_bytes());

        // Compressed size (4 bytes, big-endian)
        let compressed_size = self.data.len() as u32;
        result.extend_from_slice(&compressed_size.to_be_bytes());

        // Data
        result.extend_from_slice(&self.data);

        result
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CompressionError> {
        if bytes.len() < 9 {
            return Err(CompressionError::InvalidData);
        }

        let flags = bytes[0];
        let compressed = (flags & 1) != 0;

        let original_size = u32::from_be_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]) as usize;
        let compressed_size = u32::from_be_bytes([bytes[5], bytes[6], bytes[7], bytes[8]]) as usize;

        if bytes.len() < 9 + compressed_size {
            return Err(CompressionError::InvalidData);
        }

        let data = bytes[9..9 + compressed_size].to_vec();

        Ok(Self {
            compressed,
            data,
            original_size: if compressed { Some(original_size) } else { None },
        })
    }

    /// Get compression ratio
    pub fn compression_ratio(&self) -> f64 {
        if let Some(orig_size) = self.original_size {
            orig_size as f64 / self.data.len() as f64
        } else {
            1.0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compress_decompress() {
        let mut engine = CompressionEngine::default_config();

        // Test data with good compressibility
        let original = b"Hello, World! ".repeat(100);

        let compressed = engine.compress(&original).unwrap();
        assert!(compressed.len() < original.len());

        let decompressed = engine.decompress(&compressed, None).unwrap();
        assert_eq!(decompressed, original);
    }

    #[test]
    fn test_small_packet_skip() {
        let mut config = CompressionConfig::default();
        config.min_compress_size = 1000;

        let mut engine = CompressionEngine::new(config);

        let small_data = b"Small packet";
        let result = engine.compress(small_data).unwrap();

        // Should not be compressed
        assert_eq!(result, small_data);
        assert_eq!(engine.stats().packets_skipped, 1);
    }

    #[test]
    fn test_compression_stats() {
        let mut engine = CompressionEngine::default_config();

        let data = b"Test data ".repeat(50);
        let _ = engine.compress(&data).unwrap();

        let stats = engine.stats();
        assert!(stats.bytes_in > 0);
        assert!(stats.bytes_out > 0);
        assert!(stats.packets_compressed > 0);
        assert!(stats.compression_ratio() > 1.0);
    }

    #[test]
    fn test_compressed_packet_serialization() {
        let original_data = b"Test data for compression".to_vec();
        let compressed_data = b"Compressed".to_vec();

        let packet = CompressedPacket::compressed(compressed_data.clone(), original_data.len());

        let bytes = packet.to_bytes();
        let parsed = CompressedPacket::from_bytes(&bytes).unwrap();

        assert_eq!(parsed.compressed, true);
        assert_eq!(parsed.data, compressed_data);
        assert_eq!(parsed.original_size, Some(original_data.len()));
    }

    #[test]
    fn test_uncompressible_data() {
        let mut engine = CompressionEngine::default_config();

        // Random data is not compressible
        let random_data: Vec<u8> = (0..200).map(|i| (i * 13 + 7) as u8).collect();

        let result = engine.compress(&random_data).unwrap();

        // Should use original data if compression doesn't help
        assert_eq!(result, random_data);
    }

    #[test]
    fn test_disabled_compression() {
        let mut config = CompressionConfig::default();
        config.enabled = false;

        let mut engine = CompressionEngine::new(config);

        let data = b"Test data ".repeat(50);
        let result = engine.compress(&data).unwrap();

        // Should return original data when disabled
        assert_eq!(result, data);
        assert_eq!(engine.stats().packets_skipped, 1);
    }

    #[test]
    fn test_compression_levels() {
        let original = b"Hello, World! ".repeat(200);

        // Test fast mode
        let mut fast_engine = CompressionEngine::new(CompressionConfig {
            level: 1,
            min_compress_size: 0,
            enabled: true,
        });

        let fast_compressed = fast_engine.compress(&original).unwrap();

        // Test high compression mode
        let mut high_engine = CompressionEngine::new(CompressionConfig {
            level: 12,
            min_compress_size: 0,
            enabled: true,
        });

        let high_compressed = high_engine.compress(&original).unwrap();

        // Both should compress, high might be slightly better
        assert!(fast_compressed.len() < original.len());
        assert!(high_compressed.len() < original.len());
    }
}
