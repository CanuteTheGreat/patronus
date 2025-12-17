//! Compression Module
//!
//! Supports multiple compression algorithms optimized for different use cases

use anyhow::{Context, Result};
use flate2::read::{GzDecoder, GzEncoder};
use flate2::Compression as GzCompression;
use std::io::Read;

/// Compression algorithm
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompressionType {
    /// No compression
    None,
    /// Gzip compression (good balance)
    Gzip,
    /// LZ4 (fast compression, lower ratio)
    Lz4,
    /// Zstd (best ratio, good speed)
    Zstd,
}

/// Data compressor
pub struct Compressor {
    compression_type: CompressionType,
}

impl Compressor {
    /// Create new compressor with specified algorithm
    pub fn new(compression_type: CompressionType) -> Self {
        Self { compression_type }
    }

    /// Compress data
    pub fn compress(&self, data: &[u8]) -> Result<Vec<u8>> {
        match self.compression_type {
            CompressionType::None => Ok(data.to_vec()),
            CompressionType::Gzip => self.compress_gzip(data),
            CompressionType::Lz4 => self.compress_lz4(data),
            CompressionType::Zstd => self.compress_zstd(data),
        }
    }

    /// Decompress data
    pub fn decompress(&self, data: &[u8]) -> Result<Vec<u8>> {
        match self.compression_type {
            CompressionType::None => Ok(data.to_vec()),
            CompressionType::Gzip => self.decompress_gzip(data),
            CompressionType::Lz4 => self.decompress_lz4(data),
            CompressionType::Zstd => self.decompress_zstd(data),
        }
    }

    /// Calculate compression ratio
    pub fn compression_ratio(&self, original_size: usize, compressed_size: usize) -> f64 {
        if original_size == 0 {
            0.0
        } else {
            compressed_size as f64 / original_size as f64
        }
    }

    // Gzip implementation
    fn compress_gzip(&self, data: &[u8]) -> Result<Vec<u8>> {
        let mut encoder = GzEncoder::new(data, GzCompression::default());
        let mut compressed = Vec::new();
        encoder.read_to_end(&mut compressed)
            .context("Gzip compression failed")?;
        Ok(compressed)
    }

    fn decompress_gzip(&self, data: &[u8]) -> Result<Vec<u8>> {
        let mut decoder = GzDecoder::new(data);
        let mut decompressed = Vec::new();
        decoder.read_to_end(&mut decompressed)
            .context("Gzip decompression failed")?;
        Ok(decompressed)
    }

    // LZ4 implementation
    fn compress_lz4(&self, data: &[u8]) -> Result<Vec<u8>> {
        lz4::block::compress(data, None, true)
            .context("LZ4 compression failed")
    }

    fn decompress_lz4(&self, data: &[u8]) -> Result<Vec<u8>> {
        lz4::block::decompress(data, None)
            .context("LZ4 decompression failed")
    }

    // Zstd implementation
    fn compress_zstd(&self, data: &[u8]) -> Result<Vec<u8>> {
        zstd::bulk::compress(data, 3)
            .context("Zstd compression failed")
    }

    fn decompress_zstd(&self, data: &[u8]) -> Result<Vec<u8>> {
        zstd::bulk::decompress(data, data.len() * 100)
            .context("Zstd decompression failed")
    }
}

impl Default for Compressor {
    fn default() -> Self {
        Self::new(CompressionType::Zstd)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gzip_compression() {
        let compressor = Compressor::new(CompressionType::Gzip);
        let data = b"Hello, World! ".repeat(100);

        let compressed = compressor.compress(&data).unwrap();
        assert!(compressed.len() < data.len());

        let decompressed = compressor.decompress(&compressed).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_lz4_compression() {
        let compressor = Compressor::new(CompressionType::Lz4);
        let data = b"The quick brown fox jumps over the lazy dog. ".repeat(50);

        let compressed = compressor.compress(&data).unwrap();
        assert!(compressed.len() < data.len());

        let decompressed = compressor.decompress(&compressed).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_zstd_compression() {
        let compressor = Compressor::new(CompressionType::Zstd);
        let data = b"Lorem ipsum dolor sit amet, consectetur adipiscing elit. ".repeat(100);

        let compressed = compressor.compress(&data).unwrap();
        assert!(compressed.len() < data.len());

        let decompressed = compressor.decompress(&compressed).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_no_compression() {
        let compressor = Compressor::new(CompressionType::None);
        let data = b"Test data";

        let compressed = compressor.compress(data).unwrap();
        assert_eq!(compressed, data);

        let decompressed = compressor.decompress(&compressed).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_compression_ratio() {
        let compressor = Compressor::new(CompressionType::Gzip);
        let original_size = 1000;
        let compressed_size = 500;

        let ratio = compressor.compression_ratio(original_size, compressed_size);
        assert_eq!(ratio, 0.5);
    }
}
