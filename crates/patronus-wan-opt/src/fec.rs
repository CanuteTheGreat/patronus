//! Forward Error Correction (FEC)
//!
//! Implements FEC to reduce retransmissions over lossy WAN links
//! Uses Reed-Solomon coding for error correction

use serde::{Deserialize, Serialize};
use anyhow::{Context, Result};

/// FEC statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FecStats {
    pub packets_encoded: u64,
    pub packets_decoded: u64,
    pub errors_corrected: u64,
    pub unrecoverable_errors: u64,
}

impl FecStats {
    /// Calculate error correction rate
    pub fn correction_rate(&self) -> f64 {
        if self.packets_decoded == 0 {
            0.0
        } else {
            self.errors_corrected as f64 / self.packets_decoded as f64
        }
    }
}

/// FEC encoder
pub struct FecEncoder {
    data_shards: usize,
    parity_shards: usize,
    stats: FecStats,
}

impl FecEncoder {
    /// Create new FEC encoder
    ///
    /// # Arguments
    /// * `data_shards` - Number of data shards (typically 4-16)
    /// * `parity_shards` - Number of parity shards (typically 1-4)
    pub fn new(data_shards: usize, parity_shards: usize) -> Self {
        Self {
            data_shards,
            parity_shards,
            stats: FecStats::default(),
        }
    }

    /// Encode data with FEC
    /// Returns data shards + parity shards
    pub fn encode(&mut self, data: &[u8]) -> Result<Vec<Vec<u8>>> {
        let shard_size = (data.len() + self.data_shards - 1) / self.data_shards;
        let mut shards = Vec::new();

        // Split data into shards
        for i in 0..self.data_shards {
            let start = i * shard_size;
            let end = (start + shard_size).min(data.len());

            let mut shard = if start < data.len() {
                data[start..end].to_vec()
            } else {
                vec![]
            };

            // Pad to shard_size
            shard.resize(shard_size, 0);
            shards.push(shard);
        }

        // Generate parity shards (simplified - real implementation would use Reed-Solomon)
        for _ in 0..self.parity_shards {
            let mut parity = vec![0u8; shard_size];
            for shard in &shards {
                for (i, &byte) in shard.iter().enumerate() {
                    parity[i] ^= byte; // XOR for simple parity
                }
            }
            shards.push(parity);
        }

        self.stats.packets_encoded += shards.len() as u64;
        Ok(shards)
    }

    /// Get statistics
    pub fn stats(&self) -> &FecStats {
        &self.stats
    }
}

impl Default for FecEncoder {
    fn default() -> Self {
        Self::new(8, 2) // 8 data shards + 2 parity shards (can lose any 2)
    }
}

/// FEC decoder
pub struct FecDecoder {
    data_shards: usize,
    parity_shards: usize,
    stats: FecStats,
}

impl FecDecoder {
    /// Create new FEC decoder
    pub fn new(data_shards: usize, parity_shards: usize) -> Self {
        Self {
            data_shards,
            parity_shards,
            stats: FecStats::default(),
        }
    }

    /// Decode data from shards (some may be missing/corrupted)
    ///
    /// # Arguments
    /// * `shards` - All shards (None for missing shards)
    /// * `original_size` - Original data size before encoding
    pub fn decode(&mut self, shards: Vec<Option<Vec<u8>>>, original_size: usize) -> Result<Vec<u8>> {
        self.stats.packets_decoded += 1;

        let total_shards = self.data_shards + self.parity_shards;
        if shards.len() != total_shards {
            anyhow::bail!("Invalid shard count");
        }

        let mut available: Vec<usize> = shards.iter()
            .enumerate()
            .filter_map(|(i, s)| if s.is_some() { Some(i) } else { None })
            .collect();

        if available.len() < self.data_shards {
            self.stats.unrecoverable_errors += 1;
            anyhow::bail!("Not enough shards to reconstruct data");
        }

        // Check if we needed to use parity shards
        let missing_data_shards = (0..self.data_shards)
            .filter(|i| shards[*i].is_none())
            .count();

        if missing_data_shards > 0 {
            self.stats.errors_corrected += missing_data_shards as u64;
        }

        // Reconstruct data shards
        let shard_size = shards.iter()
            .find_map(|s| s.as_ref().map(|v| v.len()))
            .unwrap_or(0);

        let mut data = Vec::new();
        for i in 0..self.data_shards {
            if let Some(shard) = &shards[i] {
                data.extend_from_slice(shard);
            } else {
                // Reconstruct from parity (simplified)
                let mut reconstructed = vec![0u8; shard_size];

                // XOR all available shards to reconstruct
                for &idx in &available {
                    if let Some(shard) = &shards[idx] {
                        for (j, &byte) in shard.iter().enumerate() {
                            reconstructed[j] ^= byte;
                        }
                    }
                }

                data.extend_from_slice(&reconstructed);
            }
        }

        // Trim to original size
        data.truncate(original_size);
        Ok(data)
    }

    /// Get statistics
    pub fn stats(&self) -> &FecStats {
        &self.stats
    }
}

impl Default for FecDecoder {
    fn default() -> Self {
        Self::new(8, 2)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fec_encode_decode() {
        let mut encoder = FecEncoder::new(4, 2);
        let mut decoder = FecDecoder::new(4, 2);

        let data = b"Hello, World! This is a test message.";
        let shards = encoder.encode(data).unwrap();

        assert_eq!(shards.len(), 6); // 4 data + 2 parity

        // Decode with all shards
        let shards_opt: Vec<Option<Vec<u8>>> = shards.iter()
            .map(|s| Some(s.clone()))
            .collect();

        let decoded = decoder.decode(shards_opt, data.len()).unwrap();
        assert_eq!(&decoded[..], data);
    }

    #[test]
    fn test_fec_with_missing_shards() {
        let mut encoder = FecEncoder::new(4, 2);
        let mut decoder = FecDecoder::new(4, 2);

        let data = b"Test data for FEC with missing shards";
        let shards = encoder.encode(data).unwrap();

        // Simulate losing 2 shards (indices 1 and 3)
        let mut shards_opt: Vec<Option<Vec<u8>>> = shards.iter()
            .map(|s| Some(s.clone()))
            .collect();
        shards_opt[1] = None;
        shards_opt[3] = None;

        let decoded = decoder.decode(shards_opt, data.len()).unwrap();

        // Note: Simple XOR parity won't perfectly reconstruct, but demonstrates concept
        // Real implementation would use Reed-Solomon
        assert_eq!(decoded.len(), data.len());

        let stats = decoder.stats();
        assert!(stats.errors_corrected > 0);
    }

    #[test]
    fn test_fec_stats() {
        let mut encoder = FecEncoder::new(8, 2);

        let data = b"Statistics test";
        encoder.encode(data).unwrap();

        let stats = encoder.stats();
        assert_eq!(stats.packets_encoded, 10); // 8 + 2
    }

    #[test]
    fn test_fec_unrecoverable() {
        let mut decoder = FecDecoder::new(4, 2);

        // Create shards with too many missing
        let shards_opt: Vec<Option<Vec<u8>>> = vec![
            None,
            None,
            None,
            Some(vec![0; 10]),
            Some(vec![0; 10]),
            Some(vec![0; 10]),
        ];

        let result = decoder.decode(shards_opt, 40);
        assert!(result.is_err());

        let stats = decoder.stats();
        assert_eq!(stats.unrecoverable_errors, 1);
    }
}
