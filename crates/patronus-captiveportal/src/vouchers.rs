//! Voucher management system for guest access

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use chrono::{DateTime, Utc, Duration};
use rand::Rng;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Voucher {
    pub code: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub duration_hours: u32,
    pub max_uses: u32,
    pub used_count: u32,
    pub bandwidth_limit_kbps: Option<u64>,
    pub quota_mb: Option<u64>,
    pub created_by: String,
    pub notes: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VoucherBatch {
    pub batch_id: String,
    pub created_at: DateTime<Utc>,
    pub count: u32,
    pub vouchers: Vec<Voucher>,
}

pub struct VoucherManager {
    vouchers: HashMap<String, Voucher>,
    batches: HashMap<String, VoucherBatch>,
}

impl VoucherManager {
    pub fn new() -> Self {
        Self {
            vouchers: HashMap::new(),
            batches: HashMap::new(),
        }
    }

    /// Generate a batch of vouchers
    pub async fn generate_batch(
        &mut self,
        count: u32,
        duration_hours: u32,
        bandwidth_limit_kbps: Option<u64>,
        created_by: String,
    ) -> VoucherBatch {
        let batch_id = Self::generate_batch_id();
        let mut vouchers = Vec::new();

        for _ in 0..count {
            let voucher = self.create_voucher(
                duration_hours,
                1,  // Single use
                bandwidth_limit_kbps,
                created_by.clone(),
            );
            vouchers.push(voucher);
        }

        let batch = VoucherBatch {
            batch_id: batch_id.clone(),
            created_at: Utc::now(),
            count,
            vouchers: vouchers.clone(),
        };

        // Store vouchers
        for voucher in vouchers {
            self.vouchers.insert(voucher.code.clone(), voucher);
        }

        self.batches.insert(batch_id.clone(), batch.clone());

        batch
    }

    fn create_voucher(
        &self,
        duration_hours: u32,
        max_uses: u32,
        bandwidth_limit_kbps: Option<u64>,
        created_by: String,
    ) -> Voucher {
        Voucher {
            code: Self::generate_code(),
            created_at: Utc::now(),
            expires_at: Utc::now() + Duration::hours(duration_hours as i64),
            duration_hours,
            max_uses,
            used_count: 0,
            bandwidth_limit_kbps,
            quota_mb: None,
            created_by,
            notes: None,
        }
    }

    /// Redeem a voucher
    pub async fn redeem(&mut self, code: &str) -> Result<Voucher, VoucherError> {
        let voucher = self.vouchers.get_mut(code)
            .ok_or(VoucherError::NotFound)?;

        // Check expiry
        if Utc::now() > voucher.expires_at {
            return Err(VoucherError::Expired);
        }

        // Check use count
        if voucher.used_count >= voucher.max_uses {
            return Err(VoucherError::MaxUsesReached);
        }

        voucher.used_count += 1;

        Ok(voucher.clone())
    }

    /// Check voucher validity
    pub async fn check(&self, code: &str) -> Result<&Voucher, VoucherError> {
        let voucher = self.vouchers.get(code)
            .ok_or(VoucherError::NotFound)?;

        if Utc::now() > voucher.expires_at {
            return Err(VoucherError::Expired);
        }

        if voucher.used_count >= voucher.max_uses {
            return Err(VoucherError::MaxUsesReached);
        }

        Ok(voucher)
    }

    /// List all vouchers
    pub fn list_all(&self) -> Vec<&Voucher> {
        self.vouchers.values().collect()
    }

    /// Delete expired vouchers
    pub async fn cleanup_expired(&mut self) {
        let now = Utc::now();
        self.vouchers.retain(|_, v| v.expires_at > now);
    }

    fn generate_code() -> String {
        // Generate format: XXXX-XXXX-XXXX (12 chars)
        let mut rng = rand::thread_rng();
        let chars: String = (0..12)
            .map(|i| {
                if i > 0 && i % 4 == 0 {
                    '-'
                } else {
                    let charset = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";  // No confusing chars
                    charset[rng.gen_range(0..charset.len())] as char
                }
            })
            .collect();
        chars
    }

    fn generate_batch_id() -> String {
        format!("BATCH-{}", Utc::now().timestamp())
    }

    /// Export vouchers to CSV for printing
    pub fn export_to_csv(&self, batch_id: &str) -> Result<String, VoucherError> {
        let batch = self.batches.get(batch_id)
            .ok_or(VoucherError::NotFound)?;

        let mut csv = String::from("Code,Duration,Bandwidth Limit,Expires At\n");

        for voucher in &batch.vouchers {
            csv.push_str(&format!(
                "{},{} hours,{},{}\n",
                voucher.code,
                voucher.duration_hours,
                voucher.bandwidth_limit_kbps.map(|b| format!("{} kbps", b)).unwrap_or_else(|| "Unlimited".to_string()),
                voucher.expires_at.format("%Y-%m-%d %H:%M")
            ));
        }

        Ok(csv)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum VoucherError {
    #[error("Voucher not found")]
    NotFound,
    #[error("Voucher has expired")]
    Expired,
    #[error("Voucher maximum uses reached")]
    MaxUsesReached,
}
