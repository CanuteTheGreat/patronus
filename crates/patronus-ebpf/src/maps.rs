//! eBPF Map Types

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MapType {
    Hash,
    Array,
    LRU,
    PerCpuHash,
    PerCpuArray,
}

pub struct BpfMap {
    pub name: String,
    pub map_type: MapType,
    pub key_size: u32,
    pub value_size: u32,
    pub max_entries: u32,
}
