//! Protocol Optimization
//!
//! Optimizes specific protocol behaviors for WAN links:
//! - TCP window scaling
//! - HTTP/HTTPS optimization
//! - DNS caching
//! - SMB/CIFS optimization

use serde::{Deserialize, Serialize};

/// Protocol type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProtocolType {
    Tcp,
    Http,
    Https,
    Dns,
    Smb,
    Nfs,
    Other,
}

/// Protocol optimizer
pub struct ProtocolOptimizer {
    tcp_window_size: u32,
    http_persistent_connections: bool,
    dns_cache_enabled: bool,
}

impl ProtocolOptimizer {
    /// Create new protocol optimizer with defaults
    pub fn new() -> Self {
        Self {
            tcp_window_size: 65535 * 4, // 256KB window
            http_persistent_connections: true,
            dns_cache_enabled: true,
        }
    }

    /// Optimize TCP parameters for WAN
    pub fn optimize_tcp(&self, _flow_id: u64) -> TcpOptimizations {
        TcpOptimizations {
            window_size: self.tcp_window_size,
            window_scaling: true,
            selective_ack: true,
            timestamps: true,
            fast_retransmit: true,
            congestion_control: "bbr".to_string(),
        }
    }

    /// Optimize HTTP/HTTPS traffic
    pub fn optimize_http(&self) -> HttpOptimizations {
        HttpOptimizations {
            persistent_connections: self.http_persistent_connections,
            pipelining: true,
            compression: true,
            cache_enabled: true,
            prefetch_enabled: true,
        }
    }

    /// Enable DNS caching
    pub fn optimize_dns(&self) -> DnsOptimizations {
        DnsOptimizations {
            cache_enabled: self.dns_cache_enabled,
            cache_ttl_seconds: 3600,
            prefetch_popular: true,
            edns_enabled: true,
        }
    }

    /// Optimize SMB/CIFS for WAN
    pub fn optimize_smb(&self) -> SmbOptimizations {
        SmbOptimizations {
            large_mtu: true,
            multichannel: true,
            compression: true,
            encryption: true,
            cache_mode: "strict".to_string(),
        }
    }

    /// Set TCP window size
    pub fn set_tcp_window_size(&mut self, size: u32) {
        self.tcp_window_size = size;
    }
}

impl Default for ProtocolOptimizer {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpOptimizations {
    pub window_size: u32,
    pub window_scaling: bool,
    pub selective_ack: bool,
    pub timestamps: bool,
    pub fast_retransmit: bool,
    pub congestion_control: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpOptimizations {
    pub persistent_connections: bool,
    pub pipelining: bool,
    pub compression: bool,
    pub cache_enabled: bool,
    pub prefetch_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsOptimizations {
    pub cache_enabled: bool,
    pub cache_ttl_seconds: u32,
    pub prefetch_popular: bool,
    pub edns_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmbOptimizations {
    pub large_mtu: bool,
    pub multichannel: bool,
    pub compression: bool,
    pub encryption: bool,
    pub cache_mode: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tcp_optimization() {
        let optimizer = ProtocolOptimizer::new();
        let tcp_opts = optimizer.optimize_tcp(1);

        assert_eq!(tcp_opts.window_size, 262140);
        assert!(tcp_opts.window_scaling);
        assert!(tcp_opts.selective_ack);
        assert_eq!(tcp_opts.congestion_control, "bbr");
    }

    #[test]
    fn test_http_optimization() {
        let optimizer = ProtocolOptimizer::new();
        let http_opts = optimizer.optimize_http();

        assert!(http_opts.persistent_connections);
        assert!(http_opts.pipelining);
        assert!(http_opts.compression);
    }

    #[test]
    fn test_dns_optimization() {
        let optimizer = ProtocolOptimizer::new();
        let dns_opts = optimizer.optimize_dns();

        assert!(dns_opts.cache_enabled);
        assert_eq!(dns_opts.cache_ttl_seconds, 3600);
        assert!(dns_opts.prefetch_popular);
    }

    #[test]
    fn test_smb_optimization() {
        let optimizer = ProtocolOptimizer::new();
        let smb_opts = optimizer.optimize_smb();

        assert!(smb_opts.large_mtu);
        assert!(smb_opts.multichannel);
        assert!(smb_opts.compression);
        assert!(smb_opts.encryption);
    }

    #[test]
    fn test_custom_window_size() {
        let mut optimizer = ProtocolOptimizer::new();
        optimizer.set_tcp_window_size(524288);

        let tcp_opts = optimizer.optimize_tcp(1);
        assert_eq!(tcp_opts.window_size, 524288);
    }
}
