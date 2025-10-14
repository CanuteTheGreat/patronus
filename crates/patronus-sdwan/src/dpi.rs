//! Deep Packet Inspection (DPI) Engine
//!
//! Classifies network traffic by application type for intelligent routing and QoS.
//!
//! # Supported Application Types
//!
//! - Web (HTTP/HTTPS)
//! - Video (Netflix, YouTube, streaming)
//! - VoIP (SIP, RTP)
//! - Gaming (UDP-based games)
//! - File Transfer (FTP, SFTP, rsync)
//! - Database (MySQL, PostgreSQL, Redis)
//! - Unknown (unclassified traffic)

use crate::types::FlowKey;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use tracing::{debug, trace};

/// Application type classification
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ApplicationType {
    Web,
    Video,
    VoIP,
    Gaming,
    FileTransfer,
    Database,
    Unknown,
}

impl ApplicationType {
    /// Convert to string representation
    pub fn as_str(&self) -> &'static str {
        match self {
            ApplicationType::Web => "Web",
            ApplicationType::Video => "Video",
            ApplicationType::VoIP => "VoIP",
            ApplicationType::Gaming => "Gaming",
            ApplicationType::FileTransfer => "FileTransfer",
            ApplicationType::Database => "Database",
            ApplicationType::Unknown => "Unknown",
        }
    }
}

/// Trait for traffic classifiers
pub trait Classifier: Send + Sync {
    /// Classify a packet and return application type if matched
    fn classify(&self, packet: &[u8], flow: &FlowKey) -> Option<ApplicationType>;

    /// Get classifier name
    fn name(&self) -> &'static str;
}

/// Port-based classifier (simple but fast)
pub struct PortClassifier;

impl Classifier for PortClassifier {
    fn classify(&self, _packet: &[u8], flow: &FlowKey) -> Option<ApplicationType> {
        // Extract destination port from flow key
        let dst_port = flow.dst_port;

        match dst_port {
            // Web
            80 | 443 | 8080 | 8443 => Some(ApplicationType::Web),

            // VoIP
            5060 | 5061 => Some(ApplicationType::VoIP), // SIP

            // Gaming (common game ports)
            27015..=27030 => Some(ApplicationType::Gaming), // Source engine
            25565 => Some(ApplicationType::Gaming), // Minecraft
            3074 => Some(ApplicationType::Gaming), // Xbox Live

            // File Transfer
            20 | 21 => Some(ApplicationType::FileTransfer), // FTP
            22 => Some(ApplicationType::FileTransfer), // SFTP
            873 => Some(ApplicationType::FileTransfer), // rsync

            // Database
            3306 => Some(ApplicationType::Database), // MySQL
            5432 => Some(ApplicationType::Database), // PostgreSQL
            6379 => Some(ApplicationType::Database), // Redis

            _ => None,
        }
    }

    fn name(&self) -> &'static str {
        "PortClassifier"
    }
}

/// HTTP classifier (inspects HTTP headers)
pub struct HttpClassifier;

impl Classifier for HttpClassifier {
    fn classify(&self, packet: &[u8], flow: &FlowKey) -> Option<ApplicationType> {
        // Only check TCP traffic on web ports
        if flow.protocol != 6 || (flow.dst_port != 80 && flow.dst_port != 8080) {
            return None;
        }

        // Check if packet starts with HTTP method
        if packet.len() < 10 {
            return None;
        }

        let header = String::from_utf8_lossy(&packet[..std::cmp::min(100, packet.len())]);

        // Look for HTTP methods
        if header.starts_with("GET ") || header.starts_with("POST ") ||
           header.starts_with("PUT ") || header.starts_with("HEAD ") {
            // Check for video streaming patterns
            if header.contains("video/") || header.contains("youtube") ||
               header.contains("netflix") || header.contains("stream") {
                return Some(ApplicationType::Video);
            }

            return Some(ApplicationType::Web);
        }

        None
    }

    fn name(&self) -> &'static str {
        "HttpClassifier"
    }
}

/// RTP (Real-time Transport Protocol) classifier for VoIP/Video
pub struct RtpClassifier;

impl Classifier for RtpClassifier {
    fn classify(&self, packet: &[u8], flow: &FlowKey) -> Option<ApplicationType> {
        // RTP typically uses UDP on high ports
        if flow.protocol != 17 || packet.len() < 12 {
            return None;
        }

        // Check RTP header
        // Version should be 2 (bits 0-1 of first byte)
        let version = (packet[0] >> 6) & 0x03;
        if version != 2 {
            return None;
        }

        // Check payload type (byte 1, bits 0-6)
        let payload_type = packet[1] & 0x7F;

        // Audio codecs: 0-23, 96-127
        // Video codecs: 24-34, 96-127
        if payload_type <= 34 || payload_type >= 96 {
            // Check if this looks like VoIP (small packets, high frequency)
            if packet.len() < 200 {
                return Some(ApplicationType::VoIP);
            } else {
                return Some(ApplicationType::Video);
            }
        }

        None
    }

    fn name(&self) -> &'static str {
        "RtpClassifier"
    }
}

/// UDP gaming traffic classifier
pub struct GamingClassifier;

impl Classifier for GamingClassifier {
    fn classify(&self, packet: &[u8], flow: &FlowKey) -> Option<ApplicationType> {
        // Games use UDP with small, frequent packets
        if flow.protocol != 17 {
            return None;
        }

        // Gaming packets are usually 50-500 bytes
        if packet.len() < 50 || packet.len() > 500 {
            return None;
        }

        // Check for common gaming signatures
        // This is a simplified heuristic - real DPI would have more patterns
        let port = flow.dst_port;

        // Common game port ranges
        if (port >= 7000 && port <= 8000) ||  // Many FPS games
           (port >= 27000 && port <= 28000) || // Source engine
           (port >= 3000 && port <= 4000) {    // Various games
            return Some(ApplicationType::Gaming);
        }

        None
    }

    fn name(&self) -> &'static str {
        "GamingClassifier"
    }
}

/// DPI Engine coordinating multiple classifiers
pub struct DpiEngine {
    /// Ordered list of classifiers (try in order)
    classifiers: Vec<Box<dyn Classifier>>,

    /// Flow cache to avoid re-classifying established flows
    flow_cache: Arc<RwLock<HashMap<FlowKey, ApplicationType>>>,

    /// Statistics
    stats: Arc<RwLock<DpiStats>>,
}

/// DPI statistics
#[derive(Default)]
pub struct DpiStats {
    pub total_flows: u64,
    pub classified_flows: u64,
    pub cache_hits: u64,
    pub classification_errors: u64,
    pub by_type: HashMap<ApplicationType, u64>,
}

impl DpiEngine {
    /// Create a new DPI engine with default classifiers
    pub fn new() -> Self {
        let classifiers: Vec<Box<dyn Classifier>> = vec![
            Box::new(PortClassifier),
            Box::new(HttpClassifier),
            Box::new(RtpClassifier),
            Box::new(GamingClassifier),
        ];

        Self {
            classifiers,
            flow_cache: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(RwLock::new(DpiStats::default())),
        }
    }

    /// Classify a packet
    pub fn classify_packet(&self, packet: &[u8], flow: &FlowKey) -> ApplicationType {
        // Check cache first
        {
            let cache = self.flow_cache.read().unwrap();
            if let Some(&app_type) = cache.get(flow) {
                self.stats.write().unwrap().cache_hits += 1;
                trace!("DPI cache hit for flow {:?}: {}", flow, app_type.as_str());
                return app_type;
            }
        }

        // Try each classifier in order
        for classifier in &self.classifiers {
            if let Some(app_type) = classifier.classify(packet, flow) {
                debug!(
                    "DPI classified flow {:?} as {} using {}",
                    flow,
                    app_type.as_str(),
                    classifier.name()
                );

                // Cache the result
                self.flow_cache.write().unwrap().insert(*flow, app_type);

                // Update statistics
                {
                    let mut stats = self.stats.write().unwrap();
                    stats.classified_flows += 1;
                    *stats.by_type.entry(app_type).or_insert(0) += 1;
                }

                return app_type;
            }
        }

        // No classifier matched - mark as unknown
        debug!("DPI could not classify flow {:?}", flow);
        self.flow_cache.write().unwrap().insert(*flow, ApplicationType::Unknown);

        {
            let mut stats = self.stats.write().unwrap();
            *stats.by_type.entry(ApplicationType::Unknown).or_insert(0) += 1;
        }

        ApplicationType::Unknown
    }

    /// Get classification statistics
    pub fn get_stats(&self) -> DpiStats {
        let stats = self.stats.read().unwrap();
        DpiStats {
            total_flows: stats.total_flows,
            classified_flows: stats.classified_flows,
            cache_hits: stats.cache_hits,
            classification_errors: stats.classification_errors,
            by_type: stats.by_type.clone(),
        }
    }

    /// Clear flow cache (for testing or periodic cleanup)
    pub fn clear_cache(&self) {
        self.flow_cache.write().unwrap().clear();
    }

    /// Get cache size
    pub fn cache_size(&self) -> usize {
        self.flow_cache.read().unwrap().len()
    }
}

impl Default for DpiEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn create_test_flow(protocol: u8, dst_port: u16) -> FlowKey {
        use std::net::IpAddr;
        FlowKey {
            src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            src_port: 50000,
            dst_port,
            protocol,
        }
    }

    #[test]
    fn test_port_classifier_web() {
        let classifier = PortClassifier;
        let flow = create_test_flow(6, 443);
        let result = classifier.classify(&[], &flow);
        assert_eq!(result, Some(ApplicationType::Web));
    }

    #[test]
    fn test_port_classifier_voip() {
        let classifier = PortClassifier;
        let flow = create_test_flow(17, 5060);
        let result = classifier.classify(&[], &flow);
        assert_eq!(result, Some(ApplicationType::VoIP));
    }

    #[test]
    fn test_port_classifier_database() {
        let classifier = PortClassifier;
        let flow = create_test_flow(6, 3306);
        let result = classifier.classify(&[], &flow);
        assert_eq!(result, Some(ApplicationType::Database));
    }

    #[test]
    fn test_http_classifier() {
        let classifier = HttpClassifier;
        let flow = create_test_flow(6, 80);
        let packet = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let result = classifier.classify(packet, &flow);
        assert_eq!(result, Some(ApplicationType::Web));
    }

    #[test]
    fn test_http_classifier_video() {
        let classifier = HttpClassifier;
        let flow = create_test_flow(6, 80);
        let packet = b"GET /video/stream.m3u8 HTTP/1.1\r\nHost: youtube.com\r\n\r\n";
        let result = classifier.classify(packet, &flow);
        assert_eq!(result, Some(ApplicationType::Video));
    }

    #[test]
    fn test_rtp_classifier() {
        let classifier = RtpClassifier;
        let flow = create_test_flow(17, 10000);

        // Create a simple RTP packet
        // Version 2, Padding=0, Extension=0, CSRC count=0
        // Marker=0, Payload type=8 (PCMA)
        let mut packet = vec![0x80, 0x08];
        packet.extend_from_slice(&[0x00, 0x01]); // Sequence number
        packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // Timestamp
        packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // SSRC
        packet.extend_from_slice(&[0u8; 100]); // Payload (small for VoIP)

        let result = classifier.classify(&packet, &flow);
        assert_eq!(result, Some(ApplicationType::VoIP));
    }

    #[test]
    fn test_dpi_engine_classification() {
        let engine = DpiEngine::new();

        // Test web traffic
        let web_flow = create_test_flow(6, 443);
        let result = engine.classify_packet(&[], &web_flow);
        assert_eq!(result, ApplicationType::Web);

        // Test cache hit
        let result2 = engine.classify_packet(&[], &web_flow);
        assert_eq!(result2, ApplicationType::Web);

        let stats = engine.get_stats();
        assert_eq!(stats.cache_hits, 1);
    }

    #[test]
    fn test_dpi_engine_multiple_apps() {
        let engine = DpiEngine::new();

        // Classify different application types
        let web_flow = create_test_flow(6, 443);
        let voip_flow = create_test_flow(17, 5060);
        let db_flow = create_test_flow(6, 3306);

        assert_eq!(engine.classify_packet(&[], &web_flow), ApplicationType::Web);
        assert_eq!(engine.classify_packet(&[], &voip_flow), ApplicationType::VoIP);
        assert_eq!(engine.classify_packet(&[], &db_flow), ApplicationType::Database);

        let stats = engine.get_stats();
        assert_eq!(stats.by_type.get(&ApplicationType::Web), Some(&1));
        assert_eq!(stats.by_type.get(&ApplicationType::VoIP), Some(&1));
        assert_eq!(stats.by_type.get(&ApplicationType::Database), Some(&1));
    }

    #[test]
    fn test_dpi_cache_clear() {
        let engine = DpiEngine::new();

        let flow = create_test_flow(6, 443);
        engine.classify_packet(&[], &flow);
        assert_eq!(engine.cache_size(), 1);

        engine.clear_cache();
        assert_eq!(engine.cache_size(), 0);
    }
}
