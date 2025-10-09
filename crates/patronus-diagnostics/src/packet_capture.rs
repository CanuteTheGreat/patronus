//! Packet Capture (tcpdump/wireshark)
//!
//! Web-based packet capture for network troubleshooting.
//! Essential diagnostic tool for analyzing traffic.

use patronus_core::{Result, Error};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::process::Stdio;
use tokio::process::{Command, Child};
use tokio::io::{AsyncBufReadExt, BufReader};

/// Packet capture configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaptureConfig {
    pub interface: String,        // Interface to capture on
    pub filter: Option<String>,   // BPF filter expression
    pub snaplen: u32,              // Snapshot length (bytes per packet)
    pub buffer_size: u32,          // Buffer size in MB
    pub promiscuous: bool,         // Promiscuous mode
    pub max_packets: Option<u32>,  // Maximum packets to capture
    pub max_time: Option<u32>,     // Maximum capture time (seconds)
    pub max_size: Option<u32>,     // Maximum file size (MB)
}

/// Capture format
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CaptureFormat {
    Pcap,      // Standard pcap format
    PcapNg,    // Next generation pcap
    Text,      // Human-readable text
}

/// Packet capture session
#[derive(Debug)]
pub struct CaptureSession {
    pub id: String,
    pub interface: String,
    pub started_at: chrono::DateTime<chrono::Utc>,
    pub packets_captured: u64,
    pub bytes_captured: u64,
    pub output_file: PathBuf,
    process: Option<Child>,
}

/// Packet capture statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaptureStats {
    pub packets_captured: u64,
    pub packets_dropped: u64,
    pub bytes_captured: u64,
    pub duration_seconds: u64,
}

pub struct PacketCaptureManager {
    captures_dir: PathBuf,
}

impl PacketCaptureManager {
    pub fn new() -> Self {
        Self {
            captures_dir: PathBuf::from("/var/log/patronus/captures"),
        }
    }

    /// Start a new packet capture
    pub async fn start_capture(&self, config: CaptureConfig) -> Result<CaptureSession> {
        // Create captures directory
        tokio::fs::create_dir_all(&self.captures_dir).await?;

        // Generate unique session ID
        let session_id = uuid::Uuid::new_v4().to_string();
        let output_file = self.captures_dir.join(format!("{}.pcap", session_id));

        tracing::info!("Starting packet capture on {} to {}",
            config.interface, output_file.display());

        // Build tcpdump command
        let mut cmd = Command::new("tcpdump");
        cmd.arg("-i").arg(&config.interface);
        cmd.arg("-w").arg(&output_file);

        // Snapshot length
        cmd.arg("-s").arg(config.snaplen.to_string());

        // Buffer size
        cmd.arg("-B").arg((config.buffer_size * 1024).to_string());

        // Promiscuous mode
        if !config.promiscuous {
            cmd.arg("-p");
        }

        // Packet count limit
        if let Some(count) = config.max_packets {
            cmd.arg("-c").arg(count.to_string());
        }

        // File size limit
        if let Some(size_mb) = config.max_size {
            cmd.arg("-C").arg(size_mb.to_string());
        }

        // BPF filter
        if let Some(filter) = &config.filter {
            for part in filter.split_whitespace() {
                cmd.arg(part);
            }
        }

        // Start capture process
        let child = cmd
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;

        Ok(CaptureSession {
            id: session_id,
            interface: config.interface,
            started_at: chrono::Utc::now(),
            packets_captured: 0,
            bytes_captured: 0,
            output_file,
            process: Some(child),
        })
    }

    /// Stop a capture session
    pub async fn stop_capture(&self, session: &mut CaptureSession) -> Result<CaptureStats> {
        if let Some(mut process) = session.process.take() {
            // Send SIGTERM to tcpdump
            #[cfg(unix)]
            {
                use nix::sys::signal::{kill, Signal};
                use nix::unistd::Pid;

                if let Some(pid) = process.id() {
                    let _ = kill(Pid::from_raw(pid as i32), Signal::SIGTERM);
                }
            }

            // Wait for process to exit
            let _ = process.wait().await?;
        }

        // Get capture statistics
        self.get_stats(session).await
    }

    async fn get_stats(&self, session: &CaptureSession) -> Result<CaptureStats> {
        // Get file size
        let metadata = tokio::fs::metadata(&session.output_file).await?;
        let bytes = metadata.len();

        // Count packets using capinfos
        let output = Command::new("capinfos")
            .arg("-c")
            .arg(&session.output_file)
            .output()
            .await;

        let packets = if let Ok(out) = output {
            let output_str = String::from_utf8_lossy(&out.stdout);
            self.parse_packet_count(&output_str)
        } else {
            0
        };

        let duration = (chrono::Utc::now() - session.started_at).num_seconds() as u64;

        Ok(CaptureStats {
            packets_captured: packets,
            packets_dropped: 0,
            bytes_captured: bytes,
            duration_seconds: duration,
        })
    }

    fn parse_packet_count(&self, output: &str) -> u64 {
        for line in output.lines() {
            if line.contains("Number of packets") {
                if let Some(count_str) = line.split(':').nth(1) {
                    if let Ok(count) = count_str.trim().parse() {
                        return count;
                    }
                }
            }
        }
        0
    }

    /// Get packet capture in text format
    pub async fn get_packets_text(&self, capture_file: &PathBuf, count: Option<u32>) -> Result<String> {
        let mut cmd = Command::new("tcpdump");
        cmd.arg("-r").arg(capture_file);
        cmd.arg("-n");  // Don't resolve addresses
        cmd.arg("-v");  // Verbose

        if let Some(n) = count {
            cmd.arg("-c").arg(n.to_string());
        }

        let output = cmd.output().await?;

        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }

    /// Apply display filter to capture
    pub async fn filter_capture(&self, input_file: &PathBuf, filter: &str) -> Result<PathBuf> {
        let output_file = self.captures_dir.join(format!("filtered-{}.pcap",
            uuid::Uuid::new_v4()));

        let status = Command::new("tcpdump")
            .arg("-r").arg(input_file)
            .arg("-w").arg(&output_file)
            .args(filter.split_whitespace())
            .status()
            .await?;

        if !status.success() {
            return Err(Error::Network("Filter failed".to_string()));
        }

        Ok(output_file)
    }

    /// Get capture file in different format
    pub async fn convert_format(&self, input_file: &PathBuf, format: CaptureFormat) -> Result<PathBuf> {
        let extension = match format {
            CaptureFormat::Pcap => "pcap",
            CaptureFormat::PcapNg => "pcapng",
            CaptureFormat::Text => "txt",
        };

        let output_file = self.captures_dir.join(format!("converted-{}.{}",
            uuid::Uuid::new_v4(), extension));

        match format {
            CaptureFormat::PcapNg => {
                // Convert using editcap
                Command::new("editcap")
                    .arg("-F").arg("pcapng")
                    .arg(input_file)
                    .arg(&output_file)
                    .status()
                    .await?;
            }
            CaptureFormat::Text => {
                // Convert to text
                let text = self.get_packets_text(input_file, None).await?;
                tokio::fs::write(&output_file, text).await?;
            }
            CaptureFormat::Pcap => {
                // Already pcap, just copy
                tokio::fs::copy(input_file, &output_file).await?;
            }
        }

        Ok(output_file)
    }

    /// List available capture files
    pub async fn list_captures(&self) -> Result<Vec<CaptureInfo>> {
        let mut captures = Vec::new();

        if !self.captures_dir.exists() {
            return Ok(captures);
        }

        let mut entries = tokio::fs::read_dir(&self.captures_dir).await?;

        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();

            if let Some(ext) = path.extension() {
                if ext == "pcap" || ext == "pcapng" {
                    let metadata = entry.metadata().await?;

                    captures.push(CaptureInfo {
                        filename: path.file_name().unwrap().to_string_lossy().to_string(),
                        path: path.clone(),
                        size_bytes: metadata.len(),
                        created_at: metadata.created()
                            .ok()
                            .and_then(|t| chrono::DateTime::from(t).into()),
                    });
                }
            }
        }

        Ok(captures)
    }

    /// Delete a capture file
    pub async fn delete_capture(&self, filename: &str) -> Result<()> {
        let path = self.captures_dir.join(filename);

        if !path.exists() {
            return Err(Error::Config(format!("Capture file not found: {}", filename)));
        }

        tokio::fs::remove_file(path).await?;

        Ok(())
    }

    /// Get packet details
    pub async fn get_packet_details(&self, capture_file: &PathBuf, packet_num: u32) -> Result<PacketDetails> {
        // Use tshark for detailed packet dissection
        let output = Command::new("tshark")
            .arg("-r").arg(capture_file)
            .arg("-Y").arg(&format!("frame.number == {}", packet_num))
            .arg("-V")  // Verbose (full packet tree)
            .output()
            .await?;

        let details = String::from_utf8_lossy(&output.stdout).to_string();

        Ok(PacketDetails {
            packet_number: packet_num,
            details,
        })
    }

    /// Get protocol hierarchy statistics
    pub async fn get_protocol_stats(&self, capture_file: &PathBuf) -> Result<String> {
        let output = Command::new("tshark")
            .arg("-r").arg(capture_file)
            .arg("-q")  // Quiet
            .arg("-z").arg("io,phs")  // Protocol hierarchy statistics
            .output()
            .await?;

        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }

    /// Get conversation statistics
    pub async fn get_conversations(&self, capture_file: &PathBuf) -> Result<String> {
        let output = Command::new("tshark")
            .arg("-r").arg(capture_file)
            .arg("-q")
            .arg("-z").arg("conv,ip")  // IP conversations
            .output()
            .await?;

        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }

    /// Follow TCP stream
    pub async fn follow_stream(&self, capture_file: &PathBuf, stream_id: u32) -> Result<String> {
        let output = Command::new("tshark")
            .arg("-r").arg(capture_file)
            .arg("-q")
            .arg("-z").arg(&format!("follow,tcp,ascii,{}", stream_id))
            .output()
            .await?;

        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }

    /// Quick capture (30 seconds, 1000 packets max)
    pub async fn quick_capture(&self, interface: &str, filter: Option<String>) -> Result<PathBuf> {
        let config = CaptureConfig {
            interface: interface.to_string(),
            filter,
            snaplen: 65535,
            buffer_size: 2,
            promiscuous: true,
            max_packets: Some(1000),
            max_time: Some(30),
            max_size: None,
        };

        let mut session = self.start_capture(config).await?;

        // Wait for completion or timeout
        tokio::time::sleep(tokio::time::Duration::from_secs(30)).await;

        self.stop_capture(&mut session).await?;

        Ok(session.output_file)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaptureInfo {
    pub filename: String,
    pub path: PathBuf,
    pub size_bytes: u64,
    pub created_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PacketDetails {
    pub packet_number: u32,
    pub details: String,
}

impl Default for CaptureConfig {
    fn default() -> Self {
        Self {
            interface: "any".to_string(),
            filter: None,
            snaplen: 65535,  // Maximum
            buffer_size: 2,  // 2 MB
            promiscuous: true,
            max_packets: None,
            max_time: None,
            max_size: None,
        }
    }
}

/// Common BPF filter examples
pub struct BpfFilters;

impl BpfFilters {
    pub fn http() -> &'static str {
        "tcp port 80 or tcp port 443"
    }

    pub fn dns() -> &'static str {
        "udp port 53"
    }

    pub fn ssh() -> &'static str {
        "tcp port 22"
    }

    pub fn icmp() -> &'static str {
        "icmp"
    }

    pub fn host(ip: &str) -> String {
        format!("host {}", ip)
    }

    pub fn network(cidr: &str) -> String {
        format!("net {}", cidr)
    }

    pub fn port(port: u16) -> String {
        format!("port {}", port)
    }

    pub fn not_ssh() -> &'static str {
        "not tcp port 22"
    }
}
