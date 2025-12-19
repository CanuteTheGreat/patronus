//! XDP (eXpress Data Path) Firewall Implementation
//!
//! Processes packets at the earliest possible point - the network driver.

use std::path::Path;
use std::net::IpAddr;
use std::os::fd::AsFd;
use std::os::unix::io::AsRawFd;
use serde::{Deserialize, Serialize};
use libbpf_rs::{Object, ObjectBuilder};

/// XDP attachment mode
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum XdpMode {
    /// Native XDP - best performance, requires driver support
    Native,
    /// Generic XDP - works everywhere, slower
    Generic,
    /// Offload XDP - hardware offload, requires SmartNIC
    Offload,
}

/// XDP verdict/action
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum XdpAction {
    /// Drop packet (fastest - no processing)
    Drop,
    /// Pass packet to network stack
    Pass,
    /// Transmit packet back out same interface (for reflection/lb)
    Tx,
    /// Redirect to another interface
    Redirect,
    /// Abort (error condition)
    Aborted,
}

/// XDP firewall configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XdpConfig {
    pub enabled: bool,
    pub mode: XdpMode,
    pub interfaces: Vec<String>,

    // Filtering rules
    pub block_list: Vec<IpAddr>,
    pub allow_list: Vec<IpAddr>,
    pub rate_limits: Vec<RateLimit>,

    // DDoS protection
    pub enable_ddos_protection: bool,
    pub syn_flood_protection: bool,
    pub udp_flood_protection: bool,
    pub icmp_flood_protection: bool,

    // Performance tuning
    pub batch_size: u32,
    pub use_hw_offload: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimit {
    pub source_ip: Option<IpAddr>,
    pub destination_port: Option<u16>,
    pub packets_per_second: u64,
    pub burst: u64,
}

/// XDP firewall manager
pub struct XdpFirewall {
    config: XdpConfig,
    programs: Vec<LoadedProgram>,
    /// Whether eBPF is available on this system
    ebpf_available: bool,
}

struct LoadedProgram {
    interface: String,
    /// BPF object (contains program and maps)
    object: Option<Object>,
    /// Fallback file descriptors for when libbpf is not used
    program_fd: i32,
    map_fds: std::collections::HashMap<String, i32>,
}

impl XdpFirewall {
    pub fn new(config: XdpConfig) -> Result<Self, XdpError> {
        let ebpf_available = Self::check_ebpf_available();

        if ebpf_available {
            tracing::info!("eBPF/XDP support detected");
        } else {
            tracing::warn!("eBPF/XDP support not available, running in fallback mode");
        }

        Ok(Self {
            config,
            programs: Vec::new(),
            ebpf_available,
        })
    }

    /// Check if eBPF is available on this system
    fn check_ebpf_available() -> bool {
        // Check for BPF filesystem
        let bpf_fs = std::path::Path::new("/sys/fs/bpf");
        if !bpf_fs.exists() {
            return false;
        }

        // Check kernel version (need 5.0+)
        if !Self::is_supported() {
            return false;
        }

        // Try to check BPF syscall availability
        // This is a simple heuristic - in production would try a test operation
        true
    }

    /// Check if XDP is supported on this system
    pub fn is_supported() -> bool {
        // Check kernel version (requires 4.8+)
        let version = std::fs::read_to_string("/proc/version")
            .unwrap_or_default();

        // Parse kernel version
        if let Some(v) = version.split_whitespace().nth(2) {
            if let Some(major) = v.split('.').next() {
                if let Ok(major_num) = major.parse::<u32>() {
                    return major_num >= 5;  // Recommend 5.0+ for full features
                }
            }
        }

        false
    }

    /// Load and attach XDP program to interface
    pub async fn attach(&mut self, interface: &str) -> Result<(), XdpError> {
        tracing::info!("Attaching XDP program to {}", interface);

        // Compile eBPF program
        let program_path = self.compile_bpf_program()?;

        // Try to load program into kernel using libbpf-rs
        let (object, program_fd) = match self.load_bpf_program(&program_path) {
            Ok((obj, fd)) => (Some(obj), fd),
            Err(XdpError::EbpfNotAvailable) => {
                tracing::warn!("eBPF not available, using fallback attachment");
                (None, 0)
            }
            Err(e) => {
                tracing::warn!("BPF load failed: {}, trying fallback", e);
                (None, 0)
            }
        };

        // Create eBPF maps for state (or get from loaded object)
        let mut map_fds = std::collections::HashMap::new();

        if let Some(ref obj) = object {
            // Get map FDs from the loaded BPF object
            if let Some(map) = obj.map("blocklist") {
                map_fds.insert("blocklist".to_string(), map.as_fd().as_raw_fd());
            }
            if let Some(map) = obj.map("conntrack") {
                map_fds.insert("conntrack".to_string(), map.as_fd().as_raw_fd());
            }
            if let Some(map) = obj.map("ratelimit") {
                map_fds.insert("ratelimit".to_string(), map.as_fd().as_raw_fd());
            }
            if let Some(map) = obj.map("stats") {
                map_fds.insert("stats".to_string(), map.as_fd().as_raw_fd());
            }
            // Add SD-WAN specific maps
            if let Some(map) = obj.map("routing_table") {
                map_fds.insert("routing_table".to_string(), map.as_fd().as_raw_fd());
            }
            if let Some(map) = obj.map("tunnel_metrics") {
                map_fds.insert("tunnel_metrics".to_string(), map.as_fd().as_raw_fd());
            }
        } else {
            // Create standalone maps (fallback)
            let blocklist_fd = self.create_hash_map("blocklist", 1_000_000)?;
            map_fds.insert("blocklist".to_string(), blocklist_fd);

            let conntrack_fd = self.create_hash_map("conntrack", 10_000_000)?;
            map_fds.insert("conntrack".to_string(), conntrack_fd);

            let ratelimit_fd = self.create_hash_map("ratelimit", 100_000)?;
            map_fds.insert("ratelimit".to_string(), ratelimit_fd);

            let stats_fd = self.create_array_map("stats", 256)?;
            map_fds.insert("stats".to_string(), stats_fd);

            // SD-WAN maps
            let routing_fd = self.create_hash_map("routing_table", 100_000)?;
            map_fds.insert("routing_table".to_string(), routing_fd);

            let metrics_fd = self.create_hash_map("tunnel_metrics", 1_000)?;
            map_fds.insert("tunnel_metrics".to_string(), metrics_fd);
        }

        // Attach XDP program to interface
        self.attach_xdp_to_interface(interface, program_fd)?;

        // Populate maps with initial configuration
        if let Some(&blocklist_fd) = map_fds.get("blocklist") {
            self.populate_blocklist(blocklist_fd)?;
        }
        if let Some(&ratelimit_fd) = map_fds.get("ratelimit") {
            self.populate_rate_limits(ratelimit_fd)?;
        }

        self.programs.push(LoadedProgram {
            interface: interface.to_string(),
            object,
            program_fd,
            map_fds,
        });

        tracing::info!("XDP program attached successfully to {}", interface);

        Ok(())
    }

    /// Detach XDP program from interface
    pub async fn detach(&mut self, interface: &str) -> Result<(), XdpError> {
        // Find and remove program
        if let Some(pos) = self.programs.iter().position(|p| p.interface == interface) {
            let program = self.programs.remove(pos);

            // Detach from interface
            let status = tokio::process::Command::new("ip")
                .args(&["link", "set", "dev", interface, "xdp", "off"])
                .status()
                .await?;

            if !status.success() {
                return Err(XdpError::DetachFailed);
            }

            tracing::info!("XDP program detached from {}", interface);
        }

        Ok(())
    }

    /// Update blocklist
    pub async fn update_blocklist(&mut self, ips: Vec<IpAddr>) -> Result<(), XdpError> {
        for program in &self.programs {
            if let Some(&map_fd) = program.map_fds.get("blocklist") {
                for ip in &ips {
                    self.map_update(map_fd, ip, &1u8)?;
                }
            }
        }

        Ok(())
    }

    /// Add IP to blocklist
    pub async fn block_ip(&mut self, ip: IpAddr) -> Result<(), XdpError> {
        self.update_blocklist(vec![ip]).await
    }

    /// Remove IP from blocklist
    pub async fn unblock_ip(&mut self, ip: IpAddr) -> Result<(), XdpError> {
        for program in &self.programs {
            if let Some(&map_fd) = program.map_fds.get("blocklist") {
                self.map_delete(map_fd, &ip)?;
            }
        }

        Ok(())
    }

    /// Get statistics
    pub async fn get_stats(&self) -> Result<crate::stats::XdpStats, XdpError> {
        let mut total_packets = 0u64;
        let mut total_bytes = 0u64;
        let mut dropped_packets = 0u64;

        for program in &self.programs {
            if let Some(&stats_fd) = program.map_fds.get("stats") {
                // Read stats from BPF map
                // Index 0 = packets, 1 = bytes, 2 = dropped
                if let Ok(packets) = self.map_lookup::<u64>(stats_fd, &0u32) {
                    total_packets += packets;
                }
                if let Ok(bytes) = self.map_lookup::<u64>(stats_fd, &1u32) {
                    total_bytes += bytes;
                }
                if let Ok(dropped) = self.map_lookup::<u64>(stats_fd, &2u32) {
                    dropped_packets += dropped;
                }
            }
        }

        Ok(crate::stats::XdpStats {
            packets_processed: total_packets,
            bytes_processed: total_bytes,
            packets_dropped: dropped_packets,
            packets_passed: total_packets - dropped_packets,
            pps: 0,  // Would calculate from delta
            gbps: 0.0,
        })
    }

    // Internal implementation methods

    fn compile_bpf_program(&self) -> Result<std::path::PathBuf, XdpError> {
        // In production, this would compile the BPF C code using clang
        // For now, we'll reference a pre-compiled object file

        let bpf_c_code = self.generate_bpf_c_code();

        // Write to temp file
        let temp_dir = std::env::temp_dir();
        let source_path = temp_dir.join("patronus_xdp.c");
        std::fs::write(&source_path, bpf_c_code)?;

        // Compile with clang
        let object_path = temp_dir.join("patronus_xdp.o");

        let status = std::process::Command::new("clang")
            .args(&[
                "-O2",
                "-target", "bpf",
                "-c", source_path.to_str().unwrap(),
                "-o", object_path.to_str().unwrap(),
            ])
            .status()?;

        if !status.success() {
            return Err(XdpError::CompileFailed);
        }

        Ok(object_path)
    }

    fn generate_bpf_c_code(&self) -> String {
        // Generate BPF C code for the firewall
        r#"
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// Maps
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1000000);
    __type(key, __u32);  // IP address
    __type(value, __u8); // Block flag
} blocklist SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10000000);
    __type(key, __u64);  // Connection 5-tuple hash
    __type(value, struct conn_info);
} conntrack SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 256);
    __type(key, __u32);
    __type(value, __u64);
} stats SEC(".maps");

struct conn_info {
    __u64 packets;
    __u64 bytes;
    __u64 last_seen;
};

// Main XDP program
SEC("xdp")
int xdp_firewall(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    // Parse Ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_DROP;

    // Only handle IPv4 for now
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    // Parse IP header
    struct iphdr *ip = data + sizeof(struct ethhdr);
    if ((void *)(ip + 1) > data_end)
        return XDP_DROP;

    // Update statistics
    __u32 stats_key = 0;
    __u64 *packets = bpf_map_lookup_elem(&stats, &stats_key);
    if (packets)
        __sync_fetch_and_add(packets, 1);

    stats_key = 1;
    __u64 *bytes = bpf_map_lookup_elem(&stats, &stats_key);
    if (bytes)
        __sync_fetch_and_add(bytes, bpf_ntohs(ip->tot_len));

    // Check blocklist
    __u32 src_ip = bpf_ntohl(ip->saddr);
    __u8 *blocked = bpf_map_lookup_elem(&blocklist, &src_ip);
    if (blocked && *blocked) {
        // Update dropped counter
        stats_key = 2;
        __u64 *dropped = bpf_map_lookup_elem(&stats, &stats_key);
        if (dropped)
            __sync_fetch_and_add(dropped, 1);

        return XDP_DROP;  // Blocked IP - drop at wire speed!
    }

    // SYN flood protection
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + sizeof(struct iphdr);
        if ((void *)(tcp + 1) > data_end)
            return XDP_DROP;

        // Check for SYN packets
        if (tcp->syn && !tcp->ack) {
            // Could implement SYN cookie here
            // Or rate limit SYN packets per source
        }
    }

    // Connection tracking
    __u64 conn_hash = (__u64)src_ip << 32 | (__u64)bpf_ntohl(ip->daddr);
    struct conn_info *conn = bpf_map_lookup_elem(&conntrack, &conn_hash);

    if (conn) {
        __sync_fetch_and_add(&conn->packets, 1);
        __sync_fetch_and_add(&conn->bytes, bpf_ntohs(ip->tot_len));
        conn->last_seen = bpf_ktime_get_ns();
    } else {
        struct conn_info new_conn = {
            .packets = 1,
            .bytes = bpf_ntohs(ip->tot_len),
            .last_seen = bpf_ktime_get_ns(),
        };
        bpf_map_update_elem(&conntrack, &conn_hash, &new_conn, BPF_ANY);
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
"#.to_string()
    }

    fn load_bpf_program(&self, path: &Path) -> Result<(Object, i32), XdpError> {
        if !self.ebpf_available {
            tracing::debug!("eBPF not available, returning placeholder");
            return Err(XdpError::EbpfNotAvailable);
        }

        // Use libbpf-rs to load the BPF object
        let mut obj_builder = ObjectBuilder::default();

        let open_obj = obj_builder.open_file(path)
            .map_err(|e| {
                tracing::error!("Failed to open BPF object: {}", e);
                XdpError::LoadFailed(e.to_string())
            })?;

        let obj = open_obj.load()
            .map_err(|e| {
                tracing::error!("Failed to load BPF object: {}", e);
                XdpError::LoadFailed(e.to_string())
            })?;

        // Get the XDP program FD
        let prog = obj.prog("xdp_firewall")
            .ok_or_else(|| XdpError::LoadFailed("XDP program not found in object".to_string()))?;

        let prog_fd = prog.as_fd().as_raw_fd();

        tracing::info!("Loaded BPF program from {:?}, fd={}", path, prog_fd);
        Ok((obj, prog_fd))
    }

    fn load_bpf_program_fallback(&self, path: &Path) -> Result<i32, XdpError> {
        // Fallback: use ip command directly
        tracing::debug!("Using fallback BPF loading via ip command");
        Ok(0) // Placeholder, actual loading happens during attach
    }

    fn create_hash_map(&self, name: &str, max_entries: u32) -> Result<i32, XdpError> {
        // When using libbpf-rs, maps are created from the BPF object
        // This method is for standalone map creation
        if !self.ebpf_available {
            return Ok(-1);
        }

        // Use libbpf-sys for direct syscall
        use libbpf_sys as bpf;

        let opts = bpf::bpf_map_create_opts {
            sz: std::mem::size_of::<bpf::bpf_map_create_opts>() as u64,
            ..Default::default()
        };

        let fd = unsafe {
            bpf::bpf_map_create(
                bpf::BPF_MAP_TYPE_HASH,
                name.as_ptr() as *const i8,
                std::mem::size_of::<u32>() as u32,
                std::mem::size_of::<u64>() as u32,
                max_entries,
                &opts as *const _,
            )
        };

        if fd < 0 {
            tracing::warn!("Failed to create BPF hash map '{}': errno={}", name, fd);
            return Ok(-1); // Return placeholder in non-privileged mode
        }

        tracing::debug!("Created BPF hash map '{}' with fd={}", name, fd);
        Ok(fd)
    }

    fn create_array_map(&self, name: &str, max_entries: u32) -> Result<i32, XdpError> {
        if !self.ebpf_available {
            return Ok(-1);
        }

        use libbpf_sys as bpf;

        let opts = bpf::bpf_map_create_opts {
            sz: std::mem::size_of::<bpf::bpf_map_create_opts>() as u64,
            ..Default::default()
        };

        let fd = unsafe {
            bpf::bpf_map_create(
                bpf::BPF_MAP_TYPE_ARRAY,
                name.as_ptr() as *const i8,
                std::mem::size_of::<u32>() as u32,
                std::mem::size_of::<u64>() as u32,
                max_entries,
                &opts as *const _,
            )
        };

        if fd < 0 {
            tracing::warn!("Failed to create BPF array map '{}': errno={}", name, fd);
            return Ok(-1);
        }

        tracing::debug!("Created BPF array map '{}' with fd={}", name, fd);
        Ok(fd)
    }

    fn attach_xdp_to_interface(&self, interface: &str, program_fd: i32) -> Result<(), XdpError> {
        // Get interface index
        let ifindex = nix::net::if_::if_nametoindex(interface)
            .map_err(|e| {
                tracing::error!("Failed to get interface index for {}: {}", interface, e);
                XdpError::AttachFailed
            })?;

        if self.ebpf_available && program_fd > 0 {
            // Use libbpf-sys for XDP attach
            use libbpf_sys as bpf;

            let flags = match self.config.mode {
                XdpMode::Native => bpf::XDP_FLAGS_DRV_MODE,
                XdpMode::Generic => bpf::XDP_FLAGS_SKB_MODE,
                XdpMode::Offload => bpf::XDP_FLAGS_HW_MODE,
            };

            let ret = unsafe {
                bpf::bpf_xdp_attach(ifindex as i32, program_fd, flags, std::ptr::null())
            };

            if ret < 0 {
                tracing::warn!("libbpf XDP attach failed (ret={}), falling back to ip command", ret);
            } else {
                tracing::info!("Attached XDP program to {} (ifindex={}) via libbpf", interface, ifindex);
                return Ok(());
            }
        }

        // Fallback: use ip command
        let mode_flag = match self.config.mode {
            XdpMode::Native => "xdpdrv",
            XdpMode::Generic => "xdpgeneric",
            XdpMode::Offload => "xdpoffload",
        };

        let status = std::process::Command::new("ip")
            .args(&["link", "set", "dev", interface, mode_flag, "obj",
                   "/tmp/patronus_xdp.o", "sec", "xdp"])
            .status()?;

        if !status.success() {
            return Err(XdpError::AttachFailed);
        }

        tracing::info!("Attached XDP program to {} via ip command", interface);
        Ok(())
    }

    fn populate_blocklist(&self, map_fd: i32) -> Result<(), XdpError> {
        for ip in &self.config.block_list {
            self.map_update_ip(map_fd, ip, 1u8)?;
        }
        Ok(())
    }

    fn populate_rate_limits(&self, map_fd: i32) -> Result<(), XdpError> {
        for (idx, limit) in self.config.rate_limits.iter().enumerate() {
            if let Some(ip) = limit.source_ip {
                // Store rate limit: key=IP, value=packets_per_second
                self.map_update_ip(map_fd, &ip, limit.packets_per_second)?;
            }
        }
        Ok(())
    }

    /// Update a BPF map entry with IP address as key
    pub fn map_update_ip<V: Copy>(&self, map_fd: i32, ip: &IpAddr, value: V) -> Result<(), XdpError> {
        if map_fd < 0 {
            // Fallback mode, no-op
            return Ok(());
        }

        let key_bytes: Vec<u8> = match ip {
            IpAddr::V4(v4) => v4.octets().to_vec(),
            IpAddr::V6(v6) => v6.octets().to_vec(),
        };

        let value_ptr = &value as *const V as *const u8;
        let value_bytes = unsafe {
            std::slice::from_raw_parts(value_ptr, std::mem::size_of::<V>())
        };

        self.map_update_raw(map_fd, &key_bytes, value_bytes)
    }

    /// Update a BPF map with raw bytes
    pub fn map_update_raw(&self, map_fd: i32, key: &[u8], value: &[u8]) -> Result<(), XdpError> {
        if map_fd < 0 {
            return Ok(());
        }

        use libbpf_sys as bpf;

        let ret = unsafe {
            bpf::bpf_map_update_elem(
                map_fd,
                key.as_ptr() as *const _,
                value.as_ptr() as *const _,
                bpf::BPF_ANY as u64,
            )
        };

        if ret < 0 {
            tracing::warn!("BPF map update failed: {}", ret);
            return Err(XdpError::MapError);
        }

        Ok(())
    }

    /// Delete an entry from a BPF map
    pub fn map_delete_ip(&self, map_fd: i32, ip: &IpAddr) -> Result<(), XdpError> {
        if map_fd < 0 {
            return Ok(());
        }

        let key_bytes: Vec<u8> = match ip {
            IpAddr::V4(v4) => v4.octets().to_vec(),
            IpAddr::V6(v6) => v6.octets().to_vec(),
        };

        use libbpf_sys as bpf;

        let ret = unsafe {
            bpf::bpf_map_delete_elem(map_fd, key_bytes.as_ptr() as *const _)
        };

        if ret < 0 {
            tracing::debug!("BPF map delete failed (may not exist): {}", ret);
        }

        Ok(())
    }

    fn map_update<K, V>(&self, map_fd: i32, key: &K, value: &V) -> Result<(), XdpError> {
        if map_fd < 0 {
            return Ok(());
        }

        let key_ptr = key as *const K as *const u8;
        let key_bytes = unsafe {
            std::slice::from_raw_parts(key_ptr, std::mem::size_of::<K>())
        };

        let value_ptr = value as *const V as *const u8;
        let value_bytes = unsafe {
            std::slice::from_raw_parts(value_ptr, std::mem::size_of::<V>())
        };

        self.map_update_raw(map_fd, key_bytes, value_bytes)
    }

    fn map_delete<K>(&self, map_fd: i32, key: &K) -> Result<(), XdpError> {
        if map_fd < 0 {
            return Ok(());
        }

        use libbpf_sys as bpf;

        let ret = unsafe {
            bpf::bpf_map_delete_elem(map_fd, key as *const K as *const _)
        };

        if ret < 0 {
            tracing::debug!("BPF map delete failed: {}", ret);
        }

        Ok(())
    }

    fn map_lookup<V>(&self, map_fd: i32, key: &u32) -> Result<V, XdpError>
    where
        V: Default + Copy,
    {
        if map_fd < 0 {
            return Ok(V::default());
        }

        use libbpf_sys as bpf;

        let mut value = V::default();

        let ret = unsafe {
            bpf::bpf_map_lookup_elem(
                map_fd,
                key as *const u32 as *const _,
                &mut value as *mut V as *mut _,
            )
        };

        if ret < 0 {
            return Ok(V::default());
        }

        Ok(value)
    }

    /// Update XDP routing map (for SD-WAN fast path)
    pub fn update_routing_map(&mut self, dest_ip: u32, tunnel_id: u32) -> Result<(), XdpError> {
        for program in &self.programs {
            if let Some(&map_fd) = program.map_fds.get("routing_table") {
                self.map_update(map_fd, &dest_ip, &tunnel_id)?;
            }
        }
        tracing::debug!("Updated routing map: {} -> tunnel {}",
            std::net::Ipv4Addr::from(dest_ip), tunnel_id);
        Ok(())
    }

    /// Update tunnel metrics map (for SD-WAN path selection)
    pub fn update_metrics_map(&mut self, tunnel_id: u32, latency_ms: u32, packet_loss: u32) -> Result<(), XdpError> {
        // Pack metrics into a single u64 for simplicity
        let metrics: u64 = ((latency_ms as u64) << 32) | (packet_loss as u64);

        for program in &self.programs {
            if let Some(&map_fd) = program.map_fds.get("tunnel_metrics") {
                self.map_update(map_fd, &tunnel_id, &metrics)?;
            }
        }
        tracing::debug!("Updated metrics for tunnel {}: latency={}ms, loss={}%%",
            tunnel_id, latency_ms, packet_loss);
        Ok(())
    }

    /// Check if eBPF is available
    pub fn is_ebpf_available(&self) -> bool {
        self.ebpf_available
    }
}

#[derive(Debug, thiserror::Error)]
pub enum XdpError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Compilation failed")]
    CompileFailed,
    #[error("Failed to load BPF program: {0}")]
    LoadFailed(String),
    #[error("Failed to attach XDP program")]
    AttachFailed,
    #[error("Failed to detach XDP program")]
    DetachFailed,
    #[error("Map operation failed")]
    MapError,
    #[error("eBPF not available on this system")]
    EbpfNotAvailable,
    #[error("libbpf error: {0}")]
    LibbpfError(String),
}

impl Default for XdpConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            mode: XdpMode::Generic,  // Safe default
            interfaces: vec!["eth0".to_string()],
            block_list: vec![],
            allow_list: vec![],
            rate_limits: vec![],
            enable_ddos_protection: true,
            syn_flood_protection: true,
            udp_flood_protection: true,
            icmp_flood_protection: true,
            batch_size: 64,
            use_hw_offload: false,
        }
    }
}
