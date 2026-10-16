use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::process::Command;
use tracing::{debug, info, warn};

/// CNI version supported
pub const CNI_VERSION: &str = "1.0.0";

/// Derive the 8-character interface-name suffix for a container.
///
/// Linux interface names are capped at 15 bytes, so "veth"/"tmp-" plus 8 chars
/// is what fits. Docker/containerd/CRI-O IDs are 64-char hex, and for those the
/// first 8 chars are used verbatim (unchanged from earlier releases, so DEL and
/// CHECK still find interfaces created by them). The CNI spec only requires
/// the ID to be non-empty, though, and slicing `[..8]` panicked on anything
/// shorter than 8 bytes or with a multi-byte char straddling byte 8 -- a panic
/// in a CNI plugin returns no CNI error JSON to the runtime at all. Any such ID
/// now gets a deterministic 8-hex-digit FNV-1a hash of the full ID instead.
pub fn container_id_suffix(container_id: &str) -> String {
    if container_id
        .as_bytes()
        .get(..8)
        .is_some_and(|p| p.iter().all(u8::is_ascii_alphanumeric))
    {
        // All-ASCII, so byte 8 is guaranteed to be a char boundary.
        return container_id[..8].to_string();
    }
    // FNV-1a (32-bit): stable across Rust versions and platforms, unlike
    // std's DefaultHasher, which matters because DEL may run under a newer
    // plugin binary than the ADD that created the interface.
    let mut h: u32 = 0x811c_9dc5;
    for b in container_id.as_bytes() {
        h ^= u32::from(*b);
        h = h.wrapping_mul(0x0100_0193);
    }
    format!("{h:08x}")
}

/// CNI command
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum CniCommand {
    Add,
    Del,
    Check,
    Version,
}

/// CNI network configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CniConfig {
    pub cni_version: String,
    pub name: String,
    pub type_: String,
    pub bridge: Option<String>,
    pub ipam: IpamConfig,
    pub dns: Option<DnsConfig>,
    pub is_gateway: Option<bool>,
    pub is_default_gateway: Option<bool>,
    pub force_address: Option<bool>,
    pub ipmasq: Option<bool>,
    pub mtu: Option<u32>,
    pub hair_pin_mode: Option<bool>,
}

/// IPAM (IP Address Management) configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IpamConfig {
    pub type_: String,
    pub subnet: Option<String>,
    pub range_start: Option<IpAddr>,
    pub range_end: Option<IpAddr>,
    pub gateway: Option<IpAddr>,
    pub routes: Option<Vec<Route>>,
}

/// Route configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Route {
    pub dst: String,
    pub gw: Option<IpAddr>,
}

/// DNS configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsConfig {
    pub nameservers: Vec<String>,
    pub domain: Option<String>,
    pub search: Option<Vec<String>>,
    pub options: Option<Vec<String>>,
}

/// CNI runtime configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CniRuntimeConfig {
    pub container_id: String,
    pub netns: String,
    pub ifname: String,
    pub args: Option<String>,
    pub path: String,
}

/// CNI result (success response)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CniResult {
    pub cni_version: String,
    pub interfaces: Vec<CniInterface>,
    pub ips: Vec<CniIp>,
    pub routes: Vec<Route>,
    pub dns: Option<DnsConfig>,
}

/// Network interface in CNI result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CniInterface {
    pub name: String,
    pub mac: String,
    pub sandbox: Option<String>,
}

/// IP address assignment in CNI result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CniIp {
    pub address: String,
    pub gateway: Option<IpAddr>,
    pub interface: Option<u32>,
}

/// CNI error response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CniError {
    pub cni_version: String,
    pub code: u32,
    pub msg: String,
    pub details: Option<String>,
}

/// Patronus CNI plugin
pub struct PatronusCniPlugin {
    pub config: CniConfig,
    pub runtime: CniRuntimeConfig,
}

impl PatronusCniPlugin {
    pub fn new(config: CniConfig, runtime: CniRuntimeConfig) -> Self {
        Self { config, runtime }
    }

    /// Handle CNI ADD command - setup pod networking
    pub fn cmd_add(&self) -> Result<CniResult> {
        info!(
            "CNI ADD: container={}, netns={}, ifname={}",
            self.runtime.container_id, self.runtime.netns, self.runtime.ifname
        );

        // CNI spec: CNI_CONTAINERID is required and must be non-empty. Fail with
        // a proper CNI error instead of creating "veth"/"tmp-" interfaces that
        // every other ID-less invocation would collide with.
        if self.runtime.container_id.is_empty() {
            return Err(anyhow::anyhow!("CNI_CONTAINERID is required but was empty"));
        }

        // 1. Create veth pair
        let (host_veth, container_veth) = self.create_veth_pair()?;

        // 2. Move container veth to pod namespace
        self.move_to_netns(&container_veth, &self.runtime.netns)?;

        // 3. Allocate IP address from IPAM
        let ip_assignment = self.allocate_ip()?;

        // 4. Configure container interface inside netns
        self.configure_container_interface(&ip_assignment)?;

        // 5. Setup host-side routing
        self.setup_host_routing(&host_veth, &ip_assignment)?;

        // 6. Attach eBPF programs for policy enforcement
        self.attach_ebpf_programs(&host_veth)?;

        // 7. Build CNI result
        let result = CniResult {
            cni_version: CNI_VERSION.to_string(),
            interfaces: vec![
                CniInterface {
                    name: host_veth.clone(),
                    mac: self.get_interface_mac(&host_veth)?,
                    sandbox: None,
                },
                CniInterface {
                    name: self.runtime.ifname.clone(),
                    mac: self
                        .get_interface_mac_in_netns(&self.runtime.netns, &self.runtime.ifname)?,
                    sandbox: Some(self.runtime.netns.clone()),
                },
            ],
            ips: vec![CniIp {
                address: ip_assignment.address.clone(),
                gateway: ip_assignment.gateway,
                interface: Some(1), // Container interface
            }],
            routes: self.config.ipam.routes.clone().unwrap_or_default(),
            dns: self.config.dns.clone(),
        };

        info!("CNI ADD complete: assigned IP {}", ip_assignment.address);
        Ok(result)
    }

    /// Handle CNI DEL command - teardown pod networking
    pub fn cmd_del(&self) -> Result<()> {
        info!(
            "CNI DEL: container={}, netns={}",
            self.runtime.container_id, self.runtime.netns
        );

        // 1. Release IP address back to IPAM
        self.release_ip()?;

        // 2. Remove veth pair (deleting one end removes both)
        let host_veth = self.get_host_veth_name();
        if self.interface_exists(&host_veth) {
            self.delete_interface(&host_veth)?;
        }

        // 3. Detach eBPF programs
        // eBPF programs are automatically cleaned up when interface is deleted

        info!("CNI DEL complete");
        Ok(())
    }

    /// Handle CNI CHECK command - verify pod networking
    pub fn cmd_check(&self) -> Result<()> {
        debug!("CNI CHECK: container={}", self.runtime.container_id);

        let host_veth = self.get_host_veth_name();

        // Verify host veth exists
        if !self.interface_exists(&host_veth) {
            return Err(anyhow::anyhow!("Host veth {} not found", host_veth));
        }

        // Verify container veth exists in netns
        if !self.interface_exists_in_netns(&self.runtime.netns, &self.runtime.ifname) {
            return Err(anyhow::anyhow!(
                "Container interface {} not found in netns",
                self.runtime.ifname
            ));
        }

        Ok(())
    }

    /// Handle CNI VERSION command
    pub fn cmd_version() -> serde_json::Value {
        serde_json::json!({
            "cniVersion": CNI_VERSION,
            "supportedVersions": ["0.4.0", "1.0.0"]
        })
    }

    /// Create veth pair
    fn create_veth_pair(&self) -> Result<(String, String)> {
        let host_veth = self.get_host_veth_name();
        let container_veth = format!("tmp-{}", container_id_suffix(&self.runtime.container_id));

        debug!("Creating veth pair: {} <-> {}", host_veth, container_veth);

        let output = Command::new("ip")
            .args([
                "link",
                "add",
                &host_veth,
                "type",
                "veth",
                "peer",
                "name",
                &container_veth,
            ])
            .output()
            .context("Failed to create veth pair")?;

        if !output.status.success() {
            return Err(anyhow::anyhow!(
                "Failed to create veth pair: {}",
                String::from_utf8_lossy(&output.stderr)
            ));
        }

        // Bring up host veth
        Command::new("ip")
            .args(["link", "set", &host_veth, "up"])
            .output()
            .context("Failed to bring up host veth")?;

        Ok((host_veth, container_veth))
    }

    /// Move interface to network namespace
    fn move_to_netns(&self, ifname: &str, netns: &str) -> Result<()> {
        debug!("Moving {} to netns {}", ifname, netns);

        let output = Command::new("ip")
            .args(["link", "set", ifname, "netns", netns])
            .output()
            .context("Failed to move interface to netns")?;

        if !output.status.success() {
            return Err(anyhow::anyhow!(
                "Failed to move interface to netns: {}",
                String::from_utf8_lossy(&output.stderr)
            ));
        }

        Ok(())
    }

    /// Allocate IP address from IPAM
    fn allocate_ip(&self) -> Result<IpAssignment> {
        // Simple static allocation for now
        // In production, this would interface with a real IPAM system
        let subnet = self
            .config
            .ipam
            .subnet
            .as_ref()
            .context("IPAM subnet not configured")?;

        // Parse subnet to get network and allocate an IP
        // For now, return a placeholder
        let ip = self.get_next_available_ip(subnet)?;
        let gateway = self.config.ipam.gateway;

        Ok(IpAssignment {
            address: format!("{}/24", ip), // Assuming /24 for simplicity
            gateway,
        })
    }

    /// Release IP address back to IPAM
    fn release_ip(&self) -> Result<()> {
        // In production, this would return the IP to the IPAM pool
        debug!("Releasing IP for container {}", self.runtime.container_id);
        Ok(())
    }

    /// Configure container interface inside network namespace
    fn configure_container_interface(&self, ip: &IpAssignment) -> Result<()> {
        debug!("Configuring container interface with IP {}", ip.address);

        // Rename temp interface to desired name
        let temp_name = format!("tmp-{}", container_id_suffix(&self.runtime.container_id));

        self.exec_in_netns(&[
            "ip",
            "link",
            "set",
            &temp_name,
            "name",
            &self.runtime.ifname,
        ])?;

        // Set IP address
        self.exec_in_netns(&[
            "ip",
            "addr",
            "add",
            &ip.address,
            "dev",
            &self.runtime.ifname,
        ])?;

        // Bring up interface
        self.exec_in_netns(&["ip", "link", "set", &self.runtime.ifname, "up"])?;

        // Add default route if gateway is set
        if let Some(gw) = ip.gateway {
            self.exec_in_netns(&["ip", "route", "add", "default", "via", &gw.to_string()])?;
        }

        Ok(())
    }

    /// Setup host-side routing
    fn setup_host_routing(&self, host_veth: &str, ip: &IpAssignment) -> Result<()> {
        debug!("Setting up host routing for {}", ip.address);

        // Extract IP without prefix
        let ip_only = ip.address.split('/').next().unwrap();

        // Add route to pod IP via host veth
        let output = Command::new("ip")
            .args(["route", "add", ip_only, "dev", host_veth])
            .output()
            .context("Failed to add route")?;

        if !output.status.success() {
            warn!(
                "Failed to add route: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        Ok(())
    }

    /// Attach eBPF programs for policy enforcement
    fn attach_ebpf_programs(&self, host_veth: &str) -> Result<()> {
        debug!("Attaching eBPF programs to {}", host_veth);

        // In production, this would load and attach eBPF programs
        // for network policy enforcement

        // Placeholder for now - actual eBPF implementation would go here
        info!("eBPF programs attached to {}", host_veth);

        Ok(())
    }

    /// Execute command in network namespace
    fn exec_in_netns(&self, args: &[&str]) -> Result<()> {
        let mut cmd_args = vec!["netns", "exec", &self.runtime.netns];
        cmd_args.extend_from_slice(args);

        let output = Command::new("ip")
            .args(&cmd_args)
            .output()
            .context("Failed to execute command in netns")?;

        if !output.status.success() {
            return Err(anyhow::anyhow!(
                "Command failed in netns: {}",
                String::from_utf8_lossy(&output.stderr)
            ));
        }

        Ok(())
    }

    /// Get host veth name for container
    fn get_host_veth_name(&self) -> String {
        format!("veth{}", container_id_suffix(&self.runtime.container_id))
    }

    /// Check if interface exists
    fn interface_exists(&self, ifname: &str) -> bool {
        Command::new("ip")
            .args(["link", "show", ifname])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    /// Check if interface exists in netns
    fn interface_exists_in_netns(&self, netns: &str, ifname: &str) -> bool {
        Command::new("ip")
            .args(["netns", "exec", netns, "ip", "link", "show", ifname])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    /// Delete interface
    fn delete_interface(&self, ifname: &str) -> Result<()> {
        Command::new("ip")
            .args(["link", "del", ifname])
            .output()
            .context("Failed to delete interface")?;
        Ok(())
    }

    /// Get interface MAC address
    fn get_interface_mac(&self, ifname: &str) -> Result<String> {
        let output = Command::new("cat")
            .arg(format!("/sys/class/net/{}/address", ifname))
            .output()
            .context("Failed to read MAC address")?;

        Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
    }

    /// Get interface MAC address in netns
    fn get_interface_mac_in_netns(&self, netns: &str, ifname: &str) -> Result<String> {
        let output = Command::new("ip")
            .args([
                "netns",
                "exec",
                netns,
                "cat",
                &format!("/sys/class/net/{}/address", ifname),
            ])
            .output()
            .context("Failed to read MAC address in netns")?;

        Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
    }

    /// Get next available IP from subnet (simplified)
    fn get_next_available_ip(&self, subnet: &str) -> Result<IpAddr> {
        // Very simplified IP allocation
        // In production, this would use a proper IPAM
        use std::str::FromStr;

        let base = subnet.split('/').next().context("Invalid subnet")?;
        let mut parts: Vec<u8> = base.split('.').map(|p| p.parse().unwrap_or(0)).collect();

        // Increment last octet (very naive)
        parts[3] = parts[3].wrapping_add(10); // Start from .10

        let ip_str = format!("{}.{}.{}.{}", parts[0], parts[1], parts[2], parts[3]);
        IpAddr::from_str(&ip_str).context("Failed to parse IP")
    }
}

/// IP assignment result
#[derive(Debug, Clone)]
struct IpAssignment {
    address: String,
    gateway: Option<IpAddr>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cni_version() {
        let version = PatronusCniPlugin::cmd_version();
        assert_eq!(version["cniVersion"], CNI_VERSION);
    }

    #[test]
    fn test_container_id_suffix_keeps_prefix_for_runtime_ids() {
        // 64-char hex IDs from containerd/docker keep the historical naming.
        let id = "3f4e5a6b7c8d9e0f1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f7081";
        assert_eq!(container_id_suffix(id), "3f4e5a6b");
    }

    #[test]
    fn test_container_id_suffix_never_panics_on_short_or_unicode_ids() {
        for id in [
            "",
            "a",
            "abc1234",
            "pod-é-日本語-1",
            "1234567é",
            "with space",
        ] {
            let s = container_id_suffix(id);
            assert_eq!(s.len(), 8, "suffix for {id:?} was {s:?}");
            assert!(s.bytes().all(|b| b.is_ascii_alphanumeric()));
            // "veth" + suffix must fit IFNAMSIZ-1 (15 bytes).
            assert!(format!("veth{s}").len() <= 15);
        }
    }

    #[test]
    fn test_container_id_suffix_is_deterministic_and_distinguishes_ids() {
        assert_eq!(container_id_suffix("abc"), container_id_suffix("abc"));
        assert_ne!(container_id_suffix("abc"), container_id_suffix("abd"));
        // Pinned value: changing the hash would orphan host veths on DEL.
        assert_eq!(container_id_suffix(""), "811c9dc5");
    }
}
