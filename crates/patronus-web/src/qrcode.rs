//! QR Code generation for WireGuard configurations
//!
//! Provides QR code generation for easy mobile client setup.
//! WireGuard mobile apps can scan QR codes to instantly import configuration.

use anyhow::Result;
use qrcode::{QrCode, Version, EcLevel};
use qrcode::render::svg;

/// Generate WireGuard configuration string
pub fn generate_wireguard_config(
    interface_address: &str,
    private_key: &str,
    public_key: &str,
    endpoint: &str,
    allowed_ips: &str,
    dns: Option<&str>,
    persistent_keepalive: Option<u16>,
) -> String {
    let mut config = format!(
        "[Interface]\n\
        Address = {}\n\
        PrivateKey = {}\n\
        \n\
        [Peer]\n\
        PublicKey = {}\n\
        Endpoint = {}\n\
        AllowedIPs = {}\n",
        interface_address,
        private_key,
        public_key,
        endpoint,
        allowed_ips
    );

    if let Some(dns_servers) = dns {
        config.push_str(&format!("DNS = {}\n", dns_servers));
    }

    if let Some(keepalive) = persistent_keepalive {
        config.push_str(&format!("PersistentKeepalive = {}\n", keepalive));
    }

    config
}

/// Generate QR code as SVG for WireGuard configuration
pub fn generate_qr_code_svg(config: &str) -> Result<String> {
    let code = QrCode::with_version(config, Version::Normal(10), EcLevel::M)?;

    let svg = code
        .render()
        .min_dimensions(256, 256)
        .dark_color(svg::Color("#000000"))
        .light_color(svg::Color("#ffffff"))
        .build();

    Ok(svg)
}

/// Generate QR code as PNG bytes for WireGuard configuration
pub fn generate_qr_code_png(config: &str) -> Result<Vec<u8>> {
    let code = QrCode::new(config.as_bytes())?;

    // Render as image
    let image = code.render::<image::Luma<u8>>()
        .min_dimensions(512, 512)
        .build();

    // Convert to PNG bytes
    let mut png_bytes = Vec::new();
    {
        let mut cursor = std::io::Cursor::new(&mut png_bytes);
        image.write_to(&mut cursor, image::ImageFormat::Png)?;
    }

    Ok(png_bytes)
}

/// WireGuard peer configuration for QR code generation
#[derive(Debug, Clone)]
pub struct WireGuardPeerConfig {
    pub peer_name: String,
    pub interface_address: String,
    pub private_key: String,
    pub server_public_key: String,
    pub server_endpoint: String,
    pub allowed_ips: String,
    pub dns_servers: Option<String>,
    pub persistent_keepalive: Option<u16>,
}

impl WireGuardPeerConfig {
    /// Generate configuration string
    pub fn to_config_string(&self) -> String {
        generate_wireguard_config(
            &self.interface_address,
            &self.private_key,
            &self.server_public_key,
            &self.server_endpoint,
            &self.allowed_ips,
            self.dns_servers.as_deref(),
            self.persistent_keepalive,
        )
    }

    /// Generate QR code SVG
    pub fn to_qr_svg(&self) -> Result<String> {
        let config = self.to_config_string();
        generate_qr_code_svg(&config)
    }

    /// Generate QR code PNG
    pub fn to_qr_png(&self) -> Result<Vec<u8>> {
        let config = self.to_config_string();
        generate_qr_code_png(&config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_config() {
        let config = generate_wireguard_config(
            "10.0.0.2/24",
            "cBVRKzyV6FkeN9tYPqJCILdNXJKF8xhHxEYczGzfE3M=",
            "RZv3iVQPxjKqBVLPEMJJX/xJ7FDGZdKzxcY5WV9vwVU=",
            "vpn.example.com:51820",
            "0.0.0.0/0",
            Some("1.1.1.1, 8.8.8.8"),
            Some(25),
        );

        assert!(config.contains("[Interface]"));
        assert!(config.contains("Address = 10.0.0.2/24"));
        assert!(config.contains("[Peer]"));
        assert!(config.contains("DNS = 1.1.1.1, 8.8.8.8"));
        assert!(config.contains("PersistentKeepalive = 25"));
    }

    #[test]
    fn test_qr_code_generation() {
        let config = "test config";
        let svg = generate_qr_code_svg(config).unwrap();

        assert!(svg.contains("<svg"));
        assert!(svg.contains("</svg>"));
    }

    #[test]
    fn test_peer_config() {
        let peer = WireGuardPeerConfig {
            peer_name: "mobile-phone".to_string(),
            interface_address: "10.0.0.2/24".to_string(),
            private_key: "cBVRKzyV6FkeN9tYPqJCILdNXJKF8xhHxEYczGzfE3M=".to_string(),
            server_public_key: "RZv3iVQPxjKqBVLPEMJJX/xJ7FDGZdKzxcY5WV9vwVU=".to_string(),
            server_endpoint: "vpn.example.com:51820".to_string(),
            allowed_ips: "0.0.0.0/0".to_string(),
            dns_servers: Some("1.1.1.1".to_string()),
            persistent_keepalive: Some(25),
        };

        let config = peer.to_config_string();
        assert!(config.contains("mobile-phone") == false); // Name not in config
        assert!(config.contains("10.0.0.2/24"));

        let svg = peer.to_qr_svg().unwrap();
        assert!(svg.contains("<svg"));
    }
}
