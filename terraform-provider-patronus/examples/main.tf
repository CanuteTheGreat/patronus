terraform {
  required_providers {
    patronus = {
      source  = "patronus/patronus"
      version = "~> 0.1"
    }
  }
}

provider "patronus" {
  config_path = "/etc/patronus/config"
  # api_url   = "https://patronus.example.com"
  # api_token = var.patronus_api_token
}

# Office network variable
variable "office_network" {
  description = "Office network CIDR"
  type        = string
  default     = "203.0.113.0/24"
}

# WAN interface
resource "patronus_interface" "wan0" {
  name        = "wan0"
  description = "Primary WAN interface"
  enabled     = true
}

# LAN interface
resource "patronus_interface" "lan0" {
  name        = "lan0"
  description = "Primary LAN interface"
  enabled     = true
}

# Allow SSH from office network
resource "patronus_firewall_rule" "allow_ssh_office" {
  name        = "allow-ssh-office"
  description = "SSH access from office network"

  action         = "allow"
  interface      = "wan0"
  direction      = "inbound"
  protocol       = "tcp"
  source_address = var.office_network
  dest_port      = "22"

  log     = true
  enabled = true
}

# Allow HTTPS management from office
resource "patronus_firewall_rule" "allow_mgmt_office" {
  name        = "allow-mgmt-office"
  description = "HTTPS management from office"

  action         = "allow"
  interface      = "wan0"
  direction      = "inbound"
  protocol       = "tcp"
  source_address = var.office_network
  dest_port      = "443"

  log     = true
  enabled = true
}

# Allow web traffic to DMZ server
resource "patronus_firewall_rule" "allow_web_dmz" {
  name        = "allow-web-dmz"
  description = "HTTP/HTTPS to DMZ web server"

  action         = "allow"
  interface      = "wan0"
  direction      = "inbound"
  protocol       = "tcp"
  source_address = "0.0.0.0/0"
  dest_address   = "192.168.100.10"  # DMZ web server
  dest_port      = "80,443"

  log     = false  # Don't log routine web traffic
  enabled = true
}

# Allow DNS queries
resource "patronus_firewall_rule" "allow_dns" {
  name        = "allow-dns"
  description = "DNS queries to resolver"

  action       = "allow"
  interface    = "lan0"
  direction    = "inbound"
  protocol     = "udp"
  dest_address = "192.168.1.1"  # Router IP
  dest_port    = "53"

  log     = false
  enabled = true
}

# Allow DHCP
resource "patronus_firewall_rule" "allow_dhcp" {
  name        = "allow-dhcp"
  description = "DHCP requests from LAN"

  action    = "allow"
  interface = "lan0"
  direction = "inbound"
  protocol  = "udp"
  dest_port = "67,68"

  log     = false
  enabled = true
}

# Allow LAN to WAN (outbound)
resource "patronus_firewall_rule" "allow_lan_to_wan" {
  name        = "allow-lan-to-wan"
  description = "Allow all LAN traffic to internet"

  action    = "allow"
  interface = "lan0"
  direction = "outbound"

  log     = false
  enabled = true
}

# Block known malicious networks
resource "patronus_firewall_rule" "block_malicious" {
  name        = "block-malicious-networks"
  description = "Block traffic from known malicious IPs"

  action         = "deny"
  interface      = "wan0"
  direction      = "inbound"
  source_address = "198.51.100.0/24"  # Example malicious network

  log     = true
  enabled = true
}

# Rate limit SSH attempts
resource "patronus_firewall_rule" "ratelimit_ssh" {
  name        = "ratelimit-ssh"
  description = "Rate limit SSH connection attempts"

  action    = "allow"
  interface = "wan0"
  direction = "inbound"
  protocol  = "tcp"
  dest_port = "22"

  log     = true
  enabled = true
}

# Default deny inbound on WAN
resource "patronus_firewall_rule" "deny_wan_inbound" {
  name        = "deny-wan-inbound-default"
  description = "Default deny all inbound WAN traffic"

  action    = "deny"
  interface = "wan0"
  direction = "inbound"

  log     = true
  enabled = true
}

# Port forward for web server
resource "patronus_nat_rule" "web_server_forward" {
  name        = "web-server-nat"
  description = "NAT for DMZ web server"

  nat_type  = "port_forward"
  interface = "wan0"
}

# Multi-WAN gateway group
resource "patronus_gateway_group" "wan_failover" {
  name        = "wan-failover-group"
  description = "Primary and backup WAN with automatic failover"
}

# Outputs
output "ssh_rule_name" {
  description = "Name of the SSH access rule"
  value       = patronus_firewall_rule.allow_ssh_office.name
}

output "total_rules" {
  description = "Total number of firewall rules"
  value       = length([
    patronus_firewall_rule.allow_ssh_office,
    patronus_firewall_rule.allow_mgmt_office,
    patronus_firewall_rule.allow_web_dmz,
    patronus_firewall_rule.allow_dns,
    patronus_firewall_rule.allow_dhcp,
    patronus_firewall_rule.allow_lan_to_wan,
    patronus_firewall_rule.block_malicious,
    patronus_firewall_rule.ratelimit_ssh,
    patronus_firewall_rule.deny_wan_inbound,
  ])
}
