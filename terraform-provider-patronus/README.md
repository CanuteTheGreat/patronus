# Terraform Provider for Patronus Firewall

This is the official Terraform provider for Patronus Firewall, enabling Infrastructure-as-Code management of firewall configurations.

## Features

- **Full Resource Management**: Create, read, update, and delete firewall rules, NAT rules, interfaces, and gateway groups
- **Declarative Configuration**: Define your firewall state in HCL (Terraform's configuration language)
- **State Tracking**: Terraform tracks the current state and generates minimal change sets
- **Plan & Apply Workflow**: Preview changes before applying them
- **GitOps Integration**: Store Terraform configs in Git for version control and collaboration

## Installation

### Terraform 0.13+

Add to your Terraform configuration:

```hcl
terraform {
  required_providers {
    patronus = {
      source  = "patronus/patronus"
      version = "~> 0.1"
    }
  }
}
```

## Configuration

### Provider Configuration

```hcl
provider "patronus" {
  # Path where declarative YAML configs will be written
  config_path = "/etc/patronus/config"

  # Optional: API endpoint if using remote management
  api_url = "https://patronus.example.com"

  # Optional: API authentication token
  api_token = var.patronus_api_token
}
```

### Environment Variables

- `PATRONUS_CONFIG_PATH`: Default config path
- `PATRONUS_API_URL`: API endpoint URL
- `PATRONUS_API_TOKEN`: API authentication token

## Usage Examples

### Firewall Rule

```hcl
resource "patronus_firewall_rule" "allow_ssh" {
  name        = "allow-ssh-from-office"
  description = "Allow SSH from office network"

  action      = "allow"
  interface   = "wan0"
  direction   = "inbound"
  protocol    = "tcp"

  source_address = "203.0.113.0/24"  # Office network
  dest_address   = "192.168.1.10"     # Internal SSH server
  dest_port      = "22"

  log     = true
  enabled = true
}

resource "patronus_firewall_rule" "allow_web" {
  name        = "allow-web-traffic"
  description = "Allow HTTP/HTTPS to web server"

  action      = "allow"
  interface   = "wan0"
  direction   = "inbound"
  protocol    = "tcp"

  source_address = "0.0.0.0/0"       # Any source
  dest_address   = "192.168.1.20"    # Web server
  dest_port      = "80,443"          # HTTP and HTTPS

  log     = true
  enabled = true
}

resource "patronus_firewall_rule" "block_suspicious" {
  name        = "block-suspicious-country"
  description = "Block traffic from high-risk countries"

  action      = "deny"
  interface   = "wan0"
  direction   = "inbound"

  source_address = "198.51.100.0/24"  # Example suspicious network

  log     = true
  enabled = true
}
```

### NAT Rule

```hcl
resource "patronus_nat_rule" "web_server_nat" {
  name        = "web-server-port-forward"
  description = "Forward ports 80/443 to internal web server"

  nat_type  = "port_forward"
  interface = "wan0"
}
```

### Gateway Group (Multi-WAN)

```hcl
resource "patronus_gateway_group" "failover_group" {
  name        = "wan-failover"
  description = "Primary and backup WAN with automatic failover"
}
```

### Network Interface

```hcl
resource "patronus_interface" "wan0" {
  name        = "wan0"
  description = "Primary WAN interface"
  enabled     = true
}
```

### Data Source

```hcl
data "patronus_firewall_rule" "existing_rule" {
  name = "allow-ssh-from-office"
}

output "rule_action" {
  value = data.patronus_firewall_rule.existing_rule.action
}
```

## Complete Example

```hcl
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
}

# Allow SSH from office
resource "patronus_firewall_rule" "allow_ssh" {
  name           = "allow-ssh-office"
  description    = "SSH access from office"
  action         = "allow"
  interface      = "wan0"
  direction      = "inbound"
  protocol       = "tcp"
  source_address = "203.0.113.0/24"
  dest_port      = "22"
  log            = true
  enabled        = true
}

# Allow web traffic
resource "patronus_firewall_rule" "allow_web" {
  name           = "allow-web"
  description    = "Public web traffic"
  action         = "allow"
  interface      = "wan0"
  direction      = "inbound"
  protocol       = "tcp"
  dest_port      = "80,443"
  log            = false
  enabled        = true
}

# Block all other inbound
resource "patronus_firewall_rule" "deny_all" {
  name        = "deny-all-inbound"
  description = "Default deny rule"
  action      = "deny"
  interface   = "wan0"
  direction   = "inbound"
  log         = true
  enabled     = true
}
```

## Workflow

### Standard Terraform Workflow

```bash
# Initialize provider
terraform init

# Preview changes
terraform plan

# Apply changes
terraform apply

# Destroy resources
terraform destroy
```

### GitOps Workflow

1. Store Terraform configs in Git repository
2. Make changes via pull requests
3. Run `terraform plan` in CI/CD to preview changes
4. Merge PR to apply changes automatically
5. Full audit trail in Git history

## How It Works

The provider generates declarative YAML configurations that follow the Patronus configuration schema:

```yaml
apiVersion: patronus.firewall/v1
kind: FirewallRule
metadata:
  name: allow-ssh-office
  description: SSH access from office
spec:
  action: allow
  interface: wan0
  direction: inbound
  protocol: tcp
  source:
    address: 203.0.113.0/24
  destination:
    ports: [22]
  log: true
  enabled: true
```

These YAML files are:
1. Written to `config_path` directory
2. Optionally sent to Patronus API (if configured)
3. Applied atomically by Patronus's apply engine
4. Tracked in Terraform state for drift detection

## Benefits

### vs Manual Configuration
- **Reproducible**: Exact same config every time
- **Version Controlled**: Full history in Git
- **Peer Reviewed**: Changes go through PR process
- **Documented**: Configuration is self-documenting

### vs Raw YAML
- **Type Safety**: Terraform validates types at plan time
- **State Tracking**: Knows what's deployed, detects drift
- **Dependency Management**: Handles resource dependencies
- **Ecosystem**: Integrates with other Terraform providers

## Development

### Building

```bash
go build -o terraform-provider-patronus
```

### Testing

```bash
go test ./...
```

### Local Installation

```bash
# Build
go build -o terraform-provider-patronus

# Install locally
mkdir -p ~/.terraform.d/plugins/registry.terraform.io/patronus/patronus/0.1.0/linux_amd64
cp terraform-provider-patronus ~/.terraform.d/plugins/registry.terraform.io/patronus/patronus/0.1.0/linux_amd64/
```

## Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Submit a pull request

## License

See LICENSE file.

## Resources

- [Patronus Documentation](https://docs.patronus.firewall)
- [Terraform Plugin Framework](https://developer.hashicorp.com/terraform/plugin/framework)
- [Terraform Provider Development](https://developer.hashicorp.com/terraform/plugin)
