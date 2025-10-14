# Patronus SD-WAN CLI

Unified command-line interface for managing Patronus SD-WAN deployments.

## Installation

```bash
cargo install --path crates/patronus-cli
```

## Quick Start

### 1. Initialize Deployment

```bash
patronus init --name my-sdwan --org acme-corp
```

This creates a configuration file at `/etc/patronus/config.yaml`.

### 2. Create Sites

```bash
# Headquarters
patronus site create hq \
  --location "New York" \
  --address 10.0.0.1

# Branch offices
patronus site create branch1 \
  --location "Chicago" \
  --address 10.0.1.1

patronus site create branch2 \
  --location "Los Angeles" \
  --address 10.0.2.1
```

### 3. Create Tunnels

```bash
# HQ to Branch 1
patronus tunnel create hq-branch1 \
  --source hq \
  --destination branch1 \
  --protocol wireguard

# HQ to Branch 2
patronus tunnel create hq-branch2 \
  --source hq \
  --destination branch2 \
  --protocol ipsec
```

### 4. Configure Policies

```bash
# Allow HTTP traffic
patronus policy create allow-http \
  --source 10.0.0.0/8 \
  --destination 0.0.0.0/0 \
  --action allow \
  --priority 100

# Route voice traffic
patronus policy create route-voice \
  --source 10.0.0.0/24 \
  --destination 10.0.1.0/24 \
  --action route \
  --priority 50
```

### 5. Start the Daemon

```bash
patronus daemon --bind 0.0.0.0:8080
```

## Commands Reference

### Site Management

```bash
# Create a site
patronus site create <NAME> --location <LOCATION> --address <IP>

# List all sites
patronus site list

# Show site details
patronus site show <SITE>

# Delete a site
patronus site delete <SITE>
```

### Tunnel Management

```bash
# Create a tunnel
patronus tunnel create <NAME> \
  --source <SITE> \
  --destination <SITE> \
  --protocol <wireguard|ipsec|gre>

# List all tunnels
patronus tunnel list

# Show tunnel details
patronus tunnel show <TUNNEL>

# Start a tunnel
patronus tunnel start <TUNNEL>

# Stop a tunnel
patronus tunnel stop <TUNNEL>

# Delete a tunnel
patronus tunnel delete <TUNNEL>
```

### Policy Management

```bash
# Create a policy
patronus policy create <NAME> \
  --source <CIDR> \
  --destination <CIDR> \
  --action <allow|deny|route> \
  --priority <NUMBER>

# List all policies
patronus policy list

# Show policy details
patronus policy show <POLICY>

# Delete a policy
patronus policy delete <POLICY>
```

### BGP Management

```bash
# Configure BGP peer
patronus bgp peer \
  --address 192.168.1.1 \
  --asn 65000

# Show BGP status
patronus bgp status

# Show BGP routes
patronus bgp routes
```

### Status and Monitoring

```bash
# Show system status
patronus status

# Show detailed status
patronus status --detailed

# Show traffic statistics
patronus metrics traffic

# Show link health
patronus metrics health

# Show bandwidth usage
patronus metrics bandwidth
```

### Configuration Management

```bash
# Deploy configuration from file
patronus deploy config.yaml

# Validate configuration
patronus validate config.yaml
```

## Configuration File Format

```yaml
deployment:
  name: my-sdwan
  organization: acme-corp
  version: "1.0"

sites:
  - id: abc123
    name: hq
    location: New York
    address: 10.0.0.1
    enabled: true

  - id: def456
    name: branch1
    location: Chicago
    address: 10.0.1.1
    enabled: true

tunnels:
  - id: tun001
    name: hq-branch1
    source: hq
    destination: branch1
    protocol: wireguard
    status: running

policies:
  - id: pol001
    name: allow-http
    source: 10.0.0.0/8
    destination: 0.0.0.0/0
    action: allow
    priority: 100

bgp:
  enabled: false
  asn: null
  router_id: null

monitoring:
  enabled: true
  metrics_port: 9090
```

## Example Deployment Scenarios

### Hub-and-Spoke Topology

```bash
# Initialize
patronus init --name hub-spoke --org enterprise

# Create hub site
patronus site create hub --location "HQ" --address 10.0.0.1

# Create spoke sites
for i in {1..5}; do
  patronus site create spoke$i \
    --location "Branch $i" \
    --address 10.0.$i.1
done

# Create tunnels from hub to all spokes
for i in {1..5}; do
  patronus tunnel create hub-spoke$i \
    --source hub \
    --destination spoke$i \
    --protocol wireguard
done

# Start daemon
patronus daemon
```

### Full Mesh Topology

```bash
# Initialize
patronus init --name full-mesh --org distributed

# Create sites
patronus site create site1 --location "Region 1" --address 10.0.1.1
patronus site create site2 --location "Region 2" --address 10.0.2.1
patronus site create site3 --location "Region 3" --address 10.0.3.1

# Create full mesh tunnels
patronus tunnel create site1-site2 --source site1 --destination site2
patronus tunnel create site1-site3 --source site1 --destination site3
patronus tunnel create site2-site3 --source site2 --destination site3

# Configure BGP for dynamic routing
patronus bgp peer --address 10.0.2.1 --asn 65001
patronus bgp peer --address 10.0.3.1 --asn 65002
```

### Multi-Region with MPLS

```bash
# Initialize
patronus init --name multi-region --org global-corp

# Create regional hubs
patronus site create us-hub --location "US East" --address 10.1.0.1
patronus site create eu-hub --location "EU West" --address 10.2.0.1
patronus site create apac-hub --location "APAC" --address 10.3.0.1

# Inter-region MPLS connectivity
patronus tunnel create us-eu \
  --source us-hub \
  --destination eu-hub \
  --protocol mpls

patronus tunnel create us-apac \
  --source us-hub \
  --destination apac-hub \
  --protocol mpls
```

## Monitoring and Troubleshooting

### Check System Health

```bash
# Overall status
patronus status --detailed

# Link health
patronus metrics health

# Traffic statistics
patronus metrics traffic
```

### View Logs

```bash
# Follow daemon logs
tail -f /var/log/patronus/daemon.log

# View tunnel logs
patronus tunnel show hq-branch1
```

### Debug Mode

```bash
# Run with verbose output
patronus -v status

# Check configuration
patronus validate /etc/patronus/config.yaml
```

## API Access

The daemon provides a REST API on the configured bind address:

```bash
# Get status
curl http://localhost:8080/api/v1/status

# List sites
curl http://localhost:8080/api/v1/sites

# Create tunnel
curl -X POST http://localhost:8080/api/v1/tunnels \
  -H "Content-Type: application/json" \
  -d '{"name":"new-tunnel","source":"site1","destination":"site2"}'
```

## Integration

### Terraform

```hcl
resource "patronus_site" "hq" {
  name     = "hq"
  location = "New York"
  address  = "10.0.0.1"
}

resource "patronus_tunnel" "hq_branch" {
  name        = "hq-branch1"
  source      = patronus_site.hq.id
  destination = patronus_site.branch1.id
  protocol    = "wireguard"
}
```

### Ansible

```yaml
- name: Create Patronus site
  patronus_site:
    name: hq
    location: New York
    address: 10.0.0.1
    state: present

- name: Create tunnel
  patronus_tunnel:
    name: hq-branch1
    source: hq
    destination: branch1
    protocol: wireguard
    state: started
```

## Advanced Features

### Traffic Engineering

```bash
# Configure path constraints
patronus policy create latency-sensitive \
  --source 10.0.0.0/24 \
  --destination 10.0.1.0/24 \
  --action route \
  --max-latency 20ms \
  --priority 10
```

### Failover Policies

```bash
# Primary path
patronus tunnel create primary \
  --source hq \
  --destination branch1 \
  --protocol wireguard

# Backup path
patronus tunnel create backup \
  --source hq \
  --destination branch1 \
  --protocol ipsec

# Configure failover
patronus policy create auto-failover \
  --primary primary \
  --backup backup \
  --failover-threshold 100ms
```

### QoS Configuration

```bash
# Prioritize voice traffic
patronus policy create voice-qos \
  --source 10.0.0.0/24 \
  --destination any \
  --qos-class realtime \
  --bandwidth-min 10Mbps \
  --priority 1
```

## Best Practices

1. **Use descriptive names** for sites, tunnels, and policies
2. **Document your topology** with comments in config files
3. **Test in non-production** before deploying to production
4. **Monitor regularly** with `patronus status` and metrics commands
5. **Back up configurations** before making major changes
6. **Use version control** for configuration files
7. **Implement gradual rollouts** for configuration changes
8. **Set up alerting** for tunnel failures and health issues

## Troubleshooting

### Common Issues

**Tunnel won't start:**
```bash
# Check tunnel configuration
patronus tunnel show <tunnel-name>

# Check site connectivity
ping <remote-site-ip>

# View logs
journalctl -u patronus -f
```

**High latency:**
```bash
# Check link health
patronus metrics health

# View traffic statistics
patronus metrics traffic

# Check for congestion
patronus metrics bandwidth
```

**Configuration errors:**
```bash
# Validate configuration
patronus validate /etc/patronus/config.yaml

# Check syntax
cat /etc/patronus/config.yaml | yaml-lint
```

## Support

- Documentation: https://docs.patronus.io
- GitHub: https://github.com/patronus/patronus
- Issues: https://github.com/patronus/patronus/issues
- Community: https://community.patronus.io

## License

See LICENSE file in the project root.
