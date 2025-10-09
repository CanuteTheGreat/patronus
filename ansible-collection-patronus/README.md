# Ansible Collection for Patronus Firewall

This Ansible collection provides modules for managing Patronus Firewall configurations using Infrastructure-as-Code principles.

## Installation

### From Ansible Galaxy

```bash
ansible-galaxy collection install patronus.firewall
```

### From Source

```bash
ansible-galaxy collection build
ansible-galaxy collection install patronus-firewall-0.1.0.tar.gz
```

## Requirements

- Ansible 2.9 or higher
- Python 3.6 or higher
- PyYAML library

## Modules

### firewall_rule

Manage Patronus firewall rules.

**Parameters:**
- `name` (required): Rule name
- `description` (optional): Rule description
- `action` (required): Action (allow, deny, reject)
- `interface` (optional): Interface name
- `direction` (optional): Direction (inbound, outbound)
- `protocol` (optional): Protocol (tcp, udp, icmp, any)
- `source_address` (optional): Source IP/CIDR
- `source_ports` (optional): Source port list
- `dest_address` (optional): Destination IP/CIDR
- `dest_ports` (optional): Destination port list
- `log` (optional, default: false): Enable logging
- `enabled` (optional, default: true): Enable rule
- `state` (optional, default: present): present or absent
- `config_path` (optional, default: /etc/patronus/config): Config directory

### nat_rule

Manage Patronus NAT rules.

**Parameters:**
- `name` (required): Rule name
- `description` (optional): Rule description
- `nat_type` (required): NAT type (source, destination, port_forward)
- `interface` (required): Interface name
- `state` (optional, default: present): present or absent
- `config_path` (optional, default: /etc/patronus/config): Config directory

## Usage Examples

### Basic Playbook

```yaml
---
- name: Configure Patronus Firewall
  hosts: firewall
  collections:
    - patronus.firewall
  tasks:
    - name: Allow SSH from office
      firewall_rule:
        name: allow-ssh-office
        description: SSH access from office network
        action: allow
        interface: wan0
        direction: inbound
        protocol: tcp
        source_address: 203.0.113.0/24
        dest_ports: [22]
        log: true
        enabled: true
```

### Complete Firewall Configuration

```yaml
---
- name: Deploy complete firewall ruleset
  hosts: firewall
  collections:
    - patronus.firewall
  vars:
    office_network: 203.0.113.0/24
    dmz_web_server: 192.168.100.10

  tasks:
    - name: Allow SSH from office
      firewall_rule:
        name: allow-ssh-office
        description: SSH access for administrators
        action: allow
        interface: wan0
        direction: inbound
        protocol: tcp
        source_address: "{{ office_network }}"
        dest_ports: [22]
        log: true
        state: present

    - name: Allow HTTPS management
      firewall_rule:
        name: allow-mgmt-https
        description: Web UI access from office
        action: allow
        interface: wan0
        direction: inbound
        protocol: tcp
        source_address: "{{ office_network }}"
        dest_ports: [443]
        log: true
        state: present

    - name: Allow web traffic to DMZ
      firewall_rule:
        name: allow-web-dmz
        description: Public web server in DMZ
        action: allow
        interface: wan0
        direction: inbound
        protocol: tcp
        dest_address: "{{ dmz_web_server }}"
        dest_ports: [80, 443]
        log: false
        state: present

    - name: Allow DNS from LAN
      firewall_rule:
        name: allow-dns-lan
        description: DNS queries from LAN clients
        action: allow
        interface: lan0
        direction: inbound
        protocol: udp
        dest_ports: [53]
        log: false
        state: present

    - name: Block malicious networks
      firewall_rule:
        name: block-malicious
        description: Block known malicious IP ranges
        action: deny
        interface: wan0
        direction: inbound
        source_address: 198.51.100.0/24
        log: true
        state: present

    - name: Default deny inbound
      firewall_rule:
        name: deny-wan-default
        description: Default deny all inbound WAN
        action: deny
        interface: wan0
        direction: inbound
        log: true
        state: present

    - name: Configure NAT for web server
      nat_rule:
        name: web-server-nat
        description: Port forward to DMZ web server
        nat_type: port_forward
        interface: wan0
        state: present
```

### Role-Based Organization

Create a role: `roles/patronus_firewall/tasks/main.yml`

```yaml
---
- name: Configure WAN firewall rules
  include_tasks: wan_rules.yml

- name: Configure LAN firewall rules
  include_tasks: lan_rules.yml

- name: Configure NAT rules
  include_tasks: nat_rules.yml
```

`roles/patronus_firewall/tasks/wan_rules.yml`:

```yaml
---
- name: Allow management from office
  patronus.firewall.firewall_rule:
    name: allow-mgmt-office
    action: allow
    interface: wan0
    direction: inbound
    source_address: "{{ office_network }}"
    dest_ports: [22, 443]
    protocol: tcp
    log: true

- name: Block all other WAN inbound
  patronus.firewall.firewall_rule:
    name: deny-wan-default
    action: deny
    interface: wan0
    direction: inbound
    log: true
```

### Using with Ansible Vault for Secrets

```yaml
---
- name: Configure firewall with sensitive data
  hosts: firewall
  vars_files:
    - vault.yml  # Contains encrypted office_network variable
  tasks:
    - name: Allow SSH from encrypted office network
      patronus.firewall.firewall_rule:
        name: allow-ssh-office
        action: allow
        source_address: "{{ office_network }}"
        dest_ports: [22]
        protocol: tcp
```

### Dynamic Inventory Example

```yaml
---
- name: Configure all firewalls
  hosts: tag_role_firewall  # Dynamic inventory from cloud provider
  collections:
    - patronus.firewall
  tasks:
    - name: Apply standard ruleset
      include_role:
        name: patronus_firewall
```

## Idempotency

All modules are idempotent - they:
- Only make changes when configuration differs from desired state
- Report `changed: false` when no changes are needed
- Support check mode (`--check`) for dry-run testing
- Generate minimal diffs

Example:

```bash
# First run - creates rules
ansible-playbook firewall.yml
# CHANGED: 5

# Second run - no changes needed
ansible-playbook firewall.yml
# CHANGED: 0

# Check mode - show what would change
ansible-playbook firewall.yml --check --diff
```

## Integration with GitOps

Combine with Patronus GitOps watcher for full automation:

1. Store playbooks in Git repository
2. Configure Patronus GitOps to watch the config directory
3. Run Ansible playbook via CI/CD on merge to main
4. GitOps watcher detects changes and applies automatically

```yaml
# .gitlab-ci.yml or .github/workflows/deploy.yml
deploy:
  script:
    - ansible-playbook -i inventory firewall.yml
  only:
    - main
```

## How It Works

Ansible modules generate declarative YAML configurations:

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

These files are written to `/etc/patronus/config/` and can be:
- Applied directly by Patronus apply engine
- Picked up by GitOps watcher
- Version controlled in Git
- Reviewed via pull requests

## Benefits

### vs Manual Configuration
- **Reproducible**: Same playbook = same result every time
- **Auditable**: Full history in Git + Ansible logs
- **Testable**: Use `--check` mode to preview changes
- **Scalable**: Manage hundreds of firewalls with one playbook

### vs Raw YAML
- **Simplified Syntax**: Ansible's YAML is cleaner than raw configs
- **Variables & Templates**: Use Jinja2 templating
- **Conditionals & Loops**: Dynamic rule generation
- **Vault Integration**: Encrypt sensitive data

### vs Terraform
- **Procedural**: Step-by-step execution (vs declarative state)
- **Existing Ecosystem**: Leverage existing Ansible infrastructure
- **Agentless**: SSH-based, no agents required
- **Configuration Management**: Not just firewall - full system config

## Testing

### Syntax Check

```bash
ansible-playbook firewall.yml --syntax-check
```

### Dry Run

```bash
ansible-playbook firewall.yml --check
```

### Diff Mode

```bash
ansible-playbook firewall.yml --check --diff
```

### Molecule Testing

```yaml
# molecule/default/converge.yml
---
- name: Converge
  hosts: all
  tasks:
    - name: Include firewall role
      include_role:
        name: patronus_firewall
```

## Contributing

Contributions welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Add tests for new modules
4. Update documentation
5. Submit pull request

## License

MIT

## Support

- Documentation: https://docs.patronus.firewall/ansible
- Issues: https://github.com/patronus/ansible-collection-patronus/issues
- Community: https://community.patronus.firewall
