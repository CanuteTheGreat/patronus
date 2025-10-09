#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2025, Patronus Team
# MIT License

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: firewall_rule
short_description: Manage Patronus firewall rules
version_added: "0.1.0"
description:
    - Create, update, or delete Patronus firewall rules
    - Uses declarative YAML configuration
    - Idempotent operations
options:
    name:
        description: Name of the firewall rule
        required: true
        type: str
    description:
        description: Description of the firewall rule
        required: false
        type: str
    action:
        description: Action to take (allow, deny, reject)
        required: true
        type: str
        choices: ['allow', 'deny', 'reject']
    interface:
        description: Interface name (e.g., wan0, lan0)
        required: false
        type: str
    direction:
        description: Direction (inbound, outbound)
        required: false
        type: str
        choices: ['inbound', 'outbound']
    protocol:
        description: Protocol (tcp, udp, icmp, any)
        required: false
        type: str
    source_address:
        description: Source IP address or CIDR
        required: false
        type: str
    source_ports:
        description: Source port(s)
        required: false
        type: list
        elements: int
    dest_address:
        description: Destination IP address or CIDR
        required: false
        type: str
    dest_ports:
        description: Destination port(s)
        required: false
        type: list
        elements: int
    log:
        description: Enable logging for this rule
        required: false
        type: bool
        default: false
    enabled:
        description: Whether the rule is enabled
        required: false
        type: bool
        default: true
    state:
        description: Desired state of the rule
        required: false
        type: str
        choices: ['present', 'absent']
        default: present
    config_path:
        description: Path to Patronus configuration directory
        required: false
        type: str
        default: /etc/patronus/config
author:
    - Patronus Team
'''

EXAMPLES = r'''
- name: Allow SSH from office network
  patronus.firewall.firewall_rule:
    name: allow-ssh-office
    description: SSH access from office
    action: allow
    interface: wan0
    direction: inbound
    protocol: tcp
    source_address: 203.0.113.0/24
    dest_ports: [22]
    log: true
    enabled: true
    state: present

- name: Allow web traffic
  patronus.firewall.firewall_rule:
    name: allow-web
    description: HTTP/HTTPS traffic
    action: allow
    interface: wan0
    direction: inbound
    protocol: tcp
    dest_ports: [80, 443]
    log: false
    state: present

- name: Block malicious network
  patronus.firewall.firewall_rule:
    name: block-malicious
    description: Block known malicious IPs
    action: deny
    interface: wan0
    direction: inbound
    source_address: 198.51.100.0/24
    log: true
    state: present

- name: Remove old rule
  patronus.firewall.firewall_rule:
    name: old-rule
    state: absent
'''

RETURN = r'''
changed:
    description: Whether the rule was changed
    type: bool
    returned: always
rule:
    description: The firewall rule configuration
    type: dict
    returned: when state is present
message:
    description: Human-readable message about what happened
    type: str
    returned: always
'''

import os
import yaml
from ansible.module_utils.basic import AnsibleModule


def generate_config(params):
    """Generate declarative config from parameters"""
    config = {
        'apiVersion': 'patronus.firewall/v1',
        'kind': 'FirewallRule',
        'metadata': {
            'name': params['name'],
        },
        'spec': {
            'action': params['action'],
            'log': params['log'],
            'enabled': params['enabled'],
        }
    }

    if params.get('description'):
        config['metadata']['description'] = params['description']

    if params.get('interface'):
        config['spec']['interface'] = params['interface']

    if params.get('direction'):
        config['spec']['direction'] = params['direction']

    if params.get('protocol'):
        config['spec']['protocol'] = params['protocol']

    # Source specification
    source = {}
    if params.get('source_address'):
        source['address'] = params['source_address']
    if params.get('source_ports'):
        source['ports'] = params['source_ports']
    if source:
        config['spec']['source'] = source

    # Destination specification
    dest = {}
    if params.get('dest_address'):
        dest['address'] = params['dest_address']
    if params.get('dest_ports'):
        dest['ports'] = params['dest_ports']
    if dest:
        config['spec']['destination'] = dest

    return config


def config_file_path(config_path, name):
    """Get the file path for a rule config"""
    return os.path.join(config_path, f"FirewallRule-{name}.yaml")


def read_existing_config(filepath):
    """Read existing configuration from file"""
    if not os.path.exists(filepath):
        return None

    try:
        with open(filepath, 'r') as f:
            return yaml.safe_load(f)
    except Exception:
        return None


def write_config(filepath, config):
    """Write configuration to file"""
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    with open(filepath, 'w') as f:
        yaml.dump(config, f, default_flow_style=False, sort_keys=False)


def delete_config(filepath):
    """Delete configuration file"""
    if os.path.exists(filepath):
        os.remove(filepath)


def configs_equal(config1, config2):
    """Check if two configs are equivalent"""
    if config1 is None or config2 is None:
        return config1 == config2

    # Compare relevant fields
    return (
        config1.get('metadata', {}).get('name') == config2.get('metadata', {}).get('name') and
        config1.get('spec') == config2.get('spec')
    )


def main():
    module = AnsibleModule(
        argument_spec=dict(
            name=dict(type='str', required=True),
            description=dict(type='str', required=False),
            action=dict(type='str', required=True, choices=['allow', 'deny', 'reject']),
            interface=dict(type='str', required=False),
            direction=dict(type='str', required=False, choices=['inbound', 'outbound']),
            protocol=dict(type='str', required=False),
            source_address=dict(type='str', required=False),
            source_ports=dict(type='list', elements='int', required=False),
            dest_address=dict(type='str', required=False),
            dest_ports=dict(type='list', elements='int', required=False),
            log=dict(type='bool', required=False, default=False),
            enabled=dict(type='bool', required=False, default=True),
            state=dict(type='str', required=False, default='present', choices=['present', 'absent']),
            config_path=dict(type='str', required=False, default='/etc/patronus/config'),
        ),
        supports_check_mode=True,
    )

    params = module.params
    config_path = params['config_path']
    name = params['name']
    state = params['state']

    filepath = config_file_path(config_path, name)
    existing_config = read_existing_config(filepath)

    changed = False
    result = {
        'changed': False,
        'message': '',
    }

    if state == 'present':
        # Generate desired config
        desired_config = generate_config(params)

        if configs_equal(existing_config, desired_config):
            # No change needed
            result['message'] = f"Firewall rule '{name}' already exists with desired configuration"
            result['rule'] = desired_config
        else:
            # Need to create or update
            changed = True
            if existing_config is None:
                result['message'] = f"Created firewall rule '{name}'"
            else:
                result['message'] = f"Updated firewall rule '{name}'"

            result['rule'] = desired_config

            if not module.check_mode:
                write_config(filepath, desired_config)

    elif state == 'absent':
        if existing_config is not None:
            # Need to delete
            changed = True
            result['message'] = f"Deleted firewall rule '{name}'"

            if not module.check_mode:
                delete_config(filepath)
        else:
            result['message'] = f"Firewall rule '{name}' already absent"

    result['changed'] = changed
    module.exit_json(**result)


if __name__ == '__main__':
    main()
