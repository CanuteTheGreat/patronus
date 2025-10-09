#!/usr/bin/python
# -*- coding: utf-8 -*-

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: nat_rule
short_description: Manage Patronus NAT rules
version_added: "0.1.0"
description:
    - Create, update, or delete Patronus NAT rules
options:
    name:
        description: Name of the NAT rule
        required: true
        type: str
    description:
        description: Description of the NAT rule
        required: false
        type: str
    nat_type:
        description: Type of NAT (source, destination, port_forward)
        required: true
        type: str
        choices: ['source', 'destination', 'port_forward']
    interface:
        description: Interface name
        required: true
        type: str
    source_address:
        description: Source IP address or CIDR
        required: false
        type: str
    dest_address:
        description: Destination IP address or CIDR
        required: false
        type: str
    translation_address:
        description: Translation (target) IP address
        required: false
        type: str
    translation_port:
        description: Translation (target) port
        required: false
        type: int
    protocol:
        description: Protocol (tcp, udp, any)
        required: false
        type: str
    dest_port:
        description: Destination port
        required: false
        type: int
    enabled:
        description: Whether the rule is enabled
        required: false
        type: bool
        default: true
    state:
        description: Desired state
        required: false
        type: str
        choices: ['present', 'absent']
        default: present
    config_path:
        description: Path to Patronus configuration directory
        required: false
        type: str
        default: /etc/patronus/config
'''

EXAMPLES = r'''
- name: Configure port forwarding for web server
  patronus.firewall.nat_rule:
    name: web-server-nat
    description: Forward HTTP/HTTPS to DMZ web server
    nat_type: port_forward
    interface: wan0
    dest_port: 80
    translation_address: 192.168.100.10
    translation_port: 80
    protocol: tcp
    state: present

- name: Configure source NAT for LAN
  patronus.firewall.nat_rule:
    name: lan-outbound-nat
    description: Source NAT for LAN internet access
    nat_type: source
    interface: wan0
    source_address: 192.168.1.0/24
    state: present

- name: Configure destination NAT
  patronus.firewall.nat_rule:
    name: dmz-dnat
    description: Destination NAT to DMZ
    nat_type: destination
    interface: wan0
    dest_address: 203.0.113.50
    translation_address: 192.168.100.10
    state: present
'''

RETURN = r'''
changed:
    description: Whether the rule was changed
    type: bool
    returned: always
rule:
    description: The NAT rule configuration
    type: dict
    returned: when state is present
message:
    description: Human-readable message
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
        'kind': 'NatRule',
        'metadata': {
            'name': params['name'],
        },
        'spec': {
            'nat_type': params['nat_type'],
            'interface': params['interface'],
            'enabled': params['enabled'],
        }
    }

    if params.get('description'):
        config['metadata']['description'] = params['description']

    if params.get('source_address'):
        config['spec']['source_address'] = params['source_address']

    if params.get('dest_address'):
        config['spec']['dest_address'] = params['dest_address']

    if params.get('translation_address'):
        config['spec']['translation_address'] = params['translation_address']

    if params.get('translation_port'):
        config['spec']['translation_port'] = params['translation_port']

    if params.get('protocol'):
        config['spec']['protocol'] = params['protocol']

    if params.get('dest_port'):
        config['spec']['dest_port'] = params['dest_port']

    return config


def config_file_path(config_path, name):
    """Get the file path for a rule config"""
    return os.path.join(config_path, f"NatRule-{name}.yaml")


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

    return (
        config1.get('metadata', {}).get('name') == config2.get('metadata', {}).get('name') and
        config1.get('spec') == config2.get('spec')
    )


def main():
    module = AnsibleModule(
        argument_spec=dict(
            name=dict(type='str', required=True),
            description=dict(type='str', required=False),
            nat_type=dict(type='str', required=True, choices=['source', 'destination', 'port_forward']),
            interface=dict(type='str', required=True),
            source_address=dict(type='str', required=False),
            dest_address=dict(type='str', required=False),
            translation_address=dict(type='str', required=False),
            translation_port=dict(type='int', required=False),
            protocol=dict(type='str', required=False),
            dest_port=dict(type='int', required=False),
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
        desired_config = generate_config(params)

        if configs_equal(existing_config, desired_config):
            result['message'] = f"NAT rule '{name}' already exists with desired configuration"
            result['rule'] = desired_config
        else:
            changed = True
            if existing_config is None:
                result['message'] = f"Created NAT rule '{name}'"
            else:
                result['message'] = f"Updated NAT rule '{name}'"

            result['rule'] = desired_config

            if not module.check_mode:
                write_config(filepath, desired_config)

    elif state == 'absent':
        if existing_config is not None:
            changed = True
            result['message'] = f"Deleted NAT rule '{name}'"

            if not module.check_mode:
                delete_config(filepath)
        else:
            result['message'] = f"NAT rule '{name}' already absent"

    result['changed'] = changed
    module.exit_json(**result)


if __name__ == '__main__':
    main()
