#!/usr/bin/env python3
"""Basic usage examples for Patronus Python SDK."""

from patronus import PatronusClient
from patronus.exceptions import PatronusError


def main():
    """Demonstrate basic SDK usage."""
    # Initialize the client
    client = PatronusClient(
        api_url="https://api.patronus.io",
        api_key="your-api-key-here"
    )

    try:
        # Create a site
        print("Creating site...")
        site = client.sites.create(
            name="headquarters",
            location="New York, NY",
            wan_interfaces=["eth0", "eth1"],
            metadata={"datacenter": "nyc-1", "region": "us-east"}
        )
        print(f"✓ Created site: {site.name} (ID: {site.id})")

        # Create a tunnel
        print("\nCreating tunnel...")
        tunnel = client.tunnels.create(
            name="hq-to-branch-office",
            local_site_id=site.id,
            remote_site_id="remote-site-id",
            protocol="wireguard"
        )
        print(f"✓ Created tunnel: {tunnel.name} (ID: {tunnel.id})")

        # Get tunnel status
        print("\nChecking tunnel status...")
        status = client.tunnels.get_status(tunnel.id)
        print(f"✓ Tunnel status: {status['state']}")

        # Create a policy
        print("\nCreating routing policy...")
        policy = client.policies.create(
            name="allow-web-traffic",
            rules=[
                {"protocol": "tcp", "dst_port": 443, "action": "allow", "priority": 10},
                {"protocol": "tcp", "dst_port": 80, "action": "allow", "priority": 20},
            ],
            site_id=site.id
        )
        print(f"✓ Created policy: {policy.name} (ID: {policy.id})")

        # List all sites
        print("\nListing all sites...")
        sites = client.sites.list()
        print(f"✓ Found {len(sites)} site(s)")
        for s in sites:
            print(f"  - {s.name} ({s.location})")

    except PatronusError as e:
        print(f"✗ Error: {e}")
        return 1

    return 0


if __name__ == "__main__":
    exit(main())
