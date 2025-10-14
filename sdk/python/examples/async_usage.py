#!/usr/bin/env python3
"""Async usage examples for Patronus Python SDK."""

import asyncio
from patronus import AsyncPatronusClient
from patronus.exceptions import PatronusError


async def main():
    """Demonstrate async SDK usage."""
    # Initialize async client
    async with AsyncPatronusClient(
        api_url="https://api.patronus.io",
        api_key="your-api-key-here"
    ) as client:
        try:
            # List all sites
            print("Fetching sites...")
            sites = await client.sites.list()
            print(f"✓ Found {len(sites)} site(s)")

            # Create multiple sites concurrently
            print("\nCreating sites concurrently...")
            site_tasks = [
                client.sites.create(
                    name=f"branch-{i}",
                    location=f"Location {i}",
                    wan_interfaces=["eth0"]
                )
                for i in range(1, 4)
            ]

            created_sites = await asyncio.gather(*site_tasks)
            print(f"✓ Created {len(created_sites)} sites")

            # Create tunnels for each site
            print("\nCreating tunnels...")
            tunnel_tasks = [
                client.tunnels.create(
                    name=f"hq-to-branch-{i}",
                    local_site_id="hq-site-id",
                    remote_site_id=site.id,
                    protocol="wireguard"
                )
                for i, site in enumerate(created_sites, 1)
            ]

            tunnels = await asyncio.gather(*tunnel_tasks)
            print(f"✓ Created {len(tunnels)} tunnels")

            # List tunnels
            print("\nListing tunnels...")
            all_tunnels = await client.tunnels.list()
            for tunnel in all_tunnels:
                print(f"  - {tunnel.name}: {tunnel.status.state}")

        except PatronusError as e:
            print(f"✗ Error: {e}")
            return 1

    return 0


if __name__ == "__main__":
    exit(asyncio.run(main()))
