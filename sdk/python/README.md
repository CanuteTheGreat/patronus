# Patronus Python SDK

Official Python SDK for the Patronus SD-WAN Platform.

## Installation

```bash
pip install patronus-sdk
```

## Quick Start

```python
from patronus import PatronusClient

# Initialize client
client = PatronusClient(
    api_url="https://api.patronus.io",
    api_key="your-api-key"
)

# Create a site
site = client.sites.create(
    name="hq-site",
    location="New York",
    wan_interfaces=["eth0", "eth1"]
)

# Create a tunnel
tunnel = client.tunnels.create(
    name="hq-to-branch",
    local_site_id=site.id,
    remote_site_id="remote-site-id",
    protocol="wireguard"
)

# Get tunnel status
status = client.tunnels.get_status(tunnel.id)
print(f"Tunnel status: {status.state}")
```

## Async Support

```python
from patronus import AsyncPatronusClient

async def main():
    async with AsyncPatronusClient(api_url="...", api_key="...") as client:
        sites = await client.sites.list()
        for site in sites:
            print(f"Site: {site.name}")

import asyncio
asyncio.run(main())
```

## Features

- **Sites Management**: Create, update, delete, and list sites
- **Tunnels**: Manage VPN tunnels between sites
- **Policies**: Configure routing and QoS policies
- **Monitoring**: Real-time metrics and alerts
- **Organizations**: Multi-tenant organization management
- **ML Models**: Deploy and manage ML models

## Documentation

Full documentation available at: https://docs.patronus.io/sdk/python

## License

Apache 2.0
