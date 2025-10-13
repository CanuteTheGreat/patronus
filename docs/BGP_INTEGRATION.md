# Patronus SD-WAN BGP Integration Guide

**Version**: 1.0.0
**Last Updated**: 2025-10-12

---

## Overview

The Patronus BGP integration enables dynamic route advertisement and learning from upstream routers, providing enterprise-grade routing capabilities for SD-WAN deployments.

### Features

- **Dynamic Route Advertisement**: Advertise SD-WAN prefixes via BGP
- **Route Learning**: Learn routes from BGP neighbors
- **Route Policies**: Advanced route filtering and manipulation
- **Multi-Protocol BGP**: Support for IPv4 and IPv6
- **Route Maps**: Flexible route manipulation with communities, AS path prepending
- **BGP Communities**: Tag routes for policy-based routing
- **Graceful Restart**: Maintain forwarding during BGP restarts

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│              Patronus SD-WAN with BGP                    │
├─────────────────────────────────────────────────────────┤
│                                                           │
│  ┌─────────────────────────────────────────────────┐   │
│  │              BGP Manager                         │   │
│  │  - Neighbor management                           │   │
│  │  - Route processing                              │   │
│  │  - Policy application                            │   │
│  └────────────────┬────────────────────────────────┘   │
│                   │                                      │
│         ┌─────────┴─────────────────────┐               │
│         │                                │               │
│  ┌──────▼──────┐              ┌─────────▼────────┐     │
│  │   BGP       │              │   Route          │     │
│  │ Neighbors   │              │   Table          │     │
│  └──────┬──────┘              └─────────┬────────┘     │
│         │                                │               │
│         └────────────┬───────────────────┘               │
│                      │                                   │
│           ┌──────────▼──────────┐                        │
│           │   SD-WAN Routing    │                        │
│           │      Engine         │                        │
│           └─────────────────────┘                        │
│                                                           │
└─────────────────────────────────────────────────────────┘
              │                          │
              ▼                          ▼
      ┌──────────────┐          ┌──────────────┐
      │  Upstream    │          │  Upstream    │
      │  Router 1    │          │  Router 2    │
      └──────────────┘          └──────────────┘
```

---

## Configuration

### Basic BGP Configuration

```yaml
bgp:
  asn: 65001
  router_id: 10.0.0.1

  neighbors:
    - ip: 10.0.1.1
      asn: 65002
      description: "Upstream ISP Router"

  networks:
    - prefix: 192.168.0.0/16
```

### Complete Configuration Example

```yaml
bgp:
  # Local AS number
  asn: 65001

  # Router ID (typically the primary loopback address)
  router_id: 10.0.0.1

  # BGP neighbors
  neighbors:
    - ip: 10.0.1.1
      asn: 65002
      description: "Primary ISP"
      password: "bgp-secret-123"  # MD5 authentication
      timers:
        keepalive_secs: 30
        holdtime_secs: 90
      route_map_in: "ISP-IN"
      route_map_out: "ISP-OUT"

    - ip: 10.0.2.1
      asn: 65003
      description: "Secondary ISP"
      next_hop_self: true

  # Networks to advertise
  networks:
    - prefix: 192.168.0.0/16
      route_map: "ADVERTISE-SD-WAN"

    - prefix: 10.10.0.0/16

  # Route maps
  route_maps:
    - name: "ISP-IN"
      rules:
        - sequence: 10
          action: permit
          match_conditions:
            - type: prefix_list
              name: "ALLOWED-PREFIXES"
          set_actions:
            - type: local_preference
              value: 200

    - name: "ISP-OUT"
      rules:
        - sequence: 10
          action: permit
          match_conditions:
            - type: prefix
              prefix: 192.168.0.0/16
          set_actions:
            - type: community
              community: "65001:100"
            - type: as_path_prepend
              asn: 65001
              count: 2

  # Global timers
  timers:
    keepalive_secs: 30
    holdtime_secs: 90
    connect_retry_secs: 120
```

---

## Use Cases

### Use Case 1: Advertise SD-WAN Prefixes

**Scenario**: Advertise internal SD-WAN networks to upstream router.

```yaml
bgp:
  asn: 65001
  router_id: 10.0.0.1

  neighbors:
    - ip: 10.0.1.1
      asn: 65002

  networks:
    - prefix: 192.168.0.0/16  # SD-WAN internal network
    - prefix: 10.0.0.0/8       # Private network
```

### Use Case 2: Load Balancing with Multiple ISPs

**Scenario**: Use two ISPs with primary/backup configuration.

```yaml
bgp:
  asn: 65001
  router_id: 10.0.0.1

  neighbors:
    # Primary ISP (higher local preference)
    - ip: 10.0.1.1
      asn: 65002
      description: "Primary ISP"
      route_map_in: "PRIMARY-IN"

    # Backup ISP (lower local preference)
    - ip: 10.0.2.1
      asn: 65003
      description: "Backup ISP"
      route_map_in: "BACKUP-IN"

  route_maps:
    - name: "PRIMARY-IN"
      rules:
        - sequence: 10
          action: permit
          set_actions:
            - type: local_preference
              value: 200  # Higher preference

    - name: "BACKUP-IN"
      rules:
        - sequence: 10
          action: permit
          set_actions:
            - type: local_preference
              value: 100  # Lower preference
```

### Use Case 3: Traffic Engineering with Communities

**Scenario**: Tag SD-WAN traffic for policy-based routing at upstream.

```yaml
bgp:
  asn: 65001
  router_id: 10.0.0.1

  neighbors:
    - ip: 10.0.1.1
      asn: 65002
      route_map_out: "COMMUNITY-TAG"

  networks:
    - prefix: 192.168.1.0/24  # Critical traffic
    - prefix: 192.168.2.0/24  # Best-effort traffic

  route_maps:
    - name: "COMMUNITY-TAG"
      rules:
        # Tag critical traffic
        - sequence: 10
          action: permit
          match_conditions:
            - type: prefix
              prefix: 192.168.1.0/24
          set_actions:
            - type: community
              community: "65001:100"  # Priority traffic

        # Tag best-effort traffic
        - sequence: 20
          action: permit
          match_conditions:
            - type: prefix
              prefix: 192.168.2.0/24
          set_actions:
            - type: community
              community: "65001:200"  # Normal traffic
```

### Use Case 4: AS Path Prepending for Traffic Control

**Scenario**: Make a path less preferred by prepending AS numbers.

```yaml
bgp:
  asn: 65001
  router_id: 10.0.0.1

  neighbors:
    # Primary path (no prepending)
    - ip: 10.0.1.1
      asn: 65002
      description: "Primary Path"
      route_map_out: "PRIMARY-OUT"

    # Backup path (AS prepending to make less attractive)
    - ip: 10.0.2.1
      asn: 65003
      description: "Backup Path"
      route_map_out: "BACKUP-OUT"

  route_maps:
    - name: "PRIMARY-OUT"
      rules:
        - sequence: 10
          action: permit

    - name: "BACKUP-OUT"
      rules:
        - sequence: 10
          action: permit
          set_actions:
            - type: as_path_prepend
              asn: 65001
              count: 3  # Prepend 3 times: 65001 65001 65001 65001
```

---

## Route Filtering

### Prefix Lists

Define which prefixes to accept or advertise:

```yaml
bgp:
  # ... other config ...

  route_maps:
    - name: "FILTER-IN"
      rules:
        # Accept only RFC1918 private addresses
        - sequence: 10
          action: permit
          match_conditions:
            - type: prefix
              prefix: 10.0.0.0/8

        - sequence: 20
          action: permit
          match_conditions:
            - type: prefix
              prefix: 172.16.0.0/12

        - sequence: 30
          action: permit
          match_conditions:
            - type: prefix
              prefix: 192.168.0.0/16

        # Deny everything else
        - sequence: 100
          action: deny
```

### AS Path Filtering

Filter based on AS path:

```yaml
route_maps:
  - name: "AS-PATH-FILTER"
    rules:
      # Only accept routes from specific AS
      - sequence: 10
        action: permit
        match_conditions:
          - type: as_path
            pattern: "^65002$"  # Only routes originating from AS 65002

      - sequence: 20
        action: deny
```

---

## Monitoring

### BGP Status

Check BGP neighbor status:

```bash
curl http://localhost:8081/v1/bgp/neighbors
```

Response:
```json
{
  "neighbors": [
    {
      "ip": "10.0.1.1",
      "asn": 65002,
      "state": "Established",
      "uptime_secs": 3600,
      "routes_received": 1500,
      "routes_advertised": 10
    }
  ]
}
```

### BGP Routes

View BGP routing table:

```bash
curl http://localhost:8081/v1/bgp/routes
```

### Metrics

Prometheus metrics for BGP:

```
# BGP neighbor state (0=Idle, 1=Connect, ... 5=Established)
patronus_bgp_neighbor_state{peer="10.0.1.1",asn="65002"} 5

# Routes received from neighbor
patronus_bgp_routes_received{peer="10.0.1.1"} 1500

# Routes advertised to neighbor
patronus_bgp_routes_advertised{peer="10.0.1.1"} 10

# BGP session uptime (seconds)
patronus_bgp_session_uptime_seconds{peer="10.0.1.1"} 3600
```

---

## Troubleshooting

### BGP Neighbor Not Establishing

**Check connectivity**:
```bash
ping 10.0.1.1
telnet 10.0.1.1 179
```

**Check logs**:
```bash
journalctl -u patronus-sdwan | grep bgp
```

**Common issues**:
- Firewall blocking TCP port 179
- AS number mismatch
- MD5 password mismatch
- Timers incompatible

### Routes Not Being Advertised

**Check route maps**:
```bash
curl http://localhost:8081/v1/bgp/route-maps
```

**Check network configuration**:
```yaml
networks:
  - prefix: 192.168.0.0/16  # Ensure this is correct
```

**Check filters**:
- Verify route map permits the prefix
- Check export policy

### Routes Not Being Learned

**Check import policy**:
```bash
curl http://localhost:8081/v1/bgp/routes?source=neighbor&ip=10.0.1.1
```

**Check route maps**:
- Verify route map in `route_map_in` permits routes
- Check prefix lists

---

## Best Practices

### 1. Use MD5 Authentication

Always use MD5 passwords for BGP neighbors:

```yaml
neighbors:
  - ip: 10.0.1.1
    asn: 65002
    password: "strong-random-password-here"
```

### 2. Implement Route Filtering

Never accept all routes without filtering:

```yaml
# ❌ Bad: No filtering
neighbors:
  - ip: 10.0.1.1
    asn: 65002

# ✅ Good: Explicit filtering
neighbors:
  - ip: 10.0.1.1
    asn: 65002
    route_map_in: "FILTER-IN"
    route_map_out: "FILTER-OUT"
```

### 3. Use Communities for Policy

Tag routes with communities for easy policy application:

```yaml
route_maps:
  - name: "TAG-ROUTES"
    rules:
      - sequence: 10
        action: permit
        set_actions:
          - type: community
            community: "65001:100"  # Internal use
```

### 4. Monitor BGP State

Set up alerts for BGP state changes:

```yaml
# Prometheus alert example
- alert: BGPNeighborDown
  expr: patronus_bgp_neighbor_state != 5
  for: 5m
  annotations:
    summary: "BGP neighbor {{ $labels.peer }} is down"
```

### 5. Document AS Numbers and Policies

Keep clear documentation of:
- AS number assignments
- BGP community meanings
- Route map purposes
- Neighbor relationships

---

## Integration with FRRouting

For production deployments with full BGP functionality, integrate with FRRouting:

### 1. Install FRRouting

```bash
# Ubuntu/Debian
apt-get install -y frr

# Enable BGP daemon
sed -i 's/bgpd=no/bgpd=yes/' /etc/frr/daemons

# Start FRRouting
systemctl enable frr
systemctl start frr
```

### 2. Configure FRRouting

```bash
vtysh << EOF
configure terminal

router bgp 65001
  bgp router-id 10.0.0.1

  neighbor 10.0.1.1 remote-as 65002
  neighbor 10.0.1.1 description Primary ISP
  neighbor 10.0.1.1 password bgp-secret-123

  address-family ipv4 unicast
    network 192.168.0.0/16
    neighbor 10.0.1.1 activate
  exit-address-family

exit
write memory
EOF
```

### 3. Integrate with Patronus

Patronus can read routes from FRRouting via vtysh or zebra API.

---

## API Reference

### List BGP Neighbors

```bash
GET /v1/bgp/neighbors
```

### Get Neighbor Details

```bash
GET /v1/bgp/neighbors/{ip}
```

### List BGP Routes

```bash
GET /v1/bgp/routes
```

### Update BGP Configuration

```bash
PUT /v1/bgp/config
Content-Type: application/json

{
  "asn": 65001,
  "router_id": "10.0.0.1",
  "neighbors": [...]
}
```

---

## Limitations

Current implementation provides BGP configuration and management framework. For full BGP protocol implementation:

1. **Use FRRouting**: Full-featured BGP daemon
2. **Use BIRD**: Lightweight alternative
3. **Custom Implementation**: Extend `patronus-bgp` crate with full protocol support

The current implementation is ideal for:
- Configuration management
- Route advertisement to FRRouting/BIRD
- Monitoring and observability
- Policy application

---

## Future Enhancements

Planned for future releases:

- [ ] Full BGP protocol implementation (without FRRouting dependency)
- [ ] BGP multipath support
- [ ] BGP add-path
- [ ] Flowspec support
- [ ] BMP (BGP Monitoring Protocol)
- [ ] BGP-LS (Link State)

---

## Support

- **Documentation**: https://docs.patronus.dev/bgp
- **Examples**: See `examples/bgp/` directory
- **Issues**: https://github.com/patronus/patronus/issues

---

**Document Version**: 1.0.0
**Last Updated**: 2025-10-12
**Maintainer**: Network Team
