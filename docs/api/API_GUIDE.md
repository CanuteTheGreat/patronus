# Patronus SD-WAN API Guide

**Version**: 1.0.0
**API Version**: v1
**Last Updated**: 2025-10-11

---

## Quick Start

### Authentication

1. **Login** to obtain tokens:

```bash
curl -X POST http://localhost:8081/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "password": "your-password"
  }'
```

Response:
```json
{
  "access_token": "eyJhbGc...",
  "refresh_token": "dGhpcyBp...",
  "expires_in": 900,
  "token_type": "Bearer"
}
```

2. **Use access token** in subsequent requests:

```bash
curl -H "Authorization: Bearer eyJhbGc..." \
  http://localhost:8081/v1/sites
```

### API Documentation

- **OpenAPI Spec**: `/docs/api/openapi.yaml`
- **Interactive Docs**: `http://localhost:8081/docs` (Swagger UI)
- **GraphQL Playground**: `http://localhost:8081/graphql/playground`

---

## Common Use Cases

### 1. Managing Sites

**List all sites**:
```bash
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:8081/v1/sites
```

**Create a new site**:
```bash
curl -X POST \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "branch-office-nyc",
    "location": "New York, NY",
    "public_key": "Xnbn1B5BoYXOqLBz0cH8RqJLDK0lLOcS6+3eD2M0Ync=",
    "endpoints": ["203.0.113.100:51820"]
  }' \
  http://localhost:8081/v1/sites
```

**Get site details**:
```bash
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:8081/v1/sites/550e8400-e29b-41d4-a716-446655440000
```

**Update site**:
```bash
curl -X PUT \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "location": "New York City, NY",
    "status": "active"
  }' \
  http://localhost:8081/v1/sites/550e8400-e29b-41d4-a716-446655440000
```

**Delete site**:
```bash
curl -X DELETE \
  -H "Authorization: Bearer $TOKEN" \
  http://localhost:8081/v1/sites/550e8400-e29b-41d4-a716-446655440000
```

### 2. Monitoring Path Health

**Get all paths**:
```bash
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:8081/v1/paths
```

**Filter by status**:
```bash
curl -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8081/v1/paths?status=down"
```

**Get path health history**:
```bash
curl -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8081/v1/paths/path-123/health?since=2025-10-11T00:00:00Z&limit=100"
```

### 3. Managing Policies

**List policies**:
```bash
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:8081/v1/policies
```

**Create routing policy**:
```bash
curl -X POST \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "video-traffic-priority",
    "priority": 100,
    "match_criteria": {
      "protocol": "udp",
      "dst_port_range": "3478-3497",
      "dscp": 46
    },
    "action": {
      "type": "route",
      "primary_path_id": "path-fiber",
      "backup_path_id": "path-lte",
      "failover_threshold": 70
    }
  }' \
  http://localhost:8081/v1/policies
```

### 4. Traffic Statistics

**Get traffic stats**:
```bash
curl -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8081/v1/traffic/stats?since=2025-10-11T00:00:00Z&aggregation=5m"
```

**Get stats for specific policy**:
```bash
curl -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8081/v1/traffic/stats?policy_id=policy-123"
```

### 5. Metrics Export

**Prometheus format**:
```bash
curl http://localhost:8081/v1/metrics/export?format=prometheus
```

**JSON format**:
```bash
curl http://localhost:8081/v1/metrics/export?format=json
```

---

## Error Handling

All errors follow a consistent format:

```json
{
  "error": {
    "code": "SITE_NOT_FOUND",
    "message": "Site with ID 'xyz' not found",
    "details": {
      "site_id": "xyz"
    }
  }
}
```

### Common Error Codes

| Code | HTTP Status | Description |
|------|-------------|-------------|
| `INVALID_CREDENTIALS` | 401 | Username/password incorrect |
| `UNAUTHORIZED` | 401 | Missing or invalid token |
| `FORBIDDEN` | 403 | Insufficient permissions |
| `NOT_FOUND` | 404 | Resource not found |
| `VALIDATION_ERROR` | 400 | Invalid request data |
| `CONFLICT` | 409 | Resource already exists |
| `RATE_LIMIT_EXCEEDED` | 429 | Too many requests |
| `INTERNAL_ERROR` | 500 | Server error |

---

## Rate Limiting

Limits are enforced per IP address and per user:

- **Per IP**: 100 requests/minute
- **Per User**: 1000 requests/hour

Response headers include rate limit info:

```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1696881600
```

When rate limited (HTTP 429):

```json
{
  "error": {
    "code": "RATE_LIMIT_EXCEEDED",
    "message": "Rate limit exceeded. Try again in 30 seconds.",
    "details": {
      "retry_after": 30
    }
  }
}
```

---

## Pagination

List endpoints support pagination:

```bash
curl -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8081/v1/sites?limit=50&offset=100"
```

Response includes pagination info:

```json
{
  "sites": [...],
  "total": 250,
  "limit": 50,
  "offset": 100
}
```

---

## Filtering and Sorting

### Filtering

Most list endpoints support filtering:

```bash
# Filter sites by status
GET /v1/sites?status=active

# Filter paths by site
GET /v1/paths?site_id=site-123

# Filter by multiple criteria
GET /v1/sites?status=active&location=Seattle
```

### Sorting

Use `sort` parameter:

```bash
# Sort by name (ascending)
GET /v1/sites?sort=name

# Sort by name (descending)
GET /v1/sites?sort=-name

# Multiple sort fields
GET /v1/sites?sort=status,-name
```

---

## Webhooks

Subscribe to events via webhooks:

### Supported Events

- `site.created`
- `site.updated`
- `site.deleted`
- `path.status_changed`
- `failover.triggered`
- `policy.created`
- `policy.updated`

### Register Webhook

```bash
curl -X POST \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://your-server.com/webhook",
    "events": ["path.status_changed", "failover.triggered"],
    "secret": "your-webhook-secret"
  }' \
  http://localhost:8081/v1/webhooks
```

### Webhook Payload

```json
{
  "event": "path.status_changed",
  "timestamp": "2025-10-11T20:30:00Z",
  "data": {
    "path_id": "path-123",
    "old_status": "up",
    "new_status": "down",
    "health_score": 45.2
  },
  "signature": "sha256=..."
}
```

### Verify Webhook Signature

```python
import hmac
import hashlib

def verify_webhook(payload, signature, secret):
    expected = 'sha256=' + hmac.new(
        secret.encode(),
        payload.encode(),
        hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, signature)
```

---

## SDK Examples

### Python

```python
from patronus import PatronusClient

# Initialize client
client = PatronusClient(
    base_url="http://localhost:8081",
    username="admin",
    password="password"
)

# List sites
sites = client.sites.list()
for site in sites:
    print(f"{site.name}: {site.status}")

# Create site
new_site = client.sites.create(
    name="branch-sf",
    public_key="...",
    endpoints=["203.0.113.200:51820"]
)

# Get path health
health = client.paths.get_health("path-123", since="2025-10-10T00:00:00Z")
print(f"Average latency: {health.avg_latency_ms}ms")
```

### JavaScript

```javascript
const { PatronusClient } = require('patronus-sdk');

// Initialize client
const client = new PatronusClient({
  baseUrl: 'http://localhost:8081',
  username: 'admin',
  password: 'password'
});

// List sites
const sites = await client.sites.list();
sites.forEach(site => {
  console.log(`${site.name}: ${site.status}`);
});

// Create policy
const policy = await client.policies.create({
  name: 'priority-traffic',
  priority: 100,
  matchCriteria: {
    protocol: 'tcp',
    dstPortRange: '443-443'
  },
  action: {
    type: 'route',
    primaryPathId: 'path-1'
  }
});
```

### Go

```go
package main

import (
    "github.com/patronus/patronus-go"
)

func main() {
    // Initialize client
    client := patronus.NewClient(
        "http://localhost:8081",
        "admin",
        "password",
    )

    // List sites
    sites, err := client.Sites.List(context.Background())
    if err != nil {
        log.Fatal(err)
    }

    for _, site := range sites {
        fmt.Printf("%s: %s\n", site.Name, site.Status)
    }

    // Get path health
    health, err := client.Paths.GetHealth(
        context.Background(),
        "path-123",
        patronus.WithSince(time.Now().Add(-24 * time.Hour)),
    )
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("Health score: %.2f\n", health.HealthScore)
}
```

---

## GraphQL API

In addition to REST, Patronus provides a GraphQL API for complex queries.

### Query Example

```graphql
query {
  sites {
    id
    name
    status
    paths {
      id
      destination {
        name
      }
      health {
        latencyMs
        packetLossPct
        status
      }
    }
  }
}
```

### Mutation Example

```graphql
mutation {
  createSite(input: {
    name: "branch-la"
    publicKey: "..."
    endpoints: ["203.0.113.300:51820"]
  }) {
    id
    name
    status
  }
}
```

### Subscription Example

```graphql
subscription {
  pathHealthChanged {
    pathId
    health {
      latencyMs
      status
    }
  }
}
```

See GraphQL schema at: `http://localhost:8081/graphql/schema`

---

## Best Practices

### 1. Token Refresh

Access tokens expire after 15 minutes. Refresh before expiry:

```javascript
async function apiCallWithRefresh(client, apiFunc) {
  try {
    return await apiFunc();
  } catch (error) {
    if (error.status === 401) {
      await client.auth.refresh();
      return await apiFunc(); // Retry
    }
    throw error;
  }
}
```

### 2. Error Handling

Always handle errors properly:

```python
try:
    site = client.sites.get(site_id)
except patronus.NotFoundError:
    print(f"Site {site_id} not found")
except patronus.AuthenticationError:
    print("Invalid credentials")
    client.auth.login()
except patronus.RateLimitError as e:
    time.sleep(e.retry_after)
    # Retry
```

### 3. Batch Operations

Use batch endpoints when available:

```bash
# Instead of multiple calls
for site in sites:
    curl ... /v1/sites/$site

# Use batch endpoint
curl -X POST /v1/sites/batch \
  -d '{"ids": ["site-1", "site-2", "site-3"]}'
```

### 4. Webhooks vs Polling

Prefer webhooks over polling for real-time updates:

```python
# ❌ Avoid polling
while True:
    paths = client.paths.list()
    check_for_changes(paths)
    time.sleep(10)

# ✅ Use webhooks
@app.route('/webhook', methods=['POST'])
def handle_webhook():
    event = request.json
    if event['event'] == 'path.status_changed':
        handle_path_change(event['data'])
```

---

## API Versioning

The API uses URL versioning (`/v1/`, `/v2/`, etc.).

### Version Support

- **v1**: Current stable version
- **v2**: GraphQL API (also stable)

### Deprecation Policy

- New versions are additive (non-breaking)
- Breaking changes trigger new version
- Old versions supported for 12 months after deprecation
- Deprecation notices in response headers:

```
Deprecation: Sun, 01 Jan 2026 00:00:00 GMT
Sunset: Sun, 01 Jan 2027 00:00:00 GMT
Link: <https://docs.patronus.com/api/v2>; rel="successor-version"
```

---

## Troubleshooting

### "401 Unauthorized"

- Check access token is valid
- Token may have expired (refresh)
- Check token format: `Bearer <token>`

### "403 Forbidden"

- User lacks required permissions
- Check user role (admin/operator/viewer)

### "429 Rate Limit Exceeded"

- Wait for `retry_after` seconds
- Implement exponential backoff
- Consider caching responses

### "500 Internal Server Error"

- Check server logs
- Verify request payload
- Report bug if persistent

---

## Support

- **Documentation**: https://docs.patronus.com
- **API Reference**: https://api.patronus.com/docs
- **Issues**: https://github.com/patronus/patronus/issues
- **Community**: https://discord.gg/patronus

---

**Document Version**: 1.0.0
**Last Updated**: 2025-10-11
**Maintainer**: API Team
