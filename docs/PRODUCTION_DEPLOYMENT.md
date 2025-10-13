# Patronus SD-WAN Production Deployment Guide

**Version**: 1.0.0
**Last Updated**: 2025-10-12
**Target Audience**: Operations Teams, DevOps Engineers

---

## Overview

This guide covers deploying Patronus SD-WAN to production environments, including cloud, on-premises, and hybrid deployments.

### Prerequisites

- Linux servers (kernel 5.4+)
- Root or sudo access
- Network connectivity between sites
- Domain names (for HTTPS)
- SSL/TLS certificates
- Basic Kubernetes knowledge (for K8s deployment)

---

## Deployment Options

### Option 1: Cloud Deployment (Recommended)

**Advantages**:
- Quick provisioning
- High availability built-in
- Easy scaling
- Managed services available

**Supported Clouds**:
- AWS (EKS, EC2)
- Google Cloud (GKE, Compute Engine)
- Azure (AKS, Virtual Machines)
- DigitalOcean (DOKS, Droplets)

### Option 2: On-Premises Deployment

**Advantages**:
- Full control
- No cloud costs
- Compliance requirements met
- Existing infrastructure

**Requirements**:
- Physical or virtual machines
- Network infrastructure
- Storage and backup
- Monitoring setup

### Option 3: Hybrid Deployment

**Advantages**:
- Best of both worlds
- Gradual cloud migration
- Disaster recovery across environments
- Compliance + flexibility

---

## Architecture Decisions

### 1. Deployment Size

#### Small Deployment (1-10 sites)
- **Control Plane**: Single node (or 2-node HA)
- **Resources**: 2 vCPU, 4GB RAM per node
- **Database**: SQLite (local)
- **Monitoring**: Basic Prometheus + Grafana
- **Estimated Cost**: $50-200/month (cloud)

#### Medium Deployment (10-100 sites)
- **Control Plane**: 3-node HA cluster
- **Resources**: 4 vCPU, 8GB RAM per node
- **Database**: PostgreSQL (managed or self-hosted)
- **Monitoring**: Full stack with alerting
- **Estimated Cost**: $500-1000/month (cloud)

#### Large Deployment (100-1000 sites)
- **Control Plane**: 5-node HA cluster with load balancer
- **Resources**: 8 vCPU, 16GB RAM per node
- **Database**: PostgreSQL with replication
- **Monitoring**: Enterprise monitoring + logging
- **Estimated Cost**: $2000-5000/month (cloud)

#### Very Large Deployment (1000+ sites)
- **Control Plane**: Multi-region clusters
- **Resources**: 16+ vCPU, 32GB+ RAM per node
- **Database**: Distributed database (CockroachDB, etc.)
- **Monitoring**: Full observability stack
- **Estimated Cost**: $10,000+/month (cloud)

### 2. High Availability Strategy

#### Active-Passive HA
- Primary node handles all traffic
- Standby node ready for failover
- Shared storage or database replication
- RTO: 2-5 minutes
- **Use Case**: Small to medium deployments

#### Active-Active HA
- Multiple nodes handle traffic simultaneously
- Load balancer distributes requests
- Shared database with leader election
- RTO: <30 seconds (automatic)
- **Use Case**: Medium to large deployments

### 3. Network Architecture

#### Hub-and-Spoke
```
        ┌─────────────┐
        │     Hub     │
        │  (Central)  │
        └──────┬──────┘
               │
       ┌───────┼───────┐
       │       │       │
  ┌────▼──┐ ┌─▼───┐ ┌─▼────┐
  │Spoke 1│ │Spoke│ │Spoke │
  │       │ │  2  │ │  3   │
  └───────┘ └─────┘ └──────┘
```

**Pros**: Simple, centralized control
**Cons**: Single point of failure, suboptimal path

#### Full Mesh
```
  ┌─────────┐     ┌─────────┐
  │ Site A  │─────│ Site B  │
  └────┬────┘     └────┬────┘
       │               │
       │    ┌─────────┐│
       └────│ Site C  ││
            └────┬────┘│
                 └─────┘
```

**Pros**: Optimal paths, no single point of failure
**Cons**: More complex, more connections (n*(n-1)/2)

#### Hybrid (Recommended)
- Core sites in full mesh
- Edge sites in hub-and-spoke
- Best balance of performance and complexity

---

## Step-by-Step Deployment

### Phase 1: Infrastructure Setup

#### 1.1. Provision Servers

**AWS Example (Terraform)**:

```hcl
# main.tf
provider "aws" {
  region = "us-west-2"
}

resource "aws_instance" "patronus_control" {
  count         = 3
  ami           = "ami-0c55b159cbfafe1f0"  # Ubuntu 22.04
  instance_type = "t3.large"

  vpc_security_group_ids = [aws_security_group.patronus.id]
  subnet_id              = aws_subnet.patronus[count.index].id

  tags = {
    Name = "patronus-control-${count.index + 1}"
    Role = "control-plane"
  }

  user_data = <<-EOF
    #!/bin/bash
    apt-get update
    apt-get install -y wireguard
  EOF
}

resource "aws_security_group" "patronus" {
  name = "patronus-sdwan"

  ingress {
    from_port   = 8080
    to_port     = 8081
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 51820
    to_port     = 51820
    protocol    = "udp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
```

**On-Premises Example (Ansible)**:

```yaml
# playbook.yml
---
- name: Prepare Patronus SD-WAN servers
  hosts: patronus_nodes
  become: yes

  tasks:
    - name: Update system
      apt:
        update_cache: yes
        upgrade: dist

    - name: Install WireGuard
      apt:
        name: wireguard
        state: present

    - name: Enable IP forwarding
      sysctl:
        name: net.ipv4.ip_forward
        value: '1'
        sysctl_set: yes

    - name: Install Docker
      shell: |
        curl -fsSL https://get.docker.com | sh
        systemctl enable docker
        systemctl start docker
```

#### 1.2. Network Configuration

**Firewall Rules**:

```bash
# Allow SD-WAN traffic
ufw allow 8080/tcp    # Metrics
ufw allow 8081/tcp    # Dashboard
ufw allow 51820/udp   # WireGuard
ufw allow 22/tcp      # SSH (restrict to management network)

# Enable firewall
ufw enable
```

**DNS Setup**:

```bash
# Create DNS A records
# patronus-ctrl-1.example.com -> 203.0.113.1
# patronus-ctrl-2.example.com -> 203.0.113.2
# patronus-ctrl-3.example.com -> 203.0.113.3
# patronus.example.com -> load balancer IP
```

#### 1.3. Load Balancer Setup

**AWS Application Load Balancer (Terraform)**:

```hcl
resource "aws_lb" "patronus" {
  name               = "patronus-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.id]
  subnets            = aws_subnet.public[*].id
}

resource "aws_lb_target_group" "dashboard" {
  name     = "patronus-dashboard"
  port     = 8081
  protocol = "HTTP"
  vpc_id   = aws_vpc.main.id

  health_check {
    path     = "/health"
    interval = 30
  }
}

resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.patronus.arn
  port              = "443"
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS-1-2-2017-01"
  certificate_arn   = aws_acm_certificate.patronus.arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.dashboard.arn
  }
}
```

**HAProxy (On-Premises)**:

```bash
# /etc/haproxy/haproxy.cfg
global
    maxconn 4096
    daemon

defaults
    mode http
    timeout connect 5000ms
    timeout client 50000ms
    timeout server 50000ms

frontend patronus_dashboard
    bind *:443 ssl crt /etc/ssl/patronus.pem
    default_backend patronus_nodes

backend patronus_nodes
    balance roundrobin
    option httpchk GET /health
    server ctrl1 10.0.1.1:8081 check
    server ctrl2 10.0.1.2:8081 check
    server ctrl3 10.0.1.3:8081 check

frontend patronus_wireguard
    bind *:51820 udp
    default_backend wireguard_nodes

backend wireguard_nodes
    balance source  # Source IP-based routing
    server ctrl1 10.0.1.1:51820 check
    server ctrl2 10.0.1.2:51820 check
    server ctrl3 10.0.1.3:51820 check
```

---

### Phase 2: Database Setup

#### Option 1: SQLite (Small Deployments)

```bash
# Create database directory
mkdir -p /var/lib/patronus
chown patronus:patronus /var/lib/patronus

# Database created automatically on first run
# Location: /var/lib/patronus/sdwan.db
```

**Backup Configuration**:

```bash
# /etc/cron.hourly/patronus-backup
#!/bin/bash
DB_PATH="/var/lib/patronus/sdwan.db"
BACKUP_DIR="/backup/patronus"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)

sqlite3 "$DB_PATH" ".backup '$BACKUP_DIR/sdwan-$TIMESTAMP.db'"

# Keep last 24 hourly backups
find "$BACKUP_DIR" -name "sdwan-*.db" -mtime +1 -delete
```

#### Option 2: PostgreSQL (Medium/Large Deployments)

**Managed PostgreSQL (AWS RDS)**:

```hcl
resource "aws_db_instance" "patronus" {
  identifier           = "patronus-db"
  engine               = "postgres"
  engine_version       = "15.3"
  instance_class       = "db.t3.medium"
  allocated_storage    = 100
  storage_encrypted    = true

  db_name  = "patronus"
  username = "patronus_admin"
  password = var.db_password

  multi_az               = true
  backup_retention_period = 30
  backup_window          = "03:00-04:00"

  vpc_security_group_ids = [aws_security_group.db.id]
}
```

**Self-Hosted PostgreSQL (High Availability)**:

```bash
# Install PostgreSQL with streaming replication
apt-get install -y postgresql-15 postgresql-contrib

# Primary node configuration
# /etc/postgresql/15/main/postgresql.conf
wal_level = replica
max_wal_senders = 5
wal_keep_size = 1GB
hot_standby = on

# /etc/postgresql/15/main/pg_hba.conf
host replication replicator 10.0.0.0/8 md5

# Create replication user
sudo -u postgres createuser -U postgres replicator -P --replication
```

---

### Phase 3: Deploy Patronus SD-WAN

#### 3.1. Install Binary

**From GitHub Releases**:

```bash
# Download latest release
VERSION="1.0.0"
wget https://github.com/patronus/patronus/releases/download/v${VERSION}/patronus-sdwan-linux-x86_64.tar.gz

# Extract
tar xzf patronus-sdwan-linux-x86_64.tar.gz

# Install
sudo mv patronus-sdwan /usr/local/bin/
sudo chmod +x /usr/local/bin/patronus-sdwan

# Verify
patronus-sdwan --version
```

**From Docker**:

```bash
docker pull ghcr.io/patronus/patronus-sdwan:latest
```

**From Source**:

```bash
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Clone repository
git clone https://github.com/patronus/patronus.git
cd patronus

# Build release
cargo build --release

# Install
sudo cp target/release/patronus-sdwan /usr/local/bin/
```

#### 3.2. Configuration

**Create Configuration File**:

```bash
sudo mkdir -p /etc/patronus
sudo vim /etc/patronus/config.yaml
```

**Configuration Example** (`/etc/patronus/config.yaml`):

```yaml
# Patronus SD-WAN Production Configuration
version: "1.0"

# Site Configuration
site:
  id: "ctrl-primary"
  name: "Control Plane Primary"
  location: "AWS us-west-2a"
  role: "control-plane"

# Network Configuration
network:
  listen_address: "0.0.0.0:8080"
  dashboard_address: "0.0.0.0:8081"

  wireguard:
    interface: "wg0"
    listen_port: 51820
    private_key_file: "/etc/patronus/wireguard-private.key"

# Database Configuration
database:
  # SQLite
  type: "sqlite"
  path: "/var/lib/patronus/sdwan.db"

  # PostgreSQL (commented out)
  # type: "postgres"
  # host: "patronus-db.abc.us-west-2.rds.amazonaws.com"
  # port: 5432
  # database: "patronus"
  # username: "patronus_admin"
  # password_file: "/etc/patronus/db-password"
  # pool:
  #   max_connections: 20

# High Availability
ha:
  enabled: true
  cluster_size: 3
  election_timeout_ms: 5000
  heartbeat_interval_ms: 1000

  # Cluster members
  peers:
    - id: "ctrl-1"
      address: "10.0.1.1:7890"
    - id: "ctrl-2"
      address: "10.0.1.2:7890"
    - id: "ctrl-3"
      address: "10.0.1.3:7890"

# Monitoring
monitoring:
  metrics:
    enabled: true
    prometheus_port: 8080
    export_interval_secs: 15

  health:
    check_interval_secs: 10
    probes_per_check: 5

# Security
security:
  jwt_secret_file: "/etc/patronus/jwt-secret"

  tls:
    enabled: true
    cert_file: "/etc/patronus/tls/cert.pem"
    key_file: "/etc/patronus/tls/key.pem"

  rate_limiting:
    enabled: true
    requests_per_minute: 100

# Logging
logging:
  level: "info"
  format: "json"
  output: "/var/log/patronus/sdwan.log"

# Performance Tuning
performance:
  worker_threads: 8
  max_connections: 10000

  tokio:
    thread_keep_alive_ms: 60000

  database:
    connection_timeout_secs: 30
    max_lifetime_secs: 3600
```

#### 3.3. Generate Secrets

```bash
# WireGuard private key
wg genkey | sudo tee /etc/patronus/wireguard-private.key
sudo chmod 600 /etc/patronus/wireguard-private.key

# JWT secret (256-bit random key)
openssl rand -base64 32 | sudo tee /etc/patronus/jwt-secret
sudo chmod 600 /etc/patronus/jwt-secret

# Database password (if using PostgreSQL)
openssl rand -base64 32 | sudo tee /etc/patronus/db-password
sudo chmod 600 /etc/patronus/db-password
```

#### 3.4. TLS Certificates

**Option 1: Let's Encrypt (Recommended)**:

```bash
# Install certbot
apt-get install -y certbot

# Generate certificate
certbot certonly --standalone \
  -d patronus.example.com \
  --non-interactive \
  --agree-tos \
  --email admin@example.com

# Copy certificates
sudo cp /etc/letsencrypt/live/patronus.example.com/fullchain.pem /etc/patronus/tls/cert.pem
sudo cp /etc/letsencrypt/live/patronus.example.com/privkey.pem /etc/patronus/tls/key.pem

# Auto-renewal
echo "0 0 * * * certbot renew --quiet" | crontab -
```

**Option 2: Self-Signed (Development/Testing)**:

```bash
openssl req -x509 -newkey rsa:4096 -nodes \
  -keyout /etc/patronus/tls/key.pem \
  -out /etc/patronus/tls/cert.pem \
  -days 365 \
  -subj "/CN=patronus.example.com"
```

#### 3.5. Create Systemd Service

```bash
sudo vim /etc/systemd/system/patronus-sdwan.service
```

**Service File**:

```ini
[Unit]
Description=Patronus SD-WAN
After=network.target
Wants=network-online.target

[Service]
Type=simple
User=root
Group=root

ExecStart=/usr/local/bin/patronus-sdwan --config /etc/patronus/config.yaml

Restart=always
RestartSec=10

# Security
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/patronus /var/log/patronus

# Resource limits
LimitNOFILE=65536
LimitNPROC=4096

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=patronus-sdwan

[Install]
WantedBy=multi-user.target
```

#### 3.6. Start Service

```bash
# Reload systemd
sudo systemctl daemon-reload

# Enable service (start on boot)
sudo systemctl enable patronus-sdwan

# Start service
sudo systemctl start patronus-sdwan

# Check status
sudo systemctl status patronus-sdwan

# View logs
sudo journalctl -u patronus-sdwan -f
```

---

### Phase 4: Deploy Monitoring

#### 4.1. Prometheus

**Configuration** (`/etc/prometheus/prometheus.yml`):

```yaml
global:
  scrape_interval: 15s
  evaluation_interval: 15s

scrape_configs:
  - job_name: 'patronus-sdwan'
    static_configs:
      - targets:
          - 'ctrl-1.example.com:8080'
          - 'ctrl-2.example.com:8080'
          - 'ctrl-3.example.com:8080'
        labels:
          cluster: 'production'

  - job_name: 'node-exporter'
    static_configs:
      - targets:
          - 'ctrl-1.example.com:9100'
          - 'ctrl-2.example.com:9100'
          - 'ctrl-3.example.com:9100'

alerting:
  alertmanagers:
    - static_configs:
        - targets:
            - 'localhost:9093'

rule_files:
  - '/etc/prometheus/alerts/*.yml'
```

**Alert Rules** (`/etc/prometheus/alerts/patronus.yml`):

```yaml
groups:
  - name: patronus-sdwan
    interval: 30s
    rules:
      - alert: PatronusDown
        expr: up{job="patronus-sdwan"} == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "Patronus SD-WAN instance down"
          description: "{{ $labels.instance }} has been down for more than 1 minute"

      - alert: HighPathLatency
        expr: patronus_path_latency_ms > 200
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High path latency detected"
          description: "Path {{ $labels.path_id }} latency is {{ $value }}ms"

      - alert: PathDown
        expr: patronus_path_status == 0
        for: 2m
        labels:
          severity: critical
        annotations:
          summary: "Path down"
          description: "Path {{ $labels.path_id }} has been down for 2 minutes"
```

#### 4.2. Grafana

**Docker Compose** (`/opt/patronus/monitoring/docker-compose.yml`):

```yaml
version: '3.8'

services:
  prometheus:
    image: prom/prometheus:latest
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml
      - ./alerts:/etc/prometheus/alerts
      - prometheus-data:/prometheus
    ports:
      - "9090:9090"
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.retention.time=30d'

  grafana:
    image: grafana/grafana:latest
    volumes:
      - grafana-data:/var/lib/grafana
      - ./grafana-dashboards:/etc/grafana/provisioning/dashboards
      - ./grafana-datasources.yml:/etc/grafana/provisioning/datasources/datasources.yml
    ports:
      - "3000:3000"
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=your-secure-password
      - GF_SERVER_ROOT_URL=https://grafana.example.com

  alertmanager:
    image: prom/alertmanager:latest
    volumes:
      - ./alertmanager.yml:/etc/alertmanager/alertmanager.yml
      - alertmanager-data:/alertmanager
    ports:
      - "9093:9093"

volumes:
  prometheus-data:
  grafana-data:
  alertmanager-data:
```

**Start Monitoring Stack**:

```bash
cd /opt/patronus/monitoring
docker-compose up -d

# Access Grafana: https://grafana.example.com
# Default login: admin / your-secure-password
```

---

### Phase 5: Configure Sites

#### 5.1. Initialize Admin User

```bash
# Create initial admin user
curl -X POST https://patronus.example.com/v1/auth/initialize \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "password": "your-secure-password",
    "email": "admin@example.com"
  }'
```

#### 5.2. Login and Get Token

```bash
# Login
curl -X POST https://patronus.example.com/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "password": "your-secure-password"
  }' | jq -r '.access_token' > /tmp/token

# Set token for convenience
export TOKEN=$(cat /tmp/token)
```

#### 5.3. Create Sites

```bash
# Create site 1 (Branch Office NYC)
curl -X POST https://patronus.example.com/v1/sites \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "branch-nyc",
    "location": "New York, NY",
    "public_key": "'$(wg genkey | wg pubkey)'",
    "endpoints": ["203.0.113.100:51820"]
  }'

# Create site 2 (Branch Office SF)
curl -X POST https://patronus.example.com/v1/sites \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "branch-sf",
    "location": "San Francisco, CA",
    "public_key": "'$(wg genkey | wg pubkey)'",
    "endpoints": ["203.0.113.200:51820"]
  }'

# Create site 3 (Branch Office SEA)
curl -X POST https://patronus.example.com/v1/sites \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "branch-sea",
    "location": "Seattle, WA",
    "public_key": "'$(wg genkey | wg pubkey)'",
    "endpoints": ["203.0.113.300:51820"]
  }'
```

#### 5.4. Verify Sites

```bash
# List all sites
curl -H "Authorization: Bearer $TOKEN" \
  https://patronus.example.com/v1/sites | jq

# Check mesh status
curl -H "Authorization: Bearer $TOKEN" \
  https://patronus.example.com/v1/mesh/status | jq
```

---

### Phase 6: Configure Routing Policies

```bash
# Create policy for video traffic
curl -X POST https://patronus.example.com/v1/policies \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "video-conferencing-priority",
    "priority": 100,
    "match_criteria": {
      "protocol": "udp",
      "dst_port_range": "3478-3497",
      "dscp": 46
    },
    "action": {
      "type": "route",
      "qos_class": "realtime",
      "bandwidth": "10Mbps"
    }
  }'

# Create failover policy
curl -X POST https://patronus.example.com/v1/failover/policies \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "primary-backup-failover",
    "primary_path_id": "path-fiber",
    "backup_path_id": "path-lte",
    "threshold": 70,
    "cooldown_secs": 30
  }'
```

---

### Phase 7: Validate Deployment

#### 7.1. Health Checks

```bash
# System health
curl https://patronus.example.com/v1/health

# Readiness check
curl https://patronus.example.com/v1/health/ready

# Liveness check
curl https://patronus.example.com/v1/health/live
```

#### 7.2. Performance Tests

```bash
# Check path latencies
curl -H "Authorization: Bearer $TOKEN" \
  https://patronus.example.com/v1/paths | jq '.[] | {id: .id, latency: .health.latency_ms}'

# Monitor metrics
curl https://patronus.example.com/v1/metrics/export?format=prometheus
```

#### 7.3. Failover Test

```bash
# Trigger manual failover (testing)
curl -X POST https://patronus.example.com/v1/failover/trigger \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "policy_id": "primary-backup-failover",
    "reason": "manual-test"
  }'

# Verify failover event
curl -H "Authorization: Bearer $TOKEN" \
  https://patronus.example.com/v1/failover/events?limit=10 | jq
```

---

## Post-Deployment

### 1. Monitoring Setup

**Add to Monitoring**:
- [ ] Prometheus scraping configured
- [ ] Grafana dashboards imported
- [ ] Alert rules configured
- [ ] AlertManager notifications set up (email, Slack, PagerDuty)
- [ ] Log aggregation configured (ELK, Splunk, etc.)

### 2. Backup Verification

```bash
# Test backup
/usr/local/bin/patronus-backup.sh

# Verify backup file
ls -lh /backup/patronus/

# Test restore (on test environment)
# See docs/DISASTER_RECOVERY.md
```

### 3. Security Hardening

```bash
# Disable password authentication for SSH
sudo sed -i 's/PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
sudo systemctl restart sshd

# Enable automatic security updates
sudo apt-get install -y unattended-upgrades
sudo dpkg-reconfigure -plow unattended-upgrades

# Configure fail2ban
sudo apt-get install -y fail2ban
sudo systemctl enable fail2ban
sudo systemctl start fail2ban
```

### 4. Documentation

- [ ] Document server IPs and credentials (secure location)
- [ ] Create runbook for common tasks
- [ ] Document escalation procedures
- [ ] Create architecture diagram
- [ ] Update DNS documentation

### 5. Training

- [ ] Train operations team on dashboard
- [ ] Review troubleshooting procedures
- [ ] Practice disaster recovery
- [ ] Schedule regular operational reviews

---

## Troubleshooting

### Issue: Service won't start

**Check**:
```bash
# View logs
sudo journalctl -u patronus-sdwan -n 100

# Verify configuration
patronus-sdwan --config /etc/patronus/config.yaml --validate

# Check file permissions
ls -l /etc/patronus/
```

### Issue: Sites can't connect

**Check**:
```bash
# Verify WireGuard is running
sudo wg show

# Check firewall
sudo ufw status

# Test connectivity
ping <site-ip>
nc -zvu <site-ip> 51820
```

### Issue: High latency

**Check**:
```bash
# Check system load
uptime
top

# Check network interfaces
ip link
ethtool eth0

# Review performance tuning
# See docs/PERFORMANCE_TUNING.md
```

---

## Rollback Procedures

### Rollback Service

```bash
# Stop current version
sudo systemctl stop patronus-sdwan

# Restore previous version
sudo cp /usr/local/bin/patronus-sdwan.backup /usr/local/bin/patronus-sdwan

# Restore configuration
sudo cp /etc/patronus/config.yaml.backup /etc/patronus/config.yaml

# Start service
sudo systemctl start patronus-sdwan
```

### Rollback Database

```bash
# Stop service
sudo systemctl stop patronus-sdwan

# Restore database
sudo cp /backup/patronus/sdwan-<timestamp>.db /var/lib/patronus/sdwan.db

# Start service
sudo systemctl start patronus-sdwan
```

---

## Scaling

### Horizontal Scaling (Add Nodes)

```bash
# Provision new node
# Follow steps 1-3 (Infrastructure, Database, Deploy)

# Update HA configuration on all nodes
# Add new peer to /etc/patronus/config.yaml

# Restart all nodes (rolling restart)
for node in ctrl-1 ctrl-2 ctrl-3 ctrl-4; do
  ssh $node "sudo systemctl restart patronus-sdwan"
  sleep 30  # Allow time for cluster to stabilize
done
```

### Vertical Scaling (Increase Resources)

```bash
# AWS example (increase instance size)
# 1. Stop instance
# 2. Change instance type to larger size
# 3. Start instance

# Update configuration if needed
sudo vim /etc/patronus/config.yaml
# Adjust worker_threads, max_connections, etc.

sudo systemctl restart patronus-sdwan
```

---

## Production Checklist

### Pre-Deployment
- [ ] Infrastructure provisioned
- [ ] Network configured
- [ ] DNS records created
- [ ] TLS certificates obtained
- [ ] Secrets generated
- [ ] Configuration reviewed
- [ ] Backup system tested
- [ ] Monitoring configured

### Deployment
- [ ] Services deployed to all nodes
- [ ] HA cluster formed
- [ ] Database initialized or migrated
- [ ] Sites created and configured
- [ ] Policies configured
- [ ] Monitoring active

### Post-Deployment
- [ ] Health checks passing
- [ ] Traffic flowing correctly
- [ ] Performance metrics acceptable
- [ ] Alerts configured and tested
- [ ] Backup verified
- [ ] Documentation complete
- [ ] Team trained
- [ ] Support procedures in place

### 30-Day Review
- [ ] Performance review
- [ ] Incident review
- [ ] Capacity planning
- [ ] Cost optimization
- [ ] User feedback incorporated

---

## Support

**Escalation Path**:
1. Check logs and monitoring
2. Review troubleshooting guide
3. Contact operations team
4. Escalate to engineering team

**Resources**:
- Operations Runbook: `docs/OPERATIONS_RUNBOOK.md`
- Disaster Recovery: `docs/DISASTER_RECOVERY.md`
- Performance Tuning: `docs/PERFORMANCE_TUNING.md`
- API Documentation: `docs/api/API_GUIDE.md`

---

**Document Version**: 1.0.0
**Last Updated**: 2025-10-12
**Maintainer**: Operations Team
