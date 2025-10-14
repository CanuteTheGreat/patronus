# Patronus SD-WAN Quick Start Guide

Get your SD-WAN up and running in 5 minutes!

## 5-Minute Setup

### Step 1: Initialize
```bash
sudo patronus init --name my-company
```

### Step 2: Add Sites
```bash
patronus site create hq --location "New York" --address 203.0.113.10
patronus site create branch1 --location "Chicago" --address 203.0.113.20
```

### Step 3: Create Tunnel
```bash
patronus tunnel create hq-branch1 --source hq --destination branch1
```

### Step 4: Start Daemon
```bash
sudo patronus daemon
```

### Step 5: Verify
```bash
patronus status
patronus site list
patronus metrics health
```

## What You Built

✅ 2 sites connected via secure WireGuard tunnel
✅ Automatic routing between sites
✅ Built-in monitoring with Prometheus
✅ Web dashboard at http://localhost:8080
✅ Production-ready SD-WAN infrastructure

**Welcome to Patronus SD-WAN! 🚀**
