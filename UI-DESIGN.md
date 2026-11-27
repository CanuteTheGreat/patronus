# Patronus Firewall UI Design Specification

**Version:** 0.1.0

---

## Design Philosophy

### Core Principles

1. **Progressive Disclosure**
   - Simple, uncluttered default view
   - Advanced options hidden but one click away
   - Contextual help and tooltips

2. **Responsive & Modern**
   - Mobile-friendly responsive design
   - Dark/light mode support
   - Smooth animations and transitions

3. **Data-Driven**
   - Real-time updates via WebSocket
   - Interactive charts and graphs
   - Live system metrics

4. **Accessible**
   - WCAG 2.1 AA compliance
   - Keyboard navigation
   - Screen reader support

---

## UI Architecture

### Technology Stack

- **Backend:** Rust + Axum + Askama templates
- **Frontend:** HTML5 + Modern CSS + Vanilla JavaScript
- **Real-time:** WebSocket for live updates
- **Charts:** Chart.js for graphs
- **Icons:** Lucide icons (SVG)

### Layout Structure

```
┌─────────────────────────────────────────────────────────┐
│  Header: Logo + Search + User Menu + Theme Toggle      │
├─────────────────────────────────────────────────────────┤
│  ┌──────────┐  ┌────────────────────────────────────┐  │
│  │          │  │                                    │  │
│  │  Sidebar │  │         Main Content Area          │  │
│  │   Nav    │  │                                    │  │
│  │          │  │  - Breadcrumbs                     │  │
│  │          │  │  - Page Title + Actions            │  │
│  │          │  │  - Content Cards                   │  │
│  │          │  │  - Advanced Panel (collapsible)    │  │
│  │          │  │                                    │  │
│  └──────────┘  └────────────────────────────────────┘  │
├─────────────────────────────────────────────────────────┤
│  Footer: Status + Version + Uptime                     │
└─────────────────────────────────────────────────────────┘
```

---

## Page Designs

### 1. Dashboard (/)

**Purpose:** At-a-glance system overview

**Layout:**

```
┌─────────────────────────────────────────────────────────┐
│  Dashboard                                    [Refresh] │
├─────────────────────────────────────────────────────────┤
│  ┌────────────┐ ┌────────────┐ ┌────────────┐         │
│  │  System    │ │  Network   │ │  Security  │         │
│  │  Status    │ │  Traffic   │ │  Status    │         │
│  │            │ │            │ │            │         │
│  │  • CPU     │ │  • In: 2GB │ │  • Threats │         │
│  │  • RAM     │ │  • Out:1GB │ │    Blocked │         │
│  │  • Disk    │ │            │ │  • Rules   │         │
│  └────────────┘ └────────────┘ └────────────┘         │
│                                                         │
│  Traffic Graph (24h)                                   │
│  ┌───────────────────────────────────────────────────┐ │
│  │                    [Line Chart]                   │ │
│  │                                                   │ │
│  └───────────────────────────────────────────────────┘ │
│                                                         │
│  Recent Events                    [View All]           │
│  ┌───────────────────────────────────────────────────┐ │
│  │  🔴 Port scan blocked from 1.2.3.4                │ │
│  │  🟢 VPN connection established (user: alice)      │ │
│  │  🟡 DHCP lease renewed for device-123             │ │
│  └───────────────────────────────────────────────────┘ │
│                                                         │
│  Active Connections                                    │
│  ┌─────────────────────────────────────────────────┐   │
│  │  Proto  Src IP        Dst IP       State       │   │
│  │  TCP    192.168.1.10  1.2.3.4:443  ESTABLISHED │   │
│  │  ...                                           │   │
│  └─────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────┘
```

**Features:**
- Real-time metrics (CPU, RAM, bandwidth)
- Traffic graph with 1h/6h/24h/7d views
- Event stream (last 10 events)
- Active connections table
- Quick actions: Refresh, Export metrics

**Advanced Options (Click "Advanced" button):**
- Detailed system diagnostics
- Performance metrics history
- Custom metric dashboard builder

---

### 2. Firewall (/firewall)

**Purpose:** Manage firewall rules and policies

**Default View:**

```
┌─────────────────────────────────────────────────────────┐
│  Firewall Rules                    [+ Add Rule] [Apply] │
├─────────────────────────────────────────────────────────┤
│  Quick Filters:  [All] [Enabled] [Disabled] [WAN] [LAN]│
│                                                         │
│  Rules (5 active)                                       │
│  ┌───────────────────────────────────────────────────┐ │
│  │ # │ Name      │ Interface │ Action │ Enabled │ ⚙️  │ │
│  │ 1 │ Allow SSH │ lan       │ Allow  │ ✓       │ ••• │ │
│  │ 2 │ Block WAN │ wan       │ Drop   │ ✓       │ ••• │ │
│  │   └─── [▼ Advanced]                               │ │
│  │        Protocol: TCP | Port: 22                   │ │
│  │        Source: any | Dest: 192.168.1.1           │ │
│  │        [Edit] [Duplicate] [Delete] [▲ Collapse]  │ │
│  └───────────────────────────────────────────────────┘ │
│                                                         │
│  Statistics                                            │
│  • 1,234 packets allowed today                         │
│  • 567 packets blocked today                           │
│  • 15 rules total (5 enabled, 10 disabled)            │
└─────────────────────────────────────────────────────────┘
```

**Add/Edit Rule Panel:**

```
┌─────────────────────────────────────────────────────────┐
│  Add Firewall Rule                        [Save] [Close]│
├─────────────────────────────────────────────────────────┤
│  Basic Settings                                         │
│  ┌───────────────────────────────────────────────────┐ │
│  │  Name: [Allow HTTPS Traffic            ]          │ │
│  │  Interface: [wan ▼]                               │ │
│  │  Action: [allow ▼]                                │ │
│  │  Enabled: [✓]                                     │ │
│  └───────────────────────────────────────────────────┘ │
│                                                         │
│  [▼ Show Advanced Options]                             │
│  ┌───────────────────────────────────────────────────┐ │
│  │  Protocol: [tcp ▼]                                │ │
│  │  Source:                                          │ │
│  │    IP/Network: [any            ]  Port: [any   ]  │ │
│  │  Destination:                                     │ │
│  │    IP/Network: [any            ]  Port: [443   ]  │ │
│  │                                                   │ │
│  │  State Matching: [✓] Established [✓] Related     │ │
│  │  Log: [✓] Enable logging                         │ │
│  │  Priority: [100      ]                           │ │
│  │  Schedule: [Always active ▼]                      │ │
│  │  Description: [                              ]    │ │
│  └───────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────┘
```

**Advanced Features (Tabs):**
- NAT Rules
- Port Forwarding
- Connection Tracking
- Rate Limiting
- GeoIP Blocking

---

### 3. Network (/network)

**Purpose:** Network configuration and services

**Default View:**

```
┌─────────────────────────────────────────────────────────┐
│  Network Configuration                                  │
├─────────────────────────────────────────────────────────┤
│  Interfaces                                  [+ Add]    │
│  ┌───────────────────────────────────────────────────┐ │
│  │  eth0 (WAN)            203.0.113.5/24    🟢 Up    │ │
│  │  ├─ Gateway: 203.0.113.1                         │ │
│  │  ├─ DNS: 1.1.1.1, 8.8.8.8                        │ │
│  │  └─ Traffic: ↓ 1.2 GB  ↑ 456 MB                  │ │
│  │                                                   │ │
│  │  eth1 (LAN)            192.168.1.1/24    🟢 Up    │ │
│  │  ├─ DHCP: Enabled (100-200)                      │ │
│  │  ├─ DNS: Local resolver                          │ │
│  │  └─ Traffic: ↓ 890 MB  ↑ 2.1 GB                  │ │
│  │                                                   │ │
│  │  wg0 (VPN)             10.99.0.1/24      🟢 Up    │ │
│  │  └─ Peers: 3 connected                           │ │
│  └───────────────────────────────────────────────────┘ │
│                                                         │
│  Services                                              │
│  ┌───────────────────────────────────────────────────┐ │
│  │  DHCP Server       [🟢 Running]         [Config]  │ │
│  │  DNS Resolver      [🟢 Running]         [Config]  │ │
│  │  Captive Portal    [🔴 Stopped]         [Start ]  │ │
│  └───────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────┘
```

**Advanced Options:**
- VLAN Configuration
- Bridge Configuration
- Bonding/LAGG
- Quality of Service (QoS)
- Traffic Shaping

---

### 4. VPN (/vpn)

**Purpose:** VPN management (WireGuard, OpenVPN, IPsec)

**Default View:**

```
┌─────────────────────────────────────────────────────────┐
│  VPN                                                    │
├─────────────────────────────────────────────────────────┤
│  [WireGuard] [OpenVPN] [IPsec]                         │
│                                                         │
│  WireGuard (wg0)                [🟢 Running] [+ Peer]  │
│  ┌───────────────────────────────────────────────────┐ │
│  │  Interface: 10.99.0.1/24                          │ │
│  │  Listen Port: 51820                               │ │
│  │  Public Key: xK8h...7pQw                          │ │
│  │                                                   │ │
│  │  Peers (3)                                        │ │
│  │  ┌─────────────────────────────────────────────┐ │ │
│  │  │ alice@laptop     10.99.0.2  🟢 2 min ago    │ │ │
│  │  │  └─ RX: 1.2 MB  TX: 450 KB                  │ │ │
│  │  │                                             │ │ │
│  │  │ bob@phone        10.99.0.3  🟡 15 min ago   │ │ │
│  │  │  └─ RX: 890 KB  TX: 2.1 MB                  │ │ │
│  │  │                                             │ │ │
│  │  │ server-1         10.99.0.10 🟢 active       │ │ │
│  │  │  └─ RX: 45 MB   TX: 89 MB                   │ │ │
│  │  └─────────────────────────────────────────────┘ │ │
│  └───────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────┘
```

**Add Peer Panel:**
```
┌─────────────────────────────────────────────────────────┐
│  Add WireGuard Peer                     [Save] [Cancel] │
├─────────────────────────────────────────────────────────┤
│  Name: [alice@laptop              ]                     │
│  Public Key: [                                      ]   │
│  Allowed IPs: [10.99.0.2/32           ]                 │
│  Endpoint (optional): [                :51820       ]   │
│  Persistent Keepalive: [25] seconds                     │
│                                                         │
│  [Generate QR Code] [Generate Config File]             │
└─────────────────────────────────────────────────────────┘
```

---

### 5. AI / Monitoring (/ai)

**Purpose:** AI threat detection and monitoring

**Default View:**

```
┌─────────────────────────────────────────────────────────┐
│  AI Threat Detection                [🟢 Active] [Train] │
├─────────────────────────────────────────────────────────┤
│  Statistics (Last 24h)                                  │
│  ┌────────────┐ ┌────────────┐ ┌────────────┐         │
│  │  Analyzed  │ │  Threats   │ │  Auto-     │         │
│  │  Flows     │ │  Detected  │ │  Blocked   │         │
│  │            │ │            │ │            │         │
│  │  1.2M      │ │  47        │ │  12        │         │
│  └────────────┘ └────────────┘ └────────────┘         │
│                                                         │
│  Threat Feed                                           │
│  ┌───────────────────────────────────────────────────┐ │
│  │  🔴 Port Scan     1.2.3.4      95% conf   [Block] │ │
│  │  🟡 Data Exfil    5.6.7.8      78% conf   [View ] │ │
│  │  🟢 Normal        9.10.11.12   15% conf   [    ] │ │
│  └───────────────────────────────────────────────────┘ │
│                                                         │
│  Pending Auto-Generated Rules (2)           [View All] │
│  ┌───────────────────────────────────────────────────┐ │
│  │  Block 1.2.3.4 (Port Scan)      [Approve] [Reject]│ │
│  │  Rate limit 5.6.7.8 (DDoS)      [Approve] [Reject]│ │
│  └───────────────────────────────────────────────────┘ │
│                                                         │
│  Model Status                                          │
│  • Last trained: 2 hours ago                           │
│  • Accuracy: 94.2%                                     │
│  • Training samples: 1.2M flows                        │
└─────────────────────────────────────────────────────────┘
```

**Advanced Options:**
- Model tuning (threshold, confidence)
- Threat intel sources configuration
- Custom ML model upload
- Export training data

---

### 6. System (/system)

**Purpose:** System configuration and maintenance

**Default View:**

```
┌─────────────────────────────────────────────────────────┐
│  System                                                 │
├─────────────────────────────────────────────────────────┤
│  General Settings                                       │
│  ┌───────────────────────────────────────────────────┐ │
│  │  Hostname: [patronus             ]                │ │
│  │  Domain: [localdomain            ]                │ │
│  │  Timezone: [UTC ▼]                                │ │
│  │  DNS Servers: [1.1.1.1, 8.8.8.8  ]                │ │
│  └───────────────────────────────────────────────────┘ │
│                                                         │
│  Backup & Restore                                      │
│  ┌───────────────────────────────────────────────────┐ │
│  │  [Create Backup] [Restore from File]              │ │
│  │                                                   │ │
│  │  Recent Backups:                                  │ │
│  │  • backup-2025-10-08.tar.gz (12 MB) [Download]    │ │
│  │  • backup-2025-10-07.tar.gz (11 MB) [Download]    │ │
│  └───────────────────────────────────────────────────┘ │
│                                                         │
│  Updates                                               │
│  ┌───────────────────────────────────────────────────┐ │
│  │  Current Version: 0.1.0                           │ │
│  │  [Check for Updates]                              │ │
│  └───────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────┘
```

**Advanced Tabs:**
- Users & Authentication
- Secrets Management
- GitOps Configuration
- Logging Configuration
- Performance Tuning
- Developer Tools (API keys, webhooks)

---

## UI Components

### Standard Components

#### 1. Card with Advanced Panel

```html
<div class="card">
  <div class="card-header">
    <h3>Title</h3>
    <button class="btn-link" onclick="toggleAdvanced(this)">
      Advanced ▼
    </button>
  </div>

  <div class="card-body">
    <!-- Basic content -->
  </div>

  <div class="card-advanced" style="display: none;">
    <!-- Advanced options -->
  </div>
</div>
```

#### 2. Action Menu (3-dot menu)

```html
<div class="dropdown">
  <button class="btn-icon">•••</button>
  <div class="dropdown-menu">
    <a href="#">Edit</a>
    <a href="#">Duplicate</a>
    <a href="#">Delete</a>
  </div>
</div>
```

#### 3. Stat Card

```html
<div class="stat-card success">
  <h3>Metric Name</h3>
  <div class="value">1,234</div>
  <div class="label">↑ 12% from yesterday</div>
</div>
```

#### 4. Live Badge

```html
<span class="badge badge-live">
  <span class="pulse"></span> Live
</span>
```

---

## Responsive Breakpoints

```css
/* Mobile */
@media (max-width: 640px) {
  - Stack all cards vertically
  - Collapse sidebar to hamburger menu
  - Simplify tables (show key columns only)
}

/* Tablet */
@media (min-width: 641px) and (max-width: 1024px) {
  - 2-column grid for cards
  - Side drawer sidebar
}

/* Desktop */
@media (min-width: 1025px) {
  - Full sidebar
  - Multi-column layouts
  - Advanced features visible
}
```

---

## Dark Mode

### Color Palette

**Light Mode:**
- Background: #f5f5f5
- Cards: #ffffff
- Primary: #667eea
- Text: #333333

**Dark Mode:**
- Background: #1a1a1a
- Cards: #2a2a2a
- Primary: #8b5cf6
- Text: #e5e5e5

Toggle implementation:
```javascript
function toggleTheme() {
  document.body.classList.toggle('dark-mode');
  localStorage.setItem('theme',
    document.body.classList.contains('dark-mode') ? 'dark' : 'light'
  );
}
```

---

## Real-time Updates

### WebSocket Integration

```javascript
const ws = new WebSocket('wss://localhost/api/ws');

ws.onmessage = (event) => {
  const data = JSON.parse(event.data);

  switch(data.type) {
    case 'metric_update':
      updateMetric(data.metric, data.value);
      break;
    case 'threat_detected':
      showThreatAlert(data.threat);
      break;
    case 'rule_changed':
      refreshRuleTable();
      break;
  }
};
```

---

## Accessibility Features

1. **Keyboard Navigation**
   - Tab order follows visual flow
   - All actions accessible via keyboard
   - Focus indicators visible

2. **Screen Reader Support**
   - ARIA labels on all interactive elements
   - Live regions for dynamic updates
   - Semantic HTML structure

3. **Color Contrast**
   - Minimum 4.5:1 for normal text
   - Minimum 3:1 for large text
   - Icons have text alternatives

---

## Performance Optimization

1. **Lazy Loading**
   - Load advanced panels only when expanded
   - Paginate large tables
   - Defer non-critical JavaScript

2. **Caching**
   - Service Worker for offline support
   - Local Storage for user preferences
   - IndexedDB for metrics cache

3. **Compression**
   - Gzip/Brotli for assets
   - Minified CSS/JS in production
   - Optimized images (WebP)

---

## Implementation Priority

### Phase 1 (MVP) ✅
- [ ] Enhanced base template with sidebar
- [ ] Dashboard with live metrics
- [ ] Firewall rules interface
- [ ] Dark mode toggle

### Phase 2
- [ ] Network services interface
- [ ] VPN management
- [ ] Advanced panels for all sections

### Phase 3
- [ ] AI/Monitoring interface
- [ ] Real-time WebSocket updates
- [ ] Mobile responsive design

### Phase 4
- [ ] GitOps configuration UI
- [ ] Kubernetes integration UI
- [ ] Advanced visualizations

---

**Version:** 0.1.0
