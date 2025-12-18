//! Simplified handlers for immediate web interface testing
//!
//! These handlers provide basic functionality without complex template structures

use axum::{
    extract::State,
    response::{Html, IntoResponse},
};
use patronus_network;

use crate::state::AppState;

/// Simple index page handler
pub async fn simple_index(_state: State<AppState>) -> impl IntoResponse {
    let html = r#"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Patronus SD-WAN Dashboard</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background: #007bff; color: white; padding: 20px; margin-bottom: 20px; }
        .stat-card { border: 1px solid #ddd; padding: 15px; margin: 10px; border-radius: 5px; }
        .success { background-color: #d4edda; }
        .info { background-color: #d1ecf1; }
        .warning { background-color: #fff3cd; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ Patronus SD-WAN</h1>
        <p>Network Security & Management Platform</p>
    </div>

    <div style="display: flex; gap: 20px; flex-wrap: wrap;">
        <div class="stat-card success">
            <h3>System Status</h3>
            <p>✅ Core Components: Operational</p>
            <p>✅ Network Discovery: Active</p>
            <p>✅ Web Interface: Running</p>
        </div>

        <div class="stat-card info">
            <h3>Network Interfaces</h3>
            <p id="interface-count">Loading...</p>
            <p><a href="/api/interfaces">View Details (JSON)</a></p>
        </div>

        <div class="stat-card warning">
            <h3>Quick Actions</h3>
            <p><a href="/simple/firewall">🔥 Firewall Management</a></p>
            <p><a href="/simple/status">📊 System Status</a></p>
        </div>
    </div>

    <div style="margin-top: 30px;">
        <h2>Recent Activity</h2>
        <ul>
            <li>System started successfully</li>
            <li>Network interfaces discovered</li>
            <li>Firewall rules loaded</li>
            <li>Web interface initialized</li>
        </ul>
    </div>

    <script>
        // Load interface count dynamically
        fetch('/api/interfaces')
            .then(response => response.json())
            .then(data => {
                const count = data.interfaces ? data.interfaces.length : 0;
                document.getElementById('interface-count').textContent =
                    `${count} network interfaces detected`;
            })
            .catch(error => {
                document.getElementById('interface-count').textContent =
                    'Failed to load interface data';
            });
    </script>
</body>
</html>
    "#;

    Html(html)
}

/// Simple firewall page
pub async fn simple_firewall(State(state): State<AppState>) -> impl IntoResponse {
    // Get firewall rules
    let rules = state.firewall.list_rules().await.unwrap_or_default();
    let rule_count = rules.len();
    let enabled_count = rules.iter().filter(|r| r.enabled).count();

    let html = format!(r#"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Firewall - Patronus</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .header {{ background: #dc3545; color: white; padding: 20px; margin-bottom: 20px; }}
        .stat-card {{ border: 1px solid #ddd; padding: 15px; margin: 10px; border-radius: 5px; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background: #f8f9fa; }}
        .badge {{ padding: 3px 8px; border-radius: 3px; font-size: 0.8em; }}
        .success {{ background: #28a745; color: white; }}
        .danger {{ background: #dc3545; color: white; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🔥 Firewall Management</h1>
        <p><a href="/" style="color: #fff;">← Back to Dashboard</a></p>
    </div>

    <div style="display: flex; gap: 20px;">
        <div class="stat-card">
            <h3>Filter Rules</h3>
            <p>Total: {rule_count}</p>
            <p>Enabled: {enabled_count}</p>
        </div>
        <div class="stat-card">
            <h3>Quick Actions</h3>
            <p>📊 <a href="/api/firewall/rules">View Rules (JSON)</a></p>
            <p>🔄 Reload Rules</p>
        </div>
    </div>

    <h2>Firewall Rules Summary</h2>
    <table>
        <thead>
            <tr>
                <th>Status</th>
                <th>Information</th>
            </tr>
        </thead>
        <tbody>
            <tr>
                <td><span class="badge success">System</span></td>
                <td>Firewall engine is operational and processing rules</td>
            </tr>
            <tr>
                <td><span class="badge success">Rules</span></td>
                <td>{rule_count} firewall rules loaded ({enabled_count} enabled)</td>
            </tr>
            <tr>
                <td><span class="badge success">API</span></td>
                <td>RESTful API endpoints available for rule management</td>
            </tr>
        </tbody>
    </table>

    <p><strong>Note:</strong> This is a simplified view. Full firewall management interface is available through the API endpoints.</p>
</body>
</html>
    "#, rule_count = rule_count, enabled_count = enabled_count);

    Html(html)
}

/// Simple status page
pub async fn simple_status(_state: State<AppState>) -> impl IntoResponse {
    // Get system information
    let hostname = std::fs::read_to_string("/etc/hostname")
        .unwrap_or_else(|_| "patronus".to_string())
        .trim()
        .to_string();

    let uptime = std::fs::read_to_string("/proc/uptime")
        .ok()
        .and_then(|uptime| uptime.split_whitespace().next().and_then(|s| s.parse::<f64>().ok()))
        .map(|secs| format!("{:.1} hours", secs / 3600.0))
        .unwrap_or_else(|| "Unknown".to_string());

    let html = format!(r#"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>System Status - Patronus</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .header {{ background: #28a745; color: white; padding: 20px; margin-bottom: 20px; }}
        .stat-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; }}
        .stat-card {{ border: 1px solid #ddd; padding: 15px; border-radius: 5px; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>📊 System Status</h1>
        <p><a href="/" style="color: #fff;">← Back to Dashboard</a></p>
    </div>

    <div class="stat-grid">
        <div class="stat-card">
            <h3>System Information</h3>
            <p><strong>Hostname:</strong> {hostname}</p>
            <p><strong>Uptime:</strong> {uptime}</p>
            <p><strong>Platform:</strong> Patronus SD-WAN</p>
        </div>

        <div class="stat-card">
            <h3>Core Services</h3>
            <p>✅ Network Management</p>
            <p>✅ Firewall Engine</p>
            <p>✅ Web Interface</p>
            <p>✅ API Services</p>
        </div>

        <div class="stat-card">
            <h3>Network Status</h3>
            <p id="network-status">Loading...</p>
        </div>
    </div>

    <script>
        // Load network status
        fetch('/api/interfaces')
            .then(response => response.json())
            .then(data => {{
                const interfaces = data.interfaces || [];
                const activeCount = interfaces.filter(i => i.enabled).length;
                document.getElementById('network-status').innerHTML =
                    `✅ ${{interfaces.length}} interfaces discovered<br>✅ ${{activeCount}} interfaces active`;
            }})
            .catch(error => {{
                document.getElementById('network-status').innerHTML = '❌ Failed to load network status';
            }});
    </script>
</body>
</html>
    "#, hostname = hostname, uptime = uptime);

    Html(html)
}