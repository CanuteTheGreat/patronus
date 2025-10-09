//! WebSocket client for real-time updates
//!
//! Connects to WebSocket endpoints and handles incoming messages

class PatronusWebSocket {
    constructor(endpoint, onMessage, onError = null) {
        this.endpoint = endpoint;
        this.onMessage = onMessage;
        this.onError = onError;
        this.ws = null;
        this.reconnectAttempts = 0;
        this.maxReconnectAttempts = 5;
        this.reconnectDelay = 1000; // Start with 1 second
        this.connect();
    }

    connect() {
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const wsUrl = `${protocol}//${window.location.host}${this.endpoint}`;

        console.log(`Connecting to WebSocket: ${wsUrl}`);

        try {
            this.ws = new WebSocket(wsUrl);

            this.ws.onopen = () => {
                console.log(`WebSocket connected: ${this.endpoint}`);
                this.reconnectAttempts = 0;
                this.reconnectDelay = 1000;
            };

            this.ws.onmessage = (event) => {
                try {
                    const data = JSON.parse(event.data);
                    this.onMessage(data);
                } catch (err) {
                    console.error('Failed to parse WebSocket message:', err);
                }
            };

            this.ws.onerror = (error) => {
                console.error('WebSocket error:', error);
                if (this.onError) {
                    this.onError(error);
                }
            };

            this.ws.onclose = () => {
                console.log(`WebSocket closed: ${this.endpoint}`);
                this.reconnect();
            };
        } catch (err) {
            console.error('Failed to create WebSocket:', err);
            this.reconnect();
        }
    }

    reconnect() {
        if (this.reconnectAttempts >= this.maxReconnectAttempts) {
            console.error('Max reconnection attempts reached');
            return;
        }

        this.reconnectAttempts++;
        const delay = this.reconnectDelay * Math.pow(2, this.reconnectAttempts - 1);

        console.log(`Reconnecting in ${delay}ms (attempt ${this.reconnectAttempts}/${this.maxReconnectAttempts})`);

        setTimeout(() => {
            this.connect();
        }, delay);
    }

    send(data) {
        if (this.ws && this.ws.readyState === WebSocket.OPEN) {
            this.ws.send(JSON.stringify(data));
        } else {
            console.warn('WebSocket not connected, cannot send message');
        }
    }

    close() {
        if (this.ws) {
            this.ws.close();
        }
    }
}

// Global WebSocket connections
let metricsWs = null;
let logsWs = null;

/**
 * Initialize metrics WebSocket and update charts
 */
function initMetricsWebSocket() {
    metricsWs = new PatronusWebSocket('/ws/metrics', (data) => {
        if (data.type === 'system_metrics') {
            // Update Chart.js charts if they exist
            if (typeof updateChart === 'function' && cpuChart) {
                updateChart(cpuChart, 0, data.cpu);
                updateChart(cpuChart, 1, data.memory);
                updateChart(cpuChart, 2, data.disk);
            }

            if (typeof updateChart === 'function' && networkChart) {
                const rxMbps = data.network_rx / 1024 / 1024; // Convert to Mbps
                const txMbps = data.network_tx / 1024 / 1024;
                updateChart(networkChart, 0, rxMbps);
                updateChart(networkChart, 1, txMbps);
            }

            // Update dashboard stats if they exist
            updateDashboardStats(data);
        }
    });
}

/**
 * Initialize logs WebSocket and stream to console
 */
function initLogsWebSocket() {
    logsWs = new PatronusWebSocket('/ws/logs', (data) => {
        if (data.type === 'log_entry') {
            appendLogEntry(data);
        }
    });
}

/**
 * Update dashboard statistics with real-time data
 */
function updateDashboardStats(metrics) {
    // Update CPU
    const cpuElement = document.getElementById('cpu-usage');
    if (cpuElement) {
        cpuElement.textContent = metrics.cpu.toFixed(1) + '%';
    }

    // Update Memory
    const memoryElement = document.getElementById('memory-usage');
    if (memoryElement) {
        memoryElement.textContent = metrics.memory.toFixed(1) + '%';
    }

    // Update Disk
    const diskElement = document.getElementById('disk-usage');
    if (diskElement) {
        diskElement.textContent = metrics.disk.toFixed(1) + '%';
    }

    // Update Network
    const networkRxElement = document.getElementById('network-rx');
    if (networkRxElement) {
        const rxMbps = (metrics.network_rx / 1024 / 1024).toFixed(2);
        networkRxElement.textContent = rxMbps + ' Mbps';
    }

    const networkTxElement = document.getElementById('network-tx');
    if (networkTxElement) {
        const txMbps = (metrics.network_tx / 1024 / 1024).toFixed(2);
        networkTxElement.textContent = txMbps + ' Mbps';
    }
}

/**
 * Append a log entry to the live logs display
 */
function appendLogEntry(log) {
    const logsDiv = document.getElementById('live-logs');
    if (!logsDiv) return;

    const color = log.level === 'ERROR' ? '#ff0000' :
                  log.level === 'WARN' ? '#ffaa00' : '#00ff00';

    const logEntry = document.createElement('div');
    logEntry.style.marginBottom = '0.25rem';
    logEntry.innerHTML = `
        <span style="color: #888;">[${log.timestamp}]</span>
        <span style="color: ${color};">[${log.level}]</span>
        <span style="color: #00aaff;">[${log.component}]</span>
        ${log.message}
    `;

    logsDiv.appendChild(logEntry);
    logsDiv.scrollTop = logsDiv.scrollHeight;

    // Keep only last 100 entries
    const entries = logsDiv.querySelectorAll('div');
    if (entries.length > 100) {
        entries[0].remove();
    }
}

/**
 * Initialize WebSockets when on monitoring page
 */
function initializeWebSockets() {
    // Only init if we're on a page that needs WebSocket
    const monitoringPage = document.getElementById('metrics-tab');
    const logsPage = document.getElementById('logs-tab');

    if (monitoringPage || logsPage) {
        console.log('Initializing WebSocket connections...');
        initMetricsWebSocket();
        initLogsWebSocket();
    }
}

// Auto-initialize on DOM ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initializeWebSockets);
} else {
    initializeWebSockets();
}

// Cleanup on page unload
window.addEventListener('beforeunload', () => {
    if (metricsWs) metricsWs.close();
    if (logsWs) logsWs.close();
});
