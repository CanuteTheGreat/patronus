// Patronus SD-WAN Dashboard Application

class Dashboard {
    constructor() {
        this.apiBase = '/api/v1';
        this.wsMetrics = null;
        this.wsEvents = null;
        this.charts = {};
        this.metricsData = [];

        this.init();
    }

    async init() {
        console.log('Initializing dashboard...');

        // Set up navigation
        this.setupNavigation();

        // Connect WebSockets
        this.connectWebSockets();

        // Load initial data
        await this.loadSummary();
        await this.loadSites();
        await this.loadPaths();

        // Initialize charts
        this.initCharts();

        // Start periodic refresh
        this.startPeriodicRefresh();
    }

    setupNavigation() {
        const buttons = document.querySelectorAll('.nav-button');
        buttons.forEach(button => {
            button.addEventListener('click', (e) => {
                // Remove active class from all buttons and views
                document.querySelectorAll('.nav-button').forEach(b => b.classList.remove('active'));
                document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));

                // Add active class to clicked button and corresponding view
                button.classList.add('active');
                const view = button.dataset.view;
                document.getElementById(`${view}-view`).classList.add('active');
            });
        });
    }

    connectWebSockets() {
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const host = window.location.host;

        // Metrics WebSocket
        this.wsMetrics = new WebSocket(`${protocol}//${host}/ws/metrics`);

        this.wsMetrics.onopen = () => {
            console.log('Metrics WebSocket connected');
            this.updateConnectionStatus(true);
        };

        this.wsMetrics.onmessage = (event) => {
            const update = JSON.parse(event.data);
            this.handleMetricsUpdate(update);
        };

        this.wsMetrics.onclose = () => {
            console.log('Metrics WebSocket closed, reconnecting...');
            this.updateConnectionStatus(false);
            setTimeout(() => this.connectWebSockets(), 5000);
        };

        // Events WebSocket
        this.wsEvents = new WebSocket(`${protocol}//${host}/ws/events`);

        this.wsEvents.onmessage = (event) => {
            const eventData = JSON.parse(event.data);
            this.handleEvent(eventData);
        };
    }

    updateConnectionStatus(connected) {
        const dot = document.getElementById('connectionStatus');
        const text = document.getElementById('connectionText');

        if (connected) {
            dot.classList.remove('offline');
            dot.classList.add('online');
            text.textContent = 'Connected';
        } else {
            dot.classList.remove('online');
            dot.classList.add('offline');
            text.textContent = 'Disconnected';
        }
    }

    async loadSummary() {
        try {
            const response = await fetch(`${this.apiBase}/metrics/summary`);
            const data = await response.json();

            document.getElementById('totalSites').textContent = data.total_sites;
            document.getElementById('activePaths').textContent = data.up_paths;
            document.getElementById('avgLatency').textContent = `${data.avg_latency_ms.toFixed(1)} ms`;

            const healthPercent = data.total_paths > 0
                ? ((data.up_paths / data.total_paths) * 100).toFixed(0)
                : 0;
            document.getElementById('pathHealth').textContent = `${healthPercent}%`;
        } catch (error) {
            console.error('Error loading summary:', error);
        }
    }

    async loadSites() {
        try {
            const response = await fetch(`${this.apiBase}/sites`);
            const sites = await response.json();

            const container = document.getElementById('sitesList');

            if (sites.length === 0) {
                container.innerHTML = '<p class="no-data">No sites found</p>';
                return;
            }

            const table = document.createElement('table');
            table.innerHTML = `
                <thead>
                    <tr>
                        <th>Name</th>
                        <th>ID</th>
                        <th>Status</th>
                        <th>Endpoints</th>
                        <th>Last Seen</th>
                    </tr>
                </thead>
                <tbody>
                    ${sites.map(site => `
                        <tr>
                            <td>${site.name}</td>
                            <td><code>${site.id.substring(0, 8)}...</code></td>
                            <td><span class="badge ${site.status.toLowerCase()}">${site.status}</span></td>
                            <td>${site.endpoints.length}</td>
                            <td>${new Date(site.last_seen).toLocaleString()}</td>
                        </tr>
                    `).join('')}
                </tbody>
            `;

            container.innerHTML = '';
            container.appendChild(table);
        } catch (error) {
            console.error('Error loading sites:', error);
        }
    }

    async loadPaths() {
        try {
            const response = await fetch(`${this.apiBase}/paths`);
            const paths = await response.json();

            const container = document.getElementById('pathsList');

            if (paths.length === 0) {
                container.innerHTML = '<p class="no-data">No paths found</p>';
                return;
            }

            const table = document.createElement('table');
            table.innerHTML = `
                <thead>
                    <tr>
                        <th>Source</th>
                        <th>Destination</th>
                        <th>Status</th>
                        <th>Latency</th>
                        <th>Loss</th>
                        <th>Score</th>
                    </tr>
                </thead>
                <tbody>
                    ${paths.map(path => `
                        <tr>
                            <td>${path.src_endpoint}</td>
                            <td>${path.dst_endpoint}</td>
                            <td><span class="badge ${path.status.toLowerCase()}">${path.status}</span></td>
                            <td>${path.metrics.latency_ms.toFixed(1)} ms</td>
                            <td>${path.metrics.packet_loss_pct.toFixed(2)}%</td>
                            <td>${path.metrics.score}</td>
                        </tr>
                    `).join('')}
                </tbody>
            `;

            container.innerHTML = '';
            container.appendChild(table);
        } catch (error) {
            console.error('Error loading paths:', error);
        }
    }

    initCharts() {
        const commonOptions = {
            responsive: true,
            maintainAspectRatio: true,
            plugins: {
                legend: {
                    labels: {
                        color: '#e2e8f0'
                    }
                }
            },
            scales: {
                x: {
                    ticks: { color: '#94a3b8' },
                    grid: { color: '#334155' }
                },
                y: {
                    ticks: { color: '#94a3b8' },
                    grid: { color: '#334155' }
                }
            }
        };

        // Latency chart
        const latencyCtx = document.getElementById('latencyChart').getContext('2d');
        this.charts.latency = new Chart(latencyCtx, {
            type: 'line',
            data: {
                labels: [],
                datasets: [{
                    label: 'Latency (ms)',
                    data: [],
                    borderColor: '#667eea',
                    backgroundColor: 'rgba(102, 126, 234, 0.1)',
                    tension: 0.4
                }]
            },
            options: commonOptions
        });

        // Metrics latency chart
        const metricsLatencyCtx = document.getElementById('metricsLatencyChart').getContext('2d');
        this.charts.metricsLatency = new Chart(metricsLatencyCtx, {
            type: 'line',
            data: {
                labels: [],
                datasets: [{
                    label: 'Latency (ms)',
                    data: [],
                    borderColor: '#10b981',
                    backgroundColor: 'rgba(16, 185, 129, 0.1)',
                    tension: 0.4
                }]
            },
            options: commonOptions
        });

        // Packet loss chart
        const metricsLossCtx = document.getElementById('metricsLossChart').getContext('2d');
        this.charts.metricsLoss = new Chart(metricsLossCtx, {
            type: 'line',
            data: {
                labels: [],
                datasets: [{
                    label: 'Packet Loss (%)',
                    data: [],
                    borderColor: '#f59e0b',
                    backgroundColor: 'rgba(245, 158, 11, 0.1)',
                    tension: 0.4
                }]
            },
            options: commonOptions
        });
    }

    handleMetricsUpdate(update) {
        console.log('Metrics update:', update);

        // Add to metrics data
        this.metricsData.push(update);

        // Keep only last 20 data points
        if (this.metricsData.length > 20) {
            this.metricsData.shift();
        }

        // Update charts
        this.updateCharts();
    }

    updateCharts() {
        const labels = this.metricsData.map((_, i) => i.toString());
        const latencyData = this.metricsData.map(d => d.metrics.latency_ms);
        const lossData = this.metricsData.map(d => d.metrics.packet_loss_pct);

        // Update latency chart
        this.charts.latency.data.labels = labels;
        this.charts.latency.data.datasets[0].data = latencyData;
        this.charts.latency.update('none');

        // Update metrics charts
        this.charts.metricsLatency.data.labels = labels;
        this.charts.metricsLatency.data.datasets[0].data = latencyData;
        this.charts.metricsLatency.update('none');

        this.charts.metricsLoss.data.labels = labels;
        this.charts.metricsLoss.data.datasets[0].data = lossData;
        this.charts.metricsLoss.update('none');
    }

    handleEvent(event) {
        console.log('Event:', event);

        // Add event to log
        const eventsLog = document.getElementById('eventsLog');

        // Remove "no data" message if present
        const noData = eventsLog.querySelector('.no-data');
        if (noData) {
            noData.remove();
        }

        const eventItem = document.createElement('div');
        eventItem.className = 'event-item';
        eventItem.innerHTML = `
            <span>${event.type}: ${JSON.stringify(event.data)}</span>
            <span class="event-time">${new Date(event.timestamp).toLocaleTimeString()}</span>
        `;

        eventsLog.insertBefore(eventItem, eventsLog.firstChild);

        // Keep only last 10 events
        while (eventsLog.children.length > 10) {
            eventsLog.removeChild(eventsLog.lastChild);
        }
    }

    startPeriodicRefresh() {
        // Refresh summary every 5 seconds
        setInterval(() => this.loadSummary(), 5000);

        // Refresh sites and paths every 30 seconds
        setInterval(() => {
            this.loadSites();
            this.loadPaths();
        }, 30000);
    }
}

// Initialize dashboard when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    window.dashboard = new Dashboard();
});
