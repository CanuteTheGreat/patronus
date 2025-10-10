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
        await this.loadPolicies();

        // Initialize charts
        this.initCharts();

        // Set up policy editor
        this.setupPolicyEditor();

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
            this.loadPolicies();
        }, 30000);
    }

    async loadPolicies() {
        try {
            const response = await fetch(`${this.apiBase}/policies`);
            const policies = await response.json();

            const container = document.getElementById('policiesList');

            if (policies.length === 0) {
                container.innerHTML = '<p class="no-data">No policies found</p>';
                return;
            }

            const table = document.createElement('table');
            table.innerHTML = `
                <thead>
                    <tr>
                        <th>Name</th>
                        <th>Namespace</th>
                        <th>Types</th>
                        <th>Priority</th>
                        <th>Status</th>
                        <th>Rules</th>
                    </tr>
                </thead>
                <tbody>
                    ${policies.map(policy => `
                        <tr class="policy-row" data-policy-id="${policy.id}">
                            <td><strong>${policy.name}</strong></td>
                            <td><code>${policy.namespace}</code></td>
                            <td>${policy.policy_types.join(', ')}</td>
                            <td>${policy.priority}</td>
                            <td><span class="badge ${policy.enabled ? 'up' : 'down'}">${policy.enabled ? 'Enabled' : 'Disabled'}</span></td>
                            <td>I:${policy.ingress_rules.length} E:${policy.egress_rules.length}</td>
                        </tr>
                    `).join('')}
                </tbody>
            `;

            container.innerHTML = '';
            container.appendChild(table);

            // Add click handlers to policy rows
            table.querySelectorAll('.policy-row').forEach(row => {
                row.addEventListener('click', () => {
                    const policyId = row.dataset.policyId;
                    this.showPolicyDetail(policyId);
                });
            });
        } catch (error) {
            console.error('Error loading policies:', error);
        }
    }

    setupPolicyEditor() {
        this.currentPolicy = null;
        this.editMode = false;

        // Create policy button
        document.getElementById('createPolicyBtn').addEventListener('click', () => {
            this.openPolicyEditor();
        });

        // Tab switching
        document.querySelectorAll('#policyModal .tab-button').forEach(button => {
            button.addEventListener('click', () => {
                document.querySelectorAll('#policyModal .tab-button').forEach(b => b.classList.remove('active'));
                document.querySelectorAll('#policyModal .tab-content').forEach(c => c.classList.remove('active'));
                button.classList.add('active');
                document.getElementById(`${button.dataset.tab}-editor`).classList.add('active');
            });
        });

        // Modal close buttons
        document.querySelectorAll('.modal-close').forEach(btn => {
            btn.addEventListener('click', () => {
                document.querySelectorAll('.modal').forEach(m => m.classList.remove('active'));
            });
        });

        // Cancel button
        document.getElementById('cancelPolicyBtn').addEventListener('click', () => {
            document.getElementById('policyModal').classList.remove('active');
        });

        // Save button
        document.getElementById('savePolicyBtn').addEventListener('click', () => {
            this.savePolicy();
        });

        // Validate YAML button
        document.getElementById('validateYamlBtn').addEventListener('click', () => {
            this.validateYaml();
        });

        // Policy detail modal buttons
        document.getElementById('editPolicyBtn').addEventListener('click', () => {
            document.getElementById('policyDetailModal').classList.remove('active');
            this.openPolicyEditor(this.currentPolicy);
        });

        document.getElementById('deletePolicyBtn').addEventListener('click', () => {
            if (confirm(`Are you sure you want to delete policy "${this.currentPolicy.name}"?`)) {
                this.deletePolicy(this.currentPolicy.id);
            }
        });

        // Close modal on backdrop click
        document.querySelectorAll('.modal').forEach(modal => {
            modal.addEventListener('click', (e) => {
                if (e.target === modal) {
                    modal.classList.remove('active');
                }
            });
        });
    }

    openPolicyEditor(policy = null) {
        this.currentPolicy = policy;
        this.editMode = !!policy;

        const modal = document.getElementById('policyModal');
        const title = document.getElementById('modalTitle');

        title.textContent = policy ? 'Edit Network Policy' : 'Create Network Policy';

        if (policy) {
            // Populate form with policy data
            this.populatePolicyForm(policy);
        } else {
            // Reset form with example
            this.resetPolicyForm();
        }

        modal.classList.add('active');
    }

    populatePolicyForm(policy) {
        // YAML tab
        document.getElementById('policyYaml').value = this.policyToYaml(policy);

        // Form tab
        document.getElementById('policyName').value = policy.name;
        document.getElementById('policyNamespace').value = policy.namespace;
        document.getElementById('ingressType').checked = policy.policy_types.includes('Ingress');
        document.getElementById('egressType').checked = policy.policy_types.includes('Egress');
        document.getElementById('podLabels').value = JSON.stringify(policy.pod_selector.match_labels, null, 2);
        document.getElementById('ingressRules').value = JSON.stringify(policy.ingress_rules, null, 2);
        document.getElementById('egressRules').value = JSON.stringify(policy.egress_rules, null, 2);
        document.getElementById('policyPriority').value = policy.priority;
    }

    resetPolicyForm() {
        const exampleYaml = `name: allow-web-traffic
namespace: default
spec:
  pod_selector:
    match_labels:
      app: web
    match_expressions: []
  policy_types:
    - Ingress
  ingress:
    - from:
        - pod_selector:
            namespace_selector: null
            pod_selector:
              match_labels:
                role: frontend
              match_expressions: []
      ports:
        - protocol: TCP
          port: 80
          end_port: null
  egress: []
  priority: 100
  enabled: true`;

        document.getElementById('policyYaml').value = exampleYaml;

        document.getElementById('policyName').value = 'allow-web-traffic';
        document.getElementById('policyNamespace').value = 'default';
        document.getElementById('ingressType').checked = true;
        document.getElementById('egressType').checked = false;
        document.getElementById('podLabels').value = '{"app": "web"}';
        document.getElementById('ingressRules').value = '[]';
        document.getElementById('egressRules').value = '[]';
        document.getElementById('policyPriority').value = '100';
    }

    policyToYaml(policy) {
        // Simple YAML serialization
        return `name: ${policy.name}
namespace: ${policy.namespace}
spec:
  pod_selector:
    match_labels: ${JSON.stringify(policy.pod_selector.match_labels)}
    match_expressions: ${JSON.stringify(policy.pod_selector.match_expressions)}
  policy_types: [${policy.policy_types.join(', ')}]
  ingress: ${JSON.stringify(policy.ingress_rules, null, 2)}
  egress: ${JSON.stringify(policy.egress_rules, null, 2)}
  priority: ${policy.priority}
  enabled: ${policy.enabled}`;
    }

    validateYaml() {
        const yaml = document.getElementById('policyYaml').value;
        const messageDiv = document.getElementById('validationMessage');

        try {
            // Basic validation - try to parse as structured text
            const lines = yaml.split('\n');
            if (!lines.some(l => l.includes('name:'))) {
                throw new Error('Missing "name" field');
            }
            if (!lines.some(l => l.includes('namespace:'))) {
                throw new Error('Missing "namespace" field');
            }

            messageDiv.textContent = '✓ YAML syntax is valid';
            messageDiv.className = 'validation-message success';
        } catch (error) {
            messageDiv.textContent = `✗ Error: ${error.message}`;
            messageDiv.className = 'validation-message error';
        }
    }

    async savePolicy() {
        try {
            const yaml = document.getElementById('policyYaml').value;
            const request = this.yamlToRequest(yaml);

            const url = this.editMode
                ? `${this.apiBase}/policies/${this.currentPolicy.id}`
                : `${this.apiBase}/policies`;

            const method = this.editMode ? 'PUT' : 'POST';

            const response = await fetch(url, {
                method,
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(request)
            });

            if (!response.ok) {
                const error = await response.json();
                throw new Error(error.message || 'Failed to save policy');
            }

            document.getElementById('policyModal').classList.remove('active');
            await this.loadPolicies();
        } catch (error) {
            alert(`Error saving policy: ${error.message}`);
            console.error('Error saving policy:', error);
        }
    }

    yamlToRequest(yaml) {
        // Parse YAML-like text into JSON request
        const lines = yaml.split('\n');
        const request = { spec: {} };

        let inSpec = false;
        let currentIndent = 0;

        for (const line of lines) {
            const trimmed = line.trim();
            if (!trimmed || trimmed.startsWith('#')) continue;

            if (trimmed.startsWith('name:')) {
                request.name = trimmed.split(':')[1].trim();
            } else if (trimmed.startsWith('namespace:')) {
                request.namespace = trimmed.split(':')[1].trim();
            } else if (trimmed === 'spec:') {
                inSpec = true;
            } else if (inSpec) {
                // Parse spec fields
                if (trimmed.startsWith('pod_selector:')) {
                    request.spec.pod_selector = { match_labels: {}, match_expressions: [] };
                } else if (trimmed.startsWith('match_labels:')) {
                    try {
                        const jsonStr = trimmed.substring(trimmed.indexOf('{'));
                        request.spec.pod_selector.match_labels = JSON.parse(jsonStr);
                    } catch (e) {
                        request.spec.pod_selector.match_labels = {};
                    }
                } else if (trimmed.startsWith('policy_types:')) {
                    const typesStr = trimmed.substring(trimmed.indexOf('['));
                    request.spec.policy_types = JSON.parse(typesStr);
                } else if (trimmed.startsWith('ingress:')) {
                    try {
                        const jsonStr = trimmed.substring(trimmed.indexOf('['));
                        request.spec.ingress = JSON.parse(jsonStr);
                    } catch (e) {
                        request.spec.ingress = [];
                    }
                } else if (trimmed.startsWith('egress:')) {
                    try {
                        const jsonStr = trimmed.substring(trimmed.indexOf('['));
                        request.spec.egress = JSON.parse(jsonStr);
                    } catch (e) {
                        request.spec.egress = [];
                    }
                } else if (trimmed.startsWith('priority:')) {
                    request.spec.priority = parseInt(trimmed.split(':')[1].trim());
                } else if (trimmed.startsWith('enabled:')) {
                    request.spec.enabled = trimmed.split(':')[1].trim() === 'true';
                }
            }
        }

        // Set defaults
        if (!request.spec.pod_selector) {
            request.spec.pod_selector = { match_labels: {}, match_expressions: [] };
        }
        if (!request.spec.policy_types) {
            request.spec.policy_types = ['Ingress'];
        }
        if (!request.spec.ingress) {
            request.spec.ingress = [];
        }
        if (!request.spec.egress) {
            request.spec.egress = [];
        }
        if (!request.spec.priority) {
            request.spec.priority = 100;
        }
        if (request.spec.enabled === undefined) {
            request.spec.enabled = true;
        }

        return request;
    }

    async showPolicyDetail(policyId) {
        try {
            const response = await fetch(`${this.apiBase}/policies/${policyId}`);
            const policy = await response.json();

            this.currentPolicy = policy;

            const content = document.getElementById('policyDetailContent');
            content.innerHTML = `
                <div class="policy-detail-section">
                    <h3>Policy Information</h3>
                    <div class="policy-info-grid">
                        <div class="policy-info-item">
                            <div class="label">Name</div>
                            <div class="value">${policy.name}</div>
                        </div>
                        <div class="policy-info-item">
                            <div class="label">Namespace</div>
                            <div class="value">${policy.namespace}</div>
                        </div>
                        <div class="policy-info-item">
                            <div class="label">Priority</div>
                            <div class="value">${policy.priority}</div>
                        </div>
                        <div class="policy-info-item">
                            <div class="label">Status</div>
                            <div class="value">
                                <span class="badge ${policy.enabled ? 'up' : 'down'}">
                                    ${policy.enabled ? 'Enabled' : 'Disabled'}
                                </span>
                            </div>
                        </div>
                    </div>
                </div>

                <div class="policy-detail-section">
                    <h3>Policy Types</h3>
                    <p>${policy.policy_types.join(', ')}</p>
                </div>

                <div class="policy-detail-section">
                    <h3>Pod Selector</h3>
                    <pre class="policy-yaml-display">${JSON.stringify(policy.pod_selector, null, 2)}</pre>
                </div>

                <div class="policy-detail-section">
                    <h3>Ingress Rules (${policy.ingress_rules.length})</h3>
                    <pre class="policy-yaml-display">${JSON.stringify(policy.ingress_rules, null, 2)}</pre>
                </div>

                <div class="policy-detail-section">
                    <h3>Egress Rules (${policy.egress_rules.length})</h3>
                    <pre class="policy-yaml-display">${JSON.stringify(policy.egress_rules, null, 2)}</pre>
                </div>
            `;

            document.getElementById('policyDetailModal').classList.add('active');
        } catch (error) {
            console.error('Error loading policy detail:', error);
            alert('Failed to load policy details');
        }
    }

    async deletePolicy(policyId) {
        try {
            const response = await fetch(`${this.apiBase}/policies/${policyId}`, {
                method: 'DELETE'
            });

            if (!response.ok) {
                throw new Error('Failed to delete policy');
            }

            document.getElementById('policyDetailModal').classList.remove('active');
            await this.loadPolicies();
        } catch (error) {
            console.error('Error deleting policy:', error);
            alert('Failed to delete policy');
        }
    }
}

// Initialize dashboard when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    window.dashboard = new Dashboard();
});
