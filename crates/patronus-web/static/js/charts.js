//! Chart.js integration for real-time metrics visualization
//!
//! Provides interactive charts for:
//! - CPU/Memory/Disk usage over time
//! - Network throughput (RX/TX)
//! - Interface-specific statistics
//! - Connection tracking

// Chart instances
let cpuChart, memoryChart, networkChart, interfaceCharts = {};

// Chart color scheme
const colors = {
    primary: 'rgb(37, 99, 235)',
    success: 'rgb(34, 197, 94)',
    warning: 'rgb(245, 158, 11)',
    danger: 'rgb(239, 68, 68)',
    info: 'rgb(59, 130, 246)',
};

/**
 * Initialize all charts on page load
 */
function initializeCharts() {
    initSystemMetricsChart();
    initNetworkThroughputChart();
    startMetricsUpdates();
}

/**
 * Initialize system metrics chart (CPU, Memory, Disk)
 */
function initSystemMetricsChart() {
    const ctx = document.getElementById('system-metrics-chart');
    if (!ctx) return;

    const now = Date.now();
    const labels = [];
    const dataPoints = 60; // Last 60 data points

    for (let i = dataPoints; i >= 0; i--) {
        labels.push(new Date(now - i * 1000));
    }

    cpuChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: labels,
            datasets: [
                {
                    label: 'CPU %',
                    data: Array(dataPoints + 1).fill(0),
                    borderColor: colors.primary,
                    backgroundColor: 'rgba(37, 99, 235, 0.1)',
                    fill: true,
                    tension: 0.4,
                },
                {
                    label: 'Memory %',
                    data: Array(dataPoints + 1).fill(0),
                    borderColor: colors.success,
                    backgroundColor: 'rgba(34, 197, 94, 0.1)',
                    fill: true,
                    tension: 0.4,
                },
                {
                    label: 'Disk %',
                    data: Array(dataPoints + 1).fill(0),
                    borderColor: colors.warning,
                    backgroundColor: 'rgba(245, 158, 11, 0.1)',
                    fill: true,
                    tension: 0.4,
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            interaction: {
                mode: 'index',
                intersect: false,
            },
            plugins: {
                legend: {
                    position: 'top',
                },
                title: {
                    display: true,
                    text: 'System Resources'
                }
            },
            scales: {
                x: {
                    type: 'time',
                    time: {
                        unit: 'second',
                        displayFormats: {
                            second: 'HH:mm:ss'
                        }
                    },
                    ticks: {
                        maxRotation: 0,
                        autoSkipPadding: 20
                    }
                },
                y: {
                    beginAtZero: true,
                    max: 100,
                    ticks: {
                        callback: function(value) {
                            return value + '%';
                        }
                    }
                }
            }
        }
    });
}

/**
 * Initialize network throughput chart
 */
function initNetworkThroughputChart() {
    const ctx = document.getElementById('network-throughput-chart');
    if (!ctx) return;

    const now = Date.now();
    const labels = [];
    const dataPoints = 60;

    for (let i = dataPoints; i >= 0; i--) {
        labels.push(new Date(now - i * 1000));
    }

    networkChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: labels,
            datasets: [
                {
                    label: 'RX (Mbps)',
                    data: Array(dataPoints + 1).fill(0),
                    borderColor: colors.info,
                    backgroundColor: 'rgba(59, 130, 246, 0.1)',
                    fill: true,
                    tension: 0.4,
                },
                {
                    label: 'TX (Mbps)',
                    data: Array(dataPoints + 1).fill(0),
                    borderColor: colors.danger,
                    backgroundColor: 'rgba(239, 68, 68, 0.1)',
                    fill: true,
                    tension: 0.4,
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            interaction: {
                mode: 'index',
                intersect: false,
            },
            plugins: {
                legend: {
                    position: 'top',
                },
                title: {
                    display: true,
                    text: 'Network Throughput'
                }
            },
            scales: {
                x: {
                    type: 'time',
                    time: {
                        unit: 'second',
                        displayFormats: {
                            second: 'HH:mm:ss'
                        }
                    },
                    ticks: {
                        maxRotation: 0,
                        autoSkipPadding: 20
                    }
                },
                y: {
                    beginAtZero: true,
                    ticks: {
                        callback: function(value) {
                            return value.toFixed(1) + ' Mbps';
                        }
                    }
                }
            }
        }
    });
}

/**
 * Initialize per-interface chart
 */
function initInterfaceChart(interfaceName) {
    const ctx = document.getElementById(`interface-chart-${interfaceName}`);
    if (!ctx) return;

    const now = Date.now();
    const labels = [];
    const dataPoints = 30;

    for (let i = dataPoints; i >= 0; i--) {
        labels.push(new Date(now - i * 1000));
    }

    interfaceCharts[interfaceName] = new Chart(ctx, {
        type: 'line',
        data: {
            labels: labels,
            datasets: [
                {
                    label: 'RX Rate',
                    data: Array(dataPoints + 1).fill(0),
                    borderColor: colors.info,
                    tension: 0.4,
                },
                {
                    label: 'TX Rate',
                    data: Array(dataPoints + 1).fill(0),
                    borderColor: colors.danger,
                    tension: 0.4,
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    display: false,
                },
            },
            scales: {
                x: {
                    display: false
                },
                y: {
                    beginAtZero: true,
                    ticks: {
                        callback: function(value) {
                            return formatBytes(value);
                        }
                    }
                }
            }
        }
    });
}

/**
 * Update chart with new data point
 */
function updateChart(chart, datasetIndex, newValue) {
    if (!chart) return;

    const now = new Date();

    // Add new label and data
    chart.data.labels.push(now);
    chart.data.datasets[datasetIndex].data.push(newValue);

    // Remove old data (keep last 60 points)
    if (chart.data.labels.length > 61) {
        chart.data.labels.shift();
        chart.data.datasets.forEach(dataset => {
            dataset.data.shift();
        });
    }

    chart.update('none'); // Update without animation for performance
}

/**
 * Fetch and update metrics from API
 */
async function fetchAndUpdateMetrics() {
    try {
        const response = await fetch('/api/status');
        if (!response.ok) return;

        const data = await response.json();

        // Update system metrics chart
        if (cpuChart) {
            updateChart(cpuChart, 0, data.cpu_usage);
            updateChart(cpuChart, 1, data.memory_usage);
            updateChart(cpuChart, 2, data.disk_usage);
        }

        // Calculate total network throughput
        let totalRx = 0, totalTx = 0;
        if (data.interfaces) {
            data.interfaces.forEach(iface => {
                totalRx += (iface.rx_bytes || 0) / 1024 / 1024 * 8; // Convert to Mbps
                totalTx += (iface.tx_bytes || 0) / 1024 / 1024 * 8;
            });
        }

        // Update network chart
        if (networkChart) {
            updateChart(networkChart, 0, totalRx);
            updateChart(networkChart, 1, totalTx);
        }

        // Update interface-specific charts
        if (data.interfaces) {
            data.interfaces.forEach(iface => {
                if (interfaceCharts[iface.name]) {
                    const rxRate = iface.rx_bytes || 0;
                    const txRate = iface.tx_bytes || 0;
                    updateChart(interfaceCharts[iface.name], 0, rxRate);
                    updateChart(interfaceCharts[iface.name], 1, txRate);
                }
            });
        }

    } catch (err) {
        console.error('Failed to fetch metrics:', err);
    }
}

/**
 * Start periodic metrics updates
 */
function startMetricsUpdates() {
    // Update every second
    setInterval(fetchAndUpdateMetrics, 1000);

    // Initial fetch
    fetchAndUpdateMetrics();
}

/**
 * Format bytes to human-readable string
 */
function formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return (bytes / Math.pow(k, i)).toFixed(1) + ' ' + sizes[i];
}

/**
 * Create a simple gauge chart
 */
function createGaugeChart(canvasId, value, label, color) {
    const ctx = document.getElementById(canvasId);
    if (!ctx) return;

    return new Chart(ctx, {
        type: 'doughnut',
        data: {
            datasets: [{
                data: [value, 100 - value],
                backgroundColor: [color, 'rgba(0, 0, 0, 0.05)'],
                borderWidth: 0,
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            cutout: '75%',
            plugins: {
                legend: {
                    display: false
                },
                tooltip: {
                    enabled: false
                }
            }
        }
    });
}

// Initialize charts when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initializeCharts);
} else {
    initializeCharts();
}
