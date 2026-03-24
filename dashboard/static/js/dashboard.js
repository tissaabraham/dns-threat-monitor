/**
 * Dashboard JavaScript
 * Handles API calls and UI interactions
 */

// API endpoints
const API = {
    alerts: '/api/alerts',
    logs: '/api/logs',
    statistics: '/api/statistics',
    search: '/api/search'
};

// Initialize dashboard
document.addEventListener('DOMContentLoaded', function() {
    loadStatistics();
    loadAlerts();
    loadLogs();

    // Set up event listeners
    document.getElementById('severity-filter').addEventListener('change', loadAlerts);
    document.getElementById('status-filter').addEventListener('change', loadAlerts);
    document.getElementById('search').addEventListener('input', handleSearch);

    // Refresh data every 30 seconds
    setInterval(loadStatistics, 30000);
    setInterval(loadAlerts, 30000);
    setInterval(loadLogs, 60000);
});

/**
 * Load and display system statistics
 */
function loadStatistics() {
    fetch(API.statistics)
        .then(response => response.json())
        .then(data => {
            document.getElementById('total-queries').textContent =
                formatNumber(data.total_queries);
            document.getElementById('total-alerts').textContent =
                formatNumber(data.total_alerts);
            document.getElementById('high-severity-alerts').textContent =
                formatNumber(data.high_severity_alerts);
        })
        .catch(error => console.error('Error loading statistics:', error));
}

/**
 * Load and display alerts
 */
function loadAlerts() {
    const severity = document.getElementById('severity-filter').value;
    const status = document.getElementById('status-filter').value;

    let url = API.alerts;
    const params = new URLSearchParams();
    if (severity) params.append('severity', severity);
    if (status) params.append('status', status);
    if (params.toString()) url += '?' + params.toString();

    fetch(url)
        .then(response => response.json())
        .then(data => {
            const tbody = document.querySelector('#alerts-table tbody');
            tbody.innerHTML = '';

            if (data.alerts.length === 0) {
                tbody.innerHTML = '<tr><td colspan="8" style="text-align: center;">No alerts found</td></tr>';
                return;
            }

            data.alerts.forEach(alert => {
                const row = createAlertRow(alert);
                tbody.appendChild(row);
            });
        })
        .catch(error => console.error('Error loading alerts:', error));
}

/**
 * Create table row for alert
 */
function createAlertRow(alert) {
    const row = document.createElement('tr');
    const severityClass = `severity-${alert.severity.toLowerCase()}`;
    const statusClass = `status-${alert.status.toLowerCase()}`;

    row.innerHTML = `
        <td>${formatDateTime(alert.created_at)}</td>
        <td>${escapeHtml(alert.domain)}</td>
        <td>${escapeHtml(alert.source_ip)}</td>
        <td>${escapeHtml(alert.threat_type)}</td>
        <td><span class="severity-badge ${severityClass}">${alert.severity}</span></td>
        <td>${alert.threat_score}/100</td>
        <td><span class="status-badge ${statusClass}">${alert.status}</span></td>
        <td>
            <select onchange="updateAlertStatus(${alert.id}, this.value)">
                <option value="">Update...</option>
                <option value="acknowledged">Acknowledge</option>
                <option value="resolved">Resolved</option>
                <option value="archived">Archive</option>
            </select>
        </td>
    `;

    return row;
}

/**
 * Load and display DNS logs
 */
function loadLogs() {
    fetch(API.logs)
        .then(response => response.json())
        .then(data => {
            const tbody = document.querySelector('#logs-table tbody');
            tbody.innerHTML = '';

            if (data.logs.length === 0) {
                tbody.innerHTML = '<tr><td colspan="5" style="text-align: center;">No logs found</td></tr>';
                return;
            }

            data.logs.forEach(log => {
                const row = document.createElement('tr');
                row.innerHTML = `
                    <td>${formatDateTime(log.timestamp)}</td>
                    <td>${escapeHtml(log.source_ip)}</td>
                    <td>${escapeHtml(log.domain)}</td>
                    <td>${escapeHtml(log.query_type)}</td>
                    <td>${log.response_ip ? escapeHtml(log.response_ip) : 'N/A'}</td>
                `;
                tbody.appendChild(row);
            });
        })
        .catch(error => console.error('Error loading logs:', error));
}

/**
 * Update alert status
 */
function updateAlertStatus(alertId, newStatus) {
    if (!newStatus) return;

    fetch(`${API.alerts}/${alertId}`, {
        method: 'PATCH',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ status: newStatus })
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            loadAlerts();
        }
    })
    .catch(error => console.error('Error updating alert:', error));
}

/**
 * Handle search
 */
function handleSearch() {
    const query = document.getElementById('search').value;
    if (!query) {
        loadAlerts();
        return;
    }

    fetch(`${API.search}?q=${encodeURIComponent(query)}`)
        .then(response => response.json())
        .then(data => {
            // Display search results in alerts table
        })
        .catch(error => console.error('Error searching:', error));
}

/**
 * Utility functions
 */
function formatNumber(num) {
    return num.toLocaleString();
}

function formatDateTime(dateString) {
    const date = new Date(dateString);
    return date.toLocaleString();
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

