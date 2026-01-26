/**
 * Instanton Dashboard - Main Application
 */

class DashboardApp {
    constructor() {
        this.ws = new DashboardWebSocket();
        this.charts = new DashboardCharts();
        this.tunnels = [];
        this.sortColumn = 'subdomain';
        this.sortDirection = 'asc';
        this.searchFilter = '';

        // Sparkline data for requests/sec
        this.requestsHistory = [];
        this.maxSparklinePoints = 30;
    }

    /**
     * Initialize the dashboard application
     */
    init() {
        // Initialize charts
        this.charts.initialize();

        // Set up WebSocket event handlers
        this.setupWebSocketHandlers();

        // Set up UI event handlers
        this.setupUIHandlers();

        // Connect to WebSocket
        this.ws.connect();

        // Handle window resize
        window.addEventListener('resize', () => this.charts.resize());
    }

    /**
     * Set up WebSocket event handlers
     */
    setupWebSocketHandlers() {
        // Initial data load
        this.ws.on('init', (data) => {
            console.log('Received initial data:', data.history?.length, 'snapshots,', data.tunnels?.length, 'tunnels');

            // Load historical data into charts
            if (data.history && data.history.length > 0) {
                this.charts.loadHistory(data.history);

                // Update metric cards with latest data
                const latest = data.history[data.history.length - 1];
                this.updateMetricCards(latest);

                // Initialize requests sparkline
                this.requestsHistory = data.history.slice(-this.maxSparklinePoints).map(h => h.requests_per_second);
            }

            // Load tunnel list
            if (data.tunnels) {
                this.tunnels = data.tunnels;
                this.renderTunnelTable();
            }
        });

        // Real-time updates
        this.ws.on('update', (data) => {
            if (data.snapshot) {
                this.charts.updateFromSnapshot(data.snapshot);
                this.updateMetricCards(data.snapshot);
                this.charts.updateDistribution(data.snapshot.active_tunnels);

                // Update sparkline
                this.requestsHistory.push(data.snapshot.requests_per_second);
                if (this.requestsHistory.length > this.maxSparklinePoints) {
                    this.requestsHistory.shift();
                }
                this.drawSparkline();
            }
        });

        // Tunnel list updates
        this.ws.on('tunnels', (data) => {
            if (data.tunnels) {
                this.tunnels = data.tunnels;
                this.renderTunnelTable();
            }
        });

        // Tunnel details response
        this.ws.on('tunnel_details', (data) => {
            if (data.details) {
                this.showTunnelDetails(data.details);
            }
        });

        // Connection events
        this.ws.on('connected', () => {
            console.log('Dashboard connected');
        });

        this.ws.on('disconnected', () => {
            console.log('Dashboard disconnected');
        });
    }

    /**
     * Set up UI event handlers
     */
    setupUIHandlers() {
        // Table sorting
        document.querySelectorAll('.tunnel-table th[data-sort]').forEach(th => {
            th.addEventListener('click', () => {
                const column = th.dataset.sort;
                if (this.sortColumn === column) {
                    this.sortDirection = this.sortDirection === 'asc' ? 'desc' : 'asc';
                } else {
                    this.sortColumn = column;
                    this.sortDirection = 'asc';
                }
                this.updateSortIndicators();
                this.renderTunnelTable();
            });
        });

        // Search filter
        const searchInput = document.getElementById('tunnelSearch');
        if (searchInput) {
            searchInput.addEventListener('input', (e) => {
                this.searchFilter = e.target.value.toLowerCase();
                this.renderTunnelTable();
            });
        }

        // Modal close
        const modalClose = document.getElementById('modalClose');
        const modal = document.getElementById('tunnelModal');
        if (modalClose) {
            modalClose.addEventListener('click', () => {
                modal.classList.remove('active');
            });
        }
        if (modal) {
            modal.addEventListener('click', (e) => {
                if (e.target === modal) {
                    modal.classList.remove('active');
                }
            });
        }
    }

    /**
     * Update metric cards with snapshot data
     */
    updateMetricCards(snapshot) {
        // Active tunnels
        const tunnels = snapshot.active_tunnels || {};
        const total = (tunnels.http || 0) + (tunnels.tcp || 0) + (tunnels.udp || 0);
        document.getElementById('totalTunnels').textContent = total;
        document.getElementById('httpTunnels').textContent = tunnels.http || 0;
        document.getElementById('tcpTunnels').textContent = tunnels.tcp || 0;
        document.getElementById('udpTunnels').textContent = tunnels.udp || 0;

        // Requests per second
        document.getElementById('requestsPerSec').textContent =
            snapshot.requests_per_second.toFixed(1);

        // Bandwidth
        const totalBw = snapshot.bytes_in_per_second + snapshot.bytes_out_per_second;
        document.getElementById('bandwidth').textContent = this.formatBytes(totalBw) + '/s';
        document.getElementById('bytesIn').textContent = this.formatBytes(snapshot.bytes_in_per_second) + '/s';
        document.getElementById('bytesOut').textContent = this.formatBytes(snapshot.bytes_out_per_second) + '/s';

        // Latency
        document.getElementById('latencyP95').textContent =
            snapshot.latency_p95.toFixed(1) + 'ms';
        document.getElementById('latencyP50').textContent =
            snapshot.latency_p50.toFixed(1) + 'ms';
        document.getElementById('latencyP99').textContent =
            snapshot.latency_p99.toFixed(1) + 'ms';
    }

    /**
     * Draw the requests/sec sparkline
     */
    drawSparkline() {
        const canvas = document.getElementById('requestsSparkline');
        if (!canvas) return;

        const ctx = canvas.getContext('2d');
        const width = canvas.width;
        const height = canvas.height;
        const data = this.requestsHistory;

        if (data.length < 2) return;

        ctx.clearRect(0, 0, width, height);

        const max = Math.max(...data, 1);
        const stepX = width / (data.length - 1);

        ctx.beginPath();
        ctx.strokeStyle = '#58a6ff';
        ctx.lineWidth = 1.5;

        for (let i = 0; i < data.length; i++) {
            const x = i * stepX;
            const y = height - (data[i] / max) * (height - 4) - 2;

            if (i === 0) {
                ctx.moveTo(x, y);
            } else {
                ctx.lineTo(x, y);
            }
        }

        ctx.stroke();
    }

    /**
     * Render the tunnel table with current data
     */
    renderTunnelTable() {
        const tbody = document.getElementById('tunnelTableBody');
        if (!tbody) return;

        // Filter tunnels
        let filtered = this.tunnels;
        if (this.searchFilter) {
            filtered = this.tunnels.filter(t =>
                t.subdomain.toLowerCase().includes(this.searchFilter) ||
                t.type.toLowerCase().includes(this.searchFilter) ||
                t.source_ip.includes(this.searchFilter)
            );
        }

        // Sort tunnels
        filtered.sort((a, b) => {
            let aVal = a[this.sortColumn];
            let bVal = b[this.sortColumn];

            if (typeof aVal === 'string') {
                aVal = aVal.toLowerCase();
                bVal = bVal.toLowerCase();
            }

            if (aVal < bVal) return this.sortDirection === 'asc' ? -1 : 1;
            if (aVal > bVal) return this.sortDirection === 'asc' ? 1 : -1;
            return 0;
        });

        // Render rows
        if (filtered.length === 0) {
            tbody.innerHTML = '<tr class="empty-row"><td colspan="7">No active tunnels</td></tr>';
            return;
        }

        tbody.innerHTML = filtered.map(tunnel => `
            <tr data-subdomain="${tunnel.subdomain}">
                <td><code>${tunnel.subdomain}</code></td>
                <td><span class="tunnel-type ${tunnel.type}">${tunnel.type.toUpperCase()}</span></td>
                <td>${tunnel.request_count.toLocaleString()}</td>
                <td>${this.formatBytes(tunnel.bytes_in)}</td>
                <td>${this.formatBytes(tunnel.bytes_out)}</td>
                <td>${tunnel.source_ip}</td>
                <td>${this.formatUptime(tunnel.uptime_seconds)}</td>
            </tr>
        `).join('');

        // Add click handlers for row details
        tbody.querySelectorAll('tr[data-subdomain]').forEach(row => {
            row.addEventListener('click', () => {
                const subdomain = row.dataset.subdomain;
                this.ws.requestTunnelDetails(subdomain);
            });
        });
    }

    /**
     * Update sort indicators in table headers
     */
    updateSortIndicators() {
        document.querySelectorAll('.tunnel-table th[data-sort]').forEach(th => {
            th.classList.remove('sorted-asc', 'sorted-desc');
            if (th.dataset.sort === this.sortColumn) {
                th.classList.add(this.sortDirection === 'asc' ? 'sorted-asc' : 'sorted-desc');
            }
        });
    }

    /**
     * Show tunnel details in modal
     */
    showTunnelDetails(details) {
        const modal = document.getElementById('tunnelModal');
        const body = document.getElementById('tunnelDetails');

        if (!modal || !body) return;

        const rows = [
            ['Subdomain', `<code>${details.subdomain}</code>`],
            ['Type', `<span class="tunnel-type ${details.type}">${details.type.toUpperCase()}</span>`],
            ['Tunnel ID', `<code>${details.id}</code>`],
            ['Source IP', details.source_ip],
            ['Local Port', details.local_port],
            ['Requests', details.request_count.toLocaleString()],
            ['Bytes Sent', this.formatBytes(details.bytes_sent)],
            ['Bytes Received', this.formatBytes(details.bytes_received)],
            ['Connected At', new Date(details.connected_at).toLocaleString()],
            ['Last Activity', new Date(details.last_activity).toLocaleString()],
            ['Uptime', this.formatUptime(details.uptime_seconds)]
        ];

        if (details.compression) {
            rows.push(['Compression', details.compression]);
        }
        if (details.port) {
            rows.push(['Assigned Port', details.port]);
        }

        body.innerHTML = rows.map(([label, value]) => `
            <div class="detail-row">
                <span class="detail-label">${label}</span>
                <span class="detail-value">${value}</span>
            </div>
        `).join('');

        modal.classList.add('active');
    }

    /**
     * Format bytes to human-readable string
     */
    formatBytes(bytes) {
        if (bytes === 0) return '0 B';

        const units = ['B', 'KB', 'MB', 'GB', 'TB'];
        const k = 1024;
        const i = Math.floor(Math.log(bytes) / Math.log(k));

        return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + units[i];
    }

    /**
     * Format uptime seconds to human-readable string
     */
    formatUptime(seconds) {
        if (seconds < 60) return `${Math.round(seconds)}s`;
        if (seconds < 3600) return `${Math.floor(seconds / 60)}m ${Math.round(seconds % 60)}s`;
        if (seconds < 86400) {
            const hours = Math.floor(seconds / 3600);
            const mins = Math.floor((seconds % 3600) / 60);
            return `${hours}h ${mins}m`;
        }
        const days = Math.floor(seconds / 86400);
        const hours = Math.floor((seconds % 86400) / 3600);
        return `${days}d ${hours}h`;
    }
}

// Initialize app when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    window.dashboardApp = new DashboardApp();
    window.dashboardApp.init();
});
