/**
 * Plotly.js chart management for Instanton Dashboard
 */

class DashboardCharts {
    constructor(maxPoints = 300) {
        this.maxPoints = maxPoints;
        this.trafficChart = null;
        this.latencyChart = null;
        this.distributionChart = null;
        this.connectionsChart = null;
        this.initialized = false;

        // Dark theme colors
        this.colors = {
            blue: '#58a6ff',
            green: '#3fb950',
            orange: '#d29922',
            red: '#f85149',
            purple: '#a371f7',
            background: '#161b22',
            gridColor: '#30363d',
            textColor: '#8b949e'
        };

        // Common layout settings
        this.commonLayout = {
            paper_bgcolor: 'transparent',
            plot_bgcolor: 'transparent',
            font: { color: this.colors.textColor, size: 11 },
            margin: { t: 10, r: 10, b: 40, l: 50 },
            xaxis: {
                gridcolor: this.colors.gridColor,
                linecolor: this.colors.gridColor,
                tickformat: '%H:%M:%S'
            },
            yaxis: {
                gridcolor: this.colors.gridColor,
                linecolor: this.colors.gridColor
            },
            showlegend: true,
            legend: {
                orientation: 'h',
                yanchor: 'bottom',
                y: 1.02,
                xanchor: 'right',
                x: 1,
                font: { size: 10 }
            }
        };

        this.commonConfig = {
            responsive: true,
            displayModeBar: false
        };
    }

    /**
     * Initialize all charts
     */
    initialize() {
        if (this.initialized) return;

        this.initTrafficChart();
        this.initLatencyChart();
        this.initDistributionChart();
        this.initConnectionsChart();

        this.initialized = true;
    }

    /**
     * Initialize traffic chart (requests/sec + bandwidth)
     */
    initTrafficChart() {
        const traces = [
            {
                name: 'Requests/sec',
                x: [],
                y: [],
                type: 'scatter',
                mode: 'lines',
                line: { color: this.colors.blue, width: 2 },
                yaxis: 'y'
            },
            {
                name: 'Bandwidth (KB/s)',
                x: [],
                y: [],
                type: 'scatter',
                mode: 'lines',
                line: { color: this.colors.green, width: 2 },
                yaxis: 'y2'
            }
        ];

        const layout = {
            ...this.commonLayout,
            yaxis: {
                ...this.commonLayout.yaxis,
                title: { text: 'Req/s', font: { size: 10 } },
                rangemode: 'tozero'
            },
            yaxis2: {
                title: { text: 'KB/s', font: { size: 10 } },
                overlaying: 'y',
                side: 'right',
                gridcolor: 'transparent',
                rangemode: 'tozero'
            }
        };

        Plotly.newPlot('trafficChart', traces, layout, this.commonConfig);
    }

    /**
     * Initialize latency percentiles chart
     */
    initLatencyChart() {
        const traces = [
            {
                name: 'p50',
                x: [],
                y: [],
                type: 'scatter',
                mode: 'lines',
                line: { color: this.colors.green, width: 2 },
                fill: 'tonexty'
            },
            {
                name: 'p95',
                x: [],
                y: [],
                type: 'scatter',
                mode: 'lines',
                line: { color: this.colors.orange, width: 2 },
                fill: 'tonexty'
            },
            {
                name: 'p99',
                x: [],
                y: [],
                type: 'scatter',
                mode: 'lines',
                line: { color: this.colors.red, width: 2 }
            }
        ];

        const layout = {
            ...this.commonLayout,
            yaxis: {
                ...this.commonLayout.yaxis,
                title: { text: 'Latency (ms)', font: { size: 10 } },
                rangemode: 'tozero'
            }
        };

        Plotly.newPlot('latencyChart', traces, layout, this.commonConfig);
    }

    /**
     * Initialize tunnel distribution pie chart
     */
    initDistributionChart() {
        const trace = {
            values: [0, 0, 0],
            labels: ['HTTP', 'TCP', 'UDP'],
            type: 'pie',
            marker: {
                colors: [this.colors.blue, this.colors.green, this.colors.purple]
            },
            textinfo: 'label+value',
            textposition: 'inside',
            textfont: { color: '#fff', size: 12 },
            hole: 0.4
        };

        const layout = {
            paper_bgcolor: 'transparent',
            plot_bgcolor: 'transparent',
            font: { color: this.colors.textColor },
            margin: { t: 20, r: 20, b: 20, l: 20 },
            showlegend: false,
            annotations: [{
                text: 'Tunnels',
                font: { size: 14, color: this.colors.textColor },
                showarrow: false,
                x: 0.5,
                y: 0.5
            }]
        };

        Plotly.newPlot('distributionChart', [trace], layout, this.commonConfig);
    }

    /**
     * Initialize connections over time chart
     */
    initConnectionsChart() {
        const trace = {
            name: 'Connections',
            x: [],
            y: [],
            type: 'scatter',
            mode: 'lines',
            fill: 'tozeroy',
            line: { color: this.colors.purple, width: 2 },
            fillcolor: 'rgba(163, 113, 247, 0.2)'
        };

        const layout = {
            ...this.commonLayout,
            showlegend: false,
            yaxis: {
                ...this.commonLayout.yaxis,
                title: { text: 'Connections', font: { size: 10 } },
                rangemode: 'tozero'
            }
        };

        Plotly.newPlot('connectionsChart', [trace], layout, this.commonConfig);
    }

    /**
     * Update charts with new snapshot data
     */
    updateFromSnapshot(snapshot) {
        const time = new Date(snapshot.timestamp * 1000);

        // Update traffic chart
        const totalBandwidth = (snapshot.bytes_in_per_second + snapshot.bytes_out_per_second) / 1024;

        Plotly.extendTraces('trafficChart', {
            x: [[time], [time]],
            y: [[snapshot.requests_per_second], [totalBandwidth]]
        }, [0, 1], this.maxPoints);

        // Update latency chart
        Plotly.extendTraces('latencyChart', {
            x: [[time], [time], [time]],
            y: [[snapshot.latency_p50], [snapshot.latency_p95], [snapshot.latency_p99]]
        }, [0, 1, 2], this.maxPoints);

        // Update connections chart
        Plotly.extendTraces('connectionsChart', {
            x: [[time]],
            y: [[snapshot.active_connections]]
        }, [0], this.maxPoints);
    }

    /**
     * Update tunnel distribution chart
     */
    updateDistribution(tunnels) {
        const http = tunnels.http || 0;
        const tcp = tunnels.tcp || 0;
        const udp = tunnels.udp || 0;
        const total = http + tcp + udp;

        Plotly.restyle('distributionChart', {
            values: [[http, tcp, udp]]
        }, [0]);

        // Update center annotation
        Plotly.relayout('distributionChart', {
            'annotations[0].text': total > 0 ? String(total) : 'Tunnels'
        });
    }

    /**
     * Load historical data into charts
     */
    loadHistory(history) {
        if (!history || history.length === 0) return;

        const times = history.map(h => new Date(h.timestamp * 1000));
        const requests = history.map(h => h.requests_per_second);
        const bandwidth = history.map(h => (h.bytes_in_per_second + h.bytes_out_per_second) / 1024);
        const p50 = history.map(h => h.latency_p50);
        const p95 = history.map(h => h.latency_p95);
        const p99 = history.map(h => h.latency_p99);
        const connections = history.map(h => h.active_connections);

        // Update traffic chart
        Plotly.restyle('trafficChart', {
            x: [times, times],
            y: [requests, bandwidth]
        }, [0, 1]);

        // Update latency chart
        Plotly.restyle('latencyChart', {
            x: [times, times, times],
            y: [p50, p95, p99]
        }, [0, 1, 2]);

        // Update connections chart
        Plotly.restyle('connectionsChart', {
            x: [times],
            y: [connections]
        }, [0]);

        // Update distribution from latest snapshot
        const latest = history[history.length - 1];
        if (latest && latest.active_tunnels) {
            this.updateDistribution(latest.active_tunnels);
        }
    }

    /**
     * Resize all charts (call on window resize)
     */
    resize() {
        const charts = ['trafficChart', 'latencyChart', 'distributionChart', 'connectionsChart'];
        for (const chartId of charts) {
            const el = document.getElementById(chartId);
            if (el) {
                Plotly.Plots.resize(el);
            }
        }
    }
}

// Export for use in other modules
window.DashboardCharts = DashboardCharts;
