/**
 * WebSocket client with auto-reconnect for Instanton Dashboard
 */

class DashboardWebSocket {
    constructor(options = {}) {
        this.options = {
            maxRetries: 10,
            baseDelay: 1000,
            maxDelay: 30000,
            ...options
        };

        this.ws = null;
        this.retryCount = 0;
        this.connected = false;
        this.handlers = new Map();
        this.reconnectTimeout = null;
    }

    /**
     * Connect to the dashboard WebSocket endpoint
     */
    connect() {
        if (this.ws && (this.ws.readyState === WebSocket.CONNECTING || this.ws.readyState === WebSocket.OPEN)) {
            return;
        }

        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const wsUrl = `${protocol}//${window.location.host}/dashboard/ws`;

        this.updateStatus('connecting');

        try {
            this.ws = new WebSocket(wsUrl);
            this.ws.onopen = () => this.handleOpen();
            this.ws.onclose = (event) => this.handleClose(event);
            this.ws.onerror = (error) => this.handleError(error);
            this.ws.onmessage = (event) => this.handleMessage(event);
        } catch (error) {
            console.error('WebSocket connection error:', error);
            this.scheduleReconnect();
        }
    }

    /**
     * Handle WebSocket open event
     */
    handleOpen() {
        console.log('Dashboard WebSocket connected');
        this.connected = true;
        this.retryCount = 0;
        this.updateStatus('connected');
        this.emit('connected');
    }

    /**
     * Handle WebSocket close event
     */
    handleClose(event) {
        console.log('Dashboard WebSocket closed:', event.code, event.reason);
        this.connected = false;
        this.ws = null;

        if (!event.wasClean) {
            this.scheduleReconnect();
        } else {
            this.updateStatus('disconnected');
        }

        this.emit('disconnected', { code: event.code, reason: event.reason });
    }

    /**
     * Handle WebSocket error
     */
    handleError(error) {
        console.error('Dashboard WebSocket error:', error);
        this.emit('error', error);
    }

    /**
     * Handle incoming WebSocket message
     */
    handleMessage(event) {
        try {
            const data = JSON.parse(event.data);
            this.emit(data.type, data);
        } catch (error) {
            console.error('Failed to parse WebSocket message:', error);
        }
    }

    /**
     * Schedule a reconnection attempt with exponential backoff
     */
    scheduleReconnect() {
        if (this.reconnectTimeout) {
            clearTimeout(this.reconnectTimeout);
        }

        if (this.retryCount >= this.options.maxRetries) {
            console.error('Max reconnection attempts reached');
            this.updateStatus('disconnected');
            this.emit('maxRetriesReached');
            return;
        }

        // Exponential backoff with jitter
        const delay = Math.min(
            this.options.baseDelay * Math.pow(2, this.retryCount) + Math.random() * 1000,
            this.options.maxDelay
        );

        this.retryCount++;
        this.updateStatus('reconnecting');
        console.log(`Reconnecting in ${Math.round(delay)}ms (attempt ${this.retryCount}/${this.options.maxRetries})`);

        this.reconnectTimeout = setTimeout(() => {
            this.connect();
        }, delay);
    }

    /**
     * Send a message to the server
     */
    send(message) {
        if (this.ws && this.ws.readyState === WebSocket.OPEN) {
            this.ws.send(JSON.stringify(message));
        }
    }

    /**
     * Request tunnel details
     */
    requestTunnelDetails(subdomain) {
        this.send({
            type: 'tunnel_details',
            subdomain: subdomain
        });
    }

    /**
     * Register an event handler
     */
    on(event, handler) {
        if (!this.handlers.has(event)) {
            this.handlers.set(event, []);
        }
        this.handlers.get(event).push(handler);
    }

    /**
     * Remove an event handler
     */
    off(event, handler) {
        if (this.handlers.has(event)) {
            const handlers = this.handlers.get(event);
            const index = handlers.indexOf(handler);
            if (index > -1) {
                handlers.splice(index, 1);
            }
        }
    }

    /**
     * Emit an event to all registered handlers
     */
    emit(event, data) {
        if (this.handlers.has(event)) {
            for (const handler of this.handlers.get(event)) {
                try {
                    handler(data);
                } catch (error) {
                    console.error(`Error in ${event} handler:`, error);
                }
            }
        }
    }

    /**
     * Update connection status in the UI
     */
    updateStatus(status) {
        const statusEl = document.getElementById('connectionStatus');
        if (!statusEl) return;

        statusEl.className = 'connection-status ' + status;
        const textEl = statusEl.querySelector('.status-text');

        const statusText = {
            'connecting': 'Connecting...',
            'connected': 'Connected',
            'disconnected': 'Disconnected',
            'reconnecting': 'Reconnecting...'
        };

        if (textEl) {
            textEl.textContent = statusText[status] || status;
        }
    }

    /**
     * Close the WebSocket connection
     */
    close() {
        if (this.reconnectTimeout) {
            clearTimeout(this.reconnectTimeout);
            this.reconnectTimeout = null;
        }

        if (this.ws) {
            this.ws.close();
            this.ws = null;
        }

        this.connected = false;
    }
}

// Export for use in other modules
window.DashboardWebSocket = DashboardWebSocket;
