"""Web inspection server - serves traffic inspector UI at localhost:4040."""

from __future__ import annotations

import asyncio
import contextlib
import json
from typing import Any
from uuid import UUID

import structlog
from aiohttp import WSMsgType, web

from instanton.inspector.replay import (
    ReplayConfig,
    RequestReplayer,
    get_request_replayer,
)
from instanton.inspector.storage import (
    RequestFilter,
    RequestStatus,
    TrafficStorage,
    get_traffic_storage,
)

logger = structlog.get_logger()


# HTML template for the inspector UI
INSPECTOR_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Instanton Inspector</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #1a1a2e;
            color: #eee;
            display: flex;
            height: 100vh;
        }
        .sidebar {
            width: 400px;
            background: #16213e;
            border-right: 1px solid #0f3460;
            display: flex;
            flex-direction: column;
        }
        .header {
            padding: 16px;
            background: #0f3460;
            border-bottom: 1px solid #0f3460;
        }
        .header h1 {
            font-size: 18px;
            color: #00d9ff;
            margin-bottom: 8px;
        }
        .header .subtitle { font-size: 12px; color: #888; }
        .filters {
            padding: 12px;
            border-bottom: 1px solid #0f3460;
            display: flex;
            gap: 8px;
            flex-wrap: wrap;
        }
        .filters input, .filters select {
            background: #1a1a2e;
            border: 1px solid #0f3460;
            color: #eee;
            padding: 6px 10px;
            border-radius: 4px;
            font-size: 12px;
        }
        .filters input:focus, .filters select:focus {
            outline: none;
            border-color: #00d9ff;
        }
        .request-list {
            flex: 1;
            overflow-y: auto;
        }
        .request-item {
            padding: 12px 16px;
            border-bottom: 1px solid #0f3460;
            cursor: pointer;
            transition: background 0.2s;
        }
        .request-item:hover { background: #1a1a2e; }
        .request-item.selected { background: #0f3460; border-left: 3px solid #00d9ff; }
        .request-item .method {
            display: inline-block;
            padding: 2px 6px;
            border-radius: 3px;
            font-size: 10px;
            font-weight: bold;
            margin-right: 8px;
        }
        .method.GET { background: #28a745; }
        .method.POST { background: #ffc107; color: #000; }
        .method.PUT { background: #17a2b8; }
        .method.DELETE { background: #dc3545; }
        .method.PATCH { background: #6f42c1; }
        .request-item .path {
            font-family: monospace;
            font-size: 13px;
            word-break: break-all;
        }
        .request-item .meta {
            margin-top: 4px;
            font-size: 11px;
            color: #888;
        }
        .request-item .status {
            display: inline-block;
            padding: 1px 4px;
            border-radius: 2px;
            margin-left: 8px;
        }
        .status.s2xx { background: #28a745; }
        .status.s3xx { background: #17a2b8; }
        .status.s4xx { background: #ffc107; color: #000; }
        .status.s5xx { background: #dc3545; }
        .status.pending { background: #6c757d; }
        .detail-panel {
            flex: 1;
            display: flex;
            flex-direction: column;
            overflow: hidden;
        }
        .detail-header {
            padding: 16px;
            background: #16213e;
            border-bottom: 1px solid #0f3460;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .detail-header h2 { font-size: 16px; }
        .btn {
            background: #0f3460;
            color: #00d9ff;
            border: 1px solid #00d9ff;
            padding: 8px 16px;
            border-radius: 4px;
            cursor: pointer;
            font-size: 12px;
            transition: all 0.2s;
        }
        .btn:hover { background: #00d9ff; color: #000; }
        .btn.primary { background: #00d9ff; color: #000; }
        .btn.primary:hover { background: #00b8d4; }
        .tabs {
            display: flex;
            background: #16213e;
            border-bottom: 1px solid #0f3460;
        }
        .tab {
            padding: 12px 20px;
            cursor: pointer;
            border-bottom: 2px solid transparent;
            transition: all 0.2s;
        }
        .tab:hover { background: #1a1a2e; }
        .tab.active { border-bottom-color: #00d9ff; color: #00d9ff; }
        .detail-content {
            flex: 1;
            overflow-y: auto;
            padding: 16px;
        }
        .section {
            margin-bottom: 24px;
        }
        .section h3 {
            font-size: 14px;
            color: #00d9ff;
            margin-bottom: 12px;
            padding-bottom: 8px;
            border-bottom: 1px solid #0f3460;
        }
        .kv-table {
            font-size: 12px;
        }
        .kv-row {
            display: flex;
            padding: 4px 0;
            border-bottom: 1px solid #0f3460;
        }
        .kv-key {
            width: 180px;
            color: #888;
            flex-shrink: 0;
        }
        .kv-value {
            font-family: monospace;
            word-break: break-all;
        }
        .body-preview {
            background: #1a1a2e;
            border: 1px solid #0f3460;
            border-radius: 4px;
            padding: 12px;
            font-family: monospace;
            font-size: 12px;
            white-space: pre-wrap;
            word-break: break-all;
            max-height: 400px;
            overflow-y: auto;
        }
        .empty-state {
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            height: 100%;
            color: #888;
        }
        .empty-state svg {
            width: 64px;
            height: 64px;
            margin-bottom: 16px;
            opacity: 0.5;
        }
        .stats-bar {
            padding: 8px 16px;
            background: #0f3460;
            font-size: 11px;
            color: #888;
            display: flex;
            gap: 16px;
        }
        .stats-bar .stat { display: flex; gap: 4px; }
        .stats-bar .stat-value { color: #00d9ff; }
        .replay-badge {
            background: #6f42c1;
            color: #fff;
            padding: 1px 4px;
            border-radius: 2px;
            font-size: 9px;
            margin-left: 4px;
        }
        .live-indicator {
            display: inline-block;
            width: 8px;
            height: 8px;
            background: #28a745;
            border-radius: 50%;
            margin-right: 8px;
            animation: pulse 2s infinite;
        }
        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.5; }
        }
    </style>
</head>
<body>
    <div class="sidebar">
        <div class="header">
            <h1><span class="live-indicator"></span>Instanton Inspector</h1>
            <div class="subtitle">Real-time request inspection</div>
        </div>
        <div class="filters">
            <input type="text" id="pathFilter" placeholder="Filter by path..." style="flex:1;">
            <select id="methodFilter">
                <option value="">All methods</option>
                <option value="GET">GET</option>
                <option value="POST">POST</option>
                <option value="PUT">PUT</option>
                <option value="DELETE">DELETE</option>
                <option value="PATCH">PATCH</option>
            </select>
        </div>
        <div class="stats-bar">
            <div class="stat">Total: <span class="stat-value" id="totalCount">0</span></div>
            <div class="stat">Success: <span class="stat-value" id="successCount">0</span></div>
            <div class="stat">Error: <span class="stat-value" id="errorCount">0</span></div>
        </div>
        <div class="request-list" id="requestList"></div>
    </div>
    <div class="detail-panel">
        <div id="detailContent"></div>
    </div>

    <script>
        const API_BASE = '';
        let requests = [];
        let selectedId = null;
        let ws = null;

        async function loadRequests() {
            try {
                const res = await fetch(`${API_BASE}/api/requests`);
                const data = await res.json();
                requests = data.requests || [];
                renderList();
                updateStats(data.stats || {});
            } catch (e) {
                console.error('Failed to load requests:', e);
            }
        }

        function renderList() {
            const list = document.getElementById('requestList');
            const pathFilter = document.getElementById('pathFilter').value.toLowerCase();
            const methodFilter = document.getElementById('methodFilter').value;

            const filtered = requests.filter(r => {
                if (pathFilter && !r.request.path.toLowerCase().includes(pathFilter)) return false;
                if (methodFilter && r.request.method !== methodFilter) return false;
                return true;
            });

            list.innerHTML = filtered.map(r => {
                const req = r.request;
                const resp = r.response;
                const statusClass = resp ? `s${Math.floor(resp.status_code / 100)}xx` : 'pending';
                const selected = req.id === selectedId ? 'selected' : '';
                const replay = req.is_replay ? '<span class="replay-badge">REPLAY</span>' : '';
                return `
                    <div class="request-item ${selected}" data-id="${req.id}" onclick="selectRequest('${req.id}')">
                        <div>
                            <span class="method ${req.method}">${req.method}</span>
                            <span class="path">${req.path}</span>
                            ${replay}
                        </div>
                        <div class="meta">
                            ${new Date(req.timestamp).toLocaleTimeString()}
                            ${resp ? `<span class="status ${statusClass}">${resp.status_code}</span>` : '<span class="status pending">pending</span>'}
                            ${req.duration_ms ? ` - ${req.duration_ms.toFixed(0)}ms` : ''}
                        </div>
                    </div>
                `;
            }).join('');
        }

        function updateStats(stats) {
            document.getElementById('totalCount').textContent = stats.total_requests || 0;
            document.getElementById('successCount').textContent = stats.success || 0;
            document.getElementById('errorCount').textContent = stats.error || 0;
        }

        async function selectRequest(id) {
            selectedId = id;
            renderList();
            const entry = requests.find(r => r.request.id === id);
            if (!entry) return;

            const req = entry.request;
            const resp = entry.response;

            document.getElementById('detailContent').innerHTML = `
                <div class="detail-header">
                    <h2>${req.method} ${req.path}</h2>
                    <div>
                        <button class="btn" onclick="replayRequest('${id}')">Replay</button>
                        <button class="btn" onclick="replayWithMods('${id}')">Replay with modifications</button>
                    </div>
                </div>
                <div class="tabs">
                    <div class="tab active" onclick="showTab(this, 'request')">Request</div>
                    <div class="tab" onclick="showTab(this, 'response')">Response</div>
                </div>
                <div class="detail-content" id="tabContent">
                    ${renderRequestTab(req)}
                </div>
            `;

            window.currentEntry = entry;
        }

        function renderRequestTab(req) {
            const headersHtml = Object.entries(req.headers || {}).map(([k, v]) =>
                `<div class="kv-row"><div class="kv-key">${k}</div><div class="kv-value">${v}</div></div>`
            ).join('');

            return `
                <div class="section">
                    <h3>General</h3>
                    <div class="kv-table">
                        <div class="kv-row"><div class="kv-key">Request ID</div><div class="kv-value">${req.id}</div></div>
                        <div class="kv-row"><div class="kv-key">Timestamp</div><div class="kv-value">${new Date(req.timestamp).toLocaleString()}</div></div>
                        <div class="kv-row"><div class="kv-key">Source IP</div><div class="kv-value">${req.source_ip || 'N/A'}</div></div>
                        <div class="kv-row"><div class="kv-key">Duration</div><div class="kv-value">${req.duration_ms ? req.duration_ms.toFixed(2) + 'ms' : 'N/A'}</div></div>
                        <div class="kv-row"><div class="kv-key">Content Type</div><div class="kv-value">${req.content_type || 'N/A'}</div></div>
                        <div class="kv-row"><div class="kv-key">Content Length</div><div class="kv-value">${req.content_length || 0} bytes</div></div>
                    </div>
                </div>
                <div class="section">
                    <h3>Headers</h3>
                    <div class="kv-table">${headersHtml || '<div class="kv-row">No headers</div>'}</div>
                </div>
                ${req.body ? `
                <div class="section">
                    <h3>Body</h3>
                    <pre class="body-preview">${escapeHtml(req.body)}</pre>
                </div>
                ` : ''}
            `;
        }

        function renderResponseTab(resp) {
            if (!resp) return '<div class="empty-state"><p>No response yet</p></div>';

            const headersHtml = Object.entries(resp.headers || {}).map(([k, v]) =>
                `<div class="kv-row"><div class="kv-key">${k}</div><div class="kv-value">${v}</div></div>`
            ).join('');

            return `
                <div class="section">
                    <h3>General</h3>
                    <div class="kv-table">
                        <div class="kv-row"><div class="kv-key">Status</div><div class="kv-value">${resp.status_code} ${resp.status_text || ''}</div></div>
                        <div class="kv-row"><div class="kv-key">Content Type</div><div class="kv-value">${resp.content_type || 'N/A'}</div></div>
                        <div class="kv-row"><div class="kv-key">Content Length</div><div class="kv-value">${resp.content_length || 0} bytes</div></div>
                    </div>
                </div>
                <div class="section">
                    <h3>Headers</h3>
                    <div class="kv-table">${headersHtml || '<div class="kv-row">No headers</div>'}</div>
                </div>
                ${resp.body ? `
                <div class="section">
                    <h3>Body</h3>
                    <pre class="body-preview">${escapeHtml(resp.body)}</pre>
                </div>
                ` : ''}
            `;
        }

        function showTab(el, tab) {
            document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
            el.classList.add('active');
            const content = document.getElementById('tabContent');
            if (tab === 'request') {
                content.innerHTML = renderRequestTab(window.currentEntry.request);
            } else {
                content.innerHTML = renderResponseTab(window.currentEntry.response);
            }
        }

        async function replayRequest(id) {
            try {
                const res = await fetch(`${API_BASE}/api/replay/${id}`, { method: 'POST' });
                const data = await res.json();
                if (data.success) {
                    alert('Request replayed successfully!');
                    loadRequests();
                } else {
                    alert('Replay failed: ' + (data.error || 'Unknown error'));
                }
            } catch (e) {
                alert('Replay failed: ' + e.message);
            }
        }

        function replayWithMods(id) {
            const entry = requests.find(r => r.request.id === id);
            if (!entry) return;
            const req = entry.request;

            const modal = document.createElement('div');
            modal.style.cssText = 'position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,0.8);display:flex;align-items:center;justify-content:center;z-index:1000;';
            modal.innerHTML = `
                <div style="background:#16213e;padding:24px;border-radius:8px;width:600px;max-height:80vh;overflow-y:auto;">
                    <h3 style="margin-bottom:16px;color:#00d9ff;">Replay with Modifications</h3>
                    <div style="margin-bottom:12px;">
                        <label style="display:block;margin-bottom:4px;color:#888;">Method</label>
                        <input id="modMethod" value="${req.method}" style="width:100%;padding:8px;background:#1a1a2e;border:1px solid #0f3460;color:#eee;border-radius:4px;">
                    </div>
                    <div style="margin-bottom:12px;">
                        <label style="display:block;margin-bottom:4px;color:#888;">Path</label>
                        <input id="modPath" value="${req.path}" style="width:100%;padding:8px;background:#1a1a2e;border:1px solid #0f3460;color:#eee;border-radius:4px;">
                    </div>
                    <div style="margin-bottom:12px;">
                        <label style="display:block;margin-bottom:4px;color:#888;">Body</label>
                        <textarea id="modBody" rows="6" style="width:100%;padding:8px;background:#1a1a2e;border:1px solid #0f3460;color:#eee;border-radius:4px;font-family:monospace;">${escapeHtml(req.body || '')}</textarea>
                    </div>
                    <div style="display:flex;gap:8px;justify-content:flex-end;">
                        <button class="btn" onclick="this.closest('div').parentElement.remove()">Cancel</button>
                        <button class="btn primary" onclick="submitReplayMods('${id}')">Replay</button>
                    </div>
                </div>
            `;
            document.body.appendChild(modal);
        }

        async function submitReplayMods(id) {
            const method = document.getElementById('modMethod').value;
            const path = document.getElementById('modPath').value;
            const body = document.getElementById('modBody').value;

            try {
                const res = await fetch(`${API_BASE}/api/replay/${id}`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ method, path, body })
                });
                const data = await res.json();
                document.querySelector('[style*="position:fixed"]').remove();
                if (data.success) {
                    alert('Request replayed successfully!');
                    loadRequests();
                } else {
                    alert('Replay failed: ' + (data.error || 'Unknown error'));
                }
            } catch (e) {
                alert('Replay failed: ' + e.message);
            }
        }

        function escapeHtml(str) {
            if (!str) return '';
            return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
        }

        function connectWebSocket() {
            const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
            ws = new WebSocket(`${protocol}//${window.location.host}/ws`);

            ws.onmessage = (event) => {
                const data = JSON.parse(event.data);
                if (data.type === 'traffic') {
                    // Add or update request
                    const idx = requests.findIndex(r => r.request.id === data.entry.request.id);
                    if (idx >= 0) {
                        requests[idx] = data.entry;
                    } else {
                        requests.unshift(data.entry);
                    }
                    renderList();
                    if (data.stats) updateStats(data.stats);
                }
            };

            ws.onclose = () => {
                setTimeout(connectWebSocket, 2000);
            };
        }

        // Event listeners
        document.getElementById('pathFilter').addEventListener('input', renderList);
        document.getElementById('methodFilter').addEventListener('change', renderList);

        // Initial load
        loadRequests();
        connectWebSocket();

        // Show empty state initially
        document.getElementById('detailContent').innerHTML = `
            <div class="empty-state">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
                    <path d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/>
                </svg>
                <p>Select a request to view details</p>
            </div>
        `;
    </script>
</body>
</html>
"""


class InspectorServer:
    """Web server for the traffic inspector interface."""

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 4040,
        storage: TrafficStorage | None = None,
        replayer: RequestReplayer | None = None,
    ):
        self.host = host
        self.port = port
        self.storage = storage or get_traffic_storage()
        self.replayer = replayer or get_request_replayer()
        self._app: web.Application | None = None
        self._runner: web.AppRunner | None = None
        self._ws_clients: list[web.WebSocketResponse] = []
        self._traffic_task: asyncio.Task | None = None

    async def start(self) -> None:
        """Start the inspector server."""
        self._app = web.Application()
        self._app.router.add_get("/", self._handle_index)
        self._app.router.add_get("/ws", self._handle_websocket)
        self._app.router.add_get("/api/requests", self._handle_list_requests)
        self._app.router.add_get("/api/requests/{id}", self._handle_get_request)
        self._app.router.add_delete("/api/requests/{id}", self._handle_delete_request)
        self._app.router.add_post("/api/replay/{id}", self._handle_replay)
        self._app.router.add_get("/api/stats", self._handle_stats)
        self._app.router.add_post("/api/clear", self._handle_clear)

        self._runner = web.AppRunner(self._app)
        await self._runner.setup()

        site = web.TCPSite(self._runner, self.host, self.port)
        await site.start()

        # Start traffic update task
        self._traffic_task = asyncio.create_task(self._broadcast_traffic_updates())

        logger.info(
            "Inspector server started",
            url=f"http://{self.host}:{self.port}",
        )

    async def stop(self) -> None:
        """Stop the inspector server."""
        if self._traffic_task:
            self._traffic_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._traffic_task

        for ws in self._ws_clients:
            await ws.close()
        self._ws_clients.clear()

        if self._runner:
            await self._runner.cleanup()

        logger.info("Inspector server stopped")

    async def _broadcast_traffic_updates(self) -> None:
        """Broadcast traffic updates to WebSocket clients."""
        queue = self.storage.subscribe()
        try:
            while True:
                entry = await queue.get()
                stats = await self.storage.get_stats()
                message = json.dumps(
                    {
                        "type": "traffic",
                        "entry": {
                            "request": entry.request.to_dict(),
                            "response": entry.response.to_dict() if entry.response else None,
                        },
                        "stats": stats,
                    }
                )

                dead_clients = []
                for ws in self._ws_clients:
                    try:
                        await ws.send_str(message)
                    except Exception:
                        dead_clients.append(ws)

                for ws in dead_clients:
                    self._ws_clients.remove(ws)

        except asyncio.CancelledError:
            pass
        finally:
            self.storage.unsubscribe(queue)

    async def _handle_index(self, request: web.Request) -> web.Response:
        """Serve the inspector UI."""
        return web.Response(text=INSPECTOR_HTML, content_type="text/html")

    async def _handle_websocket(self, request: web.Request) -> web.WebSocketResponse:
        """Handle WebSocket connections for real-time updates."""
        ws = web.WebSocketResponse()
        await ws.prepare(request)
        self._ws_clients.append(ws)

        try:
            async for msg in ws:
                if msg.type == WSMsgType.TEXT:
                    # Handle client messages if needed
                    pass
                elif msg.type == WSMsgType.ERROR:
                    break
        finally:
            if ws in self._ws_clients:
                self._ws_clients.remove(ws)

        return ws

    async def _handle_list_requests(self, request: web.Request) -> web.Response:
        """List captured requests."""
        # Parse query parameters
        offset = int(request.query.get("offset", "0"))
        limit = int(request.query.get("limit", "100"))
        method = request.query.get("method")
        path_pattern = request.query.get("path")
        status = request.query.get("status")

        # Build filter
        filter_obj = None
        if method or path_pattern or status:
            filter_obj = RequestFilter(
                method=method,
                path_pattern=path_pattern,
                status=RequestStatus(status) if status else None,
            )

        entries = await self.storage.list_requests(
            filter=filter_obj,
            offset=offset,
            limit=limit,
        )

        stats = await self.storage.get_stats()

        return web.json_response(
            {
                "requests": [
                    {
                        "request": e.request.to_dict(),
                        "response": e.response.to_dict() if e.response else None,
                    }
                    for e in entries
                ],
                "stats": stats,
                "offset": offset,
                "limit": limit,
            }
        )

    async def _handle_get_request(self, request: web.Request) -> web.Response:
        """Get a specific request by ID."""
        try:
            request_id = UUID(request.match_info["id"])
        except ValueError:
            return web.json_response({"error": "Invalid request ID"}, status=400)

        entry = await self.storage.get_entry(request_id)
        if not entry:
            return web.json_response({"error": "Request not found"}, status=404)

        return web.json_response(
            {
                "request": entry.request.to_dict(),
                "response": entry.response.to_dict() if entry.response else None,
            }
        )

    async def _handle_delete_request(self, request: web.Request) -> web.Response:
        """Delete a specific request."""
        try:
            request_id = UUID(request.match_info["id"])
        except ValueError:
            return web.json_response({"error": "Invalid request ID"}, status=400)

        deleted = await self.storage.delete_request(request_id)
        if not deleted:
            return web.json_response({"error": "Request not found"}, status=404)

        return web.json_response({"success": True})

    async def _handle_replay(self, request: web.Request) -> web.Response:
        """Replay a captured request."""
        try:
            request_id = UUID(request.match_info["id"])
        except ValueError:
            return web.json_response({"error": "Invalid request ID"}, status=400)

        # Parse modifications from request body
        modifications: dict[str, Any] = {}
        if request.content_type == "application/json":
            with contextlib.suppress(json.JSONDecodeError):
                modifications = await request.json()

        # Build replay config
        config = ReplayConfig()
        if "method" in modifications:
            config.modify_method = modifications["method"]
        if "path" in modifications:
            config.modify_path = modifications["path"]
        if "body" in modifications:
            body = modifications["body"]
            config.modify_body = body.encode() if isinstance(body, str) else body
        if "headers" in modifications:
            config.modify_headers = modifications["headers"]
        if "target_host" in modifications:
            config.target_host = modifications["target_host"]
        if "target_port" in modifications:
            config.target_port = modifications["target_port"]

        result = await self.replayer.replay(request_id, config)

        return web.json_response(result.to_dict())

    async def _handle_stats(self, request: web.Request) -> web.Response:
        """Get traffic statistics."""
        stats = await self.storage.get_stats()
        return web.json_response(stats)

    async def _handle_clear(self, request: web.Request) -> web.Response:
        """Clear all captured traffic."""
        await self.storage.clear()
        return web.json_response({"success": True})


# Global inspector instance
_inspector: InspectorServer | None = None


def get_inspector() -> InspectorServer:
    """Get or create the global inspector server instance."""
    global _inspector
    if _inspector is None:
        _inspector = InspectorServer()
    return _inspector


def set_inspector(inspector: InspectorServer) -> None:
    """Set the global inspector server instance."""
    global _inspector
    _inspector = inspector
