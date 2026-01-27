"""DashboardBroadcaster - Manages WebSocket connections for dashboard updates."""

from __future__ import annotations

import asyncio
import json
import weakref
from typing import TYPE_CHECKING, Any

import structlog
from aiohttp import web

if TYPE_CHECKING:
    from instanton.observability.dashboard.collector import MetricsCollector

logger = structlog.get_logger()


class DashboardBroadcaster:
    """Broadcasts dashboard updates to connected WebSocket clients.

    Features:
    - Track WebSocket connections with weakref for auto-cleanup
    - Encode message once, send to all clients efficiently
    - Per-client message queues for backpressure handling
    - Automatic cleanup of dead connections
    """

    def __init__(
        self,
        collector: MetricsCollector,
        update_interval: float = 1.0,
    ):
        """Initialize the broadcaster.

        Args:
            collector: MetricsCollector instance for data.
            update_interval: How often to broadcast updates (seconds).
        """
        self._collector = collector
        self._update_interval = update_interval

        # Track connected clients
        self._clients: weakref.WeakSet[web.WebSocketResponse] = weakref.WeakSet()

        # Per-client message queues for backpressure
        self._queues: dict[int, asyncio.Queue[str]] = {}

        # Task management
        self._running = False
        self._broadcast_task: asyncio.Task | None = None
        self._sender_tasks: dict[int, asyncio.Task] = {}

    @property
    def client_count(self) -> int:
        """Return the number of connected clients."""
        return len(list(self._clients))

    async def start(self) -> None:
        """Start the broadcast loop."""
        if self._running:
            return
        self._running = True
        self._broadcast_task = asyncio.create_task(self._broadcast_loop())

    async def stop(self) -> None:
        """Stop the broadcast loop and close all connections."""
        self._running = False

        if self._broadcast_task:
            self._broadcast_task.cancel()
            try:
                await self._broadcast_task
            except asyncio.CancelledError:
                pass
            self._broadcast_task = None

        # Cancel all sender tasks
        for task in list(self._sender_tasks.values()):
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
        self._sender_tasks.clear()

        # Close all client connections
        for ws in list(self._clients):
            try:
                await ws.close()
            except Exception:
                pass

        self._queues.clear()

    async def add_client(self, ws: web.WebSocketResponse) -> None:
        """Add a new WebSocket client.

        Args:
            ws: The WebSocket connection to add.
        """
        self._clients.add(ws)
        client_id = id(ws)

        # Create message queue for this client
        self._queues[client_id] = asyncio.Queue(maxsize=10)

        # Start sender task for this client
        self._sender_tasks[client_id] = asyncio.create_task(self._client_sender(ws, client_id))

        # Send initial state immediately
        await self._send_initial_state(ws)

        logger.debug("Dashboard client connected", client_id=client_id)

    async def remove_client(self, ws: web.WebSocketResponse) -> None:
        """Remove a WebSocket client.

        Args:
            ws: The WebSocket connection to remove.
        """
        client_id = id(ws)
        self._clients.discard(ws)

        # Cancel sender task
        task = self._sender_tasks.pop(client_id, None)
        if task:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

        # Remove queue
        self._queues.pop(client_id, None)

        logger.debug("Dashboard client disconnected", client_id=client_id)

    async def _send_initial_state(self, ws: web.WebSocketResponse) -> None:
        """Send initial state to a newly connected client."""
        try:
            history = self._collector.get_history()
            tunnels = self._collector.get_tunnel_list()

            init_message = json.dumps(
                {
                    "type": "init",
                    "history": history,
                    "tunnels": tunnels,
                }
            )

            await ws.send_str(init_message)
        except Exception as e:
            logger.warning("Failed to send initial state", error=str(e))

    async def _broadcast_loop(self) -> None:
        """Main broadcast loop - sends updates to all clients."""
        while self._running:
            try:
                await asyncio.sleep(self._update_interval)

                if not self._clients:
                    continue

                # Get latest snapshot
                snapshot = self._collector.get_latest_snapshot()
                if not snapshot:
                    continue

                # Prepare update message (encode once)
                update_message = json.dumps(
                    {
                        "type": "update",
                        "snapshot": snapshot.to_dict(),
                    }
                )

                # Queue message for all clients
                await self._queue_broadcast(update_message)

                # Periodically send tunnel updates (every 5 seconds)
                if int(snapshot.timestamp) % 5 == 0:
                    tunnels = self._collector.get_tunnel_list()
                    tunnel_message = json.dumps(
                        {
                            "type": "tunnels",
                            "tunnels": tunnels,
                        }
                    )
                    await self._queue_broadcast(tunnel_message)

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("Broadcast loop error", error=str(e))

    async def _queue_broadcast(self, message: str) -> None:
        """Queue a message for all connected clients.

        Args:
            message: JSON message to broadcast.
        """
        dead_clients: list[int] = []

        for client_id, queue in list(self._queues.items()):
            try:
                # Non-blocking put - drop message if queue is full (backpressure)
                queue.put_nowait(message)
            except asyncio.QueueFull:
                # Client is too slow, might be dead
                logger.debug("Client queue full, dropping message", client_id=client_id)

        # Clean up any detected dead clients
        for client_id in dead_clients:
            self._queues.pop(client_id, None)
            task = self._sender_tasks.pop(client_id, None)
            if task:
                task.cancel()

    async def _client_sender(self, ws: web.WebSocketResponse, client_id: int) -> None:
        """Send queued messages to a specific client.

        Args:
            ws: WebSocket connection.
            client_id: Unique client identifier.
        """
        queue = self._queues.get(client_id)
        if not queue:
            return

        try:
            while self._running and not ws.closed:
                try:
                    # Wait for a message with timeout
                    message = await asyncio.wait_for(queue.get(), timeout=30.0)
                    await ws.send_str(message)
                except TimeoutError:
                    # Send ping to keep connection alive
                    continue
                except ConnectionResetError:
                    break
                except Exception as e:
                    logger.debug("Client send error", client_id=client_id, error=str(e))
                    break
        except asyncio.CancelledError:
            pass
        finally:
            # Client is done, clean up
            self._queues.pop(client_id, None)
            self._sender_tasks.pop(client_id, None)

    async def handle_client_message(self, ws: web.WebSocketResponse, data: str) -> None:
        """Handle incoming message from a dashboard client.

        Args:
            ws: WebSocket connection.
            data: Raw message data.
        """
        try:
            message = json.loads(data)
            msg_type = message.get("type")

            if msg_type == "tunnel_details":
                subdomain = message.get("subdomain")
                if subdomain:
                    details = self._get_tunnel_details(subdomain)
                    response = json.dumps(
                        {
                            "type": "tunnel_details",
                            "subdomain": subdomain,
                            "details": details,
                        }
                    )
                    await ws.send_str(response)

        except json.JSONDecodeError:
            logger.warning("Invalid JSON from dashboard client")
        except Exception as e:
            logger.warning("Error handling client message", error=str(e))

    def _get_tunnel_details(self, subdomain: str) -> dict[str, Any] | None:
        """Get detailed information about a specific tunnel.

        Args:
            subdomain: The tunnel subdomain.

        Returns:
            Detailed tunnel info or None if not found.
        """
        from datetime import UTC, datetime

        now = datetime.now(UTC)

        # Check HTTP tunnels
        tunnel = self._collector._relay._tunnels.get(subdomain)
        if tunnel:
            return {
                "subdomain": subdomain,
                "type": "http",
                "id": str(tunnel.id),
                "source_ip": tunnel.source_ip,
                "local_port": tunnel.local_port,
                "request_count": tunnel.request_count,
                "bytes_sent": tunnel.bytes_sent,
                "bytes_received": tunnel.bytes_received,
                "connected_at": tunnel.connected_at.isoformat(),
                "last_activity": tunnel.last_activity.isoformat(),
                "uptime_seconds": (now - tunnel.connected_at).total_seconds(),
                "compression": tunnel.compression.name if tunnel.compression else "NONE",
            }

        # Check TCP tunnels
        for port, t in self._collector._relay._tcp_tunnels.items():
            if t.subdomain == subdomain or subdomain == f"tcp-{port}":
                return {
                    "subdomain": t.subdomain,
                    "type": "tcp",
                    "id": str(t.id),
                    "port": port,
                    "source_ip": t.source_ip,
                    "local_port": t.local_port,
                    "request_count": t.request_count,
                    "bytes_sent": t.bytes_sent,
                    "bytes_received": t.bytes_received,
                    "connected_at": t.connected_at.isoformat(),
                    "last_activity": t.last_activity.isoformat(),
                    "uptime_seconds": (now - t.connected_at).total_seconds(),
                }

        # Check UDP tunnels
        for port, t in self._collector._relay._udp_tunnels.items():
            if t.subdomain == subdomain or subdomain == f"udp-{port}":
                return {
                    "subdomain": t.subdomain,
                    "type": "udp",
                    "id": str(t.id),
                    "port": port,
                    "source_ip": t.source_ip,
                    "local_port": t.local_port,
                    "request_count": t.request_count,
                    "bytes_sent": t.bytes_sent,
                    "bytes_received": t.bytes_received,
                    "connected_at": t.connected_at.isoformat(),
                    "last_activity": t.last_activity.isoformat(),
                    "uptime_seconds": (now - t.connected_at).total_seconds(),
                }

        return None
