"""High Availability connection manager for Instanton tunnel.

Features:
- Multi-connection pool (4 parallel connections by default)
- Replica coordination with health checking
- Geo-routing for optimal latency
- Automatic failover with connection migration
- Load balancing across connections
"""

from __future__ import annotations

import asyncio
import contextlib
import random
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import TYPE_CHECKING, Any, TypeVar
from uuid import uuid4

import structlog

if TYPE_CHECKING:
    from instanton.core.transport import Transport

logger = structlog.get_logger()

T = TypeVar("T")


# ==============================================================================
# Connection Health & State
# ==============================================================================


class ConnectionHealth(Enum):
    """Health status of a connection."""

    HEALTHY = auto()
    DEGRADED = auto()
    UNHEALTHY = auto()
    DEAD = auto()


class FailoverReason(Enum):
    """Reason for failover event."""

    HEARTBEAT_TIMEOUT = auto()
    CONNECTION_ERROR = auto()
    HIGH_LATENCY = auto()
    SERVER_SHUTDOWN = auto()
    MANUAL = auto()
    LOAD_BALANCING = auto()


@dataclass(slots=True)
class ConnectionMetrics:
    """Metrics for a single connection."""

    latency_ms: float = 0.0
    latency_avg_ms: float = 0.0
    latency_p99_ms: float = 0.0
    bytes_sent: int = 0
    bytes_received: int = 0
    messages_sent: int = 0
    messages_received: int = 0
    errors: int = 0
    last_heartbeat: float = 0.0
    uptime_seconds: float = 0.0
    health_score: float = 100.0  # 0-100


@dataclass(slots=True)
class EdgeServer:
    """Edge server endpoint for geo-routing."""

    host: str
    port: int
    region: str = "unknown"
    datacenter: str = "unknown"
    weight: int = 100  # Load balancing weight
    latency_hint_ms: float = 0.0  # Estimated latency from DNS/geo
    is_primary: bool = False


# ==============================================================================
# HA Connection
# ==============================================================================


@dataclass
class HAConnection:
    """A single HA connection in the pool."""

    id: str = field(default_factory=lambda: str(uuid4())[:8])
    transport: Transport | None = None
    server: EdgeServer | None = None
    metrics: ConnectionMetrics = field(default_factory=ConnectionMetrics)
    health: ConnectionHealth = ConnectionHealth.HEALTHY
    created_at: float = field(default_factory=time.monotonic)
    index: int = 0  # Position in connection pool

    # Latency samples for P99 calculation
    _latency_samples: list[float] = field(default_factory=list)

    def record_latency(self, latency_ms: float) -> None:
        """Record a latency sample."""
        self._latency_samples.append(latency_ms)
        if len(self._latency_samples) > 100:
            self._latency_samples.pop(0)

        self.metrics.latency_ms = latency_ms
        self.metrics.latency_avg_ms = sum(self._latency_samples) / len(self._latency_samples)

        sorted_samples = sorted(self._latency_samples)
        p99_idx = int(len(sorted_samples) * 0.99)
        self.metrics.latency_p99_ms = sorted_samples[min(p99_idx, len(sorted_samples) - 1)]

    def update_health(self) -> ConnectionHealth:
        """Update and return health status based on metrics."""
        score = 100.0

        # Latency scoring (target: < 5ms)
        if self.metrics.latency_avg_ms > 100:
            score -= 50
        elif self.metrics.latency_avg_ms > 50:
            score -= 30
        elif self.metrics.latency_avg_ms > 20:
            score -= 15
        elif self.metrics.latency_avg_ms > 10:
            score -= 5

        # Error rate scoring
        total_ops = self.metrics.messages_sent + self.metrics.messages_received
        if total_ops > 0:
            error_rate = self.metrics.errors / total_ops
            if error_rate > 0.1:
                score -= 40
            elif error_rate > 0.05:
                score -= 20
            elif error_rate > 0.01:
                score -= 10

        # Heartbeat scoring
        time_since_heartbeat = time.monotonic() - self.metrics.last_heartbeat
        if self.metrics.last_heartbeat > 0:
            if time_since_heartbeat > 60:
                score -= 50
            elif time_since_heartbeat > 30:
                score -= 20
            elif time_since_heartbeat > 15:
                score -= 10

        self.metrics.health_score = max(0, score)

        # Determine health status
        if score >= 80:
            self.health = ConnectionHealth.HEALTHY
        elif score >= 50:
            self.health = ConnectionHealth.DEGRADED
        elif score > 0:
            self.health = ConnectionHealth.UNHEALTHY
        else:
            self.health = ConnectionHealth.DEAD

        return self.health


# ==============================================================================
# Load Balancing Strategies
# ==============================================================================


class LoadBalanceStrategy(Enum):
    """Load balancing strategy."""

    ROUND_ROBIN = auto()
    LEAST_LATENCY = auto()
    LEAST_LOAD = auto()
    WEIGHTED = auto()
    RANDOM = auto()


class LoadBalancer:
    """Connection load balancer."""

    def __init__(self, strategy: LoadBalanceStrategy = LoadBalanceStrategy.LEAST_LATENCY) -> None:
        self.strategy = strategy
        self._rr_index = 0

    def select(self, connections: list[HAConnection]) -> HAConnection | None:
        """Select best connection based on strategy."""
        healthy = [c for c in connections if c.health != ConnectionHealth.DEAD]
        if not healthy:
            return None

        if self.strategy == LoadBalanceStrategy.ROUND_ROBIN:
            self._rr_index = (self._rr_index + 1) % len(healthy)
            return healthy[self._rr_index]

        elif self.strategy == LoadBalanceStrategy.LEAST_LATENCY:
            return min(healthy, key=lambda c: c.metrics.latency_avg_ms or float("inf"))

        elif self.strategy == LoadBalanceStrategy.LEAST_LOAD:
            return min(healthy, key=lambda c: c.metrics.messages_sent)

        elif self.strategy == LoadBalanceStrategy.WEIGHTED:
            total_weight = sum(c.server.weight if c.server else 100 for c in healthy)
            r = random.random() * total_weight
            cumulative = 0.0
            for conn in healthy:
                weight = conn.server.weight if conn.server else 100
                cumulative += weight
                if r <= cumulative:
                    return conn
            return healthy[-1]

        else:  # RANDOM
            return random.choice(healthy)


# ==============================================================================
# HA Connection Manager
# ==============================================================================


class HAConnectionManager:
    """High Availability connection manager.

    Features:
    - Multi-connection pool (4 parallel connections by default, configurable)
    - Automatic health checking
    - Transparent failover
    - Load balancing
    - Connection migration
    """

    DEFAULT_POOL_SIZE = 4  # Default multi-connection pool size

    def __init__(
        self,
        *,
        pool_size: int = DEFAULT_POOL_SIZE,
        heartbeat_interval: float = 5.0,
        heartbeat_timeout: float = 10.0,
        reconnect_delay: float = 1.0,
        max_reconnect_delay: float = 30.0,
        load_balance_strategy: LoadBalanceStrategy = LoadBalanceStrategy.LEAST_LATENCY,
        enable_geo_routing: bool = True,
    ) -> None:
        self.pool_size = pool_size
        self.heartbeat_interval = heartbeat_interval
        self.heartbeat_timeout = heartbeat_timeout
        self.reconnect_delay = reconnect_delay
        self.max_reconnect_delay = max_reconnect_delay
        self.enable_geo_routing = enable_geo_routing

        # Connection pool
        self._connections: list[HAConnection] = []
        self._primary_index = 0

        # Edge servers (for geo-routing)
        self._edge_servers: list[EdgeServer] = []

        # Load balancer
        self._load_balancer = LoadBalancer(load_balance_strategy)

        # Tasks
        self._health_check_task: asyncio.Task[Any] | None = None
        self._reconnect_tasks: dict[str, asyncio.Task[Any]] = {}

        # Callbacks
        self._on_failover: list[Callable[[HAConnection, HAConnection, FailoverReason], Any]] = []
        self._on_health_change: list[Callable[[HAConnection, ConnectionHealth], Any]] = []

        # State
        self._running = False
        self._shutdown_event = asyncio.Event()

        # Transport factory (set by user)
        self._transport_factory: Callable[[], Transport] | None = None

        # Connection address
        self._server_addr: str = ""

    def set_transport_factory(self, factory: Callable[[], Transport]) -> None:
        """Set the transport factory for creating connections."""
        self._transport_factory = factory

    def add_edge_server(self, server: EdgeServer) -> None:
        """Add an edge server for geo-routing."""
        self._edge_servers.append(server)
        # Sort by weight (highest first) and latency hint (lowest first)
        self._edge_servers.sort(key=lambda s: (-s.weight, s.latency_hint_ms))

    def on_failover(
        self, callback: Callable[[HAConnection, HAConnection, FailoverReason], Any]
    ) -> None:
        """Register failover callback."""
        self._on_failover.append(callback)

    def on_health_change(self, callback: Callable[[HAConnection, ConnectionHealth], Any]) -> None:
        """Register health change callback."""
        self._on_health_change.append(callback)

    async def start(self, server_addr: str) -> None:
        """Start the HA connection manager.

        Establishes initial connection pool and starts health monitoring.
        """
        if self._transport_factory is None:
            raise RuntimeError("Transport factory not set")

        self._server_addr = server_addr
        self._running = True
        self._shutdown_event.clear()

        logger.info(
            "Starting HA connection manager",
            pool_size=self.pool_size,
            server=server_addr,
        )

        # Establish initial connections
        await self._establish_pool()

        # Start health check task
        self._health_check_task = asyncio.create_task(self._health_check_loop())

        logger.info(
            "HA connection manager started",
            active_connections=len([c for c in self._connections if c.transport]),
        )

    async def stop(self) -> None:
        """Stop the HA connection manager."""
        self._running = False
        self._shutdown_event.set()

        # Cancel health check
        if self._health_check_task:
            self._health_check_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._health_check_task

        # Cancel reconnect tasks
        for task in self._reconnect_tasks.values():
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task

        # Close all connections
        for conn in self._connections:
            if conn.transport:
                with contextlib.suppress(Exception):
                    await conn.transport.close()

        self._connections.clear()
        logger.info("HA connection manager stopped")

    async def _establish_pool(self) -> None:
        """Establish initial connection pool."""
        # Create connection tasks in parallel
        tasks = [self._create_connection(i) for i in range(self.pool_size)]
        await asyncio.gather(*tasks, return_exceptions=True)

    async def _create_connection(self, index: int) -> HAConnection | None:
        """Create a single connection."""
        if not self._transport_factory:
            return None

        conn = HAConnection(index=index)
        self._connections.append(conn)

        try:
            # Select edge server if geo-routing enabled
            if self.enable_geo_routing and self._edge_servers:
                # Round-robin through edge servers for distribution
                server_idx = index % len(self._edge_servers)
                conn.server = self._edge_servers[server_idx]
                addr = f"{conn.server.host}:{conn.server.port}"
            else:
                addr = self._server_addr

            # Create transport and connect
            transport = self._transport_factory()
            await transport.connect(addr)

            conn.transport = transport
            conn.metrics.last_heartbeat = time.monotonic()
            conn.health = ConnectionHealth.HEALTHY

            logger.info(
                "HA connection established",
                conn_id=conn.id,
                index=index,
                server=addr,
            )
            return conn

        except Exception as e:
            logger.error(
                "Failed to establish HA connection",
                conn_id=conn.id,
                index=index,
                error=str(e),
            )
            conn.health = ConnectionHealth.DEAD
            # Schedule reconnection
            self._schedule_reconnect(conn)
            return None

    def _schedule_reconnect(self, conn: HAConnection) -> None:
        """Schedule reconnection for a failed connection."""
        if conn.id in self._reconnect_tasks:
            return  # Already scheduled

        task = asyncio.create_task(self._reconnect_loop(conn))
        self._reconnect_tasks[conn.id] = task

    async def _reconnect_loop(self, conn: HAConnection) -> None:
        """Reconnection loop with exponential backoff."""
        attempt = 0
        delay = self.reconnect_delay

        while self._running and not self._shutdown_event.is_set():
            attempt += 1
            delay = min(delay * 2, self.max_reconnect_delay)

            logger.info(
                "Attempting reconnection",
                conn_id=conn.id,
                attempt=attempt,
                delay=delay,
            )

            await asyncio.sleep(delay)

            if not self._running:
                break

            try:
                if self._transport_factory is None:
                    continue

                # Select edge server
                if self.enable_geo_routing and self._edge_servers:
                    server_idx = conn.index % len(self._edge_servers)
                    conn.server = self._edge_servers[server_idx]
                    addr = f"{conn.server.host}:{conn.server.port}"
                else:
                    addr = self._server_addr

                # Create new transport
                transport = self._transport_factory()
                await transport.connect(addr)

                # Close old transport if exists
                if conn.transport:
                    with contextlib.suppress(Exception):
                        await conn.transport.close()

                conn.transport = transport
                conn.metrics.last_heartbeat = time.monotonic()
                conn.metrics.errors = 0
                conn.health = ConnectionHealth.HEALTHY

                logger.info(
                    "Reconnection successful",
                    conn_id=conn.id,
                    attempt=attempt,
                )

                # Remove from reconnect tasks
                self._reconnect_tasks.pop(conn.id, None)
                return

            except Exception as e:
                logger.warning(
                    "Reconnection attempt failed",
                    conn_id=conn.id,
                    attempt=attempt,
                    error=str(e),
                )
                conn.metrics.errors += 1
                continue

    async def _health_check_loop(self) -> None:
        """Periodic health check for all connections."""
        while self._running:
            try:
                await asyncio.sleep(self.heartbeat_interval)

                if not self._running:
                    break

                # Check each connection
                for conn in self._connections:
                    old_health = conn.health
                    new_health = conn.update_health()

                    # Fire health change callback
                    if old_health != new_health:
                        await self._fire_health_change(conn, new_health)

                    # Handle dead connections
                    if new_health == ConnectionHealth.DEAD:
                        await self._handle_dead_connection(conn)

                # Log pool status
                healthy = sum(1 for c in self._connections if c.health == ConnectionHealth.HEALTHY)
                degraded = sum(
                    1 for c in self._connections if c.health == ConnectionHealth.DEGRADED
                )

                logger.debug(
                    "HA pool health check",
                    total=len(self._connections),
                    healthy=healthy,
                    degraded=degraded,
                )

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("Health check error", error=str(e))

    async def _handle_dead_connection(self, conn: HAConnection) -> None:
        """Handle a dead connection."""
        logger.warning("Connection marked dead", conn_id=conn.id)

        # Close transport
        if conn.transport:
            with contextlib.suppress(Exception):
                await conn.transport.close()
            conn.transport = None

        # Schedule reconnection
        self._schedule_reconnect(conn)

        # Trigger failover if this was primary
        if conn.index == self._primary_index:
            await self._failover(FailoverReason.CONNECTION_ERROR)

    async def _failover(self, reason: FailoverReason) -> None:
        """Perform failover to next healthy connection."""
        old_primary = self._connections[self._primary_index] if self._connections else None

        # Find next healthy connection
        for i, conn in enumerate(self._connections):
            is_usable = conn.health in (ConnectionHealth.HEALTHY, ConnectionHealth.DEGRADED)
            if is_usable and i != self._primary_index:
                self._primary_index = i
                new_primary = conn

                logger.info(
                    "Failover completed",
                    old=old_primary.id if old_primary else None,
                    new=new_primary.id,
                    reason=reason.name,
                )

                # Fire callbacks
                if old_primary:
                    await self._fire_failover(old_primary, new_primary, reason)
                return

        logger.error("No healthy connections for failover")

    async def _fire_failover(
        self,
        old: HAConnection,
        new: HAConnection,
        reason: FailoverReason,
    ) -> None:
        """Fire failover callbacks."""
        for callback in self._on_failover:
            try:
                result = callback(old, new, reason)
                if asyncio.iscoroutine(result):
                    await result
            except Exception as e:
                logger.warning("Failover callback error", error=str(e))

    async def _fire_health_change(
        self,
        conn: HAConnection,
        health: ConnectionHealth,
    ) -> None:
        """Fire health change callbacks."""
        for callback in self._on_health_change:
            try:
                result = callback(conn, health)
                if asyncio.iscoroutine(result):
                    await result
            except Exception as e:
                logger.warning("Health change callback error", error=str(e))

    # ==============================================================================
    # Public API
    # ==============================================================================

    def get_connection(self) -> HAConnection | None:
        """Get the best available connection.

        Uses load balancing to select optimal connection.
        """
        return self._load_balancer.select(self._connections)

    def get_primary(self) -> HAConnection | None:
        """Get the primary connection."""
        if not self._connections:
            return None
        return self._connections[self._primary_index]

    def get_all_connections(self) -> list[HAConnection]:
        """Get all connections in the pool."""
        return list(self._connections)

    def get_healthy_count(self) -> int:
        """Get count of healthy connections."""
        return sum(1 for c in self._connections if c.health == ConnectionHealth.HEALTHY)

    async def send(self, data: bytes, conn: HAConnection | None = None) -> bool:
        """Send data through best available connection.

        Args:
            data: Data to send
            conn: Specific connection to use (optional)

        Returns:
            True if sent successfully, False otherwise
        """
        if conn is None:
            conn = self.get_connection()

        if conn is None or conn.transport is None:
            logger.error("No available connection for send")
            return False

        try:
            start = time.monotonic()
            await conn.transport.send(data)
            latency = (time.monotonic() - start) * 1000

            conn.record_latency(latency)
            conn.metrics.messages_sent += 1
            conn.metrics.bytes_sent += len(data)

            return True

        except Exception as e:
            logger.error("Send failed", conn_id=conn.id, error=str(e))
            conn.metrics.errors += 1
            conn.update_health()

            # Try failover
            if conn.health == ConnectionHealth.DEAD:
                await self._handle_dead_connection(conn)

            return False

    async def recv(self, conn: HAConnection | None = None) -> bytes | None:
        """Receive data from connection.

        Args:
            conn: Specific connection to receive from (optional)

        Returns:
            Received data or None
        """
        if conn is None:
            conn = self.get_connection()

        if conn is None or conn.transport is None:
            return None

        try:
            data = await conn.transport.recv()
            if data:
                conn.metrics.messages_received += 1
                conn.metrics.bytes_received += len(data)
                conn.metrics.last_heartbeat = time.monotonic()
            return data

        except Exception as e:
            logger.error("Recv failed", conn_id=conn.id, error=str(e))
            conn.metrics.errors += 1
            return None

    def record_heartbeat(self, conn: HAConnection) -> None:
        """Record successful heartbeat for connection."""
        conn.metrics.last_heartbeat = time.monotonic()

    @property
    def stats(self) -> dict[str, Any]:
        """Get HA manager statistics."""
        return {
            "pool_size": self.pool_size,
            "active_connections": len([c for c in self._connections if c.transport]),
            "healthy_connections": self.get_healthy_count(),
            "primary_index": self._primary_index,
            "connections": [
                {
                    "id": c.id,
                    "index": c.index,
                    "health": c.health.name,
                    "latency_ms": c.metrics.latency_avg_ms,
                    "health_score": c.metrics.health_score,
                    "messages_sent": c.metrics.messages_sent,
                    "messages_received": c.metrics.messages_received,
                    "errors": c.metrics.errors,
                }
                for c in self._connections
            ],
        }


# ==============================================================================
# Geo-Routing Utilities
# ==============================================================================


class GeoRouter:
    """Geo-routing for optimal edge server selection.

    Uses latency hints and health data to route to best edge.
    """

    def __init__(self) -> None:
        self._edge_latencies: dict[str, float] = {}
        self._edge_health: dict[str, float] = {}

    def record_latency(self, edge_id: str, latency_ms: float) -> None:
        """Record latency measurement for an edge."""
        # Exponential moving average
        current = self._edge_latencies.get(edge_id, latency_ms)
        self._edge_latencies[edge_id] = current * 0.7 + latency_ms * 0.3

    def get_best_edge(self, edges: list[EdgeServer]) -> EdgeServer | None:
        """Get the best edge server based on latency."""
        if not edges:
            return None

        def score(edge: EdgeServer) -> float:
            edge_id = f"{edge.host}:{edge.port}"
            latency = self._edge_latencies.get(edge_id, edge.latency_hint_ms)
            health = self._edge_health.get(edge_id, 100.0)
            # Lower is better: latency - (health bonus)
            return latency - (health / 10)

        return min(edges, key=score)

    def mark_unhealthy(self, edge_id: str) -> None:
        """Mark an edge as unhealthy."""
        self._edge_health[edge_id] = max(0, self._edge_health.get(edge_id, 100) - 20)

    def mark_healthy(self, edge_id: str) -> None:
        """Mark an edge as healthy."""
        self._edge_health[edge_id] = min(100, self._edge_health.get(edge_id, 100) + 10)
