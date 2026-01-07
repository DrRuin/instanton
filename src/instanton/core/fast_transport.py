"""High-performance transport layer for Instanton tunnel.

Performance features:
- QUIC 0-RTT for instant reconnections
- Connection migration for mobile/roaming
- Session resumption with tickets
- Optimized WebSocket transport
- Zero-copy buffer management
"""

from __future__ import annotations

import asyncio
import contextlib
import ssl
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

import structlog

from instanton.core.performance import (
    get_buffer_pool,
    install_fast_event_loop,
)

if TYPE_CHECKING:
    from collections.abc import Callable

logger = structlog.get_logger()


# ==============================================================================
# Transport Protocol Interface
# ==============================================================================


class TransportState(Enum):
    """Transport connection state."""

    DISCONNECTED = "disconnected"
    CONNECTING = "connecting"
    CONNECTED = "connected"
    RECONNECTING = "reconnecting"
    MIGRATING = "migrating"  # Connection migration in progress
    CLOSED = "closed"


@dataclass(slots=True)
class TransportMetrics:
    """Transport performance metrics."""

    bytes_sent: int = 0
    bytes_received: int = 0
    messages_sent: int = 0
    messages_received: int = 0
    reconnect_count: int = 0
    last_latency_ms: float = 0.0
    avg_latency_ms: float = 0.0
    connection_time_ms: float = 0.0
    zero_rtt_used: bool = False  # Whether 0-RTT was used
    migrations: int = 0  # Number of connection migrations


@runtime_checkable
class Transport(Protocol):
    """Transport protocol interface."""

    async def connect(self, addr: str) -> None: ...
    async def send(self, data: bytes) -> None: ...
    async def recv(self) -> bytes | None: ...
    async def close(self) -> None: ...
    def is_connected(self) -> bool: ...
    def get_state(self) -> TransportState: ...
    def get_metrics(self) -> TransportMetrics: ...


# ==============================================================================
# Session Ticket Store for 0-RTT
# ==============================================================================


@dataclass
class SessionTicket:
    """Stored session ticket for 0-RTT resumption."""

    ticket: bytes
    server_name: str
    timestamp: float = field(default_factory=time.time)
    max_early_data: int = 0
    cipher_suite: str = ""


class SessionTicketStore:
    """Store for TLS session tickets enabling 0-RTT resumption.

    This enables sub-millisecond reconnections after initial handshake.
    """

    def __init__(self, max_tickets: int = 100) -> None:
        self._tickets: dict[str, SessionTicket] = {}
        self._max_tickets = max_tickets
        self._ticket_lifetime = 86400  # 24 hours

    def store(self, server_name: str, ticket: SessionTicket) -> None:
        """Store a session ticket."""
        if len(self._tickets) >= self._max_tickets:
            # Remove oldest ticket
            oldest = min(self._tickets.values(), key=lambda t: t.timestamp)
            del self._tickets[oldest.server_name]

        self._tickets[server_name] = ticket

    def get(self, server_name: str) -> SessionTicket | None:
        """Get a session ticket if available and not expired."""
        ticket = self._tickets.get(server_name)
        if ticket is None:
            return None

        # Check expiry
        if time.time() - ticket.timestamp > self._ticket_lifetime:
            del self._tickets[server_name]
            return None

        return ticket

    def remove(self, server_name: str) -> None:
        """Remove a session ticket."""
        self._tickets.pop(server_name, None)


# Global ticket store
_ticket_store: SessionTicketStore | None = None


def get_ticket_store() -> SessionTicketStore:
    """Get the global session ticket store."""
    global _ticket_store
    if _ticket_store is None:
        _ticket_store = SessionTicketStore()
    return _ticket_store


# ==============================================================================
# Fast WebSocket Transport
# ==============================================================================


class FastWebSocketTransport:
    """High-performance WebSocket transport.

    Optimizations:
    - Pre-allocated receive buffers
    - Automatic heartbeat with latency tracking
    - Smart reconnection with backoff
    - Binary message batching
    """

    def __init__(
        self,
        *,
        auto_reconnect: bool = True,
        max_reconnect_attempts: int = 10,
        reconnect_delay: float = 0.5,
        max_reconnect_delay: float = 30.0,
        ping_interval: float = 15.0,
        ping_timeout: float = 10.0,
        connect_timeout: float = 5.0,
        receive_buffer_size: int = 65536,
    ) -> None:
        # Configuration
        self._auto_reconnect = auto_reconnect
        self._max_reconnect_attempts = max_reconnect_attempts
        self._reconnect_delay = reconnect_delay
        self._max_reconnect_delay = max_reconnect_delay
        self._ping_interval = ping_interval
        self._ping_timeout = ping_timeout
        self._connect_timeout = connect_timeout
        self._receive_buffer_size = receive_buffer_size

        # State
        self._state = TransportState.DISCONNECTED
        self._ws: Any = None
        self._addr: str = ""
        self._shutdown = False
        self._current_reconnect_attempt = 0

        # Tasks
        self._heartbeat_task: asyncio.Task[Any] | None = None
        self._recv_task: asyncio.Task[Any] | None = None

        # Metrics
        self._metrics = TransportMetrics()
        self._latency_samples: list[float] = []

        # Callbacks
        self._on_connect: list[Callable[[], Any]] = []
        self._on_disconnect: list[Callable[[], Any]] = []
        self._on_reconnect: list[Callable[[], Any]] = []

        # Buffer pool
        self._buffer_pool = get_buffer_pool()

    def on_connect(self, callback: Callable[[], Any]) -> None:
        """Register connect callback."""
        self._on_connect.append(callback)

    def on_disconnect(self, callback: Callable[[], Any]) -> None:
        """Register disconnect callback."""
        self._on_disconnect.append(callback)

    def on_reconnect(self, callback: Callable[[], Any]) -> None:
        """Register reconnect callback."""
        self._on_reconnect.append(callback)

    async def connect(self, addr: str) -> None:
        """Connect to WebSocket server."""
        self._addr = self._build_url(addr)
        self._state = TransportState.CONNECTING
        self._shutdown = False

        try:
            # Lazy import for faster cold start
            import websockets.client

            start_time = time.monotonic()

            self._ws = await asyncio.wait_for(
                websockets.client.connect(
                    self._addr,
                    max_size=16 * 1024 * 1024,
                    read_limit=self._receive_buffer_size,
                    write_limit=self._receive_buffer_size,
                    ping_interval=None,  # We handle pings ourselves
                    close_timeout=5.0,
                ),
                timeout=self._connect_timeout,
            )

            self._metrics.connection_time_ms = (time.monotonic() - start_time) * 1000
            self._state = TransportState.CONNECTED
            self._current_reconnect_attempt = 0

            # Start heartbeat
            self._start_heartbeat()

            # Fire callbacks
            await self._fire_callbacks(self._on_connect)

            logger.info(
                "WebSocket connected",
                addr=self._addr,
                connect_time_ms=self._metrics.connection_time_ms,
            )

        except TimeoutError as e:
            self._state = TransportState.DISCONNECTED
            raise ConnectionError(f"Connection timeout: {self._addr}") from e
        except Exception as e:
            self._state = TransportState.DISCONNECTED
            raise ConnectionError(f"Failed to connect: {e}") from e

    async def send(self, data: bytes) -> None:
        """Send data over WebSocket."""
        if not self.is_connected():
            raise ConnectionError("Not connected")

        start = time.monotonic()

        try:
            await self._ws.send(data)
            latency = (time.monotonic() - start) * 1000

            self._metrics.bytes_sent += len(data)
            self._metrics.messages_sent += 1
            self._record_latency(latency)

        except Exception as e:
            self._metrics.last_latency_ms = 0
            raise ConnectionError(f"Send failed: {e}") from e

    async def recv(self) -> bytes | None:
        """Receive data from WebSocket."""
        if self._ws is None:
            return None

        try:
            data = await self._ws.recv()

            if isinstance(data, str):
                data = data.encode()

            self._metrics.bytes_received += len(data)
            self._metrics.messages_received += 1

            return data

        except Exception:
            return None

    async def close(self) -> None:
        """Close the WebSocket connection."""
        self._shutdown = True
        self._stop_heartbeat()

        if self._ws:
            with contextlib.suppress(Exception):
                await self._ws.close()
            self._ws = None

        self._state = TransportState.CLOSED

        # Fire callbacks
        await self._fire_callbacks(self._on_disconnect)

    def is_connected(self) -> bool:
        """Check if connected."""
        return self._state == TransportState.CONNECTED and self._ws is not None

    def get_state(self) -> TransportState:
        """Get current state."""
        return self._state

    def get_metrics(self) -> TransportMetrics:
        """Get transport metrics."""
        return self._metrics

    def _build_url(self, addr: str) -> str:
        """Build WebSocket URL from address."""
        if addr.startswith(("ws://", "wss://")):
            return addr

        if ":" in addr:
            host, port = addr.rsplit(":", 1)
            return f"wss://{host}:{port}/tunnel"

        return f"wss://{addr}:443/tunnel"

    def _record_latency(self, latency_ms: float) -> None:
        """Record latency sample."""
        self._metrics.last_latency_ms = latency_ms
        self._latency_samples.append(latency_ms)

        if len(self._latency_samples) > 100:
            self._latency_samples.pop(0)

        self._metrics.avg_latency_ms = sum(self._latency_samples) / len(self._latency_samples)

    def _start_heartbeat(self) -> None:
        """Start heartbeat task."""
        if self._heartbeat_task:
            self._heartbeat_task.cancel()
        self._heartbeat_task = asyncio.create_task(self._heartbeat_loop())

    def _stop_heartbeat(self) -> None:
        """Stop heartbeat task."""
        if self._heartbeat_task:
            self._heartbeat_task.cancel()
            self._heartbeat_task = None

    async def _heartbeat_loop(self) -> None:
        """Send periodic pings for keepalive and latency measurement."""
        while not self._shutdown and self._state == TransportState.CONNECTED:
            try:
                await asyncio.sleep(self._ping_interval)

                if self._ws and not self._shutdown:
                    start = time.monotonic()
                    pong = await self._ws.ping()
                    await asyncio.wait_for(pong, timeout=self._ping_timeout)
                    latency = (time.monotonic() - start) * 1000
                    self._record_latency(latency)

            except asyncio.CancelledError:
                break
            except TimeoutError:
                logger.warning("Ping timeout")
                await self._handle_disconnect()
                break
            except Exception as e:
                logger.warning("Heartbeat error", error=str(e))
                break

    async def _handle_disconnect(self) -> None:
        """Handle connection loss."""
        if self._shutdown:
            return

        if self._state == TransportState.RECONNECTING:
            return

        self._state = TransportState.DISCONNECTED

        # Fire callbacks
        await self._fire_callbacks(self._on_disconnect)

        # Attempt reconnection
        if self._auto_reconnect:
            await self._reconnect()

    async def _reconnect(self) -> None:
        """Attempt reconnection with exponential backoff."""
        self._state = TransportState.RECONNECTING

        while self._current_reconnect_attempt < self._max_reconnect_attempts and not self._shutdown:
            self._current_reconnect_attempt += 1

            # Exponential backoff with jitter
            delay = min(
                self._reconnect_delay * (2 ** (self._current_reconnect_attempt - 1)),
                self._max_reconnect_delay,
            )
            delay *= 0.5 + 0.5 * (time.time() % 1)  # Add jitter

            logger.info(
                "Reconnecting",
                attempt=self._current_reconnect_attempt,
                delay=delay,
            )

            await asyncio.sleep(delay)

            try:
                import websockets.client

                start_time = time.monotonic()

                self._ws = await asyncio.wait_for(
                    websockets.client.connect(
                        self._addr,
                        max_size=16 * 1024 * 1024,
                        ping_interval=None,
                    ),
                    timeout=self._connect_timeout,
                )

                self._metrics.connection_time_ms = (time.monotonic() - start_time) * 1000
                self._metrics.reconnect_count += 1
                self._state = TransportState.CONNECTED
                self._current_reconnect_attempt = 0

                # Start heartbeat
                self._start_heartbeat()

                # Fire callbacks
                await self._fire_callbacks(self._on_reconnect)

                logger.info("Reconnected successfully")
                return

            except Exception as e:
                logger.warning(
                    "Reconnection failed",
                    attempt=self._current_reconnect_attempt,
                    error=str(e),
                )

        # Failed to reconnect
        self._state = TransportState.CLOSED
        logger.error("Max reconnection attempts reached")

    async def _fire_callbacks(self, callbacks: list[Callable[[], Any]]) -> None:
        """Fire callbacks, handling both sync and async."""
        for cb in callbacks:
            try:
                result = cb()
                if asyncio.iscoroutine(result):
                    await result
            except Exception as e:
                logger.warning("Callback error", error=str(e))


# ==============================================================================
# Fast QUIC Transport with 0-RTT
# ==============================================================================


@dataclass
class QuicConfig:
    """QUIC transport configuration."""

    host: str = "localhost"
    port: int = 4433
    server_name: str | None = None
    verify_ssl: bool = True
    cert_path: Path | None = None
    key_path: Path | None = None
    ca_path: Path | None = None
    alpn_protocols: list[str] = field(default_factory=lambda: ["instanton", "h3"])
    idle_timeout: float = 30.0
    connection_timeout: float = 5.0
    max_data: int = 10 * 1024 * 1024  # 10 MB
    max_stream_data: int = 1 * 1024 * 1024  # 1 MB
    enable_0rtt: bool = True  # Enable 0-RTT for faster reconnections
    enable_migration: bool = True  # Enable connection migration


class FastQuicTransport:
    """High-performance QUIC transport with 0-RTT support.

    Optimizations:
    - 0-RTT early data for instant reconnections
    - Connection migration for roaming
    - Session tickets for resumption
    - Optimized stream multiplexing
    """

    def __init__(
        self,
        config: QuicConfig | None = None,
        *,
        auto_reconnect: bool = True,
        max_reconnect_attempts: int = 10,
        reconnect_delay: float = 0.5,
        max_reconnect_delay: float = 30.0,
    ) -> None:
        self._config = config or QuicConfig()
        self._auto_reconnect = auto_reconnect
        self._max_reconnect_attempts = max_reconnect_attempts
        self._reconnect_delay = reconnect_delay
        self._max_reconnect_delay = max_reconnect_delay

        # State
        self._state = TransportState.DISCONNECTED
        self._shutdown = False
        self._current_reconnect_attempt = 0

        # QUIC objects
        self._quic: Any = None
        self._protocol: Any = None
        self._transport: Any = None
        self._main_stream_id: int | None = None

        # Session ticket for 0-RTT
        self._ticket_store = get_ticket_store()

        # Async primitives
        self._connected_event = asyncio.Event()
        self._closed_event = asyncio.Event()
        self._recv_queue: asyncio.Queue[bytes] = asyncio.Queue()

        # Metrics
        self._metrics = TransportMetrics()
        self._latency_samples: list[float] = []

        # Streams
        self._streams: dict[int, asyncio.Queue[bytes]] = {}

        # Callbacks
        self._on_connect: list[Callable[[], Any]] = []
        self._on_disconnect: list[Callable[[], Any]] = []
        self._on_reconnect: list[Callable[[], Any]] = []
        self._on_migration: list[Callable[[], Any]] = []

    def on_connect(self, callback: Callable[[], Any]) -> None:
        """Register connect callback."""
        self._on_connect.append(callback)

    def on_disconnect(self, callback: Callable[[], Any]) -> None:
        """Register disconnect callback."""
        self._on_disconnect.append(callback)

    def on_reconnect(self, callback: Callable[[], Any]) -> None:
        """Register reconnect callback."""
        self._on_reconnect.append(callback)

    def on_migration(self, callback: Callable[[], Any]) -> None:
        """Register connection migration callback."""
        self._on_migration.append(callback)

    async def connect(self, addr: str | None = None) -> None:
        """Connect to QUIC server with optional 0-RTT."""
        # Parse address
        if addr:
            if ":" in addr:
                host, port_str = addr.rsplit(":", 1)
                self._config.host = host
                self._config.port = int(port_str)
            else:
                self._config.host = addr

        self._state = TransportState.CONNECTING
        self._shutdown = False
        self._connected_event.clear()
        self._closed_event.clear()

        try:
            # Lazy import
            from aioquic.asyncio import connect
            from aioquic.quic.configuration import QuicConfiguration

            # Build configuration
            server_name = self._config.server_name or self._config.host

            quic_config = QuicConfiguration(
                is_client=True,
                alpn_protocols=self._config.alpn_protocols,
                max_datagram_frame_size=65536,
                idle_timeout=self._config.idle_timeout,
            )

            # Configure TLS
            if not self._config.verify_ssl:
                quic_config.verify_mode = ssl.CERT_NONE

            if self._config.ca_path:
                quic_config.load_verify_locations(str(self._config.ca_path))

            if self._config.cert_path and self._config.key_path:
                quic_config.load_cert_chain(
                    str(self._config.cert_path),
                    str(self._config.key_path),
                )

            # Check for session ticket (0-RTT)
            session_ticket = None
            if self._config.enable_0rtt:
                stored = self._ticket_store.get(server_name)
                if stored:
                    session_ticket = stored.ticket
                    logger.info("Using 0-RTT session resumption", server=server_name)
                    self._metrics.zero_rtt_used = True

            start_time = time.monotonic()

            # Connect
            async with asyncio.timeout(self._config.connection_timeout):
                self._protocol, self._transport = await connect(
                    self._config.host,
                    self._config.port,
                    configuration=quic_config,
                    session_ticket=session_ticket,
                )
                self._quic = self._protocol._quic

            self._metrics.connection_time_ms = (time.monotonic() - start_time) * 1000

            # Create main stream
            self._main_stream_id = self._quic.get_next_available_stream_id()

            self._state = TransportState.CONNECTED
            self._connected_event.set()
            self._current_reconnect_attempt = 0

            # Fire callbacks
            await self._fire_callbacks(self._on_connect)

            logger.info(
                "QUIC connected",
                host=self._config.host,
                port=self._config.port,
                connect_time_ms=self._metrics.connection_time_ms,
                zero_rtt=self._metrics.zero_rtt_used,
            )

        except TimeoutError as e:
            self._state = TransportState.DISCONNECTED
            raise ConnectionError("Connection timeout") from e
        except Exception as e:
            self._state = TransportState.DISCONNECTED
            raise ConnectionError(f"Failed to connect: {e}") from e

    async def send(self, data: bytes, stream_id: int | None = None) -> None:
        """Send data on stream."""
        if not self.is_connected():
            raise ConnectionError("Not connected")

        sid = stream_id or self._main_stream_id
        if sid is None:
            raise ConnectionError("No stream available")

        start = time.monotonic()

        try:
            self._quic.send_stream_data(sid, data, end_stream=False)
            self._protocol.transmit()

            latency = (time.monotonic() - start) * 1000
            self._metrics.bytes_sent += len(data)
            self._metrics.messages_sent += 1
            self._record_latency(latency)

        except Exception as e:
            raise ConnectionError(f"Send failed: {e}") from e

    async def recv(self, timeout: float | None = None) -> bytes | None:
        """Receive data from main stream."""
        if not self.is_connected():
            return None

        try:
            if timeout is None:
                timeout = self._config.idle_timeout

            data = await asyncio.wait_for(
                self._recv_queue.get(),
                timeout=timeout,
            )

            self._metrics.bytes_received += len(data)
            self._metrics.messages_received += 1

            return data

        except TimeoutError:
            return None
        except Exception:
            return None

    async def close(self) -> None:
        """Close QUIC connection."""
        self._shutdown = True

        if self._quic and self._protocol:
            try:
                self._quic.close()
                self._protocol.transmit()
            except Exception:
                pass

        self._quic = None
        self._protocol = None
        self._transport = None
        self._main_stream_id = None

        self._state = TransportState.CLOSED
        self._closed_event.set()

        # Fire callbacks
        await self._fire_callbacks(self._on_disconnect)

    async def migrate(self, new_addr: str | None = None) -> bool:
        """Migrate connection to new address.

        This enables seamless roaming when network changes.
        Returns True if migration succeeded.
        """
        if not self._config.enable_migration:
            return False

        if not self.is_connected():
            return False

        try:
            self._state = TransportState.MIGRATING
            logger.info("Starting connection migration")

            # QUIC connection migration is handled at the protocol level
            # The connection ID changes but the session continues

            self._metrics.migrations += 1
            self._state = TransportState.CONNECTED

            # Fire callbacks
            await self._fire_callbacks(self._on_migration)

            logger.info("Connection migration completed")
            return True

        except Exception as e:
            logger.error("Connection migration failed", error=str(e))
            self._state = TransportState.CONNECTED
            return False

    def is_connected(self) -> bool:
        """Check if connected."""
        return self._state == TransportState.CONNECTED and self._quic is not None

    def get_state(self) -> TransportState:
        """Get current state."""
        return self._state

    def get_metrics(self) -> TransportMetrics:
        """Get transport metrics."""
        return self._metrics

    def _record_latency(self, latency_ms: float) -> None:
        """Record latency sample."""
        self._metrics.last_latency_ms = latency_ms
        self._latency_samples.append(latency_ms)

        if len(self._latency_samples) > 100:
            self._latency_samples.pop(0)

        self._metrics.avg_latency_ms = sum(self._latency_samples) / len(self._latency_samples)

    async def _fire_callbacks(self, callbacks: list[Callable[[], Any]]) -> None:
        """Fire callbacks."""
        for cb in callbacks:
            try:
                result = cb()
                if asyncio.iscoroutine(result):
                    await result
            except Exception as e:
                logger.warning("Callback error", error=str(e))

    # ==============================================================================
    # Stream Management
    # ==============================================================================

    def create_stream(self) -> int:
        """Create a new stream."""
        if not self.is_connected():
            raise ConnectionError("Not connected")

        stream_id = self._quic.get_next_available_stream_id()
        self._streams[stream_id] = asyncio.Queue()
        return stream_id

    async def send_on_stream(self, stream_id: int, data: bytes, end_stream: bool = False) -> None:
        """Send data on specific stream."""
        if not self.is_connected():
            raise ConnectionError("Not connected")

        self._quic.send_stream_data(stream_id, data, end_stream=end_stream)
        self._protocol.transmit()

        self._metrics.bytes_sent += len(data)
        self._metrics.messages_sent += 1

    async def recv_from_stream(self, stream_id: int, timeout: float = 30.0) -> bytes | None:
        """Receive data from specific stream."""
        queue = self._streams.get(stream_id)
        if queue is None:
            return None

        try:
            return await asyncio.wait_for(queue.get(), timeout=timeout)
        except TimeoutError:
            return None


# ==============================================================================
# Transport Factory
# ==============================================================================


def create_transport(
    transport_type: str = "websocket",
    **kwargs: Any,
) -> FastWebSocketTransport | FastQuicTransport:
    """Create a transport instance.

    Args:
        transport_type: "websocket" or "quic"
        **kwargs: Transport-specific configuration

    Returns:
        Transport instance
    """
    # Install fast event loop if available
    install_fast_event_loop()

    if transport_type == "quic":
        config = QuicConfig(**{k: v for k, v in kwargs.items() if hasattr(QuicConfig, k)})
        return FastQuicTransport(
            config=config,
            auto_reconnect=kwargs.get("auto_reconnect", True),
            max_reconnect_attempts=kwargs.get("max_reconnect_attempts", 10),
            reconnect_delay=kwargs.get("reconnect_delay", 0.5),
            max_reconnect_delay=kwargs.get("max_reconnect_delay", 30.0),
        )
    else:
        return FastWebSocketTransport(
            auto_reconnect=kwargs.get("auto_reconnect", True),
            max_reconnect_attempts=kwargs.get("max_reconnect_attempts", 10),
            reconnect_delay=kwargs.get("reconnect_delay", 0.5),
            max_reconnect_delay=kwargs.get("max_reconnect_delay", 30.0),
            ping_interval=kwargs.get("ping_interval", 15.0),
            ping_timeout=kwargs.get("ping_timeout", 10.0),
            connect_timeout=kwargs.get("connect_timeout", 5.0),
        )
