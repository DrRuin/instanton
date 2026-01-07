"""Transport layer abstraction with WebSocket and QUIC support, reconnection, and heartbeat."""

from __future__ import annotations

import asyncio
import contextlib
import ssl
import time
from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

import structlog
from websockets.asyncio.client import connect
from websockets.exceptions import ConnectionClosed, ConnectionClosedError, ConnectionClosedOK

logger = structlog.get_logger()


class ConnectionState(Enum):
    """Connection state enumeration."""

    DISCONNECTED = "disconnected"
    CONNECTING = "connecting"
    CONNECTED = "connected"
    RECONNECTING = "reconnecting"
    CLOSED = "closed"


@dataclass
class TransportStats:
    """Transport statistics."""

    bytes_sent: int = 0
    bytes_received: int = 0
    messages_sent: int = 0
    messages_received: int = 0
    reconnect_count: int = 0
    last_ping_latency: float = 0.0
    connection_start_time: float = 0.0


class TransportError(Exception):
    """Base exception for transport errors."""


class TransportConnectionError(TransportError):
    """Connection-related errors."""


class StreamError(TransportError):
    """Stream-related errors."""


class Transport(ABC):
    """Abstract transport interface."""

    @abstractmethod
    async def connect(self, addr: str) -> None:
        """Connect to remote address."""
        pass

    @abstractmethod
    async def send(self, data: bytes) -> None:
        """Send data."""
        pass

    @abstractmethod
    async def recv(self) -> bytes | None:
        """Receive data."""
        pass

    @abstractmethod
    async def close(self) -> None:
        """Close connection."""
        pass

    @abstractmethod
    def is_connected(self) -> bool:
        """Check if connected."""
        pass

    @abstractmethod
    def get_state(self) -> ConnectionState:
        """Get current connection state."""
        pass

    @abstractmethod
    def get_stats(self) -> TransportStats:
        """Get transport statistics."""
        pass


class WebSocketTransport(Transport):
    """WebSocket transport implementation with reconnection and heartbeat."""

    def __init__(
        self,
        *,
        auto_reconnect: bool = True,
        max_reconnect_attempts: int = 10,
        reconnect_delay: float = 1.0,
        max_reconnect_delay: float = 60.0,
        ping_interval: float = 30.0,
        ping_timeout: float = 10.0,
        connect_timeout: float = 10.0,
    ):
        """Initialize WebSocket transport.

        Args:
            auto_reconnect: Enable automatic reconnection on disconnect.
            max_reconnect_attempts: Maximum number of reconnection attempts (0 for infinite).
            reconnect_delay: Initial delay between reconnection attempts in seconds.
            max_reconnect_delay: Maximum delay between reconnection attempts.
            ping_interval: Interval between heartbeat pings in seconds.
            ping_timeout: Timeout for ping responses in seconds.
            connect_timeout: Timeout for initial connection in seconds.
        """
        self._ws: Any = None
        self._state = ConnectionState.DISCONNECTED
        self._stats = TransportStats()
        self._addr: str = ""

        # Reconnection settings
        self._auto_reconnect = auto_reconnect
        self._max_reconnect_attempts = max_reconnect_attempts
        self._reconnect_delay = reconnect_delay
        self._max_reconnect_delay = max_reconnect_delay
        self._current_reconnect_attempt = 0

        # Heartbeat settings
        self._ping_interval = ping_interval
        self._ping_timeout = ping_timeout
        self._connect_timeout = connect_timeout

        # Tasks
        self._heartbeat_task: asyncio.Task[Any] | None = None
        self._reconnect_lock = asyncio.Lock()
        # Track all background tasks for proper cleanup
        self._background_tasks: set[asyncio.Task[Any]] = set()

        # Callbacks
        self._on_connect: list[Callable[[], Any]] = []
        self._on_disconnect: list[Callable[[], Any]] = []
        self._on_reconnect: list[Callable[[], Any]] = []

        # Shutdown flag
        self._shutdown = False

    def on_connect(self, callback: Callable[[], Any]) -> None:
        """Register a callback for connection events."""
        self._on_connect.append(callback)

    def on_disconnect(self, callback: Callable[[], Any]) -> None:
        """Register a callback for disconnection events."""
        self._on_disconnect.append(callback)

    def on_reconnect(self, callback: Callable[[], Any]) -> None:
        """Register a callback for reconnection events."""
        self._on_reconnect.append(callback)

    async def _fire_callbacks(self, callbacks: list[Callable[[], Any]]) -> None:
        """Fire all callbacks in a list."""
        for callback in callbacks:
            try:
                result = callback()
                if asyncio.iscoroutine(result):
                    await result
            except Exception as e:
                logger.warning("Callback error", error=str(e))

    async def connect(self, addr: str, *, path: str | None = None) -> None:
        """Connect via WebSocket with timeout.

        Args:
            addr: Server address (host:port or full URL).
            path: Optional path to append to the WebSocket URL.
        """
        self._addr = addr
        self._shutdown = False
        self._state = ConnectionState.CONNECTING

        url = self._build_url(addr)
        logger.info("Connecting via WebSocket", url=url)

        try:
            self._ws = await asyncio.wait_for(
                connect(
                    url,
                    ping_interval=None,  # We handle pings ourselves
                    ping_timeout=None,
                    close_timeout=5,
                ),
                timeout=self._connect_timeout,
            )

            self._state = ConnectionState.CONNECTED
            self._stats.connection_start_time = time.time()
            self._current_reconnect_attempt = 0

            logger.info("WebSocket connected", url=url)

            # Start heartbeat task
            self._start_heartbeat()

            # Fire connect callbacks
            await self._fire_callbacks(self._on_connect)

        except TimeoutError as e:
            self._state = ConnectionState.DISCONNECTED
            logger.error("Connection timeout", url=url)
            raise TransportConnectionError(f"Connection timeout to {url}") from e
        except Exception as e:
            self._state = ConnectionState.DISCONNECTED
            logger.error("Connection failed", url=url, error=str(e))
            raise TransportConnectionError(f"Failed to connect to {url}: {e}") from e

    def _build_url(self, addr: str) -> str:
        """Build WebSocket URL from address."""
        if addr.startswith("ws://") or addr.startswith("wss://"):
            return addr
        # Default to secure WebSocket
        if ":" in addr:
            return f"wss://{addr}/tunnel"
        return f"wss://{addr}:443/tunnel"

    def _start_heartbeat(self) -> None:
        """Start the heartbeat task."""
        if self._heartbeat_task is not None:
            self._heartbeat_task.cancel()
        self._heartbeat_task = asyncio.create_task(self._heartbeat_loop())

    def _stop_heartbeat(self) -> None:
        """Stop the heartbeat task."""
        if self._heartbeat_task is not None:
            self._heartbeat_task.cancel()
            self._heartbeat_task = None

    async def _heartbeat_loop(self) -> None:
        """Send periodic heartbeat pings."""
        while not self._shutdown and self._state == ConnectionState.CONNECTED:
            try:
                await asyncio.sleep(self._ping_interval)

                if self._ws is None or self._state != ConnectionState.CONNECTED:
                    break

                # Send ping and measure latency
                start = time.time()
                pong_waiter = await self._ws.ping()

                try:
                    await asyncio.wait_for(pong_waiter, timeout=self._ping_timeout)
                    latency = time.time() - start
                    self._stats.last_ping_latency = latency
                    logger.debug("Heartbeat", latency_ms=round(latency * 1000, 2))
                except TimeoutError:
                    logger.warning("Ping timeout, connection may be dead")
                    # Trigger reconnection
                    await self._handle_disconnect()
                    break

            except ConnectionClosed:
                logger.debug("Connection closed during heartbeat")
                await self._handle_disconnect()
                break
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.warning("Heartbeat error", error=str(e))
                await self._handle_disconnect()
                break

    async def _handle_disconnect(self) -> None:
        """Handle disconnection and trigger reconnection if enabled."""
        if self._shutdown:
            return

        async with self._reconnect_lock:
            if self._state in (ConnectionState.RECONNECTING, ConnectionState.CLOSED):
                return

            self._state = ConnectionState.DISCONNECTED
            self._stop_heartbeat()

            # Fire disconnect callbacks
            await self._fire_callbacks(self._on_disconnect)

            if self._auto_reconnect and not self._shutdown:
                await self._reconnect()

    async def _reconnect(self) -> None:
        """Attempt to reconnect with exponential backoff."""
        if self._shutdown:
            return

        self._state = ConnectionState.RECONNECTING

        while not self._shutdown:
            self._current_reconnect_attempt += 1

            # Check max attempts (0 = infinite)
            if (
                self._max_reconnect_attempts > 0
                and self._current_reconnect_attempt > self._max_reconnect_attempts
            ):
                logger.error(
                    "Max reconnection attempts reached",
                    attempts=self._max_reconnect_attempts,
                )
                self._state = ConnectionState.CLOSED
                return

            # Calculate delay with exponential backoff
            delay = min(
                self._reconnect_delay * (2 ** (self._current_reconnect_attempt - 1)),
                self._max_reconnect_delay,
            )

            logger.info(
                "Reconnecting",
                attempt=self._current_reconnect_attempt,
                delay=delay,
            )

            await asyncio.sleep(delay)

            if self._shutdown:
                return

            try:
                url = self._build_url(self._addr)
                self._ws = await asyncio.wait_for(
                    connect(
                        url,
                        ping_interval=None,
                        ping_timeout=None,
                        close_timeout=5,
                    ),
                    timeout=self._connect_timeout,
                )

                self._state = ConnectionState.CONNECTED
                self._stats.reconnect_count += 1
                self._stats.connection_start_time = time.time()
                self._current_reconnect_attempt = 0

                logger.info(
                    "Reconnected successfully",
                    reconnect_count=self._stats.reconnect_count,
                )

                # Start heartbeat
                self._start_heartbeat()

                # Fire reconnect callbacks
                await self._fire_callbacks(self._on_reconnect)

                return

            except Exception as e:
                logger.warning(
                    "Reconnection attempt failed",
                    attempt=self._current_reconnect_attempt,
                    error=str(e),
                )
                continue

    async def send(self, data: bytes) -> None:
        """Send data over WebSocket.

        Args:
            data: Binary data to send.

        Raises:
            TransportConnectionError: If not connected.
        """
        if self._ws is None or self._state != ConnectionState.CONNECTED:
            raise TransportConnectionError("Not connected")

        try:
            await self._ws.send(data)
            self._stats.bytes_sent += len(data)
            self._stats.messages_sent += 1
        except ConnectionClosed as e:
            logger.debug("Connection closed during send", code=e.code)
            asyncio.create_task(self._handle_disconnect())
            raise TransportConnectionError(f"Connection closed: {e}") from e
        except Exception as e:
            logger.error("Send error", error=str(e))
            raise

    async def recv(self) -> bytes | None:
        """Receive data from WebSocket.

        Returns:
            Received bytes or None if disconnected.
        """
        if self._ws is None:
            return None

        try:
            data = await self._ws.recv()

            if isinstance(data, str):
                data = data.encode("utf-8")

            self._stats.bytes_received += len(data)
            self._stats.messages_received += 1
            return data

        except ConnectionClosedOK:
            logger.debug("Connection closed normally")
            asyncio.create_task(self._handle_disconnect())
            return None
        except ConnectionClosedError as e:
            logger.debug("Connection closed with error", code=e.code, reason=e.reason)
            asyncio.create_task(self._handle_disconnect())
            return None
        except asyncio.CancelledError:
            return None
        except Exception as e:
            logger.error("Receive error", error=str(e))
            asyncio.create_task(self._handle_disconnect())
            return None

    async def close(self) -> None:
        """Close WebSocket connection gracefully."""
        self._shutdown = True
        self._stop_heartbeat()

        # Cancel all background tasks
        for task in list(self._background_tasks):
            if not task.done():
                task.cancel()
        if self._background_tasks:
            await asyncio.gather(*self._background_tasks, return_exceptions=True)
        self._background_tasks.clear()

        # Clear callbacks to prevent memory leaks from references
        self._on_connect.clear()
        self._on_disconnect.clear()
        self._on_reconnect.clear()

        if self._ws is not None:
            try:
                await self._ws.close()
            except Exception as e:
                logger.debug("Error closing WebSocket", error=str(e))
            finally:
                self._ws = None

        self._state = ConnectionState.CLOSED
        logger.info("WebSocket connection closed")

    def is_connected(self) -> bool:
        """Check if currently connected."""
        return self._state == ConnectionState.CONNECTED and self._ws is not None

    def get_state(self) -> ConnectionState:
        """Get current connection state."""
        return self._state

    def get_stats(self) -> TransportStats:
        """Get transport statistics."""
        return self._stats


# ==============================================================================
# QUIC Transport Configuration
# ==============================================================================


@dataclass
class QuicTransportConfig:
    """Configuration for QUIC transport connections."""

    host: str = "localhost"
    port: int = 4433
    server_name: str | None = None  # SNI hostname
    verify_ssl: bool = True
    cert_path: Path | None = None
    key_path: Path | None = None
    ca_path: Path | None = None
    alpn_protocols: list[str] = field(default_factory=lambda: ["instanton"])
    idle_timeout: float = 30.0
    connection_timeout: float = 10.0
    auto_reconnect: bool = True
    max_reconnect_attempts: int = 10
    reconnect_delay: float = 1.0
    max_reconnect_delay: float = 60.0


# ==============================================================================
# QUIC Stream Handler
# ==============================================================================


class QuicStreamHandler:
    """Manages a single QUIC stream for bidirectional communication."""

    def __init__(self, stream_id: int) -> None:
        self.stream_id = stream_id
        self._recv_buffer: asyncio.Queue[bytes] = asyncio.Queue()
        self._closed = False
        self._end_stream = False

    def receive_data(self, data: bytes, end_stream: bool = False) -> None:
        """Called when data is received on this stream."""
        if data:
            self._recv_buffer.put_nowait(data)
        if end_stream:
            self._end_stream = True
            # Signal end of stream with empty bytes
            self._recv_buffer.put_nowait(b"")

    async def read(self, timeout: float | None = None) -> bytes | None:
        """Read data from stream."""
        if self._closed:
            return None
        try:
            if timeout is not None:
                data = await asyncio.wait_for(self._recv_buffer.get(), timeout=timeout)
            else:
                data = await self._recv_buffer.get()
            if data == b"" and self._end_stream:
                return None
            return data
        except TimeoutError:
            return None
        except asyncio.CancelledError:
            return None

    def close(self) -> None:
        """Close the stream."""
        self._closed = True


# ==============================================================================
# QUIC Client Protocol
# ==============================================================================


class QuicClientProtocol:
    """QUIC client protocol handler using aioquic.

    This class wraps the aioquic QuicConnection and provides a higher-level
    interface for sending and receiving data over QUIC streams.
    """

    def __init__(self, config: QuicTransportConfig) -> None:
        self._config = config
        self._quic: Any = None
        self._streams: dict[int, QuicStreamHandler] = {}
        self._connected = asyncio.Event()
        self._closed = asyncio.Event()
        self._main_stream_id: int | None = None
        self._recv_queue: asyncio.Queue[bytes] = asyncio.Queue()
        self._protocol: Any = None
        self._stats = TransportStats()

    def _handle_quic_event(self, event: Any) -> None:
        """Handle QUIC events."""
        from aioquic.quic.events import (
            ConnectionTerminated,
            HandshakeCompleted,
            StreamDataReceived,
            StreamReset,
        )

        if isinstance(event, HandshakeCompleted):
            logger.debug("QUIC handshake completed")
            self._connected.set()

        elif isinstance(event, StreamDataReceived):
            stream_id = event.stream_id
            if stream_id not in self._streams:
                self._streams[stream_id] = QuicStreamHandler(stream_id)

            handler = self._streams[stream_id]
            handler.receive_data(event.data, event.end_stream)

            # Also put in main queue for simple recv()
            if event.data:
                self._recv_queue.put_nowait(event.data)
                self._stats.bytes_received += len(event.data)
                self._stats.messages_received += 1

        elif isinstance(event, StreamReset):
            stream_id = event.stream_id
            if stream_id in self._streams:
                self._streams[stream_id].close()
            logger.debug("Stream reset", stream_id=stream_id)

        elif isinstance(event, ConnectionTerminated):
            logger.info(
                "QUIC connection terminated",
                error_code=event.error_code,
                reason=event.reason_phrase,
            )
            self._closed.set()

    async def send(self, data: bytes, stream_id: int | None = None) -> None:
        """Send data on a stream."""
        if not self._connected.is_set():
            raise TransportConnectionError("Not connected")

        if self._quic is None or self._protocol is None:
            raise TransportConnectionError("QUIC connection not established")

        sid = stream_id if stream_id is not None else self._main_stream_id
        if sid is None:
            raise StreamError("No stream available")

        self._quic.send_stream_data(sid, data, end_stream=False)
        self._protocol.transmit()
        self._stats.bytes_sent += len(data)
        self._stats.messages_sent += 1

    async def recv(self, timeout: float | None = None) -> bytes | None:
        """Receive data from main stream."""
        if not self._connected.is_set() and self._recv_queue.empty():
            return None

        try:
            if timeout is not None:
                return await asyncio.wait_for(self._recv_queue.get(), timeout=timeout)
            return await self._recv_queue.get()
        except TimeoutError:
            return None
        except asyncio.CancelledError:
            return None

    async def close(self) -> None:
        """Close the connection."""
        if self._quic is not None and self._protocol is not None:
            self._quic.close()
            self._protocol.transmit()
        self._closed.set()

    def is_connected(self) -> bool:
        """Check if connected."""
        return self._connected.is_set() and not self._closed.is_set()

    def get_stream(self, stream_id: int) -> QuicStreamHandler | None:
        """Get a stream handler by ID."""
        return self._streams.get(stream_id)

    def create_stream(self) -> int:
        """Create a new bidirectional stream."""
        if self._quic is None:
            raise TransportConnectionError("Not connected")
        stream_id = self._quic.get_next_available_stream_id()
        self._streams[stream_id] = QuicStreamHandler(stream_id)
        return stream_id


# ==============================================================================
# QUIC Transport Implementation
# ==============================================================================


class QuicTransport(Transport):
    """QUIC transport implementation using aioquic.

    This transport provides:
    - QUIC connection with TLS 1.3
    - Multiplexed streams
    - Connection migration support (QUIC feature)
    - Automatic reconnection with exponential backoff
    - Statistics tracking
    """

    def __init__(
        self,
        config: QuicTransportConfig | None = None,
        *,
        auto_reconnect: bool = True,
        max_reconnect_attempts: int = 10,
        reconnect_delay: float = 1.0,
        max_reconnect_delay: float = 60.0,
    ) -> None:
        """Initialize QUIC transport.

        Args:
            config: QUIC transport configuration.
            auto_reconnect: Enable automatic reconnection on disconnect.
            max_reconnect_attempts: Maximum number of reconnection attempts.
            reconnect_delay: Initial delay between reconnection attempts.
            max_reconnect_delay: Maximum delay between reconnection attempts.
        """
        self._config = config or QuicTransportConfig()
        self._config.auto_reconnect = auto_reconnect
        self._config.max_reconnect_attempts = max_reconnect_attempts
        self._config.reconnect_delay = reconnect_delay
        self._config.max_reconnect_delay = max_reconnect_delay

        self._state = ConnectionState.DISCONNECTED
        self._stats = TransportStats()
        self._addr: str = ""

        self._quic: Any = None
        self._protocol: Any = None
        self._connect_task: asyncio.Task[Any] | None = None
        self._recv_queue: asyncio.Queue[bytes] = asyncio.Queue()
        self._streams: dict[int, QuicStreamHandler] = {}
        self._main_stream_id: int | None = None
        self._connected_event = asyncio.Event()
        self._closed_event = asyncio.Event()

        self._shutdown = False
        self._reconnect_lock = asyncio.Lock()
        self._current_reconnect_attempt = 0

        # Callbacks
        self._on_connect: list[Callable[[], Any]] = []
        self._on_disconnect: list[Callable[[], Any]] = []
        self._on_reconnect: list[Callable[[], Any]] = []

    def on_connect(self, callback: Callable[[], Any]) -> None:
        """Register a callback for connection events."""
        self._on_connect.append(callback)

    def on_disconnect(self, callback: Callable[[], Any]) -> None:
        """Register a callback for disconnection events."""
        self._on_disconnect.append(callback)

    def on_reconnect(self, callback: Callable[[], Any]) -> None:
        """Register a callback for reconnection events."""
        self._on_reconnect.append(callback)

    async def _fire_callbacks(self, callbacks: list[Callable[[], Any]]) -> None:
        """Fire all callbacks in a list."""
        for callback in callbacks:
            try:
                result = callback()
                if asyncio.iscoroutine(result):
                    await result
            except Exception as e:
                logger.warning("Callback error", error=str(e))

    async def connect(self, addr: str, *, path: str | None = None) -> None:
        """Connect via QUIC.

        Args:
            addr: Address in format "host:port" or just "host" (default port 4433)
            path: Optional path for the connection (not used in QUIC but for API compatibility).
        """
        self._addr = addr
        self._shutdown = False
        self._state = ConnectionState.CONNECTING

        # Parse address
        if ":" in addr:
            host, port_str = addr.rsplit(":", 1)
            port = int(port_str)
        else:
            host = addr
            port = self._config.port

        self._config.host = host
        self._config.port = port

        await self._do_connect(host, port)

    async def _do_connect(self, host: str, port: int) -> None:
        """Perform the actual QUIC connection."""
        from aioquic.asyncio import connect as quic_connect
        from aioquic.asyncio.protocol import QuicConnectionProtocol
        from aioquic.quic.configuration import QuicConfiguration

        # Create QUIC configuration
        configuration = QuicConfiguration(
            is_client=True,
            alpn_protocols=self._config.alpn_protocols,
            verify_mode=ssl.CERT_REQUIRED if self._config.verify_ssl else ssl.CERT_NONE,
            idle_timeout=self._config.idle_timeout,
        )

        # Server name for SNI
        server_name = self._config.server_name or host

        # Load CA certificates if specified
        if self._config.ca_path and self._config.ca_path.exists():
            configuration.load_verify_locations(str(self._config.ca_path))

        # Load client certificate if specified
        if (
            self._config.cert_path
            and self._config.key_path
            and self._config.cert_path.exists()
            and self._config.key_path.exists()
        ):
            configuration.load_cert_chain(
                str(self._config.cert_path),
                str(self._config.key_path),
            )

        logger.info(
            "Connecting via QUIC",
            host=host,
            port=port,
            server_name=server_name,
            alpn=configuration.alpn_protocols,
        )

        # Reference to outer self for use in protocol class
        outer_self = self

        class InstantonQuicProtocol(QuicConnectionProtocol):
            """Custom protocol for handling QUIC events."""

            def quic_event_received(self, event: Any) -> None:
                outer_self._handle_quic_event(event)

        try:
            async with quic_connect(
                host,
                port,
                configuration=configuration,
                create_protocol=InstantonQuicProtocol,
            ) as protocol:
                self._protocol = protocol
                self._quic = protocol._quic

                # Wait for handshake to complete
                await asyncio.wait_for(
                    self._connected_event.wait(),
                    timeout=self._config.connection_timeout,
                )

                self._state = ConnectionState.CONNECTED
                self._stats.connection_start_time = time.time()
                self._current_reconnect_attempt = 0

                # Open the main stream for communication
                self._main_stream_id = self._quic.get_next_available_stream_id()
                self._streams[self._main_stream_id] = QuicStreamHandler(self._main_stream_id)

                logger.info("QUIC transport connected")

                # Fire connect callbacks
                await self._fire_callbacks(self._on_connect)

                # Wait until closed
                await self._closed_event.wait()

        except TimeoutError:
            self._state = ConnectionState.DISCONNECTED
            logger.error("QUIC connection timeout", host=host, port=port)
            raise TransportConnectionError("Connection timeout") from None
        except Exception as e:
            self._state = ConnectionState.DISCONNECTED
            logger.error("QUIC connection failed", error=str(e))
            raise TransportConnectionError(f"Connection failed: {e}") from e
        finally:
            await self._handle_disconnect()

    def _handle_quic_event(self, event: Any) -> None:
        """Handle QUIC events."""
        from aioquic.quic.events import (
            ConnectionTerminated,
            HandshakeCompleted,
            StreamDataReceived,
            StreamReset,
        )

        if isinstance(event, HandshakeCompleted):
            logger.debug("QUIC handshake completed")
            self._connected_event.set()

        elif isinstance(event, StreamDataReceived):
            stream_id = event.stream_id
            if stream_id not in self._streams:
                self._streams[stream_id] = QuicStreamHandler(stream_id)

            handler = self._streams[stream_id]
            handler.receive_data(event.data, event.end_stream)

            # Also put in main queue for simple recv()
            if event.data:
                self._recv_queue.put_nowait(event.data)
                self._stats.bytes_received += len(event.data)
                self._stats.messages_received += 1

        elif isinstance(event, StreamReset):
            stream_id = event.stream_id
            if stream_id in self._streams:
                self._streams[stream_id].close()
            logger.debug("Stream reset", stream_id=stream_id)

        elif isinstance(event, ConnectionTerminated):
            logger.info(
                "QUIC connection terminated",
                error_code=event.error_code,
                reason=event.reason_phrase,
            )
            self._closed_event.set()

    async def _handle_disconnect(self) -> None:
        """Handle disconnection and trigger reconnection if enabled."""
        if self._shutdown:
            return

        async with self._reconnect_lock:
            if self._state in (ConnectionState.RECONNECTING, ConnectionState.CLOSED):
                return

            prev_state = self._state
            self._state = ConnectionState.DISCONNECTED

            # Fire disconnect callbacks
            await self._fire_callbacks(self._on_disconnect)

            # Only reconnect if we were previously connected
            if (
                prev_state == ConnectionState.CONNECTED
                and self._config.auto_reconnect
                and not self._shutdown
            ):
                await self._reconnect()

    async def _reconnect(self) -> None:
        """Attempt to reconnect with exponential backoff."""
        if self._shutdown:
            return

        self._state = ConnectionState.RECONNECTING

        while not self._shutdown:
            self._current_reconnect_attempt += 1

            # Check max attempts (0 = infinite)
            if (
                self._config.max_reconnect_attempts > 0
                and self._current_reconnect_attempt > self._config.max_reconnect_attempts
            ):
                logger.error(
                    "Max reconnection attempts reached",
                    attempts=self._config.max_reconnect_attempts,
                )
                self._state = ConnectionState.CLOSED
                return

            # Calculate delay with exponential backoff
            delay = min(
                self._config.reconnect_delay * (2 ** (self._current_reconnect_attempt - 1)),
                self._config.max_reconnect_delay,
            )

            logger.info(
                "Reconnecting via QUIC",
                attempt=self._current_reconnect_attempt,
                delay=delay,
            )

            await asyncio.sleep(delay)

            if self._shutdown:
                return

            try:
                # Reset events for new connection
                self._connected_event.clear()
                self._closed_event.clear()
                self._recv_queue = asyncio.Queue()
                self._streams.clear()

                await self._do_connect(self._config.host, self._config.port)

                self._stats.reconnect_count += 1
                logger.info(
                    "QUIC reconnected successfully",
                    reconnect_count=self._stats.reconnect_count,
                )

                # Fire reconnect callbacks
                await self._fire_callbacks(self._on_reconnect)

                return

            except Exception as e:
                logger.warning(
                    "QUIC reconnection attempt failed",
                    attempt=self._current_reconnect_attempt,
                    error=str(e),
                )
                continue

    async def send(self, data: bytes) -> None:
        """Send data over QUIC.

        Args:
            data: Binary data to send.

        Raises:
            TransportConnectionError: If not connected.
        """
        if self._state != ConnectionState.CONNECTED:
            raise TransportConnectionError("Not connected")

        if self._quic is None or self._protocol is None:
            raise TransportConnectionError("QUIC connection not established")

        if self._main_stream_id is None:
            raise StreamError("No stream available")

        try:
            self._quic.send_stream_data(self._main_stream_id, data, end_stream=False)
            self._protocol.transmit()
            self._stats.bytes_sent += len(data)
            self._stats.messages_sent += 1
        except Exception as e:
            logger.error("QUIC send error", error=str(e))
            raise TransportConnectionError(f"Send failed: {e}") from e

    async def recv(self) -> bytes | None:
        """Receive data from QUIC.

        Returns:
            Received bytes or None if disconnected/timeout.
        """
        if self._state != ConnectionState.CONNECTED and self._recv_queue.empty():
            return None

        try:
            return await asyncio.wait_for(self._recv_queue.get(), timeout=self._config.idle_timeout)
        except TimeoutError:
            return None
        except asyncio.CancelledError:
            return None

    async def close(self) -> None:
        """Close QUIC connection gracefully."""
        self._shutdown = True

        if self._quic is not None and self._protocol is not None:
            try:
                self._quic.close()
                self._protocol.transmit()
            except Exception as e:
                logger.debug("Error closing QUIC", error=str(e))

        self._closed_event.set()
        self._quic = None
        self._protocol = None

        if self._connect_task:
            self._connect_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._connect_task
            self._connect_task = None

        self._state = ConnectionState.CLOSED
        logger.info("QUIC transport closed")

    def is_connected(self) -> bool:
        """Check if currently connected."""
        return self._state == ConnectionState.CONNECTED

    def get_state(self) -> ConnectionState:
        """Get current connection state."""
        return self._state

    def get_stats(self) -> TransportStats:
        """Get transport statistics."""
        return self._stats

    def get_stream(self, stream_id: int) -> QuicStreamHandler | None:
        """Get a stream handler by ID."""
        return self._streams.get(stream_id)

    def create_stream(self) -> int:
        """Create a new bidirectional stream.

        Returns:
            The stream ID.

        Raises:
            TransportConnectionError: If not connected.
        """
        if self._quic is None:
            raise TransportConnectionError("Not connected")
        stream_id = self._quic.get_next_available_stream_id()
        self._streams[stream_id] = QuicStreamHandler(stream_id)
        return stream_id


# ==============================================================================
# QUIC Server Implementation
# ==============================================================================


class QuicServer:
    """High-level QUIC server for accepting tunnel connections.

    Example usage:
        ```python
        server = QuicServer(
            cert_path=Path("cert.pem"),
            key_path=Path("key.pem"),
        )

        @server.on_connection
        async def handle_client(protocol):
            data = await protocol.recv()
            await protocol.send(b"Hello!")

        async with server:
            await asyncio.Event().wait()  # Run forever
        ```
    """

    def __init__(
        self,
        cert_path: Path,
        key_path: Path,
        host: str = "0.0.0.0",
        port: int = 4433,
        alpn_protocols: list[str] | None = None,
        idle_timeout: float = 30.0,
    ) -> None:
        """Initialize QUIC server.

        Args:
            cert_path: Path to TLS certificate file.
            key_path: Path to TLS private key file.
            host: Host address to bind to.
            port: Port to listen on.
            alpn_protocols: ALPN protocols to advertise.
            idle_timeout: Connection idle timeout in seconds.
        """
        self._cert_path = cert_path
        self._key_path = key_path
        self._host = host
        self._port = port
        self._alpn_protocols = alpn_protocols or ["instanton"]
        self._idle_timeout = idle_timeout

        self._server: Any = None
        self._connections: dict[bytes, QuicClientProtocol] = {}
        self._connection_handler: Callable[[QuicClientProtocol], Any] | None = None

    def on_connection(
        self, handler: Callable[[QuicClientProtocol], Any]
    ) -> Callable[[QuicClientProtocol], Any]:
        """Decorator to register connection handler.

        Args:
            handler: Async function to handle new connections.

        Returns:
            The handler function (unchanged).
        """
        self._connection_handler = handler
        return handler

    async def start(self) -> None:
        """Start the QUIC server."""
        from aioquic.asyncio import serve as quic_serve
        from aioquic.asyncio.protocol import QuicConnectionProtocol
        from aioquic.quic.configuration import QuicConfiguration
        from aioquic.quic.events import (
            ConnectionTerminated,
            HandshakeCompleted,
            StreamDataReceived,
        )

        # Create server configuration
        configuration = QuicConfiguration(
            is_client=False,
            alpn_protocols=self._alpn_protocols,
            idle_timeout=self._idle_timeout,
        )

        # Load server certificate (required)
        configuration.load_cert_chain(
            str(self._cert_path),
            str(self._key_path),
        )

        logger.info("Starting QUIC server", host=self._host, port=self._port)

        # Reference to outer self for use in protocol class
        outer_self = self

        class InstantonServerProtocol(QuicConnectionProtocol):
            """Server-side protocol for handling client connections."""

            def __init__(self, *args: Any, **kwargs: Any) -> None:
                super().__init__(*args, **kwargs)
                self._client: QuicClientProtocol | None = None

            def quic_event_received(self, event: Any) -> None:
                if isinstance(event, HandshakeCompleted):
                    # Create client protocol wrapper
                    config = QuicTransportConfig(
                        alpn_protocols=outer_self._alpn_protocols,
                        idle_timeout=outer_self._idle_timeout,
                    )
                    client = QuicClientProtocol(config)
                    client._quic = self._quic
                    client._protocol = self
                    client._connected.set()

                    cid = self._quic.host_cid
                    outer_self._connections[cid] = client
                    self._client = client

                    logger.info("QUIC client connected", cid=cid.hex())

                    if outer_self._connection_handler:
                        asyncio.create_task(outer_self._connection_handler(client))

                elif isinstance(event, StreamDataReceived):
                    if self._client:
                        self._client._handle_quic_event(event)

                elif isinstance(event, ConnectionTerminated):
                    cid = self._quic.host_cid
                    if cid in outer_self._connections:
                        del outer_self._connections[cid]
                    logger.info("QUIC client disconnected", cid=cid.hex())

        self._server = await quic_serve(
            self._host,
            self._port,
            configuration=configuration,
            create_protocol=InstantonServerProtocol,
        )

        logger.info("QUIC server started", host=self._host, port=self._port)

    async def stop(self) -> None:
        """Stop the QUIC server."""
        if self._server:
            self._server.close()
            self._server = None

        for client in list(self._connections.values()):
            await client.close()
        self._connections.clear()

        logger.info("QUIC server stopped")

    async def __aenter__(self) -> QuicServer:
        await self.start()
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self.stop()
