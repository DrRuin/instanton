"""TCP tunnel client implementation for non-HTTP protocols.

Provides transparent TCP tunneling for:
- SSH connections
- Database connections (PostgreSQL, MySQL, etc.)
- Raw TCP services
- Any binary protocol over TCP
"""

from __future__ import annotations

import asyncio
import contextlib
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from typing import Any
from uuid import UUID, uuid4

import structlog

from instanton.core.transport import QuicTransport, Transport, WebSocketTransport

logger = structlog.get_logger()


class TcpTunnelState(Enum):
    """TCP tunnel connection state."""

    DISCONNECTED = "disconnected"
    CONNECTING = "connecting"
    CONNECTED = "connected"
    RELAYING = "relaying"
    CLOSING = "closing"
    CLOSED = "closed"


@dataclass
class TcpTunnelStats:
    """Statistics for TCP tunnel."""

    tunnel_id: UUID = field(default_factory=uuid4)
    bytes_sent: int = 0
    bytes_received: int = 0
    packets_sent: int = 0
    packets_received: int = 0
    connections_handled: int = 0
    start_time: float = 0.0
    last_activity: float = 0.0


@dataclass
class TcpTunnelConfig:
    """Configuration for TCP tunnel."""

    local_host: str = "127.0.0.1"
    local_port: int = 22
    remote_host: str | None = None  # For connecting to remote target
    remote_port: int | None = None  # Remote port on server
    buffer_size: int = 65535
    connect_timeout: float = 30.0
    idle_timeout: float = 300.0
    max_connections: int = 100
    keepalive_interval: float = 30.0


class TcpRelayMessage:
    """Message types for TCP relay protocol."""

    # Message types
    CONNECT = 0x01  # Connect request
    CONNECT_ACK = 0x02  # Connect acknowledgment
    DATA = 0x03  # Data packet
    CLOSE = 0x04  # Close connection
    KEEPALIVE = 0x05  # Keepalive ping
    ERROR = 0x06  # Error message

    @staticmethod
    def encode_connect(
        tunnel_id: bytes,
        local_port: int,
        remote_port: int | None = None,
    ) -> bytes:
        """Encode a connect message."""
        import struct

        msg = bytearray()
        msg.append(TcpRelayMessage.CONNECT)
        msg.extend(tunnel_id[:16].ljust(16, b"\x00"))
        msg.extend(struct.pack(">H", local_port))
        msg.extend(struct.pack(">H", remote_port or 0))
        return bytes(msg)

    @staticmethod
    def encode_connect_ack(
        tunnel_id: bytes,
        assigned_port: int,
        error: str | None = None,
    ) -> bytes:
        """Encode a connect acknowledgment."""
        import struct

        msg = bytearray()
        msg.append(TcpRelayMessage.CONNECT_ACK)
        msg.extend(tunnel_id[:16].ljust(16, b"\x00"))
        msg.extend(struct.pack(">H", assigned_port))
        if error:
            error_bytes = error.encode("utf-8")[:255]
            msg.append(len(error_bytes))
            msg.extend(error_bytes)
        else:
            msg.append(0)
        return bytes(msg)

    @staticmethod
    def encode_data(
        connection_id: bytes,
        data: bytes,
    ) -> bytes:
        """Encode a data message."""
        import struct

        msg = bytearray()
        msg.append(TcpRelayMessage.DATA)
        msg.extend(connection_id[:8].ljust(8, b"\x00"))
        msg.extend(struct.pack(">I", len(data)))
        msg.extend(data)
        return bytes(msg)

    @staticmethod
    def encode_close(connection_id: bytes) -> bytes:
        """Encode a close message."""
        msg = bytearray()
        msg.append(TcpRelayMessage.CLOSE)
        msg.extend(connection_id[:8].ljust(8, b"\x00"))
        return bytes(msg)

    @staticmethod
    def encode_keepalive(tunnel_id: bytes) -> bytes:
        """Encode a keepalive message."""
        msg = bytearray()
        msg.append(TcpRelayMessage.KEEPALIVE)
        msg.extend(tunnel_id[:16].ljust(16, b"\x00"))
        return bytes(msg)

    @staticmethod
    def decode(data: bytes) -> tuple[int, dict[str, Any]] | None:
        """Decode a TCP relay message."""
        import struct

        if len(data) < 1:
            return None

        msg_type = data[0]

        if msg_type == TcpRelayMessage.CONNECT:
            if len(data) < 21:
                return None
            return msg_type, {
                "tunnel_id": data[1:17],
                "local_port": struct.unpack(">H", data[17:19])[0],
                "remote_port": struct.unpack(">H", data[19:21])[0],
            }

        elif msg_type == TcpRelayMessage.CONNECT_ACK:
            if len(data) < 20:
                return None
            error_len = data[19]
            error = data[20 : 20 + error_len].decode("utf-8") if error_len > 0 else None
            return msg_type, {
                "tunnel_id": data[1:17],
                "assigned_port": struct.unpack(">H", data[17:19])[0],
                "error": error,
            }

        elif msg_type == TcpRelayMessage.DATA:
            if len(data) < 13:
                return None
            data_len = struct.unpack(">I", data[9:13])[0]
            if len(data) < 13 + data_len:
                return None
            return msg_type, {
                "connection_id": data[1:9],
                "data": data[13 : 13 + data_len],
            }

        elif msg_type == TcpRelayMessage.CLOSE:
            if len(data) < 9:
                return None
            return msg_type, {
                "connection_id": data[1:9],
            }

        elif msg_type == TcpRelayMessage.KEEPALIVE:
            if len(data) < 17:
                return None
            return msg_type, {
                "tunnel_id": data[1:17],
            }

        return None


class TcpTunnelClient:
    """Client for establishing TCP tunnels.

    Features:
    - Transparent TCP proxy
    - Multiple concurrent connections
    - Automatic reconnection
    - Keepalive for long-lived connections
    - Bandwidth statistics
    """

    def __init__(
        self,
        config: TcpTunnelConfig | None = None,
        server_addr: str = "instanton.dev",
        use_quic: bool = False,
    ) -> None:
        """Initialize TCP tunnel client.

        Args:
            config: Tunnel configuration
            server_addr: Server address
            use_quic: Use QUIC transport
        """
        self.config = config or TcpTunnelConfig()
        self.server_addr = server_addr
        self.use_quic = use_quic

        self._state = TcpTunnelState.DISCONNECTED
        self._transport: Transport | None = None
        self._tunnel_id: bytes = uuid4().bytes
        self._assigned_port: int | None = None
        self._stats = TcpTunnelStats()
        self._running = False

        # Active connections: connection_id -> (reader, writer)
        self._connections: dict[bytes, tuple[asyncio.StreamReader, asyncio.StreamWriter]] = {}
        self._connection_tasks: dict[bytes, asyncio.Task[Any]] = {}

        # State hooks
        self._state_hooks: list[Callable[[TcpTunnelState], None]] = []

        # Server for accepting local connections
        self._local_server: asyncio.Server | None = None

        # Message handling
        self._recv_task: asyncio.Task[Any] | None = None
        self._keepalive_task: asyncio.Task[Any] | None = None

    @property
    def state(self) -> TcpTunnelState:
        """Get current tunnel state."""
        return self._state

    @property
    def stats(self) -> TcpTunnelStats:
        """Get tunnel statistics."""
        return self._stats

    @property
    def assigned_port(self) -> int | None:
        """Get assigned remote port."""
        return self._assigned_port

    @property
    def tunnel_url(self) -> str | None:
        """Get the tunnel URL."""
        if self._assigned_port:
            return f"tcp://{self.server_addr}:{self._assigned_port}"
        return None

    def add_state_hook(self, hook: Callable[[TcpTunnelState], None]) -> None:
        """Add a state change hook."""
        self._state_hooks.append(hook)

    def remove_state_hook(self, hook: Callable[[TcpTunnelState], None]) -> bool:
        """Remove a state change hook."""
        if hook in self._state_hooks:
            self._state_hooks.remove(hook)
            return True
        return False

    def _set_state(self, state: TcpTunnelState) -> None:
        """Set state and notify hooks."""
        old_state = self._state
        if old_state == state:
            return

        self._state = state
        logger.debug("TCP tunnel state change", old=old_state.value, new=state.value)

        for hook in self._state_hooks:
            try:
                hook(state)
            except Exception as e:
                logger.warning("State hook error", error=str(e))

    async def connect(self) -> str:
        """Connect to the server and establish TCP tunnel.

        Returns:
            The tunnel URL (tcp://server:port)
        """
        import time

        self._set_state(TcpTunnelState.CONNECTING)
        self._stats.start_time = time.time()

        # Create transport
        if self.use_quic:
            self._transport = QuicTransport()
        else:
            self._transport = WebSocketTransport()

        # Connect to server
        try:
            await self._transport.connect(
                self.server_addr,
                path="/tcp",  # TCP tunnel endpoint
            )
        except Exception as e:
            logger.error("Failed to connect to server", error=str(e))
            self._set_state(TcpTunnelState.DISCONNECTED)
            raise

        # Send connect request
        connect_msg = TcpRelayMessage.encode_connect(
            tunnel_id=self._tunnel_id,
            local_port=self.config.local_port,
            remote_port=self.config.remote_port,
        )
        await self._transport.send(connect_msg)

        # Wait for acknowledgment
        try:
            response = await asyncio.wait_for(
                self._transport.recv(),
                timeout=self.config.connect_timeout,
            )
            if response is None:
                raise RuntimeError("No response from server")
            decoded = TcpRelayMessage.decode(response)

            if decoded is None:
                raise RuntimeError("Invalid response from server")

            msg_type, msg_data = decoded

            if msg_type != TcpRelayMessage.CONNECT_ACK:
                raise RuntimeError(f"Unexpected message type: {msg_type}")

            if msg_data.get("error"):
                raise RuntimeError(f"Server error: {msg_data['error']}")

            self._assigned_port = msg_data["assigned_port"]

        except TimeoutError as err:
            logger.error("Connection timeout")
            self._set_state(TcpTunnelState.DISCONNECTED)
            raise RuntimeError("Connection timeout") from err

        self._set_state(TcpTunnelState.CONNECTED)
        self._running = True

        logger.info(
            "TCP tunnel established",
            local_port=self.config.local_port,
            remote_port=self._assigned_port,
            tunnel_url=self.tunnel_url,
        )

        return self.tunnel_url or ""

    async def run(self) -> None:
        """Run the tunnel, handling connections."""
        if self._state != TcpTunnelState.CONNECTED:
            raise RuntimeError("Not connected")

        self._set_state(TcpTunnelState.RELAYING)

        # Start local server to accept connections
        self._local_server = await asyncio.start_server(
            self._handle_local_connection,
            self.config.local_host,
            self.config.local_port,
        )

        # Start receive task
        self._recv_task = asyncio.create_task(self._receive_loop())

        # Start keepalive task
        self._keepalive_task = asyncio.create_task(self._keepalive_loop())

        logger.info(
            "TCP tunnel listening",
            host=self.config.local_host,
            port=self.config.local_port,
        )

        try:
            async with self._local_server:
                await self._local_server.serve_forever()
        except asyncio.CancelledError:
            pass

    async def _handle_local_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Handle an incoming local connection."""
        import time

        # Generate connection ID
        connection_id = uuid4().bytes[:8]

        self._stats.connections_handled += 1
        self._connections[connection_id] = (reader, writer)

        logger.debug("Local connection accepted", connection_id=connection_id.hex())

        try:
            # Start relaying data from local to remote
            while self._running:
                try:
                    data = await asyncio.wait_for(
                        reader.read(self.config.buffer_size),
                        timeout=self.config.idle_timeout,
                    )
                except TimeoutError:
                    logger.debug("Connection idle timeout", connection_id=connection_id.hex())
                    break

                if not data:
                    break

                # Send data through tunnel
                msg = TcpRelayMessage.encode_data(connection_id, data)
                if self._transport:
                    await self._transport.send(msg)
                    self._stats.bytes_sent += len(data)
                    self._stats.packets_sent += 1
                    self._stats.last_activity = time.time()

        except Exception as e:
            logger.debug("Local connection error", error=str(e))
        finally:
            # Cleanup
            del self._connections[connection_id]

            # Send close message
            if self._transport and self._running:
                close_msg = TcpRelayMessage.encode_close(connection_id)
                with contextlib.suppress(Exception):
                    await self._transport.send(close_msg)

            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()

            logger.debug("Local connection closed", connection_id=connection_id.hex())

    async def _receive_loop(self) -> None:
        """Receive and handle messages from server."""
        import time

        while self._running and self._transport:
            try:
                data = await asyncio.wait_for(
                    self._transport.recv(),
                    timeout=self.config.keepalive_interval * 2,
                )
                if data is None:
                    continue

                decoded = TcpRelayMessage.decode(data)
                if decoded is None:
                    continue

                msg_type, msg_data = decoded
                self._stats.last_activity = time.time()

                if msg_type == TcpRelayMessage.DATA:
                    # Forward data to local connection
                    connection_id = msg_data["connection_id"]
                    payload = msg_data["data"]

                    if connection_id in self._connections:
                        _, writer = self._connections[connection_id]
                        writer.write(payload)
                        await writer.drain()
                        self._stats.bytes_received += len(payload)
                        self._stats.packets_received += 1

                elif msg_type == TcpRelayMessage.CLOSE:
                    # Close local connection
                    connection_id = msg_data["connection_id"]
                    if connection_id in self._connections:
                        _, writer = self._connections[connection_id]
                        writer.close()

                elif msg_type == TcpRelayMessage.KEEPALIVE:
                    # Respond to keepalive
                    pass

            except TimeoutError:
                # Send keepalive
                if self._transport:
                    keepalive = TcpRelayMessage.encode_keepalive(self._tunnel_id)
                    try:
                        await self._transport.send(keepalive)
                    except Exception:
                        break

            except Exception as e:
                logger.error("Receive error", error=str(e))
                break

    async def _keepalive_loop(self) -> None:
        """Send periodic keepalive messages."""
        while self._running and self._transport:
            await asyncio.sleep(self.config.keepalive_interval)
            if self._running and self._transport:
                keepalive = TcpRelayMessage.encode_keepalive(self._tunnel_id)
                try:
                    await self._transport.send(keepalive)
                except Exception:
                    break

    async def close(self) -> None:
        """Close the tunnel and cleanup."""
        self._set_state(TcpTunnelState.CLOSING)
        self._running = False

        # Cancel tasks
        if self._recv_task:
            self._recv_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._recv_task

        if self._keepalive_task:
            self._keepalive_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._keepalive_task

        # Close all local connections
        for _connection_id, (_, writer) in list(self._connections.items()):
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()
        self._connections.clear()

        # Close local server
        if self._local_server:
            self._local_server.close()
            await self._local_server.wait_closed()

        # Close transport
        if self._transport:
            await self._transport.close()

        self._set_state(TcpTunnelState.CLOSED)
        logger.info("TCP tunnel closed", stats=self._stats)

    async def __aenter__(self) -> TcpTunnelClient:
        """Async context manager entry."""
        await self.connect()
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Async context manager exit."""
        await self.close()


async def start_tcp_tunnel(
    local_port: int,
    server_addr: str = "instanton.dev",
    remote_port: int | None = None,
    use_quic: bool = False,
) -> TcpTunnelClient:
    """Convenience function to start a TCP tunnel.

    Args:
        local_port: Local port to tunnel
        server_addr: Server address
        remote_port: Optional specific remote port
        use_quic: Use QUIC transport

    Returns:
        Connected TcpTunnelClient instance
    """
    config = TcpTunnelConfig(
        local_port=local_port,
        remote_port=remote_port,
    )
    client = TcpTunnelClient(
        config=config,
        server_addr=server_addr,
        use_quic=use_quic,
    )
    await client.connect()
    return client
