"""UDP tunnel client implementation.

Provides UDP tunneling for:
- VoIP/SIP protocols
- Gaming traffic
- DNS queries
- Real-time streaming
- Any UDP-based protocol
"""

from __future__ import annotations

import asyncio
import contextlib
import struct
from dataclasses import dataclass, field
from enum import Enum
from typing import Any
from uuid import UUID, uuid4

import structlog

from instanton.core.transport import QuicTransport, Transport, WebSocketTransport

logger = structlog.get_logger()


class UdpTunnelState(Enum):
    """UDP tunnel connection state."""

    DISCONNECTED = "disconnected"
    CONNECTING = "connecting"
    CONNECTED = "connected"
    RELAYING = "relaying"
    CLOSING = "closing"
    CLOSED = "closed"


@dataclass
class UdpTunnelStats:
    """Statistics for UDP tunnel."""

    tunnel_id: UUID = field(default_factory=uuid4)
    datagrams_sent: int = 0
    datagrams_received: int = 0
    bytes_sent: int = 0
    bytes_received: int = 0
    datagrams_dropped: int = 0
    start_time: float = 0.0
    last_activity: float = 0.0


@dataclass
class UdpTunnelConfig:
    """Configuration for UDP tunnel."""

    local_host: str = "127.0.0.1"
    local_port: int = 53  # Default to DNS
    remote_port: int | None = None  # Remote port on server
    max_datagram_size: int = 1400  # MTU-safe default
    connect_timeout: float = 30.0
    idle_timeout: float = 300.0
    keepalive_interval: float = 30.0


class UdpRelayMessage:
    """Message types for UDP relay protocol."""

    # Message types
    BIND = 0x01  # Bind request
    BIND_ACK = 0x02  # Bind acknowledgment
    DATAGRAM = 0x03  # UDP datagram
    CLOSE = 0x04  # Close tunnel
    KEEPALIVE = 0x05  # Keepalive ping
    ERROR = 0x06  # Error message

    @staticmethod
    def encode_bind(
        tunnel_id: bytes,
        local_port: int,
        remote_port: int | None = None,
    ) -> bytes:
        """Encode a bind message."""
        msg = bytearray()
        msg.append(UdpRelayMessage.BIND)
        msg.extend(tunnel_id[:16].ljust(16, b"\x00"))
        msg.extend(struct.pack(">H", local_port))
        msg.extend(struct.pack(">H", remote_port or 0))
        return bytes(msg)

    @staticmethod
    def encode_bind_ack(
        tunnel_id: bytes,
        assigned_port: int,
        error: str | None = None,
    ) -> bytes:
        """Encode a bind acknowledgment."""
        msg = bytearray()
        msg.append(UdpRelayMessage.BIND_ACK)
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
    def encode_datagram(
        source_addr: tuple[str, int],
        dest_addr: tuple[str, int],
        data: bytes,
    ) -> bytes:
        """Encode a datagram message."""
        import socket

        msg = bytearray()
        msg.append(UdpRelayMessage.DATAGRAM)

        # Source address (4 bytes IP + 2 bytes port)
        src_ip = socket.inet_aton(source_addr[0])
        msg.extend(src_ip)
        msg.extend(struct.pack(">H", source_addr[1]))

        # Dest address (4 bytes IP + 2 bytes port)
        dst_ip = socket.inet_aton(dest_addr[0])
        msg.extend(dst_ip)
        msg.extend(struct.pack(">H", dest_addr[1]))

        # Data length + data
        msg.extend(struct.pack(">H", len(data)))
        msg.extend(data)

        return bytes(msg)

    @staticmethod
    def encode_close(tunnel_id: bytes) -> bytes:
        """Encode a close message."""
        msg = bytearray()
        msg.append(UdpRelayMessage.CLOSE)
        msg.extend(tunnel_id[:16].ljust(16, b"\x00"))
        return bytes(msg)

    @staticmethod
    def encode_keepalive(tunnel_id: bytes) -> bytes:
        """Encode a keepalive message."""
        msg = bytearray()
        msg.append(UdpRelayMessage.KEEPALIVE)
        msg.extend(tunnel_id[:16].ljust(16, b"\x00"))
        return bytes(msg)

    @staticmethod
    def decode(data: bytes) -> tuple[int, dict[str, Any]] | None:
        """Decode a UDP relay message."""
        import socket

        if len(data) < 1:
            return None

        msg_type = data[0]

        if msg_type == UdpRelayMessage.BIND:
            if len(data) < 21:
                return None
            return msg_type, {
                "tunnel_id": data[1:17],
                "local_port": struct.unpack(">H", data[17:19])[0],
                "remote_port": struct.unpack(">H", data[19:21])[0],
            }

        elif msg_type == UdpRelayMessage.BIND_ACK:
            if len(data) < 20:
                return None
            error_len = data[19]
            error = data[20 : 20 + error_len].decode("utf-8") if error_len > 0 else None
            return msg_type, {
                "tunnel_id": data[1:17],
                "assigned_port": struct.unpack(">H", data[17:19])[0],
                "error": error,
            }

        elif msg_type == UdpRelayMessage.DATAGRAM:
            if len(data) < 15:
                return None
            src_ip = socket.inet_ntoa(data[1:5])
            src_port = struct.unpack(">H", data[5:7])[0]
            dst_ip = socket.inet_ntoa(data[7:11])
            dst_port = struct.unpack(">H", data[11:13])[0]
            data_len = struct.unpack(">H", data[13:15])[0]
            if len(data) < 15 + data_len:
                return None
            return msg_type, {
                "source_addr": (src_ip, src_port),
                "dest_addr": (dst_ip, dst_port),
                "data": data[15 : 15 + data_len],
            }

        elif msg_type == UdpRelayMessage.CLOSE or msg_type == UdpRelayMessage.KEEPALIVE:
            if len(data) < 17:
                return None
            return msg_type, {
                "tunnel_id": data[1:17],
            }

        return None


class UdpTunnelProtocol(asyncio.DatagramProtocol):
    """Protocol handler for local UDP socket."""

    def __init__(
        self,
        tunnel: UdpTunnelClient,
        callback: Any,
    ) -> None:
        """Initialize protocol.

        Args:
            tunnel: Parent tunnel client
            callback: Callback for received datagrams
        """
        self.tunnel = tunnel
        self.callback = callback
        self.transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport: asyncio.DatagramTransport) -> None:  # type: ignore[override]
        """Called when connection is established."""
        self.transport = transport
        logger.debug("UDP socket ready")

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        """Called when a datagram is received."""
        if self.callback:
            asyncio.create_task(self.callback(data, addr))

    def error_received(self, exc: Exception) -> None:
        """Called when an error is received."""
        logger.warning("UDP socket error", error=str(exc))

    def connection_lost(self, exc: Exception | None) -> None:
        """Called when connection is lost."""
        logger.debug("UDP socket closed", error=str(exc) if exc else None)


class UdpTunnelClient:
    """Client for establishing UDP tunnels.

    Features:
    - Transparent UDP proxy
    - Low latency datagram forwarding
    - Automatic reconnection
    - Keepalive for NAT traversal
    - Bandwidth statistics
    """

    def __init__(
        self,
        config: UdpTunnelConfig | None = None,
        server_addr: str = "instanton.dev",
        use_quic: bool = True,  # QUIC preferred for UDP
    ) -> None:
        """Initialize UDP tunnel client.

        Args:
            config: Tunnel configuration
            server_addr: Server address
            use_quic: Use QUIC transport (recommended for UDP)
        """
        self.config = config or UdpTunnelConfig()
        self.server_addr = server_addr
        self.use_quic = use_quic

        self._state = UdpTunnelState.DISCONNECTED
        self._transport: Transport | None = None
        self._tunnel_id: bytes = uuid4().bytes
        self._assigned_port: int | None = None
        self._stats = UdpTunnelStats()
        self._running = False

        # UDP socket for local traffic
        self._udp_transport: asyncio.DatagramTransport | None = None
        self._udp_protocol: UdpTunnelProtocol | None = None

        # Client address mapping for responses
        self._client_addrs: dict[tuple[str, int], tuple[str, int]] = {}

        # State hooks
        self._state_hooks: list[Any] = []

        # Tasks
        self._recv_task: asyncio.Task[Any] | None = None
        self._keepalive_task: asyncio.Task[Any] | None = None

    @property
    def state(self) -> UdpTunnelState:
        """Get current tunnel state."""
        return self._state

    @property
    def stats(self) -> UdpTunnelStats:
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
            return f"udp://{self.server_addr}:{self._assigned_port}"
        return None

    def _set_state(self, state: UdpTunnelState) -> None:
        """Set state and notify hooks."""
        old_state = self._state
        if old_state == state:
            return

        self._state = state
        logger.debug("UDP tunnel state change", old=old_state.value, new=state.value)

        for hook in self._state_hooks:
            try:
                hook(state)
            except Exception as e:
                logger.warning("State hook error", error=str(e))

    async def connect(self) -> str:
        """Connect to the server and establish UDP tunnel.

        Returns:
            The tunnel URL (udp://server:port)
        """
        import time

        self._set_state(UdpTunnelState.CONNECTING)
        self._stats.start_time = time.time()

        # Create transport (QUIC preferred for UDP tunneling)
        if self.use_quic:
            self._transport = QuicTransport()
        else:
            self._transport = WebSocketTransport()

        # Connect to server
        try:
            await self._transport.connect(
                self.server_addr,
                path="/udp",  # UDP tunnel endpoint
            )
        except Exception as e:
            logger.error("Failed to connect to server", error=str(e))
            self._set_state(UdpTunnelState.DISCONNECTED)
            raise

        # Send bind request
        bind_msg = UdpRelayMessage.encode_bind(
            tunnel_id=self._tunnel_id,
            local_port=self.config.local_port,
            remote_port=self.config.remote_port,
        )
        await self._transport.send(bind_msg)

        # Wait for acknowledgment
        try:
            response = await asyncio.wait_for(
                self._transport.recv(),
                timeout=self.config.connect_timeout,
            )
            if response is None:
                raise RuntimeError("No response from server")
            decoded = UdpRelayMessage.decode(response)

            if decoded is None:
                raise RuntimeError("Invalid response from server")

            msg_type, msg_data = decoded

            if msg_type != UdpRelayMessage.BIND_ACK:
                raise RuntimeError(f"Unexpected message type: {msg_type}")

            if msg_data.get("error"):
                raise RuntimeError(f"Server error: {msg_data['error']}")

            self._assigned_port = msg_data["assigned_port"]

        except TimeoutError as err:
            logger.error("Connection timeout")
            self._set_state(UdpTunnelState.DISCONNECTED)
            raise RuntimeError("Connection timeout") from err

        self._set_state(UdpTunnelState.CONNECTED)
        self._running = True

        logger.info(
            "UDP tunnel established",
            local_port=self.config.local_port,
            remote_port=self._assigned_port,
            tunnel_url=self.tunnel_url,
        )

        return self.tunnel_url or ""

    async def run(self) -> None:
        """Run the tunnel, handling datagrams."""
        if self._state != UdpTunnelState.CONNECTED:
            raise RuntimeError("Not connected")

        self._set_state(UdpTunnelState.RELAYING)

        # Create local UDP socket
        loop = asyncio.get_event_loop()
        self._udp_transport, self._udp_protocol = await loop.create_datagram_endpoint(
            lambda: UdpTunnelProtocol(self, self._handle_local_datagram),
            local_addr=(self.config.local_host, self.config.local_port),
        )

        # Start receive task
        self._recv_task = asyncio.create_task(self._receive_loop())

        # Start keepalive task
        self._keepalive_task = asyncio.create_task(self._keepalive_loop())

        logger.info(
            "UDP tunnel listening",
            host=self.config.local_host,
            port=self.config.local_port,
        )

        # Wait until closed
        while self._running:
            await asyncio.sleep(1.0)

    async def _handle_local_datagram(
        self,
        data: bytes,
        addr: tuple[str, int],
    ) -> None:
        """Handle a datagram received from local UDP socket."""
        import time

        if not self._transport or not self._running:
            return

        # Track client address for responses
        # Use a simple hash as key
        self._client_addrs[addr] = addr

        # Forward to server
        msg = UdpRelayMessage.encode_datagram(
            source_addr=addr,
            dest_addr=(self.server_addr, self._assigned_port or 0),
            data=data,
        )

        try:
            await self._transport.send(msg)
            self._stats.datagrams_sent += 1
            self._stats.bytes_sent += len(data)
            self._stats.last_activity = time.time()
        except Exception as e:
            logger.warning("Failed to send datagram", error=str(e))
            self._stats.datagrams_dropped += 1

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

                decoded = UdpRelayMessage.decode(data)
                if decoded is None:
                    continue

                msg_type, msg_data = decoded
                self._stats.last_activity = time.time()

                if msg_type == UdpRelayMessage.DATAGRAM:
                    # Forward datagram to local client
                    payload = msg_data["data"]
                    dest_addr = msg_data["dest_addr"]

                    if self._udp_transport:
                        self._udp_transport.sendto(payload, dest_addr)
                        self._stats.datagrams_received += 1
                        self._stats.bytes_received += len(payload)

                elif msg_type == UdpRelayMessage.CLOSE:
                    logger.info("Server closed tunnel")
                    break

                elif msg_type == UdpRelayMessage.KEEPALIVE:
                    pass

            except TimeoutError:
                # Send keepalive
                if self._transport:
                    keepalive = UdpRelayMessage.encode_keepalive(self._tunnel_id)
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
                keepalive = UdpRelayMessage.encode_keepalive(self._tunnel_id)
                try:
                    await self._transport.send(keepalive)
                except Exception:
                    break

    async def close(self) -> None:
        """Close the tunnel and cleanup."""
        self._set_state(UdpTunnelState.CLOSING)
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

        # Close UDP socket
        if self._udp_transport:
            self._udp_transport.close()

        # Send close message
        if self._transport:
            close_msg = UdpRelayMessage.encode_close(self._tunnel_id)
            with contextlib.suppress(Exception):
                await self._transport.send(close_msg)
            await self._transport.close()

        self._set_state(UdpTunnelState.CLOSED)
        logger.info("UDP tunnel closed", stats=self._stats)

    async def __aenter__(self) -> UdpTunnelClient:
        """Async context manager entry."""
        await self.connect()
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Async context manager exit."""
        await self.close()


async def start_udp_tunnel(
    local_port: int,
    server_addr: str = "instanton.dev",
    remote_port: int | None = None,
    use_quic: bool = True,
) -> UdpTunnelClient:
    """Convenience function to start a UDP tunnel.

    Args:
        local_port: Local port to tunnel
        server_addr: Server address
        remote_port: Optional specific remote port
        use_quic: Use QUIC transport (recommended)

    Returns:
        Connected UdpTunnelClient instance
    """
    config = UdpTunnelConfig(
        local_port=local_port,
        remote_port=remote_port,
    )
    client = UdpTunnelClient(
        config=config,
        server_addr=server_addr,
        use_quic=use_quic,
    )
    await client.connect()
    return client
