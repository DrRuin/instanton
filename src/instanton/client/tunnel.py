"""Tunnel client implementation with auto-reconnect and request proxying."""

from __future__ import annotations

import asyncio
import contextlib
import random
import time
from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum
from typing import Any
from uuid import UUID

import httpx
import structlog

from instanton.core.config import ClientConfig
from instanton.core.transport import QuicTransport, Transport, WebSocketTransport
from instanton.protocol.messages import (
    CHUNK_SIZE,
    ChunkAssembler,
    ChunkData,
    ChunkEnd,
    ChunkStart,
    CompressionType,
    ConnectRequest,
    ConnectResponse,
    Disconnect,
    HttpRequest,
    HttpResponse,
    NegotiateResponse,
    Ping,
    Pong,
    ProtocolNegotiator,
    create_chunks,
    decode_message,
    encode_message,
)

logger = structlog.get_logger()


class ConnectionState(Enum):
    """Client connection state."""

    DISCONNECTED = "disconnected"
    CONNECTING = "connecting"
    NEGOTIATING = "negotiating"
    CONNECTED = "connected"
    RECONNECTING = "reconnecting"
    CLOSED = "closed"


@dataclass
class ReconnectConfig:
    """Configuration for reconnection behavior."""

    enabled: bool = True
    max_attempts: int = 10
    base_delay: float = 1.0
    max_delay: float = 60.0
    jitter: float = 0.1


@dataclass
class ProxyConfig:
    """Configuration for request proxying.

    Attributes:
        connect_timeout: Timeout for establishing connection to local service.
        read_timeout: Timeout for reading response from local service.
            Set to None or 0 for no timeout (indefinite - for long-running APIs).
        write_timeout: Timeout for sending request to local service.
        pool_timeout: Timeout for getting connection from pool.
        max_connections: Maximum concurrent connections to local service.
        max_keepalive: Maximum keepalive connections to maintain.
        retry_count: Number of retry attempts on failure.
        retry_on_status: HTTP status codes to retry on.
        stream_timeout: Timeout for streaming connections.
            Set to None for indefinite streaming (real-time APIs).
    """

    connect_timeout: float = 5.0
    read_timeout: float | None = None  # None = no timeout (indefinite)
    write_timeout: float = 5.0
    pool_timeout: float = 5.0
    max_connections: int = 100
    max_keepalive: int = 20
    retry_count: int = 2
    retry_on_status: tuple[int, ...] = (502, 503, 504)
    stream_timeout: float | None = None  # None = indefinite streaming


class TunnelClient:
    """Client that establishes and manages a tunnel with auto-reconnect.

    Features:
    - Automatic reconnection with exponential backoff
    - Protocol negotiation for compression and streaming
    - Request proxying with configurable timeouts and retries
    - Connection state hooks for monitoring
    - Graceful shutdown
    """

    def __init__(
        self,
        local_port: int,
        server_addr: str = "instanton.dev",
        subdomain: str | None = None,
        use_quic: bool = False,
        config: ClientConfig | None = None,
        reconnect_config: ReconnectConfig | None = None,
        proxy_config: ProxyConfig | None = None,
    ) -> None:
        """Initialize tunnel client.

        Args:
            local_port: Local port to forward traffic to
            server_addr: Server address (hostname:port or just hostname)
            subdomain: Requested subdomain (optional, server may assign one)
            use_quic: Use QUIC transport instead of WebSocket
            config: Full client configuration (overrides individual params)
            reconnect_config: Reconnection behavior configuration
            proxy_config: Request proxying configuration
        """
        # Use config if provided, otherwise use individual params
        if config:
            self.local_port = config.local_port
            self.server_addr = config.server_addr
            self.subdomain = config.subdomain
            self.use_quic = config.use_quic
            self._keepalive_interval = config.keepalive_interval
        else:
            self.local_port = local_port
            self.server_addr = server_addr
            self.subdomain = subdomain
            self.use_quic = use_quic
            self._keepalive_interval = 30.0

        self.reconnect_config = reconnect_config or ReconnectConfig()
        self.proxy_config = proxy_config or ProxyConfig()

        # Connection state
        self._state = ConnectionState.DISCONNECTED
        self._transport: Transport | None = None
        self._tunnel_id: UUID | None = None
        self._url: str | None = None
        self._assigned_subdomain: str | None = None
        self._running = False
        self._reconnect_attempt = 0

        # Protocol negotiation
        self._negotiator = ProtocolNegotiator()
        self._compression: CompressionType = CompressionType.NONE
        self._streaming_enabled = False
        self._chunk_size = CHUNK_SIZE

        # HTTP client for proxying
        self._http_client: httpx.AsyncClient | None = None

        # Streaming support
        self._chunk_assembler = ChunkAssembler()

        # State change hooks
        self._state_hooks: list[Callable[[ConnectionState], None]] = []

        # Metrics
        self._connect_time: float | None = None
        self._requests_proxied = 0
        self._bytes_sent = 0
        self._bytes_received = 0

    @property
    def state(self) -> ConnectionState:
        """Get current connection state."""
        return self._state

    @property
    def tunnel_id(self) -> UUID | None:
        """Get tunnel ID if connected."""
        return self._tunnel_id

    @property
    def url(self) -> str | None:
        """Get public URL if connected."""
        return self._url

    @property
    def is_connected(self) -> bool:
        """Check if connected to server."""
        return self._state == ConnectionState.CONNECTED

    @property
    def stats(self) -> dict[str, Any]:
        """Get connection statistics."""
        return {
            "state": self._state.value,
            "tunnel_id": str(self._tunnel_id) if self._tunnel_id else None,
            "url": self._url,
            "requests_proxied": self._requests_proxied,
            "bytes_sent": self._bytes_sent,
            "bytes_received": self._bytes_received,
            "compression": self._compression.name,
            "streaming_enabled": self._streaming_enabled,
            "reconnect_attempts": self._reconnect_attempt,
        }

    def add_state_hook(self, hook: Callable[[ConnectionState], None]) -> None:
        """Add a hook to be called on state changes."""
        self._state_hooks.append(hook)

    def remove_state_hook(self, hook: Callable[[ConnectionState], None]) -> None:
        """Remove a state change hook."""
        if hook in self._state_hooks:
            self._state_hooks.remove(hook)

    def _set_state(self, state: ConnectionState) -> None:
        """Set state and notify hooks."""
        if self._state != state:
            old_state = self._state
            self._state = state
            logger.debug("State changed", old=old_state.value, new=state.value)
            for hook in self._state_hooks:
                try:
                    hook(state)
                except Exception as e:
                    logger.warning("State hook error", error=str(e))

    async def _create_transport(self) -> Transport:
        """Create transport based on configuration."""
        if self.use_quic:
            return QuicTransport()
        return WebSocketTransport()

    async def _create_http_client(self) -> httpx.AsyncClient:
        """Create HTTP client for proxying requests.

        Supports indefinite timeouts (None) for long-running APIs and streaming.
        """
        # httpx uses None for no timeout (indefinite wait)
        timeout = httpx.Timeout(
            connect=self.proxy_config.connect_timeout,
            read=self.proxy_config.read_timeout,  # None = indefinite
            write=self.proxy_config.write_timeout,
            pool=self.proxy_config.pool_timeout,
        )
        limits = httpx.Limits(
            max_connections=self.proxy_config.max_connections,
            max_keepalive_connections=self.proxy_config.max_keepalive,
        )
        return httpx.AsyncClient(
            timeout=timeout,
            limits=limits,
            follow_redirects=True,
        )

    async def connect(self) -> str:
        """Connect to server and establish tunnel.

        Returns:
            Public URL for the tunnel

        Raises:
            ConnectionError: If connection fails
        """
        self._set_state(ConnectionState.CONNECTING)
        start_time = time.monotonic()

        try:
            # Create transport
            self._transport = await self._create_transport()
            await self._transport.connect(self.server_addr)

            # Negotiate protocol features
            self._set_state(ConnectionState.NEGOTIATING)
            await self._negotiate_protocol()

            # Send connect request
            request = ConnectRequest(
                subdomain=self.subdomain,
                local_port=self.local_port,
            )
            await self._send_message(request)

            # Wait for response
            data = await self._transport.recv()
            if not data:
                raise ConnectionError("No response from server")

            msg = decode_message(data)
            response = ConnectResponse(**msg)

            if response.type == "error":
                raise ConnectionError(f"Connection failed: {response.error}")

            self._tunnel_id = response.tunnel_id
            self._url = response.url
            self._assigned_subdomain = response.subdomain
            self._connect_time = time.monotonic() - start_time
            self._reconnect_attempt = 0

            logger.info(
                "Tunnel established",
                tunnel_id=str(self._tunnel_id),
                url=self._url,
                connect_time_ms=int(self._connect_time * 1000),
            )

            # Create HTTP client for proxying
            self._http_client = await self._create_http_client()

            self._set_state(ConnectionState.CONNECTED)
            return self._url

        except Exception as e:
            self._set_state(ConnectionState.DISCONNECTED)
            logger.error("Connection failed", error=str(e))
            raise ConnectionError(f"Failed to connect: {e}") from e

    async def _negotiate_protocol(self) -> None:
        """Negotiate protocol features with server."""
        if not self._transport:
            return

        # Send negotiation request
        request = self._negotiator.create_request()
        await self._send_message(request)

        # Wait for response
        data = await self._transport.recv()
        if not data:
            logger.warning("No negotiation response, using defaults")
            return

        msg = decode_message(data)
        if msg.get("type") != "negotiate_response":
            # Server doesn't support negotiation, continue with defaults
            logger.debug("Server doesn't support negotiation")
            return

        response = NegotiateResponse(**msg)
        if self._negotiator.apply_response(response):
            self._compression = self._negotiator.negotiated_compression
            self._streaming_enabled = self._negotiator.streaming_enabled
            self._chunk_size = self._negotiator.chunk_size
            logger.info(
                "Protocol negotiated",
                compression=self._compression.name,
                streaming=self._streaming_enabled,
                chunk_size=self._chunk_size,
            )
        else:
            logger.warning("Protocol negotiation failed", error=response.error)

    async def _send_message(self, msg: Any) -> None:
        """Send a message with negotiated compression."""
        if not self._transport:
            return
        encoded = encode_message(msg, self._compression)
        await self._transport.send(encoded)
        self._bytes_sent += len(encoded)

    async def run(self) -> None:
        """Main loop - handle incoming requests with auto-reconnect."""
        self._running = True

        while self._running:
            try:
                if self._state == ConnectionState.CONNECTED:
                    await self._run_connected()
                elif self._state in (
                    ConnectionState.DISCONNECTED,
                    ConnectionState.RECONNECTING,
                ):
                    if self.reconnect_config.enabled:
                        await self._attempt_reconnect()
                    else:
                        break
                else:
                    await asyncio.sleep(0.1)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("Unexpected error in run loop", error=str(e))
                await asyncio.sleep(1.0)

    async def _run_connected(self) -> None:
        """Run the main message loop while connected."""
        keepalive_task = asyncio.create_task(self._keepalive_loop())

        try:
            while self._running and self._transport and self._transport.is_connected():
                data = await self._transport.recv()
                if not data:
                    logger.warning("Connection lost")
                    break

                self._bytes_received += len(data)
                await self._handle_message(data)
        except Exception as e:
            logger.error("Error in message loop", error=str(e))
        finally:
            keepalive_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await keepalive_task

        # Connection lost - prepare for reconnect
        if self._running and self.reconnect_config.enabled:
            self._set_state(ConnectionState.RECONNECTING)
        else:
            self._set_state(ConnectionState.DISCONNECTED)

    async def _attempt_reconnect(self) -> None:
        """Attempt to reconnect with exponential backoff."""
        if self._reconnect_attempt >= self.reconnect_config.max_attempts:
            logger.error(
                "Max reconnect attempts reached",
                attempts=self._reconnect_attempt,
            )
            self._set_state(ConnectionState.CLOSED)
            return

        self._reconnect_attempt += 1
        self._set_state(ConnectionState.RECONNECTING)

        # Calculate delay with exponential backoff and jitter
        delay = min(
            self.reconnect_config.base_delay * (2 ** (self._reconnect_attempt - 1)),
            self.reconnect_config.max_delay,
        )
        jitter = delay * self.reconnect_config.jitter * random.random()
        delay += jitter

        logger.info(
            "Reconnecting",
            attempt=self._reconnect_attempt,
            max_attempts=self.reconnect_config.max_attempts,
            delay_sec=round(delay, 2),
        )

        await asyncio.sleep(delay)

        # Clean up old transport
        if self._transport:
            with contextlib.suppress(Exception):
                await self._transport.close()
            self._transport = None

        # Clean up old HTTP client
        if self._http_client:
            with contextlib.suppress(Exception):
                await self._http_client.aclose()
            self._http_client = None

        try:
            await self.connect()
        except ConnectionError as e:
            logger.warning(
                "Reconnect failed",
                attempt=self._reconnect_attempt,
                error=str(e),
            )

    async def _handle_message(self, data: bytes) -> None:
        """Handle incoming message from server."""
        try:
            msg = decode_message(data)
        except Exception as e:
            logger.error("Failed to decode message", error=str(e))
            return

        msg_type = msg.get("type")

        if msg_type == "http_request":
            request = HttpRequest(**msg)
            await self._handle_http_request(request)
        elif msg_type == "pong":
            pong = Pong(**msg)
            logger.debug("Received pong", timestamp=pong.timestamp)
        elif msg_type == "chunk_start":
            chunk_start = ChunkStart(**msg)
            self._chunk_assembler.start_stream(chunk_start)
        elif msg_type == "chunk_data":
            chunk_data = ChunkData(**msg)
            self._chunk_assembler.add_chunk(chunk_data)
        elif msg_type == "chunk_end":
            chunk_end = ChunkEnd(**msg)
            assembled = self._chunk_assembler.end_stream(chunk_end)
            # Handle assembled data (would typically be processed as a request)
            logger.debug("Assembled chunk", size=len(assembled))
        elif msg_type == "disconnect":
            disconnect = Disconnect(**msg)
            logger.info("Server requested disconnect", reason=disconnect.reason)
            self._running = False
        else:
            logger.warning("Unknown message type", type=msg_type)

    async def _handle_http_request(self, request: HttpRequest) -> None:
        """Proxy HTTP request to local service with retry logic."""
        if not self._http_client:
            return

        url = f"http://localhost:{self.local_port}{request.path}"

        logger.info(
            "Proxying request",
            request_id=str(request.request_id),
            method=request.method,
            path=request.path,
        )

        response: HttpResponse | None = None
        last_error: Exception | None = None

        # Retry loop
        for attempt in range(self.proxy_config.retry_count + 1):
            try:
                resp = await self._http_client.request(
                    method=request.method,
                    url=url,
                    headers=request.headers,
                    content=request.body,
                )

                # Check if we should retry on this status
                if (
                    resp.status_code in self.proxy_config.retry_on_status
                    and attempt < self.proxy_config.retry_count
                ):
                    logger.debug(
                        "Retrying request",
                        status=resp.status_code,
                        attempt=attempt + 1,
                    )
                    await asyncio.sleep(0.1 * (attempt + 1))
                    continue

                response = HttpResponse(
                    request_id=request.request_id,
                    status=resp.status_code,
                    headers=dict(resp.headers),
                    body=resp.content,
                )
                break

            except httpx.ConnectError as e:
                last_error = e
                logger.warning(
                    "Local service connection failed",
                    attempt=attempt + 1,
                    error=str(e),
                )
                if attempt < self.proxy_config.retry_count:
                    await asyncio.sleep(0.1 * (attempt + 1))
            except httpx.TimeoutException as e:
                last_error = e
                logger.warning(
                    "Request timeout",
                    attempt=attempt + 1,
                    error=str(e),
                )
                if attempt < self.proxy_config.retry_count:
                    await asyncio.sleep(0.1 * (attempt + 1))
            except httpx.RequestError as e:
                last_error = e
                logger.error("Proxy request error", error=str(e))
                break  # Don't retry on other request errors

        if response is None:
            # All retries failed
            error_msg = str(last_error) if last_error else "Unknown error"
            logger.error("Proxy failed after retries", error=error_msg)
            response = HttpResponse(
                request_id=request.request_id,
                status=502,
                headers={"Content-Type": "text/plain"},
                body=f"Bad Gateway: {error_msg}".encode(),
            )

        # Send response back through tunnel
        if self._transport:
            self._requests_proxied += 1

            # Use streaming for large responses if enabled
            if self._streaming_enabled and len(response.body) > self._chunk_size:
                await self._send_chunked_response(response)
            else:
                await self._send_message(response)

    async def _send_chunked_response(self, response: HttpResponse) -> None:
        """Send a large response using chunked streaming."""
        start, chunks, end = create_chunks(
            response.body,
            response.request_id,
            self._chunk_size,
            response.headers.get("Content-Type", "application/octet-stream"),
        )

        # Send chunk start
        await self._send_message(start)

        # Send all chunks
        for chunk in chunks:
            await self._send_message(chunk)

        # Send chunk end
        await self._send_message(end)

        logger.debug(
            "Sent chunked response",
            request_id=str(response.request_id),
            total_chunks=len(chunks),
        )

    async def _keepalive_loop(self) -> None:
        """Send periodic pings to keep connection alive."""
        while self._running and self._transport:
            await asyncio.sleep(self._keepalive_interval)
            if not self._running or not self._transport:
                break

            ping = Ping(timestamp=int(time.time() * 1000))
            try:
                await self._send_message(ping)
                logger.debug("Sent ping", timestamp=ping.timestamp)
            except Exception as e:
                logger.warning("Failed to send ping", error=str(e))
                break

    async def close(self) -> None:
        """Close the tunnel gracefully."""
        self._running = False
        self._set_state(ConnectionState.CLOSED)

        # Send disconnect message if connected
        if self._transport and self._transport.is_connected():
            try:
                disconnect = Disconnect(reason="Client closing")
                await self._send_message(disconnect)
            except Exception:
                pass

        # Close HTTP client
        if self._http_client:
            with contextlib.suppress(Exception):
                await self._http_client.aclose()
            self._http_client = None

        # Close transport
        if self._transport:
            with contextlib.suppress(Exception):
                await self._transport.close()
            self._transport = None

        logger.info("Tunnel closed", stats=self.stats)

    async def __aenter__(self) -> TunnelClient:
        """Async context manager entry."""
        await self.connect()
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Async context manager exit."""
        await self.close()
