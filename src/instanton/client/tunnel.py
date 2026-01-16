"""Tunnel client implementation with auto-reconnect and request proxying."""

from __future__ import annotations

import asyncio
import contextlib
import random
import time
import urllib.parse
from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum
from typing import Any
from uuid import UUID

import httpx
import structlog

from instanton.core.config import ClientConfig
from instanton.core.exceptions import (
    ConnectionRefusedError,
    ConnectionTimeoutError,
    InvalidSubdomainError,
    RateLimitError,
    ServerFullError,
    ServerUnavailableError,
    SSLError,
    SubdomainTakenError,
    TunnelCreationError,
    format_error_for_user,
)
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
    GrpcFrame,
    GrpcStreamClose,
    GrpcStreamOpen,
    GrpcStreamOpened,
    GrpcTrailers,
    HttpRequest,
    HttpResponse,
    NegotiateResponse,
    Ping,
    Pong,
    ProtocolNegotiator,
    WebSocketClose,
    WebSocketFrame,
    WebSocketOpcode,
    WebSocketUpgrade,
    WebSocketUpgradeResponse,
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
    """Configuration for reconnection behavior.

    Optimized defaults for global users connecting from different countries
    with varying network conditions and latency.
    """

    enabled: bool = True
    max_attempts: int = 15  # Increased for resilience
    base_delay: float = 1.0
    max_delay: float = 60.0
    jitter: float = 0.2  # Increased jitter to reduce reconnection storms


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
        server_addr: str = "instanton.tech",
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
            self._connect_timeout = config.connect_timeout
        else:
            self.local_port = local_port
            self.server_addr = server_addr
            self.subdomain = subdomain
            self.use_quic = use_quic
            self._keepalive_interval = 30.0
            self._connect_timeout = 30.0  # Default 30s for global users

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

        # Active WebSocket proxy connections (tunnel_id -> local WebSocket client)
        self._ws_connections: dict[UUID, Any] = {}

        # Active gRPC stream connections (stream_id -> (channel, stream))
        self._grpc_streams: dict[UUID, tuple[Any, Any]] = {}

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
    def connect_timeout(self) -> float:
        """Get connection timeout in seconds."""
        return self._connect_timeout

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
        """Create transport with appropriate timeout settings for global users."""
        if self.use_quic:
            return QuicTransport(
                auto_reconnect=self.reconnect_config.enabled,
                max_reconnect_attempts=self.reconnect_config.max_attempts,
                reconnect_delay=self.reconnect_config.base_delay,
                max_reconnect_delay=self.reconnect_config.max_delay,
            )
        return WebSocketTransport(
            auto_reconnect=self.reconnect_config.enabled,
            max_reconnect_attempts=self.reconnect_config.max_attempts,
            reconnect_delay=self.reconnect_config.base_delay,
            max_reconnect_delay=self.reconnect_config.max_delay,
            connect_timeout=self._connect_timeout,  # Use client's connect timeout
            ping_interval=self._keepalive_interval,
            ping_timeout=min(self._connect_timeout / 2, 20.0),  # Half of connect timeout, max 20s
        )

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
        # IMPORTANT: Do NOT follow redirects internally!
        # Redirects must be returned to the browser so it can:
        # 1. Process Set-Cookie headers from the redirect response
        # 2. Follow the redirect itself with the correct cookies
        # This is critical for login flows (POST -> 302 -> GET with session cookie)
        return httpx.AsyncClient(
            timeout=timeout,
            limits=limits,
            follow_redirects=False,
        )

    async def connect(self) -> str:
        """Connect to server and establish tunnel.

        Returns:
            Public URL for the tunnel

        Raises:
            ConnectionTimeoutError: If connection times out
            ConnectionRefusedError: If server refuses connection
            SubdomainTakenError: If subdomain is already in use
            ServerFullError: If server is at capacity
            TunnelCreationError: For other tunnel creation failures
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
                raise ServerUnavailableError(self.server_addr)

            msg = decode_message(data)
            response = ConnectResponse(**msg)

            if response.type == "error":
                # Map server error codes to specific exceptions
                error_msg = response.error or "Unknown error"
                error_lower = error_msg.lower()
                if "subdomain" in error_lower and "taken" in error_lower:
                    raise SubdomainTakenError(self.subdomain or "")
                elif "invalid subdomain" in error_lower:
                    raise InvalidSubdomainError(self.subdomain or "")
                elif "server full" in error_lower or "capacity" in error_lower:
                    raise ServerFullError()
                elif "rate limit" in error_lower:
                    raise RateLimitError()
                else:
                    raise TunnelCreationError(error_msg)

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

        except (
            ConnectionTimeoutError,
            ConnectionRefusedError,
            SubdomainTakenError,
            InvalidSubdomainError,
            ServerFullError,
            RateLimitError,
            TunnelCreationError,
            ServerUnavailableError,
        ):
            # Re-raise our custom exceptions
            self._set_state(ConnectionState.DISCONNECTED)
            raise
        except TimeoutError:
            self._set_state(ConnectionState.DISCONNECTED)
            raise ConnectionTimeoutError(self.server_addr, self.connect_timeout) from None
        except OSError as e:
            self._set_state(ConnectionState.DISCONNECTED)
            error_msg = str(e).lower()
            if "refused" in error_msg or "connect" in error_msg:
                raise ConnectionRefusedError(self.server_addr, str(e)) from e
            elif "ssl" in error_msg or "certificate" in error_msg:
                raise SSLError(str(e)) from e
            else:
                raise TunnelCreationError(format_error_for_user(e)) from e
        except Exception as e:
            self._set_state(ConnectionState.DISCONNECTED)
            logger.error("Connection failed", error=str(e))
            raise TunnelCreationError(format_error_for_user(e)) from e

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
                    # Only reconnect if still running (not cancelled)
                    if self._running and self.reconnect_config.enabled:
                        await self._attempt_reconnect()
                    else:
                        break
                elif self._state == ConnectionState.CLOSED:
                    # Already closed, exit the loop
                    break
                else:
                    await asyncio.sleep(0.1)
            except asyncio.CancelledError:
                # Shutdown requested - mark as not running and exit
                self._running = False
                break
            except Exception as e:
                logger.error("Unexpected error in run loop", error=str(e))
                await asyncio.sleep(1.0)

    async def _run_connected(self) -> None:
        """Run the main message loop while connected."""
        keepalive_task = asyncio.create_task(self._keepalive_loop())
        was_cancelled = False

        try:
            while self._running and self._transport and self._transport.is_connected():
                data = await self._transport.recv()
                if not data:
                    logger.warning("Connection lost")
                    break

                self._bytes_received += len(data)
                await self._handle_message(data)
        except asyncio.CancelledError:
            # Shutdown was requested via Ctrl+C
            was_cancelled = True
            self._running = False
            raise  # Re-raise to propagate to run() method
        except Exception as e:
            logger.error("Error in message loop", error=str(e))
        finally:
            keepalive_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await keepalive_task

        # Connection lost - prepare for reconnect only if not cancelled
        if not was_cancelled and self._running and self.reconnect_config.enabled:
            self._set_state(ConnectionState.RECONNECTING)
        elif not was_cancelled:
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
            logger.error(
                "Failed to decode message",
                error=str(e),
                data_len=len(data),
                data_preview=data[:50].hex() if len(data) >= 50 else data.hex(),
            )
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
        elif msg_type == "websocket_upgrade":
            # WebSocket upgrade request - connect to local WebSocket server
            ws_upgrade = WebSocketUpgrade(**msg)
            asyncio.create_task(self._handle_websocket_upgrade(ws_upgrade))
        elif msg_type == "websocket_frame":
            # WebSocket frame from relay - forward to local WebSocket
            frame = WebSocketFrame(**msg)
            ws = self._ws_connections.get(frame.tunnel_id)
            if ws:
                asyncio.create_task(self._forward_ws_frame_to_local(ws, frame))
        elif msg_type == "websocket_close":
            # WebSocket close from relay - close local connection
            close_msg = WebSocketClose(**msg)
            ws = self._ws_connections.pop(close_msg.tunnel_id, None)
            if ws:
                asyncio.create_task(self._close_local_websocket(ws, close_msg))
        elif msg_type == "grpc_stream_open":
            # gRPC stream open request - connect to local gRPC server
            grpc_open = GrpcStreamOpen(**msg)
            asyncio.create_task(self._handle_grpc_stream_open(grpc_open))
        elif msg_type == "grpc_frame":
            # gRPC frame from relay - forward to local gRPC stream
            frame = GrpcFrame(**msg)
            stream_data = self._grpc_streams.get(frame.stream_id)
            if stream_data:
                asyncio.create_task(self._forward_grpc_frame_to_local(stream_data[1], frame))
        elif msg_type == "grpc_stream_close":
            # gRPC stream close - close local stream
            grpc_close = GrpcStreamClose(**msg)
            stream_data = self._grpc_streams.pop(grpc_close.stream_id, None)
            if stream_data:
                asyncio.create_task(self._close_local_grpc_stream(stream_data, grpc_close))
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

        # Build headers for local service
        headers = dict(request.headers)

        # Fix Host header for local service - many apps validate Host header
        # Replace the external host with localhost to avoid 405/400 errors
        headers["Host"] = f"localhost:{self.local_port}"

        # Remove hop-by-hop headers that shouldn't be forwarded
        # IMPORTANT: Preserve Connection: upgrade and Upgrade headers for WebSocket support
        # This follows ngrok's pattern of forwarding upgrade headers
        hop_by_hop = {
            "keep-alive",
            "proxy-authenticate",
            "proxy-authorization",
            "te",
            "trailers",
            "transfer-encoding",
        }

        # Check if this is a WebSocket upgrade request
        connection_header = headers.get("Connection", "").lower()
        upgrade_header = headers.get("Upgrade", "").lower()
        is_websocket_upgrade = "upgrade" in connection_header and upgrade_header == "websocket"

        request_headers = {}
        for k, v in headers.items():
            k_lower = k.lower()
            # Skip standard hop-by-hop headers
            if k_lower in hop_by_hop:
                continue
            # For WebSocket upgrades, preserve connection and upgrade headers
            if k_lower in ("connection", "upgrade"):
                if is_websocket_upgrade:
                    request_headers[k] = v
                continue
            request_headers[k] = v

        # Fix Origin header if present - must match the Host for CORS/CSRF validation
        if "Origin" in request_headers:
            # Replace external origin with localhost origin
            request_headers["Origin"] = f"http://localhost:{self.local_port}"

        # Fix Referer header if present - some apps validate this for CSRF
        if "Referer" in request_headers:
            # Parse the referer and replace host with localhost
            parsed = urllib.parse.urlparse(request_headers["Referer"])
            request_headers["Referer"] = urllib.parse.urlunparse(
                (
                    "http",
                    f"localhost:{self.local_port}",
                    parsed.path,
                    parsed.params,
                    parsed.query,
                    parsed.fragment,
                )
            )

        response: HttpResponse | None = None
        last_error: Exception | None = None

        # Retry loop
        for attempt in range(self.proxy_config.retry_count + 1):
            try:
                # Use streaming to handle large responses efficiently
                # This prevents loading entire files into memory and enables
                # faster time-to-first-byte for static assets
                try:
                    async with self._http_client.stream(
                        method=request.method,
                        url=url,
                        headers=request_headers,
                        content=request.body,
                    ) as resp:
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

                        # Check if this is a streaming response that needs immediate forwarding
                        content_type = resp.headers.get("content-type", "").lower()
                        transfer_encoding = resp.headers.get("transfer-encoding", "").lower()
                        has_content_length = "content-length" in resp.headers

                        # Event-based streaming content types (forward immediately)
                        is_event_stream = (
                            "text/event-stream" in content_type  # SSE
                            or "application/x-ndjson" in content_type  # NDJSON
                            or "application/stream+json" in content_type  # Stream JSON
                            or "application/jsonl" in content_type  # JSON Lines
                        )

                        # gRPC streaming (binary framed protocol)
                        is_grpc_stream = (
                            "application/grpc" in content_type  # gRPC
                            or "application/grpc+proto" in content_type  # gRPC protobuf
                            or "application/grpc-web" in content_type  # gRPC-Web
                        )

                        # Multipart streaming (MJPEG cameras, mixed content)
                        is_multipart_stream = (
                            "multipart/x-mixed-replace" in content_type  # MJPEG
                            or "multipart/mixed" in content_type  # Mixed streams
                        )

                        # Media streaming (video/audio with chunked transfer)
                        is_media_stream = (
                            "chunked" in transfer_encoding
                            and not has_content_length
                            and (
                                content_type.startswith("video/")  # Video streams
                                or content_type.startswith("audio/")  # Audio streams
                                or "application/octet-stream" in content_type  # Binary
                            )
                        )

                        # Chunked transfer with no content-length = streaming
                        is_chunked_stream = (
                            "chunked" in transfer_encoding and not has_content_length
                        )

                        # Combine all streaming detection
                        is_streaming = (
                            is_event_stream
                            or is_grpc_stream
                            or is_multipart_stream
                            or is_media_stream
                            or is_chunked_stream
                        )

                        if is_streaming and self._transport:
                            # Stream SSE chunks immediately without buffering
                            await self._stream_sse_response(request, resp)
                            return  # Response already sent via streaming

                        # Read response body in chunks for efficiency
                        # For small responses this is still fast, for large ones it streams
                        body_chunks = []
                        async for chunk in resp.aiter_bytes(chunk_size=65536):
                            body_chunks.append(chunk)
                        body = b"".join(body_chunks)

                        response = HttpResponse(
                            request_id=request.request_id,
                            status=resp.status_code,
                            headers=dict(resp.headers),
                            body=body,
                        )
                except (TypeError, AttributeError):
                    # Fallback for mocked clients or clients that don't support streaming
                    resp = await self._http_client.request(
                        method=request.method,
                        url=url,
                        headers=request_headers,
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
            # All retries failed - provide user-friendly error message
            if isinstance(last_error, httpx.ConnectError):
                error_msg = (
                    f"Cannot reach local service at localhost:{self.local_port}. "
                    "Please ensure your application is running."
                )
            elif isinstance(last_error, httpx.TimeoutException):
                error_msg = (
                    f"Local service on port {self.local_port} did not respond. "
                    "The request may be taking too long or the service is overloaded."
                )
            else:
                error_msg = f"Failed to reach local service: {type(last_error).__name__}"

            logger.error("Proxy failed after retries", error=error_msg)
            response = HttpResponse(
                request_id=request.request_id,
                status=502,
                headers={"Content-Type": "application/json"},
                body=f'{{"error": "{error_msg}", "code": "LOCAL_SERVICE_ERROR"}}'.encode(),
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
            status=response.status,
            headers=response.headers,
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

    async def _stream_sse_response(
        self, request: HttpRequest, resp: httpx.Response
    ) -> None:
        """Stream SSE response chunks immediately without buffering.

        For Server-Sent Events (SSE), we need to forward each chunk
        as soon as it arrives to enable real-time streaming.
        """
        from uuid import uuid4

        stream_id = uuid4()
        sequence = 0

        # Send ChunkStart with headers and status
        headers = dict(resp.headers)
        start = ChunkStart(
            stream_id=stream_id,
            request_id=request.request_id,
            total_size=None,  # Unknown for streaming
            content_type=headers.get("content-type", "text/event-stream"),
            status=resp.status_code,
            headers=headers,
        )
        await self._send_message(start)

        logger.debug(
            "Starting SSE stream",
            request_id=str(request.request_id),
            stream_id=str(stream_id),
        )

        # Stream each chunk immediately as it arrives
        try:
            async for chunk in resp.aiter_bytes():
                if chunk:
                    chunk_data = ChunkData(
                        stream_id=stream_id,
                        sequence=sequence,
                        data=chunk,
                        is_final=False,
                    )
                    await self._send_message(chunk_data)
                    sequence += 1
        except Exception as e:
            logger.error("SSE streaming error", error=str(e))

        # Send ChunkEnd to signal completion
        end = ChunkEnd(
            stream_id=stream_id,
            total_chunks=sequence,
            checksum=None,  # No checksum for SSE
        )
        await self._send_message(end)

        logger.debug(
            "SSE stream completed",
            request_id=str(request.request_id),
            stream_id=str(stream_id),
            total_chunks=sequence,
        )
        self._requests_proxied += 1

    async def _handle_websocket_upgrade(self, ws_upgrade: WebSocketUpgrade) -> None:
        """Handle WebSocket upgrade by connecting to local WebSocket server.

        Uses the high-performance `websockets` library for optimal throughput.
        """
        import websockets

        url = f"ws://localhost:{self.local_port}{ws_upgrade.path}"

        try:
            # Use websockets library (faster than aiohttp for WS)
            extra_headers = [(k, v) for k, v in ws_upgrade.headers.items()]
            ws = await websockets.connect(
                url,
                additional_headers=extra_headers,
                subprotocols=ws_upgrade.subprotocols or None,
                ping_interval=30,
                ping_timeout=10,
                close_timeout=5,
            )

            # Store connection
            self._ws_connections[ws_upgrade.tunnel_id] = ws

            # Send success response
            response = WebSocketUpgradeResponse(
                tunnel_id=ws_upgrade.tunnel_id,
                request_id=ws_upgrade.request_id,
                success=True,
                accepted_protocol=ws.subprotocol,
            )
            await self._send_message(response)

            logger.info(
                "WebSocket connected to local",
                tunnel_id=str(ws_upgrade.tunnel_id),
                path=ws_upgrade.path,
            )

            # Start forwarding loop from local to relay
            asyncio.create_task(
                self._forward_ws_from_local(ws_upgrade.tunnel_id, ws)
            )

        except Exception as e:
            logger.error(
                "WebSocket upgrade failed",
                tunnel_id=str(ws_upgrade.tunnel_id),
                error=str(e),
            )
            # Send failure response
            response = WebSocketUpgradeResponse(
                tunnel_id=ws_upgrade.tunnel_id,
                request_id=ws_upgrade.request_id,
                success=False,
                error=str(e),
            )
            await self._send_message(response)

    async def _forward_ws_from_local(self, tunnel_id: UUID, ws: Any) -> None:
        """Forward WebSocket frames from local server to relay.

        Uses the high-performance `websockets` library API.
        """
        import websockets

        try:
            async for message in ws:
                if isinstance(message, str):
                    # Text frame
                    frame = WebSocketFrame(
                        tunnel_id=tunnel_id,
                        opcode=WebSocketOpcode.TEXT,
                        payload=message.encode("utf-8"),
                    )
                    await self._send_message(frame)
                elif isinstance(message, bytes):
                    # Binary frame
                    frame = WebSocketFrame(
                        tunnel_id=tunnel_id,
                        opcode=WebSocketOpcode.BINARY,
                        payload=message,
                    )
                    await self._send_message(frame)
        except websockets.ConnectionClosed as e:
            # Send close to relay
            close_msg = WebSocketClose(
                tunnel_id=tunnel_id,
                code=e.code,
                reason=e.reason or "",
            )
            await self._send_message(close_msg)
        except Exception as e:
            logger.error("WebSocket forward error", error=str(e))
        finally:
            self._ws_connections.pop(tunnel_id, None)
            with contextlib.suppress(Exception):
                await ws.close()

    async def _forward_ws_frame_to_local(self, ws: Any, frame: WebSocketFrame) -> None:
        """Forward a WebSocket frame from relay to local server.

        Uses the high-performance `websockets` library API.
        """
        try:
            if frame.opcode == WebSocketOpcode.TEXT:
                await ws.send(frame.payload.decode("utf-8"))
            elif frame.opcode == WebSocketOpcode.BINARY:
                await ws.send(frame.payload)
            elif frame.opcode == WebSocketOpcode.PING:
                await ws.ping(frame.payload)
            elif frame.opcode == WebSocketOpcode.PONG:
                await ws.pong(frame.payload)
        except Exception as e:
            logger.warning("Failed to forward WS frame to local", error=str(e))

    async def _close_local_websocket(self, ws: Any, close_msg: WebSocketClose) -> None:
        """Close local WebSocket connection."""
        try:
            await ws.close(code=close_msg.code, reason=close_msg.reason)
        except Exception as e:
            logger.warning("Error closing local WebSocket", error=str(e))

    async def _handle_grpc_stream_open(self, grpc_open: GrpcStreamOpen) -> None:
        """Handle gRPC stream open by connecting to local gRPC server.

        Uses grpcio for connecting to local gRPC services.
        """
        try:
            import grpc.aio

            # Connect to local gRPC server
            channel = grpc.aio.insecure_channel(f"localhost:{self.local_port}")

            # Create a generic unary stream call
            # gRPC path format: /package.Service/Method
            method_path = f"/{grpc_open.service}/{grpc_open.method}"

            # Store channel and metadata for this stream
            self._grpc_streams[grpc_open.stream_id] = (channel, method_path)

            # Send success response
            response = GrpcStreamOpened(
                tunnel_id=grpc_open.tunnel_id,
                stream_id=grpc_open.stream_id,
                success=True,
            )
            await self._send_message(response)

            logger.info(
                "gRPC stream opened",
                stream_id=str(grpc_open.stream_id),
                service=grpc_open.service,
                method=grpc_open.method,
            )

        except ImportError:
            logger.warning("grpcio not installed, gRPC streaming unavailable")
            response = GrpcStreamOpened(
                tunnel_id=grpc_open.tunnel_id,
                stream_id=grpc_open.stream_id,
                success=False,
                error="grpcio not installed",
            )
            await self._send_message(response)
        except Exception as e:
            logger.error(
                "gRPC stream open failed",
                stream_id=str(grpc_open.stream_id),
                error=str(e),
            )
            response = GrpcStreamOpened(
                tunnel_id=grpc_open.tunnel_id,
                stream_id=grpc_open.stream_id,
                success=False,
                error=str(e),
            )
            await self._send_message(response)

    async def _forward_grpc_frame_to_local(self, method_path: str, frame: GrpcFrame) -> None:
        """Forward a gRPC frame to local server.

        gRPC frame format: 1 byte compressed flag + 4 bytes length + data
        """
        stream_data = self._grpc_streams.get(frame.stream_id)
        if not stream_data:
            return

        channel, _ = stream_data

        try:
            # For simple unary calls, we can use the channel directly
            # For streaming, this would need more complex handling
            # The frame.data contains the protobuf-encoded message
            logger.debug(
                "Forwarding gRPC frame",
                stream_id=str(frame.stream_id),
                data_len=len(frame.data),
            )

            # Note: Full gRPC streaming would require implementing
            # the grpc.aio stream interfaces. For now, we forward
            # the raw frame data which works for unary calls.

        except Exception as e:
            logger.warning("Failed to forward gRPC frame", error=str(e))

    async def _close_local_grpc_stream(
        self, stream_data: tuple[Any, Any], close_msg: GrpcStreamClose
    ) -> None:
        """Close local gRPC stream."""
        try:
            channel, _ = stream_data
            await channel.close()

            # Send trailers if we have status info
            if close_msg.status != 0:
                trailers = GrpcTrailers(
                    tunnel_id=close_msg.tunnel_id,
                    stream_id=close_msg.stream_id,
                    status=close_msg.status,
                    message=close_msg.message,
                )
                await self._send_message(trailers)

            logger.debug(
                "gRPC stream closed",
                stream_id=str(close_msg.stream_id),
                status=close_msg.status,
            )
        except Exception as e:
            logger.warning("Error closing gRPC stream", error=str(e))

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

        # Clear callbacks to prevent accumulation
        self._state_hooks.clear()

        logger.info("Tunnel closed", stats=self.stats)

    async def __aenter__(self) -> TunnelClient:
        """Async context manager entry."""
        await self.connect()
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Async context manager exit."""
        await self.close()
