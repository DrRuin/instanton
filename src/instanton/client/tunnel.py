"""Tunnel client implementation with auto-reconnect and request proxying."""

from __future__ import annotations

import asyncio
import contextlib
import random
import socket
import time
import urllib.parse
from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum
from typing import Any
from uuid import UUID, uuid4

import httpx
import structlog
from rich.console import Console

from instanton.core.config import ClientConfig, get_config
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
from instanton.core.pool import TransportPool
from instanton.core.transport import QuicTransport, Transport, WebSocketTransport
from instanton.protocol.messages import (
    ChunkAssembler,
    ChunkData,
    ChunkEnd,
    ChunkStart,
    CompressionType,
    ConnectRequest,
    ConnectResponse,
    Disconnect,
    HttpRequest,
    HttpRequestStream,
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
console = Console()


class ConnectionState(Enum):
    """Client connection state."""

    DISCONNECTED = "disconnected"
    CONNECTING = "connecting"
    NEGOTIATING = "negotiating"
    CONNECTED = "connected"
    RECONNECTING = "reconnecting"
    CLOSED = "closed"


def _get_reconnect_config():
    """Get reconnect config defaults from global config."""
    return get_config().reconnect


@dataclass
class ReconnectConfig:
    """Configuration for reconnection behavior.

    Optimized defaults for global users connecting from different countries
    with varying network conditions and latency. Defaults are loaded from
    environment variables via the global config.
    """

    enabled: bool | None = None
    max_attempts: int | None = None
    base_delay: float | None = None
    max_delay: float | None = None
    jitter: float | None = None

    def __post_init__(self):
        """Apply defaults from global config if not explicitly set."""
        cfg = _get_reconnect_config()
        if self.enabled is None:
            self.enabled = cfg.auto_reconnect
        if self.max_attempts is None:
            self.max_attempts = cfg.max_attempts
        if self.base_delay is None:
            self.base_delay = cfg.base_delay
        if self.max_delay is None:
            self.max_delay = cfg.max_delay
        if self.jitter is None:
            self.jitter = cfg.jitter


def _get_timeout_config():
    """Get timeout config defaults from global config."""
    return get_config().timeouts


def _get_resource_config():
    """Get resource config defaults from global config."""
    return get_config().resources


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

    Defaults are loaded from environment variables via the global config.
    """

    connect_timeout: float | None = None
    read_timeout: float | None = None
    write_timeout: float | None = None
    pool_timeout: float = 5.0
    max_connections: int | None = None
    max_keepalive: int | None = None
    retry_count: int = 2
    retry_on_status: tuple[int, ...] = (502, 503, 504)
    stream_timeout: float | None = None

    def __post_init__(self):
        """Apply defaults from global config if not explicitly set."""
        timeouts = _get_timeout_config()
        resources = _get_resource_config()

        if self.connect_timeout is None:
            self.connect_timeout = timeouts.connect_timeout
        if self.write_timeout is None:
            self.write_timeout = timeouts.write_timeout
        if self.max_connections is None:
            self.max_connections = resources.max_connections
        if self.max_keepalive is None:
            self.max_keepalive = resources.max_keepalive


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
        proxy_username: str | None = None,
        proxy_password: str | None = None,
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
            proxy_username: Username for proxy authentication
            proxy_password: Password for proxy authentication
        """
        if config:
            self.local_port = config.local_port
            self.server_addr = config.server_addr
            self.subdomain = config.subdomain
            self.use_quic = config.use_quic
            self._keepalive_interval = config.keepalive_interval
            self._connect_timeout = config.connect_timeout
            self._proxy_username = config.proxy_username
            self._proxy_password = config.proxy_password
        else:
            self.local_port = local_port
            self.server_addr = server_addr
            self.subdomain = subdomain
            self.use_quic = use_quic
            timeouts = _get_timeout_config()
            self._keepalive_interval = timeouts.ping_interval
            self._connect_timeout = timeouts.connect_timeout
            self._proxy_username = proxy_username
            self._proxy_password = proxy_password

        self.reconnect_config = reconnect_config or ReconnectConfig()
        self.proxy_config = proxy_config or ProxyConfig()

        self._state = ConnectionState.DISCONNECTED
        self._transport: Transport | None = None
        self._tunnel_id: UUID | None = None
        self._url: str | None = None
        self._assigned_subdomain: str | None = None
        self._running = False
        self._reconnect_attempt = 0

        self._negotiator = ProtocolNegotiator()
        self._compression: CompressionType = CompressionType.NONE
        self._streaming_enabled = False
        self._chunk_size = get_config().performance.chunk_size

        self._http_client: httpx.AsyncClient | None = None

        self._chunk_assembler = ChunkAssembler()

        self._ws_connections: dict[UUID, Any] = {}

        # Track pending streaming requests (large file uploads)
        # stream_id -> (HttpRequestStream, list of body chunks)
        self._pending_request_streams: dict[UUID, tuple[HttpRequestStream, list[bytes]]] = {}

        self._state_hooks: list[Callable[[ConnectionState], None]] = []

        self._connect_time: float | None = None
        self._requests_proxied = 0
        self._bytes_sent = 0
        self._bytes_received = 0

        # Connection pool support
        self._using_pool = False
        self._pool: TransportPool | None = None
        self._message_queue: asyncio.Queue[bytes] | None = None

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
        stats = {
            "state": self._state.value,
            "tunnel_id": str(self._tunnel_id) if self._tunnel_id else None,
            "url": self._url,
            "requests_proxied": self._requests_proxied,
            "bytes_sent": self._bytes_sent,
            "bytes_received": self._bytes_received,
            "compression": self._compression.name,
            "streaming_enabled": self._streaming_enabled,
            "reconnect_attempts": self._reconnect_attempt,
            "using_pool": self._using_pool,
        }
        if self._using_pool and self._pool:
            stats["pool_stats"] = self._pool.get_stats()
        return stats

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

    def _build_auth_header(self) -> dict[str, str]:
        """Build Proxy-Authorization header if credentials are configured."""
        if self._proxy_username and self._proxy_password:
            import base64

            credentials = f"{self._proxy_username}:{self._proxy_password}"
            encoded = base64.b64encode(credentials.encode()).decode()
            return {"Proxy-Authorization": f"Basic {encoded}"}
        return {}

    async def _create_transport(self) -> Transport:
        extra_headers = self._build_auth_header()
        pool_config = get_config().pool

        if self.use_quic and pool_config.enabled:
            self._pool = await TransportPool.get_pool(self.server_addr)

            async def create_quic_transport() -> QuicTransport:
                return QuicTransport(
                    auto_reconnect=self.reconnect_config.enabled,
                    max_reconnect_attempts=self.reconnect_config.max_attempts,
                    reconnect_delay=self.reconnect_config.base_delay,
                    max_reconnect_delay=self.reconnect_config.max_delay,
                    extra_headers=extra_headers,
                )

            transport, queue = await self._pool.acquire(
                self._tunnel_id or uuid4(),
                create_quic_transport,
            )
            self._message_queue = queue
            self._using_pool = True
            return transport

        if self.use_quic:
            return QuicTransport(
                auto_reconnect=self.reconnect_config.enabled,
                max_reconnect_attempts=self.reconnect_config.max_attempts,
                reconnect_delay=self.reconnect_config.base_delay,
                max_reconnect_delay=self.reconnect_config.max_delay,
                extra_headers=extra_headers,
            )
        return WebSocketTransport(
            auto_reconnect=self.reconnect_config.enabled,
            max_reconnect_attempts=self.reconnect_config.max_attempts,
            reconnect_delay=self.reconnect_config.base_delay,
            max_reconnect_delay=self.reconnect_config.max_delay,
            connect_timeout=self._connect_timeout,
            ping_interval=self._keepalive_interval,
            ping_timeout=min(self._connect_timeout / 2, 20.0),
            extra_headers=extra_headers,
        )

    async def _create_http_client(self) -> httpx.AsyncClient:
        """Create HTTP client for proxying requests."""
        timeout = httpx.Timeout(
            connect=self.proxy_config.connect_timeout,
            read=self.proxy_config.read_timeout,
            write=self.proxy_config.write_timeout,
            pool=self.proxy_config.pool_timeout,
        )
        limits = httpx.Limits(
            max_connections=self.proxy_config.max_connections,
            max_keepalive_connections=self.proxy_config.max_keepalive,
        )
        transport = httpx.AsyncHTTPTransport(
            retries=0,
            socket_options=[(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)],
        )
        return httpx.AsyncClient(
            timeout=timeout,
            limits=limits,
            follow_redirects=False,
            http2=True,
            transport=transport,
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
            self._transport = await self._create_transport()
            await self._transport.connect(self.server_addr)

            self._set_state(ConnectionState.NEGOTIATING)
            await self._negotiate_protocol()

            request = ConnectRequest(
                subdomain=self.subdomain,
                local_port=self.local_port,
            )
            await self._send_message(request)

            data = await self._transport.recv()
            if not data:
                raise ServerUnavailableError(self.server_addr)

            msg = decode_message(data)
            response = ConnectResponse(**msg)

            if response.type == "error":
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

            logger.debug(
                "Tunnel established",
                tunnel_id=str(self._tunnel_id),
                url=self._url,
                connect_time_ms=int(self._connect_time * 1000),
            )

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

        request = self._negotiator.create_request()
        await self._send_message(request)

        data = await self._transport.recv()
        if not data:
            logger.warning("No negotiation response, using defaults")
            return

        msg = decode_message(data)
        if msg.get("type") != "negotiate_response":
            logger.debug("Server doesn't support negotiation")
            return

        response = NegotiateResponse(**msg)
        if self._negotiator.apply_response(response):
            self._compression = self._negotiator.negotiated_compression
            self._streaming_enabled = self._negotiator.streaming_enabled
            self._chunk_size = self._negotiator.chunk_size
            logger.debug(
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
                    if self._running and self.reconnect_config.enabled:
                        await self._attempt_reconnect()
                    else:
                        break
                elif self._state == ConnectionState.CLOSED:
                    break
                else:
                    await asyncio.sleep(0.1)
            except asyncio.CancelledError:
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
                if self._using_pool and self._message_queue:
                    try:
                        data = await asyncio.wait_for(self._message_queue.get(), timeout=30.0)
                    except TimeoutError:
                        continue
                else:
                    data = await self._transport.recv()

                if not data:
                    logger.warning("Connection lost")
                    break

                self._bytes_received += len(data)
                await self._handle_message(data)
        except asyncio.CancelledError:
            was_cancelled = True
            self._running = False
            raise
        except Exception as e:
            logger.error("Error in message loop", error=str(e))
        finally:
            keepalive_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await keepalive_task

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

        delay = min(
            self.reconnect_config.base_delay * (2 ** (self._reconnect_attempt - 1)),
            self.reconnect_config.max_delay,
        )
        jitter = delay * self.reconnect_config.jitter * random.random()
        delay += jitter

        console.print(f"[yellow]Reconnecting... (attempt {self._reconnect_attempt})[/yellow]")

        await asyncio.sleep(delay)

        if self._transport:
            with contextlib.suppress(Exception):
                await self._transport.close()
            self._transport = None

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
        elif msg_type == "http_request_stream":
            stream_request = HttpRequestStream(**msg)
            await self._handle_http_request_stream(stream_request)
        elif msg_type == "pong":
            pong = Pong(**msg)
            logger.debug("Received pong", timestamp=pong.timestamp)
        elif msg_type == "chunk_start":
            chunk_start = ChunkStart(**msg)
            self._chunk_assembler.start_stream(chunk_start)
        elif msg_type == "chunk_data":
            chunk_data = ChunkData(**msg)
            if chunk_data.stream_id in self._pending_request_streams:
                stream_info, chunks = self._pending_request_streams[chunk_data.stream_id]
                chunks.append(chunk_data.data)
            else:
                self._chunk_assembler.add_chunk(chunk_data)
        elif msg_type == "chunk_end":
            chunk_end = ChunkEnd(**msg)
            if chunk_end.stream_id in self._pending_request_streams:
                await self._complete_request_stream(chunk_end)
            else:
                assembled = self._chunk_assembler.end_stream(chunk_end)
                logger.debug("Assembled chunk", size=len(assembled))
        elif msg_type == "websocket_upgrade":
            ws_upgrade = WebSocketUpgrade(**msg)
            asyncio.create_task(self._handle_websocket_upgrade(ws_upgrade))
        elif msg_type == "websocket_frame":
            frame = WebSocketFrame(**msg)
            ws = self._ws_connections.get(frame.tunnel_id)
            if ws:
                asyncio.create_task(self._forward_ws_frame_to_local(ws, frame))
        elif msg_type == "websocket_close":
            close_msg = WebSocketClose(**msg)
            ws = self._ws_connections.pop(close_msg.tunnel_id, None)
            if ws:
                asyncio.create_task(self._close_local_websocket(ws, close_msg))
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

        console.print(f"[dim]->[/dim] {request.method} {request.path}")

        headers = dict(request.headers)

        headers["Host"] = f"localhost:{self.local_port}"

        hop_by_hop = {
            "keep-alive",
            "proxy-authenticate",
            "proxy-authorization",
            "te",
            "trailers",
            "transfer-encoding",
        }

        connection_header = headers.get("Connection", "").lower()
        upgrade_header = headers.get("Upgrade", "").lower()
        is_websocket_upgrade = "upgrade" in connection_header and upgrade_header == "websocket"

        request_headers = {}
        for k, v in headers.items():
            k_lower = k.lower()
            if k_lower in hop_by_hop:
                continue
            if k_lower in ("connection", "upgrade"):
                if is_websocket_upgrade:
                    request_headers[k] = v
                continue
            request_headers[k] = v

        if "Origin" in request_headers:
            request_headers["Origin"] = f"http://localhost:{self.local_port}"

        if "Referer" in request_headers:
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

        for attempt in range(self.proxy_config.retry_count + 1):
            try:
                try:
                    async with self._http_client.stream(
                        method=request.method,
                        url=url,
                        headers=request_headers,
                        content=request.body,
                    ) as resp:
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

                        content_type = resp.headers.get("content-type", "").lower()
                        transfer_encoding = resp.headers.get("transfer-encoding", "").lower()
                        has_content_length = "content-length" in resp.headers

                        is_event_stream = (
                            "text/event-stream" in content_type
                            or "application/x-ndjson" in content_type
                            or "application/stream+json" in content_type
                            or "application/jsonl" in content_type
                        )

                        is_grpc_stream = (
                            "application/grpc" in content_type
                            or "application/grpc+proto" in content_type
                            or "application/grpc-web" in content_type
                        )

                        is_multipart_stream = (
                            "multipart/x-mixed-replace" in content_type
                            or "multipart/mixed" in content_type
                        )

                        is_media_stream = (
                            "chunked" in transfer_encoding
                            and not has_content_length
                            and (
                                content_type.startswith("video/")
                                or content_type.startswith("audio/")
                                or "application/octet-stream" in content_type
                            )
                        )

                        is_chunked_stream = (
                            "chunked" in transfer_encoding and not has_content_length
                        )

                        is_streaming = (
                            is_event_stream
                            or is_grpc_stream
                            or is_multipart_stream
                            or is_media_stream
                            or is_chunked_stream
                        )

                        if is_streaming and self._transport:
                            await self._stream_sse_response(request, resp)
                            return

                        perf_config = get_config().performance
                        content_length_str = resp.headers.get("content-length", "0")
                        try:
                            content_length = int(content_length_str)
                        except ValueError:
                            content_length = 0

                        if (
                            content_length > perf_config.stream_response_threshold
                            and self._transport
                            and self._streaming_enabled
                        ):
                            await self._stream_large_response(request, resp, content_length)
                            return

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
                    resp = await self._http_client.request(
                        method=request.method,
                        url=url,
                        headers=request_headers,
                        content=request.body,
                    )

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
                break

        if response is None:
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

        if self._transport:
            self._requests_proxied += 1

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

        await self._send_message(start)

        for chunk in chunks:
            await self._send_message(chunk)

        await self._send_message(end)

        logger.debug(
            "Sent chunked response",
            request_id=str(response.request_id),
            total_chunks=len(chunks),
        )

    async def _stream_sse_response(self, request: HttpRequest, resp: httpx.Response) -> None:
        """Stream SSE response chunks immediately without buffering.

        For Server-Sent Events (SSE), we need to forward each chunk
        as soon as it arrives to enable real-time streaming.
        """
        from uuid import uuid4

        stream_id = uuid4()
        sequence = 0

        headers = dict(resp.headers)
        start = ChunkStart(
            stream_id=stream_id,
            request_id=request.request_id,
            total_size=None,
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

        end = ChunkEnd(
            stream_id=stream_id,
            total_chunks=sequence,
            checksum=None,
        )
        await self._send_message(end)

        logger.debug(
            "SSE stream completed",
            request_id=str(request.request_id),
            stream_id=str(stream_id),
            total_chunks=sequence,
        )
        self._requests_proxied += 1

    async def _stream_large_response(
        self, request: HttpRequest, resp: httpx.Response, content_length: int
    ) -> None:
        """Stream large response without buffering."""
        from uuid import uuid4

        stream_id = uuid4()
        sequence = 0
        perf_config = get_config().performance
        chunk_size = perf_config.stream_chunk_size

        headers = dict(resp.headers)
        start = ChunkStart(
            stream_id=stream_id,
            request_id=request.request_id,
            total_size=content_length,
            content_type=headers.get("content-type", "application/octet-stream"),
            status=resp.status_code,
            headers=headers,
        )
        await self._send_message(start)

        logger.debug(
            "Starting large response stream",
            request_id=str(request.request_id),
            stream_id=str(stream_id),
            content_length=content_length,
        )

        total_bytes = 0
        try:
            async for chunk in resp.aiter_bytes(chunk_size=chunk_size):
                if chunk:
                    chunk_data = ChunkData(
                        stream_id=stream_id,
                        sequence=sequence,
                        data=chunk,
                        is_final=False,
                    )
                    await self._send_message(chunk_data)
                    sequence += 1
                    total_bytes += len(chunk)
        except Exception as e:
            logger.error("Large response streaming error", error=str(e))

        end = ChunkEnd(
            stream_id=stream_id,
            request_id=request.request_id,
            total_chunks=sequence,
            success=True,
            checksum=None,
        )
        await self._send_message(end)

        logger.debug(
            "Large response stream completed",
            request_id=str(request.request_id),
            stream_id=str(stream_id),
            total_chunks=sequence,
            total_bytes=total_bytes,
        )
        self._requests_proxied += 1

    async def _handle_http_request_stream(self, stream_request: HttpRequestStream) -> None:
        """Handle streaming HTTP request start."""
        logger.debug(
            "Starting request stream",
            request_id=str(stream_request.request_id),
            stream_id=str(stream_request.stream_id),
            method=stream_request.method,
            path=stream_request.path,
            content_length=stream_request.content_length,
        )
        self._pending_request_streams[stream_request.stream_id] = (stream_request, [])

    async def _complete_request_stream(self, chunk_end: ChunkEnd) -> None:
        """Complete streaming request and forward to local service."""
        stream_id = chunk_end.stream_id
        if stream_id not in self._pending_request_streams:
            logger.warning("Unknown request stream completed", stream_id=str(stream_id))
            return

        stream_request, chunks = self._pending_request_streams.pop(stream_id)
        body = b"".join(chunks)

        logger.debug(
            "Request stream complete",
            request_id=str(stream_request.request_id),
            stream_id=str(stream_id),
            total_chunks=len(chunks),
            body_size=len(body),
        )

        request = HttpRequest(
            request_id=stream_request.request_id,
            method=stream_request.method,
            path=stream_request.path,
            headers=stream_request.headers,
            body=body,
        )

        await self._handle_http_request(request)

    async def _handle_websocket_upgrade(self, ws_upgrade: WebSocketUpgrade) -> None:
        """Handle WebSocket upgrade by connecting to local WebSocket server.

        Uses the high-performance `websockets` library for optimal throughput.
        """
        import websockets

        url = f"ws://localhost:{self.local_port}{ws_upgrade.path}"

        try:
            hop_by_hop = {
                "keep-alive",
                "proxy-authenticate",
                "proxy-authorization",
                "te",
                "trailers",
                "transfer-encoding",
                "connection",
                "upgrade",
                "sec-websocket-key",
                "sec-websocket-version",
                "sec-websocket-extensions",
            }

            extra_headers = []
            for k, v in ws_upgrade.headers.items():
                k_lower = k.lower()

                if k_lower in hop_by_hop:
                    continue

                if k_lower == "host":
                    extra_headers.append((k, f"localhost:{self.local_port}"))
                    continue

                if k_lower == "origin":
                    extra_headers.append((k, f"http://localhost:{self.local_port}"))
                    continue

                extra_headers.append((k, v))

            timeouts = _get_timeout_config()
            ws = await websockets.connect(
                url,
                additional_headers=extra_headers,
                subprotocols=ws_upgrade.subprotocols or None,
                ping_interval=timeouts.ping_interval,
                ping_timeout=timeouts.ping_timeout,
                close_timeout=timeouts.ws_close_timeout,
            )

            self._ws_connections[ws_upgrade.tunnel_id] = ws

            response = WebSocketUpgradeResponse(
                tunnel_id=ws_upgrade.tunnel_id,
                request_id=ws_upgrade.request_id,
                success=True,
                accepted_protocol=ws.subprotocol,
            )
            await self._send_message(response)

            logger.debug(
                "WebSocket connected to local",
                tunnel_id=str(ws_upgrade.tunnel_id),
                path=ws_upgrade.path,
            )

            asyncio.create_task(self._forward_ws_from_local(ws_upgrade.tunnel_id, ws))

        except Exception as e:
            logger.error(
                "WebSocket upgrade failed",
                tunnel_id=str(ws_upgrade.tunnel_id),
                error=str(e),
            )
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
                    frame = WebSocketFrame(
                        tunnel_id=tunnel_id,
                        opcode=WebSocketOpcode.TEXT,
                        payload=message.encode("utf-8"),
                    )
                    await self._send_message(frame)
                elif isinstance(message, bytes):
                    frame = WebSocketFrame(
                        tunnel_id=tunnel_id,
                        opcode=WebSocketOpcode.BINARY,
                        payload=message,
                    )
                    await self._send_message(frame)
        except websockets.ConnectionClosed as e:
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

        if self._transport and self._transport.is_connected():
            try:
                disconnect = Disconnect(reason="Client closing")
                await self._send_message(disconnect)
            except Exception:
                pass

        if self._http_client:
            with contextlib.suppress(Exception):
                await self._http_client.aclose()
            self._http_client = None

        if self._using_pool and self._pool and self._tunnel_id:
            with contextlib.suppress(Exception):
                await self._pool.release(self._tunnel_id)
            self._pool = None
            self._message_queue = None
            self._using_pool = False
            self._transport = None
        elif self._transport:
            with contextlib.suppress(Exception):
                await self._transport.close()
            self._transport = None

        self._state_hooks.clear()

        logger.debug("Tunnel closed", stats=self.stats)

    async def __aenter__(self) -> TunnelClient:
        """Async context manager entry."""
        await self.connect()
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Async context manager exit."""
        await self.close()
