"""Relay server implementation with TLS support and subdomain/custom domain routing."""

from __future__ import annotations

import asyncio
import contextlib
import secrets
import ssl
import time
import weakref
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID, uuid4

import structlog
from aiohttp import WSMsgType, web

from instanton.core.config import ServerConfig
from instanton.domains import DomainManager, DomainStore
from instanton.protocol.messages import (
    ChunkAssembler,
    ChunkData,
    ChunkEnd,
    ChunkStart,
    CompressionType,
    ConnectRequest,
    ConnectResponse,
    ErrorCode,
    HttpRequest,
    HttpResponse,
    NegotiateRequest,
    Pong,
    ProtocolNegotiator,
    WebSocketClose,
    WebSocketFrame,
    WebSocketOpcode,
    WebSocketUpgrade,
    WebSocketUpgradeResponse,
    decode_message,
    encode_message,
)
from instanton.security.iprestrict import IPRestrictor, create_ip_restrictor
from instanton.security.ratelimit import RateLimiter, create_rate_limiter

logger = structlog.get_logger()


@dataclass
class TunnelConnection:
    """Active tunnel connection."""

    id: UUID
    subdomain: str
    websocket: web.WebSocketResponse
    local_port: int
    connected_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    request_count: int = 0
    bytes_sent: int = 0
    bytes_received: int = 0
    last_activity: datetime = field(default_factory=lambda: datetime.now(UTC))
    compression: CompressionType = CompressionType.NONE
    negotiator: ProtocolNegotiator | None = None


@dataclass
class SubdomainReservation:
    """Reserved subdomain for reconnecting clients.

    When a client disconnects (e.g., laptop lid closed), the subdomain
    is reserved for a grace period to allow the client to reconnect
    and reclaim the same URL.
    """

    subdomain: str
    tunnel_id: UUID
    local_port: int
    reserved_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    # Statistics from before disconnect (preserved for continuity)
    request_count: int = 0
    bytes_sent: int = 0
    bytes_received: int = 0


@dataclass
class RequestContext:
    """Context for an in-flight HTTP request."""

    request_id: UUID
    tunnel: TunnelConnection
    future: asyncio.Future
    created_at: float = field(default_factory=time.time)
    # SSE streaming support
    http_request: web.Request | None = None
    stream_response: web.StreamResponse | None = None
    is_sse_stream: bool = False
    sse_complete: asyncio.Event | None = None
    # SSE heartbeat task for keeping connection alive
    heartbeat_task: asyncio.Task | None = None


class RelayServer:
    """Relay server that manages tunnel connections with TLS support."""

    # Default grace period for subdomain reservations (30 minutes)
    # This allows clients to reconnect after laptop lid close, network blips,
    # or extended periods of system sleep/suspend
    # Can be overridden via config.subdomain_grace_period
    DEFAULT_SUBDOMAIN_GRACE_PERIOD = 1800.0  # 30 minutes in seconds

    def __init__(self, config: ServerConfig, domains_path: str | Path = "domains.json"):
        self.config = config
        self._tunnels: dict[str, TunnelConnection] = {}  # subdomain -> tunnel
        self._tunnel_by_id: dict[UUID, TunnelConnection] = {}
        self._pending_requests: dict[UUID, RequestContext] = {}
        self._control_app: web.Application | None = None
        self._http_app: web.Application | None = None
        self._control_runner: web.AppRunner | None = None
        self._http_runner: web.AppRunner | None = None
        self._ssl_context: ssl.SSLContext | None = None
        self._websockets: weakref.WeakSet[web.WebSocketResponse] = weakref.WeakSet()
        self._shutdown_event = asyncio.Event()
        self._cleanup_task: asyncio.Task | None = None
        # TCP/UDP tunnel port allocation (port -> tunnel_id)
        self._tcp_tunnels: dict[int, TunnelConnection] = {}
        self._udp_tunnels: dict[int, TunnelConnection] = {}
        self._next_tcp_port = 10000  # Start allocating from port 10000
        self._next_udp_port = 20000  # UDP starts from 20000
        # Chunk assembler for handling large chunked responses from clients
        self._chunk_assembler = ChunkAssembler()
        # Map stream_id -> (created_at, request_id, status, headers) for chunked responses
        self._chunk_streams: dict[UUID, tuple[float, UUID, int, dict[str, str]]] = {}
        # Active WebSocket proxy connections (tunnel_id -> browser WebSocket)
        self._ws_proxies: dict[UUID, web.WebSocketResponse] = {}
        # Subdomain reservations for disconnected clients
        # Allows clients to reconnect and reclaim the same subdomain
        self._reservations: dict[str, SubdomainReservation] = {}
        # Custom domain support
        self._domain_store = DomainStore(domains_path)
        self._domain_manager = DomainManager(self._domain_store, config.base_domain)
        # Rate limiting
        self._rate_limiter: RateLimiter | None = None
        if getattr(config, "rate_limit_enabled", False):
            self._rate_limiter = create_rate_limiter(
                requests_per_second=getattr(config, "rate_limit_rps", 100.0),
                burst_size=getattr(config, "rate_limit_burst", 10),
            )
        # IP restrictions
        self._ip_restrictor: IPRestrictor | None = None
        if getattr(config, "ip_restrict_enabled", False):
            self._ip_restrictor = create_ip_restrictor(
                allow=getattr(config, "ip_allow", []),
                deny=getattr(config, "ip_deny", []),
            )

    @property
    def subdomain_grace_period(self) -> float:
        """Get the subdomain grace period from config or use default."""
        return getattr(self.config, "subdomain_grace_period", self.DEFAULT_SUBDOMAIN_GRACE_PERIOD)

    def _create_ssl_context(self) -> ssl.SSLContext | None:
        """Create SSL context from certificate files."""
        if not self.config.cert_path or not self.config.key_path:
            logger.warning("No TLS certificates provided, running without TLS")
            return None

        cert_path = Path(self.config.cert_path)
        key_path = Path(self.config.key_path)

        if not cert_path.exists():
            logger.error("Certificate file not found", path=str(cert_path))
            return None

        if not key_path.exists():
            logger.error("Key file not found", path=str(key_path))
            return None

        try:
            ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ssl_context.load_cert_chain(str(cert_path), str(key_path))
            ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2
            ssl_context.set_ciphers("ECDHE+AESGCM:DHE+AESGCM:ECDHE+CHACHA20:DHE+CHACHA20")
            logger.info("TLS context created", cert=str(cert_path))
            return ssl_context
        except Exception as e:
            logger.error("Failed to create SSL context", error=str(e))
            return None

    async def start(self) -> None:
        """Start the relay server with both control and HTTP planes."""
        # Create SSL context if certificates provided
        self._ssl_context = self._create_ssl_context()

        # Create control plane app (WebSocket for tunnel clients)
        self._control_app = web.Application()
        self._control_app.router.add_get("/tunnel", self._handle_tunnel_connection)
        self._control_app.router.add_get("/tcp", self._handle_tcp_tunnel_connection)
        self._control_app.router.add_get("/udp", self._handle_udp_tunnel_connection)
        self._control_app.router.add_get("/health", self._handle_health_check)
        self._control_app.router.add_get("/stats", self._handle_stats)

        # Create HTTP plane app (incoming requests to route to tunnels)
        self._http_app = web.Application()
        self._http_app.router.add_route("*", "/{path:.*}", self._handle_http_request)

        # Setup runners
        self._control_runner = web.AppRunner(self._control_app)
        self._http_runner = web.AppRunner(self._http_app)
        await self._control_runner.setup()
        await self._http_runner.setup()

        # Start control plane
        control_host, control_port = self._parse_bind(self.config.control_bind)
        control_site = web.TCPSite(
            self._control_runner,
            control_host,
            control_port,
            ssl_context=self._ssl_context,
        )
        await control_site.start()
        logger.info(
            "Control plane started",
            host=control_host,
            port=control_port,
            tls=self._ssl_context is not None,
        )

        # Start HTTPS plane
        https_host, https_port = self._parse_bind(self.config.https_bind)
        https_site = web.TCPSite(
            self._http_runner,
            https_host,
            https_port,
            ssl_context=self._ssl_context,
        )
        await https_site.start()
        logger.info(
            "HTTPS plane started",
            host=https_host,
            port=https_port,
            tls=self._ssl_context is not None,
        )

        # Start cleanup task for idle tunnels
        self._cleanup_task = asyncio.create_task(self._cleanup_loop())

        logger.info(
            "Relay server started",
            base_domain=self.config.base_domain,
            control_bind=self.config.control_bind,
            https_bind=self.config.https_bind,
        )

    def _parse_bind(self, bind: str) -> tuple[str, int]:
        """Parse bind address into host and port."""
        if ":" in bind:
            host, port = bind.rsplit(":", 1)
            return host, int(port)
        return "0.0.0.0", int(bind)

    async def stop(self) -> None:
        """Stop the relay server gracefully."""
        logger.info("Stopping relay server...")
        self._shutdown_event.set()

        # Cancel cleanup task
        if self._cleanup_task:
            self._cleanup_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._cleanup_task

        # Close all WebSocket connections
        for ws in list(self._websockets):
            with contextlib.suppress(Exception):
                await ws.close()

        # Close all tunnels
        for tunnel in list(self._tunnels.values()):
            with contextlib.suppress(Exception):
                await tunnel.websocket.close()

        # Cleanup runners
        if self._control_runner:
            await self._control_runner.cleanup()
        if self._http_runner:
            await self._http_runner.cleanup()

        self._tunnels.clear()
        self._tunnel_by_id.clear()
        self._pending_requests.clear()
        self._tcp_tunnels.clear()
        self._udp_tunnels.clear()
        self._reservations.clear()

        logger.info("Relay server stopped")

    async def _cleanup_loop(self) -> None:
        """Periodically clean up idle tunnels."""
        while not self._shutdown_event.is_set():
            try:
                await asyncio.sleep(60)  # Check every minute
                await self._cleanup_idle_tunnels()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("Cleanup error", error=str(e))

    async def _cleanup_idle_tunnels(self) -> None:
        """Remove tunnels that have been idle too long, expired reservations, and stale requests."""
        now = datetime.now(UTC)
        idle_threshold = self.config.idle_timeout
        current_time = time.time()

        # Clean up idle tunnels
        for subdomain, tunnel in list(self._tunnels.items()):
            idle_seconds = (now - tunnel.last_activity).total_seconds()
            if idle_seconds > idle_threshold:
                logger.info(
                    "Closing idle tunnel",
                    subdomain=subdomain,
                    idle_seconds=idle_seconds,
                )
                with contextlib.suppress(Exception):
                    await tunnel.websocket.close()
                self._tunnels.pop(subdomain, None)
                self._tunnel_by_id.pop(tunnel.id, None)

        # Clean up expired subdomain reservations
        expired_reservations = [
            subdomain
            for subdomain, reservation in self._reservations.items()
            if (now - reservation.reserved_at).total_seconds() > self.subdomain_grace_period
        ]
        for subdomain in expired_reservations:
            reservation = self._reservations.pop(subdomain, None)
            if reservation:
                logger.info(
                    "Subdomain reservation expired",
                    subdomain=subdomain,
                    tunnel_id=str(reservation.tunnel_id),
                    grace_period=self.subdomain_grace_period,
                )

        # Clean up stale pending requests (older than request_timeout + 30s buffer)
        # Only cleanup if timeout is configured (not indefinite)
        timeout = self.config.request_timeout
        # Use timeout + buffer if configured, otherwise 10 minutes for indefinite mode
        stale_threshold = timeout + 30.0 if timeout and timeout > 0 else 600.0
        stale_request_ids = [
            req_id
            for req_id, ctx in self._pending_requests.items()
            if current_time - ctx.created_at > stale_threshold
        ]
        for req_id in stale_request_ids:
            ctx = self._pending_requests.pop(req_id, None)
            if ctx and not ctx.future.done():
                ctx.future.set_exception(TimeoutError("Request timed out"))
            logger.debug("Cleaned up stale pending request", request_id=str(req_id))

        # Clean up stale chunk streams (5 minute TTL for incomplete transfers)
        chunk_ttl = 300.0
        stale_streams = [
            stream_id
            for stream_id, (created, _, _, _) in self._chunk_streams.items()
            if current_time - created > chunk_ttl
        ]
        for stream_id in stale_streams:
            self._chunk_streams.pop(stream_id, None)
            self._chunk_assembler.abort_stream(stream_id)
            logger.debug("Cleaned up stale chunk stream", stream_id=str(stream_id))

    async def _handle_health_check(self, request: web.Request) -> web.Response:
        """Health check endpoint."""
        return web.json_response(
            {
                "status": "healthy",
                "tunnels": len(self._tunnels),
                "uptime": time.time(),
            }
        )

    async def _handle_stats(self, request: web.Request) -> web.Response:
        """Statistics endpoint."""
        tunnels_info = []
        for subdomain, tunnel in self._tunnels.items():
            tunnels_info.append(
                {
                    "subdomain": subdomain,
                    "id": str(tunnel.id),
                    "connected_at": tunnel.connected_at.isoformat(),
                    "request_count": tunnel.request_count,
                    "bytes_sent": tunnel.bytes_sent,
                    "bytes_received": tunnel.bytes_received,
                }
            )

        # Build reservations info
        reservations_info = []
        for subdomain, reservation in self._reservations.items():
            reservations_info.append(
                {
                    "subdomain": subdomain,
                    "tunnel_id": str(reservation.tunnel_id),
                    "reserved_at": reservation.reserved_at.isoformat(),
                    "local_port": reservation.local_port,
                }
            )

        return web.json_response(
            {
                "total_tunnels": len(self._tunnels),
                "total_tcp_tunnels": len(self._tcp_tunnels),
                "total_udp_tunnels": len(self._udp_tunnels),
                "total_reservations": len(self._reservations),
                "max_tunnels": self.config.max_tunnels,
                "subdomain_grace_period": self.subdomain_grace_period,
                "tunnels": tunnels_info,
                "reservations": reservations_info,
            }
        )

    async def _handle_tunnel_connection(self, request: web.Request) -> web.WebSocketResponse:
        """Handle incoming tunnel client connection."""
        ws = web.WebSocketResponse(heartbeat=30.0)
        await ws.prepare(request)
        self._websockets.add(ws)

        logger.info("New tunnel client connected", peer=request.remote)

        tunnel: TunnelConnection | None = None
        subdomain: str = ""
        tunnel_id: UUID = uuid4()

        try:
            # Wait for first message (negotiate or connect)
            msg = await ws.receive()
            if msg.type != WSMsgType.BINARY:
                await ws.close()
                return ws

            data = decode_message(msg.data)
            msg_type = data.get("type")

            # Handle protocol negotiation
            negotiator = ProtocolNegotiator()
            compression = CompressionType.NONE

            if msg_type == "negotiate":
                negotiate_req = NegotiateRequest(**data)
                negotiate_resp = negotiator.handle_request(negotiate_req)
                compression = negotiator.negotiated_compression
                await ws.send_bytes(encode_message(negotiate_resp))

                # Wait for connect message
                msg = await ws.receive()
                if msg.type != WSMsgType.BINARY:
                    await ws.close()
                    return ws
                data = decode_message(msg.data)

            # Parse connect request
            if data.get("type") != "connect":
                response = ConnectResponse(
                    type="error",
                    error="Expected connect message",
                    error_code=ErrorCode.PROTOCOL_MISMATCH,
                )
                await ws.send_bytes(encode_message(response))
                await ws.close()
                return ws

            connect_req = ConnectRequest(**data)

            # Check max tunnels
            if len(self._tunnels) >= self.config.max_tunnels:
                response = ConnectResponse(
                    type="error",
                    error="Server at capacity",
                    error_code=ErrorCode.SERVER_FULL,
                )
                await ws.send_bytes(encode_message(response))
                await ws.close()
                return ws

            # Assign subdomain
            subdomain = connect_req.subdomain or ""
            reclaimed_reservation: SubdomainReservation | None = None

            if subdomain:
                # Validate subdomain
                if not self._is_valid_subdomain(subdomain):
                    response = ConnectResponse(
                        type="error",
                        error="Invalid subdomain format",
                        error_code=ErrorCode.INVALID_SUBDOMAIN,
                    )
                    await ws.send_bytes(encode_message(response))
                    await ws.close()
                    return ws

                # Check if subdomain is currently active
                if subdomain in self._tunnels:
                    response = ConnectResponse(
                        type="error",
                        error="Subdomain already in use",
                        error_code=ErrorCode.SUBDOMAIN_TAKEN,
                    )
                    await ws.send_bytes(encode_message(response))
                    await ws.close()
                    return ws

                # Check if subdomain is reserved (client reconnecting)
                if subdomain in self._reservations:
                    reservation = self._reservations[subdomain]
                    # Allow reclaim - remove reservation and use the same tunnel_id
                    # This preserves the client's subdomain after reconnect
                    reclaimed_reservation = self._reservations.pop(subdomain)
                    tunnel_id = reclaimed_reservation.tunnel_id
                    logger.info(
                        "Client reclaiming reserved subdomain",
                        subdomain=subdomain,
                        tunnel_id=str(tunnel_id),
                        reserved_for=(datetime.now(UTC) - reservation.reserved_at).total_seconds(),
                    )
            else:
                # Generate unique random subdomain using more entropy
                # Use 6 bytes (12 hex chars) for better uniqueness
                subdomain = secrets.token_hex(6)
                attempts = 0
                while subdomain in self._tunnels:
                    subdomain = secrets.token_hex(6)
                    attempts += 1
                    if attempts > 10:
                        # Extremely unlikely, but add tunnel_id prefix for guaranteed uniqueness
                        subdomain = f"{str(tunnel_id)[:8]}{secrets.token_hex(2)}"
                        break

            # Use the tunnel_id (either from reclaimed reservation or generated at start)
            url = f"https://{subdomain}.{self.config.base_domain}"

            tunnel = TunnelConnection(
                id=tunnel_id,
                subdomain=subdomain,
                websocket=ws,
                local_port=connect_req.local_port,
                compression=compression,
                negotiator=negotiator,
            )

            # Restore stats from reclaimed reservation (preserves continuity)
            if reclaimed_reservation:
                tunnel.request_count = reclaimed_reservation.request_count
                tunnel.bytes_sent = reclaimed_reservation.bytes_sent
                tunnel.bytes_received = reclaimed_reservation.bytes_received

            self._tunnels[subdomain] = tunnel
            self._tunnel_by_id[tunnel_id] = tunnel

            # Send success response
            response = ConnectResponse(
                type="connected",
                tunnel_id=tunnel_id,
                subdomain=subdomain,
                url=url,
            )
            await ws.send_bytes(encode_message(response, compression))

            logger.info(
                "Tunnel established",
                tunnel_id=str(tunnel_id),
                subdomain=subdomain,
                compression=compression.name,
            )

            # Handle messages
            async for msg in ws:
                if msg.type == WSMsgType.BINARY:
                    tunnel.last_activity = datetime.now(UTC)
                    tunnel.bytes_received += len(msg.data)
                    await self._handle_tunnel_message(tunnel, msg.data)
                elif msg.type == WSMsgType.ERROR:
                    logger.error(
                        "WebSocket error",
                        subdomain=subdomain,
                        error=str(ws.exception()),
                    )
                    break
                elif msg.type == WSMsgType.CLOSE:
                    break

        except Exception as e:
            logger.error("Tunnel error", subdomain=subdomain, error=str(e))
        finally:
            # Cleanup
            self._websockets.discard(ws)

            # Get tunnel reference before removing from active tunnels
            disconnected_tunnel = self._tunnels.pop(subdomain, None) if subdomain else None
            if tunnel_id in self._tunnel_by_id:
                del self._tunnel_by_id[tunnel_id]

            # Create reservation for reconnection if tunnel was established
            # This allows clients to reclaim their subdomain after laptop lid close, etc.
            if disconnected_tunnel and subdomain:
                reservation = SubdomainReservation(
                    subdomain=subdomain,
                    tunnel_id=tunnel_id,
                    local_port=disconnected_tunnel.local_port,
                    request_count=disconnected_tunnel.request_count,
                    bytes_sent=disconnected_tunnel.bytes_sent,
                    bytes_received=disconnected_tunnel.bytes_received,
                )
                self._reservations[subdomain] = reservation
                logger.info(
                    "Subdomain reserved for reconnection",
                    subdomain=subdomain,
                    tunnel_id=str(tunnel_id),
                    grace_period=self.subdomain_grace_period,
                )

            # Cancel any pending requests for this tunnel
            if tunnel:
                for req_id, ctx in list(self._pending_requests.items()):
                    if ctx.tunnel.id == tunnel.id:
                        if not ctx.future.done():
                            ctx.future.set_exception(ConnectionError("Tunnel disconnected"))
                        self._pending_requests.pop(req_id, None)

            logger.info("Tunnel closed", subdomain=subdomain)

        return ws

    def _is_valid_subdomain(self, subdomain: str) -> bool:
        """Validate subdomain format."""
        if not subdomain:
            return False
        if len(subdomain) < 3 or len(subdomain) > 63:
            return False
        # Allow alphanumeric and hyphens, but not starting/ending with hyphen
        if subdomain.startswith("-") or subdomain.endswith("-"):
            return False
        return all(c.isalnum() or c == "-" for c in subdomain)

    async def _prepare_sse_stream(self, ctx: RequestContext, stream_id: UUID) -> None:
        """Prepare SSE StreamResponse for immediate streaming."""
        try:
            if ctx.stream_response and ctx.http_request:
                await ctx.stream_response.prepare(ctx.http_request)

                # Start heartbeat task to keep SSE connection alive
                ctx.heartbeat_task = asyncio.create_task(
                    self._sse_heartbeat_loop(ctx)
                )

                logger.debug(
                    "SSE stream prepared with heartbeat",
                    stream_id=str(stream_id),
                    request_id=str(ctx.request_id),
                )
        except Exception as e:
            logger.error("Failed to prepare SSE stream", error=str(e))
            # Signal completion on error so request doesn't hang
            if ctx.sse_complete:
                ctx.sse_complete.set()

    async def _sse_heartbeat_loop(self, ctx: RequestContext) -> None:
        """Send periodic heartbeat comments to keep SSE connection alive.

        SSE protocol allows comment lines starting with ':' which are ignored
        by clients but keep the connection from timing out.
        """
        heartbeat_interval = 15.0  # Send heartbeat every 15 seconds

        try:
            while ctx.stream_response and not ctx.sse_complete.is_set():
                # Wait for either heartbeat interval or stream completion
                try:
                    await asyncio.wait_for(
                        ctx.sse_complete.wait(),
                        timeout=heartbeat_interval,
                    )
                    # Stream completed, exit loop
                    break
                except TimeoutError:
                    # Timeout = send heartbeat
                    pass

                # Send heartbeat comment
                if ctx.stream_response:
                    try:
                        await ctx.stream_response.write(b":heartbeat\n\n")
                    except Exception:
                        # Connection lost, exit
                        break
        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.debug("SSE heartbeat loop ended", error=str(e))

    async def _handle_tunnel_message(self, tunnel: TunnelConnection, data: bytes) -> None:
        """Handle message from tunnel client."""
        try:
            msg = decode_message(data)
            msg_type = msg.get("type")

            if msg_type == "http_response":
                response = HttpResponse(**msg)
                ctx = self._pending_requests.get(response.request_id)
                if ctx and not ctx.future.done():
                    ctx.future.set_result(response)

            elif msg_type == "chunk_start":
                # Start of chunked response - register the stream
                chunk_start = ChunkStart(**msg)
                headers = chunk_start.headers.copy() if chunk_start.headers else {}
                if "Content-Type" not in headers:
                    headers["Content-Type"] = chunk_start.content_type

                # Check if this is a streaming response - forward immediately
                content_type = headers.get("Content-Type", "").lower()

                # Event-based streaming content types
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

                # Media streaming (video/audio)
                is_media_stream = (
                    content_type.startswith("video/")  # Video streams
                    or content_type.startswith("audio/")  # Audio streams
                )

                # Binary streaming
                is_binary_stream = "application/octet-stream" in content_type

                # Combine all streaming detection
                is_streaming_type = (
                    is_event_stream
                    or is_grpc_stream
                    or is_multipart_stream
                    or is_media_stream
                    or is_binary_stream
                )

                ctx = self._pending_requests.get(chunk_start.request_id)

                if is_streaming_type and ctx and ctx.http_request:
                    # SSE streaming - prepare StreamResponse immediately
                    ctx.is_sse_stream = True
                    stream_headers = {
                        k: str(v) if not isinstance(v, str) else v
                        for k, v in headers.items()
                        if k.lower() not in ("content-length", "transfer-encoding")
                    }
                    stream_headers["Cache-Control"] = "no-cache, no-transform"
                    stream_headers["Connection"] = "keep-alive"
                    stream_headers["X-Accel-Buffering"] = "no"

                    ctx.stream_response = web.StreamResponse(
                        status=chunk_start.status,
                        headers=stream_headers,
                    )
                    # Enable chunked encoding for streaming
                    ctx.stream_response.enable_chunked_encoding()
                    # Prepare must be awaited - schedule as task
                    asyncio.create_task(
                        self._prepare_sse_stream(ctx, chunk_start.stream_id)
                    )
                    logger.debug(
                        "SSE stream started",
                        stream_id=str(chunk_start.stream_id),
                        request_id=str(chunk_start.request_id),
                    )
                else:
                    # Regular chunked response - buffer and assemble
                    self._chunk_assembler.start_stream(chunk_start)

                # Store mapping from stream_id to (created_at, request_id, status, headers)
                self._chunk_streams[chunk_start.stream_id] = (
                    time.time(),
                    chunk_start.request_id,
                    chunk_start.status,
                    headers,
                )
                logger.debug(
                    "Chunk stream started",
                    stream_id=str(chunk_start.stream_id),
                    request_id=str(chunk_start.request_id),
                    total_size=chunk_start.total_size,
                    status=chunk_start.status,
                    is_streaming=is_streaming_type,
                )

            elif msg_type == "chunk_data":
                # Chunk data - add to assembler or stream immediately for SSE
                chunk_data = ChunkData(**msg)
                stream_info = self._chunk_streams.get(chunk_data.stream_id)

                if stream_info:
                    _created, request_id, _status, _headers = stream_info
                    ctx = self._pending_requests.get(request_id)

                    # Check if this is an SSE stream - write immediately
                    if ctx and ctx.is_sse_stream and ctx.stream_response:
                        try:
                            await ctx.stream_response.write(chunk_data.data)
                        except Exception as e:
                            logger.warning("SSE write error", error=str(e))
                    else:
                        # Regular chunked response - buffer
                        try:
                            self._chunk_assembler.add_chunk(chunk_data)
                        except ValueError as e:
                            logger.warning("Chunk error", error=str(e))
                            self._chunk_streams.pop(chunk_data.stream_id, None)
                            if ctx and not ctx.future.done():
                                error_response = HttpResponse(
                                    request_id=request_id,
                                    status=500,
                                    headers={"Content-Type": "text/plain"},
                                    body=f"Chunk transfer error: {e}".encode(),
                                )
                                ctx.future.set_result(error_response)

            elif msg_type == "chunk_end":
                # End of chunked response - assemble and deliver (or finalize SSE stream)
                chunk_end = ChunkEnd(**msg)
                stream_info = self._chunk_streams.pop(chunk_end.stream_id, None)
                if stream_info:
                    _created, request_id, status, headers = stream_info
                    ctx = self._pending_requests.get(request_id)

                    # Check if this is an SSE stream - signal completion
                    if ctx and ctx.is_sse_stream:
                        try:
                            if ctx.stream_response:
                                await ctx.stream_response.write_eof()
                        except Exception as e:
                            logger.warning("SSE write_eof error", error=str(e))
                        # Signal completion and cancel heartbeat
                        if ctx.sse_complete:
                            ctx.sse_complete.set()
                        if ctx.heartbeat_task and not ctx.heartbeat_task.done():
                            ctx.heartbeat_task.cancel()
                        logger.debug(
                            "SSE stream completed",
                            stream_id=str(chunk_end.stream_id),
                            request_id=str(request_id),
                            total_chunks=chunk_end.total_chunks,
                        )
                    else:
                        # Regular chunked response - assemble and deliver
                        try:
                            body = self._chunk_assembler.end_stream(chunk_end)
                            clean_headers = {
                                k: str(v) if not isinstance(v, str) else v
                                for k, v in headers.items()
                                if k.lower() not in ("content-length", "transfer-encoding")
                            }
                            response = HttpResponse(
                                request_id=request_id,
                                status=status,
                                headers=clean_headers,
                                body=body,
                            )
                            if ctx and not ctx.future.done():
                                ctx.future.set_result(response)
                            logger.debug(
                                "Chunk stream completed",
                                stream_id=str(chunk_end.stream_id),
                                request_id=str(request_id),
                                total_chunks=chunk_end.total_chunks,
                                body_size=len(body),
                            )
                        except ValueError as e:
                            logger.error("Chunk assembly error", error=str(e))
                            if ctx and not ctx.future.done():
                                error_response = HttpResponse(
                                    request_id=request_id,
                                    status=500,
                                    headers={"Content-Type": "text/plain"},
                                    body=f"Chunk assembly error: {e}".encode(),
                                )
                                ctx.future.set_result(error_response)
                else:
                    logger.warning(
                        "Chunk end for unknown stream",
                        stream_id=str(chunk_end.stream_id),
                    )

            elif msg_type == "ping":
                pong = Pong(timestamp=msg["timestamp"], server_time=int(time.time() * 1000))
                await tunnel.websocket.send_bytes(encode_message(pong, tunnel.compression))

            elif msg_type == "websocket_upgrade_response":
                # WebSocket upgrade response from tunnel client
                response = WebSocketUpgradeResponse(**msg)
                ctx = self._pending_requests.get(response.request_id)
                if ctx and not ctx.future.done():
                    ctx.future.set_result(response)

            elif msg_type == "websocket_frame":
                # WebSocket frame from tunnel - forward to browser
                frame = WebSocketFrame(**msg)
                ws = self._ws_proxies.get(frame.tunnel_id)
                if ws and not ws.closed:
                    try:
                        if frame.opcode == WebSocketOpcode.TEXT:
                            await ws.send_str(frame.payload.decode("utf-8"))
                        elif frame.opcode == WebSocketOpcode.BINARY:
                            await ws.send_bytes(frame.payload)
                        elif frame.opcode == WebSocketOpcode.PING:
                            await ws.ping(frame.payload)
                        elif frame.opcode == WebSocketOpcode.PONG:
                            await ws.pong(frame.payload)
                    except Exception as e:
                        logger.warning("Failed to forward WS frame", error=str(e))

            elif msg_type == "websocket_close":
                # WebSocket close from tunnel - close browser connection
                close_msg = WebSocketClose(**msg)
                ws = self._ws_proxies.pop(close_msg.tunnel_id, None)
                if ws and not ws.closed:
                    await ws.close(code=close_msg.code, message=close_msg.reason.encode())

            elif msg_type == "disconnect":
                logger.info(
                    "Client disconnect request",
                    subdomain=tunnel.subdomain,
                    reason=msg.get("reason", ""),
                )
                await tunnel.websocket.close()

        except Exception as e:
            logger.error(
                "Error handling tunnel message",
                subdomain=tunnel.subdomain,
                error=str(e),
            )

    async def _handle_websocket_proxy(
        self, request: web.Request, tunnel: TunnelConnection
    ) -> web.WebSocketResponse:
        """Handle WebSocket upgrade and bidirectional proxying through tunnel."""
        from uuid import uuid4

        tunnel_id = uuid4()
        request_id = uuid4()

        # Prepare headers for upgrade request
        headers = {}
        for key, value in request.headers.items():
            key_lower = key.lower()
            if key_lower not in ("host", "connection", "upgrade"):
                headers[key] = value
        headers["X-Forwarded-For"] = request.remote or ""
        headers["X-Forwarded-Proto"] = "https" if self._ssl_context else "http"

        # Get subprotocols
        subprotocols = []
        if "Sec-WebSocket-Protocol" in request.headers:
            subprotocols = [
                p.strip()
                for p in request.headers["Sec-WebSocket-Protocol"].split(",")
            ]

        # Create WebSocket upgrade message
        ws_upgrade = WebSocketUpgrade(
            tunnel_id=tunnel_id,
            request_id=request_id,
            path=request.path_qs,
            headers=headers,
            subprotocols=subprotocols,
        )

        # Create future for upgrade response
        future: asyncio.Future[WebSocketUpgradeResponse] = asyncio.Future()
        self._pending_requests[request_id] = RequestContext(
            request_id=request_id,
            tunnel=tunnel,
            future=future,
            http_request=request,
            sse_complete=asyncio.Event(),
        )

        try:
            # Send upgrade request to tunnel
            msg_bytes = encode_message(ws_upgrade, tunnel.compression)
            await tunnel.websocket.send_bytes(msg_bytes)

            # Wait for upgrade response
            timeout = self.config.request_timeout or 30.0
            response = await asyncio.wait_for(future, timeout=timeout)

            if not response.success:
                # Upgrade failed
                return web.Response(
                    text=response.error or "WebSocket upgrade failed",
                    status=502,
                    content_type="text/plain",
                )

            # Create WebSocket response
            ws = web.WebSocketResponse(protocols=subprotocols)
            await ws.prepare(request)

            # Store for frame forwarding
            self._ws_proxies[tunnel_id] = ws

            logger.info(
                "WebSocket proxy established",
                tunnel_id=str(tunnel_id),
                path=request.path_qs,
            )

            # Bidirectional forwarding loop
            try:
                async for msg in ws:
                    if msg.type == WSMsgType.TEXT:
                        # Forward text frame to tunnel
                        frame = WebSocketFrame(
                            tunnel_id=tunnel_id,
                            opcode=WebSocketOpcode.TEXT,
                            payload=msg.data.encode() if isinstance(msg.data, str) else msg.data,
                        )
                        await tunnel.websocket.send_bytes(
                            encode_message(frame, tunnel.compression)
                        )
                    elif msg.type == WSMsgType.BINARY:
                        # Forward binary frame to tunnel
                        frame = WebSocketFrame(
                            tunnel_id=tunnel_id,
                            opcode=WebSocketOpcode.BINARY,
                            payload=msg.data,
                        )
                        await tunnel.websocket.send_bytes(
                            encode_message(frame, tunnel.compression)
                        )
                    elif msg.type == WSMsgType.CLOSE:
                        # Send close to tunnel
                        close_msg = WebSocketClose(
                            tunnel_id=tunnel_id,
                            code=msg.data or 1000,
                            reason=msg.extra or "",
                        )
                        await tunnel.websocket.send_bytes(
                            encode_message(close_msg, tunnel.compression)
                        )
                        break
                    elif msg.type == WSMsgType.ERROR:
                        logger.error(
                            "WebSocket error",
                            tunnel_id=str(tunnel_id),
                            error=str(ws.exception()),
                        )
                        break
            finally:
                # Cleanup
                self._ws_proxies.pop(tunnel_id, None)
                if not ws.closed:
                    await ws.close()

            return ws

        except TimeoutError:
            return web.Response(
                text="WebSocket upgrade timeout",
                status=504,
                content_type="text/plain",
            )
        except Exception as e:
            logger.error("WebSocket proxy error", error=str(e))
            return web.Response(
                text=f"WebSocket error: {e}",
                status=502,
                content_type="text/plain",
            )
        finally:
            self._pending_requests.pop(request_id, None)

    async def _handle_http_request(self, request: web.Request) -> web.StreamResponse:
        """Handle incoming HTTP request and route to tunnel.

        Routing priority:
        1. Custom domain (api.mycompany.com -> tunnel via DomainManager)
        2. Subdomain (abc123.instanton.tech -> tunnel via subdomain lookup)
        """
        client_ip = request.remote or "unknown"

        # IP restrictions check (deny takes precedence)
        if self._ip_restrictor:
            ip_result = self._ip_restrictor.check(client_ip)
            if not ip_result.allowed:
                logger.warning(
                    "IP blocked",
                    ip=client_ip,
                    reason=ip_result.reason,
                    rule=ip_result.matched_rule,
                )
                return web.Response(
                    text="Forbidden",
                    status=403,
                    content_type="text/plain",
                )

        # Rate limiting check
        if self._rate_limiter:
            limit_result = await self._rate_limiter.allow(client_ip, scope="ip")
            if not limit_result.allowed:
                logger.warning(
                    "Rate limit exceeded",
                    ip=client_ip,
                    remaining=limit_result.remaining,
                    reset_after=limit_result.reset_after,
                )
                return web.Response(
                    text="Too Many Requests",
                    status=429,
                    content_type="text/plain",
                    headers={
                        "Retry-After": str(int(limit_result.reset_after) + 1),
                        "X-RateLimit-Limit": str(limit_result.limit),
                        "X-RateLimit-Remaining": str(limit_result.remaining),
                    },
                )

        host = request.host.split(":")[0].lower()
        subdomain: str | None = None

        # Check custom domains first
        tunnel = await self._find_tunnel_for_host(host)
        if tunnel:
            subdomain = tunnel.subdomain

        if tunnel is None:
            # Extract subdomain from host (for base domain subdomains)
            subdomain = self._extract_subdomain(host)

            if not subdomain:
                # Direct access to base domain - show landing page
                return web.Response(
                    text="Instanton Relay Server\n\nTunnel through barriers, instantly",
                    content_type="text/plain",
                )

            # Find tunnel by subdomain
            tunnel = self._tunnels.get(subdomain)

        if not tunnel:
            # Check if subdomain is reserved (client disconnected, may reconnect)
            if subdomain and subdomain in self._reservations:
                reservation = self._reservations[subdomain]
                reserved_seconds = (datetime.now(UTC) - reservation.reserved_at).total_seconds()
                remaining_seconds = max(0, self.subdomain_grace_period - reserved_seconds)
                remaining_int = int(remaining_seconds)
                return web.Response(
                    text=(
                        f"Service temporarily unavailable\n\n"
                        f"The tunnel client for '{subdomain}' has disconnected.\n"
                        f"Waiting for reconnection (up to {remaining_int} seconds remaining).\n\n"
                        f"If you are the tunnel owner, please check your client application."
                    ),
                    status=503,  # Service Unavailable
                    content_type="text/plain",
                    headers={"Retry-After": str(int(min(30, remaining_seconds)))},
                )
            return web.Response(
                text=f"Tunnel not found: {subdomain}",
                status=404,
                content_type="text/plain",
            )

        # Check if WebSocket is still open
        if tunnel.websocket.closed:
            self._tunnels.pop(subdomain, None)
            self._tunnel_by_id.pop(tunnel.id, None)
            return web.Response(
                text="Tunnel disconnected",
                status=502,
                content_type="text/plain",
            )

        # Create HTTP request message
        request_id = uuid4()
        body = await request.read()

        # Prepare headers (filter out hop-by-hop headers)
        # IMPORTANT: Preserve Connection: upgrade and Upgrade headers for WebSocket support
        # This follows ngrok's pattern of forwarding upgrade headers
        headers = {}
        hop_by_hop = {
            "keep-alive",
            "proxy-authenticate",
            "proxy-authorization",
            "te",
            "trailers",
            "transfer-encoding",
        }

        # Check if this is a WebSocket upgrade request
        connection_header = request.headers.get("Connection", "").lower()
        upgrade_header = request.headers.get("Upgrade", "").lower()
        is_websocket_upgrade = "upgrade" in connection_header and upgrade_header == "websocket"

        # Handle WebSocket upgrade with bidirectional forwarding
        if is_websocket_upgrade:
            return await self._handle_websocket_proxy(request, tunnel)

        for key, value in request.headers.items():
            key_lower = key.lower()
            # Skip standard hop-by-hop headers
            if key_lower in hop_by_hop:
                continue
            # For WebSocket upgrades, preserve connection and upgrade headers
            if key_lower in ("connection", "upgrade"):
                if is_websocket_upgrade:
                    headers[key] = value
                continue
            headers[key] = value

        # Add X-Forwarded headers
        headers["X-Forwarded-For"] = request.remote or ""
        headers["X-Forwarded-Proto"] = "https" if self._ssl_context else "http"
        headers["X-Forwarded-Host"] = host

        http_request = HttpRequest(
            request_id=request_id,
            method=request.method,
            path=request.path_qs,
            headers=headers,
            body=body,
        )

        # Create future for response
        future: asyncio.Future[HttpResponse] = asyncio.Future()
        ctx = RequestContext(
            request_id=request_id,
            tunnel=tunnel,
            future=future,
            http_request=request,
            sse_complete=asyncio.Event(),
        )
        self._pending_requests[request_id] = ctx

        try:
            # Send to tunnel
            msg_bytes = encode_message(http_request, tunnel.compression)
            await tunnel.websocket.send_bytes(msg_bytes)
            tunnel.request_count += 1
            tunnel.bytes_sent += len(msg_bytes)
            tunnel.last_activity = datetime.now(UTC)

            # Wait for response with configurable timeout
            # Default 120s matches Cloudflare. None/0 means indefinite.
            timeout = self.config.request_timeout

            # For SSE streams, we need to wait for both:
            # 1. The future (in case it's a regular response or error)
            # 2. The sse_complete event (for SSE streaming completion)
            async def wait_for_response():
                """Wait for either regular response or SSE completion."""
                future_task = asyncio.create_task(future)
                sse_task = asyncio.create_task(ctx.sse_complete.wait())

                done, pending = await asyncio.wait(
                    [future_task, sse_task],
                    return_when=asyncio.FIRST_COMPLETED,
                )

                # Cancel pending tasks
                for task in pending:
                    task.cancel()
                    with contextlib.suppress(asyncio.CancelledError):
                        await task

                # Check if SSE stream completed
                if ctx.is_sse_stream and ctx.stream_response:
                    return None  # SSE response already sent

                # Return regular response
                if future_task in done:
                    return future_task.result()
                return None

            if timeout is None or timeout <= 0:
                # Indefinite timeout - wait forever
                response = await wait_for_response()
            else:
                response = await asyncio.wait_for(wait_for_response(), timeout=timeout)

            # If SSE stream was handled, return the stream response
            if response is None and ctx.is_sse_stream and ctx.stream_response:
                return ctx.stream_response

            # Handle None response (shouldn't happen, but defensive)
            if response is None:
                return web.Response(
                    text="No response received",
                    status=502,
                    content_type="text/plain",
                )

            # Build response headers
            # For WebSocket upgrade responses (status 101), preserve upgrade headers
            is_websocket_response = response.status == 101
            response_headers = {}
            for key, value in response.headers.items():
                key_lower = key.lower()
                # Skip hop-by-hop headers
                if key_lower in hop_by_hop:
                    continue
                # Skip content-length as we'll let aiohttp set it correctly
                # This prevents mismatches when body size differs from original
                if key_lower == "content-length":
                    continue
                # For WebSocket responses, preserve connection and upgrade headers
                if key_lower in ("connection", "upgrade"):
                    if is_websocket_response:
                        response_headers[key] = str(value)
                    continue
                # Ensure value is a string (handle potential bytes/other types)
                response_headers[key] = str(value) if not isinstance(value, str) else value

            # Always set Connection header for proper HTTP/1.1 behavior
            # This prevents browsers from hanging while waiting for connection state
            # Cloudflare does this: "Connection: keep-alive"
            if not is_websocket_response:
                response_headers["Connection"] = "keep-alive"

            # Use StreamResponse for large responses to improve time-to-first-byte
            # This sends headers immediately and streams body in chunks
            body_size = len(response.body) if response.body else 0

            if body_size > 65536:  # 64KB threshold for streaming
                # Use streaming for large responses
                stream_response = web.StreamResponse(
                    status=response.status,
                    headers=response_headers,
                )
                # Enable chunked encoding for streaming
                stream_response.enable_chunked_encoding()
                await stream_response.prepare(request)

                # Write body in chunks
                chunk_size = 65536  # 64KB chunks
                body = response.body
                for i in range(0, body_size, chunk_size):
                    await stream_response.write(body[i : i + chunk_size])

                await stream_response.write_eof()
                return stream_response
            else:
                # Use regular response for small payloads (faster)
                return web.Response(
                    status=response.status,
                    headers=response_headers,
                    body=response.body,
                )

        except TimeoutError:
            logger.warning(
                "Request timeout",
                subdomain=subdomain,
                request_id=str(request_id),
            )
            return web.Response(
                text="Gateway Timeout",
                status=504,
                content_type="text/plain",
            )
        except ConnectionError as e:
            logger.warning(
                "Connection error",
                subdomain=subdomain,
                error=str(e),
            )
            return web.Response(
                text="Bad Gateway",
                status=502,
                content_type="text/plain",
            )
        except Exception as e:
            logger.error(
                "Request error",
                subdomain=subdomain,
                request_id=str(request_id),
                error=str(e),
            )
            return web.Response(
                text="Internal Server Error",
                status=500,
                content_type="text/plain",
            )
        finally:
            self._pending_requests.pop(request_id, None)

    def _extract_subdomain(self, host: str) -> str | None:
        """Extract subdomain from host header."""
        base_domain = self.config.base_domain.lower()
        host = host.lower()

        # Check if host ends with base domain
        if not host.endswith(base_domain):
            return None

        # Extract subdomain
        if host == base_domain:
            return None

        # host should be "subdomain.base_domain"
        suffix = f".{base_domain}"
        if host.endswith(suffix):
            subdomain = host[: -len(suffix)]
            # Ensure it's a single subdomain (no nested subdomains)
            if "." not in subdomain:
                return subdomain

        return None

    async def _find_tunnel_for_host(self, host: str) -> TunnelConnection | None:
        """Find tunnel for a host, checking custom domains.

        Args:
            host: The hostname from the request.

        Returns:
            TunnelConnection if found via custom domain, None otherwise.
        """
        # Skip if host is the base domain or a subdomain of it
        base_domain = self.config.base_domain.lower()
        if host == base_domain or host.endswith(f".{base_domain}"):
            return None

        # Check if this is a registered custom domain
        tunnel_id = await self._domain_manager.get_tunnel_for_domain(host)
        if tunnel_id:
            # Find the tunnel by subdomain (tunnel_id is stored as subdomain in our routing)
            # The tunnel_id from domain manager maps to a subdomain
            for tunnel in self._tunnels.values():
                if str(tunnel.id) == tunnel_id or tunnel.subdomain == tunnel_id:
                    return tunnel

        return None

    def get_tunnel_count(self) -> int:
        """Get current number of active tunnels."""
        return len(self._tunnels)

    def get_tunnel(self, subdomain: str) -> TunnelConnection | None:
        """Get tunnel by subdomain."""
        return self._tunnels.get(subdomain)

    def get_tunnel_by_id(self, tunnel_id: UUID) -> TunnelConnection | None:
        """Get tunnel by ID."""
        return self._tunnel_by_id.get(tunnel_id)

    def _allocate_tcp_port(self) -> int:
        """Allocate a port for TCP tunnel."""
        port = self._next_tcp_port
        self._next_tcp_port += 1
        if self._next_tcp_port > 19999:
            self._next_tcp_port = 10000  # Wrap around
        return port

    def _allocate_udp_port(self) -> int:
        """Allocate a port for UDP tunnel."""
        port = self._next_udp_port
        self._next_udp_port += 1
        if self._next_udp_port > 29999:
            self._next_udp_port = 20000  # Wrap around
        return port

    async def _handle_tcp_tunnel_connection(self, request: web.Request) -> web.WebSocketResponse:
        """Handle incoming TCP tunnel client connection."""
        import struct

        ws = web.WebSocketResponse(heartbeat=30.0)
        await ws.prepare(request)
        self._websockets.add(ws)

        logger.info("New TCP tunnel client connected", peer=request.remote)

        tunnel_id = uuid4()
        assigned_port: int | None = None

        try:
            # Wait for connect message
            msg = await ws.receive()
            if msg.type != WSMsgType.BINARY:
                await ws.close()
                return ws

            # Parse TCP connect message (simple binary format)
            # Format: 1B type (0x01) + 16B tunnel_id + 2B local_port + 2B remote_port
            data = msg.data
            if len(data) < 21 or data[0] != 0x01:
                await ws.close()
                return ws

            local_port = struct.unpack(">H", data[17:19])[0]
            requested_port = struct.unpack(">H", data[19:21])[0]

            # Allocate port
            if requested_port and requested_port not in self._tcp_tunnels:
                assigned_port = requested_port
            else:
                assigned_port = self._allocate_tcp_port()
                while assigned_port in self._tcp_tunnels:
                    assigned_port = self._allocate_tcp_port()

            # Create tunnel entry
            tunnel = TunnelConnection(
                id=tunnel_id,
                subdomain=f"tcp-{assigned_port}",
                websocket=ws,
                local_port=local_port,
            )
            self._tcp_tunnels[assigned_port] = tunnel
            self._tunnel_by_id[tunnel_id] = tunnel

            # Send connect ACK: 1B type (0x02) + 16B tunnel_id + 2B port + 1B err_len
            response = bytearray()
            response.append(0x02)  # CONNECT_ACK
            response.extend(tunnel_id.bytes)
            response.extend(struct.pack(">H", assigned_port))
            response.append(0)  # No error
            await ws.send_bytes(bytes(response))

            logger.info(
                "TCP tunnel established",
                tunnel_id=str(tunnel_id),
                assigned_port=assigned_port,
                local_port=local_port,
            )

            # Handle TCP relay messages
            async for msg in ws:
                if msg.type == WSMsgType.BINARY:
                    tunnel.last_activity = datetime.now(UTC)
                    tunnel.bytes_received += len(msg.data)
                    # TCP relay logic would go here
                    # For now, just echo back (actual implementation would forward to TCP socket)
                elif msg.type == WSMsgType.ERROR:
                    logger.error(
                        "TCP WebSocket error",
                        port=assigned_port,
                        error=str(ws.exception()),
                    )
                    break
                elif msg.type == WSMsgType.CLOSE:
                    break

        except Exception as e:
            logger.error("TCP tunnel error", port=assigned_port, error=str(e))
        finally:
            self._websockets.discard(ws)
            if assigned_port and assigned_port in self._tcp_tunnels:
                del self._tcp_tunnels[assigned_port]
            if tunnel_id in self._tunnel_by_id:
                del self._tunnel_by_id[tunnel_id]
            logger.info("TCP tunnel closed", port=assigned_port)

        return ws

    async def _handle_udp_tunnel_connection(self, request: web.Request) -> web.WebSocketResponse:
        """Handle incoming UDP tunnel client connection."""
        import struct

        ws = web.WebSocketResponse(heartbeat=30.0)
        await ws.prepare(request)
        self._websockets.add(ws)

        logger.info("New UDP tunnel client connected", peer=request.remote)

        tunnel_id = uuid4()
        assigned_port: int | None = None

        try:
            # Wait for bind message
            msg = await ws.receive()
            if msg.type != WSMsgType.BINARY:
                await ws.close()
                return ws

            # Parse UDP bind message
            # Format: 1B type (0x01=bind) + 16B tunnel_id + 2B local_port + 2B remote_port
            data = msg.data
            if len(data) < 21 or data[0] != 0x01:
                await ws.close()
                return ws

            local_port = struct.unpack(">H", data[17:19])[0]
            requested_port = struct.unpack(">H", data[19:21])[0]

            # Allocate port
            if requested_port and requested_port not in self._udp_tunnels:
                assigned_port = requested_port
            else:
                assigned_port = self._allocate_udp_port()
                while assigned_port in self._udp_tunnels:
                    assigned_port = self._allocate_udp_port()

            # Create tunnel entry
            tunnel = TunnelConnection(
                id=tunnel_id,
                subdomain=f"udp-{assigned_port}",
                websocket=ws,
                local_port=local_port,
            )
            self._udp_tunnels[assigned_port] = tunnel
            self._tunnel_by_id[tunnel_id] = tunnel

            # Send bind ACK
            response = bytearray()
            response.append(0x02)  # BIND_ACK
            response.extend(tunnel_id.bytes)
            response.extend(struct.pack(">H", assigned_port))
            response.append(0)  # No error
            await ws.send_bytes(bytes(response))

            logger.info(
                "UDP tunnel established",
                tunnel_id=str(tunnel_id),
                assigned_port=assigned_port,
                local_port=local_port,
            )

            # Handle UDP relay messages
            async for msg in ws:
                if msg.type == WSMsgType.BINARY:
                    tunnel.last_activity = datetime.now(UTC)
                    tunnel.bytes_received += len(msg.data)
                    # UDP relay logic would go here
                elif msg.type == WSMsgType.ERROR:
                    logger.error(
                        "UDP WebSocket error",
                        port=assigned_port,
                        error=str(ws.exception()),
                    )
                    break
                elif msg.type == WSMsgType.CLOSE:
                    break

        except Exception as e:
            logger.error("UDP tunnel error", port=assigned_port, error=str(e))
        finally:
            self._websockets.discard(ws)
            if assigned_port and assigned_port in self._udp_tunnels:
                del self._udp_tunnels[assigned_port]
            if tunnel_id in self._tunnel_by_id:
                del self._tunnel_by_id[tunnel_id]
            logger.info("UDP tunnel closed", port=assigned_port)

        return ws
