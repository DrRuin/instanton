"""Relay server implementation with TLS support and subdomain routing."""

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
from instanton.protocol.messages import (
    CompressionType,
    ConnectRequest,
    ConnectResponse,
    ErrorCode,
    HttpRequest,
    HttpResponse,
    NegotiateRequest,
    Pong,
    ProtocolNegotiator,
    decode_message,
    encode_message,
)

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
class RequestContext:
    """Context for an in-flight HTTP request."""

    request_id: UUID
    tunnel: TunnelConnection
    future: asyncio.Future
    created_at: float = field(default_factory=time.time)


class RelayServer:
    """Relay server that manages tunnel connections with TLS support."""

    def __init__(self, config: ServerConfig):
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
        """Remove tunnels that have been idle too long and stale pending requests."""
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

        # Clean up stale pending requests (older than 60 seconds)
        stale_request_ids = [
            req_id
            for req_id, ctx in self._pending_requests.items()
            if current_time - ctx.created_at > 60.0
        ]
        for req_id in stale_request_ids:
            ctx = self._pending_requests.pop(req_id, None)
            if ctx and not ctx.future.done():
                ctx.future.set_exception(TimeoutError("Request timed out"))
            logger.debug("Cleaned up stale pending request", request_id=str(req_id))

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

        return web.json_response(
            {
                "total_tunnels": len(self._tunnels),
                "max_tunnels": self.config.max_tunnels,
                "tunnels": tunnels_info,
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

                if subdomain in self._tunnels:
                    response = ConnectResponse(
                        type="error",
                        error="Subdomain already in use",
                        error_code=ErrorCode.SUBDOMAIN_TAKEN,
                    )
                    await ws.send_bytes(encode_message(response))
                    await ws.close()
                    return ws
            else:
                # Generate random subdomain
                subdomain = secrets.token_hex(4)
                while subdomain in self._tunnels:
                    subdomain = secrets.token_hex(4)

            # Create tunnel
            tunnel_id = uuid4()
            url = f"https://{subdomain}.{self.config.base_domain}"

            tunnel = TunnelConnection(
                id=tunnel_id,
                subdomain=subdomain,
                websocket=ws,
                local_port=connect_req.local_port,
                compression=compression,
                negotiator=negotiator,
            )

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
            if subdomain and subdomain in self._tunnels:
                del self._tunnels[subdomain]
            if tunnel_id and tunnel_id in self._tunnel_by_id:
                del self._tunnel_by_id[tunnel_id]

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

            elif msg_type == "ping":
                pong = Pong(timestamp=msg["timestamp"], server_time=int(time.time() * 1000))
                await tunnel.websocket.send_bytes(encode_message(pong, tunnel.compression))

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

    async def _handle_http_request(self, request: web.Request) -> web.Response:
        """Handle incoming HTTP request and route to tunnel."""
        host = request.host.split(":")[0]

        # Extract subdomain from host
        subdomain = self._extract_subdomain(host)

        if not subdomain:
            # Direct access to base domain - show landing page
            return web.Response(
                text="Instanton Relay Server\n\nTunnel through barriers, instantly",
                content_type="text/plain",
            )

        # Find tunnel
        tunnel = self._tunnels.get(subdomain)
        if not tunnel:
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
        headers = {}
        hop_by_hop = {
            "connection",
            "keep-alive",
            "proxy-authenticate",
            "proxy-authorization",
            "te",
            "trailers",
            "transfer-encoding",
            "upgrade",
        }
        for key, value in request.headers.items():
            if key.lower() not in hop_by_hop:
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
        )
        self._pending_requests[request_id] = ctx

        try:
            # Send to tunnel
            msg_bytes = encode_message(http_request, tunnel.compression)
            await tunnel.websocket.send_bytes(msg_bytes)
            tunnel.request_count += 1
            tunnel.bytes_sent += len(msg_bytes)
            tunnel.last_activity = datetime.now(UTC)

            # Wait for response with timeout
            response = await asyncio.wait_for(future, timeout=30.0)

            # Build response headers
            response_headers = {}
            for key, value in response.headers.items():
                if key.lower() not in hop_by_hop:
                    response_headers[key] = value

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

    def get_tunnel_count(self) -> int:
        """Get current number of active tunnels."""
        return len(self._tunnels)

    def get_tunnel(self, subdomain: str) -> TunnelConnection | None:
        """Get tunnel by subdomain."""
        return self._tunnels.get(subdomain)

    def get_tunnel_by_id(self, tunnel_id: UUID) -> TunnelConnection | None:
        """Get tunnel by ID."""
        return self._tunnel_by_id.get(tunnel_id)
