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

from instanton.core.config import ServerConfig, get_config
from instanton.domains import DomainManager, DomainStore
from instanton.observability.dashboard import (
    DashboardBroadcaster,
    DashboardHandler,
    MetricsCollector,
)
from instanton.observability.metrics import (
    ACTIVE_CONNECTIONS,
    ACTIVE_TUNNELS,
    BYTES_TRANSFERRED,
    GRPC_REQUESTS,
    HTTP_REQUESTS,
    REQUEST_DURATION,
    TUNNEL_CONNECTIONS,
    TUNNEL_PACKETS,
    WEBSOCKET_MESSAGES,
    generate_metrics,
    get_content_type,
)
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
from instanton.security.basicauth import (
    PROXY_AUTH_CHALLENGE,
    PROXY_AUTH_HEADER,
    BasicAuthenticator,
    create_basic_authenticator,
)
from instanton.security.iprestrict import IPRestrictor, create_ip_restrictor
from instanton.security.oauth import (
    OAuthAuthenticator,
    SessionManager,
    create_oauth_authenticator,
)
from instanton.security.ratelimit import RateLimiter, create_rate_limiter

logger = structlog.get_logger()


def _bucket_status(status: int) -> str:
    """Bucket HTTP status to prevent cardinality explosion."""
    if 100 <= status < 200:
        return "1xx"
    if 200 <= status < 300:
        return "2xx"
    if 300 <= status < 400:
        return "3xx"
    if 400 <= status < 500:
        return "4xx"
    if 500 <= status < 600:
        return "5xx"
    return "other"


@dataclass
class TunnelConnection:
    """Active tunnel connection."""

    id: UUID
    subdomain: str
    websocket: web.WebSocketResponse
    local_port: int
    source_ip: str = ""  # Client IP that created this tunnel
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
    http_request: web.Request | None = None
    stream_response: web.StreamResponse | None = None
    is_sse_stream: bool = False
    is_grpc: bool = False
    sse_complete: asyncio.Event | None = None
    heartbeat_task: asyncio.Task | None = None


class RelayServer:
    """Relay server that manages tunnel connections with TLS support."""

    DEFAULT_SUBDOMAIN_GRACE_PERIOD = 1800.0

    def __init__(self, config: ServerConfig, domains_path: str | Path = "domains.json"):
        self.config = config
        self._tunnels: dict[str, TunnelConnection] = {}
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
        self._tcp_tunnels: dict[int, TunnelConnection] = {}
        self._udp_tunnels: dict[int, TunnelConnection] = {}
        # Port ranges from config (with defaults if not set)
        self._tcp_port_min = getattr(config, "tcp_port_min", 10000)
        self._tcp_port_max = getattr(config, "tcp_port_max", 19999)
        self._udp_port_min = getattr(config, "udp_port_min", 20000)
        self._udp_port_max = getattr(config, "udp_port_max", 29999)
        self._next_tcp_port = self._tcp_port_min
        self._next_udp_port = self._udp_port_min
        self._chunk_assembler = ChunkAssembler()
        self._chunk_streams: dict[UUID, tuple[float, UUID, int, dict[str, str]]] = {}
        self._ws_proxies: dict[UUID, web.WebSocketResponse] = {}
        self._reservations: dict[str, SubdomainReservation] = {}
        self._domain_store = DomainStore(domains_path)
        self._domain_manager = DomainManager(self._domain_store, config.base_domain)
        self._rate_limiter: RateLimiter | None = None
        if getattr(config, "rate_limit_enabled", False):
            self._rate_limiter = create_rate_limiter(
                requests_per_second=getattr(config, "rate_limit_rps", 100.0),
                burst_size=getattr(config, "rate_limit_burst", 10),
            )
        self._ip_restrictor: IPRestrictor | None = None
        if getattr(config, "ip_restrict_enabled", False):
            self._ip_restrictor = create_ip_restrictor(
                allow=getattr(config, "ip_allow", []),
                deny=getattr(config, "ip_deny", []),
            )
        self._basic_auth: BasicAuthenticator | None = None
        if getattr(config, "auth_enabled", False):
            username = getattr(config, "auth_username", None)
            password = getattr(config, "auth_password", None)
            if username and password:
                self._basic_auth = create_basic_authenticator(username, password)

        # OAuth authentication (self-hosted only)
        self._oauth_authenticator: OAuthAuthenticator | None = None
        self._oauth_session_manager: SessionManager | None = None
        self._oauth_enabled = getattr(config, "oauth_enabled", False)

        # Per-IP tunnel tracking for abuse prevention
        self._tunnels_by_ip: dict[str, set[str]] = {}  # IP -> set of subdomains
        self._max_tunnels_per_ip = getattr(config, "max_tunnels_per_ip", 10)

        # Tunnel creation rate limiter (separate from request rate limiter)
        tunnel_rate = (
            getattr(config, "tunnel_creation_rate_limit", 5.0) / 60.0
        )  # Convert per-min to per-sec
        tunnel_burst = getattr(config, "tunnel_creation_burst", 3)
        self._tunnel_creation_limiter = create_rate_limiter(
            requests_per_second=tunnel_rate,
            burst_size=tunnel_burst,
            window_seconds=60.0,  # 1-minute window for tunnel creation
        )

        # Per-subdomain rate limiter to prevent one tunnel from DoS'ing others
        # Uses more generous limits since each tunnel should have reasonable traffic
        subdomain_rate = getattr(config, "rate_limit_rps", 100.0)  # Same as global by default
        subdomain_burst = getattr(config, "rate_limit_burst", 10) * 2  # Allow some burst
        self._subdomain_rate_limiter = create_rate_limiter(
            requests_per_second=subdomain_rate,
            burst_size=subdomain_burst,
        )

        # Failed lookup rate limiter to prevent subdomain enumeration attacks
        # More aggressive limits since legitimate users shouldn't hit many 404s
        self._failed_lookup_limiter = create_rate_limiter(
            requests_per_second=5.0,  # 5 failed lookups per second
            burst_size=10,  # Allow small burst
        )

        # Dashboard components (initialized in start() if enabled)
        self._dashboard_enabled = getattr(config, "dashboard_enabled", True)
        self._dashboard_collector: MetricsCollector | None = None
        self._dashboard_broadcaster: DashboardBroadcaster | None = None
        self._dashboard_handler: DashboardHandler | None = None

        self._http3_server: Any = None

    def _check_control_auth(self, request: web.Request) -> web.Response | None:
        """Check auth for control plane (tunnel connections). Returns error response or None if OK."""
        if not self._basic_auth:
            return None
        auth_header = request.headers.get(PROXY_AUTH_HEADER)
        auth_result = self._basic_auth.check(auth_header)
        if not auth_result.allowed:
            return web.Response(
                text="Proxy Authentication Required",
                status=407,
                headers={PROXY_AUTH_CHALLENGE: 'Basic realm="Instanton Control"'},
            )
        return None

    def _check_admin_auth(self, request: web.Request) -> web.Response | None:
        """Check auth for admin endpoints (/stats, /metrics).

        Uses dashboard credentials if configured, otherwise falls back to tunnel auth.
        This keeps sensitive data protected separately from tunnel access.
        """
        dashboard_user = getattr(self.config, "dashboard_user", None)
        dashboard_pass = getattr(self.config, "dashboard_password", None)

        # If dashboard auth is configured, use it for admin endpoints
        if dashboard_user and dashboard_pass:
            import base64

            auth_header = request.headers.get("Authorization", "")
            if not auth_header.startswith("Basic "):
                return web.Response(
                    text="Unauthorized",
                    status=401,
                    headers={"WWW-Authenticate": 'Basic realm="Instanton Admin"'},
                )

            try:
                encoded = auth_header[6:]
                decoded = base64.b64decode(encoded).decode("utf-8")
                username, password = decoded.split(":", 1)

                if secrets.compare_digest(username, dashboard_user) and secrets.compare_digest(
                    password, dashboard_pass
                ):
                    return None  # Authorized
            except (ValueError, UnicodeDecodeError):
                pass

            return web.Response(
                text="Unauthorized",
                status=401,
                headers={"WWW-Authenticate": 'Basic realm="Instanton Admin"'},
            )

        # Fall back to tunnel auth if no dashboard auth configured
        return self._check_control_auth(request)

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
        self._ssl_context = self._create_ssl_context()

        # Initialize OAuth if enabled
        if self._oauth_enabled:
            oauth_client_id = getattr(self.config, "oauth_client_id", None)
            oauth_client_secret = getattr(self.config, "oauth_client_secret", None)

            if oauth_client_id and oauth_client_secret:
                self._oauth_session_manager = SessionManager(
                    session_duration=getattr(self.config, "oauth_session_duration", 86400),
                )
                await self._oauth_session_manager.start()

                base_url = f"https://{self.config.base_domain}"
                try:
                    self._oauth_authenticator = await create_oauth_authenticator(
                        provider=getattr(self.config, "oauth_provider", "oidc"),
                        client_id=oauth_client_id,
                        client_secret=oauth_client_secret,
                        session_manager=self._oauth_session_manager,
                        base_url=base_url,
                        issuer_url=getattr(self.config, "oauth_issuer_url", None),
                        allowed_domains=getattr(self.config, "oauth_allowed_domains", []),
                        allowed_emails=getattr(self.config, "oauth_allowed_emails", []),
                        session_duration=getattr(self.config, "oauth_session_duration", 86400),
                    )
                    logger.info(
                        "OAuth authentication enabled",
                        provider=getattr(self.config, "oauth_provider", "oidc"),
                        allowed_domains=getattr(self.config, "oauth_allowed_domains", []),
                    )
                except Exception as e:
                    logger.error("Failed to initialize OAuth", error=str(e))
                    self._oauth_authenticator = None
            else:
                logger.warning("OAuth enabled but client_id/client_secret not configured")

        self._control_app = web.Application()
        self._control_app.router.add_get("/tunnel", self._handle_tunnel_connection)
        self._control_app.router.add_get("/tcp", self._handle_tcp_tunnel_connection)
        self._control_app.router.add_get("/udp", self._handle_udp_tunnel_connection)
        self._control_app.router.add_get("/health", self._handle_health_check)
        self._control_app.router.add_get("/stats", self._handle_stats)
        self._control_app.router.add_get("/metrics", self._handle_metrics)

        # Initialize dashboard if enabled
        if self._dashboard_enabled:
            update_interval = getattr(self.config, "dashboard_update_interval", 1.0)
            history_seconds = getattr(self.config, "dashboard_history_seconds", 300)

            self._dashboard_collector = MetricsCollector(
                relay_server=self,
                update_interval=update_interval,
                history_seconds=history_seconds,
            )
            self._dashboard_broadcaster = DashboardBroadcaster(
                collector=self._dashboard_collector,
                update_interval=update_interval,
            )
            self._dashboard_handler = DashboardHandler(
                broadcaster=self._dashboard_broadcaster,
                username=getattr(self.config, "dashboard_user", None),
                password=getattr(self.config, "dashboard_password", None),
                max_login_failures=getattr(self.config, "dashboard_max_login_failures", 5),
                lockout_minutes=getattr(self.config, "dashboard_lockout_minutes", 15.0),
            )

            # Register dashboard routes on control app
            self._dashboard_handler.register_routes(self._control_app)
            logger.info("Dashboard enabled at /dashboard")

        global_config = get_config()
        self._http_app = web.Application(
            client_max_size=global_config.performance.http_max_body_size
        )
        self._http_app.router.add_route("*", "/{path:.*}", self._handle_http_request)

        self._control_runner = web.AppRunner(self._control_app)
        self._http_runner = web.AppRunner(self._http_app)
        await self._control_runner.setup()
        await self._http_runner.setup()

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

        self._cleanup_task = asyncio.create_task(self._cleanup_loop())

        # Start dashboard components
        if self._dashboard_enabled and self._dashboard_collector and self._dashboard_broadcaster:
            await self._dashboard_collector.start()
            await self._dashboard_broadcaster.start()
            logger.info("Dashboard metrics collection started")

        if getattr(self.config, "http3_enabled", False):
            from instanton.server.http3 import HTTP3Server

            self._http3_server = HTTP3Server(self.config, self)
            await self._http3_server.start()

        logger.info(
            "Relay server started",
            base_domain=self.config.base_domain,
            control_bind=self.config.control_bind,
            https_bind=self.config.https_bind,
            http3_enabled=getattr(self.config, "http3_enabled", False),
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

        # Stop OAuth session manager
        if self._oauth_session_manager:
            await self._oauth_session_manager.stop()

        # Stop dashboard components
        if self._dashboard_broadcaster:
            await self._dashboard_broadcaster.stop()
        if self._dashboard_collector:
            await self._dashboard_collector.stop()

        if self._http3_server:
            await self._http3_server.stop()
            self._http3_server = None

        if self._cleanup_task:
            self._cleanup_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._cleanup_task

        for ws in list(self._websockets):
            with contextlib.suppress(Exception):
                await ws.close()

        for tunnel in list(self._tunnels.values()):
            with contextlib.suppress(Exception):
                await tunnel.websocket.close()

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
                await asyncio.sleep(60)
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

        timeout = self.config.request_timeout
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
        """Health check endpoint.

        Returns minimal info - just status. No sensitive data exposed.
        Use /stats for detailed info (requires auth).
        """
        # Only return "healthy" - no tunnel counts or uptime to prevent info leakage
        return web.json_response({"status": "healthy"})

    async def _handle_stats(self, request: web.Request) -> web.Response:
        """Statistics endpoint - requires admin/dashboard auth."""
        if auth_error := self._check_admin_auth(request):
            return auth_error

        tunnels_info = []
        for subdomain, tunnel in self._tunnels.items():
            tunnels_info.append(
                {
                    "subdomain": subdomain,
                    "id": str(tunnel.id),
                    "source_ip": tunnel.source_ip,
                    "connected_at": tunnel.connected_at.isoformat(),
                    "request_count": tunnel.request_count,
                    "bytes_sent": tunnel.bytes_sent,
                    "bytes_received": tunnel.bytes_received,
                }
            )

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

        # Per-IP tunnel counts
        tunnels_per_ip = {ip: len(subdomains) for ip, subdomains in self._tunnels_by_ip.items()}

        return web.json_response(
            {
                "total_tunnels": len(self._tunnels),
                "total_tcp_tunnels": len(self._tcp_tunnels),
                "total_udp_tunnels": len(self._udp_tunnels),
                "total_reservations": len(self._reservations),
                "unique_ips": len(self._tunnels_by_ip),
                "max_tunnels": self.config.max_tunnels,
                "max_tunnels_per_ip": self._max_tunnels_per_ip,
                "subdomain_grace_period": self.subdomain_grace_period,
                "tunnels": tunnels_info,
                "reservations": reservations_info,
                "tunnels_per_ip": tunnels_per_ip,
            }
        )

    async def _handle_metrics(self, request: web.Request) -> web.Response:
        """Prometheus metrics endpoint - requires admin/dashboard auth."""
        if auth_error := self._check_admin_auth(request):
            return auth_error

        ACTIVE_TUNNELS.labels(type="http").set(len(self._tunnels))
        ACTIVE_TUNNELS.labels(type="tcp").set(len(self._tcp_tunnels))
        ACTIVE_TUNNELS.labels(type="udp").set(len(self._udp_tunnels))
        ACTIVE_CONNECTIONS.set(len(self._websockets))

        return web.Response(
            body=generate_metrics(),
            content_type=get_content_type(),
        )

    async def _handle_tunnel_connection(
        self, request: web.Request
    ) -> web.WebSocketResponse | web.Response:
        """Handle incoming tunnel client connection."""
        client_ip = request.remote or "unknown"

        # Check auth before preparing WebSocket
        if self._basic_auth:
            auth_header = request.headers.get(PROXY_AUTH_HEADER)
            auth_result = self._basic_auth.check(auth_header)
            if not auth_result.allowed:
                return web.Response(
                    text="Proxy Authentication Required",
                    status=407,
                    headers={PROXY_AUTH_CHALLENGE: 'Basic realm="Instanton Tunnel"'},
                )

        # Check IP restrictions for tunnel creation
        if self._ip_restrictor:
            ip_result = self._ip_restrictor.check(client_ip)
            if not ip_result.allowed:
                logger.warning(
                    "Tunnel creation blocked by IP restriction",
                    ip=client_ip,
                    reason=ip_result.reason,
                )
                return web.Response(
                    text="Forbidden",
                    status=403,
                    content_type="text/plain",
                )

        # Check tunnel creation rate limit
        rate_result = await self._tunnel_creation_limiter.allow(client_ip, scope="ip")
        if not rate_result.allowed:
            logger.warning(
                "Tunnel creation rate limit exceeded",
                ip=client_ip,
                reset_after=rate_result.reset_after,
            )
            return web.Response(
                text="Too Many Requests - tunnel creation rate limit exceeded",
                status=429,
                content_type="text/plain",
                headers={"Retry-After": str(int(rate_result.reset_after) + 1)},
            )

        # Check per-IP tunnel limit
        current_ip_tunnels = len(self._tunnels_by_ip.get(client_ip, set()))
        if current_ip_tunnels >= self._max_tunnels_per_ip:
            logger.warning(
                "Per-IP tunnel limit exceeded",
                ip=client_ip,
                current=current_ip_tunnels,
                limit=self._max_tunnels_per_ip,
            )
            return web.Response(
                text=f"Too Many Tunnels - maximum {self._max_tunnels_per_ip} tunnels per IP",
                status=429,
                content_type="text/plain",
            )

        config = get_config()
        ws = web.WebSocketResponse(
            heartbeat=config.timeouts.ping_interval,
            max_msg_size=config.performance.ws_max_size,
            receive_timeout=config.timeouts.ws_receive_timeout,
        )
        await ws.prepare(request)
        self._websockets.add(ws)

        logger.info("New tunnel client connected", peer=request.remote)

        tunnel: TunnelConnection | None = None
        subdomain: str = ""
        tunnel_id: UUID = uuid4()

        try:
            msg = await ws.receive()
            if msg.type != WSMsgType.BINARY:
                await ws.close()
                return ws

            data = decode_message(msg.data)
            msg_type = data.get("type")

            negotiator = ProtocolNegotiator()
            compression = CompressionType.NONE

            if msg_type == "negotiate":
                negotiate_req = NegotiateRequest(**data)
                negotiate_resp = negotiator.handle_request(negotiate_req)
                compression = negotiator.negotiated_compression
                await ws.send_bytes(encode_message(negotiate_resp))

                msg = await ws.receive()
                if msg.type != WSMsgType.BINARY:
                    await ws.close()
                    return ws
                data = decode_message(msg.data)

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

            if len(self._tunnels) >= self.config.max_tunnels:
                response = ConnectResponse(
                    type="error",
                    error="Server at capacity",
                    error_code=ErrorCode.SERVER_FULL,
                )
                await ws.send_bytes(encode_message(response))
                await ws.close()
                return ws

            subdomain = connect_req.subdomain or ""
            reclaimed_reservation: SubdomainReservation | None = None

            if subdomain:
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

                if subdomain in self._reservations:
                    reservation = self._reservations[subdomain]
                    reclaimed_reservation = self._reservations.pop(subdomain)
                    tunnel_id = reclaimed_reservation.tunnel_id
                    logger.info(
                        "Client reclaiming reserved subdomain",
                        subdomain=subdomain,
                        tunnel_id=str(tunnel_id),
                        reserved_for=(datetime.now(UTC) - reservation.reserved_at).total_seconds(),
                    )
            else:
                subdomain = secrets.token_hex(6)
                attempts = 0
                while subdomain in self._tunnels:
                    subdomain = secrets.token_hex(6)
                    attempts += 1
                    if attempts > 10:
                        subdomain = f"{str(tunnel_id)[:8]}{secrets.token_hex(2)}"
                        break

            url = f"https://{subdomain}.{self.config.base_domain}"

            tunnel = TunnelConnection(
                id=tunnel_id,
                subdomain=subdomain,
                websocket=ws,
                local_port=connect_req.local_port,
                source_ip=client_ip,
                compression=compression,
                negotiator=negotiator,
            )

            if reclaimed_reservation:
                tunnel.request_count = reclaimed_reservation.request_count
                tunnel.bytes_sent = reclaimed_reservation.bytes_sent
                tunnel.bytes_received = reclaimed_reservation.bytes_received

            self._tunnels[subdomain] = tunnel
            self._tunnel_by_id[tunnel_id] = tunnel

            # Track tunnel by IP for per-IP limits
            if client_ip not in self._tunnels_by_ip:
                self._tunnels_by_ip[client_ip] = set()
            self._tunnels_by_ip[client_ip].add(subdomain)

            response = ConnectResponse(
                type="connected",
                tunnel_id=tunnel_id,
                subdomain=subdomain,
                url=url,
            )
            await ws.send_bytes(encode_message(response, compression))

            TUNNEL_CONNECTIONS.labels(type="http").inc()

            logger.info(
                "Tunnel established",
                tunnel_id=str(tunnel_id),
                subdomain=subdomain,
                source_ip=client_ip,
                compression=compression.name,
                ip_tunnel_count=len(self._tunnels_by_ip.get(client_ip, set())),
            )

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
            self._websockets.discard(ws)

            disconnected_tunnel = self._tunnels.pop(subdomain, None) if subdomain else None
            if tunnel_id in self._tunnel_by_id:
                del self._tunnel_by_id[tunnel_id]

            # Remove from per-IP tracking
            if disconnected_tunnel and disconnected_tunnel.source_ip:
                ip_tunnels = self._tunnels_by_ip.get(disconnected_tunnel.source_ip)
                if ip_tunnels:
                    ip_tunnels.discard(subdomain)
                    if not ip_tunnels:
                        del self._tunnels_by_ip[disconnected_tunnel.source_ip]

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
        if subdomain.startswith("-") or subdomain.endswith("-"):
            return False
        return all(c.isalnum() or c == "-" for c in subdomain)

    async def _prepare_sse_stream(self, ctx: RequestContext, stream_id: UUID) -> None:
        """Prepare SSE StreamResponse for immediate streaming."""
        try:
            if ctx.stream_response and ctx.http_request:
                await ctx.stream_response.prepare(ctx.http_request)

                ctx.heartbeat_task = asyncio.create_task(self._sse_heartbeat_loop(ctx))

                logger.debug(
                    "SSE stream prepared with heartbeat",
                    stream_id=str(stream_id),
                    request_id=str(ctx.request_id),
                )
        except Exception as e:
            logger.error("Failed to prepare SSE stream", error=str(e))
            if ctx.sse_complete:
                ctx.sse_complete.set()

    async def _sse_heartbeat_loop(self, ctx: RequestContext) -> None:
        """Send periodic heartbeat comments to keep SSE connection alive.

        SSE protocol allows comment lines starting with ':' which are ignored
        by clients but keep the connection from timing out.
        """
        heartbeat_interval = get_config().timeouts.sse_heartbeat_interval

        try:
            while ctx.stream_response and not ctx.sse_complete.is_set():
                try:
                    await asyncio.wait_for(
                        ctx.sse_complete.wait(),
                        timeout=heartbeat_interval,
                    )
                    break
                except TimeoutError:
                    pass

                if ctx.stream_response:
                    try:
                        await ctx.stream_response.write(b":heartbeat\n\n")
                    except Exception as e:
                        logger.debug("SSE heartbeat write failed", error=str(e))
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
                chunk_start = ChunkStart(**msg)
                headers = chunk_start.headers.copy() if chunk_start.headers else {}
                if "Content-Type" not in headers:
                    headers["Content-Type"] = chunk_start.content_type

                content_type = headers.get("Content-Type", "").lower()

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
                    "multipart/x-mixed-replace" in content_type or "multipart/mixed" in content_type
                )

                is_media_stream = content_type.startswith("video/") or content_type.startswith(
                    "audio/"
                )

                is_binary_stream = "application/octet-stream" in content_type

                is_streaming_type = (
                    is_event_stream
                    or is_grpc_stream
                    or is_multipart_stream
                    or is_media_stream
                    or is_binary_stream
                )

                ctx = self._pending_requests.get(chunk_start.request_id)

                if is_streaming_type and ctx and ctx.http_request:
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
                    ctx.stream_response.enable_chunked_encoding()
                    asyncio.create_task(self._prepare_sse_stream(ctx, chunk_start.stream_id))
                    logger.debug(
                        "SSE stream started",
                        stream_id=str(chunk_start.stream_id),
                        request_id=str(chunk_start.request_id),
                    )
                else:
                    self._chunk_assembler.start_stream(chunk_start)

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
                chunk_data = ChunkData(**msg)
                stream_info = self._chunk_streams.get(chunk_data.stream_id)

                if stream_info:
                    _created, request_id, _status, _headers = stream_info
                    ctx = self._pending_requests.get(request_id)

                    if ctx and ctx.is_sse_stream and ctx.stream_response:
                        try:
                            await ctx.stream_response.write(chunk_data.data)
                        except Exception as e:
                            logger.warning("SSE write error", error=str(e))
                    else:
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
                chunk_end = ChunkEnd(**msg)
                stream_info = self._chunk_streams.pop(chunk_end.stream_id, None)
                if stream_info:
                    _created, request_id, status, headers = stream_info
                    ctx = self._pending_requests.get(request_id)

                    if ctx and ctx.is_sse_stream:
                        try:
                            if ctx.stream_response:
                                await ctx.stream_response.write_eof()
                        except Exception as e:
                            logger.warning("SSE write_eof error", error=str(e))
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
                pong_bytes = encode_message(pong, tunnel.compression)
                await tunnel.websocket.send_bytes(pong_bytes)
                tunnel.bytes_sent += len(pong_bytes)

            elif msg_type == "websocket_upgrade_response":
                response = WebSocketUpgradeResponse(**msg)
                ctx = self._pending_requests.get(response.request_id)
                if ctx and not ctx.future.done():
                    ctx.future.set_result(response)

            elif msg_type == "websocket_frame":
                frame = WebSocketFrame(**msg)
                ws = self._ws_proxies.get(frame.tunnel_id)
                if ws and not ws.closed:
                    try:
                        if frame.opcode == WebSocketOpcode.TEXT:
                            await ws.send_str(frame.payload.decode("utf-8"))
                            WEBSOCKET_MESSAGES.labels(direction="out", type="text").inc()
                            BYTES_TRANSFERRED.labels(direction="out", protocol="websocket").inc(
                                len(frame.payload)
                            )
                        elif frame.opcode == WebSocketOpcode.BINARY:
                            await ws.send_bytes(frame.payload)
                            WEBSOCKET_MESSAGES.labels(direction="out", type="binary").inc()
                            BYTES_TRANSFERRED.labels(direction="out", protocol="websocket").inc(
                                len(frame.payload)
                            )
                        elif frame.opcode == WebSocketOpcode.PING:
                            await ws.ping(frame.payload)
                        elif frame.opcode == WebSocketOpcode.PONG:
                            await ws.pong(frame.payload)
                    except Exception as e:
                        logger.warning("Failed to forward WS frame", error=str(e))

            elif msg_type == "websocket_close":
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

        headers = {}
        for key, value in request.headers.items():
            key_lower = key.lower()
            if key_lower not in ("host", "connection", "upgrade"):
                headers[key] = value
        headers["X-Forwarded-For"] = request.remote or ""
        headers["X-Forwarded-Proto"] = "https" if self._ssl_context else "http"

        subprotocols = []
        if "Sec-WebSocket-Protocol" in request.headers:
            subprotocols = [p.strip() for p in request.headers["Sec-WebSocket-Protocol"].split(",")]

        ws_upgrade = WebSocketUpgrade(
            tunnel_id=tunnel_id,
            request_id=request_id,
            path=request.path_qs,
            headers=headers,
            subprotocols=subprotocols,
        )

        future: asyncio.Future[WebSocketUpgradeResponse] = asyncio.Future()
        self._pending_requests[request_id] = RequestContext(
            request_id=request_id,
            tunnel=tunnel,
            future=future,
            http_request=request,
            sse_complete=asyncio.Event(),
        )

        try:
            msg_bytes = encode_message(ws_upgrade, tunnel.compression)
            await tunnel.websocket.send_bytes(msg_bytes)
            tunnel.bytes_sent += len(msg_bytes)

            timeout = self.config.request_timeout or 30.0
            response = await asyncio.wait_for(future, timeout=timeout)

            if not response.success:
                return web.Response(
                    text=response.error or "WebSocket upgrade failed",
                    status=502,
                    content_type="text/plain",
                )

            ws = web.WebSocketResponse(protocols=subprotocols)
            await ws.prepare(request)

            self._ws_proxies[tunnel_id] = ws

            logger.info(f"WS CONNECT {request.path_qs} tunnel={str(tunnel_id)[:8]}")

            try:
                async for msg in ws:
                    if msg.type == WSMsgType.TEXT:
                        payload = msg.data.encode() if isinstance(msg.data, str) else msg.data
                        frame = WebSocketFrame(
                            tunnel_id=tunnel_id,
                            opcode=WebSocketOpcode.TEXT,
                            payload=payload,
                        )
                        frame_bytes = encode_message(frame, tunnel.compression)
                        await tunnel.websocket.send_bytes(frame_bytes)
                        tunnel.bytes_sent += len(frame_bytes)
                        WEBSOCKET_MESSAGES.labels(direction="in", type="text").inc()
                        BYTES_TRANSFERRED.labels(direction="in", protocol="websocket").inc(
                            len(payload)
                        )
                        logger.info(f"WS TEXT {len(payload)}B tunnel={str(tunnel_id)[:8]}")
                    elif msg.type == WSMsgType.BINARY:
                        frame = WebSocketFrame(
                            tunnel_id=tunnel_id,
                            opcode=WebSocketOpcode.BINARY,
                            payload=msg.data,
                        )
                        frame_bytes = encode_message(frame, tunnel.compression)
                        await tunnel.websocket.send_bytes(frame_bytes)
                        tunnel.bytes_sent += len(frame_bytes)
                        WEBSOCKET_MESSAGES.labels(direction="in", type="binary").inc()
                        BYTES_TRANSFERRED.labels(direction="in", protocol="websocket").inc(
                            len(msg.data)
                        )
                        logger.info(f"WS BINARY {len(msg.data)}B tunnel={str(tunnel_id)[:8]}")
                    elif msg.type == WSMsgType.CLOSE:
                        close_msg = WebSocketClose(
                            tunnel_id=tunnel_id,
                            code=msg.data or 1000,
                            reason=msg.extra or "",
                        )
                        close_bytes = encode_message(close_msg, tunnel.compression)
                        await tunnel.websocket.send_bytes(close_bytes)
                        tunnel.bytes_sent += len(close_bytes)
                        logger.info(f"WS CLOSE code={msg.data or 1000} tunnel={str(tunnel_id)[:8]}")
                        break
                    elif msg.type == WSMsgType.ERROR:
                        logger.error(
                            "WebSocket error",
                            tunnel_id=str(tunnel_id),
                            error=str(ws.exception()),
                        )
                        break
            finally:
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
        request_start = time.time()
        client_ip = request.remote or "unknown"

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

        if self._basic_auth:
            auth_header = request.headers.get(PROXY_AUTH_HEADER)
            auth_result = self._basic_auth.check(auth_header)
            if not auth_result.allowed:
                logger.warning(
                    "Proxy auth failed",
                    ip=client_ip,
                    reason=auth_result.reason,
                )
                return web.Response(
                    text="Proxy Authentication Required",
                    status=407,
                    content_type="text/plain",
                    headers={PROXY_AUTH_CHALLENGE: 'Basic realm="Instanton Relay"'},
                )

        # OAuth authentication (self-hosted only)
        if self._oauth_authenticator:
            # Handle OAuth callback path
            if request.path == "/_instanton/oauth/callback":
                return await self._oauth_authenticator.handle_callback(request)
            # Handle OAuth logout path
            if request.path == "/_instanton/oauth/logout":
                return await self._oauth_authenticator.handle_logout(request)

            # Check OAuth authentication for all other requests
            oauth_result = await self._oauth_authenticator.check(request)
            if not oauth_result.allowed:
                if oauth_result.redirect_url:
                    # Redirect to OAuth provider for authentication
                    raise web.HTTPFound(oauth_result.redirect_url)
                return web.Response(
                    text="Authentication required",
                    status=401,
                    content_type="text/plain",
                )

        host = request.host.split(":")[0].lower()
        subdomain: str | None = None

        tunnel = await self._find_tunnel_for_host(host)
        if tunnel:
            subdomain = tunnel.subdomain

        if tunnel is None:
            subdomain = self._extract_subdomain(host)

            if not subdomain:
                return web.Response(
                    text="Instanton Relay Server\n\nTunnel through barriers, instantly",
                    content_type="text/plain",
                )

            tunnel = self._tunnels.get(subdomain)

        if not tunnel:
            if subdomain and subdomain in self._reservations:
                reservation = self._reservations[subdomain]
                reserved_seconds = (datetime.now(UTC) - reservation.reserved_at).total_seconds()
                remaining_seconds = max(0, self.subdomain_grace_period - reserved_seconds)
                # Generic message - don't reveal subdomain or reservation details
                return web.Response(
                    text="Service temporarily unavailable. Please try again later.",
                    status=503,
                    content_type="text/plain",
                    headers={"Retry-After": str(int(min(30, remaining_seconds)))},
                )

            # Rate limit failed subdomain lookups to prevent enumeration attacks
            failed_lookup_limit = await self._failed_lookup_limiter.allow(client_ip, scope="ip")
            if not failed_lookup_limit.allowed:
                logger.warning(
                    "Failed lookup rate limit exceeded - possible enumeration attack",
                    ip=client_ip,
                    reset_after=failed_lookup_limit.reset_after,
                )
                return web.Response(
                    text="Too many requests",
                    status=429,
                    content_type="text/plain",
                    headers={"Retry-After": str(int(failed_lookup_limit.reset_after) + 1)},
                )

            # Don't leak which subdomain was requested - generic message
            return web.Response(
                text="Tunnel not found",
                status=404,
                content_type="text/plain",
            )

        if tunnel.websocket.closed:
            self._tunnels.pop(subdomain, None)
            self._tunnel_by_id.pop(tunnel.id, None)
            return web.Response(
                text="Tunnel disconnected",
                status=502,
                content_type="text/plain",
            )

        # Per-subdomain rate limiting to prevent one tunnel from DoS'ing the server
        subdomain_limit = await self._subdomain_rate_limiter.allow(
            tunnel.subdomain, scope="subdomain"
        )
        if not subdomain_limit.allowed:
            logger.warning(
                "Per-subdomain rate limit exceeded",
                subdomain=tunnel.subdomain,
                reset_after=subdomain_limit.reset_after,
            )
            return web.Response(
                text="Rate limit exceeded for this tunnel",
                status=429,
                content_type="text/plain",
                headers={"Retry-After": str(int(subdomain_limit.reset_after) + 1)},
            )

        request_id = uuid4()

        request_content_type = request.headers.get("Content-Type", "").lower()
        is_grpc_request = (
            "application/grpc" in request_content_type
            or "application/grpc+proto" in request_content_type
            or "application/grpc-web" in request_content_type
        )

        headers = {}
        hop_by_hop = {
            "keep-alive",
            "proxy-authenticate",
            "proxy-authorization",
            "te",
            "trailers",
            "transfer-encoding",
        }

        connection_header = request.headers.get("Connection", "").lower()
        upgrade_header = request.headers.get("Upgrade", "").lower()
        is_websocket_upgrade = "upgrade" in connection_header and upgrade_header == "websocket"

        if is_websocket_upgrade:
            return await self._handle_websocket_proxy(request, tunnel)

        for key, value in request.headers.items():
            key_lower = key.lower()
            if key_lower in hop_by_hop:
                continue
            if key_lower in ("connection", "upgrade"):
                if is_websocket_upgrade:
                    headers[key] = value
                continue
            headers[key] = value

        headers["X-Forwarded-For"] = request.remote or ""
        headers["X-Forwarded-Proto"] = "https" if self._ssl_context else "http"
        headers["X-Forwarded-Host"] = host

        future: asyncio.Future[HttpResponse] = asyncio.Future()
        ctx = RequestContext(
            request_id=request_id,
            tunnel=tunnel,
            future=future,
            http_request=request,
            is_grpc=is_grpc_request,
            sse_complete=asyncio.Event(),
        )
        self._pending_requests[request_id] = ctx

        try:
            body = await request.read()

            if is_grpc_request:
                BYTES_TRANSFERRED.labels(direction="in", protocol="grpc").inc(len(body))
            else:
                BYTES_TRANSFERRED.labels(direction="in", protocol="http").inc(len(body))

            http_request = HttpRequest(
                request_id=request_id,
                method=request.method,
                path=request.path_qs,
                headers=headers,
                body=body,
            )
            msg_bytes = encode_message(http_request, tunnel.compression)
            await tunnel.websocket.send_bytes(msg_bytes)
            tunnel.bytes_sent += len(msg_bytes)

            tunnel.request_count += 1
            tunnel.last_activity = datetime.now(UTC)

            timeout = self.config.request_timeout

            async def wait_for_response():
                """Wait for either regular response or SSE completion."""
                future_awaitable = asyncio.ensure_future(future)
                sse_task = asyncio.create_task(ctx.sse_complete.wait())

                done, pending = await asyncio.wait(
                    [future_awaitable, sse_task],
                    return_when=asyncio.FIRST_COMPLETED,
                )

                for task in pending:
                    task.cancel()
                    with contextlib.suppress(asyncio.CancelledError):
                        await task

                if ctx.is_sse_stream and ctx.stream_response:
                    return None

                if future_awaitable in done:
                    return future_awaitable.result()
                return None

            if timeout is None or timeout <= 0:
                response = await wait_for_response()
            else:
                response = await asyncio.wait_for(wait_for_response(), timeout=timeout)

            if response is None and ctx.is_sse_stream and ctx.stream_response:
                return ctx.stream_response

            if response is None:
                return web.Response(
                    text="No response received",
                    status=502,
                    content_type="text/plain",
                )

            is_websocket_response = response.status == 101
            response_headers = {}

            headers_dict = response.headers if response.headers else {}
            for key, value in headers_dict.items():
                if isinstance(key, bytes):
                    key = key.decode("utf-8", errors="replace")
                elif not isinstance(key, str):
                    key = str(key)

                key_lower = key.lower()
                if key_lower in hop_by_hop:
                    continue
                if key_lower == "content-length":
                    continue
                if key_lower in ("connection", "upgrade"):
                    if is_websocket_response:
                        if isinstance(value, bytes):
                            response_headers[key] = value.decode("utf-8", errors="replace")
                        else:
                            response_headers[key] = str(value) if value is not None else ""
                    continue
                if isinstance(value, bytes):
                    response_headers[key] = value.decode("utf-8", errors="replace")
                elif value is None:
                    response_headers[key] = ""
                elif not isinstance(value, str):
                    response_headers[key] = str(value)
                else:
                    response_headers[key] = value

            if not is_websocket_response:
                response_headers["Connection"] = "keep-alive"

            body = response.body if response.body is not None else b""
            body_size = len(body)

            stream_threshold = get_config().performance.stream_threshold
            if body_size > stream_threshold:
                stream_response = web.StreamResponse(
                    status=response.status,
                    headers=response_headers,
                )
                stream_response.enable_chunked_encoding()
                await stream_response.prepare(request)

                chunk_size = 65536
                body_view = memoryview(body)
                for i in range(0, body_size, chunk_size):
                    await stream_response.write(body_view[i : i + chunk_size])

                await stream_response.write_eof()
                duration_ms = int((time.time() - request_start) * 1000)
                REQUEST_DURATION.observe(time.time() - request_start)
                HTTP_REQUESTS.labels(
                    method=request.method, status=_bucket_status(response.status)
                ).inc()
                if is_grpc_request:
                    GRPC_REQUESTS.labels(
                        method=request.path, status=_bucket_status(response.status)
                    ).inc()
                    BYTES_TRANSFERRED.labels(direction="out", protocol="grpc").inc(body_size)
                    logger.info(
                        f"gRPC {request.method} {request.path_qs} {response.status} {duration_ms}ms {body_size}B"
                    )
                else:
                    BYTES_TRANSFERRED.labels(direction="out", protocol="http").inc(body_size)
                    logger.info(
                        f"HTTP {request.method} {request.path_qs} {response.status} {duration_ms}ms {body_size}B"
                    )
                return stream_response
            else:
                duration_ms = int((time.time() - request_start) * 1000)
                REQUEST_DURATION.observe(time.time() - request_start)
                HTTP_REQUESTS.labels(
                    method=request.method, status=_bucket_status(response.status)
                ).inc()
                if is_grpc_request:
                    GRPC_REQUESTS.labels(
                        method=request.path, status=_bucket_status(response.status)
                    ).inc()
                    BYTES_TRANSFERRED.labels(direction="out", protocol="grpc").inc(len(body))
                    logger.info(
                        f"gRPC {request.method} {request.path_qs} {response.status} {duration_ms}ms {len(body)}B"
                    )
                else:
                    BYTES_TRANSFERRED.labels(direction="out", protocol="http").inc(len(body))
                    logger.info(
                        f"HTTP {request.method} {request.path_qs} {response.status} {duration_ms}ms {len(body)}B"
                    )
                return web.Response(
                    status=response.status,
                    headers=response_headers,
                    body=body,
                )

        except TimeoutError:
            logger.warning(
                "Request timeout",
                subdomain=subdomain,
                request_id=str(request_id),
            )
            REQUEST_DURATION.observe(time.time() - request_start)
            HTTP_REQUESTS.labels(method=request.method, status="5xx").inc()
            if is_grpc_request:
                GRPC_REQUESTS.labels(method=request.path, status="5xx").inc()
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
            REQUEST_DURATION.observe(time.time() - request_start)
            HTTP_REQUESTS.labels(method=request.method, status="5xx").inc()
            if is_grpc_request:
                GRPC_REQUESTS.labels(method=request.path, status="5xx").inc()
            return web.Response(
                text="Bad Gateway",
                status=502,
                content_type="text/plain",
            )
        except Exception as e:
            import traceback

            logger.error(
                "Request error",
                subdomain=subdomain,
                request_id=str(request_id),
                error=str(e),
                error_type=type(e).__name__,
                traceback=traceback.format_exc(),
            )
            REQUEST_DURATION.observe(time.time() - request_start)
            HTTP_REQUESTS.labels(method=request.method, status="5xx").inc()
            if is_grpc_request:
                GRPC_REQUESTS.labels(method=request.path, status="5xx").inc()
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

        if not host.endswith(base_domain):
            return None

        if host == base_domain:
            return None

        suffix = f".{base_domain}"
        if host.endswith(suffix):
            subdomain = host[: -len(suffix)]
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
        base_domain = self.config.base_domain.lower()
        if host == base_domain or host.endswith(f".{base_domain}"):
            return None

        tunnel_id = await self._domain_manager.get_tunnel_for_domain(host)
        if tunnel_id:
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
        if self._next_tcp_port > self._tcp_port_max:
            self._next_tcp_port = self._tcp_port_min
        return port

    def _allocate_udp_port(self) -> int:
        """Allocate a port for UDP tunnel."""
        port = self._next_udp_port
        self._next_udp_port += 1
        if self._next_udp_port > self._udp_port_max:
            self._next_udp_port = self._udp_port_min
        return port

    async def _handle_tcp_tunnel_connection(
        self, request: web.Request
    ) -> web.WebSocketResponse | web.Response:
        """Handle incoming TCP tunnel client connection."""
        import struct

        client_ip = request.remote or "unknown"

        # Check auth before preparing WebSocket
        if self._basic_auth:
            auth_header = request.headers.get(PROXY_AUTH_HEADER)
            auth_result = self._basic_auth.check(auth_header)
            if not auth_result.allowed:
                return web.Response(
                    text="Proxy Authentication Required",
                    status=407,
                    headers={PROXY_AUTH_CHALLENGE: 'Basic realm="Instanton TCP Tunnel"'},
                )

        # Check IP restrictions
        if self._ip_restrictor:
            ip_result = self._ip_restrictor.check(client_ip)
            if not ip_result.allowed:
                logger.warning("TCP tunnel blocked by IP restriction", ip=client_ip)
                return web.Response(text="Forbidden", status=403)

        # Check tunnel creation rate limit
        rate_result = await self._tunnel_creation_limiter.allow(client_ip, scope="ip")
        if not rate_result.allowed:
            logger.warning("TCP tunnel creation rate limit exceeded", ip=client_ip)
            return web.Response(
                text="Too Many Requests",
                status=429,
                headers={"Retry-After": str(int(rate_result.reset_after) + 1)},
            )

        # Check per-IP tunnel limit
        current_ip_tunnels = len(self._tunnels_by_ip.get(client_ip, set()))
        if current_ip_tunnels >= self._max_tunnels_per_ip:
            logger.warning(
                "Per-IP tunnel limit exceeded for TCP", ip=client_ip, current=current_ip_tunnels
            )
            return web.Response(
                text=f"Too Many Tunnels - max {self._max_tunnels_per_ip} per IP", status=429
            )

        config = get_config()
        ws = web.WebSocketResponse(heartbeat=config.timeouts.ping_interval)
        await ws.prepare(request)
        self._websockets.add(ws)

        logger.info("New TCP tunnel client connected", peer=request.remote)

        tunnel_id = uuid4()
        assigned_port: int | None = None

        try:
            msg = await ws.receive()
            if msg.type != WSMsgType.BINARY:
                await ws.close()
                return ws

            data = msg.data
            if len(data) < 21 or data[0] != 0x01:
                await ws.close()
                return ws

            local_port = struct.unpack(">H", data[17:19])[0]
            requested_port = struct.unpack(">H", data[19:21])[0]

            if requested_port and requested_port not in self._tcp_tunnels:
                assigned_port = requested_port
            else:
                assigned_port = self._allocate_tcp_port()
                while assigned_port in self._tcp_tunnels:
                    assigned_port = self._allocate_tcp_port()

            subdomain = f"tcp-{assigned_port}"
            tunnel = TunnelConnection(
                id=tunnel_id,
                subdomain=subdomain,
                websocket=ws,
                local_port=local_port,
                source_ip=client_ip,
            )
            self._tcp_tunnels[assigned_port] = tunnel
            self._tunnel_by_id[tunnel_id] = tunnel

            # Track tunnel by IP
            if client_ip not in self._tunnels_by_ip:
                self._tunnels_by_ip[client_ip] = set()
            self._tunnels_by_ip[client_ip].add(subdomain)

            response = bytearray()
            response.append(0x02)
            response.extend(tunnel_id.bytes)
            response.extend(struct.pack(">H", assigned_port))
            response.append(0)
            await ws.send_bytes(bytes(response))

            TUNNEL_CONNECTIONS.labels(type="tcp").inc()

            logger.info(
                "TCP tunnel established",
                tunnel_id=str(tunnel_id),
                assigned_port=assigned_port,
                local_port=local_port,
                source_ip=client_ip,
            )

            async for msg in ws:
                if msg.type == WSMsgType.BINARY:
                    tunnel.last_activity = datetime.now(UTC)
                    data_len = len(msg.data)
                    tunnel.bytes_received += data_len
                    BYTES_TRANSFERRED.labels(direction="in", protocol="tcp").inc(data_len)
                    TUNNEL_PACKETS.labels(protocol="tcp", direction="in").inc()
                    logger.info(f"TCP DATA {data_len}B port={assigned_port}")
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
            tcp_tunnel = self._tcp_tunnels.get(assigned_port) if assigned_port else None
            if assigned_port and assigned_port in self._tcp_tunnels:
                del self._tcp_tunnels[assigned_port]
            if tunnel_id in self._tunnel_by_id:
                del self._tunnel_by_id[tunnel_id]
            # Remove from per-IP tracking
            if tcp_tunnel and tcp_tunnel.source_ip:
                ip_tunnels = self._tunnels_by_ip.get(tcp_tunnel.source_ip)
                if ip_tunnels:
                    ip_tunnels.discard(tcp_tunnel.subdomain)
                    if not ip_tunnels:
                        del self._tunnels_by_ip[tcp_tunnel.source_ip]
            logger.info("TCP tunnel closed", port=assigned_port)

        return ws

    async def _handle_udp_tunnel_connection(
        self, request: web.Request
    ) -> web.WebSocketResponse | web.Response:
        """Handle incoming UDP tunnel client connection."""
        import struct

        client_ip = request.remote or "unknown"

        # Check auth before preparing WebSocket
        if self._basic_auth:
            auth_header = request.headers.get(PROXY_AUTH_HEADER)
            auth_result = self._basic_auth.check(auth_header)
            if not auth_result.allowed:
                return web.Response(
                    text="Proxy Authentication Required",
                    status=407,
                    headers={PROXY_AUTH_CHALLENGE: 'Basic realm="Instanton UDP Tunnel"'},
                )

        # Check IP restrictions
        if self._ip_restrictor:
            ip_result = self._ip_restrictor.check(client_ip)
            if not ip_result.allowed:
                logger.warning("UDP tunnel blocked by IP restriction", ip=client_ip)
                return web.Response(text="Forbidden", status=403)

        # Check tunnel creation rate limit
        rate_result = await self._tunnel_creation_limiter.allow(client_ip, scope="ip")
        if not rate_result.allowed:
            logger.warning("UDP tunnel creation rate limit exceeded", ip=client_ip)
            return web.Response(
                text="Too Many Requests",
                status=429,
                headers={"Retry-After": str(int(rate_result.reset_after) + 1)},
            )

        # Check per-IP tunnel limit
        current_ip_tunnels = len(self._tunnels_by_ip.get(client_ip, set()))
        if current_ip_tunnels >= self._max_tunnels_per_ip:
            logger.warning(
                "Per-IP tunnel limit exceeded for UDP", ip=client_ip, current=current_ip_tunnels
            )
            return web.Response(
                text=f"Too Many Tunnels - max {self._max_tunnels_per_ip} per IP", status=429
            )

        config = get_config()
        ws = web.WebSocketResponse(heartbeat=config.timeouts.ping_interval)
        await ws.prepare(request)
        self._websockets.add(ws)

        logger.info("New UDP tunnel client connected", peer=request.remote)

        tunnel_id = uuid4()
        assigned_port: int | None = None

        try:
            msg = await ws.receive()
            if msg.type != WSMsgType.BINARY:
                await ws.close()
                return ws

            data = msg.data
            if len(data) < 21 or data[0] != 0x01:
                await ws.close()
                return ws

            local_port = struct.unpack(">H", data[17:19])[0]
            requested_port = struct.unpack(">H", data[19:21])[0]

            if requested_port and requested_port not in self._udp_tunnels:
                assigned_port = requested_port
            else:
                assigned_port = self._allocate_udp_port()
                while assigned_port in self._udp_tunnels:
                    assigned_port = self._allocate_udp_port()

            subdomain = f"udp-{assigned_port}"
            tunnel = TunnelConnection(
                id=tunnel_id,
                subdomain=subdomain,
                websocket=ws,
                local_port=local_port,
                source_ip=client_ip,
            )
            self._udp_tunnels[assigned_port] = tunnel
            self._tunnel_by_id[tunnel_id] = tunnel

            # Track tunnel by IP
            if client_ip not in self._tunnels_by_ip:
                self._tunnels_by_ip[client_ip] = set()
            self._tunnels_by_ip[client_ip].add(subdomain)

            response = bytearray()
            response.append(0x02)
            response.extend(tunnel_id.bytes)
            response.extend(struct.pack(">H", assigned_port))
            response.append(0)
            await ws.send_bytes(bytes(response))

            TUNNEL_CONNECTIONS.labels(type="udp").inc()

            logger.info(
                "UDP tunnel established",
                tunnel_id=str(tunnel_id),
                assigned_port=assigned_port,
                local_port=local_port,
                source_ip=client_ip,
            )

            async for msg in ws:
                if msg.type == WSMsgType.BINARY:
                    tunnel.last_activity = datetime.now(UTC)
                    data_len = len(msg.data)
                    tunnel.bytes_received += data_len
                    BYTES_TRANSFERRED.labels(direction="in", protocol="udp").inc(data_len)
                    TUNNEL_PACKETS.labels(protocol="udp", direction="in").inc()
                    logger.info(f"UDP DATA {data_len}B port={assigned_port}")
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
            udp_tunnel = self._udp_tunnels.get(assigned_port) if assigned_port else None
            if assigned_port and assigned_port in self._udp_tunnels:
                del self._udp_tunnels[assigned_port]
            if tunnel_id in self._tunnel_by_id:
                del self._tunnel_by_id[tunnel_id]
            # Remove from per-IP tracking
            if udp_tunnel and udp_tunnel.source_ip:
                ip_tunnels = self._tunnels_by_ip.get(udp_tunnel.source_ip)
                if ip_tunnels:
                    ip_tunnels.discard(udp_tunnel.subdomain)
                    if not ip_tunnels:
                        del self._tunnels_by_ip[udp_tunnel.source_ip]
            logger.info("UDP tunnel closed", port=assigned_port)

        return ws
