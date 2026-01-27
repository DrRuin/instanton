"""HTTP3."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import TYPE_CHECKING, Any
from uuid import uuid4

import structlog
from aioquic.asyncio import QuicConnectionProtocol
from aioquic.asyncio import serve as quic_serve
from aioquic.asyncio.server import QuicServer as AIQuicServer
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import DataReceived, H3Event, HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import (
    ConnectionTerminated,
    HandshakeCompleted,
    QuicEvent,
    StreamDataReceived,
)

if TYPE_CHECKING:
    from instanton.core.config import ServerConfig
    from instanton.server.relay import RelayServer

logger = structlog.get_logger()


class HTTP3RequestHandler:
    def __init__(self, relay: RelayServer, protocol: HTTP3ServerProtocol, stream_id: int) -> None:
        self._relay = relay
        self._protocol = protocol
        self._stream_id = stream_id
        self._request_id = uuid4()
        self._headers: dict[str, str] = {}
        self._body_chunks: list[bytes] = []
        self._method: str = ""
        self._path: str = ""
        self._authority: str = ""
        self._scheme: str = "https"

    def handle_headers(self, headers: list[tuple[bytes, bytes]]) -> None:
        for name, value in headers:
            name_str = name.decode("utf-8", errors="replace")
            value_str = value.decode("utf-8", errors="replace")

            if name_str == ":method":
                self._method = value_str
            elif name_str == ":path":
                self._path = value_str
            elif name_str == ":authority":
                self._authority = value_str
            elif name_str == ":scheme":
                self._scheme = value_str
            elif not name_str.startswith(":"):
                self._headers[name_str] = value_str

        if "host" not in {k.lower() for k in self._headers} and self._authority:
            self._headers["Host"] = self._authority

    def handle_data(self, data: bytes) -> None:
        self._body_chunks.append(data)

    async def handle_end_stream(self) -> None:
        body = b"".join(self._body_chunks)
        host = self._authority or self._headers.get("Host", "")
        subdomain = await self._extract_subdomain(host)

        if not subdomain:
            await self._send_error_response(400, "Missing subdomain")
            return

        tunnel = self._relay._tunnels.get(subdomain)
        if not tunnel:
            await self._send_error_response(404, f"Tunnel not found: {subdomain}")
            return

        try:
            await self._forward_to_tunnel(tunnel, body)
        except Exception as e:
            await self._send_error_response(502, str(e))

    async def _extract_subdomain(self, host: str) -> str | None:
        if not host:
            return None

        if ":" in host:
            host = host.split(":")[0]

        base_domain = self._relay.config.base_domain
        if host.endswith(f".{base_domain}"):
            return host[: -(len(base_domain) + 1)]

        tunnel_id = await self._relay._domain_manager.get_tunnel_for_domain(host)
        if tunnel_id:
            return tunnel_id
        return None

    async def _forward_to_tunnel(self, tunnel: Any, body: bytes) -> None:
        from instanton.protocol.messages import HttpRequest, encode_message
        from instanton.server.relay import RequestContext

        request = HttpRequest(
            request_id=self._request_id,
            method=self._method,
            path=self._path,
            headers=self._headers,
            body=body,
        )

        response_future: asyncio.Future[dict[str, Any]] = asyncio.get_event_loop().create_future()
        request_context = RequestContext(
            request_id=self._request_id,
            tunnel=tunnel,
            future=response_future,
        )
        self._relay._pending_requests[self._request_id] = request_context

        try:
            encoded = encode_message(request)
            await tunnel.websocket.send_bytes(encoded)

            timeout = self._relay.config.request_timeout or 600.0
            response_data = await asyncio.wait_for(response_future, timeout=timeout)

            await self._send_response(
                status=response_data.get("status", 200),
                headers=response_data.get("headers", {}),
                body=response_data.get("body", b""),
            )
        except TimeoutError:
            await self._send_error_response(504, "Gateway Timeout")
        finally:
            self._relay._pending_requests.pop(self._request_id, None)

    async def _send_response(self, status: int, headers: dict[str, str], body: bytes) -> None:
        h3_headers = [(b":status", str(status).encode())]

        for name, value in headers.items():
            if name.lower() in ("connection", "keep-alive", "transfer-encoding"):
                continue
            h3_headers.append((name.encode(), value.encode()))

        h3_headers.append((b"alt-svc", b'h3=":443"; ma=86400'))

        self._protocol.send_headers(self._stream_id, h3_headers)
        self._protocol.send_data(self._stream_id, body if body else b"", end_stream=True)

    async def _send_error_response(self, status: int, message: str) -> None:
        body = f'{{"error": "{message}"}}'.encode()
        await self._send_response(
            status=status, headers={"Content-Type": "application/json"}, body=body
        )


class HTTP3ServerProtocol(QuicConnectionProtocol):
    def __init__(self, *args: Any, relay: RelayServer, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._relay = relay
        self._h3: H3Connection | None = None
        self._handlers: dict[int, HTTP3RequestHandler] = {}

    def quic_event_received(self, event: QuicEvent) -> None:
        if isinstance(event, HandshakeCompleted):
            self._h3 = H3Connection(self._quic, enable_webtransport=False)
        elif isinstance(event, StreamDataReceived):
            if self._h3:
                for h3_event in self._h3.handle_event(event):
                    self._h3_event_received(h3_event)
        elif isinstance(event, ConnectionTerminated):
            self._handlers.clear()

    def _h3_event_received(self, event: H3Event) -> None:
        if isinstance(event, HeadersReceived):
            handler = HTTP3RequestHandler(
                relay=self._relay, protocol=self, stream_id=event.stream_id
            )
            self._handlers[event.stream_id] = handler
            handler.handle_headers(event.headers)
            if event.stream_ended:
                asyncio.create_task(handler.handle_end_stream())
        elif isinstance(event, DataReceived):
            existing = self._handlers.get(event.stream_id)
            if existing:
                existing.handle_data(event.data)
                if event.stream_ended:
                    asyncio.create_task(existing.handle_end_stream())

    def send_headers(self, stream_id: int, headers: list[tuple[bytes, bytes]]) -> None:
        if self._h3:
            self._h3.send_headers(stream_id, headers)
            self.transmit()

    def send_data(self, stream_id: int, data: bytes, end_stream: bool = False) -> None:
        if self._h3:
            self._h3.send_data(stream_id, data, end_stream)
            self.transmit()
            if end_stream:
                self._handlers.pop(stream_id, None)


class HTTP3Server:
    def __init__(self, config: ServerConfig, relay: RelayServer) -> None:
        self._config = config
        self._relay = relay
        self._server: AIQuicServer | None = None
        self._running = False

    async def start(self) -> None:
        if not self._config.cert_path or not self._config.key_path:
            return

        cert_path = Path(self._config.cert_path)
        key_path = Path(self._config.key_path)

        if not cert_path.exists() or not key_path.exists():
            return

        bind = getattr(self._config, "http3_bind", "0.0.0.0:443")
        if ":" in bind:
            host, port_str = bind.rsplit(":", 1)
            port = int(port_str)
        else:
            host = "0.0.0.0"
            port = int(bind)

        idle_timeout = getattr(self._config, "http3_idle_timeout", 60.0)

        configuration = QuicConfiguration(
            is_client=False,
            alpn_protocols=H3_ALPN,
            idle_timeout=idle_timeout,
            max_datagram_frame_size=65536,
        )
        configuration.load_cert_chain(str(cert_path), str(key_path))

        relay = self._relay

        def create_protocol(*args: Any, **kwargs: Any) -> HTTP3ServerProtocol:
            return HTTP3ServerProtocol(*args, relay=relay, **kwargs)

        try:
            self._server = await quic_serve(
                host, port, configuration=configuration, create_protocol=create_protocol
            )
            self._running = True
        except Exception:
            self._server = None

    async def stop(self) -> None:
        self._running = False
        if self._server:
            self._server.close()
            self._server = None

    @property
    def is_running(self) -> bool:
        return self._running and self._server is not None

    def get_stats(self) -> dict[str, Any]:
        return {
            "running": self._running,
            "has_server": self._server is not None,
            "bind": getattr(self._config, "http3_bind", "0.0.0.0:443"),
        }
