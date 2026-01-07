"""Tests for relay server."""

import asyncio
from typing import Any
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest

from instanton.core.config import ServerConfig
from instanton.protocol.messages import (
    CompressionType,
    ConnectRequest,
    ConnectResponse,
    ErrorCode,
    HttpRequest,
    HttpResponse,
    NegotiateRequest,
    NegotiateResponse,
    Ping,
    Pong,
    decode_message,
    encode_message,
)
from instanton.server.relay import RelayServer, RequestContext, TunnelConnection


@pytest.fixture
def server_config():
    """Create a test server configuration."""
    return ServerConfig(
        base_domain="test.local",
        https_bind="127.0.0.1:8443",
        control_bind="127.0.0.1:4443",
        max_tunnels=100,
        idle_timeout=300.0,
    )


@pytest.fixture
def relay_server(server_config):
    """Create a relay server instance."""
    return RelayServer(server_config)


class TestRelayServerInit:
    """Test RelayServer initialization."""

    def test_init_default_values(self, relay_server, server_config):
        """Test server initializes with correct default values."""
        assert relay_server.config == server_config
        assert relay_server._tunnels == {}
        assert relay_server._tunnel_by_id == {}
        assert relay_server._pending_requests == {}
        assert relay_server._control_app is None
        assert relay_server._http_app is None
        assert relay_server._ssl_context is None

    def test_parse_bind_with_port(self, relay_server):
        """Test parsing bind address with port."""
        host, port = relay_server._parse_bind("0.0.0.0:8080")
        assert host == "0.0.0.0"
        assert port == 8080

    def test_parse_bind_ipv6(self, relay_server):
        """Test parsing IPv6 bind address."""
        # IPv6 addresses have colons, so rsplit with maxsplit=1 should work
        host, port = relay_server._parse_bind("::1:8080")
        assert host == "::1"
        assert port == 8080

    def test_parse_bind_only_port(self, relay_server):
        """Test parsing bind address with only port."""
        host, port = relay_server._parse_bind("8080")
        assert host == "0.0.0.0"
        assert port == 8080


class TestSubdomainValidation:
    """Test subdomain validation."""

    def test_valid_subdomain(self, relay_server):
        """Test valid subdomain formats."""
        assert relay_server._is_valid_subdomain("abc") is True
        assert relay_server._is_valid_subdomain("test123") is True
        assert relay_server._is_valid_subdomain("my-app") is True
        assert relay_server._is_valid_subdomain("my-test-app") is True
        assert relay_server._is_valid_subdomain("a" * 63) is True

    def test_invalid_subdomain_empty(self, relay_server):
        """Test empty subdomain is invalid."""
        assert relay_server._is_valid_subdomain("") is False
        assert relay_server._is_valid_subdomain(None) is False

    def test_invalid_subdomain_too_short(self, relay_server):
        """Test subdomain that's too short."""
        assert relay_server._is_valid_subdomain("ab") is False
        assert relay_server._is_valid_subdomain("a") is False

    def test_invalid_subdomain_too_long(self, relay_server):
        """Test subdomain that's too long."""
        assert relay_server._is_valid_subdomain("a" * 64) is False

    def test_invalid_subdomain_starts_with_hyphen(self, relay_server):
        """Test subdomain starting with hyphen."""
        assert relay_server._is_valid_subdomain("-test") is False

    def test_invalid_subdomain_ends_with_hyphen(self, relay_server):
        """Test subdomain ending with hyphen."""
        assert relay_server._is_valid_subdomain("test-") is False

    def test_invalid_subdomain_special_chars(self, relay_server):
        """Test subdomain with special characters."""
        assert relay_server._is_valid_subdomain("test_app") is False
        assert relay_server._is_valid_subdomain("test.app") is False
        assert relay_server._is_valid_subdomain("test@app") is False
        assert relay_server._is_valid_subdomain("test app") is False


class TestSubdomainExtraction:
    """Test subdomain extraction from host header."""

    def test_extract_valid_subdomain(self, relay_server):
        """Test extracting valid subdomain."""
        assert relay_server._extract_subdomain("myapp.test.local") == "myapp"
        assert relay_server._extract_subdomain("abc123.test.local") == "abc123"

    def test_extract_subdomain_base_domain(self, relay_server):
        """Test extraction returns None for base domain."""
        assert relay_server._extract_subdomain("test.local") is None

    def test_extract_subdomain_wrong_domain(self, relay_server):
        """Test extraction returns None for wrong domain."""
        assert relay_server._extract_subdomain("myapp.other.local") is None
        assert relay_server._extract_subdomain("google.com") is None

    def test_extract_subdomain_nested(self, relay_server):
        """Test extraction rejects nested subdomains."""
        assert relay_server._extract_subdomain("sub.myapp.test.local") is None

    def test_extract_subdomain_case_insensitive(self, relay_server):
        """Test extraction is case-insensitive."""
        assert relay_server._extract_subdomain("MyApp.Test.Local") == "myapp"
        assert relay_server._extract_subdomain("MYAPP.TEST.LOCAL") == "myapp"


class TestTunnelManagement:
    """Test tunnel management."""

    def test_get_tunnel_count_empty(self, relay_server):
        """Test tunnel count when empty."""
        assert relay_server.get_tunnel_count() == 0

    def test_get_tunnel_count_with_tunnels(self, relay_server):
        """Test tunnel count with tunnels."""
        mock_ws = MagicMock()
        tunnel = TunnelConnection(
            id=uuid4(),
            subdomain="test",
            websocket=mock_ws,
            local_port=8080,
        )
        relay_server._tunnels["test"] = tunnel
        assert relay_server.get_tunnel_count() == 1

    def test_get_tunnel_by_subdomain(self, relay_server):
        """Test getting tunnel by subdomain."""
        mock_ws = MagicMock()
        tunnel_id = uuid4()
        tunnel = TunnelConnection(
            id=tunnel_id,
            subdomain="myapp",
            websocket=mock_ws,
            local_port=8080,
        )
        relay_server._tunnels["myapp"] = tunnel
        relay_server._tunnel_by_id[tunnel_id] = tunnel

        result = relay_server.get_tunnel("myapp")
        assert result is tunnel
        assert result.id == tunnel_id

    def test_get_tunnel_by_subdomain_not_found(self, relay_server):
        """Test getting non-existent tunnel by subdomain."""
        assert relay_server.get_tunnel("nonexistent") is None

    def test_get_tunnel_by_id(self, relay_server):
        """Test getting tunnel by ID."""
        mock_ws = MagicMock()
        tunnel_id = uuid4()
        tunnel = TunnelConnection(
            id=tunnel_id,
            subdomain="myapp",
            websocket=mock_ws,
            local_port=8080,
        )
        relay_server._tunnels["myapp"] = tunnel
        relay_server._tunnel_by_id[tunnel_id] = tunnel

        result = relay_server.get_tunnel_by_id(tunnel_id)
        assert result is tunnel

    def test_get_tunnel_by_id_not_found(self, relay_server):
        """Test getting non-existent tunnel by ID."""
        assert relay_server.get_tunnel_by_id(uuid4()) is None


class TestTunnelConnection:
    """Test TunnelConnection dataclass."""

    def test_tunnel_connection_defaults(self):
        """Test TunnelConnection has correct defaults."""
        mock_ws = MagicMock()
        tunnel = TunnelConnection(
            id=uuid4(),
            subdomain="test",
            websocket=mock_ws,
            local_port=8080,
        )
        assert tunnel.request_count == 0
        assert tunnel.bytes_sent == 0
        assert tunnel.bytes_received == 0
        assert tunnel.compression == CompressionType.NONE
        assert tunnel.negotiator is None

    def test_tunnel_connection_with_compression(self):
        """Test TunnelConnection with compression."""
        mock_ws = MagicMock()
        tunnel = TunnelConnection(
            id=uuid4(),
            subdomain="test",
            websocket=mock_ws,
            local_port=8080,
            compression=CompressionType.ZSTD,
        )
        assert tunnel.compression == CompressionType.ZSTD


class TestRequestContext:
    """Test RequestContext dataclass."""

    @pytest.mark.asyncio
    async def test_request_context_creation(self):
        """Test RequestContext creation."""
        mock_ws = MagicMock()
        tunnel = TunnelConnection(
            id=uuid4(),
            subdomain="test",
            websocket=mock_ws,
            local_port=8080,
        )
        future: asyncio.Future[Any] = asyncio.Future()
        request_id = uuid4()

        ctx = RequestContext(
            request_id=request_id,
            tunnel=tunnel,
            future=future,
        )

        assert ctx.request_id == request_id
        assert ctx.tunnel is tunnel
        assert ctx.future is future
        assert ctx.created_at > 0


class TestProtocolNegotiation:
    """Test protocol negotiation flow."""

    def test_negotiate_request_encoding(self):
        """Test NegotiateRequest encoding/decoding."""
        req = NegotiateRequest()
        encoded = encode_message(req)
        decoded = decode_message(encoded)

        assert decoded["type"] == "negotiate"
        assert decoded["supports_streaming"] is True

    def test_negotiate_response_encoding(self):
        """Test NegotiateResponse encoding/decoding."""
        resp = NegotiateResponse(
            selected_compression=CompressionType.ZSTD,
            streaming_enabled=True,
        )
        encoded = encode_message(resp)
        decoded = decode_message(encoded)

        assert decoded["type"] == "negotiate_response"
        assert decoded["success"] is True


class TestServerStartStop:
    """Test server start/stop lifecycle."""

    @pytest.mark.asyncio
    async def test_server_start_stop(self, server_config):
        """Test server can start and stop."""
        server = RelayServer(server_config)

        # Start server
        await server.start()

        assert server._control_app is not None
        assert server._http_app is not None
        assert server._control_runner is not None
        assert server._http_runner is not None
        assert server._cleanup_task is not None

        # Stop server
        await server.stop()

        assert server._tunnels == {}
        assert server._tunnel_by_id == {}

    @pytest.mark.asyncio
    async def test_server_stop_clears_tunnels(self, server_config):
        """Test stopping server clears all tunnels."""
        server = RelayServer(server_config)
        await server.start()

        # Add a mock tunnel
        mock_ws = AsyncMock()
        mock_ws.closed = False
        tunnel = TunnelConnection(
            id=uuid4(),
            subdomain="test",
            websocket=mock_ws,
            local_port=8080,
        )
        server._tunnels["test"] = tunnel
        server._tunnel_by_id[tunnel.id] = tunnel

        await server.stop()

        assert len(server._tunnels) == 0
        assert len(server._tunnel_by_id) == 0


class TestSSLContext:
    """Test SSL context creation."""

    def test_no_ssl_without_certs(self, server_config):
        """Test SSL context is None without certificates."""
        server = RelayServer(server_config)
        ctx = server._create_ssl_context()
        assert ctx is None

    def test_ssl_with_nonexistent_cert(self, server_config):
        """Test SSL context is None with nonexistent cert."""
        server_config.cert_path = "/nonexistent/cert.pem"
        server_config.key_path = "/nonexistent/key.pem"
        server = RelayServer(server_config)
        ctx = server._create_ssl_context()
        assert ctx is None


class TestHealthEndpoint:
    """Test health check endpoint."""

    @pytest.mark.asyncio
    async def test_health_check_response(self, relay_server):
        """Test health check returns correct response."""
        # Create a mock request
        mock_request = MagicMock()

        response = await relay_server._handle_health_check(mock_request)

        assert response.status == 200
        assert response.content_type == "application/json"


class TestStatsEndpoint:
    """Test stats endpoint."""

    @pytest.mark.asyncio
    async def test_stats_empty(self, relay_server):
        """Test stats with no tunnels."""
        mock_request = MagicMock()

        response = await relay_server._handle_stats(mock_request)

        assert response.status == 200
        assert response.content_type == "application/json"

    @pytest.mark.asyncio
    async def test_stats_with_tunnels(self, relay_server):
        """Test stats with tunnels."""
        mock_ws = MagicMock()
        tunnel = TunnelConnection(
            id=uuid4(),
            subdomain="test",
            websocket=mock_ws,
            local_port=8080,
            request_count=5,
            bytes_sent=1000,
            bytes_received=500,
        )
        relay_server._tunnels["test"] = tunnel

        mock_request = MagicMock()
        response = await relay_server._handle_stats(mock_request)

        assert response.status == 200


class TestHttpRequestRouting:
    """Test HTTP request routing."""

    @pytest.mark.asyncio
    async def test_base_domain_returns_landing(self, relay_server):
        """Test base domain returns landing page."""
        mock_request = MagicMock()
        mock_request.host = "test.local"

        response = await relay_server._handle_http_request(mock_request)

        assert response.status == 200
        assert "Instanton" in response.text

    @pytest.mark.asyncio
    async def test_unknown_subdomain_returns_404(self, relay_server):
        """Test unknown subdomain returns 404."""
        mock_request = MagicMock()
        mock_request.host = "unknown.test.local"

        response = await relay_server._handle_http_request(mock_request)

        assert response.status == 404

    @pytest.mark.asyncio
    async def test_disconnected_tunnel_returns_502(self, relay_server):
        """Test disconnected tunnel returns 502."""
        mock_ws = MagicMock()
        mock_ws.closed = True
        tunnel = TunnelConnection(
            id=uuid4(),
            subdomain="closed",
            websocket=mock_ws,
            local_port=8080,
        )
        relay_server._tunnels["closed"] = tunnel
        relay_server._tunnel_by_id[tunnel.id] = tunnel

        mock_request = MagicMock()
        mock_request.host = "closed.test.local"

        response = await relay_server._handle_http_request(mock_request)

        assert response.status == 502
        # Tunnel should be cleaned up
        assert "closed" not in relay_server._tunnels


class TestConnectRequest:
    """Test connect request message handling."""

    def test_connect_request_with_subdomain(self):
        """Test ConnectRequest with specified subdomain."""
        req = ConnectRequest(subdomain="myapp", local_port=3000)
        encoded = encode_message(req)
        decoded = decode_message(encoded)

        assert decoded["type"] == "connect"
        assert decoded["subdomain"] == "myapp"
        assert decoded["local_port"] == 3000

    def test_connect_request_without_subdomain(self):
        """Test ConnectRequest without subdomain."""
        req = ConnectRequest(local_port=8080)
        encoded = encode_message(req)
        decoded = decode_message(encoded)

        assert decoded["type"] == "connect"
        assert decoded["subdomain"] is None
        assert decoded["local_port"] == 8080


class TestConnectResponse:
    """Test connect response message handling."""

    def test_connect_response_success(self):
        """Test successful ConnectResponse."""
        tunnel_id = uuid4()
        resp = ConnectResponse(
            type="connected",
            tunnel_id=tunnel_id,
            subdomain="myapp",
            url="https://myapp.test.local",
        )
        encoded = encode_message(resp)
        decoded = decode_message(encoded)

        assert decoded["type"] == "connected"
        assert decoded["subdomain"] == "myapp"
        assert "https://" in decoded["url"]

    def test_connect_response_error(self):
        """Test error ConnectResponse."""
        resp = ConnectResponse(
            type="error",
            error="Subdomain already in use",
            error_code=ErrorCode.SUBDOMAIN_TAKEN,
        )
        encoded = encode_message(resp)
        decoded = decode_message(encoded)

        assert decoded["type"] == "error"
        assert decoded["error_code"] == ErrorCode.SUBDOMAIN_TAKEN


class TestPingPong:
    """Test ping/pong handling."""

    def test_ping_encoding(self):
        """Test Ping message encoding."""
        ping = Ping(timestamp=1234567890)
        encoded = encode_message(ping)
        decoded = decode_message(encoded)

        assert decoded["type"] == "ping"
        assert decoded["timestamp"] == 1234567890

    def test_pong_encoding(self):
        """Test Pong message encoding."""
        pong = Pong(timestamp=1234567890, server_time=1234567891)
        encoded = encode_message(pong)
        decoded = decode_message(encoded)

        assert decoded["type"] == "pong"
        assert decoded["timestamp"] == 1234567890
        assert decoded["server_time"] == 1234567891


class TestHttpRequestMessage:
    """Test HTTP request message handling."""

    def test_http_request_encoding(self):
        """Test HttpRequest encoding."""
        req = HttpRequest(
            method="POST",
            path="/api/data",
            headers={"Content-Type": "application/json"},
            body=b'{"key": "value"}',
        )
        encoded = encode_message(req)
        decoded = decode_message(encoded)

        assert decoded["type"] == "http_request"
        assert decoded["method"] == "POST"
        assert decoded["path"] == "/api/data"
        assert decoded["headers"]["Content-Type"] == "application/json"


class TestHttpResponseMessage:
    """Test HTTP response message handling."""

    def test_http_response_encoding(self):
        """Test HttpResponse encoding."""
        request_id = uuid4()
        resp = HttpResponse(
            request_id=request_id,
            status=200,
            headers={"Content-Type": "text/plain"},
            body=b"Hello World",
        )
        encoded = encode_message(resp)
        decoded = decode_message(encoded)

        assert decoded["type"] == "http_response"
        assert decoded["status"] == 200
