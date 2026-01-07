"""Tests for the tunnel client."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import httpx
import pytest

from instanton.client.tunnel import (
    ConnectionState,
    ProxyConfig,
    ReconnectConfig,
    TunnelClient,
)
from instanton.core.config import ClientConfig
from instanton.protocol.messages import (
    ConnectResponse,
    Disconnect,
    HttpRequest,
    NegotiateResponse,
    Pong,
    encode_message,
)


class MockTransport:
    """Mock transport for testing."""

    def __init__(self) -> None:
        self._connected = False
        self._messages: list[bytes] = []
        self._recv_queue: asyncio.Queue[bytes | None] = asyncio.Queue()
        self._sent: list[bytes] = []

    async def connect(self, addr: str) -> None:
        self._connected = True

    async def send(self, data: bytes) -> None:
        self._sent.append(data)

    async def recv(self) -> bytes | None:
        return await self._recv_queue.get()

    async def close(self) -> None:
        self._connected = False

    def is_connected(self) -> bool:
        return self._connected

    def queue_message(self, msg: bytes) -> None:
        """Queue a message for recv()."""
        self._recv_queue.put_nowait(msg)

    def queue_disconnect(self) -> None:
        """Queue a disconnect (None)."""
        self._recv_queue.put_nowait(None)


@pytest.fixture
def mock_transport() -> MockTransport:
    """Create a mock transport."""
    return MockTransport()


@pytest.fixture
def client() -> TunnelClient:
    """Create a tunnel client with default settings."""
    return TunnelClient(
        local_port=8080,
        server_addr="test.instanton.dev",
        subdomain="test",
    )


@pytest.fixture
def client_no_reconnect() -> TunnelClient:
    """Create a tunnel client with reconnect disabled."""
    return TunnelClient(
        local_port=8080,
        server_addr="test.instanton.dev",
        reconnect_config=ReconnectConfig(enabled=False),
    )


class TestTunnelClientInit:
    """Test TunnelClient initialization."""

    def test_default_init(self) -> None:
        """Test default initialization."""
        client = TunnelClient(local_port=8080)
        assert client.local_port == 8080
        assert client.server_addr == "instanton.dev"
        assert client.subdomain is None
        assert not client.use_quic
        assert client.state == ConnectionState.DISCONNECTED

    def test_init_with_params(self) -> None:
        """Test initialization with custom parameters."""
        client = TunnelClient(
            local_port=3000,
            server_addr="custom.server.com",
            subdomain="myapp",
            use_quic=True,
        )
        assert client.local_port == 3000
        assert client.server_addr == "custom.server.com"
        assert client.subdomain == "myapp"
        assert client.use_quic

    def test_init_with_config(self) -> None:
        """Test initialization with ClientConfig."""
        config = ClientConfig(
            server_addr="config.server.com:443",
            local_port=9000,
            subdomain="configured",
            use_quic=True,
            keepalive_interval=60.0,
        )
        client = TunnelClient(
            local_port=1234,  # Should be overridden by config
            config=config,
        )
        assert client.local_port == 9000
        assert client.server_addr == "config.server.com:443"
        assert client.subdomain == "configured"
        assert client.use_quic
        assert client._keepalive_interval == 60.0

    def test_init_with_reconnect_config(self) -> None:
        """Test initialization with ReconnectConfig."""
        reconnect = ReconnectConfig(
            enabled=True,
            max_attempts=5,
            base_delay=2.0,
            max_delay=120.0,
            jitter=0.2,
        )
        client = TunnelClient(
            local_port=8080,
            reconnect_config=reconnect,
        )
        assert client.reconnect_config.max_attempts == 5
        assert client.reconnect_config.base_delay == 2.0

    def test_init_with_proxy_config(self) -> None:
        """Test initialization with ProxyConfig."""
        proxy = ProxyConfig(
            connect_timeout=10.0,
            read_timeout=60.0,
            retry_count=3,
        )
        client = TunnelClient(
            local_port=8080,
            proxy_config=proxy,
        )
        assert client.proxy_config.connect_timeout == 10.0
        assert client.proxy_config.read_timeout == 60.0
        assert client.proxy_config.retry_count == 3


class TestTunnelClientProperties:
    """Test TunnelClient properties."""

    def test_state_property(self, client: TunnelClient) -> None:
        """Test state property."""
        assert client.state == ConnectionState.DISCONNECTED

    def test_tunnel_id_initially_none(self, client: TunnelClient) -> None:
        """Test tunnel_id is None before connection."""
        assert client.tunnel_id is None

    def test_url_initially_none(self, client: TunnelClient) -> None:
        """Test url is None before connection."""
        assert client.url is None

    def test_is_connected_initially_false(self, client: TunnelClient) -> None:
        """Test is_connected is False before connection."""
        assert not client.is_connected

    def test_stats(self, client: TunnelClient) -> None:
        """Test stats property."""
        stats = client.stats
        assert stats["state"] == "disconnected"
        assert stats["tunnel_id"] is None
        assert stats["url"] is None
        assert stats["requests_proxied"] == 0
        assert stats["bytes_sent"] == 0
        assert stats["bytes_received"] == 0


class TestStateHooks:
    """Test state change hooks."""

    def test_add_state_hook(self, client: TunnelClient) -> None:
        """Test adding a state hook."""
        states: list[ConnectionState] = []

        def hook(state: ConnectionState) -> None:
            states.append(state)

        client.add_state_hook(hook)
        client._set_state(ConnectionState.CONNECTING)

        assert states == [ConnectionState.CONNECTING]

    def test_remove_state_hook(self, client: TunnelClient) -> None:
        """Test removing a state hook."""
        states: list[ConnectionState] = []

        def hook(state: ConnectionState) -> None:
            states.append(state)

        client.add_state_hook(hook)
        client.remove_state_hook(hook)
        client._set_state(ConnectionState.CONNECTING)

        assert states == []

    def test_multiple_hooks(self, client: TunnelClient) -> None:
        """Test multiple state hooks."""
        states1: list[ConnectionState] = []
        states2: list[ConnectionState] = []

        def hook1(state: ConnectionState) -> None:
            states1.append(state)

        def hook2(state: ConnectionState) -> None:
            states2.append(state)

        client.add_state_hook(hook1)
        client.add_state_hook(hook2)
        client._set_state(ConnectionState.CONNECTED)

        assert states1 == [ConnectionState.CONNECTED]
        assert states2 == [ConnectionState.CONNECTED]

    def test_hook_exception_handling(self, client: TunnelClient) -> None:
        """Test that hook exceptions don't break state changes."""
        called = []

        def bad_hook(state: ConnectionState) -> None:
            raise ValueError("Hook error")

        def good_hook(state: ConnectionState) -> None:
            called.append(state)

        client.add_state_hook(bad_hook)
        client.add_state_hook(good_hook)
        client._set_state(ConnectionState.CONNECTED)

        # good_hook should still be called
        assert called == [ConnectionState.CONNECTED]

    def test_no_duplicate_state_notification(self, client: TunnelClient) -> None:
        """Test that same state doesn't trigger hooks."""
        states: list[ConnectionState] = []

        def hook(state: ConnectionState) -> None:
            states.append(state)

        client.add_state_hook(hook)
        client._set_state(ConnectionState.CONNECTING)
        client._set_state(ConnectionState.CONNECTING)  # Same state

        assert states == [ConnectionState.CONNECTING]


class TestConnect:
    """Test connection logic."""

    @pytest.mark.asyncio
    async def test_connect_success(
        self, client: TunnelClient, mock_transport: MockTransport
    ) -> None:
        """Test successful connection."""
        tunnel_id = uuid4()

        # Queue the responses
        negotiate_response = NegotiateResponse(
            server_version=2,
            selected_compression=0,
            streaming_enabled=True,
            chunk_size=65536,
            success=True,
        )
        connect_response = ConnectResponse(
            type="connected",
            tunnel_id=tunnel_id,
            subdomain="test",
            url="https://test.instanton.dev",
        )

        mock_transport.queue_message(encode_message(negotiate_response))
        mock_transport.queue_message(encode_message(connect_response))

        with patch.object(
            client, "_create_transport", return_value=mock_transport
        ):
            url = await client.connect()

        assert url == "https://test.instanton.dev"
        assert client.tunnel_id == tunnel_id
        assert client.state == ConnectionState.CONNECTED
        assert client.is_connected

    @pytest.mark.asyncio
    async def test_connect_error_response(
        self, client: TunnelClient, mock_transport: MockTransport
    ) -> None:
        """Test connection with error response."""
        # Queue the responses
        negotiate_response = NegotiateResponse(success=True)
        error_response = ConnectResponse(
            type="error",
            error="Subdomain already taken",
        )

        mock_transport.queue_message(encode_message(negotiate_response))
        mock_transport.queue_message(encode_message(error_response))

        with patch.object(
            client, "_create_transport", return_value=mock_transport
        ), pytest.raises(ConnectionError, match="Subdomain already taken"):
            await client.connect()

        assert client.state == ConnectionState.DISCONNECTED

    @pytest.mark.asyncio
    async def test_connect_no_response(
        self, client: TunnelClient, mock_transport: MockTransport
    ) -> None:
        """Test connection with no response."""
        negotiate_response = NegotiateResponse(success=True)
        mock_transport.queue_message(encode_message(negotiate_response))
        mock_transport.queue_disconnect()

        with patch.object(
            client, "_create_transport", return_value=mock_transport
        ), pytest.raises(ConnectionError, match="No response"):
            await client.connect()


class TestMessageHandling:
    """Test message handling."""

    @pytest.mark.asyncio
    async def test_handle_pong(self, client: TunnelClient) -> None:
        """Test handling pong message."""
        pong = Pong(timestamp=12345, server_time=12346)
        data = encode_message(pong)

        # Should not raise
        await client._handle_message(data)

    @pytest.mark.asyncio
    async def test_handle_disconnect(self, client: TunnelClient) -> None:
        """Test handling disconnect message."""
        client._running = True
        disconnect = Disconnect(reason="Server shutdown")
        data = encode_message(disconnect)

        await client._handle_message(data)

        assert not client._running


class TestHttpRequestProxying:
    """Test HTTP request proxying."""

    @pytest.mark.asyncio
    async def test_proxy_successful_request(
        self, client: TunnelClient, mock_transport: MockTransport
    ) -> None:
        """Test successful HTTP request proxying."""
        request_id = uuid4()
        http_request = HttpRequest(
            request_id=request_id,
            method="GET",
            path="/api/test",
            headers={"Accept": "application/json"},
        )

        # Mock HTTP client response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {"Content-Type": "application/json"}
        mock_response.content = b'{"status": "ok"}'

        mock_http_client = AsyncMock()
        mock_http_client.request.return_value = mock_response

        client._transport = mock_transport
        client._http_client = mock_http_client
        client.local_port = 8080

        await client._handle_http_request(http_request)

        # Verify HTTP client was called correctly
        mock_http_client.request.assert_called_once_with(
            method="GET",
            url="http://localhost:8080/api/test",
            headers={"Accept": "application/json"},
            content=b"",
        )

        # Verify response was sent
        assert len(mock_transport._sent) == 1

    @pytest.mark.asyncio
    async def test_proxy_with_body(
        self, client: TunnelClient, mock_transport: MockTransport
    ) -> None:
        """Test proxying request with body."""
        request_id = uuid4()
        http_request = HttpRequest(
            request_id=request_id,
            method="POST",
            path="/api/data",
            headers={"Content-Type": "application/json"},
            body=b'{"key": "value"}',
        )

        mock_response = MagicMock()
        mock_response.status_code = 201
        mock_response.headers = {}
        mock_response.content = b"Created"

        mock_http_client = AsyncMock()
        mock_http_client.request.return_value = mock_response

        client._transport = mock_transport
        client._http_client = mock_http_client

        await client._handle_http_request(http_request)

        mock_http_client.request.assert_called_once()
        call_kwargs = mock_http_client.request.call_args.kwargs
        assert call_kwargs["content"] == b'{"key": "value"}'

    @pytest.mark.asyncio
    async def test_proxy_connection_error(
        self, client: TunnelClient, mock_transport: MockTransport
    ) -> None:
        """Test proxy with connection error."""
        request_id = uuid4()
        http_request = HttpRequest(
            request_id=request_id,
            method="GET",
            path="/api/test",
        )

        mock_http_client = AsyncMock()
        mock_http_client.request.side_effect = httpx.ConnectError("Connection refused")

        client._transport = mock_transport
        client._http_client = mock_http_client
        client.proxy_config = ProxyConfig(retry_count=0)  # No retries

        await client._handle_http_request(http_request)

        # Should send 502 error response
        assert len(mock_transport._sent) == 1

    @pytest.mark.asyncio
    async def test_proxy_timeout_error(
        self, client: TunnelClient, mock_transport: MockTransport
    ) -> None:
        """Test proxy with timeout error."""
        request_id = uuid4()
        http_request = HttpRequest(
            request_id=request_id,
            method="GET",
            path="/api/slow",
        )

        mock_http_client = AsyncMock()
        mock_http_client.request.side_effect = httpx.ReadTimeout("Timeout")

        client._transport = mock_transport
        client._http_client = mock_http_client
        client.proxy_config = ProxyConfig(retry_count=0)

        await client._handle_http_request(http_request)

        # Should send 502 error response
        assert len(mock_transport._sent) == 1

    @pytest.mark.asyncio
    async def test_proxy_retry_on_error(
        self, client: TunnelClient, mock_transport: MockTransport
    ) -> None:
        """Test proxy retries on connection error."""
        request_id = uuid4()
        http_request = HttpRequest(
            request_id=request_id,
            method="GET",
            path="/api/test",
        )

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {}
        mock_response.content = b"OK"

        mock_http_client = AsyncMock()
        # First call fails, second succeeds
        mock_http_client.request.side_effect = [
            httpx.ConnectError("Connection refused"),
            mock_response,
        ]

        client._transport = mock_transport
        client._http_client = mock_http_client
        client.proxy_config = ProxyConfig(retry_count=2)

        await client._handle_http_request(http_request)

        # Should have retried and succeeded
        assert mock_http_client.request.call_count == 2
        assert len(mock_transport._sent) == 1


class TestReconnect:
    """Test reconnection logic."""

    @pytest.mark.asyncio
    async def test_reconnect_disabled(
        self, client_no_reconnect: TunnelClient
    ) -> None:
        """Test that reconnect is disabled when configured."""
        assert not client_no_reconnect.reconnect_config.enabled

    @pytest.mark.asyncio
    async def test_max_reconnect_attempts(
        self, client: TunnelClient, mock_transport: MockTransport
    ) -> None:
        """Test max reconnect attempts is respected."""
        client.reconnect_config = ReconnectConfig(
            enabled=True,
            max_attempts=2,
            base_delay=0.01,  # Very short for testing
        )
        client._reconnect_attempt = 2  # Already at max

        await client._attempt_reconnect()

        assert client.state == ConnectionState.CLOSED


class TestClose:
    """Test close functionality."""

    @pytest.mark.asyncio
    async def test_close(
        self, client: TunnelClient, mock_transport: MockTransport
    ) -> None:
        """Test closing the client."""
        client._transport = mock_transport
        mock_transport._connected = True

        mock_http_client = AsyncMock()
        client._http_client = mock_http_client

        await client.close()

        assert client.state == ConnectionState.CLOSED
        assert not client._running
        mock_http_client.aclose.assert_called_once()
        assert not mock_transport.is_connected()


class TestContextManager:
    """Test async context manager."""

    @pytest.mark.asyncio
    async def test_context_manager(
        self, mock_transport: MockTransport
    ) -> None:
        """Test async context manager usage."""
        tunnel_id = uuid4()

        negotiate_response = NegotiateResponse(success=True)
        connect_response = ConnectResponse(
            type="connected",
            tunnel_id=tunnel_id,
            subdomain="test",
            url="https://test.instanton.dev",
        )

        mock_transport.queue_message(encode_message(negotiate_response))
        mock_transport.queue_message(encode_message(connect_response))

        client = TunnelClient(local_port=8080)

        with patch.object(
            client, "_create_transport", return_value=mock_transport
        ):
            async with client as c:
                assert c.is_connected
                assert c.url == "https://test.instanton.dev"

        assert client.state == ConnectionState.CLOSED


class TestReconnectConfig:
    """Test ReconnectConfig dataclass."""

    def test_default_values(self) -> None:
        """Test default values."""
        config = ReconnectConfig()
        assert config.enabled
        assert config.max_attempts == 10
        assert config.base_delay == 1.0
        assert config.max_delay == 60.0
        assert config.jitter == 0.1

    def test_custom_values(self) -> None:
        """Test custom values."""
        config = ReconnectConfig(
            enabled=False,
            max_attempts=5,
            base_delay=2.0,
            max_delay=120.0,
            jitter=0.2,
        )
        assert not config.enabled
        assert config.max_attempts == 5


class TestProxyConfig:
    """Test ProxyConfig dataclass."""

    def test_default_values(self) -> None:
        """Test default values."""
        config = ProxyConfig()
        assert config.connect_timeout == 5.0
        assert config.read_timeout is None  # None = indefinite for long-running APIs
        assert config.write_timeout == 5.0
        assert config.pool_timeout == 5.0
        assert config.max_connections == 100
        assert config.max_keepalive == 20
        assert config.retry_count == 2
        assert config.retry_on_status == (502, 503, 504)
        assert config.stream_timeout is None  # None = indefinite streaming

    def test_custom_values(self) -> None:
        """Test custom values."""
        config = ProxyConfig(
            connect_timeout=10.0,
            retry_count=5,
            retry_on_status=(500, 502, 503),
        )
        assert config.connect_timeout == 10.0
        assert config.retry_count == 5
        assert config.retry_on_status == (500, 502, 503)


class TestCreateHttpClient:
    """Test HTTP client creation."""

    @pytest.mark.asyncio
    async def test_create_http_client(self, client: TunnelClient) -> None:
        """Test HTTP client is created with correct settings."""
        http_client = await client._create_http_client()

        try:
            assert http_client is not None
            # Check timeout is configured
            assert http_client.timeout.connect == client.proxy_config.connect_timeout
            assert http_client.timeout.read == client.proxy_config.read_timeout
        finally:
            await http_client.aclose()
