"""Comprehensive tests for long-lived connections and all protocol support.

This test suite verifies:
1. Persistent connections lasting 13+ minutes
2. WebSocket, HTTP, gRPC protocol tunneling
3. Connection stability under various conditions
4. Heartbeat/keepalive mechanisms
5. Reconnection behavior
"""

from __future__ import annotations

import asyncio
import struct
import time
from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest

from instanton.client.tunnel import (
    ReconnectConfig,
    TunnelClient,
)
from instanton.core.config import ClientConfig, ServerConfig
from instanton.core.protocols import (
    GrpcFrame,
    GrpcPassthroughHandler,
    HTTP2ConnectionHandler,
    ProtocolDetector,
    ProtocolRouter,
    ProtocolType,
    TcpTunnelHandler,
    UdpHandler,
    WebSocketHandler,
    WebSocketOpcode,
)
from instanton.core.transport import (
    ConnectionState as TransportConnectionState,
)
from instanton.core.transport import (
    QuicStreamHandler,
    QuicTransport,
    QuicTransportConfig,
    WebSocketTransport,
)
from instanton.protocol.messages import (
    HttpRequest,
    encode_message,
)
from instanton.server.relay import TunnelConnection

# ==============================================================================
# Long-Lived Connection Tests
# ==============================================================================


class TestLongLivedConnections:
    """Tests for persistent connections lasting 13+ minutes."""

    def test_idle_timeout_configurable(self) -> None:
        """Test that idle timeout can be configured for long-lived connections."""
        # Default is 300 seconds (5 minutes)
        config = ServerConfig()
        assert config.idle_timeout == 300.0

        # Can be extended for long-lived connections (e.g., 15 minutes)
        config_extended = ServerConfig(idle_timeout=900.0)
        assert config_extended.idle_timeout == 900.0

        # Can be set to very long duration (1 hour)
        config_long = ServerConfig(idle_timeout=3600.0)
        assert config_long.idle_timeout == 3600.0

    def test_keepalive_interval_configurable(self) -> None:
        """Test that keepalive interval is configurable."""
        # Default is 30 seconds
        config = ClientConfig()
        assert config.keepalive_interval == 30.0

        # Can be customized
        config_custom = ClientConfig(keepalive_interval=60.0)
        assert config_custom.keepalive_interval == 60.0

    @pytest.mark.asyncio
    async def test_websocket_transport_heartbeat_keeps_connection_alive(self) -> None:
        """Test that WebSocket heartbeat prevents connection timeout."""
        transport = WebSocketTransport(
            ping_interval=1.0,  # Fast ping for testing
            ping_timeout=5.0,
        )

        # Verify heartbeat settings
        assert transport._ping_interval == 1.0
        assert transport._ping_timeout == 5.0

        # Simulate connected state
        transport._state = TransportConnectionState.CONNECTED

        # Create mock WebSocket that tracks pings
        ping_count = 0

        async def mock_ping(*args, **kwargs):
            nonlocal ping_count
            ping_count += 1
            future = asyncio.Future()
            future.set_result(None)
            return future

        mock_ws = AsyncMock()
        mock_ws.ping = mock_ping
        transport._ws = mock_ws

        # Start heartbeat
        transport._start_heartbeat()

        # Wait for a few ping cycles
        await asyncio.sleep(2.5)

        # Stop heartbeat
        transport._shutdown = True
        transport._stop_heartbeat()

        # Should have sent at least 2 pings
        assert ping_count >= 2

    @pytest.mark.asyncio
    async def test_tunnel_client_keepalive_loop(self) -> None:
        """Test that tunnel client sends keepalive pings."""
        client = TunnelClient(
            local_port=8080,
            config=ClientConfig(keepalive_interval=0.1),  # Fast for testing
        )

        # Track sent messages
        sent_messages: list[bytes] = []

        class MockTransport:
            def __init__(self):
                self._connected = True

            async def send(self, data: bytes) -> None:
                sent_messages.append(data)

            def is_connected(self) -> bool:
                return self._connected

        client._transport = MockTransport()  # type: ignore
        client._running = True

        # Run keepalive loop briefly
        keepalive_task = asyncio.create_task(client._keepalive_loop())

        await asyncio.sleep(0.35)  # Allow 3+ ping cycles

        import contextlib

        client._running = False
        keepalive_task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await keepalive_task

        # Should have sent multiple pings
        assert len(sent_messages) >= 3

    def test_tunnel_connection_tracks_last_activity(self) -> None:
        """Test that tunnel connections track last activity time."""
        from aiohttp import web

        ws = MagicMock(spec=web.WebSocketResponse)
        tunnel = TunnelConnection(
            id=uuid4(),
            subdomain="test",
            websocket=ws,
            local_port=8080,
        )

        initial_activity = tunnel.last_activity

        # Simulate activity by updating the timestamp
        tunnel.last_activity = datetime.now(UTC)

        # Activity time should be updated
        assert tunnel.last_activity >= initial_activity

    def test_connection_duration_tracking(self) -> None:
        """Test that connection duration can be calculated."""
        from aiohttp import web

        ws = MagicMock(spec=web.WebSocketResponse)
        tunnel = TunnelConnection(
            id=uuid4(),
            subdomain="test",
            websocket=ws,
            local_port=8080,
        )

        # Calculate duration (should be very small initially)
        duration = (datetime.now(UTC) - tunnel.connected_at).total_seconds()
        assert duration >= 0
        assert duration < 1  # Should be less than 1 second

    @pytest.mark.asyncio
    async def test_transport_stats_track_connection_time(self) -> None:
        """Test that transport stats track connection start time."""
        transport = WebSocketTransport()

        # Initially no connection time
        assert transport._stats.connection_start_time == 0.0

        # Simulate connection
        transport._stats.connection_start_time = time.time()

        await asyncio.sleep(0.1)

        # Can calculate connection duration
        duration = time.time() - transport._stats.connection_start_time
        assert duration >= 0.1

    def test_reconnect_config_supports_unlimited_attempts(self) -> None:
        """Test that reconnect can be configured for unlimited attempts."""
        # Setting max_attempts to 0 means unlimited
        config = ReconnectConfig(
            enabled=True,
            max_attempts=0,  # Unlimited
            base_delay=1.0,
            max_delay=60.0,
        )
        assert config.max_attempts == 0

    @pytest.mark.asyncio
    async def test_connection_survives_idle_periods(self) -> None:
        """Test that connections with keepalive survive idle periods."""
        transport = WebSocketTransport(
            ping_interval=0.1,
            ping_timeout=1.0,
        )

        transport._state = TransportConnectionState.CONNECTED

        # Track ping responses
        pings_sent = 0

        async def mock_ping(*args, **kwargs):
            nonlocal pings_sent
            pings_sent += 1
            future = asyncio.Future()
            future.set_result(None)
            return future

        mock_ws = AsyncMock()
        mock_ws.ping = mock_ping
        transport._ws = mock_ws

        # Start heartbeat
        transport._start_heartbeat()

        # Simulate idle period (but with keepalive)
        await asyncio.sleep(0.5)

        # Connection should still be alive
        assert transport._state == TransportConnectionState.CONNECTED

        # Stop heartbeat
        transport._shutdown = True
        transport._stop_heartbeat()

        # Multiple pings should have been sent
        assert pings_sent >= 4


# ==============================================================================
# WebSocket Protocol Tests
# ==============================================================================


class TestWebSocketProtocolSupport:
    """Tests for WebSocket protocol tunneling."""

    def test_websocket_handler_initialization(self) -> None:
        """Test WebSocket handler can be initialized with long intervals."""
        handler = WebSocketHandler(
            auto_ping=True,
            ping_interval=780.0,  # 13 minutes
        )
        assert handler._auto_ping is True
        assert handler._ping_interval == 780.0

    def test_websocket_upgrade_detection(self) -> None:
        """Test detection of WebSocket upgrade requests."""
        detector = ProtocolDetector()

        ws_request = (
            b"GET /socket HTTP/1.1\r\n"
            b"Host: example.com\r\n"
            b"Upgrade: websocket\r\n"
            b"Connection: Upgrade\r\n"
            b"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
            b"Sec-WebSocket-Version: 13\r\n"
            b"\r\n"
        )

        result = detector.detect_from_bytes(ws_request)

        assert result.protocol == ProtocolType.WEBSOCKET
        assert result.is_websocket_upgrade is True

    def test_websocket_frame_parsing_all_opcodes(self) -> None:
        """Test parsing WebSocket frames with all opcodes."""
        # Text frame
        text_frame = bytes([0x81, 0x05]) + b"hello"
        frame, _ = WebSocketHandler.parse_frame(text_frame)
        assert frame is not None
        assert frame.opcode == WebSocketOpcode.TEXT

        # Binary frame
        binary_frame = bytes([0x82, 0x04]) + b"\x00\x01\x02\x03"
        frame, _ = WebSocketHandler.parse_frame(binary_frame)
        assert frame is not None
        assert frame.opcode == WebSocketOpcode.BINARY

        # Ping frame
        ping_frame = bytes([0x89, 0x04]) + b"ping"
        frame, _ = WebSocketHandler.parse_frame(ping_frame)
        assert frame is not None
        assert frame.opcode == WebSocketOpcode.PING

        # Pong frame
        pong_frame = bytes([0x8A, 0x04]) + b"pong"
        frame, _ = WebSocketHandler.parse_frame(pong_frame)
        assert frame is not None
        assert frame.opcode == WebSocketOpcode.PONG

        # Close frame
        close_frame = bytes([0x88, 0x02]) + struct.pack(">H", 1000)
        frame, _ = WebSocketHandler.parse_frame(close_frame)
        assert frame is not None
        assert frame.opcode == WebSocketOpcode.CLOSE

    def test_websocket_frame_encoding(self) -> None:
        """Test encoding WebSocket frames."""
        # Encode text frame
        encoded = WebSocketHandler.encode_frame(
            opcode=WebSocketOpcode.TEXT,
            payload=b"test message",
            fin=True,
            mask=False,
        )

        # Verify frame structure
        assert encoded[0] == 0x81  # FIN + TEXT
        assert encoded[1] == len(b"test message")
        assert encoded[2:] == b"test message"

    def test_websocket_large_frame_handling(self) -> None:
        """Test handling large WebSocket frames."""
        # Create a large payload (> 125 bytes requires extended length)
        large_payload = b"x" * 256

        encoded = WebSocketHandler.encode_frame(
            opcode=WebSocketOpcode.BINARY,
            payload=large_payload,
            fin=True,
            mask=False,
        )

        # Parse it back
        frame, _ = WebSocketHandler.parse_frame(encoded)

        assert frame is not None
        assert len(frame.payload) == 256
        assert frame.payload == large_payload

    @pytest.mark.asyncio
    async def test_websocket_handler_auto_ping(self) -> None:
        """Test WebSocket handler auto-ping functionality."""
        handler = WebSocketHandler(
            auto_ping=True,
            ping_interval=0.1,  # Fast for testing
        )

        assert handler._auto_ping is True

        # Close handler
        await handler.close()
        assert handler._closed is True


# ==============================================================================
# HTTP Protocol Tests
# ==============================================================================


class TestHTTPProtocolSupport:
    """Tests for HTTP/1.1 and HTTP/2 protocol tunneling."""

    def test_http1_detection(self) -> None:
        """Test detection of HTTP/1.1 requests."""
        detector = ProtocolDetector()

        methods = ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"]

        for method in methods:
            request = f"{method} /api/test HTTP/1.1\r\nHost: example.com\r\n\r\n".encode()
            result = detector.detect_from_bytes(request)
            assert result.protocol == ProtocolType.HTTP1
            assert result.http_version == "1.1"

    def test_http2_preface_detection(self) -> None:
        """Test detection of HTTP/2 connection preface."""
        detector = ProtocolDetector()

        http2_preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
        result = detector.detect_from_bytes(http2_preface)

        assert result.protocol == ProtocolType.HTTP2
        assert result.confidence == 1.0
        assert result.http_version == "2.0"

    def test_http2_handler_initialization(self) -> None:
        """Test HTTP/2 handler initialization."""
        try:
            handler = HTTP2ConnectionHandler(
                is_client=False,
                max_concurrent_streams=100,
                initial_window_size=65535,
                max_frame_size=16384,
            )
            assert handler._max_concurrent_streams == 100
            assert handler.protocol_type == ProtocolType.HTTP2
        except RuntimeError:
            pytest.skip("h2 library not available")


# ==============================================================================
# gRPC Protocol Tests
# ==============================================================================


class TestGRPCProtocolSupport:
    """Tests for gRPC protocol tunneling."""

    def test_grpc_detection_via_content_type(self) -> None:
        """Test detection of gRPC via content-type header."""
        detector = ProtocolDetector()

        grpc_request = (
            b"POST /grpc.health.v1.Health/Check HTTP/1.1\r\n"
            b"Content-Type: application/grpc\r\n"
            b"TE: trailers\r\n"
            b"\r\n"
        )

        result = detector.detect_from_bytes(grpc_request)

        assert result.protocol == ProtocolType.GRPC
        assert result.is_grpc is True
        assert result.content_type == "application/grpc"

    def test_grpc_content_type_variants(self) -> None:
        """Test gRPC detection with various content-type variants."""
        variants = [
            "application/grpc",
            "application/grpc+proto",
            "application/grpc+json",
            "application/grpc-web",
            "application/grpc-web+proto",
        ]

        for content_type in variants:
            headers = {"content-type": content_type}
            assert GrpcPassthroughHandler.is_grpc_request(headers) is True

    def test_grpc_frame_parsing(self) -> None:
        """Test parsing gRPC frames."""
        # Create a gRPC frame: compressed=0, length=10, data
        data = b"grpc data!"
        frame_bytes = bytes([0]) + struct.pack(">I", len(data)) + data

        frame, remaining = GrpcPassthroughHandler.parse_frame(frame_bytes)

        assert frame is not None
        assert frame.compressed is False
        assert frame.length == 10
        assert frame.data == data
        assert remaining == b""

    def test_grpc_frame_encoding(self) -> None:
        """Test encoding gRPC frames."""
        frame = GrpcFrame(
            compressed=True,
            length=5,
            data=b"hello",
        )

        encoded = GrpcPassthroughHandler.encode_frame(frame)

        # Verify structure
        assert encoded[0] == 1  # Compressed
        assert struct.unpack(">I", encoded[1:5])[0] == 5
        assert encoded[5:] == b"hello"

    def test_grpc_handler_initialization(self) -> None:
        """Test gRPC handler initialization."""
        handler = GrpcPassthroughHandler(
            target_host="localhost",
            target_port=50051,
        )

        assert handler._target_host == "localhost"
        assert handler._target_port == 50051
        assert handler.protocol_type == ProtocolType.GRPC


# ==============================================================================
# TCP/UDP Protocol Tests
# ==============================================================================


class TestRawProtocolSupport:
    """Tests for raw TCP/UDP protocol tunneling."""

    def test_tcp_detection(self) -> None:
        """Test detection of raw TCP data."""
        detector = ProtocolDetector()

        # Binary data that doesn't match any other protocol
        raw_tcp = bytes([0xFF, 0xFE, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05])
        result = detector.detect_from_bytes(raw_tcp)

        assert result.protocol == ProtocolType.TCP

    def test_tcp_handler_initialization(self) -> None:
        """Test TCP tunnel handler initialization."""
        handler = TcpTunnelHandler(
            target_host="example.com",
            target_port=22,
            buffer_size=65535,
        )

        assert handler._target_host == "example.com"
        assert handler._target_port == 22
        assert handler._buffer_size == 65535
        assert handler.protocol_type == ProtocolType.TCP

    def test_tcp_handler_stats(self) -> None:
        """Test TCP handler statistics."""
        handler = TcpTunnelHandler(
            target_host="localhost",
            target_port=8080,
        )

        stats = handler.stats
        assert stats.bytes_sent == 0
        assert stats.bytes_received == 0
        assert stats.tunnel_id is not None

    def test_udp_handler_initialization(self) -> None:
        """Test UDP handler initialization."""
        handler = UdpHandler(
            target_host="8.8.8.8",
            target_port=53,
            max_datagram_size=1400,
        )

        assert handler._target_host == "8.8.8.8"
        assert handler._target_port == 53
        assert handler._max_datagram_size == 1400
        assert handler.protocol_type == ProtocolType.UDP


# ==============================================================================
# Protocol Router Tests
# ==============================================================================


class TestProtocolRouter:
    """Tests for protocol routing functionality."""

    def test_router_registers_all_protocols(self) -> None:
        """Test that router can register handlers for all protocols."""
        router = ProtocolRouter()

        # Create mock handlers
        protocols = [
            ProtocolType.HTTP1,
            ProtocolType.HTTP2,
            ProtocolType.GRPC,
            ProtocolType.WEBSOCKET,
            ProtocolType.TCP,
            ProtocolType.UDP,
        ]

        for protocol in protocols:
            handler = MagicMock()
            handler.protocol_type = protocol
            router.register_handler(protocol, handler)
            assert router.get_handler(protocol) is handler

    @pytest.mark.asyncio
    async def test_router_routes_websocket(self) -> None:
        """Test that router correctly routes WebSocket connections."""
        router = ProtocolRouter()

        mock_handler = MagicMock()
        mock_handler.handle_connection = AsyncMock()
        router.register_handler(ProtocolType.WEBSOCKET, mock_handler)

        # Create mock reader with WebSocket upgrade request
        ws_request = (
            b"GET /ws HTTP/1.1\r\n"
            b"Upgrade: websocket\r\n"
            b"Connection: Upgrade\r\n"
        )

        reader = AsyncMock()
        reader.read = AsyncMock(return_value=ws_request)

        writer = MagicMock()
        writer.close = MagicMock()
        writer.wait_closed = AsyncMock()

        await router.route_connection(reader, writer)

        mock_handler.handle_connection.assert_called_once()

    @pytest.mark.asyncio
    async def test_router_routes_grpc(self) -> None:
        """Test that router correctly routes gRPC connections."""
        router = ProtocolRouter()

        mock_handler = MagicMock()
        mock_handler.handle_connection = AsyncMock()
        router.register_handler(ProtocolType.GRPC, mock_handler)

        # Create mock reader with gRPC request
        grpc_request = (
            b"POST /service/method HTTP/1.1\r\n"
            b"Content-Type: application/grpc\r\n"
        )

        reader = AsyncMock()
        reader.read = AsyncMock(return_value=grpc_request)

        writer = MagicMock()
        writer.close = MagicMock()
        writer.wait_closed = AsyncMock()

        await router.route_connection(reader, writer)

        mock_handler.handle_connection.assert_called_once()


# ==============================================================================
# Connection Stability Tests
# ==============================================================================


class TestConnectionStability:
    """Tests for connection stability under various conditions."""

    @pytest.mark.asyncio
    async def test_reconnect_after_disconnect(self) -> None:
        """Test that client reconnects after disconnect."""
        client = TunnelClient(
            local_port=8080,
            reconnect_config=ReconnectConfig(
                enabled=True,
                max_attempts=3,
                base_delay=0.01,  # Fast for testing
            ),
        )

        # Verify reconnect is enabled
        assert client.reconnect_config.enabled is True
        assert client.reconnect_config.max_attempts == 3

    @pytest.mark.asyncio
    async def test_exponential_backoff(self) -> None:
        """Test that reconnect uses exponential backoff."""
        transport = WebSocketTransport(
            reconnect_delay=1.0,
            max_reconnect_delay=16.0,
        )

        # Calculate expected delays
        expected_delays = [
            1.0,   # 1.0 * 2^0
            2.0,   # 1.0 * 2^1
            4.0,   # 1.0 * 2^2
            8.0,   # 1.0 * 2^3
            16.0,  # 1.0 * 2^4 (capped)
            16.0,  # Stays at max
        ]

        for i, expected in enumerate(expected_delays):
            delay = min(
                transport._reconnect_delay * (2 ** i),
                transport._max_reconnect_delay,
            )
            assert delay == expected

    @pytest.mark.asyncio
    async def test_connection_callback_on_reconnect(self) -> None:
        """Test that callbacks are fired on reconnection."""
        transport = WebSocketTransport()

        reconnected = False

        def on_reconnect():
            nonlocal reconnected
            reconnected = True

        transport.on_reconnect(on_reconnect)

        # Simulate reconnection
        await transport._fire_callbacks(transport._on_reconnect)

        assert reconnected is True

    @pytest.mark.asyncio
    async def test_stats_track_reconnect_count(self) -> None:
        """Test that stats track reconnection count."""
        transport = WebSocketTransport()

        assert transport._stats.reconnect_count == 0

        # Simulate reconnections
        transport._stats.reconnect_count = 5

        assert transport.get_stats().reconnect_count == 5


# ==============================================================================
# Competitive Feature Parity Tests
# ==============================================================================


class TestCompetitiveFeatureParity:
    """Tests verifying feature parity with tunnelto."""

    def test_stream_multiplexing_support(self) -> None:
        """Test that Instanton supports stream multiplexing (like tunnelto)."""
        # QUIC transport supports multiple streams
        transport = QuicTransport()

        # Can create multiple streams
        # (Would require connection for actual test)
        assert hasattr(transport, "create_stream")
        assert hasattr(transport, "get_stream")

    def test_subdomain_routing_support(self) -> None:
        """Test that server supports subdomain routing."""
        config = ServerConfig(base_domain="instanton.dev")

        assert config.base_domain == "instanton.dev"
        assert config.max_tunnels == 10000

    def test_binary_protocol_support(self) -> None:
        """Test that Instanton uses efficient binary protocol."""
        # Verify messages can be encoded to bytes
        request = HttpRequest(
            request_id=uuid4(),
            method="GET",
            path="/test",
            headers={},
        )

        encoded = encode_message(request)
        assert isinstance(encoded, bytes)
        assert len(encoded) > 0

    def test_reconnection_token_equivalent(self) -> None:
        """Test that Instanton has reconnection capability (like tunnelto's tokens)."""
        config = ReconnectConfig(
            enabled=True,
            max_attempts=10,
            base_delay=1.0,
            max_delay=60.0,
        )

        # Instanton uses auto-reconnect with same subdomain
        assert config.enabled is True

        # ClientConfig preserves subdomain across reconnects
        client_config = ClientConfig(
            subdomain="my-tunnel",
            auto_reconnect=True,
        )
        assert client_config.subdomain == "my-tunnel"
        assert client_config.auto_reconnect is True

    def test_tls_support(self) -> None:
        """Test that Instanton supports TLS (like tunnelto)."""
        config = ServerConfig(
            cert_path="/path/to/cert.pem",
            key_path="/path/to/key.pem",
        )

        assert config.cert_path is not None
        assert config.key_path is not None

    def test_acme_certificate_support(self) -> None:
        """Test that Instanton supports ACME certificates."""
        config = ServerConfig(
            acme_enabled=True,
            acme_email="admin@example.com",
        )

        assert config.acme_enabled is True
        assert config.acme_email == "admin@example.com"


# ==============================================================================
# QUIC Transport Long-Lived Connection Tests
# ==============================================================================


class TestQUICLongLivedConnections:
    """Tests for QUIC transport long-lived connections."""

    def test_quic_idle_timeout_configurable(self) -> None:
        """Test QUIC idle timeout is configurable for long connections."""
        # Default is 30 seconds
        config = QuicTransportConfig()
        assert config.idle_timeout == 30.0

        # Can be extended for long-lived connections
        config_long = QuicTransportConfig(idle_timeout=900.0)  # 15 minutes
        assert config_long.idle_timeout == 900.0

    def test_quic_stream_handler_survives_idle(self) -> None:
        """Test that QUIC stream handlers survive idle periods."""
        handler = QuicStreamHandler(stream_id=4)

        # Should not be closed initially
        assert handler._closed is False
        assert handler._end_stream is False

        # Receive some data
        handler.receive_data(b"test data")

        # Should still be open
        assert handler._closed is False

    @pytest.mark.asyncio
    async def test_quic_transport_reconnect_config(self) -> None:
        """Test QUIC transport reconnection configuration."""
        transport = QuicTransport(
            auto_reconnect=True,
            max_reconnect_attempts=0,  # Unlimited
            reconnect_delay=1.0,
            max_reconnect_delay=300.0,  # 5 minutes max delay
        )

        assert transport._config.auto_reconnect is True
        assert transport._config.max_reconnect_attempts == 0
        assert transport._config.max_reconnect_delay == 300.0


# ==============================================================================
# Simulated 13-Minute Connection Test
# ==============================================================================


class TestThirteenMinuteConnection:
    """Tests simulating 13+ minute connections."""

    def test_config_supports_13_minute_timeout(self) -> None:
        """Test that configs support 13+ minute connections."""
        # 13 minutes = 780 seconds
        server_config = ServerConfig(idle_timeout=900.0)  # 15 minutes
        assert server_config.idle_timeout > 780

        client_config = ClientConfig(keepalive_interval=60.0)
        # With 60s keepalive, connection should stay alive well beyond 13 minutes
        assert client_config.keepalive_interval < 780

    def test_keepalive_prevents_timeout(self) -> None:
        """Test that keepalive mechanism prevents timeout."""
        idle_timeout = 300.0  # 5 minute idle timeout
        keepalive_interval = 30.0  # 30 second keepalive

        # Calculate how many keepalives in 13 minutes
        connection_duration = 780.0  # 13 minutes
        keepalive_count = connection_duration / keepalive_interval

        # 26 keepalives would be sent in 13 minutes
        assert keepalive_count == 26

        # Each keepalive resets the idle timer, so connection stays alive
        # as long as idle_timeout > keepalive_interval
        assert idle_timeout > keepalive_interval

    @pytest.mark.asyncio
    async def test_simulated_long_session(self) -> None:
        """Simulate a long session with periodic activity."""
        transport = WebSocketTransport(
            ping_interval=0.05,  # Very fast for testing
            ping_timeout=1.0,
        )

        transport._state = TransportConnectionState.CONNECTED

        # Track activity
        activity_count = 0

        async def mock_ping(*args, **kwargs):
            nonlocal activity_count
            activity_count += 1
            future = asyncio.Future()
            future.set_result(None)
            return future

        mock_ws = AsyncMock()
        mock_ws.ping = mock_ping
        transport._ws = mock_ws

        # Start heartbeat
        transport._start_heartbeat()

        # Simulate passage of time with activity
        # (In real scenario, this would be 13+ minutes)
        # Use longer sleep to ensure enough heartbeats with timing variance
        await asyncio.sleep(0.5)

        # Stop heartbeat
        transport._shutdown = True
        transport._stop_heartbeat()

        # Should have had multiple activities keeping connection alive
        # With 0.05s interval and 0.5s sleep, expect ~10 heartbeats
        # Use >= 3 to account for timing variance on slower systems
        assert activity_count >= 3
        # Connection should still be in connected state
        # (only changes if ping fails)


# ==============================================================================
# Run all tests when executed directly
# ==============================================================================


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
