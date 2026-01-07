"""Comprehensive tests for multi-protocol support.

Tests cover:
- Protocol detection (HTTP/1, HTTP/2, gRPC, WebSocket, TCP, UDP)
- HTTP/2 handling with h2
- gRPC passthrough
- WebSocket bidirectional streaming
- TCP tunnel handling
- Message serialization for new message types
"""

from __future__ import annotations

import asyncio
import struct
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest

from instanton.core.protocols import (
    GrpcFrame,
    GrpcPassthroughHandler,
    HTTP2ConnectionHandler,
    HTTP2Stream,
    ProtocolDetectionResult,
    ProtocolDetector,
    ProtocolHandler,
    ProtocolRouter,
    ProtocolType,
    TcpTunnelHandler,
    TcpTunnelStats,
    UdpDatagram,
    UdpHandler,
    WebSocketFrame,
    WebSocketHandler,
    WebSocketOpcode,
)
from instanton.protocol.messages import (
    GrpcFrame as GrpcFrameMessage,
)
from instanton.protocol.messages import (
    GrpcStreamClose,
    GrpcStreamOpen,
    GrpcStreamOpened,
    GrpcTrailers,
    TcpData,
    TcpTunnelOpen,
    TcpTunnelOpened,
    TunnelProtocol,
    UdpTunnelOpen,
    WebSocketClose,
    WebSocketUpgrade,
    WebSocketUpgradeResponse,
    encode_message,
    parse_message,
)
from instanton.protocol.messages import (
    UdpDatagram as UdpDatagramMessage,
)
from instanton.protocol.messages import (
    WebSocketFrame as WebSocketFrameMessage,
)
from instanton.protocol.messages import (
    WebSocketOpcode as WsOpcode,
)

# ==============================================================================
# Protocol Detection Tests
# ==============================================================================


class TestProtocolDetector:
    """Tests for protocol detection functionality."""

    def test_detector_initialization(self) -> None:
        """Test detector initializes with correct defaults."""
        detector = ProtocolDetector()
        assert detector.min_bytes == 24
        assert detector.timeout == 5.0

    def test_detector_custom_settings(self) -> None:
        """Test detector with custom settings."""
        detector = ProtocolDetector(min_bytes=32, timeout=10.0)
        assert detector.min_bytes == 32
        assert detector.timeout == 10.0

    def test_detect_http2_preface(self) -> None:
        """Test detection of HTTP/2 connection preface."""
        detector = ProtocolDetector()
        http2_preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

        result = detector.detect_from_bytes(http2_preface)

        assert result.protocol == ProtocolType.HTTP2
        assert result.confidence == 1.0
        assert result.http_version == "2.0"

    def test_detect_http1_get(self) -> None:
        """Test detection of HTTP/1.x GET request."""
        detector = ProtocolDetector()
        http1_request = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"

        result = detector.detect_from_bytes(http1_request)

        assert result.protocol == ProtocolType.HTTP1
        assert result.confidence >= 0.9
        assert result.http_version == "1.1"

    def test_detect_http1_post(self) -> None:
        """Test detection of HTTP/1.x POST request."""
        detector = ProtocolDetector()
        http1_request = b"POST /api/data HTTP/1.1\r\nContent-Type: application/json\r\n\r\n"

        result = detector.detect_from_bytes(http1_request)

        assert result.protocol == ProtocolType.HTTP1
        assert result.confidence >= 0.9

    def test_detect_websocket_upgrade(self) -> None:
        """Test detection of WebSocket upgrade request."""
        detector = ProtocolDetector()
        ws_request = (
            b"GET /ws HTTP/1.1\r\n"
            b"Host: example.com\r\n"
            b"Upgrade: websocket\r\n"
            b"Connection: Upgrade\r\n"
            b"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
            b"\r\n"
        )

        result = detector.detect_from_bytes(ws_request)

        assert result.protocol == ProtocolType.WEBSOCKET
        assert result.is_websocket_upgrade is True
        assert result.confidence >= 0.9

    def test_detect_grpc_content_type(self) -> None:
        """Test detection of gRPC via content-type header."""
        detector = ProtocolDetector()
        grpc_request = (
            b"POST /grpc.service/Method HTTP/1.1\r\n"
            b"Content-Type: application/grpc\r\n"
            b"TE: trailers\r\n"
            b"\r\n"
        )

        result = detector.detect_from_bytes(grpc_request)

        assert result.protocol == ProtocolType.GRPC
        assert result.is_grpc is True
        assert result.content_type == "application/grpc"

    def test_detect_raw_tcp_binary(self) -> None:
        """Test detection of raw binary TCP data."""
        detector = ProtocolDetector()
        binary_data = bytes([0x00, 0x01, 0x02, 0xFF, 0xFE, 0x80, 0x90])

        result = detector.detect_from_bytes(binary_data)

        assert result.protocol == ProtocolType.TCP
        assert result.confidence >= 0.6

    def test_detect_raw_tcp_text(self) -> None:
        """Test detection of raw text TCP data (non-HTTP)."""
        detector = ProtocolDetector()
        text_data = b"HELLO SERVER\r\nDATA HERE\r\n"

        result = detector.detect_from_bytes(text_data)

        assert result.protocol == ProtocolType.TCP
        assert result.confidence >= 0.5

    def test_detect_empty_data(self) -> None:
        """Test detection with empty data."""
        detector = ProtocolDetector()

        result = detector.detect_from_bytes(b"")

        assert result.protocol == ProtocolType.UNKNOWN
        assert result.confidence == 0.0

    def test_detect_tls_handshake(self) -> None:
        """Test detection of TLS handshake (record type 0x16)."""
        detector = ProtocolDetector()
        # TLS handshake starts with 0x16 (ContentType.handshake)
        tls_data = bytes([0x16, 0x03, 0x01, 0x00, 0x05]) + b"hello"

        result = detector.detect_from_bytes(tls_data)

        assert result.is_tls is True

    @pytest.mark.asyncio
    async def test_detect_async_timeout(self) -> None:
        """Test async detection timeout handling."""
        detector = ProtocolDetector(timeout=0.1)

        # Create a reader that times out
        reader = AsyncMock(spec=asyncio.StreamReader)
        reader.read = AsyncMock(side_effect=TimeoutError())

        result, data = await detector.detect(reader)

        assert result.protocol == ProtocolType.UNKNOWN
        assert result.confidence == 0.0
        assert data == b""

    @pytest.mark.asyncio
    async def test_detect_async_success(self) -> None:
        """Test successful async detection."""
        detector = ProtocolDetector()

        reader = AsyncMock(spec=asyncio.StreamReader)
        http1_data = b"GET / HTTP/1.1\r\nHost: test\r\n"
        reader.read = AsyncMock(return_value=http1_data)

        result, data = await detector.detect(reader)

        assert result.protocol == ProtocolType.HTTP1
        assert data == http1_data


# ==============================================================================
# HTTP/2 Handler Tests
# ==============================================================================


class TestHTTP2Handler:
    """Tests for HTTP/2 connection handling."""

    def test_handler_requires_h2(self) -> None:
        """Test that handler checks for h2 availability."""
        # This should work if h2 is installed
        try:
            handler = HTTP2ConnectionHandler()
            assert handler.protocol_type == ProtocolType.HTTP2
        except RuntimeError as e:
            assert "h2 library is required" in str(e)

    def test_handler_initialization(self) -> None:
        """Test handler initialization with custom settings."""
        try:
            handler = HTTP2ConnectionHandler(
                is_client=True,
                max_concurrent_streams=50,
                initial_window_size=32768,
                max_frame_size=8192,
            )
            assert handler._is_client is True
            assert handler._max_concurrent_streams == 50
            assert handler._initial_window_size == 32768
            assert handler._max_frame_size == 8192
        except RuntimeError:
            pytest.skip("h2 library not available")

    def test_http2_stream_dataclass(self) -> None:
        """Test HTTP2Stream dataclass."""
        stream = HTTP2Stream(
            stream_id=1,
            headers={":method": "GET", ":path": "/"},
            request_data=b"test body",
        )

        assert stream.stream_id == 1
        assert stream.headers[":method"] == "GET"
        assert stream.request_data == b"test body"
        assert stream.is_complete is False
        assert stream.end_stream_received is False


# ==============================================================================
# gRPC Passthrough Tests
# ==============================================================================


class TestGrpcPassthrough:
    """Tests for gRPC passthrough handler."""

    def test_handler_initialization(self) -> None:
        """Test gRPC handler initialization."""
        handler = GrpcPassthroughHandler(
            target_host="localhost",
            target_port=50051,
        )

        assert handler._target_host == "localhost"
        assert handler._target_port == 50051
        assert handler.protocol_type == ProtocolType.GRPC

    def test_is_grpc_request(self) -> None:
        """Test gRPC request detection via headers."""
        grpc_headers = {"content-type": "application/grpc"}
        non_grpc_headers = {"content-type": "application/json"}

        assert GrpcPassthroughHandler.is_grpc_request(grpc_headers) is True
        assert GrpcPassthroughHandler.is_grpc_request(non_grpc_headers) is False

    def test_is_grpc_request_variants(self) -> None:
        """Test gRPC content-type variants."""
        variants = [
            {"content-type": "application/grpc"},
            {"content-type": "application/grpc+proto"},
            {"content-type": "application/grpc+json"},
            {"content-type": "APPLICATION/GRPC"},  # Case insensitive
        ]

        for headers in variants:
            assert GrpcPassthroughHandler.is_grpc_request(headers) is True

    def test_parse_grpc_frame(self) -> None:
        """Test parsing a gRPC frame."""
        # Create a valid gRPC frame: compressed=0, length=5, data="hello"
        frame_data = bytes([0]) + struct.pack(">I", 5) + b"hello"

        frame, remaining = GrpcPassthroughHandler.parse_frame(frame_data)

        assert frame is not None
        assert frame.compressed is False
        assert frame.length == 5
        assert frame.data == b"hello"
        assert remaining == b""

    def test_parse_grpc_frame_compressed(self) -> None:
        """Test parsing a compressed gRPC frame."""
        frame_data = bytes([1]) + struct.pack(">I", 3) + b"abc"

        frame, remaining = GrpcPassthroughHandler.parse_frame(frame_data)

        assert frame is not None
        assert frame.compressed is True
        assert frame.length == 3
        assert frame.data == b"abc"

    def test_parse_grpc_frame_incomplete(self) -> None:
        """Test parsing incomplete gRPC frame."""
        # Only header, no data
        incomplete_data = bytes([0]) + struct.pack(">I", 100)

        frame, remaining = GrpcPassthroughHandler.parse_frame(incomplete_data)

        assert frame is None
        assert remaining == incomplete_data

    def test_parse_grpc_frame_multiple(self) -> None:
        """Test parsing multiple gRPC frames."""
        frame1 = bytes([0]) + struct.pack(">I", 2) + b"ab"
        frame2 = bytes([0]) + struct.pack(">I", 3) + b"cde"
        data = frame1 + frame2

        # Parse first frame
        parsed1, remaining = GrpcPassthroughHandler.parse_frame(data)
        assert parsed1 is not None
        assert parsed1.data == b"ab"

        # Parse second frame
        parsed2, remaining = GrpcPassthroughHandler.parse_frame(remaining)
        assert parsed2 is not None
        assert parsed2.data == b"cde"
        assert remaining == b""

    def test_encode_grpc_frame(self) -> None:
        """Test encoding a gRPC frame."""
        frame = GrpcFrame(compressed=False, length=5, data=b"hello")

        encoded = GrpcPassthroughHandler.encode_frame(frame)

        assert encoded[0] == 0  # Not compressed
        assert struct.unpack(">I", encoded[1:5])[0] == 5
        assert encoded[5:] == b"hello"


# ==============================================================================
# WebSocket Handler Tests
# ==============================================================================


class TestWebSocketHandler:
    """Tests for WebSocket handler."""

    def test_handler_initialization(self) -> None:
        """Test WebSocket handler initialization."""
        handler = WebSocketHandler(
            auto_ping=True,
            ping_interval=30.0,
        )

        assert handler._auto_ping is True
        assert handler._ping_interval == 30.0
        assert handler.protocol_type == ProtocolType.WEBSOCKET

    def test_is_upgrade_request(self) -> None:
        """Test WebSocket upgrade detection."""
        upgrade_headers = {
            "upgrade": "websocket",
            "connection": "Upgrade",
        }
        non_upgrade_headers = {
            "upgrade": "h2c",
            "connection": "keep-alive",
        }

        assert WebSocketHandler.is_upgrade_request(upgrade_headers) is True
        assert WebSocketHandler.is_upgrade_request(non_upgrade_headers) is False

    def test_parse_websocket_frame_text(self) -> None:
        """Test parsing a WebSocket text frame."""
        # FIN=1, opcode=1 (text), mask=0, length=5
        frame_data = bytes([0x81, 0x05]) + b"hello"

        frame, remaining = WebSocketHandler.parse_frame(frame_data)

        assert frame is not None
        assert frame.opcode == WebSocketOpcode.TEXT
        assert frame.payload == b"hello"
        assert frame.fin is True
        assert remaining == b""

    def test_parse_websocket_frame_binary(self) -> None:
        """Test parsing a WebSocket binary frame."""
        # FIN=1, opcode=2 (binary), mask=0, length=4
        frame_data = bytes([0x82, 0x04]) + b"\x00\x01\x02\x03"

        frame, remaining = WebSocketHandler.parse_frame(frame_data)

        assert frame is not None
        assert frame.opcode == WebSocketOpcode.BINARY
        assert frame.payload == b"\x00\x01\x02\x03"

    def test_parse_websocket_frame_masked(self) -> None:
        """Test parsing a masked WebSocket frame."""
        # FIN=1, opcode=1, mask=1, length=5
        mask_key = bytes([0x37, 0xfa, 0x21, 0x3d])
        payload = b"hello"
        masked_payload = bytes(b ^ mask_key[i % 4] for i, b in enumerate(payload))

        frame_data = bytes([0x81, 0x85]) + mask_key + masked_payload

        frame, remaining = WebSocketHandler.parse_frame(frame_data)

        assert frame is not None
        assert frame.payload == b"hello"  # Should be unmasked

    def test_parse_websocket_frame_extended_length_16(self) -> None:
        """Test parsing WebSocket frame with 16-bit extended length."""
        # FIN=1, opcode=2, mask=0, length=126 (indicates 16-bit length follows)
        length = 256
        frame_data = bytes([0x82, 126]) + struct.pack(">H", length) + b"x" * length

        frame, remaining = WebSocketHandler.parse_frame(frame_data)

        assert frame is not None
        assert len(frame.payload) == 256

    def test_parse_websocket_frame_ping(self) -> None:
        """Test parsing WebSocket ping frame."""
        # FIN=1, opcode=9 (ping), mask=0, length=4
        frame_data = bytes([0x89, 0x04]) + b"ping"

        frame, remaining = WebSocketHandler.parse_frame(frame_data)

        assert frame is not None
        assert frame.opcode == WebSocketOpcode.PING
        assert frame.payload == b"ping"

    def test_parse_websocket_frame_close(self) -> None:
        """Test parsing WebSocket close frame."""
        # FIN=1, opcode=8 (close), mask=0, length=2 (status code)
        close_code = struct.pack(">H", 1000)
        frame_data = bytes([0x88, 0x02]) + close_code

        frame, remaining = WebSocketHandler.parse_frame(frame_data)

        assert frame is not None
        assert frame.opcode == WebSocketOpcode.CLOSE
        assert struct.unpack(">H", frame.payload)[0] == 1000

    def test_parse_websocket_frame_incomplete(self) -> None:
        """Test parsing incomplete WebSocket frame."""
        # Only header, payload incomplete
        incomplete = bytes([0x81, 0x50])  # Says 80 bytes, but none provided

        frame, remaining = WebSocketHandler.parse_frame(incomplete)

        assert frame is None
        assert remaining == incomplete

    def test_encode_websocket_frame_text(self) -> None:
        """Test encoding a WebSocket text frame."""
        encoded = WebSocketHandler.encode_frame(
            opcode=WebSocketOpcode.TEXT,
            payload=b"hello",
            fin=True,
            mask=False,
        )

        assert encoded[0] == 0x81  # FIN + TEXT
        assert encoded[1] == 5  # Length
        assert encoded[2:] == b"hello"

    def test_encode_websocket_frame_masked(self) -> None:
        """Test encoding a masked WebSocket frame."""
        encoded = WebSocketHandler.encode_frame(
            opcode=WebSocketOpcode.TEXT,
            payload=b"test",
            fin=True,
            mask=True,
        )

        assert encoded[0] == 0x81  # FIN + TEXT
        assert encoded[1] & 0x80  # Mask bit set
        assert len(encoded) == 2 + 4 + 4  # Header + mask key + payload


# ==============================================================================
# TCP Tunnel Handler Tests
# ==============================================================================


class TestTcpTunnelHandler:
    """Tests for TCP tunnel handler."""

    def test_handler_initialization(self) -> None:
        """Test TCP handler initialization."""
        handler = TcpTunnelHandler(
            target_host="example.com",
            target_port=8080,
            buffer_size=32768,
        )

        assert handler._target_host == "example.com"
        assert handler._target_port == 8080
        assert handler._buffer_size == 32768
        assert handler.protocol_type == ProtocolType.TCP

    def test_tcp_tunnel_stats(self) -> None:
        """Test TCP tunnel statistics dataclass."""
        stats = TcpTunnelStats(
            bytes_sent=1000,
            bytes_received=2000,
            start_time=12345.0,
        )

        assert stats.bytes_sent == 1000
        assert stats.bytes_received == 2000
        assert stats.start_time == 12345.0
        assert stats.tunnel_id is not None

    def test_handler_stats_property(self) -> None:
        """Test handler stats property."""
        handler = TcpTunnelHandler(
            target_host="localhost",
            target_port=80,
        )

        stats = handler.stats
        assert isinstance(stats, TcpTunnelStats)
        assert stats.bytes_sent == 0
        assert stats.bytes_received == 0


# ==============================================================================
# UDP Handler Tests
# ==============================================================================


class TestUdpHandler:
    """Tests for UDP handler."""

    def test_handler_initialization(self) -> None:
        """Test UDP handler initialization."""
        handler = UdpHandler(
            target_host="8.8.8.8",
            target_port=53,
            max_datagram_size=1200,
        )

        assert handler._target_host == "8.8.8.8"
        assert handler._target_port == 53
        assert handler._max_datagram_size == 1200
        assert handler.protocol_type == ProtocolType.UDP

    def test_udp_datagram_dataclass(self) -> None:
        """Test UdpDatagram dataclass."""
        datagram = UdpDatagram(
            data=b"dns query",
            source_addr=("192.168.1.1", 12345),
            dest_addr=("8.8.8.8", 53),
            timestamp=1234567890.0,
        )

        assert datagram.data == b"dns query"
        assert datagram.source_addr == ("192.168.1.1", 12345)
        assert datagram.dest_addr == ("8.8.8.8", 53)


# ==============================================================================
# Protocol Router Tests
# ==============================================================================


class TestProtocolRouter:
    """Tests for protocol router."""

    def test_router_initialization(self) -> None:
        """Test router initialization."""
        router = ProtocolRouter()

        assert router._detector is not None
        assert router._handlers == {}

    def test_register_handler(self) -> None:
        """Test registering a handler."""
        router = ProtocolRouter()
        handler = MagicMock(spec=ProtocolHandler)
        handler.protocol_type = ProtocolType.TCP

        router.register_handler(ProtocolType.TCP, handler)

        assert router.get_handler(ProtocolType.TCP) is handler

    def test_get_handler_default(self) -> None:
        """Test getting default handler for unknown protocol."""
        default_handler = MagicMock(spec=ProtocolHandler)
        router = ProtocolRouter(default_handler=default_handler)

        handler = router.get_handler(ProtocolType.UNKNOWN)

        assert handler is default_handler

    def test_get_handler_none(self) -> None:
        """Test getting handler when none registered."""
        router = ProtocolRouter()

        handler = router.get_handler(ProtocolType.HTTP2)

        assert handler is None

    @pytest.mark.asyncio
    async def test_route_connection(self) -> None:
        """Test routing a connection to appropriate handler."""
        router = ProtocolRouter()

        # Create mock handler
        mock_handler = MagicMock(spec=ProtocolHandler)
        mock_handler.handle_connection = AsyncMock()
        router.register_handler(ProtocolType.HTTP1, mock_handler)

        # Create mock reader/writer
        reader = AsyncMock(spec=asyncio.StreamReader)
        reader.read = AsyncMock(return_value=b"GET / HTTP/1.1\r\n")

        writer = MagicMock(spec=asyncio.StreamWriter)
        writer.close = MagicMock()
        writer.wait_closed = AsyncMock()

        await router.route_connection(reader, writer)

        mock_handler.handle_connection.assert_called_once()


# ==============================================================================
# Message Serialization Tests
# ==============================================================================


class TestMessageSerialization:
    """Tests for new message type serialization."""

    def test_tcp_tunnel_open_message(self) -> None:
        """Test TcpTunnelOpen message serialization."""
        msg = TcpTunnelOpen(
            target_host="example.com",
            target_port=8080,
            protocol=TunnelProtocol.TCP,
        )

        encoded = encode_message(msg)
        decoded = parse_message(encoded)

        assert decoded.type == "tcp_tunnel_open"
        assert decoded.target_host == "example.com"
        assert decoded.target_port == 8080

    def test_tcp_tunnel_opened_message(self) -> None:
        """Test TcpTunnelOpened message serialization."""
        tunnel_id = uuid4()
        msg = TcpTunnelOpened(
            tunnel_id=tunnel_id,
            success=True,
        )

        encoded = encode_message(msg)
        decoded = parse_message(encoded)

        assert decoded.type == "tcp_tunnel_opened"
        assert decoded.tunnel_id == tunnel_id
        assert decoded.success is True

    def test_tcp_data_message(self) -> None:
        """Test TcpData message serialization."""
        tunnel_id = uuid4()
        msg = TcpData(
            tunnel_id=tunnel_id,
            sequence=42,
            data=b"raw tcp data here",
            is_final=False,
        )

        encoded = encode_message(msg)
        decoded = parse_message(encoded)

        assert decoded.type == "tcp_data"
        assert decoded.tunnel_id == tunnel_id
        assert decoded.sequence == 42
        assert decoded.data == b"raw tcp data here"

    def test_udp_tunnel_open_message(self) -> None:
        """Test UdpTunnelOpen message serialization."""
        msg = UdpTunnelOpen(
            target_host="8.8.8.8",
            target_port=53,
        )

        encoded = encode_message(msg)
        decoded = parse_message(encoded)

        assert decoded.type == "udp_tunnel_open"
        assert decoded.target_host == "8.8.8.8"
        assert decoded.target_port == 53

    def test_udp_datagram_message(self) -> None:
        """Test UdpDatagram message serialization."""
        tunnel_id = uuid4()
        msg = UdpDatagramMessage(
            tunnel_id=tunnel_id,
            sequence=1,
            data=b"\x00\x01\x02\x03",
            source_port=12345,
            dest_port=53,
        )

        encoded = encode_message(msg)
        decoded = parse_message(encoded)

        assert decoded.type == "udp_datagram"
        assert decoded.data == b"\x00\x01\x02\x03"
        assert decoded.source_port == 12345
        assert decoded.dest_port == 53

    def test_websocket_upgrade_message(self) -> None:
        """Test WebSocketUpgrade message serialization."""
        msg = WebSocketUpgrade(
            path="/ws",
            headers={"Host": "example.com", "Origin": "http://example.com"},
            subprotocols=["chat", "superchat"],
        )

        encoded = encode_message(msg)
        decoded = parse_message(encoded)

        assert decoded.type == "websocket_upgrade"
        assert decoded.path == "/ws"
        assert decoded.headers["Host"] == "example.com"
        assert "chat" in decoded.subprotocols

    def test_websocket_upgrade_response_message(self) -> None:
        """Test WebSocketUpgradeResponse message serialization."""
        tunnel_id = uuid4()
        request_id = uuid4()
        msg = WebSocketUpgradeResponse(
            tunnel_id=tunnel_id,
            request_id=request_id,
            success=True,
            accepted_protocol="chat",
        )

        encoded = encode_message(msg)
        decoded = parse_message(encoded)

        assert decoded.type == "websocket_upgrade_response"
        assert decoded.success is True
        assert decoded.accepted_protocol == "chat"

    def test_websocket_frame_message(self) -> None:
        """Test WebSocketFrame message serialization."""
        tunnel_id = uuid4()
        msg = WebSocketFrameMessage(
            tunnel_id=tunnel_id,
            sequence=10,
            opcode=WsOpcode.TEXT,
            payload=b"hello websocket",
            fin=True,
        )

        encoded = encode_message(msg)
        decoded = parse_message(encoded)

        assert decoded.type == "websocket_frame"
        assert decoded.opcode == WsOpcode.TEXT
        assert decoded.payload == b"hello websocket"
        assert decoded.fin is True

    def test_websocket_close_message(self) -> None:
        """Test WebSocketClose message serialization."""
        tunnel_id = uuid4()
        msg = WebSocketClose(
            tunnel_id=tunnel_id,
            code=1000,
            reason="Normal closure",
        )

        encoded = encode_message(msg)
        decoded = parse_message(encoded)

        assert decoded.type == "websocket_close"
        assert decoded.code == 1000
        assert decoded.reason == "Normal closure"

    def test_grpc_stream_open_message(self) -> None:
        """Test GrpcStreamOpen message serialization."""
        msg = GrpcStreamOpen(
            service="helloworld.Greeter",
            method="SayHello",
            headers={"authorization": "Bearer token"},
            timeout_ms=5000,
        )

        encoded = encode_message(msg)
        decoded = parse_message(encoded)

        assert decoded.type == "grpc_stream_open"
        assert decoded.service == "helloworld.Greeter"
        assert decoded.method == "SayHello"
        assert decoded.timeout_ms == 5000

    def test_grpc_stream_opened_message(self) -> None:
        """Test GrpcStreamOpened message serialization."""
        tunnel_id = uuid4()
        stream_id = uuid4()
        msg = GrpcStreamOpened(
            tunnel_id=tunnel_id,
            stream_id=stream_id,
            success=True,
            headers={"content-type": "application/grpc"},
        )

        encoded = encode_message(msg)
        decoded = parse_message(encoded)

        assert decoded.type == "grpc_stream_opened"
        assert decoded.success is True

    def test_grpc_frame_message(self) -> None:
        """Test GrpcFrame message serialization."""
        tunnel_id = uuid4()
        stream_id = uuid4()
        msg = GrpcFrameMessage(
            tunnel_id=tunnel_id,
            stream_id=stream_id,
            sequence=5,
            compressed=False,
            data=b"\x0a\x05hello",
            is_final=False,
        )

        encoded = encode_message(msg)
        decoded = parse_message(encoded)

        assert decoded.type == "grpc_frame"
        assert decoded.compressed is False
        assert decoded.data == b"\x0a\x05hello"

    def test_grpc_trailers_message(self) -> None:
        """Test GrpcTrailers message serialization."""
        tunnel_id = uuid4()
        stream_id = uuid4()
        msg = GrpcTrailers(
            tunnel_id=tunnel_id,
            stream_id=stream_id,
            status=0,
            message="OK",
            trailers={"grpc-status": "0", "grpc-message": "OK"},
        )

        encoded = encode_message(msg)
        decoded = parse_message(encoded)

        assert decoded.type == "grpc_trailers"
        assert decoded.status == 0
        assert decoded.message == "OK"

    def test_grpc_stream_close_message(self) -> None:
        """Test GrpcStreamClose message serialization."""
        tunnel_id = uuid4()
        stream_id = uuid4()
        msg = GrpcStreamClose(
            tunnel_id=tunnel_id,
            stream_id=stream_id,
            status=0,
            message="Stream completed",
        )

        encoded = encode_message(msg)
        decoded = parse_message(encoded)

        assert decoded.type == "grpc_stream_close"
        assert decoded.status == 0


# ==============================================================================
# Integration-style Tests
# ==============================================================================


class TestProtocolIntegration:
    """Integration tests for protocol handling."""

    @pytest.mark.asyncio
    async def test_websocket_handler_close(self) -> None:
        """Test WebSocket handler close method."""
        handler = WebSocketHandler()
        handler._closed = False
        handler._ping_task = None
        handler._writer = None

        await handler.close()

        assert handler._closed is True

    @pytest.mark.asyncio
    async def test_tcp_handler_close(self) -> None:
        """Test TCP handler close method."""
        handler = TcpTunnelHandler(
            target_host="localhost",
            target_port=80,
        )

        await handler.close()

        assert handler._closed is True

    @pytest.mark.asyncio
    async def test_grpc_handler_close(self) -> None:
        """Test gRPC handler close method."""
        handler = GrpcPassthroughHandler(
            target_host="localhost",
            target_port=50051,
        )

        await handler.close()

        assert handler._closed is True

    @pytest.mark.asyncio
    async def test_udp_handler_close(self) -> None:
        """Test UDP handler close method."""
        handler = UdpHandler(
            target_host="localhost",
            target_port=53,
        )

        await handler.close()

        assert handler._closed is True

    @pytest.mark.asyncio
    async def test_router_close_all(self) -> None:
        """Test router closing all handlers."""
        router = ProtocolRouter()

        handler1 = MagicMock(spec=ProtocolHandler)
        handler1.close = AsyncMock()
        handler2 = MagicMock(spec=ProtocolHandler)
        handler2.close = AsyncMock()

        router.register_handler(ProtocolType.TCP, handler1)
        router.register_handler(ProtocolType.UDP, handler2)

        await router.close_all()

        handler1.close.assert_called_once()
        handler2.close.assert_called_once()


# ==============================================================================
# Edge Cases and Error Handling Tests
# ==============================================================================


class TestEdgeCases:
    """Tests for edge cases and error handling."""

    def test_protocol_detection_result_defaults(self) -> None:
        """Test ProtocolDetectionResult default values."""
        result = ProtocolDetectionResult(
            protocol=ProtocolType.HTTP1,
            confidence=0.8,
        )

        assert result.is_tls is False
        assert result.http_version is None
        assert result.is_grpc is False
        assert result.is_websocket_upgrade is False
        assert result.content_type is None
        assert result.extra_data == {}

    def test_websocket_frame_defaults(self) -> None:
        """Test WebSocketFrame default values."""
        frame = WebSocketFrame(
            opcode=WebSocketOpcode.TEXT,
            payload=b"test",
        )

        assert frame.fin is True
        assert frame.rsv1 is False
        assert frame.rsv2 is False
        assert frame.rsv3 is False
        assert frame.mask_key is None

    def test_grpc_frame_dataclass(self) -> None:
        """Test GrpcFrame dataclass."""
        frame = GrpcFrame(
            compressed=True,
            length=100,
            data=b"x" * 100,
        )

        assert frame.compressed is True
        assert frame.length == 100
        assert len(frame.data) == 100

    def test_tunnel_protocol_enum(self) -> None:
        """Test TunnelProtocol enum values."""
        assert TunnelProtocol.HTTP1 == 1
        assert TunnelProtocol.HTTP2 == 2
        assert TunnelProtocol.GRPC == 3
        assert TunnelProtocol.WEBSOCKET == 4
        assert TunnelProtocol.TCP == 5
        assert TunnelProtocol.UDP == 6

    def test_websocket_opcode_enum(self) -> None:
        """Test WebSocketOpcode enum values."""
        assert WsOpcode.CONTINUATION == 0x0
        assert WsOpcode.TEXT == 0x1
        assert WsOpcode.BINARY == 0x2
        assert WsOpcode.CLOSE == 0x8
        assert WsOpcode.PING == 0x9
        assert WsOpcode.PONG == 0xA
