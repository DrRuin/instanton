"""Tests for fast protocol messages using msgspec."""

from uuid import uuid4

import pytest

from instanton.protocol.fast_messages import (
    CHUNK_SIZE,
    MAGIC,
    MAX_MESSAGE_SIZE,
    MIN_COMPRESSION_SIZE,
    PROTOCOL_VERSION,
    ChunkData,
    ChunkStart,
    CompressionType,
    ConnectRequest,
    ConnectResponse,
    ErrorCode,
    FastChunkAssembler,
    FastProtocolNegotiator,
    GrpcFrame,
    GrpcTrailers,
    HttpRequest,
    HttpResponse,
    MessageType,
    NegotiateRequest,
    NegotiateResponse,
    Ping,
    Pong,
    TcpData,
    TcpOpen,
    UdpDatagram,
    WsFrame,
    compress_fast,
    create_chunks_fast,
    decode_fast,
    decompress_fast,
    encode_fast,
    get_codec,
)

# ==============================================================================
# Compression Tests
# ==============================================================================


class TestCompression:
    """Tests for compression functions."""

    def test_compress_decompress_lz4(self):
        """Test LZ4 compression round-trip."""
        original = b"Hello World! " * 100
        compressed = compress_fast(original, CompressionType.LZ4)
        decompressed = decompress_fast(compressed, CompressionType.LZ4)

        assert decompressed == original
        assert len(compressed) < len(original)

    def test_compress_decompress_zstd(self):
        """Test ZSTD compression round-trip."""
        original = b"Hello World! " * 100
        compressed = compress_fast(original, CompressionType.ZSTD)
        decompressed = decompress_fast(compressed, CompressionType.ZSTD)

        assert decompressed == original
        assert len(compressed) < len(original)

    def test_compress_none(self):
        """Test no compression returns unchanged."""
        original = b"Hello World!"
        result = compress_fast(original, CompressionType.NONE)
        assert result == original

    def test_small_data_not_compressed(self):
        """Test small data is not compressed."""
        small_data = b"Hi"
        result = compress_fast(small_data, CompressionType.ZSTD)
        # Small data should not be compressed
        assert result == small_data


# ==============================================================================
# FastCodec Tests
# ==============================================================================


class TestFastCodec:
    """Tests for FastCodec."""

    def test_codec_singleton(self):
        """Test global codec singleton."""
        codec1 = get_codec()
        codec2 = get_codec()
        assert codec1 is codec2

    def test_encode_decode_ping(self):
        """Test encoding/decoding ping message."""
        ping = Ping(ts=12345678)
        encoded = encode_fast(ping)
        decoded = decode_fast(encoded)

        assert isinstance(decoded, Ping)
        assert decoded.ts == 12345678

    def test_encode_decode_pong(self):
        """Test encoding/decoding pong message."""
        pong = Pong(ts=12345678, server_ts=12345679)
        encoded = encode_fast(pong)
        decoded = decode_fast(encoded)

        assert isinstance(decoded, Pong)
        assert decoded.ts == 12345678
        assert decoded.server_ts == 12345679

    def test_encode_decode_connect_request(self):
        """Test ConnectRequest encoding/decoding."""
        request = ConnectRequest(subdomain="test", local_port=8080)
        encoded = encode_fast(request)
        decoded = decode_fast(encoded)

        assert isinstance(decoded, ConnectRequest)
        assert decoded.subdomain == "test"
        assert decoded.local_port == 8080

    def test_encode_decode_connect_response(self):
        """Test ConnectResponse encoding/decoding."""
        tunnel_id = str(uuid4())
        response = ConnectResponse(
            tunnel_id=tunnel_id,
            subdomain="abc123",
            url="https://abc123.instanton.dev",
        )
        encoded = encode_fast(response)
        decoded = decode_fast(encoded)

        assert isinstance(decoded, ConnectResponse)
        assert decoded.subdomain == "abc123"
        assert decoded.url == "https://abc123.instanton.dev"

    def test_encode_decode_http_request(self):
        """Test HttpRequest encoding/decoding."""
        request_id = str(uuid4())
        request = HttpRequest(
            request_id=request_id,
            method="POST",
            path="/api/test",
            headers={"Content-Type": "application/json"},
            body=b'{"test": true}',
        )
        encoded = encode_fast(request)
        decoded = decode_fast(encoded)

        assert isinstance(decoded, HttpRequest)
        assert decoded.method == "POST"
        assert decoded.path == "/api/test"
        assert decoded.headers["Content-Type"] == "application/json"

    def test_encode_decode_http_response(self):
        """Test HttpResponse encoding/decoding."""
        request_id = str(uuid4())
        response = HttpResponse(
            request_id=request_id,
            status=200,
            headers={"Content-Type": "text/plain"},
            body=b"Hello World",
        )
        encoded = encode_fast(response)
        decoded = decode_fast(encoded)

        assert isinstance(decoded, HttpResponse)
        assert decoded.status == 200

    def test_frame_format_small(self):
        """Test frame format for small messages."""
        ping = Ping(ts=12345)
        encoded = encode_fast(ping)

        # Check magic bytes
        assert encoded[:4] == MAGIC
        # Check flags (compression bits + extended length bit)
        flags = encoded[4]
        use_extended = bool(flags & 0x04)
        assert not use_extended  # Small message

    def test_frame_format_compressed(self):
        """Test frame format with compression."""
        # Create large message to trigger compression
        request = HttpRequest(
            request_id=str(uuid4()),
            method="POST",
            path="/api/test",
            body=b"x" * 2000,
        )
        encoded = encode_fast(request, CompressionType.ZSTD)

        # Check compression flag
        flags = encoded[4]
        compression = flags & 0x03
        assert compression == CompressionType.ZSTD

    def test_decode_type(self):
        """Test decoding just message type."""
        codec = get_codec()
        ping = Ping(ts=12345)
        encoded = encode_fast(ping)

        msg_type = codec.decode_type(encoded)
        assert msg_type == MessageType.PING

    def test_invalid_magic(self):
        """Test invalid magic bytes detection."""
        data = b"XXXX" + b"\x00\x00\x00\x00\x00\x00\x00"
        with pytest.raises(ValueError, match="Invalid magic"):
            decode_fast(data)

    def test_message_too_short(self):
        """Test short message detection."""
        with pytest.raises(ValueError, match="too short"):
            decode_fast(b"TACH")


# ==============================================================================
# Negotiation Tests
# ==============================================================================


class TestNegotiation:
    """Tests for protocol negotiation."""

    def test_negotiate_request_encode_decode(self):
        """Test NegotiateRequest round-trip."""
        request = NegotiateRequest(
            client_version=PROTOCOL_VERSION,
            compressions=(
                CompressionType.NONE,
                CompressionType.LZ4,
                CompressionType.ZSTD,
            ),
            streaming=True,
            chunk_size=65536,
        )
        encoded = encode_fast(request)
        decoded = decode_fast(encoded)

        assert isinstance(decoded, NegotiateRequest)
        assert decoded.client_version == PROTOCOL_VERSION
        assert decoded.streaming is True

    def test_negotiate_response_encode_decode(self):
        """Test NegotiateResponse round-trip."""
        response = NegotiateResponse(
            server_version=PROTOCOL_VERSION,
            compression=CompressionType.ZSTD,
            streaming=True,
            chunk_size=65536,
            success=True,
        )
        encoded = encode_fast(response)
        decoded = decode_fast(encoded)

        assert isinstance(decoded, NegotiateResponse)
        assert decoded.compression == CompressionType.ZSTD
        assert decoded.success is True

    def test_negotiator_create_request(self):
        """Test FastProtocolNegotiator request creation."""
        negotiator = FastProtocolNegotiator(
            supported_compressions=(CompressionType.LZ4, CompressionType.ZSTD),
            supports_streaming=True,
            max_chunk_size=32768,
        )
        request = negotiator.create_request()

        assert request.client_version == PROTOCOL_VERSION
        assert CompressionType.LZ4 in request.compressions
        assert CompressionType.ZSTD in request.compressions
        assert request.streaming is True
        assert request.chunk_size == 32768

    def test_negotiator_handle_request_success(self):
        """Test server handling negotiation request."""
        server = FastProtocolNegotiator()
        request = NegotiateRequest(
            client_version=PROTOCOL_VERSION,
            compressions=(CompressionType.NONE, CompressionType.LZ4, CompressionType.ZSTD),
            streaming=True,
            chunk_size=CHUNK_SIZE,
        )

        response = server.handle_request(request)

        assert response.success is True
        assert response.compression == CompressionType.ZSTD  # Preferred
        assert server.negotiated_compression == CompressionType.ZSTD

    def test_negotiator_version_mismatch(self):
        """Test version mismatch handling."""
        server = FastProtocolNegotiator()
        request = NegotiateRequest(
            client_version=PROTOCOL_VERSION + 10,
            compressions=(CompressionType.NONE,),
            streaming=True,
            chunk_size=CHUNK_SIZE,
        )

        response = server.handle_request(request)

        assert response.success is False
        assert "not supported" in response.error

    def test_negotiator_apply_response(self):
        """Test client applying negotiation response."""
        client = FastProtocolNegotiator()
        response = NegotiateResponse(
            server_version=PROTOCOL_VERSION,
            compression=CompressionType.LZ4,
            streaming=True,
            chunk_size=32768,
            success=True,
        )

        success = client.apply_response(response)

        assert success is True
        assert client.negotiated_compression == CompressionType.LZ4
        assert client.streaming_enabled is True
        assert client.chunk_size == 32768


# ==============================================================================
# Streaming Chunk Tests
# ==============================================================================


class TestStreaming:
    """Tests for streaming chunk functionality."""

    def test_chunk_start_encode_decode(self):
        """Test ChunkStart round-trip."""
        request_id = str(uuid4())
        stream_id = str(uuid4())
        start = ChunkStart(
            stream_id=stream_id,
            request_id=request_id,
            total_size=10000,
            content_type="application/octet-stream",
        )

        encoded = encode_fast(start)
        decoded = decode_fast(encoded)

        assert isinstance(decoded, ChunkStart)
        assert decoded.total_size == 10000

    def test_chunk_data_encode_decode(self):
        """Test ChunkData round-trip."""
        stream_id = str(uuid4())
        chunk = ChunkData(
            stream_id=stream_id,
            seq=5,
            data=b"Hello World",
            final=False,
        )

        encoded = encode_fast(chunk)
        decoded = decode_fast(encoded)

        assert isinstance(decoded, ChunkData)
        assert decoded.seq == 5
        assert decoded.data == b"Hello World"
        assert decoded.final is False

    def test_create_chunks_small_data(self):
        """Test creating chunks for small data."""
        request_id = str(uuid4())
        data = b"Hello World"

        start, chunks, end = create_chunks_fast(data, request_id, chunk_size=100)

        assert start.total_size == len(data)
        assert len(chunks) == 1
        assert chunks[0].data == data
        assert chunks[0].final is True
        assert end.chunks == 1

    def test_create_chunks_large_data(self):
        """Test creating chunks for large data."""
        request_id = str(uuid4())
        data = b"x" * 1000
        chunk_size = 100

        start, chunks, end = create_chunks_fast(data, request_id, chunk_size=chunk_size)

        assert start.total_size == 1000
        assert len(chunks) == 10
        assert end.chunks == 10

        # Verify sequences
        for i, chunk in enumerate(chunks):
            assert chunk.seq == i

        # Verify only last is final
        for chunk in chunks[:-1]:
            assert chunk.final is False
        assert chunks[-1].final is True

        # Verify reassembly
        reassembled = b"".join(c.data for c in chunks)
        assert reassembled == data

    def test_chunk_assembler(self):
        """Test FastChunkAssembler."""
        assembler = FastChunkAssembler()
        request_id = str(uuid4())
        data = b"Hello World!"

        start, chunks, end = create_chunks_fast(data, request_id, chunk_size=4)

        assembler.start_stream(start)

        for chunk in chunks:
            assembler.add_chunk(chunk)

        result = assembler.end_stream(end)
        assert result == data

    def test_chunk_assembler_out_of_order(self):
        """Test assembler handles out-of-order chunks."""
        assembler = FastChunkAssembler()
        request_id = str(uuid4())
        data = b"ABCDEFGHIJ"

        start, chunks, end = create_chunks_fast(data, request_id, chunk_size=2)

        assembler.start_stream(start)

        # Add in reverse order
        for chunk in reversed(chunks):
            assembler.add_chunk(chunk)

        result = assembler.end_stream(end)
        assert result == data


# ==============================================================================
# Protocol Message Tests
# ==============================================================================


class TestTcpMessages:
    """Tests for TCP tunnel messages."""

    def test_tcp_open(self):
        """Test TcpOpen message."""
        msg = TcpOpen(tunnel_id="test123", host="localhost", port=3306)
        encoded = encode_fast(msg)
        decoded = decode_fast(encoded)

        assert isinstance(decoded, TcpOpen)
        assert decoded.host == "localhost"
        assert decoded.port == 3306

    def test_tcp_data(self):
        """Test TcpData message."""
        msg = TcpData(tunnel_id="test123", seq=0, data=b"hello", final=False)
        encoded = encode_fast(msg)
        decoded = decode_fast(encoded)

        assert isinstance(decoded, TcpData)
        assert decoded.data == b"hello"


class TestUdpMessages:
    """Tests for UDP tunnel messages."""

    def test_udp_datagram(self):
        """Test UdpDatagram message."""
        msg = UdpDatagram(tunnel_id="test123", seq=0, data=b"packet")
        encoded = encode_fast(msg)
        decoded = decode_fast(encoded)

        assert isinstance(decoded, UdpDatagram)
        assert decoded.data == b"packet"


class TestWebSocketMessages:
    """Tests for WebSocket messages."""

    def test_ws_frame(self):
        """Test WsFrame message."""
        msg = WsFrame(
            tunnel_id="test123",
            seq=0,
            opcode=2,
            payload=b"binary data",
            fin=True,
        )
        encoded = encode_fast(msg)
        decoded = decode_fast(encoded)

        assert isinstance(decoded, WsFrame)
        assert decoded.payload == b"binary data"
        assert decoded.opcode == 2


class TestGrpcMessages:
    """Tests for gRPC messages."""

    def test_grpc_frame(self):
        """Test GrpcFrame message."""
        msg = GrpcFrame(
            tunnel_id="test123",
            stream_id="stream456",
            seq=0,
            compressed=False,
            data=b"protobuf data",
            final=False,
        )
        encoded = encode_fast(msg)
        decoded = decode_fast(encoded)

        assert isinstance(decoded, GrpcFrame)
        assert decoded.data == b"protobuf data"

    def test_grpc_trailers(self):
        """Test GrpcTrailers message."""
        msg = GrpcTrailers(
            tunnel_id="test123",
            stream_id="stream456",
            status=0,
            message="OK",
            trailers={"grpc-status": "0"},
        )
        encoded = encode_fast(msg)
        decoded = decode_fast(encoded)

        assert isinstance(decoded, GrpcTrailers)
        assert decoded.status == 0


# ==============================================================================
# Error Code Tests
# ==============================================================================


class TestErrorCodes:
    """Tests for error codes."""

    def test_error_codes_values(self):
        """Test error code values."""
        assert ErrorCode.SUBDOMAIN_TAKEN == 1
        assert ErrorCode.AUTH_FAILED == 4
        assert ErrorCode.INTERNAL_ERROR == 255

    def test_error_response(self):
        """Test error in ConnectResponse."""
        response = ConnectResponse(
            type=MessageType.ERROR,
            error="Subdomain taken",
            error_code=ErrorCode.SUBDOMAIN_TAKEN,
        )
        encoded = encode_fast(response)
        decoded = decode_fast(encoded)

        assert decoded.error == "Subdomain taken"
        assert decoded.error_code == ErrorCode.SUBDOMAIN_TAKEN


# ==============================================================================
# Protocol Constants Tests
# ==============================================================================


class TestProtocolConstants:
    """Tests for protocol constants."""

    def test_constants(self):
        """Test protocol constants are correctly defined."""
        assert MAGIC == b"TACH"
        assert PROTOCOL_VERSION == 3
        assert MAX_MESSAGE_SIZE == 16 * 1024 * 1024
        assert CHUNK_SIZE == 64 * 1024
        assert MIN_COMPRESSION_SIZE == 512
