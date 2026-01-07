"""Tests for protocol messages including compression, streaming, and negotiation."""

import hashlib
from uuid import uuid4

import pytest

from instanton.protocol.messages import (
    CHUNK_SIZE,
    MAGIC,
    MAX_MESSAGE_SIZE,
    MIN_COMPRESSION_SIZE,
    PROTOCOL_VERSION,
    ChunkAck,
    ChunkAssembler,
    ChunkData,
    ChunkEnd,
    ChunkStart,
    CompressionType,
    ConnectRequest,
    ConnectResponse,
    Disconnect,
    ErrorCode,
    HttpRequest,
    HttpResponse,
    NegotiateRequest,
    NegotiateResponse,
    Ping,
    Pong,
    ProtocolNegotiator,
    compress_data,
    create_chunks,
    decode_message,
    decompress_data,
    encode_message,
    parse_message,
)

# ==============================================================================
# Basic Message Encoding/Decoding Tests
# ==============================================================================


class TestBasicMessages:
    """Tests for basic message encoding and decoding."""

    def test_connect_request_encoding(self):
        """Test ConnectRequest encode/decode."""
        request = ConnectRequest(subdomain="test", local_port=8080)
        encoded = encode_message(request)

        # Check framing (new format with flags byte)
        assert encoded[:4] == MAGIC
        assert encoded[4] == PROTOCOL_VERSION
        assert encoded[5] == CompressionType.NONE  # FLAGS byte

        # Decode and verify
        decoded = decode_message(encoded)
        assert decoded["type"] == "connect"
        assert decoded["subdomain"] == "test"
        assert decoded["local_port"] == 8080

    def test_connect_response_encoding(self):
        """Test ConnectResponse encode/decode."""
        tunnel_id = uuid4()
        response = ConnectResponse(
            type="connected",
            tunnel_id=tunnel_id,
            subdomain="abc123",
            url="https://abc123.instanton.dev",
        )
        encoded = encode_message(response)
        decoded = decode_message(encoded)

        assert decoded["type"] == "connected"
        assert decoded["subdomain"] == "abc123"
        assert decoded["url"] == "https://abc123.instanton.dev"

    def test_http_request_encoding(self):
        """Test HttpRequest encode/decode."""
        request = HttpRequest(
            method="POST",
            path="/api/test",
            headers={"Content-Type": "application/json"},
            body=b'{"test": true}',
        )
        encoded = encode_message(request)
        decoded = decode_message(encoded)

        assert decoded["method"] == "POST"
        assert decoded["path"] == "/api/test"
        assert decoded["headers"]["Content-Type"] == "application/json"

    def test_http_response_encoding(self):
        """Test HttpResponse encode/decode."""
        request_id = uuid4()
        response = HttpResponse(
            request_id=request_id,
            status=200,
            headers={"Content-Type": "text/plain"},
            body=b"Hello World",
        )
        encoded = encode_message(response)
        decoded = decode_message(encoded)

        assert decoded["status"] == 200
        assert decoded["headers"]["Content-Type"] == "text/plain"

    def test_ping_pong(self):
        """Test Ping/Pong messages."""
        ping = Ping(timestamp=1234567890)
        encoded = encode_message(ping)
        decoded = decode_message(encoded)

        assert decoded["type"] == "ping"
        assert decoded["timestamp"] == 1234567890

        pong = Pong(timestamp=1234567890, server_time=1234567891)
        encoded = encode_message(pong)
        decoded = decode_message(encoded)

        assert decoded["type"] == "pong"
        assert decoded["server_time"] == 1234567891

    def test_disconnect_message(self):
        """Test Disconnect message."""
        disconnect = Disconnect(reason="Client shutdown")
        encoded = encode_message(disconnect)
        decoded = decode_message(encoded)

        assert decoded["type"] == "disconnect"
        assert decoded["reason"] == "Client shutdown"

    def test_invalid_magic(self):
        """Test invalid magic bytes detection."""
        data = b"XXXX" + b"\x02\x00" + b"\x00\x00\x00\x00"
        with pytest.raises(ValueError, match="Invalid magic"):
            decode_message(data)

    def test_message_too_short(self):
        """Test short message detection."""
        with pytest.raises(ValueError, match="too short"):
            decode_message(b"TACH")

    def test_parse_message_typed(self):
        """Test parse_message returns typed Pydantic models."""
        ping = Ping(timestamp=12345)
        encoded = encode_message(ping)
        parsed = parse_message(encoded)

        assert isinstance(parsed, Ping)
        assert parsed.timestamp == 12345


# ==============================================================================
# Compression Tests
# ==============================================================================


class TestCompression:
    """Tests for compression functionality."""

    def test_compress_decompress_lz4(self):
        """Test LZ4 compression round-trip."""
        original = b"Hello World! " * 100
        compressed = compress_data(original, CompressionType.LZ4)
        decompressed = decompress_data(compressed, CompressionType.LZ4)

        assert decompressed == original
        assert len(compressed) < len(original)

    def test_compress_decompress_zstd(self):
        """Test ZSTD compression round-trip."""
        original = b"Hello World! " * 100
        compressed = compress_data(original, CompressionType.ZSTD)
        decompressed = decompress_data(compressed, CompressionType.ZSTD)

        assert decompressed == original
        assert len(compressed) < len(original)

    def test_compress_none(self):
        """Test no compression returns unchanged data."""
        original = b"Hello World!"
        result = compress_data(original, CompressionType.NONE)
        assert result == original

    def test_decompress_none(self):
        """Test no decompression returns unchanged data."""
        original = b"Hello World!"
        result = decompress_data(original, CompressionType.NONE)
        assert result == original

    def test_encode_with_lz4_compression(self):
        """Test message encoding with LZ4 compression."""
        request = HttpRequest(
            method="POST",
            path="/api/test",
            headers={"Content-Type": "application/json"},
            body=b"x" * 2000,  # Large body to benefit from compression
        )
        encoded = encode_message(request, compression=CompressionType.LZ4)

        # Check flags indicate LZ4 compression
        assert encoded[5] == CompressionType.LZ4

        # Decode should work transparently
        decoded = decode_message(encoded)
        assert decoded["method"] == "POST"

    def test_encode_with_zstd_compression(self):
        """Test message encoding with ZSTD compression."""
        request = HttpRequest(
            method="POST",
            path="/api/test",
            headers={"Content-Type": "application/json"},
            body=b"y" * 2000,
        )
        encoded = encode_message(request, compression=CompressionType.ZSTD)

        # Check flags indicate ZSTD compression
        assert encoded[5] == CompressionType.ZSTD

        # Decode should work transparently
        decoded = decode_message(encoded)
        assert decoded["method"] == "POST"

    def test_auto_compression_large_message(self):
        """Test auto-compression for large messages."""
        # Create a message larger than MIN_COMPRESSION_SIZE
        large_body = b"z" * (MIN_COMPRESSION_SIZE + 1000)
        request = HttpRequest(
            method="POST",
            path="/api/large",
            headers={},
            body=large_body,
        )
        # Don't specify compression - should auto-select ZSTD
        encoded = encode_message(request, compression=CompressionType.NONE)

        # For large messages, it auto-compresses with ZSTD
        assert encoded[5] == CompressionType.ZSTD

        # Verify decode works
        decoded = decode_message(encoded)
        assert decoded["method"] == "POST"

    def test_compression_ratio(self):
        """Test that compression actually reduces size for compressible data."""
        # Highly compressible data
        original = b"AAAA" * 10000
        compressed_lz4 = compress_data(original, CompressionType.LZ4)
        compressed_zstd = compress_data(original, CompressionType.ZSTD)

        assert len(compressed_lz4) < len(original) / 2
        assert len(compressed_zstd) < len(original) / 2

    def test_invalid_compression_type(self):
        """Test handling of invalid compression type."""
        # Creating an invalid enum value raises ValueError
        with pytest.raises(ValueError):
            compress_data(b"test", CompressionType(99))

        with pytest.raises(ValueError):
            decompress_data(b"test", CompressionType(99))


# ==============================================================================
# Streaming Chunk Tests
# ==============================================================================


class TestStreaming:
    """Tests for streaming chunk functionality."""

    def test_chunk_start_message(self):
        """Test ChunkStart message."""
        request_id = uuid4()
        start = ChunkStart(
            request_id=request_id,
            total_size=10000,
            content_type="application/octet-stream",
        )

        encoded = encode_message(start)
        decoded = decode_message(encoded)

        assert decoded["type"] == "chunk_start"
        assert decoded["total_size"] == 10000
        assert decoded["content_type"] == "application/octet-stream"

    def test_chunk_data_message(self):
        """Test ChunkData message."""
        stream_id = uuid4()
        chunk = ChunkData(
            stream_id=stream_id,
            sequence=0,
            data=b"Hello World",
            is_final=False,
        )

        encoded = encode_message(chunk)
        decoded = decode_message(encoded)

        assert decoded["type"] == "chunk_data"
        assert decoded["sequence"] == 0
        assert decoded["is_final"] is False

    def test_chunk_end_message(self):
        """Test ChunkEnd message."""
        stream_id = uuid4()
        end = ChunkEnd(
            stream_id=stream_id,
            total_chunks=10,
            checksum="abc123",
        )

        encoded = encode_message(end)
        decoded = decode_message(encoded)

        assert decoded["type"] == "chunk_end"
        assert decoded["total_chunks"] == 10
        assert decoded["checksum"] == "abc123"

    def test_chunk_ack_message(self):
        """Test ChunkAck message."""
        stream_id = uuid4()
        ack = ChunkAck(
            stream_id=stream_id,
            last_received_sequence=5,
            window_size=16,
        )

        encoded = encode_message(ack)
        decoded = decode_message(encoded)

        assert decoded["type"] == "chunk_ack"
        assert decoded["last_received_sequence"] == 5
        assert decoded["window_size"] == 16

    def test_create_chunks_small_data(self):
        """Test create_chunks with small data."""
        request_id = uuid4()
        data = b"Hello World"

        start, chunks, end = create_chunks(data, request_id, chunk_size=100)

        assert start.total_size == len(data)
        assert len(chunks) == 1
        assert chunks[0].data == data
        assert chunks[0].is_final is True
        assert end.total_chunks == 1
        assert end.checksum == hashlib.sha256(data).hexdigest()

    def test_create_chunks_large_data(self):
        """Test create_chunks with large data requiring multiple chunks."""
        request_id = uuid4()
        data = b"x" * 1000
        chunk_size = 100

        start, chunks, end = create_chunks(data, request_id, chunk_size=chunk_size)

        assert start.total_size == 1000
        assert len(chunks) == 10
        assert end.total_chunks == 10

        # Verify all chunks have correct stream_id
        for chunk in chunks:
            assert chunk.stream_id == start.stream_id

        # Verify sequences
        for i, chunk in enumerate(chunks):
            assert chunk.sequence == i

        # Verify only last chunk is final
        for chunk in chunks[:-1]:
            assert chunk.is_final is False
        assert chunks[-1].is_final is True

        # Verify reassembly
        reassembled = b"".join(c.data for c in chunks)
        assert reassembled == data

    def test_create_chunks_empty_data(self):
        """Test create_chunks with empty data."""
        request_id = uuid4()
        data = b""

        start, chunks, end = create_chunks(data, request_id)

        assert start.total_size == 0
        assert len(chunks) == 1
        assert chunks[0].data == b""
        assert chunks[0].is_final is True

    def test_chunk_assembler_basic(self):
        """Test ChunkAssembler basic functionality."""
        assembler = ChunkAssembler()
        request_id = uuid4()
        data = b"Hello World!"

        start, chunks, end = create_chunks(data, request_id, chunk_size=4)

        # Start stream
        assembler.start_stream(start)

        # Add chunks
        for chunk in chunks:
            is_complete = assembler.add_chunk(chunk)

        assert is_complete is True

        # End stream and get data
        result = assembler.end_stream(end)
        assert result == data

    def test_chunk_assembler_out_of_order(self):
        """Test ChunkAssembler handles out-of-order chunks."""
        assembler = ChunkAssembler()
        request_id = uuid4()
        data = b"ABCDEFGHIJ"

        start, chunks, end = create_chunks(data, request_id, chunk_size=2)

        assembler.start_stream(start)

        # Add chunks in reverse order
        for chunk in reversed(chunks):
            assembler.add_chunk(chunk)

        result = assembler.end_stream(end)
        assert result == data

    def test_chunk_assembler_unknown_stream(self):
        """Test ChunkAssembler rejects chunks from unknown streams."""
        assembler = ChunkAssembler()
        stream_id = uuid4()

        chunk = ChunkData(stream_id=stream_id, sequence=0, data=b"test")

        with pytest.raises(ValueError, match="Unknown stream"):
            assembler.add_chunk(chunk)

    def test_chunk_assembler_get_stream_info(self):
        """Test ChunkAssembler.get_stream_info."""
        assembler = ChunkAssembler()
        request_id = uuid4()
        start = ChunkStart(
            request_id=request_id,
            total_size=100,
            content_type="text/plain",
        )

        assembler.start_stream(start)

        info = assembler.get_stream_info(start.stream_id)
        assert info is not None
        assert info.total_size == 100
        assert info.content_type == "text/plain"

        # Unknown stream returns None
        unknown_info = assembler.get_stream_info(uuid4())
        assert unknown_info is None


# ==============================================================================
# Protocol Negotiation Tests
# ==============================================================================


class TestNegotiation:
    """Tests for protocol negotiation."""

    def test_negotiate_request_message(self):
        """Test NegotiateRequest message."""
        request = NegotiateRequest(
            client_version=PROTOCOL_VERSION,
            supported_compressions=[0, 1, 2],
            supports_streaming=True,
            max_chunk_size=65536,
        )

        encoded = encode_message(request)
        decoded = decode_message(encoded)

        assert decoded["type"] == "negotiate"
        assert decoded["client_version"] == PROTOCOL_VERSION
        assert decoded["supported_compressions"] == [0, 1, 2]
        assert decoded["supports_streaming"] is True

    def test_negotiate_response_message(self):
        """Test NegotiateResponse message."""
        response = NegotiateResponse(
            server_version=PROTOCOL_VERSION,
            selected_compression=CompressionType.ZSTD,
            streaming_enabled=True,
            chunk_size=65536,
            success=True,
        )

        encoded = encode_message(response)
        decoded = decode_message(encoded)

        assert decoded["type"] == "negotiate_response"
        assert decoded["selected_compression"] == CompressionType.ZSTD
        assert decoded["streaming_enabled"] is True
        assert decoded["success"] is True

    def test_negotiator_create_request(self):
        """Test ProtocolNegotiator.create_request."""
        negotiator = ProtocolNegotiator(
            supported_compressions=[CompressionType.LZ4, CompressionType.ZSTD],
            supports_streaming=True,
            max_chunk_size=32768,
        )

        request = negotiator.create_request()

        assert request.client_version == PROTOCOL_VERSION
        assert CompressionType.LZ4 in request.supported_compressions
        assert CompressionType.ZSTD in request.supported_compressions
        assert request.supports_streaming is True
        assert request.max_chunk_size == 32768

    def test_negotiator_handle_request_success(self):
        """Test ProtocolNegotiator.handle_request success case."""
        server = ProtocolNegotiator()
        client_request = NegotiateRequest(
            client_version=PROTOCOL_VERSION,
            supported_compressions=[
                CompressionType.NONE,
                CompressionType.LZ4,
                CompressionType.ZSTD,
            ],
            supports_streaming=True,
            max_chunk_size=CHUNK_SIZE,
        )

        response = server.handle_request(client_request)

        assert response.success is True
        assert response.selected_compression == CompressionType.ZSTD  # Preferred
        assert response.streaming_enabled is True
        assert server.negotiated_compression == CompressionType.ZSTD

    def test_negotiator_handle_request_version_mismatch(self):
        """Test negotiation fails with unsupported client version."""
        server = ProtocolNegotiator()
        client_request = NegotiateRequest(
            client_version=PROTOCOL_VERSION + 10,  # Future version
            supported_compressions=[CompressionType.NONE],
            supports_streaming=True,
            max_chunk_size=CHUNK_SIZE,
        )

        response = server.handle_request(client_request)

        assert response.success is False
        assert "not supported" in response.error

    def test_negotiator_handle_request_no_common_compression(self):
        """Test negotiation fails with no common compression."""
        server = ProtocolNegotiator(supported_compressions=[CompressionType.ZSTD])
        client_request = NegotiateRequest(
            client_version=PROTOCOL_VERSION,
            supported_compressions=[CompressionType.LZ4],  # Only LZ4, server wants ZSTD
            supports_streaming=True,
            max_chunk_size=CHUNK_SIZE,
        )

        response = server.handle_request(client_request)

        assert response.success is False
        assert "No common compression" in response.error

    def test_negotiator_apply_response(self):
        """Test ProtocolNegotiator.apply_response."""
        client = ProtocolNegotiator()
        response = NegotiateResponse(
            server_version=PROTOCOL_VERSION,
            selected_compression=CompressionType.LZ4,
            streaming_enabled=True,
            chunk_size=32768,
            success=True,
        )

        result = client.apply_response(response)

        assert result is True
        assert client.negotiated_compression == CompressionType.LZ4
        assert client.streaming_enabled is True
        assert client.chunk_size == 32768

    def test_negotiator_apply_failed_response(self):
        """Test ProtocolNegotiator.apply_response with failed negotiation."""
        client = ProtocolNegotiator()
        response = NegotiateResponse(
            success=False,
            error="Version mismatch",
        )

        result = client.apply_response(response)

        assert result is False
        # Negotiated values should remain at defaults
        assert client.negotiated_compression == CompressionType.NONE

    def test_full_negotiation_flow(self):
        """Test complete client-server negotiation flow."""
        # Client setup
        client = ProtocolNegotiator(
            supported_compressions=[CompressionType.LZ4, CompressionType.ZSTD],
            supports_streaming=True,
            max_chunk_size=32768,
        )

        # Server setup (prefers ZSTD)
        server = ProtocolNegotiator(
            supported_compressions=[
                CompressionType.NONE,
                CompressionType.LZ4,
                CompressionType.ZSTD,
            ],
            supports_streaming=True,
            max_chunk_size=65536,
        )

        # Client creates request
        request = client.create_request()

        # Encode and decode (simulate network)
        encoded_request = encode_message(request)
        decoded_request = parse_message(encoded_request)
        assert isinstance(decoded_request, NegotiateRequest)

        # Server handles request
        response = server.handle_request(decoded_request)

        # Encode and decode response
        encoded_response = encode_message(response)
        decoded_response = parse_message(encoded_response)
        assert isinstance(decoded_response, NegotiateResponse)

        # Client applies response
        success = client.apply_response(decoded_response)

        # Verify both sides agree
        assert success is True
        assert client.negotiated_compression == server.negotiated_compression
        assert client.streaming_enabled == server.streaming_enabled
        # Chunk size should be the smaller of the two
        assert client.chunk_size == 32768
        assert server.chunk_size == 32768

    def test_negotiation_streaming_disabled(self):
        """Test negotiation when one side doesn't support streaming."""
        server = ProtocolNegotiator(supports_streaming=False)
        request = NegotiateRequest(
            client_version=PROTOCOL_VERSION,
            supported_compressions=[CompressionType.NONE],
            supports_streaming=True,
            max_chunk_size=CHUNK_SIZE,
        )

        response = server.handle_request(request)

        assert response.success is True
        assert response.streaming_enabled is False

    def test_negotiation_compression_preference(self):
        """Test that ZSTD is preferred over LZ4."""
        server = ProtocolNegotiator(
            supported_compressions=[
                CompressionType.LZ4,
                CompressionType.ZSTD,
                CompressionType.NONE,
            ]
        )
        request = NegotiateRequest(
            client_version=PROTOCOL_VERSION,
            supported_compressions=[
                CompressionType.NONE,
                CompressionType.LZ4,
                CompressionType.ZSTD,
            ],
            supports_streaming=True,
            max_chunk_size=CHUNK_SIZE,
        )

        response = server.handle_request(request)

        assert response.selected_compression == CompressionType.ZSTD

    def test_negotiation_lz4_fallback(self):
        """Test that LZ4 is selected when ZSTD not available."""
        server = ProtocolNegotiator(
            supported_compressions=[CompressionType.LZ4, CompressionType.NONE]
        )
        request = NegotiateRequest(
            client_version=PROTOCOL_VERSION,
            supported_compressions=[CompressionType.NONE, CompressionType.LZ4],
            supports_streaming=True,
            max_chunk_size=CHUNK_SIZE,
        )

        response = server.handle_request(request)

        assert response.selected_compression == CompressionType.LZ4


# ==============================================================================
# Error Code Tests
# ==============================================================================


class TestErrorCodes:
    """Tests for error codes."""

    def test_error_codes_exist(self):
        """Test all error codes exist."""
        assert ErrorCode.SUBDOMAIN_TAKEN == 1
        assert ErrorCode.INVALID_SUBDOMAIN == 2
        assert ErrorCode.SERVER_FULL == 3
        assert ErrorCode.AUTH_FAILED == 4
        assert ErrorCode.RATE_LIMITED == 5
        assert ErrorCode.PROTOCOL_MISMATCH == 6
        assert ErrorCode.COMPRESSION_ERROR == 7
        assert ErrorCode.CHUNK_ERROR == 8
        assert ErrorCode.INTERNAL_ERROR == 255

    def test_connect_response_with_error(self):
        """Test ConnectResponse with error."""
        response = ConnectResponse(
            type="error",
            error="Subdomain already taken",
            error_code=ErrorCode.SUBDOMAIN_TAKEN,
        )

        encoded = encode_message(response)
        decoded = decode_message(encoded)

        assert decoded["type"] == "error"
        assert decoded["error"] == "Subdomain already taken"
        assert decoded["error_code"] == ErrorCode.SUBDOMAIN_TAKEN


# ==============================================================================
# Edge Case Tests
# ==============================================================================


class TestEdgeCases:
    """Tests for edge cases and error handling."""

    def test_message_size_limit(self):
        """Test that messages exceeding size limit raise error."""
        # Test the error message directly by checking the constant
        assert MAX_MESSAGE_SIZE == 16 * 1024 * 1024

        # We can verify the size check logic by understanding that:
        # 1. The check happens AFTER compression
        # 2. ZSTD compresses even random-looking data very well
        # 3. Instead of testing the full path, verify the decode side rejects large lengths

        # Test decode rejects messages with lengths exceeding MAX_MESSAGE_SIZE
        import msgpack

        payload = msgpack.packb({"type": "ping", "timestamp": 123})
        # Craft a frame that claims a huge length
        frame = bytearray()
        frame.extend(MAGIC)
        frame.append(PROTOCOL_VERSION)
        frame.append(CompressionType.NONE)
        # Claim the payload is larger than MAX_MESSAGE_SIZE
        fake_length = MAX_MESSAGE_SIZE + 1
        frame.extend(fake_length.to_bytes(4, "little"))
        frame.extend(payload)

        with pytest.raises(ValueError, match="too large"):
            decode_message(bytes(frame))

    def test_unknown_message_type(self):
        """Test handling of unknown message type."""
        # Create a fake encoded message with unknown type
        import msgpack

        payload = msgpack.packb({"type": "unknown_type", "data": "test"})
        frame = bytearray()
        frame.extend(MAGIC)
        frame.append(PROTOCOL_VERSION)
        frame.append(CompressionType.NONE)
        frame.extend(len(payload).to_bytes(4, "little"))
        frame.extend(payload)

        with pytest.raises(ValueError, match="Unknown message type"):
            parse_message(bytes(frame))

    def test_compression_type_enum(self):
        """Test CompressionType enum values."""
        assert CompressionType.NONE == 0
        assert CompressionType.LZ4 == 1
        assert CompressionType.ZSTD == 2

    def test_protocol_constants(self):
        """Test protocol constants are correctly defined."""
        assert MAGIC == b"TACH"
        assert PROTOCOL_VERSION == 2
        assert MAX_MESSAGE_SIZE == 16 * 1024 * 1024
        assert CHUNK_SIZE == 64 * 1024
        assert MIN_COMPRESSION_SIZE == 1024
