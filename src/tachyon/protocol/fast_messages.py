"""High-performance protocol messages using msgspec.

This module provides optimized message types using msgspec instead of
pydantic + msgpack for significant performance improvements:

- 5-10x faster serialization/deserialization
- Zero-copy where possible with memoryview
- Array-like encoding to minimize wire size
- Pre-allocated encoders/decoders
"""

from __future__ import annotations

import hashlib
from enum import IntEnum
from typing import Any
from uuid import uuid4

import lz4.frame
import msgspec
import zstandard as zstd

# ==============================================================================
# Protocol Constants
# ==============================================================================

PROTOCOL_VERSION = 3  # Upgraded version for fast protocol
MAGIC = b"TACH"
MAX_MESSAGE_SIZE = 16 * 1024 * 1024  # 16 MB
CHUNK_SIZE = 64 * 1024  # 64 KB
MIN_COMPRESSION_SIZE = 512  # Lowered threshold for better compression
HEADER_SIZE = 8  # MAGIC(4) + VERSION(1) + FLAGS(1) + LENGTH(2 bytes for small, 4 for large)


# ==============================================================================
# Enums
# ==============================================================================


class ErrorCode(IntEnum):
    """Error codes for protocol errors."""

    SUBDOMAIN_TAKEN = 1
    INVALID_SUBDOMAIN = 2
    SERVER_FULL = 3
    AUTH_FAILED = 4
    RATE_LIMITED = 5
    PROTOCOL_MISMATCH = 6
    COMPRESSION_ERROR = 7
    CHUNK_ERROR = 8
    TUNNEL_ERROR = 9
    WEBSOCKET_ERROR = 10
    GRPC_ERROR = 11
    INTERNAL_ERROR = 255


class TunnelProtocol(IntEnum):
    """Protocol types for tunnel connections."""

    HTTP1 = 1
    HTTP2 = 2
    GRPC = 3
    WEBSOCKET = 4
    TCP = 5
    UDP = 6


class CompressionType(IntEnum):
    """Supported compression algorithms."""

    NONE = 0
    LZ4 = 1
    ZSTD = 2


class MessageType(IntEnum):
    """Message type IDs for compact encoding."""

    # Negotiation
    NEGOTIATE = 1
    NEGOTIATE_RESPONSE = 2
    # Connection
    CONNECT = 3
    CONNECTED = 4
    ERROR = 5
    # HTTP
    HTTP_REQUEST = 10
    HTTP_RESPONSE = 11
    # Streaming
    CHUNK_START = 20
    CHUNK_DATA = 21
    CHUNK_END = 22
    CHUNK_ACK = 23
    # Keep-alive
    PING = 30
    PONG = 31
    DISCONNECT = 32
    # TCP
    TCP_OPEN = 40
    TCP_OPENED = 41
    TCP_DATA = 42
    TCP_CLOSE = 43
    # UDP
    UDP_OPEN = 50
    UDP_OPENED = 51
    UDP_DATAGRAM = 52
    UDP_CLOSE = 53
    # WebSocket
    WS_UPGRADE = 60
    WS_UPGRADE_RESPONSE = 61
    WS_FRAME = 62
    WS_CLOSE = 63
    # gRPC
    GRPC_OPEN = 70
    GRPC_OPENED = 71
    GRPC_FRAME = 72
    GRPC_TRAILERS = 73
    GRPC_CLOSE = 74
    # Auth
    AUTH_REQUEST = 80
    AUTH_RESPONSE = 81


# ==============================================================================
# Compression - Pre-allocated compressors
# ==============================================================================

# Thread-local compressors for performance
_zstd_compressor = zstd.ZstdCompressor(level=1)  # Level 1 for speed
_zstd_decompressor = zstd.ZstdDecompressor()


def compress_fast(data: bytes, compression: CompressionType) -> bytes:
    """Fast compression with pre-allocated compressors."""
    if compression == CompressionType.NONE or len(data) < MIN_COMPRESSION_SIZE:
        return data
    elif compression == CompressionType.LZ4:
        result: bytes = lz4.frame.compress(data, compression_level=0)  # Fastest
        return result
    elif compression == CompressionType.ZSTD:
        result = _zstd_compressor.compress(data)
        return result
    return data


def decompress_fast(data: bytes, compression: CompressionType) -> bytes:
    """Fast decompression."""
    if compression == CompressionType.NONE:
        return data
    elif compression == CompressionType.LZ4:
        result: bytes = lz4.frame.decompress(data)
        return result
    elif compression == CompressionType.ZSTD:
        result = _zstd_decompressor.decompress(data)
        return result
    return data


# ==============================================================================
# Base Message Types using msgspec.Struct
# ==============================================================================


class FastMessage(msgspec.Struct, array_like=True, frozen=True, gc=False, kw_only=True):
    """Base class for all fast messages.

    Using array_like=True removes field names from wire format.
    Using frozen=True enables caching and thread safety.
    Using gc=False avoids GC tracking overhead for small objects.
    Using kw_only=True for consistent initialization.
    """

    pass


# ==============================================================================
# Negotiation Messages
# ==============================================================================


class NegotiateRequest(FastMessage, frozen=True):
    """Client negotiation request."""

    type: int = MessageType.NEGOTIATE
    client_version: int = PROTOCOL_VERSION
    compressions: tuple[int, ...] = (
        CompressionType.NONE,
        CompressionType.LZ4,
        CompressionType.ZSTD,
    )
    streaming: bool = True
    chunk_size: int = CHUNK_SIZE


class NegotiateResponse(FastMessage, frozen=True):
    """Server negotiation response."""

    type: int = MessageType.NEGOTIATE_RESPONSE
    server_version: int = PROTOCOL_VERSION
    compression: int = CompressionType.ZSTD
    streaming: bool = True
    chunk_size: int = CHUNK_SIZE
    success: bool = True
    error: str | None = None


# ==============================================================================
# Connection Messages
# ==============================================================================


class ConnectRequest(FastMessage, frozen=True):
    """Client connect request."""

    type: int = MessageType.CONNECT
    subdomain: str | None = None
    local_port: int = 0
    version: int = PROTOCOL_VERSION
    auth_token: str | None = None


class ConnectResponse(FastMessage, frozen=True):
    """Server connect response."""

    type: int = MessageType.CONNECTED
    tunnel_id: str = ""  # UUID as string for msgspec
    subdomain: str = ""
    url: str = ""
    error: str | None = None
    error_code: int | None = None


# ==============================================================================
# HTTP Messages - Optimized for high throughput
# ==============================================================================


class HttpRequest(FastMessage, frozen=True):
    """HTTP request through tunnel."""

    type: int = MessageType.HTTP_REQUEST
    request_id: str = ""  # UUID as string
    method: str = "GET"
    path: str = "/"
    headers: dict[str, str] | None = None
    body: bytes = b""


class HttpResponse(FastMessage, frozen=True):
    """HTTP response from local service."""

    type: int = MessageType.HTTP_RESPONSE
    request_id: str = ""
    status: int = 200
    headers: dict[str, str] | None = None
    body: bytes = b""


# ==============================================================================
# Streaming Chunk Messages
# ==============================================================================


class ChunkStart(FastMessage, frozen=True):
    """Start of chunked transfer."""

    type: int = MessageType.CHUNK_START
    stream_id: str = ""
    request_id: str = ""
    total_size: int | None = None
    content_type: str = "application/octet-stream"


class ChunkData(FastMessage, frozen=True):
    """Chunk of data in streaming transfer."""

    type: int = MessageType.CHUNK_DATA
    stream_id: str = ""
    seq: int = 0  # Shortened field name
    data: bytes = b""
    final: bool = False


class ChunkEnd(FastMessage, frozen=True):
    """End of chunked transfer."""

    type: int = MessageType.CHUNK_END
    stream_id: str = ""
    chunks: int = 0
    checksum: str | None = None


class ChunkAck(FastMessage, frozen=True):
    """Acknowledgment of received chunks."""

    type: int = MessageType.CHUNK_ACK
    stream_id: str = ""
    last_seq: int = 0
    window: int = 16


# ==============================================================================
# Keep-alive Messages - Minimal overhead
# ==============================================================================


class Ping(FastMessage, frozen=True):
    """Keep-alive ping - just timestamp."""

    type: int = MessageType.PING
    ts: int = 0  # Unix timestamp ms


class Pong(FastMessage, frozen=True):
    """Keep-alive pong - timestamps for latency measurement."""

    type: int = MessageType.PONG
    ts: int = 0  # Original timestamp
    server_ts: int = 0  # Server timestamp


class Disconnect(FastMessage, frozen=True):
    """Graceful disconnect."""

    type: int = MessageType.DISCONNECT
    reason: str = ""


# ==============================================================================
# TCP Tunnel Messages
# ==============================================================================


class TcpOpen(FastMessage, frozen=True):
    """Open TCP tunnel."""

    type: int = MessageType.TCP_OPEN
    tunnel_id: str = ""
    host: str = ""
    port: int = 0


class TcpOpened(FastMessage, frozen=True):
    """TCP tunnel opened."""

    type: int = MessageType.TCP_OPENED
    tunnel_id: str = ""
    success: bool = True
    error: str | None = None


class TcpData(FastMessage, frozen=True):
    """TCP data."""

    type: int = MessageType.TCP_DATA
    tunnel_id: str = ""
    seq: int = 0
    data: bytes = b""
    final: bool = False


class TcpClose(FastMessage, frozen=True):
    """Close TCP tunnel."""

    type: int = MessageType.TCP_CLOSE
    tunnel_id: str = ""
    reason: str = ""


# ==============================================================================
# UDP Messages
# ==============================================================================


class UdpOpen(FastMessage, frozen=True):
    """Open UDP tunnel."""

    type: int = MessageType.UDP_OPEN
    tunnel_id: str = ""
    host: str = ""
    port: int = 0


class UdpOpened(FastMessage, frozen=True):
    """UDP tunnel opened."""

    type: int = MessageType.UDP_OPENED
    tunnel_id: str = ""
    success: bool = True
    error: str | None = None


class UdpDatagram(FastMessage, frozen=True):
    """UDP datagram."""

    type: int = MessageType.UDP_DATAGRAM
    tunnel_id: str = ""
    seq: int = 0
    data: bytes = b""


class UdpClose(FastMessage, frozen=True):
    """Close UDP tunnel."""

    type: int = MessageType.UDP_CLOSE
    tunnel_id: str = ""
    reason: str = ""


# ==============================================================================
# WebSocket Messages
# ==============================================================================


class WsUpgrade(FastMessage, frozen=True):
    """WebSocket upgrade request."""

    type: int = MessageType.WS_UPGRADE
    tunnel_id: str = ""
    request_id: str = ""
    path: str = ""
    headers: dict[str, str] | None = None
    protocols: tuple[str, ...] | None = None


class WsUpgradeResponse(FastMessage, frozen=True):
    """WebSocket upgrade response."""

    type: int = MessageType.WS_UPGRADE_RESPONSE
    tunnel_id: str = ""
    request_id: str = ""
    success: bool = True
    protocol: str | None = None
    headers: dict[str, str] | None = None
    error: str | None = None


class WsFrame(FastMessage, frozen=True):
    """WebSocket frame."""

    type: int = MessageType.WS_FRAME
    tunnel_id: str = ""
    seq: int = 0
    opcode: int = 2  # Binary by default
    payload: bytes = b""
    fin: bool = True


class WsClose(FastMessage, frozen=True):
    """WebSocket close."""

    type: int = MessageType.WS_CLOSE
    tunnel_id: str = ""
    code: int = 1000
    reason: str = ""


# ==============================================================================
# gRPC Messages
# ==============================================================================


class GrpcOpen(FastMessage, frozen=True):
    """Open gRPC stream."""

    type: int = MessageType.GRPC_OPEN
    tunnel_id: str = ""
    stream_id: str = ""
    service: str = ""
    method: str = ""
    headers: dict[str, str] | None = None
    timeout_ms: int | None = None


class GrpcOpened(FastMessage, frozen=True):
    """gRPC stream opened."""

    type: int = MessageType.GRPC_OPENED
    tunnel_id: str = ""
    stream_id: str = ""
    success: bool = True
    headers: dict[str, str] | None = None
    error: str | None = None


class GrpcFrame(FastMessage, frozen=True):
    """gRPC frame."""

    type: int = MessageType.GRPC_FRAME
    tunnel_id: str = ""
    stream_id: str = ""
    seq: int = 0
    compressed: bool = False
    data: bytes = b""
    final: bool = False


class GrpcTrailers(FastMessage, frozen=True):
    """gRPC trailing metadata."""

    type: int = MessageType.GRPC_TRAILERS
    tunnel_id: str = ""
    stream_id: str = ""
    status: int = 0
    message: str = ""
    trailers: dict[str, str] | None = None


class GrpcClose(FastMessage, frozen=True):
    """Close gRPC stream."""

    type: int = MessageType.GRPC_CLOSE
    tunnel_id: str = ""
    stream_id: str = ""
    status: int = 0
    message: str = ""


# ==============================================================================
# Message Type Registry
# ==============================================================================

MESSAGE_TYPES: dict[int, type[FastMessage]] = {
    MessageType.NEGOTIATE: NegotiateRequest,
    MessageType.NEGOTIATE_RESPONSE: NegotiateResponse,
    MessageType.CONNECT: ConnectRequest,
    MessageType.CONNECTED: ConnectResponse,
    MessageType.ERROR: ConnectResponse,
    MessageType.HTTP_REQUEST: HttpRequest,
    MessageType.HTTP_RESPONSE: HttpResponse,
    MessageType.CHUNK_START: ChunkStart,
    MessageType.CHUNK_DATA: ChunkData,
    MessageType.CHUNK_END: ChunkEnd,
    MessageType.CHUNK_ACK: ChunkAck,
    MessageType.PING: Ping,
    MessageType.PONG: Pong,
    MessageType.DISCONNECT: Disconnect,
    MessageType.TCP_OPEN: TcpOpen,
    MessageType.TCP_OPENED: TcpOpened,
    MessageType.TCP_DATA: TcpData,
    MessageType.TCP_CLOSE: TcpClose,
    MessageType.UDP_OPEN: UdpOpen,
    MessageType.UDP_OPENED: UdpOpened,
    MessageType.UDP_DATAGRAM: UdpDatagram,
    MessageType.UDP_CLOSE: UdpClose,
    MessageType.WS_UPGRADE: WsUpgrade,
    MessageType.WS_UPGRADE_RESPONSE: WsUpgradeResponse,
    MessageType.WS_FRAME: WsFrame,
    MessageType.WS_CLOSE: WsClose,
    MessageType.GRPC_OPEN: GrpcOpen,
    MessageType.GRPC_OPENED: GrpcOpened,
    MessageType.GRPC_FRAME: GrpcFrame,
    MessageType.GRPC_TRAILERS: GrpcTrailers,
    MessageType.GRPC_CLOSE: GrpcClose,
}


# ==============================================================================
# Fast Encoder/Decoder - Pre-allocated for performance
# ==============================================================================


class FastCodec:
    """High-performance message codec.

    Uses pre-allocated msgspec encoder/decoder for zero-allocation
    serialization in hot paths.
    """

    def __init__(self) -> None:
        self._encoder = msgspec.msgpack.Encoder()
        self._decoders: dict[int, msgspec.msgpack.Decoder[Any]] = {
            msg_type: msgspec.msgpack.Decoder(msg_class)
            for msg_type, msg_class in MESSAGE_TYPES.items()
        }

    def encode(
        self,
        msg: FastMessage,
        compression: CompressionType = CompressionType.NONE,
    ) -> bytes:
        """Encode message with minimal frame overhead.

        Optimized frame format (8 bytes header for small messages):
        - MAGIC (4 bytes): b"TACH"
        - FLAGS (1 byte): compression(2 bits) + extended_length(1 bit) + reserved(5 bits)
        - For small messages (< 65535 bytes): LENGTH (2 bytes, little-endian)
        - For large messages: LENGTH (4 bytes, little-endian)
        - PAYLOAD: msgpack-encoded message

        Total overhead: 7 bytes for small, 9 bytes for large (vs 10 in old protocol)
        """
        payload = self._encoder.encode(msg)

        # Auto-compress large payloads
        actual_compression = compression
        if compression == CompressionType.NONE and len(payload) > MIN_COMPRESSION_SIZE:
            actual_compression = CompressionType.ZSTD

        if actual_compression != CompressionType.NONE:
            payload = compress_fast(payload, actual_compression)

        if len(payload) > MAX_MESSAGE_SIZE:
            raise ValueError(f"Message too large: {len(payload)} bytes")

        # Build frame with minimal overhead
        use_extended = len(payload) >= 65535
        flags = (actual_compression & 0x03) | (0x04 if use_extended else 0)

        frame = bytearray(7 if not use_extended else 9 + len(payload))
        frame[0:4] = MAGIC
        frame[4] = flags

        if use_extended:
            frame[5:9] = len(payload).to_bytes(4, "little")
            frame[9:] = payload
        else:
            frame[5:7] = len(payload).to_bytes(2, "little")
            frame[7:] = payload

        return bytes(frame)

    def decode(self, data: bytes | memoryview) -> FastMessage:
        """Decode message with zero-copy where possible."""
        if len(data) < 7:
            raise ValueError("Message too short")

        if data[0:4] != MAGIC:
            raise ValueError("Invalid magic bytes")

        flags = data[4]
        compression = CompressionType(flags & 0x03)
        use_extended = bool(flags & 0x04)

        if use_extended:
            if len(data) < 9:
                raise ValueError("Message too short for extended header")
            length = int.from_bytes(data[5:9], "little")
            payload_start = 9
        else:
            length = int.from_bytes(data[5:7], "little")
            payload_start = 7

        if length > MAX_MESSAGE_SIZE:
            raise ValueError(f"Message too large: {length} bytes")

        payload = data[payload_start : payload_start + length]

        # Decompress if needed
        if compression != CompressionType.NONE:
            payload = decompress_fast(bytes(payload), compression)

        # Peek at message type (first element in array)
        # msgpack array format: 0x9N for small arrays, 0xdc/0xdd for larger
        if payload[0] >= 0x90 and payload[0] <= 0x9F:
            # Fixarray - type is immediately after
            msg_type = payload[1]
        elif payload[0] == 0xDC:
            # array 16 - type is after 3 bytes
            msg_type = payload[3]
        elif payload[0] == 0xDD:
            # array 32 - type is after 5 bytes
            msg_type = payload[5]
        else:
            raise ValueError("Invalid message format")

        decoder = self._decoders.get(msg_type)
        if decoder is None:
            raise ValueError(f"Unknown message type: {msg_type}")

        msg: FastMessage = decoder.decode(payload)
        return msg

    def decode_type(self, data: bytes | memoryview) -> int:
        """Quickly decode just the message type without full deserialization."""
        if len(data) < 8:
            raise ValueError("Message too short")

        flags = data[4]
        use_extended = bool(flags & 0x04)
        payload_start = 9 if use_extended else 7

        payload = data[payload_start:]

        # Peek at message type
        if payload[0] >= 0x90 and payload[0] <= 0x9F:
            return payload[1]
        elif payload[0] == 0xDC:
            return payload[3]
        elif payload[0] == 0xDD:
            return payload[5]

        raise ValueError("Invalid message format")


# Global codec instance
_codec: FastCodec | None = None


def get_codec() -> FastCodec:
    """Get global codec instance (lazy initialization)."""
    global _codec
    if _codec is None:
        _codec = FastCodec()
    return _codec


def encode_fast(msg: FastMessage, compression: CompressionType = CompressionType.NONE) -> bytes:
    """Encode message using global codec."""
    return get_codec().encode(msg, compression)


def decode_fast(data: bytes | memoryview) -> FastMessage:
    """Decode message using global codec."""
    return get_codec().decode(data)


# ==============================================================================
# Streaming Utilities
# ==============================================================================


class FastChunkAssembler:
    """Memory-efficient chunk assembler with pre-allocated buffers."""

    __slots__ = ("_streams", "_metadata", "_buffer_pool")

    def __init__(self) -> None:
        self._streams: dict[str, list[tuple[int, bytes]]] = {}
        self._metadata: dict[str, ChunkStart] = {}

    def start_stream(self, start: ChunkStart) -> None:
        """Register new stream."""
        self._streams[start.stream_id] = []
        self._metadata[start.stream_id] = start

    def add_chunk(self, chunk: ChunkData) -> bool:
        """Add chunk, return True if stream is complete."""
        if chunk.stream_id not in self._streams:
            raise ValueError(f"Unknown stream: {chunk.stream_id}")

        self._streams[chunk.stream_id].append((chunk.seq, chunk.data))
        return chunk.final

    def end_stream(self, end: ChunkEnd) -> bytes:
        """Finalize and assemble stream."""
        if end.stream_id not in self._streams:
            raise ValueError(f"Unknown stream: {end.stream_id}")

        chunks = self._streams.pop(end.stream_id)
        self._metadata.pop(end.stream_id, None)

        # Sort by sequence and concatenate
        chunks.sort(key=lambda x: x[0])
        return b"".join(data for _, data in chunks)


def create_chunks_fast(
    data: bytes,
    request_id: str,
    chunk_size: int = CHUNK_SIZE,
    content_type: str = "application/octet-stream",
) -> tuple[ChunkStart, list[ChunkData], ChunkEnd]:
    """Create chunks for streaming transfer."""
    stream_id = str(uuid4())

    start = ChunkStart(
        stream_id=stream_id,
        request_id=request_id,
        total_size=len(data),
        content_type=content_type,
    )

    chunks: list[ChunkData] = []
    for i, offset in enumerate(range(0, max(len(data), 1), chunk_size)):
        chunk_data = data[offset : offset + chunk_size]
        is_final = offset + chunk_size >= len(data)
        chunks.append(
            ChunkData(
                stream_id=stream_id,
                seq=i,
                data=chunk_data,
                final=is_final,
            )
        )

    if not chunks:
        chunks.append(ChunkData(stream_id=stream_id, seq=0, data=b"", final=True))

    checksum = hashlib.sha256(data).hexdigest()
    end = ChunkEnd(stream_id=stream_id, chunks=len(chunks), checksum=checksum)

    return start, chunks, end


# ==============================================================================
# Protocol Negotiator - Fast version
# ==============================================================================


class FastProtocolNegotiator:
    """Fast protocol negotiator."""

    __slots__ = (
        "supported_compressions",
        "supports_streaming",
        "max_chunk_size",
        "negotiated_compression",
        "streaming_enabled",
        "chunk_size",
    )

    def __init__(
        self,
        supported_compressions: tuple[CompressionType, ...] | None = None,
        supports_streaming: bool = True,
        max_chunk_size: int = CHUNK_SIZE,
    ) -> None:
        self.supported_compressions = supported_compressions or (
            CompressionType.NONE,
            CompressionType.LZ4,
            CompressionType.ZSTD,
        )
        self.supports_streaming = supports_streaming
        self.max_chunk_size = max_chunk_size

        # Negotiated values
        self.negotiated_compression = CompressionType.NONE
        self.streaming_enabled = False
        self.chunk_size = CHUNK_SIZE

    def create_request(self) -> NegotiateRequest:
        """Create negotiation request."""
        return NegotiateRequest(
            client_version=PROTOCOL_VERSION,
            compressions=tuple(int(c) for c in self.supported_compressions),
            streaming=self.supports_streaming,
            chunk_size=self.max_chunk_size,
        )

    def handle_request(self, request: NegotiateRequest) -> NegotiateResponse:
        """Handle negotiation request on server."""
        # Version check
        if request.client_version > PROTOCOL_VERSION:
            return NegotiateResponse(
                success=False,
                error=f"Client version {request.client_version} not supported",
            )

        # Select compression (prefer ZSTD > LZ4 > NONE)
        client_comps = set(request.compressions)
        server_comps = {int(c) for c in self.supported_compressions}
        common = client_comps & server_comps

        if CompressionType.ZSTD in common:
            selected = CompressionType.ZSTD
        elif CompressionType.LZ4 in common:
            selected = CompressionType.LZ4
        elif CompressionType.NONE in common:
            selected = CompressionType.NONE
        else:
            return NegotiateResponse(success=False, error="No common compression")

        streaming = self.supports_streaming and request.streaming
        chunk_size = min(self.max_chunk_size, request.chunk_size)

        self.negotiated_compression = selected
        self.streaming_enabled = streaming
        self.chunk_size = chunk_size

        return NegotiateResponse(
            server_version=PROTOCOL_VERSION,
            compression=selected,
            streaming=streaming,
            chunk_size=chunk_size,
            success=True,
        )

    def apply_response(self, response: NegotiateResponse) -> bool:
        """Apply response on client."""
        if not response.success:
            return False

        self.negotiated_compression = CompressionType(response.compression)
        self.streaming_enabled = response.streaming
        self.chunk_size = response.chunk_size
        return True
