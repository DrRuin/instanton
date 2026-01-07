"""Protocol message definitions with compression, streaming, and negotiation."""

from __future__ import annotations

from enum import IntEnum
from typing import Any, Literal
from uuid import UUID, uuid4

import lz4.frame
import msgpack
import zstandard as zstd
from pydantic import BaseModel, Field


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


# Protocol constants
PROTOCOL_VERSION = 2
MAGIC = b"TACH"
MAX_MESSAGE_SIZE = 16 * 1024 * 1024  # 16 MB
CHUNK_SIZE = 64 * 1024  # 64 KB default chunk size
MIN_COMPRESSION_SIZE = 1024  # Only compress messages > 1KB


# Pre-create compressors for performance
_zstd_compressor = zstd.ZstdCompressor(level=3)
_zstd_decompressor = zstd.ZstdDecompressor()


def compress_data(data: bytes, compression: CompressionType) -> bytes:
    """Compress data using the specified algorithm."""
    if compression == CompressionType.NONE:
        return data
    elif compression == CompressionType.LZ4:
        return lz4.frame.compress(data)
    elif compression == CompressionType.ZSTD:
        return _zstd_compressor.compress(data)
    else:
        raise ValueError(f"Unsupported compression type: {compression}")


def decompress_data(data: bytes, compression: CompressionType) -> bytes:
    """Decompress data using the specified algorithm."""
    if compression == CompressionType.NONE:
        return data
    elif compression == CompressionType.LZ4:
        return lz4.frame.decompress(data)
    elif compression == CompressionType.ZSTD:
        return _zstd_decompressor.decompress(data)
    else:
        raise ValueError(f"Unsupported compression type: {compression}")


# ==============================================================================
# Protocol Negotiation Messages
# ==============================================================================


class NegotiateRequest(BaseModel):
    """Client request to negotiate protocol features."""

    type: Literal["negotiate"] = "negotiate"
    client_version: int = PROTOCOL_VERSION
    supported_compressions: list[int] = Field(
        default_factory=lambda: [
            int(CompressionType.NONE),
            int(CompressionType.LZ4),
            int(CompressionType.ZSTD),
        ]
    )
    supports_streaming: bool = True
    max_chunk_size: int = CHUNK_SIZE


class NegotiateResponse(BaseModel):
    """Server response to negotiation request."""

    type: Literal["negotiate_response"] = "negotiate_response"
    server_version: int = PROTOCOL_VERSION
    selected_compression: int = CompressionType.ZSTD
    streaming_enabled: bool = True
    chunk_size: int = CHUNK_SIZE
    success: bool = True
    error: str | None = None


# ==============================================================================
# Connection Messages
# ==============================================================================


class ConnectRequest(BaseModel):
    """Client request to establish tunnel."""

    type: Literal["connect"] = "connect"
    subdomain: str | None = None
    local_port: int
    version: int = PROTOCOL_VERSION
    # Authentication token (JWT or API key)
    auth_token: str | None = None
    # Optional auth method hint
    auth_method: int | None = None


class ConnectResponse(BaseModel):
    """Server response to connect request."""

    type: Literal["connected", "error"] = "connected"
    tunnel_id: UUID = Field(default_factory=uuid4)
    subdomain: str = ""
    url: str = ""
    error: str | None = None
    error_code: ErrorCode | None = None


# ==============================================================================
# HTTP Messages
# ==============================================================================


class HttpRequest(BaseModel):
    """HTTP request to proxy through tunnel."""

    type: Literal["http_request"] = "http_request"
    request_id: UUID = Field(default_factory=uuid4)
    method: str
    path: str
    headers: dict[str, str] = Field(default_factory=dict)
    body: bytes = b""


class HttpResponse(BaseModel):
    """HTTP response from local service."""

    type: Literal["http_response"] = "http_response"
    request_id: UUID
    status: int
    headers: dict[str, str] = Field(default_factory=dict)
    body: bytes = b""


# ==============================================================================
# Streaming Chunk Messages
# ==============================================================================


class ChunkStart(BaseModel):
    """Indicates start of a chunked transfer."""

    type: Literal["chunk_start"] = "chunk_start"
    stream_id: UUID = Field(default_factory=uuid4)
    request_id: UUID
    total_size: int | None = None  # None if unknown (streaming)
    content_type: str = "application/octet-stream"


class ChunkData(BaseModel):
    """A chunk of data in a streaming transfer."""

    type: Literal["chunk_data"] = "chunk_data"
    stream_id: UUID
    sequence: int
    data: bytes
    is_final: bool = False


class ChunkEnd(BaseModel):
    """Indicates end of a chunked transfer."""

    type: Literal["chunk_end"] = "chunk_end"
    stream_id: UUID
    total_chunks: int
    checksum: str | None = None  # Optional SHA-256 checksum


class ChunkAck(BaseModel):
    """Acknowledgment of received chunks (for flow control)."""

    type: Literal["chunk_ack"] = "chunk_ack"
    stream_id: UUID
    last_received_sequence: int
    window_size: int = 16  # How many more chunks can be sent


# ==============================================================================
# Keep-alive Messages
# ==============================================================================


class Ping(BaseModel):
    """Keep-alive ping."""

    type: Literal["ping"] = "ping"
    timestamp: int


class Pong(BaseModel):
    """Keep-alive pong response."""

    type: Literal["pong"] = "pong"
    timestamp: int
    server_time: int


class Disconnect(BaseModel):
    """Graceful disconnect."""

    type: Literal["disconnect"] = "disconnect"
    reason: str = ""


# ==============================================================================
# Authentication Messages
# ==============================================================================


class AuthMethod(IntEnum):
    """Supported authentication methods."""

    NONE = 0
    API_KEY = 1
    JWT = 2
    BASIC = 3
    OAUTH = 4
    MTLS = 5


class AuthRequest(BaseModel):
    """Client authentication request.

    Sent before or with ConnectRequest to authenticate the client.
    """

    type: Literal["auth_request"] = "auth_request"
    method: int = AuthMethod.API_KEY
    # API Key auth
    api_key: str | None = None
    # JWT auth
    token: str | None = None
    # Basic auth
    username: str | None = None
    password: str | None = None
    # OAuth
    access_token: str | None = None
    provider: str | None = None
    # mTLS (cert info is extracted from connection)
    cert_fingerprint: str | None = None
    # Request metadata
    client_id: str | None = None
    client_version: str | None = None


class AuthResponse(BaseModel):
    """Server authentication response."""

    type: Literal["auth_response"] = "auth_response"
    success: bool = False
    error: str | None = None
    error_code: ErrorCode | None = None
    # Granted permissions
    identity: str | None = None
    scopes: list[str] = Field(default_factory=list)
    # Token info (if JWT was issued)
    access_token: str | None = None
    refresh_token: str | None = None
    expires_in: int | None = None
    token_type: str = "Bearer"


class TokenRefreshRequest(BaseModel):
    """Request to refresh an access token."""

    type: Literal["token_refresh"] = "token_refresh"
    refresh_token: str
    scopes: list[str] | None = None


class TokenRefreshResponse(BaseModel):
    """Response with new tokens."""

    type: Literal["token_refresh_response"] = "token_refresh_response"
    success: bool = False
    error: str | None = None
    access_token: str | None = None
    refresh_token: str | None = None
    expires_in: int | None = None


# ==============================================================================
# TCP Tunnel Messages
# ==============================================================================


class TcpTunnelOpen(BaseModel):
    """Request to open a raw TCP tunnel."""

    type: Literal["tcp_tunnel_open"] = "tcp_tunnel_open"
    tunnel_id: UUID = Field(default_factory=uuid4)
    target_host: str
    target_port: int
    protocol: int = TunnelProtocol.TCP


class TcpTunnelOpened(BaseModel):
    """Response confirming TCP tunnel is open."""

    type: Literal["tcp_tunnel_opened"] = "tcp_tunnel_opened"
    tunnel_id: UUID
    success: bool = True
    error: str | None = None


class TcpData(BaseModel):
    """Raw TCP data message for tunnel passthrough."""

    type: Literal["tcp_data"] = "tcp_data"
    tunnel_id: UUID
    sequence: int = 0
    data: bytes
    is_final: bool = False


class TcpTunnelClose(BaseModel):
    """Request to close a TCP tunnel."""

    type: Literal["tcp_tunnel_close"] = "tcp_tunnel_close"
    tunnel_id: UUID
    reason: str = ""


# ==============================================================================
# UDP Datagram Messages
# ==============================================================================


class UdpTunnelOpen(BaseModel):
    """Request to open a UDP tunnel."""

    type: Literal["udp_tunnel_open"] = "udp_tunnel_open"
    tunnel_id: UUID = Field(default_factory=uuid4)
    target_host: str
    target_port: int


class UdpTunnelOpened(BaseModel):
    """Response confirming UDP tunnel is open."""

    type: Literal["udp_tunnel_opened"] = "udp_tunnel_opened"
    tunnel_id: UUID
    success: bool = True
    error: str | None = None


class UdpDatagram(BaseModel):
    """UDP datagram message for tunnel passthrough."""

    type: Literal["udp_datagram"] = "udp_datagram"
    tunnel_id: UUID
    sequence: int = 0
    data: bytes
    source_port: int | None = None
    dest_port: int | None = None


class UdpTunnelClose(BaseModel):
    """Request to close a UDP tunnel."""

    type: Literal["udp_tunnel_close"] = "udp_tunnel_close"
    tunnel_id: UUID
    reason: str = ""


# ==============================================================================
# WebSocket Passthrough Messages
# ==============================================================================


class WebSocketOpcode(IntEnum):
    """WebSocket frame opcodes."""

    CONTINUATION = 0x0
    TEXT = 0x1
    BINARY = 0x2
    CLOSE = 0x8
    PING = 0x9
    PONG = 0xA


class WebSocketUpgrade(BaseModel):
    """WebSocket upgrade request for tunnel passthrough."""

    type: Literal["websocket_upgrade"] = "websocket_upgrade"
    tunnel_id: UUID = Field(default_factory=uuid4)
    request_id: UUID = Field(default_factory=uuid4)
    path: str
    headers: dict[str, str] = Field(default_factory=dict)
    subprotocols: list[str] = Field(default_factory=list)


class WebSocketUpgradeResponse(BaseModel):
    """Response to WebSocket upgrade request."""

    type: Literal["websocket_upgrade_response"] = "websocket_upgrade_response"
    tunnel_id: UUID
    request_id: UUID
    success: bool = True
    accepted_protocol: str | None = None
    headers: dict[str, str] = Field(default_factory=dict)
    error: str | None = None


class WebSocketFrame(BaseModel):
    """WebSocket frame for bidirectional passthrough."""

    type: Literal["websocket_frame"] = "websocket_frame"
    tunnel_id: UUID
    sequence: int = 0
    opcode: int = WebSocketOpcode.BINARY
    payload: bytes
    fin: bool = True
    rsv1: bool = False
    rsv2: bool = False
    rsv3: bool = False


class WebSocketClose(BaseModel):
    """WebSocket close message."""

    type: Literal["websocket_close"] = "websocket_close"
    tunnel_id: UUID
    code: int = 1000
    reason: str = ""


# ==============================================================================
# gRPC Streaming Messages
# ==============================================================================


class GrpcStreamOpen(BaseModel):
    """Request to open a gRPC stream tunnel."""

    type: Literal["grpc_stream_open"] = "grpc_stream_open"
    tunnel_id: UUID = Field(default_factory=uuid4)
    stream_id: UUID = Field(default_factory=uuid4)
    service: str
    method: str
    headers: dict[str, str] = Field(default_factory=dict)
    timeout_ms: int | None = None


class GrpcStreamOpened(BaseModel):
    """Response confirming gRPC stream is open."""

    type: Literal["grpc_stream_opened"] = "grpc_stream_opened"
    tunnel_id: UUID
    stream_id: UUID
    success: bool = True
    headers: dict[str, str] = Field(default_factory=dict)
    error: str | None = None


class GrpcFrame(BaseModel):
    """gRPC frame for streaming passthrough.

    gRPC frame format: 1 byte compressed flag + 4 bytes length + data
    """

    type: Literal["grpc_frame"] = "grpc_frame"
    tunnel_id: UUID
    stream_id: UUID
    sequence: int = 0
    compressed: bool = False
    data: bytes
    is_final: bool = False


class GrpcTrailers(BaseModel):
    """gRPC trailing metadata (status, etc.)."""

    type: Literal["grpc_trailers"] = "grpc_trailers"
    tunnel_id: UUID
    stream_id: UUID
    status: int = 0  # gRPC status code
    message: str = ""
    trailers: dict[str, str] = Field(default_factory=dict)


class GrpcStreamClose(BaseModel):
    """Request to close a gRPC stream."""

    type: Literal["grpc_stream_close"] = "grpc_stream_close"
    tunnel_id: UUID
    stream_id: UUID
    status: int = 0
    message: str = ""


# ==============================================================================
# Union Types for Message Handling
# ==============================================================================

ClientMessage = (
    NegotiateRequest
    | ConnectRequest
    | HttpResponse
    | ChunkData
    | ChunkEnd
    | ChunkAck
    | Ping
    | Disconnect
    # TCP tunnel messages
    | TcpTunnelOpen
    | TcpData
    | TcpTunnelClose
    # UDP tunnel messages
    | UdpTunnelOpen
    | UdpDatagram
    | UdpTunnelClose
    # WebSocket messages
    | WebSocketUpgrade
    | WebSocketFrame
    | WebSocketClose
    # gRPC messages
    | GrpcStreamOpen
    | GrpcFrame
    | GrpcStreamClose
)

ServerMessage = (
    NegotiateResponse
    | ConnectResponse
    | HttpRequest
    | ChunkStart
    | ChunkData
    | ChunkEnd
    | ChunkAck
    | Pong
    # TCP tunnel responses
    | TcpTunnelOpened
    | TcpData
    | TcpTunnelClose
    # UDP tunnel responses
    | UdpTunnelOpened
    | UdpDatagram
    | UdpTunnelClose
    # WebSocket responses
    | WebSocketUpgradeResponse
    | WebSocketFrame
    | WebSocketClose
    # gRPC responses
    | GrpcStreamOpened
    | GrpcFrame
    | GrpcTrailers
    | GrpcStreamClose
)

AllMessages = ClientMessage | ServerMessage

# TCP tunnel message types
TcpTunnelMessage = TcpTunnelOpen | TcpTunnelOpened | TcpData | TcpTunnelClose

# UDP tunnel message types
UdpTunnelMessage = UdpTunnelOpen | UdpTunnelOpened | UdpDatagram | UdpTunnelClose

# WebSocket message types
WebSocketMessage = WebSocketUpgrade | WebSocketUpgradeResponse | WebSocketFrame | WebSocketClose

# gRPC message types
GrpcMessage = GrpcStreamOpen | GrpcStreamOpened | GrpcFrame | GrpcTrailers | GrpcStreamClose

# Message type lookup for deserialization
MESSAGE_TYPES: dict[str, type[BaseModel]] = {
    "negotiate": NegotiateRequest,
    "negotiate_response": NegotiateResponse,
    "connect": ConnectRequest,
    "connected": ConnectResponse,
    "error": ConnectResponse,
    "http_request": HttpRequest,
    "http_response": HttpResponse,
    "chunk_start": ChunkStart,
    "chunk_data": ChunkData,
    "chunk_end": ChunkEnd,
    "chunk_ack": ChunkAck,
    "ping": Ping,
    "pong": Pong,
    "disconnect": Disconnect,
    # TCP tunnel messages
    "tcp_tunnel_open": TcpTunnelOpen,
    "tcp_tunnel_opened": TcpTunnelOpened,
    "tcp_data": TcpData,
    "tcp_tunnel_close": TcpTunnelClose,
    # UDP tunnel messages
    "udp_tunnel_open": UdpTunnelOpen,
    "udp_tunnel_opened": UdpTunnelOpened,
    "udp_datagram": UdpDatagram,
    "udp_tunnel_close": UdpTunnelClose,
    # WebSocket messages
    "websocket_upgrade": WebSocketUpgrade,
    "websocket_upgrade_response": WebSocketUpgradeResponse,
    "websocket_frame": WebSocketFrame,
    "websocket_close": WebSocketClose,
    # gRPC messages
    "grpc_stream_open": GrpcStreamOpen,
    "grpc_stream_opened": GrpcStreamOpened,
    "grpc_frame": GrpcFrame,
    "grpc_trailers": GrpcTrailers,
    "grpc_stream_close": GrpcStreamClose,
}


# ==============================================================================
# Encoding / Decoding with Compression
# ==============================================================================


def encode_message(
    msg: BaseModel,
    compression: CompressionType = CompressionType.NONE,
) -> bytes:
    """Encode a message with protocol framing and optional compression.

    Frame format:
    - MAGIC (4 bytes): b"TACH"
    - VERSION (1 byte): Protocol version
    - FLAGS (1 byte): Bit flags (bits 0-1: compression type)
    - LENGTH (4 bytes): Payload length (little-endian)
    - PAYLOAD (variable): msgpack-encoded message
    """
    payload = msgpack.packb(msg.model_dump(mode="json"), use_bin_type=True)

    # Auto-select compression for large payloads if none specified
    if compression == CompressionType.NONE and len(payload) > MIN_COMPRESSION_SIZE:
        compression = CompressionType.ZSTD

    # Compress if enabled
    if compression != CompressionType.NONE:
        payload = compress_data(payload, compression)

    if len(payload) > MAX_MESSAGE_SIZE:
        raise ValueError(f"Message too large: {len(payload)} bytes")

    # Frame: MAGIC (4) + VERSION (1) + FLAGS (1) + LENGTH (4) + PAYLOAD
    frame = bytearray()
    frame.extend(MAGIC)
    frame.append(PROTOCOL_VERSION)
    frame.append(compression)  # FLAGS byte stores compression type
    frame.extend(len(payload).to_bytes(4, "little"))
    frame.extend(payload)

    return bytes(frame)


def decode_message(data: bytes) -> dict[str, Any]:
    """Decode a framed message with automatic decompression.

    Returns the raw dict from msgpack. Use parse_message() to get a typed model.
    """
    if len(data) < 10:
        raise ValueError("Message too short")

    if data[:4] != MAGIC:
        raise ValueError("Invalid magic bytes")

    version = data[4]
    if version > PROTOCOL_VERSION:
        raise ValueError(f"Unsupported protocol version: {version}")

    flags = data[5]
    compression = CompressionType(flags & 0x03)  # Bottom 2 bits = compression

    length = int.from_bytes(data[6:10], "little")
    if length > MAX_MESSAGE_SIZE:
        raise ValueError(f"Message too large: {length} bytes")

    payload = data[10 : 10 + length]

    # Decompress if needed
    if compression != CompressionType.NONE:
        payload = decompress_data(payload, compression)

    return msgpack.unpackb(payload, raw=False)


def parse_message(data: bytes) -> BaseModel:
    """Decode and parse a framed message into a typed Pydantic model."""
    raw = decode_message(data)
    msg_type = raw.get("type")

    if msg_type not in MESSAGE_TYPES:
        raise ValueError(f"Unknown message type: {msg_type}")

    return MESSAGE_TYPES[msg_type].model_validate(raw)


# ==============================================================================
# Streaming Utilities
# ==============================================================================


class ChunkAssembler:
    """Assembles chunked data streams with TTL-based cleanup to prevent memory leaks."""

    # Maximum age for incomplete streams (5 minutes)
    MAX_STREAM_AGE_SECONDS: float = 300.0
    # Maximum size per stream (100MB)
    MAX_STREAM_SIZE: int = 100 * 1024 * 1024
    # Maximum number of concurrent streams
    MAX_CONCURRENT_STREAMS: int = 1000

    def __init__(self) -> None:
        import time

        self.streams: dict[UUID, list[tuple[int, bytes]]] = {}
        self.metadata: dict[UUID, ChunkStart] = {}
        self._stream_sizes: dict[UUID, int] = {}
        self._stream_created: dict[UUID, float] = {}
        self._time = time

    def _cleanup_expired_streams(self) -> None:
        """Remove streams that have exceeded the maximum age."""
        now = self._time.monotonic()
        expired = [
            stream_id
            for stream_id, created_at in self._stream_created.items()
            if now - created_at > self.MAX_STREAM_AGE_SECONDS
        ]
        for stream_id in expired:
            self.streams.pop(stream_id, None)
            self.metadata.pop(stream_id, None)
            self._stream_sizes.pop(stream_id, None)
            self._stream_created.pop(stream_id, None)

    def start_stream(self, start_msg: ChunkStart) -> None:
        """Register a new stream."""
        # Cleanup expired streams first
        self._cleanup_expired_streams()

        # Check concurrent stream limit
        if len(self.streams) >= self.MAX_CONCURRENT_STREAMS:
            raise ValueError("Too many concurrent streams")

        self.streams[start_msg.stream_id] = []
        self.metadata[start_msg.stream_id] = start_msg
        self._stream_sizes[start_msg.stream_id] = 0
        self._stream_created[start_msg.stream_id] = self._time.monotonic()

    def add_chunk(self, chunk: ChunkData) -> bool:
        """Add a chunk to a stream. Returns True if stream is complete."""
        if chunk.stream_id not in self.streams:
            raise ValueError(f"Unknown stream: {chunk.stream_id}")

        # Check size limit
        new_size = self._stream_sizes[chunk.stream_id] + len(chunk.data)
        if new_size > self.MAX_STREAM_SIZE:
            # Clean up the stream to prevent further memory usage
            self.abort_stream(chunk.stream_id)
            raise ValueError(f"Stream {chunk.stream_id} exceeds maximum size")

        self.streams[chunk.stream_id].append((chunk.sequence, chunk.data))
        self._stream_sizes[chunk.stream_id] = new_size
        return chunk.is_final

    def end_stream(self, end_msg: ChunkEnd) -> bytes:
        """Finalize and assemble a stream."""
        if end_msg.stream_id not in self.streams:
            raise ValueError(f"Unknown stream: {end_msg.stream_id}")

        chunks = self.streams.pop(end_msg.stream_id)
        self.metadata.pop(end_msg.stream_id, None)
        self._stream_sizes.pop(end_msg.stream_id, None)
        self._stream_created.pop(end_msg.stream_id, None)

        # Sort by sequence and concatenate
        chunks.sort(key=lambda x: x[0])
        return b"".join(data for _, data in chunks)

    def abort_stream(self, stream_id: UUID) -> None:
        """Abort and clean up a stream."""
        self.streams.pop(stream_id, None)
        self.metadata.pop(stream_id, None)
        self._stream_sizes.pop(stream_id, None)
        self._stream_created.pop(stream_id, None)

    def get_stream_info(self, stream_id: UUID) -> ChunkStart | None:
        """Get metadata about an active stream."""
        return self.metadata.get(stream_id)

    def get_active_stream_count(self) -> int:
        """Get number of active streams."""
        return len(self.streams)

    def cleanup_all(self) -> None:
        """Clean up all streams (for shutdown)."""
        self.streams.clear()
        self.metadata.clear()
        self._stream_sizes.clear()
        self._stream_created.clear()


def create_chunks(
    data: bytes,
    request_id: UUID,
    chunk_size: int = CHUNK_SIZE,
    content_type: str = "application/octet-stream",
) -> tuple[ChunkStart, list[ChunkData], ChunkEnd]:
    """Split data into chunks for streaming transfer.

    Returns:
        Tuple of (ChunkStart, list of ChunkData, ChunkEnd)
    """
    import hashlib

    stream_id = uuid4()

    start = ChunkStart(
        stream_id=stream_id,
        request_id=request_id,
        total_size=len(data),
        content_type=content_type,
    )

    chunks: list[ChunkData] = []
    for i, offset in enumerate(range(0, len(data), chunk_size)):
        chunk_data = data[offset : offset + chunk_size]
        is_final = offset + chunk_size >= len(data)
        chunks.append(
            ChunkData(
                stream_id=stream_id,
                sequence=i,
                data=chunk_data,
                is_final=is_final,
            )
        )

    # Ensure at least one chunk exists
    if not chunks:
        chunks.append(
            ChunkData(
                stream_id=stream_id,
                sequence=0,
                data=b"",
                is_final=True,
            )
        )

    checksum = hashlib.sha256(data).hexdigest()
    end = ChunkEnd(
        stream_id=stream_id,
        total_chunks=len(chunks),
        checksum=checksum,
    )

    return start, chunks, end


# ==============================================================================
# Protocol Negotiation Utilities
# ==============================================================================


class ProtocolNegotiator:
    """Handles protocol feature negotiation between client and server."""

    def __init__(
        self,
        supported_compressions: list[CompressionType] | None = None,
        supports_streaming: bool = True,
        max_chunk_size: int = CHUNK_SIZE,
    ) -> None:
        self.supported_compressions = supported_compressions or [
            CompressionType.NONE,
            CompressionType.LZ4,
            CompressionType.ZSTD,
        ]
        self.supports_streaming = supports_streaming
        self.max_chunk_size = max_chunk_size

        # Negotiated values (set after negotiation)
        self.negotiated_compression: CompressionType = CompressionType.NONE
        self.streaming_enabled: bool = False
        self.chunk_size: int = CHUNK_SIZE

    def create_request(self) -> NegotiateRequest:
        """Create a negotiation request from client."""
        return NegotiateRequest(
            client_version=PROTOCOL_VERSION,
            supported_compressions=[int(c) for c in self.supported_compressions],
            supports_streaming=self.supports_streaming,
            max_chunk_size=self.max_chunk_size,
        )

    def handle_request(self, request: NegotiateRequest) -> NegotiateResponse:
        """Handle a negotiation request on server side."""
        # Check version compatibility
        if request.client_version > PROTOCOL_VERSION:
            return NegotiateResponse(
                success=False,
                error=f"Client version {request.client_version} not supported",
            )

        # Select best compression (prefer ZSTD > LZ4 > NONE)
        client_compressions = set(request.supported_compressions)
        server_compressions = {int(c) for c in self.supported_compressions}
        common = client_compressions & server_compressions

        if CompressionType.ZSTD in common:
            selected = CompressionType.ZSTD
        elif CompressionType.LZ4 in common:
            selected = CompressionType.LZ4
        elif CompressionType.NONE in common:
            selected = CompressionType.NONE
        else:
            return NegotiateResponse(
                success=False,
                error="No common compression algorithm",
            )

        # Negotiate streaming
        streaming = self.supports_streaming and request.supports_streaming

        # Negotiate chunk size (use smaller of the two)
        chunk_size = min(self.max_chunk_size, request.max_chunk_size)

        # Store negotiated values
        self.negotiated_compression = selected
        self.streaming_enabled = streaming
        self.chunk_size = chunk_size

        return NegotiateResponse(
            server_version=PROTOCOL_VERSION,
            selected_compression=selected,
            streaming_enabled=streaming,
            chunk_size=chunk_size,
            success=True,
        )

    def apply_response(self, response: NegotiateResponse) -> bool:
        """Apply negotiation response on client side."""
        if not response.success:
            return False

        self.negotiated_compression = CompressionType(response.selected_compression)
        self.streaming_enabled = response.streaming_enabled
        self.chunk_size = response.chunk_size
        return True
