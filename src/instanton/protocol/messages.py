"""Protocol message definitions with compression, streaming, and negotiation."""

from __future__ import annotations

from enum import IntEnum
from functools import lru_cache
from typing import TYPE_CHECKING, Any, Literal
from uuid import UUID, uuid4

import brotli
import lz4.frame
import msgpack
import zstandard as zstd
from pydantic import BaseModel, Field

if TYPE_CHECKING:
    from instanton.core.config import PerformanceConfig


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
    BROTLI = 3


PROTOCOL_VERSION = 2
MAGIC = b"TACH"

_DEFAULT_MAX_MESSAGE_SIZE = 64 * 1024 * 1024
_DEFAULT_CHUNK_SIZE = 1024 * 1024
_DEFAULT_MIN_COMPRESSION_SIZE = 1024

MAX_MESSAGE_SIZE = _DEFAULT_MAX_MESSAGE_SIZE
CHUNK_SIZE = _DEFAULT_CHUNK_SIZE
MIN_COMPRESSION_SIZE = _DEFAULT_MIN_COMPRESSION_SIZE
SKIP_COMPRESSION_TYPES = {
    "image/", "video/", "audio/", "application/zip", "application/gzip",
    "application/x-rar", "application/x-7z", "application/pdf",
    "application/octet-stream",
}


def _get_perf_config() -> "PerformanceConfig":
    """Get performance config (lazy import to avoid circular imports)."""
    from instanton.core.config import get_config
    return get_config().performance


def get_chunk_size() -> int:
    """Get chunk size from config."""
    return _get_perf_config().chunk_size


def get_max_message_size() -> int:
    """Get max message size from config."""
    return _get_perf_config().max_message_size


def get_min_compression_size() -> int:
    """Get min compression size from config."""
    return _get_perf_config().min_compression_size


def get_skip_compression_types() -> set[str]:
    """Get skip compression types from config."""
    return _get_perf_config().get_skip_compression_types()


def is_compression_enabled() -> bool:
    """Check if compression is enabled."""
    return _get_perf_config().compression_enabled


def get_compression_level() -> int:
    """Get compression level from config."""
    return _get_perf_config().compression_level


_zstd_decompressor = zstd.ZstdDecompressor()


@lru_cache(maxsize=20)
def _get_zstd_compressor(level: int) -> zstd.ZstdCompressor:
    """Get a cached ZSTD compressor for the given level."""
    return zstd.ZstdCompressor(level=level)


def compress_data(data: bytes, compression: CompressionType) -> bytes:
    """Compress data using the specified algorithm."""
    if compression == CompressionType.NONE:
        return data
    elif compression == CompressionType.LZ4:
        return lz4.frame.compress(data)
    elif compression == CompressionType.ZSTD:
        level = get_compression_level()
        return _get_zstd_compressor(level).compress(data)
    elif compression == CompressionType.BROTLI:
        level = get_compression_level()
        quality = min(max(level // 2 + 1, 1), 11)
        return brotli.compress(data, quality=quality)
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
    elif compression == CompressionType.BROTLI:
        return brotli.decompress(data)
    else:
        raise ValueError(f"Unsupported compression type: {compression}")


class NegotiateRequest(BaseModel):
    """Client request to negotiate protocol features."""

    type: Literal["negotiate"] = "negotiate"
    client_version: int = PROTOCOL_VERSION
    supported_compressions: list[int] = Field(
        default_factory=lambda: [
            int(CompressionType.NONE),
            int(CompressionType.LZ4),
            int(CompressionType.ZSTD),
            int(CompressionType.BROTLI),
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


class ConnectRequest(BaseModel):
    """Client request to establish tunnel."""

    type: Literal["connect"] = "connect"
    subdomain: str | None = None
    local_port: int
    version: int = PROTOCOL_VERSION
    auth_token: str | None = None
    auth_method: int | None = None


class ConnectResponse(BaseModel):
    """Server response to connect request."""

    type: Literal["connected", "error"] = "connected"
    tunnel_id: UUID = Field(default_factory=uuid4)
    subdomain: str = ""
    url: str = ""
    error: str | None = None
    error_code: ErrorCode | None = None


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


class ChunkStart(BaseModel):
    """Indicates start of a chunked transfer."""

    type: Literal["chunk_start"] = "chunk_start"
    stream_id: UUID = Field(default_factory=uuid4)
    request_id: UUID
    total_size: int | None = None
    content_type: str = "application/octet-stream"
    status: int = 200
    headers: dict[str, str] = Field(default_factory=dict)


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
    checksum: str | None = None


class ChunkAck(BaseModel):
    """Acknowledgment of received chunks (for flow control)."""

    type: Literal["chunk_ack"] = "chunk_ack"
    stream_id: UUID
    last_received_sequence: int
    window_size: int = 16


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
    """gRPC frame for streaming passthrough."""

    type: Literal["grpc_frame"] = "grpc_frame"
    tunnel_id: UUID
    stream_id: UUID
    sequence: int = 0
    compressed: bool = False
    data: bytes
    is_final: bool = False


class GrpcTrailers(BaseModel):
    """gRPC trailing metadata."""

    type: Literal["grpc_trailers"] = "grpc_trailers"
    tunnel_id: UUID
    stream_id: UUID
    status: int = 0
    message: str = ""
    trailers: dict[str, str] = Field(default_factory=dict)


class GrpcStreamClose(BaseModel):
    """Request to close a gRPC stream."""

    type: Literal["grpc_stream_close"] = "grpc_stream_close"
    tunnel_id: UUID
    stream_id: UUID
    status: int = 0
    message: str = ""


ClientMessage = (
    NegotiateRequest
    | ConnectRequest
    | HttpResponse
    | ChunkData
    | ChunkEnd
    | ChunkAck
    | Ping
    | Disconnect
    | TcpTunnelOpen
    | TcpData
    | TcpTunnelClose
    | UdpTunnelOpen
    | UdpDatagram
    | UdpTunnelClose
    | WebSocketUpgrade
    | WebSocketFrame
    | WebSocketClose
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
    | TcpTunnelOpened
    | TcpData
    | TcpTunnelClose
    | UdpTunnelOpened
    | UdpDatagram
    | UdpTunnelClose
    | WebSocketUpgradeResponse
    | WebSocketFrame
    | WebSocketClose
    | GrpcStreamOpened
    | GrpcFrame
    | GrpcTrailers
    | GrpcStreamClose
)

AllMessages = ClientMessage | ServerMessage

TcpTunnelMessage = TcpTunnelOpen | TcpTunnelOpened | TcpData | TcpTunnelClose
UdpTunnelMessage = UdpTunnelOpen | UdpTunnelOpened | UdpDatagram | UdpTunnelClose
WebSocketMessage = WebSocketUpgrade | WebSocketUpgradeResponse | WebSocketFrame | WebSocketClose
GrpcMessage = GrpcStreamOpen | GrpcStreamOpened | GrpcFrame | GrpcTrailers | GrpcStreamClose

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
    "tcp_tunnel_open": TcpTunnelOpen,
    "tcp_tunnel_opened": TcpTunnelOpened,
    "tcp_data": TcpData,
    "tcp_tunnel_close": TcpTunnelClose,
    "udp_tunnel_open": UdpTunnelOpen,
    "udp_tunnel_opened": UdpTunnelOpened,
    "udp_datagram": UdpDatagram,
    "udp_tunnel_close": UdpTunnelClose,
    "websocket_upgrade": WebSocketUpgrade,
    "websocket_upgrade_response": WebSocketUpgradeResponse,
    "websocket_frame": WebSocketFrame,
    "websocket_close": WebSocketClose,
    "grpc_stream_open": GrpcStreamOpen,
    "grpc_stream_opened": GrpcStreamOpened,
    "grpc_frame": GrpcFrame,
    "grpc_trailers": GrpcTrailers,
    "grpc_stream_close": GrpcStreamClose,
}


def _msgpack_default(obj: Any) -> Any:
    """Custom msgpack serializer for types that msgpack doesn't handle natively."""
    if isinstance(obj, UUID):
        return str(obj)
    raise TypeError(f"Object of type {type(obj).__name__} is not msgpack serializable")


def _serialize_for_msgpack(data: Any) -> Any:
    """Recursively convert data for msgpack serialization."""
    if isinstance(data, dict):
        return {k: _serialize_for_msgpack(v) for k, v in data.items()}
    elif isinstance(data, list):
        return [_serialize_for_msgpack(v) for v in data]
    elif isinstance(data, UUID):
        return str(data)
    elif isinstance(data, bytes):
        return data
    return data


def _should_skip_compression(msg: BaseModel, payload_size: int) -> bool:
    """Check if compression should be skipped for this message."""
    if not is_compression_enabled():
        return True

    if payload_size > 100 * 1024:
        return True

    msg_type = getattr(msg, "type", "")

    if msg_type == "chunk_data":
        return True

    if msg_type in ("http_request", "http_response"):
        headers = getattr(msg, "headers", {}) or {}
        content_type = ""
        for k, v in headers.items():
            if k.lower() == "content-type":
                content_type = v.lower()
                break

        skip_types = get_skip_compression_types()
        for skip_type in skip_types:
            if skip_type in content_type:
                return True

    return False


def encode_message(
    msg: BaseModel,
    compression: CompressionType = CompressionType.NONE,
) -> bytes:
    """Encode a message with protocol framing and optional compression."""
    data = _serialize_for_msgpack(msg.model_dump())
    payload = msgpack.packb(data, use_bin_type=True)

    skip_compression = _should_skip_compression(msg, len(payload))

    min_size = get_min_compression_size()
    if not skip_compression and compression == CompressionType.NONE and len(payload) > min_size:
        compression = CompressionType.ZSTD

    if not skip_compression and compression != CompressionType.NONE:
        payload = compress_data(payload, compression)
    else:
        compression = CompressionType.NONE

    max_size = get_max_message_size()
    if len(payload) > max_size:
        raise ValueError(f"Message too large: {len(payload)} bytes (max: {max_size})")

    frame = bytearray()
    frame.extend(MAGIC)
    frame.append(PROTOCOL_VERSION)
    frame.append(compression)
    frame.extend(len(payload).to_bytes(4, "little"))
    frame.extend(payload)

    return bytes(frame)


def decode_message(data: bytes) -> dict[str, Any]:
    """Decode a framed message with automatic decompression."""
    if len(data) < 10:
        raise ValueError("Message too short")

    if data[:4] != MAGIC:
        raise ValueError("Invalid magic bytes")

    version = data[4]
    if version > PROTOCOL_VERSION:
        raise ValueError(f"Unsupported protocol version: {version}")

    flags = data[5]
    compression = CompressionType(flags & 0x03)

    length = int.from_bytes(data[6:10], "little")
    max_size = get_max_message_size()
    if length > max_size:
        raise ValueError(f"Message too large: {length} bytes (max: {max_size})")

    payload = data[10 : 10 + length]

    if compression != CompressionType.NONE:
        payload = decompress_data(payload, compression)

    try:
        return msgpack.unpackb(
            payload,
            raw=False,
            strict_map_key=False,
            unicode_errors="surrogateescape",
        )
    except Exception as e:
        try:
            return msgpack.unpackb(payload, raw=True, strict_map_key=False)
        except Exception:
            raise ValueError(
                f"Failed to decode msgpack payload (compression={compression.name}, "
                f"payload_len={len(payload)}): {e}"
            ) from e


def parse_message(data: bytes) -> BaseModel:
    """Decode and parse a framed message into a typed Pydantic model."""
    raw = decode_message(data)
    msg_type = raw.get("type")

    if msg_type not in MESSAGE_TYPES:
        raise ValueError(f"Unknown message type: {msg_type}")

    return MESSAGE_TYPES[msg_type].model_validate(raw)


class ChunkAssembler:
    """Assembles chunked data streams with TTL-based cleanup to prevent memory leaks."""

    def __init__(self) -> None:
        import time

        self.streams: dict[UUID, list[tuple[int, bytes]]] = {}
        self.metadata: dict[UUID, ChunkStart] = {}
        self._stream_sizes: dict[UUID, int] = {}
        self._stream_created: dict[UUID, float] = {}
        self._time = time

    def _get_max_stream_age(self) -> float:
        """Get max stream age from config."""
        from instanton.core.config import get_config
        return get_config().resources.chunk_stream_ttl

    def _get_max_stream_size(self) -> int:
        """Get max stream size from config."""
        from instanton.core.config import get_config
        return get_config().performance.http_max_body_size

    def _get_max_concurrent_streams(self) -> int:
        """Get max concurrent streams from config."""
        from instanton.core.config import get_config
        return get_config().resources.max_concurrent_streams

    def _cleanup_expired_streams(self) -> None:
        """Remove streams that have exceeded the maximum age."""
        now = self._time.monotonic()
        max_age = self._get_max_stream_age()
        expired = [
            stream_id
            for stream_id, created_at in self._stream_created.items()
            if now - created_at > max_age
        ]
        for stream_id in expired:
            self.streams.pop(stream_id, None)
            self.metadata.pop(stream_id, None)
            self._stream_sizes.pop(stream_id, None)
            self._stream_created.pop(stream_id, None)

    def start_stream(self, start_msg: ChunkStart) -> None:
        """Register a new stream."""
        self._cleanup_expired_streams()

        max_streams = self._get_max_concurrent_streams()
        if len(self.streams) >= max_streams:
            raise ValueError(f"Too many concurrent streams (max: {max_streams})")

        self.streams[start_msg.stream_id] = []
        self.metadata[start_msg.stream_id] = start_msg
        self._stream_sizes[start_msg.stream_id] = 0
        self._stream_created[start_msg.stream_id] = self._time.monotonic()

    def add_chunk(self, chunk: ChunkData) -> bool:
        """Add a chunk to a stream. Returns True if stream is complete."""
        if chunk.stream_id not in self.streams:
            raise ValueError(f"Unknown stream: {chunk.stream_id}")

        max_size = self._get_max_stream_size()
        new_size = self._stream_sizes[chunk.stream_id] + len(chunk.data)
        if new_size > max_size:
            self.abort_stream(chunk.stream_id)
            raise ValueError(f"Stream {chunk.stream_id} exceeds maximum size ({max_size} bytes)")

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
    status: int = 200,
    headers: dict[str, str] | None = None,
) -> tuple[ChunkStart, list[ChunkData], ChunkEnd]:
    """Split data into chunks for streaming transfer."""
    import hashlib

    stream_id = uuid4()

    start = ChunkStart(
        stream_id=stream_id,
        request_id=request_id,
        total_size=len(data),
        content_type=content_type,
        status=status,
        headers=headers or {},
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
            CompressionType.BROTLI,
        ]
        self.supports_streaming = supports_streaming
        self.max_chunk_size = max_chunk_size

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
        if request.client_version > PROTOCOL_VERSION:
            return NegotiateResponse(
                success=False,
                error=f"Client version {request.client_version} not supported",
            )

        client_compressions = set(request.supported_compressions)
        server_compressions = {int(c) for c in self.supported_compressions}
        common = client_compressions & server_compressions

        if CompressionType.BROTLI in common:
            selected = CompressionType.BROTLI
        elif CompressionType.ZSTD in common:
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

        streaming = self.supports_streaming and request.supports_streaming
        chunk_size = min(self.max_chunk_size, request.max_chunk_size)

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
