"""Multi-protocol support for HTTP/2, gRPC, WebSocket, and raw TCP/UDP tunnels.

This module provides:
- Protocol detection via connection sniffing
- HTTP/2 connection handling using h2
- gRPC passthrough (application/grpc content-type detection)
- WebSocket upgrade and bidirectional streaming
- Raw TCP tunnel support
- UDP support via QUIC datagrams
"""

from __future__ import annotations

import asyncio
import contextlib
import struct
from abc import ABC, abstractmethod
from collections.abc import AsyncIterator, Callable
from dataclasses import dataclass, field
from enum import IntEnum, auto
from typing import Any
from uuid import UUID, uuid4

import structlog

# HTTP/2 support via h2
try:
    import h2.config
    import h2.connection
    import h2.events
    import h2.exceptions

    H2_AVAILABLE = True
except ImportError:
    H2_AVAILABLE = False

# gRPC support
try:
    import grpc  # noqa: F401

    GRPC_AVAILABLE = True
except ImportError:
    GRPC_AVAILABLE = False

logger = structlog.get_logger()


# ==============================================================================
# Protocol Type Enumeration
# ==============================================================================


class ProtocolType(IntEnum):
    """Supported protocol types for tunneling."""

    UNKNOWN = 0
    HTTP1 = auto()
    HTTP2 = auto()
    GRPC = auto()
    WEBSOCKET = auto()
    TCP = auto()
    UDP = auto()


# ==============================================================================
# Protocol Detection Constants
# ==============================================================================

# HTTP/2 connection preface (client magic)
HTTP2_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
HTTP2_PREFACE_LEN = 24

# WebSocket upgrade indicators
WEBSOCKET_UPGRADE_HEADERS = (b"upgrade: websocket", b"connection: upgrade")

# gRPC content type
GRPC_CONTENT_TYPE = b"application/grpc"

# HTTP/1.x method prefixes
HTTP1_METHODS = (
    b"GET ",
    b"POST ",
    b"PUT ",
    b"DELETE ",
    b"HEAD ",
    b"OPTIONS ",
    b"PATCH ",
    b"TRACE ",
    b"CONNECT ",
)

# TLS record header for detecting encrypted connections
TLS_RECORD_HEADER = 0x16  # ContentType.handshake


# ==============================================================================
# Protocol Detection Result
# ==============================================================================


@dataclass
class ProtocolDetectionResult:
    """Result of protocol detection."""

    protocol: ProtocolType
    confidence: float  # 0.0 to 1.0
    is_tls: bool = False
    http_version: str | None = None
    is_grpc: bool = False
    is_websocket_upgrade: bool = False
    content_type: str | None = None
    extra_data: dict[str, Any] = field(default_factory=dict)


# ==============================================================================
# Protocol Detector
# ==============================================================================


class ProtocolDetector:
    """Detects the protocol type from incoming connection data.

    Uses connection sniffing to identify the protocol without consuming
    the data, allowing proper routing to protocol-specific handlers.
    """

    def __init__(
        self,
        min_bytes: int = 24,
        timeout: float = 5.0,
    ) -> None:
        """Initialize the protocol detector.

        Args:
            min_bytes: Minimum bytes to read for detection (default: 24 for HTTP/2 preface).
            timeout: Timeout for reading initial bytes.
        """
        self.min_bytes = min_bytes
        self.timeout = timeout

    async def detect(
        self,
        reader: asyncio.StreamReader,
    ) -> tuple[ProtocolDetectionResult, bytes]:
        """Detect the protocol from incoming data.

        Args:
            reader: Async stream reader to peek data from.

        Returns:
            Tuple of (detection result, peeked data).
        """
        try:
            # Read initial bytes without consuming
            data = await asyncio.wait_for(
                reader.read(self.min_bytes),
                timeout=self.timeout,
            )
        except TimeoutError:
            logger.warning("Protocol detection timeout")
            return (
                ProtocolDetectionResult(protocol=ProtocolType.UNKNOWN, confidence=0.0),
                b"",
            )
        except Exception as e:
            logger.error("Protocol detection error", error=str(e))
            return (
                ProtocolDetectionResult(protocol=ProtocolType.UNKNOWN, confidence=0.0),
                b"",
            )

        if not data:
            return (
                ProtocolDetectionResult(protocol=ProtocolType.UNKNOWN, confidence=0.0),
                b"",
            )

        result = self._analyze_data(data)
        return result, data

    def detect_from_bytes(self, data: bytes) -> ProtocolDetectionResult:
        """Detect protocol from raw bytes (synchronous).

        Args:
            data: Raw bytes to analyze.

        Returns:
            Protocol detection result.
        """
        return self._analyze_data(data)

    def _analyze_data(self, data: bytes) -> ProtocolDetectionResult:
        """Analyze data to determine protocol type."""
        if not data:
            return ProtocolDetectionResult(
                protocol=ProtocolType.UNKNOWN,
                confidence=0.0,
            )

        # Check for TLS
        is_tls = len(data) > 0 and data[0] == TLS_RECORD_HEADER

        # Check for HTTP/2 preface
        if data.startswith(HTTP2_PREFACE):
            return ProtocolDetectionResult(
                protocol=ProtocolType.HTTP2,
                confidence=1.0,
                is_tls=is_tls,
                http_version="2.0",
            )

        # Check for HTTP/1.x methods
        data_upper = data.upper()
        for method in HTTP1_METHODS:
            if data_upper.startswith(method):
                # Further check for WebSocket upgrade or gRPC
                result = self._check_http1_special(data)
                if result:
                    return result

                return ProtocolDetectionResult(
                    protocol=ProtocolType.HTTP1,
                    confidence=0.95,
                    is_tls=is_tls,
                    http_version="1.1",
                )

        # Check for raw TCP (any binary data that doesn't match other protocols)
        # If it starts with printable ASCII, might be some text protocol
        if all(32 <= b < 127 or b in (9, 10, 13) for b in data[:20] if data):
            # Looks like text but not HTTP
            return ProtocolDetectionResult(
                protocol=ProtocolType.TCP,
                confidence=0.6,
                is_tls=is_tls,
            )

        # Default to raw TCP for binary data
        return ProtocolDetectionResult(
            protocol=ProtocolType.TCP,
            confidence=0.7,
            is_tls=is_tls,
        )

    def _check_http1_special(self, data: bytes) -> ProtocolDetectionResult | None:
        """Check HTTP/1.x data for WebSocket upgrade or gRPC content."""
        data_lower = data.lower()

        # Check for WebSocket upgrade
        has_upgrade = b"upgrade:" in data_lower and b"websocket" in data_lower
        has_connection = b"connection:" in data_lower and b"upgrade" in data_lower

        if has_upgrade and has_connection:
            return ProtocolDetectionResult(
                protocol=ProtocolType.WEBSOCKET,
                confidence=0.95,
                is_websocket_upgrade=True,
                http_version="1.1",
            )

        # Check for gRPC content type
        if GRPC_CONTENT_TYPE in data_lower:
            return ProtocolDetectionResult(
                protocol=ProtocolType.GRPC,
                confidence=0.95,
                is_grpc=True,
                content_type="application/grpc",
                http_version="1.1",  # gRPC can work over HTTP/1.1 with some limitations
            )

        return None


# ==============================================================================
# Protocol Handler Interface
# ==============================================================================


class ProtocolHandler(ABC):
    """Abstract base class for protocol handlers."""

    @property
    @abstractmethod
    def protocol_type(self) -> ProtocolType:
        """Get the protocol type this handler manages."""
        pass

    @abstractmethod
    async def handle_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        initial_data: bytes | None = None,
    ) -> None:
        """Handle an incoming connection.

        Args:
            reader: Async stream reader.
            writer: Async stream writer.
            initial_data: Initial data already read during detection.
        """
        pass

    @abstractmethod
    async def close(self) -> None:
        """Close the handler and cleanup resources."""
        pass


# ==============================================================================
# HTTP/2 Connection Handler
# ==============================================================================


@dataclass
class HTTP2Stream:
    """Represents an HTTP/2 stream."""

    stream_id: int
    headers: dict[str, str] = field(default_factory=dict)
    request_data: bytes = b""
    response_data: bytes = b""
    is_complete: bool = False
    end_stream_received: bool = False


class HTTP2ConnectionHandler(ProtocolHandler):
    """HTTP/2 connection handler using the h2 library.

    Provides full HTTP/2 support including:
    - Stream multiplexing
    - Header compression (HPACK)
    - Flow control
    - Server push (optional)
    """

    def __init__(
        self,
        is_client: bool = False,
        max_concurrent_streams: int = 100,
        initial_window_size: int = 65535,
        max_frame_size: int = 16384,
        on_request: Callable[[int, dict[str, str], bytes], AsyncIterator[bytes]] | None = None,
    ) -> None:
        """Initialize HTTP/2 handler.

        Args:
            is_client: True for client-side, False for server-side.
            max_concurrent_streams: Maximum concurrent streams.
            initial_window_size: Initial flow control window size.
            max_frame_size: Maximum frame size.
            on_request: Callback for handling requests (server-side).
        """
        if not H2_AVAILABLE:
            raise RuntimeError("h2 library is required for HTTP/2 support")

        self._is_client = is_client
        self._max_concurrent_streams = max_concurrent_streams
        self._initial_window_size = initial_window_size
        self._max_frame_size = max_frame_size
        self._on_request = on_request

        self._conn: h2.connection.H2Connection | None = None
        self._streams: dict[int, HTTP2Stream] = {}
        self._writer: asyncio.StreamWriter | None = None
        self._reader: asyncio.StreamReader | None = None
        self._closed = False
        self._lock = asyncio.Lock()

    @property
    def protocol_type(self) -> ProtocolType:
        return ProtocolType.HTTP2

    async def handle_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        initial_data: bytes | None = None,
    ) -> None:
        """Handle an HTTP/2 connection."""
        self._reader = reader
        self._writer = writer

        # Create h2 connection
        config = h2.config.H2Configuration(
            client_side=self._is_client,
            header_encoding="utf-8",
        )
        self._conn = h2.connection.H2Connection(config=config)

        # Initiate connection
        if self._is_client:
            self._conn.initiate_connection()
            await self._send_pending()
        else:
            # Server waits for client preface
            if initial_data:
                await self._handle_data(initial_data)

        # Main event loop
        try:
            while not self._closed:
                try:
                    data = await asyncio.wait_for(reader.read(65535), timeout=30.0)
                except TimeoutError:
                    # Send ping to check connection
                    if self._conn:
                        self._conn.ping(b"keepaliv")
                        await self._send_pending()
                    continue

                if not data:
                    break

                await self._handle_data(data)

        except Exception as e:
            logger.error("HTTP/2 connection error", error=str(e))
        finally:
            await self.close()

    async def _handle_data(self, data: bytes) -> None:
        """Process incoming data and handle h2 events."""
        if not self._conn:
            return

        try:
            events = self._conn.receive_data(data)
        except h2.exceptions.ProtocolError as e:
            logger.error("HTTP/2 protocol error", error=str(e))
            return

        for event in events:
            await self._handle_event(event)

        await self._send_pending()

    async def _handle_event(self, event: Any) -> None:
        """Handle an h2 event."""
        if isinstance(event, h2.events.RequestReceived):
            await self._on_request_received(event)
        elif isinstance(event, h2.events.DataReceived):
            await self._on_data_received(event)
        elif isinstance(event, h2.events.StreamEnded):
            await self._on_stream_ended(event)
        elif isinstance(event, h2.events.StreamReset):
            self._on_stream_reset(event)
        elif isinstance(event, h2.events.WindowUpdated):
            pass  # Flow control - we can send more data
        elif isinstance(event, h2.events.PingAckReceived):
            logger.debug("HTTP/2 ping acknowledged")
        elif isinstance(event, h2.events.ConnectionTerminated):
            logger.info("HTTP/2 connection terminated")
            self._closed = True

    async def _on_request_received(self, event: h2.events.RequestReceived) -> None:
        """Handle incoming request headers."""
        stream_id = event.stream_id
        headers = dict(event.headers)

        self._streams[stream_id] = HTTP2Stream(
            stream_id=stream_id,
            headers=headers,
        )

        logger.debug(
            "HTTP/2 request received",
            stream_id=stream_id,
            method=headers.get(":method"),
            path=headers.get(":path"),
        )

    async def _on_data_received(self, event: h2.events.DataReceived) -> None:
        """Handle incoming data."""
        stream_id = event.stream_id
        if stream_id in self._streams:
            self._streams[stream_id].request_data += event.data

        # Acknowledge the received data for flow control
        if self._conn:
            self._conn.acknowledge_received_data(len(event.data), stream_id)

    async def _on_stream_ended(self, event: h2.events.StreamEnded) -> None:
        """Handle stream end (request complete)."""
        stream_id = event.stream_id
        if stream_id not in self._streams:
            return

        stream = self._streams[stream_id]
        stream.end_stream_received = True

        # Process the request if we have a handler
        if self._on_request and not self._is_client:
            try:
                async for chunk in self._on_request(
                    stream_id,
                    stream.headers,
                    stream.request_data,
                ):
                    await self.send_data(stream_id, chunk)
                await self.end_stream(stream_id)
            except Exception as e:
                logger.error("Request handler error", stream_id=stream_id, error=str(e))
                await self.reset_stream(stream_id)

    def _on_stream_reset(self, event: h2.events.StreamReset) -> None:
        """Handle stream reset."""
        stream_id = event.stream_id
        if stream_id in self._streams:
            del self._streams[stream_id]
        logger.debug("HTTP/2 stream reset", stream_id=stream_id)

    async def _send_pending(self) -> None:
        """Send any pending data from h2."""
        if not self._conn or not self._writer:
            return

        async with self._lock:
            data = self._conn.data_to_send()
            if data:
                self._writer.write(data)
                await self._writer.drain()

    async def send_headers(
        self,
        stream_id: int,
        headers: list[tuple[str, str]],
        end_stream: bool = False,
    ) -> None:
        """Send response headers on a stream."""
        if not self._conn:
            return

        self._conn.send_headers(stream_id, headers, end_stream=end_stream)
        await self._send_pending()

    async def send_data(
        self,
        stream_id: int,
        data: bytes,
        end_stream: bool = False,
    ) -> None:
        """Send data on a stream."""
        if not self._conn:
            return

        # Respect flow control
        while data:
            available = self._conn.local_flow_control_window(stream_id)
            chunk_size = min(len(data), available, self._max_frame_size)

            if chunk_size == 0:
                # Wait for window update
                await asyncio.sleep(0.01)
                continue

            chunk = data[:chunk_size]
            data = data[chunk_size:]

            is_end = end_stream and not data
            self._conn.send_data(stream_id, chunk, end_stream=is_end)
            await self._send_pending()

    async def end_stream(self, stream_id: int) -> None:
        """End a stream."""
        if not self._conn:
            return

        self._conn.end_stream(stream_id)
        await self._send_pending()

        if stream_id in self._streams:
            self._streams[stream_id].is_complete = True

    async def reset_stream(self, stream_id: int, error_code: int = 0) -> None:
        """Reset a stream with an error."""
        if not self._conn:
            return

        self._conn.reset_stream(stream_id, error_code)
        await self._send_pending()

        if stream_id in self._streams:
            del self._streams[stream_id]

    async def close(self) -> None:
        """Close the HTTP/2 connection."""
        if self._closed:
            return

        self._closed = True

        if self._conn:
            try:
                self._conn.close_connection()
                await self._send_pending()
            except Exception:
                pass

        if self._writer:
            try:
                self._writer.close()
                await self._writer.wait_closed()
            except Exception:
                pass

        self._streams.clear()
        logger.debug("HTTP/2 connection closed")


# ==============================================================================
# gRPC Passthrough Handler
# ==============================================================================


@dataclass
class GrpcFrame:
    """Represents a gRPC frame."""

    compressed: bool
    length: int
    data: bytes


class GrpcPassthroughHandler(ProtocolHandler):
    """gRPC passthrough handler.

    Detects gRPC traffic via application/grpc content-type and
    passes through frames without modification.
    """

    GRPC_HEADER_SIZE = 5  # 1 byte compressed flag + 4 bytes length

    def __init__(
        self,
        target_host: str = "localhost",
        target_port: int = 50051,
        on_frame: Callable[[GrpcFrame, bool], None] | None = None,
    ) -> None:
        """Initialize gRPC passthrough handler.

        Args:
            target_host: Target gRPC server host.
            target_port: Target gRPC server port.
            on_frame: Callback for intercepted frames (upstream=True for client->server).
        """
        self._target_host = target_host
        self._target_port = target_port
        self._on_frame = on_frame
        self._closed = False

    @property
    def protocol_type(self) -> ProtocolType:
        return ProtocolType.GRPC

    @staticmethod
    def is_grpc_request(headers: dict[str, str]) -> bool:
        """Check if headers indicate a gRPC request."""
        content_type = headers.get("content-type", "").lower()
        return content_type.startswith("application/grpc")

    @staticmethod
    def parse_frame(data: bytes) -> tuple[GrpcFrame | None, bytes]:
        """Parse a gRPC frame from data.

        Returns:
            Tuple of (parsed frame or None, remaining data).
        """
        if len(data) < GrpcPassthroughHandler.GRPC_HEADER_SIZE:
            return None, data

        compressed = bool(data[0])
        length = struct.unpack(">I", data[1:5])[0]

        total_size = GrpcPassthroughHandler.GRPC_HEADER_SIZE + length
        if len(data) < total_size:
            return None, data

        frame_data = data[5 : 5 + length]
        remaining = data[total_size:]

        return GrpcFrame(compressed=compressed, length=length, data=frame_data), remaining

    @staticmethod
    def encode_frame(frame: GrpcFrame) -> bytes:
        """Encode a gRPC frame to bytes."""
        header = bytes([1 if frame.compressed else 0])
        header += struct.pack(">I", len(frame.data))
        return header + frame.data

    async def handle_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        initial_data: bytes | None = None,
    ) -> None:
        """Handle gRPC passthrough connection."""
        # Connect to target gRPC server
        try:
            target_reader, target_writer = await asyncio.open_connection(
                self._target_host,
                self._target_port,
            )
        except Exception as e:
            logger.error(
                "Failed to connect to gRPC target",
                host=self._target_host,
                port=self._target_port,
                error=str(e),
            )
            writer.close()
            return

        # Forward initial data if any
        if initial_data:
            target_writer.write(initial_data)
            await target_writer.drain()

        # Create bidirectional relay tasks
        async def relay(
            src: asyncio.StreamReader,
            dst: asyncio.StreamWriter,
            upstream: bool,
        ) -> None:
            buffer = b""
            try:
                while not self._closed:
                    data = await src.read(65535)
                    if not data:
                        break

                    # Parse and optionally intercept frames
                    if self._on_frame:
                        buffer += data
                        while True:
                            frame, buffer = self.parse_frame(buffer)
                            if frame is None:
                                break
                            self._on_frame(frame, upstream)

                    dst.write(data)
                    await dst.drain()
            except Exception as e:
                logger.debug("gRPC relay error", upstream=upstream, error=str(e))
            finally:
                with contextlib.suppress(Exception):
                    dst.close()

        # Run both directions concurrently
        try:
            await asyncio.gather(
                relay(reader, target_writer, upstream=True),
                relay(target_reader, writer, upstream=False),
            )
        finally:
            await self.close()
            target_writer.close()

    async def close(self) -> None:
        """Close the handler."""
        self._closed = True


# ==============================================================================
# WebSocket Handler
# ==============================================================================


@dataclass
class WebSocketFrame:
    """Represents a WebSocket frame."""

    opcode: int
    payload: bytes
    fin: bool = True
    rsv1: bool = False
    rsv2: bool = False
    rsv3: bool = False
    mask_key: bytes | None = None


class WebSocketOpcode(IntEnum):
    """WebSocket frame opcodes."""

    CONTINUATION = 0x0
    TEXT = 0x1
    BINARY = 0x2
    CLOSE = 0x8
    PING = 0x9
    PONG = 0xA


class WebSocketHandler(ProtocolHandler):
    """WebSocket handler with full bidirectional streaming support.

    Handles WebSocket upgrade and provides frame-level access for
    passthrough or message interception.
    """

    def __init__(
        self,
        on_message: Callable[[bytes, bool], None] | None = None,
        on_close: Callable[[int, str], None] | None = None,
        auto_ping: bool = True,
        ping_interval: float = 30.0,
    ) -> None:
        """Initialize WebSocket handler.

        Args:
            on_message: Callback for received messages (data, is_text).
            on_close: Callback for close events (code, reason).
            auto_ping: Automatically send pings for keep-alive.
            ping_interval: Interval between pings in seconds.
        """
        self._on_message = on_message
        self._on_close = on_close
        self._auto_ping = auto_ping
        self._ping_interval = ping_interval
        self._closed = False
        self._writer: asyncio.StreamWriter | None = None
        self._ping_task: asyncio.Task[Any] | None = None

    @property
    def protocol_type(self) -> ProtocolType:
        return ProtocolType.WEBSOCKET

    @staticmethod
    def is_upgrade_request(headers: dict[str, str]) -> bool:
        """Check if headers indicate a WebSocket upgrade request."""
        upgrade = headers.get("upgrade", "").lower()
        connection = headers.get("connection", "").lower()
        return "websocket" in upgrade and "upgrade" in connection

    @staticmethod
    def parse_frame(data: bytes) -> tuple[WebSocketFrame | None, bytes]:
        """Parse a WebSocket frame from data.

        Returns:
            Tuple of (parsed frame or None, remaining data).
        """
        if len(data) < 2:
            return None, data

        first_byte = data[0]
        second_byte = data[1]

        fin = bool(first_byte & 0x80)
        rsv1 = bool(first_byte & 0x40)
        rsv2 = bool(first_byte & 0x20)
        rsv3 = bool(first_byte & 0x10)
        opcode = first_byte & 0x0F

        masked = bool(second_byte & 0x80)
        payload_len = second_byte & 0x7F

        offset = 2

        if payload_len == 126:
            if len(data) < offset + 2:
                return None, data
            payload_len = struct.unpack(">H", data[offset : offset + 2])[0]
            offset += 2
        elif payload_len == 127:
            if len(data) < offset + 8:
                return None, data
            payload_len = struct.unpack(">Q", data[offset : offset + 8])[0]
            offset += 8

        mask_key = None
        if masked:
            if len(data) < offset + 4:
                return None, data
            mask_key = data[offset : offset + 4]
            offset += 4

        if len(data) < offset + payload_len:
            return None, data

        payload = data[offset : offset + payload_len]

        # Unmask if masked
        if mask_key:
            payload = bytes(b ^ mask_key[i % 4] for i, b in enumerate(payload))

        remaining = data[offset + payload_len :]

        return (
            WebSocketFrame(
                opcode=opcode,
                payload=payload,
                fin=fin,
                rsv1=rsv1,
                rsv2=rsv2,
                rsv3=rsv3,
                mask_key=mask_key,
            ),
            remaining,
        )

    @staticmethod
    def encode_frame(
        opcode: int,
        payload: bytes,
        fin: bool = True,
        mask: bool = False,
    ) -> bytes:
        """Encode a WebSocket frame."""
        import os

        frame = bytearray()

        # First byte: FIN + opcode
        first_byte = (0x80 if fin else 0) | opcode
        frame.append(first_byte)

        # Payload length
        length = len(payload)
        if length < 126:
            frame.append((0x80 if mask else 0) | length)
        elif length < 65536:
            frame.append((0x80 if mask else 0) | 126)
            frame.extend(struct.pack(">H", length))
        else:
            frame.append((0x80 if mask else 0) | 127)
            frame.extend(struct.pack(">Q", length))

        # Mask key and masked payload
        if mask:
            mask_key = os.urandom(4)
            frame.extend(mask_key)
            masked_payload = bytes(b ^ mask_key[i % 4] for i, b in enumerate(payload))
            frame.extend(masked_payload)
        else:
            frame.extend(payload)

        return bytes(frame)

    async def handle_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        initial_data: bytes | None = None,
    ) -> None:
        """Handle WebSocket connection after upgrade."""
        self._writer = writer

        # Start ping task if enabled
        if self._auto_ping:
            self._ping_task = asyncio.create_task(self._ping_loop())

        buffer = initial_data or b""

        try:
            while not self._closed:
                # Read more data
                try:
                    data = await asyncio.wait_for(reader.read(65535), timeout=60.0)
                except TimeoutError:
                    continue

                if not data:
                    break

                buffer += data

                # Parse frames from buffer
                while buffer:
                    frame, buffer = self.parse_frame(buffer)
                    if frame is None:
                        break

                    await self._handle_frame(frame)

        except Exception as e:
            logger.error("WebSocket error", error=str(e))
        finally:
            await self.close()

    async def _handle_frame(self, frame: WebSocketFrame) -> None:
        """Handle a received WebSocket frame."""
        opcode = frame.opcode

        if opcode == WebSocketOpcode.TEXT:
            if self._on_message:
                self._on_message(frame.payload, True)
        elif opcode == WebSocketOpcode.BINARY:
            if self._on_message:
                self._on_message(frame.payload, False)
        elif opcode == WebSocketOpcode.PING:
            # Respond with pong
            await self.send_pong(frame.payload)
        elif opcode == WebSocketOpcode.PONG:
            logger.debug("WebSocket pong received")
        elif opcode == WebSocketOpcode.CLOSE:
            code = 1000
            reason = ""
            if len(frame.payload) >= 2:
                code = struct.unpack(">H", frame.payload[:2])[0]
                reason = frame.payload[2:].decode("utf-8", errors="ignore")
            if self._on_close:
                self._on_close(code, reason)
            await self.close(code, reason)

    async def send_text(self, message: str) -> None:
        """Send a text message."""
        await self._send_frame(WebSocketOpcode.TEXT, message.encode("utf-8"))

    async def send_binary(self, data: bytes) -> None:
        """Send a binary message."""
        await self._send_frame(WebSocketOpcode.BINARY, data)

    async def send_ping(self, data: bytes = b"") -> None:
        """Send a ping frame."""
        await self._send_frame(WebSocketOpcode.PING, data)

    async def send_pong(self, data: bytes = b"") -> None:
        """Send a pong frame."""
        await self._send_frame(WebSocketOpcode.PONG, data)

    async def _send_frame(self, opcode: int, payload: bytes) -> None:
        """Send a WebSocket frame."""
        if not self._writer or self._closed:
            return

        frame = self.encode_frame(opcode, payload, mask=False)
        self._writer.write(frame)
        await self._writer.drain()

    async def _ping_loop(self) -> None:
        """Send periodic pings."""
        while not self._closed:
            await asyncio.sleep(self._ping_interval)
            if not self._closed:
                await self.send_ping(b"ping")

    async def close(self, code: int = 1000, reason: str = "") -> None:
        """Close the WebSocket connection."""
        if self._closed:
            return

        self._closed = True

        # Cancel ping task
        if self._ping_task:
            self._ping_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._ping_task

        # Send close frame
        if self._writer:
            try:
                payload = struct.pack(">H", code) + reason.encode("utf-8")
                await self._send_frame(WebSocketOpcode.CLOSE, payload)
                self._writer.close()
                await self._writer.wait_closed()
            except Exception:
                pass

        logger.debug("WebSocket connection closed", code=code, reason=reason)


# ==============================================================================
# Raw TCP Tunnel Handler
# ==============================================================================


@dataclass
class TcpTunnelStats:
    """Statistics for a TCP tunnel."""

    bytes_sent: int = 0
    bytes_received: int = 0
    start_time: float = 0.0
    tunnel_id: UUID = field(default_factory=uuid4)


class TcpTunnelHandler(ProtocolHandler):
    """Raw TCP tunnel handler.

    Provides transparent TCP passthrough for any binary protocol.
    """

    def __init__(
        self,
        target_host: str,
        target_port: int,
        on_data: Callable[[bytes, bool], bytes | None] | None = None,
        buffer_size: int = 65535,
    ) -> None:
        """Initialize TCP tunnel handler.

        Args:
            target_host: Target server host.
            target_port: Target server port.
            on_data: Optional callback for data interception (data, upstream).
                     Return modified data or None to pass through unchanged.
            buffer_size: Read buffer size.
        """
        self._target_host = target_host
        self._target_port = target_port
        self._on_data = on_data
        self._buffer_size = buffer_size
        self._closed = False
        self._stats = TcpTunnelStats()

    @property
    def protocol_type(self) -> ProtocolType:
        return ProtocolType.TCP

    @property
    def stats(self) -> TcpTunnelStats:
        """Get tunnel statistics."""
        return self._stats

    async def handle_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        initial_data: bytes | None = None,
    ) -> None:
        """Handle TCP tunnel connection."""
        import time

        self._stats.start_time = time.time()

        # Connect to target
        try:
            target_reader, target_writer = await asyncio.open_connection(
                self._target_host,
                self._target_port,
            )
        except Exception as e:
            logger.error(
                "Failed to connect to TCP target",
                host=self._target_host,
                port=self._target_port,
                error=str(e),
            )
            writer.close()
            return

        logger.info(
            "TCP tunnel established",
            tunnel_id=str(self._stats.tunnel_id),
            target=f"{self._target_host}:{self._target_port}",
        )

        # Forward initial data if any
        if initial_data:
            data = initial_data
            if self._on_data:
                modified = self._on_data(data, True)
                if modified is not None:
                    data = modified
            target_writer.write(data)
            await target_writer.drain()
            self._stats.bytes_sent += len(data)

        # Create bidirectional relay
        async def relay(
            src: asyncio.StreamReader,
            dst: asyncio.StreamWriter,
            upstream: bool,
        ) -> None:
            try:
                while not self._closed:
                    data = await src.read(self._buffer_size)
                    if not data:
                        break

                    # Optional data interception
                    if self._on_data:
                        modified = self._on_data(data, upstream)
                        if modified is not None:
                            data = modified

                    dst.write(data)
                    await dst.drain()

                    if upstream:
                        self._stats.bytes_sent += len(data)
                    else:
                        self._stats.bytes_received += len(data)

            except Exception as e:
                logger.debug("TCP relay error", upstream=upstream, error=str(e))
            finally:
                with contextlib.suppress(Exception):
                    dst.close()

        try:
            await asyncio.gather(
                relay(reader, target_writer, upstream=True),
                relay(target_reader, writer, upstream=False),
            )
        finally:
            await self.close()
            target_writer.close()

        logger.info(
            "TCP tunnel closed",
            tunnel_id=str(self._stats.tunnel_id),
            bytes_sent=self._stats.bytes_sent,
            bytes_received=self._stats.bytes_received,
        )

    async def close(self) -> None:
        """Close the tunnel."""
        self._closed = True


# ==============================================================================
# UDP Handler (via QUIC datagrams)
# ==============================================================================


@dataclass
class UdpDatagram:
    """Represents a UDP datagram."""

    data: bytes
    source_addr: tuple[str, int] | None = None
    dest_addr: tuple[str, int] | None = None
    timestamp: float = 0.0


class UdpHandler(ProtocolHandler):
    """UDP handler supporting QUIC datagram transport.

    Provides UDP tunneling over QUIC's unreliable datagram extension
    for low-latency applications.
    """

    def __init__(
        self,
        target_host: str,
        target_port: int,
        on_datagram: Callable[[UdpDatagram, bool], None] | None = None,
        max_datagram_size: int = 1200,
    ) -> None:
        """Initialize UDP handler.

        Args:
            target_host: Target UDP server host.
            target_port: Target UDP server port.
            on_datagram: Callback for received datagrams (datagram, upstream).
            max_datagram_size: Maximum datagram size.
        """
        self._target_host = target_host
        self._target_port = target_port
        self._on_datagram = on_datagram
        self._max_datagram_size = max_datagram_size
        self._closed = False
        self._transport: asyncio.DatagramTransport | None = None
        self._protocol: asyncio.DatagramProtocol | None = None

    @property
    def protocol_type(self) -> ProtocolType:
        return ProtocolType.UDP

    async def handle_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        initial_data: bytes | None = None,
    ) -> None:
        """Handle UDP tunnel setup.

        Note: For true UDP, this would use QUIC datagrams. This implementation
        provides a simplified interface that could be backed by QUIC.
        """
        # Create UDP socket for target
        loop = asyncio.get_event_loop()

        class UdpRelayProtocol(asyncio.DatagramProtocol):
            def __init__(self, handler: UdpHandler, writer: asyncio.StreamWriter):
                self.handler = handler
                self.writer = writer

            def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
                import time

                datagram = UdpDatagram(
                    data=data,
                    source_addr=addr,
                    timestamp=time.time(),
                )
                if self.handler._on_datagram:
                    self.handler._on_datagram(datagram, False)

                # Encode and send over tunnel
                # Format: 2 bytes length + data
                encoded = struct.pack(">H", len(data)) + data
                self.writer.write(encoded)

            def error_received(self, exc: Exception) -> None:
                logger.error("UDP error", error=str(exc))

        try:
            transport, protocol = await loop.create_datagram_endpoint(
                lambda: UdpRelayProtocol(self, writer),
                remote_addr=(self._target_host, self._target_port),
            )
            self._transport = transport
            self._protocol = protocol

            # Read from tunnel and send as UDP
            buffer = initial_data or b""
            while not self._closed:
                try:
                    data = await asyncio.wait_for(reader.read(65535), timeout=30.0)
                except TimeoutError:
                    continue

                if not data:
                    break

                buffer += data

                # Parse length-prefixed datagrams
                while len(buffer) >= 2:
                    length = struct.unpack(">H", buffer[:2])[0]
                    if len(buffer) < 2 + length:
                        break

                    datagram_data = buffer[2 : 2 + length]
                    buffer = buffer[2 + length :]

                    # Send as UDP
                    import time

                    datagram = UdpDatagram(
                        data=datagram_data,
                        dest_addr=(self._target_host, self._target_port),
                        timestamp=time.time(),
                    )
                    if self._on_datagram:
                        self._on_datagram(datagram, True)

                    transport.sendto(datagram_data)

        except Exception as e:
            logger.error("UDP tunnel error", error=str(e))
        finally:
            await self.close()

    async def send_datagram(self, data: bytes) -> None:
        """Send a UDP datagram."""
        if self._transport and not self._closed:
            self._transport.sendto(data)

    async def close(self) -> None:
        """Close the UDP handler."""
        self._closed = True
        if self._transport:
            self._transport.close()
            self._transport = None


# ==============================================================================
# Protocol Router
# ==============================================================================


class ProtocolRouter:
    """Routes incoming connections to appropriate protocol handlers.

    Combines protocol detection with handler dispatch for unified
    multi-protocol support.
    """

    def __init__(
        self,
        default_handler: ProtocolHandler | None = None,
    ) -> None:
        """Initialize the protocol router.

        Args:
            default_handler: Default handler for unknown protocols.
        """
        self._detector = ProtocolDetector()
        self._handlers: dict[ProtocolType, ProtocolHandler] = {}
        self._default_handler = default_handler

    def register_handler(
        self,
        protocol: ProtocolType,
        handler: ProtocolHandler,
    ) -> None:
        """Register a handler for a protocol type.

        Args:
            protocol: Protocol type to handle.
            handler: Handler instance.
        """
        self._handlers[protocol] = handler

    def get_handler(self, protocol: ProtocolType) -> ProtocolHandler | None:
        """Get handler for a protocol type."""
        return self._handlers.get(protocol, self._default_handler)

    async def route_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Detect protocol and route to appropriate handler.

        Args:
            reader: Async stream reader.
            writer: Async stream writer.
        """
        # Detect protocol
        result, initial_data = await self._detector.detect(reader)

        logger.info(
            "Protocol detected",
            protocol=result.protocol.name,
            confidence=result.confidence,
        )

        # Get handler
        handler = self.get_handler(result.protocol)
        if handler is None:
            logger.warning(
                "No handler for protocol",
                protocol=result.protocol.name,
            )
            writer.close()
            return

        # Handle connection
        try:
            await handler.handle_connection(reader, writer, initial_data)
        except Exception as e:
            logger.error(
                "Handler error",
                protocol=result.protocol.name,
                error=str(e),
            )
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    async def close_all(self) -> None:
        """Close all registered handlers."""
        for handler in self._handlers.values():
            try:
                await handler.close()
            except Exception as e:
                logger.warning("Error closing handler", error=str(e))
