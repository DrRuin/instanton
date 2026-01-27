"""WebTransport."""

from __future__ import annotations

import asyncio
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

import structlog

if TYPE_CHECKING:
    from aioquic.h3.connection import H3Connection

logger = structlog.get_logger()


@dataclass
class WebTransportStream:
    stream_id: int
    session_id: int
    is_unidirectional: bool = False
    recv_buffer: asyncio.Queue[bytes] = field(default_factory=lambda: asyncio.Queue(maxsize=1000))
    closed: bool = False
    bytes_sent: int = 0
    bytes_received: int = 0


@dataclass
class WebTransportSession:
    session_id: int
    path: str
    streams: dict[int, WebTransportStream] = field(default_factory=dict)
    datagrams: asyncio.Queue[bytes] = field(default_factory=lambda: asyncio.Queue(maxsize=1000))
    created_at: float = field(default_factory=time.monotonic)
    closed: bool = False


class WebTransportClient:
    def __init__(self, h3_conn: H3Connection, quic_conn: Any, protocol: Any) -> None:
        self._h3 = h3_conn
        self._quic = quic_conn
        self._protocol = protocol
        self._sessions: dict[int, WebTransportSession] = {}
        self._stream_to_session: dict[int, int] = {}
        self._pending_connect: dict[int, asyncio.Future[WebTransportSession]] = {}
        self._lock = asyncio.Lock()

    async def connect(self, url: str, headers: dict[str, str] | None = None) -> WebTransportSession:
        stream_id = self._quic.get_next_available_stream_id()

        request_headers = [
            (b":method", b"CONNECT"),
            (b":protocol", b"webtransport"),
            (b":scheme", b"https"),
            (b":path", url.encode()),
        ]

        if headers:
            for k, v in headers.items():
                request_headers.append((k.encode(), v.encode()))

        self._h3.send_headers(stream_id, request_headers)
        self._protocol.transmit()

        future: asyncio.Future[WebTransportSession] = asyncio.get_event_loop().create_future()
        self._pending_connect[stream_id] = future

        try:
            session = await asyncio.wait_for(future, timeout=30.0)
            return session
        except TimeoutError:
            self._pending_connect.pop(stream_id, None)
            raise RuntimeError("WebTransport connect timeout")

    def handle_session_established(self, stream_id: int, path: str) -> WebTransportSession:
        session = WebTransportSession(session_id=stream_id, path=path)
        self._sessions[stream_id] = session

        future = self._pending_connect.pop(stream_id, None)
        if future and not future.done():
            future.set_result(session)

        return session

    async def create_bidirectional_stream(self, session_id: int) -> WebTransportStream:
        session = self._sessions.get(session_id)
        if session is None or session.closed:
            raise RuntimeError("Session not available")

        stream_id = self._quic.get_next_available_stream_id()
        stream = WebTransportStream(stream_id=stream_id, session_id=session_id)
        session.streams[stream_id] = stream
        self._stream_to_session[stream_id] = session_id
        return stream

    async def create_unidirectional_stream(self, session_id: int) -> WebTransportStream:
        session = self._sessions.get(session_id)
        if session is None or session.closed:
            raise RuntimeError("Session not available")

        stream_id = self._quic.get_next_available_stream_id(is_unidirectional=True)
        stream = WebTransportStream(
            stream_id=stream_id, session_id=session_id, is_unidirectional=True
        )
        session.streams[stream_id] = stream
        self._stream_to_session[stream_id] = session_id
        return stream

    async def send_stream_data(self, stream_id: int, data: bytes, end_stream: bool = False) -> None:
        session_id = self._stream_to_session.get(stream_id)
        if session_id is None:
            raise RuntimeError(f"Unknown stream {stream_id}")

        session = self._sessions.get(session_id)
        if session is None:
            raise RuntimeError(f"Unknown session {session_id}")

        stream = session.streams.get(stream_id)
        if stream is None or stream.closed:
            raise RuntimeError(f"Stream {stream_id} not available")

        self._quic.send_stream_data(stream_id, data, end_stream=end_stream)
        self._protocol.transmit()
        stream.bytes_sent += len(data)

        if end_stream:
            stream.closed = True

    async def recv_stream_data(self, stream_id: int, timeout: float | None = None) -> bytes | None:
        session_id = self._stream_to_session.get(stream_id)
        if session_id is None:
            return None

        session = self._sessions.get(session_id)
        if session is None:
            return None

        stream = session.streams.get(stream_id)
        if stream is None:
            return None

        try:
            if timeout is not None:
                data = await asyncio.wait_for(stream.recv_buffer.get(), timeout=timeout)
            else:
                data = await stream.recv_buffer.get()
            return data if data else None
        except (TimeoutError, asyncio.CancelledError):
            return None

    async def send_datagram(self, session_id: int, data: bytes) -> None:
        session = self._sessions.get(session_id)
        if session is None or session.closed:
            raise RuntimeError("Session not available")

        self._h3.send_datagram(session_id, data)
        self._protocol.transmit()

    async def recv_datagram(self, session_id: int, timeout: float | None = None) -> bytes | None:
        session = self._sessions.get(session_id)
        if session is None:
            return None

        try:
            if timeout is not None:
                data = await asyncio.wait_for(session.datagrams.get(), timeout=timeout)
            else:
                data = await session.datagrams.get()
            return data
        except (TimeoutError, asyncio.CancelledError):
            return None

    def handle_stream_data(self, stream_id: int, data: bytes, end_stream: bool = False) -> None:
        session_id = self._stream_to_session.get(stream_id)
        if session_id is None:
            return

        session = self._sessions.get(session_id)
        if session is None:
            return

        stream = session.streams.get(stream_id)
        if stream is None:
            stream = WebTransportStream(stream_id=stream_id, session_id=session_id)
            session.streams[stream_id] = stream
            self._stream_to_session[stream_id] = session_id

        if data:
            try:
                stream.recv_buffer.put_nowait(data)
                stream.bytes_received += len(data)
            except asyncio.QueueFull:
                pass

        if end_stream:
            stream.closed = True
            try:
                stream.recv_buffer.put_nowait(b"")
            except asyncio.QueueFull:
                pass

    def handle_datagram(self, session_id: int, data: bytes) -> None:
        session = self._sessions.get(session_id)
        if session is None:
            return

        try:
            session.datagrams.put_nowait(data)
        except asyncio.QueueFull:
            pass

    async def close_stream(self, stream_id: int) -> None:
        session_id = self._stream_to_session.pop(stream_id, None)
        if session_id is None:
            return

        session = self._sessions.get(session_id)
        if session:
            stream = session.streams.pop(stream_id, None)
            if stream:
                stream.closed = True

    async def close_session(self, session_id: int) -> None:
        session = self._sessions.pop(session_id, None)
        if session is None:
            return

        session.closed = True
        for stream_id in list(session.streams.keys()):
            self._stream_to_session.pop(stream_id, None)
        session.streams.clear()

    async def close_all(self) -> None:
        for session_id in list(self._sessions.keys()):
            await self.close_session(session_id)

    def get_stats(self) -> dict[str, Any]:
        total_streams = sum(len(s.streams) for s in self._sessions.values())
        return {
            "sessions": len(self._sessions),
            "total_streams": total_streams,
        }


class WebTransportServer:
    def __init__(self) -> None:
        self._sessions: dict[int, WebTransportSession] = {}
        self._handlers: dict[str, Callable[[WebTransportSession], Any]] = {}
        self._lock = asyncio.Lock()

    def route(
        self, path: str
    ) -> Callable[[Callable[[WebTransportSession], Any]], Callable[[WebTransportSession], Any]]:
        def decorator(
            handler: Callable[[WebTransportSession], Any],
        ) -> Callable[[WebTransportSession], Any]:
            self._handlers[path] = handler
            return handler

        return decorator

    async def handle_connect(
        self,
        stream_id: int,
        path: str,
        h3_conn: H3Connection,
        protocol: Any,
    ) -> WebTransportSession | None:
        handler = self._handlers.get(path)
        if handler is None:
            response_headers = [(b":status", b"404")]
            h3_conn.send_headers(stream_id, response_headers)
            protocol.transmit()
            return None

        session = WebTransportSession(session_id=stream_id, path=path)
        self._sessions[stream_id] = session

        response_headers = [(b":status", b"200")]
        h3_conn.send_headers(stream_id, response_headers)
        protocol.transmit()

        try:
            result = handler(session)
            if asyncio.iscoroutine(result):
                asyncio.create_task(result)
        except Exception:
            pass

        return session

    def get_session(self, session_id: int) -> WebTransportSession | None:
        return self._sessions.get(session_id)

    async def close_session(self, session_id: int) -> None:
        session = self._sessions.pop(session_id, None)
        if session:
            session.closed = True
            session.streams.clear()

    def get_stats(self) -> dict[str, Any]:
        return {
            "sessions": len(self._sessions),
            "routes": list(self._handlers.keys()),
        }
