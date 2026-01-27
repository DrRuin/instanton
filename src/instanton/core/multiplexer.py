"""Multiplexer."""

from __future__ import annotations

import asyncio
import time
from collections import deque
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any
from uuid import UUID, uuid4

import structlog

if TYPE_CHECKING:
    from aioquic.quic.connection import QuicConnection

logger = structlog.get_logger()


@dataclass
class StreamState:
    stream_id: int
    request_id: UUID
    created_at: float = field(default_factory=time.monotonic)
    bytes_sent: int = 0
    bytes_received: int = 0
    recv_buffer: asyncio.Queue[bytes] = field(default_factory=lambda: asyncio.Queue(maxsize=1000))
    closed: bool = False
    end_stream_received: bool = False


class StreamMultiplexer:
    def __init__(self, quic: QuicConnection, protocol: Any, max_streams: int = 100) -> None:
        self._quic = quic
        self._protocol = protocol
        self._max_streams = max_streams
        self._streams: dict[int, StreamState] = {}
        self._request_to_stream: dict[UUID, int] = {}
        self._stream_pool: deque[int] = deque()
        self._lock = asyncio.Lock()
        self._stats = {
            "streams_created": 0,
            "streams_closed": 0,
            "streams_reused": 0,
        }

    async def create_stream(self, request_id: UUID | None = None) -> StreamState:
        async with self._lock:
            if len(self._streams) >= self._max_streams:
                raise RuntimeError(f"Max streams reached: {self._max_streams}")

            if self._stream_pool:
                stream_id = self._stream_pool.popleft()
                self._stats["streams_reused"] += 1
            else:
                stream_id = self._quic.get_next_available_stream_id()
                self._stats["streams_created"] += 1

            rid = request_id or uuid4()
            state = StreamState(stream_id=stream_id, request_id=rid)
            self._streams[stream_id] = state
            self._request_to_stream[rid] = stream_id
            return state

    async def get_stream(self, stream_id: int) -> StreamState | None:
        return self._streams.get(stream_id)

    async def get_stream_by_request(self, request_id: UUID) -> StreamState | None:
        stream_id = self._request_to_stream.get(request_id)
        if stream_id is not None:
            return self._streams.get(stream_id)
        return None

    async def send(self, stream_id: int, data: bytes, end_stream: bool = False) -> None:
        state = self._streams.get(stream_id)
        if state is None or state.closed:
            raise RuntimeError(f"Stream {stream_id} not available")

        self._quic.send_stream_data(stream_id, data, end_stream=end_stream)
        self._protocol.transmit()
        state.bytes_sent += len(data)

        if end_stream:
            state.closed = True

    async def send_on_request(
        self, request_id: UUID, data: bytes, end_stream: bool = False
    ) -> None:
        stream_id = self._request_to_stream.get(request_id)
        if stream_id is None:
            raise RuntimeError(f"No stream for request {request_id}")
        await self.send(stream_id, data, end_stream)

    def receive_data(self, stream_id: int, data: bytes, end_stream: bool = False) -> None:
        state = self._streams.get(stream_id)
        if state is None:
            state = StreamState(stream_id=stream_id, request_id=uuid4())
            self._streams[stream_id] = state
            self._request_to_stream[state.request_id] = stream_id

        if data:
            try:
                state.recv_buffer.put_nowait(data)
                state.bytes_received += len(data)
            except asyncio.QueueFull:
                pass

        if end_stream:
            state.end_stream_received = True
            try:
                state.recv_buffer.put_nowait(b"")
            except asyncio.QueueFull:
                pass

    async def recv(self, stream_id: int, timeout: float | None = None) -> bytes | None:
        state = self._streams.get(stream_id)
        if state is None:
            return None

        try:
            if timeout is not None:
                data = await asyncio.wait_for(state.recv_buffer.get(), timeout=timeout)
            else:
                data = await state.recv_buffer.get()

            if data == b"" and state.end_stream_received:
                return None
            return data
        except (TimeoutError, asyncio.CancelledError):
            return None

    async def recv_on_request(self, request_id: UUID, timeout: float | None = None) -> bytes | None:
        stream_id = self._request_to_stream.get(request_id)
        if stream_id is None:
            return None
        return await self.recv(stream_id, timeout)

    async def close_stream(self, stream_id: int, reusable: bool = True) -> None:
        async with self._lock:
            state = self._streams.pop(stream_id, None)
            if state is None:
                return

            self._request_to_stream.pop(state.request_id, None)
            state.closed = True
            self._stats["streams_closed"] += 1

            if reusable and len(self._stream_pool) < 20:
                self._stream_pool.append(stream_id)

    async def close_by_request(self, request_id: UUID, reusable: bool = True) -> None:
        stream_id = self._request_to_stream.get(request_id)
        if stream_id is not None:
            await self.close_stream(stream_id, reusable)

    async def close_all(self) -> None:
        async with self._lock:
            for state in self._streams.values():
                state.closed = True
            self._streams.clear()
            self._request_to_stream.clear()
            self._stream_pool.clear()

    @property
    def active_stream_count(self) -> int:
        return len(self._streams)

    def get_stats(self) -> dict[str, Any]:
        return {
            "active_streams": len(self._streams),
            "pooled_streams": len(self._stream_pool),
            **self._stats,
        }
