"""Pool."""

from __future__ import annotations

import asyncio
import time
from typing import TYPE_CHECKING, Any, ClassVar
from uuid import UUID

import structlog

from instanton.core.config import get_config
from instanton.protocol.messages import decode_message

if TYPE_CHECKING:
    from instanton.core.transport import QuicTransport

logger = structlog.get_logger()


class MessageRouter:
    def __init__(self) -> None:
        self._subscriptions: dict[UUID, asyncio.Queue[bytes]] = {}
        self._lock = asyncio.Lock()

    async def subscribe(self, tunnel_id: UUID) -> asyncio.Queue[bytes]:
        async with self._lock:
            if tunnel_id in self._subscriptions:
                return self._subscriptions[tunnel_id]
            queue: asyncio.Queue[bytes] = asyncio.Queue(maxsize=1000)
            self._subscriptions[tunnel_id] = queue
            return queue

    async def route(self, data: bytes) -> None:
        try:
            msg = decode_message(data)
        except Exception:
            await self._broadcast(data)
            return

        tunnel_id = self._extract_tunnel_id(msg)
        if tunnel_id and tunnel_id in self._subscriptions:
            try:
                self._subscriptions[tunnel_id].put_nowait(data)
            except asyncio.QueueFull:
                pass
        else:
            await self._broadcast(data)

    def _extract_tunnel_id(self, msg: dict[str, Any]) -> UUID | None:
        for key in ("tunnel_id", "request_id"):
            val = msg.get(key)
            if val:
                try:
                    return UUID(val) if isinstance(val, str) else val
                except (ValueError, TypeError):
                    pass

        if msg.get("type") in ("connected", "error"):
            tid = msg.get("tunnel_id")
            if tid:
                try:
                    return UUID(tid) if isinstance(tid, str) else tid
                except (ValueError, TypeError):
                    pass
        return None

    async def _broadcast(self, data: bytes) -> None:
        async with self._lock:
            for queue in self._subscriptions.values():
                try:
                    queue.put_nowait(data)
                except asyncio.QueueFull:
                    pass

    async def unsubscribe(self, tunnel_id: UUID) -> None:
        async with self._lock:
            self._subscriptions.pop(tunnel_id, None)

    @property
    def subscriber_count(self) -> int:
        return len(self._subscriptions)

    def get_stats(self) -> dict[str, Any]:
        return {
            "subscriber_count": len(self._subscriptions),
            "tunnel_ids": [str(tid) for tid in self._subscriptions.keys()],
        }


class TransportPool:
    _pools: ClassVar[dict[str, TransportPool]] = {}
    _pools_lock: ClassVar[asyncio.Lock | None] = None

    def __init__(self, server_addr: str) -> None:
        self._server_addr = server_addr
        self._transport: QuicTransport | None = None
        self._router = MessageRouter()
        self._tunnel_count = 0
        self._lock = asyncio.Lock()
        self._recv_task: asyncio.Task[Any] | None = None
        self._last_activity = time.monotonic()
        self._created_at = time.monotonic()
        self._closed = False

    @classmethod
    def _get_pools_lock(cls) -> asyncio.Lock:
        if cls._pools_lock is None:
            cls._pools_lock = asyncio.Lock()
        return cls._pools_lock

    @classmethod
    async def get_pool(cls, server_addr: str) -> TransportPool:
        async with cls._get_pools_lock():
            if server_addr not in cls._pools:
                cls._pools[server_addr] = TransportPool(server_addr)
            return cls._pools[server_addr]

    @classmethod
    async def close_pool(cls, server_addr: str) -> None:
        async with cls._get_pools_lock():
            if server_addr in cls._pools:
                pool = cls._pools.pop(server_addr)
                await pool.close()

    @classmethod
    async def close_all_pools(cls) -> None:
        async with cls._get_pools_lock():
            for pool in cls._pools.values():
                await pool.close()
            cls._pools.clear()

    @classmethod
    def get_pool_stats(cls) -> dict[str, Any]:
        stats = {}
        for addr, pool in cls._pools.items():
            stats[addr] = {
                "tunnel_count": pool._tunnel_count,
                "router_subscribers": pool._router.subscriber_count,
                "has_transport": pool._transport is not None,
                "closed": pool._closed,
                "age_seconds": time.monotonic() - pool._created_at,
                "idle_seconds": time.monotonic() - pool._last_activity,
            }
        return stats

    async def acquire(
        self,
        tunnel_id: UUID,
        transport_factory: Any,
    ) -> tuple[Any, asyncio.Queue[bytes]]:
        async with self._lock:
            if self._closed:
                raise RuntimeError("Pool closed")

            config = get_config().pool
            if self._tunnel_count >= config.max_tunnels_per_connection:
                raise RuntimeError(f"Pool at capacity: {self._tunnel_count}")

            if self._transport is None:
                self._transport = await transport_factory()
                await self._transport.connect(self._server_addr)
                self._start_recv_loop()

            queue = await self._router.subscribe(tunnel_id)
            self._tunnel_count += 1
            self._last_activity = time.monotonic()
            return self._transport, queue

    async def release(self, tunnel_id: UUID) -> None:
        async with self._lock:
            await self._router.unsubscribe(tunnel_id)
            self._tunnel_count = max(0, self._tunnel_count - 1)
            self._last_activity = time.monotonic()

            if self._tunnel_count == 0:
                await self._close_transport()

    def _start_recv_loop(self) -> None:
        if self._recv_task is not None:
            return
        self._recv_task = asyncio.create_task(self._recv_loop())

    async def _recv_loop(self) -> None:
        try:
            while not self._closed and self._transport and self._transport.is_connected():
                data = await self._transport.recv()
                if data is None:
                    break
                self._last_activity = time.monotonic()
                await self._router.route(data)
        except asyncio.CancelledError:
            pass
        except Exception:
            pass

    async def _close_transport(self) -> None:
        if self._recv_task:
            self._recv_task.cancel()
            try:
                await self._recv_task
            except asyncio.CancelledError:
                pass
            self._recv_task = None

        if self._transport:
            try:
                await self._transport.close()
            except Exception:
                pass
            self._transport = None

    async def close(self) -> None:
        async with self._lock:
            self._closed = True
            await self._close_transport()
            self._tunnel_count = 0

    @property
    def is_healthy(self) -> bool:
        if self._transport is None:
            return True
        return self._transport.is_connected()

    @property
    def tunnel_count(self) -> int:
        return self._tunnel_count

    def get_stats(self) -> dict[str, Any]:
        return {
            "server_addr": self._server_addr,
            "tunnel_count": self._tunnel_count,
            "has_transport": self._transport is not None,
            "transport_connected": self._transport.is_connected() if self._transport else False,
            "router_stats": self._router.get_stats(),
            "closed": self._closed,
            "age_seconds": time.monotonic() - self._created_at,
            "idle_seconds": time.monotonic() - self._last_activity,
        }


async def cleanup_idle_pools() -> None:
    config = get_config().pool
    idle_threshold = config.idle_timeout
    now = time.monotonic()

    pools_to_close = []
    for addr, pool in TransportPool._pools.items():
        if pool._tunnel_count == 0 and (now - pool._last_activity) > idle_threshold:
            pools_to_close.append(addr)

    for addr in pools_to_close:
        await TransportPool.close_pool(addr)
