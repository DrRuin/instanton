"""Migration."""

from __future__ import annotations

import asyncio
import socket
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any

import structlog

if TYPE_CHECKING:
    pass

logger = structlog.get_logger()


class NetworkType(Enum):
    UNKNOWN = "unknown"
    WIFI = "wifi"
    CELLULAR = "cellular"
    ETHERNET = "ethernet"
    VPN = "vpn"


@dataclass
class NetworkState:
    interface: str = ""
    ip_address: str = ""
    network_type: NetworkType = NetworkType.UNKNOWN
    timestamp: float = field(default_factory=time.monotonic)
    is_connected: bool = True


@dataclass
class MigrationState:
    old_network: NetworkState | None = None
    new_network: NetworkState | None = None
    migration_start: float = 0.0
    migration_complete: float = 0.0
    success: bool = False
    error: str | None = None


class NetworkMonitor:
    def __init__(self, check_interval: float = 2.0) -> None:
        self._check_interval = check_interval
        self._current_state: NetworkState | None = None
        self._running = False
        self._task: asyncio.Task[Any] | None = None
        self._callbacks: list[Callable[[NetworkState | None, NetworkState], Any]] = []
        self._lock = asyncio.Lock()

    def on_network_change(
        self, callback: Callable[[NetworkState | None, NetworkState], Any]
    ) -> None:
        self._callbacks.append(callback)

    async def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._current_state = await self._detect_network()
        self._task = asyncio.create_task(self._monitor_loop())

    async def stop(self) -> None:
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None

    async def _monitor_loop(self) -> None:
        while self._running:
            try:
                await asyncio.sleep(self._check_interval)
                new_state = await self._detect_network()

                if self._has_network_changed(new_state):
                    old_state = self._current_state
                    self._current_state = new_state
                    await self._fire_callbacks(old_state, new_state)
            except asyncio.CancelledError:
                break
            except Exception:
                pass

    async def _detect_network(self) -> NetworkState:
        loop = asyncio.get_event_loop()
        try:
            ip = await loop.run_in_executor(None, self._get_local_ip)
            return NetworkState(
                ip_address=ip,
                network_type=self._guess_network_type(ip),
                is_connected=ip != "127.0.0.1",
            )
        except Exception:
            return NetworkState(is_connected=False)

    def _get_local_ip(self) -> str:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(0.1)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"

    def _guess_network_type(self, ip: str) -> NetworkType:
        if ip.startswith("10.") or ip.startswith("172.") or ip.startswith("192.168."):
            return NetworkType.WIFI
        return NetworkType.UNKNOWN

    def _has_network_changed(self, new_state: NetworkState) -> bool:
        if self._current_state is None:
            return True
        if self._current_state.ip_address != new_state.ip_address:
            return True
        if self._current_state.is_connected != new_state.is_connected:
            return True
        return False

    async def _fire_callbacks(self, old: NetworkState | None, new: NetworkState) -> None:
        for cb in self._callbacks:
            try:
                result = cb(old, new)
                if asyncio.iscoroutine(result):
                    await result
            except Exception:
                pass

    @property
    def current_state(self) -> NetworkState | None:
        return self._current_state


class ConnectionMigrator:
    def __init__(self, max_migration_time: float = 10.0, max_retries: int = 3) -> None:
        self._max_migration_time = max_migration_time
        self._max_retries = max_retries
        self._migration_history: list[MigrationState] = []
        self._current_migration: MigrationState | None = None
        self._lock = asyncio.Lock()
        self._on_migration_start: list[Callable[[], Any]] = []
        self._on_migration_complete: list[Callable[[bool], Any]] = []

    def on_migration_start(self, callback: Callable[[], Any]) -> None:
        self._on_migration_start.append(callback)

    def on_migration_complete(self, callback: Callable[[bool], Any]) -> None:
        self._on_migration_complete.append(callback)

    async def begin_migration(
        self, old_network: NetworkState, new_network: NetworkState
    ) -> MigrationState:
        async with self._lock:
            if self._current_migration is not None:
                return self._current_migration

            self._current_migration = MigrationState(
                old_network=old_network,
                new_network=new_network,
                migration_start=time.monotonic(),
            )

            for cb in self._on_migration_start:
                try:
                    result = cb()
                    if asyncio.iscoroutine(result):
                        await result
                except Exception:
                    pass

            return self._current_migration

    async def complete_migration(self, success: bool, error: str | None = None) -> None:
        async with self._lock:
            if self._current_migration is None:
                return

            self._current_migration.migration_complete = time.monotonic()
            self._current_migration.success = success
            self._current_migration.error = error
            self._migration_history.append(self._current_migration)

            if len(self._migration_history) > 100:
                self._migration_history = self._migration_history[-50:]

            for cb in self._on_migration_complete:
                try:
                    result = cb(success)
                    if asyncio.iscoroutine(result):
                        await result
                except Exception:
                    pass

            self._current_migration = None

    async def migrate_connection(
        self,
        quic_conn: Any,
        protocol: Any,
        new_network: NetworkState,
    ) -> bool:
        if quic_conn is None or protocol is None:
            return False

        try:
            addr = (new_network.ip_address, 0)
            quic_conn.change_connection_id()
            protocol.transmit()
            return True
        except Exception as e:
            logger.debug("Migration failed", error=str(e))
            return False

    @property
    def is_migrating(self) -> bool:
        return self._current_migration is not None

    def get_stats(self) -> dict[str, Any]:
        successful = sum(1 for m in self._migration_history if m.success)
        failed = len(self._migration_history) - successful
        return {
            "total_migrations": len(self._migration_history),
            "successful": successful,
            "failed": failed,
            "is_migrating": self.is_migrating,
        }
