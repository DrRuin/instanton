"""Load balancing for multiple backend services."""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import random
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Generic, TypeVar

import structlog

logger = structlog.get_logger()


T = TypeVar("T")


class LoadBalancerAlgorithm(Enum):
    """Load balancing algorithms."""

    ROUND_ROBIN = "round_robin"
    WEIGHTED_ROUND_ROBIN = "weighted_round_robin"
    LEAST_CONNECTIONS = "least_connections"
    WEIGHTED_LEAST_CONNECTIONS = "weighted_least_connections"
    RANDOM = "random"
    WEIGHTED_RANDOM = "weighted_random"
    IP_HASH = "ip_hash"
    CONSISTENT_HASH = "consistent_hash"
    LEAST_RESPONSE_TIME = "least_response_time"


class BackendHealth(Enum):
    """Backend health status."""

    HEALTHY = "healthy"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"
    DRAINING = "draining"  # Accepting no new connections, finishing existing


@dataclass
class BackendStats:
    """Statistics for a backend."""

    active_connections: int = 0
    total_requests: int = 0
    total_errors: int = 0
    total_bytes_sent: int = 0
    total_bytes_received: int = 0
    avg_response_time_ms: float = 0.0
    last_response_time_ms: float = 0.0
    last_success: float | None = None
    last_failure: float | None = None
    consecutive_failures: int = 0
    consecutive_successes: int = 0


@dataclass
class Backend:
    """Represents a backend service."""

    id: str
    host: str
    port: int
    weight: int = 1
    max_connections: int = 1000
    health: BackendHealth = BackendHealth.UNKNOWN
    stats: BackendStats = field(default_factory=BackendStats)
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def address(self) -> str:
        """Get backend address."""
        return f"{self.host}:{self.port}"

    @property
    def is_available(self) -> bool:
        """Check if backend can accept connections."""
        if self.health in (BackendHealth.UNHEALTHY, BackendHealth.DRAINING):
            return False
        return not self.stats.active_connections >= self.max_connections


@dataclass
class HealthCheckConfig:
    """Health check configuration."""

    enabled: bool = True
    interval_seconds: float = 10.0
    timeout_seconds: float = 5.0
    path: str = "/health"
    expected_status: list[int] = field(default_factory=lambda: [200])
    healthy_threshold: int = 2  # Consecutive successes to mark healthy
    unhealthy_threshold: int = 3  # Consecutive failures to mark unhealthy
    protocol: str = "http"  # http, https, tcp


class LoadBalancerStrategy(ABC, Generic[T]):
    """Base class for load balancing strategies."""

    @abstractmethod
    def select(self, backends: list[Backend], context: T | None = None) -> Backend | None:
        """Select a backend based on the strategy.

        Args:
            backends: List of available backends
            context: Optional context (e.g., client IP for hashing)

        Returns:
            Selected backend or None if no backends available
        """
        pass

    def filter_available(self, backends: list[Backend]) -> list[Backend]:
        """Filter to only available backends."""
        return [b for b in backends if b.is_available]


class RoundRobinStrategy(LoadBalancerStrategy):
    """Simple round-robin load balancing."""

    def __init__(self) -> None:
        self._index = 0
        self._lock = asyncio.Lock()

    def select(self, backends: list[Backend], context: Any = None) -> Backend | None:
        available = self.filter_available(backends)
        if not available:
            return None

        # Thread-safe index increment
        idx = self._index % len(available)
        self._index = (self._index + 1) % len(available)

        return available[idx]


class WeightedRoundRobinStrategy(LoadBalancerStrategy):
    """Weighted round-robin load balancing."""

    def __init__(self) -> None:
        self._current_weight = 0
        self._current_index = -1
        self._max_weight = 0
        self._gcd_weight = 0

    def select(self, backends: list[Backend], context: Any = None) -> Backend | None:
        available = self.filter_available(backends)
        if not available:
            return None

        if len(available) == 1:
            return available[0]

        # Calculate GCD and max weight
        weights = [b.weight for b in available]
        self._max_weight = max(weights)
        self._gcd_weight = self._gcd_list(weights)

        while True:
            self._current_index = (self._current_index + 1) % len(available)
            if self._current_index == 0:
                self._current_weight -= self._gcd_weight
                if self._current_weight <= 0:
                    self._current_weight = self._max_weight

            backend = available[self._current_index]
            if backend.weight >= self._current_weight:
                return backend

    def _gcd(self, a: int, b: int) -> int:
        while b:
            a, b = b, a % b
        return a

    def _gcd_list(self, weights: list[int]) -> int:
        result = weights[0]
        for w in weights[1:]:
            result = self._gcd(result, w)
        return result


class LeastConnectionsStrategy(LoadBalancerStrategy):
    """Least connections load balancing."""

    def select(self, backends: list[Backend], context: Any = None) -> Backend | None:
        available = self.filter_available(backends)
        if not available:
            return None

        # Select backend with fewest active connections
        return min(available, key=lambda b: b.stats.active_connections)


class WeightedLeastConnectionsStrategy(LoadBalancerStrategy):
    """Weighted least connections load balancing."""

    def select(self, backends: list[Backend], context: Any = None) -> Backend | None:
        available = self.filter_available(backends)
        if not available:
            return None

        # Score = connections / weight (lower is better)
        def score(b: Backend) -> float:
            if b.weight == 0:
                return float("inf")
            return b.stats.active_connections / b.weight

        return min(available, key=score)


class RandomStrategy(LoadBalancerStrategy):
    """Random load balancing."""

    def select(self, backends: list[Backend], context: Any = None) -> Backend | None:
        available = self.filter_available(backends)
        if not available:
            return None

        return random.choice(available)


class WeightedRandomStrategy(LoadBalancerStrategy):
    """Weighted random load balancing."""

    def select(self, backends: list[Backend], context: Any = None) -> Backend | None:
        available = self.filter_available(backends)
        if not available:
            return None

        # Build weighted list
        total_weight = sum(b.weight for b in available)
        if total_weight == 0:
            return random.choice(available)

        r = random.uniform(0, total_weight)
        current = 0
        for backend in available:
            current += backend.weight
            if r <= current:
                return backend

        return available[-1]


class IPHashStrategy(LoadBalancerStrategy[str]):
    """IP hash load balancing - same IP always goes to same backend."""

    def select(self, backends: list[Backend], context: str | None = None) -> Backend | None:
        available = self.filter_available(backends)
        if not available:
            return None

        if not context:
            # Fall back to random if no IP provided
            return random.choice(available)

        # Hash the IP to select backend
        hash_value = int(hashlib.md5(context.encode()).hexdigest(), 16)
        idx = hash_value % len(available)

        return available[idx]


class ConsistentHashStrategy(LoadBalancerStrategy[str]):
    """Consistent hash ring for stable backend selection."""

    def __init__(self, replicas: int = 150) -> None:
        self._replicas = replicas
        self._ring: dict[int, str] = {}
        self._sorted_keys: list[int] = []

    def rebuild_ring(self, backends: list[Backend]) -> None:
        """Rebuild the hash ring with current backends."""
        self._ring.clear()

        for backend in backends:
            for i in range(self._replicas):
                key = f"{backend.id}:{i}"
                hash_value = int(hashlib.md5(key.encode()).hexdigest(), 16)
                self._ring[hash_value] = backend.id

        self._sorted_keys = sorted(self._ring.keys())

    def _hash(self, key: str) -> int:
        return int(hashlib.md5(key.encode()).hexdigest(), 16)

    def select(self, backends: list[Backend], context: str | None = None) -> Backend | None:
        available = self.filter_available(backends)
        if not available:
            return None

        if not context:
            return random.choice(available)

        # Rebuild ring if needed
        if len(self._ring) == 0:
            self.rebuild_ring(available)

        # Find the first ring position >= hash
        hash_value = self._hash(context)

        # Binary search for position
        idx = self._bisect(hash_value)
        if idx >= len(self._sorted_keys):
            idx = 0

        backend_id = self._ring[self._sorted_keys[idx]]

        # Find backend by ID
        for backend in available:
            if backend.id == backend_id:
                return backend

        # Backend not found (may have been removed), fall back
        return random.choice(available)

    def _bisect(self, value: int) -> int:
        """Binary search for position."""
        lo, hi = 0, len(self._sorted_keys)
        while lo < hi:
            mid = (lo + hi) // 2
            if self._sorted_keys[mid] < value:
                lo = mid + 1
            else:
                hi = mid
        return lo


class LeastResponseTimeStrategy(LoadBalancerStrategy):
    """Select backend with lowest average response time."""

    def select(self, backends: list[Backend], context: Any = None) -> Backend | None:
        available = self.filter_available(backends)
        if not available:
            return None

        # Filter to backends with some history, prefer ones with data
        with_history = [b for b in available if b.stats.total_requests > 0]
        if not with_history:
            # No history, use random
            return random.choice(available)

        return min(with_history, key=lambda b: b.stats.avg_response_time_ms)


class LoadBalancer:
    """Load balancer with health checking and multiple algorithms."""

    def __init__(
        self,
        algorithm: LoadBalancerAlgorithm = LoadBalancerAlgorithm.ROUND_ROBIN,
        health_config: HealthCheckConfig | None = None,
    ) -> None:
        self.algorithm = algorithm
        self.health_config = health_config or HealthCheckConfig()
        self._backends: dict[str, Backend] = {}
        self._strategy = self._create_strategy(algorithm)
        self._health_check_task: asyncio.Task | None = None
        self._lock = asyncio.Lock()

    def _create_strategy(self, algorithm: LoadBalancerAlgorithm) -> LoadBalancerStrategy:
        """Create strategy instance for algorithm."""
        strategies: dict[LoadBalancerAlgorithm, type[LoadBalancerStrategy]] = {
            LoadBalancerAlgorithm.ROUND_ROBIN: RoundRobinStrategy,
            LoadBalancerAlgorithm.WEIGHTED_ROUND_ROBIN: WeightedRoundRobinStrategy,
            LoadBalancerAlgorithm.LEAST_CONNECTIONS: LeastConnectionsStrategy,
            LoadBalancerAlgorithm.WEIGHTED_LEAST_CONNECTIONS: WeightedLeastConnectionsStrategy,
            LoadBalancerAlgorithm.RANDOM: RandomStrategy,
            LoadBalancerAlgorithm.WEIGHTED_RANDOM: WeightedRandomStrategy,
            LoadBalancerAlgorithm.IP_HASH: IPHashStrategy,
            LoadBalancerAlgorithm.CONSISTENT_HASH: ConsistentHashStrategy,
            LoadBalancerAlgorithm.LEAST_RESPONSE_TIME: LeastResponseTimeStrategy,
        }
        return strategies[algorithm]()

    async def start(self) -> None:
        """Start the load balancer (including health checks)."""
        if self.health_config.enabled:
            self._health_check_task = asyncio.create_task(self._health_check_loop())
        logger.info(
            "Load balancer started",
            algorithm=self.algorithm.value,
            backends=len(self._backends),
        )

    async def stop(self) -> None:
        """Stop the load balancer."""
        if self._health_check_task:
            self._health_check_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._health_check_task
        logger.info("Load balancer stopped")

    def add_backend(self, backend: Backend) -> None:
        """Add a backend to the pool."""
        self._backends[backend.id] = backend
        logger.info(
            "Backend added",
            backend_id=backend.id,
            address=backend.address,
            weight=backend.weight,
        )

    def remove_backend(self, backend_id: str) -> bool:
        """Remove a backend from the pool."""
        if backend_id in self._backends:
            del self._backends[backend_id]
            logger.info("Backend removed", backend_id=backend_id)
            return True
        return False

    def get_backend(self, backend_id: str) -> Backend | None:
        """Get a specific backend by ID."""
        return self._backends.get(backend_id)

    def list_backends(self) -> list[Backend]:
        """List all backends."""
        return list(self._backends.values())

    def select(self, context: Any = None) -> Backend | None:
        """Select a backend for a request.

        Args:
            context: Optional context (e.g., client IP for hash-based algorithms)

        Returns:
            Selected backend or None if no backends available
        """
        backends = list(self._backends.values())
        if not backends:
            return None

        return self._strategy.select(backends, context)

    async def acquire(self, context: Any = None) -> BackendConnection | None:
        """Acquire a connection to a backend.

        Args:
            context: Optional context for selection

        Returns:
            BackendConnection context manager or None
        """
        backend = self.select(context)
        if not backend:
            return None

        async with self._lock:
            backend.stats.active_connections += 1

        return BackendConnection(self, backend)

    def record_success(self, backend: Backend, response_time_ms: float) -> None:
        """Record a successful request."""
        stats = backend.stats
        stats.total_requests += 1
        stats.last_response_time_ms = response_time_ms
        stats.last_success = time.time()
        stats.consecutive_successes += 1
        stats.consecutive_failures = 0

        # Update average response time (exponential moving average)
        alpha = 0.2
        if stats.avg_response_time_ms == 0:
            stats.avg_response_time_ms = response_time_ms
        else:
            stats.avg_response_time_ms = (
                alpha * response_time_ms + (1 - alpha) * stats.avg_response_time_ms
            )

    def record_failure(self, backend: Backend) -> None:
        """Record a failed request."""
        stats = backend.stats
        stats.total_requests += 1
        stats.total_errors += 1
        stats.last_failure = time.time()
        stats.consecutive_failures += 1
        stats.consecutive_successes = 0

    def release(self, backend: Backend) -> None:
        """Release a connection to a backend."""
        if backend.stats.active_connections > 0:
            backend.stats.active_connections -= 1

    async def _health_check_loop(self) -> None:
        """Periodically health check all backends."""
        while True:
            try:
                await asyncio.sleep(self.health_config.interval_seconds)
                await self._check_all_backends()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("Health check error", error=str(e))

    async def _check_all_backends(self) -> None:
        """Check health of all backends."""
        tasks = [self._check_backend(b) for b in self._backends.values()]
        await asyncio.gather(*tasks, return_exceptions=True)

    async def _check_backend(self, backend: Backend) -> None:
        """Check health of a single backend."""
        import httpx

        try:
            if self.health_config.protocol in ("http", "https"):
                url = f"{self.health_config.protocol}://{backend.address}{self.health_config.path}"
                async with httpx.AsyncClient() as client:
                    resp = await client.get(
                        url,
                        timeout=self.health_config.timeout_seconds,
                    )
                    is_healthy = resp.status_code in self.health_config.expected_status
            else:
                # TCP check - just try to connect
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(backend.host, backend.port),
                    timeout=self.health_config.timeout_seconds,
                )
                writer.close()
                await writer.wait_closed()
                is_healthy = True

        except Exception as e:
            logger.debug(
                "Health check failed",
                backend_id=backend.id,
                error=str(e),
            )
            is_healthy = False

        # Update health status based on thresholds
        if is_healthy:
            backend.stats.consecutive_successes += 1
            backend.stats.consecutive_failures = 0
            if backend.stats.consecutive_successes >= self.health_config.healthy_threshold:
                if backend.health != BackendHealth.HEALTHY:
                    logger.info("Backend became healthy", backend_id=backend.id)
                backend.health = BackendHealth.HEALTHY
        else:
            backend.stats.consecutive_failures += 1
            backend.stats.consecutive_successes = 0
            if backend.stats.consecutive_failures >= self.health_config.unhealthy_threshold:
                if backend.health != BackendHealth.UNHEALTHY:
                    logger.warning("Backend became unhealthy", backend_id=backend.id)
                backend.health = BackendHealth.UNHEALTHY


class BackendConnection:
    """Context manager for backend connections."""

    def __init__(self, lb: LoadBalancer, backend: Backend) -> None:
        self._lb = lb
        self.backend = backend
        self._start_time: float = 0

    async def __aenter__(self) -> Backend:
        self._start_time = time.time()
        return self.backend

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        response_time_ms = (time.time() - self._start_time) * 1000

        if exc_type is None:
            self._lb.record_success(self.backend, response_time_ms)
        else:
            self._lb.record_failure(self.backend)

        self._lb.release(self.backend)


class BackendPool:
    """Pool of backends with automatic discovery and health management."""

    def __init__(
        self,
        name: str,
        load_balancer: LoadBalancer | None = None,
    ) -> None:
        self.name = name
        self.lb = load_balancer or LoadBalancer()
        self._discovery_task: asyncio.Task | None = None

    async def start(self) -> None:
        """Start the backend pool."""
        await self.lb.start()
        logger.info("Backend pool started", name=self.name)

    async def stop(self) -> None:
        """Stop the backend pool."""
        if self._discovery_task:
            self._discovery_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._discovery_task
        await self.lb.stop()
        logger.info("Backend pool stopped", name=self.name)

    def add_backend(
        self,
        host: str,
        port: int,
        weight: int = 1,
        backend_id: str | None = None,
    ) -> Backend:
        """Add a backend to the pool."""
        backend_id = backend_id or f"{host}:{port}"
        backend = Backend(
            id=backend_id,
            host=host,
            port=port,
            weight=weight,
        )
        self.lb.add_backend(backend)
        return backend

    def remove_backend(self, backend_id: str) -> bool:
        """Remove a backend from the pool."""
        return self.lb.remove_backend(backend_id)

    async def get_connection(self, context: Any = None) -> BackendConnection | None:
        """Get a connection to a backend."""
        return await self.lb.acquire(context)

    def get_stats(self) -> dict[str, Any]:
        """Get pool statistics."""
        backends = self.lb.list_backends()
        healthy = sum(1 for b in backends if b.health == BackendHealth.HEALTHY)
        unhealthy = sum(1 for b in backends if b.health == BackendHealth.UNHEALTHY)

        return {
            "name": self.name,
            "total_backends": len(backends),
            "healthy_backends": healthy,
            "unhealthy_backends": unhealthy,
            "total_active_connections": sum(b.stats.active_connections for b in backends),
            "backends": [
                {
                    "id": b.id,
                    "address": b.address,
                    "health": b.health.value,
                    "weight": b.weight,
                    "active_connections": b.stats.active_connections,
                    "total_requests": b.stats.total_requests,
                    "avg_response_time_ms": round(b.stats.avg_response_time_ms, 2),
                }
                for b in backends
            ],
        }
