"""Health check endpoints for Instanton tunnel application.

This module provides comprehensive health checking with:
- Liveness probe endpoint (/healthz)
- Readiness probe endpoint (/readyz)
- Detailed health status (/health)
- Component health (transport, storage, etc.)
- Circuit breaker status integration
"""

from __future__ import annotations

import asyncio
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any

# Import circuit breaker for status checks
try:
    from instanton.observability.circuit_breaker import (
        CircuitBreakerRegistry,  # noqa: F401
        CircuitState,
        get_circuit_breaker_registry,
    )

    CIRCUIT_BREAKER_AVAILABLE = True
except ImportError:
    CIRCUIT_BREAKER_AVAILABLE = False


class HealthStatus(str, Enum):
    """Health status enumeration."""

    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"


@dataclass
class ComponentHealth:
    """Health status of a single component."""

    name: str
    status: HealthStatus
    message: str | None = None
    details: dict[str, Any] = field(default_factory=dict)
    last_check: datetime | None = None
    response_time_ms: float | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation.

        Returns:
            Dictionary with health information
        """
        result: dict[str, Any] = {
            "name": self.name,
            "status": self.status.value,
        }
        if self.message:
            result["message"] = self.message
        if self.details:
            result["details"] = self.details
        if self.last_check:
            result["last_check"] = self.last_check.isoformat()
        if self.response_time_ms is not None:
            result["response_time_ms"] = round(self.response_time_ms, 2)
        return result


@dataclass
class HealthResult:
    """Overall health check result."""

    status: HealthStatus
    components: list[ComponentHealth] = field(default_factory=list)
    version: str | None = None
    uptime_seconds: float | None = None
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation.

        Returns:
            Dictionary with full health information
        """
        result: dict[str, Any] = {
            "status": self.status.value,
            "timestamp": self.timestamp.isoformat(),
        }
        if self.version:
            result["version"] = self.version
        if self.uptime_seconds is not None:
            result["uptime_seconds"] = round(self.uptime_seconds, 2)
        if self.components:
            result["components"] = [c.to_dict() for c in self.components]
        return result


# Type for health check functions
HealthCheckFunc = Callable[[], ComponentHealth | bool]
AsyncHealthCheckFunc = Callable[[], Any]  # Coroutine that returns ComponentHealth | bool


class HealthCheck:
    """Health checker for Instanton application.

    Manages health check registration and execution for
    liveness, readiness, and detailed health endpoints.
    """

    _instance: HealthCheck | None = None
    _lock = threading.Lock()
    _initialized: bool = False

    def __new__(cls) -> HealthCheck:
        """Singleton pattern for health checker."""
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    instance = super().__new__(cls)
                    instance._initialized = False
                    cls._instance = instance
        return cls._instance

    def __init__(self) -> None:
        """Initialize the health checker."""
        if self._initialized:
            return

        self._liveness_checks: dict[str, HealthCheckFunc] = {}
        self._readiness_checks: dict[str, HealthCheckFunc] = {}
        self._health_checks: dict[str, HealthCheckFunc] = {}
        self._start_time = time.time()
        self._version: str | None = None
        self._initialized = True

    def set_version(self, version: str) -> None:
        """Set application version.

        Args:
            version: Application version string
        """
        self._version = version

    @property
    def uptime_seconds(self) -> float:
        """Get application uptime in seconds.

        Returns:
            Uptime in seconds
        """
        return time.time() - self._start_time

    def register_liveness_check(
        self,
        name: str,
        check: HealthCheckFunc,
    ) -> None:
        """Register a liveness check.

        Liveness checks determine if the application is alive and should
        be restarted if they fail.

        Args:
            name: Check name
            check: Check function
        """
        self._liveness_checks[name] = check

    def register_readiness_check(
        self,
        name: str,
        check: HealthCheckFunc,
    ) -> None:
        """Register a readiness check.

        Readiness checks determine if the application can handle traffic.

        Args:
            name: Check name
            check: Check function
        """
        self._readiness_checks[name] = check

    def register_health_check(
        self,
        name: str,
        check: HealthCheckFunc,
    ) -> None:
        """Register a detailed health check.

        Health checks provide detailed component status information.

        Args:
            name: Check name
            check: Check function
        """
        self._health_checks[name] = check

    def unregister_check(self, name: str) -> None:
        """Unregister a check from all categories.

        Args:
            name: Check name to remove
        """
        self._liveness_checks.pop(name, None)
        self._readiness_checks.pop(name, None)
        self._health_checks.pop(name, None)

    def _run_check(
        self,
        name: str,
        check: HealthCheckFunc,
    ) -> ComponentHealth:
        """Run a single health check.

        Args:
            name: Check name
            check: Check function

        Returns:
            ComponentHealth result
        """
        start_time = time.perf_counter()
        try:
            result = check()
            response_time = (time.perf_counter() - start_time) * 1000

            if isinstance(result, ComponentHealth):
                result.response_time_ms = response_time
                result.last_check = datetime.now(UTC)
                return result
            elif isinstance(result, bool):
                return ComponentHealth(
                    name=name,
                    status=HealthStatus.HEALTHY if result else HealthStatus.UNHEALTHY,
                    response_time_ms=response_time,
                    last_check=datetime.now(UTC),
                )
            else:
                return ComponentHealth(
                    name=name,
                    status=HealthStatus.UNKNOWN,
                    message="Invalid check result type",
                    response_time_ms=response_time,
                    last_check=datetime.now(UTC),
                )
        except Exception as e:
            response_time = (time.perf_counter() - start_time) * 1000
            return ComponentHealth(
                name=name,
                status=HealthStatus.UNHEALTHY,
                message=str(e),
                details={"error_type": type(e).__name__},
                response_time_ms=response_time,
                last_check=datetime.now(UTC),
            )

    async def _run_check_async(
        self,
        name: str,
        check: AsyncHealthCheckFunc,
    ) -> ComponentHealth:
        """Run a single async health check.

        Args:
            name: Check name
            check: Async check function

        Returns:
            ComponentHealth result
        """
        start_time = time.perf_counter()
        try:
            result = check()
            if asyncio.iscoroutine(result):
                result = await result
            response_time = (time.perf_counter() - start_time) * 1000

            if isinstance(result, ComponentHealth):
                result.response_time_ms = response_time
                result.last_check = datetime.now(UTC)
                return result
            elif isinstance(result, bool):
                return ComponentHealth(
                    name=name,
                    status=HealthStatus.HEALTHY if result else HealthStatus.UNHEALTHY,
                    response_time_ms=response_time,
                    last_check=datetime.now(UTC),
                )
            else:
                return ComponentHealth(
                    name=name,
                    status=HealthStatus.UNKNOWN,
                    message="Invalid check result type",
                    response_time_ms=response_time,
                    last_check=datetime.now(UTC),
                )
        except Exception as e:
            response_time = (time.perf_counter() - start_time) * 1000
            return ComponentHealth(
                name=name,
                status=HealthStatus.UNHEALTHY,
                message=str(e),
                details={"error_type": type(e).__name__},
                response_time_ms=response_time,
                last_check=datetime.now(UTC),
            )

    def _aggregate_status(self, components: list[ComponentHealth]) -> HealthStatus:
        """Aggregate component statuses into overall status.

        Args:
            components: List of component health results

        Returns:
            Aggregated status
        """
        if not components:
            return HealthStatus.HEALTHY

        statuses = [c.status for c in components]

        if all(s == HealthStatus.HEALTHY for s in statuses):
            return HealthStatus.HEALTHY
        elif any(s == HealthStatus.UNHEALTHY for s in statuses):
            return HealthStatus.UNHEALTHY
        elif any(s == HealthStatus.DEGRADED for s in statuses):
            return HealthStatus.DEGRADED
        else:
            return HealthStatus.UNKNOWN

    def check_liveness(self) -> HealthResult:
        """Run liveness checks.

        Returns:
            HealthResult with liveness status
        """
        if not self._liveness_checks:
            return HealthResult(
                status=HealthStatus.HEALTHY,
                version=self._version,
                uptime_seconds=self.uptime_seconds,
            )

        components = [self._run_check(name, check) for name, check in self._liveness_checks.items()]

        return HealthResult(
            status=self._aggregate_status(components),
            components=components,
            version=self._version,
            uptime_seconds=self.uptime_seconds,
        )

    def check_readiness(self) -> HealthResult:
        """Run readiness checks.

        Returns:
            HealthResult with readiness status
        """
        if not self._readiness_checks:
            return HealthResult(
                status=HealthStatus.HEALTHY,
                version=self._version,
                uptime_seconds=self.uptime_seconds,
            )

        components = [
            self._run_check(name, check) for name, check in self._readiness_checks.items()
        ]

        return HealthResult(
            status=self._aggregate_status(components),
            components=components,
            version=self._version,
            uptime_seconds=self.uptime_seconds,
        )

    def check_health(self) -> HealthResult:
        """Run all health checks for detailed status.

        Returns:
            HealthResult with detailed health information
        """
        all_checks = {
            **self._liveness_checks,
            **self._readiness_checks,
            **self._health_checks,
        }

        # Add circuit breaker status if available
        if CIRCUIT_BREAKER_AVAILABLE:
            try:
                registry = get_circuit_breaker_registry()
                for name, cb in registry.get_all().items():

                    def make_cb_check(cb_ref: Any = cb) -> ComponentHealth:
                        return ComponentHealth(
                            name=f"circuit_breaker.{cb_ref.name}",
                            status=HealthStatus.HEALTHY
                            if cb_ref.state == CircuitState.CLOSED
                            else (
                                HealthStatus.DEGRADED
                                if cb_ref.state == CircuitState.HALF_OPEN
                                else HealthStatus.UNHEALTHY
                            ),
                            details={
                                "state": cb_ref.state.value,
                                "failure_count": cb_ref.failure_count,
                                "success_count": cb_ref.success_count,
                            },
                        )

                    all_checks[f"circuit_breaker.{name}"] = make_cb_check
            except Exception:
                pass

        if not all_checks:
            return HealthResult(
                status=HealthStatus.HEALTHY,
                version=self._version,
                uptime_seconds=self.uptime_seconds,
            )

        components = [self._run_check(name, check) for name, check in all_checks.items()]

        return HealthResult(
            status=self._aggregate_status(components),
            components=components,
            version=self._version,
            uptime_seconds=self.uptime_seconds,
        )

    async def check_health_async(self) -> HealthResult:
        """Run all health checks asynchronously.

        Returns:
            HealthResult with detailed health information
        """
        all_checks = {
            **self._liveness_checks,
            **self._readiness_checks,
            **self._health_checks,
        }

        if not all_checks:
            return HealthResult(
                status=HealthStatus.HEALTHY,
                version=self._version,
                uptime_seconds=self.uptime_seconds,
            )

        # Run checks concurrently
        tasks = [self._run_check_async(name, check) for name, check in all_checks.items()]
        components = await asyncio.gather(*tasks)

        return HealthResult(
            status=self._aggregate_status(list(components)),
            components=list(components),
            version=self._version,
            uptime_seconds=self.uptime_seconds,
        )


def get_health_checker() -> HealthCheck:
    """Get the global HealthCheck instance.

    Returns:
        HealthCheck singleton
    """
    return HealthCheck()


# Pre-built health check functions
def create_memory_check(
    max_memory_mb: float = 1024,
    warning_threshold: float = 0.8,
) -> HealthCheckFunc:
    """Create a memory usage health check.

    Args:
        max_memory_mb: Maximum allowed memory in MB
        warning_threshold: Threshold for degraded status (0.0-1.0)

    Returns:
        Health check function
    """

    def check() -> ComponentHealth:
        try:
            import psutil

            process = psutil.Process()
            memory_mb = process.memory_info().rss / (1024 * 1024)
            usage_ratio = memory_mb / max_memory_mb

            if usage_ratio > 1.0:
                status = HealthStatus.UNHEALTHY
                message = f"Memory usage {memory_mb:.1f}MB exceeds limit {max_memory_mb}MB"
            elif usage_ratio > warning_threshold:
                status = HealthStatus.DEGRADED
                message = f"Memory usage {memory_mb:.1f}MB approaching limit"
            else:
                status = HealthStatus.HEALTHY
                message = None

            return ComponentHealth(
                name="memory",
                status=status,
                message=message,
                details={
                    "used_mb": round(memory_mb, 2),
                    "max_mb": max_memory_mb,
                    "usage_percent": round(usage_ratio * 100, 1),
                },
            )
        except ImportError:
            return ComponentHealth(
                name="memory",
                status=HealthStatus.UNKNOWN,
                message="psutil not available",
            )

    return check


def create_disk_check(
    path: str = "/",
    min_free_gb: float = 1.0,
    warning_threshold: float = 0.9,
) -> HealthCheckFunc:
    """Create a disk space health check.

    Args:
        path: Path to check disk space for
        min_free_gb: Minimum free space in GB
        warning_threshold: Usage threshold for degraded status (0.0-1.0)

    Returns:
        Health check function
    """

    def check() -> ComponentHealth:
        try:
            import psutil

            disk = psutil.disk_usage(path)
            free_gb = disk.free / (1024**3)
            usage_ratio = disk.percent / 100

            if free_gb < min_free_gb:
                status = HealthStatus.UNHEALTHY
                message = f"Disk space low: {free_gb:.1f}GB free"
            elif usage_ratio > warning_threshold:
                status = HealthStatus.DEGRADED
                message = f"Disk usage high: {disk.percent}%"
            else:
                status = HealthStatus.HEALTHY
                message = None

            return ComponentHealth(
                name="disk",
                status=status,
                message=message,
                details={
                    "path": path,
                    "free_gb": round(free_gb, 2),
                    "total_gb": round(disk.total / (1024**3), 2),
                    "usage_percent": disk.percent,
                },
            )
        except ImportError:
            return ComponentHealth(
                name="disk",
                status=HealthStatus.UNKNOWN,
                message="psutil not available",
            )

    return check


def create_tcp_check(
    host: str,
    port: int,
    timeout: float = 5.0,
) -> HealthCheckFunc:
    """Create a TCP connectivity health check.

    Args:
        host: Host to connect to
        port: Port to connect to
        timeout: Connection timeout in seconds

    Returns:
        Health check function
    """

    def check() -> ComponentHealth:
        import socket

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            sock.close()

            if result == 0:
                return ComponentHealth(
                    name=f"tcp.{host}:{port}",
                    status=HealthStatus.HEALTHY,
                    details={"host": host, "port": port},
                )
            else:
                return ComponentHealth(
                    name=f"tcp.{host}:{port}",
                    status=HealthStatus.UNHEALTHY,
                    message=f"Connection failed with error code {result}",
                    details={"host": host, "port": port, "error_code": result},
                )
        except TimeoutError:
            return ComponentHealth(
                name=f"tcp.{host}:{port}",
                status=HealthStatus.UNHEALTHY,
                message="Connection timed out",
                details={"host": host, "port": port, "timeout": timeout},
            )
        except Exception as e:
            return ComponentHealth(
                name=f"tcp.{host}:{port}",
                status=HealthStatus.UNHEALTHY,
                message=str(e),
                details={"host": host, "port": port, "error_type": type(e).__name__},
            )

    return check


class HealthMiddleware:
    """ASGI middleware providing health check endpoints."""

    def __init__(
        self,
        app: Any,
        health_checker: HealthCheck | None = None,
        liveness_path: str = "/healthz",
        readiness_path: str = "/readyz",
        health_path: str = "/health",
    ) -> None:
        """Initialize middleware.

        Args:
            app: ASGI application
            health_checker: HealthCheck instance
            liveness_path: Path for liveness probe
            readiness_path: Path for readiness probe
            health_path: Path for detailed health
        """
        self.app = app
        self.health_checker = health_checker or get_health_checker()
        self.liveness_path = liveness_path
        self.readiness_path = readiness_path
        self.health_path = health_path

    async def __call__(
        self,
        scope: dict[str, Any],
        receive: Callable,
        send: Callable,
    ) -> None:
        """Handle request."""
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "")

        if path == self.liveness_path:
            await self._handle_liveness(send)
        elif path == self.readiness_path:
            await self._handle_readiness(send)
        elif path == self.health_path:
            await self._handle_health(send)
        else:
            await self.app(scope, receive, send)

    async def _send_response(
        self,
        send: Callable,
        status_code: int,
        body: dict[str, Any],
    ) -> None:
        """Send JSON response.

        Args:
            send: ASGI send function
            status_code: HTTP status code
            body: Response body
        """
        import json

        body_bytes = json.dumps(body).encode("utf-8")

        await send(
            {
                "type": "http.response.start",
                "status": status_code,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(body_bytes)).encode()),
                ],
            }
        )
        await send(
            {
                "type": "http.response.body",
                "body": body_bytes,
            }
        )

    async def _handle_liveness(self, send: Callable) -> None:
        """Handle liveness probe request."""
        result = self.health_checker.check_liveness()
        status_code = 200 if result.status == HealthStatus.HEALTHY else 503
        await self._send_response(send, status_code, result.to_dict())

    async def _handle_readiness(self, send: Callable) -> None:
        """Handle readiness probe request."""
        result = self.health_checker.check_readiness()
        status_code = 200 if result.status in (HealthStatus.HEALTHY, HealthStatus.DEGRADED) else 503
        await self._send_response(send, status_code, result.to_dict())

    async def _handle_health(self, send: Callable) -> None:
        """Handle detailed health request."""
        result = await self.health_checker.check_health_async()
        status_code = (
            200
            if result.status == HealthStatus.HEALTHY
            else (207 if result.status == HealthStatus.DEGRADED else 503)
        )
        await self._send_response(send, status_code, result.to_dict())
