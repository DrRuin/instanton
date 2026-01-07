"""Prometheus metrics for Instanton tunnel application.

This module provides comprehensive Prometheus metrics including:
- Counters for requests, errors, and connections
- Gauges for active tunnels, connections, and memory usage
- Histograms for request duration and response sizes
- Custom metrics registry
- HTTP endpoint for metrics exposure
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from typing import Any, TypeVar

import psutil
from prometheus_client import (
    CONTENT_TYPE_LATEST,
    CollectorRegistry,
    Counter,
    Gauge,
    Histogram,
    Info,
    generate_latest,
    make_asgi_app,
    start_http_server,
)

# Type variable for decorator
F = TypeVar("F", bound=Callable[..., Any])

# Custom registry for Instanton metrics
metrics_registry = CollectorRegistry()

# Standard labels used across metrics
SUBDOMAIN_LABEL = "subdomain"
METHOD_LABEL = "method"
STATUS_CODE_LABEL = "status_code"
PROTOCOL_LABEL = "protocol"
TUNNEL_ID_LABEL = "tunnel_id"
ERROR_TYPE_LABEL = "error_type"


class InstantonMetrics:
    """Prometheus metrics collector for Instanton.

    Provides counters, gauges, and histograms for monitoring
    tunnel operations, requests, and system health.
    """

    _instance: InstantonMetrics | None = None
    _lock = threading.Lock()
    _initialized: bool = False

    def __new__(cls, registry: CollectorRegistry | None = None) -> InstantonMetrics:
        """Singleton pattern to ensure single metrics instance."""
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    instance = super().__new__(cls)
                    instance._initialized = False
                    cls._instance = instance
        return cls._instance

    def __init__(self, registry: CollectorRegistry | None = None) -> None:
        """Initialize metrics with custom or default registry.

        Args:
            registry: Optional custom CollectorRegistry. Uses global registry if None.
        """
        if self._initialized:
            return

        self._registry = registry or metrics_registry
        self._setup_counters()
        self._setup_gauges()
        self._setup_histograms()
        self._setup_info()
        self._initialized = True

    def _setup_counters(self) -> None:
        """Initialize counter metrics."""
        # Request counters
        self.requests_total = Counter(
            "instanton_requests_total",
            "Total number of requests processed",
            [SUBDOMAIN_LABEL, METHOD_LABEL, STATUS_CODE_LABEL, PROTOCOL_LABEL],
            registry=self._registry,
        )

        # Error counters
        self.errors_total = Counter(
            "instanton_errors_total",
            "Total number of errors encountered",
            [SUBDOMAIN_LABEL, ERROR_TYPE_LABEL],
            registry=self._registry,
        )

        # Connection counters
        self.connections_total = Counter(
            "instanton_connections_total",
            "Total number of connections established",
            [PROTOCOL_LABEL],
            registry=self._registry,
        )

        # Tunnel lifecycle counters
        self.tunnels_created_total = Counter(
            "instanton_tunnels_created_total",
            "Total number of tunnels created",
            [SUBDOMAIN_LABEL],
            registry=self._registry,
        )

        self.tunnels_closed_total = Counter(
            "instanton_tunnels_closed_total",
            "Total number of tunnels closed",
            [SUBDOMAIN_LABEL, "reason"],
            registry=self._registry,
        )

        # Bytes transferred
        self.bytes_sent_total = Counter(
            "instanton_bytes_sent_total",
            "Total bytes sent through tunnels",
            [SUBDOMAIN_LABEL],
            registry=self._registry,
        )

        self.bytes_received_total = Counter(
            "instanton_bytes_received_total",
            "Total bytes received through tunnels",
            [SUBDOMAIN_LABEL],
            registry=self._registry,
        )

    def _setup_gauges(self) -> None:
        """Initialize gauge metrics."""
        # Active tunnels
        self.active_tunnels = Gauge(
            "instanton_active_tunnels",
            "Number of currently active tunnels",
            registry=self._registry,
        )

        # Active connections
        self.active_connections = Gauge(
            "instanton_active_connections",
            "Number of currently active connections",
            [PROTOCOL_LABEL],
            registry=self._registry,
        )

        # Memory usage
        self.memory_usage_bytes = Gauge(
            "instanton_memory_usage_bytes",
            "Current memory usage in bytes",
            ["type"],  # resident, virtual
            registry=self._registry,
        )

        # CPU usage
        self.cpu_usage_percent = Gauge(
            "instanton_cpu_usage_percent",
            "Current CPU usage percentage",
            registry=self._registry,
        )

        # File descriptors
        self.open_file_descriptors = Gauge(
            "instanton_open_file_descriptors",
            "Number of open file descriptors",
            registry=self._registry,
        )

        # Circuit breaker states
        self.circuit_breaker_state = Gauge(
            "instanton_circuit_breaker_state",
            "Circuit breaker state (0=closed, 1=open, 2=half-open)",
            ["backend"],
            registry=self._registry,
        )

        # Pending requests
        self.pending_requests = Gauge(
            "instanton_pending_requests",
            "Number of pending requests",
            [SUBDOMAIN_LABEL],
            registry=self._registry,
        )

    def _setup_histograms(self) -> None:
        """Initialize histogram metrics."""
        # Request duration histogram with appropriate buckets for latency
        self.request_duration_seconds = Histogram(
            "instanton_request_duration_seconds",
            "Request duration in seconds",
            [SUBDOMAIN_LABEL, METHOD_LABEL, STATUS_CODE_LABEL],
            buckets=(0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0),
            registry=self._registry,
        )

        # Response size histogram with byte-based buckets
        self.response_size_bytes = Histogram(
            "instanton_response_size_bytes",
            "Response size in bytes",
            [SUBDOMAIN_LABEL, METHOD_LABEL],
            buckets=(100, 1000, 10000, 100000, 1000000, 10000000, 100000000),
            registry=self._registry,
        )

        # Request size histogram
        self.request_size_bytes = Histogram(
            "instanton_request_size_bytes",
            "Request size in bytes",
            [SUBDOMAIN_LABEL, METHOD_LABEL],
            buckets=(100, 1000, 10000, 100000, 1000000, 10000000),
            registry=self._registry,
        )

        # Tunnel connection duration
        self.tunnel_duration_seconds = Histogram(
            "instanton_tunnel_duration_seconds",
            "Tunnel connection duration in seconds",
            [SUBDOMAIN_LABEL],
            buckets=(1.0, 5.0, 15.0, 30.0, 60.0, 300.0, 900.0, 3600.0, 86400.0),
            registry=self._registry,
        )

        # Connection establishment time
        self.connection_establish_seconds = Histogram(
            "instanton_connection_establish_seconds",
            "Time to establish connection in seconds",
            [PROTOCOL_LABEL],
            buckets=(0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5),
            registry=self._registry,
        )

    def _setup_info(self) -> None:
        """Initialize info metrics for version and build information."""
        self.build_info = Info(
            "instanton_build",
            "Build information for Instanton",
            registry=self._registry,
        )

    def set_build_info(
        self,
        version: str,
        commit: str = "",
        build_time: str = "",
    ) -> None:
        """Set build information.

        Args:
            version: Application version
            commit: Git commit hash
            build_time: Build timestamp
        """
        self.build_info.info(
            {
                "version": version,
                "commit": commit,
                "build_time": build_time,
            }
        )

    def record_request(
        self,
        subdomain: str,
        method: str,
        status_code: int,
        protocol: str,
        duration_seconds: float,
        response_size: int,
        request_size: int = 0,
    ) -> None:
        """Record a complete request with all associated metrics.

        Args:
            subdomain: Tunnel subdomain
            method: HTTP method
            status_code: Response status code
            protocol: Protocol used (http, https, quic)
            duration_seconds: Request duration
            response_size: Response size in bytes
            request_size: Request size in bytes
        """
        status_str = str(status_code)

        self.requests_total.labels(
            subdomain=subdomain,
            method=method,
            status_code=status_str,
            protocol=protocol,
        ).inc()

        self.request_duration_seconds.labels(
            subdomain=subdomain,
            method=method,
            status_code=status_str,
        ).observe(duration_seconds)

        self.response_size_bytes.labels(
            subdomain=subdomain,
            method=method,
        ).observe(response_size)

        if request_size > 0:
            self.request_size_bytes.labels(
                subdomain=subdomain,
                method=method,
            ).observe(request_size)

    def record_error(
        self,
        subdomain: str,
        error_type: str,
    ) -> None:
        """Record an error occurrence.

        Args:
            subdomain: Tunnel subdomain
            error_type: Type of error (e.g., timeout, connection_refused)
        """
        self.errors_total.labels(
            subdomain=subdomain,
            error_type=error_type,
        ).inc()

    def record_connection(self, protocol: str) -> None:
        """Record a new connection.

        Args:
            protocol: Protocol used
        """
        self.connections_total.labels(protocol=protocol).inc()

    def update_active_connections(self, protocol: str, count: int) -> None:
        """Update active connection gauge.

        Args:
            protocol: Protocol type
            count: Current count of active connections
        """
        self.active_connections.labels(protocol=protocol).set(count)

    def increment_active_connections(self, protocol: str) -> None:
        """Increment active connections gauge.

        Args:
            protocol: Protocol type
        """
        self.active_connections.labels(protocol=protocol).inc()

    def decrement_active_connections(self, protocol: str) -> None:
        """Decrement active connections gauge.

        Args:
            protocol: Protocol type
        """
        self.active_connections.labels(protocol=protocol).dec()

    def update_system_metrics(self) -> None:
        """Update system resource metrics (memory, CPU, file descriptors)."""
        try:
            process = psutil.Process()

            # Memory usage
            mem_info = process.memory_info()
            self.memory_usage_bytes.labels(type="resident").set(mem_info.rss)
            self.memory_usage_bytes.labels(type="virtual").set(mem_info.vms)

            # CPU usage
            cpu_percent = process.cpu_percent()
            self.cpu_usage_percent.set(cpu_percent)

            # File descriptors (Unix-like systems)
            try:
                num_fds = process.num_fds()
                self.open_file_descriptors.set(num_fds)
            except AttributeError:
                # Windows doesn't have num_fds
                num_handles = len(process.open_files())
                self.open_file_descriptors.set(num_handles)
        except Exception:
            # Silently ignore if we can't get system metrics
            pass

    def generate_metrics(self) -> bytes:
        """Generate metrics in Prometheus format.

        Returns:
            Metrics data as bytes in Prometheus exposition format.
        """
        self.update_system_metrics()
        return generate_latest(self._registry)

    def get_content_type(self) -> str:
        """Get the content type for metrics response.

        Returns:
            Content type string for Prometheus metrics.
        """
        return CONTENT_TYPE_LATEST


class MetricsMiddleware:
    """ASGI middleware for automatic request metrics collection."""

    def __init__(self, app: Any, metrics: InstantonMetrics | None = None) -> None:
        """Initialize middleware.

        Args:
            app: ASGI application
            metrics: InstantonMetrics instance
        """
        self.app = app
        self.metrics = metrics or get_metrics()

    async def __call__(self, scope: dict, receive: Callable, send: Callable) -> None:
        """Process request and collect metrics."""
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        start_time = time.perf_counter()
        status_code = 500
        response_size = 0

        # Extract subdomain from host header
        headers = dict(scope.get("headers", []))
        host = headers.get(b"host", b"").decode("utf-8")
        subdomain = host.split(".")[0] if "." in host else "unknown"

        method = scope.get("method", "UNKNOWN")
        protocol = "https" if scope.get("scheme") == "https" else "http"

        async def send_wrapper(message: dict) -> None:
            nonlocal status_code, response_size

            if message["type"] == "http.response.start":
                status_code = message.get("status", 500)
            elif message["type"] == "http.response.body":
                body = message.get("body", b"")
                response_size += len(body)

            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        except Exception as e:
            self.metrics.record_error(subdomain, type(e).__name__)
            raise
        finally:
            duration = time.perf_counter() - start_time
            self.metrics.record_request(
                subdomain=subdomain,
                method=method,
                status_code=status_code,
                protocol=protocol,
                duration_seconds=duration,
                response_size=response_size,
            )


class MetricsServer:
    """Standalone HTTP server for metrics endpoint."""

    def __init__(
        self,
        metrics: InstantonMetrics | None = None,
        host: str = "0.0.0.0",
        port: int = 9090,
    ) -> None:
        """Initialize metrics server.

        Args:
            metrics: InstantonMetrics instance
            host: Host to bind to
            port: Port to listen on
        """
        self.metrics = metrics or get_metrics()
        self.host = host
        self.port = port
        self._server = None

    def start(self) -> None:
        """Start the metrics HTTP server in a background thread."""
        start_http_server(self.port, addr=self.host, registry=self.metrics._registry)

    def make_asgi_app(self) -> Any:
        """Create an ASGI app for mounting in existing applications.

        Returns:
            ASGI application that exposes metrics endpoint.
        """
        return make_asgi_app(registry=self.metrics._registry)


def get_metrics(registry: CollectorRegistry | None = None) -> InstantonMetrics:
    """Get the global InstantonMetrics instance.

    Args:
        registry: Optional custom registry

    Returns:
        InstantonMetrics singleton instance.
    """
    return InstantonMetrics(registry)


def request_timer(
    subdomain: str,
    method: str,
    metrics: InstantonMetrics | None = None,
) -> Callable[[F], F]:
    """Decorator to time function execution and record as request duration.

    Args:
        subdomain: Tunnel subdomain
        method: HTTP method
        metrics: Optional metrics instance

    Returns:
        Decorated function
    """
    _metrics = metrics or get_metrics()

    def decorator(func: F) -> F:
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            start = time.perf_counter()
            try:
                result = func(*args, **kwargs)
                status_code = 200
                return result
            except Exception:
                status_code = 500
                raise
            finally:
                duration = time.perf_counter() - start
                _metrics.request_duration_seconds.labels(
                    subdomain=subdomain,
                    method=method,
                    status_code=str(status_code),
                ).observe(duration)

        return wrapper  # type: ignore

    return decorator


async def async_request_timer(
    subdomain: str,
    method: str,
    metrics: InstantonMetrics | None = None,
) -> Callable[[F], F]:
    """Async decorator to time function execution.

    Args:
        subdomain: Tunnel subdomain
        method: HTTP method
        metrics: Optional metrics instance

    Returns:
        Decorated async function
    """
    _metrics = metrics or get_metrics()

    def decorator(func: F) -> F:
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            start = time.perf_counter()
            try:
                result = await func(*args, **kwargs)
                status_code = 200
                return result
            except Exception:
                status_code = 500
                raise
            finally:
                duration = time.perf_counter() - start
                _metrics.request_duration_seconds.labels(
                    subdomain=subdomain,
                    method=method,
                    status_code=str(status_code),
                ).observe(duration)

        return wrapper  # type: ignore

    return decorator
