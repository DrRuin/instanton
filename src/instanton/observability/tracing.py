"""OpenTelemetry distributed tracing for Instanton tunnel application.

This module provides comprehensive distributed tracing with:
- OpenTelemetry integration
- Trace context propagation
- Span creation for requests
- Custom attributes (tunnel_id, subdomain, etc.)
- W3C Trace Context support
- Jaeger/Zipkin/OTLP export support
"""

from __future__ import annotations

import functools
import threading
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from typing import Any, TypeVar

from opentelemetry import trace
from opentelemetry.baggage.propagation import W3CBaggagePropagator
from opentelemetry.context import Context
from opentelemetry.propagate import extract, inject, set_global_textmap
from opentelemetry.propagators.composite import CompositePropagator
from opentelemetry.sdk.resources import SERVICE_NAME, SERVICE_VERSION, Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import (
    BatchSpanProcessor,
    ConsoleSpanExporter,
    SimpleSpanProcessor,
    SpanExporter,
)
from opentelemetry.sdk.trace.sampling import (
    ALWAYS_OFF,
    ALWAYS_ON,
    ParentBased,
    TraceIdRatioBased,
)
from opentelemetry.trace import (
    Span,
    SpanKind,
    Status,
    StatusCode,
    get_current_span,
)
from opentelemetry.trace.propagation.tracecontext import TraceContextTextMapPropagator

# Type variables
F = TypeVar("F", bound=Callable[..., Any])

# Common attribute keys
ATTR_TUNNEL_ID = "instanton.tunnel.id"
ATTR_SUBDOMAIN = "instanton.subdomain"
ATTR_PROTOCOL = "instanton.protocol"
ATTR_CLIENT_IP = "instanton.client.ip"
ATTR_REQUEST_ID = "instanton.request.id"
ATTR_ERROR_TYPE = "instanton.error.type"
ATTR_BYTES_SENT = "instanton.bytes.sent"
ATTR_BYTES_RECEIVED = "instanton.bytes.received"


class InstantonTracer:
    """OpenTelemetry tracer for Instanton application.

    Provides span creation, context propagation, and trace export
    configuration for distributed tracing.
    """

    _instance: InstantonTracer | None = None
    _lock = threading.Lock()
    _initialized: bool = False

    def __new__(cls) -> InstantonTracer:
        """Singleton pattern for tracer instance."""
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    instance = super().__new__(cls)
                    instance._initialized = False
                    cls._instance = instance
        return cls._instance

    def __init__(self) -> None:
        """Initialize the tracer (called once due to singleton)."""
        if self._initialized:
            return

        self._tracer: trace.Tracer | None = None
        self._provider: TracerProvider | None = None
        self._exporters: list[SpanExporter] = []
        self._initialized = True

    def setup(
        self,
        service_name: str = "instanton",
        service_version: str = "1.0.0",
        environment: str = "development",
        sampling_ratio: float = 1.0,
        exporters: list[SpanExporter] | None = None,
        additional_attributes: dict[str, str] | None = None,
    ) -> None:
        """Configure the tracer with exporters and settings.

        Args:
            service_name: Name of the service
            service_version: Version of the service
            environment: Deployment environment
            sampling_ratio: Ratio of traces to sample (0.0 to 1.0)
            exporters: List of span exporters
            additional_attributes: Extra resource attributes
        """
        # Build resource attributes
        resource_attrs = {
            SERVICE_NAME: service_name,
            SERVICE_VERSION: service_version,
            "deployment.environment": environment,
        }
        if additional_attributes:
            resource_attrs.update(additional_attributes)

        resource = Resource.create(resource_attrs)

        # Configure sampler
        if sampling_ratio >= 1.0:
            sampler = ALWAYS_ON
        elif sampling_ratio <= 0.0:
            sampler = ALWAYS_OFF
        else:
            sampler = ParentBased(root=TraceIdRatioBased(sampling_ratio))

        # Create tracer provider
        self._provider = TracerProvider(
            resource=resource,
            sampler=sampler,
        )

        # Add exporters
        if exporters:
            for exporter in exporters:
                processor = BatchSpanProcessor(exporter)
                self._provider.add_span_processor(processor)
                self._exporters.append(exporter)
        else:
            # Default to console exporter for development
            console_exporter = ConsoleSpanExporter()
            processor = SimpleSpanProcessor(console_exporter)
            self._provider.add_span_processor(processor)
            self._exporters.append(console_exporter)

        # Set as global tracer provider
        trace.set_tracer_provider(self._provider)

        # Set up W3C Trace Context propagation
        propagator = CompositePropagator(
            [
                TraceContextTextMapPropagator(),
                W3CBaggagePropagator(),
            ]
        )
        set_global_textmap(propagator)

        # Get tracer
        self._tracer = trace.get_tracer(
            service_name,
            service_version,
        )

    @property
    def tracer(self) -> trace.Tracer:
        """Get the configured tracer.

        Returns:
            OpenTelemetry Tracer instance

        Raises:
            RuntimeError: If tracer is not configured
        """
        if self._tracer is None:
            # Auto-setup with defaults if not configured
            self.setup()
        return self._tracer  # type: ignore

    def create_span(
        self,
        name: str,
        kind: SpanKind = SpanKind.INTERNAL,
        attributes: dict[str, Any] | None = None,
        context: Context | None = None,
    ) -> Span:
        """Create a new span.

        Args:
            name: Span name
            kind: Span kind (client, server, internal, producer, consumer)
            attributes: Initial span attributes
            context: Parent context

        Returns:
            New span instance
        """
        return self.tracer.start_span(
            name=name,
            kind=kind,
            attributes=attributes,
            context=context,
        )

    @contextmanager
    def span(
        self,
        name: str,
        kind: SpanKind = SpanKind.INTERNAL,
        attributes: dict[str, Any] | None = None,
        record_exception: bool = True,
        set_status_on_exception: bool = True,
    ) -> Iterator[Span]:
        """Context manager for creating and managing spans.

        Args:
            name: Span name
            kind: Span kind
            attributes: Initial attributes
            record_exception: Whether to record exceptions
            set_status_on_exception: Whether to set error status on exception

        Yields:
            Active span
        """
        with self.tracer.start_as_current_span(
            name=name,
            kind=kind,
            attributes=attributes,
            record_exception=record_exception,
            set_status_on_exception=set_status_on_exception,
        ) as span:
            yield span

    def create_tunnel_span(
        self,
        tunnel_id: str,
        subdomain: str,
        protocol: str = "https",
        client_ip: str | None = None,
    ) -> Span:
        """Create a span for tunnel operations.

        Args:
            tunnel_id: Unique tunnel identifier
            subdomain: Tunnel subdomain
            protocol: Protocol being used
            client_ip: Client IP address

        Returns:
            New span with tunnel attributes
        """
        attributes = {
            ATTR_TUNNEL_ID: tunnel_id,
            ATTR_SUBDOMAIN: subdomain,
            ATTR_PROTOCOL: protocol,
        }
        if client_ip:
            attributes[ATTR_CLIENT_IP] = client_ip

        return self.create_span(
            name=f"tunnel.{subdomain}",
            kind=SpanKind.SERVER,
            attributes=attributes,
        )

    @contextmanager
    def request_span(
        self,
        method: str,
        path: str,
        subdomain: str,
        request_id: str | None = None,
        headers: dict[str, str] | None = None,
    ) -> Iterator[Span]:
        """Context manager for HTTP request spans with context extraction.

        Args:
            method: HTTP method
            path: Request path
            subdomain: Tunnel subdomain
            request_id: Unique request ID
            headers: Request headers for context extraction

        Yields:
            Active request span
        """
        # Extract context from headers if provided
        ctx = None
        if headers:
            ctx = extract(headers)

        attributes = {
            "http.method": method,
            "http.url": path,
            ATTR_SUBDOMAIN: subdomain,
        }
        if request_id:
            attributes[ATTR_REQUEST_ID] = request_id

        with self.tracer.start_as_current_span(
            name=f"{method} {path}",
            kind=SpanKind.SERVER,
            attributes=attributes,
            context=ctx,
        ) as span:
            yield span

    def inject_context(
        self,
        carrier: dict[str, str],
        context: Context | None = None,
    ) -> None:
        """Inject trace context into carrier for propagation.

        Args:
            carrier: Dictionary to inject context into
            context: Optional context to inject (uses current if None)
        """
        inject(carrier, context=context)

    def extract_context(
        self,
        carrier: dict[str, str],
    ) -> Context:
        """Extract trace context from carrier.

        Args:
            carrier: Dictionary containing trace context headers

        Returns:
            Extracted context
        """
        return extract(carrier)

    def get_current_span(self) -> Span:
        """Get the currently active span.

        Returns:
            Current span or no-op span if none active
        """
        return get_current_span()

    def get_current_trace_id(self) -> str | None:
        """Get the current trace ID as a hex string.

        Returns:
            Trace ID or None if no active span
        """
        span = get_current_span()
        if span and span.is_recording():
            return format(span.get_span_context().trace_id, "032x")
        return None

    def get_current_span_id(self) -> str | None:
        """Get the current span ID as a hex string.

        Returns:
            Span ID or None if no active span
        """
        span = get_current_span()
        if span and span.is_recording():
            return format(span.get_span_context().span_id, "016x")
        return None

    def add_event(
        self,
        name: str,
        attributes: dict[str, Any] | None = None,
    ) -> None:
        """Add an event to the current span.

        Args:
            name: Event name
            attributes: Event attributes
        """
        span = get_current_span()
        if span and span.is_recording():
            span.add_event(name, attributes=attributes)

    def set_attribute(self, key: str, value: Any) -> None:
        """Set an attribute on the current span.

        Args:
            key: Attribute key
            value: Attribute value
        """
        span = get_current_span()
        if span and span.is_recording():
            span.set_attribute(key, value)

    def set_error(
        self,
        exception: Exception,
        message: str | None = None,
    ) -> None:
        """Set error status and record exception on current span.

        Args:
            exception: Exception that occurred
            message: Optional error message
        """
        span = get_current_span()
        if span and span.is_recording():
            span.record_exception(exception)
            span.set_status(Status(StatusCode.ERROR, message or str(exception)))
            span.set_attribute(ATTR_ERROR_TYPE, type(exception).__name__)

    def shutdown(self) -> None:
        """Shutdown the tracer and flush pending spans."""
        if self._provider:
            self._provider.shutdown()


def setup_tracing(
    service_name: str = "instanton",
    service_version: str = "1.0.0",
    environment: str = "development",
    sampling_ratio: float = 1.0,
    otlp_endpoint: str | None = None,
    otlp_headers: dict[str, str] | None = None,
    jaeger_endpoint: str | None = None,
    zipkin_endpoint: str | None = None,
    console_export: bool = False,
) -> InstantonTracer:
    """Setup tracing with common exporters.

    Args:
        service_name: Name of the service
        service_version: Service version
        environment: Deployment environment
        sampling_ratio: Trace sampling ratio
        otlp_endpoint: OTLP collector endpoint
        otlp_headers: OTLP authentication headers
        jaeger_endpoint: Jaeger collector endpoint
        zipkin_endpoint: Zipkin collector endpoint
        console_export: Enable console exporter

    Returns:
        Configured InstantonTracer instance
    """
    exporters: list[SpanExporter] = []

    # OTLP exporter
    if otlp_endpoint:
        try:
            from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import (
                OTLPSpanExporter as OTLPGrpcExporter,
            )

            exporter = OTLPGrpcExporter(
                endpoint=otlp_endpoint,
                headers=otlp_headers,
            )
            exporters.append(exporter)
        except ImportError:
            try:
                from opentelemetry.exporter.otlp.proto.http.trace_exporter import (
                    OTLPSpanExporter as OTLPHttpExporter,
                )

                exporter = OTLPHttpExporter(
                    endpoint=otlp_endpoint,
                    headers=otlp_headers,
                )
                exporters.append(exporter)
            except ImportError:
                pass

    # Jaeger exporter
    if jaeger_endpoint:
        try:
            from opentelemetry.exporter.jaeger.thrift import JaegerExporter

            exporter = JaegerExporter(
                collector_endpoint=jaeger_endpoint,
            )
            exporters.append(exporter)
        except ImportError:
            pass

    # Zipkin exporter
    if zipkin_endpoint:
        try:
            from opentelemetry.exporter.zipkin.json import ZipkinExporter

            exporter = ZipkinExporter(
                endpoint=zipkin_endpoint,
            )
            exporters.append(exporter)
        except ImportError:
            pass

    # Console exporter
    if console_export or not exporters:
        exporters.append(ConsoleSpanExporter())

    tracer = InstantonTracer()
    tracer.setup(
        service_name=service_name,
        service_version=service_version,
        environment=environment,
        sampling_ratio=sampling_ratio,
        exporters=exporters,
    )

    return tracer


def get_tracer() -> InstantonTracer:
    """Get the global InstantonTracer instance.

    Returns:
        InstantonTracer singleton
    """
    return InstantonTracer()


def traced(
    name: str | None = None,
    kind: SpanKind = SpanKind.INTERNAL,
    attributes: dict[str, Any] | None = None,
) -> Callable[[F], F]:
    """Decorator to automatically trace a function.

    Args:
        name: Span name (defaults to function name)
        kind: Span kind
        attributes: Additional span attributes

    Returns:
        Decorated function
    """

    def decorator(func: F) -> F:
        span_name = name or func.__name__

        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            tracer = get_tracer()
            with tracer.span(span_name, kind=kind, attributes=attributes):
                return func(*args, **kwargs)

        @functools.wraps(func)
        async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
            tracer = get_tracer()
            with tracer.span(span_name, kind=kind, attributes=attributes):
                return await func(*args, **kwargs)

        if asyncio_iscoroutinefunction(func):
            return async_wrapper  # type: ignore
        return wrapper  # type: ignore

    return decorator


def asyncio_iscoroutinefunction(func: Any) -> bool:
    """Check if function is a coroutine function.

    Args:
        func: Function to check

    Returns:
        True if coroutine function
    """
    import asyncio

    return asyncio.iscoroutinefunction(func)


class TracingMiddleware:
    """ASGI middleware for automatic request tracing."""

    def __init__(
        self,
        app: Any,
        tracer: InstantonTracer | None = None,
    ) -> None:
        """Initialize middleware.

        Args:
            app: ASGI application
            tracer: InstantonTracer instance
        """
        self.app = app
        self.tracer = tracer or get_tracer()

    async def __call__(
        self,
        scope: dict[str, Any],
        receive: Callable,
        send: Callable,
    ) -> None:
        """Process request with tracing."""
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        # Extract headers
        headers = {k.decode("utf-8"): v.decode("utf-8") for k, v in scope.get("headers", [])}

        # Extract subdomain from host
        host = headers.get("host", "")
        subdomain = host.split(".")[0] if "." in host else "unknown"

        method = scope.get("method", "UNKNOWN")
        path = scope.get("path", "/")

        with self.tracer.request_span(
            method=method,
            path=path,
            subdomain=subdomain,
            headers=headers,
        ) as span:
            # Track response status
            status_code = 500

            async def send_wrapper(message: dict[str, Any]) -> None:
                nonlocal status_code
                if message["type"] == "http.response.start":
                    status_code = message.get("status", 500)
                    span.set_attribute("http.status_code", status_code)
                await send(message)

            try:
                await self.app(scope, receive, send_wrapper)
            except Exception as e:
                self.tracer.set_error(e)
                raise
