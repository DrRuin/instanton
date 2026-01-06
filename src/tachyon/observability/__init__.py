"""Observability module for Tachyon tunnel application.

This module provides comprehensive metrics, tracing, and observability features:
- Prometheus metrics collection and exposure
- OpenTelemetry distributed tracing
- Structured logging with trace correlation
- Health check endpoints
- Circuit breaker pattern implementation
"""

from tachyon.observability.circuit_breaker import (
    CircuitBreaker,
    CircuitBreakerRegistry,
    CircuitState,
    get_circuit_breaker_registry,
)
from tachyon.observability.health import (
    ComponentHealth,
    HealthCheck,
    HealthStatus,
    get_health_checker,
)
from tachyon.observability.logging import (
    TachyonLogger,
    get_logger,
    setup_logging,
)
from tachyon.observability.metrics import (
    TachyonMetrics,
    get_metrics,
    metrics_registry,
)
from tachyon.observability.tracing import (
    TachyonTracer,
    get_tracer,
    setup_tracing,
)

__all__ = [
    # Metrics
    "TachyonMetrics",
    "get_metrics",
    "metrics_registry",
    # Tracing
    "TachyonTracer",
    "get_tracer",
    "setup_tracing",
    # Logging
    "TachyonLogger",
    "get_logger",
    "setup_logging",
    # Health
    "HealthCheck",
    "HealthStatus",
    "ComponentHealth",
    "get_health_checker",
    # Circuit Breaker
    "CircuitBreaker",
    "CircuitState",
    "CircuitBreakerRegistry",
    "get_circuit_breaker_registry",
]
