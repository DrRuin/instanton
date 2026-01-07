"""Observability module for Instanton tunnel application.

This module provides comprehensive metrics, tracing, and observability features:
- Prometheus metrics collection and exposure
- OpenTelemetry distributed tracing
- Structured logging with trace correlation
- Health check endpoints
- Circuit breaker pattern implementation
"""

from instanton.observability.circuit_breaker import (
    CircuitBreaker,
    CircuitBreakerRegistry,
    CircuitState,
    get_circuit_breaker_registry,
)
from instanton.observability.health import (
    ComponentHealth,
    HealthCheck,
    HealthStatus,
    get_health_checker,
)
from instanton.observability.logging import (
    InstantonLogger,
    get_logger,
    setup_logging,
)
from instanton.observability.metrics import (
    InstantonMetrics,
    get_metrics,
    metrics_registry,
)
from instanton.observability.tracing import (
    InstantonTracer,
    get_tracer,
    setup_tracing,
)

__all__ = [
    # Metrics
    "InstantonMetrics",
    "get_metrics",
    "metrics_registry",
    # Tracing
    "InstantonTracer",
    "get_tracer",
    "setup_tracing",
    # Logging
    "InstantonLogger",
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
