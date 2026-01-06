"""Circuit breaker pattern implementation for service resilience.

This module provides a circuit breaker implementation for managing
service calls and preventing cascading failures in the tunnel system.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class CircuitState(str, Enum):
    """States of a circuit breaker."""

    CLOSED = "closed"  # Normal operation, requests flow through
    OPEN = "open"  # Circuit tripped, requests blocked
    HALF_OPEN = "half_open"  # Testing if service recovered


@dataclass
class CircuitStats:
    """Statistics for a circuit breaker."""

    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    rejected_requests: int = 0
    consecutive_failures: int = 0
    consecutive_successes: int = 0
    last_failure_time: float | None = None
    last_success_time: float | None = None
    state_change_count: int = 0


@dataclass
class CircuitBreakerConfig:
    """Configuration for a circuit breaker."""

    failure_threshold: int = 5  # Failures before opening circuit
    success_threshold: int = 3  # Successes in half-open to close
    timeout_seconds: float = 30.0  # Time before transitioning to half-open
    half_open_max_requests: int = 1  # Max requests allowed in half-open
    exclude_exceptions: tuple[type[Exception], ...] = field(default_factory=tuple)
    include_exceptions: tuple[type[Exception], ...] | None = None


class CircuitBreaker:
    """Implementation of the circuit breaker pattern.

    The circuit breaker monitors for failures and prevents requests
    when the failure threshold is exceeded, allowing the system to recover.

    States:
        CLOSED: Normal operation, requests flow through
        OPEN: Circuit tripped, requests are rejected
        HALF_OPEN: Testing recovery, limited requests allowed

    Example:
        ```python
        breaker = CircuitBreaker("my-service")

        try:
            async with breaker:
                await make_request()
        except CircuitOpenError:
            # Handle circuit open
            pass
        ```
    """

    def __init__(
        self,
        name: str,
        config: CircuitBreakerConfig | None = None,
        on_state_change: Callable[[str, CircuitState, CircuitState], None] | None = None,
    ) -> None:
        """Initialize circuit breaker.

        Args:
            name: Identifier for this circuit
            config: Circuit breaker configuration
            on_state_change: Callback for state changes (name, old, new)
        """
        self.name = name
        self.config = config or CircuitBreakerConfig()
        self._state = CircuitState.CLOSED
        self._stats = CircuitStats()
        self._lock = asyncio.Lock()
        self._half_open_requests = 0
        self._on_state_change = on_state_change

    @property
    def state(self) -> CircuitState:
        """Get current circuit state."""
        return self._state

    @property
    def stats(self) -> CircuitStats:
        """Get circuit statistics."""
        return self._stats

    @property
    def is_closed(self) -> bool:
        """Check if circuit is closed (normal operation)."""
        return self._state == CircuitState.CLOSED

    @property
    def is_open(self) -> bool:
        """Check if circuit is open (blocking requests)."""
        return self._state == CircuitState.OPEN

    @property
    def is_half_open(self) -> bool:
        """Check if circuit is half-open (testing recovery)."""
        return self._state == CircuitState.HALF_OPEN

    async def _transition_to(self, new_state: CircuitState) -> None:
        """Transition to a new state."""
        if self._state != new_state:
            old_state = self._state
            self._state = new_state
            self._stats.state_change_count += 1

            if new_state == CircuitState.HALF_OPEN:
                self._half_open_requests = 0

            logger.info(
                "Circuit breaker state change",
                circuit=self.name,
                old_state=old_state.value,
                new_state=new_state.value,
            )

            if self._on_state_change:
                try:
                    self._on_state_change(self.name, old_state, new_state)
                except Exception as e:
                    logger.warning("State change callback error", error=str(e))

    async def _check_state(self) -> bool:
        """Check if request should be allowed.

        Returns:
            True if request can proceed, False if blocked
        """
        async with self._lock:
            now = time.time()

            if self._state == CircuitState.CLOSED:
                return True

            if self._state == CircuitState.OPEN:
                # Check if timeout has elapsed
                if (
                    self._stats.last_failure_time
                    and now - self._stats.last_failure_time >= self.config.timeout_seconds
                ):
                    await self._transition_to(CircuitState.HALF_OPEN)
                    return True
                return False

            if self._state == CircuitState.HALF_OPEN:
                # Allow limited requests in half-open
                if self._half_open_requests < self.config.half_open_max_requests:
                    self._half_open_requests += 1
                    return True
                return False

            return False

    async def record_success(self) -> None:
        """Record a successful request."""
        async with self._lock:
            self._stats.total_requests += 1
            self._stats.successful_requests += 1
            self._stats.consecutive_failures = 0
            self._stats.consecutive_successes += 1
            self._stats.last_success_time = time.time()

            if (
                self._state == CircuitState.HALF_OPEN
                and self._stats.consecutive_successes >= self.config.success_threshold
            ):
                await self._transition_to(CircuitState.CLOSED)

    async def record_failure(self, exception: Exception | None = None) -> None:
        """Record a failed request.

        Args:
            exception: The exception that caused the failure (optional)
        """
        # Check if this exception should be excluded
        if (
            exception
            and self.config.exclude_exceptions
            and isinstance(exception, self.config.exclude_exceptions)
        ):
            # Treat as success for circuit purposes
            await self.record_success()
            return

        # Check if only specific exceptions should trip circuit
        if (
            exception
            and self.config.include_exceptions
            and not isinstance(exception, self.config.include_exceptions)
        ):
            await self.record_success()
            return

        async with self._lock:
            now = time.time()
            self._stats.total_requests += 1
            self._stats.failed_requests += 1
            self._stats.consecutive_successes = 0
            self._stats.consecutive_failures += 1
            self._stats.last_failure_time = now

            if self._state == CircuitState.CLOSED:
                if self._stats.consecutive_failures >= self.config.failure_threshold:
                    await self._transition_to(CircuitState.OPEN)

            elif self._state == CircuitState.HALF_OPEN:
                # Any failure in half-open reopens circuit
                await self._transition_to(CircuitState.OPEN)

    async def record_rejection(self) -> None:
        """Record a rejected request (circuit was open)."""
        async with self._lock:
            self._stats.total_requests += 1
            self._stats.rejected_requests += 1

    async def allow_request(self) -> bool:
        """Check if a request should be allowed.

        Returns:
            True if request is allowed, False if blocked
        """
        allowed = await self._check_state()
        if not allowed:
            await self.record_rejection()
        return allowed

    async def reset(self) -> None:
        """Reset the circuit breaker to closed state."""
        async with self._lock:
            old_state = self._state
            self._state = CircuitState.CLOSED
            self._stats.consecutive_failures = 0
            self._stats.consecutive_successes = 0
            self._half_open_requests = 0

            if old_state != CircuitState.CLOSED:
                logger.info("Circuit breaker reset", circuit=self.name)

    async def __aenter__(self) -> CircuitBreaker:
        """Async context manager entry - check if request allowed."""
        if not await self.allow_request():
            raise CircuitOpenError(f"Circuit '{self.name}' is open")
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: Any,
    ) -> bool:
        """Async context manager exit - record success or failure."""
        if exc_val is None:
            await self.record_success()
        else:
            await self.record_failure(exc_val if isinstance(exc_val, Exception) else None)
        return False  # Don't suppress exceptions

    def to_dict(self) -> dict[str, Any]:
        """Convert circuit state to dictionary."""
        return {
            "name": self.name,
            "state": self._state.value,
            "stats": {
                "total_requests": self._stats.total_requests,
                "successful_requests": self._stats.successful_requests,
                "failed_requests": self._stats.failed_requests,
                "rejected_requests": self._stats.rejected_requests,
                "consecutive_failures": self._stats.consecutive_failures,
                "consecutive_successes": self._stats.consecutive_successes,
                "state_change_count": self._stats.state_change_count,
            },
            "config": {
                "failure_threshold": self.config.failure_threshold,
                "success_threshold": self.config.success_threshold,
                "timeout_seconds": self.config.timeout_seconds,
            },
        }


class CircuitOpenError(Exception):
    """Exception raised when circuit is open and request is blocked."""

    pass


class CircuitBreakerRegistry:
    """Registry for managing multiple circuit breakers.

    Provides a central place to create, access, and monitor
    circuit breakers across the application.
    """

    def __init__(
        self,
        default_config: CircuitBreakerConfig | None = None,
        on_state_change: Callable[[str, CircuitState, CircuitState], None] | None = None,
    ) -> None:
        """Initialize registry.

        Args:
            default_config: Default configuration for new circuits
            on_state_change: Global callback for state changes
        """
        self._circuits: dict[str, CircuitBreaker] = {}
        self._default_config = default_config or CircuitBreakerConfig()
        self._on_state_change = on_state_change
        self._lock = asyncio.Lock()

    def get(
        self,
        name: str,
        config: CircuitBreakerConfig | None = None,
    ) -> CircuitBreaker:
        """Get or create a circuit breaker.

        Args:
            name: Circuit breaker identifier
            config: Optional configuration (uses default if not provided)

        Returns:
            CircuitBreaker instance
        """
        if name not in self._circuits:
            self._circuits[name] = CircuitBreaker(
                name=name,
                config=config or self._default_config,
                on_state_change=self._on_state_change,
            )
        return self._circuits[name]

    def get_all(self) -> dict[str, CircuitBreaker]:
        """Get all registered circuit breakers."""
        return dict(self._circuits)

    def remove(self, name: str) -> bool:
        """Remove a circuit breaker.

        Args:
            name: Circuit breaker to remove

        Returns:
            True if removed, False if not found
        """
        if name in self._circuits:
            del self._circuits[name]
            return True
        return False

    async def reset_all(self) -> None:
        """Reset all circuit breakers to closed state."""
        for circuit in self._circuits.values():
            await circuit.reset()

    def get_open_circuits(self) -> list[str]:
        """Get names of all open circuits."""
        return [name for name, circuit in self._circuits.items() if circuit.is_open]

    def get_stats(self) -> dict[str, Any]:
        """Get aggregated statistics for all circuits."""
        total = len(self._circuits)
        open_count = sum(1 for c in self._circuits.values() if c.is_open)
        half_open_count = sum(1 for c in self._circuits.values() if c.is_half_open)
        closed_count = sum(1 for c in self._circuits.values() if c.is_closed)

        return {
            "total_circuits": total,
            "open": open_count,
            "half_open": half_open_count,
            "closed": closed_count,
            "circuits": {name: circuit.to_dict() for name, circuit in self._circuits.items()},
        }


# Global registry instance
_global_registry: CircuitBreakerRegistry | None = None


def get_circuit_breaker_registry() -> CircuitBreakerRegistry:
    """Get the global circuit breaker registry.

    Returns:
        Global CircuitBreakerRegistry instance
    """
    global _global_registry
    if _global_registry is None:
        _global_registry = CircuitBreakerRegistry()
    return _global_registry


def get_circuit_breaker(
    name: str,
    config: CircuitBreakerConfig | None = None,
) -> CircuitBreaker:
    """Get or create a circuit breaker from the global registry.

    Args:
        name: Circuit breaker identifier
        config: Optional configuration

    Returns:
        CircuitBreaker instance
    """
    return get_circuit_breaker_registry().get(name, config)


__all__ = [
    "CircuitBreaker",
    "CircuitBreakerConfig",
    "CircuitBreakerRegistry",
    "CircuitOpenError",
    "CircuitState",
    "CircuitStats",
    "get_circuit_breaker",
    "get_circuit_breaker_registry",
]
