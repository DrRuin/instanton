"""Tests for the circuit breaker module."""

from __future__ import annotations

import asyncio

import pytest

from instanton.observability.circuit_breaker import (
    CircuitBreaker,
    CircuitBreakerConfig,
    CircuitBreakerRegistry,
    CircuitOpenError,
    CircuitState,
    get_circuit_breaker,
    get_circuit_breaker_registry,
)

# ==============================================================================
# CircuitBreaker Tests
# ==============================================================================


class TestCircuitBreakerInit:
    """Tests for circuit breaker initialization."""

    def test_default_init(self):
        """Test default initialization."""
        breaker = CircuitBreaker("test")
        assert breaker.name == "test"
        assert breaker.state == CircuitState.CLOSED
        assert breaker.is_closed
        assert not breaker.is_open
        assert not breaker.is_half_open

    def test_custom_config(self):
        """Test initialization with custom config."""
        config = CircuitBreakerConfig(
            failure_threshold=10,
            success_threshold=5,
            timeout_seconds=60.0,
        )
        breaker = CircuitBreaker("test", config=config)
        assert breaker.config.failure_threshold == 10
        assert breaker.config.success_threshold == 5
        assert breaker.config.timeout_seconds == 60.0


class TestCircuitBreakerOperations:
    """Tests for circuit breaker operations."""

    @pytest.mark.asyncio
    async def test_record_success(self):
        """Test recording successful requests."""
        breaker = CircuitBreaker("test")
        await breaker.record_success()

        assert breaker.stats.successful_requests == 1
        assert breaker.stats.total_requests == 1
        assert breaker.stats.consecutive_successes == 1

    @pytest.mark.asyncio
    async def test_record_failure(self):
        """Test recording failed requests."""
        breaker = CircuitBreaker("test")
        await breaker.record_failure()

        assert breaker.stats.failed_requests == 1
        assert breaker.stats.total_requests == 1
        assert breaker.stats.consecutive_failures == 1

    @pytest.mark.asyncio
    async def test_trip_circuit(self):
        """Test that circuit trips after failure threshold."""
        config = CircuitBreakerConfig(failure_threshold=3)
        breaker = CircuitBreaker("test", config=config)

        # Record failures up to threshold
        for _ in range(3):
            await breaker.record_failure()

        assert breaker.is_open
        assert breaker.stats.consecutive_failures == 3

    @pytest.mark.asyncio
    async def test_allow_request_when_closed(self):
        """Test that requests are allowed when closed."""
        breaker = CircuitBreaker("test")
        assert await breaker.allow_request()

    @pytest.mark.asyncio
    async def test_reject_request_when_open(self):
        """Test that requests are rejected when open."""
        config = CircuitBreakerConfig(failure_threshold=1, timeout_seconds=60)
        breaker = CircuitBreaker("test", config=config)

        await breaker.record_failure()
        assert breaker.is_open

        # Request should be rejected
        allowed = await breaker.allow_request()
        assert not allowed
        assert breaker.stats.rejected_requests == 1

    @pytest.mark.asyncio
    async def test_context_manager_success(self):
        """Test context manager with successful operation."""
        breaker = CircuitBreaker("test")

        async with breaker:
            pass  # Success

        assert breaker.stats.successful_requests == 1
        assert breaker.is_closed

    @pytest.mark.asyncio
    async def test_context_manager_failure(self):
        """Test context manager with failed operation."""
        config = CircuitBreakerConfig(failure_threshold=1)
        breaker = CircuitBreaker("test", config=config)

        with pytest.raises(ValueError):
            async with breaker:
                raise ValueError("test error")

        assert breaker.stats.failed_requests == 1
        assert breaker.is_open

    @pytest.mark.asyncio
    async def test_context_manager_circuit_open(self):
        """Test context manager raises when circuit is open."""
        config = CircuitBreakerConfig(failure_threshold=1, timeout_seconds=60)
        breaker = CircuitBreaker("test", config=config)

        await breaker.record_failure()
        assert breaker.is_open

        with pytest.raises(CircuitOpenError):
            async with breaker:
                pass

    @pytest.mark.asyncio
    async def test_reset(self):
        """Test resetting circuit breaker."""
        config = CircuitBreakerConfig(failure_threshold=1)
        breaker = CircuitBreaker("test", config=config)

        await breaker.record_failure()
        assert breaker.is_open

        await breaker.reset()
        assert breaker.is_closed
        assert breaker.stats.consecutive_failures == 0

    @pytest.mark.asyncio
    async def test_to_dict(self):
        """Test serialization to dictionary."""
        breaker = CircuitBreaker("test")
        await breaker.record_success()

        result = breaker.to_dict()
        assert result["name"] == "test"
        assert result["state"] == "closed"
        assert result["stats"]["successful_requests"] == 1


class TestCircuitBreakerHalfOpen:
    """Tests for half-open state behavior."""

    @pytest.mark.asyncio
    async def test_transition_to_half_open(self):
        """Test transition from open to half-open after timeout."""
        config = CircuitBreakerConfig(failure_threshold=1, timeout_seconds=0.01)
        breaker = CircuitBreaker("test", config=config)

        await breaker.record_failure()
        assert breaker.is_open

        # Wait for timeout
        await asyncio.sleep(0.02)

        # Next request should trigger half-open
        allowed = await breaker.allow_request()
        assert allowed
        assert breaker.is_half_open

    @pytest.mark.asyncio
    async def test_close_from_half_open_on_success(self):
        """Test circuit closes from half-open after success threshold."""
        config = CircuitBreakerConfig(
            failure_threshold=1, success_threshold=2, timeout_seconds=0.01
        )
        breaker = CircuitBreaker("test", config=config)

        # Open circuit
        await breaker.record_failure()
        assert breaker.is_open

        # Wait for timeout
        await asyncio.sleep(0.02)

        # Trigger half-open
        await breaker.allow_request()
        assert breaker.is_half_open

        # Success should start closing
        await breaker.record_success()
        assert breaker.is_half_open  # Not yet closed

        await breaker.record_success()
        assert breaker.is_closed  # Now closed

    @pytest.mark.asyncio
    async def test_reopen_from_half_open_on_failure(self):
        """Test circuit reopens from half-open on any failure."""
        config = CircuitBreakerConfig(failure_threshold=1, timeout_seconds=0.01)
        breaker = CircuitBreaker("test", config=config)

        # Open circuit
        await breaker.record_failure()
        await asyncio.sleep(0.02)

        # Trigger half-open
        await breaker.allow_request()
        assert breaker.is_half_open

        # Failure reopens circuit
        await breaker.record_failure()
        assert breaker.is_open


class TestCircuitBreakerStateCallback:
    """Tests for state change callbacks."""

    @pytest.mark.asyncio
    async def test_callback_on_state_change(self):
        """Test that callback is invoked on state change."""
        config = CircuitBreakerConfig(failure_threshold=1)
        state_changes: list[tuple[str, CircuitState, CircuitState]] = []

        def on_change(name: str, old: CircuitState, new: CircuitState):
            state_changes.append((name, old, new))

        breaker = CircuitBreaker("test", config=config, on_state_change=on_change)
        await breaker.record_failure()

        assert len(state_changes) == 1
        assert state_changes[0] == ("test", CircuitState.CLOSED, CircuitState.OPEN)


# ==============================================================================
# CircuitBreakerRegistry Tests
# ==============================================================================


class TestCircuitBreakerRegistry:
    """Tests for circuit breaker registry."""

    def test_get_creates_breaker(self):
        """Test that get creates a new breaker if not exists."""
        registry = CircuitBreakerRegistry()
        breaker = registry.get("test")

        assert breaker is not None
        assert breaker.name == "test"

    def test_get_returns_same_breaker(self):
        """Test that get returns the same breaker for same name."""
        registry = CircuitBreakerRegistry()
        breaker1 = registry.get("test")
        breaker2 = registry.get("test")

        assert breaker1 is breaker2

    def test_get_all(self):
        """Test getting all breakers."""
        registry = CircuitBreakerRegistry()
        registry.get("a")
        registry.get("b")
        registry.get("c")

        all_breakers = registry.get_all()
        assert len(all_breakers) == 3
        assert "a" in all_breakers
        assert "b" in all_breakers
        assert "c" in all_breakers

    def test_remove(self):
        """Test removing a breaker."""
        registry = CircuitBreakerRegistry()
        registry.get("test")

        assert registry.remove("test")
        assert not registry.remove("test")  # Already removed
        assert len(registry.get_all()) == 0

    @pytest.mark.asyncio
    async def test_reset_all(self):
        """Test resetting all breakers."""
        config = CircuitBreakerConfig(failure_threshold=1)
        registry = CircuitBreakerRegistry(default_config=config)

        breaker1 = registry.get("a")
        breaker2 = registry.get("b")

        await breaker1.record_failure()
        await breaker2.record_failure()

        assert breaker1.is_open
        assert breaker2.is_open

        await registry.reset_all()

        assert breaker1.is_closed
        assert breaker2.is_closed

    @pytest.mark.asyncio
    async def test_get_open_circuits(self):
        """Test getting list of open circuits."""
        config = CircuitBreakerConfig(failure_threshold=1)
        registry = CircuitBreakerRegistry(default_config=config)

        breaker1 = registry.get("a")
        breaker2 = registry.get("b")
        registry.get("c")  # Stays closed

        await breaker1.record_failure()
        await breaker2.record_failure()

        open_circuits = registry.get_open_circuits()
        assert len(open_circuits) == 2
        assert "a" in open_circuits
        assert "b" in open_circuits
        assert "c" not in open_circuits

    @pytest.mark.asyncio
    async def test_get_stats(self):
        """Test getting aggregated stats."""
        config = CircuitBreakerConfig(failure_threshold=1)
        registry = CircuitBreakerRegistry(default_config=config)

        breaker1 = registry.get("a")
        registry.get("b")

        await breaker1.record_failure()

        stats = registry.get_stats()
        assert stats["total_circuits"] == 2
        assert stats["open"] == 1
        assert stats["closed"] == 1
        assert "a" in stats["circuits"]
        assert "b" in stats["circuits"]


# ==============================================================================
# Global Function Tests
# ==============================================================================


class TestGlobalFunctions:
    """Tests for global convenience functions."""

    def test_get_circuit_breaker_registry(self):
        """Test getting global registry."""
        registry = get_circuit_breaker_registry()
        assert registry is not None
        assert isinstance(registry, CircuitBreakerRegistry)

    def test_get_circuit_breaker(self):
        """Test getting circuit breaker from global registry."""
        breaker = get_circuit_breaker("global-test")
        assert breaker is not None
        assert breaker.name == "global-test"


# ==============================================================================
# CircuitBreakerConfig Tests
# ==============================================================================


class TestCircuitBreakerConfig:
    """Tests for circuit breaker configuration."""

    def test_default_values(self):
        """Test default configuration values."""
        config = CircuitBreakerConfig()
        assert config.failure_threshold == 5
        assert config.success_threshold == 3
        assert config.timeout_seconds == 30.0
        assert config.half_open_max_requests == 1
        assert config.exclude_exceptions == ()
        assert config.include_exceptions is None

    def test_custom_values(self):
        """Test custom configuration values."""
        config = CircuitBreakerConfig(
            failure_threshold=10,
            success_threshold=5,
            timeout_seconds=60.0,
            half_open_max_requests=3,
        )
        assert config.failure_threshold == 10
        assert config.success_threshold == 5
        assert config.timeout_seconds == 60.0
        assert config.half_open_max_requests == 3


class TestExceptionFiltering:
    """Tests for exception filtering in circuit breaker."""

    @pytest.mark.asyncio
    async def test_exclude_exceptions(self):
        """Test that excluded exceptions don't trip circuit."""
        config = CircuitBreakerConfig(
            failure_threshold=1, exclude_exceptions=(ValueError,)
        )
        breaker = CircuitBreaker("test", config=config)

        # ValueError should be excluded
        await breaker.record_failure(ValueError("test"))
        assert breaker.is_closed  # Circuit stays closed

        # Other exceptions should trip circuit
        await breaker.record_failure(RuntimeError("test"))
        assert breaker.is_open

    @pytest.mark.asyncio
    async def test_include_exceptions(self):
        """Test that only included exceptions trip circuit."""
        config = CircuitBreakerConfig(
            failure_threshold=1, include_exceptions=(RuntimeError,)
        )
        breaker = CircuitBreaker("test", config=config)

        # Non-included exception doesn't trip circuit
        await breaker.record_failure(ValueError("test"))
        assert breaker.is_closed

        # Included exception trips circuit
        await breaker.record_failure(RuntimeError("test"))
        assert breaker.is_open
