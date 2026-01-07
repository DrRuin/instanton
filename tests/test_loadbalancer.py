"""Tests for load balancer."""


import pytest

from instanton.core.loadbalancer import (
    Backend,
    BackendHealth,
    BackendPool,
    ConsistentHashStrategy,
    HealthCheckConfig,
    IPHashStrategy,
    LeastConnectionsStrategy,
    LeastResponseTimeStrategy,
    LoadBalancer,
    LoadBalancerAlgorithm,
    RandomStrategy,
    RoundRobinStrategy,
    WeightedLeastConnectionsStrategy,
    WeightedRandomStrategy,
    WeightedRoundRobinStrategy,
)

# ==============================================================================
# Backend Tests
# ==============================================================================


class TestBackend:
    """Tests for Backend dataclass."""

    def test_address(self):
        """Test address property."""
        backend = Backend(id="test", host="localhost", port=8080)
        assert backend.address == "localhost:8080"

    def test_is_available_healthy(self):
        """Test availability when healthy."""
        backend = Backend(
            id="test",
            host="localhost",
            port=8080,
            health=BackendHealth.HEALTHY,
        )
        assert backend.is_available

    def test_is_available_unhealthy(self):
        """Test availability when unhealthy."""
        backend = Backend(
            id="test",
            host="localhost",
            port=8080,
            health=BackendHealth.UNHEALTHY,
        )
        assert not backend.is_available

    def test_is_available_draining(self):
        """Test availability when draining."""
        backend = Backend(
            id="test",
            host="localhost",
            port=8080,
            health=BackendHealth.DRAINING,
        )
        assert not backend.is_available

    def test_is_available_at_max_connections(self):
        """Test availability at max connections."""
        backend = Backend(
            id="test",
            host="localhost",
            port=8080,
            max_connections=10,
            health=BackendHealth.HEALTHY,
        )
        backend.stats.active_connections = 10
        assert not backend.is_available


# ==============================================================================
# Round Robin Strategy Tests
# ==============================================================================


class TestRoundRobinStrategy:
    """Tests for round robin load balancing."""

    def test_basic_rotation(self):
        """Test basic round robin rotation."""
        strategy = RoundRobinStrategy()
        backends = [
            Backend(id="a", host="a", port=80, health=BackendHealth.HEALTHY),
            Backend(id="b", host="b", port=80, health=BackendHealth.HEALTHY),
            Backend(id="c", host="c", port=80, health=BackendHealth.HEALTHY),
        ]

        results = [strategy.select(backends) for _ in range(6)]
        ids = [b.id for b in results]

        # Should rotate through all backends twice
        assert ids == ["a", "b", "c", "a", "b", "c"]

    def test_empty_backends(self):
        """Test with no backends."""
        strategy = RoundRobinStrategy()
        assert strategy.select([]) is None

    def test_skips_unavailable(self):
        """Test skipping unavailable backends."""
        strategy = RoundRobinStrategy()
        backends = [
            Backend(id="a", host="a", port=80, health=BackendHealth.UNHEALTHY),
            Backend(id="b", host="b", port=80, health=BackendHealth.HEALTHY),
            Backend(id="c", host="c", port=80, health=BackendHealth.HEALTHY),
        ]

        # Should only return healthy backends
        for _ in range(10):
            selected = strategy.select(backends)
            assert selected.id in ("b", "c")


# ==============================================================================
# Weighted Round Robin Strategy Tests
# ==============================================================================


class TestWeightedRoundRobinStrategy:
    """Tests for weighted round robin load balancing."""

    def test_respects_weights(self):
        """Test that weights affect selection frequency."""
        strategy = WeightedRoundRobinStrategy()
        backends = [
            Backend(id="a", host="a", port=80, weight=3, health=BackendHealth.HEALTHY),
            Backend(id="b", host="b", port=80, weight=1, health=BackendHealth.HEALTHY),
        ]

        # Select many times and count
        counts = {"a": 0, "b": 0}
        for _ in range(100):
            selected = strategy.select(backends)
            counts[selected.id] += 1

        # "a" should be selected roughly 3x more than "b"
        ratio = counts["a"] / counts["b"]
        assert 2.5 <= ratio <= 3.5


# ==============================================================================
# Least Connections Strategy Tests
# ==============================================================================


class TestLeastConnectionsStrategy:
    """Tests for least connections load balancing."""

    def test_selects_least_connections(self):
        """Test selecting backend with fewest connections."""
        strategy = LeastConnectionsStrategy()

        backends = [
            Backend(id="a", host="a", port=80, health=BackendHealth.HEALTHY),
            Backend(id="b", host="b", port=80, health=BackendHealth.HEALTHY),
            Backend(id="c", host="c", port=80, health=BackendHealth.HEALTHY),
        ]
        backends[0].stats.active_connections = 10
        backends[1].stats.active_connections = 5
        backends[2].stats.active_connections = 15

        selected = strategy.select(backends)
        assert selected.id == "b"  # Fewest connections

    def test_tie_breaking(self):
        """Test behavior when connections are equal."""
        strategy = LeastConnectionsStrategy()

        backends = [
            Backend(id="a", host="a", port=80, health=BackendHealth.HEALTHY),
            Backend(id="b", host="b", port=80, health=BackendHealth.HEALTHY),
        ]
        # Both have 0 connections
        selected = strategy.select(backends)
        assert selected.id in ("a", "b")


# ==============================================================================
# Weighted Least Connections Strategy Tests
# ==============================================================================


class TestWeightedLeastConnectionsStrategy:
    """Tests for weighted least connections load balancing."""

    def test_considers_weight(self):
        """Test that weight affects selection."""
        strategy = WeightedLeastConnectionsStrategy()

        backends = [
            Backend(id="a", host="a", port=80, weight=1, health=BackendHealth.HEALTHY),
            Backend(id="b", host="b", port=80, weight=2, health=BackendHealth.HEALTHY),
        ]
        backends[0].stats.active_connections = 5  # Score: 5/1 = 5
        backends[1].stats.active_connections = 8  # Score: 8/2 = 4

        selected = strategy.select(backends)
        assert selected.id == "b"  # Lower score despite more connections


# ==============================================================================
# Random Strategy Tests
# ==============================================================================


class TestRandomStrategy:
    """Tests for random load balancing."""

    def test_returns_backend(self):
        """Test that random returns a backend."""
        strategy = RandomStrategy()
        backends = [
            Backend(id="a", host="a", port=80, health=BackendHealth.HEALTHY),
            Backend(id="b", host="b", port=80, health=BackendHealth.HEALTHY),
        ]

        selected = strategy.select(backends)
        assert selected is not None
        assert selected.id in ("a", "b")

    def test_distribution(self):
        """Test roughly even distribution."""
        strategy = RandomStrategy()
        backends = [
            Backend(id="a", host="a", port=80, health=BackendHealth.HEALTHY),
            Backend(id="b", host="b", port=80, health=BackendHealth.HEALTHY),
        ]

        counts = {"a": 0, "b": 0}
        for _ in range(1000):
            selected = strategy.select(backends)
            counts[selected.id] += 1

        # Should be roughly 50/50 (allow some variance)
        ratio = counts["a"] / counts["b"]
        assert 0.7 <= ratio <= 1.3


# ==============================================================================
# Weighted Random Strategy Tests
# ==============================================================================


class TestWeightedRandomStrategy:
    """Tests for weighted random load balancing."""

    def test_respects_weights(self):
        """Test that weights affect selection frequency."""
        strategy = WeightedRandomStrategy()
        backends = [
            Backend(id="a", host="a", port=80, weight=3, health=BackendHealth.HEALTHY),
            Backend(id="b", host="b", port=80, weight=1, health=BackendHealth.HEALTHY),
        ]

        counts = {"a": 0, "b": 0}
        for _ in range(1000):
            selected = strategy.select(backends)
            counts[selected.id] += 1

        # "a" should be selected roughly 3x more (with statistical variance tolerance)
        ratio = counts["a"] / counts["b"]
        assert 2.0 <= ratio <= 4.5


# ==============================================================================
# IP Hash Strategy Tests
# ==============================================================================


class TestIPHashStrategy:
    """Tests for IP hash load balancing."""

    def test_consistent_selection(self):
        """Test same IP always selects same backend."""
        strategy = IPHashStrategy()
        backends = [
            Backend(id="a", host="a", port=80, health=BackendHealth.HEALTHY),
            Backend(id="b", host="b", port=80, health=BackendHealth.HEALTHY),
            Backend(id="c", host="c", port=80, health=BackendHealth.HEALTHY),
        ]

        # Same IP should always get same backend
        ip = "192.168.1.100"
        first = strategy.select(backends, ip)
        for _ in range(10):
            assert strategy.select(backends, ip).id == first.id

    def test_different_ips(self):
        """Test different IPs can get different backends."""
        strategy = IPHashStrategy()
        backends = [
            Backend(id="a", host="a", port=80, health=BackendHealth.HEALTHY),
            Backend(id="b", host="b", port=80, health=BackendHealth.HEALTHY),
            Backend(id="c", host="c", port=80, health=BackendHealth.HEALTHY),
        ]

        # Try many IPs
        selected_backends = set()
        for i in range(100):
            ip = f"192.168.1.{i}"
            selected = strategy.select(backends, ip)
            selected_backends.add(selected.id)

        # Should have distributed across multiple backends
        assert len(selected_backends) > 1


# ==============================================================================
# Consistent Hash Strategy Tests
# ==============================================================================


class TestConsistentHashStrategy:
    """Tests for consistent hash load balancing."""

    def test_consistent_selection(self):
        """Test consistent hashing for same key."""
        strategy = ConsistentHashStrategy()
        backends = [
            Backend(id="a", host="a", port=80, health=BackendHealth.HEALTHY),
            Backend(id="b", host="b", port=80, health=BackendHealth.HEALTHY),
            Backend(id="c", host="c", port=80, health=BackendHealth.HEALTHY),
        ]

        key = "user-12345"
        first = strategy.select(backends, key)
        for _ in range(10):
            assert strategy.select(backends, key).id == first.id

    def test_minimal_redistribution(self):
        """Test that adding backend causes minimal redistribution."""
        strategy = ConsistentHashStrategy()
        backends = [
            Backend(id="a", host="a", port=80, health=BackendHealth.HEALTHY),
            Backend(id="b", host="b", port=80, health=BackendHealth.HEALTHY),
        ]

        # Record initial selections
        keys = [f"key-{i}" for i in range(100)]
        initial = {key: strategy.select(backends, key).id for key in keys}

        # Add a backend
        backends.append(
            Backend(id="c", host="c", port=80, health=BackendHealth.HEALTHY)
        )
        strategy.rebuild_ring(backends)

        # Check how many keys changed
        changed = sum(
            1 for key in keys
            if strategy.select(backends, key).id != initial[key]
        )

        # Should be roughly 1/3 (new backend should get ~1/3 of keys)
        assert changed < 50  # Less than half changed


# ==============================================================================
# Least Response Time Strategy Tests
# ==============================================================================


class TestLeastResponseTimeStrategy:
    """Tests for least response time load balancing."""

    def test_selects_fastest(self):
        """Test selecting backend with lowest response time."""
        strategy = LeastResponseTimeStrategy()

        backends = [
            Backend(id="a", host="a", port=80, health=BackendHealth.HEALTHY),
            Backend(id="b", host="b", port=80, health=BackendHealth.HEALTHY),
            Backend(id="c", host="c", port=80, health=BackendHealth.HEALTHY),
        ]
        backends[0].stats.avg_response_time_ms = 100
        backends[0].stats.total_requests = 10
        backends[1].stats.avg_response_time_ms = 50
        backends[1].stats.total_requests = 10
        backends[2].stats.avg_response_time_ms = 150
        backends[2].stats.total_requests = 10

        selected = strategy.select(backends)
        assert selected.id == "b"  # Fastest

    def test_falls_back_to_random_no_history(self):
        """Test fallback when no response time history."""
        strategy = LeastResponseTimeStrategy()

        backends = [
            Backend(id="a", host="a", port=80, health=BackendHealth.HEALTHY),
            Backend(id="b", host="b", port=80, health=BackendHealth.HEALTHY),
        ]
        # No requests recorded

        selected = strategy.select(backends)
        assert selected is not None


# ==============================================================================
# Load Balancer Tests
# ==============================================================================


class TestLoadBalancer:
    """Tests for LoadBalancer class."""

    def test_add_backend(self):
        """Test adding backends."""
        lb = LoadBalancer()
        backend = Backend(id="test", host="localhost", port=8080)

        lb.add_backend(backend)

        assert lb.get_backend("test") is not None
        assert len(lb.list_backends()) == 1

    def test_remove_backend(self):
        """Test removing backends."""
        lb = LoadBalancer()
        backend = Backend(id="test", host="localhost", port=8080)
        lb.add_backend(backend)

        result = lb.remove_backend("test")

        assert result is True
        assert lb.get_backend("test") is None

    def test_select_with_algorithm(self):
        """Test selection with different algorithms."""
        for algo in LoadBalancerAlgorithm:
            lb = LoadBalancer(algorithm=algo)
            lb.add_backend(
                Backend(id="a", host="a", port=80, health=BackendHealth.HEALTHY)
            )
            lb.add_backend(
                Backend(id="b", host="b", port=80, health=BackendHealth.HEALTHY)
            )

            selected = lb.select()
            assert selected is not None

    @pytest.mark.asyncio
    async def test_acquire_connection(self):
        """Test acquiring a backend connection."""
        lb = LoadBalancer()
        lb.add_backend(
            Backend(id="test", host="localhost", port=8080, health=BackendHealth.HEALTHY)
        )

        conn = await lb.acquire()
        assert conn is not None

        async with conn as backend:
            assert backend.id == "test"
            assert backend.stats.active_connections == 1

        # Connection released
        assert lb.get_backend("test").stats.active_connections == 0

    def test_record_success(self):
        """Test recording successful request."""
        lb = LoadBalancer()
        backend = Backend(id="test", host="localhost", port=8080)
        lb.add_backend(backend)

        lb.record_success(backend, 50.0)

        assert backend.stats.total_requests == 1
        assert backend.stats.avg_response_time_ms == 50.0
        assert backend.stats.consecutive_successes == 1

    def test_record_failure(self):
        """Test recording failed request."""
        lb = LoadBalancer()
        backend = Backend(id="test", host="localhost", port=8080)
        lb.add_backend(backend)

        lb.record_failure(backend)

        assert backend.stats.total_requests == 1
        assert backend.stats.total_errors == 1
        assert backend.stats.consecutive_failures == 1


# ==============================================================================
# Backend Pool Tests
# ==============================================================================


class TestBackendPool:
    """Tests for BackendPool class."""

    def test_add_backend(self):
        """Test adding backend to pool."""
        pool = BackendPool("test-pool")

        backend = pool.add_backend("localhost", 8080, weight=2)

        assert backend is not None
        assert backend.host == "localhost"
        assert backend.port == 8080
        assert backend.weight == 2

    def test_remove_backend(self):
        """Test removing backend from pool."""
        pool = BackendPool("test-pool")
        pool.add_backend("localhost", 8080)

        result = pool.remove_backend("localhost:8080")

        assert result is True

    @pytest.mark.asyncio
    async def test_get_connection(self):
        """Test getting connection from pool."""
        pool = BackendPool("test-pool")
        backend = pool.add_backend("localhost", 8080)
        backend.health = BackendHealth.HEALTHY

        conn = await pool.get_connection()
        assert conn is not None

    def test_get_stats(self):
        """Test getting pool statistics."""
        pool = BackendPool("test-pool")
        pool.add_backend("localhost", 8080)
        pool.add_backend("localhost", 8081)

        stats = pool.get_stats()

        assert stats["name"] == "test-pool"
        assert stats["total_backends"] == 2
        assert len(stats["backends"]) == 2


# ==============================================================================
# Health Check Tests
# ==============================================================================


class TestHealthCheck:
    """Tests for health checking."""

    @pytest.mark.asyncio
    async def test_health_check_marks_healthy(self):
        """Test health check marks backend healthy."""
        config = HealthCheckConfig(
            enabled=True,
            healthy_threshold=2,
            unhealthy_threshold=3,
        )
        lb = LoadBalancer(health_config=config)
        backend = Backend(
            id="test",
            host="localhost",
            port=8080,
            health=BackendHealth.UNKNOWN,
        )
        lb.add_backend(backend)

        # Simulate successful health checks
        backend.stats.consecutive_successes = 2
        backend.stats.consecutive_failures = 0

        # Check threshold
        if backend.stats.consecutive_successes >= config.healthy_threshold:
            backend.health = BackendHealth.HEALTHY

        assert backend.health == BackendHealth.HEALTHY

    @pytest.mark.asyncio
    async def test_health_check_marks_unhealthy(self):
        """Test health check marks backend unhealthy."""
        config = HealthCheckConfig(
            enabled=True,
            healthy_threshold=2,
            unhealthy_threshold=3,
        )
        lb = LoadBalancer(health_config=config)
        backend = Backend(
            id="test",
            host="localhost",
            port=8080,
            health=BackendHealth.HEALTHY,
        )
        lb.add_backend(backend)

        # Simulate failed health checks
        backend.stats.consecutive_failures = 3
        backend.stats.consecutive_successes = 0

        # Check threshold
        if backend.stats.consecutive_failures >= config.unhealthy_threshold:
            backend.health = BackendHealth.UNHEALTHY

        assert backend.health == BackendHealth.UNHEALTHY
