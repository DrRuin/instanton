"""Tests for High Availability connection manager."""

import time
from unittest.mock import AsyncMock, MagicMock

import pytest

from instanton.core.ha import (
    ConnectionHealth,
    ConnectionMetrics,
    EdgeServer,
    FailoverReason,
    GeoRouter,
    HAConnection,
    HAConnectionManager,
    LoadBalancer,
    LoadBalanceStrategy,
)

# ==============================================================================
# ConnectionMetrics Tests
# ==============================================================================


class TestConnectionMetrics:
    """Tests for ConnectionMetrics."""

    def test_default_values(self):
        """Test default metric values."""
        metrics = ConnectionMetrics()

        assert metrics.latency_ms == 0.0
        assert metrics.latency_avg_ms == 0.0
        assert metrics.bytes_sent == 0
        assert metrics.bytes_received == 0
        assert metrics.errors == 0
        assert metrics.health_score == 100.0


# ==============================================================================
# EdgeServer Tests
# ==============================================================================


class TestEdgeServer:
    """Tests for EdgeServer."""

    def test_default_values(self):
        """Test default edge server values."""
        server = EdgeServer(host="edge1.example.com", port=443)

        assert server.host == "edge1.example.com"
        assert server.port == 443
        assert server.region == "unknown"
        assert server.weight == 100
        assert server.is_primary is False

    def test_custom_values(self):
        """Test custom edge server values."""
        server = EdgeServer(
            host="edge1.example.com",
            port=443,
            region="us-east",
            datacenter="dc1",
            weight=150,
            latency_hint_ms=5.0,
            is_primary=True,
        )

        assert server.region == "us-east"
        assert server.datacenter == "dc1"
        assert server.weight == 150
        assert server.latency_hint_ms == 5.0
        assert server.is_primary is True


# ==============================================================================
# HAConnection Tests
# ==============================================================================


class TestHAConnection:
    """Tests for HAConnection."""

    def test_default_values(self):
        """Test default connection values."""
        conn = HAConnection()

        assert conn.id is not None
        assert conn.transport is None
        assert conn.health == ConnectionHealth.HEALTHY
        assert conn.index == 0

    def test_record_latency(self):
        """Test latency recording."""
        conn = HAConnection()

        conn.record_latency(5.0)
        conn.record_latency(10.0)
        conn.record_latency(15.0)

        assert conn.metrics.latency_ms == 15.0
        assert conn.metrics.latency_avg_ms == 10.0

    def test_record_latency_p99(self):
        """Test P99 latency calculation."""
        conn = HAConnection()

        # Add 100 samples
        for i in range(100):
            conn.record_latency(float(i))

        # P99 should be around 99
        assert conn.metrics.latency_p99_ms >= 95

    def test_update_health_healthy(self):
        """Test health update for healthy connection."""
        conn = HAConnection()
        conn.metrics.latency_avg_ms = 3.0
        conn.metrics.last_heartbeat = time.monotonic()

        health = conn.update_health()

        assert health == ConnectionHealth.HEALTHY
        assert conn.metrics.health_score >= 80

    def test_update_health_degraded(self):
        """Test health update for degraded connection."""
        conn = HAConnection()
        conn.metrics.latency_avg_ms = 30.0  # Higher latency
        conn.metrics.last_heartbeat = time.monotonic()

        health = conn.update_health()

        assert health in (ConnectionHealth.HEALTHY, ConnectionHealth.DEGRADED)

    def test_update_health_unhealthy(self):
        """Test health update for unhealthy connection."""
        conn = HAConnection()
        conn.metrics.latency_avg_ms = 150.0  # Very high latency
        conn.metrics.errors = 100
        conn.metrics.messages_sent = 200
        conn.metrics.last_heartbeat = time.monotonic() - 40  # Old heartbeat

        health = conn.update_health()

        bad_health_states = (
            ConnectionHealth.DEGRADED,
            ConnectionHealth.UNHEALTHY,
            ConnectionHealth.DEAD,
        )
        assert health in bad_health_states


# ==============================================================================
# LoadBalancer Tests
# ==============================================================================


class TestLoadBalancer:
    """Tests for LoadBalancer."""

    def test_round_robin(self):
        """Test round-robin selection."""
        balancer = LoadBalancer(LoadBalanceStrategy.ROUND_ROBIN)

        conns = [HAConnection(index=i) for i in range(3)]

        selected = []
        for _ in range(6):
            conn = balancer.select(conns)
            selected.append(conn.index)

        # Should cycle through connections
        assert len(set(selected)) == 3

    def test_least_latency(self):
        """Test least latency selection."""
        balancer = LoadBalancer(LoadBalanceStrategy.LEAST_LATENCY)

        conns = [HAConnection(index=i) for i in range(3)]
        conns[0].metrics.latency_avg_ms = 100.0
        conns[1].metrics.latency_avg_ms = 5.0  # Lowest
        conns[2].metrics.latency_avg_ms = 50.0

        selected = balancer.select(conns)

        assert selected.index == 1

    def test_random(self):
        """Test random selection."""
        balancer = LoadBalancer(LoadBalanceStrategy.RANDOM)

        conns = [HAConnection(index=i) for i in range(3)]

        selected = balancer.select(conns)
        assert selected in conns

    def test_excludes_dead_connections(self):
        """Test that dead connections are excluded."""
        balancer = LoadBalancer(LoadBalanceStrategy.ROUND_ROBIN)

        conns = [HAConnection(index=i) for i in range(3)]
        conns[0].health = ConnectionHealth.DEAD
        conns[1].health = ConnectionHealth.DEAD

        selected = balancer.select(conns)

        assert selected.index == 2

    def test_returns_none_if_all_dead(self):
        """Test returns None if all connections dead."""
        balancer = LoadBalancer(LoadBalanceStrategy.ROUND_ROBIN)

        conns = [HAConnection(index=i) for i in range(3)]
        for conn in conns:
            conn.health = ConnectionHealth.DEAD

        selected = balancer.select(conns)

        assert selected is None


# ==============================================================================
# HAConnectionManager Tests
# ==============================================================================


class TestHAConnectionManager:
    """Tests for HAConnectionManager."""

    def test_default_initialization(self):
        """Test default initialization."""
        manager = HAConnectionManager()

        assert manager.pool_size == 4
        assert manager.heartbeat_interval == 5.0
        assert manager.enable_geo_routing is True

    def test_custom_initialization(self):
        """Test custom initialization."""
        manager = HAConnectionManager(
            pool_size=8,
            heartbeat_interval=10.0,
            heartbeat_timeout=20.0,
            load_balance_strategy=LoadBalanceStrategy.ROUND_ROBIN,
            enable_geo_routing=False,
        )

        assert manager.pool_size == 8
        assert manager.heartbeat_interval == 10.0
        assert manager.enable_geo_routing is False

    def test_add_edge_server(self):
        """Test adding edge servers."""
        manager = HAConnectionManager()

        server1 = EdgeServer(host="edge1.example.com", port=443, weight=100)
        server2 = EdgeServer(host="edge2.example.com", port=443, weight=150)

        manager.add_edge_server(server1)
        manager.add_edge_server(server2)

        # Higher weight should be first
        assert manager._edge_servers[0].weight == 150

    def test_get_connection_no_connections(self):
        """Test get_connection with no connections."""
        manager = HAConnectionManager()

        conn = manager.get_connection()
        assert conn is None

    def test_get_primary_no_connections(self):
        """Test get_primary with no connections."""
        manager = HAConnectionManager()

        primary = manager.get_primary()
        assert primary is None

    def test_get_healthy_count(self):
        """Test counting healthy connections."""
        manager = HAConnectionManager()

        conn1 = HAConnection(health=ConnectionHealth.HEALTHY)
        conn2 = HAConnection(health=ConnectionHealth.DEGRADED)
        conn3 = HAConnection(health=ConnectionHealth.DEAD)

        manager._connections = [conn1, conn2, conn3]

        assert manager.get_healthy_count() == 1

    def test_stats(self):
        """Test getting statistics."""
        manager = HAConnectionManager(pool_size=2)

        conn1 = HAConnection(index=0)
        conn1.metrics.latency_avg_ms = 5.0

        manager._connections = [conn1]

        stats = manager.stats

        assert stats["pool_size"] == 2
        assert len(stats["connections"]) == 1
        assert stats["connections"][0]["latency_ms"] == 5.0

    @pytest.mark.asyncio
    async def test_start_and_stop(self):
        """Test starting and stopping manager."""
        manager = HAConnectionManager(pool_size=2)

        # Mock transport factory
        mock_transport = AsyncMock()
        mock_transport.connect = AsyncMock()
        manager.set_transport_factory(lambda: mock_transport)

        await manager.start("test.example.com:443")

        assert manager._running is True

        await manager.stop()

        assert manager._running is False

    @pytest.mark.asyncio
    async def test_send_no_connection(self):
        """Test send with no connections."""
        manager = HAConnectionManager()

        result = await manager.send(b"test data")
        assert result is False

    @pytest.mark.asyncio
    async def test_recv_no_connection(self):
        """Test recv with no connections."""
        manager = HAConnectionManager()

        result = await manager.recv()
        assert result is None

    def test_on_failover_callback(self):
        """Test failover callback registration."""
        manager = HAConnectionManager()

        callback = MagicMock()
        manager.on_failover(callback)

        assert callback in manager._on_failover

    def test_on_health_change_callback(self):
        """Test health change callback registration."""
        manager = HAConnectionManager()

        callback = MagicMock()
        manager.on_health_change(callback)

        assert callback in manager._on_health_change


# ==============================================================================
# GeoRouter Tests
# ==============================================================================


class TestGeoRouter:
    """Tests for GeoRouter."""

    def test_record_latency(self):
        """Test latency recording."""
        router = GeoRouter()

        router.record_latency("edge1:443", 10.0)
        router.record_latency("edge1:443", 20.0)

        # Should use EMA
        assert router._edge_latencies["edge1:443"] != 20.0

    def test_get_best_edge(self):
        """Test getting best edge."""
        router = GeoRouter()

        edges = [
            EdgeServer(host="edge1", port=443, latency_hint_ms=50.0),
            EdgeServer(host="edge2", port=443, latency_hint_ms=10.0),  # Best
            EdgeServer(host="edge3", port=443, latency_hint_ms=30.0),
        ]

        best = router.get_best_edge(edges)
        assert best.host == "edge2"

    def test_get_best_edge_with_recorded_latency(self):
        """Test best edge with recorded latency."""
        router = GeoRouter()

        edges = [
            EdgeServer(host="edge1", port=443, latency_hint_ms=50.0),
            EdgeServer(host="edge2", port=443, latency_hint_ms=10.0),
        ]

        # Record actual latency showing edge1 is faster
        router.record_latency("edge1:443", 5.0)
        router.record_latency("edge2:443", 100.0)

        best = router.get_best_edge(edges)
        assert best.host == "edge1"

    def test_mark_unhealthy(self):
        """Test marking edge unhealthy."""
        router = GeoRouter()

        router.mark_unhealthy("edge1:443")
        assert router._edge_health["edge1:443"] < 100

    def test_mark_healthy(self):
        """Test marking edge healthy."""
        router = GeoRouter()

        router._edge_health["edge1:443"] = 50
        router.mark_healthy("edge1:443")

        assert router._edge_health["edge1:443"] > 50

    def test_get_best_edge_empty(self):
        """Test with no edges."""
        router = GeoRouter()

        best = router.get_best_edge([])
        assert best is None


# ==============================================================================
# FailoverReason Tests
# ==============================================================================


class TestFailoverReason:
    """Tests for FailoverReason enum."""

    def test_enum_values(self):
        """Test enum values exist."""
        assert FailoverReason.HEARTBEAT_TIMEOUT is not None
        assert FailoverReason.CONNECTION_ERROR is not None
        assert FailoverReason.HIGH_LATENCY is not None
        assert FailoverReason.SERVER_SHUTDOWN is not None
        assert FailoverReason.MANUAL is not None
        assert FailoverReason.LOAD_BALANCING is not None


# ==============================================================================
# ConnectionHealth Tests
# ==============================================================================


class TestConnectionHealth:
    """Tests for ConnectionHealth enum."""

    def test_enum_values(self):
        """Test enum values."""
        assert ConnectionHealth.HEALTHY is not None
        assert ConnectionHealth.DEGRADED is not None
        assert ConnectionHealth.UNHEALTHY is not None
        assert ConnectionHealth.DEAD is not None
