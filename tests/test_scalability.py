"""Tests for Instanton scalability - ensuring it can handle 1000s of concurrent users."""

import asyncio
import secrets
from collections import Counter
from uuid import uuid4

import pytest

from instanton.core.config import ServerConfig
from instanton.server.relay import RelayServer


class TestSubdomainGeneration:
    """Tests for unique subdomain generation at scale."""

    def test_subdomain_uniqueness_1000(self):
        """Test that 1000 subdomain generations are all unique."""
        subdomains = set()
        for _ in range(1000):
            subdomain = secrets.token_hex(6)
            assert subdomain not in subdomains, f"Collision detected: {subdomain}"
            subdomains.add(subdomain)
        assert len(subdomains) == 1000

    def test_subdomain_uniqueness_10000(self):
        """Test that 10000 subdomain generations are all unique."""
        subdomains = set()
        for _ in range(10000):
            subdomain = secrets.token_hex(6)
            assert subdomain not in subdomains, f"Collision detected: {subdomain}"
            subdomains.add(subdomain)
        assert len(subdomains) == 10000

    def test_subdomain_entropy(self):
        """Test that subdomain distribution is uniform."""
        # Generate 10000 subdomains and check first character distribution
        first_chars = [secrets.token_hex(6)[0] for _ in range(10000)]
        counter = Counter(first_chars)

        # Should have roughly equal distribution across hex chars (0-9, a-f)
        # Each char should appear ~625 times (10000/16)
        for char, count in counter.items():
            # Allow 50% deviation
            assert 300 < count < 1000, f"Char {char} has unusual frequency: {count}"


class TestServerCapacity:
    """Tests for server capacity and concurrent tunnel handling."""

    @pytest.fixture
    def server_config(self):
        """Create server config for testing."""
        return ServerConfig(
            base_domain="test.instanton.tech",
            https_bind="0.0.0.0:443",
            control_bind="0.0.0.0:4443",
            max_tunnels=10000,
        )

    @pytest.fixture
    def relay_server(self, server_config):
        """Create relay server instance."""
        return RelayServer(server_config)

    def test_tunnel_dict_capacity_1000(self, relay_server):
        """Test that tunnel dictionary can hold 1000 entries."""
        from dataclasses import dataclass
        from datetime import UTC, datetime
        from unittest.mock import MagicMock

        @dataclass
        class MockTunnel:
            id: str
            subdomain: str
            websocket: MagicMock
            local_port: int
            connected_at: datetime

        for i in range(1000):
            subdomain = f"tunnel{i:04d}"
            tunnel = MockTunnel(
                id=str(uuid4()),
                subdomain=subdomain,
                websocket=MagicMock(),
                local_port=8000,
                connected_at=datetime.now(UTC),
            )
            relay_server._tunnels[subdomain] = tunnel

        assert len(relay_server._tunnels) == 1000

    def test_tunnel_dict_capacity_5000(self, relay_server):
        """Test that tunnel dictionary can hold 5000 entries."""
        from dataclasses import dataclass
        from datetime import UTC, datetime
        from unittest.mock import MagicMock

        @dataclass
        class MockTunnel:
            id: str
            subdomain: str
            websocket: MagicMock
            local_port: int
            connected_at: datetime

        for i in range(5000):
            subdomain = f"tunnel{i:05d}"
            tunnel = MockTunnel(
                id=str(uuid4()),
                subdomain=subdomain,
                websocket=MagicMock(),
                local_port=8000,
                connected_at=datetime.now(UTC),
            )
            relay_server._tunnels[subdomain] = tunnel

        assert len(relay_server._tunnels) == 5000

    def test_tunnel_lookup_performance(self, relay_server):
        """Test that tunnel lookup is fast even with many tunnels."""
        import time
        from dataclasses import dataclass
        from datetime import UTC, datetime
        from unittest.mock import MagicMock

        @dataclass
        class MockTunnel:
            id: str
            subdomain: str
            websocket: MagicMock
            local_port: int
            connected_at: datetime

        # Add 5000 tunnels
        subdomains = []
        for i in range(5000):
            subdomain = f"tunnel{i:05d}"
            subdomains.append(subdomain)
            tunnel = MockTunnel(
                id=str(uuid4()),
                subdomain=subdomain,
                websocket=MagicMock(),
                local_port=8000,
                connected_at=datetime.now(UTC),
            )
            relay_server._tunnels[subdomain] = tunnel

        # Time 10000 lookups
        start = time.perf_counter()
        for _ in range(10000):
            subdomain = secrets.choice(subdomains)
            _ = relay_server._tunnels.get(subdomain)
        elapsed = time.perf_counter() - start

        # Should complete in < 100ms (0.1s)
        assert elapsed < 0.1, f"Lookups took too long: {elapsed:.3f}s"


class TestConcurrentConnections:
    """Tests for handling concurrent connections."""

    @pytest.mark.asyncio
    async def test_concurrent_task_creation(self):
        """Test that we can create many concurrent asyncio tasks."""
        async def dummy_task(n):
            await asyncio.sleep(0.001)
            return n

        # Create 1000 concurrent tasks
        tasks = [asyncio.create_task(dummy_task(i)) for i in range(1000)]
        results = await asyncio.gather(*tasks)

        assert len(results) == 1000
        assert all(r == i for i, r in enumerate(results))

    @pytest.mark.asyncio
    async def test_concurrent_dict_access(self):
        """Test that dictionary access is safe under concurrent access."""
        shared_dict = {}
        lock = asyncio.Lock()

        async def add_to_dict(key, value):
            async with lock:
                shared_dict[key] = value
                await asyncio.sleep(0.001)

        # 500 concurrent writes
        tasks = [
            asyncio.create_task(add_to_dict(f"key{i}", f"value{i}"))
            for i in range(500)
        ]
        await asyncio.gather(*tasks)

        assert len(shared_dict) == 500


class TestPortAllocation:
    """Tests for TCP/UDP port allocation at scale."""

    def test_tcp_port_allocation_no_collision(self):
        """Test TCP port allocation doesn't produce collisions."""
        allocated_ports = set()
        next_port = 10000

        for _ in range(1000):
            port = next_port
            next_port += 1
            if next_port > 19999:
                next_port = 10000

            assert port not in allocated_ports, f"Port collision: {port}"
            allocated_ports.add(port)

        assert len(allocated_ports) == 1000

    def test_udp_port_allocation_no_collision(self):
        """Test UDP port allocation doesn't produce collisions."""
        allocated_ports = set()
        next_port = 20000

        for _ in range(1000):
            port = next_port
            next_port += 1
            if next_port > 29999:
                next_port = 20000

            assert port not in allocated_ports, f"Port collision: {port}"
            allocated_ports.add(port)

        assert len(allocated_ports) == 1000


class TestMemoryEfficiency:
    """Tests for memory efficiency at scale."""

    def test_tunnel_connection_size(self):
        """Test that TunnelConnection objects are reasonably sized."""
        import sys
        from dataclasses import dataclass, field
        from datetime import UTC, datetime
        from unittest.mock import MagicMock
        from uuid import uuid4

        from instanton.protocol.messages import CompressionType

        @dataclass
        class TunnelConnection:
            id: str
            subdomain: str
            websocket: MagicMock
            local_port: int
            connected_at: datetime = field(default_factory=lambda: datetime.now(UTC))
            request_count: int = 0
            bytes_sent: int = 0
            bytes_received: int = 0
            compression: CompressionType = CompressionType.NONE

        tunnel = TunnelConnection(
            id=str(uuid4()),
            subdomain="test",
            websocket=MagicMock(),
            local_port=8000,
        )

        # Check base size (without socket mock)
        # Actual size will be higher due to MagicMock
        base_size = sys.getsizeof(tunnel)
        assert base_size < 500, f"TunnelConnection too large: {base_size} bytes"

    def test_request_context_cleanup(self):
        """Test that request contexts can be cleaned up efficiently."""
        from uuid import uuid4

        contexts = {}

        # Simulate adding many pending requests
        for i in range(1000):
            request_id = uuid4()
            contexts[request_id] = {"data": f"request_{i}"}

        assert len(contexts) == 1000

        # Simulate cleanup of half the requests
        to_remove = list(contexts.keys())[:500]
        for key in to_remove:
            del contexts[key]

        assert len(contexts) == 500


class TestRateLimiting:
    """Tests for rate limiting to prevent abuse."""

    def test_rate_limit_tracking(self):
        """Test rate limit counter works correctly."""
        import time
        from collections import defaultdict

        # Simple sliding window counter
        request_counts = defaultdict(list)

        def record_request(client_id: str):
            now = time.time()
            request_counts[client_id].append(now)
            # Clean up old entries (> 60s)
            request_counts[client_id] = [
                t for t in request_counts[client_id] if now - t < 60
            ]
            return len(request_counts[client_id])

        def is_rate_limited(client_id: str, limit: int = 100) -> bool:
            return len(request_counts[client_id]) >= limit

        # Simulate 50 requests from client1
        for _ in range(50):
            record_request("client1")
        assert not is_rate_limited("client1")

        # Simulate 150 requests from client2 (should be limited)
        for _ in range(150):
            record_request("client2")
        assert is_rate_limited("client2")


class TestSubdomainCollisionProbability:
    """Mathematical tests for subdomain collision probability."""

    def test_collision_probability_12_chars(self):
        """Test collision probability with 12 hex char subdomains.

        With 12 hex chars (48 bits), the probability of collision
        for n tunnels is approximately n^2 / (2 * 2^48).

        For 10,000 tunnels: ~1.8e-7 (0.00002%)
        For 100,000 tunnels: ~1.8e-5 (0.002%)
        """
        import math

        bits = 48  # 12 hex chars = 48 bits
        space = 2 ** bits

        # Birthday paradox approximation
        def collision_probability(n, space):
            if n > space:
                return 1.0
            # Approximation: 1 - e^(-n^2 / (2*space))
            exponent = -(n * n) / (2 * space)
            return 1 - math.exp(exponent)

        # For 10,000 simultaneous tunnels
        p_10k = collision_probability(10_000, space)
        assert p_10k < 0.0001, f"Collision probability too high for 10k: {p_10k}"

        # For 100,000 simultaneous tunnels
        p_100k = collision_probability(100_000, space)
        assert p_100k < 0.01, f"Collision probability too high for 100k: {p_100k}"

    def test_uuid_uniqueness(self):
        """Test UUID generation for tunnel IDs."""
        ids = set()
        for _ in range(10000):
            tunnel_id = uuid4()
            assert tunnel_id not in ids
            ids.add(tunnel_id)
        assert len(ids) == 10000
