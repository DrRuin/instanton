"""Tests for rate limiting module."""

from __future__ import annotations

import asyncio
from time import monotonic

import pytest

from instanton.security.ratelimit import (
    RateLimitConfig,
    RateLimiter,
    RateLimitResult,
    SlidingWindowCounter,
    create_rate_limiter,
)


class TestSlidingWindowCounter:
    """Tests for SlidingWindowCounter."""

    def test_basic_allow(self):
        """Test basic allow functionality."""
        counter = SlidingWindowCounter(limit=10, window_seconds=1.0)
        allowed, remaining, reset_after = counter.allow()
        assert allowed is True
        assert remaining == 9

    def test_exceeds_limit(self):
        """Test that requests are denied after limit exceeded."""
        counter = SlidingWindowCounter(limit=3, window_seconds=1.0)

        for _ in range(3):
            allowed, _, _ = counter.allow()
            assert allowed is True

        allowed, remaining, _ = counter.allow()
        assert allowed is False
        assert remaining == 0

    def test_window_rotation(self):
        """Test that counters rotate after window expires."""
        counter = SlidingWindowCounter(limit=3, window_seconds=0.1)

        for _ in range(3):
            counter.allow()

        allowed, _, _ = counter.allow()
        assert allowed is False

        import time

        time.sleep(0.15)

        allowed, _, _ = counter.allow()
        assert allowed is True

    def test_peek_doesnt_increment(self):
        """Test that peek doesn't affect counter."""
        counter = SlidingWindowCounter(limit=3, window_seconds=1.0)

        remaining1, _ = counter.peek()
        remaining2, _ = counter.peek()

        assert remaining1 == remaining2 == 3

    def test_sliding_window_interpolation(self):
        """Test that sliding window interpolates correctly after full window passes."""
        import time

        counter = SlidingWindowCounter(limit=10, window_seconds=0.1)

        for _ in range(10):
            counter.allow()

        allowed, _, _ = counter.allow()
        assert allowed is False

        time.sleep(0.25)

        remaining, _ = counter.peek()
        assert remaining == 10


class TestRateLimiter:
    """Tests for RateLimiter."""

    @pytest.mark.asyncio
    async def test_basic_allow(self):
        """Test basic rate limiter allow."""
        limiter = create_rate_limiter(requests_per_second=10.0)
        result = await limiter.allow("192.168.1.1")
        assert result.allowed is True
        assert result.remaining >= 0

    @pytest.mark.asyncio
    async def test_different_keys_independent(self):
        """Test that different keys have independent limits."""
        limiter = create_rate_limiter(requests_per_second=2.0, burst_size=2)

        await limiter.allow("key1")
        await limiter.allow("key1")
        result1 = await limiter.allow("key1")

        result2 = await limiter.allow("key2")

        assert result1.allowed is False
        assert result2.allowed is True

    @pytest.mark.asyncio
    async def test_rate_limit_result_fields(self):
        """Test RateLimitResult has correct fields."""
        limiter = create_rate_limiter(requests_per_second=100.0)
        result = await limiter.allow("test-ip")

        assert isinstance(result, RateLimitResult)
        assert isinstance(result.allowed, bool)
        assert isinstance(result.remaining, int)
        assert isinstance(result.reset_after, float)
        assert isinstance(result.limit, int)

    @pytest.mark.asyncio
    async def test_check_without_increment(self):
        """Test check doesn't increment counter."""
        limiter = create_rate_limiter(requests_per_second=2.0, burst_size=2)

        result1 = await limiter.check("test-key")
        result2 = await limiter.check("test-key")

        assert result1.remaining == result2.remaining

    @pytest.mark.asyncio
    async def test_reset_key(self):
        """Test reset clears counter for key."""
        limiter = create_rate_limiter(requests_per_second=2.0, burst_size=2)

        await limiter.allow("test-key")
        await limiter.allow("test-key")
        result1 = await limiter.allow("test-key")
        assert result1.allowed is False

        await limiter.reset("test-key")

        result2 = await limiter.allow("test-key")
        assert result2.allowed is True

    @pytest.mark.asyncio
    async def test_reset_all(self):
        """Test reset with no key clears all."""
        limiter = create_rate_limiter(requests_per_second=10.0)

        await limiter.allow("key1")
        await limiter.allow("key2")
        assert limiter.entry_count > 0

        await limiter.reset()

        assert limiter.entry_count == 0

    @pytest.mark.asyncio
    async def test_lru_eviction(self):
        """Test LRU eviction when max_entries exceeded."""
        limiter = create_rate_limiter(
            requests_per_second=100.0,
            max_entries=3,
        )

        for i in range(5):
            await limiter.allow(f"key{i}")

        assert limiter.entry_count <= 3

    @pytest.mark.asyncio
    async def test_concurrent_requests(self):
        """Test rate limiter handles concurrent requests."""
        limiter = create_rate_limiter(requests_per_second=100.0)

        async def make_request(key: str):
            return await limiter.allow(key)

        results = await asyncio.gather(
            *[make_request("concurrent-key") for _ in range(10)]
        )

        assert len(results) == 10
        assert all(isinstance(r, RateLimitResult) for r in results)

    @pytest.mark.asyncio
    async def test_scope_parameter(self):
        """Test different scopes have independent limits."""
        limiter = create_rate_limiter(requests_per_second=2.0, burst_size=2)

        await limiter.allow("test", scope="ip")
        await limiter.allow("test", scope="ip")
        result_ip = await limiter.allow("test", scope="ip")

        result_subdomain = await limiter.allow("test", scope="subdomain")

        assert result_ip.allowed is False
        assert result_subdomain.allowed is True


class TestCreateRateLimiter:
    """Tests for create_rate_limiter factory."""

    def test_creates_with_defaults(self):
        """Test create_rate_limiter with default values."""
        limiter = create_rate_limiter()
        assert limiter.config.requests_per_second == 100.0
        assert limiter.config.burst_size == 10

    def test_creates_with_custom_values(self):
        """Test create_rate_limiter with custom values."""
        limiter = create_rate_limiter(
            requests_per_second=50.0,
            burst_size=5,
            window_seconds=2.0,
            max_entries=5000,
        )
        assert limiter.config.requests_per_second == 50.0
        assert limiter.config.burst_size == 5
        assert limiter.config.window_seconds == 2.0
        assert limiter.config.max_entries == 5000


class TestRateLimitConfig:
    """Tests for RateLimitConfig."""

    def test_default_values(self):
        """Test RateLimitConfig default values."""
        config = RateLimitConfig()
        assert config.requests_per_second == 100.0
        assert config.burst_size == 10
        assert config.window_seconds == 1.0
        assert config.max_entries == 10000

    def test_custom_values(self):
        """Test RateLimitConfig with custom values."""
        config = RateLimitConfig(
            requests_per_second=200.0,
            burst_size=20,
            window_seconds=5.0,
            max_entries=20000,
        )
        assert config.requests_per_second == 200.0
        assert config.burst_size == 20
        assert config.window_seconds == 5.0
        assert config.max_entries == 20000
