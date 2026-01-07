"""Tests for rate limiting functionality."""

import asyncio
import time

import pytest

from instanton.security.ratelimit import (
    AdaptiveRateLimiter,
    LoadMetrics,
    RateLimitConfig,
    RateLimitManager,
    RateLimitResult,
    RateLimitScope,
    SlidingWindowLimiter,
    TokenBucketLimiter,
)


class TestTokenBucketLimiter:
    """Tests for TokenBucketLimiter."""

    @pytest.mark.asyncio
    async def test_basic_acquire(self) -> None:
        """Test basic token acquisition."""
        limiter = TokenBucketLimiter(rate=10, capacity=10, time_period=1.0)

        result = await limiter.acquire()
        assert result.allowed is True
        assert result.limit == 10
        assert result.remaining == 9

    @pytest.mark.asyncio
    async def test_burst_capacity(self) -> None:
        """Test that burst capacity is respected."""
        limiter = TokenBucketLimiter(rate=10, capacity=5, time_period=1.0)

        # Should allow up to capacity
        for i in range(5):
            result = await limiter.acquire()
            assert result.allowed is True, f"Request {i+1} should be allowed"

        # 6th request should be denied
        result = await limiter.acquire()
        assert result.allowed is False
        assert result.retry_after is not None
        assert result.retry_after > 0

    @pytest.mark.asyncio
    async def test_token_refill(self) -> None:
        """Test that tokens refill over time."""
        limiter = TokenBucketLimiter(rate=10, capacity=10, time_period=1.0)

        # Exhaust all tokens
        for _ in range(10):
            await limiter.acquire()

        # Should be denied
        result = await limiter.acquire()
        assert result.allowed is False

        # Wait for refill (0.2 seconds should add 2 tokens)
        await asyncio.sleep(0.2)

        # Should have 2 tokens now
        result = await limiter.acquire()
        assert result.allowed is True

    @pytest.mark.asyncio
    async def test_multi_token_acquire(self) -> None:
        """Test acquiring multiple tokens at once."""
        limiter = TokenBucketLimiter(rate=10, capacity=10, time_period=1.0)

        # Acquire 5 tokens
        result = await limiter.acquire(tokens=5)
        assert result.allowed is True
        assert result.remaining == 5

        # Acquire 5 more
        result = await limiter.acquire(tokens=5)
        assert result.allowed is True
        assert result.remaining == 0

        # Should be denied now
        result = await limiter.acquire()
        assert result.allowed is False

    @pytest.mark.asyncio
    async def test_reset(self) -> None:
        """Test resetting the bucket."""
        limiter = TokenBucketLimiter(rate=10, capacity=10, time_period=1.0)

        # Exhaust tokens
        for _ in range(10):
            await limiter.acquire()

        # Reset
        limiter.reset()

        # Should be back to full capacity
        result = await limiter.acquire()
        assert result.allowed is True
        assert result.remaining == 9

    @pytest.mark.asyncio
    async def test_result_headers(self) -> None:
        """Test that rate limit headers are properly generated."""
        limiter = TokenBucketLimiter(rate=100, capacity=100, time_period=60.0)

        result = await limiter.acquire()
        headers = result.to_headers()

        assert "X-RateLimit-Limit" in headers
        assert headers["X-RateLimit-Limit"] == "100"
        assert "X-RateLimit-Remaining" in headers
        assert "X-RateLimit-Reset" in headers


class TestSlidingWindowLimiter:
    """Tests for SlidingWindowLimiter."""

    @pytest.mark.asyncio
    async def test_basic_acquire(self) -> None:
        """Test basic request acquisition."""
        limiter = SlidingWindowLimiter(limit=10, window_size=60.0)

        result = await limiter.acquire()
        assert result.allowed is True
        assert result.limit == 10

    @pytest.mark.asyncio
    async def test_limit_enforcement(self) -> None:
        """Test that the limit is enforced."""
        limiter = SlidingWindowLimiter(limit=5, window_size=60.0)

        # Should allow up to limit
        for i in range(5):
            result = await limiter.acquire()
            assert result.allowed is True, f"Request {i+1} should be allowed"

        # 6th request should be denied
        result = await limiter.acquire()
        assert result.allowed is False
        assert result.remaining == 0

    @pytest.mark.asyncio
    async def test_window_reset(self) -> None:
        """Test that the window resets properly."""
        # Use a very short window for testing
        limiter = SlidingWindowLimiter(limit=2, window_size=0.1, precision=2)

        # Use up the limit
        await limiter.acquire()
        await limiter.acquire()

        # Should be denied
        result = await limiter.acquire()
        assert result.allowed is False

        # Wait for window to pass
        await asyncio.sleep(0.15)

        # Should be allowed again
        result = await limiter.acquire()
        assert result.allowed is True

    @pytest.mark.asyncio
    async def test_reset_method(self) -> None:
        """Test the reset method."""
        limiter = SlidingWindowLimiter(limit=2, window_size=60.0)

        # Use up the limit
        await limiter.acquire()
        await limiter.acquire()

        # Reset
        limiter.reset()

        # Should be allowed again
        result = await limiter.acquire()
        assert result.allowed is True


class TestAdaptiveRateLimiter:
    """Tests for AdaptiveRateLimiter."""

    @pytest.mark.asyncio
    async def test_basic_acquire(self) -> None:
        """Test basic request acquisition."""
        limiter = AdaptiveRateLimiter(
            base_limit=100,
            min_limit=25,
            max_limit=200,
            window_size=60.0,
        )

        result = await limiter.acquire()
        assert result.allowed is True

    @pytest.mark.asyncio
    async def test_load_adjustment_high(self) -> None:
        """Test that limits decrease under high load."""
        limiter = AdaptiveRateLimiter(
            base_limit=100,
            min_limit=25,
            max_limit=200,
            window_size=60.0,
            adjustment_interval=0.1,
            load_threshold_high=0.8,
        )

        initial_limit = limiter.current_limit
        assert initial_limit == 100

        # Simulate high load (load_factor needs to be > 0.8)
        # With weights: cpu=0.3, mem=0.2, conn=0.2, lat=0.15, err=0.15
        # load = 0.3*1.0 + 0.2*1.0 + 0.2*1.0 + 0.15*1.0 + 0.15*0.5 = 0.925
        limiter.update_load_metrics(LoadMetrics(
            cpu_usage=1.0,
            memory_usage=1.0,
            active_connections=10000,
            latency_p99=1000,
            error_rate=0.5,
        ))

        # Wait for adjustment
        await asyncio.sleep(0.15)
        await limiter.acquire()

        # Limit should have decreased
        assert limiter.current_limit < initial_limit

    @pytest.mark.asyncio
    async def test_load_adjustment_low(self) -> None:
        """Test that limits increase under low load."""
        limiter = AdaptiveRateLimiter(
            base_limit=100,
            min_limit=25,
            max_limit=200,
            window_size=60.0,
            adjustment_interval=0.1,
            load_threshold_low=0.3,
        )

        initial_limit = limiter.current_limit
        assert initial_limit == 100

        # Simulate low load
        limiter.update_load_metrics(LoadMetrics(
            cpu_usage=0.1,
            memory_usage=0.1,
            active_connections=100,
            latency_p99=10,
            error_rate=0.0,
        ))

        # Wait for adjustment
        await asyncio.sleep(0.15)
        await limiter.acquire()

        # Limit should have increased
        assert limiter.current_limit > initial_limit

    @pytest.mark.asyncio
    async def test_limit_bounds(self) -> None:
        """Test that limits stay within bounds."""
        limiter = AdaptiveRateLimiter(
            base_limit=100,
            min_limit=50,
            max_limit=150,
            window_size=60.0,
            adjustment_interval=0.05,
        )

        # Extreme high load
        limiter.update_load_metrics(LoadMetrics(
            cpu_usage=1.0,
            memory_usage=1.0,
            active_connections=10000,
            latency_p99=1000,
            error_rate=0.5,
        ))

        await asyncio.sleep(0.1)
        await limiter.acquire()

        # Should not go below min_limit
        assert limiter.current_limit >= 50


class TestRateLimitManager:
    """Tests for RateLimitManager."""

    @pytest.mark.asyncio
    async def test_basic_check(self) -> None:
        """Test basic rate limit check."""
        manager = RateLimitManager(
            global_limit=100,
            per_ip_limit=10,
            per_subdomain_limit=50,
            window_size=60.0,
            enable_adaptive=False,
        )

        result = await manager.check_rate_limit(ip_address="192.168.1.1")
        assert result.allowed is True

    @pytest.mark.asyncio
    async def test_per_ip_limiting(self) -> None:
        """Test per-IP rate limiting."""
        manager = RateLimitManager(
            global_limit=1000,
            per_ip_limit=5,
            window_size=60.0,
            enable_adaptive=False,
        )

        # Should allow 5 requests from same IP
        for i in range(5):
            result = await manager.check_rate_limit(ip_address="192.168.1.1")
            assert result.allowed is True, f"Request {i+1} should be allowed"

        # 6th request should be denied
        result = await manager.check_rate_limit(ip_address="192.168.1.1")
        assert result.allowed is False
        assert result.scope == RateLimitScope.IP

        # Different IP should still be allowed
        result = await manager.check_rate_limit(ip_address="192.168.1.2")
        assert result.allowed is True

    @pytest.mark.asyncio
    async def test_per_subdomain_limiting(self) -> None:
        """Test per-subdomain rate limiting."""
        manager = RateLimitManager(
            global_limit=1000,
            per_ip_limit=100,
            per_subdomain_limit=3,
            window_size=60.0,
            enable_adaptive=False,
        )

        # Should allow 3 requests to same subdomain (from different IPs)
        for i in range(3):
            result = await manager.check_rate_limit(
                ip_address=f"192.168.1.{i+1}",
                subdomain="test",
            )
            assert result.allowed is True, f"Request {i+1} should be allowed"

        # 4th request should be denied
        result = await manager.check_rate_limit(
            ip_address="192.168.1.100",
            subdomain="test",
        )
        assert result.allowed is False
        assert result.scope == RateLimitScope.SUBDOMAIN

    @pytest.mark.asyncio
    async def test_per_api_key_limiting(self) -> None:
        """Test per-API-key rate limiting."""
        manager = RateLimitManager(
            global_limit=1000,
            per_ip_limit=100,
            per_subdomain_limit=100,
            per_api_key_limit=3,
            window_size=60.0,
            enable_adaptive=False,
        )

        api_key = "test-api-key-12345"

        # Should allow 3 requests with same API key
        for i in range(3):
            result = await manager.check_rate_limit(
                ip_address=f"192.168.1.{i+1}",
                api_key=api_key,
            )
            assert result.allowed is True, f"Request {i+1} should be allowed"

        # 4th request should be denied
        result = await manager.check_rate_limit(
            ip_address="192.168.1.100",
            api_key=api_key,
        )
        assert result.allowed is False
        assert result.scope == RateLimitScope.API_KEY

    @pytest.mark.asyncio
    async def test_global_limiting(self) -> None:
        """Test global rate limiting."""
        manager = RateLimitManager(
            global_limit=5,
            per_ip_limit=100,
            window_size=60.0,
            enable_adaptive=False,
        )

        # Should allow up to global limit
        for i in range(5):
            result = await manager.check_rate_limit(ip_address=f"192.168.1.{i+1}")
            assert result.allowed is True, f"Request {i+1} should be allowed"

        # Global limit exceeded
        result = await manager.check_rate_limit(ip_address="192.168.1.100")
        assert result.allowed is False
        assert result.scope == RateLimitScope.GLOBAL

    @pytest.mark.asyncio
    async def test_clear_ip_limiter(self) -> None:
        """Test clearing a specific IP's rate limiter."""
        manager = RateLimitManager(
            global_limit=1000,
            per_ip_limit=2,
            window_size=60.0,
            enable_adaptive=False,
        )

        ip = "192.168.1.1"

        # Use up the limit
        await manager.check_rate_limit(ip_address=ip)
        await manager.check_rate_limit(ip_address=ip)

        # Should be denied
        result = await manager.check_rate_limit(ip_address=ip)
        assert result.allowed is False

        # Clear the limiter
        cleared = manager.clear_ip_limiter(ip)
        assert cleared is True

        # Should be allowed again
        result = await manager.check_rate_limit(ip_address=ip)
        assert result.allowed is True

    @pytest.mark.asyncio
    async def test_stats(self) -> None:
        """Test getting limiter statistics."""
        manager = RateLimitManager(
            global_limit=100,
            per_ip_limit=10,
            window_size=60.0,
            enable_adaptive=False,
        )

        # Make some requests
        await manager.check_rate_limit(ip_address="192.168.1.1")
        await manager.check_rate_limit(ip_address="192.168.1.2")

        stats = manager.get_limiter_stats()
        assert "ip_limiters_count" in stats
        assert stats["ip_limiters_count"] == 2
        assert stats["global_limit"] == 100
        assert stats["per_ip_limit"] == 10


class TestRateLimitConfig:
    """Tests for RateLimitConfig."""

    def test_default_values(self) -> None:
        """Test default configuration values."""
        config = RateLimitConfig()

        assert config.enabled is True
        assert config.global_limit == 10000
        assert config.per_ip_limit == 100
        assert config.per_subdomain_limit == 1000
        assert config.per_api_key_limit == 500
        assert config.window_size == 60.0
        assert config.enable_adaptive is True

    def test_create_manager(self) -> None:
        """Test creating a manager from config."""
        config = RateLimitConfig(
            global_limit=500,
            per_ip_limit=50,
            enable_adaptive=False,
        )

        manager = config.create_manager()

        assert isinstance(manager, RateLimitManager)
        stats = manager.get_limiter_stats()
        assert stats["global_limit"] == 500
        assert stats["per_ip_limit"] == 50


class TestConcurrency:
    """Tests for concurrent access."""

    @pytest.mark.asyncio
    async def test_concurrent_acquire(self) -> None:
        """Test concurrent token bucket access."""
        limiter = TokenBucketLimiter(rate=100, capacity=100, time_period=1.0)

        async def acquire_task() -> RateLimitResult:
            return await limiter.acquire()

        # Run 50 concurrent acquisitions
        results = await asyncio.gather(*[acquire_task() for _ in range(50)])

        # All should succeed
        assert all(r.allowed for r in results)

        # Remaining should be correct
        final_result = await limiter.acquire()
        assert final_result.remaining == 49

    @pytest.mark.asyncio
    async def test_concurrent_manager_check(self) -> None:
        """Test concurrent rate limit manager checks."""
        manager = RateLimitManager(
            global_limit=100,
            per_ip_limit=50,
            window_size=60.0,
            enable_adaptive=False,
        )

        async def check_task(ip: str) -> RateLimitResult:
            return await manager.check_rate_limit(ip_address=ip)

        # Run concurrent checks from same IP
        results = await asyncio.gather(*[
            check_task("192.168.1.1") for _ in range(30)
        ])

        # All should succeed (within limit)
        assert all(r.allowed for r in results)


class TestRateLimitResult:
    """Tests for RateLimitResult."""

    def test_to_headers_allowed(self) -> None:
        """Test header generation for allowed request."""
        result = RateLimitResult(
            allowed=True,
            limit=100,
            remaining=50,
            reset_at=time.time() + 60,
        )

        headers = result.to_headers()

        assert headers["X-RateLimit-Limit"] == "100"
        assert headers["X-RateLimit-Remaining"] == "50"
        assert "X-RateLimit-Reset" in headers
        assert "Retry-After" not in headers

    def test_to_headers_denied(self) -> None:
        """Test header generation for denied request."""
        result = RateLimitResult(
            allowed=False,
            limit=100,
            remaining=0,
            reset_at=time.time() + 60,
            retry_after=30.5,
        )

        headers = result.to_headers()

        assert headers["X-RateLimit-Limit"] == "100"
        assert headers["X-RateLimit-Remaining"] == "0"
        assert "Retry-After" in headers
        assert int(headers["Retry-After"]) >= 31

    def test_negative_remaining_clamped(self) -> None:
        """Test that negative remaining is clamped to 0."""
        result = RateLimitResult(
            allowed=False,
            limit=100,
            remaining=-5,
            reset_at=time.time(),
        )

        headers = result.to_headers()
        assert headers["X-RateLimit-Remaining"] == "0"
