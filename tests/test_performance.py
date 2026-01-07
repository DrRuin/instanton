"""Tests for performance optimization utilities."""

from unittest.mock import MagicMock

import pytest

from instanton.core.performance import (
    BufferPool,
    HTTPConnectionPool,
    LazyModule,
    MetricsCollector,
    ObjectPool,
    PerformanceMetrics,
    PooledBuffer,
    RingBuffer,
    SlidingWindowCounter,
    acquire_buffer,
    get_buffer_pool,
    install_fast_event_loop,
    lazy_import,
)

# ==============================================================================
# Buffer Pool Tests
# ==============================================================================


class TestPooledBuffer:
    """Tests for PooledBuffer."""

    def test_context_manager(self):
        """Test context manager usage."""
        pool = BufferPool()
        buffer = pool.acquire(1024)

        with buffer as data:
            assert isinstance(data, bytearray)
            assert len(data) >= 1024

        # Buffer should be released
        assert not buffer._in_use

    def test_view(self):
        """Test memoryview creation."""
        pool = BufferPool()
        buffer = pool.acquire(1024)

        view = buffer.view(0, 100)
        assert isinstance(view, memoryview)
        assert len(view) == 100

        buffer.release()

    def test_release(self):
        """Test manual release."""
        pool = BufferPool()
        buffer = pool.acquire(1024)

        assert buffer._in_use
        buffer.release()
        assert not buffer._in_use

        # Double release should be safe
        buffer.release()


class TestBufferPool:
    """Tests for BufferPool."""

    def test_default_initialization(self):
        """Test default pool initialization."""
        pool = BufferPool()
        assert pool.max_buffers_per_class == 100
        assert pool.default_size == 65536

    def test_acquire_returns_buffer(self):
        """Test acquiring a buffer."""
        pool = BufferPool()
        buffer = pool.acquire(1024)

        assert isinstance(buffer, PooledBuffer)
        assert buffer.size >= 1024
        assert buffer.pool is pool

    def test_acquire_size_classes(self):
        """Test that sizes are rounded to size classes."""
        pool = BufferPool()

        buffer_small = pool.acquire(100)
        assert buffer_small.size == 1024  # Smallest class

        buffer_medium = pool.acquire(5000)
        assert buffer_medium.size == 16384  # Next class up

        buffer_large = pool.acquire(100000)
        assert buffer_large.size == 262144

    def test_buffer_reuse(self):
        """Test that released buffers are reused."""
        pool = BufferPool()

        # Acquire and release
        buffer1 = pool.acquire(1024)
        buffer1.release()

        # Acquire again - should hit cache
        pool.acquire(1024)

        assert pool.stats["hits"] >= 1
        assert pool.stats["hit_rate"] > 0

    def test_stats(self):
        """Test pool statistics."""
        pool = BufferPool()

        buffer1 = pool.acquire(1024)
        buffer2 = pool.acquire(1024)

        stats = pool.stats
        assert stats["allocations"] == 2
        assert stats["misses"] == 2
        assert stats["releases"] == 0

        buffer1.release()
        buffer2.release()

        stats = pool.stats
        assert stats["releases"] == 2


class TestGlobalBufferPool:
    """Tests for global buffer pool functions."""

    def test_get_buffer_pool(self):
        """Test global pool singleton."""
        pool1 = get_buffer_pool()
        pool2 = get_buffer_pool()
        assert pool1 is pool2

    def test_acquire_buffer(self):
        """Test convenience function."""
        buffer = acquire_buffer(2048)
        assert buffer.size >= 2048
        buffer.release()


# ==============================================================================
# Object Pool Tests
# ==============================================================================


class TestObjectPool:
    """Tests for generic ObjectPool."""

    def test_factory_called(self):
        """Test that factory creates new objects."""
        factory = MagicMock(return_value={"value": 0})
        pool = ObjectPool(factory)

        obj = pool.acquire()
        assert obj == {"value": 0}
        factory.assert_called_once()

    def test_reset_called(self):
        """Test that reset is called on reuse."""

        def factory():
            return {"value": 0}

        reset = MagicMock()
        pool = ObjectPool(factory, reset=reset)

        obj1 = pool.acquire()
        pool.release(obj1)
        pool.acquire()

        reset.assert_called_once()

    def test_reuse(self):
        """Test object reuse."""
        def factory():
            return {"value": 0}
        pool = ObjectPool(factory)

        obj1 = pool.acquire()
        pool.release(obj1)
        obj2 = pool.acquire()

        assert obj1 is obj2  # Same object reused
        assert pool.stats["reused"] == 1

    def test_max_size(self):
        """Test pool max size."""
        pool = ObjectPool(lambda: {}, max_size=2)

        obj1 = pool.acquire()
        obj2 = pool.acquire()
        obj3 = pool.acquire()

        pool.release(obj1)
        pool.release(obj2)
        pool.release(obj3)

        # Only 2 should be kept
        assert len(pool._pool) == 2

    def test_stats(self):
        """Test pool statistics."""
        pool = ObjectPool(lambda: {})

        pool.acquire()
        pool.acquire()

        stats = pool.stats
        assert stats["created"] == 2
        assert stats["reused"] == 0


# ==============================================================================
# Memory-Efficient Data Structure Tests
# ==============================================================================


class TestSlidingWindowCounter:
    """Tests for SlidingWindowCounter."""

    def test_increment(self):
        """Test counter increment."""
        counter = SlidingWindowCounter(window_size=60.0, num_buckets=60)

        result = counter.increment(5)
        assert result == 5

        result = counter.increment(3)
        assert result == 8

    def test_count_property(self):
        """Test count property."""
        counter = SlidingWindowCounter()

        counter.increment(10)
        counter.increment(20)

        assert counter.count == 30


class TestRingBuffer:
    """Tests for RingBuffer."""

    def test_push_and_pop(self):
        """Test basic push and pop."""
        buffer: RingBuffer[int] = RingBuffer(3)

        buffer.push(1)
        buffer.push(2)
        buffer.push(3)

        assert len(buffer) == 3
        assert buffer.pop() == 1
        assert buffer.pop() == 2
        assert buffer.pop() == 3
        assert len(buffer) == 0

    def test_overflow(self):
        """Test that old items are evicted."""
        buffer: RingBuffer[int] = RingBuffer(3)

        buffer.push(1)
        buffer.push(2)
        buffer.push(3)
        evicted = buffer.push(4)  # Should evict 1

        assert evicted == 1
        assert len(buffer) == 3
        assert buffer.pop() == 2

    def test_bool(self):
        """Test boolean conversion."""
        buffer: RingBuffer[int] = RingBuffer(3)

        assert not buffer
        buffer.push(1)
        assert buffer


# ==============================================================================
# Metrics Collector Tests
# ==============================================================================


class TestMetricsCollector:
    """Tests for MetricsCollector."""

    def test_record_latency(self):
        """Test latency recording."""
        collector = MetricsCollector()

        collector.record_latency(5.0)
        collector.record_latency(10.0)
        collector.record_latency(15.0)

        metrics = collector.get_metrics()
        assert metrics.latency_p50 > 0

    def test_record_request(self):
        """Test request recording."""
        collector = MetricsCollector()

        collector.record_request(1000)
        collector.record_request(2000)

        metrics = collector.get_metrics()
        assert metrics.requests_per_second >= 0


class TestPerformanceMetrics:
    """Tests for PerformanceMetrics dataclass."""

    def test_default_values(self):
        """Test default metric values."""
        metrics = PerformanceMetrics()

        assert metrics.latency_p50 == 0.0
        assert metrics.latency_p95 == 0.0
        assert metrics.latency_p99 == 0.0
        assert metrics.throughput_bps == 0.0


# ==============================================================================
# Lazy Import Tests
# ==============================================================================


class TestLazyModule:
    """Tests for LazyModule."""

    def test_deferred_import(self):
        """Test that import is deferred."""
        lazy = LazyModule("json")
        assert lazy._module is None

        # Access triggers import
        dumps = lazy.dumps
        assert lazy._module is not None
        assert callable(dumps)

    def test_lazy_import_function(self):
        """Test lazy_import convenience function."""
        # Note: json may already be cached, so check if it's LazyModule or already loaded
        lazy = lazy_import("time")  # Use a module less likely to be cached
        assert isinstance(lazy, LazyModule) or hasattr(lazy, "_module_name")


# ==============================================================================
# Event Loop Tests
# ==============================================================================


class TestFastEventLoop:
    """Tests for fast event loop installation."""

    def test_install_fast_event_loop(self):
        """Test installing fast event loop."""
        # Just test that it doesn't crash
        # Actual behavior depends on platform
        result = install_fast_event_loop()
        assert isinstance(result, bool)


# ==============================================================================
# HTTP Connection Pool Tests
# ==============================================================================


class TestHTTPConnectionPool:
    """Tests for HTTPConnectionPool."""

    def test_initialization(self):
        """Test pool initialization."""
        pool = HTTPConnectionPool(
            max_connections=50,
            max_keepalive=10,
            keepalive_timeout=60.0,
        )

        assert pool.max_connections == 50
        assert pool.max_keepalive == 10
        assert pool.keepalive_timeout == 60.0

    @pytest.mark.asyncio
    async def test_start_and_close(self):
        """Test starting and closing pool."""
        pool = HTTPConnectionPool()

        await pool.start()
        assert hasattr(pool, "_client")

        await pool.close()

    @pytest.mark.asyncio
    async def test_stats(self):
        """Test pool statistics."""
        pool = HTTPConnectionPool()

        stats = pool.stats
        assert stats.active_connections == 0
        assert stats.idle_connections == 0
