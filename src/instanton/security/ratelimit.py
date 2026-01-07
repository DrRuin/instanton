"""Production-grade rate limiting for Instanton.

This module provides multiple rate limiting strategies:
- Token bucket rate limiter (async-safe)
- Sliding window rate limiter
- Per-IP, per-subdomain, and per-API-key rate limiting
- Adaptive rate limiting based on server load
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections import defaultdict
from dataclasses import dataclass
from enum import Enum
from typing import Any

from aiolimiter import AsyncLimiter
from cachetools import TTLCache

logger = logging.getLogger(__name__)


class RateLimitScope(Enum):
    """Scope for rate limiting."""

    GLOBAL = "global"
    IP = "ip"
    SUBDOMAIN = "subdomain"
    API_KEY = "api_key"
    PATH = "path"


@dataclass
class RateLimitResult:
    """Result of a rate limit check."""

    allowed: bool
    limit: int
    remaining: int
    reset_at: float
    retry_after: float | None = None
    scope: RateLimitScope = RateLimitScope.GLOBAL
    identifier: str = ""

    def to_headers(self) -> dict[str, str]:
        """Convert to HTTP rate limit headers."""
        headers = {
            "X-RateLimit-Limit": str(self.limit),
            "X-RateLimit-Remaining": str(max(0, self.remaining)),
            "X-RateLimit-Reset": str(int(self.reset_at)),
        }
        if self.retry_after is not None and self.retry_after > 0:
            headers["Retry-After"] = str(int(self.retry_after) + 1)
        return headers


class TokenBucketLimiter:
    """Async-safe token bucket rate limiter using aiolimiter.

    The token bucket algorithm allows bursting up to the bucket capacity,
    then limits to the sustained rate.
    """

    def __init__(
        self,
        rate: float,
        capacity: float,
        time_period: float = 1.0,
    ) -> None:
        """Initialize token bucket limiter.

        Args:
            rate: Number of tokens added per time_period
            capacity: Maximum bucket capacity (burst limit)
            time_period: Time period in seconds for rate calculation
        """
        self._rate = rate
        self._capacity = capacity
        self._time_period = time_period
        self._limiter = AsyncLimiter(rate, time_period)
        self._tokens = capacity
        self._last_update = time.monotonic()
        self._lock = asyncio.Lock()

    @property
    def rate(self) -> float:
        """Get the current rate limit."""
        return self._rate

    @property
    def capacity(self) -> float:
        """Get the bucket capacity."""
        return self._capacity

    async def acquire(self, tokens: float = 1.0) -> RateLimitResult:
        """Attempt to acquire tokens from the bucket.

        Args:
            tokens: Number of tokens to acquire

        Returns:
            RateLimitResult indicating if the request is allowed
        """
        async with self._lock:
            now = time.monotonic()
            elapsed = now - self._last_update
            self._last_update = now

            # Refill tokens based on elapsed time
            self._tokens = min(
                self._capacity, self._tokens + (elapsed * self._rate / self._time_period)
            )

            if self._tokens >= tokens:
                self._tokens -= tokens
                return RateLimitResult(
                    allowed=True,
                    limit=int(self._capacity),
                    remaining=int(self._tokens),
                    reset_at=now + self._time_period,
                )
            else:
                # Calculate when tokens will be available
                tokens_needed = tokens - self._tokens
                wait_time = tokens_needed * self._time_period / self._rate
                return RateLimitResult(
                    allowed=False,
                    limit=int(self._capacity),
                    remaining=0,
                    reset_at=now + wait_time,
                    retry_after=wait_time,
                )

    async def wait_for_token(self, tokens: float = 1.0) -> None:
        """Wait until tokens are available (blocking acquire).

        Args:
            tokens: Number of tokens to acquire
        """
        while True:
            result = await self.acquire(tokens)
            if result.allowed:
                return
            if result.retry_after:
                await asyncio.sleep(result.retry_after)

    def reset(self) -> None:
        """Reset the bucket to full capacity."""
        self._tokens = self._capacity
        self._last_update = time.monotonic()


class SlidingWindowLimiter:
    """Sliding window rate limiter.

    Provides smoother rate limiting than fixed windows by considering
    requests from the previous window proportionally.
    """

    def __init__(
        self,
        limit: int,
        window_size: float = 60.0,
        precision: int = 10,
    ) -> None:
        """Initialize sliding window limiter.

        Args:
            limit: Maximum requests per window
            window_size: Window size in seconds
            precision: Number of sub-windows for precision
        """
        self._limit = limit
        self._window_size = window_size
        self._precision = precision
        self._slot_size = window_size / precision
        self._counters: dict[int, int] = defaultdict(int)
        self._lock = asyncio.Lock()

    @property
    def limit(self) -> int:
        """Get the rate limit."""
        return self._limit

    @property
    def window_size(self) -> float:
        """Get the window size in seconds."""
        return self._window_size

    def _get_current_slot(self) -> int:
        """Get the current time slot index."""
        return int(time.monotonic() / self._slot_size)

    def _cleanup_old_slots(self, current_slot: int) -> None:
        """Remove slots outside the current window."""
        min_slot = current_slot - self._precision
        slots_to_remove = [slot for slot in self._counters if slot < min_slot]
        for slot in slots_to_remove:
            del self._counters[slot]

    async def acquire(self) -> RateLimitResult:
        """Attempt to acquire permission for a request.

        Returns:
            RateLimitResult indicating if the request is allowed
        """
        async with self._lock:
            now = time.monotonic()
            current_slot = self._get_current_slot()
            self._cleanup_old_slots(current_slot)

            # Calculate weighted count from current window
            total_count = 0
            window_start_slot = current_slot - self._precision + 1

            # Weight for previous window portion
            slot_progress = (now % self._slot_size) / self._slot_size
            prev_window_weight = 1 - slot_progress

            for slot, count in self._counters.items():
                if slot < window_start_slot:
                    # Previous window, apply weight
                    total_count += int(count * prev_window_weight)
                else:
                    total_count += count

            remaining = max(0, self._limit - total_count)
            reset_at = now + self._window_size

            if total_count < self._limit:
                self._counters[current_slot] += 1
                return RateLimitResult(
                    allowed=True,
                    limit=self._limit,
                    remaining=remaining - 1,
                    reset_at=reset_at,
                )
            else:
                # Calculate retry time
                retry_after = self._slot_size * (1 - slot_progress)
                return RateLimitResult(
                    allowed=False,
                    limit=self._limit,
                    remaining=0,
                    reset_at=reset_at,
                    retry_after=retry_after,
                )

    def reset(self) -> None:
        """Reset all counters."""
        self._counters.clear()


@dataclass
class LoadMetrics:
    """Server load metrics for adaptive rate limiting."""

    cpu_usage: float = 0.0  # 0.0 to 1.0
    memory_usage: float = 0.0  # 0.0 to 1.0
    active_connections: int = 0
    requests_per_second: float = 0.0
    latency_p99: float = 0.0  # in milliseconds
    error_rate: float = 0.0  # 0.0 to 1.0


class AdaptiveRateLimiter:
    """Adaptive rate limiter that adjusts limits based on server load.

    Automatically reduces rate limits when the server is under high load
    and increases them when load is low.
    """

    def __init__(
        self,
        base_limit: int,
        min_limit: int,
        max_limit: int,
        window_size: float = 60.0,
        adjustment_interval: float = 5.0,
        load_threshold_high: float = 0.8,
        load_threshold_low: float = 0.3,
    ) -> None:
        """Initialize adaptive rate limiter.

        Args:
            base_limit: Base rate limit when load is normal
            min_limit: Minimum rate limit under high load
            max_limit: Maximum rate limit under low load
            window_size: Window size in seconds
            adjustment_interval: How often to adjust limits (seconds)
            load_threshold_high: Load threshold to start reducing limits
            load_threshold_low: Load threshold to start increasing limits
        """
        self._base_limit = base_limit
        self._min_limit = min_limit
        self._max_limit = max_limit
        self._current_limit = base_limit
        self._window_size = window_size
        self._adjustment_interval = adjustment_interval
        self._load_threshold_high = load_threshold_high
        self._load_threshold_low = load_threshold_low
        self._limiter = SlidingWindowLimiter(base_limit, window_size)
        self._last_adjustment = time.monotonic()
        self._load_metrics = LoadMetrics()
        self._lock = asyncio.Lock()

    @property
    def current_limit(self) -> int:
        """Get the current effective rate limit."""
        return self._current_limit

    @property
    def load_metrics(self) -> LoadMetrics:
        """Get current load metrics."""
        return self._load_metrics

    def update_load_metrics(self, metrics: LoadMetrics) -> None:
        """Update server load metrics.

        Args:
            metrics: Current server load metrics
        """
        self._load_metrics = metrics

    def _calculate_load_factor(self) -> float:
        """Calculate overall load factor from metrics."""
        metrics = self._load_metrics

        # Weighted average of different load indicators
        weights = {
            "cpu": 0.3,
            "memory": 0.2,
            "connections": 0.2,
            "latency": 0.15,
            "errors": 0.15,
        }

        # Normalize connection count (assume 10000 is max)
        connection_factor = min(1.0, metrics.active_connections / 10000)

        # Normalize latency (assume 1000ms is max acceptable)
        latency_factor = min(1.0, metrics.latency_p99 / 1000)

        load_factor = (
            weights["cpu"] * metrics.cpu_usage
            + weights["memory"] * metrics.memory_usage
            + weights["connections"] * connection_factor
            + weights["latency"] * latency_factor
            + weights["errors"] * metrics.error_rate
        )

        return min(1.0, max(0.0, load_factor))

    async def _maybe_adjust_limit(self) -> None:
        """Adjust the rate limit based on current load."""
        now = time.monotonic()
        if now - self._last_adjustment < self._adjustment_interval:
            return

        self._last_adjustment = now
        load_factor = self._calculate_load_factor()

        if load_factor >= self._load_threshold_high:
            # High load - reduce limit
            reduction = (load_factor - self._load_threshold_high) / (1 - self._load_threshold_high)
            new_limit = int(self._base_limit - (self._base_limit - self._min_limit) * reduction)
        elif load_factor <= self._load_threshold_low:
            # Low load - increase limit
            increase = (self._load_threshold_low - load_factor) / self._load_threshold_low
            new_limit = int(self._base_limit + (self._max_limit - self._base_limit) * increase)
        else:
            # Normal load - use base limit
            new_limit = self._base_limit

        new_limit = max(self._min_limit, min(self._max_limit, new_limit))

        if new_limit != self._current_limit:
            logger.info(
                "Adaptive rate limit adjustment: %d -> %d (load_factor=%.2f)",
                self._current_limit,
                new_limit,
                load_factor,
            )
            self._current_limit = new_limit
            self._limiter = SlidingWindowLimiter(new_limit, self._window_size)

    async def acquire(self) -> RateLimitResult:
        """Attempt to acquire permission for a request.

        Returns:
            RateLimitResult indicating if the request is allowed
        """
        async with self._lock:
            await self._maybe_adjust_limit()

        return await self._limiter.acquire()


class RateLimitManager:
    """Manages rate limiting across multiple scopes.

    Provides per-IP, per-subdomain, and per-API-key rate limiting
    with configurable limits for each scope.
    """

    def __init__(
        self,
        global_limit: int = 10000,
        per_ip_limit: int = 100,
        per_subdomain_limit: int = 1000,
        per_api_key_limit: int = 500,
        window_size: float = 60.0,
        cache_ttl: float = 300.0,
        cache_max_size: int = 10000,
        enable_adaptive: bool = True,
    ) -> None:
        """Initialize rate limit manager.

        Args:
            global_limit: Global rate limit for all requests
            per_ip_limit: Rate limit per IP address
            per_subdomain_limit: Rate limit per subdomain
            per_api_key_limit: Rate limit per API key
            window_size: Window size in seconds
            cache_ttl: TTL for limiter cache entries
            cache_max_size: Maximum number of cached limiters
            enable_adaptive: Enable adaptive rate limiting
        """
        self._global_limit = global_limit
        self._per_ip_limit = per_ip_limit
        self._per_subdomain_limit = per_subdomain_limit
        self._per_api_key_limit = per_api_key_limit
        self._window_size = window_size
        self._cache_ttl = cache_ttl

        # Global limiter
        self._global_limiter: AdaptiveRateLimiter | SlidingWindowLimiter
        if enable_adaptive:
            self._global_limiter = AdaptiveRateLimiter(
                base_limit=global_limit,
                min_limit=global_limit // 4,
                max_limit=global_limit * 2,
                window_size=window_size,
            )
        else:
            self._global_limiter = SlidingWindowLimiter(global_limit, window_size)

        # Per-scope limiters with TTL cache
        self._ip_limiters: TTLCache = TTLCache(
            maxsize=cache_max_size,
            ttl=cache_ttl,
        )
        self._subdomain_limiters: TTLCache = TTLCache(
            maxsize=cache_max_size // 10,
            ttl=cache_ttl,
        )
        self._api_key_limiters: TTLCache = TTLCache(
            maxsize=cache_max_size // 10,
            ttl=cache_ttl,
        )

        self._lock = asyncio.Lock()

    def _get_or_create_limiter(
        self,
        cache: TTLCache,
        key: str,
        limit: int,
    ) -> SlidingWindowLimiter:
        """Get or create a limiter for a specific key."""
        if key not in cache:
            cache[key] = SlidingWindowLimiter(limit, self._window_size)
        return cache[key]

    def update_load_metrics(self, metrics: LoadMetrics) -> None:
        """Update load metrics for adaptive rate limiting."""
        if isinstance(self._global_limiter, AdaptiveRateLimiter):
            self._global_limiter.update_load_metrics(metrics)

    async def check_rate_limit(
        self,
        ip_address: str | None = None,
        subdomain: str | None = None,
        api_key: str | None = None,
    ) -> RateLimitResult:
        """Check rate limits for a request.

        Checks all applicable rate limits and returns the most restrictive result.

        Args:
            ip_address: Client IP address
            subdomain: Subdomain being accessed
            api_key: API key if provided

        Returns:
            RateLimitResult with the most restrictive limit
        """
        results: list[RateLimitResult] = []

        async with self._lock:
            # Check global limit
            global_result = await self._global_limiter.acquire()
            global_result.scope = RateLimitScope.GLOBAL
            global_result.identifier = "global"
            results.append(global_result)

            if not global_result.allowed:
                return global_result

            # Check per-IP limit
            if ip_address:
                ip_limiter = self._get_or_create_limiter(
                    self._ip_limiters, ip_address, self._per_ip_limit
                )
                ip_result = await ip_limiter.acquire()
                ip_result.scope = RateLimitScope.IP
                ip_result.identifier = ip_address
                results.append(ip_result)

                if not ip_result.allowed:
                    return ip_result

            # Check per-subdomain limit
            if subdomain:
                subdomain_limiter = self._get_or_create_limiter(
                    self._subdomain_limiters, subdomain, self._per_subdomain_limit
                )
                subdomain_result = await subdomain_limiter.acquire()
                subdomain_result.scope = RateLimitScope.SUBDOMAIN
                subdomain_result.identifier = subdomain
                results.append(subdomain_result)

                if not subdomain_result.allowed:
                    return subdomain_result

            # Check per-API-key limit
            if api_key:
                api_key_limiter = self._get_or_create_limiter(
                    self._api_key_limiters, api_key, self._per_api_key_limit
                )
                api_key_result = await api_key_limiter.acquire()
                api_key_result.scope = RateLimitScope.API_KEY
                api_key_result.identifier = api_key[:8] + "..."  # Truncate for privacy
                results.append(api_key_result)

                if not api_key_result.allowed:
                    return api_key_result

        # Return the result with lowest remaining quota
        return min(results, key=lambda r: r.remaining)

    def get_limiter_stats(self) -> dict[str, Any]:
        """Get statistics about current limiters."""
        return {
            "ip_limiters_count": len(self._ip_limiters),
            "subdomain_limiters_count": len(self._subdomain_limiters),
            "api_key_limiters_count": len(self._api_key_limiters),
            "global_limit": self._global_limit,
            "per_ip_limit": self._per_ip_limit,
            "per_subdomain_limit": self._per_subdomain_limit,
            "per_api_key_limit": self._per_api_key_limit,
        }

    def clear_ip_limiter(self, ip_address: str) -> bool:
        """Clear rate limiter for a specific IP.

        Args:
            ip_address: IP address to clear

        Returns:
            True if limiter was found and cleared
        """
        if ip_address in self._ip_limiters:
            del self._ip_limiters[ip_address]
            return True
        return False

    def clear_all_limiters(self) -> None:
        """Clear all rate limiters."""
        self._ip_limiters.clear()
        self._subdomain_limiters.clear()
        self._api_key_limiters.clear()


@dataclass
class RateLimitConfig:
    """Configuration for rate limiting."""

    enabled: bool = True
    global_limit: int = 10000
    per_ip_limit: int = 100
    per_subdomain_limit: int = 1000
    per_api_key_limit: int = 500
    window_size: float = 60.0
    cache_ttl: float = 300.0
    cache_max_size: int = 10000
    enable_adaptive: bool = True
    adaptive_min_limit_factor: float = 0.25
    adaptive_max_limit_factor: float = 2.0
    adaptive_load_threshold_high: float = 0.8
    adaptive_load_threshold_low: float = 0.3

    def create_manager(self) -> RateLimitManager:
        """Create a RateLimitManager from this configuration."""
        return RateLimitManager(
            global_limit=self.global_limit,
            per_ip_limit=self.per_ip_limit,
            per_subdomain_limit=self.per_subdomain_limit,
            per_api_key_limit=self.per_api_key_limit,
            window_size=self.window_size,
            cache_ttl=self.cache_ttl,
            cache_max_size=self.cache_max_size,
            enable_adaptive=self.enable_adaptive,
        )
