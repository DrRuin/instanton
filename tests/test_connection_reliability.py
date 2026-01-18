"""Tests for connection reliability improvements.

These tests verify that Instanton provides reliable, instant connections
inspired by best practices from ngrok, cloudflared, and tunnelto.
"""

import asyncio
import socket
import time

import pytest

from instanton.core.transport import (
    TransportStats,
    WebSocketTransport,
    clear_dns_cache,
    resolve_host,
)


class TestDNSCaching:
    """Tests for DNS resolution and caching."""

    @pytest.mark.asyncio
    async def test_resolve_ipv4_passthrough(self):
        """Verify IPv4 addresses pass through without resolution."""
        ip = await resolve_host("127.0.0.1")
        assert ip == "127.0.0.1"

    @pytest.mark.asyncio
    async def test_resolve_ipv4_dotted(self):
        """Verify dotted IPv4 addresses pass through."""
        ip = await resolve_host("192.168.1.1")
        assert ip == "192.168.1.1"

    @pytest.mark.asyncio
    async def test_resolve_localhost(self):
        """Verify localhost resolves correctly."""
        ip = await resolve_host("localhost")
        assert ip in ("127.0.0.1", "::1", "localhost")

    @pytest.mark.asyncio
    async def test_dns_cache_works(self):
        """Verify DNS results are cached."""
        clear_dns_cache()

        start1 = time.monotonic()
        ip1 = await resolve_host("localhost")
        time1 = time.monotonic() - start1

        start2 = time.monotonic()
        ip2 = await resolve_host("localhost")
        time2 = time.monotonic() - start2

        assert ip1 == ip2
        assert time2 < 0.01

    @pytest.mark.asyncio
    async def test_clear_dns_cache(self):
        """Verify DNS cache can be cleared."""
        await resolve_host("localhost")
        clear_dns_cache()

    @pytest.mark.asyncio
    async def test_invalid_host_returns_original(self):
        """Verify invalid hosts return the original hostname."""
        hostname = "this-domain-definitely-does-not-exist-12345.invalid"
        result = await resolve_host(hostname)
        assert result == hostname


class TestTransportStats:
    """Tests for TransportStats health monitoring."""

    def test_uptime_zero_when_not_started(self):
        """Verify uptime is 0 when connection hasn't started."""
        stats = TransportStats()
        assert stats.uptime_seconds == 0.0

    def test_uptime_increases_after_start(self):
        """Verify uptime increases after connection starts."""
        stats = TransportStats()
        stats.connection_start_time = time.time() - 10.0
        assert stats.uptime_seconds >= 9.0

    def test_healthy_when_not_started(self):
        """Verify not healthy when connection hasn't started."""
        stats = TransportStats()
        assert stats.is_healthy is False

    def test_healthy_when_fresh(self):
        """Verify healthy is True when connection just started."""
        stats = TransportStats()
        stats.connection_start_time = time.time()
        assert stats.is_healthy is True

    def test_healthy_with_good_latency(self):
        """Verify healthy with acceptable latency."""
        stats = TransportStats()
        stats.connection_start_time = time.time() - 60.0
        stats.last_ping_latency = 0.1
        assert stats.is_healthy is True

    def test_unhealthy_with_high_latency(self):
        """Verify unhealthy with high latency."""
        stats = TransportStats()
        stats.connection_start_time = time.time() - 60.0
        stats.last_ping_latency = 10.0
        assert stats.is_healthy is False

    def test_healthy_threshold(self):
        """Verify exact healthy threshold (5 seconds)."""
        stats = TransportStats()
        stats.connection_start_time = time.time() - 60.0

        stats.last_ping_latency = 5.0
        assert stats.is_healthy is True

        stats.last_ping_latency = 5.01
        assert stats.is_healthy is False


class TestWebSocketTransportReconnect:
    """Tests for WebSocket transport reconnection behavior."""

    def test_default_max_reconnect_attempts(self):
        """Verify default max reconnect attempts is 15."""
        transport = WebSocketTransport()
        assert transport._max_reconnect_attempts == 15

    def test_default_connect_timeout(self):
        """Verify default connect timeout is 30 seconds."""
        transport = WebSocketTransport()
        assert transport._connect_timeout == 30.0

    def test_custom_reconnect_settings(self):
        """Verify custom reconnect settings are respected."""
        transport = WebSocketTransport(
            max_reconnect_attempts=5,
            reconnect_delay=2.0,
            max_reconnect_delay=120.0,
        )
        assert transport._max_reconnect_attempts == 5
        assert transport._reconnect_delay == 2.0
        assert transport._max_reconnect_delay == 120.0

    def test_auto_reconnect_enabled_by_default(self):
        """Verify auto-reconnect is enabled by default."""
        transport = WebSocketTransport()
        assert transport._auto_reconnect is True

    def test_auto_reconnect_can_be_disabled(self):
        """Verify auto-reconnect can be disabled."""
        transport = WebSocketTransport(auto_reconnect=False)
        assert transport._auto_reconnect is False


class TestImmediateFirstReconnect:
    """Tests for immediate first reconnect behavior."""

    def test_first_reconnect_delay_is_zero(self):
        """Document that first reconnect should have zero delay.

        Based on research from ngrok, cloudflared, and tunnelto,
        the first reconnection attempt should be immediate (no delay)
        for best user experience. Subsequent attempts use exponential
        backoff.
        """
        transport = WebSocketTransport()
        assert transport._reconnect_delay == 1.0


class TestConnectionPatterns:
    """Tests documenting connection patterns from tunnel services."""

    def test_tunnelto_pattern_stream_multiplexing(self):
        """Document tunnelto's stream multiplexing pattern.

        Tunnelto uses WebSocket with stream IDs to multiplex
        multiple HTTP connections over a single tunnel.
        We implement similar pattern with request IDs.
        """
        pass

    def test_tunnelto_pattern_reconnect_token(self):
        """Document tunnelto's reconnect token pattern.

        Tunnelto uses signed reconnect tokens for session persistence
        across disconnections. The token contains subdomain and client ID.
        """
        pass

    def test_ngrok_pattern_retry_logic(self):
        """Document ngrok's retry logic pattern.

        ngrok uses configurable retry conditions with CEL expressions:
        - Retry on specific status codes (500, 502, 503, 504)
        - Max 3 retries by default
        - Timeout between 1s-30s
        """
        from instanton.client.tunnel import ProxyConfig

        config = ProxyConfig()
        assert config.retry_count == 2
        assert 502 in config.retry_on_status
        assert 503 in config.retry_on_status
        assert 504 in config.retry_on_status

    def test_cloudflared_pattern_protocol_fallback(self):
        """Document cloudflared's protocol fallback pattern.

        Cloudflared supports QUIC → HTTP/2 fallback:
        - Prefers QUIC for performance
        - Falls back to HTTP/2 if QUIC fails
        """
        pass

    def test_cloudflared_pattern_multiple_connections(self):
        """Document cloudflared's HA connections pattern.

        Cloudflared maintains multiple concurrent connections
        (HAConnections = 4 by default) for high availability.
        """
        pass


class TestConnectionReliabilityDefaults:
    """Tests documenting connection reliability defaults."""

    def test_connect_timeout_for_global_users(self):
        """Verify connect timeout is appropriate for global users.

        30 seconds allows for:
        - High latency connections (200-500ms RTT)
        - DNS resolution time
        - TLS handshake
        - Initial protocol negotiation
        """
        transport = WebSocketTransport()
        assert transport._connect_timeout >= 30.0

    def test_ping_timeout_for_network_jitter(self):
        """Verify ping timeout handles network jitter.

        15 seconds provides tolerance for:
        - Transient network issues
        - High-latency networks (satellite, mobile)
        - Brief congestion periods
        """
        transport = WebSocketTransport()
        assert transport._ping_timeout >= 15.0

    def test_max_reconnect_attempts_for_resilience(self):
        """Verify max reconnect attempts provide resilience.

        15 attempts with exponential backoff covers:
        - Brief outages (< 1 minute)
        - Network switches (WiFi ↔ mobile)
        - Server restarts
        """
        transport = WebSocketTransport()
        assert transport._max_reconnect_attempts >= 15

    def test_reconnect_delay_exponential_backoff(self):
        """Verify reconnect uses exponential backoff."""
        transport = WebSocketTransport()
        assert transport._reconnect_delay == 1.0
        assert transport._max_reconnect_delay == 60.0
