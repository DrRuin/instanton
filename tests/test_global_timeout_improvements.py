"""Tests for global timeout improvements.

These tests verify that timeout settings are properly optimized for users
connecting from different countries with varying network latency.
"""

import pytest

from instanton.client.tunnel import ReconnectConfig, TunnelClient
from instanton.core.config import ClientConfig
from instanton.core.transport import (
    QuicTransportConfig,
    WebSocketTransport,
)


class TestWebSocketGlobalTimeouts:
    """Tests for WebSocket transport global timeout settings."""

    def test_connect_timeout_increased_for_global_users(self):
        """Verify connect_timeout is 30s for high-latency international connections."""
        transport = WebSocketTransport()
        assert transport._connect_timeout == 30.0

    def test_ping_timeout_increased_for_network_jitter(self):
        """Verify ping_timeout is 15s for better tolerance of network jitter."""
        transport = WebSocketTransport()
        assert transport._ping_timeout == 15.0

    def test_max_reconnect_attempts_increased_for_resilience(self):
        """Verify max_reconnect_attempts is 15 for better resilience."""
        transport = WebSocketTransport()
        assert transport._max_reconnect_attempts == 15

    def test_timeout_values_can_be_overridden(self):
        """Verify that default timeouts can be customized for specific needs."""
        transport = WebSocketTransport(
            connect_timeout=60.0,
            ping_timeout=30.0,
            max_reconnect_attempts=20,
        )
        assert transport._connect_timeout == 60.0
        assert transport._ping_timeout == 30.0
        assert transport._max_reconnect_attempts == 20

    def test_timeout_for_local_development(self):
        """Verify local development can use shorter timeouts if desired."""
        transport = WebSocketTransport(
            connect_timeout=5.0,
            ping_timeout=3.0,
            max_reconnect_attempts=3,
        )
        assert transport._connect_timeout == 5.0
        assert transport._ping_timeout == 3.0
        assert transport._max_reconnect_attempts == 3


class TestQuicGlobalTimeouts:
    """Tests for QUIC transport global timeout settings."""

    def test_idle_timeout_increased_for_global_users(self):
        """Verify idle_timeout is 60s for global users."""
        config = QuicTransportConfig()
        assert config.idle_timeout == 60.0

    def test_connection_timeout_increased(self):
        """Verify connection_timeout is 30s for high-latency networks."""
        config = QuicTransportConfig()
        assert config.connection_timeout == 30.0

    def test_max_reconnect_attempts_increased(self):
        """Verify max_reconnect_attempts is 15 for resilience."""
        config = QuicTransportConfig()
        assert config.max_reconnect_attempts == 15

    def test_quic_timeouts_can_be_customized(self):
        """Verify QUIC timeouts can be customized."""
        config = QuicTransportConfig(
            idle_timeout=120.0,
            connection_timeout=45.0,
            max_reconnect_attempts=25,
        )
        assert config.idle_timeout == 120.0
        assert config.connection_timeout == 45.0
        assert config.max_reconnect_attempts == 25


class TestClientConfigGlobalTimeouts:
    """Tests for ClientConfig global timeout settings."""

    def test_connect_timeout_default_increased(self):
        """Verify connect_timeout default is 30s for global users."""
        config = ClientConfig()
        assert config.connect_timeout == 30.0

    def test_max_reconnect_attempts_default_increased(self):
        """Verify max_reconnect_attempts default is 15."""
        config = ClientConfig()
        assert config.max_reconnect_attempts == 15

    def test_idle_timeout_remains_generous(self):
        """Verify idle_timeout is 300s (5 minutes) for long sessions."""
        config = ClientConfig()
        assert config.idle_timeout == 300.0

    def test_keepalive_interval_appropriate(self):
        """Verify keepalive_interval is 30s for maintaining connections."""
        config = ClientConfig()
        assert config.keepalive_interval == 30.0


class TestReconnectConfigGlobalOptimizations:
    """Tests for ReconnectConfig global optimizations."""

    def test_max_attempts_increased(self):
        """Verify max_attempts is 15 for better resilience."""
        config = ReconnectConfig()
        assert config.max_attempts == 15

    def test_jitter_increased(self):
        """Verify jitter is 0.2 to reduce reconnection storms."""
        config = ReconnectConfig()
        assert config.jitter == 0.2

    def test_base_delay_appropriate(self):
        """Verify base_delay starts at 1s."""
        config = ReconnectConfig()
        assert config.base_delay == 1.0

    def test_max_delay_capped(self):
        """Verify max_delay is capped at 60s."""
        config = ReconnectConfig()
        assert config.max_delay == 60.0


class TestTunnelClientTimeoutIntegration:
    """Tests for TunnelClient timeout integration."""

    def test_tunnel_client_has_connect_timeout_property(self):
        """Verify TunnelClient exposes connect_timeout property."""
        client = TunnelClient(local_port=8000)
        assert hasattr(client, 'connect_timeout')
        assert client.connect_timeout == 30.0

    def test_tunnel_client_uses_config_timeout(self):
        """Verify TunnelClient uses timeout from ClientConfig."""
        config = ClientConfig(connect_timeout=45.0)
        client = TunnelClient(local_port=8000, config=config)
        assert client.connect_timeout == 45.0

    def test_tunnel_client_default_timeout_without_config(self):
        """Verify TunnelClient has default timeout when no config provided."""
        client = TunnelClient(local_port=8000)
        assert client._connect_timeout == 30.0

    def test_tunnel_client_keepalive_interval(self):
        """Verify TunnelClient has appropriate keepalive interval."""
        client = TunnelClient(local_port=8000)
        assert client._keepalive_interval == 30.0


class TestTimeoutScenarios:
    """Tests for various timeout scenarios users might encounter."""

    def test_asia_pacific_high_latency(self):
        """Test configuration suitable for Asia-Pacific users with high latency."""
        config = ClientConfig(
            connect_timeout=30.0,
            idle_timeout=300.0,
        )
        assert config.connect_timeout >= 20.0

    def test_satellite_internet(self):
        """Test configuration for satellite internet users."""
        config = ClientConfig(
            connect_timeout=60.0,
            idle_timeout=600.0,
        )
        assert config.connect_timeout == 60.0
        assert config.idle_timeout == 600.0

    def test_mobile_network_users(self):
        """Test configuration for mobile network users."""
        reconnect = ReconnectConfig(
            max_attempts=20,
            jitter=0.3,
        )
        assert reconnect.max_attempts == 20
        assert reconnect.jitter == 0.3

    def test_corporate_network_with_proxy(self):
        """Test configuration for corporate networks with proxy."""
        config = ClientConfig(
            connect_timeout=45.0,
            keepalive_interval=20.0,
        )
        assert config.connect_timeout == 45.0
        assert config.keepalive_interval == 20.0


class TestTimeoutDefaults:
    """Tests to document and verify all timeout defaults."""

    def test_all_websocket_defaults(self):
        """Document all WebSocketTransport default timeout values."""
        transport = WebSocketTransport()

        assert transport._connect_timeout == 30.0
        assert transport._auto_reconnect is True

        assert transport._max_reconnect_attempts == 15
        assert transport._reconnect_delay == 1.0
        assert transport._max_reconnect_delay == 60.0

        assert transport._ping_interval == 30.0
        assert transport._ping_timeout == 15.0

    def test_all_quic_defaults(self):
        """Document all QuicTransportConfig default timeout values."""
        config = QuicTransportConfig()

        assert config.connection_timeout == 30.0
        assert config.idle_timeout == 60.0
        assert config.auto_reconnect is True

        assert config.max_reconnect_attempts == 15
        assert config.reconnect_delay == 1.0
        assert config.max_reconnect_delay == 60.0

    def test_all_client_config_defaults(self):
        """Document all ClientConfig default timeout values."""
        config = ClientConfig()

        assert config.connect_timeout == 30.0
        assert config.idle_timeout == 300.0
        assert config.keepalive_interval == 30.0
        assert config.auto_reconnect is True
        assert config.max_reconnect_attempts == 15

    def test_all_reconnect_config_defaults(self):
        """Document all ReconnectConfig default values."""
        config = ReconnectConfig()

        assert config.enabled is True
        assert config.max_attempts == 15
        assert config.base_delay == 1.0
        assert config.max_delay == 60.0
        assert config.jitter == 0.2


class TestTimeoutBoundaries:
    """Tests for timeout boundary conditions."""

    def test_minimum_viable_timeouts(self):
        """Test minimum viable timeout values for fast networks."""
        transport = WebSocketTransport(
            connect_timeout=1.0,
            ping_timeout=1.0,
        )
        assert transport._connect_timeout == 1.0
        assert transport._ping_timeout == 1.0

    def test_maximum_practical_timeouts(self):
        """Test maximum practical timeout values."""
        config = ClientConfig(
            connect_timeout=120.0,
            idle_timeout=3600.0,
        )
        assert config.connect_timeout == 120.0
        assert config.idle_timeout == 3600.0

    def test_zero_timeout_handling(self):
        """Test handling of zero timeout values."""
        config = ClientConfig(
            connect_timeout=0.0,
            idle_timeout=0.0,
        )
        assert config.connect_timeout == 0.0
        assert config.idle_timeout == 0.0

    def test_negative_timeout_handling(self):
        """Test that negative timeouts are accepted (validation is caller's job)."""
        config = ClientConfig(connect_timeout=-1.0)
        assert config.connect_timeout == -1.0


class TestTransportCreation:
    """Tests for transport creation with timeout settings."""

    @pytest.mark.asyncio
    async def test_tunnel_client_creates_transport_with_timeouts(self):
        """Verify TunnelClient creates transport with correct timeouts."""
        client = TunnelClient(local_port=8000)
        transport = await client._create_transport()

        assert isinstance(transport, WebSocketTransport)
        assert transport._connect_timeout == 30.0
        assert transport._ping_interval == 30.0

    @pytest.mark.asyncio
    async def test_tunnel_client_creates_transport_with_custom_config(self):
        """Verify TunnelClient creates transport with custom config timeouts."""
        config = ClientConfig(
            connect_timeout=45.0,
            keepalive_interval=20.0,
        )
        client = TunnelClient(local_port=8000, config=config)
        transport = await client._create_transport()

        assert transport._connect_timeout == 45.0
        assert transport._ping_interval == 20.0
