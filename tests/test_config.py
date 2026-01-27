"""Tests for configuration loading from environment variables."""

from __future__ import annotations

import os
from unittest.mock import patch

import pytest

from instanton.core.config import (
    InstantonConfig,
    PerformanceConfig,
    ReconnectConfig,
    ResourceConfig,
    TimeoutConfig,
    clear_config,
    get_config,
)


class TestPerformanceConfig:
    """Test PerformanceConfig settings."""

    def test_default_values(self) -> None:
        """Test default values."""
        config = PerformanceConfig()
        assert config.chunk_size == 1024 * 1024
        assert config.max_message_size == 64 * 1024 * 1024
        assert config.compression_enabled is True
        assert config.compression_level == 3
        assert config.ws_max_size == 2 * 1024 * 1024 * 1024  # 2GB for large file support

    def test_env_override_chunk_size(self) -> None:
        """Test INSTANTON_CHUNK_SIZE env var."""
        with patch.dict(os.environ, {"INSTANTON_CHUNK_SIZE": "2097152"}):
            config = PerformanceConfig()
            assert config.chunk_size == 2097152

    def test_env_override_compression_enabled(self) -> None:
        """Test INSTANTON_COMPRESSION_ENABLED env var."""
        with patch.dict(os.environ, {"INSTANTON_COMPRESSION_ENABLED": "false"}):
            config = PerformanceConfig()
            assert config.compression_enabled is False

    def test_env_override_compression_level(self) -> None:
        """Test INSTANTON_COMPRESSION_LEVEL env var."""
        with patch.dict(os.environ, {"INSTANTON_COMPRESSION_LEVEL": "9"}):
            config = PerformanceConfig()
            assert config.compression_level == 9


class TestTimeoutConfig:
    """Test TimeoutConfig settings."""

    def test_default_values(self) -> None:
        """Test default values."""
        config = TimeoutConfig()
        assert config.connect_timeout == 30.0
        assert config.read_timeout is None
        assert config.write_timeout == 5.0
        assert config.ping_interval == 30.0
        assert config.ping_timeout == 15.0
        assert config.request_timeout == 600.0

    def test_env_override_connect_timeout(self) -> None:
        """Test INSTANTON_CONNECT_TIMEOUT env var."""
        with patch.dict(os.environ, {"INSTANTON_CONNECT_TIMEOUT": "60.0"}):
            config = TimeoutConfig()
            assert config.connect_timeout == 60.0

    def test_env_override_ping_interval(self) -> None:
        """Test INSTANTON_PING_INTERVAL env var."""
        with patch.dict(os.environ, {"INSTANTON_PING_INTERVAL": "45.0"}):
            config = TimeoutConfig()
            assert config.ping_interval == 45.0


class TestReconnectConfig:
    """Test ReconnectConfig settings."""

    def test_default_values(self) -> None:
        """Test default values."""
        config = ReconnectConfig()
        assert config.auto_reconnect is True
        assert config.max_attempts == 15
        assert config.base_delay == 1.0
        assert config.max_delay == 60.0
        assert config.jitter == 0.2

    def test_env_override_auto_reconnect(self) -> None:
        """Test INSTANTON_AUTO_RECONNECT env var."""
        with patch.dict(os.environ, {"INSTANTON_AUTO_RECONNECT": "false"}):
            config = ReconnectConfig()
            assert config.auto_reconnect is False

    def test_env_override_max_attempts(self) -> None:
        """Test INSTANTON_MAX_ATTEMPTS env var."""
        with patch.dict(os.environ, {"INSTANTON_MAX_ATTEMPTS": "30"}):
            config = ReconnectConfig()
            assert config.max_attempts == 30


class TestResourceConfig:
    """Test ResourceConfig settings."""

    def test_default_values(self) -> None:
        """Test default values."""
        config = ResourceConfig()
        assert config.max_tunnels == 10000
        assert config.max_connections == 100
        assert config.max_keepalive == 20
        assert config.tcp_port_min == 10000
        assert config.tcp_port_max == 19999
        assert config.dns_cache_ttl == 300.0

    def test_env_override_max_tunnels(self) -> None:
        """Test INSTANTON_MAX_TUNNELS env var."""
        with patch.dict(os.environ, {"INSTANTON_MAX_TUNNELS": "50000"}):
            config = ResourceConfig()
            assert config.max_tunnels == 50000

    def test_env_override_port_range(self) -> None:
        """Test TCP port range env vars."""
        with patch.dict(
            os.environ,
            {
                "INSTANTON_TCP_PORT_MIN": "20000",
                "INSTANTON_TCP_PORT_MAX": "29999",
            },
        ):
            config = ResourceConfig()
            assert config.tcp_port_min == 20000
            assert config.tcp_port_max == 29999


class TestInstantonConfig:
    """Test InstantonConfig master class."""

    def test_properties(self) -> None:
        """Test config property access."""
        config = InstantonConfig()
        assert isinstance(config.performance, PerformanceConfig)
        assert isinstance(config.timeouts, TimeoutConfig)
        assert isinstance(config.reconnect, ReconnectConfig)
        assert isinstance(config.resources, ResourceConfig)

    def test_to_env_dict(self) -> None:
        """Test env dict export."""
        config = InstantonConfig()
        env_dict = config.to_env_dict()

        assert "INSTANTON_CHUNK_SIZE" in env_dict
        assert "INSTANTON_CONNECT_TIMEOUT" in env_dict
        assert "INSTANTON_MAX_TUNNELS" in env_dict
        assert env_dict["INSTANTON_CHUNK_SIZE"] == str(1024 * 1024)

    def test_to_display_dict(self) -> None:
        """Test display dict export."""
        config = InstantonConfig()
        display = config.to_display_dict()

        assert "performance" in display
        assert "timeouts" in display
        assert "reconnect" in display
        assert "resources" in display

        assert display["performance"]["chunk_size"] == 1024 * 1024
        assert display["timeouts"]["connect_timeout"] == 30.0


class TestGetConfig:
    """Test get_config global function."""

    def test_get_config_returns_instance(self) -> None:
        """Test get_config returns InstantonConfig."""
        clear_config()
        config = get_config()
        assert isinstance(config, InstantonConfig)

    def test_get_config_caches_instance(self) -> None:
        """Test get_config returns cached instance."""
        clear_config()
        config1 = get_config()
        config2 = get_config()
        assert config1 is config2

    def test_clear_config_resets_cache(self) -> None:
        """Test clear_config resets cache."""
        clear_config()
        config1 = get_config()
        clear_config()
        config2 = get_config()
        assert config1 is not config2

    def test_get_config_with_env_override(self) -> None:
        """Test get_config respects environment variables."""
        clear_config()

        with patch.dict(os.environ, {"INSTANTON_CHUNK_SIZE": "4194304"}):
            clear_config()
            config = get_config()
            assert config.performance.chunk_size == 4194304

        clear_config()


class TestEnvVarIntegration:
    """Integration tests for env var configuration."""

    def test_multiple_env_vars(self) -> None:
        """Test multiple env vars are applied."""
        env_vars = {
            "INSTANTON_CHUNK_SIZE": "2097152",
            "INSTANTON_COMPRESSION_ENABLED": "false",
            "INSTANTON_CONNECT_TIMEOUT": "60.0",
            "INSTANTON_MAX_TUNNELS": "50000",
        }

        with patch.dict(os.environ, env_vars):
            clear_config()
            config = get_config()

            assert config.performance.chunk_size == 2097152
            assert config.performance.compression_enabled is False
            assert config.timeouts.connect_timeout == 60.0
            assert config.resources.max_tunnels == 50000

        clear_config()

    def test_invalid_env_var_ignored(self) -> None:
        """Test invalid env vars use default."""
        with patch.dict(os.environ, {"INSTANTON_CHUNK_SIZE": "invalid"}):
            with pytest.raises(Exception):
                PerformanceConfig()

    def test_compression_skip_types_parsing(self) -> None:
        """Test compression skip types are parsed correctly."""
        config = PerformanceConfig()
        skip_types = config.compression_skip_types

        assert "image/" in skip_types
        assert "video/" in skip_types
        assert "application/pdf" in skip_types
