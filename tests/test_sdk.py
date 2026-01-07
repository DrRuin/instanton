"""Tests for Instanton SDK - embeddable tunnel API."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from instanton.sdk import (
    InstantonConfig,
    Listener,
    TunnelStats,
    _sanitize_subdomain,
    _suggest_subdomain,
    config,
    forward,
    set_auth_token,
    set_server,
)


class TestSubdomainSanitization:
    """Tests for subdomain sanitization."""

    def test_lowercase_conversion(self):
        """Test that uppercase is converted to lowercase."""
        assert _sanitize_subdomain("MyApp") == "myapp"
        assert _sanitize_subdomain("ALLCAPS") == "allcaps"

    def test_underscore_to_hyphen(self):
        """Test that underscores become hyphens."""
        assert _sanitize_subdomain("my_app") == "my-app"
        assert _sanitize_subdomain("my__app") == "my-app"

    def test_space_to_hyphen(self):
        """Test that spaces become hyphens."""
        assert _sanitize_subdomain("my app") == "my-app"
        assert _sanitize_subdomain("my  app") == "my-app"

    def test_invalid_chars_removed(self):
        """Test that invalid characters are removed."""
        assert _sanitize_subdomain("my@app!") == "myapp"
        assert _sanitize_subdomain("my.app.test") == "myapptest"

    def test_leading_trailing_hyphens_removed(self):
        """Test that leading/trailing hyphens are removed."""
        assert _sanitize_subdomain("-myapp-") == "myapp"
        assert _sanitize_subdomain("--app--") == "app"

    def test_max_length_truncation(self):
        """Test that long names are truncated."""
        long_name = "a" * 100
        result = _sanitize_subdomain(long_name)
        assert len(result) <= 63

    def test_min_length_requirement(self):
        """Test that too-short names return empty."""
        assert _sanitize_subdomain("ab") == ""
        assert _sanitize_subdomain("a") == ""
        assert _sanitize_subdomain("") == ""

    def test_valid_subdomains_unchanged(self):
        """Test that valid subdomains pass through."""
        assert _sanitize_subdomain("myapp") == "myapp"
        assert _sanitize_subdomain("my-app") == "my-app"
        assert _sanitize_subdomain("app123") == "app123"


class TestSubdomainSuggestion:
    """Tests for automatic subdomain suggestion."""

    def test_suggest_from_pyproject(self, tmp_path: Path, monkeypatch):
        """Test suggestion from pyproject.toml."""
        pyproject = tmp_path / "pyproject.toml"
        pyproject.write_text('[project]\nname = "my-awesome-app"')

        monkeypatch.chdir(tmp_path)
        result = _suggest_subdomain()
        assert result == "my-awesome-app"

    def test_suggest_from_package_json(self, tmp_path: Path, monkeypatch):
        """Test suggestion from package.json."""
        package_json = tmp_path / "package.json"
        package_json.write_text('{"name": "react-app"}')

        monkeypatch.chdir(tmp_path)
        result = _suggest_subdomain()
        assert result == "react-app"

    def test_suggest_from_scoped_npm_package(self, tmp_path: Path, monkeypatch):
        """Test suggestion from scoped npm package."""
        package_json = tmp_path / "package.json"
        package_json.write_text('{"name": "@myorg/cool-package"}')

        monkeypatch.chdir(tmp_path)
        result = _suggest_subdomain()
        assert result == "cool-package"

    def test_suggest_from_directory_name(self, tmp_path: Path, monkeypatch):
        """Test suggestion from directory name."""
        project_dir = tmp_path / "my-project"
        project_dir.mkdir()

        monkeypatch.chdir(project_dir)
        result = _suggest_subdomain()
        assert result == "my-project"

    def test_suggest_ignores_common_directories(self, tmp_path: Path, monkeypatch):
        """Test that common directory names are ignored."""
        src_dir = tmp_path / "src"
        src_dir.mkdir()

        monkeypatch.chdir(src_dir)
        result = _suggest_subdomain()
        # Should return None or empty for common names
        assert result is None or result == ""

    def test_suggest_handles_invalid_pyproject(self, tmp_path: Path, monkeypatch):
        """Test handling of invalid pyproject.toml."""
        pyproject = tmp_path / "pyproject.toml"
        pyproject.write_text("invalid toml {{{")

        monkeypatch.chdir(tmp_path)
        # Should not raise, just return fallback
        result = _suggest_subdomain()
        # Falls back to directory name
        assert result is not None


class TestInstantonConfig:
    """Tests for InstantonConfig."""

    def test_default_values(self):
        """Test default configuration values."""
        cfg = InstantonConfig()
        assert cfg.auto_reconnect is True
        assert cfg.use_quic is True
        assert cfg.connect_timeout == 10.0
        assert cfg.keepalive_interval == 30.0
        assert cfg.max_reconnect_attempts == 10

    def test_configure_updates_values(self):
        """Test that configure() updates values."""
        cfg = InstantonConfig()
        cfg.configure(
            server="custom.server.com:443",
            auth_token="test-token",
            auto_reconnect=False,
            use_quic=False,
            connect_timeout=5.0,
        )

        assert cfg.server == "custom.server.com:443"
        assert cfg.auth_token == "test-token"
        assert cfg.auto_reconnect is False
        assert cfg.use_quic is False
        assert cfg.connect_timeout == 5.0

    def test_configure_partial_update(self):
        """Test that configure() only updates provided values."""
        cfg = InstantonConfig()
        original_timeout = cfg.connect_timeout

        cfg.configure(server="new.server.com")

        assert cfg.server == "new.server.com"
        assert cfg.connect_timeout == original_timeout


class TestTunnelStats:
    """Tests for TunnelStats dataclass."""

    def test_default_values(self):
        """Test default TunnelStats values."""
        stats = TunnelStats()
        assert stats.requests_proxied == 0
        assert stats.bytes_sent == 0
        assert stats.bytes_received == 0
        assert stats.connected_at is not None
        assert stats.last_activity is None

    def test_custom_values(self):
        """Test TunnelStats with custom values."""
        stats = TunnelStats(
            requests_proxied=100,
            bytes_sent=1024,
            bytes_received=2048,
        )
        assert stats.requests_proxied == 100
        assert stats.bytes_sent == 1024
        assert stats.bytes_received == 2048


class TestListener:
    """Tests for Listener class."""

    @pytest.fixture
    def mock_client(self):
        """Create a mock TunnelClient."""
        client = MagicMock()
        client.is_connected = True
        client._subdomain = "test-app"
        client._tunnel_id = "test-id-123"
        client.stats = {
            "requests_proxied": 10,
            "bytes_sent": 1024,
            "bytes_received": 2048,
        }
        client.close = AsyncMock()
        return client

    def test_listener_properties(self, mock_client):
        """Test Listener property access."""
        listener = Listener(
            url="https://test-app.instanton.dev",
            subdomain="test-app",
            local_port=8000,
            tunnel_id="test-id-123",
            _client=mock_client,
        )

        assert listener.url == "https://test-app.instanton.dev"
        assert listener.subdomain == "test-app"
        assert listener.local_port == 8000
        assert listener.tunnel_id == "test-id-123"
        assert listener.is_active is True

    def test_listener_stats(self, mock_client):
        """Test Listener stats property."""
        listener = Listener(
            url="https://test-app.instanton.dev",
            subdomain="test-app",
            local_port=8000,
            tunnel_id="test-id-123",
            _client=mock_client,
        )

        stats = listener.stats
        assert stats.requests_proxied == 10
        assert stats.bytes_sent == 1024
        assert stats.bytes_received == 2048

    @pytest.mark.asyncio
    async def test_listener_close(self, mock_client):
        """Test Listener close method."""
        listener = Listener(
            url="https://test-app.instanton.dev",
            subdomain="test-app",
            local_port=8000,
            tunnel_id="test-id-123",
            _client=mock_client,
        )

        await listener.close()
        mock_client.close.assert_called_once()

    @pytest.mark.asyncio
    async def test_listener_context_manager(self, mock_client):
        """Test Listener as async context manager."""
        listener = Listener(
            url="https://test-app.instanton.dev",
            subdomain="test-app",
            local_port=8000,
            tunnel_id="test-id-123",
            _client=mock_client,
        )

        async with listener as active_listener:
            assert active_listener is listener
            assert active_listener.is_active is True

        # Should close on exit
        mock_client.close.assert_called()


class TestSetHelpers:
    """Tests for set_* helper functions."""

    def test_set_auth_token(self):
        """Test set_auth_token updates config."""
        original = config.auth_token
        try:
            set_auth_token("new-token-123")
            assert config.auth_token == "new-token-123"
        finally:
            config.auth_token = original

    def test_set_server(self):
        """Test set_server updates config."""
        original = config.server
        try:
            set_server("custom.instanton.io:8443")
            assert config.server == "custom.instanton.io:8443"
        finally:
            config.server = original


class TestForwardFunction:
    """Tests for the forward() function."""

    @pytest.mark.asyncio
    async def test_forward_creates_listener(self):
        """Test that forward() creates and returns a Listener."""
        with patch("instanton.sdk.TunnelClient") as mock_client_class:
            mock_client = MagicMock()
            mock_client.connect = AsyncMock(return_value="https://test.instanton.dev")
            mock_client.run = AsyncMock()
            mock_client._subdomain = "test"
            mock_client._tunnel_id = "id-123"
            mock_client.is_connected = True
            mock_client.stats = {"requests_proxied": 0, "bytes_sent": 0, "bytes_received": 0}
            mock_client.add_state_hook = MagicMock()
            mock_client_class.return_value = mock_client

            listener = await forward(8000, subdomain="test", suggest_subdomain=False)

            assert listener.url == "https://test.instanton.dev"
            assert listener.local_port == 8000
            mock_client.connect.assert_called_once()

    @pytest.mark.asyncio
    async def test_forward_with_string_port(self):
        """Test forward() accepts string port."""
        with patch("instanton.sdk.TunnelClient") as mock_client_class:
            mock_client = MagicMock()
            mock_client.connect = AsyncMock(return_value="https://test.instanton.dev")
            mock_client.run = AsyncMock()
            mock_client._subdomain = "test"
            mock_client._tunnel_id = "id-123"
            mock_client.is_connected = True
            mock_client.stats = {"requests_proxied": 0, "bytes_sent": 0, "bytes_received": 0}
            mock_client.add_state_hook = MagicMock()
            mock_client_class.return_value = mock_client

            listener = await forward("3000", subdomain="test", suggest_subdomain=False)

            assert listener.local_port == 3000

    @pytest.mark.asyncio
    async def test_forward_with_callbacks(self):
        """Test forward() with on_connect/on_disconnect callbacks."""
        connect_called = False
        disconnect_called = False

        def on_connect():
            nonlocal connect_called
            connect_called = True

        def on_disconnect():
            nonlocal disconnect_called
            disconnect_called = True

        with patch("instanton.sdk.TunnelClient") as mock_client_class:
            mock_client = MagicMock()
            mock_client.connect = AsyncMock(return_value="https://test.instanton.dev")
            mock_client.run = AsyncMock()
            mock_client._subdomain = "test"
            mock_client._tunnel_id = "id-123"
            mock_client.is_connected = True
            mock_client.stats = {"requests_proxied": 0, "bytes_sent": 0, "bytes_received": 0}
            mock_client.add_state_hook = MagicMock()
            mock_client_class.return_value = mock_client

            await forward(
                8000,
                subdomain="test",
                on_connect=on_connect,
                on_disconnect=on_disconnect,
                suggest_subdomain=False,
            )

            # Verify hooks were registered
            assert mock_client.add_state_hook.call_count == 2


class TestModuleImports:
    """Tests for module-level imports and exports."""

    def test_instanton_module_exports(self):
        """Test that instanton module exports SDK functions."""
        import instanton

        # These should all be accessible
        assert hasattr(instanton, "forward")
        assert hasattr(instanton, "connect")
        assert hasattr(instanton, "listen")
        assert hasattr(instanton, "Listener")
        assert hasattr(instanton, "config")
        assert hasattr(instanton, "set_auth_token")
        assert hasattr(instanton, "set_server")
        assert hasattr(instanton, "__version__")

    def test_sdk_all_exports(self):
        """Test SDK __all__ list."""
        from instanton import sdk

        expected = [
            "forward",
            "forward_sync",
            "connect",
            "listen",
            "Listener",
            "TunnelStats",
            "InstantonConfig",
            "config",
            "set_auth_token",
            "set_server",
        ]

        for name in expected:
            assert name in sdk.__all__


class TestEnvironmentVariables:
    """Tests for environment variable handling."""

    def test_default_server_from_env(self, monkeypatch):
        """Test that INSTANTON_SERVER env var is used."""
        monkeypatch.setenv("INSTANTON_SERVER", "custom.server.com:443")

        # Re-import to pick up env var
        import importlib

        from instanton import sdk
        importlib.reload(sdk)

        assert sdk.DEFAULT_SERVER == "custom.server.com:443"

        # Reset
        monkeypatch.delenv("INSTANTON_SERVER", raising=False)
        importlib.reload(sdk)

    def test_default_auth_token_from_env(self, monkeypatch):
        """Test that INSTANTON_AUTH_TOKEN env var is used."""
        monkeypatch.setenv("INSTANTON_AUTH_TOKEN", "env-token-123")

        # Re-import to pick up env var
        import importlib

        from instanton import sdk
        importlib.reload(sdk)

        assert sdk.DEFAULT_AUTH_TOKEN == "env-token-123"

        # Reset
        monkeypatch.delenv("INSTANTON_AUTH_TOKEN", raising=False)
        importlib.reload(sdk)
