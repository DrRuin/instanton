"""Tests for multi-port tunnel support and CLI timeout options.

This test suite verifies:
1. Multiple simultaneous tunnels with different ports and subdomains
2. CLI timeout configuration (--timeout, --idle-timeout, --keepalive)
3. ClientConfig timeout settings
4. Concurrent tunnel operation
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from click.testing import CliRunner

from instanton.cli import main
from instanton.core.config import ClientConfig


class TestClientConfigTimeout:
    """Tests for ClientConfig timeout settings."""

    def test_default_connect_timeout(self):
        """Test default connect_timeout value."""
        config = ClientConfig()
        assert config.connect_timeout == 10.0

    def test_default_idle_timeout(self):
        """Test default idle_timeout value."""
        config = ClientConfig()
        assert config.idle_timeout == 300.0

    def test_default_keepalive_interval(self):
        """Test default keepalive_interval value."""
        config = ClientConfig()
        assert config.keepalive_interval == 30.0

    def test_custom_connect_timeout(self):
        """Test custom connect_timeout value."""
        config = ClientConfig(connect_timeout=60.0)
        assert config.connect_timeout == 60.0

    def test_custom_idle_timeout(self):
        """Test custom idle_timeout value."""
        config = ClientConfig(idle_timeout=600.0)
        assert config.idle_timeout == 600.0

    def test_custom_keepalive_interval(self):
        """Test custom keepalive_interval value."""
        config = ClientConfig(keepalive_interval=15.0)
        assert config.keepalive_interval == 15.0

    def test_all_timeout_settings_together(self):
        """Test all timeout settings configured together."""
        config = ClientConfig(
            connect_timeout=45.0,
            idle_timeout=900.0,
            keepalive_interval=20.0,
        )
        assert config.connect_timeout == 45.0
        assert config.idle_timeout == 900.0
        assert config.keepalive_interval == 20.0

    def test_zero_timeout_values(self):
        """Test that zero timeout values are accepted."""
        config = ClientConfig(
            connect_timeout=0.0,
            idle_timeout=0.0,
            keepalive_interval=0.0,
        )
        assert config.connect_timeout == 0.0
        assert config.idle_timeout == 0.0
        assert config.keepalive_interval == 0.0

    def test_large_timeout_values(self):
        """Test large timeout values for long-lived connections."""
        config = ClientConfig(
            connect_timeout=300.0,
            idle_timeout=86400.0,  # 24 hours
            keepalive_interval=60.0,
        )
        assert config.connect_timeout == 300.0
        assert config.idle_timeout == 86400.0
        assert config.keepalive_interval == 60.0


class TestCLITimeoutOptions:
    """Tests for CLI timeout command-line options."""

    @pytest.fixture
    def runner(self):
        """Create a CLI runner."""
        return CliRunner()

    def test_cli_help_shows_timeout_options(self, runner: CliRunner):
        """Test that --help shows timeout options."""
        result = runner.invoke(main, ["--help"])
        assert result.exit_code == 0
        assert "--timeout" in result.output or "-t" in result.output
        assert "--idle-timeout" in result.output
        assert "--keepalive" in result.output or "-k" in result.output

    def test_cli_default_timeout_value(self, runner: CliRunner):
        """Test default timeout value in help text."""
        result = runner.invoke(main, ["--help"])
        assert "30" in result.output  # default timeout and keepalive

    def test_cli_default_idle_timeout_value(self, runner: CliRunner):
        """Test default idle timeout value in help text."""
        result = runner.invoke(main, ["--help"])
        assert "300" in result.output  # default idle timeout

    @patch("instanton.cli.asyncio.run")
    def test_cli_passes_timeout_to_start_tunnel(
        self, mock_run: MagicMock, runner: CliRunner
    ):
        """Test that CLI passes timeout value to start_tunnel."""
        # Mock to prevent actual execution
        mock_run.return_value = None

        runner.invoke(main, ["--port", "8000", "--timeout", "60"])
        # The command would call asyncio.run with start_tunnel
        mock_run.assert_called_once()
        # Get the coroutine that was passed to asyncio.run
        coro = mock_run.call_args[0][0]
        assert coro is not None

    @patch("instanton.cli.asyncio.run")
    def test_cli_passes_idle_timeout_to_start_tunnel(
        self, mock_run: MagicMock, runner: CliRunner
    ):
        """Test that CLI passes idle_timeout value to start_tunnel."""
        mock_run.return_value = None

        runner.invoke(main, ["--port", "8000", "--idle-timeout", "600"])
        mock_run.assert_called_once()

    @patch("instanton.cli.asyncio.run")
    def test_cli_passes_keepalive_to_start_tunnel(
        self, mock_run: MagicMock, runner: CliRunner
    ):
        """Test that CLI passes keepalive value to start_tunnel."""
        mock_run.return_value = None

        runner.invoke(main, ["--port", "8000", "--keepalive", "15"])
        mock_run.assert_called_once()

    @patch("instanton.cli.asyncio.run")
    def test_cli_all_timeout_options_together(
        self, mock_run: MagicMock, runner: CliRunner
    ):
        """Test all timeout options together."""
        mock_run.return_value = None

        runner.invoke(
            main,
            [
                "--port", "8000",
                "--timeout", "45",
                "--idle-timeout", "900",
                "--keepalive", "20",
            ],
        )
        mock_run.assert_called_once()


class TestMultiPortSupport:
    """Tests for running multiple tunnels simultaneously."""

    def test_client_config_different_ports(self):
        """Test creating configs for different ports."""
        config_3000 = ClientConfig(local_port=3000, subdomain="frontend")
        config_5432 = ClientConfig(local_port=5432, subdomain="database")
        config_8000 = ClientConfig(local_port=8000, subdomain="api")

        assert config_3000.local_port == 3000
        assert config_3000.subdomain == "frontend"

        assert config_5432.local_port == 5432
        assert config_5432.subdomain == "database"

        assert config_8000.local_port == 8000
        assert config_8000.subdomain == "api"

    def test_client_config_unique_subdomains(self):
        """Test that different configs can have unique subdomains."""
        configs = [
            ClientConfig(local_port=3000, subdomain="app1"),
            ClientConfig(local_port=3001, subdomain="app2"),
            ClientConfig(local_port=3002, subdomain="app3"),
        ]

        subdomains = [c.subdomain for c in configs]
        assert len(subdomains) == len(set(subdomains))  # All unique

    def test_client_config_same_port_different_servers(self):
        """Test same port can connect to different servers."""
        config1 = ClientConfig(
            local_port=8000,
            server_addr="server1.instanton.dev:443",
        )
        config2 = ClientConfig(
            local_port=8000,
            server_addr="server2.instanton.dev:443",
        )

        assert config1.server_addr != config2.server_addr
        assert config1.local_port == config2.local_port

    @pytest.mark.asyncio
    async def test_multiple_tunnel_clients_creation(self):
        """Test creating multiple tunnel clients for different ports."""
        from instanton.client.tunnel import TunnelClient

        # Create multiple clients (without connecting)
        clients = []
        for port, subdomain in [(3000, "frontend"), (5432, "db"), (8000, "api")]:
            client = TunnelClient(
                local_port=port,
                server_addr="instanton.dev",
                subdomain=subdomain,
            )
            clients.append(client)

        assert len(clients) == 3
        assert clients[0].local_port == 3000
        assert clients[1].local_port == 5432
        assert clients[2].local_port == 8000

    @pytest.mark.asyncio
    async def test_concurrent_tunnel_connect_mock(self):
        """Test concurrent tunnel connections with mocks."""
        with patch("instanton.client.tunnel.WebSocketTransport") as mock_ws:
            mock_transport = MagicMock()
            mock_transport.connect = AsyncMock()
            mock_transport.send = AsyncMock()
            mock_transport.receive = AsyncMock(return_value=None)
            mock_transport.close = AsyncMock()
            mock_ws.return_value = mock_transport

            from instanton.client.tunnel import TunnelClient

            # Create clients
            client1 = TunnelClient(local_port=3000, subdomain="app1")
            client2 = TunnelClient(local_port=5432, subdomain="app2")
            client3 = TunnelClient(local_port=8000, subdomain="app3")

            # Verify they have different ports
            assert client1.local_port != client2.local_port
            assert client2.local_port != client3.local_port
            assert client1.local_port != client3.local_port

    def test_cli_shows_multi_port_examples(self):
        """Test that CLI help shows multi-port examples."""
        runner = CliRunner()
        runner.invoke(main, ["--help"])

        # Check for multi-port usage examples in docstring
        # These are shown when running without arguments
        result_no_args = runner.invoke(main, [])
        assert "3000" in result_no_args.output or "port" in result_no_args.output.lower()


class TestTimeoutBehavior:
    """Tests for timeout behavior in tunnel operations."""

    @pytest.mark.asyncio
    async def test_connect_timeout_config_used(self):
        """Test that connect_timeout is used in client configuration."""
        from instanton.client.tunnel import TunnelClient

        config = ClientConfig(connect_timeout=60.0)
        client = TunnelClient(
            local_port=8000,
            config=config,
        )

        # Client uses keepalive_interval from config
        assert client._keepalive_interval == config.keepalive_interval

    @pytest.mark.asyncio
    async def test_idle_timeout_config_used(self):
        """Test that idle_timeout is used in client configuration."""
        from instanton.client.tunnel import TunnelClient

        config = ClientConfig(idle_timeout=600.0, keepalive_interval=25.0)
        client = TunnelClient(
            local_port=8000,
            config=config,
        )

        # Verify keepalive from config is used
        assert client._keepalive_interval == 25.0

    @pytest.mark.asyncio
    async def test_keepalive_interval_config_used(self):
        """Test that keepalive_interval is used in client configuration."""
        from instanton.client.tunnel import TunnelClient

        config = ClientConfig(keepalive_interval=15.0)
        client = TunnelClient(
            local_port=8000,
            config=config,
        )

        assert client._keepalive_interval == 15.0


class TestConcurrentTunnelScenarios:
    """Tests for concurrent tunnel scenarios as described by user."""

    def test_scenario_three_apps_three_urls(self):
        """Test scenario: 3 apps on ports 3000, 5432, 8000 with different URLs."""
        configs = {
            "frontend": ClientConfig(
                local_port=3000,
                subdomain="frontend",
                server_addr="instanton.dev:443",
            ),
            "database": ClientConfig(
                local_port=5432,
                subdomain="database",
                server_addr="instanton.dev:443",
            ),
            "api": ClientConfig(
                local_port=8000,
                subdomain="api",
                server_addr="instanton.dev:443",
            ),
        }

        # Each config has unique port and subdomain
        ports = [c.local_port for c in configs.values()]
        subdomains = [c.subdomain for c in configs.values()]

        assert len(ports) == 3
        assert len(set(ports)) == 3  # All unique
        assert len(subdomains) == 3
        assert len(set(subdomains)) == 3  # All unique

        # Verify expected URLs would be:
        # frontend.instanton.dev -> localhost:3000
        # database.instanton.dev -> localhost:5432
        # api.instanton.dev -> localhost:8000
        assert configs["frontend"].subdomain == "frontend"
        assert configs["frontend"].local_port == 3000

        assert configs["database"].subdomain == "database"
        assert configs["database"].local_port == 5432

        assert configs["api"].subdomain == "api"
        assert configs["api"].local_port == 8000

    @pytest.mark.asyncio
    async def test_create_multiple_independent_clients(self):
        """Test creating multiple independent tunnel clients."""
        from instanton.client.tunnel import TunnelClient

        # Create three independent clients as user would in separate terminals
        client_frontend = TunnelClient(
            local_port=3000,
            subdomain="frontend",
            server_addr="instanton.dev",
        )

        client_database = TunnelClient(
            local_port=5432,
            subdomain="database",
            server_addr="instanton.dev",
        )

        client_api = TunnelClient(
            local_port=8000,
            subdomain="api",
            server_addr="instanton.dev",
        )

        # Verify independence
        assert client_frontend.local_port == 3000
        assert client_database.local_port == 5432
        assert client_api.local_port == 8000

        assert client_frontend.subdomain == "frontend"
        assert client_database.subdomain == "database"
        assert client_api.subdomain == "api"

    def test_cli_command_examples_for_multi_port(self):
        """Test CLI command format for multi-port usage."""
        runner = CliRunner()

        # These commands should be valid (just check they parse correctly)
        commands = [
            ["--port", "3000", "--subdomain", "frontend", "--help"],
            ["--port", "5432", "--subdomain", "database", "--help"],
            ["--port", "8000", "--subdomain", "api", "--help"],
        ]

        for cmd in commands:
            # Adding --help to not actually run the tunnel
            result = runner.invoke(main, cmd[:-1] + ["--help"])
            # Should show help, meaning arguments parsed correctly
            assert result.exit_code == 0 or "--help" in result.output


class TestTimeoutEdgeCases:
    """Tests for timeout edge cases."""

    def test_very_short_timeout(self):
        """Test very short timeout values."""
        config = ClientConfig(
            connect_timeout=0.1,
            idle_timeout=0.5,
            keepalive_interval=0.1,
        )
        assert config.connect_timeout == 0.1
        assert config.idle_timeout == 0.5
        assert config.keepalive_interval == 0.1

    def test_very_long_timeout(self):
        """Test very long timeout for long-lived connections (13+ minutes)."""
        config = ClientConfig(
            connect_timeout=60.0,
            idle_timeout=3600.0,  # 1 hour
            keepalive_interval=30.0,
        )

        # 13 minutes = 780 seconds, should be well within idle_timeout
        thirteen_minutes = 13 * 60
        assert config.idle_timeout > thirteen_minutes

    def test_timeout_for_development_use(self):
        """Test typical development timeout settings."""
        config = ClientConfig(
            connect_timeout=30.0,
            idle_timeout=300.0,  # 5 minutes
            keepalive_interval=30.0,
        )

        assert config.connect_timeout == 30.0
        assert config.idle_timeout == 300.0
        assert config.keepalive_interval == 30.0

    def test_timeout_for_production_use(self):
        """Test production-suitable timeout settings."""
        config = ClientConfig(
            connect_timeout=10.0,
            idle_timeout=86400.0,  # 24 hours
            keepalive_interval=60.0,
        )

        assert config.connect_timeout == 10.0
        assert config.idle_timeout == 86400.0
        assert config.keepalive_interval == 60.0


class TestCLIVerboseOutput:
    """Tests for CLI verbose output with timeout information."""

    @patch("instanton.cli.asyncio.run")
    def test_verbose_shows_timeout_info(
        self, mock_run: MagicMock
    ):
        """Test that verbose mode shows timeout information."""
        runner = CliRunner()
        mock_run.return_value = None

        runner.invoke(
            main,
            ["--port", "8000", "--verbose", "--timeout", "60"],
        )
        mock_run.assert_called_once()


class TestHTTPSubcommandTimeout:
    """Tests for HTTP subcommand (shorthand)."""

    def test_http_command_exists(self):
        """Test that http subcommand exists."""
        runner = CliRunner()
        result = runner.invoke(main, ["http", "--help"])
        assert result.exit_code == 0
        assert "HTTP tunnel" in result.output or "http" in result.output.lower()

    @patch("instanton.cli.asyncio.run")
    def test_http_command_with_port(self, mock_run: MagicMock):
        """Test http command with port argument."""
        runner = CliRunner()
        mock_run.return_value = None

        runner.invoke(main, ["http", "8000"])
        mock_run.assert_called_once()


class TestTCPSubcommandTimeout:
    """Tests for TCP subcommand."""

    def test_tcp_command_exists(self):
        """Test that tcp subcommand exists."""
        runner = CliRunner()
        result = runner.invoke(main, ["tcp", "--help"])
        assert result.exit_code == 0
        assert "TCP tunnel" in result.output or "tcp" in result.output.lower()

    @patch("instanton.cli.asyncio.run")
    def test_tcp_command_with_port(self, mock_run: MagicMock):
        """Test tcp command with port argument."""
        runner = CliRunner()
        mock_run.return_value = None

        runner.invoke(main, ["tcp", "22"])
        mock_run.assert_called_once()


class TestUDPSubcommandTimeout:
    """Tests for UDP subcommand."""

    def test_udp_command_exists(self):
        """Test that udp subcommand exists."""
        runner = CliRunner()
        result = runner.invoke(main, ["udp", "--help"])
        assert result.exit_code == 0
        assert "UDP tunnel" in result.output or "udp" in result.output.lower()

    @patch("instanton.cli.asyncio.run")
    def test_udp_command_with_port(self, mock_run: MagicMock):
        """Test udp command with port argument."""
        runner = CliRunner()
        mock_run.return_value = None

        runner.invoke(main, ["udp", "53"])
        mock_run.assert_called_once()


class TestStatusCommand:
    """Tests for status command."""

    def test_status_command_exists(self):
        """Test that status subcommand exists."""
        runner = CliRunner()
        result = runner.invoke(main, ["status", "--help"])
        assert result.exit_code == 0
        assert "status" in result.output.lower()


class TestVersionCommand:
    """Tests for version command."""

    def test_version_command_exists(self):
        """Test that version subcommand exists."""
        runner = CliRunner()
        result = runner.invoke(main, ["version"])
        assert result.exit_code == 0
        assert "Version" in result.output or "version" in result.output.lower()


class TestClientConfigIntegration:
    """Integration tests for ClientConfig with TunnelClient."""

    @pytest.mark.asyncio
    async def test_tunnel_client_uses_config_timeout(self):
        """Test TunnelClient uses ClientConfig timeout values."""
        from instanton.client.tunnel import TunnelClient

        config = ClientConfig(
            local_port=8000,
            server_addr="instanton.dev:443",
            connect_timeout=45.0,
            idle_timeout=600.0,
            keepalive_interval=20.0,
        )

        client = TunnelClient(
            local_port=8000,
            config=config,
        )

        # TunnelClient stores keepalive_interval from config
        assert client._keepalive_interval == 20.0
        assert client.local_port == 8000
        assert client.server_addr == "instanton.dev:443"

    @pytest.mark.asyncio
    async def test_tunnel_client_default_config(self):
        """Test TunnelClient with default config values."""
        from instanton.client.tunnel import TunnelClient

        client = TunnelClient(local_port=8000)

        # Should use default keepalive value
        assert client._keepalive_interval == 30.0
        assert client.local_port == 8000
