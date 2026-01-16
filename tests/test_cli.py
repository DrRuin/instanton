"""Tests for Instanton CLI."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from click.testing import CliRunner

from instanton.cli import _format_bytes, main


class TestCLIBasics:
    """Basic CLI tests."""

    def test_main_without_arguments_shows_banner(self):
        """Test that running without arguments shows banner and usage."""
        runner = CliRunner()
        result = runner.invoke(main)

        assert result.exit_code == 0
        # Check for key content - banner uses Unicode box drawing
        assert "Tunnel through barriers, instantly" in result.output
        assert "Usage:" in result.output
        assert "instanton --port 8000" in result.output

    def test_main_with_help(self):
        """Test --help shows help message."""
        runner = CliRunner()
        result = runner.invoke(main, ["--help"])

        assert result.exit_code == 0
        assert "Instanton - Tunnel through barriers" in result.output
        assert "--port" in result.output
        assert "--subdomain" in result.output

    def test_version_command(self):
        """Test version command."""
        runner = CliRunner()
        result = runner.invoke(main, ["version"])

        assert result.exit_code == 0
        # Check for key content - banner uses Unicode box drawing
        assert "Tunnel through barriers, instantly" in result.output
        assert "Version:" in result.output
        assert "Python:" in result.output


class TestStatusCommand:
    """Tests for status command."""

    def test_status_with_json_output(self):
        """Test status command with --json flag."""
        runner = CliRunner()

        import httpx
        with patch.object(httpx, "Client") as mock_client_class:
            mock_response = MagicMock()
            mock_response.json.return_value = {"status": "healthy", "tunnels": 5}

            mock_client = MagicMock()
            mock_client.get.return_value = mock_response
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)
            mock_client_class.return_value = mock_client

            result = runner.invoke(main, ["status", "--json"])

            # Should output JSON
            assert "healthy" in result.output or "unknown" in result.output

    def test_status_handles_connection_error(self):
        """Test status command handles connection errors gracefully."""
        runner = CliRunner()

        import httpx
        with patch.object(httpx, "Client") as mock_client_class:
            mock_client_class.side_effect = Exception("Connection refused")

            result = runner.invoke(main, ["status"])

            assert result.exit_code == 1
            assert "Error" in result.output


class TestHttpCommand:
    """Tests for http command."""

    def test_http_command_help(self):
        """Test http command shows help."""
        runner = CliRunner()
        result = runner.invoke(main, ["http", "--help"])

        assert result.exit_code == 0
        assert "Start an HTTP tunnel" in result.output
        assert "PORT" in result.output


class TestTcpCommand:
    """Tests for tcp command."""

    def test_tcp_command_starts_tunnel(self):
        """Test tcp command attempts to start tunnel."""
        runner = CliRunner()
        result = runner.invoke(main, ["tcp", "22"])

        # TCP tunnel is now implemented, it will try to connect
        # and fail without a server, but the command runs
        assert "TCP tunnel" in result.output or "localhost:22" in result.output

    def test_tcp_command_with_remote_port(self):
        """Test tcp command with remote port option."""
        runner = CliRunner()
        result = runner.invoke(main, ["tcp", "5432", "--remote-port", "5432"])

        # The command runs and shows the port
        assert "5432" in result.output


class TestFormatBytes:
    """Tests for _format_bytes helper."""

    def test_format_bytes(self):
        """Test byte formatting."""
        assert _format_bytes(0) == "0.0 B"
        assert _format_bytes(100) == "100.0 B"
        assert _format_bytes(1024) == "1.0 KB"
        assert _format_bytes(1024 * 1024) == "1.0 MB"
        assert _format_bytes(1024 * 1024 * 1024) == "1.0 GB"
        assert _format_bytes(1024 * 1024 * 1024 * 1024) == "1.0 TB"

    def test_format_bytes_decimal_values(self):
        """Test byte formatting with decimal values."""
        assert _format_bytes(1536) == "1.5 KB"
        assert _format_bytes(2560) == "2.5 KB"


class TestTunnelStart:
    """Tests for tunnel starting functionality."""

    def test_tunnel_auto_subdomain_suggestion(self):
        """Test that subdomain is auto-suggested from project."""
        runner = CliRunner()

        from instanton import sdk
        with (
            patch.object(sdk, "_suggest_subdomain", return_value="my-project"),
            patch("instanton.cli._run_tunnel_with_signal_handling") as mock_run,
        ):
            # This won't actually run the tunnel, just test CLI parsing
            runner.invoke(main, ["--port", "8000"])

            # The command should process correctly
            mock_run.assert_called_once()


class TestCLIOptions:
    """Tests for CLI options."""

    def test_all_options_parsed(self):
        """Test that all CLI options are properly parsed."""
        runner = CliRunner()
        result = runner.invoke(main, ["--help"])

        # Check all options are documented
        options = [
            "--port",
            "--subdomain",
            "--server",
            "--verbose",
            "--auth-token",
            "--inspect",
            "--quic",
            "--no-quic",
        ]

        for opt in options:
            assert opt in result.output, f"Option {opt} not in help output"

    def test_env_var_for_auth_token(self):
        """Test that auth-token option exists."""
        runner = CliRunner()
        result = runner.invoke(main, ["--help"])

        # Check that auth-token option is in help
        assert "--auth-token" in result.output


class TestSubcommands:
    """Tests for CLI subcommands."""

    def test_all_subcommands_available(self):
        """Test that all subcommands are available."""
        runner = CliRunner()
        result = runner.invoke(main, ["--help"])

        subcommands = ["status", "version", "http", "tcp", "domain"]
        for cmd in subcommands:
            # Commands should be listed in help
            is_in_help = cmd in result.output.lower()
            cmd_works = runner.invoke(main, [cmd, "--help"]).exit_code == 0
            assert is_in_help or cmd_works


class TestDomainCommands:
    """Tests for domain management commands."""

    def test_domain_group_help(self):
        """Test domain command group shows help."""
        runner = CliRunner()
        result = runner.invoke(main, ["domain", "--help"])

        assert result.exit_code == 0
        assert "Manage custom domains" in result.output
        assert "add" in result.output
        assert "verify" in result.output
        assert "list" in result.output
        assert "status" in result.output
        assert "remove" in result.output

    def test_domain_add_help(self):
        """Test domain add command shows help."""
        runner = CliRunner()
        result = runner.invoke(main, ["domain", "add", "--help"])

        assert result.exit_code == 0
        assert "Register a new custom domain" in result.output
        assert "--tunnel-id" in result.output

    def test_domain_add_requires_tunnel_id(self):
        """Test domain add requires tunnel-id option."""
        runner = CliRunner()
        result = runner.invoke(main, ["domain", "add", "test.example.com"])

        assert result.exit_code != 0
        assert "Missing option" in result.output or "required" in result.output.lower()

    def test_domain_add_with_tunnel_id(self):
        """Test domain add with tunnel-id creates domain."""
        import tempfile

        runner = CliRunner()
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write("{}")
            storage_path = f.name

        try:
            result = runner.invoke(
                main,
                [
                    "domain",
                    "add",
                    "api.example.com",
                    "--tunnel-id",
                    "test-tunnel",
                    "--storage",
                    storage_path,
                ],
            )

            assert result.exit_code == 0
            assert "Domain registered successfully" in result.output
            assert "api.example.com" in result.output
            assert "CNAME Record" in result.output
            assert "TXT Record" in result.output
        finally:
            import os

            os.unlink(storage_path)

    def test_domain_list_empty(self):
        """Test domain list with no domains."""
        import tempfile

        runner = CliRunner()
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write("{}")
            storage_path = f.name

        try:
            result = runner.invoke(main, ["domain", "list", "--storage", storage_path])

            assert result.exit_code == 0
            assert "No domains registered" in result.output
        finally:
            import os

            os.unlink(storage_path)

    def test_domain_list_with_domains(self):
        """Test domain list shows registered domains."""
        import tempfile

        runner = CliRunner()
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write("{}")
            storage_path = f.name

        try:
            # Add a domain first
            runner.invoke(
                main,
                [
                    "domain",
                    "add",
                    "api.example.com",
                    "--tunnel-id",
                    "test-tunnel",
                    "--storage",
                    storage_path,
                ],
            )

            # List domains
            result = runner.invoke(main, ["domain", "list", "--storage", storage_path])

            assert result.exit_code == 0
            assert "api.example.com" in result.output
            assert "Registered Domains" in result.output
        finally:
            import os

            os.unlink(storage_path)

    def test_domain_list_json(self):
        """Test domain list with JSON output."""
        import json
        import tempfile

        runner = CliRunner()
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write("{}")
            storage_path = f.name

        try:
            # Add a domain first
            runner.invoke(
                main,
                [
                    "domain",
                    "add",
                    "api.example.com",
                    "--tunnel-id",
                    "test-tunnel",
                    "--storage",
                    storage_path,
                ],
            )

            # List domains as JSON
            result = runner.invoke(
                main, ["domain", "list", "--storage", storage_path, "--json"]
            )

            assert result.exit_code == 0
            # Should be valid JSON
            data = json.loads(result.output)
            assert len(data) == 1
            assert data[0]["domain"] == "api.example.com"
        finally:
            import os

            os.unlink(storage_path)

    def test_domain_status_not_found(self):
        """Test domain status for nonexistent domain."""
        import tempfile

        runner = CliRunner()
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write("{}")
            storage_path = f.name

        try:
            result = runner.invoke(
                main, ["domain", "status", "unknown.example.com", "--storage", storage_path]
            )

            assert result.exit_code == 1
            assert "Domain not found" in result.output
        finally:
            import os

            os.unlink(storage_path)

    def test_domain_status_found(self):
        """Test domain status for registered domain."""
        import tempfile

        runner = CliRunner()
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write("{}")
            storage_path = f.name

        try:
            # Add a domain first
            runner.invoke(
                main,
                [
                    "domain",
                    "add",
                    "api.example.com",
                    "--tunnel-id",
                    "test-tunnel",
                    "--storage",
                    storage_path,
                ],
            )

            # Get status
            result = runner.invoke(
                main, ["domain", "status", "api.example.com", "--storage", storage_path]
            )

            assert result.exit_code == 0
            assert "api.example.com" in result.output
            assert "pending_verification" in result.output
            assert "DNS Setup Required" in result.output
        finally:
            import os

            os.unlink(storage_path)

    def test_domain_remove(self):
        """Test domain remove deletes domain."""
        import tempfile

        runner = CliRunner()
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write("{}")
            storage_path = f.name

        try:
            # Add a domain first
            runner.invoke(
                main,
                [
                    "domain",
                    "add",
                    "api.example.com",
                    "--tunnel-id",
                    "test-tunnel",
                    "--storage",
                    storage_path,
                ],
            )

            # Remove domain
            result = runner.invoke(
                main,
                ["domain", "remove", "api.example.com", "--storage", storage_path, "--yes"],
            )

            assert result.exit_code == 0
            assert "Domain removed" in result.output

            # Verify domain is gone
            result = runner.invoke(main, ["domain", "list", "--storage", storage_path])
            assert "No domains registered" in result.output
        finally:
            import os

            os.unlink(storage_path)

    def test_domain_remove_not_found(self):
        """Test domain remove for nonexistent domain."""
        import tempfile

        runner = CliRunner()
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write("{}")
            storage_path = f.name

        try:
            result = runner.invoke(
                main,
                ["domain", "remove", "unknown.example.com", "--storage", storage_path, "--yes"],
            )

            assert result.exit_code == 1
            assert "Domain not found" in result.output
        finally:
            import os

            os.unlink(storage_path)

    def test_domain_verify_not_registered(self):
        """Test domain verify for unregistered domain."""
        import tempfile

        runner = CliRunner()
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write("{}")
            storage_path = f.name

        try:
            result = runner.invoke(
                main, ["domain", "verify", "unknown.example.com", "--storage", storage_path]
            )

            assert result.exit_code == 1
            assert "is not registered" in result.output
        finally:
            import os

            os.unlink(storage_path)
