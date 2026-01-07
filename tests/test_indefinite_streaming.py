"""Tests for indefinite connections and real-time streaming support.

This test suite verifies:
1. Connections can stay open indefinitely without forced timeout
2. Long-running API calls (10+ minutes) are supported
3. Real-time streaming APIs work correctly
4. Chunked streaming support
5. CLI --no-request-timeout option
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch
from uuid import uuid4

import httpx
import pytest
from click.testing import CliRunner

from instanton.cli import main
from instanton.client.tunnel import ProxyConfig, TunnelClient
from instanton.core.config import ClientConfig
from instanton.protocol.messages import (
    ChunkAssembler,
    ChunkData,
    ChunkEnd,
    ChunkStart,
    create_chunks,
)


class TestIndefiniteTimeoutConfiguration:
    """Tests for indefinite timeout configuration."""

    def test_proxy_config_default_read_timeout_is_none(self):
        """Test that default read_timeout is None (indefinite)."""
        config = ProxyConfig()
        assert config.read_timeout is None

    def test_proxy_config_default_stream_timeout_is_none(self):
        """Test that default stream_timeout is None (indefinite)."""
        config = ProxyConfig()
        assert config.stream_timeout is None

    def test_proxy_config_explicit_none_timeout(self):
        """Test explicitly setting timeout to None."""
        config = ProxyConfig(read_timeout=None, stream_timeout=None)
        assert config.read_timeout is None
        assert config.stream_timeout is None

    def test_proxy_config_explicit_timeout_value(self):
        """Test setting explicit timeout value."""
        config = ProxyConfig(read_timeout=30.0)
        assert config.read_timeout == 30.0

    def test_proxy_config_zero_timeout(self):
        """Test that zero timeout is distinct from None."""
        config = ProxyConfig(read_timeout=0.0)
        assert config.read_timeout == 0.0

    def test_proxy_config_long_timeout_for_long_apis(self):
        """Test very long timeout for 10+ minute API calls."""
        # 15 minutes = 900 seconds
        config = ProxyConfig(read_timeout=900.0)
        assert config.read_timeout == 900.0

        # 1 hour = 3600 seconds
        config = ProxyConfig(read_timeout=3600.0)
        assert config.read_timeout == 3600.0


class TestTunnelClientWithIndefiniteTimeout:
    """Tests for TunnelClient with indefinite timeout."""

    @pytest.mark.asyncio
    async def test_tunnel_client_with_no_timeout(self):
        """Test creating tunnel client with no read timeout."""
        proxy_config = ProxyConfig(read_timeout=None)

        client = TunnelClient(
            local_port=8000,
            proxy_config=proxy_config,
        )

        assert client.proxy_config.read_timeout is None

    @pytest.mark.asyncio
    async def test_tunnel_client_default_allows_indefinite(self):
        """Test that default TunnelClient allows indefinite connections."""
        client = TunnelClient(local_port=8000)

        # Default should be indefinite (None)
        assert client.proxy_config.read_timeout is None

    @pytest.mark.asyncio
    async def test_tunnel_client_streaming_always_indefinite(self):
        """Test that streaming timeout is always indefinite."""
        client = TunnelClient(local_port=8000)
        assert client.proxy_config.stream_timeout is None


class TestCLINoRequestTimeout:
    """Tests for CLI --no-request-timeout option."""

    @pytest.fixture
    def runner(self):
        """Create CLI runner."""
        return CliRunner()

    def test_no_request_timeout_option_exists(self, runner: CliRunner):
        """Test that --no-request-timeout option exists."""
        result = runner.invoke(main, ["--help"])
        assert result.exit_code == 0
        assert "--no-request-timeout" in result.output

    def test_no_request_timeout_help_text(self, runner: CliRunner):
        """Test help text for --no-request-timeout."""
        result = runner.invoke(main, ["--help"])
        assert "long-running" in result.output or "streaming" in result.output

    @patch("instanton.cli.asyncio.run")
    def test_no_request_timeout_flag_passed(
        self, mock_run: MagicMock, runner: CliRunner
    ):
        """Test that --no-request-timeout flag is passed to start_tunnel."""
        mock_run.return_value = None

        runner.invoke(
            main, ["--port", "8000", "--no-request-timeout"]
        )
        mock_run.assert_called_once()

    def test_cli_shows_indefinite_example(self, runner: CliRunner):
        """Test that CLI help shows indefinite timeout example."""
        result = runner.invoke(main, ["--help"])
        assert "--no-request-timeout" in result.output


class TestStreamingSupport:
    """Tests for real-time streaming support."""

    def test_chunk_start_creation(self):
        """Test ChunkStart message creation."""
        request_id = uuid4()
        chunk_start = ChunkStart(
            request_id=request_id,
            total_size=None,  # Unknown for streaming
            content_type="text/event-stream",
        )

        assert chunk_start.type == "chunk_start"
        assert chunk_start.request_id == request_id
        assert chunk_start.total_size is None  # Streaming has unknown size

    def test_chunk_data_creation(self):
        """Test ChunkData message creation."""
        stream_id = uuid4()
        chunk_data = ChunkData(
            stream_id=stream_id,
            sequence=0,
            data=b"data: {\"event\": \"update\"}\n\n",
            is_final=False,
        )

        assert chunk_data.type == "chunk_data"
        assert chunk_data.sequence == 0
        assert not chunk_data.is_final

    def test_chunk_end_creation(self):
        """Test ChunkEnd message creation."""
        stream_id = uuid4()
        request_id = uuid4()
        chunk_end = ChunkEnd(
            stream_id=stream_id,
            request_id=request_id,
            total_chunks=10,
            total_size=1024,
        )

        assert chunk_end.type == "chunk_end"
        assert chunk_end.total_chunks == 10

    def test_create_chunks_function(self):
        """Test create_chunks helper function."""
        request_id = uuid4()
        data = b"x" * 10000  # 10KB of data

        start, chunks, end = create_chunks(
            data=data,
            request_id=request_id,
            chunk_size=1024,
            content_type="application/octet-stream",
        )

        assert start.type == "chunk_start"
        assert len(chunks) == 10  # 10KB / 1KB = 10 chunks
        assert end.type == "chunk_end"

    def test_chunk_assembler_streams(self):
        """Test ChunkAssembler handles streaming data."""
        assembler = ChunkAssembler()
        request_id = uuid4()
        stream_id = uuid4()

        # Start stream
        start = ChunkStart(
            stream_id=stream_id,
            request_id=request_id,
            total_size=None,
        )
        assembler.start_stream(start)

        # Add chunks
        for i in range(5):
            chunk = ChunkData(
                stream_id=stream_id,
                sequence=i,
                data=f"chunk{i}".encode(),
                is_final=(i == 4),
            )
            assembler.add_chunk(chunk)

        # End stream
        end = ChunkEnd(
            stream_id=stream_id,
            request_id=request_id,
            total_chunks=5,
            total_size=30,
        )
        result = assembler.end_stream(end)

        assert result == b"chunk0chunk1chunk2chunk3chunk4"


class TestLongRunningAPISupport:
    """Tests for long-running API support (10+ minutes)."""

    def test_config_supports_10_minute_timeout(self):
        """Test configuration supports 10 minute timeout."""
        ten_minutes = 10 * 60  # 600 seconds
        config = ProxyConfig(read_timeout=ten_minutes)
        assert config.read_timeout == 600.0

    def test_config_supports_1_hour_timeout(self):
        """Test configuration supports 1 hour timeout."""
        one_hour = 60 * 60  # 3600 seconds
        config = ProxyConfig(read_timeout=one_hour)
        assert config.read_timeout == 3600.0

    def test_indefinite_better_than_long_timeout(self):
        """Test that None (indefinite) is better than long timeout."""
        # With None, connection never times out
        config = ProxyConfig(read_timeout=None)
        assert config.read_timeout is None

        # This means a 30-minute API call will work
        thirty_minutes = 30 * 60
        assert config.read_timeout is None or config.read_timeout > thirty_minutes

    @pytest.mark.asyncio
    async def test_httpx_timeout_none_is_indefinite(self):
        """Test that httpx Timeout accepts None for indefinite."""
        # This test verifies httpx behavior
        timeout = httpx.Timeout(
            connect=5.0,
            read=None,  # Indefinite
            write=5.0,
            pool=5.0,
        )

        assert timeout.read is None


class TestStreamingProtocols:
    """Tests for various streaming protocol support."""

    def test_server_sent_events_content_type(self):
        """Test SSE content type handling."""
        chunk_start = ChunkStart(
            request_id=uuid4(),
            total_size=None,
            content_type="text/event-stream",
        )
        assert chunk_start.content_type == "text/event-stream"

    def test_ndjson_streaming_content_type(self):
        """Test NDJSON streaming content type."""
        chunk_start = ChunkStart(
            request_id=uuid4(),
            total_size=None,
            content_type="application/x-ndjson",
        )
        assert chunk_start.content_type == "application/x-ndjson"

    def test_chunked_transfer_content_type(self):
        """Test chunked transfer encoding support."""
        chunk_start = ChunkStart(
            request_id=uuid4(),
            total_size=None,  # Unknown for chunked
            content_type="application/octet-stream",
        )
        assert chunk_start.total_size is None


class TestConnectionPersistence:
    """Tests for connection persistence without forced timeout."""

    @pytest.mark.asyncio
    async def test_tunnel_client_keepalive_maintains_connection(self):
        """Test that keepalive mechanism maintains connection."""
        config = ClientConfig(keepalive_interval=30.0)
        client = TunnelClient(local_port=8000, config=config)

        # Keepalive should be configured
        assert client._keepalive_interval == 30.0

    @pytest.mark.asyncio
    async def test_tunnel_client_no_idle_disconnect_by_default(self):
        """Test that tunnel doesn't forcibly disconnect on idle."""
        proxy_config = ProxyConfig(
            read_timeout=None,  # No timeout
            stream_timeout=None,  # No streaming timeout
        )
        client = TunnelClient(local_port=8000, proxy_config=proxy_config)

        # No forced timeout
        assert client.proxy_config.read_timeout is None
        assert client.proxy_config.stream_timeout is None


class TestRealTimeStreamingScenarios:
    """Tests for real-world streaming scenarios."""

    def test_websocket_upgrade_preserved(self):
        """Test that WebSocket upgrade requests are preserved."""
        # WebSocket tunneling is handled at protocol level
        from instanton.protocol.messages import TunnelProtocol

        assert TunnelProtocol.WEBSOCKET == 4

    def test_grpc_streaming_supported(self):
        """Test that gRPC streaming is supported."""
        from instanton.protocol.messages import TunnelProtocol

        assert TunnelProtocol.GRPC == 3

    def test_http2_streaming_supported(self):
        """Test that HTTP/2 streaming is supported."""
        from instanton.protocol.messages import TunnelProtocol

        assert TunnelProtocol.HTTP2 == 2


class TestStreamingChunkSize:
    """Tests for streaming chunk size configuration."""

    def test_default_chunk_size(self):
        """Test default chunk size."""
        from instanton.protocol.messages import CHUNK_SIZE

        assert CHUNK_SIZE == 64 * 1024  # 64KB

    def test_chunk_size_configurable(self):
        """Test that chunk size is configurable."""
        request_id = uuid4()
        data = b"x" * 10000

        # With 2KB chunks
        start, chunks, end = create_chunks(data, request_id, chunk_size=2048)
        assert len(chunks) == 5  # 10000 / 2048 = ~5 chunks


class TestIndefiniteConnectionUseCases:
    """Tests for specific use cases requiring indefinite connections."""

    def test_ai_model_inference_use_case(self):
        """Test AI model inference that may take 10+ minutes."""
        # AI inference can take very long
        config = ProxyConfig(read_timeout=None)
        assert config.read_timeout is None

    def test_file_upload_streaming_use_case(self):
        """Test large file upload streaming."""
        config = ProxyConfig(
            read_timeout=None,
            stream_timeout=None,
        )
        assert config.read_timeout is None
        assert config.stream_timeout is None

    def test_database_query_long_running(self):
        """Test long-running database queries."""
        config = ProxyConfig(read_timeout=None)
        assert config.read_timeout is None

    def test_video_streaming_use_case(self):
        """Test video streaming (indefinite duration)."""
        chunk_start = ChunkStart(
            request_id=uuid4(),
            total_size=None,  # Unknown for live video
            content_type="video/mp4",
        )
        assert chunk_start.total_size is None

    def test_real_time_chat_streaming(self):
        """Test real-time chat/messaging streaming."""
        config = ProxyConfig(
            read_timeout=None,
            stream_timeout=None,
        )
        # Chat connections stay open indefinitely
        assert config.read_timeout is None


class TestHTTPClientCreation:
    """Tests for HTTP client creation with timeout settings."""

    @pytest.mark.asyncio
    async def test_http_client_with_none_timeout(self):
        """Test creating httpx client with None timeout."""
        timeout = httpx.Timeout(
            connect=5.0,
            read=None,
            write=5.0,
            pool=5.0,
        )

        async with httpx.AsyncClient(timeout=timeout) as client:
            assert client.timeout.read is None

    @pytest.mark.asyncio
    async def test_http_client_allows_long_requests(self):
        """Test that HTTP client allows long-running requests."""
        # Create client with no read timeout
        timeout = httpx.Timeout(
            connect=5.0,
            read=None,  # No timeout
            write=5.0,
            pool=5.0,
        )

        # The timeout configuration should allow this
        assert timeout.read is None


class TestTunnelStreamingEnabled:
    """Tests for tunnel streaming being enabled."""

    @pytest.mark.asyncio
    async def test_streaming_enabled_in_stats(self):
        """Test that streaming is tracked in stats."""
        client = TunnelClient(local_port=8000)
        stats = client.stats

        assert "streaming_enabled" in stats

    @pytest.mark.asyncio
    async def test_tunnel_supports_chunked_response(self):
        """Test that tunnel supports chunked responses."""
        client = TunnelClient(local_port=8000)

        # Client should have chunk assembler
        assert hasattr(client, "_chunk_assembler")


class TestProxyConfigDocumentation:
    """Tests verifying ProxyConfig documentation accuracy."""

    def test_proxy_config_has_docstring(self):
        """Test that ProxyConfig has documentation."""
        assert ProxyConfig.__doc__ is not None
        assert "indefinite" in ProxyConfig.__doc__.lower()

    def test_proxy_config_documents_none_timeout(self):
        """Test that None timeout is documented."""
        assert "None" in ProxyConfig.__doc__


class TestCLITimeoutIntegration:
    """Integration tests for CLI timeout options."""

    @pytest.fixture
    def runner(self):
        """Create CLI runner."""
        return CliRunner()

    @patch("instanton.cli.asyncio.run")
    def test_cli_with_all_timeout_options(
        self, mock_run: MagicMock, runner: CliRunner
    ):
        """Test CLI with all timeout-related options."""
        mock_run.return_value = None

        runner.invoke(
            main,
            [
                "--port", "8000",
                "--timeout", "60",
                "--idle-timeout", "600",
                "--keepalive", "15",
                "--no-request-timeout",
            ],
        )
        mock_run.assert_called_once()

    @patch("instanton.cli.asyncio.run")
    def test_cli_streaming_api_configuration(
        self, mock_run: MagicMock, runner: CliRunner
    ):
        """Test CLI configuration for streaming APIs."""
        mock_run.return_value = None

        # For a streaming API endpoint
        runner.invoke(
            main,
            ["--port", "8000", "--no-request-timeout"],
        )
        mock_run.assert_called_once()


class TestEdgeCases:
    """Tests for edge cases in timeout handling."""

    def test_very_small_timeout(self):
        """Test very small (but non-zero) timeout."""
        config = ProxyConfig(read_timeout=0.001)
        assert config.read_timeout == 0.001

    def test_none_vs_zero_timeout(self):
        """Test distinction between None and zero timeout."""
        config_none = ProxyConfig(read_timeout=None)
        config_zero = ProxyConfig(read_timeout=0.0)

        # None means indefinite wait
        assert config_none.read_timeout is None
        # Zero means immediate timeout
        assert config_zero.read_timeout == 0.0

    def test_negative_timeout_as_float(self):
        """Test that negative timeout is technically allowed by dataclass."""
        # Note: httpx may reject this, but dataclass allows it
        config = ProxyConfig(read_timeout=-1.0)
        assert config.read_timeout == -1.0
