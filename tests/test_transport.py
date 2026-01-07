"""Tests for WebSocket and QUIC transport with reconnection and heartbeat."""

import asyncio
import contextlib
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from instanton.core.transport import (
    ConnectionState,
    QuicClientProtocol,
    QuicServer,
    QuicStreamHandler,
    QuicTransport,
    QuicTransportConfig,
    StreamError,
    TransportConnectionError,
    TransportStats,
    WebSocketTransport,
)


class TestWebSocketTransportInit:
    """Tests for WebSocketTransport initialization."""

    def test_default_initialization(self):
        """Test default parameter values."""
        transport = WebSocketTransport()

        assert transport._auto_reconnect is True
        assert transport._max_reconnect_attempts == 10
        assert transport._reconnect_delay == 1.0
        assert transport._max_reconnect_delay == 60.0
        assert transport._ping_interval == 30.0
        assert transport._ping_timeout == 10.0
        assert transport._connect_timeout == 10.0
        assert transport._state == ConnectionState.DISCONNECTED
        assert transport._ws is None
        assert transport._shutdown is False

    def test_custom_initialization(self):
        """Test custom parameter values."""
        transport = WebSocketTransport(
            auto_reconnect=False,
            max_reconnect_attempts=5,
            reconnect_delay=2.0,
            max_reconnect_delay=30.0,
            ping_interval=15.0,
            ping_timeout=5.0,
            connect_timeout=20.0,
        )

        assert transport._auto_reconnect is False
        assert transport._max_reconnect_attempts == 5
        assert transport._reconnect_delay == 2.0
        assert transport._max_reconnect_delay == 30.0
        assert transport._ping_interval == 15.0
        assert transport._ping_timeout == 5.0
        assert transport._connect_timeout == 20.0


class TestConnectionState:
    """Tests for ConnectionState enum."""

    def test_state_values(self):
        """Test state enum values."""
        assert ConnectionState.DISCONNECTED.value == "disconnected"
        assert ConnectionState.CONNECTING.value == "connecting"
        assert ConnectionState.CONNECTED.value == "connected"
        assert ConnectionState.RECONNECTING.value == "reconnecting"
        assert ConnectionState.CLOSED.value == "closed"


class TestTransportStats:
    """Tests for TransportStats dataclass."""

    def test_default_stats(self):
        """Test default stats values."""
        stats = TransportStats()

        assert stats.bytes_sent == 0
        assert stats.bytes_received == 0
        assert stats.messages_sent == 0
        assert stats.messages_received == 0
        assert stats.reconnect_count == 0
        assert stats.last_ping_latency == 0.0
        assert stats.connection_start_time == 0.0

    def test_stats_modification(self):
        """Test stats can be modified."""
        stats = TransportStats()
        stats.bytes_sent = 100
        stats.messages_sent = 5

        assert stats.bytes_sent == 100
        assert stats.messages_sent == 5


class TestBuildUrl:
    """Tests for URL building."""

    def test_full_wss_url(self):
        """Test full WSS URL passthrough."""
        transport = WebSocketTransport()
        url = transport._build_url("wss://example.com/ws")
        assert url == "wss://example.com/ws"

    def test_full_ws_url(self):
        """Test full WS URL passthrough."""
        transport = WebSocketTransport()
        url = transport._build_url("ws://localhost:8080/ws")
        assert url == "ws://localhost:8080/ws"

    def test_host_port(self):
        """Test host:port format."""
        transport = WebSocketTransport()
        url = transport._build_url("example.com:443")
        assert url == "wss://example.com:443/tunnel"

    def test_host_only(self):
        """Test host only format."""
        transport = WebSocketTransport()
        url = transport._build_url("example.com")
        assert url == "wss://example.com:443/tunnel"


class TestCallbacks:
    """Tests for callback registration and firing."""

    def test_register_callbacks(self):
        """Test callback registration."""
        transport = WebSocketTransport()

        connect_cb = MagicMock()
        disconnect_cb = MagicMock()
        reconnect_cb = MagicMock()

        transport.on_connect(connect_cb)
        transport.on_disconnect(disconnect_cb)
        transport.on_reconnect(reconnect_cb)

        assert connect_cb in transport._on_connect
        assert disconnect_cb in transport._on_disconnect
        assert reconnect_cb in transport._on_reconnect

    @pytest.mark.asyncio
    async def test_fire_sync_callbacks(self):
        """Test firing synchronous callbacks."""
        transport = WebSocketTransport()

        called = []

        def cb1():
            called.append("cb1")

        def cb2():
            called.append("cb2")

        await transport._fire_callbacks([cb1, cb2])

        assert called == ["cb1", "cb2"]

    @pytest.mark.asyncio
    async def test_fire_async_callbacks(self):
        """Test firing async callbacks."""
        transport = WebSocketTransport()

        called = []

        async def cb1():
            called.append("async_cb1")

        async def cb2():
            called.append("async_cb2")

        await transport._fire_callbacks([cb1, cb2])

        assert called == ["async_cb1", "async_cb2"]

    @pytest.mark.asyncio
    async def test_callback_error_handling(self):
        """Test that callback errors don't stop other callbacks."""
        transport = WebSocketTransport()

        called = []

        def cb1():
            called.append("cb1")

        def cb_error():
            raise ValueError("Test error")

        def cb2():
            called.append("cb2")

        await transport._fire_callbacks([cb1, cb_error, cb2])

        assert "cb1" in called
        assert "cb2" in called


class TestWebSocketConnect:
    """Tests for WebSocket connection."""

    @pytest.mark.asyncio
    async def test_connect_success(self):
        """Test successful connection."""
        transport = WebSocketTransport(ping_interval=300)  # Long interval to avoid heartbeat

        mock_ws = AsyncMock()
        mock_ws.ping = AsyncMock(return_value=asyncio.Future())
        mock_ws.ping.return_value.set_result(None)

        with patch(
            "instanton.core.transport.connect",
            return_value=mock_ws,
        ) as mock_connect:
            # Make mock_connect awaitable
            async def mock_connect_coro(*args, **kwargs):
                return mock_ws

            mock_connect.side_effect = mock_connect_coro

            await transport.connect("wss://example.com/ws")

            assert transport._state == ConnectionState.CONNECTED
            assert transport._ws is mock_ws
            assert transport._addr == "wss://example.com/ws"

        # Clean up
        transport._shutdown = True
        if transport._heartbeat_task:
            transport._heartbeat_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await transport._heartbeat_task

    @pytest.mark.asyncio
    async def test_connect_timeout(self):
        """Test connection timeout."""
        transport = WebSocketTransport(connect_timeout=0.1)

        async def slow_connect(*args, **kwargs):
            await asyncio.sleep(10)

        with patch(
            "instanton.core.transport.connect",
            side_effect=slow_connect,
        ):
            with pytest.raises(TransportConnectionError, match="timeout"):
                await transport.connect("wss://example.com/ws")

            assert transport._state == ConnectionState.DISCONNECTED

    @pytest.mark.asyncio
    async def test_connect_failure(self):
        """Test connection failure."""
        transport = WebSocketTransport()

        async def failed_connect(*args, **kwargs):
            raise OSError("Connection refused")

        with patch(
            "instanton.core.transport.connect",
            side_effect=failed_connect,
        ):
            with pytest.raises(TransportConnectionError, match="Failed to connect"):
                await transport.connect("wss://example.com/ws")

            assert transport._state == ConnectionState.DISCONNECTED


class TestWebSocketSendRecv:
    """Tests for send and receive operations."""

    @pytest.mark.asyncio
    async def test_send_success(self):
        """Test successful send."""
        transport = WebSocketTransport()
        transport._state = ConnectionState.CONNECTED
        transport._ws = AsyncMock()

        data = b"test data"
        await transport.send(data)

        transport._ws.send.assert_called_once_with(data)
        assert transport._stats.bytes_sent == len(data)
        assert transport._stats.messages_sent == 1

    @pytest.mark.asyncio
    async def test_send_not_connected(self):
        """Test send when not connected."""
        transport = WebSocketTransport()
        transport._state = ConnectionState.DISCONNECTED

        with pytest.raises(TransportConnectionError, match="Not connected"):
            await transport.send(b"test")

    @pytest.mark.asyncio
    async def test_recv_success_bytes(self):
        """Test successful receive of bytes."""
        transport = WebSocketTransport()
        transport._state = ConnectionState.CONNECTED
        transport._ws = AsyncMock()
        transport._ws.recv.return_value = b"response data"

        data = await transport.recv()

        assert data == b"response data"
        assert transport._stats.bytes_received == len(b"response data")
        assert transport._stats.messages_received == 1

    @pytest.mark.asyncio
    async def test_recv_success_string(self):
        """Test successful receive of string (converted to bytes)."""
        transport = WebSocketTransport()
        transport._state = ConnectionState.CONNECTED
        transport._ws = AsyncMock()
        transport._ws.recv.return_value = "string response"

        data = await transport.recv()

        assert data == b"string response"

    @pytest.mark.asyncio
    async def test_recv_no_websocket(self):
        """Test recv with no WebSocket."""
        transport = WebSocketTransport()
        transport._ws = None

        data = await transport.recv()

        assert data is None


class TestWebSocketClose:
    """Tests for close operation."""

    @pytest.mark.asyncio
    async def test_close_success(self):
        """Test successful close."""
        transport = WebSocketTransport()
        transport._state = ConnectionState.CONNECTED
        mock_ws = AsyncMock()
        transport._ws = mock_ws

        await transport.close()

        assert transport._state == ConnectionState.CLOSED
        assert transport._shutdown is True
        assert transport._ws is None  # WebSocket is set to None after close
        mock_ws.close.assert_called_once()

    @pytest.mark.asyncio
    async def test_close_no_websocket(self):
        """Test close with no WebSocket."""
        transport = WebSocketTransport()
        transport._ws = None

        await transport.close()

        assert transport._state == ConnectionState.CLOSED
        assert transport._shutdown is True


class TestStateAndStats:
    """Tests for state and stats methods."""

    def test_is_connected_true(self):
        """Test is_connected returns True when connected."""
        transport = WebSocketTransport()
        transport._state = ConnectionState.CONNECTED
        transport._ws = MagicMock()

        assert transport.is_connected() is True

    def test_is_connected_false_wrong_state(self):
        """Test is_connected returns False when not connected."""
        transport = WebSocketTransport()
        transport._state = ConnectionState.DISCONNECTED
        transport._ws = MagicMock()

        assert transport.is_connected() is False

    def test_is_connected_false_no_ws(self):
        """Test is_connected returns False when no WebSocket."""
        transport = WebSocketTransport()
        transport._state = ConnectionState.CONNECTED
        transport._ws = None

        assert transport.is_connected() is False

    def test_get_state(self):
        """Test get_state returns current state."""
        transport = WebSocketTransport()
        transport._state = ConnectionState.RECONNECTING

        assert transport.get_state() == ConnectionState.RECONNECTING

    def test_get_stats(self):
        """Test get_stats returns stats object."""
        transport = WebSocketTransport()
        transport._stats.bytes_sent = 100

        stats = transport.get_stats()

        assert stats.bytes_sent == 100
        assert isinstance(stats, TransportStats)


class TestReconnection:
    """Tests for reconnection logic."""

    @pytest.mark.asyncio
    async def test_reconnect_exponential_backoff(self):
        """Test exponential backoff delay calculation."""
        transport = WebSocketTransport(
            reconnect_delay=1.0,
            max_reconnect_delay=10.0,
            max_reconnect_attempts=5,
        )
        transport._addr = "example.com"

        # First attempt: 1.0 * 2^0 = 1.0
        # Second attempt: 1.0 * 2^1 = 2.0
        # Third attempt: 1.0 * 2^2 = 4.0
        # Fourth attempt: 1.0 * 2^3 = 8.0
        # Fifth attempt: 1.0 * 2^4 = 16.0 -> capped at 10.0

        delays = []
        for i in range(1, 6):
            delay = min(
                transport._reconnect_delay * (2 ** (i - 1)),
                transport._max_reconnect_delay,
            )
            delays.append(delay)

        assert delays == [1.0, 2.0, 4.0, 8.0, 10.0]

    @pytest.mark.asyncio
    async def test_max_reconnect_attempts(self):
        """Test that reconnection stops after max attempts."""
        transport = WebSocketTransport(
            max_reconnect_attempts=2,
            reconnect_delay=0.01,  # Fast for testing
            auto_reconnect=True,
        )
        transport._addr = "example.com"

        async def failed_connect(*args, **kwargs):
            raise OSError("Connection refused")

        with patch(
            "instanton.core.transport.connect",
            side_effect=failed_connect,
        ), patch("asyncio.sleep", new_callable=AsyncMock):
            await transport._reconnect()

        assert transport._state == ConnectionState.CLOSED
        assert transport._current_reconnect_attempt > transport._max_reconnect_attempts

    @pytest.mark.asyncio
    async def test_reconnect_success(self):
        """Test successful reconnection."""
        transport = WebSocketTransport(
            reconnect_delay=0.01,
            ping_interval=300,  # Long interval
        )
        transport._addr = "example.com"

        mock_ws = AsyncMock()
        call_count = 0

        async def connect_after_failure(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count < 2:
                raise OSError("Connection refused")
            return mock_ws

        with patch(
            "instanton.core.transport.connect",
            side_effect=connect_after_failure,
        ), patch("asyncio.sleep", new_callable=AsyncMock):
            await transport._reconnect()

        assert transport._state == ConnectionState.CONNECTED
        assert transport._stats.reconnect_count == 1

        # Clean up
        transport._shutdown = True
        if transport._heartbeat_task:
            transport._heartbeat_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await transport._heartbeat_task


class TestHeartbeat:
    """Tests for heartbeat functionality."""

    @pytest.mark.asyncio
    async def test_heartbeat_start_stop(self):
        """Test heartbeat task start and stop."""
        transport = WebSocketTransport(ping_interval=300)
        transport._state = ConnectionState.CONNECTED
        transport._ws = AsyncMock()

        # Start heartbeat
        transport._start_heartbeat()
        assert transport._heartbeat_task is not None

        # Stop heartbeat
        transport._stop_heartbeat()
        assert transport._heartbeat_task is None

    @pytest.mark.asyncio
    async def test_heartbeat_sends_ping(self):
        """Test that heartbeat sends pings."""
        transport = WebSocketTransport(ping_interval=0.05, ping_timeout=1.0)
        transport._state = ConnectionState.CONNECTED

        ping_called = asyncio.Event()
        pong_future = asyncio.Future()
        pong_future.set_result(None)

        mock_ws = AsyncMock()

        async def mock_ping(*args, **kwargs):
            ping_called.set()
            return pong_future

        mock_ws.ping = mock_ping
        transport._ws = mock_ws

        # Start heartbeat
        transport._start_heartbeat()

        # Wait for ping
        import contextlib
        with contextlib.suppress(TimeoutError):
            await asyncio.wait_for(ping_called.wait(), timeout=1.0)

        # Stop heartbeat
        transport._shutdown = True
        transport._stop_heartbeat()

        # Ping should have been called
        assert ping_called.is_set()


class TestHandleDisconnect:
    """Tests for disconnect handling."""

    @pytest.mark.asyncio
    async def test_handle_disconnect_fires_callbacks(self):
        """Test that disconnect fires callbacks."""
        transport = WebSocketTransport(auto_reconnect=False)
        transport._state = ConnectionState.CONNECTED

        disconnected = False

        def on_disconnect():
            nonlocal disconnected
            disconnected = True

        transport.on_disconnect(on_disconnect)

        await transport._handle_disconnect()

        assert disconnected
        assert transport._state == ConnectionState.DISCONNECTED

    @pytest.mark.asyncio
    async def test_handle_disconnect_skips_if_shutdown(self):
        """Test that disconnect is skipped during shutdown."""
        transport = WebSocketTransport()
        transport._shutdown = True
        transport._state = ConnectionState.CONNECTED

        await transport._handle_disconnect()

        # State shouldn't change
        assert transport._state == ConnectionState.CONNECTED

    @pytest.mark.asyncio
    async def test_handle_disconnect_skips_if_already_reconnecting(self):
        """Test that disconnect is skipped if already reconnecting."""
        transport = WebSocketTransport(auto_reconnect=False)
        transport._state = ConnectionState.RECONNECTING

        await transport._handle_disconnect()

        # State shouldn't change
        assert transport._state == ConnectionState.RECONNECTING


# ==============================================================================
# QUIC Transport Tests
# ==============================================================================


class TestQuicTransportConfig:
    """Tests for QuicTransportConfig dataclass."""

    def test_default_config(self):
        """Test default configuration values."""
        config = QuicTransportConfig()

        assert config.host == "localhost"
        assert config.port == 4433
        assert config.server_name is None
        assert config.verify_ssl is True
        assert config.cert_path is None
        assert config.key_path is None
        assert config.ca_path is None
        assert config.alpn_protocols == ["instanton"]
        assert config.idle_timeout == 30.0
        assert config.connection_timeout == 10.0
        assert config.auto_reconnect is True
        assert config.max_reconnect_attempts == 10
        assert config.reconnect_delay == 1.0
        assert config.max_reconnect_delay == 60.0

    def test_custom_config(self):
        """Test custom configuration values."""
        config = QuicTransportConfig(
            host="example.com",
            port=8443,
            server_name="sni.example.com",
            verify_ssl=False,
            cert_path=Path("/path/to/cert.pem"),
            key_path=Path("/path/to/key.pem"),
            alpn_protocols=["h3", "instanton"],
            idle_timeout=60.0,
            connection_timeout=30.0,
            auto_reconnect=False,
            max_reconnect_attempts=5,
        )

        assert config.host == "example.com"
        assert config.port == 8443
        assert config.server_name == "sni.example.com"
        assert config.verify_ssl is False
        assert config.cert_path == Path("/path/to/cert.pem")
        assert config.key_path == Path("/path/to/key.pem")
        assert config.alpn_protocols == ["h3", "instanton"]
        assert config.idle_timeout == 60.0
        assert config.connection_timeout == 30.0
        assert config.auto_reconnect is False
        assert config.max_reconnect_attempts == 5


class TestQuicStreamHandler:
    """Tests for QuicStreamHandler."""

    def test_init(self):
        """Test stream handler initialization."""
        handler = QuicStreamHandler(stream_id=4)

        assert handler.stream_id == 4
        assert handler._closed is False
        assert handler._end_stream is False

    def test_receive_data(self):
        """Test receiving data on stream."""
        handler = QuicStreamHandler(stream_id=4)

        handler.receive_data(b"hello")
        handler.receive_data(b"world")

        # Check data is queued
        assert not handler._recv_buffer.empty()

    def test_receive_data_with_end_stream(self):
        """Test receiving data with end_stream flag."""
        handler = QuicStreamHandler(stream_id=4)

        handler.receive_data(b"final", end_stream=True)

        assert handler._end_stream is True

    @pytest.mark.asyncio
    async def test_read_success(self):
        """Test reading data from stream."""
        handler = QuicStreamHandler(stream_id=4)

        handler.receive_data(b"test data")

        data = await handler.read(timeout=1.0)
        assert data == b"test data"

    @pytest.mark.asyncio
    async def test_read_timeout(self):
        """Test read timeout."""
        handler = QuicStreamHandler(stream_id=4)

        data = await handler.read(timeout=0.01)
        assert data is None

    @pytest.mark.asyncio
    async def test_read_closed(self):
        """Test read on closed stream."""
        handler = QuicStreamHandler(stream_id=4)
        handler.close()

        data = await handler.read(timeout=0.01)
        assert data is None

    @pytest.mark.asyncio
    async def test_read_end_stream(self):
        """Test read returns None after end_stream."""
        handler = QuicStreamHandler(stream_id=4)

        handler.receive_data(b"", end_stream=True)

        data = await handler.read(timeout=1.0)
        assert data is None

    def test_close(self):
        """Test closing stream."""
        handler = QuicStreamHandler(stream_id=4)

        handler.close()

        assert handler._closed is True


class TestQuicClientProtocol:
    """Tests for QuicClientProtocol."""

    def test_init(self):
        """Test protocol initialization."""
        config = QuicTransportConfig()
        protocol = QuicClientProtocol(config)

        assert protocol._quic is None
        assert protocol._streams == {}
        assert protocol._main_stream_id is None
        assert protocol._stats.bytes_sent == 0
        assert not protocol._connected.is_set()
        assert not protocol._closed.is_set()

    def test_is_connected_false_initially(self):
        """Test is_connected returns False initially."""
        config = QuicTransportConfig()
        protocol = QuicClientProtocol(config)

        assert protocol.is_connected() is False

    def test_is_connected_true_after_connect(self):
        """Test is_connected returns True after connection."""
        config = QuicTransportConfig()
        protocol = QuicClientProtocol(config)
        protocol._connected.set()

        assert protocol.is_connected() is True

    def test_is_connected_false_after_close(self):
        """Test is_connected returns False after close."""
        config = QuicTransportConfig()
        protocol = QuicClientProtocol(config)
        protocol._connected.set()
        protocol._closed.set()

        assert protocol.is_connected() is False

    def test_get_stream_nonexistent(self):
        """Test get_stream returns None for nonexistent stream."""
        config = QuicTransportConfig()
        protocol = QuicClientProtocol(config)

        stream = protocol.get_stream(999)
        assert stream is None

    def test_get_stream_exists(self):
        """Test get_stream returns handler for existing stream."""
        config = QuicTransportConfig()
        protocol = QuicClientProtocol(config)

        handler = QuicStreamHandler(4)
        protocol._streams[4] = handler

        result = protocol.get_stream(4)
        assert result is handler

    @pytest.mark.asyncio
    async def test_send_not_connected(self):
        """Test send raises error when not connected."""
        config = QuicTransportConfig()
        protocol = QuicClientProtocol(config)

        with pytest.raises(TransportConnectionError, match="Not connected"):
            await protocol.send(b"test")

    @pytest.mark.asyncio
    async def test_send_no_stream(self):
        """Test send raises error when no stream available."""
        config = QuicTransportConfig()
        protocol = QuicClientProtocol(config)
        protocol._connected.set()

        # Mock quic and protocol but no stream
        protocol._quic = MagicMock()
        protocol._protocol = MagicMock()
        protocol._main_stream_id = None

        with pytest.raises(StreamError, match="No stream available"):
            await protocol.send(b"test")

    @pytest.mark.asyncio
    async def test_send_success(self):
        """Test successful send."""
        config = QuicTransportConfig()
        protocol = QuicClientProtocol(config)
        protocol._connected.set()

        mock_quic = MagicMock()
        mock_protocol = MagicMock()

        protocol._quic = mock_quic
        protocol._protocol = mock_protocol
        protocol._main_stream_id = 4

        await protocol.send(b"test data")

        mock_quic.send_stream_data.assert_called_once_with(4, b"test data", end_stream=False)
        mock_protocol.transmit.assert_called_once()
        assert protocol._stats.bytes_sent == 9
        assert protocol._stats.messages_sent == 1

    @pytest.mark.asyncio
    async def test_recv_not_connected(self):
        """Test recv returns None when not connected."""
        config = QuicTransportConfig()
        protocol = QuicClientProtocol(config)

        data = await protocol.recv(timeout=0.01)
        assert data is None

    @pytest.mark.asyncio
    async def test_recv_success(self):
        """Test successful receive."""
        config = QuicTransportConfig()
        protocol = QuicClientProtocol(config)
        protocol._connected.set()

        # Queue some data
        protocol._recv_queue.put_nowait(b"received data")

        data = await protocol.recv(timeout=1.0)
        assert data == b"received data"

    @pytest.mark.asyncio
    async def test_recv_timeout(self):
        """Test receive timeout."""
        config = QuicTransportConfig()
        protocol = QuicClientProtocol(config)
        protocol._connected.set()

        data = await protocol.recv(timeout=0.01)
        assert data is None

    @pytest.mark.asyncio
    async def test_close(self):
        """Test closing protocol."""
        config = QuicTransportConfig()
        protocol = QuicClientProtocol(config)
        protocol._connected.set()

        mock_quic = MagicMock()
        mock_protocol = MagicMock()
        protocol._quic = mock_quic
        protocol._protocol = mock_protocol

        await protocol.close()

        mock_quic.close.assert_called_once()
        mock_protocol.transmit.assert_called_once()
        assert protocol._closed.is_set()

    def test_create_stream_not_connected(self):
        """Test create_stream raises error when not connected."""
        config = QuicTransportConfig()
        protocol = QuicClientProtocol(config)

        with pytest.raises(TransportConnectionError, match="Not connected"):
            protocol.create_stream()

    def test_create_stream_success(self):
        """Test successful stream creation."""
        config = QuicTransportConfig()
        protocol = QuicClientProtocol(config)

        mock_quic = MagicMock()
        mock_quic.get_next_available_stream_id.return_value = 8
        protocol._quic = mock_quic

        stream_id = protocol.create_stream()

        assert stream_id == 8
        assert 8 in protocol._streams
        assert isinstance(protocol._streams[8], QuicStreamHandler)


class TestQuicClientProtocolEvents:
    """Tests for QuicClientProtocol event handling."""

    def test_handle_handshake_completed(self):
        """Test handling HandshakeCompleted event."""
        config = QuicTransportConfig()
        protocol = QuicClientProtocol(config)

        # Import and create event
        from aioquic.quic.events import HandshakeCompleted

        event = MagicMock(spec=HandshakeCompleted)

        protocol._handle_quic_event(event)

        assert protocol._connected.is_set()

    def test_handle_stream_data_received(self):
        """Test handling StreamDataReceived event."""
        config = QuicTransportConfig()
        protocol = QuicClientProtocol(config)

        # Import and create event
        from aioquic.quic.events import StreamDataReceived

        event = MagicMock(spec=StreamDataReceived)
        event.stream_id = 4
        event.data = b"test payload"
        event.end_stream = False

        protocol._handle_quic_event(event)

        # Stream should be created
        assert 4 in protocol._streams
        # Data should be in recv queue
        assert not protocol._recv_queue.empty()
        assert protocol._stats.bytes_received == len(b"test payload")
        assert protocol._stats.messages_received == 1

    def test_handle_stream_data_received_existing_stream(self):
        """Test handling StreamDataReceived for existing stream."""
        config = QuicTransportConfig()
        protocol = QuicClientProtocol(config)

        # Pre-create stream
        handler = QuicStreamHandler(4)
        protocol._streams[4] = handler

        from aioquic.quic.events import StreamDataReceived

        event = MagicMock(spec=StreamDataReceived)
        event.stream_id = 4
        event.data = b"more data"
        event.end_stream = False

        protocol._handle_quic_event(event)

        # Same handler should be used
        assert protocol._streams[4] is handler

    def test_handle_stream_reset(self):
        """Test handling StreamReset event."""
        config = QuicTransportConfig()
        protocol = QuicClientProtocol(config)

        # Pre-create stream
        handler = QuicStreamHandler(4)
        protocol._streams[4] = handler

        from aioquic.quic.events import StreamReset

        event = MagicMock(spec=StreamReset)
        event.stream_id = 4

        protocol._handle_quic_event(event)

        # Stream should be closed
        assert handler._closed is True

    def test_handle_connection_terminated(self):
        """Test handling ConnectionTerminated event."""
        config = QuicTransportConfig()
        protocol = QuicClientProtocol(config)

        from aioquic.quic.events import ConnectionTerminated

        event = MagicMock(spec=ConnectionTerminated)
        event.error_code = 0
        event.reason_phrase = "normal closure"

        protocol._handle_quic_event(event)

        assert protocol._closed.is_set()


class TestQuicTransportInit:
    """Tests for QuicTransport initialization."""

    def test_default_initialization(self):
        """Test default parameter values."""
        transport = QuicTransport()

        assert transport._config is not None
        assert transport._state == ConnectionState.DISCONNECTED
        assert transport._shutdown is False
        assert transport._quic is None
        assert transport._protocol is None
        assert transport._main_stream_id is None

    def test_custom_initialization(self):
        """Test custom parameter values."""
        config = QuicTransportConfig(
            host="example.com",
            port=8443,
        )
        transport = QuicTransport(
            config=config,
            auto_reconnect=False,
            max_reconnect_attempts=5,
            reconnect_delay=2.0,
            max_reconnect_delay=30.0,
        )

        assert transport._config.host == "example.com"
        assert transport._config.port == 8443
        assert transport._config.auto_reconnect is False
        assert transport._config.max_reconnect_attempts == 5
        assert transport._config.reconnect_delay == 2.0
        assert transport._config.max_reconnect_delay == 30.0


class TestQuicTransportCallbacks:
    """Tests for QuicTransport callback registration."""

    def test_register_callbacks(self):
        """Test callback registration."""
        transport = QuicTransport()

        connect_cb = MagicMock()
        disconnect_cb = MagicMock()
        reconnect_cb = MagicMock()

        transport.on_connect(connect_cb)
        transport.on_disconnect(disconnect_cb)
        transport.on_reconnect(reconnect_cb)

        assert connect_cb in transport._on_connect
        assert disconnect_cb in transport._on_disconnect
        assert reconnect_cb in transport._on_reconnect

    @pytest.mark.asyncio
    async def test_fire_sync_callbacks(self):
        """Test firing synchronous callbacks."""
        transport = QuicTransport()

        called = []

        def cb1():
            called.append("cb1")

        def cb2():
            called.append("cb2")

        await transport._fire_callbacks([cb1, cb2])

        assert called == ["cb1", "cb2"]

    @pytest.mark.asyncio
    async def test_fire_async_callbacks(self):
        """Test firing async callbacks."""
        transport = QuicTransport()

        called = []

        async def cb1():
            called.append("async_cb1")

        async def cb2():
            called.append("async_cb2")

        await transport._fire_callbacks([cb1, cb2])

        assert called == ["async_cb1", "async_cb2"]


class TestQuicTransportState:
    """Tests for QuicTransport state management."""

    def test_is_connected_false_initially(self):
        """Test is_connected returns False initially."""
        transport = QuicTransport()

        assert transport.is_connected() is False

    def test_is_connected_true_when_connected(self):
        """Test is_connected returns True when connected."""
        transport = QuicTransport()
        transport._state = ConnectionState.CONNECTED

        assert transport.is_connected() is True

    def test_get_state(self):
        """Test get_state returns current state."""
        transport = QuicTransport()
        transport._state = ConnectionState.RECONNECTING

        assert transport.get_state() == ConnectionState.RECONNECTING

    def test_get_stats(self):
        """Test get_stats returns stats object."""
        transport = QuicTransport()
        transport._stats.bytes_sent = 1000

        stats = transport.get_stats()

        assert stats.bytes_sent == 1000
        assert isinstance(stats, TransportStats)


class TestQuicTransportSendRecv:
    """Tests for QuicTransport send/recv operations."""

    @pytest.mark.asyncio
    async def test_send_not_connected(self):
        """Test send raises error when not connected."""
        transport = QuicTransport()

        with pytest.raises(TransportConnectionError, match="Not connected"):
            await transport.send(b"test")

    @pytest.mark.asyncio
    async def test_send_no_quic(self):
        """Test send raises error when no QUIC connection."""
        transport = QuicTransport()
        transport._state = ConnectionState.CONNECTED

        with pytest.raises(TransportConnectionError, match="not established"):
            await transport.send(b"test")

    @pytest.mark.asyncio
    async def test_send_no_stream(self):
        """Test send raises error when no stream available."""
        transport = QuicTransport()
        transport._state = ConnectionState.CONNECTED
        transport._quic = MagicMock()
        transport._protocol = MagicMock()
        transport._main_stream_id = None

        with pytest.raises(StreamError, match="No stream available"):
            await transport.send(b"test")

    @pytest.mark.asyncio
    async def test_send_success(self):
        """Test successful send."""
        transport = QuicTransport()
        transport._state = ConnectionState.CONNECTED

        mock_quic = MagicMock()
        mock_protocol = MagicMock()

        transport._quic = mock_quic
        transport._protocol = mock_protocol
        transport._main_stream_id = 4

        await transport.send(b"test data")

        mock_quic.send_stream_data.assert_called_once_with(4, b"test data", end_stream=False)
        mock_protocol.transmit.assert_called_once()
        assert transport._stats.bytes_sent == 9
        assert transport._stats.messages_sent == 1

    @pytest.mark.asyncio
    async def test_recv_not_connected(self):
        """Test recv returns None when not connected."""
        transport = QuicTransport()

        data = await transport.recv()
        assert data is None

    @pytest.mark.asyncio
    async def test_recv_success(self):
        """Test successful receive."""
        transport = QuicTransport()
        transport._state = ConnectionState.CONNECTED
        transport._config.idle_timeout = 1.0

        # Queue some data
        transport._recv_queue.put_nowait(b"received data")

        data = await transport.recv()
        assert data == b"received data"

    @pytest.mark.asyncio
    async def test_recv_timeout(self):
        """Test receive timeout."""
        transport = QuicTransport()
        transport._state = ConnectionState.CONNECTED
        transport._config.idle_timeout = 0.01

        data = await transport.recv()
        assert data is None


class TestQuicTransportStreams:
    """Tests for QuicTransport stream management."""

    def test_get_stream_nonexistent(self):
        """Test get_stream returns None for nonexistent stream."""
        transport = QuicTransport()

        stream = transport.get_stream(999)
        assert stream is None

    def test_get_stream_exists(self):
        """Test get_stream returns handler for existing stream."""
        transport = QuicTransport()

        handler = QuicStreamHandler(4)
        transport._streams[4] = handler

        result = transport.get_stream(4)
        assert result is handler

    def test_create_stream_not_connected(self):
        """Test create_stream raises error when not connected."""
        transport = QuicTransport()

        with pytest.raises(TransportConnectionError, match="Not connected"):
            transport.create_stream()

    def test_create_stream_success(self):
        """Test successful stream creation."""
        transport = QuicTransport()

        mock_quic = MagicMock()
        mock_quic.get_next_available_stream_id.return_value = 8
        transport._quic = mock_quic

        stream_id = transport.create_stream()

        assert stream_id == 8
        assert 8 in transport._streams
        assert isinstance(transport._streams[8], QuicStreamHandler)


class TestQuicTransportClose:
    """Tests for QuicTransport close operation."""

    @pytest.mark.asyncio
    async def test_close_success(self):
        """Test successful close."""
        transport = QuicTransport()
        transport._state = ConnectionState.CONNECTED

        mock_quic = MagicMock()
        mock_protocol = MagicMock()
        transport._quic = mock_quic
        transport._protocol = mock_protocol

        await transport.close()

        assert transport._state == ConnectionState.CLOSED
        assert transport._shutdown is True
        mock_quic.close.assert_called_once()
        mock_protocol.transmit.assert_called_once()
        assert transport._quic is None
        assert transport._protocol is None

    @pytest.mark.asyncio
    async def test_close_with_connect_task(self):
        """Test close cancels connect task."""
        transport = QuicTransport()

        async def long_task():
            await asyncio.sleep(100)

        transport._connect_task = asyncio.create_task(long_task())

        await transport.close()

        assert transport._connect_task is None
        assert transport._state == ConnectionState.CLOSED

    @pytest.mark.asyncio
    async def test_close_no_connection(self):
        """Test close with no active connection."""
        transport = QuicTransport()

        await transport.close()

        assert transport._state == ConnectionState.CLOSED
        assert transport._shutdown is True


class TestQuicTransportEventHandling:
    """Tests for QuicTransport event handling."""

    def test_handle_handshake_completed(self):
        """Test handling HandshakeCompleted event."""
        transport = QuicTransport()

        from aioquic.quic.events import HandshakeCompleted

        event = MagicMock(spec=HandshakeCompleted)

        transport._handle_quic_event(event)

        assert transport._connected_event.is_set()

    def test_handle_stream_data_received(self):
        """Test handling StreamDataReceived event."""
        transport = QuicTransport()

        from aioquic.quic.events import StreamDataReceived

        event = MagicMock(spec=StreamDataReceived)
        event.stream_id = 4
        event.data = b"test payload"
        event.end_stream = False

        transport._handle_quic_event(event)

        # Stream should be created
        assert 4 in transport._streams
        # Data should be in recv queue
        assert not transport._recv_queue.empty()
        assert transport._stats.bytes_received == len(b"test payload")
        assert transport._stats.messages_received == 1

    def test_handle_stream_reset(self):
        """Test handling StreamReset event."""
        transport = QuicTransport()

        # Pre-create stream
        handler = QuicStreamHandler(4)
        transport._streams[4] = handler

        from aioquic.quic.events import StreamReset

        event = MagicMock(spec=StreamReset)
        event.stream_id = 4

        transport._handle_quic_event(event)

        # Stream should be closed
        assert handler._closed is True

    def test_handle_connection_terminated(self):
        """Test handling ConnectionTerminated event."""
        transport = QuicTransport()

        from aioquic.quic.events import ConnectionTerminated

        event = MagicMock(spec=ConnectionTerminated)
        event.error_code = 0
        event.reason_phrase = "normal closure"

        transport._handle_quic_event(event)

        assert transport._closed_event.is_set()


class TestQuicTransportDisconnect:
    """Tests for QuicTransport disconnect handling."""

    @pytest.mark.asyncio
    async def test_handle_disconnect_fires_callbacks(self):
        """Test that disconnect fires callbacks."""
        config = QuicTransportConfig(auto_reconnect=False)
        transport = QuicTransport(config=config, auto_reconnect=False)
        transport._state = ConnectionState.CONNECTED

        disconnected = False

        def on_disconnect():
            nonlocal disconnected
            disconnected = True

        transport.on_disconnect(on_disconnect)

        await transport._handle_disconnect()

        assert disconnected
        assert transport._state == ConnectionState.DISCONNECTED

    @pytest.mark.asyncio
    async def test_handle_disconnect_skips_if_shutdown(self):
        """Test that disconnect is skipped during shutdown."""
        transport = QuicTransport()
        transport._shutdown = True
        transport._state = ConnectionState.CONNECTED

        await transport._handle_disconnect()

        # State shouldn't change
        assert transport._state == ConnectionState.CONNECTED

    @pytest.mark.asyncio
    async def test_handle_disconnect_skips_if_already_reconnecting(self):
        """Test that disconnect is skipped if already reconnecting."""
        transport = QuicTransport()
        transport._state = ConnectionState.RECONNECTING

        await transport._handle_disconnect()

        # State shouldn't change
        assert transport._state == ConnectionState.RECONNECTING


class TestQuicTransportReconnection:
    """Tests for QuicTransport reconnection logic."""

    @pytest.mark.asyncio
    async def test_reconnect_exponential_backoff(self):
        """Test exponential backoff delay calculation."""
        # Pass reconnect config as constructor args (not in QuicTransportConfig)
        # because QuicTransport.__init__ overrides config values with constructor args
        transport = QuicTransport(
            reconnect_delay=1.0,
            max_reconnect_delay=10.0,
            max_reconnect_attempts=5,
        )

        # First attempt: 1.0 * 2^0 = 1.0
        # Second attempt: 1.0 * 2^1 = 2.0
        # Third attempt: 1.0 * 2^2 = 4.0
        # Fourth attempt: 1.0 * 2^3 = 8.0
        # Fifth attempt: 1.0 * 2^4 = 16.0 -> capped at 10.0

        delays = []
        for i in range(1, 6):
            delay = min(
                transport._config.reconnect_delay * (2 ** (i - 1)),
                transport._config.max_reconnect_delay,
            )
            delays.append(delay)

        assert delays == [1.0, 2.0, 4.0, 8.0, 10.0]


class TestQuicServerInit:
    """Tests for QuicServer initialization."""

    def test_default_initialization(self):
        """Test default parameter values."""
        server = QuicServer(
            cert_path=Path("/tmp/cert.pem"),
            key_path=Path("/tmp/key.pem"),
        )

        assert server._cert_path == Path("/tmp/cert.pem")
        assert server._key_path == Path("/tmp/key.pem")
        assert server._host == "0.0.0.0"
        assert server._port == 4433
        assert server._alpn_protocols == ["instanton"]
        assert server._idle_timeout == 30.0
        assert server._server is None
        assert server._connections == {}
        assert server._connection_handler is None

    def test_custom_initialization(self):
        """Test custom parameter values."""
        server = QuicServer(
            cert_path=Path("/custom/cert.pem"),
            key_path=Path("/custom/key.pem"),
            host="127.0.0.1",
            port=8443,
            alpn_protocols=["h3", "instanton"],
            idle_timeout=60.0,
        )

        assert server._host == "127.0.0.1"
        assert server._port == 8443
        assert server._alpn_protocols == ["h3", "instanton"]
        assert server._idle_timeout == 60.0

    def test_on_connection_decorator(self):
        """Test on_connection decorator registers handler."""
        server = QuicServer(
            cert_path=Path("/tmp/cert.pem"),
            key_path=Path("/tmp/key.pem"),
        )

        @server.on_connection
        async def handler(protocol):
            pass

        assert server._connection_handler is handler


class TestQuicServerAsyncContext:
    """Tests for QuicServer async context manager."""

    @pytest.mark.asyncio
    async def test_stop_without_start(self):
        """Test stopping server that was never started."""
        server = QuicServer(
            cert_path=Path("/tmp/cert.pem"),
            key_path=Path("/tmp/key.pem"),
        )

        # Should not raise
        await server.stop()

        assert server._server is None
        assert server._connections == {}
