"""Tests for fast transport implementations."""

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from instanton.core.fast_transport import (
    FastQuicTransport,
    FastWebSocketTransport,
    QuicConfig,
    SessionTicket,
    SessionTicketStore,
    TransportMetrics,
    TransportState,
    create_transport,
    get_ticket_store,
)

# ==============================================================================
# TransportMetrics Tests
# ==============================================================================


class TestTransportMetrics:
    """Tests for TransportMetrics."""

    def test_default_values(self):
        """Test default metric values."""
        metrics = TransportMetrics()

        assert metrics.bytes_sent == 0
        assert metrics.bytes_received == 0
        assert metrics.messages_sent == 0
        assert metrics.messages_received == 0
        assert metrics.reconnect_count == 0
        assert metrics.last_latency_ms == 0.0
        assert metrics.avg_latency_ms == 0.0
        assert metrics.connection_time_ms == 0.0
        assert metrics.zero_rtt_used is False
        assert metrics.migrations == 0


# ==============================================================================
# TransportState Tests
# ==============================================================================


class TestTransportState:
    """Tests for TransportState enum."""

    def test_state_values(self):
        """Test state enum values."""
        assert TransportState.DISCONNECTED.value == "disconnected"
        assert TransportState.CONNECTING.value == "connecting"
        assert TransportState.CONNECTED.value == "connected"
        assert TransportState.RECONNECTING.value == "reconnecting"
        assert TransportState.MIGRATING.value == "migrating"
        assert TransportState.CLOSED.value == "closed"


# ==============================================================================
# SessionTicketStore Tests
# ==============================================================================


class TestSessionTicket:
    """Tests for SessionTicket."""

    def test_creation(self):
        """Test creating session ticket."""
        ticket = SessionTicket(
            ticket=b"ticket_data",
            server_name="test.example.com",
            max_early_data=16384,
            cipher_suite="TLS_AES_256_GCM_SHA384",
        )

        assert ticket.ticket == b"ticket_data"
        assert ticket.server_name == "test.example.com"
        assert ticket.max_early_data == 16384


class TestSessionTicketStore:
    """Tests for SessionTicketStore."""

    def test_store_and_get(self):
        """Test storing and retrieving tickets."""
        store = SessionTicketStore()
        ticket = SessionTicket(ticket=b"test", server_name="test.example.com")

        store.store("test.example.com", ticket)
        retrieved = store.get("test.example.com")

        assert retrieved is not None
        assert retrieved.ticket == b"test"

    def test_get_nonexistent(self):
        """Test getting nonexistent ticket."""
        store = SessionTicketStore()

        ticket = store.get("nonexistent.com")
        assert ticket is None

    def test_remove(self):
        """Test removing ticket."""
        store = SessionTicketStore()
        ticket = SessionTicket(ticket=b"test", server_name="test.example.com")

        store.store("test.example.com", ticket)
        store.remove("test.example.com")

        assert store.get("test.example.com") is None

    def test_max_tickets(self):
        """Test max tickets limit."""
        store = SessionTicketStore(max_tickets=3)

        for i in range(5):
            ticket = SessionTicket(ticket=f"test{i}".encode(), server_name=f"server{i}.com")
            store.store(f"server{i}.com", ticket)

        # Only 3 should remain
        assert len(store._tickets) == 3

    def test_global_store(self):
        """Test global ticket store."""
        store1 = get_ticket_store()
        store2 = get_ticket_store()
        assert store1 is store2


# ==============================================================================
# FastWebSocketTransport Tests
# ==============================================================================


class TestFastWebSocketTransportInit:
    """Tests for FastWebSocketTransport initialization."""

    def test_default_initialization(self):
        """Test default parameter values."""
        transport = FastWebSocketTransport()

        assert transport._auto_reconnect is True
        assert transport._max_reconnect_attempts == 10
        assert transport._reconnect_delay == 0.5
        assert transport._ping_interval == 15.0
        assert transport._ping_timeout == 10.0
        assert transport._connect_timeout == 5.0
        assert transport._state == TransportState.DISCONNECTED

    def test_custom_initialization(self):
        """Test custom parameter values."""
        transport = FastWebSocketTransport(
            auto_reconnect=False,
            max_reconnect_attempts=5,
            reconnect_delay=1.0,
            max_reconnect_delay=60.0,
            ping_interval=30.0,
            ping_timeout=15.0,
            connect_timeout=10.0,
        )

        assert transport._auto_reconnect is False
        assert transport._max_reconnect_attempts == 5
        assert transport._reconnect_delay == 1.0
        assert transport._ping_interval == 30.0


class TestFastWebSocketTransportBuildUrl:
    """Tests for URL building."""

    def test_full_wss_url(self):
        """Test full WSS URL passthrough."""
        transport = FastWebSocketTransport()
        url = transport._build_url("wss://example.com/ws")
        assert url == "wss://example.com/ws"

    def test_full_ws_url(self):
        """Test full WS URL passthrough."""
        transport = FastWebSocketTransport()
        url = transport._build_url("ws://localhost:8080/ws")
        assert url == "ws://localhost:8080/ws"

    def test_host_port(self):
        """Test host:port format."""
        transport = FastWebSocketTransport()
        url = transport._build_url("example.com:443")
        assert url == "wss://example.com:443/tunnel"

    def test_host_only(self):
        """Test host only format."""
        transport = FastWebSocketTransport()
        url = transport._build_url("example.com")
        assert url == "wss://example.com:443/tunnel"


class TestFastWebSocketTransportCallbacks:
    """Tests for callback registration."""

    def test_register_callbacks(self):
        """Test callback registration."""
        transport = FastWebSocketTransport()

        connect_cb = MagicMock()
        disconnect_cb = MagicMock()
        reconnect_cb = MagicMock()

        transport.on_connect(connect_cb)
        transport.on_disconnect(disconnect_cb)
        transport.on_reconnect(reconnect_cb)

        assert connect_cb in transport._on_connect
        assert disconnect_cb in transport._on_disconnect
        assert reconnect_cb in transport._on_reconnect


class TestFastWebSocketTransportState:
    """Tests for state management."""

    def test_is_connected_false_initially(self):
        """Test is_connected returns False initially."""
        transport = FastWebSocketTransport()
        assert transport.is_connected() is False

    def test_is_connected_true_when_connected(self):
        """Test is_connected returns True when connected."""
        transport = FastWebSocketTransport()
        transport._state = TransportState.CONNECTED
        transport._ws = MagicMock()

        assert transport.is_connected() is True

    def test_get_state(self):
        """Test get_state returns current state."""
        transport = FastWebSocketTransport()
        transport._state = TransportState.RECONNECTING

        assert transport.get_state() == TransportState.RECONNECTING

    def test_get_metrics(self):
        """Test get_metrics returns metrics object."""
        transport = FastWebSocketTransport()
        transport._metrics.bytes_sent = 1000

        metrics = transport.get_metrics()
        assert metrics.bytes_sent == 1000


class TestFastWebSocketTransportSendRecv:
    """Tests for send/recv operations."""

    @pytest.mark.asyncio
    async def test_send_not_connected(self):
        """Test send raises error when not connected."""
        transport = FastWebSocketTransport()

        with pytest.raises(ConnectionError, match="Not connected"):
            await transport.send(b"test")

    @pytest.mark.asyncio
    async def test_send_success(self):
        """Test successful send."""
        transport = FastWebSocketTransport()
        transport._state = TransportState.CONNECTED
        transport._ws = AsyncMock()

        await transport.send(b"test data")

        transport._ws.send.assert_called_once_with(b"test data")
        assert transport._metrics.bytes_sent == 9
        assert transport._metrics.messages_sent == 1

    @pytest.mark.asyncio
    async def test_recv_no_websocket(self):
        """Test recv with no WebSocket."""
        transport = FastWebSocketTransport()
        transport._ws = None

        data = await transport.recv()
        assert data is None

    @pytest.mark.asyncio
    async def test_recv_success_bytes(self):
        """Test successful receive of bytes."""
        transport = FastWebSocketTransport()
        transport._state = TransportState.CONNECTED
        transport._ws = AsyncMock()
        transport._ws.recv.return_value = b"response data"

        data = await transport.recv()

        assert data == b"response data"
        assert transport._metrics.bytes_received == 13
        assert transport._metrics.messages_received == 1

    @pytest.mark.asyncio
    async def test_recv_success_string(self):
        """Test successful receive of string."""
        transport = FastWebSocketTransport()
        transport._state = TransportState.CONNECTED
        transport._ws = AsyncMock()
        transport._ws.recv.return_value = "string response"

        data = await transport.recv()

        assert data == b"string response"


class TestFastWebSocketTransportClose:
    """Tests for close operation."""

    @pytest.mark.asyncio
    async def test_close_success(self):
        """Test successful close."""
        transport = FastWebSocketTransport()
        transport._state = TransportState.CONNECTED
        mock_ws = AsyncMock()
        transport._ws = mock_ws

        await transport.close()

        assert transport._state == TransportState.CLOSED
        assert transport._shutdown is True
        mock_ws.close.assert_called_once()


# ==============================================================================
# QuicConfig Tests
# ==============================================================================


class TestQuicConfig:
    """Tests for QuicConfig."""

    def test_default_config(self):
        """Test default configuration."""
        config = QuicConfig()

        assert config.host == "localhost"
        assert config.port == 4433
        assert config.server_name is None
        assert config.verify_ssl is True
        assert config.alpn_protocols == ["instanton", "h3"]
        assert config.idle_timeout == 30.0
        assert config.enable_0rtt is True
        assert config.enable_migration is True

    def test_custom_config(self):
        """Test custom configuration."""
        config = QuicConfig(
            host="example.com",
            port=8443,
            server_name="sni.example.com",
            verify_ssl=False,
            cert_path=Path("/path/to/cert.pem"),
            key_path=Path("/path/to/key.pem"),
            enable_0rtt=False,
            enable_migration=False,
        )

        assert config.host == "example.com"
        assert config.port == 8443
        assert config.server_name == "sni.example.com"
        assert config.verify_ssl is False
        assert config.enable_0rtt is False


# ==============================================================================
# FastQuicTransport Tests
# ==============================================================================


class TestFastQuicTransportInit:
    """Tests for FastQuicTransport initialization."""

    def test_default_initialization(self):
        """Test default parameter values."""
        transport = FastQuicTransport()

        assert transport._auto_reconnect is True
        assert transport._max_reconnect_attempts == 10
        assert transport._state == TransportState.DISCONNECTED
        assert transport._quic is None

    def test_custom_initialization(self):
        """Test custom initialization."""
        config = QuicConfig(host="example.com", port=8443)
        transport = FastQuicTransport(
            config=config,
            auto_reconnect=False,
            max_reconnect_attempts=5,
        )

        assert transport._config.host == "example.com"
        assert transport._auto_reconnect is False


class TestFastQuicTransportCallbacks:
    """Tests for callback registration."""

    def test_register_callbacks(self):
        """Test callback registration."""
        transport = FastQuicTransport()

        connect_cb = MagicMock()
        disconnect_cb = MagicMock()
        migration_cb = MagicMock()

        transport.on_connect(connect_cb)
        transport.on_disconnect(disconnect_cb)
        transport.on_migration(migration_cb)

        assert connect_cb in transport._on_connect
        assert disconnect_cb in transport._on_disconnect
        assert migration_cb in transport._on_migration


class TestFastQuicTransportState:
    """Tests for state management."""

    def test_is_connected_false_initially(self):
        """Test is_connected returns False initially."""
        transport = FastQuicTransport()
        assert transport.is_connected() is False

    def test_is_connected_true_when_connected(self):
        """Test is_connected returns True when connected."""
        transport = FastQuicTransport()
        transport._state = TransportState.CONNECTED
        transport._quic = MagicMock()

        assert transport.is_connected() is True

    def test_get_state(self):
        """Test get_state returns current state."""
        transport = FastQuicTransport()
        transport._state = TransportState.MIGRATING

        assert transport.get_state() == TransportState.MIGRATING


class TestFastQuicTransportSendRecv:
    """Tests for send/recv operations."""

    @pytest.mark.asyncio
    async def test_send_not_connected(self):
        """Test send raises error when not connected."""
        transport = FastQuicTransport()

        with pytest.raises(ConnectionError, match="Not connected"):
            await transport.send(b"test")

    @pytest.mark.asyncio
    async def test_send_no_stream(self):
        """Test send raises error when no stream."""
        transport = FastQuicTransport()
        transport._state = TransportState.CONNECTED
        transport._quic = MagicMock()
        transport._protocol = MagicMock()
        transport._main_stream_id = None

        with pytest.raises(ConnectionError, match="No stream"):
            await transport.send(b"test")

    @pytest.mark.asyncio
    async def test_send_success(self):
        """Test successful send."""
        transport = FastQuicTransport()
        transport._state = TransportState.CONNECTED

        mock_quic = MagicMock()
        mock_protocol = MagicMock()

        transport._quic = mock_quic
        transport._protocol = mock_protocol
        transport._main_stream_id = 4

        await transport.send(b"test data")

        mock_quic.send_stream_data.assert_called_once_with(4, b"test data", end_stream=False)
        mock_protocol.transmit.assert_called_once()
        assert transport._metrics.bytes_sent == 9

    @pytest.mark.asyncio
    async def test_recv_not_connected(self):
        """Test recv returns None when not connected."""
        transport = FastQuicTransport()

        data = await transport.recv(timeout=0.01)
        assert data is None

    @pytest.mark.asyncio
    async def test_recv_success(self):
        """Test successful receive."""
        transport = FastQuicTransport()
        transport._state = TransportState.CONNECTED
        transport._config.idle_timeout = 1.0
        transport._quic = MagicMock()  # Need to be "connected"

        transport._recv_queue.put_nowait(b"received data")

        data = await transport.recv(timeout=1.0)
        assert data == b"received data"

    @pytest.mark.asyncio
    async def test_recv_timeout(self):
        """Test receive timeout."""
        transport = FastQuicTransport()
        transport._state = TransportState.CONNECTED
        transport._config.idle_timeout = 0.01

        data = await transport.recv(timeout=0.01)
        assert data is None


class TestFastQuicTransportClose:
    """Tests for close operation."""

    @pytest.mark.asyncio
    async def test_close_success(self):
        """Test successful close."""
        transport = FastQuicTransport()
        transport._state = TransportState.CONNECTED

        mock_quic = MagicMock()
        mock_protocol = MagicMock()
        transport._quic = mock_quic
        transport._protocol = mock_protocol

        await transport.close()

        assert transport._state == TransportState.CLOSED
        assert transport._shutdown is True
        mock_quic.close.assert_called_once()

    @pytest.mark.asyncio
    async def test_close_no_connection(self):
        """Test close with no connection."""
        transport = FastQuicTransport()

        await transport.close()

        assert transport._state == TransportState.CLOSED


class TestFastQuicTransportMigration:
    """Tests for connection migration."""

    @pytest.mark.asyncio
    async def test_migrate_not_enabled(self):
        """Test migration when disabled."""
        config = QuicConfig(enable_migration=False)
        transport = FastQuicTransport(config=config)

        result = await transport.migrate()
        assert result is False

    @pytest.mark.asyncio
    async def test_migrate_not_connected(self):
        """Test migration when not connected."""
        transport = FastQuicTransport()

        result = await transport.migrate()
        assert result is False

    @pytest.mark.asyncio
    async def test_migrate_success(self):
        """Test successful migration."""
        transport = FastQuicTransport()
        transport._state = TransportState.CONNECTED
        transport._quic = MagicMock()

        result = await transport.migrate()

        assert result is True
        assert transport._metrics.migrations == 1


class TestFastQuicTransportStreams:
    """Tests for stream management."""

    def test_create_stream_not_connected(self):
        """Test create_stream when not connected."""
        transport = FastQuicTransport()

        with pytest.raises(ConnectionError, match="Not connected"):
            transport.create_stream()

    def test_create_stream_success(self):
        """Test successful stream creation."""
        transport = FastQuicTransport()
        transport._state = TransportState.CONNECTED  # Must be connected

        mock_quic = MagicMock()
        mock_quic.get_next_available_stream_id.return_value = 8
        transport._quic = mock_quic

        stream_id = transport.create_stream()

        assert stream_id == 8
        assert 8 in transport._streams


# ==============================================================================
# Transport Factory Tests
# ==============================================================================


class TestCreateTransport:
    """Tests for create_transport factory."""

    def test_create_websocket_transport(self):
        """Test creating WebSocket transport."""
        transport = create_transport("websocket")

        assert isinstance(transport, FastWebSocketTransport)

    def test_create_quic_transport(self):
        """Test creating QUIC transport."""
        transport = create_transport("quic")

        assert isinstance(transport, FastQuicTransport)

    def test_create_with_custom_params(self):
        """Test creating with custom parameters."""
        transport = create_transport(
            "websocket",
            auto_reconnect=False,
            max_reconnect_attempts=5,
        )

        assert transport._auto_reconnect is False
        assert transport._max_reconnect_attempts == 5

    def test_create_quic_with_config(self):
        """Test creating QUIC with config params."""
        transport = create_transport(
            "quic",
            host="example.com",
            port=8443,
            enable_0rtt=False,
        )

        assert transport._config.host == "example.com"
        assert transport._config.port == 8443
        assert transport._config.enable_0rtt is False
