"""Tests for TCP and UDP tunnel clients."""

import struct

from instanton.client.tcp_tunnel import (
    TcpRelayMessage,
    TcpTunnelClient,
    TcpTunnelConfig,
    TcpTunnelState,
    TcpTunnelStats,
)
from instanton.client.udp_tunnel import (
    UdpRelayMessage,
    UdpTunnelClient,
    UdpTunnelConfig,
    UdpTunnelState,
    UdpTunnelStats,
)

# ==============================================================================
# TCP Relay Message Tests
# ==============================================================================


class TestTcpRelayMessage:
    """Tests for TcpRelayMessage encoding/decoding."""

    def test_encode_connect(self):
        """Test encoding connect message."""
        tunnel_id = b"0123456789abcdef"
        msg = TcpRelayMessage.encode_connect(
            tunnel_id=tunnel_id,
            local_port=22,
            remote_port=2222,
        )
        assert msg[0] == TcpRelayMessage.CONNECT
        assert msg[1:17] == tunnel_id
        assert struct.unpack(">H", msg[17:19])[0] == 22
        assert struct.unpack(">H", msg[19:21])[0] == 2222

    def test_encode_connect_ack(self):
        """Test encoding connect acknowledgment."""
        tunnel_id = b"0123456789abcdef"
        msg = TcpRelayMessage.encode_connect_ack(
            tunnel_id=tunnel_id,
            assigned_port=12345,
        )
        assert msg[0] == TcpRelayMessage.CONNECT_ACK
        assert struct.unpack(">H", msg[17:19])[0] == 12345

    def test_encode_connect_ack_with_error(self):
        """Test encoding connect ack with error."""
        tunnel_id = b"0123456789abcdef"
        msg = TcpRelayMessage.encode_connect_ack(
            tunnel_id=tunnel_id,
            assigned_port=0,
            error="Port unavailable",
        )
        assert msg[0] == TcpRelayMessage.CONNECT_ACK
        error_len = msg[19]
        assert error_len > 0
        assert b"Port unavailable" in msg[20:]

    def test_encode_data(self):
        """Test encoding data message."""
        connection_id = b"connid12"
        data = b"Hello, World!"
        msg = TcpRelayMessage.encode_data(connection_id, data)
        assert msg[0] == TcpRelayMessage.DATA
        assert msg[1:9] == connection_id
        data_len = struct.unpack(">I", msg[9:13])[0]
        assert data_len == len(data)
        assert msg[13:] == data

    def test_encode_close(self):
        """Test encoding close message."""
        connection_id = b"connid12"
        msg = TcpRelayMessage.encode_close(connection_id)
        assert msg[0] == TcpRelayMessage.CLOSE
        assert msg[1:9] == connection_id

    def test_encode_keepalive(self):
        """Test encoding keepalive message."""
        tunnel_id = b"0123456789abcdef"
        msg = TcpRelayMessage.encode_keepalive(tunnel_id)
        assert msg[0] == TcpRelayMessage.KEEPALIVE
        assert msg[1:17] == tunnel_id

    def test_decode_connect(self):
        """Test decoding connect message."""
        tunnel_id = b"0123456789abcdef"
        msg = TcpRelayMessage.encode_connect(tunnel_id, 22, 2222)
        result = TcpRelayMessage.decode(msg)
        assert result is not None
        msg_type, data = result
        assert msg_type == TcpRelayMessage.CONNECT
        assert data["local_port"] == 22
        assert data["remote_port"] == 2222

    def test_decode_connect_ack(self):
        """Test decoding connect acknowledgment."""
        tunnel_id = b"0123456789abcdef"
        msg = TcpRelayMessage.encode_connect_ack(tunnel_id, 12345)
        result = TcpRelayMessage.decode(msg)
        assert result is not None
        msg_type, data = result
        assert msg_type == TcpRelayMessage.CONNECT_ACK
        assert data["assigned_port"] == 12345
        assert data["error"] is None

    def test_decode_data(self):
        """Test decoding data message."""
        connection_id = b"connid12"
        payload = b"Test data payload"
        msg = TcpRelayMessage.encode_data(connection_id, payload)
        result = TcpRelayMessage.decode(msg)
        assert result is not None
        msg_type, data = result
        assert msg_type == TcpRelayMessage.DATA
        assert data["data"] == payload

    def test_decode_invalid_message(self):
        """Test decoding invalid message."""
        result = TcpRelayMessage.decode(b"")
        assert result is None

        result = TcpRelayMessage.decode(b"\x01")  # Too short for connect
        assert result is None


# ==============================================================================
# UDP Relay Message Tests
# ==============================================================================


class TestUdpRelayMessage:
    """Tests for UdpRelayMessage encoding/decoding."""

    def test_encode_bind(self):
        """Test encoding bind message."""
        tunnel_id = b"0123456789abcdef"
        msg = UdpRelayMessage.encode_bind(
            tunnel_id=tunnel_id,
            local_port=53,
            remote_port=5353,
        )
        assert msg[0] == UdpRelayMessage.BIND
        assert msg[1:17] == tunnel_id
        assert struct.unpack(">H", msg[17:19])[0] == 53
        assert struct.unpack(">H", msg[19:21])[0] == 5353

    def test_encode_bind_ack(self):
        """Test encoding bind acknowledgment."""
        tunnel_id = b"0123456789abcdef"
        msg = UdpRelayMessage.encode_bind_ack(
            tunnel_id=tunnel_id,
            assigned_port=15353,
        )
        assert msg[0] == UdpRelayMessage.BIND_ACK
        assert struct.unpack(">H", msg[17:19])[0] == 15353

    def test_encode_datagram(self):
        """Test encoding datagram message."""
        source_addr = ("192.168.1.1", 12345)
        dest_addr = ("10.0.0.1", 53)
        data = b"DNS query data"
        msg = UdpRelayMessage.encode_datagram(source_addr, dest_addr, data)
        assert msg[0] == UdpRelayMessage.DATAGRAM

    def test_encode_close(self):
        """Test encoding close message."""
        tunnel_id = b"0123456789abcdef"
        msg = UdpRelayMessage.encode_close(tunnel_id)
        assert msg[0] == UdpRelayMessage.CLOSE
        assert msg[1:17] == tunnel_id

    def test_encode_keepalive(self):
        """Test encoding keepalive message."""
        tunnel_id = b"0123456789abcdef"
        msg = UdpRelayMessage.encode_keepalive(tunnel_id)
        assert msg[0] == UdpRelayMessage.KEEPALIVE
        assert msg[1:17] == tunnel_id

    def test_decode_bind(self):
        """Test decoding bind message."""
        tunnel_id = b"0123456789abcdef"
        msg = UdpRelayMessage.encode_bind(tunnel_id, 53, 5353)
        result = UdpRelayMessage.decode(msg)
        assert result is not None
        msg_type, data = result
        assert msg_type == UdpRelayMessage.BIND
        assert data["local_port"] == 53
        assert data["remote_port"] == 5353

    def test_decode_bind_ack(self):
        """Test decoding bind acknowledgment."""
        tunnel_id = b"0123456789abcdef"
        msg = UdpRelayMessage.encode_bind_ack(tunnel_id, 15353)
        result = UdpRelayMessage.decode(msg)
        assert result is not None
        msg_type, data = result
        assert msg_type == UdpRelayMessage.BIND_ACK
        assert data["assigned_port"] == 15353

    def test_decode_datagram(self):
        """Test decoding datagram message."""
        source_addr = ("192.168.1.1", 12345)
        dest_addr = ("10.0.0.1", 53)
        payload = b"Test UDP data"
        msg = UdpRelayMessage.encode_datagram(source_addr, dest_addr, payload)
        result = UdpRelayMessage.decode(msg)
        assert result is not None
        msg_type, data = result
        assert msg_type == UdpRelayMessage.DATAGRAM
        assert data["source_addr"] == source_addr
        assert data["dest_addr"] == dest_addr
        assert data["data"] == payload

    def test_decode_invalid_message(self):
        """Test decoding invalid message."""
        result = UdpRelayMessage.decode(b"")
        assert result is None


# ==============================================================================
# TCP Tunnel Client Tests
# ==============================================================================


class TestTcpTunnelConfig:
    """Tests for TcpTunnelConfig."""

    def test_default_config(self):
        """Test default configuration."""
        config = TcpTunnelConfig()
        assert config.local_host == "127.0.0.1"
        assert config.local_port == 22
        assert config.buffer_size == 65535
        assert config.connect_timeout == 30.0
        assert config.idle_timeout == 300.0

    def test_custom_config(self):
        """Test custom configuration."""
        config = TcpTunnelConfig(
            local_host="0.0.0.0",
            local_port=5432,
            remote_port=15432,
            buffer_size=32768,
        )
        assert config.local_host == "0.0.0.0"
        assert config.local_port == 5432
        assert config.remote_port == 15432
        assert config.buffer_size == 32768


class TestTcpTunnelStats:
    """Tests for TcpTunnelStats."""

    def test_default_stats(self):
        """Test default statistics."""
        stats = TcpTunnelStats()
        assert stats.bytes_sent == 0
        assert stats.bytes_received == 0
        assert stats.packets_sent == 0
        assert stats.packets_received == 0
        assert stats.connections_handled == 0


class TestTcpTunnelClient:
    """Tests for TcpTunnelClient."""

    def test_initialization(self):
        """Test client initialization."""
        config = TcpTunnelConfig(local_port=22)
        client = TcpTunnelClient(config=config)
        assert client.state == TcpTunnelState.DISCONNECTED
        assert client.assigned_port is None
        assert client.tunnel_url is None

    def test_state_property(self):
        """Test state property."""
        client = TcpTunnelClient()
        assert client.state == TcpTunnelState.DISCONNECTED

    def test_stats_property(self):
        """Test stats property."""
        client = TcpTunnelClient()
        stats = client.stats
        assert isinstance(stats, TcpTunnelStats)


# ==============================================================================
# UDP Tunnel Client Tests
# ==============================================================================


class TestUdpTunnelConfig:
    """Tests for UdpTunnelConfig."""

    def test_default_config(self):
        """Test default configuration."""
        config = UdpTunnelConfig()
        assert config.local_host == "127.0.0.1"
        assert config.local_port == 53
        assert config.max_datagram_size == 1400
        assert config.connect_timeout == 30.0
        assert config.idle_timeout == 300.0

    def test_custom_config(self):
        """Test custom configuration."""
        config = UdpTunnelConfig(
            local_host="0.0.0.0",
            local_port=5060,
            remote_port=15060,
            max_datagram_size=1200,
        )
        assert config.local_host == "0.0.0.0"
        assert config.local_port == 5060
        assert config.remote_port == 15060
        assert config.max_datagram_size == 1200


class TestUdpTunnelStats:
    """Tests for UdpTunnelStats."""

    def test_default_stats(self):
        """Test default statistics."""
        stats = UdpTunnelStats()
        assert stats.datagrams_sent == 0
        assert stats.datagrams_received == 0
        assert stats.bytes_sent == 0
        assert stats.bytes_received == 0
        assert stats.datagrams_dropped == 0


class TestUdpTunnelClient:
    """Tests for UdpTunnelClient."""

    def test_initialization(self):
        """Test client initialization."""
        config = UdpTunnelConfig(local_port=53)
        client = UdpTunnelClient(config=config)
        assert client.state == UdpTunnelState.DISCONNECTED
        assert client.assigned_port is None
        assert client.tunnel_url is None

    def test_state_property(self):
        """Test state property."""
        client = UdpTunnelClient()
        assert client.state == UdpTunnelState.DISCONNECTED

    def test_stats_property(self):
        """Test stats property."""
        client = UdpTunnelClient()
        stats = client.stats
        assert isinstance(stats, UdpTunnelStats)

    def test_use_quic_default(self):
        """Test QUIC is default for UDP."""
        client = UdpTunnelClient()
        assert client.use_quic is True


# ==============================================================================
# State Hook Tests
# ==============================================================================


class TestTcpStateHooks:
    """Tests for TCP tunnel state hooks."""

    def test_add_state_hook(self):
        """Test adding state hook."""
        client = TcpTunnelClient()
        states: list[TcpTunnelState] = []

        def hook(state: TcpTunnelState):
            states.append(state)

        client.add_state_hook(hook)
        # Trigger state change
        client._set_state(TcpTunnelState.CONNECTING)
        assert TcpTunnelState.CONNECTING in states

    def test_remove_state_hook(self):
        """Test removing state hook."""
        client = TcpTunnelClient()

        def hook(state: TcpTunnelState):
            pass

        client.add_state_hook(hook)
        assert client.remove_state_hook(hook) is True
        assert client.remove_state_hook(hook) is False  # Already removed


class TestUdpStateHooks:
    """Tests for UDP tunnel state hooks."""

    def test_state_change_notification(self):
        """Test state change notification."""
        client = UdpTunnelClient()
        states: list[UdpTunnelState] = []

        def hook(state: UdpTunnelState):
            states.append(state)

        client._state_hooks.append(hook)
        client._set_state(UdpTunnelState.CONNECTING)
        assert UdpTunnelState.CONNECTING in states


# ==============================================================================
# Tunnel URL Tests
# ==============================================================================


class TestTunnelUrls:
    """Tests for tunnel URL generation."""

    def test_tcp_tunnel_url(self):
        """Test TCP tunnel URL generation."""
        client = TcpTunnelClient(server_addr="example.com")
        client._assigned_port = 12345
        assert client.tunnel_url == "tcp://example.com:12345"

    def test_tcp_tunnel_url_none(self):
        """Test TCP tunnel URL when not connected."""
        client = TcpTunnelClient()
        assert client.tunnel_url is None

    def test_udp_tunnel_url(self):
        """Test UDP tunnel URL generation."""
        client = UdpTunnelClient(server_addr="example.com")
        client._assigned_port = 15353
        assert client.tunnel_url == "udp://example.com:15353"

    def test_udp_tunnel_url_none(self):
        """Test UDP tunnel URL when not connected."""
        client = UdpTunnelClient()
        assert client.tunnel_url is None
