"""Instanton Core - Shared functionality."""

from .config import ClientConfig, ServerConfig
from .protocols import (
    GrpcPassthroughHandler,
    HTTP2ConnectionHandler,
    ProtocolDetectionResult,
    ProtocolDetector,
    ProtocolHandler,
    ProtocolRouter,
    ProtocolType,
    TcpTunnelHandler,
    UdpHandler,
    WebSocketHandler,
)
from .transport import (
    ConnectionState,
    QuicTransport,
    Transport,
    TransportStats,
    WebSocketTransport,
)

__all__ = [
    # Transport
    "Transport",
    "WebSocketTransport",
    "QuicTransport",
    "ConnectionState",
    "TransportStats",
    # Config
    "ClientConfig",
    "ServerConfig",
    # Protocol Detection
    "ProtocolType",
    "ProtocolDetector",
    "ProtocolDetectionResult",
    "ProtocolHandler",
    "ProtocolRouter",
    # Protocol Handlers
    "HTTP2ConnectionHandler",
    "GrpcPassthroughHandler",
    "WebSocketHandler",
    "TcpTunnelHandler",
    "UdpHandler",
]
