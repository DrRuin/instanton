from prometheus_client import CONTENT_TYPE_LATEST, Counter, Gauge, Histogram, generate_latest

TUNNEL_CONNECTIONS = Counter(
    "instanton_tunnel_connections_total",
    "Total tunnel connections",
    ["type"],
)

HTTP_REQUESTS = Counter(
    "instanton_http_requests_total",
    "Total HTTP requests",
    ["method", "status"],
)

BYTES_TRANSFERRED = Counter(
    "instanton_bytes_total",
    "Bytes transferred",
    ["direction", "protocol"],
)

# WebSocket message counter
WEBSOCKET_MESSAGES = Counter(
    "instanton_websocket_messages_total",
    "Total WebSocket messages",
    ["direction", "type"],  # direction: in/out, type: text/binary
)

# gRPC request counter
GRPC_REQUESTS = Counter(
    "instanton_grpc_requests_total",
    "Total gRPC requests",
    ["method", "status"],
)

# TCP/UDP datagram counter
TUNNEL_PACKETS = Counter(
    "instanton_tunnel_packets_total",
    "Total packets through raw tunnels",
    ["protocol", "direction"],  # protocol: tcp/udp, direction: in/out
)

ACTIVE_TUNNELS = Gauge(
    "instanton_active_tunnels",
    "Current active tunnels",
    ["type"],
)

ACTIVE_CONNECTIONS = Gauge(
    "instanton_active_connections",
    "Current active connections",
)

REQUEST_DURATION = Histogram(
    "instanton_request_duration_seconds",
    "Request latency",
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0),
)


def generate_metrics() -> bytes:
    return generate_latest()


def get_content_type() -> str:
    return CONTENT_TYPE_LATEST
