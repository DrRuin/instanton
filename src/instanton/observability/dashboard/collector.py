"""MetricsCollector - Samples Prometheus metrics for dashboard display."""

from __future__ import annotations

import asyncio
import time
from collections import deque
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from instanton.observability.metrics import (
    ACTIVE_CONNECTIONS,
    ACTIVE_TUNNELS,
    BYTES_TRANSFERRED,
    GRPC_REQUESTS,
    HTTP_REQUESTS,
    REQUEST_DURATION,
    TUNNEL_PACKETS,
    WEBSOCKET_MESSAGES,
)

if TYPE_CHECKING:
    from instanton.server.relay import RelayServer


@dataclass
class MetricSnapshot:
    """A point-in-time snapshot of server metrics."""

    timestamp: float
    active_tunnels: dict[str, int] = field(default_factory=dict)  # {http, tcp, udp}
    active_connections: int = 0
    requests_per_second: float = 0.0
    bytes_in_per_second: float = 0.0
    bytes_out_per_second: float = 0.0
    latency_p50: float = 0.0
    latency_p95: float = 0.0
    latency_p99: float = 0.0

    def to_dict(self) -> dict:
        """Convert snapshot to JSON-serializable dict."""
        return {
            "timestamp": self.timestamp,
            "active_tunnels": self.active_tunnels,
            "active_connections": self.active_connections,
            "requests_per_second": round(self.requests_per_second, 2),
            "bytes_in_per_second": round(self.bytes_in_per_second, 2),
            "bytes_out_per_second": round(self.bytes_out_per_second, 2),
            "latency_p50": round(self.latency_p50 * 1000, 2),  # Convert to ms
            "latency_p95": round(self.latency_p95 * 1000, 2),
            "latency_p99": round(self.latency_p99 * 1000, 2),
        }


@dataclass
class TunnelInfo:
    """Information about an active tunnel for display."""

    subdomain: str
    tunnel_type: str  # http, tcp, udp
    request_count: int
    bytes_in: int
    bytes_out: int
    source_ip: str
    uptime_seconds: float
    connected_at: str

    def to_dict(self) -> dict:
        """Convert to JSON-serializable dict."""
        return {
            "subdomain": self.subdomain,
            "type": self.tunnel_type,
            "request_count": self.request_count,
            "bytes_in": self.bytes_in,
            "bytes_out": self.bytes_out,
            "source_ip": self.source_ip,
            "uptime_seconds": round(self.uptime_seconds, 1),
            "connected_at": self.connected_at,
        }


class MetricsCollector:
    """Collects and buffers metrics for the dashboard.

    Samples Prometheus metrics every interval (default 1s) and maintains
    a rolling buffer of snapshots for historical display.
    """

    def __init__(
        self,
        relay_server: RelayServer,
        update_interval: float = 1.0,
        history_seconds: int = 300,
    ):
        """Initialize the collector.

        Args:
            relay_server: Reference to the RelayServer for tunnel data.
            update_interval: How often to sample metrics (seconds).
            history_seconds: How many seconds of history to keep.
        """
        self._relay = relay_server
        self._update_interval = update_interval
        self._max_snapshots = history_seconds

        # Rolling buffer of snapshots
        self._history: deque[MetricSnapshot] = deque(maxlen=self._max_snapshots)

        # Previous counter values for rate calculation
        self._prev_requests_total: float = 0.0
        self._prev_bytes_in: float = 0.0
        self._prev_bytes_out: float = 0.0
        self._prev_sample_time: float = 0.0

        # Task management
        self._running = False
        self._task: asyncio.Task | None = None

    async def start(self) -> None:
        """Start the metrics collection loop."""
        if self._running:
            return
        self._running = True
        self._prev_sample_time = time.time()

        # Initialize previous counter values
        self._prev_requests_total = self._get_total_requests()
        self._prev_bytes_in = self._get_bytes_counter("in")
        self._prev_bytes_out = self._get_bytes_counter("out")

        self._task = asyncio.create_task(self._collection_loop())

    async def stop(self) -> None:
        """Stop the metrics collection loop."""
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None

    async def _collection_loop(self) -> None:
        """Main collection loop - samples metrics at regular intervals."""
        while self._running:
            try:
                snapshot = self._collect_snapshot()
                self._history.append(snapshot)
                await asyncio.sleep(self._update_interval)
            except asyncio.CancelledError:
                break
            except Exception:
                # Don't let collection errors stop the loop
                await asyncio.sleep(self._update_interval)

    def _collect_snapshot(self) -> MetricSnapshot:
        """Collect a single metrics snapshot."""
        now = time.time()
        elapsed = now - self._prev_sample_time if self._prev_sample_time else 1.0
        elapsed = max(elapsed, 0.001)  # Prevent division by zero

        # Get current counter values
        current_requests = self._get_total_requests()
        current_bytes_in = self._get_bytes_counter("in")
        current_bytes_out = self._get_bytes_counter("out")

        # Calculate rates
        requests_per_second = (current_requests - self._prev_requests_total) / elapsed
        bytes_in_per_second = (current_bytes_in - self._prev_bytes_in) / elapsed
        bytes_out_per_second = (current_bytes_out - self._prev_bytes_out) / elapsed

        # Update previous values
        self._prev_requests_total = current_requests
        self._prev_bytes_in = current_bytes_in
        self._prev_bytes_out = current_bytes_out
        self._prev_sample_time = now

        # Get tunnel counts
        active_tunnels = {
            "http": self._get_gauge_value(ACTIVE_TUNNELS, {"type": "http"}),
            "tcp": self._get_gauge_value(ACTIVE_TUNNELS, {"type": "tcp"}),
            "udp": self._get_gauge_value(ACTIVE_TUNNELS, {"type": "udp"}),
        }

        # Get latency percentiles
        p50, p95, p99 = self._get_latency_percentiles()

        return MetricSnapshot(
            timestamp=now,
            active_tunnels=active_tunnels,
            active_connections=int(self._get_gauge_value(ACTIVE_CONNECTIONS, {})),
            requests_per_second=max(0, requests_per_second),
            bytes_in_per_second=max(0, bytes_in_per_second),
            bytes_out_per_second=max(0, bytes_out_per_second),
            latency_p50=p50,
            latency_p95=p95,
            latency_p99=p99,
        )

    def _get_total_requests(self) -> float:
        """Get total request/message count across all protocols.

        Includes HTTP requests, gRPC requests, WebSocket messages, and TCP/UDP packets.
        """
        total = 0.0

        # HTTP requests
        for metric in HTTP_REQUESTS.collect():
            for sample in metric.samples:
                if sample.name.endswith("_total"):
                    total += sample.value

        # gRPC requests
        for metric in GRPC_REQUESTS.collect():
            for sample in metric.samples:
                if sample.name.endswith("_total"):
                    total += sample.value

        # WebSocket messages
        for metric in WEBSOCKET_MESSAGES.collect():
            for sample in metric.samples:
                if sample.name.endswith("_total"):
                    total += sample.value

        # TCP/UDP packets
        for metric in TUNNEL_PACKETS.collect():
            for sample in metric.samples:
                if sample.name.endswith("_total"):
                    total += sample.value

        return total

    def _get_bytes_counter(self, direction: str) -> float:
        """Get bytes counter value for a direction (summed across all protocols)."""
        total = 0.0
        for metric in BYTES_TRANSFERRED.collect():
            for sample in metric.samples:
                if sample.name.endswith("_total") and sample.labels.get("direction") == direction:
                    total += sample.value
        return total

    def _get_gauge_value(self, gauge, labels: dict) -> float:
        """Get current value of a gauge with specific labels."""
        for metric in gauge.collect():
            for sample in metric.samples:
                # Check if all required labels match
                if all(sample.labels.get(k) == v for k, v in labels.items()):
                    return sample.value
        return 0.0

    def _get_latency_percentiles(self) -> tuple[float, float, float]:
        """Calculate latency percentiles from histogram.

        Returns (p50, p95, p99) in seconds.
        """
        # Collect histogram data
        buckets: list[tuple[float, float]] = []
        count = 0.0

        for metric in REQUEST_DURATION.collect():
            for sample in metric.samples:
                if sample.name.endswith("_bucket"):
                    le = sample.labels.get("le", "+Inf")
                    if le != "+Inf":
                        buckets.append((float(le), sample.value))
                elif sample.name.endswith("_count"):
                    count = sample.value

        if count == 0 or not buckets:
            return (0.0, 0.0, 0.0)

        # Sort buckets by upper bound
        buckets.sort(key=lambda x: x[0])

        def percentile(p: float) -> float:
            target = count * p
            prev_bound = 0.0
            prev_count = 0.0
            for bound, cumulative in buckets:
                if cumulative >= target:
                    # Linear interpolation within bucket
                    bucket_count = cumulative - prev_count
                    if bucket_count > 0:
                        fraction = (target - prev_count) / bucket_count
                        return prev_bound + fraction * (bound - prev_bound)
                    return bound
                prev_bound = bound
                prev_count = cumulative
            return buckets[-1][0] if buckets else 0.0

        return (percentile(0.5), percentile(0.95), percentile(0.99))

    def get_latest_snapshot(self) -> MetricSnapshot | None:
        """Get the most recent snapshot."""
        return self._history[-1] if self._history else None

    def get_history(self) -> list[dict]:
        """Get all historical snapshots as dicts."""
        return [s.to_dict() for s in self._history]

    def get_tunnel_list(self) -> list[dict]:
        """Get list of all active tunnels with details."""
        from datetime import UTC, datetime

        tunnels: list[TunnelInfo] = []
        now = datetime.now(UTC)

        # HTTP tunnels
        for subdomain, tunnel in self._relay._tunnels.items():
            uptime = (now - tunnel.connected_at).total_seconds()
            tunnels.append(
                TunnelInfo(
                    subdomain=subdomain,
                    tunnel_type="http",
                    request_count=tunnel.request_count,
                    bytes_in=tunnel.bytes_received,
                    bytes_out=tunnel.bytes_sent,
                    source_ip=tunnel.source_ip,
                    uptime_seconds=uptime,
                    connected_at=tunnel.connected_at.isoformat(),
                )
            )

        # TCP tunnels
        for port, tunnel in self._relay._tcp_tunnels.items():
            uptime = (now - tunnel.connected_at).total_seconds()
            tunnels.append(
                TunnelInfo(
                    subdomain=f"tcp-{port}",
                    tunnel_type="tcp",
                    request_count=tunnel.request_count,
                    bytes_in=tunnel.bytes_received,
                    bytes_out=tunnel.bytes_sent,
                    source_ip=tunnel.source_ip,
                    uptime_seconds=uptime,
                    connected_at=tunnel.connected_at.isoformat(),
                )
            )

        # UDP tunnels
        for port, tunnel in self._relay._udp_tunnels.items():
            uptime = (now - tunnel.connected_at).total_seconds()
            tunnels.append(
                TunnelInfo(
                    subdomain=f"udp-{port}",
                    tunnel_type="udp",
                    request_count=tunnel.request_count,
                    bytes_in=tunnel.bytes_received,
                    bytes_out=tunnel.bytes_sent,
                    source_ip=tunnel.source_ip,
                    uptime_seconds=uptime,
                    connected_at=tunnel.connected_at.isoformat(),
                )
            )

        return [t.to_dict() for t in tunnels]
