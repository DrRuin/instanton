"""Configuration."""

from __future__ import annotations

import tomllib
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


def load_config_from_file(path: str | Path) -> dict[str, Any]:
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Config file not found: {path}")

    try:
        content = path.read_text(encoding="utf-8")
    except UnicodeDecodeError as e:
        raise ValueError(f"Config file encoding error in {path}: {e}") from e

    try:
        if path.suffix in (".yaml", ".yml"):
            return yaml.safe_load(content) or {}
        elif path.suffix == ".toml":
            return tomllib.loads(content)
        else:
            raise ValueError(f"Unsupported config format: {path.suffix}")
    except yaml.YAMLError as e:
        raise ValueError(f"Invalid YAML in {path}: {e}") from e
    except tomllib.TOMLDecodeError as e:
        raise ValueError(f"Invalid TOML in {path}: {e}") from e


def flatten_config(config: dict[str, Any], prefix: str = "") -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in config.items():
        full_key = f"{prefix}_{key}" if prefix else key
        if isinstance(value, dict):
            result.update(flatten_config(value, full_key))
        else:
            result[full_key] = value
    return result


class ClientConfig(BaseModel):
    server_addr: str = "instanton.tech:4443"
    local_port: int = 8080
    subdomain: str | None = None
    use_quic: bool = False
    connect_timeout: float = 30.0
    idle_timeout: float = 300.0
    keepalive_interval: float = 30.0
    auto_reconnect: bool = True
    max_reconnect_attempts: int = 15
    proxy_username: str | None = None
    proxy_password: str | None = None


class ServerConfig(BaseModel):
    https_bind: str = "0.0.0.0:443"
    control_bind: str = "0.0.0.0:4443"
    base_domain: str = "instanton.tech"
    cert_path: str | None = None
    key_path: str | None = None
    acme_enabled: bool = True
    acme_email: str | None = None
    max_tunnels: int = 10000
    idle_timeout: float = 300.0
    request_timeout: float | None = 600.0
    subdomain_grace_period: float = 1800.0
    domains_enabled: bool = True
    domains_storage_path: str = "domains.json"
    rate_limit_enabled: bool = False
    rate_limit_rps: float = 100.0
    rate_limit_burst: int = 10
    ip_restrict_enabled: bool = False
    ip_allow: list[str] = Field(default_factory=list)
    ip_deny: list[str] = Field(default_factory=list)
    auth_enabled: bool = False
    auth_username: str | None = None
    auth_password: str | None = Field(default=None, repr=False)
    max_tunnels_per_ip: int = 10
    tunnel_creation_rate_limit: float = 5.0
    tunnel_creation_burst: int = 3
    dashboard_enabled: bool = False
    dashboard_user: str | None = None
    dashboard_password: str | None = Field(default=None, repr=False)
    dashboard_update_interval: float = 1.0
    dashboard_history_seconds: int = 300
    dashboard_max_login_failures: int = 5
    dashboard_lockout_minutes: float = 15.0
    tcp_port_min: int = 10000
    tcp_port_max: int = 19999
    udp_port_min: int = 20000
    udp_port_max: int = 29999
    oauth_enabled: bool = False
    oauth_provider: str = "oidc"
    oauth_client_id: str | None = None
    oauth_client_secret: str | None = Field(default=None, repr=False)
    oauth_issuer_url: str | None = None
    oauth_allowed_domains: list[str] = Field(default_factory=list)
    oauth_allowed_emails: list[str] = Field(default_factory=list)
    oauth_session_duration: int = 86400
    http3_enabled: bool = False
    http3_bind: str = "0.0.0.0:443"
    http3_idle_timeout: float = 60.0


class DomainsConfig(BaseModel):
    enabled: bool = True
    storage_path: str = "domains.json"
    verification_ttl: int = 86400
    auto_tls: bool = True


class RateLimitingConfig(BaseModel):
    enabled: bool = False
    requests_per_second: float = 100.0
    burst_size: int = 10
    window_seconds: float = 1.0
    max_entries: int = 10000


class IPRestrictConfig(BaseModel):
    enabled: bool = False
    allow: list[str] = Field(default_factory=list)
    deny: list[str] = Field(default_factory=list)
    default_policy: str = "allow"


class QuicConfig(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="INSTANTON_QUIC_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    zero_rtt_enabled: bool = Field(default=True, alias="enable_0rtt")
    enable_0rtt: bool = True
    session_ticket_path: str | None = None
    session_ticket_ttl: int = 86400
    session_ticket_lifetime: int = 86400
    max_session_tickets: int = 100
    enable_connection_migration: bool = True
    max_datagram_frame_size: int = 65536


class AdaptiveBufferConfig(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="INSTANTON_BUFFER_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    enabled: bool = True
    min_size: int = 1024
    min_buffer: int = 1024
    max_size: int = 65536
    max_buffer: int = 65536
    target_latency_ms: float = 50.0
    target_latency: float = 0.05
    low_latency_threshold_ms: float = 10.0
    sample_window: int = 100
    adjustment_interval_ms: float = 1000.0


class ParallelProcessingConfig(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="INSTANTON_PARALLEL_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    enabled: bool = True
    max_concurrent_tasks: int = 10
    batch_size: int = 5


class PoolConfig(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="INSTANTON_POOL_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    enabled: bool = True
    max_tunnels_per_connection: int = 100
    idle_timeout: float = 300.0
    cleanup_interval: float = 60.0


class MultiplexerConfig(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="INSTANTON_MUX_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    enabled: bool = True
    max_concurrent_streams: int = 1000
    max_streams: int = 100
    stream_recv_buffer: int = 1000
    reuse_streams: bool = True
    max_pooled_streams: int = 20
    stream_pool_size: int = 20


class MigrationConfig(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="INSTANTON_MIGRATION_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    enabled: bool = True
    check_interval: float = 2.0
    max_migration_time: float = 10.0
    max_retries: int = 3


class CongestionConfig(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="INSTANTON_CC_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    enabled: bool = True
    initial_cwnd: int = 32768
    min_cwnd: int = 4096
    max_cwnd: int = 16777216
    pacing_gain: float = 1.25
    drain_gain: float = 0.75


class WebTransportConfig(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="INSTANTON_WT_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    enabled: bool = True
    max_sessions: int = 100
    max_streams_per_session: int = 100
    datagram_buffer_size: int = 1000
    connect_timeout: float = 30.0


class PerformanceConfig(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="INSTANTON_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    chunk_size: int = 1024 * 1024
    max_message_size: int = 64 * 1024 * 1024
    stream_threshold: int = 65536
    compression_enabled: bool = True
    compression_level: int = Field(default=3, ge=1, le=19)
    min_compression_size: int = 1024
    compression_skip_types: str = "image/,video/,audio/,application/zip,application/gzip,application/x-rar,application/x-7z,application/pdf,application/octet-stream"
    ws_max_size: int = 2 * 1024 * 1024 * 1024
    ws_read_buffer: int = 64 * 1024 * 1024
    ws_write_buffer: int = 64 * 1024 * 1024
    http_max_body_size: int = 2 * 1024 * 1024 * 1024
    stream_request_threshold: int = 1 * 1024 * 1024
    stream_response_threshold: int = 5 * 1024 * 1024
    stream_chunk_size: int = 4 * 1024 * 1024

    def get_skip_compression_types(self) -> set[str]:
        return {t.strip() for t in self.compression_skip_types.split(",") if t.strip()}


class TimeoutConfig(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="INSTANTON_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    connect_timeout: float = 30.0
    read_timeout: float | None = None
    write_timeout: float = 5.0
    ping_interval: float = 30.0
    ping_timeout: float = 15.0
    request_timeout: float | None = 600.0
    idle_timeout: float = 300.0
    ws_close_timeout: float = 5.0
    ws_receive_timeout: float = 600.0
    sse_heartbeat_interval: float = 15.0


class ReconnectConfig(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="INSTANTON_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    auto_reconnect: bool = True
    max_attempts: int = 15
    base_delay: float = 1.0
    max_delay: float = 60.0
    jitter: float = Field(default=0.2, ge=0.0, le=1.0)


class ResourceConfig(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="INSTANTON_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    max_tunnels: int = 10000
    max_connections: int = 100
    max_keepalive: int = 20
    max_concurrent_streams: int = 1000
    dns_cache_ttl: float = 300.0
    dns_cache_size: int = 100
    tcp_port_min: int = 10000
    tcp_port_max: int = 19999
    udp_port_min: int = 20000
    udp_port_max: int = 29999
    subdomain_grace_period: float = 1800.0
    cleanup_interval: float = 60.0
    chunk_stream_ttl: float = 300.0


class InstantonConfig(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="INSTANTON_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    _perf_cache: PerformanceConfig | None = None
    _timeout_cache: TimeoutConfig | None = None
    _reconnect_cache: ReconnectConfig | None = None
    _resources_cache: ResourceConfig | None = None
    _quic_cache: QuicConfig | None = None
    _adaptive_buffer_cache: AdaptiveBufferConfig | None = None
    _parallel_cache: ParallelProcessingConfig | None = None
    _pool_cache: PoolConfig | None = None
    _multiplexer_cache: MultiplexerConfig | None = None
    _migration_cache: MigrationConfig | None = None
    _congestion_cache: CongestionConfig | None = None
    _webtransport_cache: WebTransportConfig | None = None

    @property
    def performance(self) -> PerformanceConfig:
        """Get performance configuration (cached)."""
        if self._perf_cache is None:
            self._perf_cache = PerformanceConfig()
        return self._perf_cache

    @property
    def timeouts(self) -> TimeoutConfig:
        """Get timeout configuration (cached)."""
        if self._timeout_cache is None:
            self._timeout_cache = TimeoutConfig()
        return self._timeout_cache

    @property
    def reconnect(self) -> ReconnectConfig:
        """Get reconnection configuration (cached)."""
        if self._reconnect_cache is None:
            self._reconnect_cache = ReconnectConfig()
        return self._reconnect_cache

    @property
    def resources(self) -> ResourceConfig:
        """Get resource configuration (cached)."""
        if self._resources_cache is None:
            self._resources_cache = ResourceConfig()
        return self._resources_cache

    @property
    def quic(self) -> QuicConfig:
        """Get QUIC transport configuration (cached)."""
        if self._quic_cache is None:
            self._quic_cache = QuicConfig()
        return self._quic_cache

    @property
    def adaptive_buffer(self) -> AdaptiveBufferConfig:
        """Get adaptive buffer configuration (cached)."""
        if self._adaptive_buffer_cache is None:
            self._adaptive_buffer_cache = AdaptiveBufferConfig()
        return self._adaptive_buffer_cache

    @property
    def parallel(self) -> ParallelProcessingConfig:
        """Get parallel processing configuration (cached)."""
        if self._parallel_cache is None:
            self._parallel_cache = ParallelProcessingConfig()
        return self._parallel_cache

    @property
    def pool(self) -> PoolConfig:
        if self._pool_cache is None:
            self._pool_cache = PoolConfig()
        return self._pool_cache

    @property
    def multiplexer(self) -> MultiplexerConfig:
        if self._multiplexer_cache is None:
            self._multiplexer_cache = MultiplexerConfig()
        return self._multiplexer_cache

    @property
    def migration(self) -> MigrationConfig:
        if self._migration_cache is None:
            self._migration_cache = MigrationConfig()
        return self._migration_cache

    @property
    def congestion(self) -> CongestionConfig:
        if self._congestion_cache is None:
            self._congestion_cache = CongestionConfig()
        return self._congestion_cache

    @property
    def webtransport(self) -> WebTransportConfig:
        if self._webtransport_cache is None:
            self._webtransport_cache = WebTransportConfig()
        return self._webtransport_cache

    def to_env_dict(self) -> dict[str, str]:
        """Export current configuration as environment variable dictionary."""
        result = {}

        perf = self.performance
        result["INSTANTON_CHUNK_SIZE"] = str(perf.chunk_size)
        result["INSTANTON_MAX_MESSAGE_SIZE"] = str(perf.max_message_size)
        result["INSTANTON_STREAM_THRESHOLD"] = str(perf.stream_threshold)
        result["INSTANTON_COMPRESSION_ENABLED"] = str(perf.compression_enabled).lower()
        result["INSTANTON_COMPRESSION_LEVEL"] = str(perf.compression_level)
        result["INSTANTON_MIN_COMPRESSION_SIZE"] = str(perf.min_compression_size)
        result["INSTANTON_COMPRESSION_SKIP_TYPES"] = perf.compression_skip_types
        result["INSTANTON_WS_MAX_SIZE"] = str(perf.ws_max_size)
        result["INSTANTON_WS_READ_BUFFER"] = str(perf.ws_read_buffer)
        result["INSTANTON_WS_WRITE_BUFFER"] = str(perf.ws_write_buffer)
        result["INSTANTON_HTTP_MAX_BODY_SIZE"] = str(perf.http_max_body_size)

        timeouts = self.timeouts
        result["INSTANTON_CONNECT_TIMEOUT"] = str(timeouts.connect_timeout)
        result["INSTANTON_READ_TIMEOUT"] = (
            str(timeouts.read_timeout) if timeouts.read_timeout else ""
        )
        result["INSTANTON_WRITE_TIMEOUT"] = str(timeouts.write_timeout)
        result["INSTANTON_PING_INTERVAL"] = str(timeouts.ping_interval)
        result["INSTANTON_PING_TIMEOUT"] = str(timeouts.ping_timeout)
        result["INSTANTON_REQUEST_TIMEOUT"] = (
            str(timeouts.request_timeout) if timeouts.request_timeout else ""
        )
        result["INSTANTON_IDLE_TIMEOUT"] = str(timeouts.idle_timeout)
        result["INSTANTON_WS_CLOSE_TIMEOUT"] = str(timeouts.ws_close_timeout)
        result["INSTANTON_WS_RECEIVE_TIMEOUT"] = str(timeouts.ws_receive_timeout)
        result["INSTANTON_SSE_HEARTBEAT_INTERVAL"] = str(timeouts.sse_heartbeat_interval)

        reconn = self.reconnect
        result["INSTANTON_AUTO_RECONNECT"] = str(reconn.auto_reconnect).lower()
        result["INSTANTON_MAX_ATTEMPTS"] = str(reconn.max_attempts)
        result["INSTANTON_BASE_DELAY"] = str(reconn.base_delay)
        result["INSTANTON_MAX_DELAY"] = str(reconn.max_delay)
        result["INSTANTON_JITTER"] = str(reconn.jitter)

        res = self.resources
        result["INSTANTON_MAX_TUNNELS"] = str(res.max_tunnels)
        result["INSTANTON_MAX_CONNECTIONS"] = str(res.max_connections)
        result["INSTANTON_MAX_KEEPALIVE"] = str(res.max_keepalive)
        result["INSTANTON_MAX_CONCURRENT_STREAMS"] = str(res.max_concurrent_streams)
        result["INSTANTON_DNS_CACHE_TTL"] = str(res.dns_cache_ttl)
        result["INSTANTON_DNS_CACHE_SIZE"] = str(res.dns_cache_size)
        result["INSTANTON_TCP_PORT_MIN"] = str(res.tcp_port_min)
        result["INSTANTON_TCP_PORT_MAX"] = str(res.tcp_port_max)
        result["INSTANTON_UDP_PORT_MIN"] = str(res.udp_port_min)
        result["INSTANTON_UDP_PORT_MAX"] = str(res.udp_port_max)
        result["INSTANTON_SUBDOMAIN_GRACE_PERIOD"] = str(res.subdomain_grace_period)
        result["INSTANTON_CLEANUP_INTERVAL"] = str(res.cleanup_interval)
        result["INSTANTON_CHUNK_STREAM_TTL"] = str(res.chunk_stream_ttl)

        return result

    def to_display_dict(self) -> dict[str, Any]:
        """Export current configuration as a nested dictionary for display."""
        return {
            "performance": {
                "chunk_size": self.performance.chunk_size,
                "max_message_size": self.performance.max_message_size,
                "stream_threshold": self.performance.stream_threshold,
                "compression_enabled": self.performance.compression_enabled,
                "compression_level": self.performance.compression_level,
                "min_compression_size": self.performance.min_compression_size,
                "compression_skip_types": self.performance.compression_skip_types,
                "ws_max_size": self.performance.ws_max_size,
                "ws_read_buffer": self.performance.ws_read_buffer,
                "ws_write_buffer": self.performance.ws_write_buffer,
                "http_max_body_size": self.performance.http_max_body_size,
            },
            "timeouts": {
                "connect_timeout": self.timeouts.connect_timeout,
                "read_timeout": self.timeouts.read_timeout,
                "write_timeout": self.timeouts.write_timeout,
                "ping_interval": self.timeouts.ping_interval,
                "ping_timeout": self.timeouts.ping_timeout,
                "request_timeout": self.timeouts.request_timeout,
                "idle_timeout": self.timeouts.idle_timeout,
                "ws_close_timeout": self.timeouts.ws_close_timeout,
                "ws_receive_timeout": self.timeouts.ws_receive_timeout,
                "sse_heartbeat_interval": self.timeouts.sse_heartbeat_interval,
            },
            "reconnect": {
                "auto_reconnect": self.reconnect.auto_reconnect,
                "max_attempts": self.reconnect.max_attempts,
                "base_delay": self.reconnect.base_delay,
                "max_delay": self.reconnect.max_delay,
                "jitter": self.reconnect.jitter,
            },
            "resources": {
                "max_tunnels": self.resources.max_tunnels,
                "max_connections": self.resources.max_connections,
                "max_keepalive": self.resources.max_keepalive,
                "max_concurrent_streams": self.resources.max_concurrent_streams,
                "dns_cache_ttl": self.resources.dns_cache_ttl,
                "dns_cache_size": self.resources.dns_cache_size,
                "tcp_port_min": self.resources.tcp_port_min,
                "tcp_port_max": self.resources.tcp_port_max,
                "udp_port_min": self.resources.udp_port_min,
                "udp_port_max": self.resources.udp_port_max,
                "subdomain_grace_period": self.resources.subdomain_grace_period,
                "cleanup_interval": self.resources.cleanup_interval,
                "chunk_stream_ttl": self.resources.chunk_stream_ttl,
            },
            "quic": {
                "enable_0rtt": self.quic.enable_0rtt,
                "session_ticket_path": self.quic.session_ticket_path,
                "session_ticket_ttl": self.quic.session_ticket_ttl,
                "max_session_tickets": self.quic.max_session_tickets,
                "enable_connection_migration": self.quic.enable_connection_migration,
                "max_datagram_frame_size": self.quic.max_datagram_frame_size,
            },
            "adaptive_buffer": {
                "enabled": self.adaptive_buffer.enabled,
                "min_size": self.adaptive_buffer.min_size,
                "max_size": self.adaptive_buffer.max_size,
                "target_latency_ms": self.adaptive_buffer.target_latency_ms,
                "low_latency_threshold_ms": self.adaptive_buffer.low_latency_threshold_ms,
                "sample_window": self.adaptive_buffer.sample_window,
            },
            "parallel": {
                "enabled": self.parallel.enabled,
                "max_concurrent_tasks": self.parallel.max_concurrent_tasks,
                "batch_size": self.parallel.batch_size,
            },
            "pool": {
                "enabled": self.pool.enabled,
                "max_tunnels_per_connection": self.pool.max_tunnels_per_connection,
                "idle_timeout": self.pool.idle_timeout,
                "cleanup_interval": self.pool.cleanup_interval,
            },
            "multiplexer": {
                "enabled": self.multiplexer.enabled,
                "max_streams": self.multiplexer.max_streams,
            },
            "migration": {
                "enabled": self.migration.enabled,
                "check_interval": self.migration.check_interval,
            },
            "congestion": {
                "enabled": self.congestion.enabled,
                "initial_cwnd": self.congestion.initial_cwnd,
            },
            "webtransport": {
                "enabled": self.webtransport.enabled,
                "max_sessions": self.webtransport.max_sessions,
            },
        }


_config: InstantonConfig | None = None


def get_config() -> InstantonConfig:
    """Get the global configuration instance.

    Returns a cached instance of InstantonConfig that reads from environment variables.
    The instance is created once and cached for the lifetime of the process.

    To reload config (e.g., in tests), call clear_config() first.

    Example:
        config = get_config()
        chunk_size = config.performance.chunk_size
        timeout = config.timeouts.connect_timeout
    """
    global _config
    if _config is None:
        _config = InstantonConfig()
    return _config


def clear_config() -> None:
    """Clear the cached configuration.

    Call this to force reloading of environment variables on next get_config() call.
    Useful for testing.
    """
    global _config
    _config = None
