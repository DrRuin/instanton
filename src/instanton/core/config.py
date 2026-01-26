"""Configuration types with environment variable support.

All settings can be configured via environment variables with the INSTANTON_ prefix.
Example: INSTANTON_CHUNK_SIZE=2097152 sets chunk_size to 2MB.
"""

from __future__ import annotations

import tomllib
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


def load_config_from_file(path: str | Path) -> dict[str, Any]:
    """Load configuration from a YAML or TOML file.

    Args:
        path: Path to the configuration file (.yaml, .yml, or .toml)

    Returns:
        Configuration dictionary

    Raises:
        FileNotFoundError: If the config file doesn't exist
        ValueError: If the config file has encoding errors, invalid syntax, or unsupported format
    """
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
    """Client configuration optimized for global users with varying latency."""

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
    """Server configuration."""

    https_bind: str = "0.0.0.0:443"
    control_bind: str = "0.0.0.0:4443"
    base_domain: str = "instanton.tech"
    cert_path: str | None = None
    key_path: str | None = None
    acme_enabled: bool = True
    acme_email: str | None = None
    max_tunnels: int = 10000
    idle_timeout: float = 300.0
    request_timeout: float | None = Field(
        default=600.0,
        description="Timeout in seconds for HTTP requests. None or 0 for indefinite.",
    )
    subdomain_grace_period: float = Field(
        default=1800.0,
        description="Grace period in seconds to reserve subdomain after client disconnect.",
    )
    domains_enabled: bool = Field(
        default=True,
        description="Enable custom domain support.",
    )
    domains_storage_path: str = Field(
        default="domains.json",
        description="Path to the JSON file storing custom domain registrations.",
    )
    rate_limit_enabled: bool = Field(
        default=False,
        description="Enable rate limiting per IP.",
    )
    rate_limit_rps: float = Field(
        default=100.0,
        description="Requests per second limit per IP.",
    )
    rate_limit_burst: int = Field(
        default=10,
        description="Burst allowance above the per-second rate.",
    )
    ip_restrict_enabled: bool = Field(
        default=False,
        description="Enable IP allow/deny restrictions.",
    )
    ip_allow: list[str] = Field(
        default_factory=list,
        description="Allowed IPs/CIDRs.",
    )
    ip_deny: list[str] = Field(
        default_factory=list,
        description="Denied IPs/CIDRs (takes precedence).",
    )
    auth_enabled: bool = Field(
        default=False,
        description="Enable basic authentication for HTTP requests.",
    )
    auth_username: str | None = Field(
        default=None,
        description="Username for basic authentication.",
    )
    auth_password: str | None = Field(
        default=None,
        repr=False,
        description="Password for basic authentication.",
    )
    # Per-IP tunnel limits (abuse prevention)
    max_tunnels_per_ip: int = Field(
        default=10,
        description="Maximum concurrent tunnels allowed per IP address.",
    )
    tunnel_creation_rate_limit: float = Field(
        default=5.0,
        description="Maximum tunnel creations per minute per IP.",
    )
    tunnel_creation_burst: int = Field(
        default=3,
        description="Burst allowance for tunnel creation rate limit.",
    )
    # Dashboard configuration
    dashboard_enabled: bool = Field(
        default=False,
        description="Enable real-time traffic dashboard. Requires dashboard_user and dashboard_password.",
    )
    dashboard_user: str | None = Field(
        default=None,
        description="Username for dashboard authentication (required to enable dashboard).",
    )
    dashboard_password: str | None = Field(
        default=None,
        repr=False,
        description="Password for dashboard authentication (required to enable dashboard).",
    )
    dashboard_update_interval: float = Field(
        default=1.0,
        description="Dashboard metrics update interval in seconds.",
    )
    dashboard_history_seconds: int = Field(
        default=300,
        description="Dashboard history buffer size in seconds (5 minutes default).",
    )
    dashboard_max_login_failures: int = Field(
        default=5,
        description="Max failed login attempts before IP lockout.",
    )
    dashboard_lockout_minutes: float = Field(
        default=15.0,
        description="How long to lock out an IP after max failures (minutes).",
    )
    # TCP/UDP port ranges for raw tunnels
    tcp_port_min: int = Field(
        default=10000,
        description="TCP tunnel port range start.",
    )
    tcp_port_max: int = Field(
        default=19999,
        description="TCP tunnel port range end.",
    )
    udp_port_min: int = Field(
        default=20000,
        description="UDP tunnel port range start.",
    )
    udp_port_max: int = Field(
        default=29999,
        description="UDP tunnel port range end.",
    )
    # OAuth/OIDC configuration (self-hosted only)
    oauth_enabled: bool = Field(
        default=False,
        description="Enable OAuth/OIDC authentication for tunnel access.",
    )
    oauth_provider: str = Field(
        default="oidc",
        description="OAuth provider: 'github', 'google', or 'oidc'.",
    )
    oauth_client_id: str | None = Field(
        default=None,
        description="OAuth client ID.",
    )
    oauth_client_secret: str | None = Field(
        default=None,
        repr=False,
        description="OAuth client secret.",
    )
    oauth_issuer_url: str | None = Field(
        default=None,
        description="OIDC issuer URL for discovery (e.g., https://accounts.google.com).",
    )
    oauth_allowed_domains: list[str] = Field(
        default_factory=list,
        description="Allowed email domains (e.g., ['mycompany.com']).",
    )
    oauth_allowed_emails: list[str] = Field(
        default_factory=list,
        description="Allowed specific emails.",
    )
    oauth_session_duration: int = Field(
        default=86400,
        description="Session duration in seconds (default 24 hours).",
    )


class DomainsConfig(BaseModel):
    """Configuration for custom domain support.

    Custom domains allow users to use their own domains (e.g., api.mycompany.com)
    instead of the default random.instanton.tech subdomains.
    """

    enabled: bool = Field(
        default=True,
        description="Enable custom domain support.",
    )
    storage_path: str = Field(
        default="domains.json",
        description="Path to the JSON file storing domain registrations.",
    )
    verification_ttl: int = Field(
        default=86400,
        description="TTL in seconds for DNS verification tokens (24 hours default).",
    )
    auto_tls: bool = Field(
        default=True,
        description="Automatically provision TLS certificates for custom domains via ACME.",
    )


class RateLimitingConfig(BaseModel):
    """Configuration for rate limiting.

    Sliding window rate limiting protects against abuse while allowing
    legitimate burst traffic.
    """

    enabled: bool = Field(
        default=False,
        description="Enable rate limiting.",
    )
    requests_per_second: float = Field(
        default=100.0,
        description="Maximum requests per second per IP.",
    )
    burst_size: int = Field(
        default=10,
        description="Burst allowance above the per-second rate.",
    )
    window_seconds: float = Field(
        default=1.0,
        description="Time window for rate calculation.",
    )
    max_entries: int = Field(
        default=10000,
        description="Maximum tracked IPs before LRU eviction.",
    )


class IPRestrictConfig(BaseModel):
    """Configuration for IP restrictions.

    Allow or deny access based on IP addresses or CIDR ranges.
    Deny rules take precedence over allow rules.
    """

    enabled: bool = Field(
        default=False,
        description="Enable IP restrictions.",
    )
    allow: list[str] = Field(
        default_factory=list,
        description="List of allowed IPs/CIDRs (e.g., ['10.0.0.0/8', '192.168.1.1']).",
    )
    deny: list[str] = Field(
        default_factory=list,
        description="List of denied IPs/CIDRs.",
    )
    default_policy: str = Field(
        default="allow",
        description="Default policy when no rules match: 'allow' or 'deny'.",
    )


class PerformanceConfig(BaseSettings):
    """Performance tuning configuration.

    All settings can be overridden via environment variables:
    - INSTANTON_CHUNK_SIZE: Chunk size for streaming (bytes)
    - INSTANTON_MAX_MESSAGE_SIZE: Maximum message size (bytes)
    - INSTANTON_COMPRESSION_ENABLED: Enable/disable auto-compression
    - INSTANTON_COMPRESSION_LEVEL: ZSTD compression level (1-19)
    - etc.
    """

    model_config = SettingsConfigDict(
        env_prefix="INSTANTON_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    chunk_size: int = Field(
        default=1024 * 1024,
        description="Chunk size for streaming (bytes). Default 1MB.",
    )
    max_message_size: int = Field(
        default=64 * 1024 * 1024,
        description="Maximum message size (bytes). Default 64MB.",
    )
    stream_threshold: int = Field(
        default=65536,
        description="Response size threshold to use streaming. Default 64KB.",
    )

    compression_enabled: bool = Field(
        default=True,
        description="Enable automatic compression for text content.",
    )
    compression_level: int = Field(
        default=3,
        ge=1,
        le=19,
        description="ZSTD compression level (1-19). Lower is faster, higher is smaller.",
    )
    min_compression_size: int = Field(
        default=1024,
        description="Minimum payload size to trigger compression (bytes).",
    )
    compression_skip_types: str = Field(
        default="image/,video/,audio/,application/zip,application/gzip,application/x-rar,application/x-7z,application/pdf,application/octet-stream",
        description="Comma-separated content types to skip compression (already compressed).",
    )

    ws_max_size: int = Field(
        default=2 * 1024 * 1024 * 1024,
        description="WebSocket maximum message size (bytes). Default 2GB.",
    )
    ws_read_buffer: int = Field(
        default=64 * 1024 * 1024,
        description="WebSocket read buffer size (bytes). Default 64MB.",
    )
    ws_write_buffer: int = Field(
        default=64 * 1024 * 1024,
        description="WebSocket write buffer size (bytes). Default 64MB.",
    )

    http_max_body_size: int = Field(
        default=2 * 1024 * 1024 * 1024,
        description="Maximum HTTP body size (bytes). Default 2GB.",
    )

    stream_request_threshold: int = Field(
        default=1 * 1024 * 1024,
        description="Request body size threshold to use streaming (bytes). Default 1MB.",
    )
    stream_response_threshold: int = Field(
        default=5 * 1024 * 1024,
        description="Response body size threshold to use streaming (bytes). Default 5MB.",
    )
    stream_chunk_size: int = Field(
        default=4 * 1024 * 1024,
        description="Chunk size for streaming large files (bytes). Default 4MB.",
    )

    def get_skip_compression_types(self) -> set[str]:
        """Parse compression_skip_types string into a set."""
        return {t.strip() for t in self.compression_skip_types.split(",") if t.strip()}


class TimeoutConfig(BaseSettings):
    """Timeout configuration.

    All timeouts are in seconds. Set to 0 or None for indefinite where supported.
    """

    model_config = SettingsConfigDict(
        env_prefix="INSTANTON_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    connect_timeout: float = Field(
        default=30.0,
        description="Connection timeout (seconds).",
    )
    read_timeout: float | None = Field(
        default=None,
        description="Read timeout (seconds). None for indefinite.",
    )
    write_timeout: float = Field(
        default=5.0,
        description="Write timeout (seconds).",
    )
    ping_interval: float = Field(
        default=30.0,
        description="Heartbeat ping interval (seconds).",
    )
    ping_timeout: float = Field(
        default=15.0,
        description="Ping response timeout (seconds).",
    )
    request_timeout: float | None = Field(
        default=600.0,
        description="HTTP request timeout (seconds). None or 0 for indefinite.",
    )
    idle_timeout: float = Field(
        default=300.0,
        description="Idle connection timeout (seconds).",
    )
    ws_close_timeout: float = Field(
        default=5.0,
        description="WebSocket close handshake timeout (seconds).",
    )
    ws_receive_timeout: float = Field(
        default=600.0,
        description="WebSocket receive timeout (seconds).",
    )
    sse_heartbeat_interval: float = Field(
        default=15.0,
        description="SSE heartbeat interval (seconds).",
    )


class ReconnectConfig(BaseSettings):
    """Reconnection behavior configuration."""

    model_config = SettingsConfigDict(
        env_prefix="INSTANTON_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    auto_reconnect: bool = Field(
        default=True,
        description="Enable automatic reconnection on disconnect.",
    )
    max_attempts: int = Field(
        default=15,
        description="Maximum reconnection attempts. 0 for infinite.",
    )
    base_delay: float = Field(
        default=1.0,
        description="Initial reconnection delay (seconds).",
    )
    max_delay: float = Field(
        default=60.0,
        description="Maximum reconnection delay (seconds).",
    )
    jitter: float = Field(
        default=0.2,
        ge=0.0,
        le=1.0,
        description="Reconnection jitter factor (0-1). Adds randomness to prevent thundering herd.",
    )


class ResourceConfig(BaseSettings):
    """Resource allocation configuration."""

    model_config = SettingsConfigDict(
        env_prefix="INSTANTON_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    max_tunnels: int = Field(
        default=10000,
        description="Maximum concurrent tunnels.",
    )
    max_connections: int = Field(
        default=100,
        description="Maximum connections to local service.",
    )
    max_keepalive: int = Field(
        default=20,
        description="Maximum keepalive connections in pool.",
    )
    max_concurrent_streams: int = Field(
        default=1000,
        description="Maximum concurrent chunk streams.",
    )
    dns_cache_ttl: float = Field(
        default=300.0,
        description="DNS cache TTL (seconds).",
    )
    dns_cache_size: int = Field(
        default=100,
        description="Maximum DNS cache entries.",
    )
    tcp_port_min: int = Field(
        default=10000,
        description="TCP tunnel port range start.",
    )
    tcp_port_max: int = Field(
        default=19999,
        description="TCP tunnel port range end.",
    )
    udp_port_min: int = Field(
        default=20000,
        description="UDP tunnel port range start.",
    )
    udp_port_max: int = Field(
        default=29999,
        description="UDP tunnel port range end.",
    )
    subdomain_grace_period: float = Field(
        default=1800.0,
        description="Subdomain reservation grace period after disconnect (seconds).",
    )
    cleanup_interval: float = Field(
        default=60.0,
        description="Cleanup loop interval (seconds).",
    )
    chunk_stream_ttl: float = Field(
        default=300.0,
        description="Incomplete chunk stream TTL (seconds).",
    )


class InstantonConfig(BaseSettings):
    """Master configuration combining all settings.

    This is the main configuration class that aggregates all settings.
    Use get_config() to get a cached instance.

    Example:
        config = get_config()
        print(config.performance.chunk_size)
        print(config.timeouts.connect_timeout)
    """

    model_config = SettingsConfigDict(
        env_prefix="INSTANTON_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    @property
    def performance(self) -> PerformanceConfig:
        """Get performance configuration."""
        return PerformanceConfig()

    @property
    def timeouts(self) -> TimeoutConfig:
        """Get timeout configuration."""
        return TimeoutConfig()

    @property
    def reconnect(self) -> ReconnectConfig:
        """Get reconnection configuration."""
        return ReconnectConfig()

    @property
    def resources(self) -> ResourceConfig:
        """Get resource configuration."""
        return ResourceConfig()

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
        result["INSTANTON_READ_TIMEOUT"] = str(timeouts.read_timeout) if timeouts.read_timeout else ""
        result["INSTANTON_WRITE_TIMEOUT"] = str(timeouts.write_timeout)
        result["INSTANTON_PING_INTERVAL"] = str(timeouts.ping_interval)
        result["INSTANTON_PING_TIMEOUT"] = str(timeouts.ping_timeout)
        result["INSTANTON_REQUEST_TIMEOUT"] = str(timeouts.request_timeout) if timeouts.request_timeout else ""
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
