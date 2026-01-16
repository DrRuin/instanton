"""Configuration types."""

from pydantic import BaseModel, Field


class ClientConfig(BaseModel):
    """Client configuration optimized for global users with varying latency."""

    server_addr: str = "instanton.tech:4443"
    local_port: int = 8080
    subdomain: str | None = None
    use_quic: bool = False  # WebSocket is default (server compatibility)
    # Increased from 10s to 30s for users in high-latency regions
    connect_timeout: float = 30.0
    idle_timeout: float = 300.0
    keepalive_interval: float = 30.0
    auto_reconnect: bool = True
    # Increased from 10 to 15 for better resilience
    max_reconnect_attempts: int = 15


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
    # Request timeout: how long to wait for the client to respond.
    # Default 120s matches Cloudflare's proxy read timeout.
    # Set to None or 0 for indefinite (streaming/long-running APIs).
    request_timeout: float | None = Field(
        default=120.0,
        description="Timeout in seconds for HTTP requests. None or 0 for indefinite.",
    )
    # Subdomain reservation grace period: how long to hold a subdomain after client disconnects.
    # This allows clients to reconnect (e.g., after laptop lid close) and reclaim the same URL.
    # Default 30 minutes (1800s) covers most real-world scenarios.
    subdomain_grace_period: float = Field(
        default=1800.0,
        description="Grace period in seconds to reserve subdomain after client disconnect.",
    )
    # Custom domains configuration
    domains_enabled: bool = Field(
        default=True,
        description="Enable custom domain support.",
    )
    domains_storage_path: str = Field(
        default="domains.json",
        description="Path to the JSON file storing custom domain registrations.",
    )
    # Rate limiting configuration
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
    # IP restrictions configuration
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
