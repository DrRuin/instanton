"""Configuration types."""

from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, Field


class AuthBackend(str, Enum):
    """Authentication storage backend types."""

    MEMORY = "memory"
    SQLITE = "sqlite"
    REDIS = "redis"


class AuthConfig(BaseModel):
    """Authentication configuration.

    Attributes:
        enabled: Whether authentication is enabled.
        backend: Storage backend type.
        require_auth: Whether to require authentication for all requests.
        allow_anonymous: Allow anonymous access (when require_auth is False).

        # API Key settings
        api_key_enabled: Enable API key authentication.
        api_key_prefix: Prefix for generated API keys.
        api_key_header: HTTP header name for API keys.

        # JWT settings
        jwt_enabled: Enable JWT authentication.
        jwt_algorithm: JWT signing algorithm (HS256 or RS256).
        jwt_secret_key: Secret key for HS256.
        jwt_private_key_path: Path to private key for RS256.
        jwt_public_key_path: Path to public key for RS256.
        jwt_issuer: JWT issuer claim.
        jwt_audience: JWT audience claim.
        jwt_access_token_ttl: Access token lifetime in seconds.
        jwt_refresh_token_ttl: Refresh token lifetime in seconds.
        jwt_leeway: Time leeway for token validation in seconds.

        # Basic auth settings
        basic_auth_enabled: Enable HTTP Basic authentication.
        basic_auth_realm: Realm for Basic auth.

        # OAuth settings
        oauth_enabled: Enable OAuth2/OIDC authentication.
        oauth_providers: List of configured OAuth providers.

        # mTLS settings
        mtls_enabled: Enable mutual TLS authentication.
        mtls_ca_cert_path: Path to CA certificate for client verification.
        mtls_required_subjects: List of allowed subject CNs.

        # Storage settings
        sqlite_path: Path to SQLite database (for sqlite backend).
        redis_url: Redis connection URL (for redis backend).

        # Excluded paths
        excluded_paths: Paths that don't require authentication.
    """

    enabled: bool = True
    backend: AuthBackend = AuthBackend.MEMORY
    require_auth: bool = True
    allow_anonymous: bool = False

    # API Key settings
    api_key_enabled: bool = True
    api_key_prefix: str = "tach_"
    api_key_header: str = "X-API-Key"

    # JWT settings
    jwt_enabled: bool = True
    jwt_algorithm: Literal["HS256", "RS256"] = "HS256"
    jwt_secret_key: str | None = None
    jwt_private_key_path: str | None = None
    jwt_public_key_path: str | None = None
    jwt_issuer: str = "instanton"
    jwt_audience: str = "instanton"
    jwt_access_token_ttl: int = 3600  # 1 hour
    jwt_refresh_token_ttl: int = 604800  # 7 days
    jwt_leeway: int = 10

    # Basic auth settings
    basic_auth_enabled: bool = False
    basic_auth_realm: str = "Instanton"

    # OAuth settings
    oauth_enabled: bool = False
    oauth_providers: list[dict[str, Any]] = Field(default_factory=list)

    # mTLS settings
    mtls_enabled: bool = False
    mtls_ca_cert_path: str | None = None
    mtls_required_subjects: list[str] = Field(default_factory=list)

    # Storage settings
    sqlite_path: str = "instanton_auth.db"
    redis_url: str = "redis://localhost:6379/0"

    # Excluded paths
    excluded_paths: list[str] = Field(default_factory=lambda: ["/health", "/ready", "/metrics"])


class ClientConfig(BaseModel):
    """Client configuration."""

    server_addr: str = "instanton.dev:443"
    local_port: int = 8080
    subdomain: str | None = None
    use_quic: bool = True
    connect_timeout: float = 10.0
    idle_timeout: float = 300.0
    keepalive_interval: float = 30.0
    auto_reconnect: bool = True
    max_reconnect_attempts: int = 10


class RateLimitConfig(BaseModel):
    """Configuration for rate limiting.

    This configuration controls all rate limiting behavior including
    per-IP, per-subdomain, and per-API-key limits.
    """

    enabled: bool = True
    global_limit: int = Field(
        default=10000, description="Global rate limit for all requests per window"
    )
    per_ip_limit: int = Field(default=100, description="Rate limit per IP address per window")
    per_subdomain_limit: int = Field(
        default=1000, description="Rate limit per subdomain per window"
    )
    per_api_key_limit: int = Field(default=500, description="Rate limit per API key per window")
    window_size: float = Field(default=60.0, description="Rate limit window size in seconds")
    cache_ttl: float = Field(default=300.0, description="TTL for limiter cache entries")
    cache_max_size: int = Field(default=10000, description="Maximum number of cached limiters")
    enable_adaptive: bool = Field(
        default=True, description="Enable adaptive rate limiting based on load"
    )
    adaptive_min_limit_factor: float = Field(
        default=0.25, description="Minimum limit as factor of base (for adaptive)"
    )
    adaptive_max_limit_factor: float = Field(
        default=2.0, description="Maximum limit as factor of base (for adaptive)"
    )
    adaptive_load_threshold_high: float = Field(
        default=0.8, description="Load threshold to start reducing limits"
    )
    adaptive_load_threshold_low: float = Field(
        default=0.3, description="Load threshold to start increasing limits"
    )


class DDoSProtectionConfig(BaseModel):
    """Configuration for DDoS protection.

    This configuration controls DDoS detection and mitigation including
    connection tracking, flood detection, and IP reputation.
    """

    enabled: bool = True
    max_connections_per_ip: int = Field(
        default=100, description="Maximum simultaneous connections per IP"
    )
    max_total_connections: int = Field(default=10000, description="Maximum total connections")
    slow_connection_timeout: float = Field(
        default=30.0, description="Timeout for slow connections (slowloris protection)"
    )
    requests_per_second_threshold: float = Field(
        default=100.0, description="Max requests per second before flagging"
    )
    burst_threshold: int = Field(default=50, description="Max requests in burst window")
    burst_window: float = Field(default=1.0, description="Burst detection window in seconds")
    enable_fingerprinting: bool = Field(
        default=True, description="Enable request fingerprinting for bot detection"
    )
    enable_challenges: bool = Field(
        default=True, description="Enable challenge mechanism for suspicious requests"
    )
    auto_ban_threshold: float = Field(
        default=20.0, description="Reputation score threshold for auto-banning"
    )
    auto_ban_duration: float = Field(default=3600.0, description="Auto-ban duration in seconds")
    geoip_enabled: bool = Field(default=False, description="Enable GeoIP-based blocking")
    blocked_countries: list[str] = Field(
        default_factory=list, description="List of blocked country codes"
    )
    reputation_cache_size: int = Field(
        default=100000, description="Maximum IPs to track for reputation"
    )
    reputation_cache_ttl: float = Field(default=3600.0, description="TTL for reputation entries")


class FirewallConfig(BaseModel):
    """Configuration for the application firewall.

    This configuration controls IP filtering, path rules, and header-based rules.
    """

    enabled: bool = True
    default_action: str = Field(
        default="allow", description="Default action when no rules match (allow/deny)"
    )
    enable_logging: bool = Field(default=True, description="Enable logging of firewall matches")
    cache_size: int = Field(default=10000, description="Size of the decision cache")
    cache_ttl: float = Field(default=60.0, description="TTL for cached decisions")
    ip_allowlist: list[str] = Field(
        default_factory=list, description="List of allowed IP addresses"
    )
    ip_blocklist: list[str] = Field(
        default_factory=list, description="List of blocked IP addresses"
    )
    cidr_allowlist: list[str] = Field(
        default_factory=list, description="List of allowed CIDR ranges"
    )
    cidr_blocklist: list[str] = Field(
        default_factory=list, description="List of blocked CIDR ranges"
    )
    blocked_countries: list[str] = Field(
        default_factory=list, description="List of blocked country codes"
    )
    blocked_user_agents: list[str] = Field(
        default_factory=list, description="List of blocked user agent patterns"
    )
    blocked_paths: list[str] = Field(
        default_factory=list, description="List of blocked path patterns"
    )
    rules: list[dict[str, Any]] = Field(default_factory=list, description="Additional custom rules")


class SecurityConfig(BaseModel):
    """Combined security configuration.

    This provides a unified configuration for all security features.
    """

    rate_limit: RateLimitConfig = Field(default_factory=RateLimitConfig)
    ddos_protection: DDoSProtectionConfig = Field(default_factory=DDoSProtectionConfig)
    firewall: FirewallConfig = Field(default_factory=FirewallConfig)


class ServerConfig(BaseModel):
    """Server configuration."""

    https_bind: str = "0.0.0.0:443"
    control_bind: str = "0.0.0.0:4443"
    base_domain: str = "instanton.dev"
    cert_path: str | None = None
    key_path: str | None = None
    acme_enabled: bool = True
    acme_email: str | None = None
    max_tunnels: int = 10000
    rate_limit: int = 1000  # Deprecated: use security.rate_limit instead
    idle_timeout: float = 300.0
    security: SecurityConfig = Field(default_factory=SecurityConfig)
    auth: AuthConfig = Field(default_factory=AuthConfig)
