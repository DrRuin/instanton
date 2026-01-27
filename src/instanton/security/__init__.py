"""Security module for Instanton tunnel application.

This module provides security features including:
- Basic authentication (timing-attack resistant)
- Rate limiting (sliding window)
- IP restrictions (CIDR allow/deny)
- OAuth/OIDC authentication (self-hosted only)
"""

from instanton.security.basicauth import (
    PROXY_AUTH_CHALLENGE,
    PROXY_AUTH_HEADER,
    AuthResult,
    BasicAuthenticator,
    create_basic_authenticator,
)
from instanton.security.iprestrict import (
    IPCheckResult,
    IPPolicy,
    IPRestrictor,
    create_ip_restrictor,
)
from instanton.security.oauth import (
    OAuthAuthenticator,
    OAuthConfig,
    OAuthResult,
    ProviderConfig,
    Session,
    SessionManager,
    create_oauth_authenticator,
    create_provider,
)
from instanton.security.ratelimit import (
    RateLimitConfig,
    RateLimiter,
    RateLimitResult,
    SlidingWindowCounter,
    create_rate_limiter,
)

__all__ = [
    # Basic Authentication
    "PROXY_AUTH_CHALLENGE",
    "PROXY_AUTH_HEADER",
    "AuthResult",
    "BasicAuthenticator",
    "create_basic_authenticator",
    # IP Restriction
    "IPCheckResult",
    "IPPolicy",
    "IPRestrictor",
    "create_ip_restrictor",
    # Rate Limiting
    "RateLimitConfig",
    "RateLimiter",
    "RateLimitResult",
    "SlidingWindowCounter",
    "create_rate_limiter",
    # OAuth/OIDC Authentication
    "OAuthAuthenticator",
    "OAuthConfig",
    "OAuthResult",
    "ProviderConfig",
    "Session",
    "SessionManager",
    "create_oauth_authenticator",
    "create_provider",
]
