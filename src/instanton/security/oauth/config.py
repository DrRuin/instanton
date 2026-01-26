"""OAuth/OIDC configuration types for self-hosted Instanton.

This module defines configuration dataclasses for OAuth providers
and the overall OAuth settings.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ProviderConfig:
    """OAuth provider configuration.

    Supports both OIDC providers (with discovery) and manual OAuth2 providers.

    For OIDC providers (Google, Okta, Auth0, Keycloak), set issuer_url
    and endpoints will be auto-discovered via .well-known/openid-configuration.

    For OAuth2-only providers (GitHub), set authorize_url, token_url, and
    userinfo_url manually.
    """

    name: str
    client_id: str
    client_secret: str
    # OIDC discovery URL (auto-configures endpoints)
    issuer_url: str | None = None
    # Manual endpoints (if not using discovery)
    authorize_url: str | None = None
    token_url: str | None = None
    userinfo_url: str | None = None
    # Scopes to request
    scopes: list[str] = field(default_factory=lambda: ["openid", "email", "profile"])

    def __post_init__(self):
        """Validate that either issuer_url or manual endpoints are provided."""
        has_manual = self.authorize_url and self.token_url
        if not self.issuer_url and not has_manual:
            raise ValueError(
                "ProviderConfig requires either issuer_url (for OIDC discovery) "
                "or authorize_url + token_url (for manual OAuth2)"
            )


@dataclass
class OAuthConfig:
    """OAuth configuration for the self-hosted Instanton server.

    This configuration controls how OAuth/OIDC authentication is applied
    to tunnel access. When enabled, users must authenticate via the
    configured OAuth provider before accessing tunneled services.
    """

    enabled: bool = False
    provider: ProviderConfig | None = None
    # Access restrictions - if both empty, all authenticated users allowed
    allowed_emails: list[str] = field(default_factory=list)
    allowed_domains: list[str] = field(default_factory=list)
    # Session settings
    session_duration: int = 86400  # 24 hours default
    session_cookie_name: str = "_instanton_session"
    # OAuth paths (reserved on the HTTPS plane)
    callback_path: str = "/_instanton/oauth/callback"
    logout_path: str = "/_instanton/oauth/logout"

    def __post_init__(self):
        """Validate OAuth configuration."""
        if self.enabled and not self.provider:
            raise ValueError("OAuthConfig.enabled=True requires a provider configuration")
        if self.session_duration < 60:
            raise ValueError("session_duration must be at least 60 seconds")
