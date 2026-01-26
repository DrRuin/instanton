"""OAuth/OIDC authentication module for self-hosted Instanton.

This module provides OAuth 2.0 / OpenID Connect authentication for
organizations running their own Instanton server who want identity-aware
tunnel access.

Core Philosophy: Zero Trust - "Never trust, always verify" - authenticate
users at the tunnel edge before requests reach the local service.

Example usage:

    from instanton.security.oauth import (
        OAuthAuthenticator,
        OAuthConfig,
        SessionManager,
        create_oauth_authenticator,
        create_provider,
    )

    # Create session manager
    session_manager = SessionManager()
    await session_manager.start()

    # Create authenticator with factory function (recommended)
    authenticator = await create_oauth_authenticator(
        provider="github",
        client_id="...",
        client_secret="...",
        session_manager=session_manager,
        base_url="https://tunnels.mycompany.com",
        allowed_domains=["mycompany.com"],
    )

    # Or create manually for more control
    provider_config = create_provider(
        provider_type="google",
        client_id="...",
        client_secret="...",
    )
    oauth_config = OAuthConfig(
        enabled=True,
        provider=provider_config,
        allowed_domains=["mycompany.com"],
    )
    authenticator = OAuthAuthenticator(
        config=oauth_config,
        session_manager=session_manager,
        base_url="https://tunnels.mycompany.com",
    )
    await authenticator.initialize()
"""

from instanton.security.oauth.authenticator import (
    OAuthAuthenticator,
    OAuthResult,
    PendingAuth,
    create_oauth_authenticator,
)
from instanton.security.oauth.config import (
    OAuthConfig,
    ProviderConfig,
)
from instanton.security.oauth.providers import (
    create_github_provider,
    create_google_provider,
    create_oidc_provider,
    create_provider,
)
from instanton.security.oauth.session import (
    Session,
    SessionManager,
)

__all__ = [
    # Authenticator
    "OAuthAuthenticator",
    "OAuthResult",
    "PendingAuth",
    "create_oauth_authenticator",
    # Config
    "OAuthConfig",
    "ProviderConfig",
    # Providers
    "create_github_provider",
    "create_google_provider",
    "create_oidc_provider",
    "create_provider",
    # Session
    "Session",
    "SessionManager",
]
