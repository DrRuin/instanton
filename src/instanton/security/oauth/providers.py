"""Pre-configured OAuth provider templates.

Provides factory functions and templates for common OAuth providers
like GitHub, Google, and generic OIDC providers.
"""

from __future__ import annotations

from instanton.security.oauth.config import ProviderConfig


def create_github_provider(client_id: str, client_secret: str) -> ProviderConfig:
    """Create GitHub OAuth provider configuration.

    GitHub uses OAuth2 (not full OIDC), so we specify endpoints manually.
    The userinfo endpoint returns the user profile with email.

    Args:
        client_id: GitHub OAuth App client ID
        client_secret: GitHub OAuth App client secret

    Returns:
        Configured ProviderConfig for GitHub
    """
    return ProviderConfig(
        name="github",
        client_id=client_id,
        client_secret=client_secret,
        authorize_url="https://github.com/login/oauth/authorize",
        token_url="https://github.com/login/oauth/access_token",
        userinfo_url="https://api.github.com/user",
        scopes=["user:email"],
    )


def create_google_provider(client_id: str, client_secret: str) -> ProviderConfig:
    """Create Google OAuth/OIDC provider configuration.

    Google supports OIDC discovery, so we use issuer_url for auto-configuration.

    Args:
        client_id: Google OAuth client ID
        client_secret: Google OAuth client secret

    Returns:
        Configured ProviderConfig for Google
    """
    return ProviderConfig(
        name="google",
        client_id=client_id,
        client_secret=client_secret,
        issuer_url="https://accounts.google.com",
        scopes=["openid", "email", "profile"],
    )


def create_oidc_provider(
    client_id: str,
    client_secret: str,
    issuer_url: str,
    name: str = "oidc",
    scopes: list[str] | None = None,
) -> ProviderConfig:
    """Create a generic OIDC provider configuration.

    Works with any OIDC-compliant provider that supports discovery
    (Okta, Auth0, Keycloak, Azure AD, etc.).

    Args:
        client_id: OAuth client ID
        client_secret: OAuth client secret
        issuer_url: OIDC issuer URL (e.g., https://mycompany.okta.com)
        name: Provider name for logging/identification
        scopes: OAuth scopes to request (defaults to openid, email, profile)

    Returns:
        Configured ProviderConfig for the OIDC provider
    """
    return ProviderConfig(
        name=name,
        client_id=client_id,
        client_secret=client_secret,
        issuer_url=issuer_url,
        scopes=scopes or ["openid", "email", "profile"],
    )


def create_provider(
    provider_type: str,
    client_id: str,
    client_secret: str,
    issuer_url: str | None = None,
    **kwargs,
) -> ProviderConfig:
    """Factory to create provider config from type name.

    This is the main entry point for creating provider configurations.
    It handles the mapping from simple provider names to full configurations.

    Args:
        provider_type: One of "github", "google", or "oidc"
        client_id: OAuth client ID
        client_secret: OAuth client secret
        issuer_url: OIDC issuer URL (required for "oidc" type)
        **kwargs: Additional arguments passed to the provider factory

    Returns:
        Configured ProviderConfig

    Raises:
        ValueError: If provider_type is unknown or required args are missing
    """
    provider_type = provider_type.lower()

    if provider_type == "github":
        return create_github_provider(client_id, client_secret)

    elif provider_type == "google":
        return create_google_provider(client_id, client_secret)

    elif provider_type == "oidc":
        if not issuer_url:
            raise ValueError("OIDC provider requires issuer_url")
        return create_oidc_provider(
            client_id=client_id,
            client_secret=client_secret,
            issuer_url=issuer_url,
            **kwargs,
        )

    else:
        raise ValueError(
            f"Unknown provider type: {provider_type}. "
            "Supported: 'github', 'google', 'oidc'"
        )


# Common OIDC issuer URLs for reference (not used in code, just documentation)
COMMON_ISSUERS = {
    "google": "https://accounts.google.com",
    "microsoft": "https://login.microsoftonline.com/{tenant}/v2.0",
    "okta": "https://{domain}.okta.com",
    "auth0": "https://{domain}.auth0.com",
    "keycloak": "https://{host}/realms/{realm}",
}
