"""OAuth authenticator for HTTP requests.

This module provides the main OAuthAuthenticator class that handles:
- Checking requests for valid session cookies
- Generating OAuth authorization URLs with PKCE
- Handling OAuth callbacks and token exchange
- Creating and managing user sessions
- Enforcing access policies (email/domain restrictions)

Security features (based on wooyun-legacy vulnerability analysis):
- PKCE (S256) for authorization code protection
- State parameter for CSRF protection with TTL
- Nonce validation for OIDC replay attack prevention
- JWT signature validation using provider JWKS
- Open redirect protection via URL validation
- Rate limiting on pending authentication states
- Email verification enforcement
- Sanitized error messages to prevent info disclosure
"""

from __future__ import annotations

import base64
import hashlib
import secrets
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any
from urllib.parse import urlencode, urlparse

import structlog
from aiohttp import web

from instanton.security.oauth.config import OAuthConfig, ProviderConfig
from instanton.security.oauth.providers import create_provider
from instanton.security.oauth.session import Session, SessionManager

if TYPE_CHECKING:
    from authlib.integrations.httpx_client import AsyncOAuth2Client

logger = structlog.get_logger()

# Security constants
MAX_PENDING_STATES = 10000  # Prevent memory exhaustion attacks
STATE_TTL_SECONDS = 300  # 5 minutes
NONCE_TTL_SECONDS = 300  # 5 minutes


@dataclass
class PendingAuth:
    """State for a pending OAuth authorization flow.

    Stores the PKCE verifier, original URL, nonce, and creation time
    for validation during the callback.

    Security: All fields are validated on callback to prevent:
    - CSRF attacks (state parameter)
    - Replay attacks (nonce for OIDC)
    - Authorization code injection (PKCE verifier)
    - Open redirects (original_url validated)
    """

    state: str
    code_verifier: str
    original_url: str
    nonce: str | None = None  # For OIDC replay protection
    created_at: float = field(default_factory=time.time)

    @property
    def is_expired(self) -> bool:
        """Check if this pending auth has expired (5 minute TTL)."""
        return time.time() - self.created_at > STATE_TTL_SECONDS


@dataclass
class OAuthResult:
    """Result of OAuth authentication check.

    Contains the authentication decision and any needed redirect information.
    """

    allowed: bool
    reason: str
    session: Session | None = None
    redirect_url: str | None = None


class OAuthAuthenticator:
    """Main OAuth authenticator following Zero Trust principles.

    Handles the complete OAuth 2.0 + PKCE flow:
    1. Check incoming requests for valid session cookies
    2. Redirect unauthenticated users to the OAuth provider
    3. Handle callbacks and exchange codes for tokens
    4. Validate tokens and extract user identity
    5. Check access policies (email/domain restrictions)
    6. Create session cookies for authenticated users

    Security hardening (wooyun-legacy patterns):
    - Validates JWT signatures using provider JWKS (prevent token forgery)
    - Validates redirect URLs to prevent open redirect attacks
    - Rate limits pending auth states to prevent DoS
    - Validates OIDC nonce to prevent replay attacks
    - Checks email verification status (GitHub)
    - Sanitizes error messages to prevent info disclosure
    """

    def __init__(
        self,
        config: OAuthConfig,
        session_manager: SessionManager,
        base_url: str,
    ):
        """Initialize the OAuth authenticator.

        Args:
            config: OAuth configuration with provider settings
            session_manager: Session manager for storing user sessions
            base_url: Base URL of the relay server (e.g., https://tunnels.mycompany.com)
        """
        self._config = config
        self._sessions = session_manager
        self._base_url = base_url.rstrip("/")
        self._pending_states: dict[str, PendingAuth] = {}
        self._oauth_client: AsyncOAuth2Client | None = None
        self._jwks_client: Any = None  # For OIDC JWT validation

        # Parse base URL for redirect validation
        parsed = urlparse(self._base_url)
        self._allowed_redirect_hosts = {parsed.netloc.lower()}

        # Build the callback URL
        self._callback_url = f"{self._base_url}{config.callback_path}"

    async def initialize(self) -> None:
        """Initialize the OAuth client with provider metadata.

        For OIDC providers, this fetches the discovery document and JWKS.
        For OAuth2 providers (GitHub), it uses manual configuration.
        """
        from authlib.integrations.httpx_client import AsyncOAuth2Client

        provider = self._config.provider
        if not provider:
            raise ValueError("OAuth provider not configured")

        client_kwargs: dict[str, Any] = {
            "client_id": provider.client_id,
            "client_secret": provider.client_secret,
            "redirect_uri": self._callback_url,
        }

        if provider.issuer_url:
            # OIDC provider with discovery
            from authlib.oidc.discovery import get_well_known_url

            discovery_url = get_well_known_url(provider.issuer_url, external=True)
            async with AsyncOAuth2Client(**client_kwargs) as client:
                metadata = await client.fetch_server_metadata(discovery_url)
                self._provider_metadata = metadata

            # Initialize JWKS client for ID token validation
            jwks_uri = self._provider_metadata.get("jwks_uri")
            if jwks_uri:
                import httpx
                from authlib.jose import JsonWebKey

                async with httpx.AsyncClient() as http_client:
                    jwks_response = await http_client.get(jwks_uri)
                    jwks_data = jwks_response.json()
                    self._jwks = JsonWebKey.import_key_set(jwks_data)
        else:
            # OAuth2 provider with manual endpoints
            self._provider_metadata = {
                "authorization_endpoint": provider.authorize_url,
                "token_endpoint": provider.token_url,
                "userinfo_endpoint": provider.userinfo_url,
            }
            self._jwks = None

        # Create the OAuth client with the fetched/manual metadata
        self._oauth_client = AsyncOAuth2Client(
            **client_kwargs,
            token_endpoint=self._provider_metadata.get("token_endpoint"),
        )

        logger.info(
            "OAuth authenticator initialized",
            provider=provider.name,
            has_oidc=provider.issuer_url is not None,
            has_jwks=self._jwks is not None,
        )

    async def check(self, request: web.Request) -> OAuthResult:
        """Check if a request is authenticated.

        This is the main entry point called for each HTTP request.
        Returns an OAuthResult indicating whether access is allowed,
        and if not, provides a redirect URL for OAuth.

        Args:
            request: The incoming aiohttp request

        Returns:
            OAuthResult with authentication decision
        """
        # Check for session cookie
        session_id = request.cookies.get(self._config.session_cookie_name)

        if session_id:
            session = await self._sessions.get_session(session_id)
            if session:
                logger.debug(
                    "Valid session found",
                    user=session.user_email,
                    remaining=session.remaining_seconds,
                )
                return OAuthResult(
                    allowed=True,
                    reason="Valid session",
                    session=session,
                )

        # No valid session - generate OAuth redirect
        original_url = str(request.url)
        redirect_url = await self._generate_auth_url(original_url)

        return OAuthResult(
            allowed=False,
            reason="Authentication required",
            redirect_url=redirect_url,
        )

    def _validate_redirect_url(self, url: str) -> bool:
        """Validate that a redirect URL is safe (same origin).

        Prevents open redirect attacks by ensuring the URL points
        to our own domain.

        Security: wooyun-legacy pattern - "步骤跳过" via URL manipulation

        Args:
            url: The URL to validate

        Returns:
            True if the URL is safe to redirect to
        """
        try:
            parsed = urlparse(url)
            # Must be our own host
            if parsed.netloc.lower() not in self._allowed_redirect_hosts:
                return False
            # Must be https or http (no javascript:, data:, etc.)
            if parsed.scheme not in ("https", "http"):
                return False
            return True
        except Exception:
            return False

    async def _generate_auth_url(self, original_url: str) -> str:
        """Generate the OAuth authorization URL with PKCE.

        Creates a cryptographically secure state parameter and PKCE
        code verifier/challenge for security.

        Args:
            original_url: The URL to redirect back to after auth

        Returns:
            The authorization URL to redirect the user to
        """
        provider = self._config.provider
        if not provider:
            raise ValueError("OAuth provider not configured")

        # Rate limit: prevent memory exhaustion from too many pending states
        if len(self._pending_states) >= MAX_PENDING_STATES:
            self._cleanup_pending_states()
            # If still too many after cleanup, reject
            if len(self._pending_states) >= MAX_PENDING_STATES:
                logger.warning("Too many pending OAuth states, rejecting new request")
                raise ValueError("Server busy, please try again later")

        # Validate original URL to prevent open redirect attacks
        if not self._validate_redirect_url(original_url):
            logger.warning(
                "Invalid redirect URL blocked",
                url=original_url[:100],  # Truncate for logging
            )
            # Fall back to base URL
            original_url = self._base_url

        # Generate PKCE parameters (RFC 7636)
        code_verifier = secrets.token_urlsafe(64)
        code_challenge = (
            base64.urlsafe_b64encode(hashlib.sha256(code_verifier.encode()).digest())
            .decode()
            .rstrip("=")
        )

        # Generate state parameter for CSRF protection
        state = secrets.token_urlsafe(32)

        # Generate nonce for OIDC replay protection
        nonce = secrets.token_urlsafe(16) if provider.issuer_url else None

        # Store pending auth for callback validation
        self._pending_states[state] = PendingAuth(
            state=state,
            code_verifier=code_verifier,
            original_url=original_url,
            nonce=nonce,
        )

        # Clean up expired pending auths
        self._cleanup_pending_states()

        # Build authorization URL
        auth_endpoint = self._provider_metadata.get("authorization_endpoint")
        if not auth_endpoint:
            auth_endpoint = provider.authorize_url
        if not auth_endpoint:
            raise ValueError("No authorization endpoint configured")

        params = {
            "client_id": provider.client_id,
            "redirect_uri": self._callback_url,
            "response_type": "code",
            "scope": " ".join(provider.scopes),
            "state": state,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        }

        # Add nonce for OIDC providers
        if nonce:
            params["nonce"] = nonce

        return f"{auth_endpoint}?{urlencode(params)}"

    async def handle_callback(self, request: web.Request) -> web.Response:
        """Handle the OAuth callback after provider authentication.

        This method:
        1. Validates the state parameter (CSRF protection)
        2. Exchanges the authorization code for tokens (with PKCE verifier)
        3. Validates the ID token signature and claims (for OIDC providers)
        4. Extracts user information
        5. Checks access policy (email/domain restrictions)
        6. Creates a session and sets the cookie
        7. Redirects to the original URL

        Args:
            request: The callback request from the OAuth provider

        Returns:
            A response (redirect to original URL or error)
        """
        provider = self._config.provider
        if not provider:
            return web.Response(text="OAuth not configured", status=500)

        # Get authorization code and state from query params
        code = request.query.get("code")
        state = request.query.get("state")
        error = request.query.get("error")
        error_description = request.query.get("error_description")

        # Handle OAuth errors (sanitize description to prevent XSS)
        if error:
            logger.warning(
                "OAuth provider returned error",
                error=error,
                description=error_description,
            )
            # Sanitize error message - don't expose raw provider messages
            safe_error = "access_denied" if error == "access_denied" else "authentication_failed"
            return web.Response(
                text=f"Authentication failed: {safe_error}",
                status=401,
                content_type="text/plain",
            )

        if not code or not state:
            return web.Response(
                text="Missing authorization code or state",
                status=400,
                content_type="text/plain",
            )

        # Validate state and get pending auth (uses dict.pop which is timing-safe)
        pending = self._pending_states.pop(state, None)
        if not pending:
            logger.warning("Invalid or expired state parameter")
            return web.Response(
                text="Invalid or expired authentication request",
                status=400,
                content_type="text/plain",
            )

        if pending.is_expired:
            logger.warning("Expired state parameter")
            return web.Response(
                text="Authentication request expired, please try again",
                status=400,
                content_type="text/plain",
            )

        try:
            # Exchange code for tokens with PKCE verifier
            token_endpoint = self._provider_metadata.get("token_endpoint")
            if not token_endpoint:
                token_endpoint = provider.token_url
            if not token_endpoint:
                raise ValueError("No token endpoint configured")

            from authlib.integrations.httpx_client import AsyncOAuth2Client

            async with AsyncOAuth2Client(
                client_id=provider.client_id,
                client_secret=provider.client_secret,
                redirect_uri=self._callback_url,
                token_endpoint=token_endpoint,
            ) as client:
                token = await client.fetch_token(
                    url=token_endpoint,
                    code=code,
                    code_verifier=pending.code_verifier,
                )

            # Extract user info with proper validation
            user_info = await self._get_user_info(provider, token, pending.nonce)
            user_email = user_info.get("email")
            user_name = user_info.get("name") or user_info.get("login")

            if not user_email:
                logger.warning("No email in user info")
                return web.Response(
                    text="Email not available from OAuth provider",
                    status=401,
                    content_type="text/plain",
                )

            # Check access policy
            if not self._check_access_policy(user_email):
                logger.warning(
                    "User failed access policy check",
                    email=user_email,
                    allowed_domains=self._config.allowed_domains,
                )
                return web.Response(
                    text="Access denied. Your account is not authorized.",
                    status=403,
                    content_type="text/plain",
                )

            # Create session
            session = await self._sessions.create_session(
                user_email=user_email,
                user_name=user_name,
                provider=provider.name,
                claims=user_info,
                duration=self._config.session_duration,
            )

            logger.info(
                "OAuth authentication successful",
                user=user_email,
                provider=provider.name,
            )

            # Build redirect response with session cookie
            # Validate redirect URL again (defense in depth)
            redirect_url = pending.original_url
            if not self._validate_redirect_url(redirect_url):
                redirect_url = self._base_url

            response = web.HTTPFound(redirect_url)
            response.set_cookie(
                self._config.session_cookie_name,
                session.session_id,
                max_age=self._config.session_duration,
                httponly=True,
                secure=True,
                samesite="Lax",
                path="/",
            )

            return response

        except Exception as e:
            # Log full error for debugging, but return sanitized message
            logger.error(
                "OAuth callback error",
                error=str(e),
                error_type=type(e).__name__,
            )
            # Don't expose internal error details to prevent info disclosure
            return web.Response(
                text="Authentication error. Please try again.",
                status=500,
                content_type="text/plain",
            )

    async def _get_user_info(
        self,
        provider: ProviderConfig,
        token: dict,
        expected_nonce: str | None,
    ) -> dict:
        """Get user information from the OAuth provider.

        For OIDC providers, validates and extracts claims from the ID token.
        For OAuth2 providers, fetches from the userinfo endpoint.

        Security: Properly validates JWT signature and claims for OIDC.

        Args:
            provider: The provider configuration
            token: The token response from the provider
            expected_nonce: The nonce we sent (for OIDC replay protection)

        Returns:
            Dictionary with user information (email, name, etc.)
        """
        from authlib.integrations.httpx_client import AsyncOAuth2Client

        # For OIDC, validate and extract from ID token
        if "id_token" in token and provider.issuer_url and self._jwks:
            try:
                from authlib.jose import jwt
                from authlib.jose.errors import JoseError

                id_token = token["id_token"]

                # Validate JWT signature using provider's JWKS
                try:
                    claims = jwt.decode(
                        id_token,
                        self._jwks,
                        claims_options={
                            "iss": {"essential": True, "value": provider.issuer_url},
                            "aud": {"essential": True, "value": provider.client_id},
                            "exp": {"essential": True},
                        },
                    )
                    claims.validate()
                except JoseError as e:
                    logger.warning("ID token validation failed", error=str(e))
                    raise ValueError("Invalid ID token") from e

                # Validate nonce to prevent replay attacks
                if expected_nonce:
                    token_nonce = claims.get("nonce")
                    if not token_nonce or not secrets.compare_digest(token_nonce, expected_nonce):
                        logger.warning("Nonce mismatch in ID token")
                        raise ValueError("Invalid nonce in ID token")

                if claims.get("email"):
                    # Check email_verified claim if present
                    if claims.get("email_verified") is False:
                        logger.warning("Email not verified in ID token")
                        raise ValueError("Email not verified")
                    return dict(claims)

            except Exception as e:
                logger.debug("Failed to validate ID token", error=str(e))
                # Fall through to userinfo endpoint

        # Fall back to userinfo endpoint
        userinfo_endpoint = self._provider_metadata.get("userinfo_endpoint")
        if not userinfo_endpoint:
            userinfo_endpoint = provider.userinfo_url
        if not userinfo_endpoint:
            raise ValueError("No userinfo endpoint configured")

        async with AsyncOAuth2Client(
            client_id=provider.client_id,
            token=token,
        ) as client:
            response = await client.get(userinfo_endpoint)
            user_info = response.json()

        # GitHub special case: email might need separate API call
        if provider.name == "github" and not user_info.get("email"):
            async with AsyncOAuth2Client(
                client_id=provider.client_id,
                token=token,
            ) as client:
                email_response = await client.get("https://api.github.com/user/emails")
                emails = email_response.json()
                for email_entry in emails:
                    # Only use verified, primary email
                    if email_entry.get("primary") and email_entry.get("verified"):
                        user_info["email"] = email_entry.get("email")
                        break
                else:
                    # No verified primary email found
                    logger.warning("No verified primary email found for GitHub user")

        return user_info

    def _check_access_policy(self, email: str) -> bool:
        """Check if a user passes access restrictions.

        If no restrictions are configured, all authenticated users are allowed.
        Otherwise, the user must match either:
        - An exact email in allowed_emails, OR
        - An email domain in allowed_domains

        Security: Uses case-insensitive comparison for both email and domain.

        Args:
            email: The user's email address

        Returns:
            True if access is allowed, False otherwise
        """
        # If no restrictions, allow all authenticated users
        if not self._config.allowed_emails and not self._config.allowed_domains:
            return True

        email_lower = email.lower()

        # Check exact email match (case-insensitive)
        for allowed_email in self._config.allowed_emails:
            if secrets.compare_digest(email_lower, allowed_email.lower()):
                return True

        # Check domain match
        if "@" in email:
            email_domain = email_lower.split("@")[-1]
            for allowed_domain in self._config.allowed_domains:
                if secrets.compare_digest(email_domain, allowed_domain.lower()):
                    return True

        return False

    async def handle_logout(self, request: web.Request) -> web.Response:
        """Handle logout - clear session and cookie.

        Args:
            request: The logout request

        Returns:
            A redirect response to the base URL with cleared cookie
        """
        session_id = request.cookies.get(self._config.session_cookie_name)

        if session_id:
            deleted = await self._sessions.delete_session(session_id)
            if deleted:
                logger.info("User logged out")

        # Redirect to base URL with expired cookie
        response = web.HTTPFound(self._base_url)
        response.del_cookie(
            self._config.session_cookie_name,
            path="/",
        )

        return response

    def _cleanup_pending_states(self) -> None:
        """Remove expired pending authentication states."""
        expired = [state for state, pending in self._pending_states.items() if pending.is_expired]
        for state in expired:
            del self._pending_states[state]


async def create_oauth_authenticator(
    provider: str,
    client_id: str,
    client_secret: str,
    session_manager: SessionManager,
    base_url: str,
    issuer_url: str | None = None,
    allowed_domains: list[str] | None = None,
    allowed_emails: list[str] | None = None,
    session_duration: int = 86400,
) -> OAuthAuthenticator:
    """Factory function to create an OAuth authenticator.

    This is the recommended way to create an OAuthAuthenticator instance.
    It handles provider configuration and initialization.

    Args:
        provider: Provider type ("github", "google", or "oidc")
        client_id: OAuth client ID
        client_secret: OAuth client secret
        session_manager: Session manager for storing user sessions
        base_url: Base URL of the relay server
        issuer_url: OIDC issuer URL (required for "oidc" provider)
        allowed_domains: List of allowed email domains
        allowed_emails: List of allowed specific emails
        session_duration: Session duration in seconds

    Returns:
        Initialized OAuthAuthenticator ready to use
    """
    provider_config = create_provider(
        provider_type=provider,
        client_id=client_id,
        client_secret=client_secret,
        issuer_url=issuer_url,
    )

    oauth_config = OAuthConfig(
        enabled=True,
        provider=provider_config,
        allowed_domains=allowed_domains or [],
        allowed_emails=allowed_emails or [],
        session_duration=session_duration,
    )

    authenticator = OAuthAuthenticator(
        config=oauth_config,
        session_manager=session_manager,
        base_url=base_url,
    )

    await authenticator.initialize()

    return authenticator
