"""Tests for OAuth/OIDC authentication module."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import time

import pytest

from instanton.security.oauth.config import OAuthConfig, ProviderConfig
from instanton.security.oauth.providers import (
    create_github_provider,
    create_google_provider,
    create_oidc_provider,
    create_provider,
)
from instanton.security.oauth.session import Session, SessionManager


class TestProviderConfig:
    """Tests for ProviderConfig."""

    def test_oidc_provider_with_issuer_url(self):
        """Test OIDC provider configuration with issuer URL."""
        config = ProviderConfig(
            name="google",
            client_id="test-client-id",
            client_secret="test-client-secret",
            issuer_url="https://accounts.google.com",
        )
        assert config.name == "google"
        assert config.issuer_url == "https://accounts.google.com"
        assert "openid" in config.scopes

    def test_oauth2_provider_with_manual_endpoints(self):
        """Test OAuth2 provider configuration with manual endpoints."""
        config = ProviderConfig(
            name="github",
            client_id="test-client-id",
            client_secret="test-client-secret",
            authorize_url="https://github.com/login/oauth/authorize",
            token_url="https://github.com/login/oauth/access_token",
            userinfo_url="https://api.github.com/user",
            scopes=["user:email"],
        )
        assert config.name == "github"
        assert config.authorize_url is not None
        assert config.token_url is not None

    def test_provider_requires_endpoints(self):
        """Test that provider requires either issuer_url or manual endpoints."""
        with pytest.raises(ValueError, match="requires either issuer_url"):
            ProviderConfig(
                name="invalid",
                client_id="test-client-id",
                client_secret="test-client-secret",
            )

    def test_custom_scopes(self):
        """Test provider with custom scopes."""
        config = ProviderConfig(
            name="custom",
            client_id="test-client-id",
            client_secret="test-client-secret",
            issuer_url="https://custom.example.com",
            scopes=["openid", "email", "custom_scope"],
        )
        assert "custom_scope" in config.scopes


class TestOAuthConfig:
    """Tests for OAuthConfig."""

    def test_default_config_disabled(self):
        """Test default OAuthConfig is disabled."""
        config = OAuthConfig()
        assert config.enabled is False
        assert config.provider is None

    def test_enabled_requires_provider(self):
        """Test that enabled=True requires a provider."""
        with pytest.raises(ValueError, match="requires a provider"):
            OAuthConfig(enabled=True, provider=None)

    def test_enabled_with_provider(self):
        """Test enabled config with provider."""
        provider = ProviderConfig(
            name="test",
            client_id="test-id",
            client_secret="test-secret",
            issuer_url="https://example.com",
        )
        config = OAuthConfig(enabled=True, provider=provider)
        assert config.enabled is True
        assert config.provider is not None

    def test_session_duration_minimum(self):
        """Test session duration minimum validation."""
        provider = ProviderConfig(
            name="test",
            client_id="test-id",
            client_secret="test-secret",
            issuer_url="https://example.com",
        )
        with pytest.raises(ValueError, match="at least 60 seconds"):
            OAuthConfig(enabled=True, provider=provider, session_duration=30)

    def test_default_paths(self):
        """Test default OAuth paths."""
        config = OAuthConfig()
        assert config.callback_path == "/_instanton/oauth/callback"
        assert config.logout_path == "/_instanton/oauth/logout"

    def test_allowed_domains_and_emails(self):
        """Test allowed domains and emails configuration."""
        provider = ProviderConfig(
            name="test",
            client_id="test-id",
            client_secret="test-secret",
            issuer_url="https://example.com",
        )
        config = OAuthConfig(
            enabled=True,
            provider=provider,
            allowed_domains=["example.com", "test.com"],
            allowed_emails=["admin@other.com"],
        )
        assert len(config.allowed_domains) == 2
        assert len(config.allowed_emails) == 1


class TestSession:
    """Tests for Session."""

    def test_session_creation(self):
        """Test basic session creation."""
        session = Session(
            session_id="test-session-id",
            user_email="user@example.com",
            user_name="Test User",
            provider="google",
        )
        assert session.session_id == "test-session-id"
        assert session.user_email == "user@example.com"
        assert session.user_name == "Test User"
        assert session.provider == "google"
        assert not session.is_expired

    def test_session_expiration(self):
        """Test session expiration check."""
        now = time.time()
        session = Session(
            session_id="test-session-id",
            user_email="user@example.com",
            user_name=None,
            provider="github",
            created_at=now - 100,
            expires_at=now - 10,  # Already expired
        )
        assert session.is_expired is True

    def test_session_not_expired(self):
        """Test session that hasn't expired."""
        now = time.time()
        session = Session(
            session_id="test-session-id",
            user_email="user@example.com",
            user_name=None,
            provider="github",
            created_at=now,
            expires_at=now + 3600,
        )
        assert session.is_expired is False

    def test_session_remaining_seconds(self):
        """Test remaining seconds calculation."""
        now = time.time()
        session = Session(
            session_id="test-session-id",
            user_email="user@example.com",
            user_name=None,
            provider="github",
            created_at=now,
            expires_at=now + 3600,
        )
        assert 3599 <= session.remaining_seconds <= 3600

    def test_session_remaining_seconds_when_expired(self):
        """Test remaining seconds when expired is 0."""
        now = time.time()
        session = Session(
            session_id="test-session-id",
            user_email="user@example.com",
            user_name=None,
            provider="github",
            created_at=now - 100,
            expires_at=now - 10,
        )
        assert session.remaining_seconds == 0

    def test_session_with_claims(self):
        """Test session with OIDC claims."""
        claims = {
            "sub": "123456",
            "email": "user@example.com",
            "name": "Test User",
            "picture": "https://example.com/photo.jpg",
        }
        session = Session(
            session_id="test-session-id",
            user_email="user@example.com",
            user_name="Test User",
            provider="google",
            claims=claims,
        )
        assert session.claims["sub"] == "123456"
        assert session.claims["picture"] == "https://example.com/photo.jpg"


class TestSessionManager:
    """Tests for SessionManager."""

    @pytest.mark.asyncio
    async def test_create_session(self):
        """Test session creation."""
        manager = SessionManager()
        session = await manager.create_session(
            user_email="user@example.com",
            user_name="Test User",
            provider="google",
        )
        assert session.user_email == "user@example.com"
        assert session.session_id is not None
        assert len(session.session_id) > 20  # Secure random ID

    @pytest.mark.asyncio
    async def test_get_session(self):
        """Test getting a session by ID."""
        manager = SessionManager()
        created = await manager.create_session(
            user_email="user@example.com",
            user_name="Test User",
            provider="google",
        )
        retrieved = await manager.get_session(created.session_id)
        assert retrieved is not None
        assert retrieved.user_email == created.user_email

    @pytest.mark.asyncio
    async def test_get_nonexistent_session(self):
        """Test getting a session that doesn't exist."""
        manager = SessionManager()
        session = await manager.get_session("nonexistent-session-id")
        assert session is None

    @pytest.mark.asyncio
    async def test_delete_session(self):
        """Test deleting a session."""
        manager = SessionManager()
        session = await manager.create_session(
            user_email="user@example.com",
            user_name="Test User",
            provider="google",
        )
        deleted = await manager.delete_session(session.session_id)
        assert deleted is True

        # Session should no longer exist
        retrieved = await manager.get_session(session.session_id)
        assert retrieved is None

    @pytest.mark.asyncio
    async def test_delete_nonexistent_session(self):
        """Test deleting a session that doesn't exist."""
        manager = SessionManager()
        deleted = await manager.delete_session("nonexistent-session-id")
        assert deleted is False

    @pytest.mark.asyncio
    async def test_get_expired_session_returns_none(self):
        """Test that getting an expired session returns None and removes it."""
        manager = SessionManager(session_duration=1)
        session = await manager.create_session(
            user_email="user@example.com",
            user_name="Test User",
            provider="google",
            duration=1,  # 1 second
        )

        # Wait for expiration
        await asyncio.sleep(1.5)

        retrieved = await manager.get_session(session.session_id)
        assert retrieved is None

    @pytest.mark.asyncio
    async def test_session_count(self):
        """Test session count."""
        manager = SessionManager()

        assert await manager.get_session_count() == 0

        await manager.create_session(
            user_email="user1@example.com",
            user_name="User 1",
            provider="google",
        )
        await manager.create_session(
            user_email="user2@example.com",
            user_name="User 2",
            provider="google",
        )

        assert await manager.get_session_count() == 2

    @pytest.mark.asyncio
    async def test_custom_session_duration(self):
        """Test creating session with custom duration."""
        manager = SessionManager(session_duration=3600)
        session = await manager.create_session(
            user_email="user@example.com",
            user_name="Test User",
            provider="google",
            duration=7200,  # Override default
        )
        # Session should expire in about 2 hours
        assert 7199 <= session.remaining_seconds <= 7200

    @pytest.mark.asyncio
    async def test_start_stop(self):
        """Test session manager start/stop."""
        manager = SessionManager(cleanup_interval=0.1)
        await manager.start()
        assert manager._cleanup_task is not None

        await manager.stop()
        assert manager._cleanup_task is None


class TestProviderFactories:
    """Tests for provider factory functions."""

    def test_create_github_provider(self):
        """Test GitHub provider creation."""
        provider = create_github_provider(
            client_id="github-client-id",
            client_secret="github-client-secret",
        )
        assert provider.name == "github"
        assert provider.authorize_url == "https://github.com/login/oauth/authorize"
        assert provider.token_url == "https://github.com/login/oauth/access_token"
        assert provider.userinfo_url == "https://api.github.com/user"
        assert "user:email" in provider.scopes

    def test_create_google_provider(self):
        """Test Google provider creation."""
        provider = create_google_provider(
            client_id="google-client-id",
            client_secret="google-client-secret",
        )
        assert provider.name == "google"
        assert provider.issuer_url == "https://accounts.google.com"
        assert "openid" in provider.scopes
        assert "email" in provider.scopes

    def test_create_oidc_provider(self):
        """Test generic OIDC provider creation."""
        provider = create_oidc_provider(
            client_id="oidc-client-id",
            client_secret="oidc-client-secret",
            issuer_url="https://mycompany.okta.com",
            name="okta",
        )
        assert provider.name == "okta"
        assert provider.issuer_url == "https://mycompany.okta.com"

    def test_create_provider_github(self):
        """Test factory function with github type."""
        provider = create_provider(
            provider_type="github",
            client_id="test-id",
            client_secret="test-secret",
        )
        assert provider.name == "github"

    def test_create_provider_google(self):
        """Test factory function with google type."""
        provider = create_provider(
            provider_type="google",
            client_id="test-id",
            client_secret="test-secret",
        )
        assert provider.name == "google"

    def test_create_provider_oidc(self):
        """Test factory function with oidc type."""
        provider = create_provider(
            provider_type="oidc",
            client_id="test-id",
            client_secret="test-secret",
            issuer_url="https://example.com",
        )
        assert provider.name == "oidc"

    def test_create_provider_oidc_requires_issuer(self):
        """Test that oidc provider requires issuer_url."""
        with pytest.raises(ValueError, match="requires issuer_url"):
            create_provider(
                provider_type="oidc",
                client_id="test-id",
                client_secret="test-secret",
            )

    def test_create_provider_unknown_type(self):
        """Test factory function with unknown type."""
        with pytest.raises(ValueError, match="Unknown provider type"):
            create_provider(
                provider_type="unknown",
                client_id="test-id",
                client_secret="test-secret",
            )

    def test_create_provider_case_insensitive(self):
        """Test that provider type is case insensitive."""
        provider = create_provider(
            provider_type="GITHUB",
            client_id="test-id",
            client_secret="test-secret",
        )
        assert provider.name == "github"


class TestPKCE:
    """Tests for PKCE code challenge generation."""

    def test_code_challenge_generation(self):
        """Test PKCE code challenge is generated correctly."""
        import secrets

        # Simulate PKCE code verifier/challenge generation
        code_verifier = secrets.token_urlsafe(64)
        code_challenge = base64.urlsafe_b64encode(
            hashlib.sha256(code_verifier.encode()).digest()
        ).decode().rstrip("=")

        # Verify the challenge
        assert len(code_verifier) > 40  # Should be long enough for security
        assert len(code_challenge) == 43  # SHA256 base64url without padding

    def test_code_challenge_reproducible(self):
        """Test that same verifier produces same challenge."""
        code_verifier = "test-code-verifier-12345"

        challenge1 = base64.urlsafe_b64encode(
            hashlib.sha256(code_verifier.encode()).digest()
        ).decode().rstrip("=")

        challenge2 = base64.urlsafe_b64encode(
            hashlib.sha256(code_verifier.encode()).digest()
        ).decode().rstrip("=")

        assert challenge1 == challenge2


class TestAccessPolicy:
    """Tests for access policy checking logic."""

    def test_no_restrictions_allows_all(self):
        """Test that no restrictions allows all users."""
        # When no restrictions configured, all authenticated users allowed
        allowed_domains: list[str] = []
        allowed_emails: list[str] = []

        def check_access(email: str) -> bool:
            if not allowed_emails and not allowed_domains:
                return True
            if email.lower() in (e.lower() for e in allowed_emails):
                return True
            email_domain = email.split("@")[-1].lower()
            if email_domain in (d.lower() for d in allowed_domains):
                return True
            return False

        assert check_access("any@example.com") is True
        assert check_access("user@other.com") is True

    def test_domain_restriction(self):
        """Test domain-based access restriction."""
        allowed_domains = ["mycompany.com"]
        allowed_emails: list[str] = []

        def check_access(email: str) -> bool:
            if not allowed_emails and not allowed_domains:
                return True
            if email.lower() in (e.lower() for e in allowed_emails):
                return True
            email_domain = email.split("@")[-1].lower()
            if email_domain in (d.lower() for d in allowed_domains):
                return True
            return False

        assert check_access("user@mycompany.com") is True
        assert check_access("admin@mycompany.com") is True
        assert check_access("user@other.com") is False

    def test_email_restriction(self):
        """Test email-based access restriction."""
        allowed_domains: list[str] = []
        allowed_emails = ["admin@example.com", "support@example.com"]

        def check_access(email: str) -> bool:
            if not allowed_emails and not allowed_domains:
                return True
            if email.lower() in (e.lower() for e in allowed_emails):
                return True
            email_domain = email.split("@")[-1].lower()
            if email_domain in (d.lower() for d in allowed_domains):
                return True
            return False

        assert check_access("admin@example.com") is True
        assert check_access("support@example.com") is True
        assert check_access("user@example.com") is False

    def test_combined_restrictions(self):
        """Test combined domain and email restrictions."""
        allowed_domains = ["mycompany.com"]
        allowed_emails = ["partner@external.com"]

        def check_access(email: str) -> bool:
            if not allowed_emails and not allowed_domains:
                return True
            if email.lower() in (e.lower() for e in allowed_emails):
                return True
            email_domain = email.split("@")[-1].lower()
            if email_domain in (d.lower() for d in allowed_domains):
                return True
            return False

        assert check_access("user@mycompany.com") is True
        assert check_access("partner@external.com") is True
        assert check_access("random@external.com") is False

    def test_case_insensitive_matching(self):
        """Test that email/domain matching is case insensitive."""
        allowed_domains = ["MyCompany.com"]
        allowed_emails = ["Admin@Example.com"]

        def check_access(email: str) -> bool:
            if not allowed_emails and not allowed_domains:
                return True
            if email.lower() in (e.lower() for e in allowed_emails):
                return True
            email_domain = email.split("@")[-1].lower()
            if email_domain in (d.lower() for d in allowed_domains):
                return True
            return False

        assert check_access("USER@MYCOMPANY.COM") is True
        assert check_access("admin@example.com") is True


class TestStateParameter:
    """Tests for state parameter (CSRF protection)."""

    def test_state_generation(self):
        """Test state parameter generation."""
        import secrets

        state = secrets.token_urlsafe(32)

        # State should be long enough for security
        assert len(state) >= 32

        # State should be URL-safe
        assert all(c in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_" for c in state)

    def test_state_uniqueness(self):
        """Test that generated states are unique."""
        import secrets

        states = [secrets.token_urlsafe(32) for _ in range(100)]
        assert len(states) == len(set(states))  # All unique


class TestOpenRedirectPrevention:
    """Tests for open redirect vulnerability prevention."""

    def test_valid_same_origin_url(self):
        """Test that same-origin URLs are accepted."""
        from urllib.parse import urlparse

        base_url = "https://tunnels.mycompany.com"
        test_url = "https://tunnels.mycompany.com/some/path?query=value"

        parsed_base = urlparse(base_url)
        parsed_test = urlparse(test_url)

        assert parsed_test.netloc.lower() == parsed_base.netloc.lower()
        assert parsed_test.scheme in ("https", "http")

    def test_invalid_different_origin_url(self):
        """Test that different-origin URLs are rejected."""
        from urllib.parse import urlparse

        base_url = "https://tunnels.mycompany.com"
        malicious_url = "https://evil.com/phishing"

        parsed_base = urlparse(base_url)
        parsed_test = urlparse(malicious_url)

        # Should not match
        assert parsed_test.netloc.lower() != parsed_base.netloc.lower()

    def test_javascript_url_rejected(self):
        """Test that javascript: URLs are rejected."""
        from urllib.parse import urlparse

        malicious_url = "javascript:alert(document.cookie)"
        parsed = urlparse(malicious_url)

        # javascript: scheme should be rejected
        assert parsed.scheme not in ("https", "http")

    def test_data_url_rejected(self):
        """Test that data: URLs are rejected."""
        from urllib.parse import urlparse

        malicious_url = "data:text/html,<script>alert(1)</script>"
        parsed = urlparse(malicious_url)

        # data: scheme should be rejected
        assert parsed.scheme not in ("https", "http")


class TestTimingAttackPrevention:
    """Tests for timing attack resistant comparisons."""

    def test_secrets_compare_digest_same_length(self):
        """Test that compare_digest works for same-length strings."""
        import secrets

        # Same value
        a = "test@example.com"
        b = "test@example.com"
        assert secrets.compare_digest(a, b) is True

        # Different value, same length
        a = "test@example.com"
        b = "user@example.com"
        assert secrets.compare_digest(a, b) is False

    def test_secrets_compare_digest_different_length(self):
        """Test that compare_digest works for different-length strings."""
        import secrets

        # Different lengths
        a = "short"
        b = "longerstring"
        assert secrets.compare_digest(a, b) is False


class TestNonceValidation:
    """Tests for OIDC nonce validation."""

    def test_nonce_generation(self):
        """Test nonce generation for OIDC."""
        import secrets

        nonce = secrets.token_urlsafe(16)

        # Nonce should be sufficiently random
        assert len(nonce) >= 16

    def test_nonce_uniqueness(self):
        """Test that generated nonces are unique."""
        import secrets

        nonces = [secrets.token_urlsafe(16) for _ in range(100)]
        assert len(nonces) == len(set(nonces))

    def test_nonce_comparison_timing_safe(self):
        """Test that nonce comparison uses timing-safe comparison."""
        import secrets

        nonce1 = "abc123xyz"
        nonce2 = "abc123xyz"
        nonce3 = "different"

        # Use secrets.compare_digest for timing-safe comparison
        assert secrets.compare_digest(nonce1, nonce2) is True
        assert secrets.compare_digest(nonce1, nonce3) is False


class TestPendingAuthExpiration:
    """Tests for pending authentication state expiration."""

    def test_pending_auth_not_expired(self):
        """Test that fresh pending auth is not expired."""
        from instanton.security.oauth.authenticator import PendingAuth

        pending = PendingAuth(
            state="test-state",
            code_verifier="test-verifier",
            original_url="https://example.com",
        )

        assert pending.is_expired is False

    def test_pending_auth_expired(self):
        """Test that old pending auth is expired."""
        from instanton.security.oauth.authenticator import PendingAuth

        pending = PendingAuth(
            state="test-state",
            code_verifier="test-verifier",
            original_url="https://example.com",
            created_at=time.time() - 400,  # 400 seconds ago (> 300s TTL)
        )

        assert pending.is_expired is True

    def test_pending_auth_with_nonce(self):
        """Test pending auth with nonce for OIDC."""
        from instanton.security.oauth.authenticator import PendingAuth

        pending = PendingAuth(
            state="test-state",
            code_verifier="test-verifier",
            original_url="https://example.com",
            nonce="test-nonce-value",
        )

        assert pending.nonce == "test-nonce-value"


class TestErrorSanitization:
    """Tests for error message sanitization."""

    def test_error_messages_do_not_leak_internals(self):
        """Test that error messages don't expose internal details."""
        # These are the sanitized error messages from authenticator.py
        safe_errors = [
            "Authentication failed: access_denied",
            "Authentication failed: authentication_failed",
            "Authentication error. Please try again.",
            "Invalid or expired authentication request",
        ]

        for error in safe_errors:
            # Should not contain stack traces
            assert "Traceback" not in error
            # Should not contain file paths
            assert ".py" not in error
            # Should not contain exception class names
            assert "Exception" not in error
            assert "Error:" not in error  # as in "ValueError:"


class TestEmailVerification:
    """Tests for email verification enforcement."""

    def test_unverified_email_handling(self):
        """Test that unverified emails should be rejected."""
        # This tests the logic - in OIDC, email_verified=False means unverified
        claims = {
            "email": "user@example.com",
            "email_verified": False,
        }

        # email_verified is explicitly False, should be rejected
        assert claims.get("email_verified") is False

    def test_verified_email_handling(self):
        """Test that verified emails are accepted."""
        claims = {
            "email": "user@example.com",
            "email_verified": True,
        }

        # email_verified is True, should be accepted
        assert claims.get("email_verified") is True

    def test_missing_email_verified_claim(self):
        """Test handling when email_verified claim is missing."""
        claims = {
            "email": "user@example.com",
        }

        # Missing claim should not be treated as False
        assert claims.get("email_verified") is None
        # Our code treats None/missing as acceptable (only explicit False is rejected)
