"""Tests for webhook verification."""

from __future__ import annotations

import base64
import hashlib
import hmac
import time

import pytest

from instanton.webhooks.providers import (
    SUPPORTED_PROVIDERS,
    DropboxWebhook,
    GitHubWebhook,
    GitLabWebhook,
    IntercomWebhook,
    ShopifyWebhook,
    SlackWebhook,
    StripeWebhook,
    VerificationConfig,
    WebhookRequest,
    get_provider,
)
from instanton.webhooks.verifier import (
    VerificationResult,
    WebhookProvider,
    WebhookVerifier,
)


class TestGitHubWebhook:
    """Tests for GitHub webhook verification."""

    def test_valid_sha256_signature(self):
        """Test valid SHA256 signature verification."""
        provider = GitHubWebhook()
        secret = "test-secret-123"
        body = b'{"action": "opened", "number": 1}'

        # Generate valid signature
        signature = "sha256=" + hmac.new(
            secret.encode(), body, hashlib.sha256
        ).hexdigest()

        request = WebhookRequest(
            headers={"X-Hub-Signature-256": signature},
            body=body,
        )
        config = VerificationConfig(secret=secret)

        is_valid, error = provider.verify(request, config)
        assert is_valid
        assert error == ""

    def test_valid_sha1_signature(self):
        """Test valid SHA1 signature verification (fallback)."""
        provider = GitHubWebhook()
        secret = "test-secret-123"
        body = b'{"action": "opened"}'

        signature = "sha1=" + hmac.new(
            secret.encode(), body, hashlib.sha1
        ).hexdigest()

        request = WebhookRequest(
            headers={"X-Hub-Signature": signature},
            body=body,
        )
        config = VerificationConfig(secret=secret)

        is_valid, error = provider.verify(request, config)
        assert is_valid

    def test_missing_signature(self):
        """Test missing signature header."""
        provider = GitHubWebhook()
        request = WebhookRequest(headers={}, body=b'{}')
        config = VerificationConfig(secret="secret")

        is_valid, error = provider.verify(request, config)
        assert not is_valid
        assert "Missing signature" in error

    def test_invalid_signature(self):
        """Test invalid signature."""
        provider = GitHubWebhook()
        request = WebhookRequest(
            headers={"X-Hub-Signature-256": "sha256=invalid"},
            body=b'{"test": true}',
        )
        config = VerificationConfig(secret="secret")

        is_valid, error = provider.verify(request, config)
        assert not is_valid
        assert "Invalid signature" in error


class TestStripeWebhook:
    """Tests for Stripe webhook verification."""

    def test_valid_signature(self):
        """Test valid Stripe signature."""
        provider = StripeWebhook()
        secret = "whsec_test123"
        timestamp = str(int(time.time()))
        body = '{"type": "payment_intent.succeeded"}'

        # Generate signature
        signed_payload = f"{timestamp}.{body}"
        signature = hmac.new(
            secret.encode(), signed_payload.encode(), hashlib.sha256
        ).hexdigest()

        request = WebhookRequest(
            headers={"Stripe-Signature": f"t={timestamp},v1={signature}"},
            body=body.encode(),
        )
        config = VerificationConfig(secret=secret)

        is_valid, error = provider.verify(request, config)
        assert is_valid

    def test_expired_timestamp(self):
        """Test expired timestamp."""
        provider = StripeWebhook()
        secret = "whsec_test123"
        timestamp = str(int(time.time()) - 600)  # 10 minutes ago
        body = '{"type": "test"}'

        signed_payload = f"{timestamp}.{body}"
        signature = hmac.new(
            secret.encode(), signed_payload.encode(), hashlib.sha256
        ).hexdigest()

        request = WebhookRequest(
            headers={"Stripe-Signature": f"t={timestamp},v1={signature}"},
            body=body.encode(),
        )
        config = VerificationConfig(secret=secret, tolerance_seconds=300)

        is_valid, error = provider.verify(request, config)
        assert not is_valid
        assert "Timestamp" in error


class TestSlackWebhook:
    """Tests for Slack webhook verification."""

    def test_valid_signature(self):
        """Test valid Slack signature."""
        provider = SlackWebhook()
        secret = "slack-signing-secret"
        timestamp = str(int(time.time()))
        body = "token=xxx&team_id=T123"

        # Generate signature
        base_string = f"v0:{timestamp}:{body}"
        signature = "v0=" + hmac.new(
            secret.encode(), base_string.encode(), hashlib.sha256
        ).hexdigest()

        request = WebhookRequest(
            headers={
                "X-Slack-Signature": signature,
                "X-Slack-Request-Timestamp": timestamp,
            },
            body=body.encode(),
        )
        config = VerificationConfig(secret=secret)

        is_valid, error = provider.verify(request, config)
        assert is_valid

    def test_missing_headers(self):
        """Test missing Slack headers."""
        provider = SlackWebhook()
        request = WebhookRequest(headers={}, body=b"test")
        config = VerificationConfig(secret="secret")

        is_valid, error = provider.verify(request, config)
        assert not is_valid
        assert "Missing" in error


class TestShopifyWebhook:
    """Tests for Shopify webhook verification."""

    def test_valid_signature(self):
        """Test valid Shopify signature."""
        provider = ShopifyWebhook()
        secret = "shopify-secret"
        body = b'{"id": 123, "topic": "orders/create"}'

        signature = base64.b64encode(
            hmac.new(secret.encode(), body, hashlib.sha256).digest()
        ).decode()

        request = WebhookRequest(
            headers={"X-Shopify-Hmac-Sha256": signature},
            body=body,
        )
        config = VerificationConfig(secret=secret)

        is_valid, error = provider.verify(request, config)
        assert is_valid

    def test_invalid_signature(self):
        """Test invalid Shopify signature."""
        provider = ShopifyWebhook()
        request = WebhookRequest(
            headers={"X-Shopify-Hmac-Sha256": "invalid"},
            body=b'{"test": true}',
        )
        config = VerificationConfig(secret="secret")

        is_valid, error = provider.verify(request, config)
        assert not is_valid


class TestGitLabWebhook:
    """Tests for GitLab webhook verification."""

    def test_valid_token(self):
        """Test valid GitLab token."""
        provider = GitLabWebhook()
        secret = "gitlab-token-123"

        request = WebhookRequest(
            headers={"X-Gitlab-Token": secret},
            body=b'{"object_kind": "push"}',
        )
        config = VerificationConfig(secret=secret)

        is_valid, error = provider.verify(request, config)
        assert is_valid

    def test_invalid_token(self):
        """Test invalid GitLab token."""
        provider = GitLabWebhook()
        request = WebhookRequest(
            headers={"X-Gitlab-Token": "wrong-token"},
            body=b'{}',
        )
        config = VerificationConfig(secret="correct-token")

        is_valid, error = provider.verify(request, config)
        assert not is_valid
        assert "Invalid token" in error


class TestDropboxWebhook:
    """Tests for Dropbox webhook verification."""

    def test_valid_signature(self):
        """Test valid Dropbox signature."""
        provider = DropboxWebhook()
        secret = "dropbox-secret"
        body = b'{"delta": {"users": [123]}}'

        signature = hmac.new(
            secret.encode(), body, hashlib.sha256
        ).hexdigest()

        request = WebhookRequest(
            headers={"X-Dropbox-Signature": signature},
            body=body,
        )
        config = VerificationConfig(secret=secret)

        is_valid, error = provider.verify(request, config)
        assert is_valid


class TestIntercomWebhook:
    """Tests for Intercom webhook verification."""

    def test_valid_signature(self):
        """Test valid Intercom signature."""
        provider = IntercomWebhook()
        secret = "intercom-secret"
        body = b'{"type": "conversation.user.created"}'

        signature = "sha1=" + hmac.new(
            secret.encode(), body, hashlib.sha1
        ).hexdigest()

        request = WebhookRequest(
            headers={"X-Hub-Signature": signature},
            body=body,
        )
        config = VerificationConfig(secret=secret)

        is_valid, error = provider.verify(request, config)
        assert is_valid


class TestSupportedProviders:
    """Tests for provider registry."""

    def test_all_providers_listed(self):
        """Test that all expected providers are in registry."""
        expected = [
            "github", "stripe", "slack", "twilio", "shopify",
            "sendgrid", "mailgun", "paddle", "intercom", "dropbox",
            "bitbucket", "gitlab", "linear", "square", "pagerduty",
            "zendesk", "hubspot", "generic_hmac_sha256",
        ]
        for name in expected:
            assert name in SUPPORTED_PROVIDERS

    def test_get_provider(self):
        """Test getting provider by name."""
        github = get_provider("github")
        assert github is not None
        assert github.name == "github"

        unknown = get_provider("unknown")
        assert unknown is None


class TestWebhookVerifier:
    """Tests for WebhookVerifier service."""

    @pytest.fixture
    def verifier(self):
        return WebhookVerifier()

    def test_configure(self, verifier):
        """Test adding configuration."""
        verifier.configure(
            config_id="test",
            provider=WebhookProvider.GITHUB,
            secret="test-secret",
        )

        config = verifier.get_configuration("test")
        assert config is not None
        assert config.provider == "github"
        assert config.secret == "test-secret"

    def test_configure_invalid_provider(self, verifier):
        """Test configuring with invalid provider."""
        with pytest.raises(ValueError):
            verifier.configure(
                config_id="test",
                provider="invalid",
                secret="secret",
            )

    def test_remove_configuration(self, verifier):
        """Test removing configuration."""
        verifier.configure(
            config_id="test",
            provider=WebhookProvider.GITHUB,
            secret="secret",
        )

        assert verifier.remove_configuration("test")
        assert verifier.get_configuration("test") is None

    def test_list_configurations(self, verifier):
        """Test listing configurations."""
        verifier.configure("config1", WebhookProvider.GITHUB, "secret1")
        verifier.configure("config2", WebhookProvider.STRIPE, "secret2")

        configs = verifier.list_configurations()
        assert "config1" in configs
        assert "config2" in configs

    @pytest.mark.asyncio
    async def test_verify_no_config(self, verifier):
        """Test verification with no matching config."""
        result = await verifier.verify(
            headers={},
            body=b"test",
        )
        assert result.verified  # No config = skip verification
        assert not result.enforced

    @pytest.mark.asyncio
    async def test_verify_with_config(self, verifier):
        """Test verification with valid config."""
        secret = "test-secret"
        body = b'{"test": true}'

        verifier.configure(
            config_id="github",
            provider=WebhookProvider.GITHUB,
            secret=secret,
        )

        # Valid signature
        signature = "sha256=" + hmac.new(
            secret.encode(), body, hashlib.sha256
        ).hexdigest()

        result = await verifier.verify(
            headers={"X-Hub-Signature-256": signature},
            body=body,
            config_id="github",
        )
        assert result.verified
        assert result.provider == "github"

    @pytest.mark.asyncio
    async def test_verify_invalid_signature(self, verifier):
        """Test verification with invalid signature."""
        verifier.configure(
            config_id="github",
            provider=WebhookProvider.GITHUB,
            secret="correct-secret",
        )

        result = await verifier.verify(
            headers={"X-Hub-Signature-256": "sha256=invalid"},
            body=b"test",
            config_id="github",
        )
        assert not result.verified
        assert "Invalid signature" in result.error

    @pytest.mark.asyncio
    async def test_verify_with_path_matching(self, verifier):
        """Test verification with path-based config matching."""
        secret = "secret"
        body = b'{"event": "test"}'

        verifier.configure(
            config_id="api-webhooks",
            provider=WebhookProvider.GITHUB,
            secret=secret,
            paths=["/webhooks/*"],
        )

        signature = "sha256=" + hmac.new(
            secret.encode(), body, hashlib.sha256
        ).hexdigest()

        # Matching path
        result = await verifier.verify(
            headers={"X-Hub-Signature-256": signature},
            body=body,
            path="/webhooks/github",
        )
        assert result.verified

        # Non-matching path should skip verification
        result = await verifier.verify(
            headers={},
            body=body,
            path="/api/other",
        )
        assert result.verified  # Skipped, no matching config

    @pytest.mark.asyncio
    async def test_verify_enforce_mode(self, verifier):
        """Test enforce vs non-enforce mode."""
        verifier.configure(
            config_id="github",
            provider=WebhookProvider.GITHUB,
            secret="secret",
            enforce=False,  # Non-enforcing
        )

        result = await verifier.verify(
            headers={"X-Hub-Signature-256": "sha256=invalid"},
            body=b"test",
            config_id="github",
        )
        assert not result.verified
        assert not result.enforced  # Should not block request

    def test_get_stats(self, verifier):
        """Test statistics."""
        stats = verifier.get_stats()
        assert "total_verifications" in stats
        assert "successful" in stats
        assert "failed" in stats
        assert "skipped" in stats

    def test_supported_providers(self, verifier):
        """Test listing supported providers."""
        providers = verifier.supported_providers()
        assert "github" in providers
        assert "stripe" in providers
        assert "slack" in providers


class TestVerificationResult:
    """Tests for VerificationResult."""

    def test_success_result(self):
        """Test successful verification result."""
        result = VerificationResult(
            verified=True,
            provider="github",
            verification_time_ms=5.5,
        )
        assert result.verified
        assert result.error == ""

    def test_failure_result(self):
        """Test failed verification result."""
        result = VerificationResult(
            verified=False,
            provider="stripe",
            error="Invalid signature",
        )
        assert not result.verified
        assert result.error == "Invalid signature"

    def test_to_dict(self):
        """Test serialization."""
        result = VerificationResult(
            verified=True,
            provider="github",
            request_id="req-123",
        )
        data = result.to_dict()

        assert data["verified"] is True
        assert data["provider"] == "github"
        assert data["request_id"] == "req-123"


class TestTimingAttackPrevention:
    """Tests to ensure timing attack prevention."""

    def test_constant_time_comparison(self):
        """Test that signature comparison is constant-time."""
        provider = GitHubWebhook()

        # This test verifies the method exists and is used
        # Actual timing attack testing would require more sophisticated measurement
        result = provider._constant_time_compare("abc", "abc")
        assert result

        result = provider._constant_time_compare("abc", "xyz")
        assert not result

        result = provider._constant_time_compare("abc", "ab")
        assert not result
