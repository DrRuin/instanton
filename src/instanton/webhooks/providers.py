"""Instanton Webhook Providers.

Provider-specific webhook signature verification implementations for
popular services like GitHub, Stripe, Slack, and Discord.

Supported Providers:
- GitHub: X-Hub-Signature-256 with HMAC-SHA256
- Stripe: Stripe-Signature with timestamp validation
- Slack: X-Slack-Signature with timestamp validation
- Discord: X-Signature-Ed25519 with Ed25519 verification
- Custom: Configurable HMAC-SHA256 verification

Usage:
    from instanton.webhooks.providers import GitHubWebhookProvider

    provider = GitHubWebhookProvider(secret="github-webhook-secret")
    result = provider.verify(request_body, request_headers)

    if result.valid:
        # Process webhook
        pass
"""

from __future__ import annotations

import hashlib
import hmac
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any

from instanton.webhooks.verifier import (
    VerificationResult,
    VerificationStatus,
    parse_signature_header,
    parse_slack_signature,
    parse_stripe_signature,
)


class WebhookProvider(ABC):
    """Base class for webhook providers.

    Each provider implements its specific signature verification logic.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Provider name."""
        ...

    @abstractmethod
    def verify(
        self,
        payload: bytes,
        headers: dict[str, str],
    ) -> VerificationResult:
        """Verify webhook signature.

        Args:
            payload: Raw request body bytes.
            headers: Request headers dictionary.

        Returns:
            VerificationResult with status and details.
        """
        ...

    def _constant_time_compare(self, a: str, b: str) -> bool:
        """Constant-time string comparison."""
        return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))

    def _compute_hmac_sha256(self, payload: bytes, secret: str) -> str:
        """Compute HMAC-SHA256 signature."""
        return hmac.new(
            secret.encode("utf-8"),
            payload,
            hashlib.sha256,
        ).hexdigest()


@dataclass
class GitHubWebhookProvider(WebhookProvider):
    """GitHub webhook signature verification.

    GitHub sends: X-Hub-Signature-256: sha256=<signature>

    Uses HMAC-SHA256 for signature verification.
    """

    secret: str
    """Webhook secret configured in GitHub."""

    signature_header: str = "X-Hub-Signature-256"
    """Header containing the signature."""

    @property
    def name(self) -> str:
        return "github"

    def verify(
        self,
        payload: bytes,
        headers: dict[str, str],
    ) -> VerificationResult:
        """Verify GitHub webhook signature.

        Args:
            payload: Raw request body.
            headers: Request headers.

        Returns:
            VerificationResult with status.
        """
        # Get signature header (case-insensitive lookup)
        signature_header = None
        for key, value in headers.items():
            if key.lower() == self.signature_header.lower():
                signature_header = value
                break

        if not signature_header:
            return VerificationResult(
                valid=False,
                status=VerificationStatus.MISSING_SIGNATURE,
                error=f"Missing {self.signature_header} header",
                provider=self.name,
            )

        # Parse signature (remove sha256= prefix)
        signature = parse_signature_header(signature_header, prefix="sha256=")
        if not signature:
            return VerificationResult(
                valid=False,
                status=VerificationStatus.INVALID_FORMAT,
                error="Invalid signature format",
                provider=self.name,
            )

        # Compute expected signature
        expected = self._compute_hmac_sha256(payload, self.secret)

        if self._constant_time_compare(signature, expected):
            return VerificationResult(
                valid=True,
                status=VerificationStatus.VALID,
                provider=self.name,
            )

        return VerificationResult(
            valid=False,
            status=VerificationStatus.INVALID_SIGNATURE,
            error="Signature mismatch",
            provider=self.name,
        )


@dataclass
class StripeWebhookProvider(WebhookProvider):
    """Stripe webhook signature verification.

    Stripe sends: Stripe-Signature: t=<timestamp>,v1=<signature>

    Includes timestamp validation to prevent replay attacks.
    """

    secret: str
    """Webhook signing secret from Stripe dashboard."""

    signature_header: str = "Stripe-Signature"
    """Header containing the signature."""

    tolerance_seconds: int = 300
    """Maximum age of timestamp (default 5 minutes)."""

    @property
    def name(self) -> str:
        return "stripe"

    def verify(
        self,
        payload: bytes,
        headers: dict[str, str],
    ) -> VerificationResult:
        """Verify Stripe webhook signature.

        Args:
            payload: Raw request body.
            headers: Request headers.

        Returns:
            VerificationResult with status.
        """
        # Get signature header
        signature_header = None
        for key, value in headers.items():
            if key.lower() == self.signature_header.lower():
                signature_header = value
                break

        if not signature_header:
            return VerificationResult(
                valid=False,
                status=VerificationStatus.MISSING_SIGNATURE,
                error=f"Missing {self.signature_header} header",
                provider=self.name,
            )

        # Parse signature header
        parsed = parse_stripe_signature(signature_header)
        if not parsed:
            return VerificationResult(
                valid=False,
                status=VerificationStatus.INVALID_FORMAT,
                error="Invalid Stripe-Signature format",
                provider=self.name,
            )

        timestamp = parsed["timestamp"]
        signature = parsed["signature"]

        # Check timestamp
        current_time = int(time.time())
        if abs(current_time - timestamp) > self.tolerance_seconds:
            return VerificationResult(
                valid=False,
                status=VerificationStatus.EXPIRED_TIMESTAMP,
                error="Timestamp outside tolerance window",
                provider=self.name,
                timestamp=timestamp,
            )

        # Compute expected signature: signed_payload = timestamp + "." + payload
        signed_payload = f"{timestamp}.".encode() + payload
        expected = self._compute_hmac_sha256(signed_payload, self.secret)

        if self._constant_time_compare(signature, expected):
            return VerificationResult(
                valid=True,
                status=VerificationStatus.VALID,
                provider=self.name,
                timestamp=timestamp,
            )

        return VerificationResult(
            valid=False,
            status=VerificationStatus.INVALID_SIGNATURE,
            error="Signature mismatch",
            provider=self.name,
            timestamp=timestamp,
        )


@dataclass
class SlackWebhookProvider(WebhookProvider):
    """Slack webhook signature verification.

    Slack sends:
    - X-Slack-Signature: v0=<signature>
    - X-Slack-Request-Timestamp: <timestamp>

    Signature is computed over: v0:{timestamp}:{body}
    """

    secret: str
    """Slack signing secret."""

    signature_header: str = "X-Slack-Signature"
    """Header containing the signature."""

    timestamp_header: str = "X-Slack-Request-Timestamp"
    """Header containing the timestamp."""

    tolerance_seconds: int = 300
    """Maximum age of timestamp (default 5 minutes)."""

    @property
    def name(self) -> str:
        return "slack"

    def verify(
        self,
        payload: bytes,
        headers: dict[str, str],
    ) -> VerificationResult:
        """Verify Slack webhook signature.

        Args:
            payload: Raw request body.
            headers: Request headers.

        Returns:
            VerificationResult with status.
        """
        # Get headers (case-insensitive)
        signature_header = None
        timestamp_header = None
        for key, value in headers.items():
            if key.lower() == self.signature_header.lower():
                signature_header = value
            elif key.lower() == self.timestamp_header.lower():
                timestamp_header = value

        if not signature_header or not timestamp_header:
            return VerificationResult(
                valid=False,
                status=VerificationStatus.MISSING_SIGNATURE,
                error="Missing Slack signature or timestamp header",
                provider=self.name,
            )

        # Parse headers
        parsed = parse_slack_signature(signature_header, timestamp_header)
        if not parsed:
            return VerificationResult(
                valid=False,
                status=VerificationStatus.INVALID_FORMAT,
                error="Invalid Slack signature format",
                provider=self.name,
            )

        timestamp = parsed["timestamp"]
        signature = parsed["signature"]

        # Check timestamp
        current_time = int(time.time())
        if abs(current_time - timestamp) > self.tolerance_seconds:
            return VerificationResult(
                valid=False,
                status=VerificationStatus.EXPIRED_TIMESTAMP,
                error="Timestamp outside tolerance window",
                provider=self.name,
                timestamp=timestamp,
            )

        # Compute expected signature: v0:{timestamp}:{body}
        sig_basestring = f"v0:{timestamp}:".encode() + payload
        expected = self._compute_hmac_sha256(sig_basestring, self.secret)

        if self._constant_time_compare(signature, expected):
            return VerificationResult(
                valid=True,
                status=VerificationStatus.VALID,
                provider=self.name,
                timestamp=timestamp,
            )

        return VerificationResult(
            valid=False,
            status=VerificationStatus.INVALID_SIGNATURE,
            error="Signature mismatch",
            provider=self.name,
            timestamp=timestamp,
        )


@dataclass
class DiscordWebhookProvider(WebhookProvider):
    """Discord webhook signature verification.

    Discord sends:
    - X-Signature-Ed25519: <signature>
    - X-Signature-Timestamp: <timestamp>

    Uses Ed25519 for signature verification (not HMAC).
    """

    public_key: str
    """Discord application public key (hex encoded)."""

    signature_header: str = "X-Signature-Ed25519"
    """Header containing the signature."""

    timestamp_header: str = "X-Signature-Timestamp"
    """Header containing the timestamp."""

    @property
    def name(self) -> str:
        return "discord"

    def verify(
        self,
        payload: bytes,
        headers: dict[str, str],
    ) -> VerificationResult:
        """Verify Discord webhook signature using Ed25519.

        Args:
            payload: Raw request body.
            headers: Request headers.

        Returns:
            VerificationResult with status.
        """
        # Get headers (case-insensitive)
        signature_header = None
        timestamp_header = None
        for key, value in headers.items():
            if key.lower() == self.signature_header.lower():
                signature_header = value
            elif key.lower() == self.timestamp_header.lower():
                timestamp_header = value

        if not signature_header or not timestamp_header:
            return VerificationResult(
                valid=False,
                status=VerificationStatus.MISSING_SIGNATURE,
                error="Missing Discord signature or timestamp header",
                provider=self.name,
            )

        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import (
                Ed25519PublicKey,
            )

            # Parse keys
            public_key_bytes = bytes.fromhex(self.public_key)
            signature_bytes = bytes.fromhex(signature_header)

            # Load public key
            public_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)

            # Message is timestamp + body
            message = timestamp_header.encode() + payload

            # Verify signature
            public_key.verify(signature_bytes, message)

            return VerificationResult(
                valid=True,
                status=VerificationStatus.VALID,
                provider=self.name,
            )

        except ImportError:
            return VerificationResult(
                valid=False,
                status=VerificationStatus.INVALID_FORMAT,
                error="cryptography library required for Ed25519 verification",
                provider=self.name,
            )
        except ValueError as e:
            return VerificationResult(
                valid=False,
                status=VerificationStatus.INVALID_FORMAT,
                error=f"Invalid key or signature format: {e}",
                provider=self.name,
            )
        except Exception:
            return VerificationResult(
                valid=False,
                status=VerificationStatus.INVALID_SIGNATURE,
                error="Signature verification failed",
                provider=self.name,
            )


@dataclass
class CustomWebhookProvider(WebhookProvider):
    """Custom webhook signature verification.

    Configurable provider for custom webhook implementations.
    """

    secret: str
    """Shared secret for HMAC computation."""

    provider_name: str = "custom"
    """Name to identify this provider."""

    signature_header: str = "X-Webhook-Signature"
    """Header containing the signature."""

    signature_prefix: str = ""
    """Prefix to strip from signature (e.g., 'sha256=')."""

    timestamp_header: str | None = None
    """Optional header containing timestamp."""

    tolerance_seconds: int = 300
    """Maximum age of timestamp if timestamp_header is set."""

    include_timestamp_in_payload: bool = False
    """Whether to include timestamp in signed payload."""

    @property
    def name(self) -> str:
        return self.provider_name

    def verify(
        self,
        payload: bytes,
        headers: dict[str, str],
    ) -> VerificationResult:
        """Verify custom webhook signature.

        Args:
            payload: Raw request body.
            headers: Request headers.

        Returns:
            VerificationResult with status.
        """
        # Get signature header
        signature_value = None
        for key, value in headers.items():
            if key.lower() == self.signature_header.lower():
                signature_value = value
                break

        if not signature_value:
            return VerificationResult(
                valid=False,
                status=VerificationStatus.MISSING_SIGNATURE,
                error=f"Missing {self.signature_header} header",
                provider=self.name,
            )

        # Strip prefix if configured
        signature = signature_value
        if self.signature_prefix and signature.startswith(self.signature_prefix):
            signature = signature[len(self.signature_prefix) :]

        # Handle timestamp if configured
        timestamp = None
        if self.timestamp_header:
            for key, value in headers.items():
                if key.lower() == self.timestamp_header.lower():
                    try:
                        timestamp = int(value)
                    except ValueError:
                        return VerificationResult(
                            valid=False,
                            status=VerificationStatus.INVALID_TIMESTAMP,
                            error="Invalid timestamp format",
                            provider=self.name,
                        )
                    break

            if timestamp is None:
                return VerificationResult(
                    valid=False,
                    status=VerificationStatus.MISSING_SIGNATURE,
                    error=f"Missing {self.timestamp_header} header",
                    provider=self.name,
                )

            # Check timestamp tolerance
            current_time = int(time.time())
            if abs(current_time - timestamp) > self.tolerance_seconds:
                return VerificationResult(
                    valid=False,
                    status=VerificationStatus.EXPIRED_TIMESTAMP,
                    error="Timestamp outside tolerance window",
                    provider=self.name,
                    timestamp=timestamp,
                )

        # Compute expected signature
        if self.include_timestamp_in_payload and timestamp is not None:
            signed_payload = f"{timestamp}.".encode() + payload
            expected = self._compute_hmac_sha256(signed_payload, self.secret)
        else:
            expected = self._compute_hmac_sha256(payload, self.secret)

        if self._constant_time_compare(signature, expected):
            return VerificationResult(
                valid=True,
                status=VerificationStatus.VALID,
                provider=self.name,
                timestamp=timestamp,
            )

        return VerificationResult(
            valid=False,
            status=VerificationStatus.INVALID_SIGNATURE,
            error="Signature mismatch",
            provider=self.name,
            timestamp=timestamp,
        )


# Provider registry
WEBHOOK_PROVIDERS: dict[str, type[WebhookProvider]] = {
    "github": GitHubWebhookProvider,
    "stripe": StripeWebhookProvider,
    "slack": SlackWebhookProvider,
    "discord": DiscordWebhookProvider,
    "custom": CustomWebhookProvider,
}


def get_provider(
    provider_name: str,
    **kwargs: Any,
) -> WebhookProvider:
    """Get a webhook provider by name.

    Args:
        provider_name: Name of the provider.
        **kwargs: Provider-specific configuration.

    Returns:
        Configured WebhookProvider instance.

    Raises:
        ValueError: If provider is not found.
    """
    provider_class = WEBHOOK_PROVIDERS.get(provider_name.lower())
    if not provider_class:
        raise ValueError(f"Unknown webhook provider: {provider_name}")
    return provider_class(**kwargs)
