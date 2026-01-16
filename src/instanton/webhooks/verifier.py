"""Instanton Webhook Signature Verification.

Provides core HMAC-SHA256 signature verification for securing webhook endpoints
with constant-time comparison to prevent timing attacks.

Security Features:
- HMAC-SHA256 signature generation and verification
- Constant-time comparison to prevent timing attacks
- Timestamp validation to prevent replay attacks
- Configurable tolerance windows

Usage:
    from instanton.webhooks import WebhookVerifier

    verifier = WebhookVerifier(secret="my-webhook-secret")

    # Verify incoming webhook
    is_valid = verifier.verify_signature(
        payload=request_body,
        signature=request.headers["X-Webhook-Signature"],
    )
"""

from __future__ import annotations

import hashlib
import hmac
import time
from dataclasses import dataclass
from enum import Enum
from typing import Any


class VerificationStatus(Enum):
    """Status of webhook signature verification."""

    VALID = "valid"
    INVALID_SIGNATURE = "invalid_signature"
    MISSING_SIGNATURE = "missing_signature"
    EXPIRED_TIMESTAMP = "expired_timestamp"
    INVALID_TIMESTAMP = "invalid_timestamp"
    INVALID_FORMAT = "invalid_format"


@dataclass
class VerificationResult:
    """Result of webhook signature verification."""

    valid: bool
    """Whether the signature is valid."""

    status: VerificationStatus
    """Detailed verification status."""

    error: str | None = None
    """Error message if verification failed."""

    provider: str | None = None
    """Webhook provider name if identified."""

    timestamp: int | None = None
    """Request timestamp if extracted."""

    def __bool__(self) -> bool:
        """Allow using result in boolean context."""
        return self.valid


class WebhookVerifier:
    """Base webhook signature verifier using HMAC-SHA256.

    Provides constant-time signature comparison and optional
    timestamp validation for replay attack prevention.
    """

    def __init__(
        self,
        secret: str,
        timestamp_tolerance: int = 300,
        algorithm: str = "sha256",
    ) -> None:
        """Initialize the webhook verifier.

        Args:
            secret: The shared secret for HMAC computation.
            timestamp_tolerance: Maximum age of timestamp in seconds (default 5 min).
            algorithm: Hash algorithm to use (default: sha256).
        """
        self.secret = secret
        self.timestamp_tolerance = timestamp_tolerance
        self.algorithm = algorithm

    def compute_signature(self, payload: bytes) -> str:
        """Compute HMAC signature for a payload.

        Args:
            payload: The raw payload bytes to sign.

        Returns:
            Hexadecimal signature string.
        """
        return hmac.new(
            self.secret.encode("utf-8"),
            payload,
            getattr(hashlib, self.algorithm),
        ).hexdigest()

    def compute_signature_with_timestamp(
        self,
        payload: bytes,
        timestamp: int,
    ) -> str:
        """Compute HMAC signature with timestamp prefix.

        Used by providers like Stripe that include timestamp in signed payload.

        Args:
            payload: The raw payload bytes.
            timestamp: Unix timestamp.

        Returns:
            Hexadecimal signature string.
        """
        signed_payload = f"{timestamp}.".encode() + payload
        return self.compute_signature(signed_payload)

    def _constant_time_compare(self, a: str, b: str) -> bool:
        """Compare two strings in constant time.

        Prevents timing attacks by ensuring comparison takes
        the same time regardless of where strings differ.

        Args:
            a: First string.
            b: Second string.

        Returns:
            True if strings are equal.
        """
        return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))

    def verify_signature(
        self,
        payload: bytes,
        signature: str,
    ) -> VerificationResult:
        """Verify a webhook signature.

        Args:
            payload: The raw request body bytes.
            signature: The signature to verify.

        Returns:
            VerificationResult with status and details.
        """
        if not signature:
            return VerificationResult(
                valid=False,
                status=VerificationStatus.MISSING_SIGNATURE,
                error="No signature provided",
            )

        expected = self.compute_signature(payload)

        if self._constant_time_compare(signature, expected):
            return VerificationResult(
                valid=True,
                status=VerificationStatus.VALID,
            )

        return VerificationResult(
            valid=False,
            status=VerificationStatus.INVALID_SIGNATURE,
            error="Signature mismatch",
        )

    def verify_with_timestamp(
        self,
        payload: bytes,
        signature: str,
        timestamp: int,
    ) -> VerificationResult:
        """Verify a webhook signature with timestamp validation.

        Args:
            payload: The raw request body bytes.
            signature: The signature to verify.
            timestamp: Unix timestamp from the request.

        Returns:
            VerificationResult with status and details.
        """
        # Check timestamp is within tolerance
        current_time = int(time.time())
        if abs(current_time - timestamp) > self.timestamp_tolerance:
            return VerificationResult(
                valid=False,
                status=VerificationStatus.EXPIRED_TIMESTAMP,
                error=f"Timestamp {timestamp} is outside tolerance window",
                timestamp=timestamp,
            )

        # Compute expected signature
        expected = self.compute_signature_with_timestamp(payload, timestamp)

        if self._constant_time_compare(signature, expected):
            return VerificationResult(
                valid=True,
                status=VerificationStatus.VALID,
                timestamp=timestamp,
            )

        return VerificationResult(
            valid=False,
            status=VerificationStatus.INVALID_SIGNATURE,
            error="Signature mismatch",
            timestamp=timestamp,
        )


def parse_signature_header(
    header_value: str,
    prefix: str = "",
) -> str | None:
    """Extract signature from header value.

    Handles common formats like:
    - "sha256=abc123" (GitHub)
    - "abc123" (plain)

    Args:
        header_value: The header value to parse.
        prefix: Optional prefix to strip (e.g., "sha256=").

    Returns:
        The extracted signature, or None if invalid.
    """
    if not header_value:
        return None

    if prefix and header_value.startswith(prefix):
        return header_value[len(prefix) :]

    return header_value


def parse_stripe_signature(header_value: str) -> dict[str, Any] | None:
    """Parse Stripe signature header format.

    Stripe format: "t=timestamp,v1=signature"

    Args:
        header_value: The Stripe-Signature header value.

    Returns:
        Dictionary with timestamp and signature, or None if invalid.
    """
    if not header_value:
        return None

    try:
        parts = {}
        for item in header_value.split(","):
            key, value = item.split("=", 1)
            parts[key.strip()] = value.strip()

        timestamp = parts.get("t")
        signature = parts.get("v1")

        if timestamp and signature:
            return {
                "timestamp": int(timestamp),
                "signature": signature,
            }
    except (ValueError, KeyError):
        pass

    return None


def parse_slack_signature(
    signature_header: str,
    timestamp_header: str,
) -> dict[str, Any] | None:
    """Parse Slack signature headers.

    Slack sends:
    - X-Slack-Signature: v0=signature
    - X-Slack-Request-Timestamp: timestamp

    Args:
        signature_header: The X-Slack-Signature header value.
        timestamp_header: The X-Slack-Request-Timestamp header value.

    Returns:
        Dictionary with timestamp and signature, or None if invalid.
    """
    if not signature_header or not timestamp_header:
        return None

    try:
        # Remove v0= prefix
        signature = signature_header
        if signature.startswith("v0="):
            signature = signature[3:]

        timestamp = int(timestamp_header)

        return {
            "timestamp": timestamp,
            "signature": signature,
        }
    except (ValueError, AttributeError):
        pass

    return None
