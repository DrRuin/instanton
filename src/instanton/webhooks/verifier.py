"""Webhook verification service."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any

import structlog

from instanton.webhooks.providers import (
    SUPPORTED_PROVIDERS,
    VerificationConfig,
    WebhookProviderBase,
    WebhookRequest,
)

logger = structlog.get_logger()


class WebhookProvider(str, Enum):
    """Supported webhook providers."""

    GITHUB = "github"
    STRIPE = "stripe"
    SLACK = "slack"
    TWILIO = "twilio"
    SHOPIFY = "shopify"
    SENDGRID = "sendgrid"
    MAILGUN = "mailgun"
    PADDLE = "paddle"
    INTERCOM = "intercom"
    DROPBOX = "dropbox"
    BITBUCKET = "bitbucket"
    GITLAB = "gitlab"
    LINEAR = "linear"
    SQUARE = "square"
    PAGERDUTY = "pagerduty"
    ZENDESK = "zendesk"
    HUBSPOT = "hubspot"
    GENERIC = "generic_hmac_sha256"


@dataclass
class VerificationResult:
    """Result of webhook verification."""

    verified: bool = False
    provider: str = ""
    error: str = ""
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))
    verification_time_ms: float = 0.0
    request_id: str = ""
    enforced: bool = True  # Whether verification failure blocks request

    def to_dict(self) -> dict[str, Any]:
        return {
            "verified": self.verified,
            "provider": self.provider,
            "error": self.error,
            "timestamp": self.timestamp.isoformat(),
            "verification_time_ms": self.verification_time_ms,
            "request_id": self.request_id,
            "enforced": self.enforced,
        }


@dataclass
class WebhookConfiguration:
    """Configuration for a webhook endpoint."""

    provider: str
    secret: str
    tolerance_seconds: int = 300
    enforce: bool = True
    paths: list[str] = field(default_factory=list)  # Empty = all paths
    subdomains: list[str] = field(default_factory=list)  # Empty = all subdomains


class WebhookVerifier:
    """Service for verifying webhook signatures."""

    def __init__(self):
        self._configurations: dict[str, WebhookConfiguration] = {}
        self._providers: dict[str, WebhookProviderBase] = {}
        self._stats: dict[str, int] = {
            "total_verifications": 0,
            "successful": 0,
            "failed": 0,
            "skipped": 0,
        }
        self._lock = asyncio.Lock()

        # Initialize providers
        for name, provider_class in SUPPORTED_PROVIDERS.items():
            self._providers[name] = provider_class()

    def configure(
        self,
        config_id: str,
        provider: str | WebhookProvider,
        secret: str,
        tolerance_seconds: int = 300,
        enforce: bool = True,
        paths: list[str] | None = None,
        subdomains: list[str] | None = None,
    ) -> None:
        """Configure webhook verification for an endpoint.

        Args:
            config_id: Unique identifier for this configuration
            provider: Webhook provider name
            secret: Shared secret for signature verification
            tolerance_seconds: Timestamp tolerance (default 5 minutes)
            enforce: If False, log failures but don't reject
            paths: Specific paths to verify (empty = all)
            subdomains: Specific subdomains to verify (empty = all)
        """
        provider_name = provider.value if isinstance(provider, WebhookProvider) else provider

        if provider_name not in SUPPORTED_PROVIDERS:
            raise ValueError(f"Unsupported provider: {provider_name}")

        self._configurations[config_id] = WebhookConfiguration(
            provider=provider_name,
            secret=secret,
            tolerance_seconds=tolerance_seconds,
            enforce=enforce,
            paths=paths or [],
            subdomains=subdomains or [],
        )

        logger.info(
            "Webhook configuration added",
            config_id=config_id,
            provider=provider_name,
            enforce=enforce,
        )

    def remove_configuration(self, config_id: str) -> bool:
        """Remove a webhook configuration."""
        if config_id in self._configurations:
            del self._configurations[config_id]
            return True
        return False

    def get_configuration(self, config_id: str) -> WebhookConfiguration | None:
        """Get a webhook configuration."""
        return self._configurations.get(config_id)

    def list_configurations(self) -> list[str]:
        """List all configuration IDs."""
        return list(self._configurations.keys())

    async def verify(
        self,
        headers: dict[str, str],
        body: bytes,
        method: str = "POST",
        path: str = "/",
        subdomain: str = "",
        config_id: str | None = None,
    ) -> VerificationResult:
        """Verify a webhook request.

        Args:
            headers: Request headers
            body: Request body
            method: HTTP method
            path: Request path
            subdomain: Subdomain the request came from
            config_id: Specific configuration to use (optional)

        Returns:
            VerificationResult with outcome
        """
        import time

        start_time = time.time()
        self._stats["total_verifications"] += 1

        # Find matching configuration
        config = None
        if config_id:
            config = self._configurations.get(config_id)
        else:
            config = self._find_matching_config(path, subdomain)

        if not config:
            # No configuration found, skip verification
            self._stats["skipped"] += 1
            return VerificationResult(
                verified=True,
                error="No webhook configuration found",
                verification_time_ms=(time.time() - start_time) * 1000,
                enforced=False,
            )

        # Get provider
        provider = self._providers.get(config.provider)
        if not provider:
            return VerificationResult(
                verified=False,
                provider=config.provider,
                error=f"Provider not found: {config.provider}",
                verification_time_ms=(time.time() - start_time) * 1000,
                enforced=config.enforce,
            )

        # Create webhook request
        webhook_request = WebhookRequest(
            headers=headers,
            body=body,
            method=method,
            path=path,
        )

        # Create verification config
        verification_config = VerificationConfig(
            secret=config.secret,
            tolerance_seconds=config.tolerance_seconds,
            enforce=config.enforce,
        )

        # Verify
        try:
            is_valid, error = provider.verify(webhook_request, verification_config)
        except Exception as e:
            logger.error(
                "Webhook verification error",
                provider=config.provider,
                error=str(e),
            )
            is_valid = False
            error = str(e)

        verification_time_ms = (time.time() - start_time) * 1000

        if is_valid:
            self._stats["successful"] += 1
            logger.debug(
                "Webhook verified",
                provider=config.provider,
                path=path,
            )
        else:
            self._stats["failed"] += 1
            logger.warning(
                "Webhook verification failed",
                provider=config.provider,
                path=path,
                error=error,
                enforced=config.enforce,
            )

        return VerificationResult(
            verified=is_valid,
            provider=config.provider,
            error=error,
            verification_time_ms=verification_time_ms,
            enforced=config.enforce,
        )

    def _find_matching_config(
        self,
        path: str,
        subdomain: str,
    ) -> WebhookConfiguration | None:
        """Find a configuration matching the request."""
        for config in self._configurations.values():
            # Check subdomain match
            if config.subdomains and subdomain not in config.subdomains:
                continue

            # Check path match
            if config.paths:
                path_matches = False
                for pattern in config.paths:
                    if pattern.endswith("*"):
                        if path.startswith(pattern[:-1]):
                            path_matches = True
                            break
                    elif path == pattern:
                        path_matches = True
                        break
                if not path_matches:
                    continue

            return config

        return None

    def get_stats(self) -> dict[str, Any]:
        """Get verification statistics."""
        return {
            **self._stats,
            "configurations": len(self._configurations),
            "providers": len(self._providers),
        }

    def reset_stats(self) -> None:
        """Reset statistics."""
        self._stats = {
            "total_verifications": 0,
            "successful": 0,
            "failed": 0,
            "skipped": 0,
        }

    @staticmethod
    def supported_providers() -> list[str]:
        """List all supported webhook providers."""
        return list(SUPPORTED_PROVIDERS.keys())


# Global verifier instance
_verifier: WebhookVerifier | None = None


def get_webhook_verifier() -> WebhookVerifier:
    """Get or create the global webhook verifier instance."""
    global _verifier
    if _verifier is None:
        _verifier = WebhookVerifier()
    return _verifier


def set_webhook_verifier(verifier: WebhookVerifier) -> None:
    """Set the global webhook verifier instance."""
    global _verifier
    _verifier = verifier
