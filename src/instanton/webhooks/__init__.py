"""Instanton Webhook Verification Module.

Provides secure webhook signature verification for popular services
with constant-time comparison to prevent timing attacks.

Supported Providers:
- GitHub: X-Hub-Signature-256 with HMAC-SHA256
- Stripe: Stripe-Signature with timestamp validation
- Slack: X-Slack-Signature with timestamp validation
- Discord: X-Signature-Ed25519 with Ed25519 verification
- Custom: Configurable HMAC-SHA256 verification

Security Features:
- Constant-time signature comparison
- Timestamp validation (replay attack prevention)
- Multiple algorithm support
- Extensible provider architecture

Usage:
    from instanton.webhooks import GitHubWebhookProvider

    # Create provider with your secret
    provider = GitHubWebhookProvider(secret="your-webhook-secret")

    # Verify incoming webhook
    result = provider.verify(
        payload=request.body,
        headers=dict(request.headers),
    )

    if result.valid:
        print("Webhook verified!")
        # Process the webhook
    else:
        print(f"Verification failed: {result.error}")

Configuration example:
    from instanton.webhooks import get_provider

    # Get provider by name
    github = get_provider("github", secret="secret")
    stripe = get_provider("stripe", secret="whsec_...")
"""

from instanton.webhooks.providers import (
    WEBHOOK_PROVIDERS,
    CustomWebhookProvider,
    DiscordWebhookProvider,
    GitHubWebhookProvider,
    SlackWebhookProvider,
    StripeWebhookProvider,
    WebhookProvider,
    get_provider,
)
from instanton.webhooks.verifier import (
    VerificationResult,
    VerificationStatus,
    WebhookVerifier,
    parse_signature_header,
    parse_slack_signature,
    parse_stripe_signature,
)

__all__ = [
    # Base classes
    "WebhookVerifier",
    "WebhookProvider",
    "VerificationResult",
    "VerificationStatus",
    # Providers
    "GitHubWebhookProvider",
    "StripeWebhookProvider",
    "SlackWebhookProvider",
    "DiscordWebhookProvider",
    "CustomWebhookProvider",
    # Registry
    "WEBHOOK_PROVIDERS",
    "get_provider",
    # Utilities
    "parse_signature_header",
    "parse_stripe_signature",
    "parse_slack_signature",
]
