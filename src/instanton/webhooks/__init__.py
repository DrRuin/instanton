"""Webhook verification module for Instanton tunnel application.

Features:
- Signature validation for 50+ webhook providers
- Replay attack prevention via timestamp validation
- Configurable enforcement modes
- Support for custom webhook providers
"""

from instanton.webhooks.providers import (
    SUPPORTED_PROVIDERS,
    DropboxWebhook,
    GitHubWebhook,
    IntercomWebhook,
    MailgunWebhook,
    PaddleWebhook,
    SendGridWebhook,
    ShopifyWebhook,
    SlackWebhook,
    StripeWebhook,
    TwilioWebhook,
)
from instanton.webhooks.verifier import (
    VerificationResult,
    WebhookProvider,
    WebhookVerifier,
    get_webhook_verifier,
)

__all__ = [
    # Verifier
    "WebhookVerifier",
    "WebhookProvider",
    "VerificationResult",
    "get_webhook_verifier",
    # Providers
    "SUPPORTED_PROVIDERS",
    "GitHubWebhook",
    "StripeWebhook",
    "SlackWebhook",
    "TwilioWebhook",
    "ShopifyWebhook",
    "SendGridWebhook",
    "MailgunWebhook",
    "PaddleWebhook",
    "IntercomWebhook",
    "DropboxWebhook",
]
