"""Instanton Custom Domain Management.

This module provides custom domain support allowing users to use their own domains
(e.g., api.mycompany.com) instead of the default random.instanton.tech subdomains.

Features:
- DNS verification (CNAME + TXT records) for domain ownership
- Wildcard domain support (*.mycompany.com)
- JSON file storage for domain registrations
- Auto TLS certificate provisioning via ACME
- Domain status tracking and management

Usage:
    from instanton.domains import DomainManager, DomainStore

    # Initialize
    store = DomainStore("domains.json")
    manager = DomainManager(store, base_domain="instanton.tech")

    # Register and verify an exact domain
    registration = await manager.register_domain("api.mycompany.com", tunnel_id="abc123")
    result = await manager.verify_domain("api.mycompany.com")

    # Register a wildcard domain
    wildcard_reg = await manager.register_domain("*.mycompany.com", tunnel_id="abc123")
"""

from instanton.domains.manager import DomainInfo, DomainManager, DomainStatus
from instanton.domains.storage import DomainRegistration, DomainStore
from instanton.domains.verification import DNSVerifier, VerificationResult
from instanton.domains.wildcards import (
    find_matching_wildcard,
    get_base_domain,
    is_wildcard_pattern,
    match_wildcard,
    validate_wildcard_pattern,
)

__all__ = [
    "DomainManager",
    "DomainStatus",
    "DomainInfo",
    "DomainStore",
    "DomainRegistration",
    "DNSVerifier",
    "VerificationResult",
    "is_wildcard_pattern",
    "match_wildcard",
    "get_base_domain",
    "validate_wildcard_pattern",
    "find_matching_wildcard",
]
