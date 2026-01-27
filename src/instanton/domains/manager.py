"""Domain manager for custom domain lifecycle management.

This module provides the main interface for managing custom domains:
- Registration with automatic verification token generation
- DNS verification (CNAME + TXT)
- Status tracking
- Integration with certificate provisioning

Usage:
    manager = DomainManager(store, base_domain="instanton.tech")

    # Register a new domain
    reg = await manager.register_domain("api.mycompany.com", "tunnel-123")

    # Verify DNS records
    result = await manager.verify_domain("api.mycompany.com")

    # Check status
    status = await manager.get_domain_status("api.mycompany.com")
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from enum import Enum

from instanton.domains.storage import DomainRegistration, DomainStore
from instanton.domains.verification import DNSVerifier, VerificationResult, VerificationStatus
from instanton.domains.wildcards import (
    get_base_domain,
    is_wildcard_pattern,
    match_wildcard,
    validate_wildcard_pattern,
)


class DomainStatus(Enum):
    """Overall status of a custom domain."""

    NOT_FOUND = "not_found"
    PENDING_VERIFICATION = "pending_verification"
    CNAME_ONLY = "cname_only"
    VERIFIED = "verified"
    CERTIFICATE_PENDING = "certificate_pending"
    ACTIVE = "active"


@dataclass
class DomainInfo:
    """Complete information about a domain's status."""

    domain: str
    status: DomainStatus
    tunnel_id: str | None
    verification_token: str | None
    verified: bool
    verified_at: datetime | None
    created_at: datetime | None
    certificate_ready: bool
    dns_instructions: str | None = None
    is_wildcard: bool = False
    wildcard_pattern: str | None = None


class DomainManager:
    """Manages custom domain registration and verification.

    Coordinates between DNS verification and storage to provide
    a simple interface for domain management.
    """

    def __init__(
        self,
        store: DomainStore,
        base_domain: str = "instanton.tech",
    ) -> None:
        """Initialize domain manager.

        Args:
            store: Storage backend for domain registrations.
            base_domain: Base domain for CNAME targets.
        """
        self.store = store
        self.base_domain = base_domain
        self.verifier = DNSVerifier(base_domain)

    async def register_domain(
        self,
        domain: str,
        tunnel_id: str,
    ) -> DomainRegistration:
        """Register a new custom domain or wildcard pattern.

        Generates a verification token and saves the registration.
        The user must then configure DNS records and call verify_domain().

        Supports both exact domains (api.mycompany.com) and wildcard patterns
        (*.mycompany.com).

        Args:
            domain: The custom domain or wildcard pattern to register.
            tunnel_id: The tunnel ID this domain should route to.

        Returns:
            DomainRegistration with verification instructions.

        Raises:
            ValueError: If domain is already registered to a different tunnel,
                        or if wildcard pattern is invalid.
        """
        domain = domain.lower().strip()

        wildcard = is_wildcard_pattern(domain)
        if wildcard:
            valid, error = validate_wildcard_pattern(domain)
            if not valid:
                raise ValueError(f"Invalid wildcard pattern: {error}")

        existing = await self.store.get(domain)
        if existing:
            if existing.tunnel_id != tunnel_id:
                raise ValueError(
                    f"Domain {domain} is already registered to tunnel {existing.tunnel_id}"
                )
            return existing

        verification_domain = get_base_domain(domain) if wildcard else domain
        token = self.verifier.generate_verification_token(verification_domain)

        registration = DomainRegistration(
            domain=domain,
            tunnel_id=tunnel_id,
            verification_token=token,
            verified=False,
            is_wildcard=wildcard,
            wildcard_pattern=domain if wildcard else None,
        )

        await self.store.save(registration)

        return registration

    async def verify_domain(self, domain: str) -> VerificationResult:
        """Verify DNS records for a domain.

        Checks both CNAME and TXT records. If verification succeeds,
        updates the registration as verified.

        Args:
            domain: The domain to verify.

        Returns:
            VerificationResult with status and details.

        Raises:
            ValueError: If domain is not registered.
        """
        domain = domain.lower().strip()

        registration = await self.store.get(domain)
        if not registration:
            raise ValueError(f"Domain {domain} is not registered")

        result = await self.verifier.verify_domain(domain, registration.verification_token)

        if result.is_verified and not registration.verified:
            registration.verified = True
            registration.verified_at = datetime.now(UTC)
            await self.store.save(registration)

        return result

    async def get_domain_status(self, domain: str) -> DomainInfo:
        """Get complete status information for a domain.

        Args:
            domain: The domain to check.

        Returns:
            DomainInfo with full status details.
        """
        domain = domain.lower().strip()

        registration = await self.store.get(domain)

        if not registration:
            return DomainInfo(
                domain=domain,
                status=DomainStatus.NOT_FOUND,
                tunnel_id=None,
                verification_token=None,
                verified=False,
                verified_at=None,
                created_at=None,
                certificate_ready=False,
                dns_instructions=None,
            )

        if registration.verified:
            if registration.certificate_path:
                status = DomainStatus.ACTIVE
            else:
                status = DomainStatus.CERTIFICATE_PENDING
        else:
            result = await self.verifier.verify_domain(domain, registration.verification_token)
            if result.status == VerificationStatus.CNAME_VERIFIED:
                status = DomainStatus.CNAME_ONLY
            else:
                status = DomainStatus.PENDING_VERIFICATION

        dns_instructions = None
        if not registration.verified:
            dns_instructions = self._generate_dns_instructions(
                domain, registration.verification_token
            )

        return DomainInfo(
            domain=domain,
            status=status,
            tunnel_id=registration.tunnel_id,
            verification_token=registration.verification_token,
            verified=registration.verified,
            verified_at=registration.verified_at,
            created_at=registration.created_at,
            certificate_ready=registration.certificate_path is not None,
            dns_instructions=dns_instructions,
            is_wildcard=registration.is_wildcard,
            wildcard_pattern=registration.wildcard_pattern,
        )

    async def delete_domain(self, domain: str) -> bool:
        """Delete a domain registration.

        Args:
            domain: The domain to delete.

        Returns:
            True if deleted, False if not found.
        """
        domain = domain.lower().strip()
        return await self.store.delete(domain)

    async def get_tunnel_for_domain(self, domain: str) -> str | None:
        """Get the tunnel ID for a verified domain.

        This is the primary lookup method used by the relay server
        to route requests to the correct tunnel.

        First checks for exact domain match, then falls back to
        wildcard pattern matching.

        Args:
            domain: The domain to look up.

        Returns:
            Tunnel ID if domain is verified and active, None otherwise.
        """
        domain = domain.lower().strip()

        registration = await self.store.get(domain)
        if registration and registration.verified:
            return registration.tunnel_id

        return await self.get_tunnel_for_wildcard(domain)

    async def get_tunnel_for_wildcard(self, host: str) -> str | None:
        """Find a tunnel matching a wildcard pattern for a hostname.

        Checks all verified wildcard registrations and returns the
        tunnel ID for the first matching pattern.

        Args:
            host: The hostname to match against wildcard patterns.

        Returns:
            Tunnel ID if a matching wildcard is found, None otherwise.
        """
        host = host.lower().strip()

        wildcards = await self.store.list_verified_wildcards()

        for registration in wildcards:
            if registration.wildcard_pattern and match_wildcard(
                host, registration.wildcard_pattern
            ):
                return registration.tunnel_id

        return None

    async def list_domains(self, tunnel_id: str | None = None) -> list[DomainRegistration]:
        """List domain registrations.

        Args:
            tunnel_id: If provided, filter by tunnel ID.

        Returns:
            List of domain registrations.
        """
        if tunnel_id:
            return await self.store.get_by_tunnel(tunnel_id)
        return await self.store.list_all()

    async def set_certificate_path(self, domain: str, cert_path: str) -> None:
        """Update the certificate path for a domain.

        Called after ACME certificate provisioning completes.

        Args:
            domain: The domain to update.
            cert_path: Path to the certificate file.
        """
        domain = domain.lower().strip()
        registration = await self.store.get(domain)

        if not registration:
            raise ValueError(f"Domain {domain} is not registered")

        registration.certificate_path = cert_path
        await self.store.save(registration)

    def _generate_dns_instructions(self, domain: str, token: str) -> str:
        """Generate DNS setup instructions for the user.

        Handles both exact domains and wildcard patterns with appropriate
        DNS record configuration.
        """
        if is_wildcard_pattern(domain):
            base = get_base_domain(domain)
            return f"""Add the following DNS records for wildcard domain {domain}:

1. CNAME Record (routes all subdomains to relay):
   Name: {domain}
   Type: CNAME
   Value: {self.base_domain}

   Note: Some DNS providers require entering just "*" as the name
   under the {base} zone.

2. TXT Record (verifies ownership of base domain):
   Name: _instanton.{base}
   Type: TXT
   Value: {token}

After adding these records, run: instanton domain verify {domain}

Note: Wildcard certificates require DNS-01 ACME challenge for TLS."""
        else:
            return f"""Add the following DNS records:

1. CNAME Record (routes traffic to relay):
   Name: {domain}
   Type: CNAME
   Value: {self.base_domain}

2. TXT Record (verifies ownership):
   Name: _instanton.{domain}
   Type: TXT
   Value: {token}

After adding these records, run: instanton domain verify {domain}"""
