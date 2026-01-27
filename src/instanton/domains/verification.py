"""DNS verification for custom domain ownership.

This module verifies domain ownership by checking DNS records:
1. CNAME record: Routes traffic to the relay server
2. TXT record: Proves ownership with a verification token

Example DNS setup required by user:
    # CNAME record (routes traffic)
    api.mycompany.com  CNAME  instanton.tech

    # TXT record (proves ownership)
    _instanton.api.mycompany.com  TXT  "verify=abc123xyz"
"""

from __future__ import annotations

import asyncio
import hashlib
import secrets
import sys
from dataclasses import dataclass
from enum import Enum

import aiodns


class VerificationStatus(Enum):
    """Status of domain verification."""

    PENDING = "pending"
    CNAME_VERIFIED = "cname_verified"
    FULLY_VERIFIED = "fully_verified"
    FAILED = "failed"


@dataclass
class VerificationResult:
    """Result of domain verification attempt."""

    domain: str
    status: VerificationStatus
    cname_valid: bool
    cname_target: str | None
    txt_valid: bool
    txt_value: str | None
    error: str | None = None

    @property
    def is_verified(self) -> bool:
        """Check if domain is fully verified."""
        return self.status == VerificationStatus.FULLY_VERIFIED


class DNSVerifier:
    """Verifies domain ownership via DNS records.

    Verification requires two DNS records:
    1. CNAME: domain → base_domain (e.g., api.mycompany.com → instanton.tech)
    2. TXT: _instanton.domain → verify=<token> (proves ownership)
    """

    def __init__(self, base_domain: str = "instanton.tech") -> None:
        """Initialize DNS verifier.

        Args:
            base_domain: The base domain that CNAME should point to.
        """
        self.base_domain = base_domain
        self._resolver: aiodns.DNSResolver | None = None

    def _get_resolver(self) -> aiodns.DNSResolver:
        """Get or create DNS resolver with proper event loop handling."""
        if self._resolver is None:
            if sys.platform == "win32":
                try:
                    loop = asyncio.get_running_loop()
                except RuntimeError:
                    loop = asyncio.new_event_loop()
                self._resolver = aiodns.DNSResolver(loop=loop)
            else:
                self._resolver = aiodns.DNSResolver()
        return self._resolver

    def generate_verification_token(self, domain: str) -> str:
        """Generate a unique verification token for a domain.

        Token is deterministic based on domain + random salt for reproducibility
        while still being unpredictable.

        Args:
            domain: The domain to generate token for.

        Returns:
            A verification token string (e.g., "verify=a1b2c3d4e5f6")
        """
        salt = secrets.token_hex(8)
        hash_input = f"{domain}:{salt}".encode()
        token = hashlib.sha256(hash_input).hexdigest()[:16]
        return f"verify={token}"

    async def verify_cname(self, domain: str) -> tuple[bool, str | None]:
        """Verify CNAME record points to base domain.

        Args:
            domain: The custom domain to verify.

        Returns:
            Tuple of (is_valid, actual_target).
        """
        resolver = self._get_resolver()
        try:
            result = await resolver.query_dns(domain, "CNAME")
            if result:
                target = result.cname.rstrip(".")
                is_valid = target == self.base_domain or target.endswith(f".{self.base_domain}")
                return is_valid, target
            return False, None
        except aiodns.error.DNSError:
            return False, None
        except Exception:
            return False, None

    async def verify_txt_record(self, domain: str, expected_token: str) -> tuple[bool, str | None]:
        """Verify TXT record contains expected verification token.

        The TXT record should be at _instanton.<domain> with value matching
        the expected token.

        Args:
            domain: The custom domain to verify.
            expected_token: The expected token value (e.g., "verify=abc123")

        Returns:
            Tuple of (is_valid, actual_value).
        """
        resolver = self._get_resolver()
        txt_domain = f"_instanton.{domain}"

        try:
            result = await resolver.query_dns(txt_domain, "TXT")
            if result:
                for record in result:
                    value = record.text.strip('"').strip("'")
                    if value == expected_token:
                        return True, value
                first_value = result[0].text.strip('"').strip("'") if result else None
                return False, first_value
            return False, None
        except aiodns.error.DNSError:
            return False, None
        except Exception:
            return False, None

    async def verify_domain(self, domain: str, expected_token: str) -> VerificationResult:
        """Perform full domain verification (CNAME + TXT).

        Args:
            domain: The custom domain to verify.
            expected_token: The expected TXT verification token.

        Returns:
            VerificationResult with status and details.
        """
        cname_task = self.verify_cname(domain)
        txt_task = self.verify_txt_record(domain, expected_token)

        (cname_valid, cname_target), (txt_valid, txt_value) = await asyncio.gather(
            cname_task, txt_task
        )

        if cname_valid and txt_valid:
            status = VerificationStatus.FULLY_VERIFIED
            error = None
        elif cname_valid:
            status = VerificationStatus.CNAME_VERIFIED
            error = f"TXT record not found or invalid at _instanton.{domain}"
        else:
            status = VerificationStatus.FAILED
            if not cname_valid:
                error = f"CNAME record not found. Expected {domain} → {self.base_domain}"
            else:
                error = f"TXT record verification failed at _instanton.{domain}"

        return VerificationResult(
            domain=domain,
            status=status,
            cname_valid=cname_valid,
            cname_target=cname_target,
            txt_valid=txt_valid,
            txt_value=txt_value,
            error=error,
        )

    async def check_domain_reachable(self, domain: str) -> bool:
        """Check if domain resolves to any IP address.

        This is a quick check to see if DNS is configured at all.

        Args:
            domain: The domain to check.

        Returns:
            True if domain resolves to an IP.
        """
        resolver = self._get_resolver()
        try:
            result = await resolver.query_dns(domain, "A")
            return bool(result)
        except aiodns.error.DNSError:
            try:
                result = await resolver.query_dns(domain, "AAAA")
                return bool(result)
            except aiodns.error.DNSError:
                return False
        except Exception:
            return False
