"""Anti-abuse measures for Instanton Cloud.

This module provides protection against:
- VPN/Proxy abuse
- Disposable email addresses
- Multiple accounts per IP/fingerprint
- High-risk IP addresses
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING

import httpx

if TYPE_CHECKING:
    from instanton.dashboard.config import DashboardConfig


class AbuseCheckResult(Enum):
    """Result of an abuse check."""

    ALLOWED = "allowed"
    VPN_DETECTED = "vpn_detected"
    PROXY_DETECTED = "proxy_detected"
    TOR_DETECTED = "tor_detected"
    DISPOSABLE_EMAIL = "disposable_email"
    IP_LIMIT_REACHED = "ip_limit_reached"
    FINGERPRINT_LIMIT = "fingerprint_limit_reached"
    HIGH_RISK_IP = "high_risk_ip"
    DATACENTER_IP = "datacenter_ip"


@dataclass
class IPInfo:
    """Information about an IP address."""

    ip: str
    country: str
    city: str
    asn: int
    org: str
    is_vpn: bool
    is_proxy: bool
    is_tor: bool
    is_datacenter: bool
    risk_score: int


# Common disposable email domains
DISPOSABLE_EMAIL_DOMAINS = frozenset([
    "tempmail.com",
    "guerrillamail.com",
    "10minutemail.com",
    "mailinator.com",
    "throwaway.email",
    "temp-mail.org",
    "fakeinbox.com",
    "getnada.com",
    "maildrop.cc",
    "mohmal.com",
    "minutemail.com",
    "tempr.email",
    "discard.email",
    "sharklasers.com",
    "spam4.me",
    "grr.la",
    "guerrillamailblock.com",
    "pokemail.net",
    "spamgourmet.com",
    "mytrashmail.com",
    "mailnesia.com",
    "trashmail.com",
    "tempail.com",
    "emailondeck.com",
    "mintemail.com",
    "mailcatch.com",
    "tempmailaddress.com",
    "yopmail.com",
    "jetable.org",
    "spambox.us",
    "anonymbox.com",
    "tempinbox.com",
    "33mail.com",
    "fakemailgenerator.com",
    "emailfake.com",
    "crazymailing.com",
    "tempmailo.com",
    "tempail.com",
    "mailsac.com",
    "burnermail.io",
    "temp-mail.io",
    "disposablemail.com",
    "emailtemporario.com.br",
    "tmpmail.org",
    "tmpmail.net",
    "dropmail.me",
])


class AntiAbuseChecker:
    """Checks for abuse patterns during signup and tunnel creation."""

    def __init__(self, config: DashboardConfig) -> None:
        """Initialize the anti-abuse checker.

        Args:
            config: Dashboard configuration.
        """
        self._config = config
        self._http_client: httpx.AsyncClient | None = None

    async def _get_client(self) -> httpx.AsyncClient:
        """Get or create HTTP client."""
        if self._http_client is None:
            self._http_client = httpx.AsyncClient(timeout=10.0)
        return self._http_client

    async def close(self) -> None:
        """Close the HTTP client."""
        if self._http_client:
            await self._http_client.aclose()
            self._http_client = None

    async def check_ip(self, ip: str) -> IPInfo:
        """Check IP against VPN/proxy detection service.

        Uses ipinfo.io or similar service to detect:
        - VPN connections
        - Proxy servers
        - Tor exit nodes
        - Datacenter IPs

        Args:
            ip: IP address to check.

        Returns:
            IPInfo with detection results.
        """
        # Default info for localhost/private IPs
        if ip in ("127.0.0.1", "::1") or ip.startswith(("10.", "192.168.", "172.")):
            return IPInfo(
                ip=ip,
                country="Local",
                city="Local",
                asn=0,
                org="Local Network",
                is_vpn=False,
                is_proxy=False,
                is_tor=False,
                is_datacenter=False,
                risk_score=0,
            )

        try:
            client = await self._get_client()

            # Use ipinfo.io (free tier allows 50k requests/month)
            response = await client.get(f"https://ipinfo.io/{ip}/json")

            if response.status_code != 200:
                # On error, allow the request but log
                return self._default_ip_info(ip)

            data = response.json()

            # Detect hosting/datacenter by org name
            org = data.get("org", "").lower()
            is_datacenter = any(
                keyword in org
                for keyword in [
                    "amazon",
                    "aws",
                    "google",
                    "microsoft",
                    "azure",
                    "digitalocean",
                    "linode",
                    "vultr",
                    "ovh",
                    "hetzner",
                    "cloudflare",
                    "hosting",
                    "datacenter",
                    "data center",
                    "server",
                    "vps",
                ]
            )

            # Parse ASN
            asn_str = data.get("asn", {}).get("asn", "0")
            try:
                asn = int(asn_str.replace("AS", ""))
            except (ValueError, AttributeError):
                asn = 0

            # Basic heuristic for VPN detection based on privacy field
            privacy = data.get("privacy", {})
            is_vpn = privacy.get("vpn", False)
            is_proxy = privacy.get("proxy", False)
            is_tor = privacy.get("tor", False)

            # Calculate risk score (0-100)
            risk_score = 0
            if is_vpn:
                risk_score += 40
            if is_proxy:
                risk_score += 30
            if is_tor:
                risk_score += 50
            if is_datacenter:
                risk_score += 20

            return IPInfo(
                ip=ip,
                country=data.get("country", "Unknown"),
                city=data.get("city", "Unknown"),
                asn=asn,
                org=data.get("org", "Unknown"),
                is_vpn=is_vpn,
                is_proxy=is_proxy,
                is_tor=is_tor,
                is_datacenter=is_datacenter,
                risk_score=min(risk_score, 100),
            )

        except Exception:
            # On any error, return default (allow)
            return self._default_ip_info(ip)

    def _default_ip_info(self, ip: str) -> IPInfo:
        """Return default IP info when detection fails."""
        return IPInfo(
            ip=ip,
            country="Unknown",
            city="Unknown",
            asn=0,
            org="Unknown",
            is_vpn=False,
            is_proxy=False,
            is_tor=False,
            is_datacenter=False,
            risk_score=0,
        )

    def check_email(self, email: str) -> AbuseCheckResult:
        """Check if email domain is disposable.

        Args:
            email: Email address to check.

        Returns:
            AbuseCheckResult.ALLOWED or AbuseCheckResult.DISPOSABLE_EMAIL.
        """
        try:
            domain = email.split("@")[1].lower()
        except IndexError:
            # Invalid email format
            return AbuseCheckResult.DISPOSABLE_EMAIL

        if domain in DISPOSABLE_EMAIL_DOMAINS:
            return AbuseCheckResult.DISPOSABLE_EMAIL

        return AbuseCheckResult.ALLOWED

    async def check_ip_account_limit(
        self,
        ip: str,
        current_accounts: int,
    ) -> AbuseCheckResult:
        """Check if IP has reached account limit.

        Args:
            ip: IP address.
            current_accounts: Number of accounts already created from this IP.

        Returns:
            AbuseCheckResult.ALLOWED or AbuseCheckResult.IP_LIMIT_REACHED.
        """
        if current_accounts >= self._config.max_accounts_per_ip:
            return AbuseCheckResult.IP_LIMIT_REACHED
        return AbuseCheckResult.ALLOWED

    async def check_fingerprint_limit(
        self,
        fingerprint: str,
        current_accounts: int,
    ) -> AbuseCheckResult:
        """Check if fingerprint has reached account limit.

        Args:
            fingerprint: Browser fingerprint hash.
            current_accounts: Number of accounts with this fingerprint.

        Returns:
            AbuseCheckResult.ALLOWED or AbuseCheckResult.FINGERPRINT_LIMIT.
        """
        if current_accounts >= self._config.max_accounts_per_fingerprint:
            return AbuseCheckResult.FINGERPRINT_LIMIT
        return AbuseCheckResult.ALLOWED

    async def full_signup_check(
        self,
        email: str,
        ip: str,
        fingerprint: str,
        ip_account_count: int = 0,
        fingerprint_account_count: int = 0,
    ) -> tuple[AbuseCheckResult, IPInfo | None]:
        """Run all anti-abuse checks for signup.

        Args:
            email: User's email address.
            ip: User's IP address.
            fingerprint: Browser fingerprint hash.
            ip_account_count: Existing accounts from this IP.
            fingerprint_account_count: Existing accounts with this fingerprint.

        Returns:
            Tuple of (result, ip_info). ip_info is None on early failure.
        """
        # Check 1: Email domain
        email_result = self.check_email(email)
        if email_result != AbuseCheckResult.ALLOWED:
            return email_result, None

        # Check 2: IP address
        ip_info = await self.check_ip(ip)

        # Block Tor exit nodes
        if ip_info.is_tor:
            return AbuseCheckResult.TOR_DETECTED, ip_info

        # Block high-risk IPs
        if ip_info.risk_score >= self._config.high_risk_threshold:
            return AbuseCheckResult.HIGH_RISK_IP, ip_info

        # Check VPN/Proxy (configurable)
        if self._config.block_vpn and ip_info.is_vpn:
            return AbuseCheckResult.VPN_DETECTED, ip_info

        if self._config.block_proxy and ip_info.is_proxy:
            return AbuseCheckResult.PROXY_DETECTED, ip_info

        if self._config.block_datacenter and ip_info.is_datacenter:
            return AbuseCheckResult.DATACENTER_IP, ip_info

        # Check 3: IP account limit
        ip_limit_result = await self.check_ip_account_limit(ip, ip_account_count)
        if ip_limit_result != AbuseCheckResult.ALLOWED:
            return ip_limit_result, ip_info

        # Check 4: Fingerprint limit
        fp_result = await self.check_fingerprint_limit(
            fingerprint, fingerprint_account_count
        )
        if fp_result != AbuseCheckResult.ALLOWED:
            return fp_result, ip_info

        return AbuseCheckResult.ALLOWED, ip_info


def hash_fingerprint(fingerprint_data: str) -> str:
    """Hash browser fingerprint data for storage.

    Args:
        fingerprint_data: Raw fingerprint data from browser.

    Returns:
        SHA-256 hash of the fingerprint.
    """
    return hashlib.sha256(fingerprint_data.encode()).hexdigest()


# Singleton instance
_checker: AntiAbuseChecker | None = None


def get_antiabuse_checker() -> AntiAbuseChecker:
    """Get the global anti-abuse checker instance.

    Returns:
        AntiAbuseChecker instance.

    Raises:
        RuntimeError: If checker not initialized.
    """
    if _checker is None:
        raise RuntimeError("Anti-abuse checker not initialized. Call init_antiabuse first.")
    return _checker


def init_antiabuse(config: DashboardConfig) -> AntiAbuseChecker:
    """Initialize the global anti-abuse checker.

    Args:
        config: Dashboard configuration.

    Returns:
        Initialized AntiAbuseChecker.
    """
    global _checker
    _checker = AntiAbuseChecker(config)
    return _checker
