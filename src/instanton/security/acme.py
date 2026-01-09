"""Full ACME (RFC 8555) client for Let's Encrypt certificate automation.

This module provides:
- Full ACME protocol implementation (RFC 8555)
- HTTP-01 and DNS-01 challenge support
- Automatic certificate issuance and renewal
- Multiple DNS provider integrations
- sslip.io and nip.io wildcard DNS support
- Caddy integration for automatic TLS
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import hashlib
import json
import secrets
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Any, Protocol

import httpx
import structlog
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509.oid import NameOID

logger = structlog.get_logger()


# ==============================================================================
# Constants
# ==============================================================================


class ACMEDirectory(Enum):
    """ACME directory URLs."""

    LETSENCRYPT_PRODUCTION = "https://acme-v02.api.letsencrypt.org/directory"
    LETSENCRYPT_STAGING = "https://acme-staging-v02.api.letsencrypt.org/directory"
    ZEROSSL = "https://acme.zerossl.com/v2/DV90"
    BUYPASS_PRODUCTION = "https://api.buypass.com/acme/directory"
    BUYPASS_STAGING = "https://api.test4.buypass.no/acme/directory"


class ChallengeType(Enum):
    """ACME challenge types."""

    HTTP_01 = "http-01"
    DNS_01 = "dns-01"
    TLS_ALPN_01 = "tls-alpn-01"


class OrderStatus(Enum):
    """ACME order status."""

    PENDING = "pending"
    READY = "ready"
    PROCESSING = "processing"
    VALID = "valid"
    INVALID = "invalid"


class AuthorizationStatus(Enum):
    """ACME authorization status."""

    PENDING = "pending"
    VALID = "valid"
    INVALID = "invalid"
    DEACTIVATED = "deactivated"
    EXPIRED = "expired"
    REVOKED = "revoked"


# ==============================================================================
# Data Classes
# ==============================================================================


@dataclass
class ACMEChallenge:
    """ACME challenge information."""

    type: ChallengeType
    url: str
    token: str
    status: str
    key_authorization: str | None = None
    dns_value: str | None = None
    validated: datetime | None = None
    error: dict[str, Any] | None = None


@dataclass
class ACMEAuthorization:
    """ACME authorization information."""

    identifier: str
    identifier_type: str  # "dns" or "ip"
    status: AuthorizationStatus
    expires: datetime | None
    challenges: list[ACMEChallenge]
    wildcard: bool = False


@dataclass
class ACMEOrder:
    """ACME order information."""

    url: str
    status: OrderStatus
    expires: datetime | None
    identifiers: list[dict[str, str]]
    authorizations: list[str]
    finalize_url: str
    certificate_url: str | None = None


@dataclass
class ACMEAccount:
    """ACME account information."""

    url: str
    status: str
    contact: list[str]
    created_at: datetime | None = None
    orders_url: str | None = None


@dataclass
class CertificateResult:
    """Result of certificate issuance."""

    certificate_pem: bytes
    private_key_pem: bytes
    chain_pem: bytes
    domains: list[str]
    not_before: datetime
    not_after: datetime
    issuer: str


# ==============================================================================
# JWS/JWK Utilities
# ==============================================================================


def _b64url_encode(data: bytes) -> str:
    """Base64url encode without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(data: str) -> bytes:
    """Base64url decode with padding restoration."""
    padded = data + "=" * (4 - len(data) % 4)
    return base64.urlsafe_b64decode(padded)


def _get_jwk(private_key: ec.EllipticCurvePrivateKey | rsa.RSAPrivateKey) -> dict[str, Any]:
    """Get JWK representation of public key."""
    if isinstance(private_key, ec.EllipticCurvePrivateKey):
        public_key = private_key.public_key()
        public_numbers = public_key.public_numbers()

        # Get curve name
        curve = public_key.curve
        if isinstance(curve, ec.SECP256R1):
            crv = "P-256"
            coord_size = 32
        elif isinstance(curve, ec.SECP384R1):
            crv = "P-384"
            coord_size = 48
        elif isinstance(curve, ec.SECP521R1):
            crv = "P-521"
            coord_size = 66
        else:
            raise ValueError(f"Unsupported curve: {curve.name}")

        return {
            "kty": "EC",
            "crv": crv,
            "x": _b64url_encode(public_numbers.x.to_bytes(coord_size, "big")),
            "y": _b64url_encode(public_numbers.y.to_bytes(coord_size, "big")),
        }
    elif isinstance(private_key, rsa.RSAPrivateKey):
        public_key = private_key.public_key()
        public_numbers = public_key.public_numbers()

        # Calculate byte sizes
        n_bytes = (public_numbers.n.bit_length() + 7) // 8
        e_bytes = (public_numbers.e.bit_length() + 7) // 8

        return {
            "kty": "RSA",
            "n": _b64url_encode(public_numbers.n.to_bytes(n_bytes, "big")),
            "e": _b64url_encode(public_numbers.e.to_bytes(e_bytes, "big")),
        }
    else:
        raise ValueError(f"Unsupported key type: {type(private_key)}")


def _get_jwk_thumbprint(jwk: dict[str, Any]) -> str:
    """Calculate JWK thumbprint (RFC 7638)."""
    if jwk["kty"] == "EC":
        canonical = json.dumps(
            {"crv": jwk["crv"], "kty": "EC", "x": jwk["x"], "y": jwk["y"]},
            sort_keys=True,
            separators=(",", ":"),
        )
    else:
        canonical = json.dumps(
            {"e": jwk["e"], "kty": "RSA", "n": jwk["n"]},
            sort_keys=True,
            separators=(",", ":"),
        )
    return _b64url_encode(hashlib.sha256(canonical.encode()).digest())


def _sign_jws(
    private_key: ec.EllipticCurvePrivateKey | rsa.RSAPrivateKey,
    protected: dict[str, Any],
    payload: dict[str, Any] | str,
) -> dict[str, str]:
    """Create a JWS (JSON Web Signature)."""
    # Encode protected header
    protected_b64 = _b64url_encode(json.dumps(protected, separators=(",", ":")).encode())

    # Encode payload
    if payload == "":
        payload_b64 = ""
    else:
        payload_b64 = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())

    # Sign
    signing_input = f"{protected_b64}.{payload_b64}".encode()

    if isinstance(private_key, ec.EllipticCurvePrivateKey):
        # EC signature
        signature = private_key.sign(signing_input, ec.ECDSA(hashes.SHA256()))

        # Convert from DER to raw R||S format
        from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

        r, s = decode_dss_signature(signature)

        # Determine coordinate size based on curve
        curve = private_key.curve
        if isinstance(curve, ec.SECP256R1):
            coord_size = 32
        elif isinstance(curve, ec.SECP384R1):
            coord_size = 48
        elif isinstance(curve, ec.SECP521R1):
            coord_size = 66
        else:
            coord_size = 32

        signature = r.to_bytes(coord_size, "big") + s.to_bytes(coord_size, "big")
    else:
        # RSA signature
        signature = private_key.sign(
            signing_input,
            padding.PKCS1v15(),
            hashes.SHA256(),
        )

    signature_b64 = _b64url_encode(signature)

    return {
        "protected": protected_b64,
        "payload": payload_b64,
        "signature": signature_b64,
    }


# ==============================================================================
# DNS Provider Protocol
# ==============================================================================


class DNSProvider(Protocol):
    """Protocol for DNS providers supporting DNS-01 challenges."""

    async def create_txt_record(self, domain: str, name: str, value: str, ttl: int = 300) -> str:
        """Create a TXT record for DNS-01 challenge.

        Args:
            domain: The domain (e.g., "example.com")
            name: Record name (e.g., "_acme-challenge")
            value: TXT record value
            ttl: Time to live in seconds

        Returns:
            Record ID for later deletion
        """
        ...

    async def delete_txt_record(self, domain: str, record_id: str) -> bool:
        """Delete a TXT record.

        Args:
            domain: The domain
            record_id: ID returned from create_txt_record

        Returns:
            True if deleted successfully
        """
        ...

    async def wait_for_propagation(
        self, domain: str, name: str, value: str, timeout: float = 120.0
    ) -> bool:
        """Wait for DNS record to propagate.

        Args:
            domain: The domain
            name: Record name
            value: Expected TXT value
            timeout: Maximum wait time in seconds

        Returns:
            True if record is visible
        """
        ...


# ==============================================================================
# Built-in DNS Providers
# ==============================================================================


class CloudflareDNSProvider:
    """Cloudflare DNS provider for DNS-01 challenges."""

    API_BASE = "https://api.cloudflare.com/client/v4"

    def __init__(
        self,
        api_token: str | None = None,
        api_key: str | None = None,
        email: str | None = None,
        zone_id: str | None = None,
    ):
        """Initialize Cloudflare DNS provider.

        Args:
            api_token: Cloudflare API token (preferred)
            api_key: Cloudflare Global API Key (legacy)
            email: Email for Global API Key auth
            zone_id: Optional pre-configured zone ID
        """
        self.api_token = api_token
        self.api_key = api_key
        self.email = email
        self._zone_id = zone_id
        self._zone_cache: dict[str, str] = {}

    def _get_headers(self) -> dict[str, str]:
        """Get authorization headers."""
        if self.api_token:
            return {"Authorization": f"Bearer {self.api_token}"}
        elif self.api_key and self.email:
            return {"X-Auth-Key": self.api_key, "X-Auth-Email": self.email}
        else:
            raise ValueError("Cloudflare API token or API key+email required")

    async def _get_zone_id(self, domain: str) -> str:
        """Get zone ID for a domain."""
        if self._zone_id:
            return self._zone_id

        # Find the zone for this domain
        parts = domain.split(".")
        for i in range(len(parts) - 1):
            zone_name = ".".join(parts[i:])
            if zone_name in self._zone_cache:
                return self._zone_cache[zone_name]

            async with httpx.AsyncClient() as client:
                resp = await client.get(
                    f"{self.API_BASE}/zones",
                    headers=self._get_headers(),
                    params={"name": zone_name},
                )
                data = resp.json()
                if data.get("success") and data.get("result"):
                    zone_id = data["result"][0]["id"]
                    self._zone_cache[zone_name] = zone_id
                    return zone_id

        raise ValueError(f"Could not find Cloudflare zone for {domain}")

    async def create_txt_record(self, domain: str, name: str, value: str, ttl: int = 120) -> str:
        """Create a TXT record."""
        zone_id = await self._get_zone_id(domain)
        record_name = f"{name}.{domain}"

        async with httpx.AsyncClient() as client:
            resp = await client.post(
                f"{self.API_BASE}/zones/{zone_id}/dns_records",
                headers=self._get_headers(),
                json={
                    "type": "TXT",
                    "name": record_name,
                    "content": value,
                    "ttl": ttl,
                },
            )
            data = resp.json()
            if not data.get("success"):
                raise RuntimeError(f"Failed to create TXT record: {data.get('errors')}")

            return data["result"]["id"]

    async def delete_txt_record(self, domain: str, record_id: str) -> bool:
        """Delete a TXT record."""
        zone_id = await self._get_zone_id(domain)

        async with httpx.AsyncClient() as client:
            resp = await client.delete(
                f"{self.API_BASE}/zones/{zone_id}/dns_records/{record_id}",
                headers=self._get_headers(),
            )
            data = resp.json()
            return data.get("success", False)

    async def wait_for_propagation(
        self, domain: str, name: str, value: str, timeout: float = 120.0
    ) -> bool:
        """Wait for DNS propagation."""
        record_name = f"{name}.{domain}"
        start = time.monotonic()

        while time.monotonic() - start < timeout:
            try:
                # Try to resolve using system DNS
                import dns.resolver  # type: ignore

                resolver = dns.resolver.Resolver()
                resolver.nameservers = ["8.8.8.8", "1.1.1.1"]
                answers = resolver.resolve(record_name, "TXT")
                for rdata in answers:
                    for txt in rdata.strings:
                        if txt.decode() == value:
                            return True
            except Exception:
                pass

            await asyncio.sleep(5)

        return False


class HostingerDNSProvider:
    """Hostinger DNS provider for DNS-01 challenges.

    Note: Hostinger API access may require specific plan or configuration.
    This implementation uses Hostinger's API if available.
    """

    API_BASE = "https://api.hostinger.com/v1"

    def __init__(self, api_key: str, domain_id: str | None = None):
        """Initialize Hostinger DNS provider.

        Args:
            api_key: Hostinger API key
            domain_id: Optional pre-configured domain ID
        """
        self.api_key = api_key
        self._domain_id = domain_id

    def _get_headers(self) -> dict[str, str]:
        """Get authorization headers."""
        return {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

    async def create_txt_record(self, domain: str, name: str, value: str, ttl: int = 300) -> str:
        """Create a TXT record via Hostinger API."""
        async with httpx.AsyncClient() as client:
            # First, get domain info
            resp = await client.get(
                f"{self.API_BASE}/domains/{domain}/dns",
                headers=self._get_headers(),
            )

            if resp.status_code == 200:
                # Create the record
                resp = await client.post(
                    f"{self.API_BASE}/domains/{domain}/dns/records",
                    headers=self._get_headers(),
                    json={
                        "type": "TXT",
                        "name": name,
                        "content": value,
                        "ttl": ttl,
                    },
                )
                if resp.status_code in (200, 201):
                    data = resp.json()
                    return data.get("id", f"{name}-{value[:8]}")

            raise RuntimeError(f"Hostinger API error: {resp.status_code}")

    async def delete_txt_record(self, domain: str, record_id: str) -> bool:
        """Delete a TXT record."""
        async with httpx.AsyncClient() as client:
            resp = await client.delete(
                f"{self.API_BASE}/domains/{domain}/dns/records/{record_id}",
                headers=self._get_headers(),
            )
            return resp.status_code in (200, 204)

    async def wait_for_propagation(
        self, domain: str, name: str, value: str, timeout: float = 120.0
    ) -> bool:
        """Wait for DNS propagation."""
        record_name = f"{name}.{domain}" if name else domain
        start = time.monotonic()

        while time.monotonic() - start < timeout:
            try:
                import dns.resolver  # type: ignore

                resolver = dns.resolver.Resolver()
                resolver.nameservers = ["8.8.8.8", "1.1.1.1"]
                answers = resolver.resolve(record_name, "TXT")
                for rdata in answers:
                    for txt in rdata.strings:
                        if txt.decode() == value:
                            return True
            except Exception:
                pass

            await asyncio.sleep(5)

        return False


class ManualDNSProvider:
    """Manual DNS provider that prompts user for DNS changes."""

    def __init__(self, callback: Callable[[str, str, str], None] | None = None):
        """Initialize manual DNS provider.

        Args:
            callback: Optional callback(domain, name, value) for automation
        """
        self.callback = callback
        self._records: dict[str, str] = {}

    async def create_txt_record(self, domain: str, name: str, value: str, ttl: int = 300) -> str:
        """Create a TXT record (manual)."""
        record_name = f"{name}.{domain}"
        record_id = f"manual-{secrets.token_hex(8)}"

        if self.callback:
            self.callback(domain, name, value)
        else:
            logger.info(
                "Manual DNS action required",
                action="CREATE TXT RECORD",
                name=record_name,
                value=value,
                ttl=ttl,
            )
            print(f"\n{'=' * 60}")
            print("MANUAL DNS ACTION REQUIRED")
            print(f"{'=' * 60}")
            print("Create TXT record:")
            print(f"  Name:  {record_name}")
            print(f"  Value: {value}")
            print(f"  TTL:   {ttl}")
            print(f"{'=' * 60}\n")

        self._records[record_id] = record_name
        return record_id

    async def delete_txt_record(self, domain: str, record_id: str) -> bool:
        """Delete a TXT record (manual)."""
        record_name = self._records.pop(record_id, f"_acme-challenge.{domain}")

        logger.info(
            "Manual DNS action required",
            action="DELETE TXT RECORD",
            name=record_name,
        )
        return True

    async def wait_for_propagation(
        self, domain: str, name: str, value: str, timeout: float = 300.0
    ) -> bool:
        """Wait for DNS propagation with user confirmation."""
        record_name = f"{name}.{domain}"
        start = time.monotonic()

        while time.monotonic() - start < timeout:
            try:
                import dns.resolver  # type: ignore

                resolver = dns.resolver.Resolver()
                resolver.nameservers = ["8.8.8.8", "1.1.1.1"]
                answers = resolver.resolve(record_name, "TXT")
                for rdata in answers:
                    for txt in rdata.strings:
                        if txt.decode() == value:
                            logger.info("DNS record propagated", name=record_name)
                            return True
            except Exception:
                pass

            logger.debug("Waiting for DNS propagation", name=record_name)
            await asyncio.sleep(10)

        return False


# ==============================================================================
# sslip.io / nip.io Support
# ==============================================================================


@dataclass
class WildcardDNSConfig:
    """Configuration for wildcard DNS services like sslip.io."""

    service: str = "sslip.io"  # or "nip.io"
    base_ip: str = ""  # e.g., "127.0.0.1" or public IP
    custom_subdomain: str = ""  # Optional prefix

    @property
    def domain(self) -> str:
        """Generate the wildcard DNS domain."""
        ip_part = self.base_ip.replace(".", "-")
        if self.custom_subdomain:
            return f"{self.custom_subdomain}.{ip_part}.{self.service}"
        return f"{ip_part}.{self.service}"


def get_sslip_domain(ip: str, subdomain: str = "") -> str:
    """Get an sslip.io domain for an IP address.

    Args:
        ip: IP address (e.g., "203.0.113.42")
        subdomain: Optional subdomain prefix

    Returns:
        Domain like "myapp.203-0-113-42.sslip.io"
    """
    ip_part = ip.replace(".", "-")
    if subdomain:
        return f"{subdomain}.{ip_part}.sslip.io"
    return f"{ip_part}.sslip.io"


def get_nip_domain(ip: str, subdomain: str = "") -> str:
    """Get a nip.io domain for an IP address.

    Args:
        ip: IP address (e.g., "203.0.113.42")
        subdomain: Optional subdomain prefix

    Returns:
        Domain like "myapp.203.0.113.42.nip.io"
    """
    if subdomain:
        return f"{subdomain}.{ip}.nip.io"
    return f"{ip}.nip.io"


async def get_public_ip() -> str:
    """Get the public IP address of this machine."""
    services = [
        "https://api.ipify.org",
        "https://ifconfig.me/ip",
        "https://icanhazip.com",
        "https://ipinfo.io/ip",
    ]

    async with httpx.AsyncClient(timeout=10.0) as client:
        for service in services:
            try:
                resp = await client.get(service)
                if resp.status_code == 200:
                    return resp.text.strip()
            except Exception:
                continue

    raise RuntimeError("Could not determine public IP address")


# ==============================================================================
# HTTP-01 Challenge Server
# ==============================================================================


class HTTP01ChallengeServer:
    """HTTP server for handling HTTP-01 ACME challenges."""

    def __init__(self, host: str = "0.0.0.0", port: int = 80):
        """Initialize challenge server.

        Args:
            host: Bind address
            port: Bind port (must be 80 for HTTP-01)
        """
        self.host = host
        self.port = port
        self._challenges: dict[str, str] = {}  # token -> key_authorization
        self._server: Any = None

    def add_challenge(self, token: str, key_authorization: str) -> None:
        """Add a challenge response."""
        self._challenges[token] = key_authorization
        logger.debug("Added HTTP-01 challenge", token=token[:16])

    def remove_challenge(self, token: str) -> None:
        """Remove a challenge response."""
        self._challenges.pop(token, None)

    async def start(self) -> None:
        """Start the challenge server."""
        from aiohttp import web

        async def handle_challenge(request: web.Request) -> web.Response:
            token = request.match_info.get("token", "")
            if token in self._challenges:
                logger.info("Served HTTP-01 challenge", token=token[:16])
                return web.Response(
                    text=self._challenges[token],
                    content_type="text/plain",
                )
            return web.Response(status=404, text="Challenge not found")

        async def handle_health(request: web.Request) -> web.Response:
            return web.Response(text="OK")

        app = web.Application()
        app.router.add_get("/.well-known/acme-challenge/{token}", handle_challenge)
        app.router.add_get("/health", handle_health)

        runner = web.AppRunner(app)
        await runner.setup()
        self._server = web.TCPSite(runner, self.host, self.port)
        await self._server.start()

        logger.info("HTTP-01 challenge server started", host=self.host, port=self.port)

    async def stop(self) -> None:
        """Stop the challenge server."""
        if self._server:
            await self._server.stop()
            self._server = None
            logger.info("HTTP-01 challenge server stopped")


# ==============================================================================
# ACME Client
# ==============================================================================


class FullACMEClient:
    """Full ACME client implementation (RFC 8555)."""

    def __init__(
        self,
        email: str,
        directory: ACMEDirectory | str = ACMEDirectory.LETSENCRYPT_PRODUCTION,
        account_key_path: Path | None = None,
        key_type: str = "EC",  # "EC" or "RSA"
    ):
        """Initialize ACME client.

        Args:
            email: Contact email for account
            directory: ACME directory URL or enum
            account_key_path: Path to store/load account key
            key_type: Account key type ("EC" or "RSA")
        """
        self.email = email
        self.directory_url = directory.value if isinstance(directory, ACMEDirectory) else directory
        self.account_key_path = account_key_path
        self.key_type = key_type

        self._account_key: ec.EllipticCurvePrivateKey | rsa.RSAPrivateKey | None = None
        self._account: ACMEAccount | None = None
        self._directory: dict[str, Any] = {}
        self._nonce: str | None = None

        # Challenge handlers
        self._http_server: HTTP01ChallengeServer | None = None
        self._dns_provider: DNSProvider | None = None

    async def initialize(self) -> ACMEAccount:
        """Initialize client: load/create account key and register with ACME.

        Returns:
            Account information
        """
        # Fetch directory
        async with httpx.AsyncClient() as client:
            resp = await client.get(self.directory_url)
            resp.raise_for_status()
            self._directory = resp.json()

        # Load or generate account key
        self._account_key = self._load_or_create_account_key()

        # Get initial nonce
        await self._get_nonce()

        # Register or get existing account
        self._account = await self._register_account()

        logger.info(
            "ACME client initialized",
            directory=self.directory_url,
            account=self._account.url,
        )

        return self._account

    def _load_or_create_account_key(
        self,
    ) -> ec.EllipticCurvePrivateKey | rsa.RSAPrivateKey:
        """Load existing account key or create new one."""
        if self.account_key_path and self.account_key_path.exists():
            key_pem = self.account_key_path.read_bytes()
            key = serialization.load_pem_private_key(key_pem, password=None)
            if isinstance(key, (ec.EllipticCurvePrivateKey, rsa.RSAPrivateKey)):
                logger.info("Loaded existing account key", path=str(self.account_key_path))
                return key
            raise ValueError(f"Unsupported key type: {type(key)}")

        # Generate new key
        if self.key_type == "RSA":
            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        else:
            key = ec.generate_private_key(ec.SECP256R1())

        # Save key if path specified
        if self.account_key_path:
            self.account_key_path.parent.mkdir(parents=True, exist_ok=True)
            key_pem = key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
            self.account_key_path.write_bytes(key_pem)
            self.account_key_path.chmod(0o600)
            logger.info("Generated new account key", path=str(self.account_key_path))

        return key

    async def _get_nonce(self) -> str:
        """Get a fresh anti-replay nonce."""
        async with httpx.AsyncClient() as client:
            resp = await client.head(self._directory["newNonce"])
            self._nonce = resp.headers["Replay-Nonce"]
            return self._nonce

    async def _signed_request(
        self,
        url: str,
        payload: dict[str, Any] | str,
        use_kid: bool = True,
    ) -> httpx.Response:
        """Make a signed request to ACME server.

        Args:
            url: Request URL
            payload: Request payload (or "" for POST-as-GET)
            use_kid: Use account URL (kid) instead of JWK

        Returns:
            HTTP response
        """
        if not self._account_key:
            raise RuntimeError("Account key not initialized")

        if not self._nonce:
            await self._get_nonce()

        # Build protected header
        is_ec = isinstance(self._account_key, ec.EllipticCurvePrivateKey)
        protected: dict[str, Any] = {
            "alg": "ES256" if is_ec else "RS256",
            "nonce": self._nonce,
            "url": url,
        }

        if use_kid and self._account:
            protected["kid"] = self._account.url
        else:
            protected["jwk"] = _get_jwk(self._account_key)

        # Sign request
        jws = _sign_jws(self._account_key, protected, payload)

        # Send request
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                url,
                json=jws,
                headers={"Content-Type": "application/jose+json"},
            )

        # Update nonce
        if "Replay-Nonce" in resp.headers:
            self._nonce = resp.headers["Replay-Nonce"]

        return resp

    async def _register_account(self) -> ACMEAccount:
        """Register or retrieve existing account."""
        payload = {
            "termsOfServiceAgreed": True,
            "contact": [f"mailto:{self.email}"],
        }

        resp = await self._signed_request(
            self._directory["newAccount"],
            payload,
            use_kid=False,
        )

        if resp.status_code not in (200, 201):
            raise RuntimeError(f"Account registration failed: {resp.text}")

        data = resp.json()
        account_url = resp.headers.get("Location", "")

        return ACMEAccount(
            url=account_url,
            status=data.get("status", "valid"),
            contact=data.get("contact", []),
            orders_url=data.get("orders"),
        )

    async def create_order(self, domains: list[str]) -> ACMEOrder:
        """Create a new certificate order.

        Args:
            domains: List of domain names (first is primary)

        Returns:
            Order information
        """
        identifiers = [{"type": "dns", "value": d} for d in domains]

        resp = await self._signed_request(
            self._directory["newOrder"],
            {"identifiers": identifiers},
        )

        if resp.status_code not in (200, 201):
            raise RuntimeError(f"Order creation failed: {resp.text}")

        data = resp.json()
        order_url = resp.headers.get("Location", "")

        return ACMEOrder(
            url=order_url,
            status=OrderStatus(data["status"]),
            expires=datetime.fromisoformat(data["expires"].replace("Z", "+00:00"))
            if "expires" in data
            else None,
            identifiers=data["identifiers"],
            authorizations=data["authorizations"],
            finalize_url=data["finalize"],
            certificate_url=data.get("certificate"),
        )

    async def get_authorization(self, authz_url: str) -> ACMEAuthorization:
        """Get authorization details.

        Args:
            authz_url: Authorization URL from order

        Returns:
            Authorization information with challenges
        """
        resp = await self._signed_request(authz_url, "")

        if resp.status_code != 200:
            raise RuntimeError(f"Authorization fetch failed: {resp.text}")

        data = resp.json()

        # Get key authorization thumbprint
        if not self._account_key:
            raise RuntimeError("Account key not initialized")
        jwk = _get_jwk(self._account_key)
        thumbprint = _get_jwk_thumbprint(jwk)

        challenges = []
        for ch in data.get("challenges", []):
            token = ch.get("token", "")
            key_auth = f"{token}.{thumbprint}"

            # Calculate DNS-01 value
            dns_value = _b64url_encode(hashlib.sha256(key_auth.encode()).digest())

            challenges.append(
                ACMEChallenge(
                    type=ChallengeType(ch["type"]),
                    url=ch["url"],
                    token=token,
                    status=ch["status"],
                    key_authorization=key_auth,
                    dns_value=dns_value,
                )
            )

        return ACMEAuthorization(
            identifier=data["identifier"]["value"],
            identifier_type=data["identifier"]["type"],
            status=AuthorizationStatus(data["status"]),
            expires=datetime.fromisoformat(data["expires"].replace("Z", "+00:00"))
            if "expires" in data
            else None,
            challenges=challenges,
            wildcard=data.get("wildcard", False),
        )

    async def respond_to_challenge(self, challenge: ACMEChallenge) -> bool:
        """Respond to a challenge.

        Args:
            challenge: Challenge to respond to

        Returns:
            True if challenge response was accepted
        """
        resp = await self._signed_request(challenge.url, {})

        if resp.status_code != 200:
            logger.error("Challenge response failed", error=resp.text)
            return False

        return True

    async def poll_authorization(self, authz_url: str, timeout: float = 120.0) -> ACMEAuthorization:
        """Poll authorization until it's valid or invalid.

        Args:
            authz_url: Authorization URL
            timeout: Maximum wait time in seconds

        Returns:
            Final authorization status
        """
        start = time.monotonic()

        while time.monotonic() - start < timeout:
            authz = await self.get_authorization(authz_url)

            if authz.status == AuthorizationStatus.VALID:
                logger.info("Authorization valid", domain=authz.identifier)
                return authz
            elif authz.status == AuthorizationStatus.INVALID:
                raise RuntimeError(f"Authorization invalid for {authz.identifier}")
            elif authz.status == AuthorizationStatus.PENDING:
                await asyncio.sleep(2)
            else:
                await asyncio.sleep(2)

        raise TimeoutError(f"Authorization polling timed out for {authz_url}")

    async def finalize_order(
        self, order: ACMEOrder, private_key: rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey
    ) -> ACMEOrder:
        """Finalize order with CSR.

        Args:
            order: Order to finalize
            private_key: Private key for certificate

        Returns:
            Updated order with certificate URL
        """
        # Build CSR
        domains = [id["value"] for id in order.identifiers]
        csr = self._create_csr(domains, private_key)
        csr_der = csr.public_bytes(serialization.Encoding.DER)
        csr_b64 = _b64url_encode(csr_der)

        resp = await self._signed_request(order.finalize_url, {"csr": csr_b64})

        if resp.status_code != 200:
            raise RuntimeError(f"Order finalization failed: {resp.text}")

        data = resp.json()

        return ACMEOrder(
            url=order.url,
            status=OrderStatus(data["status"]),
            expires=order.expires,
            identifiers=order.identifiers,
            authorizations=order.authorizations,
            finalize_url=order.finalize_url,
            certificate_url=data.get("certificate"),
        )

    def _create_csr(
        self,
        domains: list[str],
        private_key: rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey,
    ) -> x509.CertificateSigningRequest:
        """Create a CSR for the given domains."""
        # Primary domain as CN
        subject = x509.Name(
            [
                x509.NameAttribute(NameOID.COMMON_NAME, domains[0]),
            ]
        )

        # All domains as SANs
        san = x509.SubjectAlternativeName([x509.DNSName(d) for d in domains])

        builder = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(subject)
            .add_extension(san, critical=False)
        )

        return builder.sign(private_key, hashes.SHA256())

    async def poll_order(self, order: ACMEOrder, timeout: float = 120.0) -> ACMEOrder:
        """Poll order until certificate is ready.

        Args:
            order: Order to poll
            timeout: Maximum wait time in seconds

        Returns:
            Order with certificate URL
        """
        start = time.monotonic()

        while time.monotonic() - start < timeout:
            resp = await self._signed_request(order.url, "")
            data = resp.json()

            status = OrderStatus(data["status"])

            if status == OrderStatus.VALID:
                return ACMEOrder(
                    url=order.url,
                    status=status,
                    expires=order.expires,
                    identifiers=order.identifiers,
                    authorizations=order.authorizations,
                    finalize_url=order.finalize_url,
                    certificate_url=data.get("certificate"),
                )
            elif status == OrderStatus.INVALID:
                raise RuntimeError("Order became invalid")

            await asyncio.sleep(2)

        raise TimeoutError("Order polling timed out")

    async def download_certificate(self, order: ACMEOrder) -> tuple[bytes, bytes]:
        """Download certificate from completed order.

        Args:
            order: Completed order with certificate URL

        Returns:
            Tuple of (certificate_pem, chain_pem)
        """
        if not order.certificate_url:
            raise ValueError("Order has no certificate URL")

        resp = await self._signed_request(order.certificate_url, "")

        if resp.status_code != 200:
            raise RuntimeError(f"Certificate download failed: {resp.text}")

        full_chain = resp.content

        # Split into certificate and chain
        certs = full_chain.split(b"-----END CERTIFICATE-----")
        cert_pem = certs[0] + b"-----END CERTIFICATE-----\n"
        chain_pem = b"-----END CERTIFICATE-----".join(certs[1:])
        if chain_pem:
            chain_pem = chain_pem.strip()

        return cert_pem, chain_pem

    async def obtain_certificate(
        self,
        domains: list[str],
        challenge_type: ChallengeType = ChallengeType.HTTP_01,
        dns_provider: DNSProvider | None = None,
    ) -> CertificateResult:
        """Obtain a certificate for the given domains.

        Args:
            domains: List of domains (first is primary)
            challenge_type: Type of challenge to use
            dns_provider: DNS provider for DNS-01 challenges

        Returns:
            Certificate result with cert, key, and chain
        """
        logger.info("Obtaining certificate", domains=domains, challenge=challenge_type.value)

        # Generate certificate key
        cert_key = ec.generate_private_key(ec.SECP256R1())
        cert_key_pem = cert_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )

        # Create order
        order = await self.create_order(domains)
        logger.info("Created order", url=order.url)

        # Process each authorization
        cleanup_tasks = []
        try:
            for authz_url in order.authorizations:
                authz = await self.get_authorization(authz_url)
                logger.info("Processing authorization", domain=authz.identifier)

                # Find the right challenge
                challenge = None
                for ch in authz.challenges:
                    if ch.type == challenge_type:
                        challenge = ch
                        break

                if not challenge:
                    raise RuntimeError(
                        f"No {challenge_type.value} challenge for {authz.identifier}"
                    )

                # Set up challenge
                if challenge_type == ChallengeType.HTTP_01:
                    if not self._http_server:
                        self._http_server = HTTP01ChallengeServer()
                        await self._http_server.start()
                    self._http_server.add_challenge(
                        challenge.token, challenge.key_authorization or ""
                    )
                elif challenge_type == ChallengeType.DNS_01:
                    if not dns_provider:
                        raise ValueError("DNS provider required for DNS-01 challenge")

                    # Create TXT record
                    domain = authz.identifier
                    if authz.wildcard:
                        domain = domain.lstrip("*.")

                    record_id = await dns_provider.create_txt_record(
                        domain,
                        "_acme-challenge",
                        challenge.dns_value or "",
                    )
                    cleanup_tasks.append((dns_provider, domain, record_id))

                    # Wait for propagation
                    await dns_provider.wait_for_propagation(
                        domain,
                        "_acme-challenge",
                        challenge.dns_value or "",
                    )

                # Respond to challenge
                await self.respond_to_challenge(challenge)

                # Poll authorization
                await self.poll_authorization(authz_url)

            # Finalize order
            order = await self.finalize_order(order, cert_key)
            order = await self.poll_order(order)

            # Download certificate
            cert_pem, chain_pem = await self.download_certificate(order)

            # Parse certificate for info
            cert = x509.load_pem_x509_certificate(cert_pem)

            return CertificateResult(
                certificate_pem=cert_pem,
                private_key_pem=cert_key_pem,
                chain_pem=chain_pem,
                domains=domains,
                not_before=cert.not_valid_before_utc,
                not_after=cert.not_valid_after_utc,
                issuer=cert.issuer.rfc4514_string(),
            )

        finally:
            # Cleanup
            for dns_prov, domain, record_id in cleanup_tasks:
                try:
                    await dns_prov.delete_txt_record(domain, record_id)
                except Exception as e:
                    logger.warning("Failed to cleanup DNS record", error=str(e))

            if self._http_server:
                await self._http_server.stop()
                self._http_server = None


# ==============================================================================
# Caddy Integration
# ==============================================================================


@dataclass
class CaddyConfig:
    """Configuration for Caddy reverse proxy integration."""

    admin_api: str = "http://localhost:2019"
    email: str = ""
    acme_ca: str = ""  # Empty for Let's Encrypt production
    on_demand_tls: bool = False
    storage_path: str = ""


class CaddyManager:
    """Manager for Caddy reverse proxy with automatic TLS."""

    def __init__(self, config: CaddyConfig):
        """Initialize Caddy manager.

        Args:
            config: Caddy configuration
        """
        self.config = config

    async def configure_domain(
        self,
        domain: str,
        upstream: str,
        https_port: int = 443,
        http_port: int = 80,
    ) -> bool:
        """Configure Caddy to serve a domain.

        Args:
            domain: Domain name to serve
            upstream: Upstream server (e.g., "localhost:8000")
            https_port: HTTPS port
            http_port: HTTP port

        Returns:
            True if configuration was successful
        """
        caddy_config = {
            "apps": {
                "http": {
                    "servers": {
                        "srv0": {
                            "listen": [f":{https_port}"],
                            "routes": [
                                {
                                    "match": [{"host": [domain]}],
                                    "handle": [
                                        {
                                            "handler": "reverse_proxy",
                                            "upstreams": [{"dial": upstream}],
                                        }
                                    ],
                                }
                            ],
                            "tls_connection_policies": [{}],
                        }
                    }
                },
                "tls": {
                    "automation": {
                        "policies": [
                            {
                                "subjects": [domain],
                                "issuers": [
                                    {
                                        "module": "acme",
                                        "email": self.config.email,
                                    }
                                ],
                            }
                        ]
                    }
                },
            }
        }

        if self.config.acme_ca:
            caddy_config["apps"]["tls"]["automation"]["policies"][0]["issuers"][0]["ca"] = (
                self.config.acme_ca
            )

        async with httpx.AsyncClient() as client:
            try:
                resp = await client.post(
                    f"{self.config.admin_api}/load",
                    json=caddy_config,
                    headers={"Content-Type": "application/json"},
                )
                if resp.status_code == 200:
                    logger.info("Caddy configured", domain=domain)
                    return True
                else:
                    logger.error("Caddy configuration failed", error=resp.text)
                    return False
            except Exception as e:
                logger.error("Caddy API error", error=str(e))
                return False

    async def add_route(
        self,
        domain: str,
        upstream: str,
        path: str = "*",
    ) -> bool:
        """Add a route to existing Caddy configuration.

        Args:
            domain: Domain for the route
            upstream: Upstream server
            path: Path pattern (default: all paths)

        Returns:
            True if route was added
        """
        route = {
            "@id": f"route-{domain}-{secrets.token_hex(4)}",
            "match": [{"host": [domain], "path": [path]}],
            "handle": [
                {
                    "handler": "reverse_proxy",
                    "upstreams": [{"dial": upstream}],
                }
            ],
        }

        async with httpx.AsyncClient() as client:
            try:
                resp = await client.post(
                    f"{self.config.admin_api}/config/apps/http/servers/srv0/routes",
                    json=route,
                    headers={"Content-Type": "application/json"},
                )
                return resp.status_code == 200
            except Exception as e:
                logger.error("Failed to add Caddy route", error=str(e))
                return False

    async def remove_route(self, route_id: str) -> bool:
        """Remove a route from Caddy.

        Args:
            route_id: Route ID to remove

        Returns:
            True if removed
        """
        async with httpx.AsyncClient() as client:
            try:
                resp = await client.delete(
                    f"{self.config.admin_api}/id/{route_id}",
                )
                return resp.status_code == 200
            except Exception as e:
                logger.error("Failed to remove Caddy route", error=str(e))
                return False

    async def get_certificate_info(self, domain: str) -> dict[str, Any] | None:
        """Get certificate information for a domain.

        Args:
            domain: Domain to check

        Returns:
            Certificate info or None
        """
        async with httpx.AsyncClient() as client:
            try:
                resp = await client.get(
                    f"{self.config.admin_api}/certificates/{domain}",
                )
                if resp.status_code == 200:
                    return resp.json()
                return None
            except Exception:
                return None


# ==============================================================================
# Certificate Auto-Renewal Manager
# ==============================================================================


class CertificateAutoRenewal:
    """Automatic certificate renewal manager."""

    def __init__(
        self,
        acme_client: FullACMEClient,
        cert_store_path: Path,
        renewal_days: int = 30,
        check_interval: float = 3600,  # 1 hour
    ):
        """Initialize auto-renewal manager.

        Args:
            acme_client: ACME client for renewals
            cert_store_path: Path to store certificates
            renewal_days: Days before expiry to renew
            check_interval: Seconds between renewal checks
        """
        self.acme_client = acme_client
        self.cert_store_path = cert_store_path
        self.renewal_days = renewal_days
        self.check_interval = check_interval

        self._running = False
        self._task: asyncio.Task | None = None
        self._domains: dict[str, datetime] = {}  # domain -> expiry

    async def start(self) -> None:
        """Start the auto-renewal manager."""
        self.cert_store_path.mkdir(parents=True, exist_ok=True)
        self._running = True
        self._task = asyncio.create_task(self._renewal_loop())
        logger.info("Certificate auto-renewal started")

    async def stop(self) -> None:
        """Stop the auto-renewal manager."""
        self._running = False
        if self._task:
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._task
        logger.info("Certificate auto-renewal stopped")

    def register_domain(self, domain: str, expiry: datetime) -> None:
        """Register a domain for renewal tracking.

        Args:
            domain: Domain name
            expiry: Certificate expiry date
        """
        self._domains[domain] = expiry
        logger.info("Registered domain for renewal", domain=domain, expires=expiry)

    async def _renewal_loop(self) -> None:
        """Main renewal check loop."""
        while self._running:
            try:
                await self._check_renewals()
            except Exception as e:
                logger.error("Renewal check failed", error=str(e))

            await asyncio.sleep(self.check_interval)

    async def _check_renewals(self) -> None:
        """Check all domains for needed renewals."""
        now = datetime.now(UTC)
        renewal_threshold = now + timedelta(days=self.renewal_days)

        for domain, expiry in list(self._domains.items()):
            if expiry <= renewal_threshold:
                logger.info(
                    "Certificate needs renewal",
                    domain=domain,
                    expires=expiry,
                    days_remaining=(expiry - now).days,
                )

                try:
                    await self._renew_certificate(domain)
                except Exception as e:
                    logger.error("Renewal failed", domain=domain, error=str(e))

    async def _renew_certificate(self, domain: str) -> None:
        """Renew a certificate.

        Args:
            domain: Domain to renew
        """
        result = await self.acme_client.obtain_certificate([domain])

        # Save renewed certificate
        cert_path = self.cert_store_path / domain / "cert.pem"
        key_path = self.cert_store_path / domain / "key.pem"
        chain_path = self.cert_store_path / domain / "chain.pem"

        cert_path.parent.mkdir(parents=True, exist_ok=True)
        cert_path.write_bytes(result.certificate_pem)
        key_path.write_bytes(result.private_key_pem)
        key_path.chmod(0o600)
        if result.chain_pem:
            chain_path.write_bytes(result.chain_pem)

        # Update tracking
        self._domains[domain] = result.not_after

        logger.info(
            "Certificate renewed",
            domain=domain,
            expires=result.not_after,
        )


# ==============================================================================
# Exports
# ==============================================================================


__all__ = [
    # Enums
    "ACMEDirectory",
    "ChallengeType",
    "OrderStatus",
    "AuthorizationStatus",
    # Data classes
    "ACMEChallenge",
    "ACMEAuthorization",
    "ACMEOrder",
    "ACMEAccount",
    "CertificateResult",
    "WildcardDNSConfig",
    # DNS Providers
    "DNSProvider",
    "CloudflareDNSProvider",
    "HostingerDNSProvider",
    "ManualDNSProvider",
    # Wildcard DNS helpers
    "get_sslip_domain",
    "get_nip_domain",
    "get_public_ip",
    # Challenge server
    "HTTP01ChallengeServer",
    # ACME Client
    "FullACMEClient",
    # Caddy integration
    "CaddyConfig",
    "CaddyManager",
    # Auto-renewal
    "CertificateAutoRenewal",
]
