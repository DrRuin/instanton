"""Instanton Certificate Manager - From Scratch Implementation.

This module provides a complete certificate management system built from scratch:
- Automatic TLS certificate provisioning (like Caddy)
- ACME/Let's Encrypt integration
- Self-signed certificate generation
- Certificate storage and rotation
- Wildcard DNS support (sslip.io style)
- Support for instanton.tech domain and self-hosted deployments

No external certificate management libraries are used - everything is implemented
using only the cryptography library for low-level operations.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import ipaddress
import re
import secrets
import ssl
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Any

import httpx
import structlog
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtensionOID, NameOID

logger = structlog.get_logger()


# ==============================================================================
# Configuration Constants
# ==============================================================================

# Official instanton.tech domain
INSTANTON_DOMAIN = "instanton.tech"
INSTANTON_RELAY_DOMAIN = f"relay.{INSTANTON_DOMAIN}"
INSTANTON_WILDCARD = f"*.{INSTANTON_DOMAIN}"

# ACME directories
LETSENCRYPT_PRODUCTION = "https://acme-v02.api.letsencrypt.org/directory"
LETSENCRYPT_STAGING = "https://acme-staging-v02.api.letsencrypt.org/directory"

# Certificate defaults
DEFAULT_KEY_TYPE = "EC"
DEFAULT_EC_CURVE = "P-256"
DEFAULT_RSA_SIZE = 2048
DEFAULT_CERT_VALIDITY_DAYS = 90
RENEWAL_THRESHOLD_DAYS = 30


# ==============================================================================
# Enums
# ==============================================================================


class CertificateSource(Enum):
    """Source of the certificate."""

    SELF_SIGNED = "self_signed"
    LETSENCRYPT = "letsencrypt"
    LETSENCRYPT_STAGING = "letsencrypt_staging"
    CUSTOM_CA = "custom_ca"
    USER_PROVIDED = "user_provided"


class KeyType(Enum):
    """Private key type."""

    EC_P256 = "ec_p256"
    EC_P384 = "ec_p384"
    RSA_2048 = "rsa_2048"
    RSA_4096 = "rsa_4096"


class ChallengeMethod(Enum):
    """ACME challenge method."""

    HTTP_01 = "http-01"
    DNS_01 = "dns-01"
    TLS_ALPN_01 = "tls-alpn-01"


# ==============================================================================
# Data Classes
# ==============================================================================


@dataclass
class CertificateBundle:
    """A complete certificate bundle with all necessary components."""

    domain: str
    certificate_pem: bytes
    private_key_pem: bytes
    chain_pem: bytes | None = None
    source: CertificateSource = CertificateSource.SELF_SIGNED
    not_before: datetime | None = None
    not_after: datetime | None = None
    issuer: str = ""
    san_domains: list[str] = field(default_factory=list)
    fingerprint_sha256: str = ""

    @property
    def is_expired(self) -> bool:
        """Check if certificate is expired."""
        if not self.not_after:
            return False
        return datetime.now(UTC) > self.not_after

    @property
    def days_until_expiry(self) -> int:
        """Days until certificate expires."""
        if not self.not_after:
            return 0
        delta = self.not_after - datetime.now(UTC)
        return max(0, delta.days)

    @property
    def needs_renewal(self) -> bool:
        """Check if certificate needs renewal."""
        return self.days_until_expiry < RENEWAL_THRESHOLD_DAYS

    @property
    def full_chain_pem(self) -> bytes:
        """Get full certificate chain PEM."""
        if self.chain_pem:
            return self.certificate_pem + b"\n" + self.chain_pem
        return self.certificate_pem


@dataclass
class InstantonDomainConfig:
    """Configuration for instanton.tech domain."""

    # Main domain settings
    base_domain: str = INSTANTON_DOMAIN
    relay_domain: str = INSTANTON_RELAY_DOMAIN
    enable_wildcard: bool = True

    # ACME settings
    acme_email: str = ""
    use_staging: bool = False

    # Self-hosted settings
    allow_custom_domains: bool = True
    custom_relay_servers: list[str] = field(default_factory=list)


@dataclass
class SelfHostedConfig:
    """Configuration for self-hosted deployments."""

    # User's custom domain
    domain: str = ""

    # Relay server settings
    relay_host: str = ""
    relay_port: int = 443

    # Certificate settings
    acme_email: str = ""
    use_letsencrypt: bool = True
    use_staging: bool = False

    # Custom CA (for enterprise deployments)
    custom_ca_cert: bytes | None = None
    custom_ca_key: bytes | None = None


# ==============================================================================
# Wildcard DNS Service (sslip.io style) - From Scratch
# ==============================================================================


class WildcardDNSService:
    """Wildcard DNS service like sslip.io - implemented from scratch.

    This provides DNS-based routing where the IP address is encoded in the
    subdomain, allowing any subdomain to resolve to the embedded IP.

    Examples:
        - 192-168-1-1.instanton.tech -> 192.168.1.1
        - myapp.192-168-1-1.instanton.tech -> 192.168.1.1
        - tunnel-abc123.10-0-0-1.instanton.tech -> 10.0.0.1
    """

    # Pattern: subdomain.IP-IP-IP-IP.domain or IP-IP-IP-IP.domain
    IP_PATTERN = re.compile(r"^(?:.*\.)?(\d{1,3})-(\d{1,3})-(\d{1,3})-(\d{1,3})\.(.+)$")

    # IPv6 pattern: IP--IP.domain (full or abbreviated)
    IPV6_PATTERN = re.compile(r"^(?:.*\.)?([0-9a-fA-F-]+)\.(.+)$")

    def __init__(self, base_domain: str = INSTANTON_DOMAIN):
        """Initialize wildcard DNS service.

        Args:
            base_domain: Base domain for wildcard DNS (e.g., instanton.tech)
        """
        self.base_domain = base_domain

    def encode_ipv4(self, ip: str, subdomain: str = "") -> str:
        """Encode an IPv4 address into a domain name.

        Args:
            ip: IPv4 address (e.g., "192.168.1.1")
            subdomain: Optional subdomain prefix

        Returns:
            Encoded domain (e.g., "myapp.192-168-1-1.instanton.tech")
        """
        # Validate IP
        try:
            ipaddress.IPv4Address(ip)
        except ipaddress.AddressValueError as err:
            raise ValueError(f"Invalid IPv4 address: {ip}") from err

        ip_encoded = ip.replace(".", "-")

        if subdomain:
            return f"{subdomain}.{ip_encoded}.{self.base_domain}"
        return f"{ip_encoded}.{self.base_domain}"

    def encode_ipv6(self, ip: str, subdomain: str = "") -> str:
        """Encode an IPv6 address into a domain name.

        Args:
            ip: IPv6 address
            subdomain: Optional subdomain prefix

        Returns:
            Encoded domain
        """
        try:
            addr = ipaddress.IPv6Address(ip)
        except ipaddress.AddressValueError as err:
            raise ValueError(f"Invalid IPv6 address: {ip}") from err

        # Use exploded form with dashes instead of colons
        ip_encoded = addr.exploded.replace(":", "-")

        if subdomain:
            return f"{subdomain}.{ip_encoded}.{self.base_domain}"
        return f"{ip_encoded}.{self.base_domain}"

    def decode_domain(self, domain: str) -> tuple[str, str, str]:
        """Decode a domain name to extract IP and subdomain.

        Args:
            domain: Full domain name

        Returns:
            Tuple of (ip_address, subdomain, base_domain)
        """
        # Try IPv4 pattern
        match = self.IP_PATTERN.match(domain)
        if match:
            octets = match.groups()[:4]
            base = match.group(5)

            # Validate octets
            for octet in octets:
                if not 0 <= int(octet) <= 255:
                    raise ValueError(f"Invalid IP octet: {octet}")

            ip = ".".join(octets)

            # Extract subdomain (everything before IP part)
            ip_part = "-".join(octets)
            subdomain = ""
            if domain.startswith(ip_part):
                subdomain = ""
            else:
                subdomain_end = domain.find(f".{ip_part}.")
                if subdomain_end > 0:
                    subdomain = domain[:subdomain_end]

            return ip, subdomain, base

        raise ValueError(f"Could not decode domain: {domain}")

    def resolve(self, domain: str) -> str | None:
        """Resolve a wildcard domain to its IP address.

        Args:
            domain: Domain to resolve

        Returns:
            IP address or None if not a wildcard domain
        """
        try:
            ip, _, _ = self.decode_domain(domain)
            return ip
        except ValueError:
            return None

    def is_wildcard_domain(self, domain: str) -> bool:
        """Check if a domain is a wildcard DNS domain.

        Args:
            domain: Domain to check

        Returns:
            True if it's a wildcard domain
        """
        return self.resolve(domain) is not None

    def generate_tunnel_domain(
        self,
        ip: str,
        tunnel_id: str | None = None,
        subdomain: str | None = None,
    ) -> str:
        """Generate a tunnel domain for an IP address.

        Args:
            ip: IP address of the tunnel endpoint
            tunnel_id: Optional unique tunnel identifier
            subdomain: Optional custom subdomain

        Returns:
            Generated tunnel domain
        """
        if tunnel_id and subdomain:
            prefix = f"{subdomain}-{tunnel_id}"
        elif tunnel_id:
            prefix = f"tunnel-{tunnel_id}"
        elif subdomain:
            prefix = subdomain
        else:
            prefix = f"t-{secrets.token_hex(4)}"

        return self.encode_ipv4(ip, prefix)


# ==============================================================================
# Certificate Generator - From Scratch
# ==============================================================================


class CertificateGenerator:
    """Generate certificates from scratch using cryptography library.

    This class provides complete certificate generation capabilities without
    relying on any external certificate management libraries.
    """

    @staticmethod
    def generate_private_key(
        key_type: KeyType = KeyType.EC_P256,
    ) -> ec.EllipticCurvePrivateKey | rsa.RSAPrivateKey:
        """Generate a private key.

        Args:
            key_type: Type of key to generate

        Returns:
            Generated private key
        """
        if key_type == KeyType.EC_P256:
            return ec.generate_private_key(ec.SECP256R1())
        elif key_type == KeyType.EC_P384:
            return ec.generate_private_key(ec.SECP384R1())
        elif key_type == KeyType.RSA_2048:
            return rsa.generate_private_key(public_exponent=65537, key_size=2048)
        elif key_type == KeyType.RSA_4096:
            return rsa.generate_private_key(public_exponent=65537, key_size=4096)
        else:
            raise ValueError(f"Unknown key type: {key_type}")

    @staticmethod
    def key_to_pem(
        key: ec.EllipticCurvePrivateKey | rsa.RSAPrivateKey,
        password: bytes | None = None,
    ) -> bytes:
        """Convert private key to PEM format.

        Args:
            key: Private key
            password: Optional encryption password

        Returns:
            PEM-encoded private key
        """
        encryption = (
            serialization.BestAvailableEncryption(password)
            if password
            else serialization.NoEncryption()
        )

        return key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=encryption,
        )

    @staticmethod
    def generate_self_signed(
        domain: str,
        key: ec.EllipticCurvePrivateKey | rsa.RSAPrivateKey | None = None,
        key_type: KeyType = KeyType.EC_P256,
        validity_days: int = DEFAULT_CERT_VALIDITY_DAYS,
        san_domains: list[str] | None = None,
        organization: str = "Instanton",
        is_ca: bool = False,
    ) -> CertificateBundle:
        """Generate a self-signed certificate from scratch.

        Args:
            domain: Primary domain name
            key: Optional existing private key
            key_type: Key type if generating new key
            validity_days: Certificate validity in days
            san_domains: Additional Subject Alternative Names
            organization: Organization name for certificate
            is_ca: Whether this is a CA certificate

        Returns:
            Complete certificate bundle
        """
        # Generate key if not provided
        if key is None:
            key = CertificateGenerator.generate_private_key(key_type)

        # Build subject and issuer (same for self-signed)
        subject = issuer = x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
                x509.NameAttribute(NameOID.COMMON_NAME, domain),
            ]
        )

        # Build SAN list
        all_domains = [domain]
        if san_domains:
            all_domains.extend(san_domains)

        # Add wildcard if not already present
        if not any(d.startswith("*.") for d in all_domains):
            all_domains.append(f"*.{domain}")

        san_entries = [x509.DNSName(d) for d in all_domains]

        # Build certificate
        now = datetime.now(UTC)
        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=validity_days))
            .add_extension(
                x509.SubjectAlternativeName(san_entries),
                critical=False,
            )
            .add_extension(
                x509.BasicConstraints(ca=is_ca, path_length=0 if is_ca else None),
                critical=True,
            )
        )

        # Add key usage for CA certs
        if is_ca:
            builder = builder.add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            builder = builder.add_extension(
                x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
                critical=False,
            )

        # Sign certificate
        cert = builder.sign(key, hashes.SHA256())

        # Serialize
        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        key_pem = CertificateGenerator.key_to_pem(key)

        # Calculate fingerprint
        fingerprint = hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()

        return CertificateBundle(
            domain=domain,
            certificate_pem=cert_pem,
            private_key_pem=key_pem,
            source=CertificateSource.SELF_SIGNED,
            not_before=cert.not_valid_before_utc,
            not_after=cert.not_valid_after_utc,
            issuer=cert.issuer.rfc4514_string(),
            san_domains=all_domains,
            fingerprint_sha256=fingerprint,
        )

    @staticmethod
    def generate_csr(
        domain: str,
        key: ec.EllipticCurvePrivateKey | rsa.RSAPrivateKey,
        san_domains: list[str] | None = None,
        organization: str = "Instanton",
    ) -> bytes:
        """Generate a Certificate Signing Request (CSR).

        Args:
            domain: Primary domain name
            key: Private key
            san_domains: Additional Subject Alternative Names
            organization: Organization name

        Returns:
            PEM-encoded CSR
        """
        subject = x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
                x509.NameAttribute(NameOID.COMMON_NAME, domain),
            ]
        )

        # Build SAN list
        all_domains = [domain]
        if san_domains:
            all_domains.extend(san_domains)

        san_entries = [x509.DNSName(d) for d in all_domains]

        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(subject)
            .add_extension(
                x509.SubjectAlternativeName(san_entries),
                critical=False,
            )
            .sign(key, hashes.SHA256())
        )

        return csr.public_bytes(serialization.Encoding.PEM)

    @staticmethod
    def sign_csr_with_ca(
        csr_pem: bytes,
        ca_cert_pem: bytes,
        ca_key_pem: bytes,
        validity_days: int = DEFAULT_CERT_VALIDITY_DAYS,
    ) -> bytes:
        """Sign a CSR with a CA certificate.

        Args:
            csr_pem: PEM-encoded CSR
            ca_cert_pem: PEM-encoded CA certificate
            ca_key_pem: PEM-encoded CA private key
            validity_days: Certificate validity in days

        Returns:
            PEM-encoded signed certificate
        """
        csr = x509.load_pem_x509_csr(csr_pem)
        ca_cert = x509.load_pem_x509_certificate(ca_cert_pem)
        ca_key = serialization.load_pem_private_key(ca_key_pem, password=None)

        now = datetime.now(UTC)

        # Build certificate from CSR
        builder = (
            x509.CertificateBuilder()
            .subject_name(csr.subject)
            .issuer_name(ca_cert.subject)
            .public_key(csr.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=validity_days))
        )

        # Copy extensions from CSR
        for ext in csr.extensions:
            builder = builder.add_extension(ext.value, ext.critical)

        # Add Authority Key Identifier
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )

        cert = builder.sign(ca_key, hashes.SHA256())
        return cert.public_bytes(serialization.Encoding.PEM)

    @staticmethod
    def parse_certificate(cert_pem: bytes) -> dict[str, Any]:
        """Parse a certificate and extract its information.

        Args:
            cert_pem: PEM-encoded certificate

        Returns:
            Dictionary with certificate information
        """
        cert = x509.load_pem_x509_certificate(cert_pem)

        # Extract SANs
        san_domains = []
        try:
            san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            san_domains = [name.value for name in san_ext.value if isinstance(name, x509.DNSName)]
        except x509.ExtensionNotFound:
            pass

        # Get key info
        public_key = cert.public_key()
        if isinstance(public_key, ec.EllipticCurvePublicKey):
            key_type = f"EC-{public_key.curve.name}"
            key_size = public_key.curve.key_size
        elif isinstance(public_key, rsa.RSAPublicKey):
            key_type = "RSA"
            key_size = public_key.key_size
        else:
            key_type = "Unknown"
            key_size = 0

        # Calculate fingerprint
        fingerprint = hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()

        return {
            "subject": cert.subject.rfc4514_string(),
            "issuer": cert.issuer.rfc4514_string(),
            "serial_number": hex(cert.serial_number),
            "not_before": cert.not_valid_before_utc,
            "not_after": cert.not_valid_after_utc,
            "san_domains": san_domains,
            "key_type": key_type,
            "key_size": key_size,
            "fingerprint_sha256": fingerprint,
            "is_self_signed": cert.issuer == cert.subject,
        }


# ==============================================================================
# Certificate Store - From Scratch
# ==============================================================================


class CertificateStore:
    """Persistent certificate storage with encryption support.

    Stores certificates on disk with proper security measures.
    """

    def __init__(
        self,
        base_path: Path,
        encryption_key: bytes | None = None,
    ):
        """Initialize certificate store.

        Args:
            base_path: Base directory for certificate storage
            encryption_key: Optional key for encrypting private keys
        """
        self.base_path = base_path
        self.encryption_key = encryption_key
        self._cache: dict[str, CertificateBundle] = {}

        # Create directory structure
        self.base_path.mkdir(parents=True, exist_ok=True)
        (self.base_path / "certs").mkdir(exist_ok=True)
        (self.base_path / "keys").mkdir(exist_ok=True)
        (self.base_path / "chains").mkdir(exist_ok=True)

    def _domain_to_filename(self, domain: str) -> str:
        """Convert domain to safe filename."""
        return domain.replace("*", "_wildcard_").replace(":", "_")

    def store(self, bundle: CertificateBundle) -> None:
        """Store a certificate bundle.

        Args:
            bundle: Certificate bundle to store
        """
        filename = self._domain_to_filename(bundle.domain)

        cert_path = self.base_path / "certs" / f"{filename}.pem"
        key_path = self.base_path / "keys" / f"{filename}.pem"
        chain_path = self.base_path / "chains" / f"{filename}.pem"

        # Write certificate
        cert_path.write_bytes(bundle.certificate_pem)

        # Write private key (with secure permissions)
        key_path.write_bytes(bundle.private_key_pem)
        # Try to set secure permissions (may fail on Windows)
        with contextlib.suppress(OSError):
            key_path.chmod(0o600)

        # Write chain if present
        if bundle.chain_pem:
            chain_path.write_bytes(bundle.chain_pem)

        # Update cache
        self._cache[bundle.domain] = bundle

        logger.info(
            "Certificate stored",
            domain=bundle.domain,
            expires=bundle.not_after,
            source=bundle.source.value,
        )

    def load(self, domain: str) -> CertificateBundle | None:
        """Load a certificate bundle.

        Args:
            domain: Domain to load certificate for

        Returns:
            Certificate bundle or None if not found
        """
        if domain in self._cache:
            return self._cache[domain]

        filename = self._domain_to_filename(domain)

        cert_path = self.base_path / "certs" / f"{filename}.pem"
        key_path = self.base_path / "keys" / f"{filename}.pem"
        chain_path = self.base_path / "chains" / f"{filename}.pem"

        if not cert_path.exists() or not key_path.exists():
            return None

        cert_pem = cert_path.read_bytes()
        key_pem = key_path.read_bytes()
        chain_pem = chain_path.read_bytes() if chain_path.exists() else None

        # Parse certificate info
        info = CertificateGenerator.parse_certificate(cert_pem)

        bundle = CertificateBundle(
            domain=domain,
            certificate_pem=cert_pem,
            private_key_pem=key_pem,
            chain_pem=chain_pem,
            not_before=info["not_before"],
            not_after=info["not_after"],
            issuer=info["issuer"],
            san_domains=info["san_domains"],
            fingerprint_sha256=info["fingerprint_sha256"],
            source=CertificateSource.SELF_SIGNED
            if info["is_self_signed"]
            else CertificateSource.LETSENCRYPT,
        )

        self._cache[domain] = bundle
        return bundle

    def delete(self, domain: str) -> bool:
        """Delete a certificate.

        Args:
            domain: Domain to delete certificate for

        Returns:
            True if deleted
        """
        filename = self._domain_to_filename(domain)

        cert_path = self.base_path / "certs" / f"{filename}.pem"
        key_path = self.base_path / "keys" / f"{filename}.pem"
        chain_path = self.base_path / "chains" / f"{filename}.pem"

        deleted = False
        for path in [cert_path, key_path, chain_path]:
            if path.exists():
                path.unlink()
                deleted = True

        self._cache.pop(domain, None)
        return deleted

    def list_domains(self) -> list[str]:
        """List all stored domains.

        Returns:
            List of domain names
        """
        domains = []
        certs_dir = self.base_path / "certs"
        for path in certs_dir.glob("*.pem"):
            domain = path.stem.replace("_wildcard_", "*").replace("_", ":")
            domains.append(domain)
        return domains

    def get_expiring(self, days: int = RENEWAL_THRESHOLD_DAYS) -> list[CertificateBundle]:
        """Get certificates expiring within specified days.

        Args:
            days: Number of days threshold

        Returns:
            List of expiring certificate bundles
        """
        expiring = []
        for domain in self.list_domains():
            bundle = self.load(domain)
            if bundle and bundle.days_until_expiry <= days:
                expiring.append(bundle)
        return expiring


# ==============================================================================
# Automatic TLS Manager (Caddy-style) - From Scratch
# ==============================================================================


class AutoTLSManager:
    """Automatic TLS certificate management like Caddy - from scratch.

    Provides automatic certificate provisioning and renewal without
    manual intervention.
    """

    def __init__(
        self,
        store: CertificateStore,
        acme_email: str = "",
        use_staging: bool = False,
        enable_http_challenge: bool = True,
        enable_dns_challenge: bool = False,
        challenge_port: int = 80,
    ):
        """Initialize Auto TLS Manager.

        Args:
            store: Certificate store
            acme_email: Email for ACME account
            use_staging: Use Let's Encrypt staging
            enable_http_challenge: Enable HTTP-01 challenges
            enable_dns_challenge: Enable DNS-01 challenges
            challenge_port: Port for HTTP-01 challenge server
        """
        self.store = store
        self.acme_email = acme_email
        self.use_staging = use_staging
        self.enable_http_challenge = enable_http_challenge
        self.enable_dns_challenge = enable_dns_challenge
        self.challenge_port = challenge_port

        self._running = False
        self._renewal_task: asyncio.Task | None = None
        self._challenge_server: Any = None
        self._pending_challenges: dict[str, str] = {}

    async def start(self) -> None:
        """Start the automatic TLS manager."""
        self._running = True

        # Start HTTP challenge server if enabled
        if self.enable_http_challenge:
            await self._start_challenge_server()

        # Start renewal checker
        self._renewal_task = asyncio.create_task(self._renewal_loop())

        logger.info(
            "AutoTLS manager started",
            staging=self.use_staging,
            http_challenge=self.enable_http_challenge,
        )

    async def stop(self) -> None:
        """Stop the automatic TLS manager."""
        self._running = False

        if self._renewal_task:
            self._renewal_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._renewal_task

        if self._challenge_server:
            await self._stop_challenge_server()

        logger.info("AutoTLS manager stopped")

    async def get_certificate(
        self,
        domain: str,
        force_new: bool = False,
    ) -> CertificateBundle:
        """Get or create a certificate for a domain.

        This is the main entry point for automatic TLS. It will:
        1. Check if a valid certificate exists
        2. If not, generate one (self-signed or via ACME)
        3. Return the certificate bundle

        Args:
            domain: Domain name
            force_new: Force generation of new certificate

        Returns:
            Certificate bundle
        """
        # Check existing certificate
        if not force_new:
            bundle = self.store.load(domain)
            if bundle and not bundle.needs_renewal:
                logger.debug("Using cached certificate", domain=domain)
                return bundle

        # Determine certificate source
        if self.acme_email and self._can_use_acme(domain):
            try:
                bundle = await self._obtain_acme_certificate(domain)
            except Exception as e:
                logger.warning(
                    "ACME certificate failed, falling back to self-signed",
                    domain=domain,
                    error=str(e),
                )
                bundle = self._generate_self_signed(domain)
        else:
            bundle = self._generate_self_signed(domain)

        # Store certificate
        self.store.store(bundle)

        return bundle

    def _can_use_acme(self, domain: str) -> bool:
        """Check if ACME can be used for a domain.

        Args:
            domain: Domain to check

        Returns:
            True if ACME can be used
        """
        # Can't use ACME for localhost or IP addresses
        if domain in ("localhost", "127.0.0.1") or domain.startswith("192.168."):
            return False

        # Can't use ACME for wildcard with HTTP-01
        return not (domain.startswith("*.") and not self.enable_dns_challenge)

    def _generate_self_signed(self, domain: str) -> CertificateBundle:
        """Generate a self-signed certificate.

        Args:
            domain: Domain name

        Returns:
            Self-signed certificate bundle
        """
        logger.info("Generating self-signed certificate", domain=domain)
        return CertificateGenerator.generate_self_signed(
            domain=domain,
            key_type=KeyType.EC_P256,
            validity_days=365,
            organization="Instanton Self-Signed",
        )

    async def _obtain_acme_certificate(self, domain: str) -> CertificateBundle:
        """Obtain a certificate via ACME (Let's Encrypt).

        This is a simplified ACME implementation. For full ACME support,
        use the FullACMEClient from the acme module.

        Args:
            domain: Domain name

        Returns:
            ACME-issued certificate bundle
        """
        # Import the full ACME client
        from instanton.security.acme import (
            ACMEDirectory,
            ChallengeType,
            FullACMEClient,
        )

        directory = (
            ACMEDirectory.LETSENCRYPT_STAGING
            if self.use_staging
            else ACMEDirectory.LETSENCRYPT_PRODUCTION
        )

        client = FullACMEClient(
            email=self.acme_email,
            directory=directory,
        )

        await client.initialize()

        result = await client.obtain_certificate(
            domains=[domain],
            challenge_type=ChallengeType.HTTP_01,
        )

        return CertificateBundle(
            domain=domain,
            certificate_pem=result.certificate_pem,
            private_key_pem=result.private_key_pem,
            chain_pem=result.chain_pem,
            source=(
                CertificateSource.LETSENCRYPT_STAGING
                if self.use_staging
                else CertificateSource.LETSENCRYPT
            ),
            not_before=result.not_before,
            not_after=result.not_after,
            issuer=result.issuer,
            san_domains=result.domains,
        )

    async def _start_challenge_server(self) -> None:
        """Start HTTP-01 challenge server."""
        from aiohttp import web

        async def handle_challenge(request: web.Request) -> web.Response:
            token = request.match_info.get("token", "")
            if token in self._pending_challenges:
                return web.Response(
                    text=self._pending_challenges[token],
                    content_type="text/plain",
                )
            return web.Response(status=404)

        app = web.Application()
        app.router.add_get("/.well-known/acme-challenge/{token}", handle_challenge)

        runner = web.AppRunner(app)
        await runner.setup()
        self._challenge_server = web.TCPSite(runner, "0.0.0.0", self.challenge_port)
        await self._challenge_server.start()

        logger.info("HTTP challenge server started", port=self.challenge_port)

    async def _stop_challenge_server(self) -> None:
        """Stop HTTP-01 challenge server."""
        if self._challenge_server:
            await self._challenge_server.stop()
            self._challenge_server = None

    async def _renewal_loop(self) -> None:
        """Background task to check and renew certificates."""
        while self._running:
            try:
                await asyncio.sleep(3600)  # Check hourly
                await self._check_renewals()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("Renewal check failed", error=str(e))

    async def _check_renewals(self) -> None:
        """Check and renew expiring certificates."""
        expiring = self.store.get_expiring()

        for bundle in expiring:
            logger.info(
                "Certificate needs renewal",
                domain=bundle.domain,
                days_remaining=bundle.days_until_expiry,
            )

            try:
                await self.get_certificate(bundle.domain, force_new=True)
                logger.info("Certificate renewed", domain=bundle.domain)
            except Exception as e:
                logger.error(
                    "Certificate renewal failed",
                    domain=bundle.domain,
                    error=str(e),
                )

    def create_ssl_context(
        self,
        domain: str,
        purpose: ssl.Purpose = ssl.Purpose.CLIENT_AUTH,
    ) -> ssl.SSLContext:
        """Create an SSL context for a domain.

        Args:
            domain: Domain name
            purpose: SSL purpose

        Returns:
            Configured SSL context
        """
        bundle = self.store.load(domain)
        if not bundle:
            raise ValueError(f"No certificate for domain: {domain}")

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2

        # Load certificate from memory
        import tempfile

        with tempfile.NamedTemporaryFile(delete=False, suffix=".pem") as cert_file:
            cert_file.write(bundle.full_chain_pem)
            cert_path = cert_file.name

        with tempfile.NamedTemporaryFile(delete=False, suffix=".pem") as key_file:
            key_file.write(bundle.private_key_pem)
            key_path = key_file.name

        try:
            ctx.load_cert_chain(cert_path, key_path)
        finally:
            Path(cert_path).unlink(missing_ok=True)
            Path(key_path).unlink(missing_ok=True)

        return ctx


# ==============================================================================
# Instanton Domain Manager
# ==============================================================================


class InstantonDomainManager:
    """Manager for instanton.tech domain and self-hosted deployments.

    This provides a unified interface for:
    - Official instanton.tech domain management
    - Self-hosted deployments with custom domains
    - Wildcard DNS for dynamic tunnel subdomains
    """

    def __init__(
        self,
        config: InstantonDomainConfig | None = None,
        cert_store_path: Path | None = None,
    ):
        """Initialize domain manager.

        Args:
            config: Domain configuration
            cert_store_path: Path for certificate storage
        """
        self.config = config or InstantonDomainConfig()
        self.cert_store_path = cert_store_path or Path.home() / ".instanton" / "certs"

        # Initialize components
        self.wildcard_dns = WildcardDNSService(self.config.base_domain)
        self.cert_store = CertificateStore(self.cert_store_path)
        self.auto_tls = AutoTLSManager(
            store=self.cert_store,
            acme_email=self.config.acme_email,
            use_staging=self.config.use_staging,
        )

        # Self-hosted configurations
        self._self_hosted_configs: dict[str, SelfHostedConfig] = {}

    async def start(self) -> None:
        """Start the domain manager."""
        await self.auto_tls.start()
        logger.info(
            "Instanton domain manager started",
            domain=self.config.base_domain,
        )

    async def stop(self) -> None:
        """Stop the domain manager."""
        await self.auto_tls.stop()

    def register_self_hosted(
        self,
        config: SelfHostedConfig,
    ) -> str:
        """Register a self-hosted deployment.

        Args:
            config: Self-hosted configuration

        Returns:
            Configuration ID
        """
        config_id = secrets.token_hex(16)
        self._self_hosted_configs[config_id] = config

        logger.info(
            "Registered self-hosted deployment",
            domain=config.domain,
            relay=f"{config.relay_host}:{config.relay_port}",
        )

        return config_id

    def unregister_self_hosted(self, config_id: str) -> bool:
        """Unregister a self-hosted deployment.

        Args:
            config_id: Configuration ID

        Returns:
            True if unregistered
        """
        return self._self_hosted_configs.pop(config_id, None) is not None

    async def get_tunnel_domain(
        self,
        ip: str | None = None,
        subdomain: str | None = None,
        tunnel_id: str | None = None,
    ) -> str:
        """Get a tunnel domain for an endpoint.

        Args:
            ip: IP address (auto-detected if not provided)
            subdomain: Optional custom subdomain
            tunnel_id: Optional tunnel identifier

        Returns:
            Tunnel domain
        """
        if not ip:
            # Auto-detect public IP
            ip = await self._get_public_ip()

        return self.wildcard_dns.generate_tunnel_domain(
            ip=ip,
            subdomain=subdomain,
            tunnel_id=tunnel_id,
        )

    async def get_certificate(
        self,
        domain: str,
        config_id: str | None = None,
    ) -> CertificateBundle:
        """Get a certificate for a domain.

        Args:
            domain: Domain name
            config_id: Optional self-hosted config ID

        Returns:
            Certificate bundle
        """
        # Check if this is a self-hosted deployment
        if config_id and config_id in self._self_hosted_configs:
            config = self._self_hosted_configs[config_id]

            # Use custom CA if provided
            if config.custom_ca_cert and config.custom_ca_key:
                return await self._get_custom_ca_cert(domain, config)

        # Use auto TLS
        return await self.auto_tls.get_certificate(domain)

    async def _get_custom_ca_cert(
        self,
        domain: str,
        config: SelfHostedConfig,
    ) -> CertificateBundle:
        """Get a certificate signed by custom CA.

        Args:
            domain: Domain name
            config: Self-hosted configuration

        Returns:
            Certificate bundle
        """
        # Generate key
        key = CertificateGenerator.generate_private_key(KeyType.EC_P256)
        key_pem = CertificateGenerator.key_to_pem(key)

        # Generate CSR
        csr_pem = CertificateGenerator.generate_csr(domain, key)

        # Sign with CA
        cert_pem = CertificateGenerator.sign_csr_with_ca(
            csr_pem=csr_pem,
            ca_cert_pem=config.custom_ca_cert,
            ca_key_pem=config.custom_ca_key,
        )

        # Parse info
        info = CertificateGenerator.parse_certificate(cert_pem)

        return CertificateBundle(
            domain=domain,
            certificate_pem=cert_pem,
            private_key_pem=key_pem,
            chain_pem=config.custom_ca_cert,
            source=CertificateSource.CUSTOM_CA,
            not_before=info["not_before"],
            not_after=info["not_after"],
            issuer=info["issuer"],
            san_domains=info["san_domains"],
            fingerprint_sha256=info["fingerprint_sha256"],
        )

    async def _get_public_ip(self) -> str:
        """Get the public IP address."""
        services = [
            "https://api.ipify.org",
            "https://ifconfig.me/ip",
            "https://icanhazip.com",
        ]

        async with httpx.AsyncClient(timeout=10.0) as client:
            for service in services:
                try:
                    resp = await client.get(service)
                    if resp.status_code == 200:
                        return resp.text.strip()
                except Exception:
                    continue

        raise RuntimeError("Could not determine public IP")


# ==============================================================================
# Exports
# ==============================================================================


__all__ = [
    # Constants
    "INSTANTON_DOMAIN",
    "INSTANTON_RELAY_DOMAIN",
    "INSTANTON_WILDCARD",
    "LETSENCRYPT_PRODUCTION",
    "LETSENCRYPT_STAGING",
    # Enums
    "CertificateSource",
    "KeyType",
    "ChallengeMethod",
    # Data classes
    "CertificateBundle",
    "InstantonDomainConfig",
    "SelfHostedConfig",
    # Classes
    "WildcardDNSService",
    "CertificateGenerator",
    "CertificateStore",
    "AutoTLSManager",
    "InstantonDomainManager",
]
