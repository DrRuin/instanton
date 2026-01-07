"""Certificate management with ACME/Let's Encrypt support."""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import ssl
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import structlog
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

logger = structlog.get_logger()


@dataclass
class CertificateInfo:
    """Information about a certificate."""

    domain: str
    not_before: datetime
    not_after: datetime
    issuer: str
    subject: str
    serial_number: str
    fingerprint_sha256: str
    san_domains: list[str] = field(default_factory=list)
    is_self_signed: bool = False
    key_type: str = "RSA"
    key_size: int = 2048

    @property
    def is_expired(self) -> bool:
        """Check if certificate is expired."""
        return datetime.now(UTC) > self.not_after

    @property
    def days_until_expiry(self) -> int:
        """Days until certificate expires."""
        delta = self.not_after - datetime.now(UTC)
        return max(0, delta.days)

    @property
    def needs_renewal(self) -> bool:
        """Check if certificate needs renewal (< 30 days)."""
        return self.days_until_expiry < 30


class CertificateStore:
    """Stores and manages certificates on disk."""

    def __init__(self, base_path: Path) -> None:
        self.base_path = base_path
        self.base_path.mkdir(parents=True, exist_ok=True)
        self._cache: dict[str, tuple[bytes, bytes]] = {}

    def _domain_path(self, domain: str) -> Path:
        """Get path for a domain's certificates."""
        safe_domain = domain.replace("*", "_wildcard_")
        return self.base_path / safe_domain

    def store(
        self,
        domain: str,
        cert_pem: bytes,
        key_pem: bytes,
        chain_pem: bytes | None = None,
    ) -> None:
        """Store certificate and key for a domain."""
        domain_path = self._domain_path(domain)
        domain_path.mkdir(parents=True, exist_ok=True)

        cert_path = domain_path / "cert.pem"
        key_path = domain_path / "key.pem"

        # Write certificate (with chain if provided)
        full_cert = cert_pem
        if chain_pem:
            full_cert = cert_pem + b"\n" + chain_pem

        cert_path.write_bytes(full_cert)
        key_path.write_bytes(key_pem)

        # Secure permissions on key file
        key_path.chmod(0o600)

        # Update cache
        self._cache[domain] = (full_cert, key_pem)

        logger.info("Certificate stored", domain=domain, path=str(domain_path))

    def load(self, domain: str) -> tuple[bytes, bytes] | None:
        """Load certificate and key for a domain."""
        if domain in self._cache:
            return self._cache[domain]

        domain_path = self._domain_path(domain)
        cert_path = domain_path / "cert.pem"
        key_path = domain_path / "key.pem"

        if not cert_path.exists() or not key_path.exists():
            return None

        cert_pem = cert_path.read_bytes()
        key_pem = key_path.read_bytes()

        self._cache[domain] = (cert_pem, key_pem)
        return cert_pem, key_pem

    def get_info(self, domain: str) -> CertificateInfo | None:
        """Get certificate info for a domain."""
        data = self.load(domain)
        if not data:
            return None

        cert_pem, _ = data
        return parse_certificate_info(cert_pem, domain)

    def list_domains(self) -> list[str]:
        """List all domains with stored certificates."""
        domains = []
        for path in self.base_path.iterdir():
            if path.is_dir() and (path / "cert.pem").exists():
                domain = path.name.replace("_wildcard_", "*")
                domains.append(domain)
        return domains

    def delete(self, domain: str) -> bool:
        """Delete certificate for a domain."""
        domain_path = self._domain_path(domain)
        if not domain_path.exists():
            return False

        import shutil

        shutil.rmtree(domain_path)
        self._cache.pop(domain, None)
        logger.info("Certificate deleted", domain=domain)
        return True


def parse_certificate_info(cert_pem: bytes, domain: str) -> CertificateInfo:
    """Parse certificate PEM and extract info."""
    cert = x509.load_pem_x509_certificate(cert_pem)

    # Extract SAN domains
    san_domains = []
    try:
        san_ext = cert.extensions.get_extension_for_oid(
            x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        )
        san_domains = [name.value for name in san_ext.value if isinstance(name, x509.DNSName)]
    except x509.ExtensionNotFound:
        pass

    # Determine key type and size
    public_key = cert.public_key()
    if isinstance(public_key, rsa.RSAPublicKey):
        key_type = "RSA"
        key_size = public_key.key_size
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        key_type = "EC"
        key_size = public_key.curve.key_size
    else:
        key_type = "Unknown"
        key_size = 0

    # Check if self-signed
    is_self_signed = cert.issuer == cert.subject

    # Calculate fingerprint
    fingerprint = hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()

    return CertificateInfo(
        domain=domain,
        not_before=cert.not_valid_before_utc,
        not_after=cert.not_valid_after_utc,
        issuer=cert.issuer.rfc4514_string(),
        subject=cert.subject.rfc4514_string(),
        serial_number=format(cert.serial_number, "x"),
        fingerprint_sha256=fingerprint,
        san_domains=san_domains,
        is_self_signed=is_self_signed,
        key_type=key_type,
        key_size=key_size,
    )


def generate_self_signed_cert(
    domain: str,
    days_valid: int = 365,
    key_type: str = "EC",
    key_size: int = 256,
) -> tuple[bytes, bytes]:
    """Generate a self-signed certificate for development.

    Args:
        domain: Domain name for the certificate
        days_valid: Number of days the certificate is valid
        key_type: Key type - "RSA" or "EC"
        key_size: Key size (2048/4096 for RSA, 256/384 for EC)

    Returns:
        Tuple of (cert_pem, key_pem)
    """
    # Generate private key
    if key_type == "EC":
        if key_size == 256:
            curve = ec.SECP256R1()
        elif key_size == 384:
            curve = ec.SECP384R1()
        else:
            curve = ec.SECP256R1()
        private_key = ec.generate_private_key(curve)
    else:
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
        )

    # Generate certificate
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Instanton Dev"),
            x509.NameAttribute(NameOID.COMMON_NAME, domain),
        ]
    )

    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=days_valid))
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName(domain),
                    x509.DNSName(f"*.{domain}"),
                ]
            ),
            critical=False,
        )
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .sign(private_key, hashes.SHA256())
    )

    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )

    logger.info(
        "Generated self-signed certificate",
        domain=domain,
        key_type=key_type,
        days_valid=days_valid,
    )

    return cert_pem, key_pem


class ACMEClient:
    """ACME client for Let's Encrypt certificate automation."""

    LETSENCRYPT_STAGING = "https://acme-staging-v02.api.letsencrypt.org/directory"
    LETSENCRYPT_PRODUCTION = "https://acme-v02.api.letsencrypt.org/directory"

    def __init__(
        self,
        email: str,
        staging: bool = False,
        account_key_path: Path | None = None,
    ) -> None:
        self.email = email
        self.directory_url = self.LETSENCRYPT_STAGING if staging else self.LETSENCRYPT_PRODUCTION
        self.account_key_path = account_key_path
        self._account_key: ec.EllipticCurvePrivateKey | None = None
        self._account_url: str | None = None
        self._directory: dict[str, Any] = {}
        self._nonce: str | None = None

    async def initialize(self) -> None:
        """Initialize ACME client - fetch directory and register account."""
        import httpx

        async with httpx.AsyncClient() as client:
            # Fetch directory
            resp = await client.get(self.directory_url)
            self._directory = resp.json()

            # Load or generate account key
            if self.account_key_path and self.account_key_path.exists():
                key_pem = self.account_key_path.read_bytes()
                self._account_key = serialization.load_pem_private_key(key_pem, password=None)
            else:
                self._account_key = ec.generate_private_key(ec.SECP256R1())
                if self.account_key_path:
                    key_pem = self._account_key.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.TraditionalOpenSSL,
                        encryption_algorithm=serialization.NoEncryption(),
                    )
                    self.account_key_path.parent.mkdir(parents=True, exist_ok=True)
                    self.account_key_path.write_bytes(key_pem)
                    self.account_key_path.chmod(0o600)

            # Get initial nonce
            resp = await client.head(self._directory["newNonce"])
            self._nonce = resp.headers["Replay-Nonce"]

        logger.info("ACME client initialized", directory=self.directory_url)

    async def obtain_certificate(
        self,
        domains: list[str],
        challenge_callback: Any = None,
    ) -> tuple[bytes, bytes, bytes]:
        """Obtain a certificate for the given domains.

        Args:
            domains: List of domains to include in certificate
            challenge_callback: Async callback(domain, token, key_auth) for HTTP-01 challenge

        Returns:
            Tuple of (cert_pem, key_pem, chain_pem)

        Note: This is a simplified implementation. For production use,
        consider using an established ACME library like acme or certbot.
        """
        # For a full implementation, you would:
        # 1. Create an order for the domains
        # 2. Get authorizations for each domain
        # 3. Complete HTTP-01 or DNS-01 challenges
        # 4. Finalize the order with a CSR
        # 5. Download the certificate

        # This is a placeholder - actual ACME implementation requires
        # proper JWS signing and challenge handling
        raise NotImplementedError(
            "Full ACME implementation pending. "
            "Use generate_self_signed_cert() for development or "
            "provide pre-existing certificates."
        )


class CertificateManager:
    """Manages certificates with automatic renewal."""

    def __init__(
        self,
        store: CertificateStore,
        acme_client: ACMEClient | None = None,
        renewal_days: int = 30,
    ) -> None:
        self.store = store
        self.acme_client = acme_client
        self.renewal_days = renewal_days
        self._renewal_task: asyncio.Task | None = None
        self._ssl_contexts: dict[str, ssl.SSLContext] = {}

    async def start(self) -> None:
        """Start the certificate manager."""
        if self.acme_client:
            await self.acme_client.initialize()

        # Start renewal check task
        self._renewal_task = asyncio.create_task(self._renewal_loop())
        logger.info("Certificate manager started")

    async def stop(self) -> None:
        """Stop the certificate manager."""
        if self._renewal_task:
            self._renewal_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._renewal_task
        logger.info("Certificate manager stopped")

    async def _renewal_loop(self) -> None:
        """Periodically check for certificates needing renewal."""
        while True:
            try:
                await asyncio.sleep(3600)  # Check hourly
                await self._check_renewals()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("Renewal check failed", error=str(e))

    async def _check_renewals(self) -> None:
        """Check all certificates for renewal needs."""
        for domain in self.store.list_domains():
            info = self.store.get_info(domain)
            if info and info.needs_renewal:
                logger.info(
                    "Certificate needs renewal",
                    domain=domain,
                    days_remaining=info.days_until_expiry,
                )
                # Trigger renewal if ACME is configured
                if self.acme_client:
                    try:
                        await self.renew_certificate(domain)
                    except Exception as e:
                        logger.error("Renewal failed", domain=domain, error=str(e))

    async def renew_certificate(self, domain: str) -> bool:
        """Renew certificate for a domain."""
        if not self.acme_client:
            logger.warning("No ACME client configured for renewal")
            return False

        try:
            cert_pem, key_pem, chain_pem = await self.acme_client.obtain_certificate([domain])
            self.store.store(domain, cert_pem, key_pem, chain_pem)

            # Invalidate cached SSL context
            self._ssl_contexts.pop(domain, None)

            logger.info("Certificate renewed", domain=domain)
            return True
        except Exception as e:
            logger.error("Certificate renewal failed", domain=domain, error=str(e))
            return False

    def get_ssl_context(
        self,
        domain: str,
        purpose: ssl.Purpose = ssl.Purpose.CLIENT_AUTH,
    ) -> ssl.SSLContext | None:
        """Get SSL context for a domain."""
        if domain in self._ssl_contexts:
            return self._ssl_contexts[domain]

        data = self.store.load(domain)
        if not data:
            return None

        cert_pem, key_pem = data

        # Create SSL context
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2

        # Set modern cipher suites
        ctx.set_ciphers("ECDHE+AESGCM:DHE+AESGCM:ECDHE+CHACHA20:DHE+CHACHA20")

        # Load certificate and key from memory
        import tempfile

        with tempfile.NamedTemporaryFile(delete=False, suffix=".pem") as cert_file:
            cert_file.write(cert_pem)
            cert_path = cert_file.name

        with tempfile.NamedTemporaryFile(delete=False, suffix=".pem") as key_file:
            key_file.write(key_pem)
            key_path = key_file.name

        try:
            ctx.load_cert_chain(cert_path, key_path)
        finally:
            Path(cert_path).unlink(missing_ok=True)
            Path(key_path).unlink(missing_ok=True)

        self._ssl_contexts[domain] = ctx
        return ctx

    def ensure_certificate(
        self,
        domain: str,
        generate_self_signed: bool = True,
    ) -> tuple[bytes, bytes]:
        """Ensure a certificate exists for domain, creating if needed."""
        data = self.store.load(domain)
        if data:
            info = self.store.get_info(domain)
            if info and not info.is_expired:
                return data

        if not generate_self_signed:
            raise ValueError(f"No valid certificate for {domain}")

        # Generate self-signed certificate
        cert_pem, key_pem = generate_self_signed_cert(domain)
        self.store.store(domain, cert_pem, key_pem)

        logger.info("Generated certificate for domain", domain=domain)
        return cert_pem, key_pem
