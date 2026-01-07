"""TLS Hardening for Instanton Tunnel Application.

This module provides comprehensive TLS security including:
- Modern cipher suite configuration (TLS 1.2+, AEAD only)
- Certificate validation
- OCSP stapling support
- Certificate pinning support
- Perfect Forward Secrecy enforcement
"""

from __future__ import annotations

import contextlib
import hashlib
import ssl
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path
from typing import Any

import structlog
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtensionOID

logger = structlog.get_logger()


# ==============================================================================
# TLS Configuration
# ==============================================================================


class TLSVersion(Enum):
    """Supported TLS versions."""

    TLS_1_2 = "TLSv1.2"
    TLS_1_3 = "TLSv1.3"


class CipherStrength(Enum):
    """Cipher suite strength categories."""

    HIGH = "high"  # Only strongest ciphers
    MEDIUM = "medium"  # Good security with broader compatibility
    COMPATIBLE = "compatible"  # Maximum compatibility


@dataclass
class TLSConfig:
    """TLS hardening configuration."""

    # Minimum TLS version (1.2 is the minimum recommended)
    minimum_version: TLSVersion = TLSVersion.TLS_1_2

    # Cipher strength
    cipher_strength: CipherStrength = CipherStrength.HIGH

    # Certificate paths
    cert_path: Path | None = None
    key_path: Path | None = None
    ca_path: Path | None = None

    # Certificate validation
    verify_client: bool = False
    verify_depth: int = 4

    # OCSP stapling
    enable_ocsp_stapling: bool = True
    ocsp_timeout: float = 5.0

    # Certificate pinning
    pinned_certificates: list[str] = field(default_factory=list)  # SHA256 hashes
    pinned_public_keys: list[str] = field(default_factory=list)  # SPKI SHA256 hashes

    # Session settings
    session_timeout: int = 300
    session_cache_size: int = 1024

    # ALPN protocols
    alpn_protocols: list[str] = field(default_factory=lambda: ["h2", "http/1.1"])

    # Hostname verification
    check_hostname: bool = True

    # Enforce Perfect Forward Secrecy
    require_pfs: bool = True


# ==============================================================================
# Modern Cipher Suites
# ==============================================================================


class CipherSuites:
    """Modern cipher suite configurations.

    Based on Mozilla SSL Configuration Generator recommendations.
    https://ssl-config.mozilla.org/
    """

    # TLS 1.3 ciphersuites (all provide AEAD and PFS)
    TLS13_CIPHERS = [
        "TLS_AES_256_GCM_SHA384",
        "TLS_CHACHA20_POLY1305_SHA256",
        "TLS_AES_128_GCM_SHA256",
    ]

    # TLS 1.2 ciphersuites - HIGH security (AEAD only with PFS)
    TLS12_HIGH_CIPHERS = [
        "ECDHE-ECDSA-AES256-GCM-SHA384",
        "ECDHE-RSA-AES256-GCM-SHA384",
        "ECDHE-ECDSA-CHACHA20-POLY1305",
        "ECDHE-RSA-CHACHA20-POLY1305",
        "ECDHE-ECDSA-AES128-GCM-SHA256",
        "ECDHE-RSA-AES128-GCM-SHA256",
    ]

    # TLS 1.2 ciphersuites - MEDIUM security (includes some non-AEAD with PFS)
    TLS12_MEDIUM_CIPHERS = TLS12_HIGH_CIPHERS + [
        "ECDHE-ECDSA-AES256-SHA384",
        "ECDHE-RSA-AES256-SHA384",
        "ECDHE-ECDSA-AES128-SHA256",
        "ECDHE-RSA-AES128-SHA256",
    ]

    # TLS 1.2 ciphersuites - Compatible (broader support, still PFS)
    TLS12_COMPATIBLE_CIPHERS = TLS12_MEDIUM_CIPHERS + [
        "DHE-RSA-AES256-GCM-SHA384",
        "DHE-RSA-AES128-GCM-SHA256",
        "DHE-RSA-AES256-SHA256",
        "DHE-RSA-AES128-SHA256",
    ]

    # Ciphers to explicitly disable
    DISABLED_CIPHERS = [
        "!aNULL",  # No authentication
        "!eNULL",  # No encryption
        "!EXPORT",  # Export ciphers
        "!DES",  # DES
        "!3DES",  # Triple DES
        "!RC4",  # RC4
        "!MD5",  # MD5
        "!PSK",  # Pre-shared key
        "!SRP",  # Secure Remote Password
        "!CAMELLIA",  # Camellia
        "!ARIA",  # ARIA
        "!SEED",  # SEED
        "!IDEA",  # IDEA
        "!DSS",  # DSS
    ]

    @classmethod
    def get_cipher_string(cls, strength: CipherStrength) -> str:
        """Get OpenSSL cipher string for given strength level."""
        if strength == CipherStrength.HIGH:
            ciphers = cls.TLS12_HIGH_CIPHERS
        elif strength == CipherStrength.MEDIUM:
            ciphers = cls.TLS12_MEDIUM_CIPHERS
        else:
            ciphers = cls.TLS12_COMPATIBLE_CIPHERS

        # Combine with disabled ciphers
        cipher_parts = ciphers + cls.DISABLED_CIPHERS
        return ":".join(cipher_parts)

    @classmethod
    def get_tls13_ciphers(cls) -> str:
        """Get TLS 1.3 ciphersuites string."""
        return ":".join(cls.TLS13_CIPHERS)


# ==============================================================================
# Elliptic Curve Configuration
# ==============================================================================


class ECCurves:
    """Elliptic curve configuration for ECDHE key exchange."""

    # Recommended curves in order of preference
    RECOMMENDED_CURVES = [
        "X25519",  # Curve25519 - fastest and most secure
        "secp384r1",  # P-384 - NIST curve
        "secp256r1",  # P-256 - NIST curve
    ]

    @classmethod
    def get_curves_string(cls) -> str:
        """Get curves configuration string."""
        return ":".join(cls.RECOMMENDED_CURVES)


# ==============================================================================
# Certificate Validation
# ==============================================================================


@dataclass
class CertificateInfo:
    """Certificate information extracted from X.509 certificate."""

    subject: dict[str, str]
    issuer: dict[str, str]
    serial_number: int
    not_before: datetime
    not_after: datetime
    fingerprint_sha256: str
    spki_hash: str  # Subject Public Key Info hash for pinning
    san_dns: list[str]
    san_ips: list[str]
    is_ca: bool
    key_usage: list[str]
    extended_key_usage: list[str]
    ocsp_responders: list[str]
    crl_distribution_points: list[str]


class CertificateValidator:
    """Validates X.509 certificates."""

    def __init__(self, config: TLSConfig | None = None):
        self.config = config or TLSConfig()

    def load_certificate(self, cert_path: Path) -> x509.Certificate:
        """Load certificate from file."""
        cert_data = cert_path.read_bytes()

        # Try PEM first, then DER
        try:
            return x509.load_pem_x509_certificate(cert_data)
        except Exception:
            return x509.load_der_x509_certificate(cert_data)

    def get_certificate_info(self, cert: x509.Certificate) -> CertificateInfo:
        """Extract information from certificate."""
        # Extract subject
        subject = {}
        for attr in cert.subject:
            subject[attr.oid._name] = attr.value

        # Extract issuer
        issuer = {}
        for attr in cert.issuer:
            issuer[attr.oid._name] = attr.value

        # Calculate fingerprints
        fingerprint_sha256 = cert.fingerprint(hashes.SHA256()).hex()

        # Calculate SPKI hash for pinning
        public_key_der = cert.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        spki_hash = hashlib.sha256(public_key_der).hexdigest()

        # Extract SANs
        san_dns: list[str] = []
        san_ips: list[str] = []
        try:
            san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            for name in san_ext.value:
                if isinstance(name, x509.DNSName):
                    san_dns.append(name.value)
                elif isinstance(name, x509.IPAddress):
                    san_ips.append(str(name.value))
        except x509.ExtensionNotFound:
            pass

        # Check if CA
        is_ca = False
        try:
            basic_constraints = cert.extensions.get_extension_for_oid(
                ExtensionOID.BASIC_CONSTRAINTS
            )
            is_ca = basic_constraints.value.ca
        except x509.ExtensionNotFound:
            pass

        # Key usage
        key_usage: list[str] = []
        try:
            ku_ext = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE)
            ku = ku_ext.value
            if ku.digital_signature:
                key_usage.append("digital_signature")
            if ku.key_encipherment:
                key_usage.append("key_encipherment")
            if ku.key_agreement:
                key_usage.append("key_agreement")
            if ku.key_cert_sign:
                key_usage.append("key_cert_sign")
            if ku.crl_sign:
                key_usage.append("crl_sign")
        except (x509.ExtensionNotFound, AttributeError):
            pass

        # Extended key usage
        extended_key_usage: list[str] = []
        try:
            eku_ext = cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE)
            for eku in eku_ext.value:
                extended_key_usage.append(eku._name)
        except x509.ExtensionNotFound:
            pass

        # OCSP responders
        ocsp_responders: list[str] = []
        try:
            aia = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS)
            for desc in aia.value:
                if desc.access_method == x509.oid.AuthorityInformationAccessOID.OCSP and isinstance(
                    desc.access_location, x509.UniformResourceIdentifier
                ):
                    ocsp_responders.append(desc.access_location.value)
        except x509.ExtensionNotFound:
            pass

        # CRL distribution points
        crl_distribution_points: list[str] = []
        try:
            cdp = cert.extensions.get_extension_for_oid(ExtensionOID.CRL_DISTRIBUTION_POINTS)
            for dp in cdp.value:
                if dp.full_name:
                    for name in dp.full_name:
                        if isinstance(name, x509.UniformResourceIdentifier):
                            crl_distribution_points.append(name.value)
        except x509.ExtensionNotFound:
            pass

        return CertificateInfo(
            subject=subject,
            issuer=issuer,
            serial_number=cert.serial_number,
            not_before=cert.not_valid_before_utc,
            not_after=cert.not_valid_after_utc,
            fingerprint_sha256=fingerprint_sha256,
            spki_hash=spki_hash,
            san_dns=san_dns,
            san_ips=san_ips,
            is_ca=is_ca,
            key_usage=key_usage,
            extended_key_usage=extended_key_usage,
            ocsp_responders=ocsp_responders,
            crl_distribution_points=crl_distribution_points,
        )

    def validate_certificate(
        self, cert: x509.Certificate, hostname: str | None = None
    ) -> tuple[bool, list[str]]:
        """Validate certificate and return (valid, errors)."""
        errors: list[str] = []
        now = datetime.now(UTC)

        info = self.get_certificate_info(cert)

        # Check validity period
        if now < info.not_before:
            errors.append(f"Certificate not yet valid (valid from {info.not_before})")

        if now > info.not_after:
            errors.append(f"Certificate has expired (expired on {info.not_after})")

        # Check hostname if provided
        if hostname and not self._check_hostname(hostname, info):
            errors.append(f"Hostname '{hostname}' does not match certificate")

        # Check key size
        key_size_error = self._check_key_size(cert)
        if key_size_error:
            errors.append(key_size_error)

        # Check if certificate is pinned
        if (
            self.config.pinned_certificates
            and info.fingerprint_sha256 not in self.config.pinned_certificates
        ):
            errors.append("Certificate fingerprint not in pinned certificates")

        if self.config.pinned_public_keys and info.spki_hash not in self.config.pinned_public_keys:
            errors.append("Public key not in pinned public keys")

        return len(errors) == 0, errors

    def _check_hostname(self, hostname: str, info: CertificateInfo) -> bool:
        """Check if hostname matches certificate."""
        hostname_lower = hostname.lower()

        # Check exact match in SANs
        for san in info.san_dns:
            if self._match_hostname(hostname_lower, san.lower()):
                return True

        # Check Common Name as fallback
        cn = info.subject.get("commonName", "")
        return bool(cn and self._match_hostname(hostname_lower, cn.lower()))

    def _match_hostname(self, hostname: str, pattern: str) -> bool:
        """Match hostname against pattern (supports wildcards)."""
        if pattern.startswith("*."):
            # Wildcard - matches any subdomain at the leftmost level
            suffix = pattern[2:]
            if hostname == suffix:
                return False  # *.example.com doesn't match example.com
            return hostname.endswith("." + suffix) and "." not in hostname[: -len(suffix) - 1]
        return hostname == pattern

    def _check_key_size(self, cert: x509.Certificate) -> str | None:
        """Check if key size meets minimum requirements."""
        public_key = cert.public_key()

        if isinstance(public_key, rsa.RSAPublicKey):
            key_size = public_key.key_size
            if key_size < 2048:
                return f"RSA key size {key_size} is below minimum (2048)"
            if key_size < 3072:
                logger.warning("RSA key size below recommended", size=key_size, recommended=3072)
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            key_size = public_key.key_size
            if key_size < 256:
                return f"EC key size {key_size} is below minimum (256)"

        return None


# ==============================================================================
# Certificate Pinning
# ==============================================================================


class CertificatePinner:
    """Certificate pinning validation."""

    def __init__(self, config: TLSConfig):
        self.config = config
        self._pins_cert: set[str] = set(config.pinned_certificates)
        self._pins_spki: set[str] = set(config.pinned_public_keys)

    def add_certificate_pin(self, fingerprint_sha256: str) -> None:
        """Add a certificate fingerprint pin."""
        self._pins_cert.add(fingerprint_sha256.lower())

    def add_public_key_pin(self, spki_sha256: str) -> None:
        """Add a public key (SPKI) pin."""
        self._pins_spki.add(spki_sha256.lower())

    def verify_pin(self, cert: x509.Certificate) -> tuple[bool, str | None]:
        """Verify certificate against pins. Returns (valid, error)."""
        if not self._pins_cert and not self._pins_spki:
            return True, None  # No pins configured

        # Calculate fingerprint
        fingerprint = cert.fingerprint(hashes.SHA256()).hex().lower()

        # Calculate SPKI hash
        public_key_der = cert.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        spki_hash = hashlib.sha256(public_key_der).hexdigest().lower()

        # Check certificate pins
        if self._pins_cert and fingerprint in self._pins_cert:
            return True, None

        # Check SPKI pins
        if self._pins_spki and spki_hash in self._pins_spki:
            return True, None

        if self._pins_cert:
            return False, f"Certificate fingerprint {fingerprint} not in pinned certificates"
        else:
            return False, f"Public key hash {spki_hash} not in pinned public keys"

    @staticmethod
    def extract_pin_from_certificate(cert_path: Path) -> tuple[str, str]:
        """Extract pin hashes from a certificate file.

        Returns (certificate_fingerprint, spki_hash).
        """
        cert_data = cert_path.read_bytes()

        try:
            cert = x509.load_pem_x509_certificate(cert_data)
        except Exception:
            cert = x509.load_der_x509_certificate(cert_data)

        fingerprint = cert.fingerprint(hashes.SHA256()).hex()

        public_key_der = cert.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        spki_hash = hashlib.sha256(public_key_der).hexdigest()

        return fingerprint, spki_hash


# ==============================================================================
# SSL Context Factory
# ==============================================================================


class TLSContextFactory:
    """Creates hardened SSL contexts."""

    def __init__(self, config: TLSConfig | None = None):
        self.config = config or TLSConfig()

    def create_server_context(self) -> ssl.SSLContext:
        """Create a hardened SSL context for server use."""
        # Use TLS 1.2+ minimum
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

        # Set minimum version
        if self.config.minimum_version == TLSVersion.TLS_1_3:
            ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        else:
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2

        # Apply cipher configuration
        cipher_string = CipherSuites.get_cipher_string(self.config.cipher_strength)
        ctx.set_ciphers(cipher_string)

        # Set TLS 1.3 ciphersuites if supported
        with contextlib.suppress(AttributeError, ssl.SSLError):
            ctx.set_ciphersuites(CipherSuites.get_tls13_ciphers())

        # Disable session resumption for better security (optional)
        ctx.options |= ssl.OP_NO_TICKET

        # Enable server cipher preference
        ctx.options |= ssl.OP_CIPHER_SERVER_PREFERENCE

        # Disable compression (CRIME attack)
        ctx.options |= ssl.OP_NO_COMPRESSION

        # Enable session cache
        ctx.options |= ssl.OP_NO_SSLv2
        ctx.options |= ssl.OP_NO_SSLv3

        # Set session cache
        ctx.set_session_cache_mode(ssl.SESS_CACHE_SERVER)

        # Load certificate and key
        if self.config.cert_path and self.config.key_path:
            ctx.load_cert_chain(str(self.config.cert_path), str(self.config.key_path))

        # Load CA for client verification
        if self.config.verify_client:
            ctx.verify_mode = ssl.CERT_REQUIRED
            if self.config.ca_path:
                ctx.load_verify_locations(str(self.config.ca_path))
            else:
                ctx.load_default_certs()
            ctx.verify_depth = self.config.verify_depth

        # Set ALPN protocols
        if self.config.alpn_protocols:
            ctx.set_alpn_protocols(self.config.alpn_protocols)

        logger.info(
            "Created server TLS context",
            min_version=str(ctx.minimum_version),
            cipher_count=len(ctx.get_ciphers()) if hasattr(ctx, "get_ciphers") else "N/A",
            client_auth=self.config.verify_client,
        )

        return ctx

    def create_client_context(
        self, verify: bool = True, check_hostname: bool | None = None
    ) -> ssl.SSLContext:
        """Create a hardened SSL context for client use."""
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

        # Set minimum version
        if self.config.minimum_version == TLSVersion.TLS_1_3:
            ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        else:
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2

        # Apply cipher configuration
        cipher_string = CipherSuites.get_cipher_string(self.config.cipher_strength)
        ctx.set_ciphers(cipher_string)

        # Set TLS 1.3 ciphersuites if supported
        with contextlib.suppress(AttributeError, ssl.SSLError):
            ctx.set_ciphersuites(CipherSuites.get_tls13_ciphers())

        # Disable compression
        ctx.options |= ssl.OP_NO_COMPRESSION

        # Certificate verification
        if verify:
            ctx.verify_mode = ssl.CERT_REQUIRED
            if self.config.ca_path:
                ctx.load_verify_locations(str(self.config.ca_path))
            else:
                ctx.load_default_certs()
        else:
            ctx.verify_mode = ssl.CERT_NONE

        # Hostname checking
        ctx.check_hostname = (
            check_hostname if check_hostname is not None else self.config.check_hostname and verify
        )

        # Load client certificate if configured
        if self.config.cert_path and self.config.key_path:
            ctx.load_cert_chain(str(self.config.cert_path), str(self.config.key_path))

        # Set ALPN protocols
        if self.config.alpn_protocols:
            ctx.set_alpn_protocols(self.config.alpn_protocols)

        logger.info(
            "Created client TLS context",
            min_version=str(ctx.minimum_version),
            verify=verify,
            check_hostname=ctx.check_hostname,
        )

        return ctx


# ==============================================================================
# OCSP Stapling Support
# ==============================================================================


class OCSPStapler:
    """OCSP stapling support for certificate validation.

    Note: Full OCSP implementation requires network access and is complex.
    This provides the framework and basic validation.
    """

    def __init__(self, config: TLSConfig | None = None):
        self.config = config or TLSConfig()
        self._stapled_response: bytes | None = None
        self._stapled_response_time: float = 0
        self._staple_validity: float = 3600 * 24  # 24 hours

    def set_stapled_response(self, response: bytes) -> None:
        """Set the OCSP response to staple."""
        self._stapled_response = response
        self._stapled_response_time = datetime.now(UTC).timestamp()

    def get_stapled_response(self) -> bytes | None:
        """Get the stapled OCSP response if still valid."""
        if self._stapled_response is None:
            return None

        now = datetime.now(UTC).timestamp()
        if now - self._stapled_response_time > self._staple_validity:
            self._stapled_response = None
            return None

        return self._stapled_response

    def get_ocsp_responders(self, cert: x509.Certificate) -> list[str]:
        """Extract OCSP responder URLs from certificate."""
        responders: list[str] = []
        try:
            aia = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS)
            for desc in aia.value:
                if desc.access_method == x509.oid.AuthorityInformationAccessOID.OCSP and isinstance(
                    desc.access_location, x509.UniformResourceIdentifier
                ):
                    responders.append(desc.access_location.value)
        except x509.ExtensionNotFound:
            pass
        return responders


# ==============================================================================
# TLS Manager
# ==============================================================================


class TLSManager:
    """Main manager for TLS security features."""

    def __init__(self, config: TLSConfig | None = None):
        self.config = config or TLSConfig()
        self.context_factory = TLSContextFactory(config)
        self.certificate_validator = CertificateValidator(config)
        self.certificate_pinner = CertificatePinner(self.config)
        self.ocsp_stapler = OCSPStapler(config)

    def create_server_context(self) -> ssl.SSLContext:
        """Create a hardened server SSL context."""
        return self.context_factory.create_server_context()

    def create_client_context(
        self, verify: bool = True, check_hostname: bool | None = None
    ) -> ssl.SSLContext:
        """Create a hardened client SSL context."""
        return self.context_factory.create_client_context(verify, check_hostname)

    def validate_server_certificate(self, cert_der: bytes, hostname: str) -> tuple[bool, list[str]]:
        """Validate a server certificate."""
        cert = x509.load_der_x509_certificate(cert_der)

        # Standard validation
        valid, errors = self.certificate_validator.validate_certificate(cert, hostname)

        # Pin verification
        if self.config.pinned_certificates or self.config.pinned_public_keys:
            pin_valid, pin_error = self.certificate_pinner.verify_pin(cert)
            if not pin_valid and pin_error:
                valid = False
                errors.append(pin_error)

        return valid, errors

    def get_peer_certificate_info(self, ssl_socket: ssl.SSLSocket) -> CertificateInfo | None:
        """Get certificate info from an SSL socket."""
        cert_der = ssl_socket.getpeercert(binary_form=True)
        if not cert_der:
            return None

        cert = x509.load_der_x509_certificate(cert_der)
        return self.certificate_validator.get_certificate_info(cert)

    def get_connection_info(self, ssl_socket: ssl.SSLSocket) -> dict[str, Any]:
        """Get detailed TLS connection information."""
        return {
            "protocol": ssl_socket.version(),
            "cipher": ssl_socket.cipher(),
            "compression": ssl_socket.compression(),
            "alpn_protocol": ssl_socket.selected_alpn_protocol(),
            "server_hostname": ssl_socket.server_hostname,
        }


__all__ = [
    "TLSVersion",
    "CipherStrength",
    "TLSConfig",
    "CipherSuites",
    "ECCurves",
    "CertificateInfo",
    "CertificateValidator",
    "CertificatePinner",
    "TLSContextFactory",
    "OCSPStapler",
    "TLSManager",
]
