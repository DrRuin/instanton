"""Mutual TLS (mTLS) support for client certificate authentication."""

from __future__ import annotations

import ssl
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path
from typing import Any

import structlog
from cryptography import x509
from cryptography.hazmat.primitives import serialization

logger = structlog.get_logger()


class ClientCertVerifyMode(Enum):
    """Client certificate verification modes."""

    NONE = "none"  # No client cert required
    OPTIONAL = "optional"  # Client cert optional, validated if provided
    REQUIRED = "required"  # Client cert required


@dataclass
class MTLSConfig:
    """Configuration for mTLS."""

    enabled: bool = False
    verify_mode: ClientCertVerifyMode = ClientCertVerifyMode.OPTIONAL
    ca_cert_path: Path | None = None
    ca_cert_data: bytes | None = None
    crl_path: Path | None = None  # Certificate Revocation List
    ocsp_enabled: bool = False  # Online Certificate Status Protocol
    allowed_subjects: list[str] = field(default_factory=list)  # Allowed subject patterns
    allowed_issuers: list[str] = field(default_factory=list)  # Allowed issuer patterns
    require_san_match: bool = False  # Require SAN to match request host
    max_cert_chain_depth: int = 3
    check_cert_expiry: bool = True


@dataclass
class ClientCertInfo:
    """Information extracted from a client certificate."""

    subject: str
    issuer: str
    serial_number: str
    not_before: datetime
    not_after: datetime
    fingerprint_sha256: str
    common_name: str | None = None
    organization: str | None = None
    san_domains: list[str] = field(default_factory=list)
    san_emails: list[str] = field(default_factory=list)
    is_valid: bool = True
    validation_error: str | None = None

    @property
    def is_expired(self) -> bool:
        """Check if certificate is expired."""
        return datetime.now(UTC) > self.not_after

    @property
    def identity(self) -> str:
        """Get the primary identity from the certificate."""
        return self.common_name or self.subject


class ClientCertValidator:
    """Validates client certificates for mTLS."""

    def __init__(self, config: MTLSConfig) -> None:
        self.config = config
        self._ca_certs: list[x509.Certificate] = []
        self._revoked_serials: set[str] = set()
        self._load_ca_certs()
        self._load_crl()

    def _load_ca_certs(self) -> None:
        """Load CA certificates for validation."""
        if self.config.ca_cert_path and self.config.ca_cert_path.exists():
            pem_data = self.config.ca_cert_path.read_bytes()
            self._ca_certs = self._parse_pem_certs(pem_data)
        elif self.config.ca_cert_data:
            self._ca_certs = self._parse_pem_certs(self.config.ca_cert_data)

        logger.info("Loaded CA certificates", count=len(self._ca_certs))

    def _parse_pem_certs(self, pem_data: bytes) -> list[x509.Certificate]:
        """Parse multiple certificates from PEM data."""
        certs = []
        # Split PEM data into individual certificates
        pem_str = pem_data.decode("utf-8")
        cert_markers = pem_str.split("-----BEGIN CERTIFICATE-----")

        for marker in cert_markers[1:]:  # Skip first empty part
            cert_pem = (
                "-----BEGIN CERTIFICATE-----"
                + marker.split("-----END CERTIFICATE-----")[0]
                + "-----END CERTIFICATE-----"
            )
            try:
                cert = x509.load_pem_x509_certificate(cert_pem.encode())
                certs.append(cert)
            except Exception as e:
                logger.warning("Failed to parse certificate", error=str(e))

        return certs

    def _load_crl(self) -> None:
        """Load Certificate Revocation List."""
        if not self.config.crl_path or not self.config.crl_path.exists():
            return

        try:
            crl_data = self.config.crl_path.read_bytes()
            crl = x509.load_pem_x509_crl(crl_data)

            for revoked in crl:
                self._revoked_serials.add(format(revoked.serial_number, "x"))

            logger.info("Loaded CRL", revoked_count=len(self._revoked_serials))
        except Exception as e:
            logger.error("Failed to load CRL", error=str(e))

    def validate(self, cert_pem: bytes) -> ClientCertInfo:
        """Validate a client certificate.

        Args:
            cert_pem: PEM-encoded client certificate

        Returns:
            ClientCertInfo with validation results
        """
        try:
            cert = x509.load_pem_x509_certificate(cert_pem)
        except Exception as e:
            return ClientCertInfo(
                subject="",
                issuer="",
                serial_number="",
                not_before=datetime.min.replace(tzinfo=UTC),
                not_after=datetime.min.replace(tzinfo=UTC),
                fingerprint_sha256="",
                is_valid=False,
                validation_error=f"Invalid certificate format: {e}",
            )

        # Extract certificate info
        info = self._extract_cert_info(cert)

        # Perform validation checks
        if self.config.check_cert_expiry and info.is_expired:
            info.is_valid = False
            info.validation_error = "Certificate has expired"
            return info

        # Check if certificate is not yet valid
        if datetime.now(UTC) < info.not_before:
            info.is_valid = False
            info.validation_error = "Certificate is not yet valid"
            return info

        # Check revocation
        if info.serial_number in self._revoked_serials:
            info.is_valid = False
            info.validation_error = "Certificate has been revoked"
            return info

        # Check allowed subjects
        if self.config.allowed_subjects and not self._match_patterns(
            info.subject, self.config.allowed_subjects
        ):
            info.is_valid = False
            info.validation_error = "Certificate subject not in allowed list"
            return info

        # Check allowed issuers
        if self.config.allowed_issuers and not self._match_patterns(
            info.issuer, self.config.allowed_issuers
        ):
            info.is_valid = False
            info.validation_error = "Certificate issuer not in allowed list"
            return info

        # Verify certificate chain if CA certs are configured
        if self._ca_certs:
            chain_valid, chain_error = self._verify_chain(cert)
            if not chain_valid:
                info.is_valid = False
                info.validation_error = chain_error
                return info

        logger.debug(
            "Client certificate validated",
            subject=info.subject,
            issuer=info.issuer,
        )

        return info

    def _extract_cert_info(self, cert: x509.Certificate) -> ClientCertInfo:
        """Extract information from a certificate."""
        import hashlib

        # Extract common name
        common_name = None
        organization = None
        for attr in cert.subject:
            if attr.oid == x509.oid.NameOID.COMMON_NAME:
                common_name = attr.value
            elif attr.oid == x509.oid.NameOID.ORGANIZATION_NAME:
                organization = attr.value

        # Extract SANs
        san_domains = []
        san_emails = []
        try:
            san_ext = cert.extensions.get_extension_for_oid(
                x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
            )
            for name in san_ext.value:
                if isinstance(name, x509.DNSName):
                    san_domains.append(name.value)
                elif isinstance(name, x509.RFC822Name):
                    san_emails.append(name.value)
        except x509.ExtensionNotFound:
            pass

        # Calculate fingerprint
        fingerprint = hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()

        return ClientCertInfo(
            subject=cert.subject.rfc4514_string(),
            issuer=cert.issuer.rfc4514_string(),
            serial_number=format(cert.serial_number, "x"),
            not_before=cert.not_valid_before_utc,
            not_after=cert.not_valid_after_utc,
            fingerprint_sha256=fingerprint,
            common_name=common_name,
            organization=organization,
            san_domains=san_domains,
            san_emails=san_emails,
        )

    def _match_patterns(self, value: str, patterns: list[str]) -> bool:
        """Check if value matches any pattern."""
        import fnmatch

        value_lower = value.lower()
        return any(fnmatch.fnmatch(value_lower, pattern.lower()) for pattern in patterns)

    def _verify_chain(self, cert: x509.Certificate) -> tuple[bool, str | None]:
        """Verify certificate chain against CA certificates."""
        # Simple chain verification - check if any CA signed this cert
        for ca_cert in self._ca_certs:
            try:
                # Verify signature
                ca_cert.public_key().verify(
                    cert.signature,
                    cert.tbs_certificate_bytes,
                    cert.signature_algorithm_parameters,
                )
                return True, None
            except Exception:
                continue

        # Check if self-signed and in CA list
        if cert.issuer == cert.subject:
            for ca_cert in self._ca_certs:
                if ca_cert.subject == cert.subject:
                    return True, None

        return False, "Certificate chain validation failed"


class MTLSContext:
    """Creates and manages mTLS SSL contexts."""

    def __init__(self, config: MTLSConfig) -> None:
        self.config = config
        self.validator = ClientCertValidator(config)

    def create_server_context(
        self,
        cert_path: Path,
        key_path: Path,
    ) -> ssl.SSLContext:
        """Create an SSL context for server with mTLS support.

        Args:
            cert_path: Path to server certificate
            key_path: Path to server private key

        Returns:
            Configured SSL context
        """
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

        # Set minimum TLS version
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2

        # Set modern cipher suites (AEAD only, with PFS)
        ctx.set_ciphers(
            "ECDHE+AESGCM:DHE+AESGCM:ECDHE+CHACHA20:DHE+CHACHA20:!aNULL:!eNULL:!MD5:!DSS:!RC4:!3DES"
        )

        # Load server certificate and key
        ctx.load_cert_chain(str(cert_path), str(key_path))

        # Configure client certificate verification
        if self.config.enabled:
            if self.config.verify_mode == ClientCertVerifyMode.REQUIRED:
                ctx.verify_mode = ssl.CERT_REQUIRED
            elif self.config.verify_mode == ClientCertVerifyMode.OPTIONAL:
                ctx.verify_mode = ssl.CERT_OPTIONAL
            else:
                ctx.verify_mode = ssl.CERT_NONE

            # Load CA certificates for client verification
            if self.config.ca_cert_path and self.config.ca_cert_path.exists():
                ctx.load_verify_locations(str(self.config.ca_cert_path))

        else:
            ctx.verify_mode = ssl.CERT_NONE

        # Enable OCSP stapling if supported
        if hasattr(ctx, "set_ocsp_client_callback") and self.config.ocsp_enabled:
            ctx.set_ocsp_client_callback(self._ocsp_callback)

        logger.info(
            "Created mTLS server context",
            verify_mode=self.config.verify_mode.value,
            enabled=self.config.enabled,
        )

        return ctx

    def create_client_context(
        self,
        cert_path: Path | None = None,
        key_path: Path | None = None,
        verify_server: bool = True,
    ) -> ssl.SSLContext:
        """Create an SSL context for client with optional client certificate.

        Args:
            cert_path: Path to client certificate (optional)
            key_path: Path to client private key (optional)
            verify_server: Whether to verify server certificate

        Returns:
            Configured SSL context
        """
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

        # Set minimum TLS version
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2

        # Set modern cipher suites
        ctx.set_ciphers("ECDHE+AESGCM:DHE+AESGCM:ECDHE+CHACHA20:DHE+CHACHA20")

        # Configure server verification
        if verify_server:
            ctx.verify_mode = ssl.CERT_REQUIRED
            ctx.check_hostname = True
            ctx.load_default_certs()

            # Load custom CA if configured
            if self.config.ca_cert_path and self.config.ca_cert_path.exists():
                ctx.load_verify_locations(str(self.config.ca_cert_path))
        else:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

        # Load client certificate if provided
        if cert_path and key_path:
            ctx.load_cert_chain(str(cert_path), str(key_path))

        logger.info(
            "Created mTLS client context",
            has_client_cert=cert_path is not None,
            verify_server=verify_server,
        )

        return ctx

    def _ocsp_callback(
        self,
        conn: Any,
        ocsp_data: bytes | None,
        user_data: Any,
    ) -> bool:
        """OCSP stapling callback."""
        if not ocsp_data:
            logger.warning("No OCSP response received")
            return True  # Allow connection to proceed

        # Parse and validate OCSP response
        # This is a simplified implementation
        try:
            from cryptography.x509 import ocsp

            response = ocsp.load_der_ocsp_response(ocsp_data)
            if response.response_status == ocsp.OCSPResponseStatus.SUCCESSFUL:
                cert_status = response.certificate_status
                if cert_status == ocsp.OCSPCertStatus.GOOD:
                    return True
                elif cert_status == ocsp.OCSPCertStatus.REVOKED:
                    logger.warning("Certificate revoked per OCSP")
                    return False
        except Exception as e:
            logger.warning("OCSP validation failed", error=str(e))

        return True  # Default to allowing if OCSP check fails

    def validate_peer_cert(self, cert_pem: bytes) -> ClientCertInfo:
        """Validate a peer certificate and return info."""
        return self.validator.validate(cert_pem)


def extract_client_cert_from_ssl(ssl_object: ssl.SSLObject) -> bytes | None:
    """Extract client certificate from SSL connection."""
    cert_der = ssl_object.getpeercert(binary_form=True)
    if not cert_der:
        return None

    # Convert DER to PEM
    from cryptography.hazmat.primitives.serialization import Encoding

    cert = x509.load_der_x509_certificate(cert_der)
    return cert.public_bytes(Encoding.PEM)
