"""Tests for certificate management and mTLS."""

import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

from instanton.security.certificates import (
    CertificateManager,
    CertificateStore,
    generate_self_signed_cert,
    parse_certificate_info,
)
from instanton.security.mtls import (
    ClientCertInfo,
    ClientCertValidator,
    ClientCertVerifyMode,
    MTLSConfig,
    MTLSContext,
)

# ==============================================================================
# Certificate Generation Tests
# ==============================================================================


class TestSelfSignedCertGeneration:
    """Tests for self-signed certificate generation."""

    def test_generate_ec_cert(self):
        """Test generating EC certificate."""
        cert_pem, key_pem = generate_self_signed_cert(
            domain="test.example.com",
            key_type="EC",
            key_size=256,
        )

        assert b"BEGIN CERTIFICATE" in cert_pem
        assert b"BEGIN EC PRIVATE KEY" in key_pem or b"BEGIN PRIVATE KEY" in key_pem

        # Parse and verify
        cert = x509.load_pem_x509_certificate(cert_pem)
        cn_attr = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0]
        assert cn_attr.value == "test.example.com"

    def test_generate_rsa_cert(self):
        """Test generating RSA certificate."""
        cert_pem, key_pem = generate_self_signed_cert(
            domain="test.example.com",
            key_type="RSA",
            key_size=2048,
        )

        assert b"BEGIN CERTIFICATE" in cert_pem
        assert b"BEGIN RSA PRIVATE KEY" in key_pem or b"BEGIN PRIVATE KEY" in key_pem

        # Verify key type
        cert = x509.load_pem_x509_certificate(cert_pem)
        public_key = cert.public_key()
        assert isinstance(public_key, rsa.RSAPublicKey)

    def test_cert_validity_period(self):
        """Test certificate validity period."""
        cert_pem, _ = generate_self_signed_cert(
            domain="test.example.com",
            days_valid=30,
        )

        cert = x509.load_pem_x509_certificate(cert_pem)
        now = datetime.now(UTC)

        # Should be valid now
        assert cert.not_valid_before_utc <= now
        assert cert.not_valid_after_utc > now

        # Should expire in approximately 30 days
        days_valid = (cert.not_valid_after_utc - now).days
        assert 29 <= days_valid <= 31

    def test_cert_has_san(self):
        """Test certificate has Subject Alternative Names."""
        cert_pem, _ = generate_self_signed_cert(domain="example.com")

        cert = x509.load_pem_x509_certificate(cert_pem)
        san_ext = cert.extensions.get_extension_for_oid(
            x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        )

        san_names = [name.value for name in san_ext.value if isinstance(name, x509.DNSName)]
        assert "example.com" in san_names
        assert "*.example.com" in san_names  # Wildcard


# ==============================================================================
# Certificate Store Tests
# ==============================================================================


class TestCertificateStore:
    """Tests for certificate storage."""

    def test_store_and_load(self):
        """Test storing and loading certificates."""
        with tempfile.TemporaryDirectory() as tmpdir:
            store = CertificateStore(Path(tmpdir))

            cert_pem, key_pem = generate_self_signed_cert("test.example.com")
            store.store("test.example.com", cert_pem, key_pem)

            # Load back
            loaded = store.load("test.example.com")
            assert loaded is not None
            loaded_cert, loaded_key = loaded

            assert loaded_cert == cert_pem
            assert loaded_key == key_pem

    def test_load_nonexistent(self):
        """Test loading nonexistent certificate."""
        with tempfile.TemporaryDirectory() as tmpdir:
            store = CertificateStore(Path(tmpdir))

            loaded = store.load("nonexistent.example.com")
            assert loaded is None

    def test_list_domains(self):
        """Test listing stored domains."""
        with tempfile.TemporaryDirectory() as tmpdir:
            store = CertificateStore(Path(tmpdir))

            # Store multiple certs
            for domain in ["a.example.com", "b.example.com", "c.example.com"]:
                cert_pem, key_pem = generate_self_signed_cert(domain)
                store.store(domain, cert_pem, key_pem)

            domains = store.list_domains()
            assert len(domains) == 3
            assert set(domains) == {"a.example.com", "b.example.com", "c.example.com"}

    def test_delete_certificate(self):
        """Test deleting a certificate."""
        with tempfile.TemporaryDirectory() as tmpdir:
            store = CertificateStore(Path(tmpdir))

            cert_pem, key_pem = generate_self_signed_cert("test.example.com")
            store.store("test.example.com", cert_pem, key_pem)

            # Verify it exists
            assert store.load("test.example.com") is not None

            # Delete
            result = store.delete("test.example.com")
            assert result is True

            # Verify it's gone
            assert store.load("test.example.com") is None

    def test_get_info(self):
        """Test getting certificate info."""
        with tempfile.TemporaryDirectory() as tmpdir:
            store = CertificateStore(Path(tmpdir))

            cert_pem, key_pem = generate_self_signed_cert("test.example.com")
            store.store("test.example.com", cert_pem, key_pem)

            info = store.get_info("test.example.com")
            assert info is not None
            assert info.domain == "test.example.com"
            assert not info.is_expired
            assert info.is_self_signed


# ==============================================================================
# Certificate Info Tests
# ==============================================================================


class TestCertificateInfo:
    """Tests for certificate info parsing."""

    def test_parse_info(self):
        """Test parsing certificate info."""
        cert_pem, _ = generate_self_signed_cert("test.example.com")

        info = parse_certificate_info(cert_pem, "test.example.com")

        assert info.domain == "test.example.com"
        assert not info.is_expired
        assert info.days_until_expiry > 0
        assert "test.example.com" in info.san_domains

    def test_needs_renewal(self):
        """Test renewal detection."""
        # Create cert that's about to expire (1 day)
        cert_pem, _ = generate_self_signed_cert("test.example.com", days_valid=15)
        info = parse_certificate_info(cert_pem, "test.example.com")

        # 15 days < 30 days threshold
        assert info.needs_renewal

        # Create cert with plenty of time
        cert_pem, _ = generate_self_signed_cert("test.example.com", days_valid=90)
        info = parse_certificate_info(cert_pem, "test.example.com")

        assert not info.needs_renewal

    def test_fingerprint(self):
        """Test fingerprint calculation."""
        cert_pem, _ = generate_self_signed_cert("test.example.com")

        info = parse_certificate_info(cert_pem, "test.example.com")

        # Fingerprint should be a hex string
        assert len(info.fingerprint_sha256) == 64
        assert all(c in "0123456789abcdef" for c in info.fingerprint_sha256)


# ==============================================================================
# Certificate Manager Tests
# ==============================================================================


class TestCertificateManager:
    """Tests for certificate manager."""

    def test_ensure_certificate_creates_new(self):
        """Test ensuring certificate creates new one if missing."""
        with tempfile.TemporaryDirectory() as tmpdir:
            store = CertificateStore(Path(tmpdir))
            manager = CertificateManager(store)

            cert_pem, key_pem = manager.ensure_certificate(
                "test.example.com",
                generate_self_signed=True,
            )

            assert cert_pem is not None
            assert key_pem is not None

            # Should be stored
            assert store.load("test.example.com") is not None

    def test_ensure_certificate_uses_existing(self):
        """Test ensuring certificate uses existing one."""
        with tempfile.TemporaryDirectory() as tmpdir:
            store = CertificateStore(Path(tmpdir))
            manager = CertificateManager(store)

            # Pre-store a certificate
            original_cert, original_key = generate_self_signed_cert("test.example.com")
            store.store("test.example.com", original_cert, original_key)

            # Ensure should return existing
            cert_pem, key_pem = manager.ensure_certificate("test.example.com")

            assert cert_pem == original_cert
            assert key_pem == original_key


# ==============================================================================
# mTLS Config Tests
# ==============================================================================


class TestMTLSConfig:
    """Tests for mTLS configuration."""

    def test_default_config(self):
        """Test default mTLS configuration."""
        config = MTLSConfig()

        assert config.enabled is False
        assert config.verify_mode == ClientCertVerifyMode.OPTIONAL
        assert config.check_cert_expiry is True

    def test_custom_config(self):
        """Test custom mTLS configuration."""
        config = MTLSConfig(
            enabled=True,
            verify_mode=ClientCertVerifyMode.REQUIRED,
            allowed_subjects=["CN=*.example.com"],
            allowed_issuers=["O=Example CA"],
        )

        assert config.enabled is True
        assert config.verify_mode == ClientCertVerifyMode.REQUIRED
        assert "CN=*.example.com" in config.allowed_subjects


# ==============================================================================
# Client Certificate Validator Tests
# ==============================================================================


class TestClientCertValidator:
    """Tests for client certificate validation."""

    def test_validate_valid_cert(self):
        """Test validating a valid certificate."""
        config = MTLSConfig(enabled=True)
        validator = ClientCertValidator(config)

        cert_pem, _ = generate_self_signed_cert("client.example.com")

        info = validator.validate(cert_pem)

        assert info.is_valid
        assert info.validation_error is None

    def test_validate_expired_cert(self):
        """Test validating an expired certificate."""
        config = MTLSConfig(enabled=True, check_cert_expiry=True)
        validator = ClientCertValidator(config)

        # Generate an already-expired cert manually
        private_key = ec.generate_private_key(ec.SECP256R1())
        now = datetime.now(UTC)

        cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, "expired.example.com"),
            ]))
            .issuer_name(x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, "expired.example.com"),
            ]))
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=365))
            .not_valid_after(now - timedelta(days=1))  # Expired yesterday
            .sign(private_key, hashes.SHA256())
        )

        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        info = validator.validate(cert_pem)

        assert not info.is_valid
        assert "expired" in info.validation_error.lower()

    def test_validate_with_allowed_subjects(self):
        """Test validation with subject allowlist."""
        config = MTLSConfig(
            enabled=True,
            allowed_subjects=["*example.com*"],
        )
        validator = ClientCertValidator(config)

        # Valid subject
        cert_pem, _ = generate_self_signed_cert("client.example.com")
        info = validator.validate(cert_pem)
        assert info.is_valid

    def test_validate_with_disallowed_subject(self):
        """Test validation rejects disallowed subjects."""
        config = MTLSConfig(
            enabled=True,
            allowed_subjects=["*trusted.org*"],  # Only trust *.trusted.org
        )
        validator = ClientCertValidator(config)

        # Subject doesn't match the trusted.org pattern
        cert_pem, _ = generate_self_signed_cert("client.untrusted.com")
        info = validator.validate(cert_pem)

        assert not info.is_valid
        assert "not in allowed list" in info.validation_error.lower()


# ==============================================================================
# mTLS Context Tests
# ==============================================================================


class TestMTLSContext:
    """Tests for mTLS SSL context creation."""

    def test_create_server_context(self):
        """Test creating server SSL context."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmppath = Path(tmpdir)

            # Generate cert and key
            cert_pem, key_pem = generate_self_signed_cert("server.example.com")
            cert_path = tmppath / "cert.pem"
            key_path = tmppath / "key.pem"
            cert_path.write_bytes(cert_pem)
            key_path.write_bytes(key_pem)

            config = MTLSConfig(enabled=True, verify_mode=ClientCertVerifyMode.OPTIONAL)
            mtls = MTLSContext(config)

            ctx = mtls.create_server_context(cert_path, key_path)

            assert ctx is not None
            # Optional means CERT_OPTIONAL
            import ssl
            assert ctx.verify_mode == ssl.CERT_OPTIONAL

    def test_create_server_context_required(self):
        """Test creating server context with required client certs."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmppath = Path(tmpdir)

            cert_pem, key_pem = generate_self_signed_cert("server.example.com")
            cert_path = tmppath / "cert.pem"
            key_path = tmppath / "key.pem"
            cert_path.write_bytes(cert_pem)
            key_path.write_bytes(key_pem)

            config = MTLSConfig(enabled=True, verify_mode=ClientCertVerifyMode.REQUIRED)
            mtls = MTLSContext(config)

            ctx = mtls.create_server_context(cert_path, key_path)

            import ssl
            assert ctx.verify_mode == ssl.CERT_REQUIRED

    def test_create_client_context(self):
        """Test creating client SSL context."""
        config = MTLSConfig()
        mtls = MTLSContext(config)

        ctx = mtls.create_client_context(verify_server=False)

        assert ctx is not None
        import ssl
        assert ctx.verify_mode == ssl.CERT_NONE

    def test_create_client_context_with_cert(self):
        """Test creating client context with client certificate."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmppath = Path(tmpdir)

            cert_pem, key_pem = generate_self_signed_cert("client.example.com")
            cert_path = tmppath / "client_cert.pem"
            key_path = tmppath / "client_key.pem"
            cert_path.write_bytes(cert_pem)
            key_path.write_bytes(key_pem)

            config = MTLSConfig()
            mtls = MTLSContext(config)

            ctx = mtls.create_client_context(
                cert_path=cert_path,
                key_path=key_path,
                verify_server=False,
            )

            assert ctx is not None


# ==============================================================================
# Client Certificate Info Tests
# ==============================================================================


class TestClientCertInfo:
    """Tests for ClientCertInfo dataclass."""

    def test_is_expired(self):
        """Test expiry detection."""
        now = datetime.now(UTC)

        info = ClientCertInfo(
            subject="CN=test",
            issuer="CN=test",
            serial_number="abc",
            not_before=now - timedelta(days=365),
            not_after=now - timedelta(days=1),  # Expired
            fingerprint_sha256="abc123",
        )

        assert info.is_expired

    def test_identity_with_cn(self):
        """Test identity extraction with common name."""
        now = datetime.now(UTC)

        info = ClientCertInfo(
            subject="CN=test.example.com,O=Example",
            issuer="CN=CA",
            serial_number="abc",
            not_before=now - timedelta(days=1),
            not_after=now + timedelta(days=365),
            fingerprint_sha256="abc123",
            common_name="test.example.com",
        )

        assert info.identity == "test.example.com"

    def test_identity_fallback_to_subject(self):
        """Test identity falls back to subject if no CN."""
        now = datetime.now(UTC)

        info = ClientCertInfo(
            subject="O=Example Org",
            issuer="CN=CA",
            serial_number="abc",
            not_before=now - timedelta(days=1),
            not_after=now + timedelta(days=365),
            fingerprint_sha256="abc123",
            common_name=None,
        )

        assert info.identity == "O=Example Org"
