"""Tests for Instanton Certificate Manager - From Scratch Implementation."""

import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from instanton.security.certmanager import (
    INSTANTON_DOMAIN,
    AutoTLSManager,
    CertificateBundle,
    CertificateGenerator,
    CertificateSource,
    CertificateStore,
    InstantonDomainConfig,
    InstantonDomainManager,
    KeyType,
    SelfHostedConfig,
    WildcardDNSService,
)


# ==============================================================================
# Wildcard DNS Service Tests
# ==============================================================================


class TestWildcardDNSService:
    """Tests for sslip.io-style wildcard DNS service."""

    def test_encode_ipv4_simple(self):
        """Test encoding a simple IPv4 address."""
        dns = WildcardDNSService("instanton.tech")
        domain = dns.encode_ipv4("192.168.1.1")
        assert domain == "192-168-1-1.instanton.tech"

    def test_encode_ipv4_with_subdomain(self):
        """Test encoding IPv4 with subdomain."""
        dns = WildcardDNSService("instanton.tech")
        domain = dns.encode_ipv4("10.0.0.1", "myapp")
        assert domain == "myapp.10-0-0-1.instanton.tech"

    def test_encode_ipv4_public_ip(self):
        """Test encoding a public IP."""
        dns = WildcardDNSService("instanton.tech")
        domain = dns.encode_ipv4("203.0.113.42", "tunnel")
        assert domain == "tunnel.203-0-113-42.instanton.tech"

    def test_encode_ipv4_invalid(self):
        """Test encoding invalid IPv4 raises error."""
        dns = WildcardDNSService("instanton.tech")
        with pytest.raises(ValueError, match="Invalid IPv4"):
            dns.encode_ipv4("256.1.1.1")

    def test_encode_ipv6_simple(self):
        """Test encoding IPv6 address."""
        dns = WildcardDNSService("instanton.tech")
        domain = dns.encode_ipv6("::1")
        assert "instanton.tech" in domain
        assert "-" in domain  # Colons replaced with dashes

    def test_decode_domain_simple(self):
        """Test decoding a simple domain."""
        dns = WildcardDNSService("instanton.tech")
        ip, subdomain, base = dns.decode_domain("192-168-1-1.instanton.tech")
        assert ip == "192.168.1.1"
        assert subdomain == ""
        assert base == "instanton.tech"

    def test_decode_domain_with_subdomain(self):
        """Test decoding domain with subdomain."""
        dns = WildcardDNSService("instanton.tech")
        ip, subdomain, base = dns.decode_domain("myapp.10-0-0-1.instanton.tech")
        assert ip == "10.0.0.1"
        assert subdomain == "myapp"

    def test_resolve_valid_domain(self):
        """Test resolving a valid wildcard domain."""
        dns = WildcardDNSService("instanton.tech")
        ip = dns.resolve("tunnel.192-168-0-100.instanton.tech")
        assert ip == "192.168.0.100"

    def test_resolve_invalid_domain(self):
        """Test resolving an invalid domain returns None."""
        dns = WildcardDNSService("instanton.tech")
        ip = dns.resolve("not-a-valid-domain.com")
        assert ip is None

    def test_is_wildcard_domain(self):
        """Test checking if domain is wildcard."""
        dns = WildcardDNSService("instanton.tech")
        assert dns.is_wildcard_domain("10-0-0-1.instanton.tech") is True
        assert dns.is_wildcard_domain("example.com") is False

    def test_generate_tunnel_domain(self):
        """Test generating tunnel domain."""
        dns = WildcardDNSService("instanton.tech")
        domain = dns.generate_tunnel_domain("192.168.1.1", tunnel_id="abc123")
        assert "192-168-1-1" in domain
        assert "instanton.tech" in domain
        assert "abc123" in domain

    def test_generate_tunnel_domain_with_custom_subdomain(self):
        """Test generating tunnel domain with custom subdomain."""
        dns = WildcardDNSService("instanton.tech")
        domain = dns.generate_tunnel_domain(
            "10.0.0.1",
            subdomain="myapi",
            tunnel_id="xyz"
        )
        assert "myapi" in domain
        assert "10-0-0-1" in domain


# ==============================================================================
# Certificate Generator Tests
# ==============================================================================


class TestCertificateGenerator:
    """Tests for from-scratch certificate generation."""

    def test_generate_ec_p256_key(self):
        """Test generating EC P-256 key."""
        key = CertificateGenerator.generate_private_key(KeyType.EC_P256)
        assert isinstance(key, ec.EllipticCurvePrivateKey)
        assert key.curve.name == "secp256r1"

    def test_generate_ec_p384_key(self):
        """Test generating EC P-384 key."""
        key = CertificateGenerator.generate_private_key(KeyType.EC_P384)
        assert isinstance(key, ec.EllipticCurvePrivateKey)
        assert key.curve.name == "secp384r1"

    def test_generate_rsa_2048_key(self):
        """Test generating RSA 2048 key."""
        key = CertificateGenerator.generate_private_key(KeyType.RSA_2048)
        assert isinstance(key, rsa.RSAPrivateKey)
        assert key.key_size == 2048

    def test_generate_rsa_4096_key(self):
        """Test generating RSA 4096 key."""
        key = CertificateGenerator.generate_private_key(KeyType.RSA_4096)
        assert isinstance(key, rsa.RSAPrivateKey)
        assert key.key_size == 4096

    def test_key_to_pem(self):
        """Test converting key to PEM."""
        key = CertificateGenerator.generate_private_key(KeyType.EC_P256)
        pem = CertificateGenerator.key_to_pem(key)
        assert b"-----BEGIN" in pem
        assert b"PRIVATE KEY-----" in pem

    def test_key_to_pem_encrypted(self):
        """Test converting key to encrypted PEM."""
        key = CertificateGenerator.generate_private_key(KeyType.EC_P256)
        pem = CertificateGenerator.key_to_pem(key, password=b"secret")
        assert b"ENCRYPTED" in pem

    def test_generate_self_signed_ec(self):
        """Test generating self-signed EC certificate."""
        bundle = CertificateGenerator.generate_self_signed(
            domain="test.instanton.tech",
            key_type=KeyType.EC_P256,
        )

        assert bundle.domain == "test.instanton.tech"
        assert bundle.source == CertificateSource.SELF_SIGNED
        assert b"BEGIN CERTIFICATE" in bundle.certificate_pem
        assert b"BEGIN" in bundle.private_key_pem
        assert "test.instanton.tech" in bundle.san_domains
        assert bundle.not_before is not None
        assert bundle.not_after is not None
        assert not bundle.is_expired

    def test_generate_self_signed_rsa(self):
        """Test generating self-signed RSA certificate."""
        bundle = CertificateGenerator.generate_self_signed(
            domain="test.example.com",
            key_type=KeyType.RSA_2048,
        )

        assert bundle.domain == "test.example.com"
        assert b"BEGIN CERTIFICATE" in bundle.certificate_pem

    def test_generate_self_signed_with_sans(self):
        """Test generating certificate with SANs."""
        bundle = CertificateGenerator.generate_self_signed(
            domain="api.instanton.tech",
            san_domains=["www.api.instanton.tech", "v2.api.instanton.tech"],
        )

        assert "api.instanton.tech" in bundle.san_domains
        assert "www.api.instanton.tech" in bundle.san_domains
        assert "v2.api.instanton.tech" in bundle.san_domains

    def test_generate_self_signed_ca(self):
        """Test generating CA certificate."""
        bundle = CertificateGenerator.generate_self_signed(
            domain="Instanton Root CA",
            is_ca=True,
            validity_days=3650,
        )

        # Parse and verify
        cert = x509.load_pem_x509_certificate(bundle.certificate_pem)
        bc_ext = cert.extensions.get_extension_for_oid(
            x509.oid.ExtensionOID.BASIC_CONSTRAINTS
        )
        assert bc_ext.value.ca is True

    def test_generate_csr(self):
        """Test generating CSR."""
        key = CertificateGenerator.generate_private_key(KeyType.EC_P256)
        csr_pem = CertificateGenerator.generate_csr(
            domain="csr.instanton.tech",
            key=key,
            san_domains=["www.csr.instanton.tech"],
        )

        assert b"BEGIN CERTIFICATE REQUEST" in csr_pem

        # Parse CSR
        csr = x509.load_pem_x509_csr(csr_pem)
        cn = csr.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0]
        assert cn.value == "csr.instanton.tech"

    def test_sign_csr_with_ca(self):
        """Test signing CSR with CA."""
        # Generate CA
        ca_bundle = CertificateGenerator.generate_self_signed(
            domain="Test CA",
            is_ca=True,
        )

        # Generate CSR
        key = CertificateGenerator.generate_private_key(KeyType.EC_P256)
        csr_pem = CertificateGenerator.generate_csr(
            domain="signed.instanton.tech",
            key=key,
        )

        # Sign CSR
        cert_pem = CertificateGenerator.sign_csr_with_ca(
            csr_pem=csr_pem,
            ca_cert_pem=ca_bundle.certificate_pem,
            ca_key_pem=ca_bundle.private_key_pem,
        )

        assert b"BEGIN CERTIFICATE" in cert_pem

        # Verify issuer
        cert = x509.load_pem_x509_certificate(cert_pem)
        assert cert.issuer != cert.subject  # Not self-signed

    def test_parse_certificate(self):
        """Test parsing certificate information."""
        bundle = CertificateGenerator.generate_self_signed(
            domain="parse.instanton.tech",
            key_type=KeyType.EC_P256,
        )

        info = CertificateGenerator.parse_certificate(bundle.certificate_pem)

        assert "parse.instanton.tech" in info["subject"]
        assert info["is_self_signed"] is True
        assert "EC" in info["key_type"]
        assert info["fingerprint_sha256"] == bundle.fingerprint_sha256

    def test_certificate_validity(self):
        """Test certificate validity period."""
        bundle = CertificateGenerator.generate_self_signed(
            domain="validity.test",
            validity_days=30,
        )

        assert bundle.days_until_expiry >= 29
        assert bundle.days_until_expiry <= 31
        assert not bundle.is_expired
        # Should need renewal (< 30 days threshold)
        assert bundle.needs_renewal


# ==============================================================================
# Certificate Bundle Tests
# ==============================================================================


class TestCertificateBundle:
    """Tests for CertificateBundle dataclass."""

    def test_is_expired_false(self):
        """Test non-expired certificate."""
        bundle = CertificateBundle(
            domain="test.com",
            certificate_pem=b"cert",
            private_key_pem=b"key",
            not_after=datetime.now(UTC) + timedelta(days=30),
        )
        assert not bundle.is_expired

    def test_is_expired_true(self):
        """Test expired certificate."""
        bundle = CertificateBundle(
            domain="test.com",
            certificate_pem=b"cert",
            private_key_pem=b"key",
            not_after=datetime.now(UTC) - timedelta(days=1),
        )
        assert bundle.is_expired

    def test_days_until_expiry(self):
        """Test days until expiry calculation."""
        bundle = CertificateBundle(
            domain="test.com",
            certificate_pem=b"cert",
            private_key_pem=b"key",
            not_after=datetime.now(UTC) + timedelta(days=45),
        )
        assert 44 <= bundle.days_until_expiry <= 46

    def test_needs_renewal_true(self):
        """Test certificate needs renewal."""
        bundle = CertificateBundle(
            domain="test.com",
            certificate_pem=b"cert",
            private_key_pem=b"key",
            not_after=datetime.now(UTC) + timedelta(days=15),
        )
        assert bundle.needs_renewal

    def test_needs_renewal_false(self):
        """Test certificate doesn't need renewal."""
        bundle = CertificateBundle(
            domain="test.com",
            certificate_pem=b"cert",
            private_key_pem=b"key",
            not_after=datetime.now(UTC) + timedelta(days=60),
        )
        assert not bundle.needs_renewal

    def test_full_chain_with_chain(self):
        """Test full chain PEM with chain."""
        bundle = CertificateBundle(
            domain="test.com",
            certificate_pem=b"cert",
            private_key_pem=b"key",
            chain_pem=b"chain",
        )
        assert bundle.full_chain_pem == b"cert\nchain"

    def test_full_chain_without_chain(self):
        """Test full chain PEM without chain."""
        bundle = CertificateBundle(
            domain="test.com",
            certificate_pem=b"cert",
            private_key_pem=b"key",
        )
        assert bundle.full_chain_pem == b"cert"


# ==============================================================================
# Certificate Store Tests
# ==============================================================================


class TestCertificateStore:
    """Tests for certificate storage."""

    def test_store_and_load(self):
        """Test storing and loading certificates."""
        with tempfile.TemporaryDirectory() as tmpdir:
            store = CertificateStore(Path(tmpdir))

            bundle = CertificateGenerator.generate_self_signed("store.test")
            store.store(bundle)

            loaded = store.load("store.test")
            assert loaded is not None
            assert loaded.domain == "store.test"
            assert loaded.certificate_pem == bundle.certificate_pem

    def test_load_nonexistent(self):
        """Test loading nonexistent certificate."""
        with tempfile.TemporaryDirectory() as tmpdir:
            store = CertificateStore(Path(tmpdir))
            loaded = store.load("nonexistent.test")
            assert loaded is None

    def test_delete(self):
        """Test deleting certificate."""
        with tempfile.TemporaryDirectory() as tmpdir:
            store = CertificateStore(Path(tmpdir))

            bundle = CertificateGenerator.generate_self_signed("delete.test")
            store.store(bundle)

            assert store.load("delete.test") is not None
            assert store.delete("delete.test") is True
            assert store.load("delete.test") is None

    def test_list_domains(self):
        """Test listing stored domains."""
        with tempfile.TemporaryDirectory() as tmpdir:
            store = CertificateStore(Path(tmpdir))

            for domain in ["a.test", "b.test", "c.test"]:
                bundle = CertificateGenerator.generate_self_signed(domain)
                store.store(bundle)

            domains = store.list_domains()
            assert len(domains) == 3
            assert set(domains) == {"a.test", "b.test", "c.test"}

    def test_get_expiring(self):
        """Test getting expiring certificates."""
        with tempfile.TemporaryDirectory() as tmpdir:
            store = CertificateStore(Path(tmpdir))

            # Create expiring cert
            expiring = CertificateGenerator.generate_self_signed(
                "expiring.test",
                validity_days=10,
            )
            store.store(expiring)

            # Create non-expiring cert
            valid = CertificateGenerator.generate_self_signed(
                "valid.test",
                validity_days=90,
            )
            store.store(valid)

            expiring_list = store.get_expiring(days=30)
            assert len(expiring_list) == 1
            assert expiring_list[0].domain == "expiring.test"

    def test_wildcard_domain_storage(self):
        """Test storing wildcard domain certificate."""
        with tempfile.TemporaryDirectory() as tmpdir:
            store = CertificateStore(Path(tmpdir))

            bundle = CertificateGenerator.generate_self_signed("*.instanton.tech")
            store.store(bundle)

            loaded = store.load("*.instanton.tech")
            assert loaded is not None
            assert loaded.domain == "*.instanton.tech"


# ==============================================================================
# Configuration Tests
# ==============================================================================


class TestInstantonDomainConfig:
    """Tests for Instanton domain configuration."""

    def test_default_config(self):
        """Test default configuration."""
        config = InstantonDomainConfig()
        assert config.base_domain == INSTANTON_DOMAIN
        assert config.enable_wildcard is True
        assert config.allow_custom_domains is True

    def test_custom_config(self):
        """Test custom configuration."""
        config = InstantonDomainConfig(
            base_domain="custom.example.com",
            acme_email="admin@example.com",
            use_staging=True,
        )
        assert config.base_domain == "custom.example.com"
        assert config.acme_email == "admin@example.com"
        assert config.use_staging is True


class TestSelfHostedConfig:
    """Tests for self-hosted configuration."""

    def test_default_config(self):
        """Test default self-hosted configuration."""
        config = SelfHostedConfig()
        assert config.domain == ""
        assert config.relay_port == 443
        assert config.use_letsencrypt is True

    def test_custom_config(self):
        """Test custom self-hosted configuration."""
        config = SelfHostedConfig(
            domain="mycompany.com",
            relay_host="relay.mycompany.com",
            relay_port=8443,
            acme_email="admin@mycompany.com",
        )
        assert config.domain == "mycompany.com"
        assert config.relay_host == "relay.mycompany.com"


# ==============================================================================
# AutoTLS Manager Tests
# ==============================================================================


class TestAutoTLSManager:
    """Tests for automatic TLS manager."""

    def test_initialization(self):
        """Test AutoTLS manager initialization."""
        with tempfile.TemporaryDirectory() as tmpdir:
            store = CertificateStore(Path(tmpdir))
            manager = AutoTLSManager(
                store=store,
                acme_email="test@example.com",
                use_staging=True,
            )

            assert manager.acme_email == "test@example.com"
            assert manager.use_staging is True

    def test_can_use_acme_localhost(self):
        """Test ACME cannot be used for localhost."""
        with tempfile.TemporaryDirectory() as tmpdir:
            store = CertificateStore(Path(tmpdir))
            manager = AutoTLSManager(store=store)

            assert manager._can_use_acme("localhost") is False
            assert manager._can_use_acme("127.0.0.1") is False

    def test_can_use_acme_public_domain(self):
        """Test ACME can be used for public domain."""
        with tempfile.TemporaryDirectory() as tmpdir:
            store = CertificateStore(Path(tmpdir))
            manager = AutoTLSManager(store=store, acme_email="test@example.com")

            assert manager._can_use_acme("example.com") is True

    def test_can_use_acme_wildcard_no_dns(self):
        """Test ACME cannot use wildcard without DNS challenge."""
        with tempfile.TemporaryDirectory() as tmpdir:
            store = CertificateStore(Path(tmpdir))
            manager = AutoTLSManager(
                store=store,
                enable_http_challenge=True,
                enable_dns_challenge=False,
            )

            assert manager._can_use_acme("*.example.com") is False

    def test_generate_self_signed(self):
        """Test self-signed certificate generation."""
        with tempfile.TemporaryDirectory() as tmpdir:
            store = CertificateStore(Path(tmpdir))
            manager = AutoTLSManager(store=store)

            bundle = manager._generate_self_signed("test.local")

            assert bundle.domain == "test.local"
            assert bundle.source == CertificateSource.SELF_SIGNED


# ==============================================================================
# Instanton Domain Manager Tests
# ==============================================================================


class TestInstantonDomainManager:
    """Tests for Instanton domain manager."""

    def test_initialization(self):
        """Test domain manager initialization."""
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = InstantonDomainManager(
                cert_store_path=Path(tmpdir),
            )

            assert manager.config.base_domain == INSTANTON_DOMAIN
            assert manager.wildcard_dns is not None
            assert manager.cert_store is not None

    def test_register_self_hosted(self):
        """Test registering self-hosted deployment."""
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = InstantonDomainManager(cert_store_path=Path(tmpdir))

            config = SelfHostedConfig(
                domain="myapp.example.com",
                relay_host="relay.example.com",
            )

            config_id = manager.register_self_hosted(config)

            assert config_id is not None
            assert len(config_id) == 32  # Hex string

    def test_unregister_self_hosted(self):
        """Test unregistering self-hosted deployment."""
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = InstantonDomainManager(cert_store_path=Path(tmpdir))

            config = SelfHostedConfig(domain="test.example.com")
            config_id = manager.register_self_hosted(config)

            assert manager.unregister_self_hosted(config_id) is True
            assert manager.unregister_self_hosted(config_id) is False


# ==============================================================================
# Integration Tests
# ==============================================================================


class TestIntegration:
    """Integration tests for the certificate management system."""

    def test_full_workflow_self_signed(self):
        """Test complete workflow with self-signed certificates."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Setup
            store = CertificateStore(Path(tmpdir))

            # Generate certificate
            bundle = CertificateGenerator.generate_self_signed(
                domain="workflow.instanton.tech",
                key_type=KeyType.EC_P256,
                validity_days=90,
            )

            # Store
            store.store(bundle)

            # Load
            loaded = store.load("workflow.instanton.tech")
            assert loaded is not None

            # Verify
            info = CertificateGenerator.parse_certificate(loaded.certificate_pem)
            assert "workflow.instanton.tech" in info["subject"]

    def test_wildcard_dns_with_certs(self):
        """Test wildcard DNS with certificate generation."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Generate tunnel domain
            dns = WildcardDNSService("instanton.tech")
            domain = dns.generate_tunnel_domain("192.168.1.100", subdomain="api")

            # Generate certificate for tunnel domain
            bundle = CertificateGenerator.generate_self_signed(domain)

            # Store
            store = CertificateStore(Path(tmpdir))
            store.store(bundle)

            # Verify domain can be resolved
            ip = dns.resolve(domain)
            assert ip == "192.168.1.100"

    def test_ca_signed_certificate_chain(self):
        """Test CA-signed certificate chain."""
        # Generate Root CA
        root_ca = CertificateGenerator.generate_self_signed(
            domain="Instanton Root CA",
            is_ca=True,
            validity_days=3650,
        )

        # Generate end-entity key and CSR
        ee_key = CertificateGenerator.generate_private_key(KeyType.EC_P256)
        csr = CertificateGenerator.generate_csr(
            domain="signed.instanton.tech",
            key=ee_key,
        )

        # Sign with CA
        signed_cert = CertificateGenerator.sign_csr_with_ca(
            csr_pem=csr,
            ca_cert_pem=root_ca.certificate_pem,
            ca_key_pem=root_ca.private_key_pem,
        )

        # Parse and verify chain
        cert = x509.load_pem_x509_certificate(signed_cert)
        ca_cert = x509.load_pem_x509_certificate(root_ca.certificate_pem)

        assert cert.issuer == ca_cert.subject
        assert cert.issuer != cert.subject  # Not self-signed
