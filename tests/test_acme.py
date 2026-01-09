"""Tests for ACME (Let's Encrypt) certificate management."""

import asyncio
import base64
import hashlib
import json
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

from instanton.security.acme import (
    ACMEAccount,
    ACMEAuthorization,
    ACMEChallenge,
    ACMEDirectory,
    ACMEOrder,
    AuthorizationStatus,
    CaddyConfig,
    CaddyManager,
    CertificateAutoRenewal,
    CertificateResult,
    ChallengeType,
    CloudflareDNSProvider,
    FullACMEClient,
    HostingerDNSProvider,
    HTTP01ChallengeServer,
    ManualDNSProvider,
    OrderStatus,
    WildcardDNSConfig,
    _b64url_decode,
    _b64url_encode,
    _get_jwk,
    _get_jwk_thumbprint,
    _sign_jws,
    get_nip_domain,
    get_sslip_domain,
)


# ==============================================================================
# Base64URL Encoding Tests
# ==============================================================================


class TestBase64URLEncoding:
    """Tests for base64url encoding/decoding."""

    def test_b64url_encode_simple(self):
        """Test encoding simple data."""
        data = b"hello world"
        encoded = _b64url_encode(data)
        assert isinstance(encoded, str)
        assert "=" not in encoded  # No padding
        assert "+" not in encoded  # URL-safe
        assert "/" not in encoded  # URL-safe

    def test_b64url_decode_simple(self):
        """Test decoding simple data."""
        data = b"hello world"
        encoded = _b64url_encode(data)
        decoded = _b64url_decode(encoded)
        assert decoded == data

    def test_b64url_roundtrip(self):
        """Test encoding and decoding roundtrip."""
        test_data = [
            b"",
            b"a",
            b"ab",
            b"abc",
            b"abcd",
            b"\x00\x01\x02\x03",
            b"test data with spaces",
            b"\xff\xfe\xfd\xfc",
        ]
        for data in test_data:
            encoded = _b64url_encode(data)
            decoded = _b64url_decode(encoded)
            assert decoded == data, f"Failed for {data!r}"


# ==============================================================================
# JWK Tests
# ==============================================================================


class TestJWK:
    """Tests for JWK (JSON Web Key) operations."""

    def test_ec_key_jwk(self):
        """Test JWK generation for EC key."""
        private_key = ec.generate_private_key(ec.SECP256R1())
        jwk = _get_jwk(private_key)

        assert jwk["kty"] == "EC"
        assert jwk["crv"] == "P-256"
        assert "x" in jwk
        assert "y" in jwk
        # x and y should be 32 bytes = 43 base64url chars
        assert len(jwk["x"]) == 43
        assert len(jwk["y"]) == 43

    def test_ec_384_key_jwk(self):
        """Test JWK generation for EC P-384 key."""
        private_key = ec.generate_private_key(ec.SECP384R1())
        jwk = _get_jwk(private_key)

        assert jwk["crv"] == "P-384"
        # 48 bytes = 64 base64url chars
        assert len(jwk["x"]) == 64
        assert len(jwk["y"]) == 64

    def test_rsa_key_jwk(self):
        """Test JWK generation for RSA key."""
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        jwk = _get_jwk(private_key)

        assert jwk["kty"] == "RSA"
        assert "n" in jwk
        assert "e" in jwk

    def test_jwk_thumbprint_ec(self):
        """Test JWK thumbprint calculation for EC key."""
        private_key = ec.generate_private_key(ec.SECP256R1())
        jwk = _get_jwk(private_key)
        thumbprint = _get_jwk_thumbprint(jwk)

        # Thumbprint should be SHA256 hash = 32 bytes = 43 base64url chars
        assert len(thumbprint) == 43
        # Should be deterministic
        assert _get_jwk_thumbprint(jwk) == thumbprint

    def test_jwk_thumbprint_rsa(self):
        """Test JWK thumbprint calculation for RSA key."""
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        jwk = _get_jwk(private_key)
        thumbprint = _get_jwk_thumbprint(jwk)

        assert len(thumbprint) == 43


# ==============================================================================
# JWS Signing Tests
# ==============================================================================


class TestJWSSigning:
    """Tests for JWS (JSON Web Signature) operations."""

    def test_sign_jws_ec(self):
        """Test JWS signing with EC key."""
        private_key = ec.generate_private_key(ec.SECP256R1())

        protected = {
            "alg": "ES256",
            "nonce": "test-nonce",
            "url": "https://example.com/test",
            "jwk": _get_jwk(private_key),
        }
        payload = {"test": "data"}

        jws = _sign_jws(private_key, protected, payload)

        assert "protected" in jws
        assert "payload" in jws
        assert "signature" in jws

    def test_sign_jws_rsa(self):
        """Test JWS signing with RSA key."""
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        protected = {
            "alg": "RS256",
            "nonce": "test-nonce",
            "url": "https://example.com/test",
            "jwk": _get_jwk(private_key),
        }
        payload = {"test": "data"}

        jws = _sign_jws(private_key, protected, payload)

        assert "protected" in jws
        assert "payload" in jws
        assert "signature" in jws

    def test_sign_jws_empty_payload(self):
        """Test JWS signing with empty payload (POST-as-GET)."""
        private_key = ec.generate_private_key(ec.SECP256R1())

        protected = {
            "alg": "ES256",
            "kid": "https://example.com/account/123",
            "nonce": "test-nonce",
            "url": "https://example.com/test",
        }

        jws = _sign_jws(private_key, protected, "")

        assert jws["payload"] == ""


# ==============================================================================
# sslip.io / nip.io Domain Tests
# ==============================================================================


class TestWildcardDNS:
    """Tests for wildcard DNS domain generation."""

    def test_sslip_domain_basic(self):
        """Test basic sslip.io domain generation."""
        domain = get_sslip_domain("192.168.1.1")
        assert domain == "192-168-1-1.sslip.io"

    def test_sslip_domain_with_subdomain(self):
        """Test sslip.io domain with subdomain."""
        domain = get_sslip_domain("192.168.1.1", "myapp")
        assert domain == "myapp.192-168-1-1.sslip.io"

    def test_nip_domain_basic(self):
        """Test basic nip.io domain generation."""
        domain = get_nip_domain("10.0.0.1")
        assert domain == "10.0.0.1.nip.io"

    def test_nip_domain_with_subdomain(self):
        """Test nip.io domain with subdomain."""
        domain = get_nip_domain("10.0.0.1", "api")
        assert domain == "api.10.0.0.1.nip.io"

    def test_wildcard_dns_config(self):
        """Test WildcardDNSConfig."""
        config = WildcardDNSConfig(
            service="sslip.io",
            base_ip="203.0.113.42",
            custom_subdomain="tunnel",
        )
        assert config.domain == "tunnel.203-0-113-42.sslip.io"

    def test_wildcard_dns_config_no_subdomain(self):
        """Test WildcardDNSConfig without subdomain."""
        config = WildcardDNSConfig(
            service="sslip.io",
            base_ip="203.0.113.42",
        )
        assert config.domain == "203-0-113-42.sslip.io"


# ==============================================================================
# ACME Directory Tests
# ==============================================================================


class TestACMEDirectory:
    """Tests for ACME directory enum."""

    def test_letsencrypt_production(self):
        """Test Let's Encrypt production URL."""
        assert "acme-v02.api.letsencrypt.org" in ACMEDirectory.LETSENCRYPT_PRODUCTION.value

    def test_letsencrypt_staging(self):
        """Test Let's Encrypt staging URL."""
        assert "staging" in ACMEDirectory.LETSENCRYPT_STAGING.value

    def test_zerossl(self):
        """Test ZeroSSL URL."""
        assert "zerossl.com" in ACMEDirectory.ZEROSSL.value


# ==============================================================================
# Challenge Type Tests
# ==============================================================================


class TestChallengeType:
    """Tests for ACME challenge types."""

    def test_challenge_values(self):
        """Test challenge type values."""
        assert ChallengeType.HTTP_01.value == "http-01"
        assert ChallengeType.DNS_01.value == "dns-01"
        assert ChallengeType.TLS_ALPN_01.value == "tls-alpn-01"


# ==============================================================================
# Data Class Tests
# ==============================================================================


class TestDataClasses:
    """Tests for ACME data classes."""

    def test_acme_challenge(self):
        """Test ACMEChallenge dataclass."""
        challenge = ACMEChallenge(
            type=ChallengeType.HTTP_01,
            url="https://acme.example.com/challenge/123",
            token="abc123token",
            status="pending",
            key_authorization="abc123token.thumbprint",
        )
        assert challenge.type == ChallengeType.HTTP_01
        assert challenge.token == "abc123token"

    def test_acme_authorization(self):
        """Test ACMEAuthorization dataclass."""
        authz = ACMEAuthorization(
            identifier="example.com",
            identifier_type="dns",
            status=AuthorizationStatus.PENDING,
            expires=datetime.now(UTC) + timedelta(days=7),
            challenges=[],
        )
        assert authz.identifier == "example.com"
        assert authz.status == AuthorizationStatus.PENDING

    def test_acme_order(self):
        """Test ACMEOrder dataclass."""
        order = ACMEOrder(
            url="https://acme.example.com/order/123",
            status=OrderStatus.PENDING,
            expires=datetime.now(UTC) + timedelta(days=7),
            identifiers=[{"type": "dns", "value": "example.com"}],
            authorizations=["https://acme.example.com/authz/456"],
            finalize_url="https://acme.example.com/finalize/123",
        )
        assert order.status == OrderStatus.PENDING
        assert len(order.identifiers) == 1

    def test_acme_account(self):
        """Test ACMEAccount dataclass."""
        account = ACMEAccount(
            url="https://acme.example.com/account/123",
            status="valid",
            contact=["mailto:admin@example.com"],
        )
        assert account.status == "valid"
        assert "mailto:admin@example.com" in account.contact

    def test_certificate_result(self):
        """Test CertificateResult dataclass."""
        now = datetime.now(UTC)
        result = CertificateResult(
            certificate_pem=b"-----BEGIN CERTIFICATE-----\n...",
            private_key_pem=b"-----BEGIN PRIVATE KEY-----\n...",
            chain_pem=b"-----BEGIN CERTIFICATE-----\n...",
            domains=["example.com", "www.example.com"],
            not_before=now,
            not_after=now + timedelta(days=90),
            issuer="CN=Let's Encrypt Authority X3",
        )
        assert len(result.domains) == 2
        assert result.issuer.startswith("CN=")


# ==============================================================================
# Manual DNS Provider Tests
# ==============================================================================


class TestManualDNSProvider:
    """Tests for ManualDNSProvider."""

    @pytest.mark.asyncio
    async def test_create_txt_record(self):
        """Test creating a TXT record."""
        records = []

        def callback(domain, name, value):
            records.append((domain, name, value))

        provider = ManualDNSProvider(callback=callback)
        record_id = await provider.create_txt_record(
            "example.com",
            "_acme-challenge",
            "test-value",
        )

        assert record_id.startswith("manual-")
        assert len(records) == 1
        assert records[0] == ("example.com", "_acme-challenge", "test-value")

    @pytest.mark.asyncio
    async def test_delete_txt_record(self):
        """Test deleting a TXT record."""
        provider = ManualDNSProvider()
        record_id = await provider.create_txt_record(
            "example.com",
            "_acme-challenge",
            "test-value",
        )

        result = await provider.delete_txt_record("example.com", record_id)
        assert result is True


# ==============================================================================
# HTTP-01 Challenge Server Tests
# ==============================================================================


class TestHTTP01ChallengeServer:
    """Tests for HTTP-01 challenge server."""

    def test_add_remove_challenge(self):
        """Test adding and removing challenges."""
        server = HTTP01ChallengeServer()
        server.add_challenge("test-token", "test-key-auth")

        assert "test-token" in server._challenges
        assert server._challenges["test-token"] == "test-key-auth"

        server.remove_challenge("test-token")
        assert "test-token" not in server._challenges


# ==============================================================================
# ACME Client Tests
# ==============================================================================


class TestFullACMEClient:
    """Tests for the full ACME client."""

    def test_client_initialization(self):
        """Test client initialization."""
        client = FullACMEClient(
            email="admin@example.com",
            directory=ACMEDirectory.LETSENCRYPT_STAGING,
        )
        assert client.email == "admin@example.com"
        assert "staging" in client.directory_url

    def test_client_with_account_key_path(self):
        """Test client with account key path."""
        with tempfile.TemporaryDirectory() as tmpdir:
            key_path = Path(tmpdir) / "account.key"

            client = FullACMEClient(
                email="admin@example.com",
                account_key_path=key_path,
            )
            assert client.account_key_path == key_path

    def test_load_or_create_account_key_new(self):
        """Test creating a new account key."""
        with tempfile.TemporaryDirectory() as tmpdir:
            key_path = Path(tmpdir) / "account.key"

            client = FullACMEClient(
                email="admin@example.com",
                account_key_path=key_path,
                key_type="EC",
            )

            key = client._load_or_create_account_key()

            assert isinstance(key, ec.EllipticCurvePrivateKey)
            assert key_path.exists()

    def test_load_or_create_account_key_existing(self):
        """Test loading an existing account key."""
        with tempfile.TemporaryDirectory() as tmpdir:
            key_path = Path(tmpdir) / "account.key"

            # Create key first
            original_key = ec.generate_private_key(ec.SECP256R1())
            key_pem = original_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
            key_path.write_bytes(key_pem)

            client = FullACMEClient(
                email="admin@example.com",
                account_key_path=key_path,
            )

            loaded_key = client._load_or_create_account_key()

            # Keys should have same public key
            orig_pub = original_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            loaded_pub = loaded_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            assert orig_pub == loaded_pub

    def test_create_csr(self):
        """Test CSR creation."""
        client = FullACMEClient(email="admin@example.com")
        private_key = ec.generate_private_key(ec.SECP256R1())

        domains = ["example.com", "www.example.com"]
        csr = client._create_csr(domains, private_key)

        assert isinstance(csr, x509.CertificateSigningRequest)

        # Check CN
        cn = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0]
        assert cn.value == "example.com"

        # Check SANs
        san_ext = csr.extensions.get_extension_for_oid(
            x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        )
        san_names = [name.value for name in san_ext.value if isinstance(name, x509.DNSName)]
        assert "example.com" in san_names
        assert "www.example.com" in san_names


# ==============================================================================
# Caddy Integration Tests
# ==============================================================================


class TestCaddyConfig:
    """Tests for Caddy configuration."""

    def test_default_config(self):
        """Test default Caddy configuration."""
        config = CaddyConfig()
        assert config.admin_api == "http://localhost:2019"
        assert config.on_demand_tls is False

    def test_custom_config(self):
        """Test custom Caddy configuration."""
        config = CaddyConfig(
            admin_api="http://127.0.0.1:2019",
            email="admin@example.com",
            acme_ca=ACMEDirectory.LETSENCRYPT_STAGING.value,
            on_demand_tls=True,
        )
        assert config.email == "admin@example.com"
        assert "staging" in config.acme_ca


class TestCaddyManager:
    """Tests for Caddy manager."""

    @pytest.mark.asyncio
    async def test_configure_domain_mock(self):
        """Test configuring a domain with mocked API."""
        config = CaddyConfig(email="admin@example.com")
        manager = CaddyManager(config)

        with patch("httpx.AsyncClient") as mock_client:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_client.return_value.__aenter__.return_value.post = AsyncMock(
                return_value=mock_response
            )

            result = await manager.configure_domain(
                "example.com",
                "localhost:8000",
            )

            # The mock should have been called
            assert mock_client.called


# ==============================================================================
# Certificate Auto-Renewal Tests
# ==============================================================================


class TestCertificateAutoRenewal:
    """Tests for certificate auto-renewal."""

    def test_register_domain(self):
        """Test registering a domain for renewal."""
        with tempfile.TemporaryDirectory() as tmpdir:
            client = MagicMock(spec=FullACMEClient)
            manager = CertificateAutoRenewal(
                acme_client=client,
                cert_store_path=Path(tmpdir),
            )

            expiry = datetime.now(UTC) + timedelta(days=60)
            manager.register_domain("example.com", expiry)

            assert "example.com" in manager._domains
            assert manager._domains["example.com"] == expiry


# ==============================================================================
# Cloudflare DNS Provider Tests
# ==============================================================================


class TestCloudflareDNSProvider:
    """Tests for Cloudflare DNS provider."""

    def test_init_with_token(self):
        """Test initialization with API token."""
        provider = CloudflareDNSProvider(api_token="test-token")
        headers = provider._get_headers()

        assert "Authorization" in headers
        assert headers["Authorization"] == "Bearer test-token"

    def test_init_with_key(self):
        """Test initialization with API key and email."""
        provider = CloudflareDNSProvider(
            api_key="test-key",
            email="admin@example.com",
        )
        headers = provider._get_headers()

        assert "X-Auth-Key" in headers
        assert "X-Auth-Email" in headers

    def test_init_without_credentials(self):
        """Test initialization without credentials raises error."""
        provider = CloudflareDNSProvider()

        with pytest.raises(ValueError, match="API token or API key"):
            provider._get_headers()


# ==============================================================================
# Hostinger DNS Provider Tests
# ==============================================================================


class TestHostingerDNSProvider:
    """Tests for Hostinger DNS provider."""

    def test_init(self):
        """Test initialization."""
        provider = HostingerDNSProvider(api_key="test-key")
        headers = provider._get_headers()

        assert "Authorization" in headers
        assert "Bearer test-key" in headers["Authorization"]


# ==============================================================================
# Integration Smoke Tests
# ==============================================================================


class TestIntegrationSmoke:
    """Smoke tests for integration scenarios."""

    def test_full_workflow_mock(self):
        """Test the conceptual workflow (without actual ACME calls)."""
        # This test verifies the API surface works correctly
        client = FullACMEClient(
            email="admin@example.com",
            directory=ACMEDirectory.LETSENCRYPT_STAGING,
        )

        # Verify client has required methods
        assert hasattr(client, "initialize")
        assert hasattr(client, "create_order")
        assert hasattr(client, "get_authorization")
        assert hasattr(client, "respond_to_challenge")
        assert hasattr(client, "finalize_order")
        assert hasattr(client, "download_certificate")
        assert hasattr(client, "obtain_certificate")

    def test_dns_provider_interface(self):
        """Test DNS provider interface compliance."""
        providers = [
            ManualDNSProvider(),
            CloudflareDNSProvider(api_token="test"),
            HostingerDNSProvider(api_key="test"),
        ]

        for provider in providers:
            assert hasattr(provider, "create_txt_record")
            assert hasattr(provider, "delete_txt_record")
            assert hasattr(provider, "wait_for_propagation")

    def test_caddy_manager_interface(self):
        """Test Caddy manager interface."""
        config = CaddyConfig()
        manager = CaddyManager(config)

        assert hasattr(manager, "configure_domain")
        assert hasattr(manager, "add_route")
        assert hasattr(manager, "remove_route")
        assert hasattr(manager, "get_certificate_info")
