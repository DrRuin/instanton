"""Tests for the custom domains module."""

from __future__ import annotations

import json
import tempfile
from datetime import datetime
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from instanton.domains import (
    DomainManager,
    DomainRegistration,
    DomainStatus,
    DomainStore,
    DNSVerifier,
    VerificationResult,
)
from instanton.domains.verification import VerificationStatus


class TestDomainRegistration:
    """Tests for DomainRegistration dataclass."""

    def test_to_dict(self):
        """Test serialization to dictionary."""
        reg = DomainRegistration(
            domain="api.example.com",
            tunnel_id="tunnel-123",
            verification_token="verify=abc123",
            verified=True,
            verified_at=datetime(2024, 1, 15, 10, 30, 0),
            created_at=datetime(2024, 1, 15, 10, 0, 0),
            certificate_path="/certs/api.example.com.pem",
        )

        data = reg.to_dict()

        assert data["domain"] == "api.example.com"
        assert data["tunnel_id"] == "tunnel-123"
        assert data["verification_token"] == "verify=abc123"
        assert data["verified"] is True
        assert data["verified_at"] == "2024-01-15T10:30:00"
        assert data["created_at"] == "2024-01-15T10:00:00"
        assert data["certificate_path"] == "/certs/api.example.com.pem"

    def test_from_dict(self):
        """Test deserialization from dictionary."""
        data = {
            "domain": "api.example.com",
            "tunnel_id": "tunnel-123",
            "verification_token": "verify=abc123",
            "verified": True,
            "verified_at": "2024-01-15T10:30:00",
            "created_at": "2024-01-15T10:00:00",
            "certificate_path": "/certs/api.example.com.pem",
        }

        reg = DomainRegistration.from_dict(data)

        assert reg.domain == "api.example.com"
        assert reg.tunnel_id == "tunnel-123"
        assert reg.verification_token == "verify=abc123"
        assert reg.verified is True
        assert reg.verified_at == datetime(2024, 1, 15, 10, 30, 0)
        assert reg.created_at == datetime(2024, 1, 15, 10, 0, 0)
        assert reg.certificate_path == "/certs/api.example.com.pem"

    def test_from_dict_minimal(self):
        """Test deserialization with minimal data."""
        data = {
            "domain": "api.example.com",
            "tunnel_id": "tunnel-123",
            "verification_token": "verify=abc123",
        }

        reg = DomainRegistration.from_dict(data)

        assert reg.domain == "api.example.com"
        assert reg.verified is False
        assert reg.verified_at is None
        assert reg.certificate_path is None


class TestDomainStore:
    """Tests for DomainStore JSON storage."""

    @pytest.fixture
    def temp_storage(self):
        """Create a temporary storage file."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write("{}")
            return Path(f.name)

    @pytest.mark.asyncio
    async def test_save_and_get(self, temp_storage):
        """Test saving and retrieving a domain."""
        store = DomainStore(temp_storage)

        reg = DomainRegistration(
            domain="api.example.com",
            tunnel_id="tunnel-123",
            verification_token="verify=abc123",
        )

        await store.save(reg)
        retrieved = await store.get("api.example.com")

        assert retrieved is not None
        assert retrieved.domain == "api.example.com"
        assert retrieved.tunnel_id == "tunnel-123"

    @pytest.mark.asyncio
    async def test_get_nonexistent(self, temp_storage):
        """Test getting a domain that doesn't exist."""
        store = DomainStore(temp_storage)

        result = await store.get("nonexistent.example.com")

        assert result is None

    @pytest.mark.asyncio
    async def test_delete(self, temp_storage):
        """Test deleting a domain."""
        store = DomainStore(temp_storage)

        reg = DomainRegistration(
            domain="api.example.com",
            tunnel_id="tunnel-123",
            verification_token="verify=abc123",
        )
        await store.save(reg)

        deleted = await store.delete("api.example.com")
        assert deleted is True

        retrieved = await store.get("api.example.com")
        assert retrieved is None

    @pytest.mark.asyncio
    async def test_delete_nonexistent(self, temp_storage):
        """Test deleting a domain that doesn't exist."""
        store = DomainStore(temp_storage)

        deleted = await store.delete("nonexistent.example.com")
        assert deleted is False

    @pytest.mark.asyncio
    async def test_list_all(self, temp_storage):
        """Test listing all domains."""
        store = DomainStore(temp_storage)

        reg1 = DomainRegistration(
            domain="api1.example.com",
            tunnel_id="tunnel-1",
            verification_token="verify=1",
        )
        reg2 = DomainRegistration(
            domain="api2.example.com",
            tunnel_id="tunnel-2",
            verification_token="verify=2",
        )

        await store.save(reg1)
        await store.save(reg2)

        all_domains = await store.list_all()

        assert len(all_domains) == 2
        domains = {d.domain for d in all_domains}
        assert "api1.example.com" in domains
        assert "api2.example.com" in domains

    @pytest.mark.asyncio
    async def test_get_by_tunnel(self, temp_storage):
        """Test filtering domains by tunnel ID."""
        store = DomainStore(temp_storage)

        reg1 = DomainRegistration(
            domain="api1.example.com",
            tunnel_id="tunnel-1",
            verification_token="verify=1",
        )
        reg2 = DomainRegistration(
            domain="api2.example.com",
            tunnel_id="tunnel-1",
            verification_token="verify=2",
        )
        reg3 = DomainRegistration(
            domain="api3.example.com",
            tunnel_id="tunnel-2",
            verification_token="verify=3",
        )

        await store.save(reg1)
        await store.save(reg2)
        await store.save(reg3)

        tunnel1_domains = await store.get_by_tunnel("tunnel-1")

        assert len(tunnel1_domains) == 2
        domains = {d.domain for d in tunnel1_domains}
        assert "api1.example.com" in domains
        assert "api2.example.com" in domains

    @pytest.mark.asyncio
    async def test_list_verified(self, temp_storage):
        """Test listing only verified domains."""
        store = DomainStore(temp_storage)

        reg1 = DomainRegistration(
            domain="api1.example.com",
            tunnel_id="tunnel-1",
            verification_token="verify=1",
            verified=True,
        )
        reg2 = DomainRegistration(
            domain="api2.example.com",
            tunnel_id="tunnel-2",
            verification_token="verify=2",
            verified=False,
        )

        await store.save(reg1)
        await store.save(reg2)

        verified = await store.list_verified()

        assert len(verified) == 1
        assert verified[0].domain == "api1.example.com"

    @pytest.mark.asyncio
    async def test_exists(self, temp_storage):
        """Test checking if a domain exists."""
        store = DomainStore(temp_storage)

        reg = DomainRegistration(
            domain="api.example.com",
            tunnel_id="tunnel-123",
            verification_token="verify=abc123",
        )
        await store.save(reg)

        assert await store.exists("api.example.com") is True
        assert await store.exists("other.example.com") is False

    @pytest.mark.asyncio
    async def test_persistence(self, temp_storage):
        """Test that data persists across store instances."""
        store1 = DomainStore(temp_storage)

        reg = DomainRegistration(
            domain="api.example.com",
            tunnel_id="tunnel-123",
            verification_token="verify=abc123",
        )
        await store1.save(reg)

        # Create new store instance pointing to same file
        store2 = DomainStore(temp_storage)
        retrieved = await store2.get("api.example.com")

        assert retrieved is not None
        assert retrieved.domain == "api.example.com"


class TestDNSVerifier:
    """Tests for DNSVerifier."""

    def test_generate_verification_token(self):
        """Test verification token generation."""
        verifier = DNSVerifier("instanton.tech")

        token1 = verifier.generate_verification_token("api.example.com")
        token2 = verifier.generate_verification_token("api.example.com")

        # Tokens should start with "verify="
        assert token1.startswith("verify=")
        assert token2.startswith("verify=")

        # Tokens should be different (random salt)
        assert token1 != token2

        # Token should have reasonable length
        assert len(token1) > 10

    @pytest.mark.asyncio
    async def test_verify_cname_valid(self):
        """Test CNAME verification with valid record."""
        verifier = DNSVerifier("instanton.tech")

        # Mock the resolver
        mock_result = MagicMock()
        mock_result.cname = "instanton.tech."

        with patch.object(verifier, "_get_resolver") as mock_get_resolver:
            mock_resolver = AsyncMock()
            mock_resolver.query_dns = AsyncMock(return_value=mock_result)
            mock_get_resolver.return_value = mock_resolver

            is_valid, target = await verifier.verify_cname("api.example.com")

            assert is_valid is True
            assert target == "instanton.tech"

    @pytest.mark.asyncio
    async def test_verify_cname_invalid_target(self):
        """Test CNAME verification with wrong target."""
        verifier = DNSVerifier("instanton.tech")

        mock_result = MagicMock()
        mock_result.cname = "other-domain.com."

        with patch.object(verifier, "_get_resolver") as mock_get_resolver:
            mock_resolver = AsyncMock()
            mock_resolver.query_dns = AsyncMock(return_value=mock_result)
            mock_get_resolver.return_value = mock_resolver

            is_valid, target = await verifier.verify_cname("api.example.com")

            assert is_valid is False
            assert target == "other-domain.com"

    @pytest.mark.asyncio
    async def test_verify_txt_record_valid(self):
        """Test TXT record verification with valid record."""
        verifier = DNSVerifier("instanton.tech")

        mock_record = MagicMock()
        mock_record.text = "verify=abc123"

        with patch.object(verifier, "_get_resolver") as mock_get_resolver:
            mock_resolver = AsyncMock()
            mock_resolver.query_dns = AsyncMock(return_value=[mock_record])
            mock_get_resolver.return_value = mock_resolver

            is_valid, value = await verifier.verify_txt_record(
                "api.example.com", "verify=abc123"
            )

            assert is_valid is True
            assert value == "verify=abc123"

    @pytest.mark.asyncio
    async def test_verify_txt_record_wrong_value(self):
        """Test TXT record verification with wrong value."""
        verifier = DNSVerifier("instanton.tech")

        mock_record = MagicMock()
        mock_record.text = "verify=wrongvalue"

        with patch.object(verifier, "_get_resolver") as mock_get_resolver:
            mock_resolver = AsyncMock()
            mock_resolver.query_dns = AsyncMock(return_value=[mock_record])
            mock_get_resolver.return_value = mock_resolver

            is_valid, value = await verifier.verify_txt_record(
                "api.example.com", "verify=abc123"
            )

            assert is_valid is False
            assert value == "verify=wrongvalue"


class TestVerificationResult:
    """Tests for VerificationResult."""

    def test_is_verified_true(self):
        """Test is_verified property when fully verified."""
        result = VerificationResult(
            domain="api.example.com",
            status=VerificationStatus.FULLY_VERIFIED,
            cname_valid=True,
            cname_target="instanton.tech",
            txt_valid=True,
            txt_value="verify=abc123",
        )

        assert result.is_verified is True

    def test_is_verified_false(self):
        """Test is_verified property when not fully verified."""
        result = VerificationResult(
            domain="api.example.com",
            status=VerificationStatus.CNAME_VERIFIED,
            cname_valid=True,
            cname_target="instanton.tech",
            txt_valid=False,
            txt_value=None,
        )

        assert result.is_verified is False


class TestDomainManager:
    """Tests for DomainManager."""

    @pytest.fixture
    def temp_storage(self):
        """Create a temporary storage file."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write("{}")
            return Path(f.name)

    @pytest.mark.asyncio
    async def test_register_domain(self, temp_storage):
        """Test registering a new domain."""
        store = DomainStore(temp_storage)
        manager = DomainManager(store, "instanton.tech")

        registration = await manager.register_domain("api.example.com", "tunnel-123")

        assert registration.domain == "api.example.com"
        assert registration.tunnel_id == "tunnel-123"
        assert registration.verification_token.startswith("verify=")
        assert registration.verified is False

    @pytest.mark.asyncio
    async def test_register_domain_duplicate_same_tunnel(self, temp_storage):
        """Test registering same domain for same tunnel returns existing."""
        store = DomainStore(temp_storage)
        manager = DomainManager(store, "instanton.tech")

        reg1 = await manager.register_domain("api.example.com", "tunnel-123")
        reg2 = await manager.register_domain("api.example.com", "tunnel-123")

        assert reg1.verification_token == reg2.verification_token

    @pytest.mark.asyncio
    async def test_register_domain_duplicate_different_tunnel(self, temp_storage):
        """Test registering same domain for different tunnel raises error."""
        store = DomainStore(temp_storage)
        manager = DomainManager(store, "instanton.tech")

        await manager.register_domain("api.example.com", "tunnel-123")

        with pytest.raises(ValueError, match="already registered"):
            await manager.register_domain("api.example.com", "tunnel-456")

    @pytest.mark.asyncio
    async def test_get_tunnel_for_domain_verified(self, temp_storage):
        """Test getting tunnel for a verified domain."""
        store = DomainStore(temp_storage)
        manager = DomainManager(store, "instanton.tech")

        # Create verified registration
        reg = DomainRegistration(
            domain="api.example.com",
            tunnel_id="tunnel-123",
            verification_token="verify=abc123",
            verified=True,
        )
        await store.save(reg)

        tunnel_id = await manager.get_tunnel_for_domain("api.example.com")

        assert tunnel_id == "tunnel-123"

    @pytest.mark.asyncio
    async def test_get_tunnel_for_domain_unverified(self, temp_storage):
        """Test getting tunnel for an unverified domain returns None."""
        store = DomainStore(temp_storage)
        manager = DomainManager(store, "instanton.tech")

        reg = DomainRegistration(
            domain="api.example.com",
            tunnel_id="tunnel-123",
            verification_token="verify=abc123",
            verified=False,
        )
        await store.save(reg)

        tunnel_id = await manager.get_tunnel_for_domain("api.example.com")

        assert tunnel_id is None

    @pytest.mark.asyncio
    async def test_delete_domain(self, temp_storage):
        """Test deleting a domain."""
        store = DomainStore(temp_storage)
        manager = DomainManager(store, "instanton.tech")

        await manager.register_domain("api.example.com", "tunnel-123")
        deleted = await manager.delete_domain("api.example.com")

        assert deleted is True
        assert await store.get("api.example.com") is None

    @pytest.mark.asyncio
    async def test_list_domains(self, temp_storage):
        """Test listing domains."""
        store = DomainStore(temp_storage)
        manager = DomainManager(store, "instanton.tech")

        await manager.register_domain("api1.example.com", "tunnel-1")
        await manager.register_domain("api2.example.com", "tunnel-2")

        all_domains = await manager.list_domains()
        assert len(all_domains) == 2

        tunnel1_domains = await manager.list_domains("tunnel-1")
        assert len(tunnel1_domains) == 1
        assert tunnel1_domains[0].domain == "api1.example.com"

    @pytest.mark.asyncio
    async def test_get_domain_status_not_found(self, temp_storage):
        """Test getting status for nonexistent domain."""
        store = DomainStore(temp_storage)
        manager = DomainManager(store, "instanton.tech")

        info = await manager.get_domain_status("nonexistent.example.com")

        assert info.status == DomainStatus.NOT_FOUND
        assert info.tunnel_id is None

    @pytest.mark.asyncio
    async def test_domain_case_insensitive(self, temp_storage):
        """Test that domain lookups are case-insensitive."""
        store = DomainStore(temp_storage)
        manager = DomainManager(store, "instanton.tech")

        await manager.register_domain("API.Example.COM", "tunnel-123")

        # Should find domain regardless of case
        reg = await store.get("api.example.com")
        assert reg is not None

    @pytest.mark.asyncio
    async def test_set_certificate_path(self, temp_storage):
        """Test setting certificate path."""
        store = DomainStore(temp_storage)
        manager = DomainManager(store, "instanton.tech")

        await manager.register_domain("api.example.com", "tunnel-123")
        await manager.set_certificate_path("api.example.com", "/certs/cert.pem")

        reg = await store.get("api.example.com")
        assert reg.certificate_path == "/certs/cert.pem"

    def test_generate_dns_instructions(self, temp_storage):
        """Test DNS instruction generation."""
        store = DomainStore(temp_storage)
        manager = DomainManager(store, "instanton.tech")

        instructions = manager._generate_dns_instructions(
            "api.example.com", "verify=abc123"
        )

        assert "api.example.com" in instructions
        assert "CNAME" in instructions
        assert "TXT" in instructions
        assert "instanton.tech" in instructions
        assert "verify=abc123" in instructions
        assert "_instanton.api.example.com" in instructions
