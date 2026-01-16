"""Storage for custom domain registrations.

This module provides JSON file-based storage for domain registrations,
suitable for self-hosted deployments.

Storage file format (domains.json):
    {
        "domains": {
            "api.mycompany.com": {
                "domain": "api.mycompany.com",
                "tunnel_id": "abc123",
                "verification_token": "verify=xyz789",
                "verified": true,
                "verified_at": "2024-01-15T10:30:00Z",
                "created_at": "2024-01-15T10:00:00Z",
                "certificate_path": "/certs/api.mycompany.com.pem"
            }
        }
    }
"""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


def _utc_now() -> datetime:
    """Return current UTC datetime."""
    return datetime.now(UTC)


@dataclass
class DomainRegistration:
    """Represents a registered custom domain.

    Supports both exact domains (api.example.com) and wildcard patterns
    (*.example.com) for flexible routing.
    """

    domain: str
    tunnel_id: str
    verification_token: str
    verified: bool = False
    verified_at: datetime | None = None
    created_at: datetime = field(default_factory=_utc_now)
    certificate_path: str | None = None
    is_wildcard: bool = False
    wildcard_pattern: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "domain": self.domain,
            "tunnel_id": self.tunnel_id,
            "verification_token": self.verification_token,
            "verified": self.verified,
            "verified_at": self.verified_at.isoformat() if self.verified_at else None,
            "created_at": self.created_at.isoformat(),
            "certificate_path": self.certificate_path,
            "is_wildcard": self.is_wildcard,
            "wildcard_pattern": self.wildcard_pattern,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> DomainRegistration:
        """Create from dictionary (JSON deserialization)."""
        return cls(
            domain=data["domain"],
            tunnel_id=data["tunnel_id"],
            verification_token=data["verification_token"],
            verified=data.get("verified", False),
            verified_at=datetime.fromisoformat(data["verified_at"])
            if data.get("verified_at")
            else None,
            created_at=datetime.fromisoformat(data["created_at"])
            if data.get("created_at")
            else datetime.now(UTC),
            certificate_path=data.get("certificate_path"),
            is_wildcard=data.get("is_wildcard", False),
            wildcard_pattern=data.get("wildcard_pattern"),
        )


class DomainStore:
    """JSON file-based storage for domain registrations.

    Thread-safe via asyncio locks. Suitable for self-hosted deployments
    with moderate domain counts (<1000).

    For high-scale deployments, consider implementing a database backend.
    """

    def __init__(self, storage_path: str | Path = "domains.json") -> None:
        """Initialize domain store.

        Args:
            storage_path: Path to the JSON storage file.
        """
        self.storage_path = Path(storage_path)
        self._lock = asyncio.Lock()
        self._cache: dict[str, DomainRegistration] | None = None

    async def _load(self) -> dict[str, DomainRegistration]:
        """Load domains from storage file."""
        if self._cache is not None:
            return self._cache

        if not self.storage_path.exists():
            self._cache = {}
            return self._cache

        try:
            content = await asyncio.to_thread(self.storage_path.read_text)
            data = json.loads(content)
            self._cache = {
                domain: DomainRegistration.from_dict(reg_data)
                for domain, reg_data in data.get("domains", {}).items()
            }
        except (json.JSONDecodeError, KeyError):
            self._cache = {}

        return self._cache

    async def _save(self, domains: dict[str, DomainRegistration]) -> None:
        """Save domains to storage file."""
        data = {"domains": {domain: reg.to_dict() for domain, reg in domains.items()}}
        content = json.dumps(data, indent=2)
        await asyncio.to_thread(self.storage_path.write_text, content)
        self._cache = domains

    async def save(self, registration: DomainRegistration) -> None:
        """Save or update a domain registration.

        Args:
            registration: The domain registration to save.
        """
        async with self._lock:
            domains = await self._load()
            domains[registration.domain] = registration
            await self._save(domains)

    async def get(self, domain: str) -> DomainRegistration | None:
        """Get a domain registration by domain name.

        Args:
            domain: The domain to look up.

        Returns:
            The registration if found, None otherwise.
        """
        async with self._lock:
            domains = await self._load()
            return domains.get(domain)

    async def get_by_tunnel(self, tunnel_id: str) -> list[DomainRegistration]:
        """Get all domains registered to a specific tunnel.

        Args:
            tunnel_id: The tunnel ID to filter by.

        Returns:
            List of domain registrations for the tunnel.
        """
        async with self._lock:
            domains = await self._load()
            return [reg for reg in domains.values() if reg.tunnel_id == tunnel_id]

    async def list_all(self) -> list[DomainRegistration]:
        """Get all domain registrations.

        Returns:
            List of all domain registrations.
        """
        async with self._lock:
            domains = await self._load()
            return list(domains.values())

    async def list_verified(self) -> list[DomainRegistration]:
        """Get all verified domain registrations.

        Returns:
            List of verified domain registrations.
        """
        async with self._lock:
            domains = await self._load()
            return [reg for reg in domains.values() if reg.verified]

    async def list_wildcards(self) -> list[DomainRegistration]:
        """Get all wildcard domain registrations.

        Returns:
            List of wildcard domain registrations (verified and unverified).
        """
        async with self._lock:
            domains = await self._load()
            return [reg for reg in domains.values() if reg.is_wildcard]

    async def list_verified_wildcards(self) -> list[DomainRegistration]:
        """Get all verified wildcard domain registrations.

        Returns:
            List of verified wildcard domain registrations.
        """
        async with self._lock:
            domains = await self._load()
            return [reg for reg in domains.values() if reg.is_wildcard and reg.verified]

    async def delete(self, domain: str) -> bool:
        """Delete a domain registration.

        Args:
            domain: The domain to delete.

        Returns:
            True if deleted, False if not found.
        """
        async with self._lock:
            domains = await self._load()
            if domain in domains:
                del domains[domain]
                await self._save(domains)
                return True
            return False

    async def exists(self, domain: str) -> bool:
        """Check if a domain is registered.

        Args:
            domain: The domain to check.

        Returns:
            True if domain exists in storage.
        """
        async with self._lock:
            domains = await self._load()
            return domain in domains

    def invalidate_cache(self) -> None:
        """Invalidate the in-memory cache.

        Call this after external modifications to the storage file.
        """
        self._cache = None
