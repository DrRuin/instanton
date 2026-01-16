"""Instanton API Token Service.

Manages API token generation, verification, and lifecycle for authenticating
CLI connections and programmatic API access to Instanton. Tokens use secure
SHA-256 hashing and support expiration and revocation.
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

from instanton.dashboard.services.supabase import (
    get_local_storage,
    get_supabase_client,
    is_cloud_mode,
)


@dataclass
class APIToken:
    """Represents an API token."""

    id: str
    name: str
    token_hash: str
    token_prefix: str
    scopes: list[str]
    created_at: datetime
    last_used_at: datetime | None = None
    expires_at: datetime | None = None
    revoked_at: datetime | None = None
    total_requests: int = 0
    user_id: str | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> APIToken:
        """Create APIToken from dictionary."""
        scopes = data.get("scopes", [])
        if isinstance(scopes, str):
            # Handle JSON string or comma-separated
            import json

            try:
                scopes = json.loads(scopes)
            except Exception:
                scopes = scopes.split(",") if scopes else []

        return cls(
            id=data["id"],
            name=data["name"],
            token_hash=data["token_hash"],
            token_prefix=data["token_prefix"],
            scopes=scopes,
            created_at=_parse_datetime(data["created_at"]) or datetime.now(UTC),
            last_used_at=_parse_datetime(data.get("last_used_at")),
            expires_at=_parse_datetime(data.get("expires_at")),
            revoked_at=_parse_datetime(data.get("revoked_at")),
            total_requests=data.get("total_requests", 0),
            user_id=data.get("user_id"),
        )

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        import json

        return {
            "id": self.id,
            "name": self.name,
            "token_hash": self.token_hash,
            "token_prefix": self.token_prefix,
            "scopes": json.dumps(self.scopes),
            "created_at": self.created_at.isoformat(),
            "last_used_at": self.last_used_at.isoformat() if self.last_used_at else None,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "revoked_at": self.revoked_at.isoformat() if self.revoked_at else None,
            "total_requests": self.total_requests,
            "user_id": self.user_id,
        }

    @property
    def is_valid(self) -> bool:
        """Check if token is valid (not expired or revoked)."""
        if self.revoked_at:
            return False
        if self.expires_at and self.expires_at < datetime.now(UTC):
            return False
        return True


def _parse_datetime(value: str | datetime | None) -> datetime | None:
    """Parse datetime from string or datetime."""
    if value is None:
        return None
    if isinstance(value, datetime):
        return value
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except Exception:
        return None


class TokenService:
    """Instanton API Token Service.

    Provides secure token generation, verification, and management for
    the Instanton dashboard. Tokens follow the format `tach_<base64-encoded>`
    and are stored as SHA-256 hashes for security.
    """

    TOKEN_PREFIX = "tach_"
    TOKEN_LENGTH = 32

    def generate_token(self) -> str:
        """Generate a new raw token.

        Returns:
            Raw token string (e.g., 'tach_abc123...').
        """
        import base64

        random_bytes = secrets.token_bytes(self.TOKEN_LENGTH)
        random_part = base64.urlsafe_b64encode(random_bytes).decode().rstrip("=")
        return f"{self.TOKEN_PREFIX}{random_part}"

    def hash_token(self, raw_token: str) -> str:
        """Hash a token for secure storage.

        Args:
            raw_token: The raw token string.

        Returns:
            SHA-256 hash of the token.
        """
        return hashlib.sha256(raw_token.encode()).hexdigest()

    def get_token_prefix(self, raw_token: str) -> str:
        """Get display prefix from raw token.

        Args:
            raw_token: The raw token string.

        Returns:
            First 12 characters for display.
        """
        return raw_token[:12]

    async def create_token(
        self,
        name: str,
        user_id: str | None = None,
        scopes: list[str] | None = None,
        expires_in: timedelta | None = None,
    ) -> tuple[str, APIToken]:
        """Create a new API token.

        Args:
            name: Human-readable token name.
            user_id: Owner user ID.
            scopes: Token scopes/permissions.
            expires_in: Token lifetime (None = never expires).

        Returns:
            Tuple of (raw_token, APIToken).
            NOTE: raw_token is only returned once.
        """
        raw_token = self.generate_token()
        token_hash = self.hash_token(raw_token)
        token_prefix = self.get_token_prefix(raw_token)

        expires_at = None
        if expires_in:
            expires_at = datetime.now(UTC) + expires_in

        token = APIToken(
            id=str(uuid4()),
            name=name,
            token_hash=token_hash,
            token_prefix=token_prefix,
            scopes=scopes or ["tunnel:create"],
            created_at=datetime.now(UTC),
            expires_at=expires_at,
            user_id=user_id,
        )

        if is_cloud_mode():
            client = get_supabase_client()
            client.table("api_tokens").insert(token.to_dict()).execute()
        else:
            storage = get_local_storage()
            storage.save_token(token.to_dict())

        return raw_token, token

    async def verify_token(self, raw_token: str) -> APIToken | None:
        """Verify a token and return its metadata.

        Args:
            raw_token: The raw token to verify.

        Returns:
            APIToken if valid, None otherwise.
        """
        token_hash = self.hash_token(raw_token)

        if is_cloud_mode():
            client = get_supabase_client()
            response = (
                client.table("api_tokens")
                .select("*")
                .eq("token_hash", token_hash)
                .single()
                .execute()
            )
            if response.data:
                token = APIToken.from_dict(response.data)
                if token.is_valid:
                    # Update usage stats
                    await self._increment_usage(token.id)
                    return token
            return None
        else:
            storage = get_local_storage()
            data = storage.get_token_by_hash(token_hash)
            if data:
                token = APIToken.from_dict(data)
                if token.is_valid:
                    storage.increment_token_usage(token.id)
                    return token
            return None

    async def list_tokens(self, user_id: str | None = None) -> list[APIToken]:
        """List tokens for a user.

        Args:
            user_id: Filter by user ID.

        Returns:
            List of APIToken objects (not revoked).
        """
        if is_cloud_mode():
            client = get_supabase_client()
            query = client.table("api_tokens").select("*").is_("revoked_at", "null")

            if user_id and user_id != "local":
                query = query.eq("user_id", user_id)

            response = query.order("created_at", desc=True).execute()
            return [APIToken.from_dict(d) for d in response.data]
        else:
            storage = get_local_storage()
            data = storage.list_tokens()
            return [APIToken.from_dict(d) for d in data]

    async def get_token(self, token_id: str) -> APIToken | None:
        """Get token by ID.

        Args:
            token_id: Token ID.

        Returns:
            APIToken or None if not found.
        """
        if is_cloud_mode():
            client = get_supabase_client()
            response = (
                client.table("api_tokens")
                .select("*")
                .eq("id", token_id)
                .single()
                .execute()
            )
            if response.data:
                return APIToken.from_dict(response.data)
            return None
        else:
            storage = get_local_storage()
            data = storage.get_token(token_id)
            return APIToken.from_dict(data) if data else None

    async def revoke_token(self, token_id: str) -> bool:
        """Revoke a token.

        Args:
            token_id: Token ID to revoke.

        Returns:
            True if revoked, False if not found.
        """
        if is_cloud_mode():
            client = get_supabase_client()
            response = (
                client.table("api_tokens")
                .update({"revoked_at": datetime.now(UTC).isoformat()})
                .eq("id", token_id)
                .execute()
            )
            return len(response.data) > 0
        else:
            storage = get_local_storage()
            return storage.revoke_token(token_id)

    async def revoke_all_tokens(self, user_id: str | None = None) -> int:
        """Revoke all tokens for a user.

        Marks all active tokens as revoked. In self-hosted mode,
        revokes all tokens. In cloud mode, revokes only the specified user's tokens.

        Args:
            user_id: User ID whose tokens to revoke. Required in cloud mode.

        Returns:
            Number of tokens revoked.
        """
        if is_cloud_mode():
            if not user_id or user_id == "local":
                return 0

            client = get_supabase_client()
            response = (
                client.table("api_tokens")
                .update({"revoked_at": datetime.now(UTC).isoformat()})
                .eq("user_id", user_id)
                .is_("revoked_at", "null")
                .execute()
            )
            return len(response.data)
        else:
            storage = get_local_storage()
            tokens = storage.list_tokens()
            count = 0
            for token in tokens:
                if not token.get("revoked_at"):
                    storage.revoke_token(token["id"])
                    count += 1
            return count

    async def _increment_usage(self, token_id: str) -> None:
        """Increment token usage counter."""
        if is_cloud_mode():
            client = get_supabase_client()
            # Use RPC for atomic increment
            client.rpc(
                "increment_token_usage",
                {"token_id": token_id},
            ).execute()


# Singleton instance
_token_service: TokenService | None = None


def get_token_service() -> TokenService:
    """Get the Instanton token service singleton instance.

    Returns:
        Global TokenService instance for API token management.
    """
    global _token_service
    if _token_service is None:
        _token_service = TokenService()
    return _token_service
