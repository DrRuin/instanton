"""Token management for Instanton authentication.

Provides:
- API key generation with secure random bytes
- API key hashing with Argon2
- JWT creation and validation
- Token refresh mechanism
- Token revocation list
"""

from __future__ import annotations

import hashlib
import secrets
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

from jose import jwt
from jose.exceptions import JWTError

# ==============================================================================
# API Key Management
# ==============================================================================


@dataclass
class APIKey:
    """Represents an API key with metadata.

    Attributes:
        key_id: Unique identifier for the key.
        key_hash: Hashed version of the key (never store raw key).
        client_id: Owner of the key.
        name: Human-readable name for the key.
        scopes: Granted permissions/scopes.
        created_at: When the key was created.
        expires_at: When the key expires (None for non-expiring).
        last_used_at: Last time the key was used.
        revoked: Whether the key has been revoked.
        metadata: Additional key metadata.
    """

    key_id: str
    key_hash: str
    client_id: str
    name: str = ""
    scopes: list[str] = field(default_factory=list)
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    expires_at: datetime | None = None
    last_used_at: datetime | None = None
    revoked: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for storage."""
        return {
            "key_id": self.key_id,
            "key_hash": self.key_hash,
            "client_id": self.client_id,
            "name": self.name,
            "scopes": self.scopes,
            "created_at": self.created_at.isoformat(),
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "last_used_at": self.last_used_at.isoformat() if self.last_used_at else None,
            "revoked": self.revoked,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> APIKey:
        """Create from dictionary."""
        return cls(
            key_id=data["key_id"],
            key_hash=data["key_hash"],
            client_id=data["client_id"],
            name=data.get("name", ""),
            scopes=data.get("scopes", []),
            created_at=(
                datetime.fromisoformat(data["created_at"])
                if isinstance(data["created_at"], str)
                else data["created_at"]
            ),
            expires_at=(
                datetime.fromisoformat(data["expires_at"])
                if data.get("expires_at") and isinstance(data["expires_at"], str)
                else data.get("expires_at")
            ),
            last_used_at=(
                datetime.fromisoformat(data["last_used_at"])
                if data.get("last_used_at") and isinstance(data["last_used_at"], str)
                else data.get("last_used_at")
            ),
            revoked=data.get("revoked", False),
            metadata=data.get("metadata", {}),
        )


class APIKeyManager:
    """Manages API key generation, hashing, and validation.

    Features:
    - Secure random key generation
    - Argon2 hashing for key storage
    - Key prefixing for easy identification
    - Expiration support
    """

    def __init__(
        self,
        prefix: str = "tach_",
        key_length: int = 32,
        use_argon2: bool = True,
    ) -> None:
        """Initialize API key manager.

        Args:
            prefix: Prefix for generated keys (e.g., 'tach_').
            key_length: Length of the random portion in bytes.
            use_argon2: Whether to use Argon2 for hashing (requires passlib).
        """
        self.prefix = prefix
        self.key_length = key_length
        self.use_argon2 = use_argon2

        # Initialize Argon2 hasher if available and requested
        self._hasher: Any = None
        if use_argon2:
            try:
                from passlib.hash import argon2

                self._hasher = argon2
            except ImportError:
                self.use_argon2 = False

    def generate_key(self) -> str:
        """Generate a new API key.

        Returns:
            A new API key with the configured prefix.
        """
        # Generate secure random bytes
        random_bytes = secrets.token_bytes(self.key_length)

        # Encode as URL-safe base64 and remove padding
        import base64

        random_part = base64.urlsafe_b64encode(random_bytes).decode().rstrip("=")

        return f"{self.prefix}{random_part}"

    def hash_key(self, key: str) -> str:
        """Hash an API key for secure storage.

        Args:
            key: The raw API key.

        Returns:
            Hashed key (Argon2 if available, SHA-256 otherwise).
        """
        if self.use_argon2 and self._hasher:
            return self._hasher.hash(key)

        # Fallback to SHA-256
        return hashlib.sha256(key.encode()).hexdigest()

    def verify_key(self, key: str, key_hash: str) -> bool:
        """Verify an API key against its hash.

        Args:
            key: The raw API key.
            key_hash: The stored hash.

        Returns:
            True if the key matches, False otherwise.
        """
        if self.use_argon2 and self._hasher:
            try:
                return self._hasher.verify(key, key_hash)
            except Exception:
                return False

        # Fallback to SHA-256 comparison
        return hashlib.sha256(key.encode()).hexdigest() == key_hash

    def create_api_key(
        self,
        client_id: str,
        name: str = "",
        scopes: list[str] | None = None,
        expires_in: timedelta | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> tuple[str, APIKey]:
        """Create a new API key with metadata.

        Args:
            client_id: Owner of the key.
            name: Human-readable name.
            scopes: Granted scopes.
            expires_in: Time until expiration (None for non-expiring).
            metadata: Additional metadata.

        Returns:
            Tuple of (raw_key, APIKey object).
            Note: The raw key is only returned once and should be shown to the user.
        """
        raw_key = self.generate_key()
        key_hash = self.hash_key(raw_key)
        key_id = f"key_{secrets.token_hex(8)}"

        expires_at = None
        if expires_in:
            expires_at = datetime.now(UTC) + expires_in

        api_key = APIKey(
            key_id=key_id,
            key_hash=key_hash,
            client_id=client_id,
            name=name,
            scopes=scopes or [],
            expires_at=expires_at,
            metadata=metadata or {},
        )

        return raw_key, api_key

    def quick_hash(self, key: str) -> str:
        """Quick SHA-256 hash for key lookup (not for storage).

        Args:
            key: The raw API key.

        Returns:
            SHA-256 hash hex string.
        """
        return hashlib.sha256(key.encode()).hexdigest()


# ==============================================================================
# JWT Management
# ==============================================================================


@dataclass
class JWTConfig:
    """Configuration for JWT token generation.

    Attributes:
        secret_key: Secret for HS256 algorithm.
        private_key: Private key for RS256 algorithm.
        public_key: Public key for RS256 verification.
        algorithm: JWT algorithm (HS256, RS256, etc.).
        issuer: Token issuer (iss claim).
        audience: Token audience (aud claim).
        access_token_ttl: Access token lifetime.
        refresh_token_ttl: Refresh token lifetime.
        leeway: Time leeway for validation.
    """

    secret_key: str | None = None
    private_key: str | None = None
    public_key: str | None = None
    algorithm: str = "HS256"
    issuer: str = "instanton"
    audience: str = "instanton"
    access_token_ttl: timedelta = field(default_factory=lambda: timedelta(hours=1))
    refresh_token_ttl: timedelta = field(default_factory=lambda: timedelta(days=7))
    leeway: int = 10


@dataclass
class TokenPair:
    """A pair of access and refresh tokens.

    Attributes:
        access_token: The JWT access token.
        refresh_token: The JWT refresh token.
        token_type: Token type (always 'Bearer').
        expires_in: Seconds until access token expires.
        refresh_expires_in: Seconds until refresh token expires.
        scope: Granted scopes.
    """

    access_token: str
    refresh_token: str
    token_type: str = "Bearer"
    expires_in: int = 3600
    refresh_expires_in: int = 604800
    scope: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Convert to OAuth2 token response format."""
        return {
            "access_token": self.access_token,
            "refresh_token": self.refresh_token,
            "token_type": self.token_type,
            "expires_in": self.expires_in,
            "scope": self.scope,
        }


class JWTManager:
    """Manages JWT token creation, validation, and refresh.

    Features:
    - Access and refresh token generation
    - Support for HS256 and RS256 algorithms
    - Token refresh mechanism
    - Integration with revocation list
    """

    def __init__(self, config: JWTConfig) -> None:
        """Initialize JWT manager.

        Args:
            config: JWT configuration.
        """
        self.config = config

        # Determine signing/verification keys
        if config.algorithm.startswith("HS"):
            if not config.secret_key:
                raise ValueError("Secret key required for HS* algorithms")
            self._sign_key = config.secret_key
            self._verify_key = config.secret_key
        elif config.algorithm.startswith("RS") or config.algorithm.startswith("ES"):
            if not config.private_key:
                raise ValueError("Private key required for RS*/ES* algorithms")
            if not config.public_key:
                raise ValueError("Public key required for RS*/ES* algorithms")
            self._sign_key = config.private_key
            self._verify_key = config.public_key
        else:
            raise ValueError(f"Unsupported algorithm: {config.algorithm}")

        # Revocation list
        self._revocation_list: TokenRevocationList = TokenRevocationList()

    @property
    def revocation_list(self) -> TokenRevocationList:
        """Get the token revocation list."""
        return self._revocation_list

    def create_access_token(
        self,
        subject: str,
        scopes: list[str] | None = None,
        claims: dict[str, Any] | None = None,
        ttl: timedelta | None = None,
    ) -> str:
        """Create an access token.

        Args:
            subject: Token subject (user ID, client ID).
            scopes: Granted scopes.
            claims: Additional custom claims.
            ttl: Token lifetime (overrides config).

        Returns:
            JWT access token string.
        """
        now = datetime.now(UTC)
        ttl = ttl or self.config.access_token_ttl
        exp = now + ttl

        token_claims = {
            "sub": subject,
            "iss": self.config.issuer,
            "aud": self.config.audience,
            "iat": now,
            "exp": exp,
            "nbf": now,
            "jti": str(uuid4()),
            "type": "access",
        }

        # Add scopes
        if scopes:
            token_claims["scope"] = " ".join(scopes)

        # Add custom claims
        if claims:
            token_claims.update(claims)

        return jwt.encode(token_claims, self._sign_key, algorithm=self.config.algorithm)

    def create_refresh_token(
        self,
        subject: str,
        scopes: list[str] | None = None,
        claims: dict[str, Any] | None = None,
        ttl: timedelta | None = None,
    ) -> str:
        """Create a refresh token.

        Args:
            subject: Token subject.
            scopes: Granted scopes.
            claims: Additional custom claims.
            ttl: Token lifetime (overrides config).

        Returns:
            JWT refresh token string.
        """
        now = datetime.now(UTC)
        ttl = ttl or self.config.refresh_token_ttl
        exp = now + ttl

        token_claims = {
            "sub": subject,
            "iss": self.config.issuer,
            "aud": self.config.audience,
            "iat": now,
            "exp": exp,
            "nbf": now,
            "jti": str(uuid4()),
            "type": "refresh",
        }

        # Add scopes
        if scopes:
            token_claims["scope"] = " ".join(scopes)

        # Add custom claims
        if claims:
            token_claims.update(claims)

        return jwt.encode(token_claims, self._sign_key, algorithm=self.config.algorithm)

    def create_token_pair(
        self,
        subject: str,
        scopes: list[str] | None = None,
        claims: dict[str, Any] | None = None,
    ) -> TokenPair:
        """Create an access/refresh token pair.

        Args:
            subject: Token subject.
            scopes: Granted scopes.
            claims: Additional custom claims.

        Returns:
            TokenPair with both tokens.
        """
        access_token = self.create_access_token(subject, scopes, claims)
        refresh_token = self.create_refresh_token(subject, scopes, claims)

        return TokenPair(
            access_token=access_token,
            refresh_token=refresh_token,
            expires_in=int(self.config.access_token_ttl.total_seconds()),
            refresh_expires_in=int(self.config.refresh_token_ttl.total_seconds()),
            scope=" ".join(scopes) if scopes else "",
        )

    def decode_token(
        self,
        token: str,
        verify_exp: bool = True,
        required_type: str | None = None,
    ) -> dict[str, Any]:
        """Decode and validate a JWT token.

        Args:
            token: The JWT to decode.
            verify_exp: Whether to verify expiration.
            required_type: Required token type ('access' or 'refresh').

        Returns:
            Decoded token claims.

        Raises:
            JWTError: If token is invalid.
        """
        options = {
            "verify_signature": True,
            "verify_exp": verify_exp,
            "verify_iat": True,
            "verify_nbf": True,
            "require_exp": True,
            "leeway": self.config.leeway,
        }

        claims = jwt.decode(
            token,
            self._verify_key,
            algorithms=[self.config.algorithm],
            audience=self.config.audience,
            issuer=self.config.issuer,
            options=options,
        )

        # Check revocation
        if (jti := claims.get("jti")) and self._revocation_list.is_revoked(jti):
            raise JWTError("Token has been revoked")

        # Check token type
        if required_type and claims.get("type") != required_type:
            raise JWTError(f"Expected {required_type} token, got {claims.get('type')}")

        return claims

    def refresh_tokens(
        self,
        refresh_token: str,
        scopes: list[str] | None = None,
    ) -> TokenPair:
        """Refresh tokens using a refresh token.

        Args:
            refresh_token: The refresh token.
            scopes: New scopes (must be subset of original).

        Returns:
            New TokenPair.

        Raises:
            JWTError: If refresh token is invalid.
        """
        # Decode and validate refresh token
        claims = self.decode_token(refresh_token, required_type="refresh")

        # Extract original scopes
        original_scopes = claims.get("scope", "").split()
        if scopes:
            # Validate that requested scopes are subset of original
            if not set(scopes).issubset(set(original_scopes)):
                raise JWTError("Requested scopes exceed original grant")
        else:
            scopes = original_scopes

        # Revoke old refresh token
        if jti := claims.get("jti"):
            exp = claims.get("exp", 0)
            self._revocation_list.revoke(jti, datetime.fromtimestamp(exp, tz=UTC))

        # Create new token pair
        return self.create_token_pair(
            subject=claims["sub"],
            scopes=scopes,
        )

    def revoke_token(self, token: str) -> bool:
        """Revoke a token.

        Args:
            token: The token to revoke.

        Returns:
            True if revoked successfully.
        """
        try:
            claims = self.decode_token(token, verify_exp=False)
            if jti := claims.get("jti"):
                exp = claims.get("exp", 0)
                self._revocation_list.revoke(
                    jti,
                    datetime.fromtimestamp(exp, tz=UTC),
                )
                return True
        except JWTError:
            pass
        return False


# ==============================================================================
# Token Revocation List
# ==============================================================================


class TokenRevocationList:
    """Manages revoked token IDs (JTIs).

    Features:
    - In-memory storage of revoked JTIs
    - Automatic cleanup of expired entries
    - Integration with external storage backends
    """

    def __init__(self) -> None:
        """Initialize revocation list."""
        # Maps JTI to expiration time
        self._revoked: dict[str, datetime] = {}
        self._last_cleanup: float = time.time()
        self._cleanup_interval: float = 3600  # 1 hour

    def revoke(self, jti: str, expires_at: datetime | None = None) -> None:
        """Add a token ID to the revocation list.

        Args:
            jti: The JWT ID to revoke.
            expires_at: When the token would have expired.
        """
        # Default to 7 days if no expiration provided
        if expires_at is None:
            expires_at = datetime.now(UTC) + timedelta(days=7)

        self._revoked[jti] = expires_at
        self._maybe_cleanup()

    def is_revoked(self, jti: str) -> bool:
        """Check if a token ID is revoked.

        Args:
            jti: The JWT ID to check.

        Returns:
            True if revoked, False otherwise.
        """
        return jti in self._revoked

    def remove(self, jti: str) -> bool:
        """Remove a token ID from the revocation list.

        Args:
            jti: The JWT ID to remove.

        Returns:
            True if removed, False if not found.
        """
        if jti in self._revoked:
            del self._revoked[jti]
            return True
        return False

    def clear(self) -> None:
        """Clear all revoked tokens."""
        self._revoked.clear()

    def _maybe_cleanup(self) -> None:
        """Perform cleanup if enough time has passed."""
        now = time.time()
        if now - self._last_cleanup > self._cleanup_interval:
            self.cleanup()
            self._last_cleanup = now

    def cleanup(self) -> int:
        """Remove expired entries from the revocation list.

        Returns:
            Number of entries removed.
        """
        now = datetime.now(UTC)
        expired = [jti for jti, exp in self._revoked.items() if exp < now]
        for jti in expired:
            del self._revoked[jti]
        return len(expired)

    def get_all(self) -> dict[str, datetime]:
        """Get all revoked token IDs.

        Returns:
            Dictionary of JTI to expiration time.
        """
        return dict(self._revoked)

    def load(self, data: dict[str, str | datetime]) -> None:
        """Load revocation data from storage.

        Args:
            data: Dictionary of JTI to expiration time.
        """
        for jti, exp in data.items():
            if isinstance(exp, str):
                exp = datetime.fromisoformat(exp)
            self._revoked[jti] = exp

    def dump(self) -> dict[str, str]:
        """Dump revocation data for storage.

        Returns:
            Dictionary of JTI to ISO format expiration time.
        """
        return {jti: exp.isoformat() for jti, exp in self._revoked.items()}

    def __len__(self) -> int:
        """Return number of revoked tokens."""
        return len(self._revoked)

    def __contains__(self, jti: str) -> bool:
        """Check if JTI is in revocation list."""
        return self.is_revoked(jti)
