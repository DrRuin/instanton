"""Auth storage backends for Instanton.

Provides:
- In-memory storage (for development)
- SQLite storage (for single-node production)
- Redis storage interface (for distributed deployments)
"""

from __future__ import annotations

import json
import sqlite3
import threading
from abc import ABC, abstractmethod
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from instanton.auth.tokens import APIKey

# ==============================================================================
# Abstract Storage Interface
# ==============================================================================


class AuthStorage(ABC):
    """Abstract base class for auth storage backends.

    Defines the interface for storing and retrieving authentication data.
    """

    # API Key Operations

    @abstractmethod
    async def store_api_key(self, key_hash: str, api_key: APIKey) -> None:
        """Store an API key.

        Args:
            key_hash: The hash of the API key (for lookup).
            api_key: The APIKey object to store.
        """
        ...

    @abstractmethod
    async def get_api_key(self, key_hash: str) -> APIKey | None:
        """Retrieve an API key by its hash.

        Args:
            key_hash: The hash of the API key.

        Returns:
            The APIKey object or None if not found.
        """
        ...

    @abstractmethod
    async def delete_api_key(self, key_hash: str) -> bool:
        """Delete an API key.

        Args:
            key_hash: The hash of the API key.

        Returns:
            True if deleted, False if not found.
        """
        ...

    @abstractmethod
    async def list_api_keys(self, client_id: str | None = None) -> list[APIKey]:
        """List API keys, optionally filtered by client ID.

        Args:
            client_id: Optional client ID filter.

        Returns:
            List of APIKey objects.
        """
        ...

    @abstractmethod
    async def update_api_key_last_used(self, key_hash: str) -> None:
        """Update the last_used_at timestamp for an API key.

        Args:
            key_hash: The hash of the API key.
        """
        ...

    # Token Revocation Operations

    @abstractmethod
    async def revoke_token(self, jti: str, expires_at: datetime) -> None:
        """Add a token to the revocation list.

        Args:
            jti: The JWT ID.
            expires_at: When the token expires.
        """
        ...

    @abstractmethod
    async def is_token_revoked(self, jti: str) -> bool:
        """Check if a token is revoked.

        Args:
            jti: The JWT ID.

        Returns:
            True if revoked.
        """
        ...

    @abstractmethod
    async def cleanup_expired_revocations(self) -> int:
        """Remove expired entries from the revocation list.

        Returns:
            Number of entries removed.
        """
        ...

    # User/Client Operations (optional - subclasses may override)

    async def store_user(self, user_id: str, data: dict[str, Any]) -> None:  # noqa: B027
        """Store user data (optional).

        Args:
            user_id: User identifier.
            data: User data to store.
        """

    async def get_user(self, user_id: str) -> dict[str, Any] | None:
        """Get user data (optional).

        Args:
            user_id: User identifier.

        Returns:
            User data or None.
        """
        return None

    # Lifecycle (optional - subclasses may override)

    async def initialize(self) -> None:  # noqa: B027
        """Initialize the storage backend."""

    async def close(self) -> None:  # noqa: B027
        """Close the storage backend."""


# ==============================================================================
# In-Memory Storage
# ==============================================================================


class InMemoryStorage(AuthStorage):
    """In-memory storage backend for development and testing.

    Features:
    - Fast access
    - No persistence
    - Thread-safe operations
    """

    def __init__(self) -> None:
        """Initialize in-memory storage."""
        self._api_keys: dict[str, APIKey] = {}
        self._revoked_tokens: dict[str, datetime] = {}
        self._users: dict[str, dict[str, Any]] = {}
        self._lock = threading.RLock()

    async def store_api_key(self, key_hash: str, api_key: APIKey) -> None:
        with self._lock:
            self._api_keys[key_hash] = api_key

    async def get_api_key(self, key_hash: str) -> APIKey | None:
        with self._lock:
            return self._api_keys.get(key_hash)

    async def delete_api_key(self, key_hash: str) -> bool:
        with self._lock:
            if key_hash in self._api_keys:
                del self._api_keys[key_hash]
                return True
            return False

    async def list_api_keys(self, client_id: str | None = None) -> list[APIKey]:
        with self._lock:
            if client_id:
                return [key for key in self._api_keys.values() if key.client_id == client_id]
            return list(self._api_keys.values())

    async def update_api_key_last_used(self, key_hash: str) -> None:
        with self._lock:
            if key := self._api_keys.get(key_hash):
                key.last_used_at = datetime.now(UTC)

    async def revoke_token(self, jti: str, expires_at: datetime) -> None:
        with self._lock:
            self._revoked_tokens[jti] = expires_at

    async def is_token_revoked(self, jti: str) -> bool:
        with self._lock:
            return jti in self._revoked_tokens

    async def cleanup_expired_revocations(self) -> int:
        with self._lock:
            now = datetime.now(UTC)
            expired = [jti for jti, exp in self._revoked_tokens.items() if exp < now]
            for jti in expired:
                del self._revoked_tokens[jti]
            return len(expired)

    async def store_user(self, user_id: str, data: dict[str, Any]) -> None:
        with self._lock:
            self._users[user_id] = data

    async def get_user(self, user_id: str) -> dict[str, Any] | None:
        with self._lock:
            return self._users.get(user_id)

    def get_api_key_storage(self) -> dict[str, dict[str, Any]]:
        """Get API key storage as dict for provider integration.

        Returns:
            Dictionary mapping key hashes to key metadata.
        """
        with self._lock:
            return {key_hash: key.to_dict() for key_hash, key in self._api_keys.items()}


# ==============================================================================
# SQLite Storage
# ==============================================================================


class SQLiteStorage(AuthStorage):
    """SQLite storage backend for single-node production.

    Features:
    - Persistent storage
    - ACID compliance
    - Thread-safe with connection pooling
    """

    def __init__(
        self,
        db_path: str | Path = "instanton_auth.db",
        pool_size: int = 5,
    ) -> None:
        """Initialize SQLite storage.

        Args:
            db_path: Path to SQLite database file.
            pool_size: Number of connections in pool.
        """
        self.db_path = Path(db_path)
        self.pool_size = pool_size
        self._local = threading.local()
        self._initialized = False

    def _get_connection(self) -> sqlite3.Connection:
        """Get a thread-local database connection."""
        if not hasattr(self._local, "connection"):
            conn = sqlite3.connect(
                str(self.db_path),
                check_same_thread=False,
            )
            conn.row_factory = sqlite3.Row
            self._local.connection = conn
        return self._local.connection

    @contextmanager
    def _cursor(self) -> Iterator[sqlite3.Cursor]:
        """Get a cursor with automatic commit/rollback."""
        conn = self._get_connection()
        cursor = conn.cursor()
        try:
            yield cursor
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            cursor.close()

    async def initialize(self) -> None:
        """Initialize the database schema."""
        if self._initialized:
            return

        with self._cursor() as cursor:
            # API Keys table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS api_keys (
                    key_hash TEXT PRIMARY KEY,
                    key_id TEXT UNIQUE NOT NULL,
                    client_id TEXT NOT NULL,
                    name TEXT,
                    scopes TEXT,
                    created_at TEXT NOT NULL,
                    expires_at TEXT,
                    last_used_at TEXT,
                    revoked INTEGER DEFAULT 0,
                    metadata TEXT
                )
            """)

            # Revoked tokens table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS revoked_tokens (
                    jti TEXT PRIMARY KEY,
                    expires_at TEXT NOT NULL
                )
            """)

            # Users table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    user_id TEXT PRIMARY KEY,
                    data TEXT NOT NULL
                )
            """)

            # Create indexes
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_api_keys_client_id
                ON api_keys(client_id)
            """)

            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_revoked_tokens_expires_at
                ON revoked_tokens(expires_at)
            """)

        self._initialized = True

    async def close(self) -> None:
        """Close database connections."""
        if hasattr(self._local, "connection"):
            self._local.connection.close()
            del self._local.connection

    async def store_api_key(self, key_hash: str, api_key: APIKey) -> None:
        await self.initialize()

        with self._cursor() as cursor:
            cursor.execute(
                """
                INSERT OR REPLACE INTO api_keys
                (key_hash, key_id, client_id, name, scopes,
                 created_at, expires_at, last_used_at, revoked, metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    key_hash,
                    api_key.key_id,
                    api_key.client_id,
                    api_key.name,
                    json.dumps(api_key.scopes),
                    api_key.created_at.isoformat(),
                    api_key.expires_at.isoformat() if api_key.expires_at else None,
                    api_key.last_used_at.isoformat() if api_key.last_used_at else None,
                    1 if api_key.revoked else 0,
                    json.dumps(api_key.metadata),
                ),
            )

    async def get_api_key(self, key_hash: str) -> APIKey | None:
        await self.initialize()

        with self._cursor() as cursor:
            cursor.execute(
                "SELECT * FROM api_keys WHERE key_hash = ?",
                (key_hash,),
            )
            row = cursor.fetchone()

            if not row:
                return None

            return APIKey(
                key_id=row["key_id"],
                key_hash=row["key_hash"],
                client_id=row["client_id"],
                name=row["name"] or "",
                scopes=json.loads(row["scopes"]) if row["scopes"] else [],
                created_at=datetime.fromisoformat(row["created_at"]),
                expires_at=datetime.fromisoformat(row["expires_at"]) if row["expires_at"] else None,
                last_used_at=datetime.fromisoformat(row["last_used_at"])
                if row["last_used_at"]
                else None,
                revoked=bool(row["revoked"]),
                metadata=json.loads(row["metadata"]) if row["metadata"] else {},
            )

    async def delete_api_key(self, key_hash: str) -> bool:
        await self.initialize()

        with self._cursor() as cursor:
            cursor.execute(
                "DELETE FROM api_keys WHERE key_hash = ?",
                (key_hash,),
            )
            return cursor.rowcount > 0

    async def list_api_keys(self, client_id: str | None = None) -> list[APIKey]:
        await self.initialize()

        with self._cursor() as cursor:
            if client_id:
                cursor.execute(
                    "SELECT * FROM api_keys WHERE client_id = ?",
                    (client_id,),
                )
            else:
                cursor.execute("SELECT * FROM api_keys")

            rows = cursor.fetchall()

            return [
                APIKey(
                    key_id=row["key_id"],
                    key_hash=row["key_hash"],
                    client_id=row["client_id"],
                    name=row["name"] or "",
                    scopes=json.loads(row["scopes"]) if row["scopes"] else [],
                    created_at=datetime.fromisoformat(row["created_at"]),
                    expires_at=datetime.fromisoformat(row["expires_at"])
                    if row["expires_at"]
                    else None,
                    last_used_at=datetime.fromisoformat(row["last_used_at"])
                    if row["last_used_at"]
                    else None,
                    revoked=bool(row["revoked"]),
                    metadata=json.loads(row["metadata"]) if row["metadata"] else {},
                )
                for row in rows
            ]

    async def update_api_key_last_used(self, key_hash: str) -> None:
        await self.initialize()

        with self._cursor() as cursor:
            cursor.execute(
                "UPDATE api_keys SET last_used_at = ? WHERE key_hash = ?",
                (datetime.now(UTC).isoformat(), key_hash),
            )

    async def revoke_token(self, jti: str, expires_at: datetime) -> None:
        await self.initialize()

        with self._cursor() as cursor:
            cursor.execute(
                "INSERT OR REPLACE INTO revoked_tokens (jti, expires_at) VALUES (?, ?)",
                (jti, expires_at.isoformat()),
            )

    async def is_token_revoked(self, jti: str) -> bool:
        await self.initialize()

        with self._cursor() as cursor:
            cursor.execute(
                "SELECT 1 FROM revoked_tokens WHERE jti = ?",
                (jti,),
            )
            return cursor.fetchone() is not None

    async def cleanup_expired_revocations(self) -> int:
        await self.initialize()

        with self._cursor() as cursor:
            cursor.execute(
                "DELETE FROM revoked_tokens WHERE expires_at < ?",
                (datetime.now(UTC).isoformat(),),
            )
            return cursor.rowcount

    async def store_user(self, user_id: str, data: dict[str, Any]) -> None:
        await self.initialize()

        with self._cursor() as cursor:
            cursor.execute(
                "INSERT OR REPLACE INTO users (user_id, data) VALUES (?, ?)",
                (user_id, json.dumps(data)),
            )

    async def get_user(self, user_id: str) -> dict[str, Any] | None:
        await self.initialize()

        with self._cursor() as cursor:
            cursor.execute(
                "SELECT data FROM users WHERE user_id = ?",
                (user_id,),
            )
            row = cursor.fetchone()
            if row:
                return json.loads(row["data"])
            return None

    def get_api_key_storage(self) -> dict[str, dict[str, Any]]:
        """Get API key storage as dict for provider integration.

        Note: This is a sync method for compatibility.

        Returns:
            Dictionary mapping key hashes to key metadata.
        """
        with self._cursor() as cursor:
            cursor.execute("SELECT * FROM api_keys")
            rows = cursor.fetchall()

            return {
                row["key_hash"]: {
                    "key_id": row["key_id"],
                    "client_id": row["client_id"],
                    "name": row["name"],
                    "scopes": json.loads(row["scopes"]) if row["scopes"] else [],
                    "created_at": row["created_at"],
                    "expires_at": row["expires_at"],
                    "last_used_at": row["last_used_at"],
                    "revoked": bool(row["revoked"]),
                    "metadata": json.loads(row["metadata"]) if row["metadata"] else {},
                }
                for row in rows
            }


# ==============================================================================
# Redis Storage Interface
# ==============================================================================


class RedisStorage(AuthStorage):
    """Redis storage backend for distributed deployments.

    Features:
    - Distributed storage
    - Automatic TTL for revoked tokens
    - High availability with Redis Cluster support

    Note: Requires the `redis` package to be installed.
    """

    def __init__(
        self,
        redis_url: str = "redis://localhost:6379/0",
        key_prefix: str = "instanton:auth:",
        ttl_buffer: int = 3600,  # Keep revoked tokens 1 hour past expiry
    ) -> None:
        """Initialize Redis storage.

        Args:
            redis_url: Redis connection URL.
            key_prefix: Prefix for all Redis keys.
            ttl_buffer: Extra seconds to keep revoked tokens.
        """
        self.redis_url = redis_url
        self.key_prefix = key_prefix
        self.ttl_buffer = ttl_buffer
        self._redis: Any = None

    async def initialize(self) -> None:
        """Initialize Redis connection."""
        if self._redis is not None:
            return

        try:
            import redis.asyncio as redis

            self._redis = redis.from_url(self.redis_url, decode_responses=True)
            # Test connection
            await self._redis.ping()
        except ImportError as err:
            raise ImportError("Redis package required. Install with: pip install redis") from err

    async def close(self) -> None:
        """Close Redis connection."""
        if self._redis:
            await self._redis.close()
            self._redis = None

    def _key(self, *parts: str) -> str:
        """Build a Redis key with prefix."""
        return self.key_prefix + ":".join(parts)

    async def store_api_key(self, key_hash: str, api_key: APIKey) -> None:
        await self.initialize()

        key = self._key("apikey", key_hash)
        data = api_key.to_dict()

        # Store as hash
        await self._redis.hset(
            key,
            mapping={
                k: json.dumps(v) if isinstance(v, (list, dict)) else str(v) if v is not None else ""
                for k, v in data.items()
            },
        )

        # Add to client's key set
        await self._redis.sadd(
            self._key("client_keys", api_key.client_id),
            key_hash,
        )

        # Set TTL if key expires
        if api_key.expires_at:
            ttl = int((api_key.expires_at - datetime.now(UTC)).total_seconds())
            if ttl > 0:
                await self._redis.expire(key, ttl + self.ttl_buffer)

    async def get_api_key(self, key_hash: str) -> APIKey | None:
        await self.initialize()

        key = self._key("apikey", key_hash)
        data = await self._redis.hgetall(key)

        if not data:
            return None

        # Parse stored data
        return APIKey(
            key_id=data.get("key_id", ""),
            key_hash=data.get("key_hash", key_hash),
            client_id=data.get("client_id", ""),
            name=data.get("name", ""),
            scopes=json.loads(data.get("scopes", "[]")),
            created_at=datetime.fromisoformat(data["created_at"])
            if data.get("created_at")
            else datetime.now(UTC),
            expires_at=datetime.fromisoformat(data["expires_at"])
            if data.get("expires_at")
            else None,
            last_used_at=datetime.fromisoformat(data["last_used_at"])
            if data.get("last_used_at")
            else None,
            revoked=data.get("revoked", "False").lower() == "true",
            metadata=json.loads(data.get("metadata", "{}")),
        )

    async def delete_api_key(self, key_hash: str) -> bool:
        await self.initialize()

        key = self._key("apikey", key_hash)

        # Get client_id to remove from set
        api_key = await self.get_api_key(key_hash)
        if api_key:
            await self._redis.srem(
                self._key("client_keys", api_key.client_id),
                key_hash,
            )

        result = await self._redis.delete(key)
        return result > 0

    async def list_api_keys(self, client_id: str | None = None) -> list[APIKey]:
        await self.initialize()

        if client_id:
            # Get keys for specific client
            key_hashes = await self._redis.smembers(self._key("client_keys", client_id))
        else:
            # Scan for all API key hashes
            key_hashes = set()
            pattern = self._key("apikey", "*")
            async for key in self._redis.scan_iter(pattern):
                # Extract hash from key
                key_hash = key.split(":")[-1]
                key_hashes.add(key_hash)

        result = []
        for key_hash in key_hashes:
            api_key = await self.get_api_key(key_hash)
            if api_key:
                result.append(api_key)

        return result

    async def update_api_key_last_used(self, key_hash: str) -> None:
        await self.initialize()

        key = self._key("apikey", key_hash)
        await self._redis.hset(
            key,
            "last_used_at",
            datetime.now(UTC).isoformat(),
        )

    async def revoke_token(self, jti: str, expires_at: datetime) -> None:
        await self.initialize()

        key = self._key("revoked", jti)

        # Calculate TTL
        ttl = int((expires_at - datetime.now(UTC)).total_seconds())
        ttl = max(ttl + self.ttl_buffer, 1)  # At least 1 second

        await self._redis.setex(key, ttl, expires_at.isoformat())

    async def is_token_revoked(self, jti: str) -> bool:
        await self.initialize()

        key = self._key("revoked", jti)
        return await self._redis.exists(key) > 0

    async def cleanup_expired_revocations(self) -> int:
        """Cleanup is automatic with Redis TTL."""
        return 0

    async def store_user(self, user_id: str, data: dict[str, Any]) -> None:
        await self.initialize()

        key = self._key("user", user_id)
        await self._redis.set(key, json.dumps(data))

    async def get_user(self, user_id: str) -> dict[str, Any] | None:
        await self.initialize()

        key = self._key("user", user_id)
        data = await self._redis.get(key)
        if data:
            return json.loads(data)
        return None


# ==============================================================================
# Storage Factory
# ==============================================================================


def create_storage(
    backend: str = "memory",
    **kwargs: Any,
) -> AuthStorage:
    """Create a storage backend.

    Args:
        backend: Storage backend type ('memory', 'sqlite', 'redis').
        **kwargs: Backend-specific configuration.

    Returns:
        Configured AuthStorage instance.

    Raises:
        ValueError: If backend is unknown.
    """
    backends = {
        "memory": InMemoryStorage,
        "sqlite": SQLiteStorage,
        "redis": RedisStorage,
    }

    if backend not in backends:
        raise ValueError(f"Unknown storage backend: {backend}")

    return backends[backend](**kwargs)
