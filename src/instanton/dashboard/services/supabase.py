"""Storage backend wrapper for Instanton Dashboard.

Supports multiple backends:
- SQLite (local, simple)
- PostgreSQL (self-hosted, production)
- Supabase (cloud mode)
"""

from __future__ import annotations

import sqlite3
import threading
from abc import ABC, abstractmethod
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from supabase import Client

from instanton.dashboard.config import DashboardConfig, DatabaseType

# Global storage instances
_supabase_client: Client | None = None
_storage: BaseStorage | None = None
_config: DashboardConfig | None = None


def init_storage(config: DashboardConfig) -> None:
    """Initialize storage backend based on config.

    Supports:
    - SQLite: sqlite:///path/to/db.sqlite or sqlite::memory:
    - PostgreSQL: postgresql://user:pass@host:port/dbname
    - Supabase: Cloud mode with Supabase credentials
    """
    global _config, _supabase_client, _storage

    _config = config

    db_type = config.database_type

    if db_type == DatabaseType.SUPABASE:
        _init_supabase(config)
    elif db_type == DatabaseType.POSTGRESQL:
        _init_postgresql(config)
    else:
        _init_sqlite(config)


def _init_supabase(config: DashboardConfig) -> None:
    """Initialize Supabase client."""
    global _supabase_client

    if _supabase_client is not None:
        return

    missing = config.validate_cloud_config()
    if missing:
        raise ValueError(f"Missing cloud config: {', '.join(missing)}")

    from supabase import create_client

    _supabase_client = create_client(
        config.supabase_url,  # type: ignore
        config.supabase_anon_key,  # type: ignore
    )


def _init_postgresql(config: DashboardConfig) -> None:
    """Initialize PostgreSQL storage."""
    global _storage

    if _storage is not None:
        return

    _storage = PostgresStorage(config.effective_database_url)
    _storage.initialize()


def _init_sqlite(config: DashboardConfig) -> None:
    """Initialize SQLite storage."""
    global _storage

    if _storage is not None:
        return

    # Parse SQLite path from URL
    db_url = config.effective_database_url
    if db_url == "sqlite::memory:":
        db_path = ":memory:"
    elif db_url.startswith("sqlite:///"):
        db_path = db_url[10:]  # Remove "sqlite:///"
    else:
        db_path = config.local_storage_path

    _storage = SQLiteStorage(db_path)
    _storage.initialize()


def get_supabase_client() -> Client:
    """Get Supabase client (cloud mode only).

    Raises:
        RuntimeError: If not in cloud mode or not initialized.
    """
    if _config is None:
        raise RuntimeError("Storage not initialized. Call init_storage() first.")

    if _config.database_type != DatabaseType.SUPABASE:
        raise RuntimeError("Supabase client only available in cloud mode.")

    if _supabase_client is None:
        raise RuntimeError("Supabase client not initialized.")

    return _supabase_client


def get_storage() -> BaseStorage:
    """Get the storage backend (SQLite or PostgreSQL).

    Raises:
        RuntimeError: If using Supabase or not initialized.
    """
    if _config is None:
        raise RuntimeError("Storage not initialized. Call init_storage() first.")

    if _config.database_type == DatabaseType.SUPABASE:
        raise RuntimeError("Use get_supabase_client() for Supabase mode.")

    if _storage is None:
        raise RuntimeError("Storage not initialized.")

    return _storage


def get_local_storage() -> BaseStorage:
    """Get local storage (backwards compatibility alias for get_storage)."""
    return get_storage()


def get_config() -> DashboardConfig:
    """Get current dashboard config."""
    if _config is None:
        raise RuntimeError("Storage not initialized. Call init_storage() first.")
    return _config


def is_cloud_mode() -> bool:
    """Check if running in cloud/Supabase mode."""
    return _config is not None and _config.database_type == DatabaseType.SUPABASE


def is_local_mode() -> bool:
    """Check if running in local/self-hosted mode (SQLite or PostgreSQL)."""
    return _config is not None and _config.database_type != DatabaseType.SUPABASE


def is_postgresql() -> bool:
    """Check if using PostgreSQL backend."""
    return _config is not None and _config.database_type == DatabaseType.POSTGRESQL


def is_sqlite() -> bool:
    """Check if using SQLite backend."""
    return _config is not None and _config.database_type == DatabaseType.SQLITE


# =============================================================================
# Abstract Base Storage
# =============================================================================


class BaseStorage(ABC):
    """Abstract base class for storage backends."""

    @abstractmethod
    def initialize(self) -> None:
        """Initialize database schema."""

    @abstractmethod
    def close(self) -> None:
        """Close database connection."""

    # Tunnel operations
    @abstractmethod
    def save_tunnel(self, tunnel: dict[str, Any]) -> None:
        """Save or update a tunnel."""

    @abstractmethod
    def get_tunnel(self, tunnel_id: str) -> dict[str, Any] | None:
        """Get tunnel by ID."""

    @abstractmethod
    def list_tunnels(self, status: str | None = None) -> list[dict[str, Any]]:
        """List tunnels, optionally filtered by status."""

    @abstractmethod
    def update_tunnel_status(self, tunnel_id: str, status: str) -> None:
        """Update tunnel status."""

    # Traffic log operations
    @abstractmethod
    def log_traffic(self, log: dict[str, Any]) -> int:
        """Log a traffic entry."""

    @abstractmethod
    def list_traffic_logs(
        self,
        tunnel_id: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """List traffic logs."""

    @abstractmethod
    def get_traffic_log(self, log_id: int) -> dict[str, Any] | None:
        """Get traffic log by ID."""

    @abstractmethod
    def count_traffic_logs(self, tunnel_id: str | None = None) -> int:
        """Count traffic logs."""

    @abstractmethod
    def cleanup_old_logs(self, max_logs: int) -> int:
        """Delete oldest logs if count exceeds max."""

    # Token operations
    @abstractmethod
    def save_token(self, token: dict[str, Any]) -> None:
        """Save or update an API token."""

    @abstractmethod
    def get_token(self, token_id: str) -> dict[str, Any] | None:
        """Get token by ID."""

    @abstractmethod
    def get_token_by_hash(self, token_hash: str) -> dict[str, Any] | None:
        """Get token by hash."""

    @abstractmethod
    def list_tokens(self, user_id: str | None = None) -> list[dict[str, Any]]:
        """List all tokens."""

    @abstractmethod
    def revoke_token(self, token_id: str) -> bool:
        """Revoke a token."""

    @abstractmethod
    def increment_token_usage(self, token_id: str) -> None:
        """Increment token usage counter."""

    # Anti-abuse operations (optional, for self-hosted with auth)
    def count_accounts_by_ip(self, ip: str) -> int:
        """Count accounts created from an IP address."""
        return 0

    def count_accounts_by_fingerprint(self, fingerprint: str) -> int:
        """Count accounts with the same browser fingerprint."""
        return 0

    def save_user(self, user: dict[str, Any]) -> None:
        """Save a user (self-hosted auth mode)."""

    def get_user_by_email(self, email: str) -> dict[str, Any] | None:
        """Get user by email."""
        return None

    def get_user(self, user_id: str) -> dict[str, Any] | None:
        """Get user by ID."""
        return None


# =============================================================================
# SQLite Storage Implementation
# =============================================================================


class SQLiteStorage(BaseStorage):
    """SQLite storage backend for self-hosted mode.

    Provides a lightweight, file-based database for single-server deployments.
    """

    def __init__(self, db_path: str | Path = "instanton_dashboard.db") -> None:
        """Initialize SQLite storage.

        Args:
            db_path: Path to SQLite database file, or ":memory:" for in-memory.
        """
        self.db_path = str(db_path)
        self._local = threading.local()
        self._initialized = False

    def _get_connection(self) -> sqlite3.Connection:
        """Get thread-local database connection."""
        if not hasattr(self._local, "connection"):
            conn = sqlite3.connect(
                self.db_path,
                check_same_thread=False,
            )
            conn.row_factory = sqlite3.Row
            self._local.connection = conn
        return self._local.connection

    @contextmanager
    def cursor(self) -> Iterator[sqlite3.Cursor]:
        """Get a cursor with automatic commit/rollback."""
        conn = self._get_connection()
        cur = conn.cursor()
        try:
            yield cur
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            cur.close()

    def initialize(self) -> None:
        """Initialize database schema."""
        if self._initialized:
            return

        with self.cursor() as cur:
            # Users table (for self-hosted auth)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id TEXT PRIMARY KEY,
                    email TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    display_name TEXT,
                    tier TEXT DEFAULT 'free',
                    max_tunnels INTEGER DEFAULT 999999,
                    max_requests_per_day INTEGER DEFAULT 999999999,
                    signup_ip TEXT,
                    signup_fingerprint TEXT,
                    created_at TEXT NOT NULL,
                    last_login_at TEXT
                )
            """)

            # Tunnels table
            cur.execute("""
                CREATE TABLE IF NOT EXISTS tunnels (
                    id TEXT PRIMARY KEY,
                    user_id TEXT,
                    subdomain TEXT UNIQUE NOT NULL,
                    tunnel_type TEXT NOT NULL,
                    local_port INTEGER NOT NULL,
                    public_url TEXT NOT NULL,
                    connected_at TEXT NOT NULL,
                    last_activity_at TEXT,
                    disconnected_at TEXT,
                    client_ip TEXT,
                    client_version TEXT,
                    status TEXT DEFAULT 'active',
                    FOREIGN KEY (user_id) REFERENCES users(id)
                )
            """)

            # Traffic logs table
            cur.execute("""
                CREATE TABLE IF NOT EXISTS traffic_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    tunnel_id TEXT NOT NULL,
                    user_id TEXT,
                    request_method TEXT NOT NULL,
                    request_path TEXT NOT NULL,
                    request_headers TEXT,
                    request_body TEXT,
                    request_size INTEGER,
                    response_status INTEGER,
                    response_headers TEXT,
                    response_body TEXT,
                    response_size INTEGER,
                    response_time_ms INTEGER,
                    client_ip TEXT,
                    timestamp TEXT NOT NULL,
                    FOREIGN KEY (tunnel_id) REFERENCES tunnels(id),
                    FOREIGN KEY (user_id) REFERENCES users(id)
                )
            """)

            # API tokens table
            cur.execute("""
                CREATE TABLE IF NOT EXISTS api_tokens (
                    id TEXT PRIMARY KEY,
                    user_id TEXT,
                    name TEXT NOT NULL,
                    token_hash TEXT UNIQUE NOT NULL,
                    token_prefix TEXT NOT NULL,
                    scopes TEXT,
                    created_at TEXT NOT NULL,
                    last_used_at TEXT,
                    expires_at TEXT,
                    revoked_at TEXT,
                    total_requests INTEGER DEFAULT 0,
                    FOREIGN KEY (user_id) REFERENCES users(id)
                )
            """)

            # Create indexes
            cur.execute("""
                CREATE INDEX IF NOT EXISTS idx_traffic_logs_tunnel_timestamp
                ON traffic_logs(tunnel_id, timestamp DESC)
            """)

            cur.execute("""
                CREATE INDEX IF NOT EXISTS idx_tunnels_status
                ON tunnels(status)
            """)

            cur.execute("""
                CREATE INDEX IF NOT EXISTS idx_users_signup_ip
                ON users(signup_ip)
            """)

            cur.execute("""
                CREATE INDEX IF NOT EXISTS idx_users_signup_fingerprint
                ON users(signup_fingerprint)
            """)

        self._initialized = True

    def close(self) -> None:
        """Close database connection."""
        if hasattr(self._local, "connection"):
            self._local.connection.close()
            del self._local.connection

    # Tunnel operations

    def save_tunnel(self, tunnel: dict[str, Any]) -> None:
        """Save or update a tunnel."""
        with self.cursor() as cur:
            cur.execute(
                """
                INSERT OR REPLACE INTO tunnels
                (id, subdomain, tunnel_type, local_port, public_url,
                 connected_at, last_activity_at, disconnected_at,
                 client_ip, client_version, status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    tunnel["id"],
                    tunnel["subdomain"],
                    tunnel["tunnel_type"],
                    tunnel["local_port"],
                    tunnel["public_url"],
                    tunnel["connected_at"],
                    tunnel.get("last_activity_at"),
                    tunnel.get("disconnected_at"),
                    tunnel.get("client_ip"),
                    tunnel.get("client_version"),
                    tunnel.get("status", "active"),
                ),
            )

    def get_tunnel(self, tunnel_id: str) -> dict[str, Any] | None:
        """Get tunnel by ID."""
        with self.cursor() as cur:
            cur.execute("SELECT * FROM tunnels WHERE id = ?", (tunnel_id,))
            row = cur.fetchone()
            return dict(row) if row else None

    def list_tunnels(self, status: str | None = None) -> list[dict[str, Any]]:
        """List tunnels, optionally filtered by status."""
        with self.cursor() as cur:
            if status:
                cur.execute("SELECT * FROM tunnels WHERE status = ?", (status,))
            else:
                cur.execute("SELECT * FROM tunnels")
            return [dict(row) for row in cur.fetchall()]

    def update_tunnel_status(self, tunnel_id: str, status: str) -> None:
        """Update tunnel status."""
        with self.cursor() as cur:
            cur.execute(
                "UPDATE tunnels SET status = ?, last_activity_at = ? WHERE id = ?",
                (status, datetime.now(UTC).isoformat(), tunnel_id),
            )

    # Traffic log operations

    def log_traffic(self, log: dict[str, Any]) -> int:
        """Log a traffic entry."""
        with self.cursor() as cur:
            cur.execute(
                """
                INSERT INTO traffic_logs
                (tunnel_id, request_method, request_path, request_headers,
                 request_body, request_size, response_status, response_headers,
                 response_body, response_size, response_time_ms, client_ip, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    log["tunnel_id"],
                    log["request_method"],
                    log["request_path"],
                    log.get("request_headers"),
                    log.get("request_body"),
                    log.get("request_size"),
                    log.get("response_status"),
                    log.get("response_headers"),
                    log.get("response_body"),
                    log.get("response_size"),
                    log.get("response_time_ms"),
                    log.get("client_ip"),
                    log.get("timestamp", datetime.now(UTC).isoformat()),
                ),
            )
            return cur.lastrowid or 0

    def list_traffic_logs(
        self,
        tunnel_id: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """List traffic logs."""
        with self.cursor() as cur:
            if tunnel_id:
                cur.execute(
                    """
                    SELECT * FROM traffic_logs
                    WHERE tunnel_id = ?
                    ORDER BY timestamp DESC
                    LIMIT ? OFFSET ?
                """,
                    (tunnel_id, limit, offset),
                )
            else:
                cur.execute(
                    """
                    SELECT * FROM traffic_logs
                    ORDER BY timestamp DESC
                    LIMIT ? OFFSET ?
                """,
                    (limit, offset),
                )
            return [dict(row) for row in cur.fetchall()]

    def get_traffic_log(self, log_id: int) -> dict[str, Any] | None:
        """Get traffic log by ID."""
        with self.cursor() as cur:
            cur.execute("SELECT * FROM traffic_logs WHERE id = ?", (log_id,))
            row = cur.fetchone()
            return dict(row) if row else None

    def count_traffic_logs(self, tunnel_id: str | None = None) -> int:
        """Count traffic logs."""
        with self.cursor() as cur:
            if tunnel_id:
                cur.execute(
                    "SELECT COUNT(*) FROM traffic_logs WHERE tunnel_id = ?",
                    (tunnel_id,),
                )
            else:
                cur.execute("SELECT COUNT(*) FROM traffic_logs")
            return cur.fetchone()[0]

    def cleanup_old_logs(self, max_logs: int) -> int:
        """Delete oldest logs if count exceeds max."""
        with self.cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM traffic_logs")
            count = cur.fetchone()[0]

            if count <= max_logs:
                return 0

            to_delete = count - max_logs
            cur.execute(
                """
                DELETE FROM traffic_logs
                WHERE id IN (
                    SELECT id FROM traffic_logs
                    ORDER BY timestamp ASC
                    LIMIT ?
                )
            """,
                (to_delete,),
            )
            return cur.rowcount

    # Token operations

    def save_token(self, token: dict[str, Any]) -> None:
        """Save or update an API token."""
        with self.cursor() as cur:
            cur.execute(
                """
                INSERT OR REPLACE INTO api_tokens
                (id, name, token_hash, token_prefix, scopes,
                 created_at, last_used_at, expires_at, revoked_at, total_requests)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    token["id"],
                    token["name"],
                    token["token_hash"],
                    token["token_prefix"],
                    token.get("scopes"),
                    token["created_at"],
                    token.get("last_used_at"),
                    token.get("expires_at"),
                    token.get("revoked_at"),
                    token.get("total_requests", 0),
                ),
            )

    def get_token(self, token_id: str) -> dict[str, Any] | None:
        """Get token by ID."""
        with self.cursor() as cur:
            cur.execute("SELECT * FROM api_tokens WHERE id = ?", (token_id,))
            row = cur.fetchone()
            return dict(row) if row else None

    def get_token_by_hash(self, token_hash: str) -> dict[str, Any] | None:
        """Get token by hash."""
        with self.cursor() as cur:
            cur.execute("SELECT * FROM api_tokens WHERE token_hash = ?", (token_hash,))
            row = cur.fetchone()
            return dict(row) if row else None

    def list_tokens(self, user_id: str | None = None) -> list[dict[str, Any]]:
        """List all tokens, optionally filtered by user."""
        with self.cursor() as cur:
            if user_id:
                cur.execute(
                    "SELECT * FROM api_tokens WHERE user_id = ? AND revoked_at IS NULL",
                    (user_id,),
                )
            else:
                cur.execute("SELECT * FROM api_tokens WHERE revoked_at IS NULL")
            return [dict(row) for row in cur.fetchall()]

    def revoke_token(self, token_id: str) -> bool:
        """Revoke a token."""
        with self.cursor() as cur:
            cur.execute(
                "UPDATE api_tokens SET revoked_at = ? WHERE id = ?",
                (datetime.now(UTC).isoformat(), token_id),
            )
            return cur.rowcount > 0

    def increment_token_usage(self, token_id: str) -> None:
        """Increment token usage counter."""
        with self.cursor() as cur:
            cur.execute(
                """
                UPDATE api_tokens
                SET total_requests = total_requests + 1, last_used_at = ?
                WHERE id = ?
            """,
                (datetime.now(UTC).isoformat(), token_id),
            )

    # Anti-abuse operations

    def count_accounts_by_ip(self, ip: str) -> int:
        """Count accounts created from an IP address."""
        with self.cursor() as cur:
            cur.execute(
                "SELECT COUNT(*) FROM users WHERE signup_ip = ?",
                (ip,),
            )
            return cur.fetchone()[0]

    def count_accounts_by_fingerprint(self, fingerprint: str) -> int:
        """Count accounts with the same browser fingerprint."""
        with self.cursor() as cur:
            cur.execute(
                "SELECT COUNT(*) FROM users WHERE signup_fingerprint = ?",
                (fingerprint,),
            )
            return cur.fetchone()[0]

    def save_user(self, user: dict[str, Any]) -> None:
        """Save a user (self-hosted auth mode)."""
        with self.cursor() as cur:
            cur.execute(
                """
                INSERT OR REPLACE INTO users
                (id, email, password_hash, display_name, tier,
                 max_tunnels, max_requests_per_day, signup_ip,
                 signup_fingerprint, created_at, last_login_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    user["id"],
                    user["email"],
                    user["password_hash"],
                    user.get("display_name"),
                    user.get("tier", "free"),
                    user.get("max_tunnels", 999999),
                    user.get("max_requests_per_day", 999999999),
                    user.get("signup_ip"),
                    user.get("signup_fingerprint"),
                    user.get("created_at", datetime.now(UTC).isoformat()),
                    user.get("last_login_at"),
                ),
            )

    def get_user_by_email(self, email: str) -> dict[str, Any] | None:
        """Get user by email."""
        with self.cursor() as cur:
            cur.execute("SELECT * FROM users WHERE email = ?", (email,))
            row = cur.fetchone()
            return dict(row) if row else None

    def get_user(self, user_id: str) -> dict[str, Any] | None:
        """Get user by ID."""
        with self.cursor() as cur:
            cur.execute("SELECT * FROM users WHERE id = ?", (user_id,))
            row = cur.fetchone()
            return dict(row) if row else None


# =============================================================================
# PostgreSQL Storage Implementation
# =============================================================================


class PostgresStorage(BaseStorage):
    """PostgreSQL storage backend for production self-hosted deployments.

    Requires psycopg2 or asyncpg to be installed.
    """

    def __init__(self, database_url: str) -> None:
        """Initialize PostgreSQL storage.

        Args:
            database_url: PostgreSQL connection string.
        """
        self.database_url = database_url
        self._conn: Any = None
        self._initialized = False

    def _get_connection(self) -> Any:
        """Get database connection."""
        if self._conn is None:
            try:
                import psycopg2
                import psycopg2.extras

                self._conn = psycopg2.connect(self.database_url)
                self._conn.autocommit = False
            except ImportError:
                raise ImportError(
                    "PostgreSQL support requires psycopg2. "
                    "Install with: pip install psycopg2-binary"
                )
        return self._conn

    @contextmanager
    def cursor(self) -> Iterator[Any]:
        """Get a cursor with automatic commit/rollback."""
        import psycopg2.extras

        conn = self._get_connection()
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        try:
            yield cur
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            cur.close()

    def initialize(self) -> None:
        """Initialize database schema."""
        if self._initialized:
            return

        with self.cursor() as cur:
            # Users table
            cur.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id TEXT PRIMARY KEY,
                    email TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    display_name TEXT,
                    tier TEXT DEFAULT 'free',
                    max_tunnels INTEGER DEFAULT 999999,
                    max_requests_per_day INTEGER DEFAULT 999999999,
                    signup_ip INET,
                    signup_fingerprint TEXT,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    last_login_at TIMESTAMPTZ
                )
            """)

            # Tunnels table
            cur.execute("""
                CREATE TABLE IF NOT EXISTS tunnels (
                    id TEXT PRIMARY KEY,
                    user_id TEXT REFERENCES users(id),
                    subdomain TEXT UNIQUE NOT NULL,
                    tunnel_type TEXT NOT NULL,
                    local_port INTEGER NOT NULL,
                    public_url TEXT NOT NULL,
                    connected_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    last_activity_at TIMESTAMPTZ,
                    disconnected_at TIMESTAMPTZ,
                    client_ip INET,
                    client_version TEXT,
                    status TEXT DEFAULT 'active'
                )
            """)

            # Traffic logs table
            cur.execute("""
                CREATE TABLE IF NOT EXISTS traffic_logs (
                    id SERIAL PRIMARY KEY,
                    tunnel_id TEXT NOT NULL REFERENCES tunnels(id),
                    user_id TEXT REFERENCES users(id),
                    request_method TEXT NOT NULL,
                    request_path TEXT NOT NULL,
                    request_headers JSONB,
                    request_body TEXT,
                    request_size INTEGER,
                    response_status INTEGER,
                    response_headers JSONB,
                    response_body TEXT,
                    response_size INTEGER,
                    response_time_ms INTEGER,
                    client_ip INET,
                    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW()
                )
            """)

            # API tokens table
            cur.execute("""
                CREATE TABLE IF NOT EXISTS api_tokens (
                    id TEXT PRIMARY KEY,
                    user_id TEXT REFERENCES users(id),
                    name TEXT NOT NULL,
                    token_hash TEXT UNIQUE NOT NULL,
                    token_prefix TEXT NOT NULL,
                    scopes TEXT[],
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    last_used_at TIMESTAMPTZ,
                    expires_at TIMESTAMPTZ,
                    revoked_at TIMESTAMPTZ,
                    total_requests BIGINT DEFAULT 0
                )
            """)

            # Create indexes
            cur.execute("""
                CREATE INDEX IF NOT EXISTS idx_traffic_logs_tunnel_timestamp
                ON traffic_logs(tunnel_id, timestamp DESC)
            """)

            cur.execute("""
                CREATE INDEX IF NOT EXISTS idx_tunnels_status
                ON tunnels(status)
            """)

            cur.execute("""
                CREATE INDEX IF NOT EXISTS idx_users_signup_ip
                ON users(signup_ip)
            """)

            cur.execute("""
                CREATE INDEX IF NOT EXISTS idx_users_signup_fingerprint
                ON users(signup_fingerprint)
            """)

        self._initialized = True

    def close(self) -> None:
        """Close database connection."""
        if self._conn is not None:
            self._conn.close()
            self._conn = None

    # Tunnel operations

    def save_tunnel(self, tunnel: dict[str, Any]) -> None:
        """Save or update a tunnel."""
        with self.cursor() as cur:
            cur.execute(
                """
                INSERT INTO tunnels
                (id, user_id, subdomain, tunnel_type, local_port, public_url,
                 connected_at, last_activity_at, disconnected_at,
                 client_ip, client_version, status)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (id) DO UPDATE SET
                    subdomain = EXCLUDED.subdomain,
                    last_activity_at = EXCLUDED.last_activity_at,
                    disconnected_at = EXCLUDED.disconnected_at,
                    status = EXCLUDED.status
            """,
                (
                    tunnel["id"],
                    tunnel.get("user_id"),
                    tunnel["subdomain"],
                    tunnel["tunnel_type"],
                    tunnel["local_port"],
                    tunnel["public_url"],
                    tunnel["connected_at"],
                    tunnel.get("last_activity_at"),
                    tunnel.get("disconnected_at"),
                    tunnel.get("client_ip"),
                    tunnel.get("client_version"),
                    tunnel.get("status", "active"),
                ),
            )

    def get_tunnel(self, tunnel_id: str) -> dict[str, Any] | None:
        """Get tunnel by ID."""
        with self.cursor() as cur:
            cur.execute("SELECT * FROM tunnels WHERE id = %s", (tunnel_id,))
            row = cur.fetchone()
            return dict(row) if row else None

    def list_tunnels(self, status: str | None = None) -> list[dict[str, Any]]:
        """List tunnels, optionally filtered by status."""
        with self.cursor() as cur:
            if status:
                cur.execute("SELECT * FROM tunnels WHERE status = %s", (status,))
            else:
                cur.execute("SELECT * FROM tunnels")
            return [dict(row) for row in cur.fetchall()]

    def update_tunnel_status(self, tunnel_id: str, status: str) -> None:
        """Update tunnel status."""
        with self.cursor() as cur:
            cur.execute(
                "UPDATE tunnels SET status = %s, last_activity_at = NOW() WHERE id = %s",
                (status, tunnel_id),
            )

    # Traffic log operations

    def log_traffic(self, log: dict[str, Any]) -> int:
        """Log a traffic entry."""
        with self.cursor() as cur:
            cur.execute(
                """
                INSERT INTO traffic_logs
                (tunnel_id, user_id, request_method, request_path, request_headers,
                 request_body, request_size, response_status, response_headers,
                 response_body, response_size, response_time_ms, client_ip, timestamp)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING id
            """,
                (
                    log["tunnel_id"],
                    log.get("user_id"),
                    log["request_method"],
                    log["request_path"],
                    log.get("request_headers"),
                    log.get("request_body"),
                    log.get("request_size"),
                    log.get("response_status"),
                    log.get("response_headers"),
                    log.get("response_body"),
                    log.get("response_size"),
                    log.get("response_time_ms"),
                    log.get("client_ip"),
                    log.get("timestamp", datetime.now(UTC)),
                ),
            )
            result = cur.fetchone()
            return result["id"] if result else 0

    def list_traffic_logs(
        self,
        tunnel_id: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """List traffic logs."""
        with self.cursor() as cur:
            if tunnel_id:
                cur.execute(
                    """
                    SELECT * FROM traffic_logs
                    WHERE tunnel_id = %s
                    ORDER BY timestamp DESC
                    LIMIT %s OFFSET %s
                """,
                    (tunnel_id, limit, offset),
                )
            else:
                cur.execute(
                    """
                    SELECT * FROM traffic_logs
                    ORDER BY timestamp DESC
                    LIMIT %s OFFSET %s
                """,
                    (limit, offset),
                )
            return [dict(row) for row in cur.fetchall()]

    def get_traffic_log(self, log_id: int) -> dict[str, Any] | None:
        """Get traffic log by ID."""
        with self.cursor() as cur:
            cur.execute("SELECT * FROM traffic_logs WHERE id = %s", (log_id,))
            row = cur.fetchone()
            return dict(row) if row else None

    def count_traffic_logs(self, tunnel_id: str | None = None) -> int:
        """Count traffic logs."""
        with self.cursor() as cur:
            if tunnel_id:
                cur.execute(
                    "SELECT COUNT(*) as count FROM traffic_logs WHERE tunnel_id = %s",
                    (tunnel_id,),
                )
            else:
                cur.execute("SELECT COUNT(*) as count FROM traffic_logs")
            return cur.fetchone()["count"]

    def cleanup_old_logs(self, max_logs: int) -> int:
        """Delete oldest logs if count exceeds max."""
        with self.cursor() as cur:
            cur.execute("SELECT COUNT(*) as count FROM traffic_logs")
            count = cur.fetchone()["count"]

            if count <= max_logs:
                return 0

            to_delete = count - max_logs
            cur.execute(
                """
                DELETE FROM traffic_logs
                WHERE id IN (
                    SELECT id FROM traffic_logs
                    ORDER BY timestamp ASC
                    LIMIT %s
                )
            """,
                (to_delete,),
            )
            return cur.rowcount

    # Token operations

    def save_token(self, token: dict[str, Any]) -> None:
        """Save or update an API token."""
        with self.cursor() as cur:
            cur.execute(
                """
                INSERT INTO api_tokens
                (id, user_id, name, token_hash, token_prefix, scopes,
                 created_at, last_used_at, expires_at, revoked_at, total_requests)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (id) DO UPDATE SET
                    last_used_at = EXCLUDED.last_used_at,
                    revoked_at = EXCLUDED.revoked_at,
                    total_requests = EXCLUDED.total_requests
            """,
                (
                    token["id"],
                    token.get("user_id"),
                    token["name"],
                    token["token_hash"],
                    token["token_prefix"],
                    token.get("scopes"),
                    token["created_at"],
                    token.get("last_used_at"),
                    token.get("expires_at"),
                    token.get("revoked_at"),
                    token.get("total_requests", 0),
                ),
            )

    def get_token(self, token_id: str) -> dict[str, Any] | None:
        """Get token by ID."""
        with self.cursor() as cur:
            cur.execute("SELECT * FROM api_tokens WHERE id = %s", (token_id,))
            row = cur.fetchone()
            return dict(row) if row else None

    def get_token_by_hash(self, token_hash: str) -> dict[str, Any] | None:
        """Get token by hash."""
        with self.cursor() as cur:
            cur.execute("SELECT * FROM api_tokens WHERE token_hash = %s", (token_hash,))
            row = cur.fetchone()
            return dict(row) if row else None

    def list_tokens(self, user_id: str | None = None) -> list[dict[str, Any]]:
        """List all tokens, optionally filtered by user."""
        with self.cursor() as cur:
            if user_id:
                cur.execute(
                    "SELECT * FROM api_tokens WHERE user_id = %s AND revoked_at IS NULL",
                    (user_id,),
                )
            else:
                cur.execute("SELECT * FROM api_tokens WHERE revoked_at IS NULL")
            return [dict(row) for row in cur.fetchall()]

    def revoke_token(self, token_id: str) -> bool:
        """Revoke a token."""
        with self.cursor() as cur:
            cur.execute(
                "UPDATE api_tokens SET revoked_at = NOW() WHERE id = %s",
                (token_id,),
            )
            return cur.rowcount > 0

    def increment_token_usage(self, token_id: str) -> None:
        """Increment token usage counter."""
        with self.cursor() as cur:
            cur.execute(
                """
                UPDATE api_tokens
                SET total_requests = total_requests + 1, last_used_at = NOW()
                WHERE id = %s
            """,
                (token_id,),
            )

    # Anti-abuse operations

    def count_accounts_by_ip(self, ip: str) -> int:
        """Count accounts created from an IP address."""
        with self.cursor() as cur:
            cur.execute(
                "SELECT COUNT(*) as count FROM users WHERE signup_ip = %s::inet",
                (ip,),
            )
            return cur.fetchone()["count"]

    def count_accounts_by_fingerprint(self, fingerprint: str) -> int:
        """Count accounts with the same browser fingerprint."""
        with self.cursor() as cur:
            cur.execute(
                "SELECT COUNT(*) as count FROM users WHERE signup_fingerprint = %s",
                (fingerprint,),
            )
            return cur.fetchone()["count"]

    def save_user(self, user: dict[str, Any]) -> None:
        """Save a user (self-hosted auth mode)."""
        with self.cursor() as cur:
            cur.execute(
                """
                INSERT INTO users
                (id, email, password_hash, display_name, tier,
                 max_tunnels, max_requests_per_day, signup_ip,
                 signup_fingerprint, created_at, last_login_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s::inet, %s, %s, %s)
                ON CONFLICT (id) DO UPDATE SET
                    display_name = EXCLUDED.display_name,
                    tier = EXCLUDED.tier,
                    last_login_at = EXCLUDED.last_login_at
            """,
                (
                    user["id"],
                    user["email"],
                    user["password_hash"],
                    user.get("display_name"),
                    user.get("tier", "free"),
                    user.get("max_tunnels", 999999),
                    user.get("max_requests_per_day", 999999999),
                    user.get("signup_ip"),
                    user.get("signup_fingerprint"),
                    user.get("created_at", datetime.now(UTC)),
                    user.get("last_login_at"),
                ),
            )

    def get_user_by_email(self, email: str) -> dict[str, Any] | None:
        """Get user by email."""
        with self.cursor() as cur:
            cur.execute("SELECT * FROM users WHERE email = %s", (email,))
            row = cur.fetchone()
            return dict(row) if row else None

    def get_user(self, user_id: str) -> dict[str, Any] | None:
        """Get user by ID."""
        with self.cursor() as cur:
            cur.execute("SELECT * FROM users WHERE id = %s", (user_id,))
            row = cur.fetchone()
            return dict(row) if row else None


# Backwards compatibility alias
LocalStorage = SQLiteStorage
