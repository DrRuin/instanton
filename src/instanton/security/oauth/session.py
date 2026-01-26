"""Session management for OAuth authentication.

Provides in-memory session storage with automatic expiration cleanup.
Sessions are stored server-side with only a secure session ID sent to clients.
"""

from __future__ import annotations

import asyncio
import secrets
import time
from dataclasses import dataclass, field
from typing import Any


@dataclass
class Session:
    """User session after OAuth authentication.

    Stores user identity and claims from the OAuth provider.
    Sessions are identified by a cryptographically secure session_id.
    """

    session_id: str
    user_email: str
    user_name: str | None
    provider: str
    claims: dict[str, Any] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)
    expires_at: float = 0.0

    def __post_init__(self):
        """Set default expiration if not provided."""
        if self.expires_at == 0.0:
            # Default 24 hour expiration
            self.expires_at = self.created_at + 86400

    @property
    def is_expired(self) -> bool:
        """Check if session has expired."""
        return time.time() > self.expires_at

    @property
    def remaining_seconds(self) -> float:
        """Get remaining session lifetime in seconds."""
        return max(0.0, self.expires_at - time.time())


class SessionManager:
    """In-memory session storage with expiration cleanup.

    Manages user sessions for OAuth authentication. Sessions are stored
    in memory and automatically cleaned up when expired.

    Thread-safe via asyncio locks for concurrent access.
    """

    def __init__(
        self,
        cleanup_interval: float = 300.0,
        session_duration: int = 86400,
    ):
        """Initialize session manager.

        Args:
            cleanup_interval: How often to run cleanup in seconds (default 5 min)
            session_duration: Default session duration in seconds (default 24 hours)
        """
        self._sessions: dict[str, Session] = {}
        self._cleanup_interval = cleanup_interval
        self._session_duration = session_duration
        self._cleanup_task: asyncio.Task | None = None
        self._lock = asyncio.Lock()

    async def start(self) -> None:
        """Start the background cleanup task."""
        if self._cleanup_task is None:
            self._cleanup_task = asyncio.create_task(self._cleanup_loop())

    async def stop(self) -> None:
        """Stop the background cleanup task."""
        if self._cleanup_task:
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass
            self._cleanup_task = None

    async def create_session(
        self,
        user_email: str,
        user_name: str | None,
        provider: str,
        claims: dict[str, Any] | None = None,
        duration: int | None = None,
    ) -> Session:
        """Create a new session with secure random ID.

        Args:
            user_email: The authenticated user's email
            user_name: The user's display name (optional)
            provider: The OAuth provider name
            claims: Full OIDC claims from the provider
            duration: Session duration in seconds (uses default if not specified)

        Returns:
            The created Session object
        """
        session_id = secrets.token_urlsafe(32)
        duration = duration or self._session_duration
        now = time.time()

        session = Session(
            session_id=session_id,
            user_email=user_email,
            user_name=user_name,
            provider=provider,
            claims=claims or {},
            created_at=now,
            expires_at=now + duration,
        )

        async with self._lock:
            self._sessions[session_id] = session

        return session

    async def get_session(self, session_id: str) -> Session | None:
        """Retrieve a session by ID.

        Returns None if the session doesn't exist or has expired.
        Expired sessions are removed when accessed.

        Args:
            session_id: The session identifier from the cookie

        Returns:
            The Session if valid, None otherwise
        """
        async with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                return None

            if session.is_expired:
                del self._sessions[session_id]
                return None

            return session

    async def delete_session(self, session_id: str) -> bool:
        """Explicitly invalidate a session (logout).

        Args:
            session_id: The session identifier to delete

        Returns:
            True if session was deleted, False if not found
        """
        async with self._lock:
            if session_id in self._sessions:
                del self._sessions[session_id]
                return True
            return False

    async def get_session_count(self) -> int:
        """Get the current number of active sessions."""
        async with self._lock:
            return len(self._sessions)

    async def _cleanup_loop(self) -> None:
        """Background task to remove expired sessions."""
        while True:
            try:
                await asyncio.sleep(self._cleanup_interval)
                await self._cleanup_expired()
            except asyncio.CancelledError:
                break

    async def _cleanup_expired(self) -> int:
        """Remove all expired sessions.

        Returns:
            Number of sessions removed
        """
        now = time.time()
        removed = 0

        async with self._lock:
            expired_ids = [
                sid for sid, session in self._sessions.items()
                if session.expires_at < now
            ]
            for sid in expired_ids:
                del self._sessions[sid]
                removed += 1

        return removed
