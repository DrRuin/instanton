"""DashboardHandler - HTTP/WebSocket handlers for the dashboard."""

from __future__ import annotations

import base64
import secrets
import time
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

import structlog
from aiohttp import WSMsgType, web

if TYPE_CHECKING:
    from instanton.observability.dashboard.broadcaster import DashboardBroadcaster

logger = structlog.get_logger()

# Path to static files - relative to this file's location
STATIC_DIR = Path(__file__).parent.parent.parent / "static" / "dashboard"


@dataclass
class FailedAttempt:
    """Tracks failed login attempts for an IP."""

    count: int = 0
    first_attempt: float = 0.0
    last_attempt: float = 0.0
    locked_until: float = 0.0


class BruteForceProtection:
    """Protects against brute-force login attacks.

    Features:
    - Tracks failed attempts per IP
    - Locks out IP after max_failures for lockout_duration
    - Auto-cleanup of old entries
    """

    def __init__(
        self,
        max_failures: int = 5,
        lockout_duration: float = 900.0,  # 15 minutes
        cleanup_interval: float = 300.0,  # 5 minutes
    ):
        self.max_failures = max_failures
        self.lockout_duration = lockout_duration
        self.cleanup_interval = cleanup_interval
        self._attempts: dict[str, FailedAttempt] = defaultdict(FailedAttempt)
        self._last_cleanup = time.time()

    def is_locked(self, ip: str) -> tuple[bool, float]:
        """Check if an IP is locked out.

        Returns:
            (is_locked, seconds_remaining)
        """
        self._maybe_cleanup()
        attempt = self._attempts.get(ip)

        if not attempt:
            return False, 0.0

        now = time.time()

        if attempt.locked_until > now:
            return True, attempt.locked_until - now

        return False, 0.0

    def record_failure(self, ip: str) -> tuple[bool, float, int]:
        """Record a failed login attempt.

        Returns:
            (now_locked, lockout_seconds, attempt_count)
        """
        now = time.time()
        attempt = self._attempts[ip]

        # Reset if it's been a while since last attempt
        if attempt.last_attempt and (now - attempt.last_attempt) > self.lockout_duration:
            attempt.count = 0
            attempt.locked_until = 0.0

        if attempt.count == 0:
            attempt.first_attempt = now

        attempt.count += 1
        attempt.last_attempt = now

        # Lock out if max failures reached
        if attempt.count >= self.max_failures:
            attempt.locked_until = now + self.lockout_duration
            logger.warning(
                "Dashboard login locked out",
                ip=ip,
                failures=attempt.count,
                lockout_minutes=self.lockout_duration / 60,
            )
            return True, self.lockout_duration, attempt.count

        remaining = self.max_failures - attempt.count
        logger.warning(
            "Dashboard login failed",
            ip=ip,
            failures=attempt.count,
            remaining_attempts=remaining,
        )
        return False, 0.0, attempt.count

    def record_success(self, ip: str) -> None:
        """Clear failed attempts after successful login."""
        if ip in self._attempts:
            del self._attempts[ip]

    def _maybe_cleanup(self) -> None:
        """Remove old entries periodically."""
        now = time.time()
        if now - self._last_cleanup < self.cleanup_interval:
            return

        self._last_cleanup = now
        cutoff = now - self.lockout_duration * 2

        # Remove entries that are old and not locked
        to_remove = [
            ip
            for ip, attempt in self._attempts.items()
            if attempt.last_attempt < cutoff and attempt.locked_until < now
        ]

        for ip in to_remove:
            del self._attempts[ip]


class DashboardHandler:
    """Handles HTTP and WebSocket requests for the dashboard.

    Routes:
        GET /dashboard         - Serve dashboard HTML
        GET /dashboard/ws      - WebSocket for real-time updates
        GET /dashboard/static/ - Static assets (CSS, JS)

    All routes require Basic Auth when credentials are configured.
    Includes brute-force protection against password guessing.
    """

    def __init__(
        self,
        broadcaster: DashboardBroadcaster,
        username: str | None = None,
        password: str | None = None,
        max_login_failures: int = 5,
        lockout_minutes: float = 15.0,
    ):
        """Initialize the handler.

        Args:
            broadcaster: DashboardBroadcaster for WebSocket management.
            username: Required username for dashboard access.
            password: Required password for dashboard access.
            max_login_failures: Max failed logins before lockout (default: 5).
            lockout_minutes: How long to lock out an IP (default: 15 min).
        """
        self._broadcaster = broadcaster
        self._username = username
        self._password = password
        self._auth_required = bool(username and password)
        self._brute_force = BruteForceProtection(
            max_failures=max_login_failures,
            lockout_duration=lockout_minutes * 60,
        )

    def register_routes(self, app: web.Application) -> None:
        """Register dashboard routes on an aiohttp application.

        Args:
            app: The aiohttp Application to add routes to.
        """
        app.router.add_get("/dashboard", self.handle_dashboard)
        app.router.add_get("/dashboard/", self.handle_dashboard)
        app.router.add_get("/dashboard/ws", self.handle_websocket)
        app.router.add_get("/dashboard/static/{path:.*}", self.handle_static)

    def _get_client_ip(self, request: web.Request) -> str:
        """Extract client IP from request, considering proxies."""
        # Check X-Forwarded-For first (if behind reverse proxy)
        forwarded = request.headers.get("X-Forwarded-For", "")
        if forwarded:
            # Take the first IP (original client)
            return forwarded.split(",")[0].strip()

        # Check X-Real-IP
        real_ip = request.headers.get("X-Real-IP", "")
        if real_ip:
            return real_ip.strip()

        # Fall back to direct connection
        return request.remote or "unknown"

    def _check_auth(self, request: web.Request) -> web.Response | None:
        """Check Basic Auth for dashboard access with brute-force protection.

        Args:
            request: The incoming HTTP request.

        Returns:
            None if authorized, or an error Response if not.
        """
        if not self._auth_required:
            return None

        client_ip = self._get_client_ip(request)

        # Check if IP is locked out
        is_locked, seconds_remaining = self._brute_force.is_locked(client_ip)
        if is_locked:
            minutes = int(seconds_remaining / 60) + 1
            return web.Response(
                text=f"Too many failed attempts. Try again in {minutes} minutes.",
                status=429,
                headers={"Retry-After": str(int(seconds_remaining) + 1)},
            )

        auth_header = request.headers.get("Authorization", "")

        if not auth_header.startswith("Basic "):
            # No auth header - prompt for login (don't count as failure)
            return self._auth_required_response()

        try:
            # Decode base64 credentials
            encoded = auth_header[6:]  # Remove "Basic "
            decoded = base64.b64decode(encoded).decode("utf-8")
            username, password = decoded.split(":", 1)

            # Constant-time comparison to prevent timing attacks
            username_match = secrets.compare_digest(username, self._username or "")
            password_match = secrets.compare_digest(password, self._password or "")

            if username_match and password_match:
                # Success - clear any failed attempts
                self._brute_force.record_success(client_ip)
                return None  # Authorized

        except (ValueError, UnicodeDecodeError):
            pass

        # Failed login attempt - record it
        now_locked, lockout_secs, attempt_count = self._brute_force.record_failure(client_ip)

        if now_locked:
            minutes = int(lockout_secs / 60)
            return web.Response(
                text=f"Too many failed attempts. Locked out for {minutes} minutes.",
                status=429,
                headers={"Retry-After": str(int(lockout_secs))},
            )

        remaining = self._brute_force.max_failures - attempt_count
        return self._auth_failed_response(remaining)

    def _auth_required_response(self) -> web.Response:
        """Return a 401 Unauthorized response with WWW-Authenticate header."""
        return web.Response(
            text="Unauthorized - Dashboard requires authentication",
            status=401,
            headers={"WWW-Authenticate": 'Basic realm="Instanton Dashboard"'},
        )

    def _auth_failed_response(self, remaining_attempts: int) -> web.Response:
        """Return a 401 response indicating failed auth with attempts remaining."""
        return web.Response(
            text=f"Invalid credentials. {remaining_attempts} attempts remaining before lockout.",
            status=401,
            headers={"WWW-Authenticate": 'Basic realm="Instanton Dashboard"'},
        )

    async def handle_dashboard(self, request: web.Request) -> web.Response:
        """Serve the main dashboard HTML page.

        Args:
            request: The incoming HTTP request.

        Returns:
            Response with dashboard HTML.
        """
        # Check authentication
        if auth_error := self._check_auth(request):
            return auth_error

        html_path = STATIC_DIR / "index.html"

        if not html_path.exists():
            logger.error("Dashboard HTML not found", path=str(html_path))
            return web.Response(
                text="Dashboard not available - static files missing",
                status=503,
                content_type="text/plain",
            )

        try:
            html_content = html_path.read_text(encoding="utf-8")
            return web.Response(
                text=html_content,
                content_type="text/html",
            )
        except Exception as e:
            logger.error("Failed to read dashboard HTML", error=str(e))
            return web.Response(
                text="Dashboard error",
                status=500,
                content_type="text/plain",
            )

    async def handle_websocket(self, request: web.Request) -> web.WebSocketResponse | web.Response:
        """Handle WebSocket connection for real-time dashboard updates.

        Args:
            request: The incoming HTTP request.

        Returns:
            WebSocket response or auth error.
        """
        # Check authentication (WebSocket upgrade includes auth header)
        if auth_error := self._check_auth(request):
            return auth_error

        ws = web.WebSocketResponse(
            heartbeat=30.0,
            receive_timeout=60.0,
        )
        await ws.prepare(request)

        # Register client with broadcaster
        await self._broadcaster.add_client(ws)

        try:
            async for msg in ws:
                if msg.type == WSMsgType.TEXT:
                    # Handle client messages (e.g., requests for tunnel details)
                    await self._broadcaster.handle_client_message(ws, msg.data)
                elif msg.type == WSMsgType.ERROR:
                    logger.warning(
                        "Dashboard WebSocket error",
                        error=str(ws.exception()),
                    )
                    break
                elif msg.type == WSMsgType.CLOSE:
                    break
        except Exception as e:
            logger.debug("Dashboard WebSocket exception", error=str(e))
        finally:
            await self._broadcaster.remove_client(ws)

        return ws

    async def handle_static(self, request: web.Request) -> web.Response:
        """Serve static assets (CSS, JS).

        Args:
            request: The incoming HTTP request.

        Returns:
            Response with static file content.
        """
        # Check authentication
        if auth_error := self._check_auth(request):
            return auth_error

        path = request.match_info.get("path", "")

        # Security: prevent directory traversal
        if ".." in path or path.startswith("/"):
            return web.Response(text="Forbidden", status=403)

        file_path = STATIC_DIR / path

        if not file_path.exists() or not file_path.is_file():
            return web.Response(text="Not found", status=404)

        # Determine content type
        content_type = self._get_content_type(file_path)

        try:
            if content_type.startswith("text/") or content_type.endswith("/javascript"):
                content = file_path.read_text(encoding="utf-8")
                return web.Response(
                    text=content,
                    content_type=content_type,
                    headers={"Cache-Control": "public, max-age=300"},
                )
            else:
                content = file_path.read_bytes()
                return web.Response(
                    body=content,
                    content_type=content_type,
                    headers={"Cache-Control": "public, max-age=300"},
                )
        except Exception as e:
            logger.error("Failed to read static file", path=path, error=str(e))
            return web.Response(text="Internal error", status=500)

    def _get_content_type(self, path: Path) -> str:
        """Get MIME content type for a file.

        Args:
            path: File path.

        Returns:
            MIME type string.
        """
        suffix = path.suffix.lower()
        content_types = {
            ".html": "text/html",
            ".css": "text/css",
            ".js": "application/javascript",
            ".json": "application/json",
            ".png": "image/png",
            ".jpg": "image/jpeg",
            ".jpeg": "image/jpeg",
            ".gif": "image/gif",
            ".svg": "image/svg+xml",
            ".ico": "image/x-icon",
            ".woff": "font/woff",
            ".woff2": "font/woff2",
            ".ttf": "font/ttf",
        }
        return content_types.get(suffix, "application/octet-stream")
